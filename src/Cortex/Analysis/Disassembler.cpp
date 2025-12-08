/**
 * @file Disassembler.cpp
 * @brief Implementation of Capstone-based disassembler
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include "Disassembler.hpp"
#include <capstone/capstone.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <unordered_set>

namespace Sentinel::Cortex {

// ============================================================================
// Helper Functions
// ============================================================================

std::string DisassembledInstruction::bytesHex() const {
    return formatBytes(bytes);
}

std::string formatAddress(Address address, bool is64Bit) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::setfill('0');
    if (is64Bit) {
        ss << std::setw(16) << std::hex << address;
    } else {
        ss << std::setw(8) << std::hex << static_cast<uint32_t>(address);
    }
    return ss.str();
}

std::string formatBytes(ByteSpan bytes, const std::string& separator) {
    std::ostringstream ss;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) ss << separator;
        ss << std::uppercase << std::setfill('0') << std::setw(2) 
           << std::hex << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

bool isControlFlowInstruction(const DisassembledInstruction& insn) {
    return insn.isBranch || insn.isCall || insn.isReturn;
}

Address calculateBranchTarget(const DisassembledInstruction& insn) {
    return insn.branchTarget;
}

// ============================================================================
// Disassembler Implementation
// ============================================================================

class Disassembler::Impl {
public:
    explicit Impl(const DisassemblerOptions& options)
        : m_options(options)
        , m_handle(0)
        , m_valid(false)
    {
        cs_arch arch;
        cs_mode mode;
        
        switch (options.architecture) {
            case Architecture::X86_32:
                arch = CS_ARCH_X86;
                mode = CS_MODE_32;
                break;
            case Architecture::X86_64:
                arch = CS_ARCH_X86;
                mode = CS_MODE_64;
                break;
            default:
                return;
        }
        
        if (cs_open(arch, mode, &m_handle) != CS_ERR_OK) {
            return;
        }
        
        // Enable detailed instruction information
        cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
        
        m_valid = true;
    }
    
    ~Impl() {
        if (m_valid) {
            cs_close(&m_handle);
        }
    }
    
    bool isValid() const noexcept { return m_valid; }
    
    const DisassemblerOptions& getOptions() const noexcept { return m_options; }
    
    void setOptions(const DisassemblerOptions& options) {
        // If architecture changed, reinitialize
        if (options.architecture != m_options.architecture) {
            if (m_valid) {
                cs_close(&m_handle);
                m_valid = false;
            }
            
            cs_arch arch;
            cs_mode mode;
            
            switch (options.architecture) {
                case Architecture::X86_32:
                    arch = CS_ARCH_X86;
                    mode = CS_MODE_32;
                    break;
                case Architecture::X86_64:
                    arch = CS_ARCH_X86;
                    mode = CS_MODE_64;
                    break;
                default:
                    return;
            }
            
            if (cs_open(arch, mode, &m_handle) == CS_ERR_OK) {
                cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
                m_valid = true;
            }
        }
        
        m_options = options;
    }
    
    void setSymbolResolver(std::function<std::string(Address)> resolver) {
        m_symbolResolver = std::move(resolver);
    }
    
    Result<std::vector<DisassembledInstruction>> disassemble(
        ByteSpan code,
        Address baseAddress
    ) {
        if (!m_valid) return ErrorCode::InvalidState;
        if (code.empty()) return ErrorCode::InvalidArgument;
        
        std::vector<DisassembledInstruction> result;
        
        cs_insn* insn;
        size_t count = cs_disasm(m_handle, code.data(), code.size(), baseAddress, 0, &insn);
        
        if (count == 0) {
            cs_err err = cs_errno(m_handle);
            if (err != CS_ERR_OK) {
                return ErrorCode::DisassemblyFailed;
            }
            return result; // Empty but valid
        }
        
        result.reserve(count);
        
        for (size_t i = 0; i < count; ++i) {
            DisassembledInstruction di = convertInstruction(insn[i]);
            result.push_back(std::move(di));
            
            if (m_options.maxInstructions > 0 && result.size() >= m_options.maxInstructions) {
                break;
            }
        }
        
        cs_free(insn, count);
        
        return result;
    }
    
    Result<DisassembledInstruction> disassembleOne(ByteSpan code, Address address) {
        if (!m_valid) return ErrorCode::InvalidState;
        if (code.empty()) return ErrorCode::InvalidArgument;
        
        cs_insn* insn;
        size_t count = cs_disasm(m_handle, code.data(), code.size(), address, 1, &insn);
        
        if (count == 0) {
            return ErrorCode::DisassemblyFailed;
        }
        
        DisassembledInstruction result = convertInstruction(insn[0]);
        cs_free(insn, count);
        
        return result;
    }
    
    Result<FunctionInfo> disassembleFunction(
        ByteSpan code,
        Address functionStart,
        Address baseAddress
    ) {
        if (!m_valid) return ErrorCode::InvalidState;
        
        FunctionInfo func;
        func.startAddress = functionStart;
        func.name = resolveSymbol(functionStart);
        
        // Calculate offset into code buffer
        if (functionStart < baseAddress) {
            return ErrorCode::InvalidArgument;
        }
        
        size_t offset = static_cast<size_t>(functionStart - baseAddress);
        if (offset >= code.size()) {
            return ErrorCode::InvalidArgument;
        }
        
        ByteSpan funcCode = code.subspan(offset);
        
        // Track basic block starts
        std::unordered_set<Address> blockStarts;
        blockStarts.insert(functionStart);
        
        // Disassemble until we hit a return or run out of code
        const uint8_t* codePtr = funcCode.data();
        size_t codeSize = funcCode.size();
        Address currentAddr = functionStart;
        
        cs_insn* insn = cs_malloc(m_handle);
        if (!insn) {
            return ErrorCode::AllocationFailed;
        }
        
        bool inFunction = true;
        while (inFunction && codeSize > 0) {
            if (!cs_disasm_iter(m_handle, &codePtr, &codeSize, &currentAddr, insn)) {
                break;
            }
            
            DisassembledInstruction di = convertInstruction(*insn);
            func.instructions.push_back(di);
            
            // Track control flow
            if (di.isConditionalJump && di.branchTarget != 0) {
                blockStarts.insert(di.branchTarget);
                blockStarts.insert(currentAddr); // Fall-through is also a block start
            }
            
            if (di.isReturn) {
                inFunction = false;
            }
            
            // Heuristic: stop at unconditional jump with no following code
            if (di.isJump && !di.isConditionalJump) {
                // Check if next address is referenced elsewhere
                // For now, just stop
                inFunction = false;
            }
        }
        
        cs_free(insn, 1);
        
        if (func.instructions.empty()) {
            return ErrorCode::FunctionNotFound;
        }
        
        func.endAddress = func.instructions.back().address + func.instructions.back().size;
        func.size = static_cast<size_t>(func.endAddress - func.startAddress);
        
        // Copy basic block starts
        func.basicBlockStarts.assign(blockStarts.begin(), blockStarts.end());
        std::sort(func.basicBlockStarts.begin(), func.basicBlockStarts.end());
        
        return func;
    }
    
    size_t getInstructionLength(ByteSpan code) {
        if (!m_valid || code.empty()) return 0;
        
        cs_insn* insn;
        size_t count = cs_disasm(m_handle, code.data(), 
            std::min(code.size(), size_t(15)), 0, 1, &insn);
        
        if (count == 0) return 0;
        
        size_t len = insn[0].size;
        cs_free(insn, count);
        
        return len;
    }
    
    static std::string getCapstoneVersion() {
        int major, minor;
        cs_version(&major, &minor);
        return std::to_string(major) + "." + std::to_string(minor);
    }

private:
    DisassembledInstruction convertInstruction(const cs_insn& insn) {
        DisassembledInstruction di;
        
        di.address = insn.address;
        di.bytes.assign(insn.bytes, insn.bytes + insn.size);
        di.mnemonic = insn.mnemonic;
        di.operandString = insn.op_str;
        di.size = insn.size;
        
        // Analyze instruction details
        if (insn.detail) {
            const cs_x86& x86 = insn.detail->x86;
            
            // Parse operands
            for (uint8_t i = 0; i < x86.op_count; ++i) {
                const cs_x86_op& op = x86.operands[i];
                OperandInfo opInfo;
                
                switch (op.type) {
                    case X86_OP_REG:
                        opInfo.type = OperandType::Register;
                        opInfo.reg = cs_reg_name(m_handle, op.reg);
                        break;
                        
                    case X86_OP_IMM:
                        opInfo.type = OperandType::Immediate;
                        opInfo.value = op.imm;
                        break;
                        
                    case X86_OP_MEM:
                        opInfo.type = OperandType::Memory;
                        if (op.mem.base != X86_REG_INVALID) {
                            opInfo.memBase = cs_reg_name(m_handle, op.mem.base);
                        }
                        if (op.mem.index != X86_REG_INVALID) {
                            opInfo.memIndex = cs_reg_name(m_handle, op.mem.index);
                        }
                        opInfo.memScale = op.mem.scale;
                        opInfo.memDisp = op.mem.disp;
                        break;
                        
                    default:
                        opInfo.type = OperandType::Invalid;
                        break;
                }
                
                opInfo.size = op.size;
                di.operands.push_back(opInfo);
            }
            
            // Classify instruction
            di.group = classifyInstruction(insn);
            
            // Check for control flow
            for (uint8_t i = 0; i < insn.detail->groups_count; ++i) {
                switch (insn.detail->groups[i]) {
                    case CS_GRP_JUMP:
                        di.isJump = true;
                        di.isBranch = true;
                        break;
                    case CS_GRP_CALL:
                        di.isCall = true;
                        di.isBranch = true;
                        break;
                    case CS_GRP_RET:
                        di.isReturn = true;
                        break;
                    case CS_GRP_BRANCH_RELATIVE:
                        di.isBranch = true;
                        break;
                    default:
                        break;
                }
            }
            
            // Check for conditional jump
            if (di.isJump) {
                // If mnemonic is not "jmp", it's conditional
                di.isConditionalJump = (di.mnemonic != "jmp");
            }
            
            // Calculate branch target
            if (di.isBranch && x86.op_count > 0 && x86.operands[0].type == X86_OP_IMM) {
                di.branchTarget = static_cast<Address>(x86.operands[0].imm);
            }
        }
        
        return di;
    }
    
    InstructionGroup classifyInstruction(const cs_insn& insn) {
        if (!insn.detail) return InstructionGroup::Unknown;
        
        for (uint8_t i = 0; i < insn.detail->groups_count; ++i) {
            switch (insn.detail->groups[i]) {
                case CS_GRP_JUMP:
                case CS_GRP_BRANCH_RELATIVE:
                    return InstructionGroup::Jump;
                case CS_GRP_CALL:
                    return InstructionGroup::Call;
                case CS_GRP_RET:
                    return InstructionGroup::Return;
                case CS_GRP_INT:
                    return InstructionGroup::Interrupt;
                case CS_GRP_PRIVILEGE:
                    return InstructionGroup::Privileged;
                default:
                    break;
            }
        }
        
        // Classify by mnemonic prefix
        if (insn.mnemonic[0] == 'j') {
            return InstructionGroup::Jump;
        }
        if (strncmp(insn.mnemonic, "call", 4) == 0) {
            return InstructionGroup::Call;
        }
        if (strncmp(insn.mnemonic, "ret", 3) == 0) {
            return InstructionGroup::Return;
        }
        if (strncmp(insn.mnemonic, "mov", 3) == 0 ||
            strncmp(insn.mnemonic, "push", 4) == 0 ||
            strncmp(insn.mnemonic, "pop", 3) == 0 ||
            strncmp(insn.mnemonic, "lea", 3) == 0) {
            return InstructionGroup::DataTransfer;
        }
        if (strncmp(insn.mnemonic, "add", 3) == 0 ||
            strncmp(insn.mnemonic, "sub", 3) == 0 ||
            strncmp(insn.mnemonic, "mul", 3) == 0 ||
            strncmp(insn.mnemonic, "div", 3) == 0 ||
            strncmp(insn.mnemonic, "inc", 3) == 0 ||
            strncmp(insn.mnemonic, "dec", 3) == 0) {
            return InstructionGroup::Arithmetic;
        }
        if (strncmp(insn.mnemonic, "and", 3) == 0 ||
            strncmp(insn.mnemonic, "or", 2) == 0 ||
            strncmp(insn.mnemonic, "xor", 3) == 0 ||
            strncmp(insn.mnemonic, "not", 3) == 0 ||
            strncmp(insn.mnemonic, "shl", 3) == 0 ||
            strncmp(insn.mnemonic, "shr", 3) == 0) {
            return InstructionGroup::Logic;
        }
        
        return InstructionGroup::Unknown;
    }
    
    std::string resolveSymbol(Address address) {
        if (m_symbolResolver) {
            return m_symbolResolver(address);
        }
        return "";
    }
    
    DisassemblerOptions m_options;
    csh m_handle;
    bool m_valid;
    std::function<std::string(Address)> m_symbolResolver;
};

// ============================================================================
// Public Interface
// ============================================================================

Disassembler::Disassembler(Architecture arch)
    : m_impl(std::make_unique<Impl>(DisassemblerOptions{arch}))
{}

Disassembler::Disassembler(const DisassemblerOptions& options)
    : m_impl(std::make_unique<Impl>(options))
{}

Disassembler::~Disassembler() = default;

Disassembler::Disassembler(Disassembler&&) noexcept = default;
Disassembler& Disassembler::operator=(Disassembler&&) noexcept = default;

Result<std::vector<DisassembledInstruction>> Disassembler::disassemble(
    ByteSpan code,
    Address baseAddress
) {
    return m_impl->disassemble(code, baseAddress);
}

Result<DisassembledInstruction> Disassembler::disassembleOne(
    ByteSpan code,
    Address address
) {
    return m_impl->disassembleOne(code, address);
}

Result<FunctionInfo> Disassembler::disassembleFunction(
    ByteSpan code,
    Address functionStart,
    Address baseAddress
) {
    return m_impl->disassembleFunction(code, functionStart, baseAddress);
}

Result<std::vector<FunctionInfo>> Disassembler::detectFunctions(
    ByteSpan code,
    Address baseAddress
) {
    // This is a simplified implementation
    // A full implementation would use more sophisticated heuristics
    std::vector<FunctionInfo> functions;
    
    auto disasmResult = m_impl->disassemble(code, baseAddress);
    if (disasmResult.isFailure()) return disasmResult.error();
    
    const auto& instructions = disasmResult.value();
    
    // Find function starts by looking for call targets
    std::unordered_set<Address> callTargets;
    for (const auto& insn : instructions) {
        if (insn.isCall && insn.branchTarget >= baseAddress && 
            insn.branchTarget < baseAddress + code.size()) {
            callTargets.insert(insn.branchTarget);
        }
    }
    
    // Also consider the start of the code as a potential function
    callTargets.insert(baseAddress);
    
    // Disassemble each detected function
    for (Address funcStart : callTargets) {
        auto funcResult = m_impl->disassembleFunction(code, funcStart, baseAddress);
        if (funcResult.isSuccess()) {
            functions.push_back(std::move(funcResult.value()));
        }
    }
    
    // Sort by address
    std::sort(functions.begin(), functions.end(),
        [](const FunctionInfo& a, const FunctionInfo& b) {
            return a.startAddress < b.startAddress;
        });
    
    return functions;
}

Result<DisassembledInstruction> Disassembler::getInstructionAt(
    ByteSpan code,
    Address address,
    Address baseAddress
) {
    if (address < baseAddress) return ErrorCode::InvalidAddress;
    
    size_t offset = static_cast<size_t>(address - baseAddress);
    if (offset >= code.size()) return ErrorCode::InvalidAddress;
    
    return m_impl->disassembleOne(code.subspan(offset), address);
}

size_t Disassembler::getInstructionLength(ByteSpan code) {
    return m_impl->getInstructionLength(code);
}

bool Disassembler::isInstructionBoundary(ByteSpan code, Address address, Address baseAddress) {
    auto result = getInstructionAt(code, address, baseAddress);
    return result.isSuccess();
}

void Disassembler::setSymbolResolver(std::function<std::string(Address)> resolver) {
    m_impl->setSymbolResolver(std::move(resolver));
}

const DisassemblerOptions& Disassembler::getOptions() const noexcept {
    return m_impl->getOptions();
}

void Disassembler::setOptions(const DisassemblerOptions& options) {
    m_impl->setOptions(options);
}

bool Disassembler::isValid() const noexcept {
    return m_impl->isValid();
}

std::string Disassembler::getCapstoneVersion() {
    return Impl::getCapstoneVersion();
}

} // namespace Sentinel::Cortex
