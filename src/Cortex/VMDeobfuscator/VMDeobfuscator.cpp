/**
 * @file VMDeobfuscator.cpp
 * @brief VM Deobfuscation Engine Implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include "VMDeobfuscator.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace Sentinel::Cortex::VMDeobfuscator {

// ============================================================================
// VirtualInstruction Implementation
// ============================================================================

std::string VirtualInstruction::toString() const {
    std::ostringstream oss;
    oss << std::hex << std::setw(8) << std::setfill('0') << vmAddress << ": ";
    oss << mnemonic;
    
    if (!operands.empty()) {
        oss << " ";
        for (size_t i = 0; i < operands.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << "0x" << std::hex << operands[i];
        }
    }
    
    if (!comment.empty()) {
        oss << " ; " << comment;
    }
    
    return oss.str();
}

// ============================================================================
// VirtualCFG Implementation
// ============================================================================

const VirtualBasicBlock* VirtualCFG::getBlockAt(Address addr) const {
    auto it = blocks.find(addr);
    return (it != blocks.end()) ? &it->second : nullptr;
}

std::vector<const VirtualBasicBlock*> VirtualCFG::getBlocksInOrder() const {
    std::vector<const VirtualBasicBlock*> result;
    result.reserve(blocks.size());
    
    for (const auto& pair : blocks) {
        result.push_back(&pair.second);
    }
    
    // Sort by start address
    std::sort(result.begin(), result.end(),
        [](const VirtualBasicBlock* a, const VirtualBasicBlock* b) {
            return a->startAddress < b->startAddress;
        });
    
    return result;
}

// ============================================================================
// SSAValue Implementation
// ============================================================================

SSAValue SSAValue::constant(uint64_t val, size_t bits) {
    SSAValue value;
    value.type = SSAValueType::Constant;
    value.constantValue = val;
    value.bitWidth = bits;
    return value;
}

SSAValue SSAValue::temp(uint64_t id, size_t bits) {
    SSAValue value;
    value.type = SSAValueType::Temporary;
    value.id = id;
    value.bitWidth = bits;
    return value;
}

// ============================================================================
// SSAInstruction Implementation
// ============================================================================

std::string SSAInstruction::toString() const {
    std::ostringstream oss;
    
    // Result
    if (result.type != SSAValueType::Undefined) {
        oss << "%" << result.id << " = ";
    }
    
    // Opcode
    switch (opcode) {
        case SSAOpcode::Add: oss << "add"; break;
        case SSAOpcode::Sub: oss << "sub"; break;
        case SSAOpcode::Mul: oss << "mul"; break;
        case SSAOpcode::And: oss << "and"; break;
        case SSAOpcode::Or: oss << "or"; break;
        case SSAOpcode::Xor: oss << "xor"; break;
        case SSAOpcode::Load: oss << "load"; break;
        case SSAOpcode::Store: oss << "store"; break;
        case SSAOpcode::Br: oss << "br"; break;
        case SSAOpcode::Ret: oss << "ret"; break;
        default: oss << "unknown"; break;
    }
    
    // Operands
    if (!operands.empty()) {
        oss << " ";
        for (size_t i = 0; i < operands.size(); ++i) {
            if (i > 0) oss << ", ";
            if (operands[i].type == SSAValueType::Constant) {
                oss << operands[i].constantValue.value();
            } else {
                oss << "%" << operands[i].id;
            }
        }
    }
    
    if (!comment.empty()) {
        oss << " ; " << comment;
    }
    
    return oss.str();
}

// ============================================================================
// SSAFunction Implementation
// ============================================================================

const SSABasicBlock* SSAFunction::getEntryBlock() const {
    return blocks.empty() ? nullptr : &blocks[0];
}

std::string SSAFunction::toPseudoC() const {
    std::ostringstream oss;
    
    oss << "// Function: " << name << "\n";
    oss << "void " << name << "() {\n";
    
    for (const auto& block : blocks) {
        oss << block.label << ":\n";
        for (const auto& instr : block.instructions) {
            oss << "    " << instr.toString() << "\n";
        }
    }
    
    oss << "}\n";
    
    return oss.str();
}

std::string SSAFunction::toLLVMIR() const {
    std::ostringstream oss;
    
    oss << "define void @" << name << "() {\n";
    
    for (const auto& block : blocks) {
        oss << block.label << ":\n";
        for (const auto& instr : block.instructions) {
            oss << "  " << instr.toString() << "\n";
        }
    }
    
    oss << "}\n";
    
    return oss.str();
}

// ============================================================================
// ExecutionTrace Implementation
// ============================================================================

ExecutionTrace ExecutionTrace::filterRange(Address start, Address end) const {
    ExecutionTrace filtered;
    filtered.startAddress = start;
    filtered.endAddress = end;
    
    for (const auto& entry : entries) {
        if (entry.address >= start && entry.address < end) {
            filtered.entries.push_back(entry);
        }
    }
    
    filtered.instructionCount = filtered.entries.size();
    return filtered;
}

std::set<Address> ExecutionTrace::getUniqueAddresses() const {
    std::set<Address> addresses;
    for (const auto& entry : entries) {
        addresses.insert(entry.address);
    }
    return addresses;
}

// ============================================================================
// DeobfuscationResult Implementation
// ============================================================================

std::string DeobfuscationResult::toJSON() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"protector\": \"" << protectorTypeToString(detection.type) << "\",\n";
    oss << "  \"confidence\": " << static_cast<int>(detection.confidence) << ",\n";
    oss << "  \"virtualInstructionCount\": " << virtualInstructionCount << ",\n";
    oss << "  \"handlerCount\": " << handlerCount << ",\n";
    oss << "  \"basicBlockCount\": " << basicBlockCount << ",\n";
    oss << "  \"analysisTimeSeconds\": " << analysisTimeSeconds << "\n";
    oss << "}\n";
    return oss.str();
}

// ============================================================================
// VMDeobfuscatorEngine::Impl
// ============================================================================

class VMDeobfuscatorEngine::Impl {
public:
    std::string lastError;
    int progress = 0;
    bool cancelRequested = false;
    bool initialized = false;
    
    // Detection patterns for known protectors
    struct ProtectorPattern {
        VMProtectorType type;
        std::vector<uint8_t> signature;
        std::string description;
    };
    
    std::vector<ProtectorPattern> knownPatterns;
    
    Impl() {
        initializePatterns();
        initialized = true;
    }
    
    void initializePatterns() {
        // VMProtect pattern (simplified)
        knownPatterns.push_back({
            VMProtectorType::VMProtect,
            {0x55, 0x8B, 0xEC, 0x83, 0xEC}, // push ebp; mov ebp, esp; sub esp, ...
            "VMProtect prologue"
        });
        
        // Themida pattern (simplified)
        knownPatterns.push_back({
            VMProtectorType::Themida,
            {0x60, 0x9C, 0xBE}, // pushad; pushfd; mov esi, ...
            "Themida prologue"
        });
    }
    
    VMDetectionResult detectProtectorFromCode(ByteSpan code) {
        VMDetectionResult result;
        result.confidence = ConfidenceLevel::None;
        result.type = VMProtectorType::Unknown;
        
        // Simple pattern matching
        for (const auto& pattern : knownPatterns) {
            if (code.size() < pattern.signature.size()) continue;
            
            bool matched = true;
            for (size_t i = 0; i < pattern.signature.size(); ++i) {
                if (code[i] != pattern.signature[i]) {
                    matched = false;
                    break;
                }
            }
            
            if (matched) {
                result.type = pattern.type;
                result.confidence = ConfidenceLevel::Medium;
                result.notes = pattern.description;
                break;
            }
        }
        
        return result;
    }
    
    ExecutionTrace simulateExecution(ByteSpan code, Address entryPoint, const DeobfuscatorOptions& options) {
        ExecutionTrace trace;
        trace.startAddress = entryPoint;
        trace.endAddress = entryPoint;
        
        // Simplified simulation - in real implementation would use PIN/DynamoRIO
        // For now, just create a stub trace
        TraceEntry entry;
        entry.address = entryPoint;
        entry.instruction.assign(code.begin(), code.begin() + std::min<size_t>(code.size(), 16));
        entry.disassembly = "stub instruction";
        entry.timestamp = 0;
        
        trace.entries.push_back(entry);
        trace.instructionCount = 1;
        
        return trace;
    }
    
    std::map<Address, VirtualOpcodeType> analyzeHandlersFromTrace(const ExecutionTrace& trace) {
        std::map<Address, VirtualOpcodeType> handlers;
        
        // Stub implementation - would analyze execution patterns
        for (const auto& entry : trace.entries) {
            // Detect handler type based on patterns
            handlers[entry.address] = VirtualOpcodeType::Unknown;
        }
        
        return handlers;
    }
    
    VirtualCFG buildCFGFromTrace(const ExecutionTrace& trace, const std::map<Address, VirtualOpcodeType>& handlers) {
        VirtualCFG cfg;
        
        if (trace.entries.empty()) return cfg;
        
        cfg.entryPoint = trace.entries[0].address;
        
        // Create basic blocks from trace
        VirtualBasicBlock currentBlock;
        currentBlock.startAddress = trace.entries[0].address;
        
        for (const auto& entry : trace.entries) {
            VirtualInstruction vinstr;
            vinstr.vmAddress = entry.address;
            vinstr.opcode = VirtualOpcodeType::Unknown;
            vinstr.mnemonic = entry.disassembly;
            
            currentBlock.instructions.push_back(vinstr);
        }
        
        if (!trace.entries.empty()) {
            currentBlock.endAddress = trace.entries.back().address;
            cfg.blocks[currentBlock.startAddress] = currentBlock;
        }
        
        return cfg;
    }
    
    SSAFunction liftCFGToSSA(const VirtualCFG& cfg, const DeobfuscatorOptions& options) {
        SSAFunction func;
        func.name = "deobfuscated_function";
        func.originalAddress = cfg.entryPoint;
        
        // Create entry block
        SSABasicBlock entryBlock;
        entryBlock.label = "entry";
        
        // Add stub instructions
        SSAInstruction retInstr;
        retInstr.opcode = SSAOpcode::Ret;
        retInstr.comment = "Stub return";
        
        entryBlock.instructions.push_back(retInstr);
        func.blocks.push_back(entryBlock);
        
        return func;
    }
    
    std::string generatePseudoC(const SSAFunction& func) {
        return func.toPseudoC();
    }
};

// ============================================================================
// VMDeobfuscatorEngine Implementation
// ============================================================================

VMDeobfuscatorEngine::VMDeobfuscatorEngine()
    : m_impl(std::make_unique<Impl>()) {
}

VMDeobfuscatorEngine::~VMDeobfuscatorEngine() = default;

VMDeobfuscatorEngine::VMDeobfuscatorEngine(VMDeobfuscatorEngine&&) noexcept = default;
VMDeobfuscatorEngine& VMDeobfuscatorEngine::operator=(VMDeobfuscatorEngine&&) noexcept = default;

Sentinel::Result<DeobfuscationResult> VMDeobfuscatorEngine::analyze(
    const std::string& binaryPath,
    Address vmEntryPoint,
    const DeobfuscatorOptions& options) {
    
    if (!m_impl->initialized) {
        return Sentinel::Result<DeobfuscationResult>::Error(
            Sentinel::ErrorCode::NotInitialized, "Engine not initialized");
    }
    
    // Read binary
    std::ifstream file(binaryPath, std::ios::binary);
    if (!file) {
        return Sentinel::Result<DeobfuscationResult>::Error(
            Sentinel::ErrorCode::FileNotFound, "Cannot open binary file");
    }
    
    std::vector<uint8_t> code((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    
    return analyzeMemory(code, 0x400000, vmEntryPoint, options);
}

Sentinel::Result<DeobfuscationResult> VMDeobfuscatorEngine::analyzeMemory(
    ByteSpan code,
    Address baseAddress,
    Address vmEntryPoint,
    const DeobfuscatorOptions& options) {
    
    m_impl->progress = 0;
    auto startTime = std::chrono::high_resolution_clock::now();
    
    DeobfuscationResult result;
    
    // Step 1: Detect protector
    m_impl->progress = 10;
    result.detection = m_impl->detectProtectorFromCode(code);
    
    if (options.progressCallback) {
        options.progressCallback("Detected protector", m_impl->progress);
    }
    
    // Step 2: Trace execution
    m_impl->progress = 30;
    if (options.enableDynamicTracing) {
        result.trace = m_impl->simulateExecution(code, vmEntryPoint, options);
    }
    
    if (options.progressCallback) {
        options.progressCallback("Traced execution", m_impl->progress);
    }
    
    // Step 3: Analyze handlers
    m_impl->progress = 50;
    auto handlers = m_impl->analyzeHandlersFromTrace(result.trace);
    result.handlerCount = handlers.size();
    
    if (options.progressCallback) {
        options.progressCallback("Analyzed handlers", m_impl->progress);
    }
    
    // Step 4: Build CFG
    m_impl->progress = 70;
    result.virtualCFG = m_impl->buildCFGFromTrace(result.trace, handlers);
    result.basicBlockCount = result.virtualCFG.blocks.size();
    result.virtualInstructionCount = 0;
    
    for (const auto& block : result.virtualCFG.blocks) {
        result.virtualInstructionCount += block.second.instructions.size();
    }
    
    if (options.progressCallback) {
        options.progressCallback("Built CFG", m_impl->progress);
    }
    
    // Step 5: Lift to SSA
    m_impl->progress = 85;
    if (options.enableSSALifting) {
        auto ssaFunc = m_impl->liftCFGToSSA(result.virtualCFG, options);
        result.liftedFunctions.push_back(ssaFunc);
    }
    
    if (options.progressCallback) {
        options.progressCallback("Lifted to SSA", m_impl->progress);
    }
    
    // Step 6: Generate pseudo-C
    m_impl->progress = 95;
    if (options.generatePseudoC && !result.liftedFunctions.empty()) {
        result.pseudoCode = m_impl->generatePseudoC(result.liftedFunctions[0]);
    }
    
    // Calculate analysis time
    auto endTime = std::chrono::high_resolution_clock::now();
    result.analysisTimeSeconds = std::chrono::duration<double>(endTime - startTime).count();
    
    m_impl->progress = 100;
    if (options.progressCallback) {
        options.progressCallback("Analysis complete", m_impl->progress);
    }
    
    return Sentinel::Result<DeobfuscationResult>::Success(result);
}

Sentinel::Result<VMDetectionResult> VMDeobfuscatorEngine::detectProtector(const std::string& binaryPath) {
    std::ifstream file(binaryPath, std::ios::binary);
    if (!file) {
        return Sentinel::Result<VMDetectionResult>::Error(
            Sentinel::ErrorCode::FileNotFound, "Cannot open binary file");
    }
    
    std::vector<uint8_t> code((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    
    return detectProtectorInMemory(code, 0x400000);
}

Sentinel::Result<VMDetectionResult> VMDeobfuscatorEngine::detectProtectorInMemory(
    ByteSpan code,
    Address baseAddress) {
    
    auto result = m_impl->detectProtectorFromCode(code);
    return Sentinel::Result<VMDetectionResult>::Success(result);
}

Sentinel::Result<std::vector<Address>> VMDeobfuscatorEngine::findVMEntryPoints(const std::string& binaryPath) {
    std::vector<Address> entryPoints;
    
    // Stub implementation - would scan for VM entry patterns
    entryPoints.push_back(0x401000); // Example entry point
    
    return Sentinel::Result<std::vector<Address>>::Success(entryPoints);
}

Sentinel::Result<ExecutionTrace> VMDeobfuscatorEngine::traceExecution(
    const std::string& binaryPath,
    Address entryPoint,
    const DeobfuscatorOptions& options) {
    
    std::ifstream file(binaryPath, std::ios::binary);
    if (!file) {
        return Sentinel::Result<ExecutionTrace>::Error(
            Sentinel::ErrorCode::FileNotFound, "Cannot open binary file");
    }
    
    std::vector<uint8_t> code((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    
    auto trace = m_impl->simulateExecution(code, entryPoint, options);
    return Sentinel::Result<ExecutionTrace>::Success(trace);
}

Sentinel::Result<std::map<Address, VirtualOpcodeType>> VMDeobfuscatorEngine::analyzeHandlers(
    const ExecutionTrace& trace) {
    
    auto handlers = m_impl->analyzeHandlersFromTrace(trace);
    return Sentinel::Result<std::map<Address, VirtualOpcodeType>>::Success(handlers);
}

Sentinel::Result<VirtualCFG> VMDeobfuscatorEngine::buildVirtualCFG(
    const ExecutionTrace& trace,
    const std::map<Address, VirtualOpcodeType>& handlers) {
    
    auto cfg = m_impl->buildCFGFromTrace(trace, handlers);
    return Sentinel::Result<VirtualCFG>::Success(cfg);
}

Sentinel::Result<SSAFunction> VMDeobfuscatorEngine::liftToSSA(
    const VirtualCFG& cfg,
    const DeobfuscatorOptions& options) {
    
    auto func = m_impl->liftCFGToSSA(cfg, options);
    return Sentinel::Result<SSAFunction>::Success(func);
}

Sentinel::Result<std::string> VMDeobfuscatorEngine::generatePseudoC(const SSAFunction& ssaFunc) {
    auto code = m_impl->generatePseudoC(ssaFunc);
    return Sentinel::Result<std::string>::Success(code);
}

bool VMDeobfuscatorEngine::isReady() const noexcept {
    return m_impl->initialized;
}

std::string VMDeobfuscatorEngine::getLastError() const {
    return m_impl->lastError;
}

void VMDeobfuscatorEngine::cancelAnalysis() {
    m_impl->cancelRequested = true;
}

int VMDeobfuscatorEngine::getProgress() const noexcept {
    return m_impl->progress;
}

std::vector<std::string> VMDeobfuscatorEngine::getSupportedProtectors() {
    return {
        "VMProtect",
        "Themida",
        "CodeVirtualizer",
        "Enigma",
        "Obsidium",
        "Custom"
    };
}

// ============================================================================
// HandlerDatabase Implementation
// ============================================================================

class HandlerDatabase::Impl {
public:
    struct Pattern {
        VirtualOpcodeType opcodeType;
        std::vector<uint8_t> bytes;
        std::string mask;
    };
    
    std::vector<Pattern> patterns;
};

HandlerDatabase::HandlerDatabase()
    : m_impl(std::make_unique<Impl>()) {
}

HandlerDatabase::~HandlerDatabase() = default;

bool HandlerDatabase::load(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    
    // Would load patterns from file
    return true;
}

bool HandlerDatabase::save(const std::string& path) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    
    // Would save patterns to file
    return true;
}

std::pair<VirtualOpcodeType, ConfidenceLevel> HandlerDatabase::match(ByteSpan handlerCode) const {
    // Simple pattern matching
    for (const auto& pattern : m_impl->patterns) {
        if (handlerCode.size() < pattern.bytes.size()) continue;
        
        bool matched = true;
        for (size_t i = 0; i < pattern.bytes.size(); ++i) {
            if (pattern.mask[i] == 'x' && handlerCode[i] != pattern.bytes[i]) {
                matched = false;
                break;
            }
        }
        
        if (matched) {
            return {pattern.opcodeType, ConfidenceLevel::High};
        }
    }
    
    return {VirtualOpcodeType::Unknown, ConfidenceLevel::None};
}

void HandlerDatabase::addPattern(
    VirtualOpcodeType opcodeType,
    ByteSpan pattern,
    const std::string& mask) {
    
    HandlerDatabase::Impl::Pattern p;
    p.opcodeType = opcodeType;
    p.bytes.assign(pattern.begin(), pattern.end());
    p.mask = mask;
    
    m_impl->patterns.push_back(p);
}

size_t HandlerDatabase::patternCount() const noexcept {
    return m_impl->patterns.size();
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string opcodeTypeToString(VirtualOpcodeType opcode) {
    switch (opcode) {
        case VirtualOpcodeType::VPush: return "VPush";
        case VirtualOpcodeType::VPop: return "VPop";
        case VirtualOpcodeType::VAdd: return "VAdd";
        case VirtualOpcodeType::VSub: return "VSub";
        case VirtualOpcodeType::VMul: return "VMul";
        case VirtualOpcodeType::VDiv: return "VDiv";
        case VirtualOpcodeType::VAnd: return "VAnd";
        case VirtualOpcodeType::VOr: return "VOr";
        case VirtualOpcodeType::VXor: return "VXor";
        case VirtualOpcodeType::VLoad: return "VLoad";
        case VirtualOpcodeType::VStore: return "VStore";
        case VirtualOpcodeType::VJmp: return "VJmp";
        case VirtualOpcodeType::VJcc: return "VJcc";
        case VirtualOpcodeType::VCall: return "VCall";
        case VirtualOpcodeType::VRet: return "VRet";
        case VirtualOpcodeType::VNop: return "VNop";
        case VirtualOpcodeType::Unknown:
        default: return "Unknown";
    }
}

std::string protectorTypeToString(VMProtectorType type) {
    switch (type) {
        case VMProtectorType::VMProtect: return "VMProtect";
        case VMProtectorType::Themida: return "Themida";
        case VMProtectorType::CodeVirtualizer: return "Code Virtualizer";
        case VMProtectorType::Enigma: return "Enigma";
        case VMProtectorType::Obsidium: return "Obsidium";
        case VMProtectorType::ASProtect: return "ASProtect";
        case VMProtectorType::Safengine: return "Safengine";
        case VMProtectorType::Custom: return "Custom";
        case VMProtectorType::Unknown:
        default: return "Unknown";
    }
}

std::string confidenceToString(ConfidenceLevel level) {
    switch (level) {
        case ConfidenceLevel::Certain: return "Certain";
        case ConfidenceLevel::High: return "High";
        case ConfidenceLevel::Medium: return "Medium";
        case ConfidenceLevel::Low: return "Low";
        case ConfidenceLevel::None:
        default: return "None";
    }
}

} // namespace Sentinel::Cortex::VMDeobfuscator
