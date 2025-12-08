/**
 * @file Disassembler.hpp
 * @brief Capstone-based disassembly engine for binary analysis
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#pragma once

#ifndef SENTINEL_CORTEX_DISASSEMBLER_HPP
#define SENTINEL_CORTEX_DISASSEMBLER_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace Sentinel::Cortex {

// ============================================================================
// Instruction Details
// ============================================================================

/**
 * @brief x86/x64 instruction groups
 */
enum class InstructionGroup {
    Unknown,
    Jump,           ///< Jump instructions (jmp, je, jne, etc.)
    Call,           ///< Call instructions
    Return,         ///< Return instructions (ret, retn)
    Interrupt,      ///< Interrupt instructions (int, syscall)
    Privileged,     ///< Privileged instructions
    Branch,         ///< Branch-related (jump/call)
    Arithmetic,     ///< Arithmetic operations
    Logic,          ///< Logical operations
    DataTransfer,   ///< Data movement (mov, push, pop)
    String,         ///< String operations (rep, movs)
    Crypto,         ///< Cryptographic instructions (AES-NI)
    SIMD,           ///< SSE/AVX instructions
    Invalid         ///< Invalid or undefined
};

/**
 * @brief Operand type
 */
enum class OperandType {
    Invalid,
    Register,       ///< Register operand
    Immediate,      ///< Immediate value
    Memory          ///< Memory reference
};

/**
 * @brief Detailed operand information
 */
struct OperandInfo {
    OperandType type = OperandType::Invalid;
    std::string text;           ///< String representation
    int64_t value = 0;          ///< Immediate value (if applicable)
    std::string reg;            ///< Register name (if applicable)
    std::string memBase;        ///< Memory base register
    std::string memIndex;       ///< Memory index register
    int memScale = 1;           ///< Memory scale factor
    int64_t memDisp = 0;        ///< Memory displacement
    size_t size = 0;            ///< Operand size in bytes
};

/**
 * @brief Detailed disassembled instruction
 */
struct DisassembledInstruction {
    Address address;            ///< Instruction address
    ByteBuffer bytes;           ///< Raw instruction bytes
    std::string mnemonic;       ///< Instruction mnemonic
    std::string operandString;  ///< Full operand string
    std::vector<OperandInfo> operands; ///< Parsed operands
    size_t size;                ///< Instruction size in bytes
    InstructionGroup group;     ///< Instruction classification
    
    // Control flow information
    bool isJump = false;        ///< Is a jump instruction
    bool isConditionalJump = false; ///< Is conditional jump
    bool isCall = false;        ///< Is a call instruction
    bool isReturn = false;      ///< Is a return instruction
    bool isBranch = false;      ///< Is any branch instruction
    Address branchTarget = 0;   ///< Branch target address (if branch)
    
    /// Full instruction as string
    [[nodiscard]] std::string toString() const {
        if (operandString.empty()) return mnemonic;
        return mnemonic + " " + operandString;
    }
    
    /// Hex string of bytes
    [[nodiscard]] std::string bytesHex() const;
};

/**
 * @brief Function boundary information
 */
struct FunctionInfo {
    Address startAddress;       ///< Function start
    Address endAddress;         ///< Function end (exclusive)
    std::string name;           ///< Function name (if known)
    size_t size;                ///< Function size in bytes
    std::vector<DisassembledInstruction> instructions; ///< All instructions
    std::vector<Address> basicBlockStarts; ///< Basic block boundaries
    
    /// Get instruction count
    [[nodiscard]] size_t instructionCount() const {
        return instructions.size();
    }
};

// ============================================================================
// Disassembler Configuration
// ============================================================================

/**
 * @brief Disassembly options
 */
struct DisassemblerOptions {
    Architecture architecture = Architecture::X86_64;
    bool resolveSymbols = true;         ///< Attempt to resolve symbol names
    bool analyzeControlFlow = true;     ///< Analyze branches and calls
    bool detectFunctions = true;        ///< Try to detect function boundaries
    size_t maxInstructions = 0;         ///< Maximum instructions (0 = unlimited)
    Address baseAddress = 0;            ///< Base address for relative calculations
};

// ============================================================================
// Disassembler Class
// ============================================================================

/**
 * @brief Capstone-based disassembler engine
 * 
 * High-level wrapper around Capstone disassembly engine providing:
 * - x86/x64 disassembly
 * - Control flow analysis
 * - Function boundary detection
 * - Basic block identification
 * 
 * @example
 * ```cpp
 * Disassembler disasm(Architecture::X86_64);
 * 
 * auto result = disasm.disassemble(codeBuffer, baseAddress);
 * if (result.isSuccess()) {
 *     for (const auto& insn : result.value()) {
 *         std::cout << std::hex << insn.address << ": " 
 *                   << insn.toString() << std::endl;
 *     }
 * }
 * ```
 */
class Disassembler {
public:
    /**
     * @brief Construct disassembler for architecture
     * @param arch Target architecture
     */
    explicit Disassembler(Architecture arch = Architecture::X86_64);
    
    /**
     * @brief Construct with full options
     * @param options Disassembler configuration
     */
    explicit Disassembler(const DisassemblerOptions& options);
    
    /// Destructor
    ~Disassembler();
    
    // Non-copyable
    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;
    
    // Movable
    Disassembler(Disassembler&&) noexcept;
    Disassembler& operator=(Disassembler&&) noexcept;
    
    /**
     * @brief Disassemble code buffer
     * @param code Code bytes to disassemble
     * @param baseAddress Base address for the code
     * @return Vector of disassembled instructions or error
     */
    [[nodiscard]] Result<std::vector<DisassembledInstruction>> disassemble(
        ByteSpan code,
        Address baseAddress = 0
    );
    
    /**
     * @brief Disassemble single instruction
     * @param code Code bytes
     * @param address Instruction address
     * @return Disassembled instruction or error
     */
    [[nodiscard]] Result<DisassembledInstruction> disassembleOne(
        ByteSpan code,
        Address address = 0
    );
    
    /**
     * @brief Disassemble function
     * @param code Full code buffer
     * @param functionStart Start address of function
     * @param baseAddress Base address of the buffer
     * @return Function information or error
     */
    [[nodiscard]] Result<FunctionInfo> disassembleFunction(
        ByteSpan code,
        Address functionStart,
        Address baseAddress = 0
    );
    
    /**
     * @brief Disassemble and detect all functions
     * @param code Full code buffer
     * @param baseAddress Base address of the buffer
     * @return Vector of detected functions or error
     */
    [[nodiscard]] Result<std::vector<FunctionInfo>> detectFunctions(
        ByteSpan code,
        Address baseAddress = 0
    );
    
    /**
     * @brief Get instruction at address
     * @param code Full code buffer
     * @param address Instruction address
     * @param baseAddress Base address of the buffer
     * @return Instruction or error
     */
    [[nodiscard]] Result<DisassembledInstruction> getInstructionAt(
        ByteSpan code,
        Address address,
        Address baseAddress = 0
    );
    
    /**
     * @brief Calculate instruction length
     * @param code Code bytes (need at least 15 bytes)
     * @return Instruction length or 0 on error
     */
    [[nodiscard]] size_t getInstructionLength(ByteSpan code);
    
    /**
     * @brief Check if address is valid instruction boundary
     * @param code Full code buffer
     * @param address Address to check
     * @param baseAddress Base address of the buffer
     * @return true if valid instruction boundary
     */
    [[nodiscard]] bool isInstructionBoundary(
        ByteSpan code,
        Address address,
        Address baseAddress = 0
    );
    
    /**
     * @brief Set symbol resolver callback
     * @param resolver Function to resolve address to symbol name
     */
    void setSymbolResolver(std::function<std::string(Address)> resolver);
    
    /**
     * @brief Get current options
     * @return Disassembler options
     */
    [[nodiscard]] const DisassemblerOptions& getOptions() const noexcept;
    
    /**
     * @brief Set options
     * @param options New options
     */
    void setOptions(const DisassemblerOptions& options);
    
    /**
     * @brief Check if disassembler is valid
     * @return true if initialized successfully
     */
    [[nodiscard]] bool isValid() const noexcept;
    
    /**
     * @brief Get Capstone version string
     * @return Version string
     */
    [[nodiscard]] static std::string getCapstoneVersion();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Format address for display
 * @param address Address to format
 * @param is64Bit Whether to use 64-bit format
 * @return Formatted address string
 */
[[nodiscard]] std::string formatAddress(Address address, bool is64Bit = true);

/**
 * @brief Format bytes as hex string
 * @param bytes Bytes to format
 * @param separator Separator between bytes (default: space)
 * @return Hex string
 */
[[nodiscard]] std::string formatBytes(ByteSpan bytes, const std::string& separator = " ");

/**
 * @brief Check if instruction modifies control flow
 * @param insn Instruction to check
 * @return true if instruction affects control flow
 */
[[nodiscard]] bool isControlFlowInstruction(const DisassembledInstruction& insn);

/**
 * @brief Calculate relative jump/call target
 * @param insn Jump or call instruction
 * @return Target address or 0 if not calculable
 */
[[nodiscard]] Address calculateBranchTarget(const DisassembledInstruction& insn);

} // namespace Sentinel::Cortex

#endif // SENTINEL_CORTEX_DISASSEMBLER_HPP
