/**
 * @file VMDeobfuscator.hpp
 * @brief VM Deobfuscation Engine for protected binaries
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This module provides advanced VM deobfuscation capabilities for analyzing
 * binaries protected by virtualization obfuscators like VMProtect, Themida,
 * Code Virtualizer, and custom VM protectors.
 * 
 * The engine combines:
 * - Dynamic instrumentation (Intel PIN / DynamoRIO)
 * - Symbolic execution (Triton / Z3)
 * - SSA lifting and IR analysis
 * - Pattern matching and heuristics
 * - AI-assisted opcode classification
 * 
 * NOTE: Some capabilities described here represent idealized/theoretical
 * functionality that goes beyond current real-world feasibility.
 */

#pragma once

#ifndef SENTINEL_CORTEX_VM_DEOBFUSCATOR_HPP
#define SENTINEL_CORTEX_VM_DEOBFUSCATOR_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <variant>

namespace Sentinel::Cortex::VMDeobfuscator {

// ============================================================================
// VM Protector Detection
// ============================================================================

/**
 * @brief Known VM protector types
 */
enum class VMProtectorType {
    Unknown,
    VMProtect,          ///< VMProtect by vmpsoft
    Themida,            ///< Themida/WinLicense by Oreans
    CodeVirtualizer,    ///< Code Virtualizer by Oreans
    Enigma,             ///< Enigma Protector
    Obsidium,           ///< Obsidium
    ASProtect,          ///< ASProtect
    Safengine,          ///< Safengine
    Custom              ///< Custom/Unknown VM
};

/**
 * @brief Detection confidence level
 */
enum class ConfidenceLevel {
    None = 0,
    Low = 25,
    Medium = 50,
    High = 75,
    Certain = 100
};

/**
 * @brief VM protector detection result
 */
struct VMDetectionResult {
    VMProtectorType type = VMProtectorType::Unknown;
    std::string version;                ///< Detected version (if known)
    ConfidenceLevel confidence = ConfidenceLevel::None;
    std::vector<Address> vmEntryPoints; ///< Detected VM entry points
    std::vector<Address> vmHandlers;    ///< Detected VM handler addresses
    Address dispatcherAddress = 0;      ///< VM dispatcher/interpreter address
    std::string notes;                  ///< Additional detection notes
};

// ============================================================================
// VM Instruction Representation
// ============================================================================

/**
 * @brief Virtual opcode type classification
 */
enum class VirtualOpcodeType {
    Unknown,
    // Stack operations
    VPush,              ///< Push value onto VM stack
    VPop,               ///< Pop value from VM stack
    VDup,               ///< Duplicate top of stack
    // Arithmetic
    VAdd,               ///< Addition
    VSub,               ///< Subtraction
    VMul,               ///< Multiplication
    VDiv,               ///< Division
    VMod,               ///< Modulo
    VNeg,               ///< Negation
    // Bitwise
    VAnd,               ///< Bitwise AND
    VOr,                ///< Bitwise OR
    VXor,               ///< Bitwise XOR
    VNot,               ///< Bitwise NOT
    VShl,               ///< Shift left
    VShr,               ///< Shift right
    VRor,               ///< Rotate right
    VRol,               ///< Rotate left
    // Memory
    VLoad,              ///< Load from memory
    VStore,             ///< Store to memory
    // Control flow
    VJmp,               ///< Unconditional jump
    VJcc,               ///< Conditional jump
    VCall,              ///< Call (VM or native)
    VRet,               ///< Return
    // Register operations
    VGetReg,            ///< Get native register value
    VSetReg,            ///< Set native register value
    // Native
    VNative,            ///< Execute native instruction
    VNop,               ///< No operation
    // Special
    VEnter,             ///< Enter VM context
    VExit,              ///< Exit VM context
    VChecksum,          ///< Integrity check
    VDecrypt            ///< Decrypt data/code
};

/**
 * @brief Represents a decoded virtual instruction
 */
struct VirtualInstruction {
    Address vmAddress;              ///< Address in VM bytecode
    Address nativeAddress;          ///< Original native address (if known)
    VirtualOpcodeType opcode;       ///< Decoded opcode type
    uint64_t rawOpcode;             ///< Raw opcode value
    std::vector<uint64_t> operands; ///< Operand values
    size_t size;                    ///< Size in VM bytecode
    std::string mnemonic;           ///< Human-readable mnemonic
    std::string comment;            ///< Analysis notes
    
    /// Convert to string representation
    [[nodiscard]] std::string toString() const;
};

/**
 * @brief Basic block in the virtual control flow graph
 */
struct VirtualBasicBlock {
    Address startAddress;           ///< Block start address
    Address endAddress;             ///< Block end address (exclusive)
    std::vector<VirtualInstruction> instructions;
    std::vector<Address> predecessors;  ///< Incoming edges
    std::vector<Address> successors;    ///< Outgoing edges
    bool isEntry = false;           ///< Is VM entry point
    bool isExit = false;            ///< Exits to native code
};

/**
 * @brief Control flow graph for virtualized code
 */
struct VirtualCFG {
    std::map<Address, VirtualBasicBlock> blocks;
    Address entryPoint = 0;
    std::vector<Address> exitPoints;
    
    /// Get block containing address
    [[nodiscard]] const VirtualBasicBlock* getBlockAt(Address addr) const;
    
    /// Get all blocks in order
    [[nodiscard]] std::vector<const VirtualBasicBlock*> getBlocksInOrder() const;
};

// ============================================================================
// Symbolic Execution Types
// ============================================================================

/**
 * @brief Symbolic value representation
 */
struct SymbolicValue {
    std::string expression;         ///< Symbolic expression
    std::optional<uint64_t> concrete; ///< Concrete value if known
    size_t bitWidth = 64;           ///< Value width in bits
    bool isTainted = false;         ///< From user input
    
    /// Check if value is concrete
    [[nodiscard]] bool isConcrete() const { return concrete.has_value(); }
    
    /// Get concrete value or default
    [[nodiscard]] uint64_t getConcreteOr(uint64_t defaultVal) const {
        return concrete.value_or(defaultVal);
    }
};

/**
 * @brief Symbolic execution state
 */
struct SymbolicState {
    std::map<std::string, SymbolicValue> registers;
    std::map<Address, SymbolicValue> memory;
    std::vector<std::string> pathConstraints;
    Address pc = 0;                 ///< Program counter
    size_t depth = 0;               ///< Execution depth
};

// ============================================================================
// Lifted IR Types
// ============================================================================

/**
 * @brief SSA value type
 */
enum class SSAValueType {
    Undefined,
    Constant,
    Register,
    Memory,
    Temporary,
    Parameter,
    Return
};

/**
 * @brief SSA instruction opcode
 */
enum class SSAOpcode {
    // Constants
    Const,
    // Arithmetic
    Add, Sub, Mul, UDiv, SDiv, URem, SRem,
    // Bitwise
    And, Or, Xor, Not, Shl, LShr, AShr, Rotl, Rotr,
    // Comparison
    Eq, Ne, Ult, Ule, Ugt, Uge, Slt, Sle, Sgt, Sge,
    // Memory
    Load, Store,
    // Control flow
    Br, CondBr, Call, Ret, Unreachable,
    // Type operations
    ZExt, SExt, Trunc, Bitcast,
    // Special
    Phi, Select, Extract, Insert
};

/**
 * @brief SSA value
 */
struct SSAValue {
    SSAValueType type = SSAValueType::Undefined;
    uint64_t id = 0;                ///< Unique value ID
    size_t bitWidth = 64;           ///< Bit width
    std::optional<uint64_t> constantValue;
    std::string name;               ///< Optional name
    
    /// Create constant value
    static SSAValue constant(uint64_t val, size_t bits = 64);
    
    /// Create temporary value
    static SSAValue temp(uint64_t id, size_t bits = 64);
};

/**
 * @brief SSA instruction
 */
struct SSAInstruction {
    SSAOpcode opcode;
    SSAValue result;                ///< Destination (if any)
    std::vector<SSAValue> operands; ///< Source operands
    Address originalAddress = 0;    ///< Original VM address
    std::string comment;
    
    /// Convert to string representation
    [[nodiscard]] std::string toString() const;
};

/**
 * @brief SSA basic block
 */
struct SSABasicBlock {
    std::string label;              ///< Block label
    std::vector<SSAInstruction> instructions;
    std::vector<std::string> predecessors;
    std::vector<std::string> successors;
};

/**
 * @brief SSA function
 */
struct SSAFunction {
    std::string name;
    Address originalAddress = 0;
    std::vector<SSAValue> parameters;
    SSAValue returnType;
    std::vector<SSABasicBlock> blocks;
    
    /// Get entry block
    [[nodiscard]] const SSABasicBlock* getEntryBlock() const;
    
    /// Emit as pseudo-C code
    [[nodiscard]] std::string toPseudoC() const;
    
    /// Emit as LLVM IR-like text
    [[nodiscard]] std::string toLLVMIR() const;
};

// ============================================================================
// Trace and Logging Types
// ============================================================================

/**
 * @brief Execution trace entry
 */
struct TraceEntry {
    Address address;                ///< Executed address
    ByteBuffer instruction;         ///< Instruction bytes
    std::string disassembly;        ///< Disassembled text
    std::map<std::string, uint64_t> regsBefore;
    std::map<std::string, uint64_t> regsAfter;
    std::vector<std::pair<Address, uint64_t>> memReads;
    std::vector<std::pair<Address, uint64_t>> memWrites;
    uint64_t timestamp;             ///< Timestamp counter
};

/**
 * @brief Execution trace
 */
struct ExecutionTrace {
    std::vector<TraceEntry> entries;
    Address startAddress = 0;
    Address endAddress = 0;
    size_t instructionCount = 0;
    
    /// Filter trace to specific address range
    [[nodiscard]] ExecutionTrace filterRange(Address start, Address end) const;
    
    /// Get all unique addresses executed
    [[nodiscard]] std::set<Address> getUniqueAddresses() const;
};

// ============================================================================
// Deobfuscation Results
// ============================================================================

/**
 * @brief Deobfuscation analysis result
 */
struct DeobfuscationResult {
    VMDetectionResult detection;
    VirtualCFG virtualCFG;
    std::vector<SSAFunction> liftedFunctions;
    ExecutionTrace trace;
    std::string pseudoCode;         ///< Generated pseudo-C
    std::string analysisLog;        ///< Detailed analysis log
    
    // Statistics
    size_t virtualInstructionCount = 0;
    size_t handlerCount = 0;
    size_t basicBlockCount = 0;
    double analysisTimeSeconds = 0.0;
    
    /// Export results to JSON
    [[nodiscard]] std::string toJSON() const;
};

// ============================================================================
// Deobfuscator Configuration
// ============================================================================

/**
 * @brief Analysis options
 */
struct DeobfuscatorOptions {
    /// Dynamic analysis options
    bool enableDynamicTracing = true;
    size_t maxTraceInstructions = 1000000;
    Milliseconds traceTimeout{60000};
    
    /// Symbolic execution options
    bool enableSymbolicExecution = true;
    size_t maxSymbolicDepth = 100;
    size_t maxPathsToExplore = 1000;
    
    /// SSA lifting options
    bool enableSSALifting = true;
    bool optimizeSSA = true;
    bool generatePseudoC = true;
    
    /// Pattern matching options
    bool enablePatternMatching = true;
    bool useAIClassification = false; ///< Use AI for opcode classification
    
    /// Anti-analysis bypass
    bool bypassTimingChecks = true;
    bool bypassDebuggerChecks = true;
    bool bypassIntegrityChecks = true;
    
    /// Output options
    bool verboseLogging = false;
    std::string outputDirectory;
    
    /// Progress callback
    std::function<void(const std::string&, int)> progressCallback;
};

// ============================================================================
// VM Deobfuscator Engine
// ============================================================================

/**
 * @brief Main VM Deobfuscation Engine
 * 
 * This engine combines multiple analysis techniques to reverse
 * virtualization-based obfuscation:
 * 
 * 1. **Detection Phase**
 *    - Identify the VM protector type
 *    - Locate VM entry points and handlers
 * 
 * 2. **Dynamic Tracing Phase**
 *    - Execute code under instrumentation
 *    - Record all executed instructions
 *    - Capture register and memory state
 * 
 * 3. **Handler Analysis Phase**
 *    - Identify VM opcode handlers
 *    - Map raw opcodes to semantic operations
 * 
 * 4. **Symbolic Execution Phase**
 *    - Build symbolic expressions
 *    - Resolve control flow
 * 
 * 5. **SSA Lifting Phase**
 *    - Convert to SSA form
 *    - Perform optimizations
 *    - Generate pseudo-C output
 * 
 * @example
 * ```cpp
 * VMDeobfuscatorEngine engine;
 * 
 * DeobfuscatorOptions options;
 * options.enableDynamicTracing = true;
 * options.generatePseudoC = true;
 * 
 * auto result = engine.analyze(binaryPath, vmEntryPoint, options);
 * if (result.isSuccess()) {
 *     std::cout << result.value().pseudoCode << std::endl;
 * }
 * ```
 */
class VMDeobfuscatorEngine {
public:
    VMDeobfuscatorEngine();
    ~VMDeobfuscatorEngine();
    
    // Non-copyable
    VMDeobfuscatorEngine(const VMDeobfuscatorEngine&) = delete;
    VMDeobfuscatorEngine& operator=(const VMDeobfuscatorEngine&) = delete;
    
    // Movable
    VMDeobfuscatorEngine(VMDeobfuscatorEngine&&) noexcept;
    VMDeobfuscatorEngine& operator=(VMDeobfuscatorEngine&&) noexcept;
    
    // ========================================================================
    // Main Analysis Functions
    // ========================================================================
    
    /**
     * @brief Perform full deobfuscation analysis
     * @param binaryPath Path to the protected binary
     * @param vmEntryPoint VM entry point address (0 = auto-detect)
     * @param options Analysis options
     * @return Deobfuscation result or error
     */
    [[nodiscard]] Result<DeobfuscationResult> analyze(
        const std::string& binaryPath,
        Address vmEntryPoint = 0,
        const DeobfuscatorOptions& options = {}
    );
    
    /**
     * @brief Analyze in-memory code
     * @param code Code buffer
     * @param baseAddress Base address of the code
     * @param vmEntryPoint VM entry point address
     * @param options Analysis options
     * @return Deobfuscation result or error
     */
    [[nodiscard]] Result<DeobfuscationResult> analyzeMemory(
        ByteSpan code,
        Address baseAddress,
        Address vmEntryPoint,
        const DeobfuscatorOptions& options = {}
    );
    
    // ========================================================================
    // Detection Functions
    // ========================================================================
    
    /**
     * @brief Detect VM protector type
     * @param binaryPath Path to binary
     * @return Detection result
     */
    [[nodiscard]] Result<VMDetectionResult> detectProtector(
        const std::string& binaryPath
    );
    
    /**
     * @brief Detect VM protector from code buffer
     * @param code Code buffer
     * @param baseAddress Base address
     * @return Detection result
     */
    [[nodiscard]] Result<VMDetectionResult> detectProtectorInMemory(
        ByteSpan code,
        Address baseAddress
    );
    
    /**
     * @brief Find VM entry points in binary
     * @param binaryPath Path to binary
     * @return Vector of entry point addresses
     */
    [[nodiscard]] Result<std::vector<Address>> findVMEntryPoints(
        const std::string& binaryPath
    );
    
    // ========================================================================
    // Tracing Functions
    // ========================================================================
    
    /**
     * @brief Execute and trace virtualized code
     * @param binaryPath Path to binary
     * @param entryPoint Entry point address
     * @param options Tracing options
     * @return Execution trace or error
     */
    [[nodiscard]] Result<ExecutionTrace> traceExecution(
        const std::string& binaryPath,
        Address entryPoint,
        const DeobfuscatorOptions& options = {}
    );
    
    // ========================================================================
    // Analysis Functions
    // ========================================================================
    
    /**
     * @brief Analyze VM handlers
     * @param trace Execution trace to analyze
     * @return Map of handler addresses to opcodes
     */
    [[nodiscard]] Result<std::map<Address, VirtualOpcodeType>> analyzeHandlers(
        const ExecutionTrace& trace
    );
    
    /**
     * @brief Build virtual CFG from trace
     * @param trace Execution trace
     * @param handlers Handler mapping
     * @return Virtual control flow graph
     */
    [[nodiscard]] Result<VirtualCFG> buildVirtualCFG(
        const ExecutionTrace& trace,
        const std::map<Address, VirtualOpcodeType>& handlers
    );
    
    /**
     * @brief Lift to SSA form
     * @param cfg Virtual CFG
     * @param options Lifting options
     * @return SSA function
     */
    [[nodiscard]] Result<SSAFunction> liftToSSA(
        const VirtualCFG& cfg,
        const DeobfuscatorOptions& options = {}
    );
    
    /**
     * @brief Generate pseudo-C code
     * @param ssaFunc SSA function
     * @return Pseudo-C code string
     */
    [[nodiscard]] Result<std::string> generatePseudoC(
        const SSAFunction& ssaFunc
    );
    
    // ========================================================================
    // Utility Functions
    // ========================================================================
    
    /**
     * @brief Check if engine is ready
     * @return true if initialized
     */
    [[nodiscard]] bool isReady() const noexcept;
    
    /**
     * @brief Get last error message
     * @return Error message string
     */
    [[nodiscard]] std::string getLastError() const;
    
    /**
     * @brief Cancel ongoing analysis
     */
    void cancelAnalysis();
    
    /**
     * @brief Get analysis progress
     * @return Progress percentage (0-100)
     */
    [[nodiscard]] int getProgress() const noexcept;
    
    /**
     * @brief Get supported protector types
     * @return Vector of supported protector type names
     */
    [[nodiscard]] static std::vector<std::string> getSupportedProtectors();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Handler Database
// ============================================================================

/**
 * @brief Database of known VM handler patterns
 */
class HandlerDatabase {
public:
    HandlerDatabase();
    ~HandlerDatabase();
    
    /**
     * @brief Load handler patterns from file
     * @param path Path to pattern file
     * @return true if loaded successfully
     */
    bool load(const std::string& path);
    
    /**
     * @brief Save handler patterns to file
     * @param path Path to save to
     * @return true if saved successfully
     */
    bool save(const std::string& path);
    
    /**
     * @brief Match handler against known patterns
     * @param handlerCode Handler code bytes
     * @return Matched opcode type and confidence
     */
    [[nodiscard]] std::pair<VirtualOpcodeType, ConfidenceLevel> match(
        ByteSpan handlerCode
    ) const;
    
    /**
     * @brief Add new pattern to database
     * @param opcodeType Opcode type
     * @param pattern Pattern bytes
     * @param mask Pattern mask (? = wildcard)
     */
    void addPattern(
        VirtualOpcodeType opcodeType,
        ByteSpan pattern,
        const std::string& mask
    );
    
    /**
     * @brief Get pattern count
     * @return Number of patterns in database
     */
    [[nodiscard]] size_t patternCount() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Convert opcode type to string
 * @param opcode Opcode type
 * @return String representation
 */
[[nodiscard]] std::string opcodeTypeToString(VirtualOpcodeType opcode);

/**
 * @brief Convert protector type to string
 * @param type Protector type
 * @return String representation
 */
[[nodiscard]] std::string protectorTypeToString(VMProtectorType type);

/**
 * @brief Convert confidence level to string
 * @param level Confidence level
 * @return String representation
 */
[[nodiscard]] std::string confidenceToString(ConfidenceLevel level);

} // namespace Sentinel::Cortex::VMDeobfuscator

#endif // SENTINEL_CORTEX_VM_DEOBFUSCATOR_HPP
