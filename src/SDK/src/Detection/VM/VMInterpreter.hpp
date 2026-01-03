/**
 * @file VMInterpreter.hpp
 * @brief Sentinel Defensive Virtual Machine Interpreter
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2026
 * 
 * @copyright Copyright (c) 2026 Sentinel Security. All rights reserved.
 * 
 * ARCHITECTURE PHILOSOPHY:
 * ========================
 * This is a DEFENSIVE virtual machine.  It does NOT: 
 * - Modify game memory
 * - Execute arbitrary code
 * - Crash the game process on failure
 * 
 * It DOES:
 * - Execute sandboxed integrity checks
 * - Return detection results safely
 * - Trap all exceptions internally
 */

#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <memory>
#include <functional>
#include <chrono>
#include <string>

namespace Sentinel::VM {

// Forward declarations
class Bytecode;
struct ExecutionContext;

// ============================================================================
// VM Configuration
// ============================================================================

/**
 * @brief VM execution limits for sandboxing
 * 
 * TIMEOUT ENFORCEMENT (STAB-003):
 * The timeout applies to the entire VM execution including external callbacks.
 * External callbacks (registered via registerExternal()) are executed with
 * timeout enforcement - if a callback exceeds the remaining timeout budget,
 * the VM returns VMResult::Timeout immediately.
 */
struct VMConfig {
    uint32_t max_instructions = 100000;     ///< Max opcodes before forced halt
    uint32_t max_stack_depth = 1024;        ///< Stack overflow protection
    uint32_t max_memory_reads = 10000;      ///< Limit external memory access
    
    /// Execution timeout in milliseconds (STAB-003)
    /// Applies to entire execution including external callback time.
    /// External callbacks that exceed remaining timeout trigger VMResult::Timeout.
    uint32_t timeout_ms = 5000;
    
    bool enable_safe_reads = true;          ///< Use VirtualQuery validation
};

// ============================================================================
// VM Execution Result
// ============================================================================

/**
 * @brief Result of VM execution
 */
enum class VMResult : uint8_t {
    Clean = 0,          ///< No violations detected
    Violation = 1,      ///< Integrity violation detected
    Error = 2,          ///< VM error (treat as clean, log internally)
    Timeout = 3,        ///< Execution timeout (treat as clean)
    Halted = 4          ///< Explicit halt opcode
};

/**
 * @brief Detailed execution output
 * 
 * TELEMETRY INTEGRATION (STAB-012):
 * ===================================
 * VMOutput contains critical metrics that should be logged and sent to telemetry
 * for production monitoring. These metrics enable:
 * 
 * 1. **Performance Regression Detection**
 *    - Monitor `elapsed` time: Alert if p95 > 100ms or p99 > 500ms
 *    - Track `instructions_executed`: Detect abnormally complex bytecode
 *    - Correlate with game frame times to ensure VM doesn't degrade performance
 * 
 * 2. **Security Anomaly Detection**
 *    - Monitor `memory_reads_performed`: Alert if exceeding normal patterns (possible attack)
 *    - Track timeout frequency: High timeout rate (>1%) indicates malformed bytecode
 *    - Analyze `result` distribution: Violation spike may indicate cheat tool deployment
 * 
 * 3. **Operational Health**
 *    - Track Error vs Clean ratio: High error rate indicates bytecode compatibility issues
 *    - Monitor timeout rate: Indicates need for bytecode optimization
 *    - Measure execution time variance: High variance indicates VM performance instability
 * 
 * RECOMMENDED TELEMETRY IMPLEMENTATION:
 * - Use PerfTelemetry::RecordOperation() to log execution time
 * - Use TelemetryEmitter to report aggregated metrics (every 100th execution to reduce overhead)
 * - Log format: [VMResult][instructions][memory_reads][elapsed_us][detection_flags]
 * - DO NOT log: error_message (may contain PII), bytecode content, memory addresses
 * - Sampling: Report every Nth execution where N is configurable (default: 100)
 * 
 * METRICS DEFINITIONS:
 * - result: Execution outcome (Clean=0, Violation=1, Error=2, Timeout=3, Halted=4)
 * - detection_flags: Bitmask of detected issues (64-bit, see opcodes for flag meanings)
 * - instructions_executed: Number of opcodes executed (max: config.max_instructions)
 * - memory_reads_performed: Number of safe memory read operations (max: config.max_memory_reads)
 * - elapsed: Wall-clock execution time including callback time (microseconds)
 * - error_message: Human-readable error (debug only, DO NOT send to telemetry)
 * 
 * ALERTING THRESHOLDS (Recommended):
 * - P95 elapsed > 100ms: Performance regression
 * - P99 elapsed > 500ms: Critical performance issue
 * - Timeout rate > 1%: Bytecode needs optimization
 * - Error rate > 5%: Compatibility issues
 * - Memory reads spike >2x baseline: Possible attack pattern
 */
struct VMOutput {
    VMResult result = VMResult::Clean;
    uint64_t detection_flags = 0;           ///< Bitmask of detected issues
    uint32_t instructions_executed = 0;     ///< Performance metric
    uint32_t memory_reads_performed = 0;    ///< Safety metric
    std::chrono::microseconds elapsed{0};   ///< Timing
    std::string error_message;              ///< Debug info (empty in release)
};

// ============================================================================
// VM Interpreter
// ============================================================================

/**
 * @brief Stack-based bytecode interpreter for integrity checks
 * 
 * The VM executes custom bytecode that performs: 
 * - Safe memory reads (validated with VirtualQuery)
 * - CRC32/XXH3 integrity hashes
 * - Pattern matching against known cheat signatures
 * 
 * SAFETY GUARANTEES:
 * ✅ All exceptions caught internally (SEH on Windows, try-catch otherwise)
 * ✅ Invalid memory access returns zero, does not crash process
 * ✅ Stack overflow returns VMResult::Error
 * ✅ Infinite loop protection via instruction counter and timeout
 * ✅ External callbacks have timeout enforcement (STAB-003)
 * ✅ Hash operations have integer overflow protection (STAB-005)
 * ✅ Jump instructions have correct bounds checking (>= not >)
 * 
 * KNOWN LIMITATIONS: 
 * - Callbacks may continue running in background thread after timeout
 * - Memory reads are safe but may return stale data under race
 * - RDTSC timing checks have hypervisor-adjusted thresholds
 * 
 * WHAT IS NOT IMPLEMENTED (DO NOT ASSUME THESE EXIST):
 * - ❌ JIT compilation (bytecode is always interpreted)
 * - ❌ Bytecode compiler/assembler (server-side component, not in this codebase)
 * - ❌ Automatic bytecode obfuscation
 * - ❌ Garbage collection (uses manual memory management)
 * - ❌ Dynamic opcode generation at runtime
 * - ❌ Bytecode versioning/migration (version field exists but not enforced)
 * 
 * TEST COVERAGE (tests/SDK/test_vm.cpp):
 * - 83 total tests across 3 test suites
 * - OpcodeTests: 7 tests (opcode map, metadata)
 * - BytecodeTests: 13 tests (loading, verification, constants)
 * - VMInterpreterTests: 63 tests (execution, safety, callbacks, security)
 * - All core functionality tested and passing
 */
class VMInterpreter {
public:
    /**
     * @brief Construct interpreter with configuration
     * @param config Execution limits and safety settings
     */
    explicit VMInterpreter(const VMConfig& config = VMConfig{});
    
    ~VMInterpreter();
    
    // Non-copyable, movable
    VMInterpreter(const VMInterpreter&) = delete;
    VMInterpreter& operator=(const VMInterpreter&) = delete;
    VMInterpreter(VMInterpreter&&) noexcept;
    VMInterpreter& operator=(VMInterpreter&&) noexcept;
    
    /**
     * @brief Execute bytecode program
     * @param bytecode Compiled bytecode to execute
     * @return Execution result (noexcept, returns Error on exceptions)
     */
    [[nodiscard]] VMOutput execute(const Bytecode& bytecode) noexcept;
    
    /**
     * @brief Register external function callback
     * @param id Function ID (0-255)
     * @param callback Function to call when OP_CALL_EXT is executed
     * 
     * @note CALLBACK TIMEOUT ENFORCEMENT (STAB-003):
     * Callbacks are executed with timeout enforcement to prevent blocking VM execution.
     * - Callback execution time counts against VM timeout budget
     * - If callback exceeds remaining timeout, VM returns VMResult::Timeout
     * - Callbacks are executed asynchronously with std::async
     * - Fast callbacks (< 1ms) have minimal overhead
     * - Blocking callbacks (> timeout) are terminated
     * - Exceptions are caught and return 0 (safe failure)
     * - Re-entrancy is prevented (callbacks cannot call back into VM)
     * 
     * @warning Callbacks must be thread-safe as they run in separate thread
     * @warning Callbacks that block indefinitely will cause timeout but may
     *          continue running in background (defensive behavior)
     */
    void registerExternal(uint8_t id, std::function<uint64_t(uint64_t, uint64_t)> callback);
    
    /**
     * @brief Update opcode map for polymorphism
     * @param new_map 256-byte permutation table
     * @note Called when new bytecode version is received from server
     */
    void setOpcodeMap(const std::array<uint8_t, 256>& new_map);
    
    /**
     * @brief Get current configuration
     */
    const VMConfig& getConfig() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Bytecode Container
// ============================================================================

/**
 * @brief Bytecode header structure for integrity verification
 * 
 * Format: [Header (24 bytes)] [Constant Pool] [Instructions]
 * 
 * Header layout:
 * - magic: 0x53454E54 ("SENT") - uint32_t
 * - version: Bytecode format version - uint16_t
 * - flags: Reserved for future use - uint16_t
 * - xxh3_hash: XXH3 hash of instructions (computed at compile-time) - uint64_t
 * - instruction_count: Number of instruction bytes - uint32_t
 * - constant_count: Number of constants in pool - uint32_t
 */
struct BytecodeHeader {
    uint32_t magic;              ///< 0x53454E54 ('SENT')
    uint16_t version;            ///< Bytecode format version
    uint16_t flags;              ///< Reserved flags
    uint64_t xxh3_hash;          ///< Hash of instructions (computed at compile-time)
    uint32_t instruction_count;  ///< Number of instruction bytes
    uint32_t constant_count;     ///< Number of 8-byte constants
};

static_assert(sizeof(BytecodeHeader) == 24, "BytecodeHeader must be 24 bytes");

/**
 * @brief Container for compiled VM bytecode
 * 
 * Format: [Header (24 bytes)] [Constant Pool] [Instructions]
 * 
 * BYTECODE INTEGRITY:
 * verify() and execute() hash identical byte ranges to prevent: 
 * - Trailing data smuggling (attacker appends bytes after instruction_count)
 * - Hash collision exploitation (different inputs, same hash)
 * 
 * INVARIANT:  hash_input = raw[instruction_offset : instruction_offset + instruction_count]
 * 
 * INTEGRITY VERIFICATION (STAB-001 - Fixed 2026-01-03):
 * - verify() reads instruction_count from header (offset 16)
 * - Hashes exactly instruction_count bytes (not all remaining data)
 * - REJECTS bytecode with trailing bytes beyond instruction_count
 * - Both verify() and execute() hash identical byte ranges
 * 
 * IMPLEMENTATION NOTES:
 * - load() validates header structure but does NOT verify hash
 * - verify() must be called separately to check integrity
 * - instructionCount() returns header value (not computed from buffer size)
 * - Bytecode with size mismatch is rejected for defense-in-depth
 * 
 * WHAT IS NOT IMPLEMENTED:
 * - ❌ Automatic hash computation during load (must be pre-computed)
 * - ❌ Signature verification (only hash-based integrity)
 * - ❌ Encryption/decryption of bytecode
 * - ❌ Version migration or compatibility checks
 */
class Bytecode {
public: 
    /**
     * @brief Load bytecode from buffer
     * @param data Raw bytecode bytes
     * @return true if valid bytecode, false if corrupted
     */
    [[nodiscard]] bool load(const std::vector<uint8_t>& data);
    
    /**
     * @brief Verify bytecode integrity
     * 
     * STAB-001 (Fixed 2026-01-03): Hash verification consistency
     * - Reads instruction_count from header (offset 16)
     * - Computes XXH3 hash over exactly instruction_count bytes
     * - REJECTS bytecode where actual_size != instruction_count (defense-in-depth)
     * - Matches hash computation in VMInterpreter::execute()
     * 
     * @return true if hash matches AND no trailing bytes, false otherwise
     * 
     * @note This method does NOT throw exceptions (noexcept)
     * @note Must be called after load() - does not load bytecode itself
     * @note Rejection of trailing bytes prevents accepting malformed bytecode
     */
    [[nodiscard]] bool verify() const noexcept;
    
    /**
     * @brief Get instruction pointer
     * @return Pointer to first instruction (after header + constants)
     */
    [[nodiscard]] const uint8_t* instructions() const noexcept;
    
    /**
     * @brief Get instruction count from header
     * 
     * STAB-001 (Fixed 2026-01-03): Returns header value, not computed size
     * - Returns instruction_count field from BytecodeHeader (offset 16)
     * - Does NOT compute from m_data.size() - m_instruction_offset
     * - This matches the value used by verify() and execute()
     * 
     * @return Number of instruction bytes from header, or 0 if invalid
     */
    [[nodiscard]] size_t instructionCount() const noexcept;
    
    /**
     * @brief Get constant from pool
     * @param index Constant index
     * @return Constant value or 0 if out of bounds
     */
    [[nodiscard]] uint64_t getConstant(uint16_t index) const noexcept;
    
    /**
     * @brief Get bytecode version
     */
    [[nodiscard]] uint16_t version() const noexcept;
    
    /**
     * @brief Get raw bytecode data pointer
     * @return Pointer to raw bytecode buffer
     */
    [[nodiscard]] const uint8_t* rawData() const noexcept;
    
    /**
     * @brief Get raw bytecode data size
     * @return Size of raw bytecode buffer in bytes
     */
    [[nodiscard]] size_t rawSize() const noexcept;

private:
    std::vector<uint8_t> m_data;
    size_t m_instruction_offset = 0;
    size_t m_constant_pool_offset = 24;  // After header (BytecodeHeader is 24 bytes)
    uint16_t m_version = 0;
    uint64_t m_xxh3_hash = 0;  // Changed from uint32_t checksum to uint64_t XXH3 hash
};

} // namespace Sentinel::VM
