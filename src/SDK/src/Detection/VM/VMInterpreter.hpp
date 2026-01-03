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
 */
struct VMConfig {
    uint32_t max_instructions = 100000;     ///< Max opcodes before forced halt
    uint32_t max_stack_depth = 1024;        ///< Stack overflow protection
    uint32_t max_memory_reads = 10000;      ///< Limit external memory access
    uint32_t timeout_ms = 5000;             ///< Execution timeout
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
 * - All exceptions are caught internally (SEH on Windows)
 * - Invalid memory access returns zero, never crashes
 * - Stack overflow returns Error result
 * - Infinite loop protection via instruction counter
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
     * @return Execution result (NEVER throws, NEVER crashes)
     */
    [[nodiscard]] VMOutput execute(const Bytecode& bytecode) noexcept;
    
    /**
     * @brief Register external function callback
     * @param id Function ID (0-255)
     * @param callback Function to call when OP_CALL_EXT is executed
     * @note Callbacks must be noexcept and return within timeout
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
 * @brief Container for compiled VM bytecode
 * 
 * Format: [Header (16 bytes)] [Constant Pool] [Instructions]
 * 
 * Header:
 * - Magic:  0x53454E54 ("SENT")
 * - Version: uint16_t
 * - Flags: uint16_t
 * - Checksum: uint32_t (CRC32 of instructions)
 * - Constant Pool Size: uint32_t
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
     * @return true if checksum matches
     */
    [[nodiscard]] bool verify() const noexcept;
    
    /**
     * @brief Get instruction pointer
     * @return Pointer to first instruction (after header + constants)
     */
    [[nodiscard]] const uint8_t* instructions() const noexcept;
    
    /**
     * @brief Get instruction count
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

private:
    std::vector<uint8_t> m_data;
    size_t m_instruction_offset = 0;
    size_t m_constant_pool_offset = 16;  // After header
    uint16_t m_version = 0;
    uint32_t m_checksum = 0;
};

} // namespace Sentinel::VM
