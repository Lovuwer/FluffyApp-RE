/**
 * @file Opcodes.hpp
 * @brief Sentinel VM Opcode Definitions
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2026
 * 
 * @copyright Copyright (c) 2026 Sentinel Security. All rights reserved. 
 * 
 * OPCODE DESIGN:
 * ==============
 * Each opcode is 1 byte.  Operands follow inline. 
 * Polymorphism:  Opcode values are remapped via build-time seed.
 * 
 * STACK MODEL:
 * - 64-bit values on stack
 * - Stack grows upward (push = sp++)
 * - Operations consume and produce stack values
 */

#pragma once

#include <cstdint>
#include <array>

namespace Sentinel::VM {

// ============================================================================
// Opcode Enumeration (Canonical Values)
// ============================================================================

/**
 * @brief VM opcodes (canonical, pre-polymorphism)
 * 
 * These are the "logical" opcode values.  Actual bytecode uses
 * permuted values based on build seed.
 */
enum class Opcode : uint8_t {
    // ========== Control Flow ==========
    NOP         = 0x00,     ///< No operation
    HALT        = 0x01,     ///< Stop execution (result = Clean)
    HALT_FAIL   = 0x02,     ///< Stop execution (result = Violation)
    
    // ========== Stack Operations ==========
    PUSH_IMM    = 0x10,     ///< Push 8-byte immediate [imm64]
    PUSH_CONST  = 0x11,     ///< Push from constant pool [idx16]
    POP         = 0x12,     ///< Discard top of stack
    DUP         = 0x13,     ///< Duplicate top of stack
    SWAP        = 0x14,     ///< Swap top two values
    
    // ========== Arithmetic ==========
    ADD         = 0x20,     ///< a + b
    SUB         = 0x21,     ///< a - b
    MUL         = 0x22,     ///< a * b
    XOR         = 0x23,     ///< a ^ b
    AND         = 0x24,     ///< a & b
    OR          = 0x25,     ///< a | b
    SHL         = 0x26,     ///< a << (b & 63)
    SHR         = 0x27,     ///< a >> (b & 63)
    ROL         = 0x28,     ///< Rotate left
    ROR         = 0x29,     ///< Rotate right
    
    // ========== Comparison ==========
    CMP_EQ      = 0x30,     ///< a == b → 1 or 0
    CMP_NE      = 0x31,     ///< a != b → 1 or 0
    CMP_LT      = 0x32,     ///< a < b (unsigned)
    CMP_GT      = 0x33,     ///< a > b (unsigned)
    
    // ========== Branching ==========
    JMP         = 0x40,     ///< Unconditional jump [offset16]
    JMP_Z       = 0x41,     ///< Jump if top == 0 [offset16]
    JMP_NZ      = 0x42,     ///< Jump if top != 0 [offset16]
    
    // ========== Memory (SAFE) ==========
    /**
     * @brief Safe memory read with VirtualQuery validation
     * 
     * Stack: [address] → [value]
     * 
     * Behavior:
     * 1. Pop address from stack
     * 2. Call VirtualQuery to validate: 
     *    - Page is committed (MEM_COMMIT)
     *    - Page is readable (PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, etc.)
     * 3. If invalid:  push 0, set error flag, continue
     * 4. If valid: read 8 bytes, push to stack
     * 
     * NEVER crashes on bad address. 
     */
    READ_SAFE_8  = 0x50,    ///< Safe 8-byte read
    READ_SAFE_4  = 0x51,    ///< Safe 4-byte read (zero-extended)
    READ_SAFE_2  = 0x52,    ///< Safe 2-byte read (zero-extended)
    READ_SAFE_1  = 0x53,    ///< Safe 1-byte read (zero-extended)
    
    // ========== Integrity ==========
    /**
     * @brief CRC32 hash of memory range
     * 
     * Stack: [address, size] → [crc32]
     * 
     * Uses safe reads internally.  Invalid pages hash as 0.
     */
    HASH_CRC32  = 0x60,
    
    /**
     * @brief XXH3 hash of memory range (faster, 64-bit)
     * 
     * Stack: [address, size] → [xxh3_hash]
     */
    HASH_XXH3   = 0x61,
    
    /**
     * @brief Compare hash against expected value
     * 
     * Stack: [computed_hash, expected_hash] → [match (1/0)]
     * 
     * If mismatch, sets detection flag.
     */
    CHECK_HASH  = 0x62,
    
    // ========== Detection Flags ==========
    /**
     * @brief Set detection flag bit
     * 
     * Stack: [flag_bit] → []
     * 
     * flag_bit is 0-63, sets that bit in VMOutput::detection_flags
     */
    SET_FLAG    = 0x70,
    
    /**
     * @brief Get current detection flags
     * 
     * Stack: [] → [flags64]
     */
    GET_FLAGS   = 0x71,
    
    // ========== External Calls ==========
    /**
     * @brief Call registered external function
     * 
     * [func_id8] operand
     * Stack: [arg1, arg2] → [result]
     * 
     * Used for: 
     * - Querying game state
     * - Checking driver communication
     */
    CALL_EXT    = 0x80,
    
    // ========== Anti-Analysis ==========
    /**
     * @brief Timing check opcode
     * 
     * Stack: [] → [rdtsc_low32]
     * 
     * Used to detect single-stepping (massive timing gap between instructions)
     */
    RDTSC_LOW   = 0x90,
    
    /**
     * @brief Opaque predicate (always true/false, but obscured)
     * 
     * Stack: [] → [result]
     * 
     * Result is compile-time constant but appears data-dependent
     */
    OPAQUE_TRUE = 0x91,
    OPAQUE_FALSE = 0x92,
    
    /**
     * @brief Exception handler integrity test (Anti-VEH Canary)
     * 
     * Stack: [] → [result]
     * 
     * Behavior:
     * 1. Registers temporary VEH handler with priority 1 (first)
     * 2. Creates guard page and triggers controlled access violation
     * 3. VEH handler sets thread-local confirmation flag
     * 4. SEH handler verifies VEH was called (checks flag)
     * 5. If flag not set, another VEH handler swallowed our exception
     * 
     * Result: 1 = integrity OK, 0 = VEH hijacking detected (sets flag bit 8)
     */
    OP_TEST_EXCEPTION = 0xA0,
    
    /**
     * @brief RDTSC timing differential check (Anti-Emulation)
     * 
     * Stack: [] → [result]
     * 
     * Behavior: 
     * 1. Execute RDTSC twice with known-cost operations between
     * 2. Measure delta in CPU cycles
     * 3. Check for emulation signatures: 
     *    a. Delta too low (emulator not simulating real timing)
     *    b. Delta too consistent (no natural variance)
     *    c. Delta unrealistically high (single-stepping)
     * 4. Performs CPUID serialization to prevent out-of-order issues
     * 
     * Result: 1 = timing OK, 0 = emulation/debugging detected (sets flag bit 9)
     * 
     * Anti-Analysis: Uses CPUID leaf 0 (which must be emulated) to force
     * emulator to handle serializing instruction, exposing timing gaps. 
     */
    OP_RDTSC_DIFF = 0xA1,
    
    /**
     * @brief Read Thread Environment Block base address
     * 
     * Stack:  [] → [teb_address]
     * 
     * Windows x64: Returns GS:[0x30] (self-pointer to TEB)
     * Windows x86: Returns FS:[0x18] (self-pointer to TEB)
     * Linux: Returns 0 (placeholder)
     */
    OP_READ_TEB = 0xA2,

    /**
     * @brief Read Process Environment Block base address  
     * 
     * Stack: [] → [peb_address]
     * 
     * Windows x64: Returns GS:[0x60] (TEB.ProcessEnvironmentBlock)
     * Windows x86: Returns FS:[0x30] (TEB.ProcessEnvironmentBlock)
     * Linux: Returns 0 (placeholder)
     */
    OP_READ_PEB = 0xA3,
    
    // Reserved:  0xF0-0xFF for future/custom use
};

// ============================================================================
// Opcode Metadata
// ============================================================================

/**
 * @brief Get number of stack values consumed by opcode
 */
constexpr uint8_t opcodeStackConsume(Opcode op) noexcept {
    switch (op) {
        case Opcode::POP:
        case Opcode::JMP_Z:
        case Opcode::JMP_NZ: 
        case Opcode::READ_SAFE_8:
        case Opcode::READ_SAFE_4:
        case Opcode::READ_SAFE_2:
        case Opcode::READ_SAFE_1:
        case Opcode::SET_FLAG:
            return 1;
        
        case Opcode::ADD:
        case Opcode::SUB:
        case Opcode::MUL:
        case Opcode::XOR: 
        case Opcode::AND:
        case Opcode::OR:
        case Opcode::SHL:
        case Opcode::SHR: 
        case Opcode::ROL:
        case Opcode::ROR:
        case Opcode::CMP_EQ:
        case Opcode::CMP_NE: 
        case Opcode::CMP_LT:
        case Opcode::CMP_GT:
        case Opcode::CHECK_HASH:
        case Opcode::HASH_CRC32:
        case Opcode::HASH_XXH3:
        case Opcode::CALL_EXT:
            return 2;
        
        default:
            return 0;
    }
}

/**
 * @brief Get number of stack values produced by opcode
 */
constexpr uint8_t opcodeStackProduce(Opcode op) noexcept {
    switch (op) {
        case Opcode::POP:
        case Opcode::HALT:
        case Opcode::HALT_FAIL:
        case Opcode::NOP:
        case Opcode::JMP: 
        case Opcode::JMP_Z:
        case Opcode::JMP_NZ:
        case Opcode::SET_FLAG:
            return 0;
        
        case Opcode::DUP:
            return 2;  // Consumes 1, produces 2 (net +1)
        
        default:
            return 1;
    }
}

/**
 * @brief Get operand size in bytes for opcode
 */
constexpr uint8_t opcodeOperandSize(Opcode op) noexcept {
    switch (op) {
        case Opcode::PUSH_IMM:
            return 8;  // 64-bit immediate
        
        case Opcode::PUSH_CONST:
        case Opcode::JMP:
        case Opcode::JMP_Z:
        case Opcode::JMP_NZ:
            return 2;  // 16-bit index/offset
        
        case Opcode::CALL_EXT:
            return 1;  // 8-bit function ID
        
        default: 
            return 0;
    }
}

// ============================================================================
// Polymorphic Opcode Mapping
// ============================================================================

/**
 * @brief Generate polymorphic opcode map from seed
 * 
 * @param seed Build seed (from server or compile-time)
 * @return 256-byte permutation table
 * 
 * Algorithm:
 * 1. Initialize with identity map [0, 1, 2, ..., 255]
 * 2. Fisher-Yates shuffle seeded with XXH3(seed)
 * 
 * Result: opcode_map[canonical] = polymorphic
 */
std::array<uint8_t, 256> generateOpcodeMap(uint64_t seed);

/**
 * @brief Generate inverse opcode map for decoding
 * 
 * @param forward_map Result of generateOpcodeMap
 * @return Inverse permutation:  inverse[polymorphic] = canonical
 */
std::array<uint8_t, 256> invertOpcodeMap(const std::array<uint8_t, 256>& forward_map);

} // namespace Sentinel::VM
