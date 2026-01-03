/**
 * @file VMInterpreter.cpp
 * @brief Sentinel VM Interpreter Implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2026
 * 
 * @copyright Copyright (c) 2026 Sentinel Security. All rights reserved.
 */

#include "VMInterpreter.hpp"
#include "Opcodes.hpp"
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <stdexcept>
#include <future>
#include <atomic>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include <immintrin.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#endif

namespace Sentinel::VM {

namespace {
    // Read little-endian values
    template<typename T>
    T readLE(const uint8_t* data) noexcept {
        T value = 0;
        for (size_t i = 0; i < sizeof(T); ++i) {
            value |= static_cast<T>(data[i]) << (i * 8);
        }
        return value;
    }
    
    // Simple CRC32 for hash operations
    uint32_t crc32_hash(const uint8_t* data, size_t length) noexcept {
        static constexpr uint32_t polynomial = 0xEDB88320;
        
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < length; ++i) {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
            }
        }
        return ~crc;
    }
    
    // Simple XXH3-like hash for hash operations
    uint64_t xxh3_hash(const uint8_t* data, size_t length) noexcept {
        constexpr uint64_t PRIME64_1 = 0x9E3779B185EBCA87ULL;
        constexpr uint64_t PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
        constexpr uint64_t PRIME64_3 = 0x165667B19E3779F9ULL;
        constexpr uint64_t PRIME64_4 = 0x85EBCA77C2B2AE63ULL;
        constexpr uint64_t PRIME64_5 = 0x27D4EB2F165667C5ULL;
        
        uint64_t h64 = PRIME64_5 + length;
        
        // Process 8-byte chunks
        size_t i = 0;
        while (i + 8 <= length) {
            uint64_t k1 = readLE<uint64_t>(data + i);
            k1 *= PRIME64_2;
            k1 = (k1 << 31) | (k1 >> 33);
            k1 *= PRIME64_1;
            h64 ^= k1;
            h64 = ((h64 << 27) | (h64 >> 37)) * PRIME64_1 + PRIME64_4;
            i += 8;
        }
        
        // Process remaining bytes
        while (i < length) {
            h64 ^= static_cast<uint64_t>(data[i]) * PRIME64_5;
            h64 = ((h64 << 11) | (h64 >> 53)) * PRIME64_1;
            ++i;
        }
        
        // Avalanche
        h64 ^= h64 >> 33;
        h64 *= PRIME64_2;
        h64 ^= h64 >> 29;
        h64 *= PRIME64_3;
        h64 ^= h64 >> 32;
        
        return h64;
    }
    
    // Rotate left
    inline uint64_t rotl64(uint64_t value, int shift) noexcept {
        shift &= 63;
        return (value << shift) | (value >> (64 - shift));
    }
    
    // Rotate right
    inline uint64_t rotr64(uint64_t value, int shift) noexcept {
        shift &= 63;
        return (value >> shift) | (value << (64 - shift));
    }
    
    // Safe memory read with validation
    bool isMemoryReadable(const void* address, size_t size) noexcept {
#ifdef _WIN32
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
            return false;
        }
        
        // Check if memory is committed
        if (mbi.State != MEM_COMMIT) {
            return false;
        }
        
        // Check if memory is readable
        const DWORD readable_flags = PAGE_READONLY | PAGE_READWRITE | 
                                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                    PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
        if ((mbi.Protect & readable_flags) == 0) {
            return false;
        }
        
        // Check if entire range is within the region
        uintptr_t start = reinterpret_cast<uintptr_t>(address);
        uintptr_t end = start + size;
        uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        
        return end <= region_end;
#else
        // On Linux, attempt to use mincore or just try-catch approach
        // For simplicity, we'll use a basic check
        (void)address;  // Unused in simplified implementation
        (void)size;     // Unused in simplified implementation
        int page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0) page_size = 4096;
        
        // Very basic check - production would use mincore
        // Try to access first byte - would need proper signal handling in production
        return true;  // Simplified for this implementation
#endif
    }
    
    template<typename T>
    T safeRead(const void* address, bool& success) noexcept {
        if (!isMemoryReadable(address, sizeof(T))) {
            success = false;
            return 0;
        }
        
        try {
#ifdef _WIN32
            __try {
                T value;
                memcpy(&value, address, sizeof(T));
                success = true;
                return value;
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                success = false;
                return 0;
            }
#else
            T value;
            memcpy(&value, address, sizeof(T));
            success = true;
            return value;
#endif
        } catch (...) {
            success = false;
            return 0;
        }
    }
}

// ============================================================================
// VMInterpreter::Impl
// ============================================================================

class VMInterpreter::Impl {
public:
    explicit Impl(const VMConfig& config) 
        : config_(config)
    {
        // Initialize identity opcode map
        for (uint32_t i = 0; i < 256; ++i) {
            opcode_map_inverse_[i] = static_cast<uint8_t>(i);
        }
    }
    
    VMOutput execute(const Bytecode& bytecode) noexcept {
        VMOutput output;
        
        try {
            // Re-entrancy protection (STAB-003)
            // Prevent external callbacks from calling back into VM
            bool expected = false;
            if (!executing_.compare_exchange_strong(expected, true)) {
                output.result = VMResult::Error;
                output.error_message = "VM re-entrancy detected";
                return output;
            }
            
            // Ensure we reset the flag on exit
            struct ExecutionGuard {
                std::atomic<bool>& flag;
                ~ExecutionGuard() { flag.store(false); }
            } guard{executing_};
            
            auto start_time = std::chrono::high_resolution_clock::now();
            
            // Verify bytecode integrity FIRST
            const uint8_t* raw = bytecode.rawData();
            size_t raw_size = bytecode.rawSize();
            
            if (raw_size < sizeof(BytecodeHeader)) {
                output.result = VMResult::Error;
                output.error_message = "Invalid bytecode header";
                return output;
            }
            
            const BytecodeHeader* header = reinterpret_cast<const BytecodeHeader*>(raw);
            
            // Verify magic
            if (header->magic != 0x53454E54) {
                output.result = VMResult::Error;
                output.error_message = "Invalid bytecode magic";
                return output;
            }
            
            // Compute hash of instructions and verify
            size_t instruction_offset = sizeof(BytecodeHeader) + (header->constant_count * 8);
            if (raw_size < instruction_offset + header->instruction_count) {
                output.result = VMResult::Error;
                output.error_message = "Invalid bytecode size";
                return output;
            }
            
            uint64_t computed_hash = xxh3_hash(
                raw + instruction_offset, 
                header->instruction_count  // Use exact instruction count from header
            );
            
            if (computed_hash != header->xxh3_hash) {
                // Bytecode has been tampered!
                output.result = VMResult::Violation;
                output.error_message = "Bytecode integrity violation";
                output.detection_flags |= (1ULL << 11);  // Bytecode tamper flag
                return output;
            }
            
            // Reset state
            stack_.clear();
            detection_flags_ = 0;
            memory_reads_ = 0;
            
            // Get instructions
            const uint8_t* instructions = bytecode.instructions();
            size_t instruction_count = bytecode.instructionCount();
            
            if (!instructions || instruction_count == 0) {
                output.result = VMResult::Error;
                output.error_message = "No instructions";
                return output;
            }
            
            // Execute
            size_t ip = 0;
            uint32_t instr_executed = 0;
            
            while (ip < instruction_count) {
                // Check instruction limit
                if (++instr_executed > config_.max_instructions) {
                    output.result = VMResult::Timeout;
                    output.instructions_executed = instr_executed;
                    return output;
                }
                
                // Check timeout
                auto now = std::chrono::high_resolution_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
                if (elapsed.count() > config_.timeout_ms) {
                    output.result = VMResult::Timeout;
                    output.instructions_executed = instr_executed;
                    output.elapsed = std::chrono::duration_cast<std::chrono::microseconds>(elapsed);
                    return output;
                }
                
                // Decode opcode
                uint8_t encoded_opcode = instructions[ip++];
                uint8_t canonical_opcode = opcode_map_inverse_[encoded_opcode];
                Opcode op = static_cast<Opcode>(canonical_opcode);
                
                // ================================================================
                // SPECIAL HANDLING: CALL_EXT with Timeout Enforcement (STAB-003)
                // ================================================================
                // External callbacks are handled here (not in executeOpcode) to
                // access start_time and enforce timeout against remaining budget.
                // ================================================================
                if (op == Opcode::CALL_EXT) {
                    if (ip >= instruction_count) {
                        output.result = VMResult::Error;
                        output.error_message = "CALL_EXT: Invalid instruction pointer";
                        output.instructions_executed = instr_executed;
                        return output;
                    }
                    
                    uint8_t func_id = instructions[ip++];
                    
                    uint64_t arg2, arg1;
                    if (!pop(arg2) || !pop(arg1)) {
                        output.result = VMResult::Error;
                        output.error_message = "CALL_EXT: Stack underflow";
                        output.instructions_executed = instr_executed;
                        return output;
                    }
                    
                    uint64_t result = 0;
                    auto it = external_functions_.find(func_id);
                    if (it != external_functions_.end() && it->second) {
                        // Calculate remaining timeout budget
                        auto now = std::chrono::high_resolution_clock::now();
                        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
                        int64_t remaining_ms = config_.timeout_ms - elapsed.count();
                        
                        // Execute callback with timeout enforcement
                        bool timed_out = false;
                        result = executeCallbackWithTimeout(it->second, arg1, arg2, remaining_ms, timed_out);
                        
                        if (timed_out) {
                            // Callback exceeded timeout - return immediately
                            output.result = VMResult::Timeout;
                            output.instructions_executed = instr_executed;
                            auto final_elapsed = std::chrono::high_resolution_clock::now() - start_time;
                            output.elapsed = std::chrono::duration_cast<std::chrono::microseconds>(final_elapsed);
                            return output;
                        }
                    }
                    
                    if (!push(result)) {
                        output.result = VMResult::Error;
                        output.error_message = "CALL_EXT: Stack overflow";
                        output.instructions_executed = instr_executed;
                        return output;
                    }
                    
                    // Continue to next instruction
                    continue;
                }
                
                // Execute other opcodes normally
                bool should_halt = false;
                if (!executeOpcode(op, instructions, instruction_count, ip, bytecode, should_halt)) {
                    output.result = VMResult::Error;
                    output.error_message = "Execution error";
                    output.instructions_executed = instr_executed;
                    return output;
                }
                
                if (should_halt) {
                    if (op == Opcode::HALT_FAIL) {
                        output.result = VMResult::Violation;
                    } else {
                        output.result = VMResult::Halted;
                    }
                    break;
                }
            }
            
            // Set output
            auto end_time = std::chrono::high_resolution_clock::now();
            output.detection_flags = detection_flags_;
            output.instructions_executed = instr_executed;
            output.memory_reads_performed = memory_reads_;
            output.elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            
            if (output.result != VMResult::Halted && output.result != VMResult::Violation) {
                output.result = VMResult::Clean;
            }
            
            // ================================================================
            // TELEMETRY INTEGRATION POINT (STAB-012)
            // ================================================================
            // TODO: Add VM execution metrics to telemetry here
            // 
            // RECOMMENDED IMPLEMENTATION:
            // 1. Log execution metrics for debugging:
            //    Logger::Debug("VM executed: result={} instructions={} elapsed={}us",
            //                  static_cast<int>(output.result), 
            //                  output.instructions_executed,
            //                  output.elapsed.count());
            // 
            // 2. Report to telemetry with sampling (every Nth execution):
            //    static thread_local uint32_t execution_count = 0;
            //    if (++execution_count % 100 == 0) {
            //        TelemetryEmitter::ReportVMExecution(
            //            output.result,
            //            output.instructions_executed,
            //            output.memory_reads_performed,
            //            output.elapsed.count()
            //            // DO NOT include: detection_flags (sensitive), error_message (PII)
            //        );
            //    }
            // 
            // 3. Record performance metrics:
            //    PerfTelemetry::RecordOperation(OperationType::VMExecution, output.elapsed);
            // 
            // 4. Alert on anomalies:
            //    if (output.elapsed.count() > 100000) { // 100ms
            //        Logger::Warn("VM execution took {}us (threshold: 100ms)", output.elapsed.count());
            //    }
            //    if (output.result == VMResult::Timeout) {
            //        Logger::Warn("VM execution timeout ({}us)", output.elapsed.count());
            //    }
            // 
            // IMPORTANT: Use sampling to avoid performance overhead. Do NOT log
            // every execution in production. Recommended sample rate: 1/100 or 1/1000.
            // ================================================================
            
        } catch (const std::exception& e) {
            output.result = VMResult::Error;
            output.error_message = e.what();
        } catch (...) {
            output.result = VMResult::Error;
            output.error_message = "Unknown error";
        }
        
        return output;
    }
    
    void registerExternal(uint8_t id, std::function<uint64_t(uint64_t, uint64_t)> callback) {
        external_functions_[id] = std::move(callback);
    }
    
    void setOpcodeMap(const std::array<uint8_t, 256>& new_map) {
        opcode_map_inverse_ = invertOpcodeMap(new_map);
    }
    
    const VMConfig& getConfig() const noexcept {
        return config_;
    }

private:
    /**
     * @brief Execute external callback with timeout enforcement (STAB-003)
     * @param callback The callback function to execute
     * @param arg1 First argument
     * @param arg2 Second argument
     * @param timeout_ms Maximum time allowed for callback
     * @param timed_out Output parameter set to true if callback times out
     * @return Result from callback, or 0 if timeout/exception
     * 
     * This method executes an external callback asynchronously with timeout
     * enforcement. If the callback exceeds the timeout, it returns 0 and
     * sets timed_out to true. The callback may continue running in background.
     */
    uint64_t executeCallbackWithTimeout(
        const std::function<uint64_t(uint64_t, uint64_t)>& callback,
        uint64_t arg1,
        uint64_t arg2,
        int64_t timeout_ms,
        bool& timed_out) noexcept 
    {
        timed_out = false;
        
        if (timeout_ms <= 0) {
            timed_out = true;
            return 0;
        }
        
        try {
            // Launch callback asynchronously
            auto callback_future = std::async(std::launch::async,
                [&callback, arg1, arg2]() -> uint64_t {
                    try {
                        return callback(arg1, arg2);
                    } catch (...) {
                        return 0;
                    }
                });
            
            // Wait for callback with timeout
            auto wait_status = callback_future.wait_for(
                std::chrono::milliseconds(timeout_ms));
            
            if (wait_status == std::future_status::ready) {
                // Callback completed within timeout
                return callback_future.get();
            } else {
                // Callback timed out
                timed_out = true;
                return 0;
            }
        } catch (...) {
            // Exception in async mechanism - fail safely
            return 0;
        }
    }

    bool executeOpcode(Opcode op, const uint8_t* instructions, size_t instruction_count,
                      size_t& ip, const Bytecode& bytecode, bool& should_halt) noexcept {
        try {
            switch (op) {
                case Opcode::NOP:
                    break;
                    
                case Opcode::HALT:
                    should_halt = true;
                    break;
                    
                case Opcode::HALT_FAIL:
                    should_halt = true;
                    break;
                    
                case Opcode::PUSH_IMM: {
                    if (ip + 8 > instruction_count) return false;
                    uint64_t value = readLE<uint64_t>(instructions + ip);
                    ip += 8;
                    if (!push(value)) return false;
                    break;
                }
                
                case Opcode::PUSH_CONST: {
                    if (ip + 2 > instruction_count) return false;
                    uint16_t index = readLE<uint16_t>(instructions + ip);
                    ip += 2;
                    uint64_t value = bytecode.getConstant(index);
                    if (!push(value)) return false;
                    break;
                }
                
                case Opcode::POP: {
                    uint64_t dummy;
                    if (!pop(dummy)) return false;
                    break;
                }
                
                case Opcode::DUP: {
                    if (stack_.empty()) return false;
                    uint64_t value = stack_.back();
                    if (!push(value)) return false;
                    break;
                }
                
                case Opcode::SWAP: {
                    if (stack_.size() < 2) return false;
                    std::swap(stack_[stack_.size() - 1], stack_[stack_.size() - 2]);
                    break;
                }
                
                // Arithmetic operations
                case Opcode::ADD: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a + b)) return false;
                    break;
                }
                
                case Opcode::SUB: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a - b)) return false;
                    break;
                }
                
                case Opcode::MUL: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a * b)) return false;
                    break;
                }
                
                case Opcode::XOR: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a ^ b)) return false;
                    break;
                }
                
                case Opcode::AND: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a & b)) return false;
                    break;
                }
                
                case Opcode::OR: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a | b)) return false;
                    break;
                }
                
                case Opcode::SHL: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a << (b & 63))) return false;
                    break;
                }
                
                case Opcode::SHR: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a >> (b & 63))) return false;
                    break;
                }
                
                case Opcode::ROL: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(rotl64(a, static_cast<int>(b)))) return false;
                    break;
                }
                
                case Opcode::ROR: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(rotr64(a, static_cast<int>(b)))) return false;
                    break;
                }
                
                // Comparison operations
                case Opcode::CMP_EQ: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a == b ? 1 : 0)) return false;
                    break;
                }
                
                case Opcode::CMP_NE: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a != b ? 1 : 0)) return false;
                    break;
                }
                
                case Opcode::CMP_LT: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a < b ? 1 : 0)) return false;
                    break;
                }
                
                case Opcode::CMP_GT: {
                    uint64_t b, a;
                    if (!pop(b) || !pop(a)) return false;
                    if (!push(a > b ? 1 : 0)) return false;
                    break;
                }
                
                // Branching
                case Opcode::JMP: {
                    if (ip + 2 > instruction_count) return false;
                    int16_t offset = static_cast<int16_t>(readLE<uint16_t>(instructions + ip));
                    ip += 2;
                    size_t new_ip = static_cast<size_t>(static_cast<int64_t>(ip) + offset);
                    if (new_ip >= instruction_count) return false;
                    ip = new_ip;
                    break;
                }
                
                case Opcode::JMP_Z: {
                    if (ip + 2 > instruction_count) return false;
                    int16_t offset = static_cast<int16_t>(readLE<uint16_t>(instructions + ip));
                    ip += 2;
                    uint64_t value;
                    if (!pop(value)) return false;
                    if (value == 0) {
                        size_t new_ip = static_cast<size_t>(static_cast<int64_t>(ip) + offset);
                        if (new_ip >= instruction_count) return false;
                        ip = new_ip;
                    }
                    break;
                }
                
                case Opcode::JMP_NZ: {
                    if (ip + 2 > instruction_count) return false;
                    int16_t offset = static_cast<int16_t>(readLE<uint16_t>(instructions + ip));
                    ip += 2;
                    uint64_t value;
                    if (!pop(value)) return false;
                    if (value != 0) {
                        size_t new_ip = static_cast<size_t>(static_cast<int64_t>(ip) + offset);
                        if (new_ip >= instruction_count) return false;
                        ip = new_ip;
                    }
                    break;
                }
                
                // Safe memory reads
                case Opcode::READ_SAFE_8: {
                    uint64_t address;
                    if (!pop(address)) return false;
                    if (++memory_reads_ > config_.max_memory_reads) return false;
                    
                    bool success = false;
                    uint64_t value = config_.enable_safe_reads ? 
                        safeRead<uint64_t>(reinterpret_cast<const void*>(address), success) : 0;
                    if (!push(value)) return false;
                    break;
                }
                
                case Opcode::READ_SAFE_4: {
                    uint64_t address;
                    if (!pop(address)) return false;
                    if (++memory_reads_ > config_.max_memory_reads) return false;
                    
                    bool success = false;
                    uint32_t value = config_.enable_safe_reads ? 
                        safeRead<uint32_t>(reinterpret_cast<const void*>(address), success) : 0;
                    if (!push(static_cast<uint64_t>(value))) return false;
                    break;
                }
                
                case Opcode::READ_SAFE_2: {
                    uint64_t address;
                    if (!pop(address)) return false;
                    if (++memory_reads_ > config_.max_memory_reads) return false;
                    
                    bool success = false;
                    uint16_t value = config_.enable_safe_reads ? 
                        safeRead<uint16_t>(reinterpret_cast<const void*>(address), success) : 0;
                    if (!push(static_cast<uint64_t>(value))) return false;
                    break;
                }
                
                case Opcode::READ_SAFE_1: {
                    uint64_t address;
                    if (!pop(address)) return false;
                    if (++memory_reads_ > config_.max_memory_reads) return false;
                    
                    bool success = false;
                    uint8_t value = config_.enable_safe_reads ? 
                        safeRead<uint8_t>(reinterpret_cast<const void*>(address), success) : 0;
                    if (!push(static_cast<uint64_t>(value))) return false;
                    break;
                }
                
                // Hash operations
                // ================================================================
                // HASH OPERATIONS WITH OVERFLOW PROTECTION (STAB-005)
                // ================================================================
                // These opcodes compute hashes over memory regions. Security concerns:
                // 1. Integer overflow in address + size calculation
                // 2. Vector allocation failure for large sizes
                // 3. Reading arbitrary memory via overflow
                //
                // Protections:
                // - Check for integer overflow before computing address + size
                // - Catch std::bad_alloc and return descriptive error
                // - Limit maximum hash size to 1MB
                // - Use safe memory reads with validation
                // ================================================================
                
                case Opcode::HASH_CRC32: {
                    uint64_t size, address;
                    if (!pop(size) || !pop(address)) return false;
                    
                    // Limit hash size to prevent excessive memory allocation
                    if (size > 1024 * 1024) size = 1024 * 1024;  // 1MB max
                    
                    // Integer overflow protection (STAB-005)
                    // Check if address + size would overflow or wrap around
                    if (size > 0 && address > UINTPTR_MAX - size) {
                        // Overflow detected: address + size would exceed maximum address space
                        // This prevents reading arbitrary memory via integer wraparound
                        if (!push(0)) return false;
                        break;
                    }
                    
                    uint32_t hash = 0;
                    if (config_.enable_safe_reads && size > 0) {
                        try {
                            // Allocate buffer for hash computation
                            // This may throw std::bad_alloc if size is too large
                            std::vector<uint8_t> buffer(size);
                            bool success = true;
                            
                            // Read memory safely byte-by-byte
                            for (size_t i = 0; i < size && success; ++i) {
                                buffer[i] = safeRead<uint8_t>(
                                    reinterpret_cast<const void*>(address + i), success);
                            }
                            
                            if (success) {
                                hash = crc32_hash(buffer.data(), size);
                            }
                        } catch (const std::bad_alloc&) {
                            // Memory allocation failed - return 0 hash safely
                            // This can happen if size is close to 1MB limit and system is low on memory
                            hash = 0;
                        }
                    }
                    if (!push(static_cast<uint64_t>(hash))) return false;
                    break;
                }
                
                case Opcode::HASH_XXH3: {
                    uint64_t size, address;
                    if (!pop(size) || !pop(address)) return false;
                    
                    // Limit hash size to prevent excessive memory allocation
                    if (size > 1024 * 1024) size = 1024 * 1024;  // 1MB max
                    
                    // Integer overflow protection (STAB-005)
                    // Check if address + size would overflow or wrap around
                    if (size > 0 && address > UINTPTR_MAX - size) {
                        // Overflow detected: address + size would exceed maximum address space
                        // This prevents reading arbitrary memory via integer wraparound
                        if (!push(0)) return false;
                        break;
                    }
                    
                    uint64_t hash = 0;
                    if (config_.enable_safe_reads && size > 0) {
                        try {
                            // Allocate buffer for hash computation
                            // This may throw std::bad_alloc if size is too large
                            std::vector<uint8_t> buffer(size);
                            bool success = true;
                            
                            // Read memory safely byte-by-byte
                            for (size_t i = 0; i < size && success; ++i) {
                                buffer[i] = safeRead<uint8_t>(
                                    reinterpret_cast<const void*>(address + i), success);
                            }
                            
                            if (success) {
                                hash = xxh3_hash(buffer.data(), size);
                            }
                        } catch (const std::bad_alloc&) {
                            // Memory allocation failed - return 0 hash safely
                            // This can happen if size is close to 1MB limit and system is low on memory
                            hash = 0;
                        }
                    }
                    if (!push(hash)) return false;
                    break;
                }
                
                case Opcode::CHECK_HASH: {
                    uint64_t expected, computed;
                    if (!pop(expected) || !pop(computed)) return false;
                    bool match = (computed == expected);
                    if (!match) {
                        detection_flags_ |= 0x01;  // Generic hash mismatch flag
                    }
                    if (!push(match ? 1 : 0)) return false;
                    break;
                }
                
                // Detection flags
                case Opcode::SET_FLAG: {
                    uint64_t flag_bit;
                    if (!pop(flag_bit)) return false;
                    if (flag_bit < 64) {
                        detection_flags_ |= (1ULL << flag_bit);
                    }
                    break;
                }
                
                case Opcode::GET_FLAGS: {
                    if (!push(detection_flags_)) return false;
                    break;
                }
                
                // External calls
                case Opcode::CALL_EXT: {
                    if (ip >= instruction_count) return false;
                    uint8_t func_id = instructions[ip++];
                    
                    uint64_t arg2, arg1;
                    if (!pop(arg2) || !pop(arg1)) return false;
                    
                    uint64_t result = 0;
                    auto it = external_functions_.find(func_id);
                    if (it != external_functions_.end() && it->second) {
                        try {
                            result = it->second(arg1, arg2);
                        } catch (...) {
                            result = 0;
                        }
                    }
                    if (!push(result)) return false;
                    break;
                }
                
                // Anti-analysis
                case Opcode::RDTSC_LOW: {
#ifdef _WIN32
                    uint64_t tsc = __rdtsc();
                    if (!push(tsc & 0xFFFFFFFF)) return false;
#else
                    // Simplified timestamp for non-Windows
                    auto now = std::chrono::high_resolution_clock::now();
                    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(
                        now.time_since_epoch()).count();
                    if (!push(static_cast<uint64_t>(nanos) & 0xFFFFFFFF)) return false;
#endif
                    break;
                }
                
                case Opcode::OPAQUE_TRUE: {
                    if (!push(1)) return false;
                    break;
                }
                
                case Opcode::OPAQUE_FALSE: {
                    if (!push(0)) return false;
                    break;
                }
                
                case Opcode::OP_TEST_EXCEPTION: {
#ifdef _WIN32
                    // Thread-local storage for canary verification
                    thread_local volatile void* tls_canary_address = nullptr;
                    thread_local volatile bool tls_canary_set = false;
                    
                    // Reset canary state
                    tls_canary_set = false;
                    tls_canary_address = nullptr;
                    
                    // Define VEH handler that will set the canary flag
                    // Note: Lambda captures the thread_local variables by reference
                    auto veh_handler = +[](PEXCEPTION_POINTERS ex) -> LONG {
                        if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
                            // Store the faulting address to verify we were called first
                            tls_canary_address = ex->ExceptionRecord->ExceptionAddress;
                            tls_canary_set = true;
                            // Let SEH handle the actual recovery
                            return EXCEPTION_CONTINUE_SEARCH;
                        }
                        return EXCEPTION_CONTINUE_SEARCH;
                    };
                    
                    // Register VEH handler with priority 1 (first to be called)
                    PVOID handler_handle = AddVectoredExceptionHandler(1, veh_handler);
                    
                    uint64_t result = 1;  // Default: integrity OK
                    
                    if (handler_handle) {
                        // Create guard page for controlled exception
                        SYSTEM_INFO si;
                        GetSystemInfo(&si);
                        LPVOID guard_page = VirtualAlloc(nullptr, si.dwPageSize, 
                                                        MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
                        
                        if (guard_page) {
                            __try {
                                // Trigger controlled access violation
                                volatile uint8_t probe = *static_cast<uint8_t*>(guard_page);
                                (void)probe;  // Suppress unused warning
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER) {
                                // Exception was handled - check if our VEH was called first
                                // The VEH should have been called before this SEH handler
                                if (!tls_canary_set) {
                                    // VEH handler was NOT called, meaning another VEH swallowed it
                                    result = 0;
                                    detection_flags_ |= (1ULL << 8);  // Set VEH hijacking flag
                                }
                            }
                            
                            // Cleanup guard page
                            VirtualFree(guard_page, 0, MEM_RELEASE);
                        }
                        
                        // Remove VEH handler
                        RemoveVectoredExceptionHandler(handler_handle);
                    }
                    
                    if (!push(result)) return false;
#else
                    // Non-Windows always passes
                    if (!push(1)) return false;
#endif
                    break;
                }
                
                case Opcode::OP_RDTSC_DIFF: {
#ifdef _WIN32
                    // Detect hypervisor using CPUID (same as AntiDebug.cpp)
                    static thread_local bool hypervisor_checked = false;
                    static thread_local bool hypervisor_detected = false;
                    
                    if (!hypervisor_checked) {
                        int cpuid_check[4] = {0};
                        __cpuid(cpuid_check, 0);
                        if (cpuid_check[0] >= 1) {
                            __cpuid(cpuid_check, 1);
                            // ECX bit 31 indicates hypervisor presence
                            hypervisor_detected = (cpuid_check[2] & (1 << 31)) != 0;
                        }
                        hypervisor_checked = true;
                    }
                    
                    // Serialize with CPUID (forces emulator to handle this)
                    int cpuid_data[4];
                    __cpuid(cpuid_data, 0);
                    
                    uint64_t tsc1 = __rdtsc();
                    
                    // Known-cost operations that must take measurable time
                    // These operations are chosen to stress emulator accuracy: 
                    // - Memory fence (MFENCE via interlocked op)
                    // - Floating point (often poorly emulated)
                    // - Cache interaction
                    volatile int64_t accumulator = 0;
                    for (int i = 0; i < 50; ++i) {
                        accumulator += i * i;  // Integer multiply
                        _mm_mfence();          // Memory barrier (forces serialization)
                    }
                    
                    // Serialize again
                    __cpuid(cpuid_data, 0);
                    uint64_t tsc2 = __rdtsc();
                    
                    uint64_t delta = tsc2 - tsc1;
                    (void)accumulator;  // Prevent optimization
                    
                    bool is_emulated = false;
                    
                    // Apply 100x multiplier for hypervisor thresholds to accommodate timing variance
                    // Hypervisors have significant timing overhead and variability
                    uint64_t threshold_low = hypervisor_detected ? 50 : 500;
                    uint64_t threshold_high = hypervisor_detected ? 500000000 : 5000000;
                    
                    // Check 1: Delta too low (emulator returning fake constant TSC)
                    // 50 iterations with MFENCE should take AT MINIMUM 1000 cycles on real hardware
                    // Even a 5GHz CPU:  50 * ~20 cycles per MFENCE = 1000+ cycles
                    // Under hypervisor: 10x more lenient threshold
                    if (delta < threshold_low) {
                        is_emulated = true;
                    }
                    
                    // Check 2: Delta suspiciously high (single-stepping or breakpoint)
                    // Normal execution: 1000-50000 cycles
                    // Single-stepping: 1,000,000+ cycles per iteration
                    // Under hypervisor: 10x more lenient threshold
                    if (delta > threshold_high) {  // 5M cycles = obvious debugging (50M under hypervisor)
                        is_emulated = true;
                    }
                    
                    // Check 3: Statistical consistency check over multiple samples
                    // Real hardware has variance; emulators often don't
                    // NOTE: This check only applies after 8 samples have been collected
                    static thread_local uint64_t last_deltas[8] = {0};
                    static thread_local int delta_index = 0;
                    
                    last_deltas[delta_index & 7] = delta;
                    delta_index++;
                    
                    // Only check variance after we have enough samples
                    if (delta_index > 8) {
                        uint64_t sum = 0, variance_sum = 0;
                        for (int i = 0; i < 8; ++i) sum += last_deltas[i];
                        uint64_t mean = sum / 8;
                        for (int i = 0; i < 8; ++i) {
                            int64_t diff = static_cast<int64_t>(last_deltas[i]) - static_cast<int64_t>(mean);
                            variance_sum += diff * diff;
                        }
                        // If variance is near-zero, likely emulation
                        // Under hypervisor: disable variance check entirely (set to 0)
                        // as hypervisors can have inconsistent timing
                        if (!hypervisor_detected) {
                            if (variance_sum < 10000) {
                                is_emulated = true;
                            }
                        }
                    }
                    
                    if (is_emulated) {
                        detection_flags_ |= (1ULL << 9);  // Emulation detected flag
                    }
                    
                    if (!push(is_emulated ? 0ULL : 1ULL)) return false;
#else
                    // Non-Windows: Basic timing check using clock_gettime
                    struct timespec ts1, ts2;
                    clock_gettime(CLOCK_MONOTONIC, &ts1);
                    volatile int64_t acc = 0;
                    for (int i = 0; i < 50; ++i) acc += i * i;
                    clock_gettime(CLOCK_MONOTONIC, &ts2);
                    (void)acc;
                    
                    uint64_t delta_ns = (ts2.tv_sec - ts1.tv_sec) * 1000000000ULL + 
                                        (ts2.tv_nsec - ts1.tv_nsec);
                    // 50 ops should take > 100ns on real hardware
                    bool is_emulated = (delta_ns < 50 || delta_ns > 100000000);
                    if (is_emulated) detection_flags_ |= (1ULL << 9);
                    if (!push(is_emulated ? 0ULL : 1ULL)) return false;
#endif
                    break;
                }
                
                case Opcode::OP_READ_TEB: {
#ifdef _WIN32
    #ifdef _WIN64
                    uint64_t teb = __readgsqword(0x30);
    #else
                    uint64_t teb = __readfsdword(0x18);
    #endif
                    if (!push(teb)) return false;
#else
                    if (!push(0)) return false;  // Linux placeholder
#endif
                    break;
                }

                case Opcode::OP_READ_PEB: {
#ifdef _WIN32
    #ifdef _WIN64
                    uint64_t peb = __readgsqword(0x60);
    #else  
                    uint64_t peb = __readfsdword(0x30);
    #endif
                    if (!push(peb)) return false;
#else
                    if (!push(0)) return false;  // Linux placeholder
#endif
                    break;
                }
                
                case Opcode::OP_CHECK_SYSCALL: {
#ifdef _WIN32
                    uint64_t func_addr;
                    if (!pop(func_addr)) return false;
                    
                    uint64_t syscall_num = 0;
                    bool is_hooked = false;
                    
                    // Read first 16 bytes of function
                    uint8_t stub[16] = {0};
                    bool read_success = true;
                    for (int i = 0; i < 16 && read_success; ++i) {
                        stub[i] = safeRead<uint8_t>(
                            reinterpret_cast<const void*>(func_addr + i), read_success);
                    }
                    
                    if (read_success) {
                        // Check for hook signatures FIRST (before pattern validation)
                        
                        // E9 XX XX XX XX = JMP rel32 (most common detour)
                        if (stub[0] == 0xE9) {
                            is_hooked = true;
                        }
                        // FF 25 XX XX XX XX = JMP [rip+disp32] (IAT-style hook)
                        else if (stub[0] == 0xFF && stub[1] == 0x25) {
                            is_hooked = true;
                        }
                        // 48 B8 = MOV RAX, imm64 (setup for absolute jump)
                        else if (stub[0] == 0x48 && stub[1] == 0xB8) {
                            is_hooked = true;
                        }
                        // CC = INT3 breakpoint
                        else if (stub[0] == 0xCC) {
                            is_hooked = true;
                        }
                        // Check for valid syscall stub pattern
                        else if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&  // mov r10, rcx
                                 stub[3] == 0xB8) {  // mov eax, imm32
                            // Extract syscall number (little-endian at offset 4)
                            // Use memcpy for safe type-punning
                            uint32_t syscall_num_32;
                            std::memcpy(&syscall_num_32, &stub[4], sizeof(uint32_t));
                            syscall_num = syscall_num_32;
                            
                            // Validate syscall/ret sequence
                            // Note: Some Windows versions have test/jne before syscall
                            bool found_syscall = false;
                            for (int i = 8; i < 14; ++i) {
                                if (stub[i] == 0x0F && stub[i+1] == 0x05) {  // syscall
                                    found_syscall = true;
                                    break;
                                }
                            }
                            
                            if (!found_syscall) {
                                is_hooked = true;
                                syscall_num = 0;
                            }
                        } else {
                            // Pattern doesn't match - either hooked or unknown format
                            is_hooked = true;
                        }
                    } else {
                        is_hooked = true;  // Couldn't read memory
                    }
                    
                    if (is_hooked) {
                        detection_flags_ |= (1ULL << 10);  // Hook detection flag
                        syscall_num = 0;
                    }
                    
                    if (!push(syscall_num)) return false;
#else
                    uint64_t dummy;
                    if (!pop(dummy)) return false;
                    if (!push(0)) return false;  // No syscalls on Linux equivalent
#endif
                    break;
                }
                
                default:
                    // Unknown opcode
                    return false;
            }
            
            return true;
            
        } catch (...) {
            return false;
        }
    }
    
    bool push(uint64_t value) noexcept {
        if (stack_.size() >= config_.max_stack_depth) {
            return false;
        }
        try {
            stack_.push_back(value);
            return true;
        } catch (...) {
            return false;
        }
    }
    
    bool pop(uint64_t& value) noexcept {
        if (stack_.empty()) {
            return false;
        }
        value = stack_.back();
        stack_.pop_back();
        return true;
    }
    
    VMConfig config_;
    std::vector<uint64_t> stack_;
    std::array<uint8_t, 256> opcode_map_inverse_;
    std::unordered_map<uint8_t, std::function<uint64_t(uint64_t, uint64_t)>> external_functions_;
    uint64_t detection_flags_ = 0;
    uint32_t memory_reads_ = 0;
    std::atomic<bool> executing_{false};  // Re-entrancy protection for callbacks
};

// ============================================================================
// VMInterpreter Public API
// ============================================================================

VMInterpreter::VMInterpreter(const VMConfig& config)
    : m_impl(std::make_unique<Impl>(config))
{
}

VMInterpreter::~VMInterpreter() = default;

VMInterpreter::VMInterpreter(VMInterpreter&&) noexcept = default;
VMInterpreter& VMInterpreter::operator=(VMInterpreter&&) noexcept = default;

VMOutput VMInterpreter::execute(const Bytecode& bytecode) noexcept {
    // Execute the bytecode and return metrics
    // 
    // TELEMETRY NOTE (STAB-012): 
    // The returned VMOutput contains important execution metrics that should be
    // logged and reported to telemetry for production monitoring. See VMOutput
    // documentation in VMInterpreter.hpp for complete telemetry integration guide.
    // 
    // Key metrics available:
    // - result: Execution outcome (Clean, Violation, Error, Timeout, Halted)
    // - instructions_executed: Number of opcodes executed
    // - memory_reads_performed: Number of safe memory read operations
    // - elapsed: Wall-clock execution time (microseconds)
    // - detection_flags: Bitmask of detected security issues
    // 
    // Recommended: Log these metrics with sampling (e.g., every 100th execution)
    // to enable performance regression detection and security anomaly monitoring.
    return m_impl->execute(bytecode);
}

void VMInterpreter::registerExternal(uint8_t id, std::function<uint64_t(uint64_t, uint64_t)> callback) {
    m_impl->registerExternal(id, std::move(callback));
}

void VMInterpreter::setOpcodeMap(const std::array<uint8_t, 256>& new_map) {
    m_impl->setOpcodeMap(new_map);
}

const VMConfig& VMInterpreter::getConfig() const noexcept {
    return m_impl->getConfig();
}

} // namespace Sentinel::VM
