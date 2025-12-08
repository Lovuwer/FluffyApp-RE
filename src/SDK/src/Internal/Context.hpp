/**
 * Sentinel SDK - Internal Context Structures
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#pragma once

#include <cstdint>
#include <string>
#include <chrono>
#include <array>

namespace Sentinel {
namespace SDK {

/**
 * Protected memory region tracking
 */
struct MemoryRegion {
    uintptr_t address;
    size_t size;
    std::string name;
    uint64_t original_hash;
    std::chrono::steady_clock::time_point protected_time;
};

/**
 * Protected function tracking
 */
struct FunctionProtection {
    uintptr_t address;
    std::string name;
    std::array<uint8_t, 32> original_prologue;
    size_t prologue_size;
};

/**
 * Obfuscated value storage
 * Uses XOR encryption with rotating key
 */
class ProtectedValue {
public:
    void SetValue(int64_t value) {
        // Rotate key
        key_ = (key_ * 1103515245 + 12345) & 0x7FFFFFFF;
        
        // XOR with key and store
        stored_value_ = value ^ static_cast<int64_t>(key_);
        
        // Store checksum
        checksum_ = ComputeChecksum(value);
    }
    
    int64_t GetValue() const {
        int64_t value = stored_value_ ^ static_cast<int64_t>(key_);
        
        // Verify checksum
        if (ComputeChecksum(value) != checksum_) {
            // Tampering detected!
            return 0;
        }
        
        return value;
    }
    
    bool Verify() const {
        int64_t value = stored_value_ ^ static_cast<int64_t>(key_);
        return ComputeChecksum(value) == checksum_;
    }
    
private:
    int64_t stored_value_ = 0;
    uint32_t key_ = 0xDEADBEEF;
    uint32_t checksum_ = 0;
    
    static uint32_t ComputeChecksum(int64_t value) {
        uint32_t hash = 0x811c9dc5;
        for (int i = 0; i < 8; i++) {
            hash ^= (value >> (i * 8)) & 0xFF;
            hash *= 0x01000193;
        }
        return hash;
    }
};

/**
 * Internal utility functions
 */
namespace Internal {

/**
 * Compute fast hash of memory region
 */
inline uint64_t ComputeHash(const void* data, size_t size) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint64_t hash = 0xcbf29ce484222325ULL;
    
    for (size_t i = 0; i < size; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;
    }
    
    return hash;
}

/**
 * Get function prologue size (minimum bytes needed for hook detection)
 */
inline size_t GetPrologueSize(const void* function) {
    // Simple heuristic - in real implementation would use disassembler
    (void)function;
    return 16;
}

/**
 * Generate hardware fingerprint
 */
std::string GenerateHardwareId();

/**
 * Generate session token
 */
std::string GenerateSessionToken();

} // namespace Internal

} // namespace SDK
} // namespace Sentinel
