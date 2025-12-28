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

// Include the hardened ProtectedValue implementation
#include "ProtectedValue.hpp"

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
    uint64_t last_scanned_timestamp = 0;  // Timestamp in milliseconds for probabilistic scanning
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
