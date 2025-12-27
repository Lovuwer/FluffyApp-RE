/**
 * Sentinel SDK - Safe Memory Access Utilities
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 6: Crash-Safe Memory Access for Detection Modules
 * 
 * Provides crash-safe memory access functions that handle access violations
 * gracefully instead of crashing the protected process. Essential for
 * scanning memory that may be freed, unmapped, or otherwise inaccessible.
 */

#pragma once

#include <cstdint>
#include <cstddef>

namespace Sentinel {
namespace SDK {

/**
 * Safe memory access utilities
 * 
 * All functions in this class handle access violations gracefully,
 * returning false/failure instead of crashing the process.
 */
class SafeMemory {
public:
    /**
     * Check if memory region is readable
     * 
     * Uses VirtualQuery to verify the memory is committed and accessible
     * before attempting to read.
     * 
     * @param address Memory address to check
     * @param size Size of region in bytes
     * @return true if memory is readable, false otherwise
     */
    static bool IsReadable(const void* address, size_t size);
    
    /**
     * Safely read memory with SEH protection
     * 
     * Attempts to read memory into a buffer. If an access violation occurs,
     * returns false instead of crashing.
     * 
     * @param address Source memory address
     * @param buffer Destination buffer
     * @param size Number of bytes to read
     * @return true if read succeeded, false if access violation occurred
     */
    static bool SafeRead(const void* address, void* buffer, size_t size);
    
    /**
     * Safely compare memory with expected bytes
     * 
     * Compares memory at address with expected data. If an access violation
     * occurs, returns false instead of crashing.
     * 
     * @param address Memory address to compare
     * @param expected Expected byte pattern
     * @param size Number of bytes to compare
     * @return true if memory matches expected, false if mismatch or access violation
     */
    static bool SafeCompare(const void* address, const void* expected, size_t size);
    
    /**
     * Safely compute hash of memory region
     * 
     * Computes a hash of the memory region. If an access violation occurs,
     * returns 0 instead of crashing.
     * 
     * @param address Memory address to hash
     * @param size Number of bytes to hash
     * @param out_hash Output hash value (only valid if function returns true)
     * @return true if hash computed successfully, false if access violation
     */
    static bool SafeHash(const void* address, size_t size, uint64_t* out_hash);
};

} // namespace SDK
} // namespace Sentinel
