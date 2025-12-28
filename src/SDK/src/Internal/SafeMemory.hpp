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
 * Exception statistics for scan cycle tracking
 */
struct ExceptionStats {
    uint32_t access_violations = 0;
    uint32_t guard_page_hits = 0;
    uint32_t stack_overflows = 0;
    uint32_t other_exceptions = 0;
    
    uint32_t GetTotalExceptions() const {
        return access_violations + guard_page_hits + stack_overflows + other_exceptions;
    }
    
    void Reset() {
        access_violations = 0;
        guard_page_hits = 0;
        stack_overflows = 0;
        other_exceptions = 0;
    }
};

/**
 * Safe memory access utilities
 * 
 * All functions in this class handle access violations gracefully,
 * returning false/failure instead of crashing the process.
 * 
 * Task 5: Enhanced with crash-proof memory scanning features:
 * - Pre-scan VirtualQuery with PAGE_GUARD detection
 * - Secondary VirtualQuery before read (TOCTOU protection)
 * - Distinguished exception handling by exception code
 * - Scan canary mechanism for VEH tampering detection
 * - Exception count limiting per scan cycle
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
     * Safely read memory with SEH protection and TOCTOU defense
     * 
     * Attempts to read memory into a buffer. Performs secondary VirtualQuery
     * immediately before read to detect TOCTOU attacks. If an access violation
     * occurs, returns false instead of crashing.
     * 
     * Task 5: Enhanced with:
     * - Secondary VirtualQuery before read
     * - Distinguished exception handling
     * - Exception count tracking
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
    
    /**
     * Validate scan canary to detect VEH tampering
     * 
     * Reads a known-good memory region to ensure exception handlers
     * haven't been tampered with.
     * 
     * @return true if canary is intact, false if VEH tampering detected
     */
    static bool ValidateScanCanary();
    
    /**
     * Get exception statistics for current scan cycle
     * 
     * @return Reference to exception statistics
     */
    static ExceptionStats& GetExceptionStats();
    
    /**
     * Reset exception statistics (should be called at start of each scan cycle)
     */
    static void ResetExceptionStats();
    
    /**
     * Check if exception limit has been exceeded
     * 
     * @param max_exceptions Maximum allowed exceptions (default: 10)
     * @return true if limit exceeded
     */
    static bool IsExceptionLimitExceeded(uint32_t max_exceptions = 10);
    
private:
    static ExceptionStats exception_stats_;
    static uint8_t canary_buffer_[64];
    static bool canary_initialized_;
    
    static void InitializeCanary();
};

} // namespace SDK
} // namespace Sentinel
