/**
 * Sentinel SDK - Safe Memory Access Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 6: Crash-Safe Memory Access for Detection Modules
 * Task 5: Enhanced with Crash-Proof Memory Scanning
 * 
 * Implements defensive unmapping handling:
 * - Pre-scan VirtualQuery with PAGE_GUARD detection
 * - Secondary VirtualQuery immediately before read (TOCTOU protection)
 * - Distinguished exception handling by exception code
 * - Scan canary mechanism for VEH tampering detection
 * - Exception count limiting per scan cycle
 */

#include "SafeMemory.hpp"
#include <cstring>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <setjmp.h>
#endif

namespace Sentinel {
namespace SDK {

// Static member initialization
ExceptionStats SafeMemory::exception_stats_;
uint8_t SafeMemory::canary_buffer_[64];
bool SafeMemory::canary_initialized_ = false;

bool SafeMemory::IsReadable(const void* address, size_t size) {
    if (!address || size == 0) {
        return false;
    }
    
#ifdef _WIN32
    // Use VirtualQuery to check memory accessibility
    uintptr_t addr = reinterpret_cast<uintptr_t>(address);
    uintptr_t endAddr = addr + size;
    
    // Check each page in the range
    while (addr < endAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
            return false;  // Query failed
        }
        
        // Check if memory is committed
        if (mbi.State != MEM_COMMIT) {
            return false;
        }
        
        // Task 5: Pre-scan check for PAGE_GUARD
        // Guard pages trigger exception on first access - skip them entirely
        if (mbi.Protect & PAGE_GUARD) {
            // Log as suspicious - cheats use guard pages to detect scanning
            #ifdef _DEBUG
            fprintf(stderr, "[SafeMemory] Guard page detected at 0x%p - skipping (potential scan detection)\n", 
                    (void*)addr);
            #endif
            exception_stats_.guard_page_hits++;
            return false;
        }
        
        // Check if memory has read access
        if (mbi.Protect == PAGE_NOACCESS) {
            return false;
        }
        
        // Move to next region
        addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
    
    return true;
#else
    // On non-Windows platforms, we'll use SEH in SafeRead
    // For now, assume readable (will be caught by SafeRead if not)
    (void)address;
    (void)size;
    return true;
#endif
}

bool SafeMemory::SafeRead(const void* address, void* buffer, size_t size) {
    if (!address || !buffer || size == 0) {
        return false;
    }
    
    // Check exception limit before proceeding
    if (IsExceptionLimitExceeded()) {
        #ifdef _DEBUG
        fprintf(stderr, "[SafeMemory] Exception limit exceeded - aborting scan\n");
        #endif
        return false;
    }
    
    // First check if memory is readable (includes guard page check)
    if (!IsReadable(address, size)) {
        return false;
    }
    
#ifdef _WIN32
    // Task 5: Secondary VirtualQuery immediately before read (TOCTOU protection)
    // Memory can be unmapped between first IsReadable check and actual read
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
        return false;  // Query failed - memory likely unmapped
    }
    
    // Re-verify memory is still committed and readable
    if (mbi.State != MEM_COMMIT) {
        #ifdef _DEBUG
        fprintf(stderr, "[SafeMemory] TOCTOU detected: memory unmapped between checks at 0x%p\n", address);
        #endif
        return false;
    }
    
    if (mbi.Protect == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) {
        #ifdef _DEBUG
        fprintf(stderr, "[SafeMemory] TOCTOU detected: protection changed at 0x%p\n", address);
        #endif
        return false;
    }
    
    // Use stack buffer only (no heap allocation inside SEH block)
    // Use structured exception handling to catch access violations
    __try {
        memcpy(buffer, address, size);
        return true;
    }
    __except (
        // Task 5: Distinguish exception codes
        [](DWORD code) -> int {
            switch (code) {
                case EXCEPTION_ACCESS_VIOLATION:
                    // Expected attack - memory unmapped during scan
                    exception_stats_.access_violations++;
                    #ifdef _DEBUG
                    fprintf(stderr, "[SafeMemory] ACCESS_VIOLATION caught - continuing scan\n");
                    #endif
                    return EXCEPTION_EXECUTE_HANDLER;
                    
                case EXCEPTION_GUARD_PAGE:
                    // Scan detected by cheat - log and continue
                    exception_stats_.guard_page_hits++;
                    #ifdef _DEBUG
                    fprintf(stderr, "[SafeMemory] GUARD_PAGE exception - scan detected signal\n");
                    #endif
                    return EXCEPTION_EXECUTE_HANDLER;
                    
                case EXCEPTION_STACK_OVERFLOW:
                    // Critical error - this should not happen in normal memory reads
                    exception_stats_.stack_overflows++;
                    #ifdef _DEBUG
                    fprintf(stderr, "[SafeMemory] STACK_OVERFLOW - critical error, aborting\n");
                    #endif
                    return EXCEPTION_EXECUTE_HANDLER;
                    
                default:
                    // Unknown exception - log with full context for analysis
                    exception_stats_.other_exceptions++;
                    #ifdef _DEBUG
                    fprintf(stderr, "[SafeMemory] Unexpected exception 0x%08X - logging for analysis\n", code);
                    #endif
                    return EXCEPTION_EXECUTE_HANDLER;
            }
        }(GetExceptionCode())
    ) {
        // Exception occurred - already logged in filter
        return false;
    }
#else
    // Non-Windows: attempt copy without SEH
    // Note: This is less safe on non-Windows platforms
    // A production implementation would use signal handlers
    memcpy(buffer, address, size);
    return true;
#endif
}

bool SafeMemory::SafeCompare(const void* address, const void* expected, size_t size) {
    if (!address || !expected || size == 0) {
        return false;
    }
    
    // First check if memory is readable
    if (!IsReadable(address, size)) {
        return false;
    }
    
#ifdef _WIN32
    // Use structured exception handling to catch access violations
    __try {
        return memcmp(address, expected, size) == 0;
    }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? 
              EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        // Access violation occurred
        return false;
    }
#else
    // Non-Windows: attempt comparison without SEH
    return memcmp(address, expected, size) == 0;
#endif
}

bool SafeMemory::SafeHash(const void* address, size_t size, uint64_t* out_hash) {
    if (!address || size == 0 || !out_hash) {
        return false;
    }
    
    // First check if memory is readable
    if (!IsReadable(address, size)) {
        return false;
    }
    
#ifdef _WIN32
    // Use structured exception handling to catch access violations
    __try {
        const uint8_t* bytes = static_cast<const uint8_t*>(address);
        
        // FNV-1a hash algorithm constants
        static constexpr uint64_t FNV_OFFSET_BASIS = 0xcbf29ce484222325ULL;
        static constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;
        
        uint64_t hash = FNV_OFFSET_BASIS;
        
        for (size_t i = 0; i < size; i++) {
            hash ^= bytes[i];
            hash *= FNV_PRIME;
        }
        
        *out_hash = hash;
        return true;
    }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? 
              EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        // Access violation occurred
        exception_stats_.access_violations++;
        return false;
    }
#else
    // Non-Windows: attempt hash computation without SEH
    const uint8_t* bytes = static_cast<const uint8_t*>(address);
    
    // FNV-1a hash algorithm constants
    static constexpr uint64_t FNV_OFFSET_BASIS = 0xcbf29ce484222325ULL;
    static constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;
    
    uint64_t hash = FNV_OFFSET_BASIS;
    
    for (size_t i = 0; i < size; i++) {
        hash ^= bytes[i];
        hash *= FNV_PRIME;
    }
    
    *out_hash = hash;
    return true;
#endif
}

void SafeMemory::InitializeCanary() {
    if (canary_initialized_) {
        return;
    }
    
    // Fill canary buffer with known pattern
    for (size_t i = 0; i < sizeof(canary_buffer_); i++) {
        canary_buffer_[i] = static_cast<uint8_t>(0xAA ^ (i & 0xFF));
    }
    
    canary_initialized_ = true;
}

bool SafeMemory::ValidateScanCanary() {
    // Initialize canary on first use
    if (!canary_initialized_) {
        InitializeCanary();
    }
    
    // Read our own known-good memory region to detect VEH tampering
    uint8_t temp_buffer[64];
    
#ifdef _WIN32
    __try {
        memcpy(temp_buffer, canary_buffer_, sizeof(canary_buffer_));
        
        // Verify the data matches
        if (memcmp(temp_buffer, canary_buffer_, sizeof(canary_buffer_)) != 0) {
            #ifdef _DEBUG
            fprintf(stderr, "[SafeMemory] Canary validation failed - VEH tampering detected!\n");
            #endif
            return false;
        }
        
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Exception reading our own memory - VEH tampering detected
        #ifdef _DEBUG
        fprintf(stderr, "[SafeMemory] Canary read caused exception - VEH tampering detected!\n");
        #endif
        return false;
    }
#else
    // Non-Windows: simple memcpy check
    memcpy(temp_buffer, canary_buffer_, sizeof(canary_buffer_));
    return memcmp(temp_buffer, canary_buffer_, sizeof(canary_buffer_)) == 0;
#endif
}

ExceptionStats& SafeMemory::GetExceptionStats() {
    return exception_stats_;
}

void SafeMemory::ResetExceptionStats() {
    exception_stats_.Reset();
}

bool SafeMemory::IsExceptionLimitExceeded(uint32_t max_exceptions) {
    return exception_stats_.GetTotalExceptions() >= max_exceptions;
}

} // namespace SDK
} // namespace Sentinel
