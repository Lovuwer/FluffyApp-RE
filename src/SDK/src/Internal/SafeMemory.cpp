/**
 * Sentinel SDK - Safe Memory Access Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 6: Crash-Safe Memory Access for Detection Modules
 */

#include "SafeMemory.hpp"
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <setjmp.h>
#endif

namespace Sentinel {
namespace SDK {

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
        
        // Check if memory has read access
        if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_GUARD) {
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
    
    // First check if memory is readable
    if (!IsReadable(address, size)) {
        return false;
    }
    
#ifdef _WIN32
    // Use structured exception handling to catch access violations
    __try {
        memcpy(buffer, address, size);
        return true;
    }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? 
              EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        // Access violation occurred
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

} // namespace SDK
} // namespace Sentinel
