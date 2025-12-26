/**
 * @file SecureZero.cpp
 * @brief Secure memory zeroing implementation with compiler barrier protection
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Implements compiler-barrier-protected memory erasure to prevent Dead Store
 * Elimination (DSE) from optimizing away sensitive data cleanup.
 * 
 * Defense Against:
 * - Passive Memory Analysis (memory scrapers, hibernation file analysis)
 * - Information Disclosure via Persistent Memory Artifacts
 * 
 * Implementation:
 * - Windows: Uses SecureZeroMemory intrinsic (guaranteed not to be optimized)
 * - Non-Windows: Uses volatile pointer technique + memory barrier
 */

#include <Sentinel/Core/Crypto.hpp>
#include <cstdint>
#include <cstddef>
#include <atomic>

#ifdef _WIN32
#include <windows.h>
#endif

namespace Sentinel::Crypto {

/**
 * @brief Securely zero memory with compiler barrier protection
 * 
 * This function overwrites a memory region with zeros in a way that cannot
 * be optimized away by the compiler. This is critical for clearing sensitive
 * data such as cryptographic keys, plaintext, and session tokens.
 * 
 * @param data Pointer to memory region to zero
 * @param size Number of bytes to zero
 * 
 * @note This function is noexcept. NULL pointer with size > 0 results in
 *       undefined behavior (caller must validate inputs).
 * @note Thread-safe: operates only on caller-provided buffer
 * @note If size is 0, this is a no-op
 * 
 * @warning Caller is responsible for validating that data is a valid pointer
 *          when size > 0. Invalid memory regions will cause OS access violations.
 */
void secureZero(void* data, size_t size) noexcept {
    // Handle zero-size case early (no-op)
    if (size == 0) {
        return;
    }
    
#ifdef _WIN32
    // Windows Implementation
    // SecureZeroMemory is a compiler intrinsic that MSVC guarantees will not
    // be optimized away, even if the buffer is never read afterward.
    SecureZeroMemory(data, size);
#else
    // Cross-Platform Fallback
    // Use volatile pointer technique to prevent compiler from optimizing away
    // the write operations. The volatile qualifier forces the compiler to
    // perform the actual memory write.
    volatile unsigned char* ptr = static_cast<volatile unsigned char*>(data);
    while (size--) {
        *ptr++ = 0;
    }
    
    // Memory barrier to prevent speculative execution from reordering
    // operations. This ensures that the zeroing completes before any
    // subsequent operations that might depend on it.
    #if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
    #elif defined(_MSC_VER)
        _ReadWriteBarrier();
    #else
        // For other compilers, volatile should be sufficient
        // but we add an atomic fence for extra safety
        std::atomic_thread_fence(std::memory_order_seq_cst);
    #endif
#endif
}

} // namespace Sentinel::Crypto
