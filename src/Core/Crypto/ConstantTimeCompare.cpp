/**
 * @file ConstantTimeCompare.cpp
 * @brief Constant-time comparison function to prevent timing side-channel attacks
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This module implements constant-time comparison to prevent timing oracle attacks
 * during MAC/hash verification. The implementation ensures comparison time is
 * independent of input content to defend against byte-by-byte secret recovery.
 */

#include <Sentinel/Core/Crypto.hpp>

#ifdef SENTINEL_USE_OPENSSL
#include <openssl/crypto.h>
#endif

namespace Sentinel::Crypto {

/**
 * @brief Constant-time comparison of byte arrays
 * 
 * Compares two byte spans in constant time to prevent timing side-channel attacks.
 * This is critical for cryptographic operations like MAC verification where timing
 * differences could leak information about secret values.
 * 
 * **Security Properties:**
 * - Always iterates through ALL bytes regardless of mismatch position
 * - Uses volatile accumulator to prevent compiler optimizations
 * - No early returns based on data content
 * - No conditional branches based on intermediate comparison results
 * 
 * **Implementation Notes:**
 * - Length comparison IS timing-variable, but length is typically public (e.g., MACs have fixed size)
 * - Uses bitwise OR to accumulate differences (XOR result)
 * - Returns true only if all bytes matched (result == 0)
 * 
 * @param a First buffer
 * @param b Second buffer
 * @return true if contents are identical, false otherwise
 * 
 * @note Thread-safe: Pure function with no state
 * @note Different sizes return immediately (acceptable; sizes are typically public)
 */
bool constantTimeCompare(ByteSpan a, ByteSpan b) noexcept {
#ifdef SENTINEL_USE_OPENSSL
    // Prefer OpenSSL's audited implementation when available
    if (a.size() != b.size()) {
        return false;
    }
    
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
#else
    // Fallback implementation when OpenSSL is not available
    
    // Different lengths are not constant-time comparable
    // This length comparison IS timing-variable, but length
    // is typically not secret (e.g., MACs have fixed size)
    if (a.size() != b.size()) {
        return false;
    }
    
    // Use volatile to prevent compiler optimizations that might
    // short-circuit the comparison
    volatile uint8_t result = 0;
    
    // CRITICAL: Always iterate through ALL bytes regardless of mismatch
    // Use bitwise OR to accumulate differences (XOR result)
    // No early return inside the loop
    // No conditional based on intermediate XOR values
    for (size_t i = 0; i < a.size(); ++i) {
        result |= a[i] ^ b[i];
    }
    
    // Convert to bool without branching
    // result == 0 means all bytes matched
    return result == 0;
#endif
}

} // namespace Sentinel::Crypto
