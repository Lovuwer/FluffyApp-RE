/**
 * @file OpenSSLRAII.hpp
 * @brief RAII wrappers for OpenSSL contexts to prevent resource leaks
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Provides RAII (Resource Acquisition Is Initialization) wrappers for OpenSSL
 * contexts to ensure automatic cleanup on scope exit, including exception paths.
 * 
 * This prevents memory/resource leaks that can accumulate during long game
 * sessions and cause eventual crashes, which would be blamed on anti-cheat.
 * 
 * Design:
 * - Template-based approach for type safety
 * - Non-copyable, moveable for efficiency
 * - Automatic cleanup via destructor
 * - Explicit conversion to raw pointer when needed
 * - Null-safe operations
 * 
 * Usage Pattern:
 * @code
 * // Instead of:
 * EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
 * // ... operations ...
 * EVP_CIPHER_CTX_free(ctx);  // Can be missed on error paths!
 * 
 * // Use:
 * EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
 * // ... operations ...
 * // Automatic cleanup on scope exit, even if exception thrown
 * @endcode
 */

#pragma once

#ifndef SENTINEL_CRYPTO_OPENSSL_RAII_HPP
#define SENTINEL_CRYPTO_OPENSSL_RAII_HPP

#include <openssl/evp.h>
#include <utility>

namespace Sentinel::Crypto {

// ============================================================================
// Generic RAII Wrapper Template
// ============================================================================

/**
 * @brief Generic RAII wrapper for OpenSSL resources
 * 
 * Provides automatic resource management for OpenSSL contexts and objects.
 * The template takes a pointer type and a deleter function.
 * 
 * @tparam T Pointer type (e.g., EVP_CIPHER_CTX*)
 * @tparam Deleter Function pointer type for cleanup
 */
template<typename T, void (*Deleter)(T*)>
class OpenSSLRAII {
public:
    /**
     * @brief Construct from raw pointer (takes ownership)
     * @param ptr Raw pointer to OpenSSL resource (can be nullptr)
     */
    explicit OpenSSLRAII(T* ptr = nullptr) noexcept
        : m_ptr(ptr) {
    }
    
    /**
     * @brief Destructor - automatically frees the resource
     */
    ~OpenSSLRAII() noexcept {
        reset();
    }
    
    // Disable copy operations (RAII should have unique ownership)
    OpenSSLRAII(const OpenSSLRAII&) = delete;
    OpenSSLRAII& operator=(const OpenSSLRAII&) = delete;
    
    /**
     * @brief Move constructor
     * @param other Source wrapper (will be set to nullptr)
     */
    OpenSSLRAII(OpenSSLRAII&& other) noexcept
        : m_ptr(other.m_ptr) {
        other.m_ptr = nullptr;
    }
    
    /**
     * @brief Move assignment
     * @param other Source wrapper (will be set to nullptr)
     * @return Reference to this
     */
    OpenSSLRAII& operator=(OpenSSLRAII&& other) noexcept {
        if (this != &other) {
            reset();
            m_ptr = other.m_ptr;
            other.m_ptr = nullptr;
        }
        return *this;
    }
    
    /**
     * @brief Reset the wrapper with a new pointer, freeing the old one
     * @param ptr New pointer (can be nullptr)
     */
    void reset(T* ptr = nullptr) noexcept {
        if (m_ptr != nullptr) {
            Deleter(m_ptr);
        }
        m_ptr = ptr;
    }
    
    /**
     * @brief Release ownership without freeing
     * @return Raw pointer (caller takes ownership)
     */
    [[nodiscard]] T* release() noexcept {
        T* ptr = m_ptr;
        m_ptr = nullptr;
        return ptr;
    }
    
    /**
     * @brief Get raw pointer (does not transfer ownership)
     * @return Raw pointer (can be nullptr)
     */
    [[nodiscard]] T* get() const noexcept {
        return m_ptr;
    }
    
    /**
     * @brief Check if wrapper holds a valid pointer
     * @return true if pointer is not nullptr
     */
    [[nodiscard]] explicit operator bool() const noexcept {
        return m_ptr != nullptr;
    }
    
    /**
     * @brief Implicit conversion to raw pointer for OpenSSL API calls
     * @return Raw pointer (can be nullptr)
     */
    operator T*() const noexcept {
        return m_ptr;
    }

private:
    T* m_ptr;
};

// ============================================================================
// Specialized RAII Wrappers for OpenSSL Types
// ============================================================================

/**
 * @brief RAII wrapper for EVP_CIPHER_CTX
 * 
 * Used for symmetric encryption/decryption contexts (AES-GCM).
 * Ensures EVP_CIPHER_CTX_free() is called on scope exit.
 * 
 * @example
 * EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
 * if (!ctx) {
 *     return ErrorCode::CryptoError;
 * }
 * EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), key, iv, NULL);
 * // Automatic cleanup on scope exit
 */
using EVPCipherCtxPtr = OpenSSLRAII<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;

/**
 * @brief RAII wrapper for EVP_MD_CTX
 * 
 * Used for message digest (hash) contexts.
 * Ensures EVP_MD_CTX_free() is called on scope exit.
 * 
 * @example
 * EVPMDCtxPtr ctx(EVP_MD_CTX_new());
 * if (!ctx) {
 *     return ErrorCode::CryptoError;
 * }
 * EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
 * // Automatic cleanup on scope exit
 */
using EVPMDCtxPtr = OpenSSLRAII<EVP_MD_CTX, EVP_MD_CTX_free>;

/**
 * @brief RAII wrapper for EVP_MAC_CTX
 * 
 * Used for MAC (HMAC) contexts.
 * Ensures EVP_MAC_CTX_free() is called on scope exit.
 * 
 * @example
 * EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
 * EVPMACCtxPtr ctx(EVP_MAC_CTX_new(mac));
 * if (!ctx) {
 *     return ErrorCode::CryptoError;
 * }
 * // Automatic cleanup on scope exit
 */
using EVPMACCtxPtr = OpenSSLRAII<EVP_MAC_CTX, EVP_MAC_CTX_free>;

/**
 * @brief RAII wrapper for EVP_MAC
 * 
 * Used for MAC algorithm objects.
 * Ensures EVP_MAC_free() is called on scope exit.
 * 
 * @example
 * EVPMACPtr mac(EVP_MAC_fetch(NULL, "HMAC", NULL));
 * if (!mac) {
 *     return ErrorCode::CryptoError;
 * }
 * EVPMACCtxPtr ctx(EVP_MAC_CTX_new(mac));
 * // Automatic cleanup on scope exit
 */
using EVPMACPtr = OpenSSLRAII<EVP_MAC, EVP_MAC_free>;

/**
 * @brief RAII wrapper for EVP_PKEY
 * 
 * Used for public/private key contexts (RSA, EC, etc.).
 * Ensures EVP_PKEY_free() is called on scope exit.
 * 
 * @example
 * EVPPKeyPtr pkey(d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, derKey.size()));
 * if (!pkey) {
 *     return ErrorCode::InvalidKey;
 * }
 * // Automatic cleanup on scope exit
 */
using EVPPKeyPtr = OpenSSLRAII<EVP_PKEY, EVP_PKEY_free>;

} // namespace Sentinel::Crypto

#endif // SENTINEL_CRYPTO_OPENSSL_RAII_HPP
