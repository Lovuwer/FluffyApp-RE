/**
 * @file AESCipher.cpp
 * @brief AES-256-GCM authenticated encryption implementation using OpenSSL EVP API
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Provides authenticated encryption with AES-256-GCM:
 * - 256-bit key (32 bytes)
 * - 96-bit nonce (12 bytes) - automatically generated from CSPRNG
 * - 128-bit authentication tag (16 bytes)
 * - Optional Additional Authenticated Data (AAD)
 * 
 * Security properties:
 * - Confidentiality: Ciphertext reveals nothing about plaintext
 * - Authenticity: Tag verification prevents tampering
 * - Nonce uniqueness: Always generates fresh random nonce per encryption
 * 
 * CRITICAL SECURITY REQUIREMENTS:
 * =================================
 * 
 * 1. NONCE REUSE IS CATASTROPHIC IN AES-GCM
 *    - Reusing a nonce with the same key breaks ALL security properties
 *    - Attackers can recover the authentication key and forge messages
 *    - Attackers can recover plaintext from ciphertexts
 * 
 * 2. KEY LIFETIME CONSTRAINTS
 *    - Keys MUST be ephemeral (single process lifetime only)
 *    - Random nonces are safe ONLY when keys are not reused across restarts
 *    - If persistent keys are needed, implement counter-based or HKDF-derived nonces
 * 
 * 3. NONCE GENERATION STRATEGY
 *    - Current implementation: Cryptographically secure random nonces (96 bits)
 *    - Safe for: Single-process lifetime, ephemeral keys
 *    - Unsafe for: Persistent keys, distributed systems without coordination
 * 
 * 4. RESTART SAFETY
 *    - Process restart with same key = potential nonce collision
 *    - Always generate fresh keys on process startup
 *    - For persistent encryption, use key derivation per session
 * 
 * Defends against:
 * - Ciphertext tampering (GCM authentication tag verified by OpenSSL)
 * - Plaintext recovery without key
 * - Timing attacks (OpenSSL performs constant-time tag verification)
 * - Nonce reuse (prevented by API design - encryptWithNonce is private)
 */

#include <Sentinel/Core/Crypto.hpp>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <algorithm>

namespace Sentinel::Crypto {

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Securely zero memory to prevent sensitive data leakage
 * 
 * Uses compiler barriers to prevent optimization from removing the zeroing.
 * This is critical for key material and other sensitive data.
 */
void secureZero(void* data, size_t size) noexcept {
    if (data == nullptr || size == 0) {
        return;
    }
    
    // Use volatile to prevent compiler optimization
    volatile unsigned char* p = static_cast<volatile unsigned char*>(data);
    while (size--) {
        *p++ = 0;
    }
}

/**
 * @brief Constant-time comparison to prevent timing attacks
 * 
 * Compares two byte arrays without early exit, preventing timing side-channels
 * that could leak information about the data being compared.
 * 
 * **Important usage notes:**
 * - Use for comparing HMAC tags, password hashes, or other non-AEAD MACs
 * - DO NOT use for AES-GCM authentication tags (OpenSSL handles this internally)
 * - OpenSSL's EVP_DecryptFinal_ex performs constant-time AEAD tag verification
 * - Manual AEAD tag comparison bypasses cryptographic library protections
 * 
 * For AES-GCM decryption, always use the decrypt() method which internally
 * calls EVP_DecryptFinal_ex for secure tag verification.
 */
bool constantTimeCompare(ByteSpan a, ByteSpan b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    
    // Use volatile to prevent compiler optimization
    volatile unsigned char result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= a[i] ^ b[i];
    }
    
    return result == 0;
}

// ============================================================================
// AESCipher::Impl - OpenSSL EVP AES-256-GCM implementation
// ============================================================================

class AESCipher::Impl {
public:
    explicit Impl(const AESKey& key)
        : m_key(key)
        , m_rng()
    {
    }
    
    ~Impl() {
        // Securely zero the key to prevent memory leakage
        secureZero(m_key.data(), m_key.size());
    }
    
    Result<ByteBuffer> encrypt(ByteSpan plaintext, ByteSpan associatedData) {
        // Generate random nonce (12 bytes for GCM)
        auto nonceResult = m_rng.generateNonce();
        if (nonceResult.isFailure()) {
            return nonceResult.error();
        }
        
        const AESNonce& nonce = nonceResult.value();
        
        // Perform encryption with nonce
        auto ciphertextResult = encryptWithNonce(plaintext, nonce, associatedData);
        if (ciphertextResult.isFailure()) {
            return ciphertextResult.error();
        }
        
        // Prepend nonce to output: nonce (12) + ciphertext + tag (16)
        ByteBuffer output(12 + ciphertextResult.value().size());
        std::copy(nonce.begin(), nonce.end(), output.begin());
        std::copy(ciphertextResult.value().begin(), ciphertextResult.value().end(), 
                  output.begin() + 12);
        
        return output;
    }
    
    Result<ByteBuffer> decrypt(ByteSpan ciphertext, ByteSpan associatedData) {
        // Minimum size: nonce (12) + tag (16) = 28 bytes
        if (ciphertext.size() < 28) {
            return ErrorCode::InvalidArgument;
        }
        
        // Extract nonce (first 12 bytes)
        AESNonce nonce;
        std::copy(ciphertext.begin(), ciphertext.begin() + 12, nonce.begin());
        
        // Extract ciphertext + tag (remaining bytes)
        ByteSpan ctWithTag{ciphertext.data() + 12, ciphertext.size() - 12};
        
        // Perform decryption with nonce
        return decryptWithNonce(ctWithTag, nonce, associatedData);
    }
    
    Result<ByteBuffer> encryptWithNonce(
        ByteSpan plaintext,
        const AESNonce& nonce,
        ByteSpan associatedData
    ) {
        // Create context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
            return ErrorCode::CryptoError;
        }
        
        // Initialize encryption with AES-256-GCM
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::EncryptionFailed;
        }
        
        // Set IV length (12 bytes for GCM)
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::EncryptionFailed;
        }
        
        // Set key and nonce
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, m_key.data(), nonce.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::EncryptionFailed;
        }
        
        // Set AAD if provided
        if (!associatedData.empty()) {
            int aad_len;
            if (EVP_EncryptUpdate(ctx, nullptr, &aad_len, 
                                 associatedData.data(), 
                                 static_cast<int>(associatedData.size())) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return ErrorCode::EncryptionFailed;
            }
        }
        
        // Allocate output buffer: ciphertext + tag (16 bytes)
        ByteBuffer output(plaintext.size() + 16);
        int len = 0;
        int ciphertext_len = 0;
        
        // Encrypt plaintext
        if (plaintext.size() > 0) {
            if (EVP_EncryptUpdate(ctx, output.data(), &len, 
                                 plaintext.data(), 
                                 static_cast<int>(plaintext.size())) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return ErrorCode::EncryptionFailed;
            }
            ciphertext_len = len;
        }
        
        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, output.data() + ciphertext_len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::EncryptionFailed;
        }
        ciphertext_len += len;
        
        // Get authentication tag (16 bytes)
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, 
                                output.data() + ciphertext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::EncryptionFailed;
        }
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Resize output to actual size (ciphertext + tag)
        output.resize(ciphertext_len + 16);
        return output;
    }
    
    Result<ByteBuffer> decryptWithNonce(
        ByteSpan ciphertext,
        const AESNonce& nonce,
        ByteSpan associatedData
    ) {
        // Minimum size: tag (16 bytes)
        if (ciphertext.size() < 16) {
            return ErrorCode::InvalidArgument;
        }
        
        // Extract tag (last 16 bytes)
        size_t ctLen = ciphertext.size() - 16;
        ByteSpan ct{ciphertext.data(), ctLen};
        ByteSpan tag{ciphertext.data() + ctLen, 16};
        
        // Create context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
            return ErrorCode::CryptoError;
        }
        
        // Initialize decryption with AES-256-GCM
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::DecryptionFailed;
        }
        
        // Set IV length (12 bytes for GCM)
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::DecryptionFailed;
        }
        
        // Set key and nonce
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, m_key.data(), nonce.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::DecryptionFailed;
        }
        
        // Set AAD if provided
        if (!associatedData.empty()) {
            int aad_len;
            if (EVP_DecryptUpdate(ctx, nullptr, &aad_len, 
                                 associatedData.data(), 
                                 static_cast<int>(associatedData.size())) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return ErrorCode::DecryptionFailed;
            }
        }
        
        // Allocate output buffer for plaintext
        ByteBuffer output(ctLen);
        int len = 0;
        int plaintext_len = 0;
        
        // Decrypt ciphertext
        if (ctLen > 0) {
            if (EVP_DecryptUpdate(ctx, output.data(), &len, 
                                 ct.data(), 
                                 static_cast<int>(ctLen)) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return ErrorCode::DecryptionFailed;
            }
            plaintext_len = len;
        }
        
        // Set expected tag value
        // CRITICAL: Must be done BEFORE EVP_DecryptFinal_ex
        // Note: const_cast is required for OpenSSL API compatibility
        // OpenSSL does not modify the tag data when setting it
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, 
                                const_cast<Byte*>(tag.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::DecryptionFailed;
        }
        
        // Finalize and verify authentication tag
        // CRITICAL: If this returns 0, authentication FAILED - return error immediately
        int ret = EVP_DecryptFinal_ex(ctx, output.data() + plaintext_len, &len);
        EVP_CIPHER_CTX_free(ctx);
        
        if (ret != 1) {
            // Authentication failed - return error WITHOUT any plaintext
            secureZero(output.data(), output.size());
            return ErrorCode::AuthenticationFailed;
        }
        
        plaintext_len += len;
        
        // Resize output to actual plaintext size
        output.resize(plaintext_len);
        return output;
    }
    
    void setKey(const AESKey& key) {
        // Securely zero old key
        secureZero(m_key.data(), m_key.size());
        // Set new key
        m_key = key;
    }

private:
    AESKey m_key;
    SecureRandom m_rng;
};

// ============================================================================
// AESCipher - Public API
// ============================================================================

AESCipher::AESCipher(const AESKey& key)
    : m_impl(std::make_unique<Impl>(key)) {
}

AESCipher::AESCipher(ByteSpan key)
    : m_impl(nullptr) {
    // Validate key size
    if (key.size() != 32) {
        throw std::invalid_argument("AES key must be exactly 32 bytes");
    }
    
    // Copy key to AESKey
    AESKey aesKey;
    std::copy(key.begin(), key.end(), aesKey.begin());
    
    m_impl = std::make_unique<Impl>(aesKey);
}

AESCipher::~AESCipher() = default;

Result<ByteBuffer> AESCipher::encrypt(ByteSpan plaintext, ByteSpan associatedData) {
    return m_impl->encrypt(plaintext, associatedData);
}

Result<ByteBuffer> AESCipher::decrypt(ByteSpan ciphertext, ByteSpan associatedData) {
    return m_impl->decrypt(ciphertext, associatedData);
}

Result<ByteBuffer> AESCipher::encryptWithNonce(
    ByteSpan plaintext,
    const AESNonce& nonce,
    ByteSpan associatedData
) {
    return m_impl->encryptWithNonce(plaintext, nonce, associatedData);
}

Result<ByteBuffer> AESCipher::decryptWithNonce(
    ByteSpan ciphertext,
    const AESNonce& nonce,
    ByteSpan associatedData
) {
    return m_impl->decryptWithNonce(ciphertext, nonce, associatedData);
}

void AESCipher::setKey(const AESKey& key) {
    m_impl->setKey(key);
}

// ============================================================================
// Utility Function Exports
// ============================================================================

// These are already implemented above but need to be exported
// for other modules to use

} // namespace Sentinel::Crypto
