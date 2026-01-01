/**
 * @file AESCipher.cpp
 * @brief AES-256-GCM authenticated encryption implementation using OpenSSL 3.0 EVP API
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Implements authenticated encryption using AES-256-GCM via OpenSSL 3.0 Provider API.
 * Ensures IV uniqueness and proper tag verification to defend against:
 * - Ciphertext forgery
 * - Confidentiality breaches
 * - Replay attacks
 * - Padding oracle attacks (Vaudenay attack)
 * - Chosen ciphertext attacks
 */

#include <Sentinel/Core/Crypto.hpp>
#include <Sentinel/Core/Crypto/OpenSSLRAII.hpp>
#include <Sentinel/Core/Logger.hpp>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>

namespace Sentinel::Crypto {

namespace {
    constexpr size_t AES_256_KEY_SIZE = 32;   // 256 bits
    constexpr size_t AES_GCM_IV_SIZE = 12;    // 96 bits (NIST recommended)
    constexpr size_t AES_GCM_TAG_SIZE = 16;   // 128 bits
}

// ============================================================================
// AESCipher::Impl - Implementation class
// ============================================================================

class AESCipher::Impl {
public:
    explicit Impl(const AESKey& key) {
        static_assert(sizeof(key) == AES_256_KEY_SIZE, "Key must be 256 bits");
        std::memcpy(m_key.data(), key.data(), AES_256_KEY_SIZE);
    }
    
    ~Impl() {
        // Secure erase key material
        secureZero(m_key.data(), m_key.size());
    }
    
    Result<ByteBuffer> encrypt(ByteSpan plaintext, ByteSpan associatedData) {
        // Generate random IV using SecureRandom
        SecureRandom rng;
        auto ivResult = rng.generate(AES_GCM_IV_SIZE);
        if (ivResult.isFailure()) {
            return ivResult.error();
        }
        
        AESNonce iv;
        std::memcpy(iv.data(), ivResult.value().data(), AES_GCM_IV_SIZE);
        
        // Encrypt with the generated IV
        auto encResult = encryptWithNonce(plaintext, iv, associatedData);
        if (encResult.isFailure()) {
            return encResult.error();
        }
        
        // Prepend IV to the result: [IV || Ciphertext || Tag]
        ByteBuffer output;
        output.reserve(AES_GCM_IV_SIZE + encResult.value().size());
        output.insert(output.end(), iv.begin(), iv.end());
        output.insert(output.end(), encResult.value().begin(), encResult.value().end());
        
        return output;
    }
    
    Result<ByteBuffer> decrypt(ByteSpan ciphertext, ByteSpan associatedData) {
        // Validate input size >= IV_SIZE + TAG_SIZE (28 bytes minimum)
        if (ciphertext.size() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) {
            return ErrorCode::InvalidArgument;
        }
        
        // Extract IV from first 12 bytes
        AESNonce iv;
        std::memcpy(iv.data(), ciphertext.data(), AES_GCM_IV_SIZE);
        
        // Remaining data is ciphertext + tag
        ByteSpan ctWithTag = ciphertext.subspan(AES_GCM_IV_SIZE);
        
        return decryptWithNonce(ctWithTag, iv, associatedData);
    }
    
    Result<ByteBuffer> encryptWithNonce(
        ByteSpan plaintext,
        const AESNonce& nonce,
        ByteSpan associatedData
    ) {
        EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            return ErrorCode::CryptoError;
        }
        
        // Allocate output buffer: ciphertext + tag
        ByteBuffer output(plaintext.size() + AES_GCM_TAG_SIZE);
        int len = 0;
        int ciphertext_len = 0;
        
        // Initialize encryption with AES-256-GCM
        if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), m_key.data(), nonce.data(), NULL) != 1) {
            return ErrorCode::EncryptionFailed;
        }
        
        // Set AAD if provided
        if (!associatedData.empty()) {
            if (EVP_EncryptUpdate(ctx, NULL, &len, associatedData.data(), 
                                 static_cast<int>(associatedData.size())) != 1) {
                return ErrorCode::EncryptionFailed;
            }
        }
        
        // Encrypt plaintext
        if (EVP_EncryptUpdate(ctx, output.data(), &len, plaintext.data(), 
                             static_cast<int>(plaintext.size())) != 1) {
            return ErrorCode::EncryptionFailed;
        }
        ciphertext_len = len;
        
        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, output.data() + len, &len) != 1) {
            return ErrorCode::EncryptionFailed;
        }
        ciphertext_len += len;
        
        // Get authentication tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, 
                               output.data() + ciphertext_len) != 1) {
            return ErrorCode::EncryptionFailed;
        }
        
        // Success - resize output to actual size
        output.resize(ciphertext_len + AES_GCM_TAG_SIZE);
        return output;
    }
    
    Result<ByteBuffer> decryptWithNonce(
        ByteSpan ciphertext,
        const AESNonce& nonce,
        ByteSpan associatedData
    ) {
        // Validate input size >= TAG_SIZE (16 bytes minimum)
        if (ciphertext.size() < AES_GCM_TAG_SIZE) {
            return ErrorCode::InvalidArgument;
        }
        
        EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            return ErrorCode::CryptoError;
        }
        
        // Extract tag from last 16 bytes
        size_t ct_len = ciphertext.size() - AES_GCM_TAG_SIZE;
        const Byte* tag = ciphertext.data() + ct_len;
        
        // Allocate output buffer for plaintext
        ByteBuffer plaintext(ct_len);
        int len = 0;
        int plaintext_len = 0;
        
        // Initialize decryption with AES-256-GCM
        if (EVP_DecryptInit_ex2(ctx, EVP_aes_256_gcm(), m_key.data(), nonce.data(), NULL) != 1) {
            return ErrorCode::DecryptionFailed;
        }
        
        // Set expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, 
                               const_cast<Byte*>(tag)) != 1) {
            return ErrorCode::DecryptionFailed;
        }
        
        // Set AAD if provided
        if (!associatedData.empty()) {
            if (EVP_DecryptUpdate(ctx, NULL, &len, associatedData.data(), 
                                 static_cast<int>(associatedData.size())) != 1) {
                return ErrorCode::DecryptionFailed;
            }
        }
        
        // Decrypt ciphertext
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), 
                             static_cast<int>(ct_len)) != 1) {
            return ErrorCode::DecryptionFailed;
        }
        plaintext_len = len;
        
        // CRITICAL VERIFICATION: Finalize and verify tag
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        
        if (ret <= 0) {
            // Tag verification failed - immediately zero plaintext buffer
            secureZero(plaintext.data(), plaintext.size());
            SENTINEL_LOG_ERROR("AES-GCM authentication tag verification failed");
            return ErrorCode::AuthenticationFailed;
        }
        
        plaintext_len += len;
        
        // Success - resize output to actual size
        plaintext.resize(plaintext_len);
        return plaintext;
    }
    
    void setKey(const AESKey& key) {
        secureZero(m_key.data(), m_key.size());
        std::memcpy(m_key.data(), key.data(), AES_256_KEY_SIZE);
    }
    
private:
    AESKey m_key;
};

// ============================================================================
// AESCipher - Public API
// ============================================================================

AESCipher::AESCipher(const AESKey& key)
    : m_impl(std::make_unique<Impl>(key)) {
}

AESCipher::AESCipher(ByteSpan key)
    : m_impl(nullptr) {
    if (key.size() != AES_256_KEY_SIZE) {
        throw std::invalid_argument("AES key must be 32 bytes");
    }
    
    AESKey aesKey;
    std::memcpy(aesKey.data(), key.data(), AES_256_KEY_SIZE);
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

} // namespace Sentinel::Crypto
