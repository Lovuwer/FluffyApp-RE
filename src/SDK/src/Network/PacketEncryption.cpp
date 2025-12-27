/**
 * Sentinel SDK - Packet Encryption Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * AES-256-GCM packet encryption with anti-replay protection
 */

#include "Internal/Detection.hpp"
#include <Sentinel/Core/Crypto.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <cstring>
#include <mutex>

namespace Sentinel {
namespace SDK {

namespace {
    constexpr size_t KEY_SIZE = 32;      // AES-256
    constexpr size_t IV_SIZE = 12;       // GCM standard
    constexpr size_t TAG_SIZE = 16;      // 128-bit auth tag
    constexpr size_t HEADER_SIZE = IV_SIZE + sizeof(uint32_t); // IV + sequence
}

class PacketEncryptionImpl {
public: 
    void Initialize() {
        // Generate session key
        if (RAND_bytes(session_key_, KEY_SIZE) != 1) {
            // Handle error - could throw or set error state
        }
        current_sequence_ = 0;
        expected_sequence_ = 0;
    }
    
    void Shutdown() {
        // Secure erase key
        Crypto::secureZero(session_key_, KEY_SIZE);
        current_sequence_ = 0;
        expected_sequence_ = 0;
    }
    
    void DeriveSessionKey(const uint8_t* master_key, size_t master_key_len,
                          const uint8_t* salt, size_t salt_len) {
        // Use HKDF to derive session key from master key
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!ctx) return;
        
        if (EVP_PKEY_derive_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        
        if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
                               EVP_PKEY_CTRL_HKDF_MD, 0, (void*)EVP_sha256()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        
        if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
                               EVP_PKEY_CTRL_HKDF_KEY, master_key_len,
                               (void*)master_key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        
        if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
                               EVP_PKEY_CTRL_HKDF_SALT, salt_len,
                               (void*)salt) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        
        const unsigned char* info = (const unsigned char*)"Sentinel Packet Key";
        if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
                               EVP_PKEY_CTRL_HKDF_INFO, 19,
                               (void*)info) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        
        size_t keylen = KEY_SIZE;
        EVP_PKEY_derive(ctx, session_key_, &keylen);
        
        EVP_PKEY_CTX_free(ctx);
    }
    
    uint8_t session_key_[KEY_SIZE];
    uint32_t current_sequence_;
    uint32_t expected_sequence_;
    std::mutex mutex_;
};

static PacketEncryptionImpl g_impl;

void PacketEncryption::Initialize() {
    g_impl.Initialize();
}

void PacketEncryption::Shutdown() {
    g_impl.Shutdown();
}

ErrorCode PacketEncryption::Encrypt(
    const void* data, 
    size_t size,
    void* out_buffer, 
    size_t* out_size) {
    
    std::lock_guard<std::mutex> lock(g_impl.mutex_);
    
    if (!data || !out_buffer || !out_size) {
        return ErrorCode::InvalidArgument;
    }
    
    // Calculate required output size
    // Format: [4-byte sequence][12-byte IV][ciphertext][16-byte tag]
    size_t required_size = sizeof(uint32_t) + IV_SIZE + size + TAG_SIZE;
    
    if (*out_size < required_size) {
        *out_size = required_size;
        return ErrorCode::BufferTooSmall;
    }
    
    uint8_t* output = static_cast<uint8_t*>(out_buffer);
    
    // Write sequence number
    uint32_t seq = ++g_impl.current_sequence_;
    memcpy(output, &seq, sizeof(seq));
    output += sizeof(seq);
    
    // Generate IV (include sequence to ensure uniqueness)
    uint8_t iv[IV_SIZE];
    if (RAND_bytes(iv, 8) != 1) {
        return ErrorCode::CryptoError;
    }
    // Embed sequence in last 4 bytes of IV for additional uniqueness
    memcpy(iv + 8, &seq, 4);
    
    memcpy(output, iv, IV_SIZE);
    output += IV_SIZE;
    
    // Encrypt with AES-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return ErrorCode::CryptoError;
    }
    
    int ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), 
                                  nullptr, g_impl.session_key_, iv);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::CryptoError;
    }
    
    // Encrypt plaintext
    int outlen = 0;
    ret = EVP_EncryptUpdate(ctx, output, &outlen,
                            static_cast<const uint8_t*>(data), (int)size);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::CryptoError;
    }
    output += outlen;
    
    // Finalize
    int final_len = 0;
    ret = EVP_EncryptFinal_ex(ctx, output, &final_len);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::CryptoError;
    }
    output += final_len;
    
    // Get authentication tag
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, output);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::CryptoError;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    *out_size = required_size;
    return ErrorCode::Success;
}

ErrorCode PacketEncryption::Decrypt(
    const void* data, 
    size_t size,
    void* out_buffer, 
    size_t* out_size) {
    
    std::lock_guard<std::mutex> lock(g_impl.mutex_);
    
    if (!data || !out_buffer || !out_size) {
        return ErrorCode::InvalidArgument;
    }
    
    // Minimum size: sequence + IV + tag (no payload)
    size_t min_size = sizeof(uint32_t) + IV_SIZE + TAG_SIZE;
    if (size < min_size) {
        return ErrorCode::InvalidInput;
    }
    
    const uint8_t* input = static_cast<const uint8_t*>(data);
    
    // Extract sequence
    uint32_t seq;
    memcpy(&seq, input, sizeof(seq));
    input += sizeof(seq);
    
    // Validate sequence (anti-replay)
    if (!ValidateSequence(seq)) {
        return ErrorCode::ReplayDetected;
    }
    
    // Extract IV
    uint8_t iv[IV_SIZE];
    memcpy(iv, input, IV_SIZE);
    input += IV_SIZE;
    
    // Verify sequence embedded in IV matches header sequence (integrity check)
    uint32_t iv_seq;
    memcpy(&iv_seq, iv + 8, sizeof(iv_seq));
    if (iv_seq != seq) {
        // Sequence tampering detected
        return ErrorCode::AuthenticationFailed;
    }
    
    // Calculate ciphertext size
    size_t ciphertext_size = size - sizeof(uint32_t) - IV_SIZE - TAG_SIZE;
    size_t plaintext_size = ciphertext_size;
    
    if (*out_size < plaintext_size) {
        *out_size = plaintext_size;
        return ErrorCode::BufferTooSmall;
    }
    
    // Extract tag (last 16 bytes)
    const uint8_t* tag = static_cast<const uint8_t*>(data) + size - TAG_SIZE;
    
    // Decrypt with AES-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return ErrorCode::CryptoError;
    }
    
    int ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), 
                                  nullptr, g_impl.session_key_, iv);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::CryptoError;
    }
    
    // Decrypt ciphertext
    int outlen = 0;
    ret = EVP_DecryptUpdate(ctx, static_cast<uint8_t*>(out_buffer), &outlen,
                            input, (int)ciphertext_size);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::CryptoError;
    }
    
    // Set expected tag
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, 
                               const_cast<uint8_t*>(tag));
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::CryptoError;
    }
    
    // Finalize and verify tag
    int final_len = 0;
    ret = EVP_DecryptFinal_ex(ctx, 
        static_cast<uint8_t*>(out_buffer) + outlen, &final_len);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret != 1) {
        // CRITICAL: Zero output buffer on auth failure
        Crypto::secureZero(out_buffer, *out_size);
        return ErrorCode::AuthenticationFailed;
    }
    
    *out_size = outlen + final_len;
    return ErrorCode::Success;
}

uint32_t PacketEncryption::GetNextSequence() {
    std::lock_guard<std::mutex> lock(g_impl.mutex_);
    return ++g_impl.current_sequence_;
}

bool PacketEncryption::ValidateSequence(uint32_t sequence) {
    // Strict anti-replay: only accept sequences > expected
    // This prevents replay attacks but doesn't handle out-of-order delivery
    // For production use with UDP, implement a proper sliding window with a bitmap
    
    if (sequence > g_impl.expected_sequence_) {
        // New sequence - update expected
        g_impl.expected_sequence_ = sequence;
        return true;
    }
    
    // Reject: either equal (replay) or less than expected (old packet)
    return false;
}

void PacketEncryption::DeriveSessionKey() {
    // This method is kept for API compatibility but not used in current implementation
    // Session key is auto-generated in Initialize()
}

} // namespace SDK
} // namespace Sentinel
