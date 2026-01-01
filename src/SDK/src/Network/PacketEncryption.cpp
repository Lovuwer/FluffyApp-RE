/**
 * Sentinel SDK - Packet Encryption Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * AES-256-GCM packet encryption with:
 * - HKDF key derivation with server nonce
 * - Key rotation every 10000 packets
 * - Replay detection with 1000-packet window
 * - Timestamp validation (30-second window)
 * - HMAC authentication separate from encryption
 */

#include "Internal/Detection.hpp"
#include <Sentinel/Core/Crypto.hpp>
#include <Sentinel/Core/Crypto/OpenSSLRAII.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <cstring>
#include <mutex>
#include <chrono>

namespace Sentinel {
namespace SDK {

namespace {
    constexpr size_t KEY_SIZE = 32;      // AES-256
    constexpr size_t IV_SIZE = 12;       // GCM standard
    constexpr size_t TAG_SIZE = 16;      // 128-bit auth tag
    constexpr size_t HMAC_SIZE = 32;     // SHA-256 HMAC
    constexpr size_t TIMESTAMP_SIZE = 8; // 64-bit timestamp
    constexpr size_t HEADER_SIZE = sizeof(uint32_t) + TIMESTAMP_SIZE + IV_SIZE + HMAC_SIZE; // seq + timestamp + IV + HMAC
    constexpr const char* HKDF_INFO = "Sentinel Packet Key";
    constexpr size_t HKDF_INFO_LEN = sizeof(HKDF_INFO) - 1;  // -1 to exclude null terminator
    constexpr const char* HMAC_HKDF_INFO = "Sentinel Packet HMAC";
    constexpr size_t HMAC_HKDF_INFO_LEN = sizeof(HMAC_HKDF_INFO) - 1;
    
    // Helper functions for endianness handling
    // Using little-endian for consistency across platforms
    inline void writeUint32LE(uint8_t* buffer, uint32_t value) {
        buffer[0] = static_cast<uint8_t>(value & 0xFF);
        buffer[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
        buffer[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
        buffer[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
    }
    
    inline uint32_t readUint32LE(const uint8_t* buffer) {
        return static_cast<uint32_t>(buffer[0]) |
               (static_cast<uint32_t>(buffer[1]) << 8) |
               (static_cast<uint32_t>(buffer[2]) << 16) |
               (static_cast<uint32_t>(buffer[3]) << 24);
    }
    
    inline void writeUint64LE(uint8_t* buffer, uint64_t value) {
        for (int i = 0; i < 8; ++i) {
            buffer[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
        }
    }
    
    inline uint64_t readUint64LE(const uint8_t* buffer) {
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
            value |= static_cast<uint64_t>(buffer[i]) << (i * 8);
        }
        return value;
    }
    
    // Get current time in milliseconds
    inline uint64_t getCurrentTimeMs() {
        auto now = std::chrono::steady_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    }
}

class PacketEncryptionImpl {
public: 
    void Initialize() {
        // Initialize with temporary key (will be replaced by HKDF derivation)
        if (RAND_bytes(session_key_, KEY_SIZE) != 1) {
            Crypto::secureZero(session_key_, KEY_SIZE);
        }
        if (RAND_bytes(hmac_key_, KEY_SIZE) != 1) {
            Crypto::secureZero(hmac_key_, KEY_SIZE);
        }
        current_sequence_ = 0;
        expected_sequence_ = 0;
        window_base_ = 0;
        packets_since_rotation_ = 0;
        session_start_time_ = getCurrentTimeMs();
        std::memset(window_bitmap_, 0, sizeof(window_bitmap_));
        params_set_ = false;
    }
    
    void Shutdown() {
        // Secure erase keys
        Crypto::secureZero(session_key_, KEY_SIZE);
        Crypto::secureZero(hmac_key_, KEY_SIZE);
        Crypto::secureZero(server_nonce_, sizeof(server_nonce_));
        Crypto::secureZero(server_salt_, sizeof(server_salt_));
        current_sequence_ = 0;
        expected_sequence_ = 0;
        window_base_ = 0;
        packets_since_rotation_ = 0;
        session_start_time_ = 0;
        std::memset(window_bitmap_, 0, sizeof(window_bitmap_));
        params_set_ = false;
    }
    
    void SetKeyDerivationParams(
        const char* hardware_id,
        const char* session_token,
        const uint8_t* server_nonce,
        const uint8_t* server_salt) {
        
        if (hardware_id) hardware_id_ = hardware_id;
        if (session_token) session_token_ = session_token;
        if (server_nonce) std::memcpy(server_nonce_, server_nonce, 32);
        if (server_salt) std::memcpy(server_salt_, server_salt, 32);
        params_set_ = true;
        
        // Derive keys now that we have parameters
        DeriveSessionKey();
    }
    
    void DeriveSessionKey() {
        if (!params_set_) {
            // If params not set, use random keys (fallback for backwards compatibility)
            return;
        }
        
        // Construct master key material: hardware_id || session_token || server_nonce
        std::string master_material = hardware_id_ + session_token_;
        std::vector<uint8_t> master_key(master_material.begin(), master_material.end());
        master_key.insert(master_key.end(), server_nonce_, server_nonce_ + 32);
        
        // Derive session key using HKDF-SHA256
        DeriveKeyHKDF(master_key.data(), master_key.size(), 
                      server_salt_, 32,
                      HKDF_INFO, HKDF_INFO_LEN,
                      session_key_, KEY_SIZE);
        
        // Derive HMAC key using different info string
        DeriveKeyHKDF(master_key.data(), master_key.size(),
                      server_salt_, 32,
                      HMAC_HKDF_INFO, HMAC_HKDF_INFO_LEN,
                      hmac_key_, KEY_SIZE);
        
        // Securely zero the master material
        Crypto::secureZero(master_key.data(), master_key.size());
    }
    
    void RotateKeyIfNeeded() {
        if (packets_since_rotation_ >= KEY_ROTATION_INTERVAL) {
            // Key ratcheting: new_key = HKDF(old_key, counter)
            uint8_t old_key[KEY_SIZE];
            std::memcpy(old_key, session_key_, KEY_SIZE);
            
            // Use packet counter as additional context
            uint8_t counter_bytes[4];
            writeUint32LE(counter_bytes, current_sequence_);
            
            // Ratchet session key
            DeriveKeyHKDF(old_key, KEY_SIZE,
                          counter_bytes, sizeof(counter_bytes),
                          HKDF_INFO, HKDF_INFO_LEN,
                          session_key_, KEY_SIZE);
            
            // Ratchet HMAC key
            std::memcpy(old_key, hmac_key_, KEY_SIZE);
            DeriveKeyHKDF(old_key, KEY_SIZE,
                          counter_bytes, sizeof(counter_bytes),
                          HMAC_HKDF_INFO, HMAC_HKDF_INFO_LEN,
                          hmac_key_, KEY_SIZE);
            
            packets_since_rotation_ = 0;
            
            // Securely zero old key
            Crypto::secureZero(old_key, KEY_SIZE);
        }
    }
    
    bool ValidateTimestamp(uint64_t packet_timestamp) {
        uint64_t current_time = getCurrentTimeMs();
        uint64_t session_elapsed = current_time - session_start_time_;
        
        // Check if timestamp is within acceptable range relative to session start
        if (packet_timestamp > session_elapsed + TIMESTAMP_TOLERANCE_MS) {
            return false;  // Packet from future
        }
        
        if (session_elapsed > packet_timestamp + TIMESTAMP_TOLERANCE_MS) {
            return false;  // Packet too old
        }
        
        return true;
    }
    
    ErrorCode ComputeHMAC(const void* data, size_t size, uint8_t* hmac_out) {
        unsigned int hmac_len = 0;
        unsigned char* result = HMAC(EVP_sha256(), hmac_key_, KEY_SIZE,
                                     static_cast<const unsigned char*>(data), size,
                                     hmac_out, &hmac_len);
        
        if (!result || hmac_len != HMAC_SIZE) {
            return ErrorCode::CryptoError;
        }
        
        return ErrorCode::Success;
    }
    
    ErrorCode VerifyHMAC(const void* data, size_t size, const uint8_t* expected_hmac) {
        uint8_t computed_hmac[HMAC_SIZE];
        ErrorCode result = ComputeHMAC(data, size, computed_hmac);
        
        if (result != ErrorCode::Success) {
            return result;
        }
        
        // Constant-time comparison
        if (!Crypto::constantTimeCompare(
                {computed_hmac, HMAC_SIZE},
                {expected_hmac, HMAC_SIZE})) {
            return ErrorCode::AuthenticationFailed;
        }
        
        return ErrorCode::Success;
    }
    
    bool ValidateSequenceWindow(uint32_t sequence) {
        // Handle sequence number wraparound and window tracking
        
        // If this is a new packet beyond current window, it's valid
        if (sequence > window_base_ + SEQUENCE_WINDOW - 1) {
            // Advance window
            uint32_t shift = sequence - (window_base_ + SEQUENCE_WINDOW - 1);
            
            // Shift bitmap
            if (shift >= SEQUENCE_WINDOW) {
                // Complete window reset
                std::memset(window_bitmap_, 0, sizeof(window_bitmap_));
                window_base_ = sequence;
            } else {
                // Partial shift
                ShiftWindowBitmap(shift);
                window_base_ += shift;
            }
            
            // Mark this sequence as seen
            uint32_t offset = sequence - window_base_;
            window_bitmap_[offset / 8] |= (1 << (offset % 8));
            
            return true;
        }
        
        // Check if sequence is within current window
        if (sequence >= window_base_) {
            uint32_t offset = sequence - window_base_;
            
            // Check if already seen
            if (window_bitmap_[offset / 8] & (1 << (offset % 8))) {
                return false;  // Replay detected
            }
            
            // Mark as seen
            window_bitmap_[offset / 8] |= (1 << (offset % 8));
            return true;
        }
        
        // Sequence is before current window - reject as replay
        return false;
    }
    
    void ShiftWindowBitmap(uint32_t shift) {
        // Shift bitmap left by 'shift' bits
        if (shift >= SEQUENCE_WINDOW) {
            std::memset(window_bitmap_, 0, sizeof(window_bitmap_));
            return;
        }
        
        size_t byte_shift = shift / 8;
        size_t bit_shift = shift % 8;
        
        if (bit_shift == 0) {
            // Simple byte shift
            std::memmove(window_bitmap_, window_bitmap_ + byte_shift,
                        sizeof(window_bitmap_) - byte_shift);
            std::memset(window_bitmap_ + sizeof(window_bitmap_) - byte_shift, 0, byte_shift);
        } else {
            // Complex bit shift
            size_t max_i = sizeof(window_bitmap_) - byte_shift - 1;
            for (size_t i = 0; i < max_i; ++i) {
                window_bitmap_[i] = (window_bitmap_[i + byte_shift] << bit_shift) |
                                   (window_bitmap_[i + byte_shift + 1] >> (8 - bit_shift));
            }
            // Handle last byte separately to avoid out-of-bounds access
            if (max_i < sizeof(window_bitmap_)) {
                window_bitmap_[max_i] = window_bitmap_[max_i + byte_shift] << bit_shift;
            }
            std::memset(window_bitmap_ + sizeof(window_bitmap_) - byte_shift, 0, byte_shift);
        }
    }
    
private:
    void DeriveKeyHKDF(const uint8_t* master_key, size_t master_key_len,
                       const uint8_t* salt, size_t salt_len,
                       const char* info, size_t info_len,
                       uint8_t* out_key, size_t out_key_len) {
        
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
        
        if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
                               EVP_PKEY_CTRL_HKDF_INFO, info_len,
                               (void*)info) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        
        size_t keylen = out_key_len;
        EVP_PKEY_derive(ctx, out_key, &keylen);
        
        EVP_PKEY_CTX_free(ctx);
    }

public:
    uint8_t session_key_[KEY_SIZE];
    uint8_t hmac_key_[KEY_SIZE];
    uint32_t current_sequence_;
    uint32_t expected_sequence_;
    uint32_t packets_since_rotation_;
    uint32_t window_base_;
    uint8_t window_bitmap_[125];
    uint64_t session_start_time_;
    std::string hardware_id_;
    std::string session_token_;
    uint8_t server_nonce_[32];
    uint8_t server_salt_[32];
    bool params_set_;
    std::mutex mutex_;
    
    static constexpr uint32_t KEY_ROTATION_INTERVAL = 10000;
    static constexpr uint32_t SEQUENCE_WINDOW = 1000;
    static constexpr uint64_t TIMESTAMP_TOLERANCE_MS = 30000;
};

static PacketEncryptionImpl g_impl;

void PacketEncryption::Initialize() {
    g_impl.Initialize();
}

void PacketEncryption::Shutdown() {
    g_impl.Shutdown();
}

void PacketEncryption::SetKeyDerivationParams(
    const char* hardware_id,
    const char* session_token,
    const uint8_t* server_nonce,
    const uint8_t* server_salt) {
    g_impl.SetKeyDerivationParams(hardware_id, session_token, server_nonce, server_salt);
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
    
    // Rotate key if needed
    g_impl.RotateKeyIfNeeded();
    
    // Calculate required output size
    // Format: [4-byte sequence][8-byte timestamp][12-byte IV][32-byte HMAC][ciphertext][16-byte tag]
    size_t required_size = sizeof(uint32_t) + TIMESTAMP_SIZE + IV_SIZE + HMAC_SIZE + size + TAG_SIZE;
    
    if (*out_size < required_size) {
        *out_size = required_size;
        return ErrorCode::BufferTooSmall;
    }
    
    uint8_t* output = static_cast<uint8_t*>(out_buffer);
    
    // Write sequence number in little-endian for cross-platform compatibility
    uint32_t seq = ++g_impl.current_sequence_;
    writeUint32LE(output, seq);
    output += sizeof(seq);
    
    // Write timestamp (milliseconds since session start)
    uint64_t timestamp = getCurrentTimeMs() - g_impl.session_start_time_;
    writeUint64LE(output, timestamp);
    output += TIMESTAMP_SIZE;
    
    // Generate IV (include sequence to ensure uniqueness)
    uint8_t iv[IV_SIZE];
    if (RAND_bytes(iv, 8) != 1) {
        return ErrorCode::CryptoError;
    }
    // Embed sequence in last 4 bytes of IV for additional uniqueness (little-endian)
    writeUint32LE(iv + 8, seq);
    
    memcpy(output, iv, IV_SIZE);
    output += IV_SIZE;
    
    // Reserve space for HMAC (will be computed after encryption)
    uint8_t* hmac_position = output;
    output += HMAC_SIZE;
    
    // Encrypt with AES-256-GCM
    Crypto::EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return ErrorCode::CryptoError;
    }
    
    int ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), 
                                  nullptr, g_impl.session_key_, iv);
    if (ret != 1) {
        return ErrorCode::CryptoError;
    }
    
    // Encrypt plaintext
    int outlen = 0;
    ret = EVP_EncryptUpdate(ctx, output, &outlen,
                            static_cast<const uint8_t*>(data), (int)size);
    if (ret != 1) {
        return ErrorCode::CryptoError;
    }
    output += outlen;
    
    // Finalize
    int final_len = 0;
    ret = EVP_EncryptFinal_ex(ctx, output, &final_len);
    if (ret != 1) {
        return ErrorCode::CryptoError;
    }
    output += final_len;
    
    // Get authentication tag
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, output);
    if (ret != 1) {
        return ErrorCode::CryptoError;
    }
    
    // Compute HMAC over entire packet (excluding HMAC field itself)
    // HMAC covers: sequence + timestamp + IV + ciphertext + tag
    // Use stack-allocated buffer to avoid heap allocation
    uint8_t* packet_start = static_cast<uint8_t*>(out_buffer);
    
    // For HMAC computation, we need to combine header + data_after_hmac
    // We can use iovec or just compute on the full buffer excluding HMAC
    // Since the HMAC field is in the middle, we use a temporary approach
    size_t header_size = sizeof(uint32_t) + TIMESTAMP_SIZE + IV_SIZE;
    size_t data_after_hmac_size = size + TAG_SIZE;
    
    // Small optimization: use stack buffer for small packets, heap for large
    uint8_t stack_buffer[2048];
    uint8_t* hmac_input;
    bool use_heap = (header_size + data_after_hmac_size) > sizeof(stack_buffer);
    
    if (use_heap) {
        hmac_input = new uint8_t[header_size + data_after_hmac_size];
    } else {
        hmac_input = stack_buffer;
    }
    
    // Copy header and data after HMAC to contiguous buffer
    memcpy(hmac_input, packet_start, header_size);
    memcpy(hmac_input + header_size, packet_start + header_size + HMAC_SIZE, data_after_hmac_size);
    
    ErrorCode hmac_result = g_impl.ComputeHMAC(hmac_input, header_size + data_after_hmac_size, hmac_position);
    
    if (use_heap) {
        delete[] hmac_input;
    }
    
    if (hmac_result != ErrorCode::Success) {
        return hmac_result;
    }
    
    *out_size = required_size;
    g_impl.packets_since_rotation_++;
    
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
    
    // Minimum size: sequence + timestamp + IV + HMAC + tag (no payload)
    size_t min_size = sizeof(uint32_t) + TIMESTAMP_SIZE + IV_SIZE + HMAC_SIZE + TAG_SIZE;
    if (size < min_size) {
        return ErrorCode::InvalidInput;
    }
    
    const uint8_t* input = static_cast<const uint8_t*>(data);
    
    // Extract sequence number (little-endian for cross-platform compatibility)
    uint32_t seq = readUint32LE(input);
    input += sizeof(seq);
    
    // Extract timestamp
    uint64_t timestamp = readUint64LE(input);
    input += TIMESTAMP_SIZE;
    
    // Extract IV
    uint8_t iv[IV_SIZE];
    memcpy(iv, input, IV_SIZE);
    input += IV_SIZE;
    
    // Extract HMAC
    uint8_t received_hmac[HMAC_SIZE];
    memcpy(received_hmac, input, HMAC_SIZE);
    input += HMAC_SIZE;
    
    // Verify HMAC before attempting decryption
    // HMAC covers: sequence + timestamp + IV + ciphertext + tag
    size_t header_size = sizeof(uint32_t) + TIMESTAMP_SIZE + IV_SIZE;
    size_t data_after_hmac_size = size - header_size - HMAC_SIZE;
    
    // Use stack-allocated buffer for small packets, heap for large
    uint8_t stack_buffer[2048];
    uint8_t* hmac_input;
    bool use_heap = (header_size + data_after_hmac_size) > sizeof(stack_buffer);
    
    if (use_heap) {
        hmac_input = new uint8_t[header_size + data_after_hmac_size];
    } else {
        hmac_input = stack_buffer;
    }
    
    // Copy header and data after HMAC to contiguous buffer
    memcpy(hmac_input, data, header_size);
    memcpy(hmac_input + header_size,
           static_cast<const uint8_t*>(data) + header_size + HMAC_SIZE,
           data_after_hmac_size);
    
    uint8_t computed_hmac[HMAC_SIZE];
    ErrorCode hmac_result = g_impl.ComputeHMAC(hmac_input, header_size + data_after_hmac_size, computed_hmac);
    
    if (use_heap) {
        delete[] hmac_input;
    }
    
    if (hmac_result != ErrorCode::Success) {
        return hmac_result;
    }
    
    // Constant-time comparison
    if (!Crypto::constantTimeCompare(
            {computed_hmac, HMAC_SIZE},
            {received_hmac, HMAC_SIZE})) {
        return ErrorCode::AuthenticationFailed;
    }
    
    // Validate timestamp (anti-replay via time window)
    if (!g_impl.ValidateTimestamp(timestamp)) {
        return ErrorCode::ReplayDetected;
    }
    
    // Validate sequence (anti-replay via sliding window)
    if (!g_impl.ValidateSequenceWindow(seq)) {
        return ErrorCode::ReplayDetected;
    }
    
    // Verify sequence embedded in IV matches header sequence (integrity check, little-endian)
    uint32_t iv_seq = readUint32LE(iv + 8);
    if (iv_seq != seq) {
        // Sequence tampering detected
        return ErrorCode::AuthenticationFailed;
    }
    
    // Calculate ciphertext size
    size_t ciphertext_size = size - sizeof(uint32_t) - TIMESTAMP_SIZE - IV_SIZE - HMAC_SIZE - TAG_SIZE;
    size_t plaintext_size = ciphertext_size;
    
    if (*out_size < plaintext_size) {
        *out_size = plaintext_size;
        return ErrorCode::BufferTooSmall;
    }
    
    // Extract tag (last 16 bytes)
    const uint8_t* tag = static_cast<const uint8_t*>(data) + size - TAG_SIZE;
    
    // Decrypt with AES-256-GCM
    Crypto::EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return ErrorCode::CryptoError;
    }
    
    int ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), 
                                  nullptr, g_impl.session_key_, iv);
    if (ret != 1) {
        return ErrorCode::CryptoError;
    }
    
    // Decrypt ciphertext
    int outlen = 0;
    ret = EVP_DecryptUpdate(ctx, static_cast<uint8_t*>(out_buffer), &outlen,
                            input, (int)ciphertext_size);
    if (ret != 1) {
        return ErrorCode::CryptoError;
    }
    
    // Set expected tag
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, 
                               const_cast<uint8_t*>(tag));
    if (ret != 1) {
        return ErrorCode::CryptoError;
    }
    
    // Finalize and verify tag
    int final_len = 0;
    ret = EVP_DecryptFinal_ex(ctx, 
        static_cast<uint8_t*>(out_buffer) + outlen, &final_len);
    
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
    // Delegate to window-based validation
    return g_impl.ValidateSequenceWindow(sequence);
}

void PacketEncryption::DeriveSessionKey() {
    // This method is now called via SetKeyDerivationParams
    // Kept for backwards compatibility
    g_impl.DeriveSessionKey();
}

void PacketEncryption::RotateKeyIfNeeded() {
    g_impl.RotateKeyIfNeeded();
}

bool PacketEncryption::ValidateTimestamp(uint64_t timestamp) {
    return g_impl.ValidateTimestamp(timestamp);
}

ErrorCode PacketEncryption::ComputeHMAC(const void* data, size_t size, uint8_t* hmac_out) {
    return g_impl.ComputeHMAC(data, size, hmac_out);
}

ErrorCode PacketEncryption::VerifyHMAC(const void* data, size_t size, const uint8_t* expected_hmac) {
    return g_impl.VerifyHMAC(data, size, expected_hmac);
}

} // namespace SDK
} // namespace Sentinel
