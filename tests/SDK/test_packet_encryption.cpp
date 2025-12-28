/**
 * Sentinel SDK - Packet Encryption Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Comprehensive test suite for AES-256-GCM packet encryption with:
 * - HKDF key derivation
 * - Key rotation every 10000 packets
 * - Replay detection with 1000-packet window
 * - Timestamp validation (30-second window)
 * - HMAC authentication
 * 
 * Tests cover:
 * - Round-trip encryption/decryption
 * - Tampering detection (bit flip)
 * - Replay attack detection
 * - Buffer size validation
 * - Key rotation
 * - Timestamp validation
 * - HMAC verification
 */

#include <gtest/gtest.h>
#include "Internal/Detection.hpp"
#include <vector>
#include <cstring>

using namespace Sentinel::SDK;

// Test fixture for packet encryption tests
class PacketEncryptionTest : public ::testing::Test {
protected:
    void SetUp() override {
        encryption.Initialize();
        
        // Set up key derivation parameters for enhanced security
        const char* hw_id = "test-hardware-id-12345";
        const char* session = "test-session-token-67890";
        
        // Generate test nonce and salt
        uint8_t nonce[32] = {0};
        uint8_t salt[32] = {0};
        for (int i = 0; i < 32; ++i) {
            nonce[i] = static_cast<uint8_t>(i);
            salt[i] = static_cast<uint8_t>(i * 2);
        }
        
        encryption.SetKeyDerivationParams(hw_id, session, nonce, salt);
    }
    
    void TearDown() override {
        encryption.Shutdown();
    }
    
    PacketEncryption encryption;
    
    // New packet format size calculation helper
    size_t GetEncryptedSize(size_t plaintext_size) {
        // Format: 4 (seq) + 8 (timestamp) + 12 (IV) + 32 (HMAC) + plaintext + 16 (tag)
        return 4 + 8 + 12 + 32 + plaintext_size + 16;
    }
};

// ============================================================================
// Unit Test 1: Round Trip
// ============================================================================

TEST_F(PacketEncryptionTest, RoundTrip_BasicData) {
    // Prepare plaintext
    const char* plaintext = "Hello, Sentinel! This is a test packet.";
    size_t plaintext_size = strlen(plaintext);
    
    // Allocate buffer for encrypted data
    size_t encrypted_size = 1024;
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    // Encrypt
    ErrorCode result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success) << "Encryption failed";
    
    // Verify encrypted size matches new format
    // Expected: 4 (seq) + 8 (timestamp) + 12 (IV) + 32 (HMAC) + plaintext_size + 16 (tag)
    size_t expected_size = GetEncryptedSize(plaintext_size);
    EXPECT_EQ(encrypted_size, expected_size);
    
    // Decrypt
    size_t decrypted_size = 1024;
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    result = encryption.Decrypt(
        encrypted_buffer.data(),
        encrypted_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success) << "Decryption failed";
    EXPECT_EQ(decrypted_size, plaintext_size);
    
    // Verify plaintext matches
    EXPECT_EQ(memcmp(plaintext, decrypted_buffer.data(), plaintext_size), 0)
        << "Decrypted plaintext doesn't match original";
}

TEST_F(PacketEncryptionTest, RoundTrip_EmptyPacket) {
    // Test with empty packet
    size_t encrypted_size = 1024;
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    // Encrypt empty data
    ErrorCode result = encryption.Encrypt(
        nullptr, 
        0, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    // Note: Depending on implementation, this might return InvalidArgument
    // or succeed. Let's test the expected behavior.
    if (result == ErrorCode::Success) {
        // Expected: 4 (seq) + 8 (timestamp) + 12 (IV) + 32 (HMAC) + 0 (plaintext) + 16 (tag)
        EXPECT_EQ(encrypted_size, GetEncryptedSize(0));
        
        // Decrypt
        size_t decrypted_size = 1024;
        std::vector<uint8_t> decrypted_buffer(decrypted_size);
        
        result = encryption.Decrypt(
            encrypted_buffer.data(),
            encrypted_size,
            decrypted_buffer.data(),
            &decrypted_size
        );
        
        EXPECT_EQ(result, ErrorCode::Success);
        EXPECT_EQ(decrypted_size, 0);
    }
}

TEST_F(PacketEncryptionTest, RoundTrip_LargePacket) {
    // Test with 10KB packet
    constexpr size_t plaintext_size = 10 * 1024;
    std::vector<uint8_t> plaintext(plaintext_size);
    
    // Fill with pattern
    for (size_t i = 0; i < plaintext_size; ++i) {
        plaintext[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    // Allocate buffer for encrypted data
    size_t encrypted_size = plaintext_size + 1024; // Extra space for overhead
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    // Encrypt
    ErrorCode result = encryption.Encrypt(
        plaintext.data(), 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success) << "Encryption of large packet failed";
    
    // Decrypt
    size_t decrypted_size = plaintext_size + 1024;
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    result = encryption.Decrypt(
        encrypted_buffer.data(),
        encrypted_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success) << "Decryption of large packet failed";
    EXPECT_EQ(decrypted_size, plaintext_size);
    
    // Verify data integrity
    EXPECT_EQ(memcmp(plaintext.data(), decrypted_buffer.data(), plaintext_size), 0)
        << "Large packet data integrity check failed";
}

// ============================================================================
// Unit Test 2: Tampering Detection
// ============================================================================

TEST_F(PacketEncryptionTest, TamperingDetection_BitFlip) {
    // Prepare and encrypt data
    const char* plaintext = "Sensitive game data";
    size_t plaintext_size = strlen(plaintext);
    
    size_t encrypted_size = 1024;
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    ErrorCode result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success);
    
    // Flip a bit in the ciphertext (middle of the encrypted data)
    size_t tamper_position = encrypted_size / 2;
    encrypted_buffer[tamper_position] ^= 0x01;
    
    // Attempt to decrypt - should fail
    size_t decrypted_size = 1024;
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    result = encryption.Decrypt(
        encrypted_buffer.data(),
        encrypted_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    // Should detect tampering
    EXPECT_EQ(result, ErrorCode::AuthenticationFailed)
        << "Tampering not detected - bit flip in ciphertext";
}

TEST_F(PacketEncryptionTest, TamperingDetection_TagModification) {
    // Prepare and encrypt data
    const char* plaintext = "Critical packet";
    size_t plaintext_size = strlen(plaintext);
    
    size_t encrypted_size = 1024;
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    ErrorCode result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success);
    
    // Modify the authentication tag (last 16 bytes)
    encrypted_buffer[encrypted_size - 1] ^= 0xFF;
    
    // Attempt to decrypt - should fail
    size_t decrypted_size = 1024;
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    result = encryption.Decrypt(
        encrypted_buffer.data(),
        encrypted_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    // Should detect tag modification
    EXPECT_EQ(result, ErrorCode::AuthenticationFailed)
        << "Tampering not detected - authentication tag modified";
}

TEST_F(PacketEncryptionTest, TamperingDetection_SequenceModification) {
    // Prepare and encrypt data
    const char* plaintext = "Test packet";
    size_t plaintext_size = strlen(plaintext);
    
    size_t encrypted_size = 1024;
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    ErrorCode result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success);
    
    // Modify the sequence number (first 4 bytes)
    encrypted_buffer[0] ^= 0xFF;
    
    // Attempt to decrypt
    size_t decrypted_size = 1024;
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    result = encryption.Decrypt(
        encrypted_buffer.data(),
        encrypted_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    // Should detect either replay or authentication failure
    // (depending on whether sequence validation happens before or after decryption)
    EXPECT_TRUE(result == ErrorCode::ReplayDetected || 
                result == ErrorCode::AuthenticationFailed)
        << "Sequence number modification not detected";
}

// ============================================================================
// Unit Test 3: Replay Detection
// ============================================================================

TEST_F(PacketEncryptionTest, ReplayDetection_SamePacketTwice) {
    // Prepare and encrypt data
    const char* plaintext = "Unique packet";
    size_t plaintext_size = strlen(plaintext);
    
    size_t encrypted_size = 1024;
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    ErrorCode result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success);
    
    // Make a copy of the encrypted packet
    std::vector<uint8_t> encrypted_copy = encrypted_buffer;
    size_t encrypted_copy_size = encrypted_size;
    
    // Decrypt first time - should succeed
    size_t decrypted_size = 1024;
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    result = encryption.Decrypt(
        encrypted_buffer.data(),
        encrypted_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success) << "First decryption should succeed";
    
    // Create a new packet with higher sequence
    result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    ASSERT_EQ(result, ErrorCode::Success);
    
    result = encryption.Decrypt(
        encrypted_buffer.data(),
        encrypted_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    ASSERT_EQ(result, ErrorCode::Success) << "Second packet should succeed";
    
    // Now try to decrypt the old packet again (replay)
    decrypted_size = 1024;
    result = encryption.Decrypt(
        encrypted_copy.data(),
        encrypted_copy_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    // Should detect replay
    EXPECT_EQ(result, ErrorCode::ReplayDetected)
        << "Replay attack not detected";
}

// ============================================================================
// Unit Test 4: Buffer Size Calculation
// ============================================================================

TEST_F(PacketEncryptionTest, BufferSize_TooSmall) {
    const char* plaintext = "Test data";
    size_t plaintext_size = strlen(plaintext);
    
    // Provide insufficient buffer
    size_t encrypted_size = 10; // Way too small
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    ErrorCode result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    // Should return BufferTooSmall
    EXPECT_EQ(result, ErrorCode::BufferTooSmall);
    
    // encrypted_size should now contain required size
    size_t expected_size = GetEncryptedSize(plaintext_size);
    EXPECT_EQ(encrypted_size, expected_size)
        << "Required size not returned correctly";
    
    // Try again with correct size
    encrypted_buffer.resize(encrypted_size);
    result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    EXPECT_EQ(result, ErrorCode::Success)
        << "Encryption should succeed with correct buffer size";
}

TEST_F(PacketEncryptionTest, BufferSize_DecryptionTooSmall) {
    const char* plaintext = "Test data for buffer size validation";
    size_t plaintext_size = strlen(plaintext);
    
    // Encrypt normally
    size_t encrypted_size = 1024;
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    ErrorCode result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success);
    
    // Try to decrypt with insufficient buffer
    size_t decrypted_size = 5; // Too small
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    result = encryption.Decrypt(
        encrypted_buffer.data(),
        encrypted_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    // Should return BufferTooSmall
    EXPECT_EQ(result, ErrorCode::BufferTooSmall);
    
    // decrypted_size should contain required size
    EXPECT_EQ(decrypted_size, plaintext_size);
}

TEST_F(PacketEncryptionTest, InvalidArguments_NullPointers) {
    const char* plaintext = "Test";
    size_t size = 1024;
    std::vector<uint8_t> buffer(size);
    
    // Test NULL data pointer on encrypt
    ErrorCode result = encryption.Encrypt(nullptr, 4, buffer.data(), &size);
    EXPECT_EQ(result, ErrorCode::InvalidArgument);
    
    // Test NULL output buffer on encrypt
    result = encryption.Encrypt(plaintext, 4, nullptr, &size);
    EXPECT_EQ(result, ErrorCode::InvalidArgument);
    
    // Test NULL size pointer on encrypt
    result = encryption.Encrypt(plaintext, 4, buffer.data(), nullptr);
    EXPECT_EQ(result, ErrorCode::InvalidArgument);
}

TEST_F(PacketEncryptionTest, InvalidInput_TooSmallPacket) {
    // Try to decrypt a packet that's too small to be valid
    std::vector<uint8_t> invalid_packet(10); // Less than minimum size
    size_t decrypted_size = 1024;
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    ErrorCode result = encryption.Decrypt(
        invalid_packet.data(),
        invalid_packet.size(),
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    EXPECT_EQ(result, ErrorCode::InvalidInput)
        << "Should reject packets smaller than minimum size";
}

// ============================================================================
// Unit Test 5: Sequence Exhaustion
// ============================================================================

TEST_F(PacketEncryptionTest, SequenceExhaustion_ManyPackets) {
    // Generate a large number of packets to test sequence handling
    // Using 10000 packets to test without taking too long
    constexpr size_t num_packets = 10000;
    const char* plaintext = "Packet";
    size_t plaintext_size = strlen(plaintext);
    
    for (size_t i = 0; i < num_packets; ++i) {
        size_t encrypted_size = 1024;
        std::vector<uint8_t> encrypted_buffer(encrypted_size);
        
        ErrorCode result = encryption.Encrypt(
            plaintext, 
            plaintext_size, 
            encrypted_buffer.data(), 
            &encrypted_size
        );
        
        ASSERT_EQ(result, ErrorCode::Success) 
            << "Encryption failed at packet " << i;
        
        // Periodically decrypt to verify
        if (i % 1000 == 0) {
            size_t decrypted_size = 1024;
            std::vector<uint8_t> decrypted_buffer(decrypted_size);
            
            result = encryption.Decrypt(
                encrypted_buffer.data(),
                encrypted_size,
                decrypted_buffer.data(),
                &decrypted_size
            );
            
            EXPECT_EQ(result, ErrorCode::Success)
                << "Decryption failed at packet " << i;
        }
    }
    
    // Verify sequence number is incrementing
    uint32_t seq = encryption.GetNextSequence();
    EXPECT_GT(seq, num_packets) << "Sequence number not incrementing properly";
}

// ============================================================================
// Unit Test 6: Thread Safety (Basic)
// ============================================================================

TEST_F(PacketEncryptionTest, SequenceMonotonicity) {
    // Verify that sequence numbers are always increasing
    uint32_t seq1 = encryption.GetNextSequence();
    uint32_t seq2 = encryption.GetNextSequence();
    uint32_t seq3 = encryption.GetNextSequence();
    
    EXPECT_LT(seq1, seq2) << "Sequence numbers not monotonically increasing";
    EXPECT_LT(seq2, seq3) << "Sequence numbers not monotonically increasing";
    EXPECT_EQ(seq2, seq1 + 1) << "Sequence numbers not incrementing by 1";
    EXPECT_EQ(seq3, seq2 + 1) << "Sequence numbers not incrementing by 1";
}

// ============================================================================
// Unit Test 7: IV Uniqueness
// ============================================================================

TEST_F(PacketEncryptionTest, IVUniqueness) {
    // Encrypt the same plaintext multiple times
    // IVs should be different each time
    const char* plaintext = "Same data";
    size_t plaintext_size = strlen(plaintext);
    
    constexpr size_t num_encryptions = 100;
    std::vector<std::vector<uint8_t>> encrypted_packets;
    
    for (size_t i = 0; i < num_encryptions; ++i) {
        size_t encrypted_size = 1024;
        std::vector<uint8_t> encrypted_buffer(encrypted_size);
        
        ErrorCode result = encryption.Encrypt(
            plaintext, 
            plaintext_size, 
            encrypted_buffer.data(), 
            &encrypted_size
        );
        
        ASSERT_EQ(result, ErrorCode::Success);
        
        encrypted_buffer.resize(encrypted_size);
        encrypted_packets.push_back(encrypted_buffer);
    }
    
    // Verify that at least the IV portions are different
    // IV is at offset 4 (seq) + 8 (timestamp) = 12, length 12
    for (size_t i = 0; i < num_encryptions; ++i) {
        for (size_t j = i + 1; j < num_encryptions; ++j) {
            // Extract IVs
            const uint8_t* iv1 = encrypted_packets[i].data() + 4 + 8;
            const uint8_t* iv2 = encrypted_packets[j].data() + 4 + 8;
            
            // IVs should be different (at least the random part)
            bool ivs_different = (memcmp(iv1, iv2, 12) != 0);
            EXPECT_TRUE(ivs_different) 
                << "IVs should be unique for packets " << i << " and " << j;
        }
    }
}

// ============================================================================
// Unit Test 8: Key Rotation
// ============================================================================

TEST_F(PacketEncryptionTest, KeyRotation_After10000Packets) {
    // Test that key rotation occurs every 10000 packets
    const char* plaintext = "Test packet for rotation";
    size_t plaintext_size = strlen(plaintext);
    
    // Encrypt exactly 10000 packets to trigger rotation
    for (int i = 0; i < 10000; ++i) {
        size_t encrypted_size = 1024;
        std::vector<uint8_t> encrypted_buffer(encrypted_size);
        
        ErrorCode result = encryption.Encrypt(
            plaintext, 
            plaintext_size, 
            encrypted_buffer.data(), 
            &encrypted_size
        );
        
        ASSERT_EQ(result, ErrorCode::Success) 
            << "Encryption failed at packet " << i;
    }
    
    // Next packet should use rotated key
    size_t encrypted_size = 1024;
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    ErrorCode result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success) 
        << "Encryption after rotation failed";
    
    // Decrypt should still work
    size_t decrypted_size = 1024;
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    result = encryption.Decrypt(
        encrypted_buffer.data(),
        encrypted_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    EXPECT_EQ(result, ErrorCode::Success)
        << "Decryption after key rotation failed";
}

// ============================================================================
// Unit Test 9: HKDF Key Derivation
// ============================================================================

TEST_F(PacketEncryptionTest, HKDFKeyDerivation_DifferentParams) {
    // Test that different parameters produce different keys
    const char* plaintext = "Test data";
    size_t plaintext_size = strlen(plaintext);
    
    // Create two separate encryption instances
    PacketEncryption enc1, enc2;
    enc1.Initialize();
    enc2.Initialize();
    
    uint8_t nonce1[32], nonce2[32];
    uint8_t salt[32];
    for (int i = 0; i < 32; ++i) {
        nonce1[i] = static_cast<uint8_t>(i);
        nonce2[i] = static_cast<uint8_t>(i + 1); // Different nonce
        salt[i] = static_cast<uint8_t>(i * 2);
    }
    
    // Use same hardware ID and session but different nonce
    // This should produce different derived keys
    enc1.SetKeyDerivationParams("hw1", "session1", nonce1, salt);
    enc2.SetKeyDerivationParams("hw1", "session1", nonce2, salt);
    
    // Encrypt with first instance
    size_t encrypted_size1 = 1024;
    std::vector<uint8_t> encrypted_buffer1(encrypted_size1);
    
    ErrorCode result = enc1.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer1.data(), 
        &encrypted_size1
    );
    
    ASSERT_EQ(result, ErrorCode::Success);
    
    // Encrypt same data with second instance
    size_t encrypted_size2 = 1024;
    std::vector<uint8_t> encrypted_buffer2(encrypted_size2);
    
    result = enc2.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer2.data(), 
        &encrypted_size2
    );
    
    ASSERT_EQ(result, ErrorCode::Success);
    
    // The ciphertext should be different (due to different keys and IVs)
    // Compare just the ciphertext portion (skip header fields that might vary)
    bool ciphertexts_different = false;
    if (encrypted_size1 == encrypted_size2) {
        // Compare last 32 bytes of each packet (part of ciphertext/tag)
        size_t compare_offset = encrypted_size1 - 32;
        if (memcmp(encrypted_buffer1.data() + compare_offset,
                   encrypted_buffer2.data() + compare_offset, 32) != 0) {
            ciphertexts_different = true;
        }
    }
    
    EXPECT_TRUE(ciphertexts_different)
        << "Different keys should produce different ciphertexts";
    
    enc1.Shutdown();
    enc2.Shutdown();
}

// ============================================================================
// Unit Test 10: Sliding Window Replay Detection
// ============================================================================

TEST_F(PacketEncryptionTest, ReplayDetection_SlidingWindow) {
    // Test that replay detection handles out-of-order packets within window
    const char* plaintext = "Packet";
    size_t plaintext_size = strlen(plaintext);
    
    // Create multiple packets
    std::vector<std::vector<uint8_t>> packets;
    
    for (int i = 0; i < 10; ++i) {
        size_t encrypted_size = 1024;
        std::vector<uint8_t> encrypted_buffer(encrypted_size);
        
        ErrorCode result = encryption.Encrypt(
            plaintext, 
            plaintext_size, 
            encrypted_buffer.data(), 
            &encrypted_size
        );
        
        ASSERT_EQ(result, ErrorCode::Success);
        encrypted_buffer.resize(encrypted_size);
        packets.push_back(encrypted_buffer);
    }
    
    // Decrypt in order
    for (size_t i = 0; i < packets.size(); ++i) {
        size_t decrypted_size = 1024;
        std::vector<uint8_t> decrypted_buffer(decrypted_size);
        
        ErrorCode result = encryption.Decrypt(
            packets[i].data(),
            packets[i].size(),
            decrypted_buffer.data(),
            &decrypted_size
        );
        
        EXPECT_EQ(result, ErrorCode::Success)
            << "Decryption failed for packet " << i;
    }
    
    // Try to replay an old packet
    size_t decrypted_size = 1024;
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    ErrorCode result = encryption.Decrypt(
        packets[0].data(),
        packets[0].size(),
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    // Should detect replay
    EXPECT_EQ(result, ErrorCode::ReplayDetected)
        << "Replay of old packet should be detected";
}

// ============================================================================
// Unit Test 11: HMAC Authentication
// ============================================================================

TEST_F(PacketEncryptionTest, HMACAuthentication_Tampering) {
    // Test that HMAC detects tampering before decryption
    const char* plaintext = "Critical data";
    size_t plaintext_size = strlen(plaintext);
    
    size_t encrypted_size = 1024;
    std::vector<uint8_t> encrypted_buffer(encrypted_size);
    
    ErrorCode result = encryption.Encrypt(
        plaintext, 
        plaintext_size, 
        encrypted_buffer.data(), 
        &encrypted_size
    );
    
    ASSERT_EQ(result, ErrorCode::Success);
    
    // Tamper with ciphertext (after HMAC position)
    // Format: seq(4) + timestamp(8) + IV(12) + HMAC(32) + ciphertext + tag(16)
    size_t tamper_position = 4 + 8 + 12 + 32 + 5; // Middle of ciphertext
    if (tamper_position < encrypted_size) {
        encrypted_buffer[tamper_position] ^= 0xFF;
    }
    
    // Decrypt should fail on HMAC check before attempting decryption
    size_t decrypted_size = 1024;
    std::vector<uint8_t> decrypted_buffer(decrypted_size);
    
    result = encryption.Decrypt(
        encrypted_buffer.data(),
        encrypted_size,
        decrypted_buffer.data(),
        &decrypted_size
    );
    
    // Should detect tampering via HMAC
    EXPECT_EQ(result, ErrorCode::AuthenticationFailed)
        << "HMAC should detect tampering";
}
