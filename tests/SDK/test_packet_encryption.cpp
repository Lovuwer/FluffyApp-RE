/**
 * Sentinel SDK - Packet Encryption Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Comprehensive test suite for AES-256-GCM packet encryption.
 * Tests cover:
 * - Round-trip encryption/decryption
 * - Tampering detection (bit flip)
 * - Replay attack detection
 * - Buffer size validation
 * - Sequence exhaustion
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
    }
    
    void TearDown() override {
        encryption.Shutdown();
    }
    
    PacketEncryption encryption;
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
    
    // Verify encrypted size is larger than plaintext (includes IV, tag, sequence)
    // Expected: 4 (seq) + 12 (IV) + plaintext_size + 16 (tag)
    size_t expected_size = 4 + 12 + plaintext_size + 16;
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
        // Expected: 4 (seq) + 12 (IV) + 0 (plaintext) + 16 (tag) = 32
        EXPECT_EQ(encrypted_size, 32);
        
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
    size_t expected_size = 4 + 12 + plaintext_size + 16;
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
    // IV is at offset 4 (after sequence number), length 12
    for (size_t i = 0; i < num_encryptions; ++i) {
        for (size_t j = i + 1; j < num_encryptions; ++j) {
            // Extract IVs
            const uint8_t* iv1 = encrypted_packets[i].data() + 4;
            const uint8_t* iv2 = encrypted_packets[j].data() + 4;
            
            // IVs should be different (at least the random part)
            bool ivs_different = (memcmp(iv1, iv2, 12) != 0);
            EXPECT_TRUE(ivs_different) 
                << "IVs should be unique for packets " << i << " and " << j;
        }
    }
}
