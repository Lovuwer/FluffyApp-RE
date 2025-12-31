/**
 * @file test_aes_cipher.cpp
 * @brief Unit tests for AES-256-GCM cipher
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Comprehensive test suite for AES-256-GCM authenticated encryption implementation.
 * Tests cover:
 * - Round-trip encryption/decryption
 * - Empty plaintext handling
 * - AAD binding verification
 * - Bit flip detection
 * - Tag truncation detection
 * - IV uniqueness
 * - Large data handling
 * - NIST test vectors
 */

#include <Sentinel/Core/Crypto.hpp>
#include "TestHarness.hpp"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <set>

using namespace Sentinel;
using namespace Sentinel::Crypto;
using namespace Sentinel::Testing;

// ============================================================================
// Helper Functions (declared in test_crypto.cpp)
// ============================================================================

// These are already defined in test_crypto.cpp
extern ByteBuffer hexToBytes(const std::string& hex);
extern std::string bytesToHex(ByteSpan bytes);

// ============================================================================
// Unit Test 1: Round Trip
// ============================================================================

TEST(AESCipher, RoundTrip_1KB_Plaintext) {
    // Generate random key
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess()) << "Failed to generate AES key";
    
    AESCipher cipher(keyResult.value());
    
    // Generate 1KB random plaintext
    auto plaintextResult = rng.generate(1024);
    ASSERT_TRUE(plaintextResult.isSuccess()) << "Failed to generate plaintext";
    ByteBuffer plaintext = plaintextResult.value();
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintext);
    ASSERT_TRUE(encryptResult.isSuccess()) << "Encryption failed";
    ByteBuffer ciphertext = encryptResult.value();
    
    // Verify output size: IV (12) + plaintext (1024) + tag (16) = 1052
    EXPECT_EQ(ciphertext.size(), 1024 + 12 + 16);
    
    // Decrypt
    auto decryptResult = cipher.decrypt(ciphertext);
    ASSERT_TRUE(decryptResult.isSuccess()) << "Decryption failed";
    ByteBuffer decrypted = decryptResult.value();
    
    // Verify plaintext matches
    EXPECT_EQ(plaintext.size(), decrypted.size());
    EXPECT_EQ(std::memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0)
        << "Decrypted plaintext doesn't match original";
}

// ============================================================================
// Unit Test 2: Empty Plaintext
// ============================================================================

TEST(AESCipher, EmptyPlaintext_RoundTrip) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    // Encrypt empty buffer
    ByteBuffer emptyPlaintext;
    auto encryptResult = cipher.encrypt(emptyPlaintext);
    ASSERT_TRUE(encryptResult.isSuccess()) << "Failed to encrypt empty plaintext";
    
    // Verify output size: IV (12) + tag (16) = 28 bytes
    EXPECT_EQ(encryptResult.value().size(), 12 + 16);
    
    // Decrypt
    auto decryptResult = cipher.decrypt(encryptResult.value());
    ASSERT_TRUE(decryptResult.isSuccess()) << "Failed to decrypt empty ciphertext";
    
    // Verify result is empty
    EXPECT_EQ(decryptResult.value().size(), 0u) << "Decrypted data should be empty";
}

// ============================================================================
// Unit Test 3: AAD Binding
// ============================================================================

TEST(AESCipher, AAD_Binding_MismatchFails) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    ByteBuffer plaintext = {0x01, 0x02, 0x03, 0x04};
    std::string aad1 = "context1";
    std::string aad2 = "context2";
    
    ByteSpan aad1Span(reinterpret_cast<const Byte*>(aad1.data()), aad1.size());
    ByteSpan aad2Span(reinterpret_cast<const Byte*>(aad2.data()), aad2.size());
    
    // Encrypt with AAD = "context1"
    auto encryptResult = cipher.encrypt(plaintext, aad1Span);
    ASSERT_TRUE(encryptResult.isSuccess()) << "Encryption with AAD failed";
    
    // Attempt decrypt with AAD = "context2"
    auto decryptResult = cipher.decrypt(encryptResult.value(), aad2Span);
    
    // Verify authentication failed
    EXPECT_TRUE(decryptResult.isFailure()) << "Decryption should fail with mismatched AAD";
    EXPECT_EQ(decryptResult.error(), ErrorCode::AuthenticationFailed)
        << "Should return AuthenticationFailed error";
}

TEST(AESCipher, AAD_Binding_CorrectAAD_Succeeds) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    ByteBuffer plaintext = {0x01, 0x02, 0x03, 0x04};
    std::string aad = "test-context";
    ByteSpan aadSpan(reinterpret_cast<const Byte*>(aad.data()), aad.size());
    
    // Encrypt with AAD
    auto encryptResult = cipher.encrypt(plaintext, aadSpan);
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Decrypt with same AAD
    auto decryptResult = cipher.decrypt(encryptResult.value(), aadSpan);
    ASSERT_TRUE(decryptResult.isSuccess()) << "Decryption should succeed with correct AAD";
    
    // Verify plaintext matches
    EXPECT_EQ(plaintext, decryptResult.value());
}

// ============================================================================
// Unit Test 4: Bit Flip Detection
// ============================================================================

TEST(AESCipher, BitFlip_InCiphertext_DetectedByTag) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    ByteBuffer plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintext);
    ASSERT_TRUE(encryptResult.isSuccess());
    ByteBuffer ciphertext = encryptResult.value();
    
    // Flip one bit in ciphertext portion (skip IV, before tag)
    // IV is first 12 bytes, tag is last 16 bytes
    size_t flipPosition = 12 + 2; // Flip a bit in the ciphertext portion
    ciphertext[flipPosition] ^= 0x01;
    
    // Attempt decrypt
    auto decryptResult = cipher.decrypt(ciphertext);
    
    // Verify authentication failed
    EXPECT_TRUE(decryptResult.isFailure()) << "Bit flip should be detected";
    EXPECT_EQ(decryptResult.error(), ErrorCode::AuthenticationFailed)
        << "Should return AuthenticationFailed error";
}

TEST(AESCipher, BitFlip_InTag_DetectedByVerification) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    ByteBuffer plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintext);
    ASSERT_TRUE(encryptResult.isSuccess());
    ByteBuffer ciphertext = encryptResult.value();
    
    // Flip one bit in tag (last 16 bytes)
    size_t tagPosition = ciphertext.size() - 8; // Flip a bit in the tag
    ciphertext[tagPosition] ^= 0x80;
    
    // Attempt decrypt
    auto decryptResult = cipher.decrypt(ciphertext);
    
    // Verify authentication failed
    EXPECT_TRUE(decryptResult.isFailure()) << "Tag modification should be detected";
    EXPECT_EQ(decryptResult.error(), ErrorCode::AuthenticationFailed)
        << "Should return AuthenticationFailed error";
}

// ============================================================================
// Unit Test 5: Tag Truncation
// ============================================================================

TEST(AESCipher, TagTruncation_DetectedByLengthCheck) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    ByteBuffer plaintext = {0x01, 0x02, 0x03, 0x04};
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintext);
    ASSERT_TRUE(encryptResult.isSuccess());
    ByteBuffer ciphertext = encryptResult.value();
    
    // Truncate last byte (partial tag)
    ciphertext.pop_back();
    
    // Attempt decrypt
    auto decryptResult = cipher.decrypt(ciphertext);
    
    // Verify input validation error or authentication failure
    // Either is acceptable - size check might pass but tag verification will fail
    EXPECT_TRUE(decryptResult.isFailure()) << "Truncated tag should be rejected";
    EXPECT_TRUE(decryptResult.error() == ErrorCode::InvalidArgument ||
                decryptResult.error() == ErrorCode::AuthenticationFailed)
        << "Should return InvalidArgument or AuthenticationFailed error for truncated input";
}

TEST(AESCipher, TooShortInput_RejectedImmediately) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    // Input smaller than IV + TAG (< 28 bytes)
    ByteBuffer tooShort(20, 0x00);
    
    auto decryptResult = cipher.decrypt(tooShort);
    
    EXPECT_TRUE(decryptResult.isFailure()) << "Too short input should be rejected";
    EXPECT_EQ(decryptResult.error(), ErrorCode::InvalidArgument);
}

// ============================================================================
// Unit Test 6: IV Uniqueness
// ============================================================================

TEST(AESCipher, IVUniqueness_SamePlaintext_DifferentCiphertext) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    ByteBuffer plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    // Encrypt same plaintext twice
    auto encrypt1 = cipher.encrypt(plaintext);
    auto encrypt2 = cipher.encrypt(plaintext);
    
    ASSERT_TRUE(encrypt1.isSuccess());
    ASSERT_TRUE(encrypt2.isSuccess());
    
    // Verify ciphertext differs (due to different IVs)
    EXPECT_NE(encrypt1.value(), encrypt2.value())
        << "Same plaintext encrypted twice should produce different ciphertext";
    
    // Verify IVs are different (first 12 bytes)
    EXPECT_NE(std::memcmp(encrypt1.value().data(), encrypt2.value().data(), 12), 0)
        << "IVs should be different";
    
    // Both should decrypt correctly
    auto decrypt1 = cipher.decrypt(encrypt1.value());
    auto decrypt2 = cipher.decrypt(encrypt2.value());
    
    ASSERT_TRUE(decrypt1.isSuccess());
    ASSERT_TRUE(decrypt2.isSuccess());
    EXPECT_EQ(plaintext, decrypt1.value());
    EXPECT_EQ(plaintext, decrypt2.value());
}

// ============================================================================
// Unit Test 7: Large Data (Adversarial Test)
// ============================================================================

TEST(AESCipher, LargeData_10MB_RoundTrip) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    // Generate 10MB of random data
    constexpr size_t dataSize = 10 * 1024 * 1024;
    auto plaintextResult = rng.generate(dataSize);
    ASSERT_TRUE(plaintextResult.isSuccess()) << "Failed to generate 10MB plaintext";
    ByteBuffer plaintext = plaintextResult.value();
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintext);
    ASSERT_TRUE(encryptResult.isSuccess()) << "Failed to encrypt 10MB data";
    
    // Decrypt
    auto decryptResult = cipher.decrypt(encryptResult.value());
    ASSERT_TRUE(decryptResult.isSuccess()) << "Failed to decrypt 10MB data";
    
    // Verify data matches
    EXPECT_EQ(plaintext.size(), decryptResult.value().size());
    EXPECT_EQ(std::memcmp(plaintext.data(), decryptResult.value().data(), plaintext.size()), 0)
        << "Large data decryption failed to match original";
}

// ============================================================================
// Unit Test 8: NIST Test Vectors (Adversarial Test)
// ============================================================================

// NIST CAVP AES-GCM Test Vector
// From: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
TEST(AESCipher, NIST_TestVector_1) {
    // Test Case 1 from NIST CAVP GCMVS
    // Key (256 bits)
    std::string keyHex = "0000000000000000000000000000000000000000000000000000000000000000";
    AESKey key;
    auto keyBytes = hexToBytes(keyHex);
    std::memcpy(key.data(), keyBytes.data(), 32);
    
    // IV (96 bits)
    std::string ivHex = "000000000000000000000000";
    AESNonce iv;
    auto ivBytes = hexToBytes(ivHex);
    std::memcpy(iv.data(), ivBytes.data(), 12);
    
    // Plaintext (empty)
    ByteBuffer plaintext;
    
    // Expected ciphertext + tag
    std::string expectedTagHex = "530f8afbc74536b9a963b4f1c4cb738b";
    ByteBuffer expectedTag = hexToBytes(expectedTagHex);
    
    AESCipher cipher(key);
    
    // Encrypt with nonce using test accessor
    auto encryptResult = AESCipher::TestAccess::encryptWithNonce(cipher, plaintext, iv);
    ASSERT_TRUE(encryptResult.isSuccess()) << "NIST test vector encryption failed";
    
    // Verify tag matches (ciphertext is empty, so result should be just the tag)
    EXPECT_EQ(encryptResult.value().size(), 16u);
    EXPECT_EQ(bytesToHex(encryptResult.value()), expectedTagHex)
        << "NIST test vector tag mismatch";
    
    // Decrypt and verify using test accessor
    auto decryptResult = AESCipher::TestAccess::decryptWithNonce(cipher, encryptResult.value(), iv);
    ASSERT_TRUE(decryptResult.isSuccess()) << "NIST test vector decryption failed";
    EXPECT_EQ(decryptResult.value().size(), 0u);
}

TEST(AESCipher, NIST_TestVector_2_WithPlaintext) {
    // Test Case with plaintext
    // Key (256 bits)
    std::string keyHex = "0000000000000000000000000000000000000000000000000000000000000000";
    AESKey key;
    auto keyBytes = hexToBytes(keyHex);
    std::memcpy(key.data(), keyBytes.data(), 32);
    
    // IV (96 bits)
    std::string ivHex = "000000000000000000000000";
    AESNonce iv;
    auto ivBytes = hexToBytes(ivHex);
    std::memcpy(iv.data(), ivBytes.data(), 12);
    
    // Plaintext (128 bits / 16 bytes of zeros)
    std::string ptHex = "00000000000000000000000000000000";
    ByteBuffer plaintext = hexToBytes(ptHex);
    
    // Expected ciphertext
    std::string expectedCtHex = "cea7403d4d606b6e074ec5d3baf39d18";
    ByteBuffer expectedCt = hexToBytes(expectedCtHex);
    
    // Expected tag
    std::string expectedTagHex = "d0d1c8a799996bf0265b98b5d48ab919";
    ByteBuffer expectedTag = hexToBytes(expectedTagHex);
    
    AESCipher cipher(key);
    
    // Encrypt with nonce using test accessor
    auto encryptResult = AESCipher::TestAccess::encryptWithNonce(cipher, plaintext, iv);
    ASSERT_TRUE(encryptResult.isSuccess()) << "NIST test vector encryption failed";
    
    // Verify ciphertext and tag
    EXPECT_EQ(encryptResult.value().size(), 16u + 16u); // CT + TAG
    
    // Extract ciphertext and tag
    ByteBuffer actualCt(encryptResult.value().begin(), encryptResult.value().begin() + 16);
    ByteBuffer actualTag(encryptResult.value().begin() + 16, encryptResult.value().end());
    
    EXPECT_EQ(bytesToHex(actualCt), expectedCtHex)
        << "NIST test vector ciphertext mismatch";
    EXPECT_EQ(bytesToHex(actualTag), expectedTagHex)
        << "NIST test vector tag mismatch";
    
    // Decrypt and verify using test accessor
    auto decryptResult = AESCipher::TestAccess::decryptWithNonce(cipher, encryptResult.value(), iv);
    ASSERT_TRUE(decryptResult.isSuccess()) << "NIST test vector decryption failed";
    EXPECT_EQ(bytesToHex(decryptResult.value()), ptHex);
}

// ============================================================================
// Additional Edge Cases and Security Tests
// ============================================================================

TEST(AESCipher, EncryptWithNonce_SameNonce_ProducesSameCiphertext) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    // Generate a fixed nonce
    auto nonceResult = rng.generateNonce();
    ASSERT_TRUE(nonceResult.isSuccess());
    AESNonce nonce = nonceResult.value();
    
    ByteBuffer plaintext = {0x01, 0x02, 0x03, 0x04};
    
    // Encrypt twice with same nonce using test accessor
    auto encrypt1 = AESCipher::TestAccess::encryptWithNonce(cipher, plaintext, nonce);
    auto encrypt2 = AESCipher::TestAccess::encryptWithNonce(cipher, plaintext, nonce);
    
    ASSERT_TRUE(encrypt1.isSuccess());
    ASSERT_TRUE(encrypt2.isSuccess());
    
    // Should produce identical ciphertext (demonstrates importance of nonce uniqueness)
    EXPECT_EQ(encrypt1.value(), encrypt2.value())
        << "Same plaintext with same nonce should produce identical ciphertext";
}

TEST(AESCipher, SetKey_ChangesEncryption) {
    SecureRandom rng;
    auto key1Result = rng.generateAESKey();
    auto key2Result = rng.generateAESKey();
    ASSERT_TRUE(key1Result.isSuccess());
    ASSERT_TRUE(key2Result.isSuccess());
    
    AESCipher cipher(key1Result.value());
    
    ByteBuffer plaintext = {0x01, 0x02, 0x03, 0x04};
    
    // Encrypt with key 1
    auto encrypt1 = cipher.encrypt(plaintext);
    ASSERT_TRUE(encrypt1.isSuccess());
    
    // Change key
    cipher.setKey(key2Result.value());
    
    // Encrypt with key 2 (different key should fail to decrypt previous ciphertext)
    auto decryptResult = cipher.decrypt(encrypt1.value());
    EXPECT_TRUE(decryptResult.isFailure()) 
        << "Decryption with different key should fail";
}

TEST(AESCipher, ThreadSafety_MultipleInstances) {
    // Multiple cipher instances should work independently
    SecureRandom rng;
    auto key1 = rng.generateAESKey();
    auto key2 = rng.generateAESKey();
    ASSERT_TRUE(key1.isSuccess());
    ASSERT_TRUE(key2.isSuccess());
    
    AESCipher cipher1(key1.value());
    AESCipher cipher2(key2.value());
    
    ByteBuffer plaintext = {0x01, 0x02, 0x03, 0x04};
    
    auto encrypt1 = cipher1.encrypt(plaintext);
    auto encrypt2 = cipher2.encrypt(plaintext);
    
    ASSERT_TRUE(encrypt1.isSuccess());
    ASSERT_TRUE(encrypt2.isSuccess());
    
    // Each cipher should only decrypt its own ciphertext
    auto decrypt1 = cipher1.decrypt(encrypt1.value());
    auto decrypt2 = cipher2.decrypt(encrypt2.value());
    
    ASSERT_TRUE(decrypt1.isSuccess());
    ASSERT_TRUE(decrypt2.isSuccess());
    EXPECT_EQ(plaintext, decrypt1.value());
    EXPECT_EQ(plaintext, decrypt2.value());
    
    // Cross-decryption should fail
    auto crossDecrypt1 = cipher1.decrypt(encrypt2.value());
    auto crossDecrypt2 = cipher2.decrypt(encrypt1.value());
    
    EXPECT_TRUE(crossDecrypt1.isFailure());
    EXPECT_TRUE(crossDecrypt2.isFailure());
}

TEST(AESCipher, ConstructFromByteSpan_Works) {
    SecureRandom rng;
    auto keyBytesResult = rng.generate(32);
    ASSERT_TRUE(keyBytesResult.isSuccess());
    
    ByteSpan keySpan(keyBytesResult.value().data(), keyBytesResult.value().size());
    
    // Construct cipher from ByteSpan
    AESCipher cipher(keySpan);
    
    ByteBuffer plaintext = {0x01, 0x02, 0x03, 0x04};
    
    // Encrypt and decrypt
    auto encryptResult = cipher.encrypt(plaintext);
    ASSERT_TRUE(encryptResult.isSuccess());
    
    auto decryptResult = cipher.decrypt(encryptResult.value());
    ASSERT_TRUE(decryptResult.isSuccess());
    EXPECT_EQ(plaintext, decryptResult.value());
}

TEST(AESCipher, ConstructFromByteSpan_InvalidSize_Throws) {
    ByteBuffer shortKey(16, 0x00); // Only 16 bytes, need 32
    ByteSpan shortKeySpan(shortKey.data(), shortKey.size());
    
    // Should throw exception for invalid key size
    EXPECT_THROW({
        AESCipher cipher(shortKeySpan);
    }, std::invalid_argument);
}

// ============================================================================
// Security Test: Nonce Uniqueness Across Many Encryptions
// ============================================================================

TEST(AESCipher, NonceUniqueness_10000Encryptions_AllUnique) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    // Plaintext for testing
    ByteBuffer plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    // Set to track unique nonces using hash of nonce bytes
    std::set<ByteBuffer> uniqueNonces;
    
    // Perform 10,000 encryptions
    // This number is intentionally high to provide strong statistical confidence
    // that nonce generation is truly random and collision-free under normal operation.
    // Even a single collision in 10K iterations would be a critical security vulnerability.
    constexpr size_t iterations = 10000;
    for (size_t i = 0; i < iterations; ++i) {
        auto encryptResult = cipher.encrypt(plaintext);
        ASSERT_TRUE(encryptResult.isSuccess()) << "Encryption failed at iteration " << i;
        
        // Extract nonce (first 12 bytes)
        const auto& ciphertext = encryptResult.value();
        ASSERT_GE(ciphertext.size(), 12u) << "Ciphertext too short at iteration " << i;
        
        ByteBuffer nonce(ciphertext.begin(), ciphertext.begin() + 12);
        
        // Verify this nonce hasn't been used before
        auto insertResult = uniqueNonces.insert(nonce);
        EXPECT_TRUE(insertResult.second) 
            << "Nonce reuse detected at iteration " << i 
            << " - this is a critical security vulnerability!";
    }
    
    // Verify we have exactly 10,000 unique nonces
    EXPECT_EQ(uniqueNonces.size(), iterations)
        << "Expected " << iterations << " unique nonces, but got " << uniqueNonces.size();
}
