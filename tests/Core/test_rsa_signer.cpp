/**
 * @file test_rsa_signer.cpp
 * @brief Unit tests for RSA-PSS signature implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Tests RSA-PSS signing to ensure:
 * - Strong key validation (min 2048 bits, e=65537)
 * - Non-deterministic signatures (random salt)
 * - Tampering detection
 * - Protection against weak keys
 */

#include <Sentinel/Core/Crypto.hpp>
#include "TestHarness.hpp"
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

using namespace Sentinel;
using namespace Sentinel::Crypto;
using namespace Sentinel::Testing;

// ============================================================================
// Helper Functions - Key Generation for Tests
// ============================================================================

/**
 * @brief Generate RSA key pair for testing
 * @param bits Key size in bits
 * @param e Public exponent (default 65537)
 * @return EVP_PKEY* containing the key pair (caller must free)
 */
EVP_PKEY* generateTestKey(int bits, unsigned long e = 65537) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        return nullptr;
    }
    
    if (EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    // Set public exponent
    BIGNUM* bn_e = BN_new();
    if (!bn_e || !BN_set_word(bn_e, e)) {
        BN_free(bn_e);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn_e) != 1) {
        BN_free(bn_e);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    BN_free(bn_e);
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/**
 * @brief Export private key to DER format
 */
ByteBuffer exportPrivateKeyDER(EVP_PKEY* pkey) {
    unsigned char* der = nullptr;
    int len = i2d_PrivateKey(pkey, &der);
    if (len <= 0) {
        return ByteBuffer();
    }
    
    ByteBuffer result(der, der + len);
    OPENSSL_free(der);
    return result;
}

/**
 * @brief Export public key to DER format
 */
ByteBuffer exportPublicKeyDER(EVP_PKEY* pkey) {
    unsigned char* der = nullptr;
    int len = i2d_PUBKEY(pkey, &der);
    if (len <= 0) {
        return ByteBuffer();
    }
    
    ByteBuffer result(der, der + len);
    OPENSSL_free(der);
    return result;
}

// ============================================================================
// Unit Tests - Key Generation and Round Trip
// ============================================================================

TEST(RSASigner, KeyGenerationAndRoundTrip) {
    // Generate 2048-bit RSA key pair
    EVP_PKEY* pkey = generateTestKey(2048);
    ASSERT_NE(pkey, nullptr) << "Failed to generate test key";
    
    // Export keys to DER
    ByteBuffer privateKeyDer = exportPrivateKeyDER(pkey);
    ByteBuffer publicKeyDer = exportPublicKeyDER(pkey);
    ASSERT_FALSE(privateKeyDer.empty()) << "Failed to export private key";
    ASSERT_FALSE(publicKeyDer.empty()) << "Failed to export public key";
    
    // Clean up the original key
    EVP_PKEY_free(pkey);
    
    // Load private key and sign
    RSASigner signer;
    auto loadResult = signer.loadPrivateKey(privateKeyDer);
    ASSERT_TRUE(loadResult.isSuccess()) << "Failed to load private key";
    EXPECT_TRUE(signer.hasPrivateKey()) << "Private key should be loaded";
    
    // Sign test data
    std::string testData = "Test data for signing";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(testData.data()), testData.size());
    
    auto signResult = signer.sign(dataSpan);
    ASSERT_TRUE(signResult.isSuccess()) << "Failed to sign data";
    
    Signature signature = signResult.value();
    EXPECT_GT(signature.size(), 0u) << "Signature should not be empty";
    
    // Load public key and verify
    RSASigner verifier;
    auto loadPubResult = verifier.loadPublicKey(publicKeyDer);
    ASSERT_TRUE(loadPubResult.isSuccess()) << "Failed to load public key";
    EXPECT_TRUE(verifier.hasPublicKey()) << "Public key should be loaded";
    
    auto verifyResult = verifier.verify(dataSpan, signature);
    ASSERT_TRUE(verifyResult.isSuccess()) << "Verification should not error";
    EXPECT_TRUE(verifyResult.value()) << "Signature should be valid";
}

// ============================================================================
// Unit Tests - Reject Weak Keys
// ============================================================================

TEST(RSASigner, Reject1024BitKey) {
    // Generate 1024-bit key (too weak)
    EVP_PKEY* pkey = generateTestKey(1024);
    ASSERT_NE(pkey, nullptr) << "Failed to generate 1024-bit test key";
    
    ByteBuffer privateKeyDer = exportPrivateKeyDER(pkey);
    EVP_PKEY_free(pkey);
    
    ASSERT_FALSE(privateKeyDer.empty()) << "Failed to export 1024-bit key";
    
    // Attempt to load the weak key
    RSASigner signer;
    auto loadResult = signer.loadPrivateKey(privateKeyDer);
    
    ASSERT_TRUE(loadResult.isFailure()) << "Should reject 1024-bit key";
    EXPECT_EQ(loadResult.error(), ErrorCode::WeakKey) << "Should return WeakKey error";
    EXPECT_FALSE(signer.hasPrivateKey()) << "Private key should not be loaded";
}

TEST(RSASigner, RejectLowExponentKey) {
    // Generate key with e=3 (too weak)
    EVP_PKEY* pkey = generateTestKey(2048, 3);
    ASSERT_NE(pkey, nullptr) << "Failed to generate e=3 test key";
    
    ByteBuffer privateKeyDer = exportPrivateKeyDER(pkey);
    EVP_PKEY_free(pkey);
    
    ASSERT_FALSE(privateKeyDer.empty()) << "Failed to export e=3 key";
    
    // Attempt to load the weak key
    RSASigner signer;
    auto loadResult = signer.loadPrivateKey(privateKeyDer);
    
    ASSERT_TRUE(loadResult.isFailure()) << "Should reject e=3 key";
    EXPECT_EQ(loadResult.error(), ErrorCode::WeakKey) << "Should return WeakKey error";
    EXPECT_FALSE(signer.hasPrivateKey()) << "Private key should not be loaded";
}

// ============================================================================
// Unit Tests - Signature Non-Determinism (PSS Random Salt)
// ============================================================================

TEST(RSASigner, SignatureNonDeterminism) {
    // Generate 2048-bit key
    EVP_PKEY* pkey = generateTestKey(2048);
    ASSERT_NE(pkey, nullptr) << "Failed to generate test key";
    
    ByteBuffer privateKeyDer = exportPrivateKeyDER(pkey);
    ByteBuffer publicKeyDer = exportPublicKeyDER(pkey);
    EVP_PKEY_free(pkey);
    
    // Load private key
    RSASigner signer;
    ASSERT_TRUE(signer.loadPrivateKey(privateKeyDer).isSuccess());
    
    // Sign same data twice
    std::string testData = "Same data for both signatures";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(testData.data()), testData.size());
    
    auto signResult1 = signer.sign(dataSpan);
    ASSERT_TRUE(signResult1.isSuccess()) << "First signature failed";
    
    auto signResult2 = signer.sign(dataSpan);
    ASSERT_TRUE(signResult2.isSuccess()) << "Second signature failed";
    
    Signature sig1 = signResult1.value();
    Signature sig2 = signResult2.value();
    
    // Signatures should be different due to random salt in PSS
    EXPECT_NE(sig1, sig2) << "PSS signatures should be non-deterministic";
    
    // But both should verify correctly
    RSASigner verifier;
    ASSERT_TRUE(verifier.loadPublicKey(publicKeyDer).isSuccess());
    
    auto verify1 = verifier.verify(dataSpan, sig1);
    ASSERT_TRUE(verify1.isSuccess() && verify1.value()) << "First signature should verify";
    
    auto verify2 = verifier.verify(dataSpan, sig2);
    ASSERT_TRUE(verify2.isSuccess() && verify2.value()) << "Second signature should verify";
}

// ============================================================================
// Unit Tests - Tampering Detection
// ============================================================================

TEST(RSASigner, TamperingDetection) {
    // Generate key and sign data
    EVP_PKEY* pkey = generateTestKey(2048);
    ASSERT_NE(pkey, nullptr);
    
    ByteBuffer privateKeyDer = exportPrivateKeyDER(pkey);
    ByteBuffer publicKeyDer = exportPublicKeyDER(pkey);
    EVP_PKEY_free(pkey);
    
    RSASigner signer;
    ASSERT_TRUE(signer.loadPrivateKey(privateKeyDer).isSuccess());
    
    std::string testData = "Original data";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(testData.data()), testData.size());
    
    auto signResult = signer.sign(dataSpan);
    ASSERT_TRUE(signResult.isSuccess());
    
    Signature signature = signResult.value();
    
    // Tamper with the signature (flip one bit in the middle)
    ASSERT_GT(signature.size(), 10u) << "Signature should be large enough to modify";
    const size_t tamperIndex = signature.size() / 2;  // Modify middle byte
    signature[tamperIndex] ^= 0x01;  // Flip one bit
    
    // Verification should fail
    RSASigner verifier;
    ASSERT_TRUE(verifier.loadPublicKey(publicKeyDer).isSuccess());
    
    auto verifyResult = verifier.verify(dataSpan, signature);
    ASSERT_TRUE(verifyResult.isSuccess()) << "Verification should not error";
    EXPECT_FALSE(verifyResult.value()) << "Tampered signature should not verify";
}

// ============================================================================
// Unit Tests - Error Handling
// ============================================================================

TEST(RSASigner, SignWithoutKey) {
    RSASigner signer;
    
    std::string testData = "Test data";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(testData.data()), testData.size());
    
    auto signResult = signer.sign(dataSpan);
    ASSERT_TRUE(signResult.isFailure()) << "Sign without key should fail";
    EXPECT_EQ(signResult.error(), ErrorCode::KeyNotLoaded);
}

TEST(RSASigner, VerifyWithoutKey) {
    RSASigner verifier;
    
    std::string testData = "Test data";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(testData.data()), testData.size());
    
    // For a 2048-bit RSA key, signature size is 256 bytes
    constexpr size_t expectedSignatureSize = 256;
    ByteBuffer fakeSignature(expectedSignatureSize, 0x00);  // Fake signature
    
    auto verifyResult = verifier.verify(dataSpan, fakeSignature);
    ASSERT_TRUE(verifyResult.isFailure()) << "Verify without key should fail";
    EXPECT_EQ(verifyResult.error(), ErrorCode::KeyNotLoaded);
}

TEST(RSASigner, InvalidDERFormat) {
    RSASigner signer;
    
    // Invalid DER data
    ByteBuffer invalidDer = {0x30, 0x82, 0xFF, 0xFF};  // Truncated/invalid DER
    
    auto loadResult = signer.loadPrivateKey(invalidDer);
    ASSERT_TRUE(loadResult.isFailure()) << "Loading invalid DER should fail";
    EXPECT_EQ(loadResult.error(), ErrorCode::InvalidKey);
}

// ============================================================================
// Unit Tests - Data Tampering
// ============================================================================

TEST(RSASigner, ModifiedDataFailsVerification) {
    // Generate key and sign data
    EVP_PKEY* pkey = generateTestKey(2048);
    ASSERT_NE(pkey, nullptr);
    
    ByteBuffer privateKeyDer = exportPrivateKeyDER(pkey);
    ByteBuffer publicKeyDer = exportPublicKeyDER(pkey);
    EVP_PKEY_free(pkey);
    
    RSASigner signer;
    ASSERT_TRUE(signer.loadPrivateKey(privateKeyDer).isSuccess());
    
    std::string testData = "Original data";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(testData.data()), testData.size());
    
    auto signResult = signer.sign(dataSpan);
    ASSERT_TRUE(signResult.isSuccess());
    
    Signature signature = signResult.value();
    
    // Modify the data
    std::string modifiedData = "Modified data";
    ByteSpan modifiedSpan(reinterpret_cast<const Byte*>(modifiedData.data()), modifiedData.size());
    
    // Verification with modified data should fail
    RSASigner verifier;
    ASSERT_TRUE(verifier.loadPublicKey(publicKeyDer).isSuccess());
    
    auto verifyResult = verifier.verify(modifiedSpan, signature);
    ASSERT_TRUE(verifyResult.isSuccess()) << "Verification should not error";
    EXPECT_FALSE(verifyResult.value()) << "Modified data should not verify";
}

// ============================================================================
// Unit Tests - Key Size Validation
// ============================================================================

TEST(RSASigner, Accept2048BitKey) {
    // Generate exactly 2048-bit key (minimum acceptable)
    EVP_PKEY* pkey = generateTestKey(2048);
    ASSERT_NE(pkey, nullptr);
    
    ByteBuffer privateKeyDer = exportPrivateKeyDER(pkey);
    EVP_PKEY_free(pkey);
    
    RSASigner signer;
    auto loadResult = signer.loadPrivateKey(privateKeyDer);
    
    EXPECT_TRUE(loadResult.isSuccess()) << "Should accept 2048-bit key";
}

TEST(RSASigner, Accept4096BitKey) {
    // Generate 4096-bit key (stronger)
    EVP_PKEY* pkey = generateTestKey(4096);
    ASSERT_NE(pkey, nullptr);
    
    ByteBuffer privateKeyDer = exportPrivateKeyDER(pkey);
    EVP_PKEY_free(pkey);
    
    RSASigner signer;
    auto loadResult = signer.loadPrivateKey(privateKeyDer);
    
    EXPECT_TRUE(loadResult.isSuccess()) << "Should accept 4096-bit key";
}

// ============================================================================
// Unit Tests - Empty Data
// ============================================================================

TEST(RSASigner, SignEmptyData) {
    // Generate key
    EVP_PKEY* pkey = generateTestKey(2048);
    ASSERT_NE(pkey, nullptr);
    
    ByteBuffer privateKeyDer = exportPrivateKeyDER(pkey);
    ByteBuffer publicKeyDer = exportPublicKeyDER(pkey);
    EVP_PKEY_free(pkey);
    
    RSASigner signer;
    ASSERT_TRUE(signer.loadPrivateKey(privateKeyDer).isSuccess());
    
    // Sign empty data
    ByteSpan emptyData;
    auto signResult = signer.sign(emptyData);
    ASSERT_TRUE(signResult.isSuccess()) << "Should be able to sign empty data";
    
    // Verify
    RSASigner verifier;
    ASSERT_TRUE(verifier.loadPublicKey(publicKeyDer).isSuccess());
    
    auto verifyResult = verifier.verify(emptyData, signResult.value());
    ASSERT_TRUE(verifyResult.isSuccess() && verifyResult.value()) 
        << "Empty data signature should verify";
}
