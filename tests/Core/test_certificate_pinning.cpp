/**
 * @file test_certificate_pinning.cpp
 * @brief Unit tests for TLS certificate pinning
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/Network.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include "TestHarness.hpp"
#include <gtest/gtest.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace Sentinel;
using namespace Sentinel::Network;
using namespace Sentinel::Crypto;
using namespace Sentinel::Testing;

// ============================================================================
// Test Certificate Generation Helper
// ============================================================================

/**
 * @brief Generate a self-signed test certificate
 * @return DER-encoded certificate
 */
static ByteBuffer generateTestCertificate() {
    // Generate RSA key
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);
    
    BN_free(e);
    
    // Create certificate
    X509* cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 year
    
    X509_set_pubkey(cert, pkey);
    
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (unsigned char*)"Sentinel Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)"test.example.com", -1, -1, 0);
    
    X509_set_issuer_name(cert, name);
    
    // Sign certificate
    X509_sign(cert, pkey, EVP_sha256());
    
    // Convert to DER
    int der_len = i2d_X509(cert, nullptr);
    ByteBuffer cert_der(der_len);
    unsigned char* der_ptr = cert_der.data();
    i2d_X509(cert, &der_ptr);
    
    EVP_PKEY_free(pkey);
    X509_free(cert);
    
    return cert_der;
}

/**
 * @brief Generate a different self-signed test certificate
 * @return DER-encoded certificate
 */
static ByteBuffer generateDifferentTestCertificate() {
    // Generate RSA key with different modulus
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);
    
    BN_free(e);
    
    // Create certificate
    X509* cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    
    X509_set_pubkey(cert, pkey);
    
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (unsigned char*)"Sentinel Test Backup", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)"backup.example.com", -1, -1, 0);
    
    X509_set_issuer_name(cert, name);
    
    // Sign certificate
    X509_sign(cert, pkey, EVP_sha256());
    
    // Convert to DER
    int der_len = i2d_X509(cert, nullptr);
    ByteBuffer cert_der(der_len);
    unsigned char* der_ptr = cert_der.data();
    i2d_X509(cert, &der_ptr);
    
    EVP_PKEY_free(pkey);
    X509_free(cert);
    
    return cert_der;
}

// ============================================================================
// Unit Tests
// ============================================================================

TEST(CertificatePinning, ComputeSPKIHash_ValidCertificate) {
    // Generate test certificate
    ByteBuffer cert_der = generateTestCertificate();
    ASSERT_GT(cert_der.size(), 0u);
    
    // Compute SPKI hash
    auto result = computeSPKIHash(cert_der);
    
    ASSERT_TRUE(result.isSuccess()) << "Failed to compute SPKI hash";
    EXPECT_GT(result.value().size(), 0u) << "Hash should not be empty";
    
    // Verify it's a valid base64 string (length should be multiple of 4 when padded)
    std::string hash = result.value();
    // Base64 of SHA-256 (32 bytes) should be 44 characters (with padding)
    EXPECT_EQ(hash.size(), 44u) << "Base64-encoded SHA-256 should be 44 characters";
}

TEST(CertificatePinning, ComputeSPKIHash_InvalidCertificate) {
    // Invalid certificate data
    ByteBuffer invalid_cert = {0x30, 0x82, 0x00, 0x00};
    
    auto result = computeSPKIHash(invalid_cert);
    
    ASSERT_TRUE(result.isFailure()) << "Should fail on invalid certificate";
    EXPECT_EQ(result.error(), ErrorCode::CertificateInvalid);
}

TEST(CertificatePinning, ComputeSPKIHash_Deterministic) {
    // Generate test certificate
    ByteBuffer cert_der = generateTestCertificate();
    
    // Compute hash twice
    auto result1 = computeSPKIHash(cert_der);
    auto result2 = computeSPKIHash(cert_der);
    
    ASSERT_TRUE(result1.isSuccess());
    ASSERT_TRUE(result2.isSuccess());
    
    // Hashes should be identical
    EXPECT_EQ(result1.value(), result2.value()) 
        << "SPKI hash should be deterministic";
}

TEST(CertificatePinning, PinMatch_ValidCertificate) {
    // Generate test certificate
    ByteBuffer cert_der = generateTestCertificate();
    
    // Compute SPKI hash
    auto hashResult = computeSPKIHash(cert_der);
    ASSERT_TRUE(hashResult.isSuccess());
    
    // Configure pinning
    CertificatePinner pinner;
    PinningConfig config;
    config.hostname = "test.example.com";
    config.pins = {{hashResult.value(), "Primary"}};
    config.enforce = true;
    
    pinner.addPins(config);
    
    // Verify with matching certificate
    std::vector<ByteBuffer> chain = {cert_der};
    auto result = pinner.verify("test.example.com", chain);
    
    ASSERT_TRUE(result.isSuccess()) << "Verification should succeed";
    EXPECT_TRUE(result.value()) << "Pin should match";
}

TEST(CertificatePinning, PinMismatch_DifferentCertificate) {
    // Generate two different certificates
    ByteBuffer cert1_der = generateTestCertificate();
    ByteBuffer cert2_der = generateDifferentTestCertificate();
    
    // Compute SPKI hash of first certificate
    auto hash1Result = computeSPKIHash(cert1_der);
    ASSERT_TRUE(hash1Result.isSuccess());
    
    // Configure pinning with first certificate's hash
    CertificatePinner pinner;
    PinningConfig config;
    config.hostname = "test.example.com";
    config.pins = {{hash1Result.value(), "Primary"}};
    config.enforce = true;
    
    pinner.addPins(config);
    
    // Verify with different certificate
    std::vector<ByteBuffer> chain = {cert2_der};
    auto result = pinner.verify("test.example.com", chain);
    
    ASSERT_TRUE(result.isSuccess()) << "Verification should complete";
    EXPECT_FALSE(result.value()) << "Pin should not match";
}

TEST(CertificatePinning, MultiplePins_BackupMatches) {
    // Generate two different certificates
    ByteBuffer cert1_der = generateTestCertificate();
    ByteBuffer cert2_der = generateDifferentTestCertificate();
    
    // Compute SPKI hashes
    auto hash1Result = computeSPKIHash(cert1_der);
    auto hash2Result = computeSPKIHash(cert2_der);
    ASSERT_TRUE(hash1Result.isSuccess());
    ASSERT_TRUE(hash2Result.isSuccess());
    
    // Configure pinning with both hashes
    CertificatePinner pinner;
    PinningConfig config;
    config.hostname = "test.example.com";
    config.pins = {
        {hash1Result.value(), "Primary"},
        {hash2Result.value(), "Backup"}
    };
    config.enforce = true;
    
    pinner.addPins(config);
    
    // Verify with backup certificate
    std::vector<ByteBuffer> chain = {cert2_der};
    auto result = pinner.verify("test.example.com", chain);
    
    ASSERT_TRUE(result.isSuccess()) << "Verification should succeed";
    EXPECT_TRUE(result.value()) << "Backup pin should match";
}

TEST(CertificatePinning, NoPinsConfigured_AllowByDefault) {
    // Generate test certificate
    ByteBuffer cert_der = generateTestCertificate();
    
    // Create pinner without any pins configured
    CertificatePinner pinner;
    
    // Verify with certificate
    std::vector<ByteBuffer> chain = {cert_der};
    auto result = pinner.verify("unknown.example.com", chain);
    
    ASSERT_TRUE(result.isSuccess()) << "Verification should succeed";
    EXPECT_TRUE(result.value()) << "Should allow when no pins configured";
}

TEST(CertificatePinning, EmptyCertificateChain_ReturnsFailure) {
    // Configure pinning
    CertificatePinner pinner;
    PinningConfig config;
    config.hostname = "test.example.com";
    config.pins = {{"dummy_hash", "Primary"}};
    config.enforce = true;
    
    pinner.addPins(config);
    
    // Verify with empty chain
    std::vector<ByteBuffer> empty_chain;
    auto result = pinner.verify("test.example.com", empty_chain);
    
    ASSERT_TRUE(result.isSuccess()) << "Verification should complete";
    EXPECT_FALSE(result.value()) << "Should fail with empty chain";
}

TEST(CertificatePinning, EnforceFlag_False_AllowsOnMismatch) {
    // Generate two different certificates
    ByteBuffer cert1_der = generateTestCertificate();
    ByteBuffer cert2_der = generateDifferentTestCertificate();
    
    // Compute SPKI hash of first certificate
    auto hash1Result = computeSPKIHash(cert1_der);
    ASSERT_TRUE(hash1Result.isSuccess());
    
    // Configure pinning with enforce = false
    CertificatePinner pinner;
    PinningConfig config;
    config.hostname = "test.example.com";
    config.pins = {{hash1Result.value(), "Primary"}};
    config.enforce = false;  // Don't enforce, just log
    
    pinner.addPins(config);
    
    // Verify with different certificate
    std::vector<ByteBuffer> chain = {cert2_der};
    auto result = pinner.verify("test.example.com", chain);
    
    ASSERT_TRUE(result.isSuccess()) << "Verification should succeed";
    EXPECT_TRUE(result.value()) << "Should allow when enforce=false";
}

TEST(CertificatePinning, ThreadSafety_ConcurrentVerification) {
    // Generate test certificate
    ByteBuffer cert_der = generateTestCertificate();
    
    // Compute SPKI hash
    auto hashResult = computeSPKIHash(cert_der);
    ASSERT_TRUE(hashResult.isSuccess());
    
    // Configure pinning
    CertificatePinner pinner;
    PinningConfig config;
    config.hostname = "test.example.com";
    config.pins = {{hashResult.value(), "Primary"}};
    config.enforce = true;
    
    pinner.addPins(config);
    
    // Launch multiple threads to verify concurrently
    std::vector<std::thread> threads;
    std::atomic<int> successes{0};
    
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&pinner, &cert_der, &successes]() {
            for (int j = 0; j < 100; ++j) {
                std::vector<ByteBuffer> chain = {cert_der};
                auto result = pinner.verify("test.example.com", chain);
                if (result.isSuccess() && result.value()) {
                    successes++;
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // All verifications should succeed
    EXPECT_EQ(successes, 1000) << "All concurrent verifications should succeed";
}

// ============================================================================
// Performance Tests
// ============================================================================

TEST(CertificatePinning, Performance_SPKIHashComputation) {
    ByteBuffer cert_der = generateTestCertificate();
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Compute hash 1000 times
    for (int i = 0; i < 1000; ++i) {
        auto result = computeSPKIHash(cert_der);
        ASSERT_TRUE(result.isSuccess());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Should complete in reasonable time (< 1 second for 1000 operations)
    EXPECT_LT(duration.count(), 1000) 
        << "SPKI hash computation taking too long: " << duration.count() << "ms";
}

TEST(CertificatePinning, Performance_VerificationWithCache) {
    // Generate test certificate
    ByteBuffer cert_der = generateTestCertificate();
    
    // Compute SPKI hash
    auto hashResult = computeSPKIHash(cert_der);
    ASSERT_TRUE(hashResult.isSuccess());
    
    // Configure pinning
    CertificatePinner pinner;
    PinningConfig config;
    config.hostname = "test.example.com";
    config.pins = {{hashResult.value(), "Primary"}};
    config.enforce = true;
    
    pinner.addPins(config);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Verify 10000 times
    for (int i = 0; i < 10000; ++i) {
        std::vector<ByteBuffer> chain = {cert_der};
        auto result = pinner.verify("test.example.com", chain);
        ASSERT_TRUE(result.isSuccess());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Should complete in reasonable time
    EXPECT_LT(duration.count(), 5000) 
        << "Pin verification taking too long: " << duration.count() << "ms";
}
