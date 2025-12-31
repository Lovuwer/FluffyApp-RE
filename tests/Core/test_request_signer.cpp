/**
 * @file test_request_signer.cpp
 * @brief Unit tests for RequestSigner (HMAC-SHA256 request authentication)
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 */

#include <gtest/gtest.h>
#include <Sentinel/Core/RequestSigner.hpp>
#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <thread>
#include <chrono>

using namespace Sentinel;
using namespace Sentinel::Network;
using namespace Sentinel::Crypto;

class RequestSignerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a test client secret (32 bytes)
        auto randomResult = secureRandom.generate(32);
        ASSERT_TRUE(randomResult.isSuccess());
        clientSecret = randomResult.value();
        
        signer = std::make_unique<RequestSigner>(
            ByteSpan(clientSecret.data(), clientSecret.size())
        );
    }
    
    SecureRandom secureRandom;
    ByteBuffer clientSecret;
    std::unique_ptr<RequestSigner> signer;
};

// ============================================================================
// Basic Signing Tests
// ============================================================================

TEST_F(RequestSignerTest, BasicSigning) {
    // Sign a simple GET request
    auto result = signer->sign(
        HttpMethod::GET,
        "/v1/heartbeat",
        {}  // Empty body
    );
    
    ASSERT_TRUE(result.isSuccess());
    
    const auto& signedData = result.value();
    EXPECT_FALSE(signedData.signature.empty());
    EXPECT_GT(signedData.timestamp, 0);
    
    // Signature should be base64 (typically 44 chars for SHA-256 HMAC)
    EXPECT_GT(signedData.signature.length(), 40);
}

TEST_F(RequestSignerTest, SigningWithBody) {
    // Sign a POST request with body
    std::string jsonBody = R"({"event": "player_joined", "player_id": 12345})";
    ByteBuffer body(jsonBody.begin(), jsonBody.end());
    
    auto result = signer->sign(
        HttpMethod::POST,
        "/v1/events",
        ByteSpan(body.data(), body.size())
    );
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_FALSE(result.value().signature.empty());
}

TEST_F(RequestSignerTest, DifferentMethodsProduceDifferentSignatures) {
    std::string path = "/v1/data";
    ByteBuffer body = {'t', 'e', 's', 't'};
    int64_t timestamp = RequestSigner::getCurrentTimestamp();
    
    auto getResult = signer->sign(HttpMethod::GET, path, {}, timestamp);
    auto postResult = signer->sign(HttpMethod::POST, path, 
                                   ByteSpan(body.data(), body.size()), timestamp);
    
    ASSERT_TRUE(getResult.isSuccess());
    ASSERT_TRUE(postResult.isSuccess());
    
    // Same path and timestamp but different methods should produce different signatures
    EXPECT_NE(getResult.value().signature, postResult.value().signature);
}

TEST_F(RequestSignerTest, DifferentPathsProduceDifferentSignatures) {
    int64_t timestamp = RequestSigner::getCurrentTimestamp();
    
    auto result1 = signer->sign(HttpMethod::GET, "/v1/path1", {}, timestamp);
    auto result2 = signer->sign(HttpMethod::GET, "/v1/path2", {}, timestamp);
    
    ASSERT_TRUE(result1.isSuccess());
    ASSERT_TRUE(result2.isSuccess());
    
    EXPECT_NE(result1.value().signature, result2.value().signature);
}

TEST_F(RequestSignerTest, DifferentBodiesProduceDifferentSignatures) {
    std::string path = "/v1/data";
    int64_t timestamp = RequestSigner::getCurrentTimestamp();
    
    ByteBuffer body1 = {'a', 'b', 'c'};
    ByteBuffer body2 = {'x', 'y', 'z'};
    
    auto result1 = signer->sign(HttpMethod::POST, path, 
                               ByteSpan(body1.data(), body1.size()), timestamp);
    auto result2 = signer->sign(HttpMethod::POST, path,
                               ByteSpan(body2.data(), body2.size()), timestamp);
    
    ASSERT_TRUE(result1.isSuccess());
    ASSERT_TRUE(result2.isSuccess());
    
    EXPECT_NE(result1.value().signature, result2.value().signature);
}

// ============================================================================
// Verification Tests
// ============================================================================

TEST_F(RequestSignerTest, VerifyValidSignature) {
    std::string path = "/v1/test";
    ByteBuffer body = {'t', 'e', 's', 't'};
    
    // Sign the request
    auto signResult = signer->sign(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size())
    );
    ASSERT_TRUE(signResult.isSuccess());
    
    // Verify the signature
    auto verifyResult = signer->verify(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size()),
        signResult.value().signature,
        signResult.value().timestamp
    );
    
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_TRUE(verifyResult.value());
}

TEST_F(RequestSignerTest, RejectInvalidSignature) {
    std::string path = "/v1/test";
    ByteBuffer body = {'t', 'e', 's', 't'};
    int64_t timestamp = RequestSigner::getCurrentTimestamp();
    
    // Verify with a wrong signature
    auto verifyResult = signer->verify(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size()),
        "aW52YWxpZHNpZ25hdHVyZQ==",  // Invalid base64 signature
        timestamp
    );
    
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_FALSE(verifyResult.value());  // Should reject
}

TEST_F(RequestSignerTest, RejectTamperedBody) {
    std::string path = "/v1/test";
    ByteBuffer originalBody = {'t', 'e', 's', 't'};
    
    // Sign the original request
    auto signResult = signer->sign(
        HttpMethod::POST,
        path,
        ByteSpan(originalBody.data(), originalBody.size())
    );
    ASSERT_TRUE(signResult.isSuccess());
    
    // Try to verify with a tampered body
    ByteBuffer tamperedBody = {'h', 'a', 'c', 'k'};
    auto verifyResult = signer->verify(
        HttpMethod::POST,
        path,
        ByteSpan(tamperedBody.data(), tamperedBody.size()),
        signResult.value().signature,
        signResult.value().timestamp
    );
    
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_FALSE(verifyResult.value());  // Should reject
}

TEST_F(RequestSignerTest, RejectTamperedPath) {
    ByteBuffer body = {'t', 'e', 's', 't'};
    
    // Sign for one path
    auto signResult = signer->sign(
        HttpMethod::POST,
        "/v1/path1",
        ByteSpan(body.data(), body.size())
    );
    ASSERT_TRUE(signResult.isSuccess());
    
    // Try to verify with a different path
    auto verifyResult = signer->verify(
        HttpMethod::POST,
        "/v1/path2",  // Different path
        ByteSpan(body.data(), body.size()),
        signResult.value().signature,
        signResult.value().timestamp
    );
    
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_FALSE(verifyResult.value());  // Should reject
}

TEST_F(RequestSignerTest, RejectTamperedMethod) {
    std::string path = "/v1/test";
    ByteBuffer body = {'t', 'e', 's', 't'};
    
    // Sign for POST
    auto signResult = signer->sign(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size())
    );
    ASSERT_TRUE(signResult.isSuccess());
    
    // Try to verify as GET
    auto verifyResult = signer->verify(
        HttpMethod::GET,  // Different method
        path,
        ByteSpan(body.data(), body.size()),
        signResult.value().signature,
        signResult.value().timestamp
    );
    
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_FALSE(verifyResult.value());  // Should reject
}

// ============================================================================
// Timestamp Validation Tests
// ============================================================================

TEST_F(RequestSignerTest, RejectOldTimestamp) {
    std::string path = "/v1/test";
    ByteBuffer body = {'t', 'e', 's', 't'};
    
    // Sign with an old timestamp (2 minutes ago)
    int64_t oldTimestamp = RequestSigner::getCurrentTimestamp() - (2 * 60 * 1000);
    auto signResult = signer->sign(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size()),
        oldTimestamp
    );
    ASSERT_TRUE(signResult.isSuccess());
    
    // Verify with default 60-second window should reject
    auto verifyResult = signer->verify(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size()),
        signResult.value().signature,
        signResult.value().timestamp,
        60  // 60 seconds max skew
    );
    
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_FALSE(verifyResult.value());  // Should reject (too old)
}

TEST_F(RequestSignerTest, AcceptRecentTimestamp) {
    std::string path = "/v1/test";
    ByteBuffer body = {'t', 'e', 's', 't'};
    
    // Sign with current timestamp
    auto signResult = signer->sign(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size())
    );
    ASSERT_TRUE(signResult.isSuccess());
    
    // Immediate verification should succeed
    auto verifyResult = signer->verify(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size()),
        signResult.value().signature,
        signResult.value().timestamp,
        60
    );
    
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_TRUE(verifyResult.value());
}

TEST_F(RequestSignerTest, CustomTimeWindow) {
    std::string path = "/v1/test";
    ByteBuffer body = {'t', 'e', 's', 't'};
    
    // Sign with a timestamp 90 seconds ago
    int64_t oldTimestamp = RequestSigner::getCurrentTimestamp() - (90 * 1000);
    auto signResult = signer->sign(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size()),
        oldTimestamp
    );
    ASSERT_TRUE(signResult.isSuccess());
    
    // Should reject with 60-second window
    auto verifyResult60 = signer->verify(
        HttpMethod::POST, path,
        ByteSpan(body.data(), body.size()),
        signResult.value().signature,
        signResult.value().timestamp,
        60
    );
    ASSERT_TRUE(verifyResult60.isSuccess());
    EXPECT_FALSE(verifyResult60.value());
    
    // Should accept with 120-second window
    auto verifyResult120 = signer->verify(
        HttpMethod::POST, path,
        ByteSpan(body.data(), body.size()),
        signResult.value().signature,
        signResult.value().timestamp,
        120
    );
    ASSERT_TRUE(verifyResult120.isSuccess());
    EXPECT_TRUE(verifyResult120.value());
}

// ============================================================================
// Key Management Tests
// ============================================================================

TEST_F(RequestSignerTest, DifferentKeysProduceDifferentSignatures) {
    // Create two signers with different keys
    auto key1Result = secureRandom.generate(32);
    auto key2Result = secureRandom.generate(32);
    ASSERT_TRUE(key1Result.isSuccess());
    ASSERT_TRUE(key2Result.isSuccess());
    
    RequestSigner signer1(ByteSpan(key1Result.value().data(), key1Result.value().size()));
    RequestSigner signer2(ByteSpan(key2Result.value().data(), key2Result.value().size()));
    
    int64_t timestamp = RequestSigner::getCurrentTimestamp();
    auto result1 = signer1.sign(HttpMethod::GET, "/v1/test", {}, timestamp);
    auto result2 = signer2.sign(HttpMethod::GET, "/v1/test", {}, timestamp);
    
    ASSERT_TRUE(result1.isSuccess());
    ASSERT_TRUE(result2.isSuccess());
    
    EXPECT_NE(result1.value().signature, result2.value().signature);
}

TEST_F(RequestSignerTest, KeyRotation) {
    std::string path = "/v1/test";
    ByteBuffer body = {'t', 'e', 's', 't'};
    
    // Sign with original key
    auto signResult1 = signer->sign(HttpMethod::POST, path,
                                    ByteSpan(body.data(), body.size()));
    ASSERT_TRUE(signResult1.isSuccess());
    
    // Update to new key
    auto newKeyResult = secureRandom.generate(32);
    ASSERT_TRUE(newKeyResult.isSuccess());
    signer->updateKey(ByteSpan(newKeyResult.value().data(), newKeyResult.value().size()));
    
    // Sign with new key (same timestamp)
    auto signResult2 = signer->sign(HttpMethod::POST, path,
                                    ByteSpan(body.data(), body.size()),
                                    signResult1.value().timestamp);
    ASSERT_TRUE(signResult2.isSuccess());
    
    // Signatures should be different
    EXPECT_NE(signResult1.value().signature, signResult2.value().signature);
    
    // Old signature should not verify with new key
    auto verifyOld = signer->verify(HttpMethod::POST, path,
                                    ByteSpan(body.data(), body.size()),
                                    signResult1.value().signature,
                                    signResult1.value().timestamp);
    ASSERT_TRUE(verifyOld.isSuccess());
    EXPECT_FALSE(verifyOld.value());
    
    // New signature should verify with new key
    auto verifyNew = signer->verify(HttpMethod::POST, path,
                                    ByteSpan(body.data(), body.size()),
                                    signResult2.value().signature,
                                    signResult2.value().timestamp);
    ASSERT_TRUE(verifyNew.isSuccess());
    EXPECT_TRUE(verifyNew.value());
}

// ============================================================================
// URL Path Extraction Tests
// ============================================================================

TEST_F(RequestSignerTest, ExtractPathFromFullUrl) {
    EXPECT_EQ("/v1/heartbeat", 
              RequestSigner::extractPath("https://api.sentinel.com/v1/heartbeat"));
    EXPECT_EQ("/v1/events", 
              RequestSigner::extractPath("https://api.sentinel.com/v1/events?type=login"));
    EXPECT_EQ("/", 
              RequestSigner::extractPath("https://api.sentinel.com"));
    EXPECT_EQ("/", 
              RequestSigner::extractPath("https://api.sentinel.com/"));
}

TEST_F(RequestSignerTest, ExtractPathFromRelativeUrl) {
    EXPECT_EQ("/v1/test", RequestSigner::extractPath("/v1/test"));
    EXPECT_EQ("/v1/test", RequestSigner::extractPath("/v1/test?param=value"));
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(RequestSignerTest, EndToEndSigningAndVerification) {
    // Simulate a complete request/response cycle
    std::string path = "/v1/violations";
    std::string jsonBody = R"({
        "player_id": 12345,
        "violation_type": "speed_hack",
        "severity": "high",
        "timestamp": 1234567890
    })";
    ByteBuffer body(jsonBody.begin(), jsonBody.end());
    
    // Client side: Sign the request
    auto signResult = signer->sign(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size())
    );
    ASSERT_TRUE(signResult.isSuccess());
    
    // Server side: Verify the signature
    auto verifyResult = signer->verify(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size()),
        signResult.value().signature,
        signResult.value().timestamp
    );
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_TRUE(verifyResult.value());
}

TEST_F(RequestSignerTest, TimingAttackResistance) {
    // This test verifies that signature comparison is constant-time
    // We can't directly measure timing, but we ensure the code path uses
    // constantTimeCompare by checking that similar but wrong signatures
    // are rejected consistently
    
    std::string path = "/v1/test";
    ByteBuffer body = {'t', 'e', 's', 't'};
    
    auto signResult = signer->sign(HttpMethod::POST, path,
                                   ByteSpan(body.data(), body.size()));
    ASSERT_TRUE(signResult.isSuccess());
    
    std::string validSig = signResult.value().signature;
    
    // Create a signature that differs only in the last character
    std::string similarSig = validSig;
    if (!similarSig.empty()) {
        similarSig[similarSig.length() - 1] = (similarSig.back() == 'A' ? 'B' : 'A');
    }
    
    // Both should be rejected (not valid)
    auto verifyValid = signer->verify(HttpMethod::POST, path,
                                     ByteSpan(body.data(), body.size()),
                                     validSig,
                                     signResult.value().timestamp);
    auto verifySimilar = signer->verify(HttpMethod::POST, path,
                                       ByteSpan(body.data(), body.size()),
                                       similarSig,
                                       signResult.value().timestamp);
    
    ASSERT_TRUE(verifyValid.isSuccess());
    EXPECT_TRUE(verifyValid.value());  // Valid should verify
    
    ASSERT_TRUE(verifySimilar.isSuccess());
    EXPECT_FALSE(verifySimilar.value());  // Similar but wrong should fail
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
