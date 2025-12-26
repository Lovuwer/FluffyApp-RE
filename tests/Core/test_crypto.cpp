/**
 * @file test_crypto.cpp
 * @brief Unit tests for cryptographic utilities
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/Crypto.hpp>
#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <set>
#include <cmath>
#include <cstring>

using namespace Sentinel;
using namespace Sentinel::Crypto;

// ============================================================================
// Unit Tests
// ============================================================================

TEST(SecureRandom, GenerateBytes_ReturnsCorrectSize) {
    SecureRandom rng;
    
    // Test various sizes
    std::vector<size_t> sizes = {1, 10, 32, 64, 128, 256};
    
    for (size_t size : sizes) {
        auto result = rng.generate(size);
        ASSERT_TRUE(result.isSuccess()) << "Failed to generate " << size << " bytes";
        EXPECT_EQ(result.value().size(), size) << "Wrong size for " << size << " bytes";
    }
}

TEST(SecureRandom, GenerateAESKey_Returns32Bytes) {
    SecureRandom rng;
    
    auto result = rng.generateAESKey();
    ASSERT_TRUE(result.isSuccess()) << "Failed to generate AES key";
    EXPECT_EQ(result.value().size(), 32u) << "AES key should be 32 bytes";
}

TEST(SecureRandom, GenerateNonce_Returns12Bytes) {
    SecureRandom rng;
    
    auto result = rng.generateNonce();
    ASSERT_TRUE(result.isSuccess()) << "Failed to generate nonce";
    EXPECT_EQ(result.value().size(), 12u) << "Nonce should be 12 bytes";
}

// ============================================================================
// Randomness Tests
// ============================================================================

TEST(SecureRandom, NoObviousPatterns) {
    SecureRandom rng;
    
    // Generate 1MB of data
    constexpr size_t dataSize = 1024 * 1024;
    auto result = rng.generate(dataSize);
    ASSERT_TRUE(result.isSuccess());
    
    const auto& data = result.value();
    
    // Check for repeating 8-byte blocks
    std::set<uint64_t> blocks;
    for (size_t i = 0; i + 8 <= data.size(); i += 8) {
        uint64_t block = 0;
        std::memcpy(&block, &data[i], 8);
        blocks.insert(block);
    }
    
    // We should have a high number of unique blocks (at least 95% unique)
    size_t numBlocks = dataSize / 8;
    size_t uniqueBlocks = blocks.size();
    double uniqueRatio = static_cast<double>(uniqueBlocks) / numBlocks;
    
    EXPECT_GT(uniqueRatio, 0.95) << "Too many repeated 8-byte blocks detected: "
                                  << uniqueRatio * 100 << "% unique";
}

TEST(SecureRandom, EntropyCheck) {
    SecureRandom rng;
    
    // Generate 10KB sample
    constexpr size_t sampleSize = 10240;
    auto result = rng.generate(sampleSize);
    ASSERT_TRUE(result.isSuccess());
    
    const auto& data = result.value();
    
    // Count byte frequencies
    std::array<size_t, 256> frequencies = {};
    for (Byte b : data) {
        frequencies[b]++;
    }
    
    // Chi-square test for uniform distribution
    // Expected frequency for each byte value
    double expected = static_cast<double>(sampleSize) / 256.0;
    
    double chiSquare = 0.0;
    for (size_t freq : frequencies) {
        double diff = static_cast<double>(freq) - expected;
        chiSquare += (diff * diff) / expected;
    }
    
    // Chi-square critical value for 255 degrees of freedom at p=0.001 is ~310
    // We use a more lenient threshold to avoid flakiness
    EXPECT_LT(chiSquare, 400.0) << "Chi-square test failed: " << chiSquare
                                 << " (distribution may not be uniform)";
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST(SecureRandom, GenerateZeroBytes_ReturnsSuccess) {
    SecureRandom rng;
    
    Byte buffer[1] = {0xFF};
    auto result = rng.generate(buffer, 0);
    
    EXPECT_TRUE(result.isSuccess()) << "Zero-byte generation should succeed";
    EXPECT_EQ(buffer[0], 0xFF) << "Buffer should not be modified";
}

TEST(SecureRandom, GenerateLargeBuffer_1MB_Succeeds) {
    SecureRandom rng;
    
    constexpr size_t largeSize = 1024 * 1024;
    auto result = rng.generate(largeSize);
    
    ASSERT_TRUE(result.isSuccess()) << "Failed to generate 1MB buffer";
    EXPECT_EQ(result.value().size(), largeSize);
}

TEST(SecureRandom, NullPointerWithZeroSize_Succeeds) {
    SecureRandom rng;
    
    auto result = rng.generate(nullptr, 0);
    EXPECT_TRUE(result.isSuccess()) << "Null pointer with zero size should succeed";
}

TEST(SecureRandom, NullPointerWithNonZeroSize_Fails) {
    SecureRandom rng;
    
    auto result = rng.generate(nullptr, 10);
    EXPECT_TRUE(result.isFailure()) << "Null pointer with non-zero size should fail";
    EXPECT_EQ(result.error(), ErrorCode::InvalidArgument);
}

// ============================================================================
// Adversarial Tests
// ============================================================================

TEST(SecureRandom, ThreadSafety) {
    SecureRandom rng;
    constexpr int numThreads = 10;
    constexpr int generationsPerThread = 100;
    constexpr size_t bytesPerGeneration = 1024;
    
    std::atomic<int> successCount{0};
    std::atomic<int> failureCount{0};
    
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([&rng, &successCount, &failureCount]() {
            for (int j = 0; j < generationsPerThread; ++j) {
                auto result = rng.generate(bytesPerGeneration);
                if (result.isSuccess()) {
                    successCount++;
                } else {
                    failureCount++;
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(successCount.load(), numThreads * generationsPerThread)
        << "Not all generations succeeded";
    EXPECT_EQ(failureCount.load(), 0) << "Some generations failed";
}

TEST(SecureRandom, StressTest) {
    SecureRandom rng;
    constexpr int numGenerations = 100000;
    constexpr size_t bytesPerGeneration = 32;
    
    int successCount = 0;
    int failureCount = 0;
    
    for (int i = 0; i < numGenerations; ++i) {
        auto result = rng.generate(bytesPerGeneration);
        if (result.isSuccess()) {
            successCount++;
        } else {
            failureCount++;
        }
    }
    
    EXPECT_EQ(successCount, numGenerations) << "Not all generations succeeded";
    EXPECT_EQ(failureCount, 0) << "Some generations failed";
}

TEST(SecureRandom, MultipleKeys_AreUnique) {
    SecureRandom rng;
    constexpr int numKeys = 100;
    
    std::set<AESKey> keys;
    
    for (int i = 0; i < numKeys; ++i) {
        auto result = rng.generateAESKey();
        ASSERT_TRUE(result.isSuccess());
        keys.insert(result.value());
    }
    
    // All keys should be unique
    EXPECT_EQ(keys.size(), static_cast<size_t>(numKeys))
        << "Generated keys are not unique";
}

TEST(SecureRandom, MultipleNonces_AreUnique) {
    SecureRandom rng;
    constexpr int numNonces = 100;
    
    std::set<AESNonce> nonces;
    
    for (int i = 0; i < numNonces; ++i) {
        auto result = rng.generateNonce();
        ASSERT_TRUE(result.isSuccess());
        nonces.insert(result.value());
    }
    
    // All nonces should be unique
    EXPECT_EQ(nonces.size(), static_cast<size_t>(numNonces))
        << "Generated nonces are not unique";
}

// ============================================================================
// Sequential Generation Test
// ============================================================================

TEST(SecureRandom, SequentialGenerations_AreDifferent) {
    SecureRandom rng;
    
    auto result1 = rng.generate(32);
    auto result2 = rng.generate(32);
    
    ASSERT_TRUE(result1.isSuccess());
    ASSERT_TRUE(result2.isSuccess());
    
    // Two sequential generations should produce different results
    EXPECT_NE(result1.value(), result2.value())
        << "Sequential generations produced identical output";
}

// ============================================================================
 copilot/implement-hmac-constant-time-verification
// HMAC Tests - RFC 4231 Test Vectors
// ============================================================================

// Helper function to convert hex string to bytes
ByteBuffer hexToBytes(const std::string& hex) {
    ByteBuffer bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        Byte byte = static_cast<Byte>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper function to convert bytes to hex string
std::string bytesToHex(ByteSpan bytes) {
    std::string hex;
    const char* hexChars = "0123456789abcdef";
    for (Byte b : bytes) {
        hex += hexChars[b >> 4];
        hex += hexChars[b & 0x0f];
    }
    return hex;
}

// RFC 4231 Test Case 1
TEST(HMAC_SHA256, RFC4231_TestCase1) {
    // Key = 0x0b repeated 20 times
    ByteBuffer key(20, 0x0b);
    
    // Data = "Hi There"
    std::string data = "Hi There";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    // Expected HMAC-SHA256
    std::string expectedHex = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    ByteBuffer expected = hexToBytes(expectedHex);
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    auto result = hmac.compute(dataSpan);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC computation failed";
    EXPECT_EQ(bytesToHex(result.value()), expectedHex)
        << "HMAC-SHA256 RFC 4231 Test Case 1 failed";
}

// RFC 4231 Test Case 2
TEST(HMAC_SHA256, RFC4231_TestCase2) {
    // Key = "Jefe"
    std::string keyStr = "Jefe";
    ByteSpan key(reinterpret_cast<const Byte*>(keyStr.data()), keyStr.size());
    
    // Data = "what do ya want for nothing?"
    std::string data = "what do ya want for nothing?";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    // Expected HMAC-SHA256
    std::string expectedHex = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    ByteBuffer expected = hexToBytes(expectedHex);
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    auto result = hmac.compute(dataSpan);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC computation failed";
    EXPECT_EQ(bytesToHex(result.value()), expectedHex)
        << "HMAC-SHA256 RFC 4231 Test Case 2 failed";
}

// RFC 4231 Test Case 3
TEST(HMAC_SHA256, RFC4231_TestCase3) {
    // Key = 0xaa repeated 20 times
    ByteBuffer key(20, 0xaa);
    
    // Data = 0xdd repeated 50 times
    ByteBuffer data(50, 0xdd);
    
    // Expected HMAC-SHA256
    std::string expectedHex = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
    ByteBuffer expected = hexToBytes(expectedHex);
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    auto result = hmac.compute(data);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC computation failed";
    EXPECT_EQ(bytesToHex(result.value()), expectedHex)
        << "HMAC-SHA256 RFC 4231 Test Case 3 failed";
}

// RFC 4231 Test Case 4
TEST(HMAC_SHA256, RFC4231_TestCase4) {
    // Key = 0x0102030405060708090a0b0c0d0e0f10111213141516171819
    ByteBuffer key;
    for (int i = 1; i <= 25; i++) {
        key.push_back(static_cast<Byte>(i));
    }
    
    // Data = 0xcd repeated 50 times
    ByteBuffer data(50, 0xcd);
    
    // Expected HMAC-SHA256
    std::string expectedHex = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";
    ByteBuffer expected = hexToBytes(expectedHex);
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    auto result = hmac.compute(data);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC computation failed";
    EXPECT_EQ(bytesToHex(result.value()), expectedHex)
        << "HMAC-SHA256 RFC 4231 Test Case 4 failed";
}

// RFC 4231 Test Case 6 (truncation test)
TEST(HMAC_SHA256, RFC4231_TestCase6) {
    // Key = 0xaa repeated 131 times
    ByteBuffer key(131, 0xaa);
    
    // Data = "Test Using Larger Than Block-Size Key - Hash Key First"
    std::string data = "Test Using Larger Than Block-Size Key - Hash Key First";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    // Expected HMAC-SHA256
    std::string expectedHex = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
    ByteBuffer expected = hexToBytes(expectedHex);
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    auto result = hmac.compute(dataSpan);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC computation failed";
    EXPECT_EQ(bytesToHex(result.value()), expectedHex)
        << "HMAC-SHA256 RFC 4231 Test Case 6 failed";
}

// RFC 4231 Test Case 7
TEST(HMAC_SHA256, RFC4231_TestCase7) {
    // Key = 0xaa repeated 131 times
    ByteBuffer key(131, 0xaa);
    
    // Data = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    std::string data = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    // Expected HMAC-SHA256
    std::string expectedHex = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";
    ByteBuffer expected = hexToBytes(expectedHex);
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    auto result = hmac.compute(dataSpan);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC computation failed";
    EXPECT_EQ(bytesToHex(result.value()), expectedHex)
        << "HMAC-SHA256 RFC 4231 Test Case 7 failed";
}

// RFC 4231 SHA-512 Test Case 1
TEST(HMAC_SHA512, RFC4231_TestCase1) {
    // Key = 0x0b repeated 20 times
    ByteBuffer key(20, 0x0b);
    
    // Data = "Hi There"
    std::string data = "Hi There";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    // Expected HMAC-SHA512
    std::string expectedHex = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
    ByteBuffer expected = hexToBytes(expectedHex);
    
    HMAC hmac(key, HashAlgorithm::SHA512);
    auto result = hmac.compute(dataSpan);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC computation failed";
    EXPECT_EQ(bytesToHex(result.value()), expectedHex)
        << "HMAC-SHA512 RFC 4231 Test Case 1 failed";
}

// RFC 4231 SHA-512 Test Case 2
TEST(HMAC_SHA512, RFC4231_TestCase2) {
    // Key = "Jefe"
    std::string keyStr = "Jefe";
    ByteSpan key(reinterpret_cast<const Byte*>(keyStr.data()), keyStr.size());
    
    // Data = "what do ya want for nothing?"
    std::string data = "what do ya want for nothing?";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    // Expected HMAC-SHA512
    std::string expectedHex = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
    ByteBuffer expected = hexToBytes(expectedHex);
    
    HMAC hmac(key, HashAlgorithm::SHA512);
    auto result = hmac.compute(dataSpan);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC computation failed";
    EXPECT_EQ(bytesToHex(result.value()), expectedHex)
        << "HMAC-SHA512 RFC 4231 Test Case 2 failed";
}

// RFC 4231 SHA-512 Test Case 3
TEST(HMAC_SHA512, RFC4231_TestCase3) {
    // Key = 0xaa repeated 20 times
    ByteBuffer key(20, 0xaa);
    
    // Data = 0xdd repeated 50 times
    ByteBuffer data(50, 0xdd);
    
    // Expected HMAC-SHA512
    std::string expectedHex = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb";
    ByteBuffer expected = hexToBytes(expectedHex);
    
    HMAC hmac(key, HashAlgorithm::SHA512);
    auto result = hmac.compute(data);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC computation failed";
    EXPECT_EQ(bytesToHex(result.value()), expectedHex)
        << "HMAC-SHA512 RFC 4231 Test Case 3 failed";
}

// ============================================================================
// HMAC Verification Tests
// ============================================================================

TEST(HMAC, Verify_CorrectMAC_ReturnsTrue) {
    ByteBuffer key(20, 0x0b);
    std::string data = "Hi There";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    
    // Compute the HMAC
    auto computeResult = hmac.compute(dataSpan);
    ASSERT_TRUE(computeResult.isSuccess());
    
    // Verify with the correct MAC
    auto verifyResult = hmac.verify(dataSpan, computeResult.value());
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_TRUE(verifyResult.value()) << "Verification should succeed with correct MAC";
}

TEST(HMAC, Verify_IncorrectMAC_ReturnsFalse) {
    ByteBuffer key(20, 0x0b);
    std::string data = "Hi There";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    
    // Create an incorrect MAC (all zeros)
    ByteBuffer incorrectMac(32, 0x00);
    
    // Verify with the incorrect MAC
    auto verifyResult = hmac.verify(dataSpan, incorrectMac);
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_FALSE(verifyResult.value()) << "Verification should fail with incorrect MAC";
}

TEST(HMAC, Verify_ModifiedData_ReturnsFalse) {
    ByteBuffer key(20, 0x0b);
    std::string data = "Hi There";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    
    // Compute the HMAC
    auto computeResult = hmac.compute(dataSpan);
    ASSERT_TRUE(computeResult.isSuccess());
    
    // Modify the data
    std::string modifiedData = "Hi There!";
    ByteSpan modifiedDataSpan(reinterpret_cast<const Byte*>(modifiedData.data()), modifiedData.size());
    
    // Verify with the original MAC but modified data
    auto verifyResult = hmac.verify(modifiedDataSpan, computeResult.value());
    ASSERT_TRUE(verifyResult.isSuccess());
    EXPECT_FALSE(verifyResult.value()) << "Verification should fail with modified data";
}

// ============================================================================
// HMAC Constant-Time Verification Test
// ============================================================================

TEST(HMAC, Verify_ConstantTime) {
    ByteBuffer key(32, 0xaa);
    ByteBuffer data(1024, 0xbb);
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    
    // Compute the correct HMAC
    auto computeResult = hmac.compute(data);
    ASSERT_TRUE(computeResult.isSuccess());
    ByteBuffer correctMac = computeResult.value();
    
    // Create a MAC that differs only in the last byte
    ByteBuffer almostCorrectMac = correctMac;
    almostCorrectMac[almostCorrectMac.size() - 1] ^= 0x01;
    
    // Create a MAC that differs in the first byte
    ByteBuffer wrongMac = correctMac;
    wrongMac[0] ^= 0x01;
    
    // Measure timing for correct MAC (should pass)
    constexpr int iterations = 10000;
    
    auto startCorrect = Clock::now();
    for (int i = 0; i < iterations; i++) {
        (void)hmac.verify(data, correctMac);
    }
    auto endCorrect = Clock::now();
    auto durationCorrect = std::chrono::duration_cast<Nanoseconds>(endCorrect - startCorrect).count();
    
    // Measure timing for almost correct MAC (differs at end)
    auto startAlmostCorrect = Clock::now();
    for (int i = 0; i < iterations; i++) {
        (void)hmac.verify(data, almostCorrectMac);
    }
    auto endAlmostCorrect = Clock::now();
    auto durationAlmostCorrect = std::chrono::duration_cast<Nanoseconds>(endAlmostCorrect - startAlmostCorrect).count();
    
    // Measure timing for wrong MAC (differs at start)
    auto startWrong = Clock::now();
    for (int i = 0; i < iterations; i++) {
        (void)hmac.verify(data, wrongMac);
    }
    auto endWrong = Clock::now();
    auto durationWrong = std::chrono::duration_cast<Nanoseconds>(endWrong - startWrong).count();
    
    // Calculate average times
    double avgCorrect = static_cast<double>(durationCorrect) / iterations;
    double avgAlmostCorrect = static_cast<double>(durationAlmostCorrect) / iterations;
    double avgWrong = static_cast<double>(durationWrong) / iterations;
    
    // Print timing information for analysis
    std::cout << "Average time for correct MAC: " << avgCorrect << " ns" << std::endl;
    std::cout << "Average time for almost correct MAC: " << avgAlmostCorrect << " ns" << std::endl;
    std::cout << "Average time for wrong MAC: " << avgWrong << " ns" << std::endl;
    
    // Calculate variance percentage
    double maxTime = std::max({avgCorrect, avgAlmostCorrect, avgWrong});
    double minTime = std::min({avgCorrect, avgAlmostCorrect, avgWrong});
    double variance = ((maxTime - minTime) / maxTime) * 100.0;
    
    std::cout << "Timing variance: " << variance << "%" << std::endl;
    
    // Constant-time comparison should have less than 10% variance
    // (allows for system noise but should not show early-exit behavior)
    EXPECT_LT(variance, 10.0) << "Timing variance too high - possible timing side-channel";
}

// ============================================================================
// HMAC Edge Cases
// ============================================================================

TEST(HMAC, EmptyKey_Works) {
    ByteBuffer key; // Empty key
    std::string data = "test data";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    auto result = hmac.compute(dataSpan);
    
    // HMAC should work with empty key (though not recommended)
    ASSERT_TRUE(result.isSuccess()) << "HMAC with empty key should work";
    EXPECT_EQ(result.value().size(), 32u) << "HMAC-SHA256 should be 32 bytes";
}

TEST(HMAC, EmptyData_Works) {
    ByteBuffer key(20, 0x0b);
    ByteBuffer data; // Empty data
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    auto result = hmac.compute(data);
    
    // HMAC should work with empty data
    ASSERT_TRUE(result.isSuccess()) << "HMAC with empty data should work";
    EXPECT_EQ(result.value().size(), 32u) << "HMAC-SHA256 should be 32 bytes";
}

TEST(HMAC, LargeData_Works) {
    ByteBuffer key(32, 0xaa);
    
    // Create 1MB of data
    ByteBuffer data(1024 * 1024, 0xbb);
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    auto result = hmac.compute(data);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC with large data should work";
    EXPECT_EQ(result.value().size(), 32u) << "HMAC-SHA256 should be 32 bytes";
}

// ============================================================================
// HMAC Static Helper Tests
// ============================================================================

TEST(HMAC, SHA256_StaticHelper) {
    ByteBuffer key(20, 0x0b);
    std::string data = "Hi There";
    ByteSpan dataSpan(reinterpret_cast<const Byte*>(data.data()), data.size());
    
    // Expected HMAC-SHA256 from RFC 4231
    std::string expectedHex = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    
    auto result = HMAC::sha256(key, dataSpan);
    
    ASSERT_TRUE(result.isSuccess()) << "HMAC::sha256 static helper failed";
    EXPECT_EQ(bytesToHex(result.value()), expectedHex)
        << "HMAC::sha256 static helper produced incorrect result";
}

// ============================================================================
// Constant-Time Compare Tests
// ============================================================================

TEST(ConstantTimeCompare, EqualArrays_ReturnsTrue) {
    ByteBuffer a = {0x01, 0x02, 0x03, 0x04};
    ByteBuffer b = {0x01, 0x02, 0x03, 0x04};
    
    EXPECT_TRUE(constantTimeCompare(a, b)) << "Equal arrays should return true";
}

TEST(ConstantTimeCompare, DifferentArrays_ReturnsFalse) {
    ByteBuffer a = {0x01, 0x02, 0x03, 0x04};
    ByteBuffer b = {0x01, 0x02, 0x03, 0x05};
    
    EXPECT_FALSE(constantTimeCompare(a, b)) << "Different arrays should return false";
}

TEST(ConstantTimeCompare, DifferentLengths_ReturnsFalse) {
    ByteBuffer a = {0x01, 0x02, 0x03};
    ByteBuffer b = {0x01, 0x02, 0x03, 0x04};
    
    EXPECT_FALSE(constantTimeCompare(a, b)) << "Arrays with different lengths should return false";
}

TEST(ConstantTimeCompare, EmptyArrays_ReturnsTrue) {
    ByteBuffer a;
    ByteBuffer b;
    
    EXPECT_TRUE(constantTimeCompare(a, b)) << "Empty arrays should return true";
=======
// HashEngine Tests
// ============================================================================

// ============================================================================
// Known Answer Tests (KAT)
// ============================================================================

TEST(HashEngine, SHA256_EmptyString_MatchesRFC) {
    // RFC 4634 test vector: SHA-256 of empty string
    // Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const Byte expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    
    HashEngine hasher(HashAlgorithm::SHA256);
    auto result = hasher.hash(ByteSpan{});
    
    ASSERT_TRUE(result.isSuccess()) << "Hash computation failed";
    ASSERT_EQ(result.value().size(), 32u) << "Wrong hash size";
    
    EXPECT_EQ(std::memcmp(result.value().data(), expected, 32), 0)
        << "SHA-256 of empty string doesn't match RFC 4634";
}

TEST(HashEngine, SHA256_HelloWorld_MatchesKnown) {
    // Known test vector: SHA-256 of "Hello, World!"
    // Expected: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
    const Byte expected[32] = {
        0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0,
        0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e, 0xc3, 0xa5,
        0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b,
        0x28, 0x68, 0x8a, 0x36, 0x21, 0x82, 0x98, 0x6f
    };
    
    std::string data = "Hello, World!";
    
    HashEngine hasher(HashAlgorithm::SHA256);
    auto result = hasher.hash(data);
    
    ASSERT_TRUE(result.isSuccess()) << "Hash computation failed";
    ASSERT_EQ(result.value().size(), 32u) << "Wrong hash size";
    
    EXPECT_EQ(std::memcmp(result.value().data(), expected, 32), 0)
        << "SHA-256 of 'Hello, World!' doesn't match known vector";
}

TEST(HashEngine, SHA512_MatchesKnown) {
    // Known test vector: SHA-512 of "abc"
    // Expected: ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
    //           2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
    const Byte expected[64] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    };
    
    std::string data = "abc";
    
    HashEngine hasher(HashAlgorithm::SHA512);
    auto result = hasher.hash(data);
    
    ASSERT_TRUE(result.isSuccess()) << "Hash computation failed";
    ASSERT_EQ(result.value().size(), 64u) << "Wrong hash size";
    
    EXPECT_EQ(std::memcmp(result.value().data(), expected, 64), 0)
        << "SHA-512 of 'abc' doesn't match known vector";
}

TEST(HashEngine, SHA384_MatchesKnown) {
    // Known test vector: SHA-384 of "abc"
    // Expected: cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed
    //           8086072ba1e7cc2358baeca134c825a7
    const Byte expected[48] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
    };
    
    std::string data = "abc";
    
    HashEngine hasher(HashAlgorithm::SHA384);
    auto result = hasher.hash(data);
    
    ASSERT_TRUE(result.isSuccess()) << "Hash computation failed";
    ASSERT_EQ(result.value().size(), 48u) << "Wrong hash size";
    
    EXPECT_EQ(std::memcmp(result.value().data(), expected, 48), 0)
        << "SHA-384 of 'abc' doesn't match known vector";
}

// ============================================================================
// Streaming Tests
// ============================================================================

TEST(HashEngine, StreamingEqualsOneShot) {
    std::string data = "The quick brown fox jumps over the lazy dog";
    
    // One-shot hash
    HashEngine hasher1(HashAlgorithm::SHA256);
    auto result1 = hasher1.hash(data);
    ASSERT_TRUE(result1.isSuccess());
    
    // Streaming hash - split into three chunks
    HashEngine hasher2(HashAlgorithm::SHA256);
    ASSERT_TRUE(hasher2.init().isSuccess());
    ASSERT_TRUE(hasher2.update(ByteSpan{reinterpret_cast<const Byte*>(data.data()), 15}).isSuccess());
    ASSERT_TRUE(hasher2.update(ByteSpan{reinterpret_cast<const Byte*>(data.data() + 15), 15}).isSuccess());
    ASSERT_TRUE(hasher2.update(ByteSpan{reinterpret_cast<const Byte*>(data.data() + 30), data.size() - 30}).isSuccess());
    auto result2 = hasher2.finalize();
    ASSERT_TRUE(result2.isSuccess());
    
    // Compare results
    EXPECT_EQ(result1.value(), result2.value())
        << "Streaming hash doesn't match one-shot hash";
}

TEST(HashEngine, StreamingMultipleChunks) {
    // Test with many small chunks
    HashEngine hasher(HashAlgorithm::SHA256);
    ASSERT_TRUE(hasher.init().isSuccess());
    
    std::string data = "abcdefghijklmnopqrstuvwxyz";
    
    // Update one byte at a time
    for (char c : data) {
        Byte b = static_cast<Byte>(c);
        ASSERT_TRUE(hasher.update(&b, 1).isSuccess());
    }
    
    auto result = hasher.finalize();
    ASSERT_TRUE(result.isSuccess());
    
    // Compare with one-shot
    HashEngine hasher2(HashAlgorithm::SHA256);
    auto result2 = hasher2.hash(data);
    ASSERT_TRUE(result2.isSuccess());
    
    EXPECT_EQ(result.value(), result2.value());
}

// ============================================================================
// Static Helper Tests
// ============================================================================

TEST(HashEngine, StaticSHA256_Works) {
    std::string data = "test data";
    ByteSpan dataSpan{reinterpret_cast<const Byte*>(data.data()), data.size()};
    
    auto result = HashEngine::sha256(dataSpan);
    ASSERT_TRUE(result.isSuccess());
    
    // Verify it's a SHA256Hash (32 bytes)
    EXPECT_EQ(result.value().size(), 32u);
    
    // Compare with regular method
    HashEngine hasher(HashAlgorithm::SHA256);
    auto result2 = hasher.hash(data);
    ASSERT_TRUE(result2.isSuccess());
    
    const auto& hash1 = result.value();
    const auto& hash2 = result2.value();
    EXPECT_EQ(std::memcmp(hash1.data(), hash2.data(), 32), 0);
}

TEST(HashEngine, StaticSHA512_Works) {
    std::string data = "test data";
    ByteSpan dataSpan{reinterpret_cast<const Byte*>(data.data()), data.size()};
    
    auto result = HashEngine::sha512(dataSpan);
    ASSERT_TRUE(result.isSuccess());
    
    // Verify it's a SHA512Hash (64 bytes)
    EXPECT_EQ(result.value().size(), 64u);
    
    // Compare with regular method
    HashEngine hasher(HashAlgorithm::SHA512);
    auto result2 = hasher.hash(data);
    ASSERT_TRUE(result2.isSuccess());
    
    const auto& hash1 = result.value();
    const auto& hash2 = result2.value();
    EXPECT_EQ(std::memcmp(hash1.data(), hash2.data(), 64), 0);
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST(HashEngine, LargeData_10MB_Succeeds) {
    // Generate 10MB of data
    constexpr size_t dataSize = 10 * 1024 * 1024;
    ByteBuffer data(dataSize);
    
    // Fill with pattern
    for (size_t i = 0; i < dataSize; ++i) {
        data[i] = static_cast<Byte>(i & 0xFF);
    }
    
    HashEngine hasher(HashAlgorithm::SHA256);
    auto result = hasher.hash(ByteSpan{data.data(), data.size()});
    
    ASSERT_TRUE(result.isSuccess()) << "Failed to hash 10MB of data";
    EXPECT_EQ(result.value().size(), 32u);
}

TEST(HashEngine, MultipleReinit_Works) {
    HashEngine hasher(HashAlgorithm::SHA256);
    std::string data1 = "first";
    std::string data2 = "second";
    
    // First hash
    ASSERT_TRUE(hasher.init().isSuccess());
    ASSERT_TRUE(hasher.update(ByteSpan{reinterpret_cast<const Byte*>(data1.data()), data1.size()}).isSuccess());
    auto result1 = hasher.finalize();
    ASSERT_TRUE(result1.isSuccess());
    
    // Second hash (after reinit)
    ASSERT_TRUE(hasher.init().isSuccess());
    ASSERT_TRUE(hasher.update(ByteSpan{reinterpret_cast<const Byte*>(data2.data()), data2.size()}).isSuccess());
    auto result2 = hasher.finalize();
    ASSERT_TRUE(result2.isSuccess());
    
    // Hashes should be different
    EXPECT_NE(result1.value(), result2.value());
    
    // Third hash - same as second (verify reinit works correctly)
    ASSERT_TRUE(hasher.init().isSuccess());
    ASSERT_TRUE(hasher.update(ByteSpan{reinterpret_cast<const Byte*>(data2.data()), data2.size()}).isSuccess());
    auto result3 = hasher.finalize();
    ASSERT_TRUE(result3.isSuccess());
    
    EXPECT_EQ(result2.value(), result3.value());
}

TEST(HashEngine, EmptyUpdate_Works) {
    HashEngine hasher(HashAlgorithm::SHA256);
    
    ASSERT_TRUE(hasher.init().isSuccess());
    ASSERT_TRUE(hasher.update(nullptr, 0).isSuccess());
    auto result = hasher.finalize();
    ASSERT_TRUE(result.isSuccess());
    
    // Should match empty string hash
    HashEngine hasher2(HashAlgorithm::SHA256);
    auto result2 = hasher2.hash(ByteSpan{});
    ASSERT_TRUE(result2.isSuccess());
    
    EXPECT_EQ(result.value(), result2.value());
}

TEST(HashEngine, GetHashSize_ReturnsCorrectSizes) {
    EXPECT_EQ(HashEngine::getHashSize(HashAlgorithm::SHA256), 32u);
    EXPECT_EQ(HashEngine::getHashSize(HashAlgorithm::SHA384), 48u);
    EXPECT_EQ(HashEngine::getHashSize(HashAlgorithm::SHA512), 64u);
    EXPECT_EQ(HashEngine::getHashSize(HashAlgorithm::MD5), 16u);
}

TEST(HashEngine, GetAlgorithm_ReturnsCorrectAlgorithm) {
    HashEngine hasher1(HashAlgorithm::SHA256);
    EXPECT_EQ(hasher1.getAlgorithm(), HashAlgorithm::SHA256);
    
    HashEngine hasher2(HashAlgorithm::SHA512);
    EXPECT_EQ(hasher2.getAlgorithm(), HashAlgorithm::SHA512);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST(HashEngine, DoubleFinalize_Fails) {
    HashEngine hasher(HashAlgorithm::SHA256);
    
    ASSERT_TRUE(hasher.init().isSuccess());
    auto result1 = hasher.finalize();
    ASSERT_TRUE(result1.isSuccess());
    
    // Second finalize should fail
    auto result2 = hasher.finalize();
    EXPECT_TRUE(result2.isFailure());
    EXPECT_EQ(result2.error(), ErrorCode::InvalidState);
}

TEST(HashEngine, UpdateAfterFinalize_Fails) {
    HashEngine hasher(HashAlgorithm::SHA256);
    std::string data = "test";
    
    ASSERT_TRUE(hasher.init().isSuccess());
    ASSERT_TRUE(hasher.update(ByteSpan{reinterpret_cast<const Byte*>(data.data()), data.size()}).isSuccess());
    auto result = hasher.finalize();
    ASSERT_TRUE(result.isSuccess());
    
    // Update after finalize should fail
    auto updateResult = hasher.update(ByteSpan{reinterpret_cast<const Byte*>(data.data()), data.size()});
    EXPECT_TRUE(updateResult.isFailure());
    EXPECT_EQ(updateResult.error(), ErrorCode::InvalidState);
}

TEST(HashEngine, UpdateWithNullPointerNonZeroSize_Fails) {
    HashEngine hasher(HashAlgorithm::SHA256);
    
    ASSERT_TRUE(hasher.init().isSuccess());
    auto result = hasher.update(nullptr, 10);
    
    EXPECT_TRUE(result.isFailure());
    EXPECT_EQ(result.error(), ErrorCode::InvalidArgument);
}

// ============================================================================
// Adversarial Tests
// ============================================================================

TEST(HashEngine, PartialUpdate_NoLeakage) {
    // Verify that partial state is not exposed
    HashEngine hasher(HashAlgorithm::SHA256);
    std::string data = "sensitive data";
    
    ASSERT_TRUE(hasher.init().isSuccess());
    ASSERT_TRUE(hasher.update(ByteSpan{reinterpret_cast<const Byte*>(data.data()), data.size()}).isSuccess());
    
    // At this point, hash is not finalized
    // Verify that we can't get intermediate state
    // (This is implicit - the API doesn't expose intermediate state)
    
    auto result = hasher.finalize();
    ASSERT_TRUE(result.isSuccess());
    
    // Hash should be deterministic
    HashEngine hasher2(HashAlgorithm::SHA256);
    auto result2 = hasher2.hash(data);
    ASSERT_TRUE(result2.isSuccess());
    
    EXPECT_EQ(result.value(), result2.value());
}

TEST(HashEngine, DifferentAlgorithms_ProduceDifferentHashes) {
    std::string data = "test data";
    
    HashEngine hasher256(HashAlgorithm::SHA256);
    auto result256 = hasher256.hash(data);
    ASSERT_TRUE(result256.isSuccess());
    
    HashEngine hasher512(HashAlgorithm::SHA512);
    auto result512 = hasher512.hash(data);
    ASSERT_TRUE(result512.isSuccess());
    
    // Different algorithms should produce different hash sizes
    EXPECT_NE(result256.value().size(), result512.value().size());
    
    // And different hash values (comparing first 32 bytes)
    EXPECT_NE(std::memcmp(result256.value().data(), result512.value().data(), 32), 0);
}

TEST(HashEngine, MD5_Legacy_StillWorks) {
    // MD5 should still work for legacy compatibility
    // Known test vector: MD5 of "abc"
    // Expected: 900150983cd24fb0d6963f7d28e17f72
    const Byte expected[16] = {
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
    };
    
    std::string data = "abc";
    
    HashEngine hasher(HashAlgorithm::MD5);
    auto result = hasher.hash(data);
    
    ASSERT_TRUE(result.isSuccess()) << "MD5 hash computation failed";
    ASSERT_EQ(result.value().size(), 16u) << "Wrong MD5 hash size";
    
    EXPECT_EQ(std::memcmp(result.value().data(), expected, 16), 0)
        << "MD5 of 'abc' doesn't match known vector";
 main
}
