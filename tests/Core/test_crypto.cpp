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
}
