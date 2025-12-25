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
