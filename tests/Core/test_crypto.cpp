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
 copilot/fix-nonce-reuse-risk
// Test-only accessor for private AESCipher methods
// ============================================================================

namespace Sentinel::Crypto {

/**
 * @brief Test accessor for AESCipher private methods
 * 
 * This class is used ONLY for testing NIST test vectors and validating
 * the low-level encryption/decryption with known nonces.
 * 
 * Uses friend access to AESCipher class to access private methods that
 * would otherwise expose catastrophic nonce reuse vulnerabilities if public.
 * 
 * WARNING: This accessor should NEVER be used in production code!
 * The encryptWithNonce/decryptWithNonce methods are intentionally private
 * to prevent catastrophic nonce reuse.
 */
class AESCipherTestAccessor {
=======
// Test Helper - Friend class to access private encryptWithNonce API
// ============================================================================

/**
 * @brief Test helper to access unsafe/private AESCipher methods
 * 
 * This class is a friend of AESCipher and provides controlled access
 * to the private encryptWithNonce/decryptWithNonce methods for testing.
 * 
 * **WARNING:** These methods expose catastrophic nonce-reuse risk.
 * Only use in controlled test environments with known-unique nonces.
 */
class AESCipherTest {
 copilot/implement-aescipher-aes-256-gcm
public:
    static Result<ByteBuffer> encryptWithNonce(
        AESCipher& cipher,
        ByteSpan plaintext,
        const AESNonce& nonce,
        ByteSpan associatedData = {}
    ) {
        return cipher.encryptWithNonce(plaintext, nonce, associatedData);
    }
    
    static Result<ByteBuffer> decryptWithNonce(
        AESCipher& cipher,
        ByteSpan ciphertext,
        const AESNonce& nonce,
        ByteSpan associatedData = {}
    ) {
        return cipher.decryptWithNonce(ciphertext, nonce, associatedData);
    }
};

 copilot/fix-nonce-reuse-risk
} // namespace Sentinel::Crypto

=======
 copilot/implement-aescipher-aes-256-gcm
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
}

// ============================================================================
// AESCipher Tests
// ============================================================================

// ============================================================================
// Round-trip Tests
// ============================================================================

TEST(AESCipher, EncryptDecrypt_RoundTrip) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    std::string plaintext = "Hello, World! This is a test message.";
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintextSpan);
    ASSERT_TRUE(encryptResult.isSuccess()) << "Encryption failed";
    
    // Verify output size: nonce (12) + ciphertext (plaintext.size()) + tag (16)
    EXPECT_EQ(encryptResult.value().size(), 12 + plaintext.size() + 16);
    
    // Decrypt
    auto decryptResult = cipher.decrypt(encryptResult.value());
    ASSERT_TRUE(decryptResult.isSuccess()) << "Decryption failed";
    
    // Verify round-trip
    EXPECT_EQ(decryptResult.value().size(), plaintext.size());
    EXPECT_EQ(std::memcmp(decryptResult.value().data(), plaintext.data(), plaintext.size()), 0)
        << "Decrypted plaintext doesn't match original";
}

TEST(AESCipher, WithAAD_RoundTrip) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    std::string plaintext = "Secret message";
    std::string aad = "Additional authenticated data";
    
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    ByteSpan aadSpan{reinterpret_cast<const Byte*>(aad.data()), aad.size()};
    
    // Encrypt with AAD
    auto encryptResult = cipher.encrypt(plaintextSpan, aadSpan);
    ASSERT_TRUE(encryptResult.isSuccess()) << "Encryption with AAD failed";
    
    // Decrypt with same AAD
    auto decryptResult = cipher.decrypt(encryptResult.value(), aadSpan);
    ASSERT_TRUE(decryptResult.isSuccess()) << "Decryption with AAD failed";
    
    // Verify round-trip
    EXPECT_EQ(decryptResult.value().size(), plaintext.size());
    EXPECT_EQ(std::memcmp(decryptResult.value().data(), plaintext.data(), plaintext.size()), 0);
}

TEST(AESCipher, EmptyPlaintext_Succeeds) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    ByteSpan emptyPlaintext{};
    
    // Encrypt empty plaintext
    auto encryptResult = cipher.encrypt(emptyPlaintext);
    ASSERT_TRUE(encryptResult.isSuccess()) << "Encryption of empty plaintext failed";
    
    // Output should be: nonce (12) + tag (16) = 28 bytes
    EXPECT_EQ(encryptResult.value().size(), 28u);
    
    // Decrypt
    auto decryptResult = cipher.decrypt(encryptResult.value());
    ASSERT_TRUE(decryptResult.isSuccess()) << "Decryption of empty plaintext failed";
    
    EXPECT_EQ(decryptResult.value().size(), 0u);
}

TEST(AESCipher, LargePlaintext_1MB) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    // Generate 1MB of data
    constexpr size_t dataSize = 1024 * 1024;
    ByteBuffer plaintext(dataSize);
    for (size_t i = 0; i < dataSize; ++i) {
        plaintext[i] = static_cast<Byte>(i & 0xFF);
    }
    
    ByteSpan plaintextSpan{plaintext.data(), plaintext.size()};
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintextSpan);
    ASSERT_TRUE(encryptResult.isSuccess()) << "Encryption of 1MB failed";
    
    // Decrypt
    auto decryptResult = cipher.decrypt(encryptResult.value());
    ASSERT_TRUE(decryptResult.isSuccess()) << "Decryption of 1MB failed";
    
    // Verify
    EXPECT_EQ(decryptResult.value().size(), dataSize);
    EXPECT_EQ(plaintext, decryptResult.value());
}

// ============================================================================
// Authentication Tests
// ============================================================================

TEST(AESCipher, TamperedCiphertext_Fails) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    std::string plaintext = "Important message";
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintextSpan);
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Tamper with ciphertext (modify a byte in the middle)
    ByteBuffer tampered = encryptResult.value();
    if (tampered.size() > 20) {
        tampered[20] ^= 0xFF;
    }
    
    // Decrypt should fail
    auto decryptResult = cipher.decrypt(tampered);
    EXPECT_TRUE(decryptResult.isFailure()) << "Tampered ciphertext should fail authentication";
    EXPECT_EQ(decryptResult.error(), ErrorCode::AuthenticationFailed);
}

TEST(AESCipher, TamperedTag_Fails) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    std::string plaintext = "Important message";
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintextSpan);
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Tamper with tag (last 16 bytes)
    ByteBuffer tampered = encryptResult.value();
    tampered[tampered.size() - 1] ^= 0xFF;
    
    // Decrypt should fail
    auto decryptResult = cipher.decrypt(tampered);
    EXPECT_TRUE(decryptResult.isFailure()) << "Tampered tag should fail authentication";
    EXPECT_EQ(decryptResult.error(), ErrorCode::AuthenticationFailed);
}

TEST(AESCipher, TamperedNonce_Fails) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    std::string plaintext = "Important message";
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintextSpan);
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Tamper with nonce (first 12 bytes)
    ByteBuffer tampered = encryptResult.value();
    tampered[5] ^= 0xFF;
    
    // Decrypt should fail (wrong nonce leads to authentication failure)
    auto decryptResult = cipher.decrypt(tampered);
    EXPECT_TRUE(decryptResult.isFailure()) << "Tampered nonce should fail authentication";
}

TEST(AESCipher, WrongKey_Fails) {
    SecureRandom rng;
    auto key1Result = rng.generateAESKey();
    auto key2Result = rng.generateAESKey();
    ASSERT_TRUE(key1Result.isSuccess());
    ASSERT_TRUE(key2Result.isSuccess());
    
    AESCipher cipher1(key1Result.value());
    AESCipher cipher2(key2Result.value());
    
    std::string plaintext = "Important message";
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    
    // Encrypt with cipher1
    auto encryptResult = cipher1.encrypt(plaintextSpan);
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Try to decrypt with cipher2 (wrong key)
    auto decryptResult = cipher2.decrypt(encryptResult.value());
    EXPECT_TRUE(decryptResult.isFailure()) << "Wrong key should fail authentication";
    EXPECT_EQ(decryptResult.error(), ErrorCode::AuthenticationFailed);
}

TEST(AESCipher, WrongAAD_Fails) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    std::string plaintext = "Secret message";
    std::string aad1 = "Correct AAD";
    std::string aad2 = "Wrong AAD";
    
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    ByteSpan aad1Span{reinterpret_cast<const Byte*>(aad1.data()), aad1.size()};
    ByteSpan aad2Span{reinterpret_cast<const Byte*>(aad2.data()), aad2.size()};
    
    // Encrypt with aad1
    auto encryptResult = cipher.encrypt(plaintextSpan, aad1Span);
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Try to decrypt with aad2
    auto decryptResult = cipher.decrypt(encryptResult.value(), aad2Span);
    EXPECT_TRUE(decryptResult.isFailure()) << "Wrong AAD should fail authentication";
    EXPECT_EQ(decryptResult.error(), ErrorCode::AuthenticationFailed);
}

TEST(AESCipher, NoPlaintextOnAuthFailure) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    std::string plaintext = "Sensitive data that should never be exposed";
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    
    // Encrypt
    auto encryptResult = cipher.encrypt(plaintextSpan);
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Tamper with ciphertext
    ByteBuffer tampered = encryptResult.value();
    tampered[20] ^= 0xFF;
    
    // Decrypt should fail and return NO plaintext
    auto decryptResult = cipher.decrypt(tampered);
    ASSERT_TRUE(decryptResult.isFailure());
    
    // Verify that Result doesn't contain plaintext (should throw when accessing value)
    EXPECT_THROW({
        auto& value = decryptResult.value();
        (void)value;
    }, std::runtime_error);
}

// ============================================================================
// Known Answer Tests (NIST CAVP Test Vectors)
// ============================================================================

TEST(AESCipher, NIST_GCM_TestVector1) {
    // NIST CAVP GCM test vector
    // Key: 00000000000000000000000000000000 00000000000000000000000000000000
    // IV:  000000000000000000000000
    // PT:  (empty)
    // AAD: (empty)
    // CT:  (empty)
    // Tag: 530f8afbc74536b9a963b4f1c4cb738b
    
    AESKey key{};  // All zeros
    AESNonce nonce{};  // All zeros
    
    AESCipher cipher(key);
    
    ByteSpan emptyPlaintext{};
    
 copilot/fix-nonce-reuse-risk
    auto encryptResult = AESCipherTestAccessor::encryptWithNonce(cipher, emptyPlaintext, nonce);
=======
    auto encryptResult = AESCipherTest::encryptWithNonce(cipher, emptyPlaintext, nonce);
 copilot/implement-aescipher-aes-256-gcm
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Extract tag (last 16 bytes)
    ASSERT_GE(encryptResult.value().size(), 16u);
    const Byte expectedTag[16] = {
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
        0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b
    };
    
    ByteSpan actualTag{encryptResult.value().data() + encryptResult.value().size() - 16, 16};
    EXPECT_EQ(std::memcmp(actualTag.data(), expectedTag, 16), 0)
        << "NIST test vector tag doesn't match";
}

TEST(AESCipher, NIST_GCM_TestVector2) {
    // NIST CAVP GCM test vector with plaintext
    // Key: 00000000000000000000000000000000 00000000000000000000000000000000
    // IV:  000000000000000000000000
    // PT:  00000000000000000000000000000000
    // AAD: (empty)
    // CT:  cea7403d4d606b6e074ec5d3baf39d18
    // Tag: d0d1c8a799996bf0265b98b5d48ab919
    
    AESKey key{};  // All zeros
    AESNonce nonce{};  // All zeros
    
    Byte plaintext[16] = {};  // All zeros
    
    AESCipher cipher(key);
    
    ByteSpan plaintextSpan{plaintext, 16};
    
 copilot/fix-nonce-reuse-risk
    auto encryptResult = AESCipherTestAccessor::encryptWithNonce(cipher, plaintextSpan, nonce);
=======
    auto encryptResult = AESCipherTest::encryptWithNonce(cipher, plaintextSpan, nonce);
 copilot/implement-aescipher-aes-256-gcm
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Verify ciphertext (first 16 bytes)
    ASSERT_GE(encryptResult.value().size(), 32u);  // 16 bytes CT + 16 bytes tag
    
    const Byte expectedCT[16] = {
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18
    };
    
    ByteSpan actualCT{encryptResult.value().data(), 16};
    EXPECT_EQ(std::memcmp(actualCT.data(), expectedCT, 16), 0)
        << "NIST test vector ciphertext doesn't match";
    
    // Verify tag (last 16 bytes)
    const Byte expectedTag[16] = {
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
    };
    
    ByteSpan actualTag{encryptResult.value().data() + 16, 16};
    EXPECT_EQ(std::memcmp(actualTag.data(), expectedTag, 16), 0)
        << "NIST test vector tag doesn't match";
}

// ============================================================================
// Advanced Features
// ============================================================================

TEST(AESCipher, EncryptWithNonce_CustomNonce) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    auto nonceResult = rng.generateNonce();
    ASSERT_TRUE(keyResult.isSuccess());
    ASSERT_TRUE(nonceResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    std::string plaintext = "Test message";
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    
 copilot/fix-nonce-reuse-risk
    // Encrypt with custom nonce (using test accessor)
    auto encryptResult = AESCipherTestAccessor::encryptWithNonce(cipher, plaintextSpan, nonceResult.value());
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Decrypt with same nonce (using test accessor)
    auto decryptResult = AESCipherTestAccessor::decryptWithNonce(cipher, encryptResult.value(), nonceResult.value());
=======
    // Encrypt with custom nonce
    auto encryptResult = AESCipherTest::encryptWithNonce(cipher, plaintextSpan, nonceResult.value());
    ASSERT_TRUE(encryptResult.isSuccess());
    
    // Decrypt with same nonce
    auto decryptResult = AESCipherTest::decryptWithNonce(cipher, encryptResult.value(), nonceResult.value());
 copilot/implement-aescipher-aes-256-gcm
    ASSERT_TRUE(decryptResult.isSuccess());
    
    EXPECT_EQ(decryptResult.value().size(), plaintext.size());
    EXPECT_EQ(std::memcmp(decryptResult.value().data(), plaintext.data(), plaintext.size()), 0);
}

TEST(AESCipher, SetKey_ChangesEncryption) {
    SecureRandom rng;
    auto key1Result = rng.generateAESKey();
    auto key2Result = rng.generateAESKey();
    ASSERT_TRUE(key1Result.isSuccess());
    ASSERT_TRUE(key2Result.isSuccess());
    
    AESCipher cipher(key1Result.value());
    
    std::string plaintext = "Test message";
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    
    // Encrypt with key1 (using test accessor)
    auto nonceResult = rng.generateNonce();
    ASSERT_TRUE(nonceResult.isSuccess());
 copilot/fix-nonce-reuse-risk
    auto encryptResult1 = AESCipherTestAccessor::encryptWithNonce(cipher, plaintextSpan, nonceResult.value());
=======
    auto encryptResult1 = AESCipherTest::encryptWithNonce(cipher, plaintextSpan, nonceResult.value());
 copilot/implement-aescipher-aes-256-gcm
    ASSERT_TRUE(encryptResult1.isSuccess());
    
    // Change key
    cipher.setKey(key2Result.value());
    
 copilot/fix-nonce-reuse-risk
    // Encrypt with key2 (same nonce for comparison) (using test accessor)
    auto encryptResult2 = AESCipherTestAccessor::encryptWithNonce(cipher, plaintextSpan, nonceResult.value());
=======
    // Encrypt with key2 (same nonce for comparison)
    auto encryptResult2 = AESCipherTest::encryptWithNonce(cipher, plaintextSpan, nonceResult.value());
 copilot/implement-aescipher-aes-256-gcm
    ASSERT_TRUE(encryptResult2.isSuccess());
    
    // Ciphertexts should be different
    EXPECT_NE(encryptResult1.value(), encryptResult2.value());
}

TEST(AESCipher, MultipleEncryptions_DifferentNonces) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    std::string plaintext = "Same message";
    ByteSpan plaintextSpan{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    
    // Encrypt multiple times
    auto encrypt1 = cipher.encrypt(plaintextSpan);
    auto encrypt2 = cipher.encrypt(plaintextSpan);
    auto encrypt3 = cipher.encrypt(plaintextSpan);
    
    ASSERT_TRUE(encrypt1.isSuccess());
    ASSERT_TRUE(encrypt2.isSuccess());
    ASSERT_TRUE(encrypt3.isSuccess());
    
    // All ciphertexts should be different (different nonces)
    EXPECT_NE(encrypt1.value(), encrypt2.value());
    EXPECT_NE(encrypt1.value(), encrypt3.value());
    EXPECT_NE(encrypt2.value(), encrypt3.value());
}

// ============================================================================
// Error Handling
// ============================================================================

TEST(AESCipher, InvalidKeySize_Throws) {
    Byte shortKey[16] = {};
    ByteSpan shortKeySpan{shortKey, 16};
    
    EXPECT_THROW({
        AESCipher cipher(shortKeySpan);
    }, std::invalid_argument);
    
    Byte longKey[64] = {};
    ByteSpan longKeySpan{longKey, 64};
    
    EXPECT_THROW({
        AESCipher cipher(longKeySpan);
    }, std::invalid_argument);
}

TEST(AESCipher, TooShortCiphertext_Fails) {
    SecureRandom rng;
    auto keyResult = rng.generateAESKey();
    ASSERT_TRUE(keyResult.isSuccess());
    
    AESCipher cipher(keyResult.value());
    
    // Ciphertext too short (minimum is 28 bytes: 12 nonce + 16 tag)
    Byte shortCiphertext[20] = {};
    ByteSpan shortSpan{shortCiphertext, 20};
    
    auto decryptResult = cipher.decrypt(shortSpan);
    EXPECT_TRUE(decryptResult.isFailure());
    EXPECT_EQ(decryptResult.error(), ErrorCode::InvalidArgument);
}

// ============================================================================
// Utility Function Tests
// ============================================================================

TEST(CryptoUtils, ConstantTimeCompare_SameArrays) {
    Byte arr1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    Byte arr2[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    EXPECT_TRUE(constantTimeCompare(ByteSpan{arr1, 16}, ByteSpan{arr2, 16}));
}

TEST(CryptoUtils, ConstantTimeCompare_DifferentArrays) {
    Byte arr1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    Byte arr2[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17};
    
    EXPECT_FALSE(constantTimeCompare(ByteSpan{arr1, 16}, ByteSpan{arr2, 16}));
}

TEST(CryptoUtils, ConstantTimeCompare_DifferentSizes) {
    Byte arr1[16] = {};
    Byte arr2[8] = {};
    
    EXPECT_FALSE(constantTimeCompare(ByteSpan{arr1, 16}, ByteSpan{arr2, 8}));
}

TEST(CryptoUtils, SecureZero_ZerosMemory) {
    Byte buffer[32];
    std::fill(buffer, buffer + 32, static_cast<Byte>(0xFF));
    
    secureZero(buffer, 32);
    
    for (size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(buffer[i], 0);
    }
}

TEST(CryptoUtils, ToHex_ConvertsCorrectly) {
    Byte data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    ByteSpan dataSpan{data, 4};
    
    std::string hex = toHex(dataSpan);
    EXPECT_EQ(hex, "deadbeef");
}

TEST(CryptoUtils, FromHex_ConvertsCorrectly) {
    std::string hex = "deadbeef";
    auto result = fromHex(hex);
    
    ASSERT_TRUE(result.isSuccess());
    ASSERT_EQ(result.value().size(), 4u);
    
    EXPECT_EQ(result.value()[0], 0xDE);
    EXPECT_EQ(result.value()[1], 0xAD);
    EXPECT_EQ(result.value()[2], 0xBE);
    EXPECT_EQ(result.value()[3], 0xEF);
}

TEST(CryptoUtils, HexRoundTrip) {
    SecureRandom rng;
    auto dataResult = rng.generate(32);
    ASSERT_TRUE(dataResult.isSuccess());
    
    ByteSpan dataSpan{dataResult.value().data(), dataResult.value().size()};
    std::string hex = toHex(dataSpan);
    
    auto fromHexResult = fromHex(hex);
    ASSERT_TRUE(fromHexResult.isSuccess());
    
    EXPECT_EQ(dataResult.value(), fromHexResult.value());
}

TEST(CryptoUtils, Base64RoundTrip) {
    SecureRandom rng;
    auto dataResult = rng.generate(64);
    ASSERT_TRUE(dataResult.isSuccess());
    
    ByteSpan dataSpan{dataResult.value().data(), dataResult.value().size()};
    std::string base64 = toBase64(dataSpan);
    
    auto fromBase64Result = fromBase64(base64);
    ASSERT_TRUE(fromBase64Result.isSuccess());
    
    EXPECT_EQ(dataResult.value(), fromBase64Result.value());
}
