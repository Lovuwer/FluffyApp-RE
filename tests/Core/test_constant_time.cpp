/**
 * @file test_constant_time.cpp
 * @brief Unit tests for constant-time comparison function
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Tests the constant-time comparison function to ensure:
 * 1. Correct functionality for all input cases
 * 2. Timing-independent behavior to prevent side-channel attacks
 */

#include <Sentinel/Core/Crypto.hpp>
#include <Sentinel/Core/Types.hpp>
#include <gtest/gtest.h>
#include <random>
#include <chrono>
#include <algorithm>
#include <iostream>
#include <iomanip>

using namespace Sentinel;
using namespace Sentinel::Crypto;

// ============================================================================
// Unit Tests
// ============================================================================

/**
 * @brief Test that identical buffers return true
 */
TEST(ConstantTimeCompare, Equal32ByteBuffers_ReturnsTrue) {
    // Create two identical 32-byte buffers
    ByteBuffer a(32);
    ByteBuffer b(32);
    
    // Fill with same pattern
    for (size_t i = 0; i < 32; ++i) {
        a[i] = static_cast<Byte>(i);
        b[i] = static_cast<Byte>(i);
    }
    
    EXPECT_TRUE(constantTimeCompare(a, b))
        << "Identical 32-byte buffers should return true";
}

/**
 * @brief Test that buffers differing in first byte return false
 */
TEST(ConstantTimeCompare, DifferenceAtFirstByte_ReturnsFalse) {
    // Create two 32-byte buffers that differ only at index 0
    ByteBuffer a(32, 0x00);
    ByteBuffer b(32, 0x00);
    
    // Make first byte different
    a[0] = 0x00;
    b[0] = 0x01;
    
    EXPECT_FALSE(constantTimeCompare(a, b))
        << "Buffers differing at first byte should return false";
}

/**
 * @brief Test that buffers differing in last byte return false
 */
TEST(ConstantTimeCompare, DifferenceAtLastByte_ReturnsFalse) {
    // Create two 32-byte buffers that differ only at last index
    ByteBuffer a(32, 0xAA);
    ByteBuffer b(32, 0xAA);
    
    // Make last byte different
    a[31] = 0xAA;
    b[31] = 0xBB;
    
    EXPECT_FALSE(constantTimeCompare(a, b))
        << "Buffers differing at last byte should return false";
}

/**
 * @brief Test that buffers of different lengths return false
 */
TEST(ConstantTimeCompare, DifferentBufferLengths_ReturnsFalse) {
    ByteBuffer a(32, 0xFF);
    ByteBuffer b(31, 0xFF);
    
    EXPECT_FALSE(constantTimeCompare(a, b))
        << "Buffers with different lengths should return false";
    
    // Also test the reverse
    EXPECT_FALSE(constantTimeCompare(b, a))
        << "Buffers with different lengths (reversed) should return false";
}

/**
 * @brief Test that two empty buffers return true
 */
TEST(ConstantTimeCompare, BothEmptyBuffers_ReturnsTrue) {
    ByteBuffer a;  // Empty
    ByteBuffer b;  // Empty
    
    EXPECT_TRUE(constantTimeCompare(a, b))
        << "Two empty buffers should return true";
}

// ============================================================================
// Additional Functional Tests
// ============================================================================

/**
 * @brief Test with various buffer sizes
 */
TEST(ConstantTimeCompare, VariousSizes_WorkCorrectly) {
    std::vector<size_t> sizes = {1, 8, 16, 32, 64, 128, 256};
    
    for (size_t size : sizes) {
        ByteBuffer a(size, 0x42);
        ByteBuffer b(size, 0x42);
        
        EXPECT_TRUE(constantTimeCompare(a, b))
            << "Identical buffers of size " << size << " should return true";
        
        // Make them different at middle position
        if (size > 0) {
            b[size / 2] ^= 0x01;
            EXPECT_FALSE(constantTimeCompare(a, b))
                << "Different buffers of size " << size << " should return false";
        }
    }
}

/**
 * @brief Test with all bytes different
 */
TEST(ConstantTimeCompare, AllBytesDifferent_ReturnsFalse) {
    ByteBuffer a(32, 0x00);
    ByteBuffer b(32, 0xFF);
    
    EXPECT_FALSE(constantTimeCompare(a, b))
        << "Buffers with all bytes different should return false";
}

/**
 * @brief Test with single byte difference at various positions
 */
TEST(ConstantTimeCompare, SingleByteDifferenceAtVariousPositions_ReturnsFalse) {
    constexpr size_t bufferSize = 32;
    
    for (size_t pos = 0; pos < bufferSize; ++pos) {
        ByteBuffer a(bufferSize, 0x55);
        ByteBuffer b(bufferSize, 0x55);
        
        // Make them differ at position 'pos'
        b[pos] ^= 0x01;
        
        EXPECT_FALSE(constantTimeCompare(a, b))
            << "Buffers differing at position " << pos << " should return false";
    }
}

// ============================================================================
// Adversarial Test - Timing Analysis
// ============================================================================

/**
 * @brief Timing analysis test to verify constant-time behavior
 * 
 * This test measures the time taken to compare buffers that differ at:
 * - 0 bytes (all match)
 * - 16 bytes (first half matches)
 * - 31 bytes (all but last match)
 * - 32 bytes (none match)
 * 
 * The timing variance between any two cases should be < 10% to pass.
 */
TEST(ConstantTimeCompare, TimingAnalysis_VarianceLessThan10Percent) {
    constexpr size_t secretSize = 32;
    constexpr int iterations = 500000;  // Increased from 100000 for better accuracy
    
    // Generate random "secret"
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    ByteBuffer secret(secretSize);
    for (size_t i = 0; i < secretSize; ++i) {
        secret[i] = static_cast<Byte>(dis(gen));
    }
    
    // Create "guess" buffers that match different amounts
    ByteBuffer guess0(secretSize);   // 0 bytes match
    ByteBuffer guess16(secretSize);  // 16 bytes match (first half)
    ByteBuffer guess31(secretSize);  // 31 bytes match (all but last)
    ByteBuffer guess32(secret);      // 32 bytes match (all)
    
    // Fill guess0 with completely different values
    for (size_t i = 0; i < secretSize; ++i) {
        guess0[i] = secret[i] ^ 0xFF;  // Invert all bits
    }
    
    // Fill guess16 - first half matches
    for (size_t i = 0; i < 16; ++i) {
        guess16[i] = secret[i];
    }
    for (size_t i = 16; i < secretSize; ++i) {
        guess16[i] = secret[i] ^ 0xFF;
    }
    
    // Fill guess31 - all but last match
    for (size_t i = 0; i < 31; ++i) {
        guess31[i] = secret[i];
    }
    guess31[31] = secret[31] ^ 0x01;  // Different last byte
    
    // Measure timing for each case
    auto measure = [&](const ByteBuffer& guess) -> double {
        auto start = Clock::now();
        for (int i = 0; i < iterations; ++i) {
            // Use volatile to prevent optimization
            volatile bool result = constantTimeCompare(secret, guess);
            (void)result;  // Suppress unused warning
        }
        auto end = Clock::now();
        auto duration = std::chrono::duration_cast<Nanoseconds>(end - start).count();
        return static_cast<double>(duration) / iterations;
    };
    
    // Measure all cases
    double time0 = measure(guess0);    // 0 bytes match
    double time16 = measure(guess16);  // 16 bytes match
    double time31 = measure(guess31);  // 31 bytes match
    double time32 = measure(guess32);  // 32 bytes match (all)
    
    // Print timing data for manual review
    std::cout << "\n=== Constant-Time Comparison Timing Analysis ===" << std::endl;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Average time for  0 matching bytes: " << time0 << " ns" << std::endl;
    std::cout << "Average time for 16 matching bytes: " << time16 << " ns" << std::endl;
    std::cout << "Average time for 31 matching bytes: " << time31 << " ns" << std::endl;
    std::cout << "Average time for 32 matching bytes: " << time32 << " ns" << std::endl;
    
    // Calculate variance
    std::vector<double> times = {time0, time16, time31, time32};
    double maxTime = *std::max_element(times.begin(), times.end());
    double minTime = *std::min_element(times.begin(), times.end());
    
    double variance = ((maxTime - minTime) / maxTime) * 100.0;
    
    std::cout << "Maximum time: " << maxTime << " ns" << std::endl;
    std::cout << "Minimum time: " << minTime << " ns" << std::endl;
    std::cout << "Timing variance: " << variance << "%" << std::endl;
    std::cout << "================================================\n" << std::endl;
    
    // Acceptance Criteria: Maximum variance between any two cases < 10%
    EXPECT_LT(variance, 10.0)
        << "Timing variance too high - possible timing side-channel vulnerability";
}

// ============================================================================
// Edge Cases and Robustness Tests
// ============================================================================

/**
 * @brief Test with zero-filled buffers
 */
TEST(ConstantTimeCompare, ZeroFilledBuffers_WorkCorrectly) {
    ByteBuffer a(32, 0x00);
    ByteBuffer b(32, 0x00);
    
    EXPECT_TRUE(constantTimeCompare(a, b))
        << "Identical zero-filled buffers should return true";
    
    b[0] = 0x01;
    EXPECT_FALSE(constantTimeCompare(a, b))
        << "Different zero-filled buffers should return false";
}

/**
 * @brief Test with 0xFF-filled buffers
 */
TEST(ConstantTimeCompare, FFFilledBuffers_WorkCorrectly) {
    ByteBuffer a(32, 0xFF);
    ByteBuffer b(32, 0xFF);
    
    EXPECT_TRUE(constantTimeCompare(a, b))
        << "Identical 0xFF-filled buffers should return true";
    
    b[15] = 0xFE;
    EXPECT_FALSE(constantTimeCompare(a, b))
        << "Different 0xFF-filled buffers should return false";
}

/**
 * @brief Test with large buffers (1KB)
 */
TEST(ConstantTimeCompare, LargeBuffers_WorkCorrectly) {
    constexpr size_t largeSize = 1024;
    ByteBuffer a(largeSize);
    ByteBuffer b(largeSize);
    
    // Fill with pattern
    for (size_t i = 0; i < largeSize; ++i) {
        a[i] = static_cast<Byte>(i & 0xFF);
        b[i] = static_cast<Byte>(i & 0xFF);
    }
    
    EXPECT_TRUE(constantTimeCompare(a, b))
        << "Identical 1KB buffers should return true";
    
    // Change middle byte
    b[largeSize / 2] ^= 0x01;
    EXPECT_FALSE(constantTimeCompare(a, b))
        << "Different 1KB buffers should return false";
}

/**
 * @brief Test with one empty and one non-empty buffer
 */
TEST(ConstantTimeCompare, MismatchedEmptyBuffers_ReturnFalse) {
    ByteBuffer empty;
    ByteBuffer nonEmpty(1, 0x00);
    
    EXPECT_FALSE(constantTimeCompare(empty, nonEmpty))
        << "Empty and non-empty buffers should return false";
    
    EXPECT_FALSE(constantTimeCompare(nonEmpty, empty))
        << "Non-empty and empty buffers should return false";
}

/**
 * @brief Test realistic MAC verification scenario
 */
TEST(ConstantTimeCompare, RealisticMACVerification_WorksCorrectly) {
    // Simulate HMAC-SHA256 output (32 bytes)
    ByteBuffer computedMAC = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };
    
    ByteBuffer receivedMAC = computedMAC;  // Copy
    
    // Valid case - MACs match
    EXPECT_TRUE(constantTimeCompare(computedMAC, receivedMAC))
        << "Matching MACs should return true";
    
    // Invalid case - MACs differ by one bit
    receivedMAC[0] ^= 0x01;
    EXPECT_FALSE(constantTimeCompare(computedMAC, receivedMAC))
        << "Non-matching MACs should return false";
}

/**
 * @brief Verify deterministic behavior
 */
TEST(ConstantTimeCompare, DeterministicBehavior) {
    ByteBuffer a(32, 0xAA);
    ByteBuffer b(32, 0xAA);
    
    // Multiple comparisons should yield same result
    bool result1 = constantTimeCompare(a, b);
    bool result2 = constantTimeCompare(a, b);
    bool result3 = constantTimeCompare(a, b);
    
    EXPECT_EQ(result1, result2);
    EXPECT_EQ(result2, result3);
    EXPECT_TRUE(result1) << "Identical buffers should consistently return true";
    
    // Make them different
    b[10] ^= 0x01;
    
    result1 = constantTimeCompare(a, b);
    result2 = constantTimeCompare(a, b);
    result3 = constantTimeCompare(a, b);
    
    EXPECT_EQ(result1, result2);
    EXPECT_EQ(result2, result3);
    EXPECT_FALSE(result1) << "Different buffers should consistently return false";
}
