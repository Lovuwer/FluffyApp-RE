/**
 * @file test_harness.cpp
 * @brief Meta-tests for the test harness utilities
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include "TestHarness.hpp"
#include <gtest/gtest.h>

using namespace Sentinel;
using namespace Sentinel::Testing;

// ============================================================================
// Memory Utility Tests
// ============================================================================

TEST(TestHarness, isZeroed_WithZeroedBuffer_ReturnsTrue) {
    ByteBuffer buffer(100, 0x00);
    EXPECT_TRUE(isZeroed(buffer.data(), buffer.size()));
}

TEST(TestHarness, isZeroed_WithNonZeroedBuffer_ReturnsFalse) {
    ByteBuffer buffer(100, 0x00);
    buffer[50] = 0x01;  // Set one byte to non-zero
    EXPECT_FALSE(isZeroed(buffer.data(), buffer.size()));
}

TEST(TestHarness, isZeroed_WithEmptyBuffer_ReturnsTrue) {
    ByteBuffer buffer;
    EXPECT_TRUE(isZeroed(buffer.data(), buffer.size()));
}

TEST(TestHarness, fillPattern_FillsCorrectly) {
    ByteBuffer buffer(100);
    fillPattern(buffer.data(), buffer.size(), 0xAA);
    
    for (auto byte : buffer) {
        EXPECT_EQ(byte, 0xAA);
    }
}

TEST(TestHarness, fillPattern_DifferentPatterns) {
    std::vector<uint8_t> patterns = {0x00, 0x55, 0xAA, 0xFF};
    
    for (auto pattern : patterns) {
        ByteBuffer buffer(50);
        fillPattern(buffer.data(), buffer.size(), pattern);
        
        for (auto byte : buffer) {
            EXPECT_EQ(byte, pattern);
        }
    }
}

// ============================================================================
// GuardedBuffer Tests
// ============================================================================

TEST(TestHarness, GuardedBuffer_AllocatesCorrectSize) {
    GuardedBuffer buffer(1024);
    EXPECT_EQ(buffer.size(), 1024u);
    EXPECT_NE(buffer.data(), nullptr);
}

TEST(TestHarness, GuardedBuffer_CanWriteAndRead) {
    GuardedBuffer buffer(256);
    
    // Fill with pattern
    fillPattern(buffer.data(), buffer.size(), 0x42);
    
    // Verify we can read it back
    const uint8_t* bytes = static_cast<const uint8_t*>(buffer.data());
    for (size_t i = 0; i < buffer.size(); i++) {
        EXPECT_EQ(bytes[i], 0x42);
    }
}

TEST(TestHarness, GuardedBuffer_SmallAllocation) {
    GuardedBuffer buffer(1);
    EXPECT_EQ(buffer.size(), 1u);
    
    uint8_t* byte = static_cast<uint8_t*>(buffer.data());
    *byte = 0xFF;
    EXPECT_EQ(*byte, 0xFF);
}

TEST(TestHarness, GuardedBuffer_LargeAllocation) {
    GuardedBuffer buffer(8192);
    EXPECT_EQ(buffer.size(), 8192u);
    EXPECT_NE(buffer.data(), nullptr);
}

// ============================================================================
// Random Data Generation Tests
// ============================================================================

TEST(TestHarness, randomBytes_GeneratesCorrectSize) {
    std::vector<size_t> sizes = {1, 10, 32, 64, 128, 256, 1024};
    
    for (auto size : sizes) {
        auto data = randomBytes(size);
        EXPECT_EQ(data.size(), size);
    }
}

TEST(TestHarness, randomBytes_GeneratesDifferentData) {
    auto data1 = randomBytes(32);
    auto data2 = randomBytes(32);
    
    // Very unlikely to be identical for 32 random bytes
    EXPECT_NE(data1, data2);
}

TEST(TestHarness, randomString_GeneratesCorrectLength) {
    std::vector<size_t> lengths = {1, 10, 50, 100};
    
    for (auto length : lengths) {
        auto str = randomString(length);
        EXPECT_EQ(str.length(), length);
    }
}

TEST(TestHarness, randomString_ContainsValidCharacters) {
    auto str = randomString(100);
    
    for (char c : str) {
        bool isValid = (c >= 'a' && c <= 'z') ||
                       (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9');
        EXPECT_TRUE(isValid) << "Invalid character: " << c;
    }
}

TEST(TestHarness, randomString_GeneratesDifferentStrings) {
    auto str1 = randomString(50);
    auto str2 = randomString(50);
    
    EXPECT_NE(str1, str2);
}

// ============================================================================
// BitFlipper Tests
// ============================================================================

TEST(TestHarness, BitFlipper_flipBit_FlipsCorrectBit) {
    ByteBuffer data = {0x00, 0x00, 0x00};
    
    // Flip bit 0 of byte 0
    BitFlipper::flipBit(data, 0);
    EXPECT_EQ(data[0], 0x01);
    EXPECT_EQ(data[1], 0x00);
    EXPECT_EQ(data[2], 0x00);
    
    // Flip bit 7 of byte 0
    BitFlipper::flipBit(data, 7);
    EXPECT_EQ(data[0], 0x81);
    
    // Flip bit 0 of byte 1
    BitFlipper::flipBit(data, 8);
    EXPECT_EQ(data[1], 0x01);
}

TEST(TestHarness, BitFlipper_flipBit_TogglesBack) {
    ByteBuffer data = {0xFF};
    
    // Flip bit should toggle
    BitFlipper::flipBit(data, 0);
    EXPECT_EQ(data[0], 0xFE);
    
    // Flip again should toggle back
    BitFlipper::flipBit(data, 0);
    EXPECT_EQ(data[0], 0xFF);
}

TEST(TestHarness, BitFlipper_flipRandomBit_FlipsSomeBit) {
    ByteBuffer data(4, 0x00);
    
    size_t flipped_bit = BitFlipper::flipRandomBit(data);
    
    // Should have flipped exactly one bit
    int bit_count = 0;
    for (auto byte : data) {
        for (int i = 0; i < 8; i++) {
            if (byte & (1 << i)) {
                bit_count++;
            }
        }
    }
    
    EXPECT_EQ(bit_count, 1);
    EXPECT_LT(flipped_bit, data.size() * 8);
}

TEST(TestHarness, BitFlipper_forEachBitFlip_CallsForEachBit) {
    ByteBuffer original = {0x00, 0x00};
    int callback_count = 0;
    
    BitFlipper::forEachBitFlip(original, [&](const ByteBuffer& modified, size_t /* bit */) {
        callback_count++;
        
        // Exactly one bit should be different
        int diff_bits = 0;
        for (size_t i = 0; i < original.size() * 8; i++) {
            size_t byte_pos = i / 8;
            size_t bit_offset = i % 8;
            
            bool orig_bit = (original[byte_pos] & (1 << bit_offset)) != 0;
            bool mod_bit = (modified[byte_pos] & (1 << bit_offset)) != 0;
            
            if (orig_bit != mod_bit) {
                diff_bits++;
            }
        }
        
        EXPECT_EQ(diff_bits, 1) << "Modified buffer should differ by exactly 1 bit";
    });
    
    EXPECT_EQ(callback_count, 16) << "Should call callback for each of 16 bits";
}

// ============================================================================
// SimpleFuzzer Tests
// ============================================================================

TEST(TestHarness, SimpleFuzzer_generate_GeneratesWithinSizeRange) {
    SimpleFuzzer fuzzer(12345);  // Fixed seed for reproducibility
    
    for (int i = 0; i < 10; i++) {
        auto data = fuzzer.generate(10, 100);
        EXPECT_GE(data.size(), 10u);
        EXPECT_LE(data.size(), 100u);
    }
}

TEST(TestHarness, SimpleFuzzer_generate_SameSeedProducesSameSequence) {
    SimpleFuzzer fuzzer1(42);
    SimpleFuzzer fuzzer2(42);
    
    auto data1 = fuzzer1.generate(50, 50);
    auto data2 = fuzzer2.generate(50, 50);
    
    EXPECT_EQ(data1, data2);
}

TEST(TestHarness, SimpleFuzzer_generateEdgeCases_IncludesEmpty) {
    SimpleFuzzer fuzzer;
    auto cases = fuzzer.generateEdgeCases();
    
    EXPECT_GT(cases.size(), 0u);
    
    // First case should be empty
    EXPECT_EQ(cases[0].size(), 0u);
}

TEST(TestHarness, SimpleFuzzer_generateEdgeCases_IncludesSingleBytes) {
    SimpleFuzzer fuzzer;
    auto cases = fuzzer.generateEdgeCases();
    
    // Should include all 256 single-byte values (indices 1-256)
    for (int i = 0; i < 256; i++) {
        EXPECT_EQ(cases[i + 1].size(), 1u);
        EXPECT_EQ(cases[i + 1][0], static_cast<uint8_t>(i));
    }
}

TEST(TestHarness, SimpleFuzzer_generateEdgeCases_IncludesPowersOfTwo) {
    SimpleFuzzer fuzzer;
    auto cases = fuzzer.generateEdgeCases();
    
    // Check that we have sizes that are powers of 2
    bool has_power_of_2 = false;
    for (const auto& test_case : cases) {
        size_t size = test_case.size();
        // Check if size is a power of 2
        if (size > 0 && (size & (size - 1)) == 0) {
            has_power_of_2 = true;
            break;
        }
    }
    
    EXPECT_TRUE(has_power_of_2);
}

// ============================================================================
// Timing Utility Tests
// ============================================================================

TEST(TestHarness, measureTime_ReturnsPositiveDuration) {
    auto duration = measureTime([]() {
        volatile int sum = 0;
        for (int i = 0; i < 100; i++) {
            sum += i;
        }
    }, 10);
    
    EXPECT_GT(duration, 0.0);
}

TEST(TestHarness, measureTime_LongerOperationTakesMoreTime) {
    auto short_duration = measureTime([]() {
        volatile int sum = 0;
        (void)sum;  // Suppress warning
        sum = sum + 1;
    }, 100);
    
    auto long_duration = measureTime([]() {
        volatile int sum = 0;
        for (int i = 0; i < 10000; i++) {
            sum += i;
        }
    }, 100);
    
    // Longer operation should take more time (on average)
    // Note: This is probabilistic but should hold for most systems
    EXPECT_GT(long_duration, short_duration * 0.5);
}

TEST(TestHarness, isConstantTime_WithConstantTimes_ReturnsTrue) {
    std::vector<double> times = {100.0, 105.0, 98.0, 102.0, 103.0};
    EXPECT_TRUE(isConstantTime(times, 10.0));
}

TEST(TestHarness, isConstantTime_WithVariableTimes_ReturnsFalse) {
    std::vector<double> times = {100.0, 200.0, 100.0, 100.0};
    EXPECT_FALSE(isConstantTime(times, 10.0));
}

TEST(TestHarness, isConstantTime_WithEmptyVector_ReturnsTrue) {
    std::vector<double> times;
    EXPECT_TRUE(isConstantTime(times, 10.0));
}

TEST(TestHarness, isConstantTime_WithZeroTimes_ReturnsTrue) {
    std::vector<double> times = {0.0, 0.0, 0.0};
    EXPECT_TRUE(isConstantTime(times, 10.0));
}

// ============================================================================
// Test Fixture Tests
// ============================================================================

class TestCryptoTestFixture : public CryptoTestFixture {
public:
    void TestKeyGeneration() {
        auto key = generateKey(32);
        EXPECT_EQ(key.size(), 32u);
        
        auto key2 = generateKey(16);
        EXPECT_EQ(key2.size(), 16u);
    }
    
    void TestDataGeneration() {
        auto data = generateData(1024);
        EXPECT_EQ(data.size(), 1024u);
        
        auto data2 = generateData(512);
        EXPECT_EQ(data2.size(), 512u);
    }
};

TEST_F(TestCryptoTestFixture, generateKey_GeneratesCorrectSize) {
    TestKeyGeneration();
}

TEST_F(TestCryptoTestFixture, generateData_GeneratesCorrectSize) {
    TestDataGeneration();
}

class TestTimingTestFixture : public TimingTestFixture {};

TEST_F(TestTimingTestFixture, SetUp_DoesNotThrow) {
    // If we got here, SetUp() ran successfully
    SUCCEED();
}

// ============================================================================
// Assertion Helper Tests
// ============================================================================

TEST(TestHarness, ASSERT_ZEROED_WithZeroedMemory_Passes) {
    ByteBuffer buffer(100, 0x00);
    ASSERT_ZEROED(buffer.data(), buffer.size());
}

TEST(TestHarness, ASSERT_CONSTANT_TIME_WithConstantTimes_Passes) {
    std::vector<double> times = {100.0, 102.0, 99.0, 101.0};
    ASSERT_CONSTANT_TIME(times, 10.0);
}
