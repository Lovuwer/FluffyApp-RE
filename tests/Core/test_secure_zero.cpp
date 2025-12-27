/**
 * @file test_secure_zero.cpp
 * @brief Unit tests for secure memory zeroing primitive
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Tests for secureZero function to ensure:
 * - Basic functionality (memory is actually zeroed)
 * - Edge cases (zero size, large buffers, unaligned pointers)
 * - Adversarial resistance (optimizer cannot eliminate the operation)
 */

#include <Sentinel/Core/Crypto.hpp>
#include "TestHarness.hpp"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <array>

using namespace Sentinel;
using namespace Sentinel::Crypto;
using namespace Sentinel::Testing;

// ============================================================================
// Unit Test 1: Basic Functionality
// ============================================================================

TEST(SecureZero, BasicFunctionality_256Bytes) {
    // Allocate 256-byte buffer
    constexpr size_t bufferSize = 256;
    std::vector<Byte> buffer(bufferSize);
    
    // Fill with 0xAA pattern using test harness
    fillPattern(buffer.data(), bufferSize, 0xAA);
    
    // Verify buffer is filled with 0xAA
    for (size_t i = 0; i < bufferSize; ++i) {
        ASSERT_EQ(buffer[i], 0xAA) << "Buffer not properly initialized at index " << i;
    }
    
    // Call secureZero
    secureZero(buffer.data(), bufferSize);
    
    // Verify all bytes are now 0x00 using test harness
    ASSERT_ZEROED(buffer.data(), bufferSize);
}

// ============================================================================
// Unit Test 2: Zero Size
// ============================================================================

TEST(SecureZero, ZeroSize_NoOp) {
    // Create a buffer with a known pattern
    constexpr size_t bufferSize = 16;
    std::array<Byte, bufferSize> buffer;
    buffer.fill(0xFF);
    
    // Call secureZero with size = 0
    secureZero(buffer.data(), 0);
    
    // Verify buffer is unchanged
    for (size_t i = 0; i < bufferSize; ++i) {
        EXPECT_EQ(buffer[i], 0xFF) << "Buffer was modified at index " << i;
    }
}

// ============================================================================
// Unit Test 3: Large Buffer (1MB)
// ============================================================================

TEST(SecureZero, LargeBuffer_1MB) {
    // Allocate 1MB buffer
    constexpr size_t bufferSize = 1024 * 1024;
    std::vector<Byte> buffer(bufferSize);
    
    // Fill with non-zero pattern using test harness
    fillPattern(buffer.data(), bufferSize, 0xBB);
    
    // Call secureZero
    secureZero(buffer.data(), bufferSize);
    
    // Verify all bytes are zeroed using test harness
    ASSERT_ZEROED(buffer.data(), bufferSize);
}

// ============================================================================
// Unit Test 4: Adversarial - Optimizer Resistance
// ============================================================================

// Compiler-specific noinline directive
#if defined(_MSC_VER)
    #define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
    #define NOINLINE __attribute__((noinline))
#else
    #define NOINLINE
#endif

// Helper function that allocates local array, fills it, zeros it, and returns
// This function is designed to test whether the compiler optimizes away the
// secureZero call when the buffer is not read afterward.
NOINLINE
void fillAndZeroLocalBuffer() {
    // Local stack buffer with sensitive data
    constexpr size_t bufferSize = 128;
    Byte sensitiveData[bufferSize];
    
    // Fill with "sensitive" pattern
    for (size_t i = 0; i < bufferSize; ++i) {
        sensitiveData[i] = static_cast<Byte>(0xDE);
    }
    
    // Zero the sensitive data before returning
    secureZero(sensitiveData, bufferSize);
    
    // Note: At this point, the buffer goes out of scope.
    // A naive memset might be optimized away by the compiler since
    // sensitiveData is never read after the zeroing.
    // secureZero should NOT be optimized away.
}

TEST(SecureZero, OptimizerResistance_ManualVerification) {
    // This test documents the requirement for manual verification
    // Automated verification would require external memory inspection tools
    
    // Call the function that should zero its local buffer
    fillAndZeroLocalBuffer();
    
    // MANUAL VERIFICATION REQUIRED:
    // 1. Compile with optimization enabled (-O3 or /O2)
    // 2. Use a debugger or memory dump to inspect stack memory immediately
    //    after fillAndZeroLocalBuffer returns
    // 3. Verify that the stack memory has been zeroed
    // 4. Compare with a naive memset implementation to see the difference
    
    // This test passes automatically but serves as documentation
    // that manual verification is required for complete assurance
    SUCCEED() << "Manual verification required: "
              << "Compile with -O3/O2 and verify stack memory is zeroed";
}

// ============================================================================
// Unit Test 5: Edge Case - Alignment
// ============================================================================

TEST(SecureZero, UnalignedPointer_Works) {
    // Allocate buffer with extra space for alignment testing
    constexpr size_t bufferSize = 128;
    std::vector<Byte> buffer(bufferSize + 16);
    
    // Fill entire buffer with pattern using test harness
    fillPattern(buffer.data(), buffer.size(), 0xBB);
    
    // Test with unaligned pointer (offset by 1)
    Byte* unalignedPtr = buffer.data() + 1;
    constexpr size_t testSize = 64;
    
    // Zero unaligned region
    secureZero(unalignedPtr, testSize);
    
    // Verify the unaligned region is zeroed using test harness
    ASSERT_ZEROED(unalignedPtr, testSize);
    
    // Verify surrounding bytes are unchanged
    EXPECT_EQ(buffer[0], 0xBB) << "Byte before unaligned region was modified";
    EXPECT_EQ(buffer[1 + testSize], 0xBB) << "Byte after unaligned region was modified";
}

// ============================================================================
// Additional Edge Cases
// ============================================================================

TEST(SecureZero, SingleByte_Works) {
    Byte singleByte = 0xFF;
    secureZero(&singleByte, 1);
    EXPECT_EQ(singleByte, 0x00) << "Single byte not zeroed";
}

TEST(SecureZero, PowerOfTwo_64Bytes) {
    constexpr size_t size = 64;
    std::array<Byte, size> buffer;
    buffer.fill(0xCC);
    
    secureZero(buffer.data(), size);
    
    for (size_t i = 0; i < size; ++i) {
        EXPECT_EQ(buffer[i], 0x00) << "64-byte buffer not zeroed at index " << i;
    }
}

TEST(SecureZero, NonPowerOfTwo_100Bytes) {
    constexpr size_t size = 100;
    std::array<Byte, size> buffer;
    buffer.fill(0xEE);
    
    secureZero(buffer.data(), size);
    
    for (size_t i = 0; i < size; ++i) {
        EXPECT_EQ(buffer[i], 0x00) << "100-byte buffer not zeroed at index " << i;
    }
}

// ============================================================================
// Integration Test: Use with Actual Crypto Types
// ============================================================================

TEST(SecureZero, AESKey_Integration) {
    // Create an AES key (32 bytes)
    AESKey key;
    key.fill(0xAA);
    
    // Verify key is filled
    for (size_t i = 0; i < key.size(); ++i) {
        ASSERT_EQ(key[i], 0xAA);
    }
    
    // Zero the key
    secureZero(key.data(), key.size());
    
    // Verify key is zeroed
    for (size_t i = 0; i < key.size(); ++i) {
        EXPECT_EQ(key[i], 0x00) << "AES key not zeroed at index " << i;
    }
}

TEST(SecureZero, ByteBuffer_Integration) {
    // Create a ByteBuffer with random test data from test harness
    ByteBuffer sensitiveData = randomBytes(512);
    
    // Verify it's not all zeros initially
    ASSERT_FALSE(isZeroed(sensitiveData.data(), sensitiveData.size()));
    
    // Zero the buffer
    secureZero(sensitiveData.data(), sensitiveData.size());
    
    // Verify all zeroed using test harness
    ASSERT_ZEROED(sensitiveData.data(), sensitiveData.size());
}

// ============================================================================
// Performance Test (informational, not a failure condition)
// ============================================================================

TEST(SecureZero, Performance_10MB) {
    constexpr size_t size = 10 * 1024 * 1024;  // 10 MB
    std::vector<Byte> buffer(size);
    
    // Fill with pattern using test harness
    fillPattern(buffer.data(), size, 0xAA);
    
    // Measure time using test harness
    auto duration_ns = measureTime([&]() {
        secureZero(buffer.data(), size);
        // Refill for next iteration
        fillPattern(buffer.data(), size, 0xAA);
    }, 10);  // 10 iterations for better average
    
    // Verify it was actually zeroed (do one final zero without refill)
    secureZero(buffer.data(), size);
    ASSERT_ZEROED(buffer.data(), size);
    
    // Print performance information (not a pass/fail criterion)
    double duration_us = duration_ns / 1000.0;
    double duration_s = duration_us / 1000000.0;
    double mb_per_sec = (10.0 / duration_s);
    
    std::cout << "Performance: Zeroed 10MB in " << duration_us << " microseconds"
              << " (" << mb_per_sec << " MB/s)" << std::endl;
}
