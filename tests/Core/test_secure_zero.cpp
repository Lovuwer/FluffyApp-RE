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
#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <array>

using namespace Sentinel;
using namespace Sentinel::Crypto;

// ============================================================================
// Unit Test 1: Basic Functionality
// ============================================================================

TEST(SecureZero, BasicFunctionality_256Bytes) {
    // Allocate 256-byte buffer
    constexpr size_t bufferSize = 256;
    std::vector<Byte> buffer(bufferSize);
    
    // Fill with 0xAA pattern
    std::memset(buffer.data(), 0xAA, bufferSize);
    
    // Verify buffer is filled with 0xAA
    for (size_t i = 0; i < bufferSize; ++i) {
        ASSERT_EQ(buffer[i], 0xAA) << "Buffer not properly initialized at index " << i;
    }
    
    // Call secureZero
    secureZero(buffer.data(), bufferSize);
    
    // Verify all bytes are now 0x00
    for (size_t i = 0; i < bufferSize; ++i) {
        EXPECT_EQ(buffer[i], 0x00) << "Buffer not zeroed at index " << i;
    }
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
    
    // Fill with non-zero pattern
    for (size_t i = 0; i < bufferSize; ++i) {
        buffer[i] = static_cast<Byte>(i & 0xFF);
    }
    
    // Call secureZero
    secureZero(buffer.data(), bufferSize);
    
    // Verify all bytes are zeroed
    // Sample check at various positions for efficiency
    EXPECT_EQ(buffer[0], 0x00) << "First byte not zeroed";
    EXPECT_EQ(buffer[bufferSize / 4], 0x00) << "Quarter position not zeroed";
    EXPECT_EQ(buffer[bufferSize / 2], 0x00) << "Middle not zeroed";
    EXPECT_EQ(buffer[3 * bufferSize / 4], 0x00) << "Three-quarter position not zeroed";
    EXPECT_EQ(buffer[bufferSize - 1], 0x00) << "Last byte not zeroed";
    
    // Full verification (may be slow, but ensures correctness)
    for (size_t i = 0; i < bufferSize; ++i) {
        if (buffer[i] != 0x00) {
            FAIL() << "Buffer not zeroed at index " << i;
        }
    }
}

// ============================================================================
// Unit Test 4: Adversarial - Optimizer Resistance
// ============================================================================

// Helper function that allocates local array, fills it, zeros it, and returns
// This function is designed to test whether the compiler optimizes away the
// secureZero call when the buffer is not read afterward.
__attribute__((noinline))  // GCC/Clang: prevent inlining
#ifdef _MSC_VER
__declspec(noinline)       // MSVC: prevent inlining
#endif
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
    
    // Fill entire buffer with pattern
    std::memset(buffer.data(), 0xBB, buffer.size());
    
    // Test with unaligned pointer (offset by 1)
    Byte* unalignedPtr = buffer.data() + 1;
    constexpr size_t testSize = 64;
    
    // Zero unaligned region
    secureZero(unalignedPtr, testSize);
    
    // Verify the unaligned region is zeroed
    for (size_t i = 0; i < testSize; ++i) {
        EXPECT_EQ(unalignedPtr[i], 0x00) << "Unaligned region not zeroed at offset " << i;
    }
    
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
    // Create a ByteBuffer with sensitive data
    ByteBuffer sensitiveData(512);
    for (size_t i = 0; i < sensitiveData.size(); ++i) {
        sensitiveData[i] = static_cast<Byte>(i & 0xFF);
    }
    
    // Zero the buffer
    secureZero(sensitiveData.data(), sensitiveData.size());
    
    // Verify all zeroed
    for (size_t i = 0; i < sensitiveData.size(); ++i) {
        EXPECT_EQ(sensitiveData[i], 0x00) << "ByteBuffer not zeroed at index " << i;
    }
}

// ============================================================================
// Performance Test (informational, not a failure condition)
// ============================================================================

TEST(SecureZero, Performance_10MB) {
    constexpr size_t size = 10 * 1024 * 1024;  // 10 MB
    std::vector<Byte> buffer(size);
    
    // Fill with pattern
    std::memset(buffer.data(), 0xAA, size);
    
    auto start = Clock::now();
    secureZero(buffer.data(), size);
    auto end = Clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Verify it was actually zeroed
    bool allZero = true;
    for (size_t i = 0; i < size && allZero; ++i) {
        if (buffer[i] != 0x00) {
            allZero = false;
        }
    }
    
    EXPECT_TRUE(allZero) << "10MB buffer not completely zeroed";
    
    // Print performance information (not a pass/fail criterion)
    std::cout << "Performance: Zeroed 10MB in " << duration.count() << " microseconds"
              << " (" << (10.0 / (duration.count() / 1000000.0)) << " MB/s)" << std::endl;
}
