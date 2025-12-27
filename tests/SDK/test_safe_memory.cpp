/**
 * Sentinel SDK - SafeMemory Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 6: Tests for Crash-Safe Memory Access
 */

#include <gtest/gtest.h>
#include "Internal/SafeMemory.hpp"
#include <vector>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace Sentinel::SDK;

/**
 * Test 1: SafeRead with valid memory
 * Verifies that SafeRead successfully reads from valid memory
 */
TEST(SafeMemoryTests, SafeReadValidMemory) {
    // Create a valid buffer
    uint8_t source[32];
    for (int i = 0; i < 32; i++) {
        source[i] = static_cast<uint8_t>(i);
    }
    
    uint8_t dest[32];
    memset(dest, 0, 32);
    
    // Should succeed
    bool result = SafeMemory::SafeRead(source, dest, 32);
    
    EXPECT_TRUE(result) << "SafeRead should succeed with valid memory";
    EXPECT_EQ(0, memcmp(source, dest, 32)) << "Data should match";
}

/**
 * Test 2: SafeRead with null pointer
 * Verifies that SafeRead returns false for null pointer
 */
TEST(SafeMemoryTests, SafeReadNullPointer) {
    uint8_t dest[32];
    
    bool result = SafeMemory::SafeRead(nullptr, dest, 32);
    
    EXPECT_FALSE(result) << "SafeRead should fail with null pointer";
}

/**
 * Test 3: SafeCompare with matching memory
 * Verifies that SafeCompare returns true for matching memory
 */
TEST(SafeMemoryTests, SafeCompareMatching) {
    uint8_t buffer1[32];
    uint8_t buffer2[32];
    
    for (int i = 0; i < 32; i++) {
        buffer1[i] = static_cast<uint8_t>(i * 2);
        buffer2[i] = static_cast<uint8_t>(i * 2);
    }
    
    bool result = SafeMemory::SafeCompare(buffer1, buffer2, 32);
    
    EXPECT_TRUE(result) << "SafeCompare should return true for matching memory";
}

/**
 * Test 4: SafeCompare with non-matching memory
 * Verifies that SafeCompare returns false for non-matching memory
 */
TEST(SafeMemoryTests, SafeCompareNonMatching) {
    uint8_t buffer1[32];
    uint8_t buffer2[32];
    
    for (int i = 0; i < 32; i++) {
        buffer1[i] = static_cast<uint8_t>(i);
        buffer2[i] = static_cast<uint8_t>(i + 1);
    }
    
    bool result = SafeMemory::SafeCompare(buffer1, buffer2, 32);
    
    EXPECT_FALSE(result) << "SafeCompare should return false for non-matching memory";
}

/**
 * Test 5: IsReadable with valid memory
 * Verifies that IsReadable returns true for valid memory
 */
TEST(SafeMemoryTests, IsReadableValidMemory) {
    uint8_t buffer[128];
    memset(buffer, 0, 128);
    
    bool result = SafeMemory::IsReadable(buffer, 128);
    
    EXPECT_TRUE(result) << "IsReadable should return true for valid memory";
}

/**
 * Test 6: IsReadable with null pointer
 * Verifies that IsReadable returns false for null pointer
 */
TEST(SafeMemoryTests, IsReadableNullPointer) {
    bool result = SafeMemory::IsReadable(nullptr, 128);
    
    EXPECT_FALSE(result) << "IsReadable should return false for null pointer";
}

/**
 * Test 7: SafeHash with valid memory
 * Verifies that SafeHash computes a hash of valid memory
 */
TEST(SafeMemoryTests, SafeHashValidMemory) {
    uint8_t buffer[64];
    for (int i = 0; i < 64; i++) {
        buffer[i] = static_cast<uint8_t>(i);
    }
    
    uint64_t hash1 = 0;
    uint64_t hash2 = 0;
    
    bool result1 = SafeMemory::SafeHash(buffer, 64, &hash1);
    bool result2 = SafeMemory::SafeHash(buffer, 64, &hash2);
    
    EXPECT_TRUE(result1) << "SafeHash should succeed with valid memory";
    EXPECT_TRUE(result2) << "SafeHash should succeed with valid memory";
    EXPECT_EQ(hash1, hash2) << "Identical buffers should produce identical hashes";
    EXPECT_NE(hash1, 0ULL) << "Hash should not be zero";
}

/**
 * Test 8: SafeHash with different data produces different hash
 * Verifies that SafeHash produces different hashes for different data
 */
TEST(SafeMemoryTests, SafeHashDifferentData) {
    uint8_t buffer1[64];
    uint8_t buffer2[64];
    
    for (int i = 0; i < 64; i++) {
        buffer1[i] = static_cast<uint8_t>(i);
        buffer2[i] = static_cast<uint8_t>(i + 1);
    }
    
    uint64_t hash1 = 0;
    uint64_t hash2 = 0;
    
    SafeMemory::SafeHash(buffer1, 64, &hash1);
    SafeMemory::SafeHash(buffer2, 64, &hash2);
    
    EXPECT_NE(hash1, hash2) << "Different data should produce different hashes";
}

/**
 * Test 9: SafeHash with null pointer
 * Verifies that SafeHash returns false for null pointer
 */
TEST(SafeMemoryTests, SafeHashNullPointer) {
    uint64_t hash = 0;
    
    bool result = SafeMemory::SafeHash(nullptr, 64, &hash);
    
    EXPECT_FALSE(result) << "SafeHash should fail with null pointer";
}

#ifdef _WIN32
/**
 * Test 10: IsReadable with invalid memory (Windows only)
 * Verifies that IsReadable returns false for invalid memory addresses
 */
TEST(SafeMemoryTests, IsReadableInvalidMemory) {
    // Try an address that's likely to be invalid (high address space)
    void* invalidAddr = reinterpret_cast<void*>(0x0000DEAD00000000ULL);
    
    bool result = SafeMemory::IsReadable(invalidAddr, 128);
    
    EXPECT_FALSE(result) << "IsReadable should return false for invalid memory";
}

/**
 * Test 11: SafeRead with freed memory (Windows only)
 * Verifies that SafeRead returns false when reading freed memory
 */
TEST(SafeMemoryTests, SafeReadFreedMemory) {
    // Allocate and then free memory
    void* buffer = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(buffer, nullptr) << "VirtualAlloc should succeed";
    
    VirtualFree(buffer, 0, MEM_RELEASE);
    
    // Try to read from freed memory
    uint8_t dest[32];
    bool result = SafeMemory::SafeRead(buffer, dest, 32);
    
    EXPECT_FALSE(result) << "SafeRead should fail with freed memory";
}

/**
 * Test 12: SafeCompare with inaccessible memory (Windows only)
 * Verifies that SafeCompare returns false when comparing inaccessible memory
 */
TEST(SafeMemoryTests, SafeCompareInaccessibleMemory) {
    uint8_t buffer[32];
    memset(buffer, 0x42, 32);
    
    // Allocate memory with no access
    void* noAccessMem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(noAccessMem, nullptr) << "VirtualAlloc should succeed";
    
    // Try to compare with inaccessible memory
    bool result = SafeMemory::SafeCompare(noAccessMem, buffer, 32);
    
    EXPECT_FALSE(result) << "SafeCompare should fail with inaccessible memory";
    
    VirtualFree(noAccessMem, 0, MEM_RELEASE);
}

/**
 * Test 13: SafeHash with protected memory pages (Windows only)
 * Verifies that SafeHash can read from protected memory
 */
TEST(SafeMemoryTests, SafeHashProtectedMemory) {
    // Allocate read-only memory
    void* readOnlyMem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(readOnlyMem, nullptr) << "VirtualAlloc should succeed";
    
    uint64_t hash = 0;
    bool result = SafeMemory::SafeHash(readOnlyMem, 4096, &hash);
    
    EXPECT_TRUE(result) << "SafeHash should succeed with readable memory";
    
    VirtualFree(readOnlyMem, 0, MEM_RELEASE);
}

/**
 * Test 14: Multiple concurrent SafeRead operations
 * Verifies that SafeMemory operations work correctly with multiple buffers
 */
TEST(SafeMemoryTests, MultipleSafeRead) {
    const int numBuffers = 100;
    std::vector<uint8_t*> buffers;
    
    // Create multiple buffers
    for (int i = 0; i < numBuffers; i++) {
        uint8_t* buffer = new uint8_t[128];
        memset(buffer, static_cast<uint8_t>(i), 128);
        buffers.push_back(buffer);
    }
    
    // Read from all buffers
    bool allSuccess = true;
    for (int i = 0; i < numBuffers; i++) {
        uint8_t dest[128];
        if (!SafeMemory::SafeRead(buffers[i], dest, 128)) {
            allSuccess = false;
        }
    }
    
    EXPECT_TRUE(allSuccess) << "All SafeRead operations should succeed";
    
    // Cleanup
    for (auto* buffer : buffers) {
        delete[] buffer;
    }
}
#endif

/**
 * Test 15: SafeRead with zero size
 * Verifies that SafeRead handles zero size correctly
 */
TEST(SafeMemoryTests, SafeReadZeroSize) {
    uint8_t buffer[32];
    uint8_t dest[32];
    
    bool result = SafeMemory::SafeRead(buffer, dest, 0);
    
    EXPECT_FALSE(result) << "SafeRead should fail with zero size";
}
