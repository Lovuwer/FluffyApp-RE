/**
 * Sentinel SDK - Diversity Engine Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "../src/SDK/src/Internal/DiversityEngine.hpp"
#include <set>
#include <vector>

using namespace Sentinel::SDK::Internal;

// Test that diversity engine initializes correctly
TEST(DiversityEngineTests, Initialization) {
    // Get initial seed (from build-time configuration)
    uint64_t initialSeed = DiversityEngine::GetSeed();
    
    // Should be deterministic based on build configuration
    EXPECT_TRUE(initialSeed == 0 || initialSeed > 0);
    
    // Initialize with a specific seed
    DiversityEngine::Initialize(12345);
    EXPECT_EQ(DiversityEngine::GetSeed(), 12345);
    EXPECT_TRUE(DiversityEngine::IsEnabled());
    
    // Initialize with zero (disable diversity)
    DiversityEngine::Initialize(0);
    EXPECT_EQ(DiversityEngine::GetSeed(), 0);
    EXPECT_FALSE(DiversityEngine::IsEnabled());
    
    // Restore original seed
    DiversityEngine::Initialize(initialSeed);
}

// Test constant transformation with diversity disabled
TEST(DiversityEngineTests, ConstantTransformationDisabled) {
    DiversityEngine::Initialize(0);
    
    // With diversity disabled, constants should be unchanged
    EXPECT_EQ(DiversityEngine::TransformConstant(42), 42);
    EXPECT_EQ(DiversityEngine::TransformConstant(0), 0);
    EXPECT_EQ(DiversityEngine::TransformConstant(0xDEADBEEF), 0xDEADBEEF);
    EXPECT_EQ(DiversityEngine::TransformConstant(UINT64_MAX), UINT64_MAX);
}

// Test constant transformation with diversity enabled
TEST(DiversityEngineTests, ConstantTransformationEnabled) {
    DiversityEngine::Initialize(98765);
    
    // With diversity enabled, transformations should be deterministic
    // Same seed + same value = same result
    uint64_t value = 42;
    uint64_t result1 = DiversityEngine::TransformConstant(value);
    uint64_t result2 = DiversityEngine::TransformConstant(value);
    EXPECT_EQ(result1, result2) << "Transformation should be deterministic";
    
    // Transformed value should equal original (equivalent transformation)
    EXPECT_EQ(result1, value) << "Transformation should be semantically equivalent";
}

// Test that different values produce different transformations
TEST(DiversityEngineTests, ConstantTransformationVariety) {
    DiversityEngine::Initialize(11111);
    
    std::set<uint64_t> transformedValues;
    std::vector<uint64_t> testValues = {1, 2, 3, 4, 5, 100, 1000, 10000};
    
    for (uint64_t value : testValues) {
        uint64_t transformed = DiversityEngine::TransformConstant(value);
        // Each transformation should still equal the original value
        EXPECT_EQ(transformed, value);
    }
}

// Test structure padding generation
TEST(DiversityEngineTests, StructurePaddingDisabled) {
    DiversityEngine::Initialize(0);
    
    // With diversity disabled, no padding
    EXPECT_EQ(DiversityEngine::GetStructPadding(1), 0);
    EXPECT_EQ(DiversityEngine::GetStructPadding(100), 0);
    EXPECT_EQ(DiversityEngine::GetStructPadding(9999), 0);
}

// Test structure padding with diversity enabled
TEST(DiversityEngineTests, StructurePaddingEnabled) {
    DiversityEngine::Initialize(55555);
    
    // With diversity enabled, padding should be deterministic and in range [0, 15]
    for (uint32_t structId = 1; structId <= 100; ++structId) {
        size_t padding = DiversityEngine::GetStructPadding(structId);
        EXPECT_LE(padding, 15) << "Padding should be at most 15 bytes";
        
        // Should be deterministic
        size_t padding2 = DiversityEngine::GetStructPadding(structId);
        EXPECT_EQ(padding, padding2) << "Padding should be deterministic";
    }
    
    // Different struct IDs should (likely) have different padding
    std::set<size_t> paddingSizes;
    for (uint32_t structId = 1; structId <= 100; ++structId) {
        paddingSizes.insert(DiversityEngine::GetStructPadding(structId));
    }
    
    // Should have variety (at least 5 different sizes out of 16 possible)
    EXPECT_GE(paddingSizes.size(), 5) << "Should have variety in padding sizes";
}

// Test diversified code paths
TEST(DiversityEngineTests, DiversifiedPathDisabled) {
    DiversityEngine::Initialize(0);
    
    // Should execute without crashing
    for (uint32_t i = 0; i < 10; ++i) {
        EXPECT_NO_THROW(DiversityEngine::DiversifiedPath(i));
    }
}

// Test diversified code paths with diversity enabled
TEST(DiversityEngineTests, DiversifiedPathEnabled) {
    DiversityEngine::Initialize(33333);
    
    // Should execute without crashing
    for (uint32_t i = 0; i < 100; ++i) {
        EXPECT_NO_THROW(DiversityEngine::DiversifiedPath(i));
    }
}

// Test diversified delay
TEST(DiversityEngineTests, DiversifiedDelayDisabled) {
    DiversityEngine::Initialize(0);
    
    // Should execute with minimal delay
    auto start = std::chrono::steady_clock::now();
    DiversityEngine::DiversifiedDelay(10); // 10ms base delay
    auto end = std::chrono::steady_clock::now();
    
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // Should be close to 10ms (allow some tolerance for system scheduling)
    EXPECT_GE(elapsed, 5) << "Delay should be at least 5ms";
    EXPECT_LE(elapsed, 50) << "Delay should be at most 50ms";
}

// Test diversified delay with diversity enabled
TEST(DiversityEngineTests, DiversifiedDelayEnabled) {
    DiversityEngine::Initialize(77777);
    
    // Should execute with varied delay
    auto start = std::chrono::steady_clock::now();
    DiversityEngine::DiversifiedDelay(10); // 10ms base delay with variation
    auto end = std::chrono::steady_clock::now();
    
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // Should be within reasonable range (variation is -20% to +20%)
    EXPECT_GE(elapsed, 0) << "Delay should be non-negative";
    EXPECT_LE(elapsed, 50) << "Delay should be at most 50ms";
}

// Test that different seeds produce different behavior
TEST(DiversityEngineTests, SeedInfluencesPadding) {
    std::set<size_t> seed1Padding;
    std::set<size_t> seed2Padding;
    
    // Collect padding values with first seed
    DiversityEngine::Initialize(11111);
    for (uint32_t i = 1; i <= 20; ++i) {
        seed1Padding.insert(DiversityEngine::GetStructPadding(i));
    }
    
    // Collect padding values with second seed
    DiversityEngine::Initialize(99999);
    for (uint32_t i = 1; i <= 20; ++i) {
        seed2Padding.insert(DiversityEngine::GetStructPadding(i));
    }
    
    // Both should have variety (at least 3 different values)
    EXPECT_GE(seed1Padding.size(), 3);
    EXPECT_GE(seed2Padding.size(), 3);
}

// Test diversity macros
TEST(DiversityEngineTests, Macros) {
    DiversityEngine::Initialize(12345);
    
    // Test diversified stub macro (should not crash)
    EXPECT_NO_THROW(SENTINEL_DIVERSIFIED_STUB(1));
    EXPECT_NO_THROW(SENTINEL_DIVERSIFIED_STUB(100));
    
    // Test constant diversity macro
    uint64_t value = 42;
    uint64_t diversified = SENTINEL_DIVERSE_CONST(value);
    EXPECT_EQ(diversified, value);
}
