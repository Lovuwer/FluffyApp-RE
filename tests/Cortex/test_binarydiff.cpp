/**
 * Sentinel Cortex - BinaryDiffer Tests
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "../../src/Cortex/Analysis/BinaryDiffer.hpp"
#include <Sentinel/Core/Types.hpp>

using namespace Sentinel::Cortex;
using namespace Sentinel::Core;

/**
 * Test basic binary diffing functionality
 */
TEST(BinaryDifferTest, BasicByteDiff) {
    BinaryDifferConfig config;
    config.include_byte_diffs = true;
    
    BinaryDiffer differ(config);
    ASSERT_TRUE(differ.Initialize().isSuccess());
    
    // Create two simple buffers
    ByteBuffer source = {0x01, 0x02, 0x03, 0x04, 0x05};
    ByteBuffer target = {0x01, 0x02, 0xFF, 0x04, 0x05};
    
    auto result = differ.DiffBuffers(source, target);
    
    ASSERT_TRUE(result.isSuccess());
    
    const auto& diff = result.value();
    
    // Should detect one byte difference at offset 2
    EXPECT_EQ(diff.byte_diffs.size(), 1);
    EXPECT_EQ(diff.byte_diffs[0].offset, 2);
    EXPECT_EQ(diff.byte_diffs[0].source_byte, 0x03);
    EXPECT_EQ(diff.byte_diffs[0].target_byte, 0xFF);
    EXPECT_EQ(diff.byte_diffs[0].type, DiffType::Modified);
    
    // Similarity should be 80% (4 out of 5 bytes match)
    EXPECT_NEAR(diff.overall_similarity, 0.8f, 0.01f);
}

/**
 * Test identical buffers
 */
TEST(BinaryDifferTest, IdenticalBuffers) {
    BinaryDifferConfig config;
    BinaryDiffer differ(config);
    
    ByteBuffer source = {0x01, 0x02, 0x03, 0x04, 0x05};
    ByteBuffer target = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    auto result = differ.DiffBuffers(source, target);
    
    ASSERT_TRUE(result.isSuccess());
    
    const auto& diff = result.value();
    
    // Should have no differences
    EXPECT_EQ(diff.total_bytes_changed, 0);
    EXPECT_EQ(diff.overall_similarity, 1.0f);
}

/**
 * Test completely different buffers
 */
TEST(BinaryDifferTest, CompletelyDifferent) {
    BinaryDifferConfig config;
    config.include_byte_diffs = true;
    
    BinaryDiffer differ(config);
    
    ByteBuffer source = {0x01, 0x02, 0x03, 0x04, 0x05};
    ByteBuffer target = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB};
    
    auto result = differ.DiffBuffers(source, target);
    
    ASSERT_TRUE(result.isSuccess());
    
    const auto& diff = result.value();
    
    // All 5 bytes should be different
    EXPECT_EQ(diff.byte_diffs.size(), 5);
    EXPECT_EQ(diff.overall_similarity, 0.0f);
}

/**
 * Test different sized buffers
 */
TEST(BinaryDifferTest, DifferentSizes) {
    BinaryDifferConfig config;
    config.include_byte_diffs = true;
    
    BinaryDiffer differ(config);
    
    ByteBuffer source = {0x01, 0x02, 0x03};
    ByteBuffer target = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    auto result = differ.DiffBuffers(source, target);
    
    ASSERT_TRUE(result.isSuccess());
    
    const auto& diff = result.value();
    
    // Should detect 2 added bytes
    EXPECT_GE(diff.byte_diffs.size(), 2);
}

/**
 * Test patch generation
 */
TEST(BinaryDifferTest, PatchGeneration) {
    BinaryDifferConfig config;
    config.include_byte_diffs = true;
    
    BinaryDiffer differ(config);
    
    ByteBuffer source = {0x01, 0x02, 0x03, 0x04, 0x05};
    ByteBuffer target = {0x01, 0x02, 0xFF, 0x04, 0x05};
    
    auto diff_result = differ.DiffBuffers(source, target);
    ASSERT_TRUE(diff_result.isSuccess());
    
    auto patch_result = differ.GeneratePatch(diff_result.value());
    ASSERT_TRUE(patch_result.isSuccess());
    
    const auto& patch_data = patch_result.value();
    
    // Patch should contain header and data
    EXPECT_GT(patch_data.size(), 5);
}

/**
 * Test patch instructions
 */
TEST(BinaryDifferTest, PatchInstructions) {
    BinaryDifferConfig config;
    config.include_byte_diffs = true;
    
    BinaryDiffer differ(config);
    
    ByteBuffer source = {0x01, 0x02, 0x03};
    ByteBuffer target = {0x01, 0xFF, 0x03};
    
    auto diff_result = differ.DiffBuffers(source, target);
    ASSERT_TRUE(diff_result.isSuccess());
    
    auto instructions = differ.GeneratePatchInstructions(diff_result.value());
    
    EXPECT_EQ(instructions.size(), 1);
    EXPECT_TRUE(instructions[0].find("0x1") != std::string::npos ||
                instructions[0].find("0x01") != std::string::npos);
}

/**
 * Test similarity threshold
 */
TEST(BinaryDifferTest, SimilarityThreshold) {
    BinaryDifferConfig config;
    config.similarity_threshold = 0.7f;
    
    BinaryDiffer differ(config);
    
    const auto& cfg = differ.GetConfig();
    EXPECT_EQ(cfg.similarity_threshold, 0.7f);
}

/**
 * Test utility functions
 */
TEST(BinaryDiffUtilsTest, DiffTypeToString) {
    EXPECT_EQ(BinaryDiffUtils::DiffTypeToString(DiffType::Added), "Added");
    EXPECT_EQ(BinaryDiffUtils::DiffTypeToString(DiffType::Removed), "Removed");
    EXPECT_EQ(BinaryDiffUtils::DiffTypeToString(DiffType::Modified), "Modified");
    EXPECT_EQ(BinaryDiffUtils::DiffTypeToString(DiffType::Moved), "Moved");
    EXPECT_EQ(BinaryDiffUtils::DiffTypeToString(DiffType::Identical), "Identical");
}

/**
 * Test Levenshtein distance
 */
TEST(BinaryDiffUtilsTest, LevenshteinDistance) {
    std::vector<uint8_t> a = {0x01, 0x02, 0x03};
    std::vector<uint8_t> b = {0x01, 0x02, 0x04};
    
    int distance = BinaryDiffUtils::LevenshteinDistance(a, b);
    EXPECT_EQ(distance, 1);
    
    std::vector<uint8_t> c = {0x01, 0x02, 0x03};
    std::vector<uint8_t> d = {0x01, 0x02, 0x03};
    
    distance = BinaryDiffUtils::LevenshteinDistance(c, d);
    EXPECT_EQ(distance, 0);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
