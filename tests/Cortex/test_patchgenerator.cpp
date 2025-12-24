/**
 * test_patchgenerator.cpp
 * Unit tests for PatchGenerator
 */

#include <gtest/gtest.h>
#include "PatchGen/PatchGenerator.hpp"

using namespace Sentinel::Cortex;

class PatchGeneratorTest : public ::testing::Test {
protected:
    void SetUp() override {
        generator = std::make_unique<PatchGenerator>();
        ASSERT_TRUE(generator->Initialize().isSuccess());
    }
    
    void TearDown() override {
        if (generator) {
            generator->Shutdown();
        }
    }
    
    std::unique_ptr<PatchGenerator> generator;
};

TEST_F(PatchGeneratorTest, CreateInlinePatch) {
    std::vector<uint8_t> original = {0x90, 0x90, 0x90};
    std::vector<uint8_t> replacement = {0xCC, 0xCC, 0xCC};
    
    auto result = generator->CreateInlinePatch(0x1000, original, replacement, "TestPatch");
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_EQ(result.value().name, "TestPatch");
    EXPECT_EQ(result.value().type, PatchType::Inline);
    EXPECT_EQ(result.value().target_address, 0x1000);
    EXPECT_EQ(result.value().original_bytes, original);
    EXPECT_EQ(result.value().patch_bytes, replacement);
}

TEST_F(PatchGeneratorTest, CreateNopPatch) {
    auto result = generator->CreateNopPatch(0x2000, 5, "NopTest");
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_EQ(result.value().name, "NopTest");
    EXPECT_EQ(result.value().patch_bytes.size(), 5);
    
    // All bytes should be NOPs (0x90 for x86/x64)
    for (auto byte : result.value().patch_bytes) {
        EXPECT_EQ(byte, 0x90);
    }
}

TEST_F(PatchGeneratorTest, CreateReturnPatch) {
    auto result = generator->CreateReturnPatch(0x3000, std::nullopt, "RetTest");
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_EQ(result.value().name, "RetTest");
    EXPECT_FALSE(result.value().patch_bytes.empty());
    
    // Should contain RET instruction (0xC3)
    EXPECT_EQ(result.value().patch_bytes.back(), 0xC3);
}

TEST_F(PatchGeneratorTest, CreateSignaturePatch) {
    std::string pattern = "48 8B 05 ?? ?? ?? ??";
    std::string mask = "xxx????";
    std::vector<uint8_t> replacement = {0x90, 0x90, 0x90};
    
    auto result = generator->CreateSignaturePatch(pattern, mask, replacement, 0, "SigPatch");
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_EQ(result.value().name, "SigPatch");
    EXPECT_EQ(result.value().type, PatchType::Signature);
    EXPECT_EQ(result.value().pattern, pattern);
    EXPECT_EQ(result.value().mask, mask);
}

TEST_F(PatchGeneratorTest, GenerateJump) {
    auto result = generator->GenerateJump(0x1000, 0x2000, PatchArchitecture::x64);
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_FALSE(result.value().empty());
    
    // Should be E9 (near jump) or MOV+JMP for far jump
    EXPECT_TRUE(result.value()[0] == 0xE9 || result.value()[0] == 0x48);
}

TEST_F(PatchGeneratorTest, PatchSetManagement) {
    auto patchSet = generator->CreatePatchSet("TestSet", "TestApp.exe");
    
    EXPECT_EQ(patchSet.name, "TestSet");
    EXPECT_EQ(patchSet.target_name, "TestApp.exe");
    EXPECT_TRUE(patchSet.patches.empty());
    
    // Add a patch
    auto patch = generator->CreateNopPatch(0x1000, 3, "Patch1");
    ASSERT_TRUE(patch.isSuccess());
    generator->AddPatchToSet(patchSet, patch.value());
    
    EXPECT_EQ(patchSet.patches.size(), 1);
    
    // Validate
    auto errors = generator->ValidatePatchSet(patchSet);
    EXPECT_TRUE(errors.empty());
}

TEST_F(PatchGeneratorTest, PatchUtilsByteConversion) {
    std::vector<uint8_t> bytes = {0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC};
    std::string hex = PatchUtils::BytesToHex(bytes);
    
    EXPECT_FALSE(hex.empty());
    EXPECT_NE(hex.find("48"), std::string::npos);
    
    auto parsed = PatchUtils::HexToBytes(hex);
    EXPECT_EQ(parsed, bytes);
}

TEST_F(PatchGeneratorTest, PatchUtilsPatternParsing) {
    std::string pattern = "48 8B 05 ?? ?? ?? ??";
    auto [bytes, mask] = PatchUtils::ParsePattern(pattern);
    
    EXPECT_EQ(bytes.size(), 7);
    EXPECT_EQ(mask.size(), 7);
    EXPECT_EQ(bytes[0], 0x48);
    EXPECT_EQ(bytes[1], 0x8B);
    EXPECT_EQ(bytes[2], 0x05);
    EXPECT_EQ(mask[0], 'x');
    EXPECT_EQ(mask[1], 'x');
    EXPECT_EQ(mask[2], 'x');
    EXPECT_EQ(mask[3], '?');
}

TEST_F(PatchGeneratorTest, RelativeOffsetCalculation) {
    int32_t offset = PatchUtils::CalculateRelativeOffset(0x1000, 0x2000, 5);
    EXPECT_EQ(offset, 0x2000 - 0x1000 - 5);
}

TEST_F(PatchGeneratorTest, CreateCodecavePatch) {
    std::vector<uint8_t> caveCode = {0x90, 0x90, 0xC3};
    auto result = generator->CreateCodecavePatch(0x5000, caveCode, "CavePatch");
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_EQ(result.value().name, "CavePatch");
    EXPECT_EQ(result.value().type, PatchType::Codecave);
    EXPECT_EQ(result.value().hook_code, caveCode);
}

TEST_F(PatchGeneratorTest, EmptyBytesError) {
    std::vector<uint8_t> empty;
    std::vector<uint8_t> valid = {0x90};
    
    auto result = generator->CreateInlinePatch(0x1000, empty, valid);
    EXPECT_FALSE(result.isSuccess());
}

TEST_F(PatchGeneratorTest, ExportAsCppSource) {
    auto patchSet = generator->CreatePatchSet("ExportTest", "test.exe");
    auto patch = generator->CreateNopPatch(0x1000, 3, "TestPatch");
    
    if (patch.isSuccess()) {
        generator->AddPatchToSet(patchSet, patch.value());
    }
    
    std::string outputPath = "/tmp/test_export.cpp";
    auto result = generator->ExportAsCpp(patchSet, outputPath);
    
    EXPECT_TRUE(result.isSuccess());
}

TEST_F(PatchGeneratorTest, PatchTypeToString) {
    EXPECT_EQ(PatchUtils::PatchTypeToString(PatchType::Inline), "Inline");
    EXPECT_EQ(PatchUtils::PatchTypeToString(PatchType::Detour), "Detour");
    EXPECT_EQ(PatchUtils::PatchTypeToString(PatchType::Signature), "Signature");
}

TEST_F(PatchGeneratorTest, ArchToString) {
    EXPECT_EQ(PatchUtils::ArchToString(PatchArchitecture::x86), "x86");
    EXPECT_EQ(PatchUtils::ArchToString(PatchArchitecture::x64), "x64");
    EXPECT_EQ(PatchUtils::ArchToString(PatchArchitecture::ARM64), "ARM64");
}
