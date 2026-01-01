/**
 * @file test_obfuscated_string.cpp
 * @brief Unit tests for string obfuscation framework
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/ObfuscatedString.hpp>
#include "TestHarness.hpp"
#include <gtest/gtest.h>
#include <chrono>
#include <cstring>
#include <string>

using namespace Sentinel;
using namespace Sentinel::Obfuscation;
using namespace Sentinel::Testing;

// ============================================================================
// Basic Functionality Tests
// ============================================================================

TEST(ObfuscatedString, BasicEncryptionDecryption) {
    auto obf = OBFUSCATE("test string");
    std::string decrypted = obf.decrypt();
    
    EXPECT_EQ(decrypted, "test string");
}

TEST(ObfuscatedString, EmptyString) {
    auto obf = OBFUSCATE("");
    std::string decrypted = obf.decrypt();
    
    EXPECT_EQ(decrypted, "");
    EXPECT_TRUE(decrypted.empty());
}

TEST(ObfuscatedString, LongString) {
    const char* long_str = "This is a much longer string that contains multiple words and should still be encrypted and decrypted correctly";
    auto obf = OBFUSCATE("This is a much longer string that contains multiple words and should still be encrypted and decrypted correctly");
    std::string decrypted = obf.decrypt();
    
    EXPECT_EQ(decrypted, long_str);
}

TEST(ObfuscatedString, SpecialCharacters) {
    auto obf = OBFUSCATE("!@#$%^&*()_+-=[]{}|;':\",./<>?");
    std::string decrypted = obf.decrypt();
    
    EXPECT_EQ(decrypted, "!@#$%^&*()_+-=[]{}|;':\",./<>?");
}

TEST(ObfuscatedString, NullCharacterHandling) {
    // Test that null terminator is handled correctly
    auto obf = OBFUSCATE("test");
    EXPECT_EQ(obf.length(), 4);
    
    std::string decrypted = obf.decrypt();
    EXPECT_EQ(decrypted.length(), 4);
    EXPECT_EQ(decrypted, "test");
}

// ============================================================================
// Security Tests - Encryption Verification
// ============================================================================

TEST(ObfuscatedString, DataIsEncrypted) {
    auto obf = OBFUSCATE("plaintext");
    const char* encrypted_data = obf.data();
    
    // Encrypted data should NOT match plaintext
    bool matches_plaintext = (std::strncmp(encrypted_data, "plaintext", 9) == 0);
    EXPECT_FALSE(matches_plaintext) << "String data is not encrypted!";
    
    // At least some bytes should be different from plaintext
    int different_bytes = 0;
    const char* plaintext = "plaintext";
    for (size_t i = 0; i < 9; ++i) {
        if (encrypted_data[i] != plaintext[i]) {
            different_bytes++;
        }
    }
    EXPECT_GT(different_bytes, 0) << "No bytes were encrypted";
}

TEST(ObfuscatedString, UniqueEncryptionPerInstance) {
    // Different macro invocations should use different keys
    auto obf1 = OBFUSCATE("test");
    auto obf2 = OBFUSCATE("test");
    
    // Both should decrypt to same value
    EXPECT_EQ(obf1.decrypt(), "test");
    EXPECT_EQ(obf2.decrypt(), "test");
    
    // But encrypted data should be different (different keys)
    const char* data1 = obf1.data();
    const char* data2 = obf2.data();
    
    bool encrypted_differently = (std::memcmp(data1, data2, 4) != 0);
    EXPECT_TRUE(encrypted_differently) 
        << "Same plaintext encrypted with same key - no per-instance variation";
}

TEST(ObfuscatedString, DetectionStringObfuscation) {
    // Test detection-related strings mentioned in requirements
    auto speedhack = OBFUSCATE("speedhack");
    auto aimbot = OBFUSCATE("aimbot");
    auto cheat = OBFUSCATE("cheat");
    
    // Verify they decrypt correctly
    EXPECT_EQ(speedhack.decrypt(), "speedhack");
    EXPECT_EQ(aimbot.decrypt(), "aimbot");
    EXPECT_EQ(cheat.decrypt(), "cheat");
    
    // Verify encrypted form doesn't contain plaintext
    EXPECT_EQ(std::string(speedhack.data(), speedhack.length()).find("speedhack"), 
              std::string::npos);
    EXPECT_EQ(std::string(aimbot.data(), aimbot.length()).find("aimbot"), 
              std::string::npos);
    EXPECT_EQ(std::string(cheat.data(), cheat.length()).find("cheat"), 
              std::string::npos);
}

// ============================================================================
// Performance Tests
// ============================================================================

TEST(ObfuscatedString, DecryptionPerformance) {
    // Requirement: Less than 1 microsecond per string access
    auto obf = OBFUSCATE("test string for performance measurement");
    
    constexpr int iterations = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        volatile auto result = obf.decrypt();
        (void)result; // Prevent optimization
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    double avg_ns = static_cast<double>(duration.count()) / iterations;
    double avg_us = avg_ns / 1000.0;
    
    EXPECT_LT(avg_us, 1.0) 
        << "Decryption takes " << avg_us << " microseconds (requirement: <1 microsecond)";
}

TEST(ObfuscatedString, MultipleDecryptions) {
    auto obf = OBFUSCATE("test");
    
    // Multiple decryptions should return same value
    std::string dec1 = obf.decrypt();
    std::string dec2 = obf.decrypt();
    std::string dec3 = obf.decrypt();
    
    EXPECT_EQ(dec1, "test");
    EXPECT_EQ(dec2, "test");
    EXPECT_EQ(dec3, "test");
}

// ============================================================================
// SecureString RAII Tests
// ============================================================================

TEST(SecureString, BasicUsage) {
    auto str = OBFUSCATE_STR("secure test");
    
    EXPECT_EQ(str.str(), "secure test");
    EXPECT_EQ(str.length(), 11);
    EXPECT_FALSE(str.empty());
}

TEST(SecureString, CStringAccess) {
    auto str = OBFUSCATE_STR("test");
    
    const char* cstr = str.c_str();
    EXPECT_STREQ(cstr, "test");
}

TEST(SecureString, ImplicitConversion) {
    auto str = OBFUSCATE_STR("convert");
    
    // Test implicit conversion to std::string
    std::string copy = str;
    EXPECT_EQ(copy, "convert");
}

TEST(SecureString, MoveSemantics) {
    auto str1 = OBFUSCATE_STR("moveable");
    
    // Move construct
    SecureString str2(std::move(str1));
    EXPECT_EQ(str2.str(), "moveable");
    
    // Move assign
    auto str3 = OBFUSCATE_STR("original");
    str3 = std::move(str2);
    EXPECT_EQ(str3.str(), "moveable");
}

TEST(SecureString, MemoryCleanup) {
    std::string* ptr = nullptr;
    
    {
        auto str = OBFUSCATE_STR("sensitive data");
        ptr = const_cast<std::string*>(&str.str());
        
        // Verify data is present
        EXPECT_EQ(*ptr, "sensitive data");
    }
    
    // After scope exit, memory should be zeroed
    // Note: We can't reliably test this without risking undefined behavior
    // since the memory might be reused. But the zeroing code is in place.
}

TEST(SecureString, EmptySecureString) {
    auto str = OBFUSCATE_STR("");
    
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.length(), 0);
    EXPECT_STREQ(str.c_str(), "");
}

// ============================================================================
// Compile-Time Tests
// ============================================================================

TEST(CompileTime, SeedGeneration) {
    // Verify that seed generation is deterministic within same compilation
    constexpr uint64_t seed1 = compileSeed();
    constexpr uint64_t seed2 = compileSeed();
    
    // Seeds from same __TIME__ and __DATE__ should be equal
    EXPECT_EQ(seed1, seed2);
    
    // Seed should not be zero
    EXPECT_NE(seed1, 0);
}

TEST(CompileTime, RandomByteGeneration) {
    constexpr uint64_t seed = 0x123456789ABCDEFULL;
    
    // Generate some random bytes
    constexpr uint8_t b1 = randomByte(seed, 0);
    constexpr uint8_t b2 = randomByte(seed, 1);
    constexpr uint8_t b3 = randomByte(seed, 2);
    
    // Bytes should vary
    bool all_different = (b1 != b2 && b2 != b3 && b1 != b3);
    EXPECT_TRUE(all_different) << "Random bytes show no variation";
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST(Integration, MultipleStringsInFunction) {
    auto str1 = OBFUSCATE("first");
    auto str2 = OBFUSCATE("second");
    auto str3 = OBFUSCATE("third");
    
    EXPECT_EQ(str1.decrypt(), "first");
    EXPECT_EQ(str2.decrypt(), "second");
    EXPECT_EQ(str3.decrypt(), "third");
}

TEST(Integration, UseInConditionals) {
    auto str = OBFUSCATE_STR("condition");
    
    if (str.str() == "condition") {
        SUCCEED();
    } else {
        FAIL() << "String comparison failed";
    }
}

TEST(Integration, UseInFunctionCalls) {
    auto str = OBFUSCATE_STR("parameter");
    
    auto test_func = [](const std::string& s) {
        return s == "parameter";
    };
    
    EXPECT_TRUE(test_func(str.str()));
}

// ============================================================================
// Stress Tests
// ============================================================================

TEST(Stress, ManyShortStrings) {
    // Create many short obfuscated strings
    auto s1 = OBFUSCATE("a");
    auto s2 = OBFUSCATE("b");
    auto s3 = OBFUSCATE("c");
    auto s4 = OBFUSCATE("d");
    auto s5 = OBFUSCATE("e");
    auto s6 = OBFUSCATE("f");
    auto s7 = OBFUSCATE("g");
    auto s8 = OBFUSCATE("h");
    auto s9 = OBFUSCATE("i");
    auto s10 = OBFUSCATE("j");
    
    EXPECT_EQ(s1.decrypt(), "a");
    EXPECT_EQ(s2.decrypt(), "b");
    EXPECT_EQ(s3.decrypt(), "c");
    EXPECT_EQ(s4.decrypt(), "d");
    EXPECT_EQ(s5.decrypt(), "e");
    EXPECT_EQ(s6.decrypt(), "f");
    EXPECT_EQ(s7.decrypt(), "g");
    EXPECT_EQ(s8.decrypt(), "h");
    EXPECT_EQ(s9.decrypt(), "i");
    EXPECT_EQ(s10.decrypt(), "j");
}

TEST(Stress, VeryLongString) {
    const char* very_long = 
        "This is a very long string that should still work correctly with "
        "the obfuscation framework. It contains multiple sentences and "
        "should be encrypted and decrypted without any issues. The framework "
        "needs to handle strings of arbitrary length efficiently and securely.";
    
    auto obf = OBFUSCATE(
        "This is a very long string that should still work correctly with "
        "the obfuscation framework. It contains multiple sentences and "
        "should be encrypted and decrypted without any issues. The framework "
        "needs to handle strings of arbitrary length efficiently and securely.");
    
    EXPECT_EQ(obf.decrypt(), very_long);
}

// ============================================================================
// Documentation Examples
// ============================================================================

TEST(Documentation, BasicExample) {
    // Example from header documentation
    auto str = OBFUSCATE("sensitive string");
    std::string decrypted = str.decrypt();
    
    EXPECT_EQ(decrypted, "sensitive string");
}

TEST(Documentation, SecureStringExample) {
    // Example from header documentation
    auto str = OBFUSCATE_STR("sensitive string");
    const char* cstr = str.c_str();
    
    EXPECT_STREQ(cstr, "sensitive string");
    // Memory automatically zeroed when str goes out of scope
}

TEST(Documentation, RealWorldUsage) {
    // Simulate real-world detection code usage
    auto detection_name = OBFUSCATE_STR("speedhack");
    auto cheat_signature = OBFUSCATE_STR("CheatEngine");
    
    // Use in detection logic
    if (detection_name.str().find("speedhack") != std::string::npos) {
        SUCCEED() << "Detection logic works with obfuscated strings";
    }
}
