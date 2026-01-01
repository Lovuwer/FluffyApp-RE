/**
 * Sentinel SDK - Signature Manager Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 13: Tests for Detection Signature Update Mechanism
 */

#include <gtest/gtest.h>
#include "Internal/SignatureManager.hpp"
#include "RSATestHelpers.hpp"
#include <Sentinel/Core/Crypto.hpp>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>

using namespace Sentinel::SDK;
using namespace Sentinel;

class SignatureManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary test directory
        test_dir = std::filesystem::temp_directory_path() / "sentinel_test_signatures";
        std::filesystem::create_directories(test_dir);
        
        // Generate RSA key pair for testing using helper
        rsa_signer = std::make_unique<Crypto::RSASigner>();
        auto key_result = Testing::setupTestRSAKey(*rsa_signer);
        ASSERT_TRUE(key_result.isSuccess()) << "Failed to setup test RSA key";
        public_key = key_result.value();
        
        // Initialize signature manager
        manager = std::make_unique<SignatureManager>();
        auto init_result = manager->initialize(test_dir.string(), public_key);
        ASSERT_TRUE(init_result.isSuccess());
    }
    
    void TearDown() override {
        manager.reset();
        rsa_signer.reset();
        
        // Clean up test directory
        try {
            std::filesystem::remove_all(test_dir);
        } catch (...) {
            // Ignore errors during cleanup
        }
    }
    
    // Helper: Create a valid signature set
    SignatureSet createValidSignatureSet(uint32_t version = 1) {
        SignatureSet sig_set;
        sig_set.set_version = version;
        sig_set.deployed_at = std::chrono::system_clock::now();
        
        // Add sample signatures
        DetectionSignature sig1;
        sig1.id = "TEST_001";
        sig1.name = "Test Signature 1";
        sig1.type = SignatureType::MemoryPattern;
        sig1.version = 1;
        sig1.threat_family = "TestCheat";
        sig1.severity = ThreatLevel::High;
        sig1.pattern_data = {0x48, 0x89, 0x5C, 0x24, 0x08};
        sig1.description = "Test pattern";
        sig1.created_at = std::chrono::system_clock::now();
        sig1.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);
        
        sig_set.signatures.push_back(sig1);
        
        // Sign the set
        auto hash_result = sig_set.calculateSetHash();
        EXPECT_TRUE(hash_result.isSuccess());
        
        ByteBuffer hash_vec(hash_result.value().begin(), hash_result.value().end());
        auto sig_result = rsa_signer->sign(hash_vec);
        EXPECT_TRUE(sig_result.isSuccess());
        sig_set.set_signature = sig_result.value();
        
        return sig_set;
    }
    
    // Helper: Create malformed JSON
    std::string createMalformedJson() {
        return R"({
            "version": "not_a_number",
            "signatures": [
                {"id": "INVALID"
            ]
        })";
    }
    
    std::filesystem::path test_dir;
    std::unique_ptr<Crypto::RSASigner> rsa_signer;
    ByteBuffer public_key;
    std::unique_ptr<SignatureManager> manager;
};

// ============================================================================
// Basic Functionality Tests
// ============================================================================

TEST_F(SignatureManagerTest, InitializationSuccess) {
    // Manager should be initialized in SetUp
    auto stats = manager->getStatistics();
    EXPECT_EQ(stats.current_version, 0);
    EXPECT_EQ(stats.total_signatures, 0);
}

TEST_F(SignatureManagerTest, ApplyValidSignatureSet) {
    auto sig_set = createValidSignatureSet(1);
    
    auto result = manager->applySignatureSet(sig_set, false);
    ASSERT_TRUE(result.isSuccess());
    
    auto stats = manager->getStatistics();
    EXPECT_EQ(stats.current_version, 1);
    EXPECT_EQ(stats.total_signatures, 1);
}

TEST_F(SignatureManagerTest, GetSignatureById) {
    auto sig_set = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set, false);
    
    auto sig_result = manager->getSignatureById("TEST_001");
    ASSERT_TRUE(sig_result.isSuccess());
    EXPECT_EQ(sig_result.value().id, "TEST_001");
    EXPECT_EQ(sig_result.value().name, "Test Signature 1");
}

TEST_F(SignatureManagerTest, GetNonExistentSignature) {
    auto sig_set = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set, false);
    
    auto sig_result = manager->getSignatureById("NONEXISTENT");
    EXPECT_TRUE(sig_result.isFailure());
    EXPECT_EQ(sig_result.error(), ErrorCode::SignatureNotFound);
}

TEST_F(SignatureManagerTest, GetSignaturesByType) {
    auto sig_set = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set, false);
    
    auto sigs = manager->getSignaturesByType(SignatureType::MemoryPattern);
    EXPECT_EQ(sigs.size(), 1);
    EXPECT_EQ(sigs[0].id, "TEST_001");
    
    auto hash_sigs = manager->getSignaturesByType(SignatureType::HashSignature);
    EXPECT_EQ(hash_sigs.size(), 0);
}

// ============================================================================
// Versioning Tests
// ============================================================================

TEST_F(SignatureManagerTest, VersionUpgradeAllowed) {
    auto sig_set_v1 = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set_v1, false);
    
    auto sig_set_v2 = createValidSignatureSet(2);
    auto result = manager->applySignatureSet(sig_set_v2, false);
    ASSERT_TRUE(result.isSuccess());
    
    auto stats = manager->getStatistics();
    EXPECT_EQ(stats.current_version, 2);
}

TEST_F(SignatureManagerTest, VersionDowngradeBlocked) {
    auto sig_set_v2 = createValidSignatureSet(2);
    manager->applySignatureSet(sig_set_v2, false);
    
    auto sig_set_v1 = createValidSignatureSet(1);
    auto result = manager->applySignatureSet(sig_set_v1, false);
    EXPECT_TRUE(result.isFailure());
    EXPECT_EQ(result.error(), ErrorCode::PatchVersionMismatch);
}

TEST_F(SignatureManagerTest, ForceApplyLowerVersion) {
    auto sig_set_v2 = createValidSignatureSet(2);
    manager->applySignatureSet(sig_set_v2, false);
    
    auto sig_set_v1 = createValidSignatureSet(1);
    auto result = manager->applySignatureSet(sig_set_v1, true);  // Force
    ASSERT_TRUE(result.isSuccess());
    
    auto stats = manager->getStatistics();
    EXPECT_EQ(stats.current_version, 1);
}

// ============================================================================
// Rollback Tests
// ============================================================================

TEST_F(SignatureManagerTest, RollbackToPrevious) {
    auto sig_set_v1 = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set_v1, false);
    
    auto sig_set_v2 = createValidSignatureSet(2);
    manager->applySignatureSet(sig_set_v2, false);
    
    // Rollback to v1
    auto result = manager->rollbackToPrevious();
    ASSERT_TRUE(result.isSuccess());
    
    auto stats = manager->getStatistics();
    EXPECT_EQ(stats.current_version, 1);
}

TEST_F(SignatureManagerTest, RollbackWithoutPrevious) {
    auto sig_set = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set, false);
    
    // No previous version to rollback to
    auto result = manager->rollbackToPrevious();
    EXPECT_TRUE(result.isFailure());
    EXPECT_EQ(result.error(), ErrorCode::PatchNotFound);
}

// ============================================================================
// Caching Tests
// ============================================================================

TEST_F(SignatureManagerTest, SaveAndLoadFromCache) {
    auto sig_set = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set, false);
    
    // Cache should be saved automatically
    auto cache_result = manager->loadFromCache(24);
    ASSERT_TRUE(cache_result.isSuccess());
    
    auto loaded_set = cache_result.value();
    EXPECT_EQ(loaded_set.set_version, 1);
    EXPECT_EQ(loaded_set.signatures.size(), 1);
}

TEST_F(SignatureManagerTest, CacheExpiration) {
    auto sig_set = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set, false);
    
    // Try to load with 0 hour max age (should succeed as we just saved it)
    auto cache_result = manager->loadFromCache(0);
    EXPECT_TRUE(cache_result.isSuccess());
}

TEST_F(SignatureManagerTest, CacheSurvivesReinitialization) {
    auto sig_set = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set, false);
    
    // Create new manager instance
    auto new_manager = std::make_unique<SignatureManager>();
    auto init_result = new_manager->initialize(test_dir.string(), public_key);
    ASSERT_TRUE(init_result.isSuccess());
    
    // Should load from cache automatically during init
    auto current = new_manager->getCurrentSignatureSet();
    ASSERT_TRUE(current.isSuccess());
    EXPECT_EQ(current.value().set_version, 1);
}

// ============================================================================
// Sandboxed Parsing Tests (Malformed Input)
// ============================================================================

TEST_F(SignatureManagerTest, ParseMalformedJsonDoesNotCrash) {
    std::string malformed_json = createMalformedJson();
    
    // Should not crash, just return error
    auto result = manager->loadSignaturesFromJson(malformed_json, false);
    EXPECT_TRUE(result.isFailure());
}

TEST_F(SignatureManagerTest, ParseEmptyJsonDoesNotCrash) {
    std::string empty_json = "";
    
    auto result = manager->loadSignaturesFromJson(empty_json, false);
    EXPECT_TRUE(result.isFailure());
}

TEST_F(SignatureManagerTest, ParseInvalidJsonStructure) {
    std::string invalid_json = R"({"version": 1, "signatures": "not_an_array"})";
    
    auto result = manager->loadSignaturesFromJson(invalid_json, false);
    EXPECT_TRUE(result.isFailure());
}

TEST_F(SignatureManagerTest, ParsePartiallyValidJson) {
    // JSON with some valid and some invalid signatures
    std::string partial_json = R"({
        "version": 1,
        "deployed_at": "2025-01-01T00:00:00",
        "signatures": [
            {
                "id": "VALID_001",
                "name": "Valid Signature",
                "version": 1,
                "type": "memory_pattern",
                "threat_family": "Test",
                "severity": 3,
                "pattern": "4889",
                "description": "Valid"
            },
            {
                "id": "INVALID_001"
            }
        ],
        "signature": ""
    })";
    
    auto result = manager->loadSignaturesFromJson(partial_json, false);
    // Should succeed with at least the valid signature
    EXPECT_TRUE(result.isSuccess());
    if (result.isSuccess()) {
        EXPECT_GE(result.value().signatures.size(), 1);
    }
}

// ============================================================================
// Signature Verification Tests
// ============================================================================

TEST_F(SignatureManagerTest, VerifyValidSignature) {
    auto sig_set = createValidSignatureSet(1);
    
    auto result = manager->validateSignatureSet(sig_set);
    ASSERT_TRUE(result.isSuccess());
    EXPECT_TRUE(result.value());
}

TEST_F(SignatureManagerTest, RejectTamperedSignature) {
    auto sig_set = createValidSignatureSet(1);
    
    // Tamper with the signature
    sig_set.set_signature[0] ^= 0xFF;
    
    auto result = manager->validateSignatureSet(sig_set);
    EXPECT_TRUE(result.isSuccess());
    EXPECT_FALSE(result.value());
}

TEST_F(SignatureManagerTest, RejectEmptySignatureSet) {
    SignatureSet empty_set;
    empty_set.set_version = 1;
    empty_set.deployed_at = std::chrono::system_clock::now();
    // No signatures added
    
    auto result = manager->validateSignatureSet(empty_set);
    EXPECT_TRUE(result.isSuccess());
    EXPECT_FALSE(result.value());
}

// ============================================================================
// Expiration Tests
// ============================================================================

TEST_F(SignatureManagerTest, CleanupExpiredSignatures) {
    SignatureSet sig_set;
    sig_set.set_version = 1;
    sig_set.deployed_at = std::chrono::system_clock::now();
    
    // Add expired signature
    DetectionSignature expired_sig;
    expired_sig.id = "EXPIRED_001";
    expired_sig.name = "Expired Signature";
    expired_sig.type = SignatureType::MemoryPattern;
    expired_sig.version = 1;
    expired_sig.threat_family = "Test";
    expired_sig.severity = ThreatLevel::Low;
    expired_sig.pattern_data = {0x90, 0x90};
    expired_sig.created_at = std::chrono::system_clock::now() - std::chrono::hours(48);
    expired_sig.expires_at = std::chrono::system_clock::now() - std::chrono::hours(1);
    sig_set.signatures.push_back(expired_sig);
    
    // Add valid signature
    DetectionSignature valid_sig;
    valid_sig.id = "VALID_001";
    valid_sig.name = "Valid Signature";
    valid_sig.type = SignatureType::MemoryPattern;
    valid_sig.version = 1;
    valid_sig.threat_family = "Test";
    valid_sig.severity = ThreatLevel::High;
    valid_sig.pattern_data = {0x48, 0x89};
    valid_sig.created_at = std::chrono::system_clock::now();
    valid_sig.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);
    sig_set.signatures.push_back(valid_sig);
    
    // Sign and apply
    auto hash_result = sig_set.calculateSetHash();
    ASSERT_TRUE(hash_result.isSuccess());
    ByteBuffer hash_vec(hash_result.value().begin(), hash_result.value().end());
    auto sig_result = rsa_signer->sign(hash_vec);
    ASSERT_TRUE(sig_result.isSuccess());
    sig_set.set_signature = sig_result.value();
    
    manager->applySignatureSet(sig_set, true);
    
    // Cleanup expired
    int removed = manager->cleanupExpiredSignatures();
    EXPECT_EQ(removed, 1);
    
    auto stats = manager->getStatistics();
    EXPECT_EQ(stats.total_signatures, 1);
    EXPECT_EQ(stats.expired_signatures, 0);
}

// ============================================================================
// Callback Tests
// ============================================================================

TEST_F(SignatureManagerTest, UpdateCallbackInvoked) {
    bool callback_invoked = false;
    uint32_t callback_version = 0;
    
    manager->setUpdateCallback([&](const SignatureSet& sig_set) {
        callback_invoked = true;
        callback_version = sig_set.set_version;
    });
    
    auto sig_set = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set, false);
    
    EXPECT_TRUE(callback_invoked);
    EXPECT_EQ(callback_version, 1);
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

TEST_F(SignatureManagerTest, ConcurrentReadAccess) {
    auto sig_set = createValidSignatureSet(1);
    manager->applySignatureSet(sig_set, false);
    
    // Multiple threads reading simultaneously
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&]() {
            auto result = manager->getSignatureById("TEST_001");
            if (result.isSuccess()) {
                success_count++;
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(success_count.load(), 10);
}
