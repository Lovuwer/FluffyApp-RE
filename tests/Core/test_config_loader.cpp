/**
 * @file test_config_loader.cpp
 * @brief Unit tests for secure configuration loader
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Tests secure configuration loading to ensure:
 * - TOCTOU-safe loading (atomic operations)
 * - Path traversal blocked
 * - Size limits enforced
 * - Optional signature verification
 */

#include <Sentinel/Core/Config.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include "TestHarness.hpp"
#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

using namespace Sentinel;
using namespace Sentinel::Config;
using namespace Sentinel::Crypto;
using namespace Sentinel::Testing;

namespace fs = std::filesystem;

// ============================================================================
// Helper Functions - Key Generation for Tests
// ============================================================================

/**
 * @brief Generate RSA key pair for testing
 */
static EVP_PKEY* generateTestKey(int bits = 2048) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        return nullptr;
    }
    
    if (EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    // Set public exponent
    BIGNUM* bn_e = BN_new();
    if (!bn_e || !BN_set_word(bn_e, 65537)) {
        BN_free(bn_e);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn_e) != 1) {
        BN_free(bn_e);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    BN_free(bn_e);
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/**
 * @brief Export private key to DER format
 */
static ByteBuffer exportPrivateKeyDER(EVP_PKEY* pkey) {
    unsigned char* der = nullptr;
    int len = i2d_PrivateKey(pkey, &der);
    if (len <= 0) {
        return ByteBuffer();
    }
    
    ByteBuffer result(der, der + len);
    OPENSSL_free(der);
    return result;
}

/**
 * @brief Export public key to DER format
 */
static ByteBuffer exportPublicKeyDER(EVP_PKEY* pkey) {
    unsigned char* der = nullptr;
    int len = i2d_PUBKEY(pkey, &der);
    if (len <= 0) {
        return ByteBuffer();
    }
    
    ByteBuffer result(der, der + len);
    OPENSSL_free(der);
    return result;
}

// ============================================================================
// Test Fixture
// ============================================================================

class ConfigLoaderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for test files
        tempDir = fs::temp_directory_path() / "sentinel_config_test";
        fs::create_directories(tempDir);
    }
    
    void TearDown() override {
        // Clean up temporary files
        if (fs::exists(tempDir)) {
            fs::remove_all(tempDir);
        }
    }
    
    // Helper to create a test config file
    std::string createTestConfig(const std::string& filename, const std::string& content) {
        fs::path filepath = tempDir / filename;
        std::ofstream file(filepath);
        file << content;
        file.close();
        return filepath.string();
    }
    
    // Helper to create a large file
    std::string createLargeFile(const std::string& filename, size_t sizeBytes) {
        fs::path filepath = tempDir / filename;
        std::ofstream file(filepath, std::ios::binary);
        std::vector<char> buffer(sizeBytes, 'A');
        file.write(buffer.data(), buffer.size());
        file.close();
        return filepath.string();
    }
    
    // Helper to generate test key pair
    void generateTestKeyPair() {
        EVP_PKEY* pkey = generateTestKey(2048);
        ASSERT_NE(pkey, nullptr);
        
        privateKey = exportPrivateKeyDER(pkey);
        publicKey = exportPublicKeyDER(pkey);
        
        EVP_PKEY_free(pkey);
        
        ASSERT_FALSE(privateKey.empty());
        ASSERT_FALSE(publicKey.empty());
    }
    
    // Helper to sign data
    ByteBuffer signData(ByteSpan data) {
        RSASigner signer;
        auto loadResult = signer.loadPrivateKey(privateKey);
        EXPECT_TRUE(loadResult.isSuccess());
        
        auto signResult = signer.sign(data);
        EXPECT_TRUE(signResult.isSuccess());
        return signResult.value();
    }
    
    fs::path tempDir;
    ByteBuffer privateKey;
    ByteBuffer publicKey;
};

// ============================================================================
// Unit Test 1: Basic Load
// ============================================================================

TEST_F(ConfigLoaderTest, BasicLoad) {
    // Create temp config file
    std::string configContent = 
        "# Test configuration\n"
        "key1=value1\n"
        "key2=value2\n"
        "number=42\n";
    
    std::string configPath = createTestConfig("test.conf", configContent);
    
    // Load and parse
    SecureConfigLoader loader;
    auto result = loader.load(configPath);
    
    // Verify success
    ASSERT_TRUE(result.isSuccess());
    
    // Verify values
    ConfigMap config = result.value();
    EXPECT_EQ(config.size(), 3u);
    EXPECT_EQ(std::get<std::string>(config["key1"]), "value1");
    EXPECT_EQ(std::get<std::string>(config["key2"]), "value2");
    EXPECT_EQ(std::get<std::string>(config["number"]), "42");
}

// ============================================================================
// Unit Test 2: Path Traversal Blocked
// ============================================================================

TEST_F(ConfigLoaderTest, PathTraversalBlocked) {
    // Configure allowed directory
    SecureConfigLoader::Options options;
    options.allowed_directory = tempDir.string();
    
    SecureConfigLoader loader(options);
    
    // Attempt to load file outside allowed directory
    std::string traversalPath = (tempDir / ".." / "etc" / "passwd").string();
    auto result = loader.load(traversalPath);
    
    // Verify access denied (or file not found, depending on OS)
    ASSERT_TRUE(result.isFailure());
    EXPECT_TRUE(result.error() == ErrorCode::AccessDenied || 
                result.error() == ErrorCode::FileNotFound ||
                result.error() == ErrorCode::InvalidPath);
}

// ============================================================================
// Unit Test 3: Size Limit
// ============================================================================

TEST_F(ConfigLoaderTest, SizeLimit) {
    // Configure small size limit
    SecureConfigLoader::Options options;
    options.max_file_size = 1024;  // 1KB limit
    
    SecureConfigLoader loader(options);
    
    // Create file larger than limit (2KB)
    std::string largePath = createLargeFile("large.conf", 2048);
    
    // Attempt to load
    auto result = loader.load(largePath);
    
    // Verify FileTooLarge error
    ASSERT_TRUE(result.isFailure());
    EXPECT_EQ(result.error(), ErrorCode::FileTooLarge);
}

// ============================================================================
// Unit Test 4: Directory Restriction
// ============================================================================

TEST_F(ConfigLoaderTest, DirectoryRestriction) {
    // Create subdirectory
    fs::path subDir = tempDir / "allowed";
    fs::create_directories(subDir);
    
    // Create config in subdirectory
    std::string allowedPath = createTestConfig("allowed/test.conf", "key=value\n");
    
    // Create config outside subdirectory
    std::string deniedPath = createTestConfig("denied.conf", "key=value\n");
    
    // Configure allowed directory to subdirectory
    SecureConfigLoader::Options options;
    options.allowed_directory = subDir.string();
    
    SecureConfigLoader loader(options);
    
    // Load from allowed directory should succeed
    auto allowedResult = loader.load(allowedPath);
    ASSERT_TRUE(allowedResult.isSuccess());
    
    // Load from outside allowed directory should fail
    auto deniedResult = loader.load(deniedPath);
    ASSERT_TRUE(deniedResult.isFailure());
    EXPECT_EQ(deniedResult.error(), ErrorCode::AccessDenied);
}

// ============================================================================
// Unit Test 5: Signature Verification
// ============================================================================

TEST_F(ConfigLoaderTest, SignatureVerification) {
    // Generate test key pair
    generateTestKeyPair();
    
    // Create config content
    std::string configContent = "key=value\nsecret=12345\n";
    ByteBuffer configData(configContent.begin(), configContent.end());
    
    // Sign config
    ByteBuffer signature = signData(configData);
    
    // Create config and signature files
    std::string configPath = createTestConfig("signed.conf", configContent);
    std::string sigPath = configPath + ".sig";
    std::ofstream sigFile(sigPath, std::ios::binary);
    sigFile.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    sigFile.close();
    
    // Configure loader with signature verification
    SecureConfigLoader::Options options;
    options.verify_signature = true;
    options.signature_public_key = publicKey;
    
    SecureConfigLoader loader(options);
    
    // Load with verification
    auto result = loader.load(configPath);
    
    // Verify success
    ASSERT_TRUE(result.isSuccess());
    ConfigMap config = result.value();
    EXPECT_EQ(std::get<std::string>(config["key"]), "value");
    EXPECT_EQ(std::get<std::string>(config["secret"]), "12345");
}

// ============================================================================
// Unit Test 6: Invalid Signature
// ============================================================================

TEST_F(ConfigLoaderTest, InvalidSignature) {
    // Generate test key pair
    generateTestKeyPair();
    
    // Create config content
    std::string configContent = "key=value\n";
    ByteBuffer configData(configContent.begin(), configContent.end());
    
    // Sign config
    ByteBuffer signature = signData(configData);
    
    // Modify config (tampering)
    std::string modifiedContent = "key=hacked\n";
    std::string configPath = createTestConfig("tampered.conf", modifiedContent);
    
    // Write original signature
    std::string sigPath = configPath + ".sig";
    std::ofstream sigFile(sigPath, std::ios::binary);
    sigFile.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    sigFile.close();
    
    // Configure loader with signature verification
    SecureConfigLoader::Options options;
    options.verify_signature = true;
    options.signature_public_key = publicKey;
    
    SecureConfigLoader loader(options);
    
    // Attempt load
    auto result = loader.load(configPath);
    
    // Verify SignatureInvalid error
    ASSERT_TRUE(result.isFailure());
    EXPECT_EQ(result.error(), ErrorCode::SignatureInvalid);
}

// ============================================================================
// Unit Test 7: Load From Memory
// ============================================================================

TEST_F(ConfigLoaderTest, LoadFromMemory) {
    // Create config data in memory
    std::string configContent = "memory_key=memory_value\n";
    ByteBuffer configData(configContent.begin(), configContent.end());
    
    // Load from memory
    SecureConfigLoader loader;
    auto result = loader.loadFromMemory(configData);
    
    // Verify success
    ASSERT_TRUE(result.isSuccess());
    ConfigMap config = result.value();
    EXPECT_EQ(std::get<std::string>(config["memory_key"]), "memory_value");
}

// ============================================================================
// Unit Test 8: Missing Signature File
// ============================================================================

TEST_F(ConfigLoaderTest, MissingSignatureFile) {
    // Generate test key pair
    generateTestKeyPair();
    
    // Create config without signature
    std::string configPath = createTestConfig("nosig.conf", "key=value\n");
    
    // Configure loader with signature verification (but no .sig file)
    SecureConfigLoader::Options options;
    options.verify_signature = true;
    options.signature_public_key = publicKey;
    
    SecureConfigLoader loader(options);
    
    // Attempt load
    auto result = loader.load(configPath);
    
    // Verify SignatureNotFound error
    ASSERT_TRUE(result.isFailure());
    EXPECT_EQ(result.error(), ErrorCode::SignatureNotFound);
}

// ============================================================================
// Unit Test 9: Empty Configuration
// ============================================================================

TEST_F(ConfigLoaderTest, EmptyConfiguration) {
    // Create empty config file
    std::string configPath = createTestConfig("empty.conf", "");
    
    // Load
    SecureConfigLoader loader;
    auto result = loader.load(configPath);
    
    // Verify success with empty config
    ASSERT_TRUE(result.isSuccess());
    ConfigMap config = result.value();
    EXPECT_EQ(config.size(), 0u);
}

// ============================================================================
// Unit Test 10: Comments and Whitespace
// ============================================================================

TEST_F(ConfigLoaderTest, CommentsAndWhitespace) {
    // Create config with comments and whitespace
    std::string configContent = 
        "# This is a comment\n"
        "\n"
        "  key1  =  value1  \n"
        "; Another comment\n"
        "key2=value2\n"
        "  \n";
    
    std::string configPath = createTestConfig("comments.conf", configContent);
    
    // Load
    SecureConfigLoader loader;
    auto result = loader.load(configPath);
    
    // Verify success
    ASSERT_TRUE(result.isSuccess());
    ConfigMap config = result.value();
    EXPECT_EQ(config.size(), 2u);
    EXPECT_EQ(std::get<std::string>(config["key1"]), "value1");
    EXPECT_EQ(std::get<std::string>(config["key2"]), "value2");
}
