/**
 * Sentinel SDK - Update Client Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 13: Tests for Update Client
 */

#include <gtest/gtest.h>
#include "Network/UpdateClient.hpp"
#include "Internal/SignatureManager.hpp"
#include "RSATestHelpers.hpp"
#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <filesystem>
#include <thread>
#include <chrono>

using namespace Sentinel::SDK;
using namespace Sentinel;

// Mock HTTP Client for testing
class MockHttpClient : public Network::HttpClient {
public:
    MockHttpClient() : m_should_fail(false), m_version_response(1) {}
    
    void setShouldFail(bool fail) { m_should_fail = fail; }
    void setVersionResponse(uint32_t version) { m_version_response = version; }
    void setSignatureResponse(const std::string& json) { m_signature_response = json; }
    
    Result<Network::HttpResponse> send(const Network::HttpRequest& request) override {
        if (m_should_fail) {
            return ErrorCode::NetworkError;
        }
        
        Network::HttpResponse response;
        response.statusCode = 200;
        
        // Check endpoint
        if (request.url.find("/version") != std::string::npos) {
            // Version endpoint
            std::string json = R"({"version": )" + std::to_string(m_version_response) + "}";
            response.body = ByteBuffer(json.begin(), json.end());
        } else if (request.url.find("/download") != std::string::npos) {
            // Download endpoint
            response.body = ByteBuffer(m_signature_response.begin(), m_signature_response.end());
        } else {
            response.statusCode = 404;
        }
        
        response.headers["content-type"] = "application/json";
        return response;
    }
    
private:
    bool m_should_fail;
    uint32_t m_version_response;
    std::string m_signature_response;
};

class UpdateClientTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary test directory
        test_dir = std::filesystem::temp_directory_path() / "sentinel_test_updates";
        std::filesystem::create_directories(test_dir);
        
        // Generate RSA key pair for testing using helper
        rsa_signer = std::make_unique<Crypto::RSASigner>();
        auto key_result = Testing::setupTestRSAKey(*rsa_signer);
        ASSERT_TRUE(key_result.isSuccess()) << "Failed to setup test RSA key";
        public_key = key_result.value();
        
        // Initialize signature manager
        signature_manager = std::make_shared<SignatureManager>();
        auto init_result = signature_manager->initialize(test_dir.string(), public_key);
        ASSERT_TRUE(init_result.isSuccess());
        
        // Create mock HTTP client
        mock_http_client = std::make_shared<MockHttpClient>();
        
        // Initialize update client
        update_client = std::make_unique<UpdateClient>();
        
        UpdateClientConfig config;
        config.server_url = "https://test.sentinel.com";
        config.api_key = "test_api_key";
        config.game_id = "test_game";
        config.check_interval = std::chrono::seconds(5);
        config.timeout = std::chrono::seconds(10);
        config.max_retries = 3;
        config.retry_delay = std::chrono::seconds(1);
        config.enable_pinning = false;  // Disable for testing
        
        auto client_init = update_client->initialize(config, signature_manager);
        ASSERT_TRUE(client_init.isSuccess());
        
        // Set mock HTTP client
        update_client->setHttpClient(mock_http_client);
    }
    
    void TearDown() override {
        update_client->stopAutoUpdate();
        update_client.reset();
        signature_manager.reset();
        mock_http_client.reset();
        rsa_signer.reset();
        
        // Clean up test directory
        try {
            std::filesystem::remove_all(test_dir);
        } catch (...) {
            // Ignore errors during cleanup
        }
    }
    
    // Helper: Create a valid signature JSON response
    std::string createValidSignatureJson(uint32_t version = 1) {
        SignatureSet sig_set;
        sig_set.set_version = version;
        sig_set.deployed_at = std::chrono::system_clock::now();
        
        DetectionSignature sig;
        sig.id = "TEST_001";
        sig.name = "Test Signature";
        sig.type = SignatureType::MemoryPattern;
        sig.version = 1;
        sig.threat_family = "TestCheat";
        sig.severity = ThreatLevel::High;
        sig.pattern_data = {0x48, 0x89, 0x5C, 0x24, 0x08};
        sig.description = "Test pattern";
        sig.created_at = std::chrono::system_clock::now();
        sig.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);
        
        sig_set.signatures.push_back(sig);
        
        // Sign the set
        auto hash_result = sig_set.calculateSetHash();
        if (hash_result.isFailure()) return "";
        
        ByteBuffer hash_vec(hash_result.value().begin(), hash_result.value().end());
        auto sig_result = rsa_signer->sign(hash_vec);
        if (sig_result.isFailure()) return "";
        sig_set.set_signature = sig_result.value();
        
        // Serialize to JSON
        auto json_result = signature_manager->loadSignaturesFromJson("", false);  // Use manager's serializer
        
        // Manually create JSON for testing
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"version\": " << version << ",\n";
        oss << "  \"deployed_at\": \"2025-01-01T00:00:00Z\",\n";
        oss << "  \"signatures\": [\n";
        oss << "    {\n";
        oss << "      \"id\": \"TEST_001\",\n";
        oss << "      \"name\": \"Test Signature\",\n";
        oss << "      \"version\": 1,\n";
        oss << "      \"type\": \"memory_pattern\",\n";
        oss << "      \"threat_family\": \"TestCheat\",\n";
        oss << "      \"severity\": 3,\n";
        oss << "      \"pattern\": \"48895c2408\",\n";
        oss << "      \"description\": \"Test pattern\",\n";
        oss << "      \"created_at\": \"2025-01-01T00:00:00Z\",\n";
        oss << "      \"expires_at\": \"2025-01-02T00:00:00Z\"\n";
        oss << "    }\n";
        oss << "  ],\n";
        oss << "  \"signature\": \"";
        
        // Convert signature to hex
        for (auto byte : sig_set.set_signature) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        oss << "\"\n";
        oss << "}\n";
        
        return oss.str();
    }
    
    std::filesystem::path test_dir;
    std::unique_ptr<Crypto::RSASigner> rsa_signer;
    ByteBuffer public_key;
    std::shared_ptr<SignatureManager> signature_manager;
    std::shared_ptr<MockHttpClient> mock_http_client;
    std::unique_ptr<UpdateClient> update_client;
};

// ============================================================================
// Basic Functionality Tests
// ============================================================================

TEST_F(UpdateClientTest, InitializationSuccess) {
    auto stats = update_client->getStatistics();
    EXPECT_EQ(stats.total_updates, 0);
    EXPECT_EQ(stats.failed_updates, 0);
    EXPECT_EQ(stats.current_version, 0);
}

TEST_F(UpdateClientTest, CheckForUpdatesAvailable) {
    // Set mock to return version 1
    mock_http_client->setVersionResponse(1);
    
    auto result = update_client->checkForUpdates(false);
    ASSERT_TRUE(result.isSuccess());
    EXPECT_TRUE(result.value());  // Update available
}

TEST_F(UpdateClientTest, CheckForUpdatesNoneAvailable) {
    // Apply version 1 first
    mock_http_client->setVersionResponse(1);
    mock_http_client->setSignatureResponse(createValidSignatureJson(1));
    update_client->performUpdate(true);
    
    // Check again with same version
    mock_http_client->setVersionResponse(1);
    auto result = update_client->checkForUpdates(false);
    ASSERT_TRUE(result.isSuccess());
    EXPECT_FALSE(result.value());  // No update available
}

TEST_F(UpdateClientTest, CheckForUpdatesNetworkFailure) {
    mock_http_client->setShouldFail(true);
    
    auto result = update_client->checkForUpdates(false);
    EXPECT_TRUE(result.isFailure());
}

// ============================================================================
// Download and Apply Tests
// ============================================================================

TEST_F(UpdateClientTest, DownloadAndApplySuccess) {
    mock_http_client->setVersionResponse(1);
    mock_http_client->setSignatureResponse(createValidSignatureJson(1));
    
    auto result = update_client->downloadAndApply();
    ASSERT_TRUE(result.isSuccess());
    
    auto stats = update_client->getStatistics();
    EXPECT_EQ(stats.total_updates, 1);
    EXPECT_EQ(stats.current_version, 1);
}

TEST_F(UpdateClientTest, DownloadFailureIncrementsCounter) {
    mock_http_client->setShouldFail(true);
    
    auto result = update_client->downloadAndApply();
    EXPECT_TRUE(result.isFailure());
    
    auto stats = update_client->getStatistics();
    EXPECT_GT(stats.failed_updates, 0);
}

TEST_F(UpdateClientTest, PerformFullUpdateCycle) {
    mock_http_client->setVersionResponse(1);
    mock_http_client->setSignatureResponse(createValidSignatureJson(1));
    
    auto result = update_client->performUpdate(false);
    ASSERT_TRUE(result.isSuccess());
    
    auto stats = update_client->getStatistics();
    EXPECT_EQ(stats.total_updates, 1);
    EXPECT_EQ(stats.current_version, 1);
}

// ============================================================================
// Signature Verification Tests
// ============================================================================

TEST_F(UpdateClientTest, RejectTamperedSignature) {
    std::string tampered_json = createValidSignatureJson(1);
    // Tamper with the signature
    size_t sig_pos = tampered_json.find("\"signature\":");
    if (sig_pos != std::string::npos) {
        tampered_json[sig_pos + 20] = 'X';  // Modify signature hex
    }
    
    mock_http_client->setSignatureResponse(tampered_json);
    
    auto result = update_client->downloadAndApply();
    EXPECT_TRUE(result.isFailure());
}

TEST_F(UpdateClientTest, RejectMalformedJson) {
    mock_http_client->setSignatureResponse("{invalid json");
    
    auto result = update_client->downloadAndApply();
    EXPECT_TRUE(result.isFailure());
}

// ============================================================================
// Network Resilience Tests
// ============================================================================

TEST_F(UpdateClientTest, RetryOnTransientFailure) {
    // First attempt fails, second succeeds
    int call_count = 0;
    
    // This is a simplified test - in reality, retries happen within the update client
    mock_http_client->setShouldFail(true);
    auto result1 = update_client->checkForUpdates(false);
    EXPECT_TRUE(result1.isFailure());
    
    mock_http_client->setShouldFail(false);
    mock_http_client->setVersionResponse(1);
    auto result2 = update_client->checkForUpdates(false);
    EXPECT_TRUE(result2.isSuccess());
}

TEST_F(UpdateClientTest, GracefulDegradationOnNetworkOutage) {
    // Apply initial signatures
    mock_http_client->setVersionResponse(1);
    mock_http_client->setSignatureResponse(createValidSignatureJson(1));
    update_client->performUpdate(true);
    
    // Simulate network outage
    mock_http_client->setShouldFail(true);
    auto result = update_client->performUpdate(false);
    EXPECT_TRUE(result.isFailure());
    
    // Verify we still have the old signatures
    auto current = signature_manager->getCurrentSignatureSet();
    ASSERT_TRUE(current.isSuccess());
    EXPECT_EQ(current.value().set_version, 1);
}

// ============================================================================
// Auto-Update Tests
// ============================================================================

TEST_F(UpdateClientTest, StartAutoUpdate) {
    auto result = update_client->startAutoUpdate();
    ASSERT_TRUE(result.isSuccess());
    EXPECT_TRUE(update_client->isAutoUpdateRunning());
    
    // Let it run for a moment
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    update_client->stopAutoUpdate();
    EXPECT_FALSE(update_client->isAutoUpdateRunning());
}

TEST_F(UpdateClientTest, AutoUpdatePerformsUpdates) {
    mock_http_client->setVersionResponse(1);
    mock_http_client->setSignatureResponse(createValidSignatureJson(1));
    
    update_client->startAutoUpdate();
    
    // Wait for at least one update cycle
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    update_client->stopAutoUpdate();
    
    // Should have attempted at least one update
    auto stats = update_client->getStatistics();
    EXPECT_GT(stats.total_updates + stats.failed_updates, 0);
}

TEST_F(UpdateClientTest, StopAutoUpdateGracefully) {
    update_client->startAutoUpdate();
    EXPECT_TRUE(update_client->isAutoUpdateRunning());
    
    update_client->stopAutoUpdate();
    EXPECT_FALSE(update_client->isAutoUpdateRunning());
    
    // Should be able to stop again without error
    update_client->stopAutoUpdate();
}

// ============================================================================
// Callback Tests
// ============================================================================

TEST_F(UpdateClientTest, ProgressCallbackInvoked) {
    bool callback_invoked = false;
    UpdateStatus last_status = UpdateStatus::Idle;
    
    update_client->setProgressCallback([&](UpdateStatus status, const std::string& message) {
        callback_invoked = true;
        last_status = status;
    });
    
    mock_http_client->setVersionResponse(1);
    mock_http_client->setSignatureResponse(createValidSignatureJson(1));
    
    update_client->performUpdate(false);
    
    EXPECT_TRUE(callback_invoked);
    // Last status should be Success or Idle
    EXPECT_TRUE(last_status == UpdateStatus::Success || last_status == UpdateStatus::Idle);
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(UpdateClientTest, EndToEndUpdateFlow) {
    // 1. Check for updates (version 1 available)
    mock_http_client->setVersionResponse(1);
    auto check_result = update_client->checkForUpdates(false);
    ASSERT_TRUE(check_result.isSuccess());
    EXPECT_TRUE(check_result.value());
    
    // 2. Download and apply
    mock_http_client->setSignatureResponse(createValidSignatureJson(1));
    auto apply_result = update_client->downloadAndApply();
    ASSERT_TRUE(apply_result.isSuccess());
    
    // 3. Verify signature manager has new signatures
    auto sig_result = signature_manager->getSignatureById("TEST_001");
    ASSERT_TRUE(sig_result.isSuccess());
    EXPECT_EQ(sig_result.value().name, "Test Signature");
    
    // 4. Check for updates again (none available)
    auto check_result2 = update_client->checkForUpdates(false);
    ASSERT_TRUE(check_result2.isSuccess());
    EXPECT_FALSE(check_result2.value());
}

TEST_F(UpdateClientTest, MultipleSequentialUpdates) {
    // Apply version 1
    mock_http_client->setVersionResponse(1);
    mock_http_client->setSignatureResponse(createValidSignatureJson(1));
    auto result1 = update_client->performUpdate(false);
    ASSERT_TRUE(result1.isSuccess());
    
    // Apply version 2
    mock_http_client->setVersionResponse(2);
    mock_http_client->setSignatureResponse(createValidSignatureJson(2));
    auto result2 = update_client->performUpdate(false);
    ASSERT_TRUE(result2.isSuccess());
    
    auto stats = update_client->getStatistics();
    EXPECT_EQ(stats.total_updates, 2);
    EXPECT_EQ(stats.current_version, 2);
}

// ============================================================================
// Cache Survival Tests (24-hour network outage requirement)
// ============================================================================

TEST_F(UpdateClientTest, CachedSignaturesSurviveRestart) {
    // Apply signatures
    mock_http_client->setVersionResponse(1);
    mock_http_client->setSignatureResponse(createValidSignatureJson(1));
    update_client->performUpdate(true);
    
    // Simulate restart by creating new client and manager
    auto new_manager = std::make_shared<SignatureManager>();
    auto init_result = new_manager->initialize(test_dir.string(), public_key);
    ASSERT_TRUE(init_result.isSuccess());
    
    // Should have loaded from cache
    auto current = new_manager->getCurrentSignatureSet();
    ASSERT_TRUE(current.isSuccess());
    EXPECT_EQ(current.value().set_version, 1);
}
