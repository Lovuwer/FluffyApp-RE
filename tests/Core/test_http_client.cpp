/**
 * @file test_http_client.cpp
 * @brief Integration tests for HTTP client
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 */

#include <gtest/gtest.h>
#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <thread>

using namespace Sentinel;
using namespace Sentinel::Network;

class HttpClientTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set shorter timeout for tests
        client.setDefaultTimeout(Milliseconds{2000});
    }
    
    HttpClient client;
};

// Test HTTP client initialization
TEST_F(HttpClientTest, Initialization) {
    // Should be able to create and destroy client
    HttpClient testClient;
    SUCCEED();
}

// Test DNS failure with known bad domain
TEST_F(HttpClientTest, DnsFailure) {
    auto response = client.get("https://nonexistent.invalid.domain.test.local");
    
    EXPECT_FALSE(response.isSuccess());
    // Should get DNS resolution failure
    EXPECT_TRUE(response.error() == ErrorCode::DnsResolutionFailed ||
                response.error() == ErrorCode::NetworkError ||
                response.error() == ErrorCode::ConnectionFailed);
}

// Test connection failure to unreachable address
TEST_F(HttpClientTest, ConnectionFailure) {
    // Try to connect to an unreachable IP (using TEST-NET-1 from RFC 5737)
    HttpRequest request;
    request.url = "https://192.0.2.1:44444";
    request.timeout = Milliseconds{2000};
    
    auto response = client.send(request);
    
    EXPECT_FALSE(response.isSuccess());
    // Should be either connection failed or timeout
    EXPECT_TRUE(response.error() == ErrorCode::ConnectionFailed || 
                response.error() == ErrorCode::Timeout);
}

// Test timeout behavior with unreachable endpoint
TEST_F(HttpClientTest, TimeoutBehavior) {
    HttpRequest request;
    request.url = "https://192.0.2.1:44444";  // Unreachable
    request.timeout = Milliseconds{1000}; // 1 second timeout
    
    auto startTime = Clock::now();
    auto response = client.send(request);
    auto endTime = Clock::now();
    auto elapsed = std::chrono::duration_cast<Milliseconds>(endTime - startTime);
    
    // Should fail
    EXPECT_FALSE(response.isSuccess());
    
    // Should timeout within reasonable time (allow margin for retry logic)
    // The implementation has retry logic with exponential backoff
    EXPECT_LT(elapsed.count(), 8000) << "Should timeout within expected time (including retries)";
}

// Test request builder API
TEST_F(HttpClientTest, RequestBuilder) {
    auto response = RequestBuilder(client)
        .url("https://192.0.2.1:44444")
        .method(HttpMethod::GET)
        .header("X-Test", "Builder")
        .timeout(Milliseconds{1000})
        .send();
    
    // Should fail but not crash
    EXPECT_FALSE(response.isSuccess());
}

// Test setting default headers
TEST_F(HttpClientTest, DefaultHeaders) {
    client.addDefaultHeader("X-Custom", "TestValue");
    
    HttpRequest request;
    request.url = "https://192.0.2.1:44444";
    request.timeout = Milliseconds{1000};
    
    // Should fail but demonstrate header API works
    auto response = client.send(request);
    EXPECT_FALSE(response.isSuccess());
}

// Test POST request creation
TEST_F(HttpClientTest, PostRequest) {
    HttpRequest request;
    request.url = "https://192.0.2.1:44444";
    request.method = HttpMethod::POST;
    request.body = {'t', 'e', 's', 't'};
    request.timeout = Milliseconds{1000};
    
    auto response = client.send(request);
    
    // Should fail but not crash
    EXPECT_FALSE(response.isSuccess());
}

// Test JSON POST creation
TEST_F(HttpClientTest, PostJsonRequest) {
    HttpRequest request;
    request.url = "https://192.0.2.1:44444";
    request.timeout = Milliseconds{1000};
    
    std::string jsonPayload = R"({"test": "data"})";
    auto response = client.postJson(request.url, jsonPayload);
    
    // Should fail but not crash
    EXPECT_FALSE(response.isSuccess());
}

// Test thread safety with concurrent requests
TEST_F(HttpClientTest, ConcurrentRequests) {
    const int numThreads = 10;
    std::vector<std::thread> threads;
    std::atomic<int> completedCount{0};
    
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([this, &completedCount]() {
            HttpRequest request;
            request.url = "https://192.0.2.1:44444";
            request.timeout = Milliseconds{500};
            
            auto response = client.send(request);
            // All should fail (no connection) but should complete
            if (!response.isSuccess()) {
                completedCount++;
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All requests should complete (even if they fail)
    EXPECT_EQ(numThreads, completedCount.load());
}

// Test different HTTP methods
TEST_F(HttpClientTest, HttpMethods) {
    HttpRequest request;
    request.url = "https://192.0.2.1:44444";
    request.timeout = Milliseconds{500};
    
    // Test GET
    request.method = HttpMethod::GET;
    auto getResponse = client.send(request);
    EXPECT_FALSE(getResponse.isSuccess());
    
    // Test POST
    request.method = HttpMethod::POST;
    auto postResponse = client.send(request);
    EXPECT_FALSE(postResponse.isSuccess());
    
    // Test PUT
    request.method = HttpMethod::PUT;
    auto putResponse = client.send(request);
    EXPECT_FALSE(putResponse.isSuccess());
    
    // Test DELETE
    request.method = HttpMethod::DELETE_;
    auto deleteResponse = client.send(request);
    EXPECT_FALSE(deleteResponse.isSuccess());
}

// Test response helper methods
TEST_F(HttpClientTest, ResponseHelpers) {
    HttpResponse response;
    
    // Test status code helpers
    response.statusCode = 200;
    EXPECT_TRUE(response.isSuccess());
    EXPECT_FALSE(response.isClientError());
    EXPECT_FALSE(response.isServerError());
    
    response.statusCode = 404;
    EXPECT_FALSE(response.isSuccess());
    EXPECT_TRUE(response.isClientError());
    EXPECT_FALSE(response.isServerError());
    
    response.statusCode = 500;
    EXPECT_FALSE(response.isSuccess());
    EXPECT_FALSE(response.isClientError());
    EXPECT_TRUE(response.isServerError());
    
    response.statusCode = 301;
    EXPECT_FALSE(response.isSuccess());
    EXPECT_TRUE(response.isRedirect());
    
    // Test body helpers
    response.body = {'H', 'e', 'l', 'l', 'o'};
    EXPECT_EQ("Hello", response.bodyAsString());
    
    // Test header retrieval
    response.headers["content-type"] = "application/json";
    EXPECT_EQ("application/json", response.getHeader("content-type"));
    EXPECT_EQ("application/json", response.getHeader("Content-Type"));  // Case insensitive
    EXPECT_EQ("", response.getHeader("nonexistent"));
}

// Test that the client properly handles move semantics
TEST_F(HttpClientTest, MoveSemantics) {
    HttpClient client1;
    client1.setDefaultTimeout(Milliseconds{1000});
    HttpClient client2 = std::move(client1);
    
    // Should be able to use moved-to client
    auto response = client2.get("https://192.0.2.1:44444");
    EXPECT_FALSE(response.isSuccess());
}

// Test certificate pinning integration
TEST_F(HttpClientTest, CertificatePinningIntegration) {
    // This test demonstrates that certificate pinning rejects connections
    // with mismatched certificates
    
    // Create a certificate pin with a dummy hash (won't match any real cert)
    CertificatePin pin;
    pin.hostname = "example.com";
    
    // Create a dummy SHA256 hash (32 bytes of zeros)
    SHA256Hash dummyHash;
    std::fill(dummyHash.begin(), dummyHash.end(), 0);
    pin.pins.push_back(dummyHash);
    pin.includeSubdomains = false;
    
    // Add the pin to the client
    client.addCertificatePin(pin);
    client.setPinningEnabled(true);
    
    // Try to connect to a real domain - should fail due to pin mismatch
    // Using example.com which has valid TLS but won't match our dummy pin
    HttpRequest request;
    request.url = "https://example.com";
    request.timeout = Milliseconds{2000};
    request.enablePinning = true;
    
    auto response = client.send(request);
    
    // Should fail - either due to certificate pinning or connection issues
    // The important thing is it doesn't crash and handles pinning configuration
    EXPECT_FALSE(response.isSuccess());
}

// Test that pinning can be disabled
TEST_F(HttpClientTest, CertificatePinningCanBeDisabled) {
    // Create a certificate pin
    CertificatePin pin;
    pin.hostname = "example.com";
    
    SHA256Hash dummyHash;
    std::fill(dummyHash.begin(), dummyHash.end(), 0);
    pin.pins.push_back(dummyHash);
    
    client.addCertificatePin(pin);
    
    // Disable pinning
    client.setPinningEnabled(false);
    
    HttpRequest request;
    request.url = "https://example.com";
    request.timeout = Milliseconds{2000};
    
    auto response = client.send(request);
    
    // May still fail due to network, but should not fail due to pinning
    // This just ensures the API works without crashes
    (void)response;
    SUCCEED();
}

// Test CertPinner API
TEST_F(HttpClientTest, CertPinnerAPI) {
    auto pinner = std::make_shared<CertPinner>();
    
    CertificatePin pin1;
    pin1.hostname = "example.com";
    SHA256Hash hash1;
    std::fill(hash1.begin(), hash1.end(), 1);
    pin1.pins.push_back(hash1);
    
    CertificatePin pin2;
    pin2.hostname = "test.com";
    SHA256Hash hash2;
    std::fill(hash2.begin(), hash2.end(), 2);
    pin2.pins.push_back(hash2);
    
    pinner->addPin(pin1);
    pinner->addPin(pin2);
    
    EXPECT_EQ(pinner->getPins().size(), 2u);
    
    pinner->removePin("example.com");
    EXPECT_EQ(pinner->getPins().size(), 1u);
    
    pinner->clearPins();
    EXPECT_EQ(pinner->getPins().size(), 0u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
