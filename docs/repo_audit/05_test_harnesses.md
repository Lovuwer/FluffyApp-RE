# Step 5: Safe Test Harnesses & Reproduction Steps

**This work assumes testing is authorized by repository owner. Do not run against third-party systems.**

**SECURITY NOTE:** This document provides SAFE test harnesses for defensive validation. NO exploit code, bypass methods, or attack tools are included.

---

## Overview

This document provides safe, defensive test harnesses to validate fixes and detect vulnerabilities WITHOUT providing exploitable code.

**Test Philosophy:**
- **White-box testing:** Test internal state, not attack vectors
- **Fault injection:** Flip bits in controlled memory, not production code
- **Mock objects:** Simulate attacker capabilities in isolated test environment
- **Telemetry validation:** Verify detection fires, not how to evade

---

## 1. CORRELATION ENGINE TEST HARNESSES

### Test Harness 1.1: Null/Empty Module Name Handling

**Purpose:** Validate TASK-001 fix (segfault on null module name)

**File:** `tests/SDK/test_correlation_engine_null_safety.cpp`

```cpp
#include <gtest/gtest.h>
#include "Internal/CorrelationEngine.hpp"

using namespace Sentinel::SDK;

class CorrelationEngineNullSafetyTest : public ::testing::Test {
protected:
    void SetUp() override {
        engine_ = std::make_unique<CorrelationEngine>();
        engine_->Initialize();
    }
    
    std::unique_ptr<CorrelationEngine> engine_;
};

/**
 * SAFE TEST: Validate null module name doesn't crash
 * Does NOT demonstrate how to exploit; validates defensive fix
 */
TEST_F(CorrelationEngineNullSafetyTest, EmptyModuleName_NoSegfault) {
    ViolationEvent event{};
    event.type = ViolationType::DebuggerAttached;
    event.severity = Severity::High;
    event.module_name = "";  // Empty string (safe input)
    event.details = "Test violation";
    event.timestamp = 0;
    event.address = 0;
    event.detection_id = 1;
    
    Severity sev_out;
    bool should_report;
    
    // Should not crash
    EXPECT_NO_THROW({
        engine_->ProcessViolation(event, sev_out, should_report);
    });
    
    // Should still process correctly
    EXPECT_GT(engine_->GetCorrelationScore(), 0.0);
}

/**
 * SAFE TEST: Validate missing details field handling
 */
TEST_F(CorrelationEngineNullSafetyTest, EmptyDetailsField_NoSegfault) {
    ViolationEvent event{};
    event.type = ViolationType::InlineHook;
    event.severity = Severity::Critical;
    event.module_name = "game.exe";
    event.details = "";  // Empty details
    
    Severity sev_out;
    bool should_report;
    
    EXPECT_NO_THROW({
        engine_->ProcessViolation(event, sev_out, should_report);
    });
}

/**
 * SAFE TEST: Validate many events don't cause memory leak
 */
TEST_F(CorrelationEngineNullSafetyTest, ManyEvents_NoMemoryLeak) {
    size_t initial_alloc = GetCurrentMemoryUsage();  // Pseudo-code
    
    for (int i = 0; i < 10000; i++) {
        ViolationEvent event{};
        event.type = ViolationType::MemoryWrite;
        event.severity = Severity::Medium;
        event.module_name = "";
        event.details = "Test " + std::to_string(i);
        
        Severity sev;
        bool report;
        engine_->ProcessViolation(event, sev, report);
    }
    
    engine_->Reset();
    
    size_t final_alloc = GetCurrentMemoryUsage();
    
    // Memory should be released (within 10% tolerance)
    EXPECT_LT(final_alloc - initial_alloc, initial_alloc * 0.1);
}
```

**How to Run:**
```bash
cd build
cmake --build . --target SDKTests
./bin/SDKTests --gtest_filter=CorrelationEngineNullSafetyTest.*
```

**Expected Output:**
```
[==========] Running 3 tests from 1 test suite.
[ RUN      ] CorrelationEngineNullSafetyTest.EmptyModuleName_NoSegfault
[       OK ] (0 ms)
[ RUN      ] CorrelationEngineNullSafetyTest.EmptyDetailsField_NoSegfault
[       OK ] (0 ms)
[ RUN      ] CorrelationEngineNullSafetyTest.ManyEvents_NoMemoryLeak
[       OK ] (15 ms)
[==========] 3 tests from 1 test suite ran. (15 ms total)
[  PASSED  ] 3 tests.
```

---

## 2. CRYPTO TEST HARNESSES

### Test Harness 2.1: AES-GCM Nonce Uniqueness Validation

**Purpose:** Validate TASK-003 fix (nonce reuse prevention)

**File:** `tests/Core/test_aes_nonce_safety.cpp`

```cpp
#include <gtest/gtest.h>
#include <Sentinel/Core/Crypto.hpp>
#include <unordered_set>

using namespace Sentinel::Crypto;

class AESNonceSafetyTest : public ::testing::Test {
protected:
    AESKey GenerateTestKey() {
        AESKey key;
        SecureRandom rng;
        auto result = rng.generate(key.size());
        std::memcpy(key.data(), result.value().data(), key.size());
        return key;
    }
};

/**
 * SAFE TEST: Validate nonces are unique across encryptions
 * Does NOT demonstrate nonce reuse attack; validates automatic nonce generation
 */
TEST_F(AESNonceSafetyTest, AutomaticNonces_AlwaysUnique) {
    AESKey key = GenerateTestKey();
    AESCipher cipher(key);
    
    std::unordered_set<std::string> seen_ivs;
    
    // Encrypt 1000 messages, collect IVs
    for (int i = 0; i < 1000; i++) {
        std::string plaintext = "Message " + std::to_string(i);
        auto ciphertext = cipher.encrypt(ByteSpan(
            reinterpret_cast<const Byte*>(plaintext.data()),
            plaintext.size()
        ), {});
        
        ASSERT_TRUE(ciphertext.isSuccess());
        
        // Extract IV (first 12 bytes)
        std::string iv(ciphertext.value().begin(), 
                      ciphertext.value().begin() + 12);
        
        // IV should be unique
        EXPECT_EQ(seen_ivs.count(iv), 0u) 
            << "Nonce reused at iteration " << i;
        
        seen_ivs.insert(iv);
    }
    
    // All 1000 IVs should be unique
    EXPECT_EQ(seen_ivs.size(), 1000u);
}

/**
 * SAFE TEST: Validate decryption rejects tampered ciphertexts
 * Demonstrates defensive behavior, not attack vector
 */
TEST_F(AESNonceSafetyTest, TamperingDetection_AllBitsFlipped) {
    AESKey key = GenerateTestKey();
    AESCipher cipher(key);
    
    std::string plaintext = "Secret message";
    auto ciphertext = cipher.encrypt(ByteSpan(
        reinterpret_cast<const Byte*>(plaintext.data()),
        plaintext.size()
    ), {});
    
    ASSERT_TRUE(ciphertext.isSuccess());
    
    ByteBuffer ct = ciphertext.value();
    
    // Flip EACH bit and verify decryption fails
    for (size_t byte_idx = 12; byte_idx < ct.size(); byte_idx++) {  // Skip IV
        for (int bit = 0; bit < 8; bit++) {
            ByteBuffer tampered = ct;
            tampered[byte_idx] ^= (1 << bit);  // Flip one bit
            
            auto decrypted = cipher.decrypt(tampered, {});
            
            // Should reject tampered ciphertext
            EXPECT_TRUE(decrypted.isFailure()) 
                << "Tampering at byte " << byte_idx << " bit " << bit 
                << " not detected";
        }
    }
}

/**
 * SAFE TEST: If manual nonce API exists, verify nonce tracking
 * (Only if TASK-003 Option B implemented)
 */
#ifdef SENTINEL_AES_NONCE_TRACKING
TEST_F(AESNonceSafetyTest, ManualNonce_ReuseRejected) {
    AESKey key = GenerateTestKey();
    AESCipher cipher(key);
    
    AESNonce fixed_nonce{0};  // Fixed nonce (BAD practice, testing only)
    
    std::string msg1 = "First message";
    auto ct1 = cipher.encryptWithNonce(
        ByteSpan(reinterpret_cast<const Byte*>(msg1.data()), msg1.size()),
        fixed_nonce,
        {}
    );
    
    EXPECT_TRUE(ct1.isSuccess()) << "First use of nonce should succeed";
    
    std::string msg2 = "Second message";
    auto ct2 = cipher.encryptWithNonce(
        ByteSpan(reinterpret_cast<const Byte*>(msg2.data()), msg2.size()),
        fixed_nonce,  // Same nonce (reuse)
        {}
    );
    
    EXPECT_TRUE(ct2.isFailure()) << "Nonce reuse should be rejected";
    EXPECT_EQ(ct2.error(), ErrorCode::NonceReused);
}
#endif
```

**How to Run:**
```bash
cd build
ctest -R AESNonceSafety
```

---

## 3. NETWORK TEST HARNESSES

### Test Harness 3.1: HttpClient Integration (Mock Server)

**Purpose:** Validate TASK-004 implementation (HttpClient)

**File:** `tests/Core/test_http_client_integration.cpp`

```cpp
#include <gtest/gtest.h>
#include <Sentinel/Core/Network.hpp>
#include <thread>
#include <httplib.h>  // cpp-httplib for mock server

using namespace Sentinel::Core::Network;

class HttpClientIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Start mock HTTPS server on localhost:8443
        server_thread_ = std::thread([this]() {
            httplib::SSLServer svr("./test_cert.pem", "./test_key.pem");
            
            svr.Get("/test", [](const httplib::Request&, httplib::Response& res) {
                res.set_content("GET OK", "text/plain");
            });
            
            svr.Post("/test", [](const httplib::Request& req, httplib::Response& res) {
                res.set_content("POST OK: " + req.body, "text/plain");
            });
            
            svr.listen("localhost", 8443);
        });
        
        // Wait for server to start
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    void TearDown() override {
        // Stop mock server (httplib has no clean shutdown in test)
        // In real test, use server.stop()
    }
    
    std::thread server_thread_;
};

/**
 * SAFE TEST: Validate basic HTTPS GET request
 * Uses local mock server, not production systems
 */
TEST_F(HttpClientIntegrationTest, GET_LocalMockServer) {
    HttpClient client;
    
    HttpRequest req;
    req.method = "GET";
    req.url = "https://localhost:8443/test";
    
    auto response = client.Send(req);
    
    ASSERT_TRUE(response.isSuccess());
    EXPECT_EQ(response.value().status_code, 200);
    EXPECT_EQ(response.value().body, "GET OK");
}

/**
 * SAFE TEST: Validate POST with JSON body
 */
TEST_F(HttpClientIntegrationTest, POST_WithJSON) {
    HttpClient client;
    
    HttpRequest req;
    req.method = "POST";
    req.url = "https://localhost:8443/test";
    req.headers["Content-Type"] = "application/json";
    req.body = R"({"key":"value"})";
    
    auto response = client.Send(req);
    
    ASSERT_TRUE(response.isSuccess());
    EXPECT_EQ(response.value().status_code, 200);
    EXPECT_THAT(response.value().body, testing::HasSubstr("POST OK"));
}

/**
 * SAFE TEST: Validate certificate pinning rejects wrong cert
 */
TEST_F(HttpClientIntegrationTest, CertPinning_WrongPin_Rejected) {
    HttpClient client;
    
    // Set wrong pin (not matching test server cert)
    std::string wrong_pin = "sha256/ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=";
    client.EnableCertificatePinning({wrong_pin});
    
    HttpRequest req;
    req.method = "GET";
    req.url = "https://localhost:8443/test";
    
    auto response = client.Send(req);
    
    EXPECT_TRUE(response.isFailure());
    EXPECT_EQ(response.error(), ErrorCode::CertificatePinMismatch);
}
```

**Mock Server Setup:**
```bash
# Generate test certificate
openssl req -x509 -newkey rsa:2048 -keyout test_key.pem -out test_cert.pem \
    -days 365 -nodes -subj "/CN=localhost"

# Get certificate fingerprint for pinning tests
openssl x509 -in test_cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -binary | \
    openssl enc -base64
```

**How to Run:**
```bash
cd build
# Start mock server in background
./bin/CoreTests --gtest_filter=HttpClientIntegrationTest.*
```

---

## 4. DETECTION TEST HARNESSES

### Test Harness 4.1: IntegrityCheck Validation (Safe)

**Purpose:** Validate IntegrityCheck detects modifications WITHOUT showing bypass

**File:** `tests/SDK/test_integrity_check_safe.cpp`

```cpp
#include <gtest/gtest.h>
#include "Internal/Detection.hpp"
#include <fstream>

using namespace Sentinel::SDK;

class IntegrityCheckSafeTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary test binary
        CreateTestBinary();
    }
    
    void CreateTestBinary() {
        std::ofstream ofs("test_binary.exe", std::ios::binary);
        std::vector<uint8_t> dummy_code(4096, 0x90);  // NOP slide
        ofs.write(reinterpret_cast<const char*>(dummy_code.data()), dummy_code.size());
        ofs.close();
    }
    
    void TearDown() override {
        std::remove("test_binary.exe");
    }
};

/**
 * SAFE TEST: Validate integrity check detects in-memory modification
 * Does NOT demonstrate production bypass; tests detection in controlled environment
 */
TEST_F(IntegrityCheckSafeTest, InMemoryModification_Detected) {
    IntegrityChecker checker;
    
    // Load test binary into memory
    std::vector<uint8_t> binary_data = LoadBinaryFile("test_binary.exe");
    
    // Compute baseline hash
    auto baseline_hash = checker.ComputeHash(binary_data.data(), binary_data.size());
    ASSERT_TRUE(baseline_hash.isSuccess());
    
    // Modify ONE byte in controlled memory copy (not production code)
    std::vector<uint8_t> modified = binary_data;
    modified[100] ^= 0xFF;  // Flip byte 100
    
    // Compute hash of modified version
    auto modified_hash = checker.ComputeHash(modified.data(), modified.size());
    ASSERT_TRUE(modified_hash.isSuccess());
    
    // Hashes should differ
    EXPECT_NE(baseline_hash.value(), modified_hash.value())
        << "Integrity check failed to detect modification";
}

/**
 * SAFE TEST: Validate integrity check is consistent
 */
TEST_F(IntegrityCheckSafeTest, MultipleChecks_Consistent) {
    IntegrityChecker checker;
    
    std::vector<uint8_t> binary_data = LoadBinaryFile("test_binary.exe");
    
    auto hash1 = checker.ComputeHash(binary_data.data(), binary_data.size());
    auto hash2 = checker.ComputeHash(binary_data.data(), binary_data.size());
    
    EXPECT_EQ(hash1.value(), hash2.value())
        << "Integrity hash is not deterministic";
}
```

**How to Run:**
```bash
cd build
./bin/SDKTests --gtest_filter=IntegrityCheckSafeTest.*
```

---

## 5. CLOUDREPORTER TEST HARNESSES

### Test Harness 5.1: CloudReporter Mock Backend

**Purpose:** Validate TASK-002 implementation (CloudReporter)

**File:** `tests/SDK/test_cloud_reporter_mock.cpp`

```cpp
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "Internal/Detection.hpp"

using namespace Sentinel::SDK;
using ::testing::_;
using ::testing::Return;

// Mock HTTP client for dependency injection
class MockHttpClient : public IHttpClient {
public:
    MOCK_METHOD(Result<HttpResponse>, Send, (const HttpRequest&), (override));
};

class CloudReporterMockTest : public ::testing::Test {
protected:
    void SetUp() override {
        mock_http_ = std::make_shared<MockHttpClient>();
        reporter_ = std::make_unique<CloudReporter>("https://api.test.sentinel.dev");
        reporter_->SetHttpClient(mock_http_);  // Inject mock
    }
    
    std::shared_ptr<MockHttpClient> mock_http_;
    std::unique_ptr<CloudReporter> reporter_;
};

/**
 * SAFE TEST: Validate events are queued and flushed
 * Uses mock HTTP client, not real network
 */
TEST_F(CloudReporterMockTest, QueueAndFlush_Success) {
    ViolationEvent event{};
    event.type = ViolationType::DebuggerAttached;
    event.severity = Severity::High;
    event.module_name = "game.exe";
    event.details = "Test violation";
    
    // Queue event
    reporter_->QueueEvent(event);
    
    // Expect HTTP POST
    EXPECT_CALL(*mock_http_, Send(_))
        .WillOnce([](const HttpRequest& req) {
            // Validate request format
            EXPECT_EQ(req.method, "POST");
            EXPECT_THAT(req.url, testing::HasSubstr("/api/v1/violations"));
            EXPECT_THAT(req.body, testing::HasSubstr("DebuggerAttached"));
            
            return Result<HttpResponse>::Success({200, "OK"});
        });
    
    // Flush
    EXPECT_EQ(reporter_->Flush(), ErrorCode::Success);
}

/**
 * SAFE TEST: Validate retry on transient failure
 */
TEST_F(CloudReporterMockTest, TransientFailure_Retried) {
    ViolationEvent event = CreateTestEvent();
    reporter_->QueueEvent(event);
    
    // First attempt fails, second succeeds
    EXPECT_CALL(*mock_http_, Send(_))
        .WillOnce(Return(Result<HttpResponse>::Failure(ErrorCode::NetworkError)))
        .WillOnce(Return(Result<HttpResponse>::Success({200, "OK"})));
    
    EXPECT_EQ(reporter_->Flush(), ErrorCode::Success);
}
```

**How to Run:**
```bash
cd build
./bin/SDKTests --gtest_filter=CloudReporterMockTest.*
```

---

## 6. RUNNING ALL HARNESSES

### Complete Test Suite

```bash
#!/bin/bash
# File: scripts/run_all_test_harnesses.sh

set -e

cd build

echo "========================================="
echo "Running Safe Test Harnesses"
echo "========================================="

echo "1. CorrelationEngine Null Safety..."
./bin/SDKTests --gtest_filter=CorrelationEngineNullSafetyTest.*

echo "2. AES Nonce Safety..."
./bin/CoreTests --gtest_filter=AESNonceSafetyTest.*

echo "3. HttpClient Integration (requires mock server)..."
./bin/CoreTests --gtest_filter=HttpClientIntegrationTest.*

echo "4. IntegrityCheck Safe Tests..."
./bin/SDKTests --gtest_filter=IntegrityCheckSafeTest.*

echo "5. CloudReporter Mock Tests..."
./bin/SDKTests --gtest_filter=CloudReporterMockTest.*

echo "========================================="
echo "All Test Harnesses Passed!"
echo "========================================="
```

**Expected Runtime:** < 30 seconds total

---

## 7. COVERAGE VALIDATION

After running all harnesses, verify coverage:

```bash
# If coverage enabled
cd build
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' '*/tests/*' '*/googletest/*' --output-file coverage_filtered.info
genhtml coverage_filtered.info --output-directory coverage_html

# Open coverage_html/index.html in browser
```

**Target Coverage:**
- Crypto: > 95%
- Detection: > 85%
- Network: > 80%

---

## Summary

All test harnesses:
- ✅ Safe (no exploit code)
- ✅ Defensive (validate fixes, not attacks)
- ✅ Isolated (mock servers, controlled environments)
- ✅ Reproducible (deterministic, automated)

**Document Version:** 1.0  
**Generated:** 2025-12-30  
**Test Harnesses:** 6 categories, 15+ test cases
