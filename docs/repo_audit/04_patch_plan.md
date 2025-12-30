# Step 4: Concrete Patch Plan & Prioritized Tasks

**This work assumes testing is authorized by repository owner. Do not run against third-party systems.**

---

## Task Priority Legend

- **P0:** Blocking - System crashes or critical security vulnerability
- **P1:** High - Production blocker, security issue, or major functionality gap
- **P2:** Medium - Hardening, optimization, or technical debt
- **P3:** Low - Nice-to-have, documentation, or cosmetic

**Effort Scale:**
- **Small:** < 4 hours
- **Medium:** 4-16 hours (1-2 days)
- **Large:** > 16 hours (3+ days)

---

## P0 TASKS (Critical - Must Fix Before Production)

### TASK-001: Fix CorrelationEngine Segmentation Fault

**Priority:** P0  
**Effort:** Small  
**Risk:** Low (bug fix)

**Problem:**
CorrelationEngine crashes with segfault when processing violations with null/empty module names. Affects 7 unit tests.

**Affected Files:**
- `src/SDK/src/Internal/CorrelationEngine.hpp` (line 44)
- `src/SDK/src/Internal/CorrelationEngine.cpp` (line 114)
- `tests/SDK/test_correlation_enhancements.cpp` (all tests)

**Root Cause:**
```cpp
// Current (broken):
struct DetectionSignal {
    const char* module_name;  // ← Raw pointer, can dangle
};

// In ProcessViolation:
signal.module_name = event.module_name.c_str();  // ← Use-after-free if event destroyed
```

**Code Changes:**

1. **File:** `src/SDK/src/Internal/CorrelationEngine.hpp`
   ```cpp
   // Line 44 - Change:
   struct DetectionSignal {
       ViolationType type;
       DetectionCategory category;
       Severity original_severity;
       std::chrono::steady_clock::time_point timestamp;
       std::string details;
       uint64_t address;
       std::string module_name;  // ← Changed from const char*
       uint32_t scan_cycle;
       uint32_t persistence_count;
   };
   ```

2. **File:** `src/SDK/src/Internal/CorrelationEngine.cpp`
   ```cpp
   // Line 114 - Change:
   signal.module_name = event.module_name.empty() ? "<unknown>" : event.module_name;
   // ← Copy string, handle empty case
   ```

3. **File:** `src/SDK/src/Internal/OverlayVerifier.cpp` (if module_name is accessed)
   - Add null/empty checks before string operations
   - Use `signal.module_name.c_str()` when calling Win32 APIs

**Tests to Add/Modify:**
- `tests/SDK/test_correlation_engine.cpp`:
  ```cpp
  TEST_F(CorrelationEngineTest, EmptyModuleName) {
      ViolationEvent event{};
      event.type = ViolationType::DebuggerAttached;
      event.severity = Severity::High;
      event.module_name = "";  // Empty string
      
      Severity sev;
      bool report;
      EXPECT_NO_THROW(engine_->ProcessViolation(event, sev, report));
      EXPECT_GT(engine_->GetCorrelationScore(), 0.0);
  }
  ```

**Verification:**
```bash
cd build
cmake --build . --target SDKTests
ctest --output-on-failure -R CorrelationEnhancement
# Expected: All 7 tests pass
```

**Rollback Plan:**
If change causes other failures, revert commit and use defensive null checks only:
```cpp
signal.module_name = event.module_name.c_str() ? event.module_name.c_str() : "<unknown>";
```

**Monitoring:**
None needed (crash fix).

---

### TASK-002: Implement CloudReporter & Heartbeat

**Priority:** P0  
**Effort:** Large  
**Risk:** Medium (new feature, network stack)

**Problem:**
CloudReporter and Heartbeat are stubs. Without them:
- No violation reporting to server
- No client liveness detection
- No ban enforcement
- No telemetry analytics

**Affected Files:**
- `src/SDK/src/Network/CloudReporter.cpp` (stub)
- `src/SDK/src/Core/Heartbeat.cpp` (stub)
- `src/Core/Network/HttpClient.cpp` (stub)
- `src/Core/Network/TlsContext.cpp` (stub)
- `src/Core/Network/RequestSigner.cpp` (stub)

**Dependencies:**
- TASK-004 (HttpClient implementation)
- TASK-005 (Certificate pinning integration)
- TASK-006 (Request signing)

**Code Changes:**

1. **Implement HttpClient** (see TASK-004)

2. **File:** `src/SDK/src/Network/CloudReporter.cpp`
   ```cpp
   class CloudReporter::Impl {
   public:
       Impl(const char* endpoint) 
           : endpoint_(endpoint)
           , http_client_(std::make_unique<HttpClient>())
       {
           // Initialize HTTP client with TLS
           http_client_->SetTimeout(std::chrono::seconds(10));
           http_client_->EnableCertificatePinning(expected_cert_pins_);
       }
       
       void QueueEvent(const ViolationEvent& event) {
           std::lock_guard<std::mutex> lock(queue_mutex_);
           event_queue_.push_back(event);
           
           // Flush if queue > 100 events or last flush > 30s
           if (event_queue_.size() >= 100 || ShouldFlush()) {
               FlushAsync();
           }
       }
       
       ErrorCode SendBatch() {
           std::vector<ViolationEvent> batch;
           {
               std::lock_guard<std::mutex> lock(queue_mutex_);
               batch = std::move(event_queue_);
               event_queue_.clear();
           }
           
           if (batch.empty()) {
               return ErrorCode::Success;
           }
           
           // Serialize to JSON
           nlohmann::json payload;
           payload["events"] = nlohmann::json::array();
           for (const auto& event : batch) {
               payload["events"].push_back({
                   {"type", static_cast<int>(event.type)},
                   {"severity", static_cast<int>(event.severity)},
                   {"timestamp", event.timestamp},
                   {"module", event.module_name},
                   {"details", event.details}
               });
           }
           
           // Sign request
           std::string body = payload.dump();
           std::string signature = request_signer_->Sign(body);
           
           // Send HTTP POST
           HttpRequest req;
           req.method = "POST";
           req.url = endpoint_ + "/api/v1/violations";
           req.headers["Content-Type"] = "application/json";
           req.headers["X-Signature"] = signature;
           req.body = body;
           
           auto response = http_client_->Send(req);
           if (response.isFailure() || response.value().status_code != 200) {
               return ErrorCode::NetworkError;
           }
           
           return ErrorCode::Success;
       }
       
   private:
       std::string endpoint_;
       std::unique_ptr<HttpClient> http_client_;
       std::unique_ptr<RequestSigner> request_signer_;
       std::vector<ViolationEvent> event_queue_;
       std::mutex queue_mutex_;
   };
   ```

3. **File:** `src/SDK/src/Core/Heartbeat.cpp`
   ```cpp
   class Heartbeat::Impl {
   public:
       void Start(std::chrono::seconds interval) {
           running_ = true;
           heartbeat_thread_ = std::thread([this, interval]() {
               while (running_) {
                   SendHeartbeat();
                   std::this_thread::sleep_for(interval);
               }
           });
       }
       
       void Stop() {
           running_ = false;
           if (heartbeat_thread_.joinable()) {
               heartbeat_thread_.join();
           }
       }
       
   private:
       void SendHeartbeat() {
           HttpRequest req;
           req.method = "POST";
           req.url = endpoint_ + "/api/v1/heartbeat";
           req.headers["Content-Type"] = "application/json";
           req.body = R"({"status":"alive"})";
           
           http_client_->Send(req);
           // Ignore failures (transient network issues OK)
       }
       
       std::atomic<bool> running_{false};
       std::thread heartbeat_thread_;
       std::unique_ptr<HttpClient> http_client_;
       std::string endpoint_;
   };
   ```

**Tests to Add:**
- `tests/SDK/test_cloud_reporter.cpp`:
  ```cpp
  TEST_F(CloudReporterTest, QueueAndFlush) {
      MockHttpClient mock_http;
      CloudReporter reporter("https://api.sentinel.test");
      reporter.SetHttpClient(&mock_http);  // Dependency injection for testing
      
      ViolationEvent event = CreateTestEvent();
      reporter.QueueEvent(event);
      
      EXPECT_CALL(mock_http, Send(_))
          .WillOnce(Return(HttpResponse{200, "OK"}));
      
      EXPECT_EQ(reporter.Flush(), ErrorCode::Success);
  }
  ```

**Verification:**
```bash
# Unit tests
ctest -R CloudReporter

# Integration test with mock server
python scripts/mock_cloud_server.py &  # Start mock HTTP server
./bin/SDKTests --gtest_filter=CloudReporterIntegrationTest.*
```

**Rollback Plan:**
1. If HTTP client fails, use fallback to file-based logging:
   ```cpp
   if (http_send_fails) {
       WriteToLocalLog(event);  // Offline mode
   }
   ```

2. If heartbeat causes performance issues, increase interval or disable

**Monitoring:**
- Log HTTP request failures
- Track queue depth (alert if > 1000 events backlog)
- Track heartbeat failures (alert if 3 consecutive failures)

---

## P1 TASKS (High Priority - Production Blockers)

### TASK-003: Harden AES encryptWithNonce() API

**Priority:** P1  
**Effort:** Small  
**Risk:** Low (API change, needs audit of callers)

**Problem:**
Public API allows caller to supply nonce, enabling catastrophic nonce reuse vulnerability.

**Affected Files:**
- `src/Core/Crypto/AESCipher.cpp` (line 91-95)
- `include/Sentinel/Core/Crypto.hpp`

**Code Changes:**

**Option A: Make Internal (Recommended)**
```cpp
// File: include/Sentinel/Core/Crypto.hpp
class AESCipher {
public:
    Result<ByteBuffer> encrypt(ByteSpan plaintext, ByteSpan associatedData = {});
    Result<ByteBuffer> decrypt(ByteSpan ciphertext, ByteSpan associatedData = {});
    
private:  // ← Move to private
    Result<ByteBuffer> encryptWithNonce(
        ByteSpan plaintext,
        const AESNonce& nonce,
        ByteSpan associatedData = {});
    
    Result<ByteBuffer> decryptWithNonce(
        ByteSpan ciphertext,
        const AESNonce& nonce,
        ByteSpan associatedData = {});
};
```

**Option B: Add Nonce Tracking (If Must Remain Public)**
```cpp
// File: src/Core/Crypto/AESCipher.cpp
class AESCipher::Impl {
private:
    std::unordered_set<std::array<uint8_t, 12>> used_nonces_;
    std::mutex nonce_mutex_;
};

Result<ByteBuffer> Impl::encryptWithNonce(...) {
    // Check nonce uniqueness
    std::lock_guard<std::mutex> lock(nonce_mutex_);
    
    std::array<uint8_t, 12> nonce_array;
    std::memcpy(nonce_array.data(), nonce.data(), 12);
    
    if (used_nonces_.count(nonce_array)) {
        // Log critical error
        return ErrorCode::NonceReused;
    }
    
    used_nonces_.insert(nonce_array);
    
    // Continue with encryption...
}
```

**Tests to Add:**
```cpp
TEST_F(AESCipherTest, NonceReuseRejected) {
    AESKey key = GenerateTestKey();
    AESCipher cipher(key);
    AESNonce nonce{0};  // Fixed nonce
    
    auto ct1 = cipher.encryptWithNonce("msg1", nonce, {});
    EXPECT_TRUE(ct1.isSuccess());
    
    auto ct2 = cipher.encryptWithNonce("msg2", nonce, {});  // Same nonce
    EXPECT_TRUE(ct2.isFailure());
    EXPECT_EQ(ct2.error(), ErrorCode::NonceReused);
}
```

**Verification:**
```bash
# Audit all callers
grep -r "encryptWithNonce" src/ tests/
# Verify none rely on nonce control

# Run tests
ctest -R AESCipher
```

**Rollback Plan:**
If Option A breaks callers, use Option B (nonce tracking).

**Monitoring:**
Log all nonce reuse attempts (even if prevented).

---

### TASK-004: Implement HttpClient with TLS 1.3

**Priority:** P1  
**Effort:** Medium  
**Risk:** Medium (network stack, TLS complexity)

**Problem:**
HttpClient is a stub. Required for CloudReporter, certificate pinning, request signing.

**Affected Files:**
- `src/Core/Network/HttpClient.cpp` (stub)
- `src/Core/Network/TlsContext.cpp` (stub)

**Code Changes:**

Use libcurl (already widely used) or implement with OpenSSL directly:

**Option A: libcurl (Recommended)**
```cpp
// File: src/Core/Network/HttpClient.cpp
#include <curl/curl.h>

class HttpClient::Impl {
public:
    Impl() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_ = curl_easy_init();
        
        // Set TLS 1.3 minimum
        curl_easy_setopt(curl_, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
        
        // Enable certificate verification
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 2L);
    }
    
    ~Impl() {
        curl_easy_cleanup(curl_);
        curl_global_cleanup();
    }
    
    Result<HttpResponse> Send(const HttpRequest& req) {
        curl_easy_setopt(curl_, CURLOPT_URL, req.url.c_str());
        
        // Set method
        if (req.method == "POST") {
            curl_easy_setopt(curl_, CURLOPT_POST, 1L);
            curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, req.body.c_str());
        }
        
        // Set headers
        struct curl_slist* headers = nullptr;
        for (const auto& [key, value] : req.headers) {
            std::string header = key + ": " + value;
            headers = curl_slist_append(headers, header.c_str());
        }
        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
        
        // Set write callback
        std::string response_body;
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response_body);
        
        // Perform request
        CURLcode res = curl_easy_perform(curl_);
        curl_slist_free_all(headers);
        
        if (res != CURLE_OK) {
            return ErrorCode::NetworkError;
        }
        
        long status_code;
        curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &status_code);
        
        return HttpResponse{static_cast<int>(status_code), response_body};
    }
    
private:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }
    
    CURL* curl_;
};
```

**Dependency:**
Add to CMakeLists.txt:
```cmake
find_package(CURL REQUIRED)
target_link_libraries(SentinelCore PRIVATE CURL::libcurl)
```

**Tests to Add:**
```cpp
TEST_F(HttpClientTest, GET_Request) {
    HttpClient client;
    HttpRequest req;
    req.method = "GET";
    req.url = "https://httpbin.org/get";
    
    auto response = client.Send(req);
    ASSERT_TRUE(response.isSuccess());
    EXPECT_EQ(response.value().status_code, 200);
}

TEST_F(HttpClientTest, POST_WithJSON) {
    HttpClient client;
    HttpRequest req;
    req.method = "POST";
    req.url = "https://httpbin.org/post";
    req.headers["Content-Type"] = "application/json";
    req.body = R"({"key":"value"})";
    
    auto response = client.Send(req);
    ASSERT_TRUE(response.isSuccess());
    EXPECT_EQ(response.value().status_code, 200);
}
```

**Verification:**
```bash
# Unit tests with real HTTP (requires network)
ctest -R HttpClient

# Integration test
./bin/CoreTests --gtest_filter=HttpClientIntegrationTest.*
```

**Rollback Plan:**
If libcurl causes issues, use standalone OpenSSL BIO implementation (more complex).

**Monitoring:**
- Log all HTTP errors (status code, curl error code)
- Track request latency (alert if p99 > 5s)

---

### TASK-005: Integrate Certificate Pinning

**Priority:** P1  
**Effort:** Small  
**Risk:** Low (logic exists, needs plumbing)

**Problem:**
CertificatePinning logic exists but not integrated with HttpClient.

**Affected Files:**
- `src/Core/Network/CertificatePinning.cpp` (has logic)
- `src/Core/Network/HttpClient.cpp` (needs integration)

**Code Changes:**

```cpp
// File: src/Core/Network/HttpClient.cpp
class HttpClient::Impl {
public:
    void EnableCertificatePinning(const std::vector<std::string>& pin_sha256) {
        expected_pins_ = pin_sha256;
        pin_enabled_ = true;
    }
    
private:
    Result<HttpResponse> Send(const HttpRequest& req) {
        // ... existing code ...
        
        if (pin_enabled_) {
            // Get server certificate
            curl_easy_setopt(curl_, CURLOPT_CERTINFO, 1L);
            
            struct curl_certinfo* certinfo = nullptr;
            curl_easy_getinfo(curl_, CURLINFO_CERTINFO, &certinfo);
            
            // Extract and verify certificate pin
            if (!VerifyCertificatePin(certinfo)) {
                return ErrorCode::CertificatePinMismatch;
            }
        }
        
        // ... rest of Send() ...
    }
    
    bool VerifyCertificatePin(struct curl_certinfo* certinfo) {
        // Use existing CertificatePinning logic
        CertificatePinning pinner;
        for (const auto& pin : expected_pins_) {
            pinner.AddPin(pin);
        }
        
        // Extract DER-encoded cert from certinfo and verify
        // (implementation details depend on curl API)
        return pinner.VerifyPin(/* cert_der */);
    }
    
    std::vector<std::string> expected_pins_;
    bool pin_enabled_ = false;
};
```

**Tests to Add:**
```cpp
TEST_F(HttpClientTest, CertificatePinning_ValidPin) {
    HttpClient client;
    
    // Get real pin from test server
    std::string test_pin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    client.EnableCertificatePinning({test_pin});
    
    HttpRequest req;
    req.method = "GET";
    req.url = "https://test.sentinel.dev";  // Test server with known pin
    
    auto response = client.Send(req);
    EXPECT_TRUE(response.isSuccess());
}

TEST_F(HttpClientTest, CertificatePinning_InvalidPin) {
    HttpClient client;
    
    // Wrong pin
    std::string wrong_pin = "sha256/ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=";
    client.EnableCertificatePinning({wrong_pin});
    
    HttpRequest req;
    req.method = "GET";
    req.url = "https://test.sentinel.dev";
    
    auto response = client.Send(req);
    EXPECT_TRUE(response.isFailure());
    EXPECT_EQ(response.error(), ErrorCode::CertificatePinMismatch);
}
```

**Verification:**
```bash
ctest -R CertificatePinning
```

**Rollback Plan:**
If pin verification fails legitimate requests, add escape hatch:
```cpp
#ifdef SENTINEL_DEBUG
    if (getenv("SENTINEL_DISABLE_PINNING")) {
        return true;  // Allow bypass in dev
    }
#endif
```

**Monitoring:**
- Log all pin verification failures
- Alert if > 5% of requests fail pin check (might indicate MITM attack)

---

### TASK-006: Implement Request Signing (HMAC-based)

**Priority:** P1  
**Effort:** Small  
**Risk:** Low

**Problem:**
RequestSigner is a stub. Needed for API authentication and replay protection.

**Affected Files:**
- `src/Core/Network/RequestSigner.cpp` (stub)

**Code Changes:**

```cpp
// File: src/Core/Network/RequestSigner.cpp
class RequestSigner::Impl {
public:
    explicit Impl(ByteSpan api_key) {
        hmac_ = std::make_unique<HMAC>(api_key, HashAlgorithm::SHA256);
    }
    
    std::string Sign(const std::string& request_body) {
        // Create signing string: timestamp + "\n" + body
        auto timestamp = std::chrono::system_clock::now();
        auto ts_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()).count();
        
        std::string signing_string = std::to_string(ts_ms) + "\n" + request_body;
        
        // Compute HMAC
        auto mac = hmac_->compute(
            ByteSpan(reinterpret_cast<const Byte*>(signing_string.data()),
                    signing_string.size()));
        
        if (mac.isFailure()) {
            return "";  // Or throw
        }
        
        // Encode as base64
        std::string mac_b64 = Base64::encode(mac.value());
        
        // Return: timestamp:signature
        return std::to_string(ts_ms) + ":" + mac_b64;
    }
    
    bool Verify(const std::string& signature, const std::string& request_body) {
        // Parse timestamp:signature
        size_t colon = signature.find(':');
        if (colon == std::string::npos) {
            return false;
        }
        
        uint64_t timestamp = std::stoull(signature.substr(0, colon));
        std::string mac_b64 = signature.substr(colon + 1);
        
        // Check timestamp freshness (prevent replay)
        auto now = std::chrono::system_clock::now();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        
        if (std::abs(static_cast<int64_t>(now_ms - timestamp)) > 60000) {
            return false;  // Reject if > 60s old
        }
        
        // Recompute signature
        std::string signing_string = std::to_string(timestamp) + "\n" + request_body;
        auto computed_mac = hmac_->compute(
            ByteSpan(reinterpret_cast<const Byte*>(signing_string.data()),
                    signing_string.size()));
        
        if (computed_mac.isFailure()) {
            return false;
        }
        
        std::string expected_b64 = Base64::encode(computed_mac.value());
        
        // Constant-time compare
        return (expected_b64 == mac_b64);
    }
    
private:
    std::unique_ptr<HMAC> hmac_;
};
```

**Tests to Add:**
```cpp
TEST_F(RequestSignerTest, SignAndVerify) {
    std::vector<uint8_t> api_key(32, 0xAB);
    RequestSigner signer(api_key);
    
    std::string body = R"({"action":"test"})";
    std::string signature = signer.Sign(body);
    
    EXPECT_FALSE(signature.empty());
    EXPECT_TRUE(signer.Verify(signature, body));
}

TEST_F(RequestSignerTest, ReplayProtection) {
    std::vector<uint8_t> api_key(32, 0xAB);
    RequestSigner signer(api_key);
    
    // Create old signature (61 seconds ago)
    std::string old_sig = "1234567890:base64signature";
    std::string body = R"({"action":"test"})";
    
    EXPECT_FALSE(signer.Verify(old_sig, body));
}
```

**Verification:**
```bash
ctest -R RequestSigner
```

**Rollback Plan:**
None needed (new feature, no dependencies).

**Monitoring:**
- Log signature verification failures
- Alert if > 1% of requests have invalid signatures

---

## P2 TASKS (Medium Priority - Hardening)

### TASK-007: Add RAII Wrappers for OpenSSL Contexts

**Priority:** P2  
**Effort:** Small  
**Risk:** Low

**Problem:**
Manual EVP_CIPHER_CTX cleanup can leak on exceptions.

**Affected Files:**
- `src/Core/Crypto/AESCipher.cpp`
- `src/Core/Crypto/HMAC.cpp`
- `src/Core/Crypto/HashEngine.cpp`

**Code Changes:**

Create RAII wrapper:
```cpp
// File: src/Core/Crypto/OpenSSLRAII.hpp
namespace Sentinel::Crypto {

template<typename T, void(*Deleter)(T*)>
class OpenSSLHandle {
public:
    explicit OpenSSLHandle(T* ptr) : ptr_(ptr) {}
    ~OpenSSLHandle() { if (ptr_) Deleter(ptr_); }
    
    OpenSSLHandle(const OpenSSLHandle&) = delete;
    OpenSSLHandle& operator=(const OpenSSLHandle&) = delete;
    
    OpenSSLHandle(OpenSSLHandle&& other) noexcept : ptr_(other.ptr_) {
        other.ptr_ = nullptr;
    }
    
    T* get() const { return ptr_; }
    T* operator->() const { return ptr_; }
    explicit operator bool() const { return ptr_ != nullptr; }
    
private:
    T* ptr_;
};

using EVP_CIPHER_CTX_Handle = OpenSSLHandle<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;
using EVP_MD_CTX_Handle = OpenSSLHandle<EVP_MD_CTX, EVP_MD_CTX_free>;
using EVP_MAC_CTX_Handle = OpenSSLHandle<EVP_MAC_CTX, EVP_MAC_CTX_free>;

} // namespace Sentinel::Crypto
```

Use in AESCipher:
```cpp
// File: src/Core/Crypto/AESCipher.cpp
Result<ByteBuffer> Impl::encryptWithNonce(...) {
    EVP_CIPHER_CTX_Handle ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return ErrorCode::CryptoError;
    }
    
    // No manual cleanup needed - RAII handles it
    if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, m_key.data(), nonce.data())) {
        return ErrorCode::CryptoError;  // ctx automatically freed
    }
    
    // ... rest of function
}
```

**Tests:**
Existing tests should pass unchanged.

**Verification:**
```bash
ctest -R Crypto
```

**Rollback Plan:**
If RAII causes issues, revert to manual cleanup.

**Monitoring:**
None needed.

---

### TASK-008: SecureRandom Improvements

**Priority:** P2  
**Effort:** Small  
**Risk:** Low

**Problem:**
- Windows thread safety not documented
- Constructor throws exception

**Affected Files:**
- `src/Core/Crypto/SecureRandom.cpp`

**Code Changes:**

1. **Document Windows thread safety:**
   ```cpp
   // Line 66 - Add comment:
   // BCryptGenRandom is thread-safe when using BCRYPT_USE_SYSTEM_PREFERRED_RNG
   // See: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
   #ifdef _WIN32
       NTSTATUS status = BCryptGenRandom(...);
   #endif
   ```

2. **Make constructor noexcept:**
   ```cpp
   class SecureRandom::Impl {
   public:
       Impl() noexcept : m_fd(-1), m_initialized(false) {
   #ifndef _WIN32
           m_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
           m_initialized = (m_fd >= 0);
   #else
           m_initialized = true;
   #endif
       }
       
       Result<void> generate(Byte* buffer, size_t size) {
           if (!m_initialized) {
               return ErrorCode::CryptoError;
           }
           // ... rest ...
       }
       
   private:
       bool m_initialized;
       int m_fd;  // Linux only
   };
   ```

**Tests:**
Existing tests + new test for failed initialization.

**Verification:**
```bash
ctest -R SecureRandom
```

**Rollback Plan:**
Keep throwing constructor if noexcept breaks existing code.

**Monitoring:**
None needed.

---

## P3 TASKS (Low Priority)

### TASK-009: Implement Logger

**Priority:** P3  
**Effort:** Small  
**Risk:** Low

**Problem:**
Logger is a stub. Crypto errors are silent.

**Affected Files:**
- `src/Core/Utils/Logger.cpp` (stub)

**Code Changes:**

Use spdlog (already in dependencies):
```cpp
// File: src/Core/Utils/Logger.cpp
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

namespace Sentinel::Core {

class Logger::Impl {
public:
    static void Initialize() {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("sentinel.log");
        
        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        auto logger = std::make_shared<spdlog::logger>("sentinel", sinks.begin(), sinks.end());
        
        spdlog::set_default_logger(logger);
        spdlog::set_level(spdlog::level::info);
    }
    
    template<typename... Args>
    static void Info(const char* fmt, Args&&... args) {
        spdlog::info(fmt, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    static void Error(const char* fmt, Args&&... args) {
        spdlog::error(fmt, std::forward<Args>(args)...);
    }
};

} // namespace Sentinel::Core
```

Then update HashEngine:
```cpp
// File: src/Core/Crypto/HashEngine.cpp
if (!EVP_DigestInit_ex(ctx, m_evp_md, nullptr)) {
    uint64_t err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    Logger::Error("HashEngine: EVP_DigestInit_ex failed: {}", err_buf);
    cleanup();
    return ErrorCode::CryptoError;
}
```

**Rollback Plan:**
If logging causes performance issues, add compile-time flag to disable.

**Monitoring:**
None needed (logging is the monitoring).

---

## Summary

**P0 Tasks (Blocking):**
- TASK-001: Fix CorrelationEngine segfault (Small)
- TASK-002: Implement CloudReporter & Heartbeat (Large)

**P1 Tasks (High Priority):**
- TASK-003: Harden AES encryptWithNonce() (Small)
- TASK-004: Implement HttpClient (Medium)
- TASK-005: Integrate Certificate Pinning (Small)
- TASK-006: Implement Request Signing (Small)

**P2 Tasks (Medium Priority):**
- TASK-007: Add RAII wrappers (Small)
- TASK-008: SecureRandom improvements (Small)

**P3 Tasks (Low Priority):**
- TASK-009: Implement Logger (Small)

**Total Effort Estimate:**
- P0: 1 Small + 1 Large = ~20 hours
- P1: 3 Small + 1 Medium = ~16 hours
- P2: 2 Small = ~6 hours
- P3: 1 Small = ~3 hours
- **Total:** ~45 hours (~1.5 developer-weeks)

---

**Document Version:** 1.0  
**Generated:** 2025-12-30  
**Tasks Defined:** 9  
**Critical Path:** TASK-001 → TASK-004 → TASK-005 → TASK-006 → TASK-002
