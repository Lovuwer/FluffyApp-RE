# Security Invariants

**Classification:** Internal Engineering Reference  
**Purpose:** Define non-negotiable security requirements that MUST be maintained  
**Last Updated:** 2025-01-29

---

## Overview

Security invariants are **absolute requirements** that the system must maintain at all times. Violation of an invariant indicates either:
1. A critical implementation bug, OR
2. An active attack in progress

These are NOT goals or best practices—they are **hard requirements** enforced by the code.

---

## Table of Contents

1. [Cryptographic Invariants](#cryptographic-invariants)
2. [Memory Safety Invariants](#memory-safety-invariants)
3. [State Management Invariants](#state-management-invariants)
4. [Network Security Invariants](#network-security-invariants)
5. [Detection Invariants](#detection-invariants)
6. [Resource Management Invariants](#resource-management-invariants)
7. [Initialization Invariants](#initialization-invariants)

---

## Cryptographic Invariants

### INV-CRYPTO-001: Nonce Reuse Must Be Impossible

**Requirement:** No cryptographic nonce/IV shall ever be reused with the same key

**Rationale:** Nonce reuse in stream ciphers (AES-CTR, ChaCha20) or authenticated encryption (AES-GCM) completely breaks confidentiality and/or authentication.

**Enforcement:**
```cpp
// Each packet gets unique nonce derived from counter
uint64_t packet_nonce = nonce_counter_.fetch_add(1, std::memory_order_seq_cst);
// If counter wraps, key MUST be rotated
assert(packet_nonce != 0 && "Nonce counter wrapped - rotate key immediately");
```

**Verification:**
- Static analysis: Grep for nonce generation, verify atomic increment
- Runtime: Assert on nonce == 0 (wraparound)
- Testing: Send 2^64 packets, verify key rotation before wraparound

**Violation Impact:** CRITICAL - Complete encryption compromise

---

### INV-CRYPTO-002: Secrets Must Be Zeroed on All Exits

**Requirement:** All cryptographic keys, nonces, and sensitive data MUST be zeroed before deallocation

**Rationale:** Prevent key extraction from memory dumps, swap files, or hibernation files.

**Enforcement:**
```cpp
class SecretKey {
    ~SecretKey() {
        SecureZero(key_data_, key_size_);  // Volatile writes, compiler can't optimize away
    }
};
```

**Verification:**
- Code review: All key classes use SecureZero in destructor
- Runtime: Use memory scanning tool to verify keys zeroed after shutdown
- Testing: Crash process, dump memory, grep for known keys

**Violation Impact:** HIGH - Key leakage to disk/memory dumps

---

### INV-CRYPTO-003: No Weak Algorithms Shall Be Used

**Requirement:** Only approved cryptographic algorithms with minimum key sizes

**Approved:**
- Encryption: AES-256, ChaCha20
- Hashing: SHA-256, SHA-512, BLAKE2b
- MAC: HMAC-SHA256
- Signing: RSA-2048+, ECDSA-P256+
- KDF: PBKDF2, Argon2

**Forbidden:**
- MD5, SHA-1 (collision attacks)
- DES, 3DES, RC4 (broken)
- AES-128 (insufficient margin)
- RSA-1024 (factorable)
- Custom crypto ("roll your own")

**Enforcement:**
```cpp
static_assert(AES_KEY_SIZE >= 256, "AES key must be at least 256 bits");
```

**Verification:**
- Static analysis: Grep for forbidden algorithm names
- Code review: Approve all crypto code changes
- Dependency audit: Ensure OpenSSL configured to reject weak ciphers

**Violation Impact:** CRITICAL - Use of broken crypto

---

### INV-CRYPTO-004: Cryptographic Randomness for Security

**Requirement:** All security-sensitive random values MUST use cryptographic RNG (not pseudo-random)

**Approved Sources:**
- Windows: `BCryptGenRandom` (CNG)
- Linux: `/dev/urandom`
- C++: `std::random_device` (if backed by OS RNG)

**Forbidden:**
- `rand()`, `srand()` (predictable)
- `std::mt19937` without seed from crypto RNG
- RDTSC-based "randomness"
- Timestamp-based seeds

**Enforcement:**
```cpp
// Use SecureRandom wrapper, never std::rand()
uint64_t nonce = SecureRandom::GetUInt64();
```

**Verification:**
- Static analysis: Grep for `rand(`, `srand(`, `mt19937`
- Code review: All random security values use SecureRandom
- Testing: NIST randomness test suite on output

**Violation Impact:** CRITICAL - Predictable keys/nonces

---

## Memory Safety Invariants

### INV-MEM-001: Memory Reads Must Be Validated

**Requirement:** All memory reads (especially from untrusted addresses) MUST be validated before access

**Rationale:** Prevent crashes from reading unmapped memory, catch tampering attempts

**Enforcement:**
```cpp
if (!SafeMemory::IsReadable(address, size)) {
    return Error::InvalidAddress;
}
// Only read after validation
memcpy(dest, address, size);
```

**Verification:**
- Code review: All memory access uses SafeMemory wrappers
- Fuzzing: Send invalid addresses, verify no crash
- SEH: Exception handler should NEVER be triggered in production

**Violation Impact:** HIGH - Crashes, denial of service

---

### INV-MEM-002: No Unbounded Allocations

**Requirement:** All memory allocations MUST have size limits

**Rationale:** Prevent memory exhaustion attacks, OOM kills

**Enforcement:**
```cpp
constexpr size_t MAX_PACKET_SIZE = 1024 * 1024;  // 1MB
if (packet_size > MAX_PACKET_SIZE) {
    return Error::PacketTooLarge;
}
```

**Verification:**
- Code review: All allocation sites have max size checks
- Fuzzing: Send huge allocation requests, verify rejection
- Resource testing: Monitor memory under sustained load

**Violation Impact:** HIGH - Memory exhaustion, DoS

---

### INV-MEM-003: Use-After-Free Must Be Impossible

**Requirement:** No pointer shall be dereferenced after the object is destroyed

**Rationale:** UAF is most common security vulnerability, exploitable for code execution

**Enforcement:**
- Use RAII (smart pointers, containers)
- Never store raw pointers to owned objects
- Use weak_ptr for optional references

```cpp
// GOOD: RAII ensures lifetime
std::unique_ptr<Detector> detector = std::make_unique<AntiDebugDetector>();

// BAD: Raw pointer, no lifetime guarantee
Detector* detector = new AntiDebugDetector();  // ❌ FORBIDDEN
```

**Verification:**
- Code review: No manual `new`/`delete` without RAII wrapper
- AddressSanitizer: Run all tests with ASAN enabled
- Static analysis: Use lifetime analysis tools

**Violation Impact:** CRITICAL - Code execution vulnerability

---

### INV-MEM-004: Buffer Overflows Must Be Impossible

**Requirement:** All buffer writes MUST be bounds-checked

**Rationale:** Buffer overflow = code execution

**Enforcement:**
```cpp
// Use safe string functions
strncpy_s(dest, dest_size, src, _TRUNCATE);  // ✅
strcpy(dest, src);  // ❌ FORBIDDEN

// Use std::vector, not raw arrays
std::vector<uint8_t> buffer(size);  // ✅
uint8_t buffer[1024]; // ❌ AVOID (fixed size)
```

**Verification:**
- Static analysis: Ban unsafe functions (strcpy, sprintf, gets)
- Fuzzing: Send oversized inputs, verify no crash
- AddressSanitizer: Detects all buffer overflows

**Violation Impact:** CRITICAL - Code execution vulnerability

---

## State Management Invariants

### INV-STATE-001: Initialization Before Use

**Requirement:** No SDK function (except `Initialize()`) shall be called before SDK is initialized

**Rationale:** Prevents null pointer dereferences, undefined behavior

**Enforcement:**
```cpp
ErrorCode Update() {
    if (!IsInitialized()) {
        return ErrorCode::NotInitialized;
    }
    // ... actual work
}
```

**Verification:**
- Code review: All API functions check `IsInitialized()`
- Testing: Call functions before init, verify error return
- Runtime: Assert in debug builds

**Violation Impact:** HIGH - Crashes, undefined behavior

---

### INV-STATE-002: Double-Initialization Forbidden

**Requirement:** `Initialize()` shall fail if already initialized

**Rationale:** Prevents resource leaks, state corruption

**Enforcement:**
```cpp
ErrorCode Initialize(const Configuration* config) {
    if (IsInitialized()) {
        return ErrorCode::AlreadyInitialized;
    }
    // ... initialization
}
```

**Verification:**
- Testing: Call Initialize() twice, verify error on second call
- Resource tracking: Monitor for leaks after double-init attempt

**Violation Impact:** MEDIUM - Resource leaks

---

### INV-STATE-003: Thread-Safe State Transitions

**Requirement:** All shared state modifications MUST be protected by mutex or atomic operations

**Rationale:** Data races lead to undefined behavior, crashes

**Enforcement:**
```cpp
class Detector {
    void AddFunction(const FunctionProtection& func) {
        std::lock_guard<std::mutex> lock(mutex_);  // ✅
        functions_.push_back(func);
    }
private:
    std::mutex mutex_;
    std::vector<FunctionProtection> functions_;
};
```

**Verification:**
- Thread Sanitizer: Run all tests with TSAN
- Code review: All shared state protected
- Stress testing: Concurrent access from multiple threads

**Violation Impact:** HIGH - Data corruption, crashes

---

## Network Security Invariants

### INV-NET-001: All Requests Must Be Authenticated

**Requirement:** No cloud request shall be accepted without valid HMAC signature

**Rationale:** Prevent request forgery, impersonation

**Enforcement:**
```cpp
bool VerifyRequest(const Request& req) {
    auto computed_hmac = HMAC_SHA256(license_key_, req.payload);
    return ConstantTimeCompare(computed_hmac, req.hmac);
}
```

**Verification:**
- Testing: Send unsigned request, verify rejection
- Testing: Send wrong signature, verify rejection
- Timing: Verify constant-time comparison (prevent timing attacks)

**Violation Impact:** CRITICAL - Request forgery

---

### INV-NET-002: Replay Protection Required

**Requirement:** All network requests MUST include nonce and timestamp, validated by server

**Rationale:** Prevent replay attacks

**Enforcement:**
```cpp
struct Request {
    uint64_t nonce;        // Monotonic counter
    uint64_t timestamp;    // Unix epoch seconds
    // ... payload
};

// Server validates
bool ValidateRequest(const Request& req) {
    if (req.timestamp < now() - 300) return false;  // Max 5 min old
    if (seen_nonces_.contains(req.nonce)) return false;  // Duplicate
    seen_nonces_.insert(req.nonce);
    return true;
}
```

**Verification:**
- Testing: Replay captured request, verify rejection
- Testing: Send old timestamp, verify rejection
- Testing: Send duplicate nonce, verify rejection

**Violation Impact:** CRITICAL - Replay attacks

---

### INV-NET-003: Certificate Pinning for Cloud Endpoints

**Requirement:** TLS connections to cloud MUST validate against pinned certificate

**Rationale:** Prevent MITM attacks even with compromised root CA

**Enforcement:**
```cpp
bool ValidateCertificate(X509* cert) {
    auto cert_hash = SHA256(cert);
    return cert_hash == PINNED_CERT_HASH;
}
```

**Verification:**
- Testing: Install root CA, try MITM, verify connection rejected
- Certificate rotation: Update pin when cert expires

**Violation Impact:** HIGH - MITM attacks

---

## Detection Invariants

### INV-DETECT-001: No Single Detector May Cause a Ban

**Requirement:** Ban action requires 3+ correlated detectors OR Critical confidence + repeat offense

**Rationale:** Prevent false positive bans

**Enforcement:**
```cpp
bool ShouldBan(const std::vector<ViolationEvent>& events) {
    // Count unique detector types
    std::set<ViolationType> types;
    for (const auto& ev : events) {
        types.insert(ev.type);
    }
    
    // Require correlation
    if (types.size() < 3) {
        return false;  // Single detector, no ban
    }
    
    return true;
}
```

**Verification:**
- Testing: Trigger single detector, verify no ban
- Telemetry: Monitor ban decisions, ensure correlation

**Violation Impact:** HIGH - False positive bans

---

### INV-DETECT-002: Honeypot Exception

**Requirement:** Honeypot modification is ALWAYS Critical severity and may trigger immediate ban

**Rationale:** Honeypots are never called legitimately, 100% cheat indicator

**Enforcement:**
```cpp
if (honeypot_modified) {
    // Immediate critical, bypass correlation requirement
    return ErrorCode::TamperingDetected;
}
```

**Verification:**
- Testing: Modify honeypot, verify immediate Critical event
- False positive check: Ensure honeypot never called in normal operation

**Violation Impact:** CRITICAL if violated - False bans

---

### INV-DETECT-003: Detection Shall Not Impair Performance

**Requirement:** Per-frame overhead MUST NOT exceed 0.1ms on reference hardware

**Rationale:** Anti-cheat must not impact gameplay

**Enforcement:**
```cpp
// Budget enforcement
if (GetCurrentTimeMs() - scan_start_time_ > SCAN_BUDGET_MS) {
    break;  // Abort scan, resume next frame
}
```

**Verification:**
- Profiling: Measure Update() time on low-end hardware
- Frame time monitoring: Ensure no frame drops

**Violation Impact:** HIGH - Unplayable game

---

## Resource Management Invariants

### INV-RES-001: All Resources Must Have Cleanup

**Requirement:** Every allocated resource MUST have a corresponding cleanup path

**Rationale:** Prevent leaks, resource exhaustion

**Enforcement:**
- RAII: Use smart pointers, containers
- Shutdown: `Shutdown()` cleans all resources

```cpp
void Shutdown() {
    // Clean all resources
    registered_functions_.clear();
    registered_regions_.clear();
    // ...
}
```

**Verification:**
- Leak detection: Run under Valgrind, Dr. Memory
- Stress testing: Repeated init/shutdown, check for leaks

**Violation Impact:** MEDIUM - Resource leaks

---

### INV-RES-002: Handles Must Be Validated Before Use

**Requirement:** All handles (memory regions, functions, values) MUST be validated before dereferencing

**Rationale:** Invalid handles cause crashes

**Enforcement:**
```cpp
bool VerifyMemory(uint64_t handle) {
    if (handle >= registered_regions_.size()) {
        return false;  // Invalid handle
    }
    return true;
}
```

**Verification:**
- Testing: Pass invalid handles, verify graceful error
- Fuzzing: Random handle values, no crashes

**Violation Impact:** HIGH - Crashes

---

## Initialization Invariants

### INV-INIT-001: Initialization Must Be Idempotent

**Requirement:** If `Initialize()` fails, calling it again with same config MUST work

**Rationale:** Allow retry after transient failures

**Enforcement:**
```cpp
ErrorCode Initialize(const Configuration* config) {
    // Clean any partial state from previous failed attempt
    Shutdown();
    
    // Attempt initialization
    if (!InitSubsystemA()) {
        Shutdown();  // Clean up
        return ErrorCode::InitializationFailed;
    }
    // ...
}
```

**Verification:**
- Testing: Simulate init failure (e.g., no network), retry, verify success

**Violation Impact:** MEDIUM - Unusable SDK after transient failures

---

### INV-INIT-002: Partial Initialization Forbidden

**Requirement:** If any subsystem fails to initialize, ALL must be cleaned up (atomic init)

**Rationale:** Prevent inconsistent state

**Enforcement:**
```cpp
ErrorCode Initialize(const Configuration* config) {
    if (!InitA()) { Shutdown(); return Error; }
    if (!InitB()) { Shutdown(); return Error; }  // Clean ALL, not just B
    if (!InitC()) { Shutdown(); return Error; }
    return Success;
}
```

**Verification:**
- Testing: Fail each subsystem, verify full cleanup
- State inspection: Check no subsystem left initialized after partial failure

**Violation Impact:** HIGH - Undefined behavior from partial init

---

## Summary: Invariant Enforcement Checklist

### Required for All Invariants

- [ ] Documented in code comments
- [ ] Enforced by runtime checks (asserts, error returns)
- [ ] Verified by unit tests
- [ ] Monitored by telemetry (if applicable)
- [ ] Reviewed in security audits

### Critical Invariants (Zero Tolerance)

Must have ALL of:
- [ ] Static assertions where possible
- [ ] Runtime assertions in debug builds
- [ ] Error returns in release builds (never crash)
- [ ] Automated testing
- [ ] Manual security review

**Examples:** Crypto invariants, memory safety invariants

### High Priority Invariants

Must have:
- [ ] Runtime checks
- [ ] Unit test coverage
- [ ] Documentation

**Examples:** State management, network security

### Medium Priority Invariants

Must have:
- [ ] Documentation
- [ ] Basic testing

**Examples:** Resource management, initialization

---

## Violation Response

### Development/Testing

- **Assert Failure:** Break into debugger
- **Unit Test:** Fail test immediately
- **Log:** Error-level logging

### Production

- **Critical Invariant:** Log error + telemetry + graceful failure (never crash)
- **High Invariant:** Log warning + telemetry + degrade functionality
- **Medium Invariant:** Log info + continue

**Example:**
```cpp
if (!ValidateInvariant()) {
    #ifdef _DEBUG
        assert(false && "Invariant violated");
    #else
        LogError("Critical invariant violated");
        ReportTelemetry("invariant_violation", details);
        return ErrorCode::InternalError;  // Fail gracefully
    #endif
}
```

---

## Conclusion

**Invariants are not guidelines—they are LAWS.**

Violating an invariant means either:
1. A bug that MUST be fixed immediately, OR
2. An active attack that MUST be reported

**All invariants MUST:**
- Be documented
- Be tested
- Be enforced at runtime
- Be reviewed in security audits

**When in doubt:**
- Add an invariant (better too strict than too loose)
- Assert it in code
- Test it in unit tests
- Monitor it in production

**Security is built on invariants. Break an invariant, break security.**
