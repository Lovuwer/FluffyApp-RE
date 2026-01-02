# Sentinel Anti-Cheat SDK: Task Execution Pack

**Document Type:** Agent-Assignable Task Definitions  
**Classification:** Engineering Operations  
**Prepared For:** GitHub Issues / Copilot Workflows / Sprint Planning  
**Date:** 2025-12-31  
**Source:** Production Execution Plan (2025-12-31)

> **IMPORTANT:** This document operationalizes the Production Execution Plan into 40+ execution-ready tasks.  
> Each task can be independently assigned to agents, converted to GitHub Issues, or used for sprint planning.

---

## TABLE OF CONTENTS

1. [Section A: Repository Confirmation](#section-a--repository-confirmation)
2. [Section B: Agent Task Definitions](#section-b--agent-task-definitions)
   - [Phase 1: Hardening & Correctness (14 tasks)](#phase-1-hardening--correctness)
   - [Phase 2: Architectural Diversification (11 tasks)](#phase-2-architectural-diversification)
   - [Phase 3: Runtime Variability (10 tasks)](#phase-3-runtime-variability)
   - [Phase 4: Telemetry & Server-Side Adjudication (10 tasks)](#phase-4-telemetry--server-side-adjudication)
3. [Section C: Parallel Execution Map](#section-c--parallel-execution-map)
4. [Section D: Risk & Validation Flags](#section-d--risk--validation-flags)

---

## SECTION A — REPOSITORY CONFIRMATION

### Assumed Repository Structure

Based on analysis of the Sentiel-RE repository at `/home/runner/work/Sentiel-RE/Sentiel-RE`:

```
Sentiel-RE/
├── .github/workflows/build.yml           ✅ CONFIRMED
├── docs/
│   ├── architecture/ARCHITECTURE.md      ✅ CONFIRMED
│   ├── SECURITY_INVARIANTS.md            ✅ CONFIRMED
│   ├── DEFENSIVE_GAPS.md                 ✅ CONFIRMED
│   ├── INTEGRATION_GUIDE.md              ✅ CONFIRMED
│   ├── api/                              ⚠️  CREATE (P2-A3)
│   ├── protocols/                        ⚠️  CREATE (P2-C4)
│   ├── research/                         ⚠️  CREATE (P3-B1, P3-B2)
│   ├── integration/                      ⚠️  CREATE (Phase 4)
│   ├── operations/                       ⚠️  CREATE (Phase 4)
│   └── performance/                      ⚠️  CREATE (P1-A1)
├── src/
│   ├── Core/
│   │   ├── Crypto/                       ✅ CONFIRMED (Hash, HMAC modules exist)
│   │   ├── Memory/                       ✅ CONFIRMED
│   │   ├── Network/                      ✅ CONFIRMED
│   │   └── Utils/                        ✅ CONFIRMED
│   ├── SDK/src/
│   │   ├── Detection/
│   │   │   ├── AntiDebug.cpp             ✅ CONFIRMED
│   │   │   ├── AntiHook.cpp              ✅ CONFIRMED
│   │   │   ├── IntegrityCheck.cpp        ✅ CONFIRMED
│   │   │   ├── InjectionDetect.cpp       ✅ CONFIRMED
│   │   │   ├── SpeedHack.cpp             ✅ CONFIRMED
│   │   │   └── EnvironmentDetection.cpp  ✅ CONFIRMED
│   │   ├── Internal/
│   │   │   ├── CorrelationEngine.*       ✅ CONFIRMED
│   │   │   ├── TelemetryEmitter.*        ✅ CONFIRMED
│   │   │   ├── SafeMemory.*              ✅ CONFIRMED
│   │   │   ├── ProtectedValue.hpp        ✅ CONFIRMED
│   │   │   ├── RuntimeConfig.*           ✅ CONFIRMED
│   │   │   ├── PointerGuard.hpp          ⚠️  CREATE (P2-B2)
│   │   │   └── ViolationAggregator.*     ⚠️  CREATE (P2-C2)
│   │   ├── Network/                      ✅ EXISTS (directory)
│   │   │   ├── Heartbeat.*               ⚠️  CREATE (P1-B1)
│   │   │   ├── CertPinning.*             ⚠️  CREATE (P1-B2)
│   │   │   ├── Attestation.*             ⚠️  CREATE (P3-C1)
│   │   │   └── RemoteConfig.*            ⚠️  CREATE (P3-C2)
│   │   ├── Telemetry/                    ⚠️  CREATE DIRECTORY
│   │   │   ├── FPTracker.*               ⚠️  CREATE (P1-C3)
│   │   │   ├── BehaviorMetrics.*         ⚠️  CREATE (P3-C3, P4-B2)
│   │   │   └── HWID.*                    ⚠️  CREATE (P4-B3)
│   │   └── SentinelSDK.cpp               ✅ CONFIRMED (🔴 HIGH-RISK SHARED FILE)
├── include/Sentinel/                     ✅ EXISTS
│   └── SentinelMacros.hpp                ⚠️  CREATE (P2-C3)
├── examples/DummyGame/                   ✅ CONFIRMED
├── tests/
│   ├── SDK/                              ✅ EXISTS
│   │   └── simulation/                   ⚠️  CREATE (P1-C4)
│   ├── Core/                             ✅ EXISTS
│   └── TestHarness.*                     ✅ CONFIRMED
├── scripts/                              ⚠️  CREATE DIRECTORY (P1-A1)
└── CMakeLists.txt                        ✅ CONFIRMED (🔴 HIGH-RISK SHARED FILE)
```

### Validation Notes

#### ✅ Confirmed Elements (Exist in Repository)
- Complete Core infrastructure: Crypto (HMAC, Hash, SecureRandom), Memory, Network, Utils
- All 6 Detection modules: AntiDebug, AntiHook, IntegrityCheck, InjectionDetect, SpeedHack, EnvironmentDetection
- Internal correlation engine and telemetry emitter
- DummyGame test application
- Test infrastructure with TestHarness
- GitHub Actions CI/CD (build.yml)
- Comprehensive security documentation (SECURITY_INVARIANTS.md, DEFENSIVE_GAPS.md)
- Architecture documentation

#### ⚠️  Assumptions Requiring Confirmation

**New Directories Required:**
- `docs/api/` — P2-A3 will create
- `docs/protocols/` — P2-C4 will create
- `docs/research/` — P3-B1, P3-B2 will create
- `docs/integration/` — Phase 4 deliverables
- `docs/operations/` — Phase 4 deliverables  
- `docs/performance/` — P1-A1 will create
- `src/SDK/src/Telemetry/` — P1-C3 will create
- `tests/SDK/simulation/` — P1-C4 will create
- `scripts/` — P1-A1 will create

**New Files Required (Validated Paths):**
- All paths follow established repository conventions
- Module boundaries respected
- No conflicts with existing structure

**Backend Service Tasks:** P4-A*, P4-C*, P4-D2 are OUT OF SCOPE for Sentiel-RE repository.  
These tasks belong in a separate backend service repository. Only client-side tasks (P4-B*, P4-D1) apply to Sentiel-RE.

#### 🔴 High-Risk Shared Files

Files that MULTIPLE tasks will modify — require careful coordination:

| File | Tasks | Risk Level | Mitigation |
|------|-------|------------|------------|
| `src/SDK/src/SentinelSDK.cpp` | P1-A2, P1-A4, P1-B1, P2-B3, P3-A3 | 🔴 HIGH | Use feature flags, modular functions |
| `src/SDK/src/Detection/IntegrityCheck.cpp` | P1-A3, P2-A4, P2-C1 | 🔴 HIGH | Coordinate P1-A3 → P2-A4 → P2-C1 |
| `src/SDK/src/Detection/AntiDebug.cpp` | P3-A1 | 🟡 MEDIUM | Single major refactor in P3 |
| `src/SDK/src/Detection/AntiHook.cpp` | P3-A2 | 🟡 MEDIUM | Single major refactor in P3 |
| **All** `Detection/*.cpp` | P2-A1 | 🔴 CRITICAL | Phase gate: P2-A1 blocks other Phase 2 tasks |
| `CMakeLists.txt` | P1-A1, P1-A3, P1-C2, P3-B3 | 🟡 MEDIUM | Separate sections per task |
| `.github/workflows/build.yml` | P1-C2 | 🟢 LOW | Additive changes only |

**Coordination Strategy:**
1. **P2-A1** is a phase gate — must complete before other Phase 2 detection tasks
2. **SentinelSDK.cpp** changes must use feature flags and separate functions
3. **CMakeLists.txt** changes must use separate sections/options
4. Tasks touching shared files should merge frequently to minimize divergence

#### Path Validation Status
- ✅ All existing file references verified against repository
- ✅ New file paths validated for consistency with existing conventions
- ✅ Module boundaries respected
- ✅ No naming conflicts identified
- ⚠️  Backend tasks excluded (not applicable to client SDK repository)

---

## SECTION B — AGENT TASK DEFINITIONS


### PHASE 1: Hardening & Correctness

**Timeline:** Q1 2026 (12 weeks)  
**Primary Objective:** Establish stable, performant, low-false-positive baseline with operational telemetry infrastructure.

**Exit Criteria Summary:**
- [ ] DummyGame test suite: zero false positives
- [ ] Update() P95 latency < 0.1ms
- [ ] FullScan() P95 latency < 5ms
- [ ] All SECURITY_INVARIANTS.md invariants enforced
- [ ] Telemetry heartbeat operational
- [ ] Certificate pinning and request signing implemented
- [ ] 90%+ code coverage on security-critical paths

---

#### 🧩 Task ID: **P1-A1**
**Title:** Profile Update() Bottlenecks

##### 🎯 Goal
Establish performance baseline for Update() method, identify optimization targets, ensure sub-0.1ms P95 latency is achievable.

##### 📍 Scope
**Included:**
- Instrument SentinelSDK::Update() with profiling hooks
- Measure per-detector execution time
- Document P50/P95/P99 latencies on reference hardware
- Identify top 3 bottlenecks
- Generate profiling report with recommendations

**Excluded:**
- Implementing optimizations (separate tasks: P1-A2, P1-A3, P1-A4)
- FullScan() profiling (different performance budget)
- Cross-platform profiling (Linux baseline only)

##### 📂 Files / Modules
- `src/SDK/src/SentinelSDK.cpp`
- `src/SDK/src/Detection/*.cpp` (all detectors)
- `CMakeLists.txt` (add SENTINEL_ENABLE_PROFILING option)
- **NEW:** `docs/performance/update_baseline_profile.md`
- **NEW:** `scripts/profile_update.sh`

##### 🔧 Work Instructions
1. Add `SENTINEL_ENABLE_PROFILING` CMake option (default: OFF)
2. Implement lightweight timer instrumentation:
   ```cpp
   auto start = std::chrono::high_resolution_clock::now();
   // detector call
   auto end = std::chrono::high_resolution_clock::now();
   LogTiming("DetectorName", end - start);
   ```
3. Run DummyGame with profiling enabled, collect 10,000 Update() samples
4. Calculate P50/P95/P99 for overall Update() and each detector
5. Identify detectors exceeding 0.01ms average
6. Document findings in `docs/performance/update_baseline_profile.md`
7. Create `scripts/profile_update.sh` automation script

##### 📦 Required Outputs
- [ ] CMake profiling option
- [ ] Timer instrumentation in SentinelSDK.cpp
- [ ] Profiling automation script
- [ ] Performance report containing:
  - Hardware specs (CPU, RAM, OS)
  - Test methodology
  - Latency measurements (P50/P95/P99)
  - Per-detector breakdown
  - Top 3 bottlenecks identified
  - Recommendations for P1-A2, P1-A3, P1-A4

##### ✅ Definition of Done (DoD)
- [ ] Profiling enabled via CMake flag
- [ ] 10,000+ Update() samples collected
- [ ] All detectors individually timed
- [ ] Top 3 bottlenecks identified with μs precision
- [ ] Profiling overhead < 5% when enabled
- [ ] Zero performance regression when disabled (default)
- [ ] Report exists and is actionable

##### 🔗 Dependencies
**Blocking:** None  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-B1, P1-B2, P1-C1, P1-C2, P1-D1, P1-D2  
**Merge risk:** 🟢 LOW — Additive instrumentation only  
**Coordination:** Results inform priorities for P1-A2, P1-A3, P1-A4

##### 🚫 Non-Goals
- Do NOT implement optimizations
- Do NOT change detection logic
- Do NOT add permanent runtime overhead
- Do NOT profile other platforms yet

---

#### 🧩 Task ID: **P1-A2**
**Title:** Implement Scan Budget Enforcement

##### 🎯 Goal
Prevent FullScan() from exceeding time budget, ensuring predictable performance under all conditions.

##### 📍 Scope
**Included:**
- Time-boxed loops in all scan operations
- Early exit when budget exceeded
- Scan state persistence for resumption
- Budget configuration via RuntimeConfig
- Telemetry logging for budget exhaustion

**Excluded:**
- Optimizing scan algorithms (separate concern)
- Changing what is scanned
- Inter-frame scan scheduling (deferred to later phase)

##### 📂 Files / Modules
- `src/SDK/src/Detection/IntegrityCheck.cpp`
- `src/SDK/src/Detection/InjectionDetect.cpp`
- `src/SDK/src/Detection/AntiHook.cpp`
- `src/SDK/src/Internal/RuntimeConfig.cpp/.hpp`
- `include/Sentinel/SentinelSDK.hpp` (if API changes)

##### 🔧 Work Instructions
1. Add `max_scan_duration_ms` to RuntimeConfig (default: 5ms)
2. Create deadline checker utility:
   ```cpp
   class ScopedTimer {
       std::chrono::time_point<...> deadline_;
       bool Expired() const;
   };
   ```
3. Wrap scan loops:
   ```cpp
   ScopedTimer timer(config.max_scan_duration_ms);
   while (!timer.Expired() && HasMoreWork()) {
       // scan logic
   }
   ```
4. Persist scan cursor for resumption on next call
5. Emit telemetry event when budget exhausted
6. Test with low budgets (0.5ms) to verify early exit works
7. Ensure no false positives from partial scans

##### 📦 Required Outputs
- [ ] RuntimeConfig field for scan budget
- [ ] Deadline checker utility (ScopedTimer or equivalent)
- [ ] Time-boxed loops in all scan functions
- [ ] Scan state persistence
- [ ] Telemetry event for budget exhaustion
- [ ] Unit tests for budget enforcement (0.5ms, 5ms, 50ms)
- [ ] Integration test with DummyGame

##### ✅ Definition of Done (DoD)
- [ ] FullScan() never exceeds configured budget
- [ ] Scans resume correctly if interrupted
- [ ] Budget exhaustion logged to telemetry
- [ ] Zero false positives when scans interrupted
- [ ] Tests pass at 0.5ms, 5ms, 50ms budgets
- [ ] Performance impact < 1% when budget not hit
- [ ] RuntimeConfig documentation updated

##### 🔗 Dependencies
**Blocking:** P1-A1 (need baseline to validate budget targets)  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-B1, P1-B2, P1-C1, P1-D1, P1-D2  
**Merge risk:** 🟡 MEDIUM — Touches multiple detection files  
**Coordination:** Coordinate timing with P2-A1 (detection refactor)

##### 🚫 Non-Goals
- Do NOT optimize scan algorithms themselves
- Do NOT implement adaptive budgets
- Do NOT add inter-frame scheduling
- Do NOT change detection logic beyond early exit

---

#### 🧩 Task ID: **P1-A3**
**Title:** Optimize Hash Computation

##### 🎯 Goal
Accelerate integrity hash computation using SIMD if beneficial (≥2x speedup), reducing FullScan() latency.

##### 📍 Scope
**Included:**
- Evaluate SIMD-accelerated SHA-256 libraries
- Benchmark current vs. SIMD implementations
- Integrate if speedup ≥ 2x
- Maintain cryptographic correctness

**Excluded:**
- Switching hash algorithms (must remain SHA-256)
- Changing what is hashed
- GPU acceleration

##### 📂 Files / Modules
- `src/Core/Crypto/Hash.cpp/.hpp` (validate exists)
- `src/SDK/src/Detection/IntegrityCheck.cpp`
- `CMakeLists.txt` (potential new dependency)
- **NEW:** `tests/Core/HashPerformance.cpp`

##### 🔧 Work Instructions
1. Profile current SHA-256 throughput (MB/s)
2. Evaluate SIMD options:
   - Intel SHA Extensions (SHA-NI)
   - Portable SIMD (e.g., simde library)
3. Benchmark with 1MB, 10MB, 100MB inputs on reference hardware
4. **If** SIMD achieves ≥2x speedup:
   - Integrate with runtime CPU detection
   - Implement fallback to scalar for unsupported CPUs
   - Verify hash outputs match test vectors (NIST, etc.)
   - Add performance regression test
5. **Else:** Document why rejected, suggest alternatives
6. Create decision document

##### 📦 Required Outputs
**Always:**
- [ ] Current hash performance baseline (MB/s)
- [ ] SIMD library evaluation report
- [ ] Decision document with justification

**If SIMD integrated:**
- [ ] SIMD-accelerated SHA-256 implementation
- [ ] Runtime CPU feature detection (CPUID)
- [ ] Scalar fallback for old CPUs
- [ ] Test vectors verification (all match)
- [ ] Performance regression test in CI

**If SIMD rejected:**
- [ ] Document why speedup insufficient
- [ ] Alternative optimization suggestions

##### ✅ Definition of Done (DoD)
- [ ] Baseline documented
- [ ] SIMD evaluation complete with data
- [ ] Decision made with clear justification
- **If integrated:**
  - [ ] Hash correctness verified (test vectors)
  - [ ] Speedup ≥2x demonstrated
  - [ ] Works on CPUs with/without SIMD
  - [ ] CI regression test added
- [ ] No security degradation

##### 🔗 Dependencies
**Blocking:** P1-A1 (need baseline)  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-A2, P1-B1, P1-B2, P1-C2, P1-D2  
**Merge risk:** 🟢 LOW  
**Coordination:** Check license compatibility if adding dependency

##### 🚫 Non-Goals
- Do NOT change hash algorithm
- Do NOT implement GPU hashing
- Do NOT integrate if speedup < 2x
- Do NOT sacrifice correctness for speed

---

#### 🧩 Task ID: **P1-A4**
**Title:** Lazy Detector Initialization

##### 🎯 Goal
Reduce SDK initialization time by deferring detector construction until first use.

##### 📍 Scope
**Included:**
- Convert detector initialization to lazy pattern
- Thread-safe lazy init (std::call_once)
- Measure startup time improvement
- Ensure first Update() initializes all detectors

**Excluded:**
- Lazy config loading
- Dynamic detector enable/disable
- Detector unloading

##### 📂 Files / Modules
- `src/SDK/src/SentinelSDK.cpp`
- `src/SDK/src/Internal/Detection.hpp`
- All `src/SDK/src/Detection/*.cpp` detector classes

##### 🔧 Work Instructions
1. Measure current SDK initialization time (baseline)
2. Refactor each detector for lazy init:
   ```cpp
   class Detector {
       std::once_flag init_flag_;
       void EnsureInitialized() {
           std::call_once(init_flag_, [this]() { Initialize(); });
       }
       void Initialize() { /* heavy work here */ }
   public:
       void Check() {
           EnsureInitialized();
           // detection logic
       }
   };
   ```
3. Move heavy init (signature loading, etc.) to Initialize()
4. Call EnsureInitialized() at start of each Check() method
5. Measure new init time and first Update() time
6. Test thread safety with concurrent Update() calls

##### 📦 Required Outputs
- [ ] Lazy initialization in all detectors
- [ ] Thread-safe init using std::call_once
- [ ] Before/after startup time measurements
- [ ] First Update() latency measurement
- [ ] Thread safety test (concurrent calls)
- [ ] Documentation in Detection.hpp

##### ✅ Definition of Done (DoD)
- [ ] SDK init time reduced ≥50%
- [ ] First Update() completes within acceptable latency (< 10ms)
- [ ] All detectors work identically to eager init
- [ ] Thread-safe init verified (no races)
- [ ] Performance tests pass
- [ ] Documentation updated

##### 🔗 Dependencies
**Blocking:** None  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-A1, P1-B1, P1-B2, P1-C1, P1-D1  
**Merge risk:** 🟡 MEDIUM — Changes initialization pattern  
**Coordination:** Coordinate with P1-D1 for invariant assertions during init

##### 🚫 Non-Goals
- Do NOT implement detector unloading
- Do NOT add dynamic enable/disable
- Do NOT defer config loading
- Do NOT introduce lazy initialization races

---

#### 🧩 Task ID: **P1-B1**
**Title:** Implement Heartbeat Client

##### 🎯 Goal
Create network client for periodic server check-in, establishing telemetry infrastructure foundation.

##### 📍 Scope
**Included:**
- HTTP/HTTPS client for heartbeat
- Configurable interval (default: 60s)
- Retry logic with exponential backoff
- Timeout handling
- Basic error reporting

**Excluded:**
- Certificate pinning (P1-B2)
- Request signing (P1-B3)
- Replay protection (P1-B4)
- Server implementation

##### 📂 Files / Modules
- **NEW:** `src/SDK/src/Network/Heartbeat.cpp/.hpp`
- `src/Core/Network/` (validate HTTP client exists)
- `src/SDK/src/Internal/RuntimeConfig.cpp/.hpp` (add config)
- `CMakeLists.txt` (link network deps)

##### 🔧 Work Instructions
1. Create Heartbeat class:
   ```cpp
   class Heartbeat {
   public:
       Heartbeat(const std::string& server_url, int interval_sec);
       bool SendHeartbeat();  // returns success/failure
   };
   ```
2. Implement exponential backoff:
   - Initial retry: 1s
   - Max retry: 60s
   - Max attempts: 5
3. Heartbeat payload (JSON):
   ```json
   {
     "sdk_version": "1.0.0",
     "license_id_hash": "<sha256>",
     "session_id": "<uuid>",
     "timestamp": "2025-12-31T09:00:00Z"
   }
   ```
4. Add HeartbeatConfig to RuntimeConfig
5. Integrate into SentinelSDK::Update() (call every N updates)
6. Create mock server endpoint for testing
7. Test failure scenarios: timeout, 404, 500, network down

##### 📦 Required Outputs
- [ ] Heartbeat.cpp/.hpp with SendHeartbeat()
- [ ] Exponential backoff retry logic
- [ ] RuntimeConfig integration
- [ ] SDK Update() integration
- [ ] Mock server endpoint (can be Python script)
- [ ] Unit tests for retry logic
- [ ] Integration test with DummyGame

##### ✅ Definition of Done (DoD)
- [ ] Heartbeat successfully sent to mock server
- [ ] Retry logic verified with failing server
- [ ] No crashes on network failure
- [ ] Heartbeat interval configurable
- [ ] No game thread blocking (< 1ms when successful)
- [ ] Errors logged not thrown
- [ ] Tests cover happy path and all failure modes

##### 🔗 Dependencies
**Blocking:** None  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-A1, P1-A2, P1-A3, P1-C1, P1-C2, P1-D1, P1-D2  
**Merge risk:** 🟢 LOW  
**Coordination:** P1-B2, P1-B3, P1-B4 will extend this

##### 🚫 Non-Goals
- Do NOT implement cert pinning (P1-B2)
- Do NOT implement signing (P1-B3)
- Do NOT implement replay protection (P1-B4)
- Do NOT block game thread
- Do NOT implement server

---

#### 🧩 Task ID: **P1-B2**
**Title:** Certificate Pinning

##### 🎯 Goal
Prevent MITM attacks via TLS certificate pinning.

##### 📍 Scope
**Included:**
- Hardcoded SHA-256 of expected server certificate
- Certificate validation in TLS handshake
- Pinning failure detection
- Support multiple pinned hashes (certificate rotation)

**Excluded:**
- Certificate auto-update mechanism
- Public key pinning (use cert pinning)
- OCSP stapling

##### 📂 Files / Modules
- **NEW:** `src/SDK/src/Network/CertPinning.cpp/.hpp`
- `src/SDK/src/Network/Heartbeat.cpp` (integrate)
- `src/Core/Network/` (TLS layer)
- `src/Core/Crypto/Hash.cpp/.hpp` (SHA-256)

##### 🔧 Work Instructions
1. Create CertPinning class:
   ```cpp
   class CertPinning {
       std::vector<std::array<uint8_t, 32>> pinned_hashes_;
   public:
       void AddPinnedCert(const std::array<uint8_t, 32>& sha256);
       bool ValidateCertificate(const X509* cert);
   };
   ```
2. Implement TLS callback to extract server cert
3. Compute SHA-256 of DER-encoded certificate
4. Compare against pinned hashes
5. Fail connection if no match
6. Support multiple hashes (primary + secondary for rotation)
7. Emit telemetry event on failure
8. Test: correct cert, self-signed, expired, wrong cert

##### 📦 Required Outputs
- [ ] CertPinning.cpp/.hpp
- [ ] Certificate validation integrated into network layer
- [ ] Multiple pinned cert support
- [ ] Pinning failure telemetry event
- [ ] Tests: valid cert (pass), invalid certs (fail)
- [ ] Certificate rotation procedure documented

##### ✅ Definition of Done (DoD)
- [ ] Connections succeed with correct certificate
- [ ] Connections fail with wrong certificate
- [ ] Pinning failure logged
- [ ] Multiple hashes supported
- [ ] No performance impact on successful connections
- [ ] All test scenarios pass
- [ ] Rotation procedure documented

##### 🔗 Dependencies
**Blocking:** P1-B1 (heartbeat must exist)  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-A1, P1-A2, P1-A3, P1-C1, P1-D1, P1-D2  
**Merge risk:** 🟢 LOW  
**Coordination:** Extends P1-B1

##### 🚫 Non-Goals
- Do NOT auto-update certificates
- Do NOT implement OCSP
- Do NOT pin public keys
- Do NOT hardcode certs in public code

---

#### 🧩 Task ID: **P1-B3**
**Title:** Request Signing (HMAC)

##### 🎯 Goal
Cryptographically sign all outbound requests to prevent forgery.

##### 📍 Scope
**Included:**
- HMAC-SHA256 signing of request body
- License-derived HMAC key
- Signature in HTTP header
- Server-side verification design documentation

**Excluded:**
- Server-side verification implementation
- Key rotation mechanism
- Per-session key derivation (use license key)

##### 📂 Files / Modules
- `src/Core/Crypto/HMAC.cpp/.hpp` (validate or create)
- `src/SDK/src/Network/Heartbeat.cpp`
- All future network request code

##### 🔧 Work Instructions
1. Verify or implement HMAC-SHA256:
   ```cpp
   std::vector<uint8_t> HMAC_SHA256(
       const uint8_t* key, size_t key_len,
       const uint8_t* data, size_t data_len);
   ```
2. Derive HMAC key from license:
   ```cpp
   hmac_key = SHA256(license_id + salt)
   ```
3. For each request:
   - Serialize request body
   - Compute: `signature = HMAC-SHA256(hmac_key, body)`
   - Add header: `X-Sentinel-Signature: <hex(signature)>`
4. Integrate into Heartbeat
5. Document signature format for server
6. Test signature verification independently

##### 📦 Required Outputs
- [ ] HMAC-SHA256 implementation (or validated)
- [ ] Key derivation from license
- [ ] Request signing in network layer
- [ ] Signature in HTTP header
- [ ] Server signature format documentation
- [ ] Unit tests with test vectors
- [ ] Integration test verifying signature presence

##### ✅ Definition of Done (DoD)
- [ ] All requests include valid HMAC signature
- [ ] Signature matches test vectors
- [ ] Key never logged or exposed
- [ ] Signature format documented for server
- [ ] Tests verify correctness
- [ ] Performance overhead < 0.1ms

##### 🔗 Dependencies
**Blocking:** P1-B1 (heartbeat client)  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-C1, P1-C2, P1-D1, P1-D2  
**Merge risk:** 🟢 LOW  
**Coordination:** Extends P1-B1, coordinates with P1-B4

##### 🚫 Non-Goals
- Do NOT implement server-side verification
- Do NOT implement key rotation
- Do NOT use per-session keys yet
- Do NOT include signature in body

---

#### 🧩 Task ID: **P1-B4**
**Title:** Replay Protection

##### 🎯 Goal
Prevent replay attacks via nonce and timestamp validation.

##### 📍 Scope
**Included:**
- Random nonce (16 bytes) per request
- Timestamp per request
- Document server-side validation requirements
- Cryptographic RNG for nonce

**Excluded:**
- Server-side nonce tracking
- Clock skew handling (server responsibility)
- Nonce cache limits (server responsibility)

##### 📂 Files / Modules
- `src/SDK/src/Network/Heartbeat.cpp`
- `src/Core/Crypto/SecureRandom.cpp/.hpp` (validate RNG)
- All network request code

##### 🔧 Work Instructions
1. Generate per-request:
   - Nonce: 16 cryptographically random bytes
   - Timestamp: UTC ISO 8601
2. Include in request:
   ```json
   {
     "nonce": "<hex>",
     "timestamp": "2025-12-31T09:00:00Z",
     "payload": { ... }
   }
   ```
3. Update HMAC to cover nonce + timestamp + payload
4. Document server validation:
   - Timestamp within ±5 minutes
   - Nonce never seen before (server cache)
5. Test nonce uniqueness (10,000 requests)

##### 📦 Required Outputs
- [ ] Nonce generation (secure RNG)
- [ ] Timestamp in ISO 8601
- [ ] Nonce + timestamp in all requests
- [ ] Updated HMAC covering nonce/timestamp/payload
- [ ] Server validation requirements documented
- [ ] Nonce uniqueness test (10K requests)
- [ ] Timestamp format test

##### ✅ Definition of Done (DoD)
- [ ] All requests include nonce + timestamp
- [ ] Nonces cryptographically random (no collisions in 10K)
- [ ] Timestamps accurate to 1 second
- [ ] HMAC covers nonce + timestamp + payload
- [ ] Server validation documented
- [ ] Tests pass

##### 🔗 Dependencies
**Blocking:** P1-B3 (signing must exist)  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-C1, P1-C2, P1-D1, P1-D2  
**Merge risk:** 🟢 LOW  
**Coordination:** Extends P1-B3

##### 🚫 Non-Goals
- Do NOT implement server nonce cache
- Do NOT handle clock skew on client
- Do NOT implement nonce expiration
- Do NOT persist nonces

---

#### 🧩 Task ID: **P1-C1**
**Title:** Expand DummyGame Test Scenarios

##### 🎯 Goal
Increase test coverage with edge-case scenarios that commonly trigger false positives.

##### 📍 Scope
**Included:**
- VM environment simulation
- Pause/resume simulation
- High CPU load simulation
- Debugger attachment (intentional, not bypass)
- Rapid init/shutdown cycles

**Excluded:**
- Actual VM testing (requires VM infrastructure - see P1-C2)
- Network failure scenarios (covered in network tasks)
- Bypass testing (P1-C4)

##### 📂 Files / Modules
- `examples/DummyGame/` (all files)
- **NEW:** `examples/DummyGame/scenarios/`
- `examples/DummyGame/README.md`

##### 🔧 Work Instructions
1. Create test scenarios:
   - **VM Simulation**: Set VM-like env vars, fake CPUID
   - **Pause/Resume**: Sleep 30s, then resume
   - **High CPU**: Saturate CPU with spin threads
   - **Debugger**: Attach debugger, verify detection
   - **Rapid Cycle**: Init→Shutdown 100 times
2. Add CLI flags:
   ```
   --scenario=vm
   --scenario=pause-resume
   --scenario=high-cpu
   --scenario=debugger
   --scenario=rapid-cycle
   ```
3. Run each, collect results
4. Document expected behavior
5. Add to CI if feasible

##### 📦 Required Outputs
- [ ] 5 test scenarios implemented
- [ ] CLI for scenario selection
- [ ] All scenarios run without crashes
- [ ] Expected behavior documented
- [ ] Test results for each scenario
- [ ] CI integration (if feasible)

##### ✅ Definition of Done (DoD)
- [ ] All 5 scenarios implemented
- [ ] Zero false positives in legitimate scenarios
- [ ] Expected violations detected (e.g., debugger)
- [ ] No crashes or hangs
- [ ] Documentation updated
- [ ] CI runs ≥3 scenarios (VM may need separate infra)

##### 🔗 Dependencies
**Blocking:** None  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-A1, P1-A2, P1-B1, P1-B2, P1-D1, P1-D2  
**Merge risk:** 🟢 LOW  
**Coordination:** Provides test infra for other tasks

##### 🚫 Non-Goals
- Do NOT implement bypasses
- Do NOT require actual VM (simulate only)
- Do NOT test network failures
- Do NOT test server logic

---

#### 🧩 Task ID: **P1-C2**
**Title:** VM Test Environment in CI

##### 🎯 Goal
Establish CI with VM runner to detect false positives in virtualized environments.

##### 📍 Scope
**Included:**
- Configure GitHub Actions with nested virtualization
- Run DummyGame in VM
- Collect false positive metrics
- Optional CI step (not every commit)

**Excluded:**
- Container testing (not true VM)
- MacOS/Windows VMs (Linux only)
- Performance testing in VM

##### 📂 Files / Modules
- `.github/workflows/` (new or extend existing)
- **NEW:** `.github/workflows/vm-test.yml`
- `examples/DummyGame/`

##### 🔧 Work Instructions
1. Research GitHub Actions nested virtualization support
2. If not supported, evaluate:
   - Self-hosted runner with VM capability
   - Cloud VM provider integration
3. Create workflow:
   - Provision VM (QEMU/VirtualBox/cloud)
   - Build SDK in VM
   - Run DummyGame in VM
   - Collect FP metrics
4. Make optional (manual trigger or nightly)
5. Document VM setup

##### 📦 Required Outputs
- [ ] VM test workflow in .github/workflows/
- [ ] VM provisioning automated
- [ ] SDK builds and runs in VM
- [ ] False positive count collected
- [ ] VM setup documentation
- [ ] Decision: integrated or manual trigger

##### ✅ Definition of Done (DoD)
- [ ] VM workflow exists and triggerable
- [ ] SDK runs successfully in VM
- [ ] FP count = 0 in VM
- [ ] Workflow documented
- [ ] If not feasible: document why + propose alternative
- [ ] No CI performance regression (optional workflow)

##### 🔗 Dependencies
**Blocking:** None  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-A1, P1-A3, P1-B1, P1-D1, P1-D2  
**Merge risk:** 🟢 LOW  
**Coordination:** May require infra approval for self-hosted runner

##### 🚫 Non-Goals
- Do NOT require VM on every commit
- Do NOT test Windows/MacOS initially
- Do NOT use containers as VM substitute
- Do NOT performance test in VM

---

#### 🧩 Task ID: **P1-C3**
**Title:** False Positive Tracking System

##### 🎯 Goal
Implement client-side FP event logging and server-side dashboard schema design.

##### 📍 Scope
**Included:**
- Client FP event logging
- Structured FP event format
- Send FP events to server
- FP dashboard schema design

**Excluded:**
- Actual dashboard implementation (backend out of scope)
- Automated FP analysis
- FP suppression rules

##### 📂 Files / Modules
- **NEW:** `src/SDK/src/Telemetry/FPTracker.cpp/.hpp`
- `src/SDK/src/Internal/TelemetryEmitter.cpp/.hpp`
- `src/SDK/src/SentinelSDK.cpp`
- **NEW:** `docs/telemetry/fp_event_schema.md`

##### 🔧 Work Instructions
1. Create FPTracker:
   ```cpp
   void ReportFalsePositive(DetectorType detector, 
                            const std::string& context);
   ```
2. Define FP event schema:
   ```json
   {
     "event": "false_positive",
     "detector": "AntiDebug",
     "timestamp": "...",
     "session_id": "...",
     "context": "IsDebuggerPresent in VM"
   }
   ```
3. Integrate into violation reporting:
   - Informational severity → potential FP
   - Log to FPTracker
4. Send via telemetry channel
5. Document schema for dashboard
6. Test with P1-C1 scenarios

##### 📦 Required Outputs
- [ ] FPTracker.cpp/.hpp
- [ ] FP event schema documented
- [ ] Integration into SDK
- [ ] FP events sent to server
- [ ] Unit tests
- [ ] Integration test with DummyGame scenarios

##### ✅ Definition of Done (DoD)
- [ ] FP events logged for informational violations
- [ ] Events sent to server (verified with mock)
- [ ] Schema documented
- [ ] Performance impact < 0.1ms per event
- [ ] Tests verify structure
- [ ] DummyGame scenarios generate expected events

##### 🔗 Dependencies
**Blocking:** P1-B1 (heartbeat for transport)  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-C1, P1-C2 (complementary)  
**Merge risk:** 🟢 LOW  
**Coordination:** Uses P1-B1 telemetry transport

##### 🚫 Non-Goals
- Do NOT implement dashboard
- Do NOT implement FP suppression
- Do NOT automate FP analysis
- Do NOT change violation severity logic

---

#### 🧩 Task ID: **P1-C4**
**Title:** Bypass Simulation Framework

##### 🎯 Goal
Create test harness for simulating known bypass patterns (defensive testing only).

##### 📍 Scope
**Included:**
- Simulate known bypass patterns
- Verify SDK detects simulated bypasses
- Document bypass patterns tested
- Framework for adding new simulations

**Excluded:**
- Actual offensive bypass tools
- Public release of simulations
- Testing unknown/novel bypasses

##### 📂 Files / Modules
- **NEW:** `tests/SDK/simulation/` (all code)
- **NEW:** `tests/SDK/simulation/BypassSimulator.hpp/.cpp`
- **NEW:** `tests/SDK/simulation/README.md` (INTERNAL ONLY)
- **NEW:** `tests/SDK/simulation/scenarios/`

##### 🔧 Work Instructions
1. Create framework:
   ```cpp
   class BypassSimulator {
       virtual void SimulateBypass() = 0;
       virtual bool ShouldDetect() = 0;
   };
   ```
2. Implement simulations:
   - **Hook Removal**: Remove IAT hook, verify detection
   - **Debugger Hiding**: Clear PEB flags, verify detection
   - **Memory Tampering**: Modify code section, verify detection
   - **Thread Injection**: Inject remote thread, verify detection
3. For each:
   - Run SDK with bypass active
   - Verify violation reported
   - Test detection works
4. Run in isolated process (sandboxed)
5. Document all techniques (internal)
6. Mark as internal-only (not in public CI)

##### 📦 Required Outputs
- [ ] BypassSimulator framework
- [ ] 4+ bypass simulations
- [ ] Each simulation verifies detection
- [ ] README (internal documentation)
- [ ] Tests run in isolated environment
- [ ] All simulations detected by SDK

##### ✅ Definition of Done (DoD)
- [ ] Framework supports adding simulations
- [ ] All bypasses detected by SDK
- [ ] Simulations sandboxed/isolated
- [ ] Internal documentation exists
- [ ] Tests pass
- [ ] No simulations in public repo (if public)
- [ ] Senior engineer security review completed

##### 🔗 Dependencies
**Blocking:** P1-C1 (stable test suite)  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** None — SERIAL TASK (assign senior engineer)  
**Merge risk:** 🟡 MEDIUM — Touches multiple detection modules  
**Coordination:** Security review before merge

##### 🚫 Non-Goals
- Do NOT create public offensive tools
- Do NOT test novel bypass techniques
- Do NOT release simulation code publicly
- Do NOT implement actual bypasses (simulate only)

---

#### 🧩 Task ID: **P1-D1**
**Title:** Enforce Security Invariants

##### 🎯 Goal
Add runtime assertions for all invariants in SECURITY_INVARIANTS.md.

##### 📍 Scope
**Included:**
- Add assert/SENTINEL_ASSERT for each invariant
- Cover all invariants from SECURITY_INVARIANTS.md
- Active in debug, compiled out in release
- Invariant violation logging in release

**Excluded:**
- Changing invariant definitions
- Adding new invariants (enforce existing only)
- Performance-critical path assertions (strategic placement)

##### 📂 Files / Modules
- `docs/SECURITY_INVARIANTS.md` (reference)
- All `src/SDK/src/Detection/*.cpp`
- `src/Core/Crypto/` (cryptographic invariants)
- `src/SDK/src/Internal/` (state invariants)
- **NEW:** `include/Sentinel/SentinelAssert.hpp`

##### 🔧 Work Instructions
1. Read SECURITY_INVARIANTS.md, list all invariants
2. Create SENTINEL_ASSERT macro:
   ```cpp
   #ifdef NDEBUG
   #define SENTINEL_ASSERT(cond, msg) \
       if (!(cond)) { LogInvariantViolation(msg); }
   #else
   #define SENTINEL_ASSERT(cond, msg) assert((cond) && (msg))
   #endif
   ```
3. For each invariant, add assertion:
   - INV-CRYPTO-001: Assert nonce != 0 after increment
   - INV-MEM-001: Assert pointer in allocated region
   - INV-STATE-001: Assert valid state transitions
   - etc.
4. Test assertions trigger (unit tests violate invariants)
5. Verify compiled out in release
6. Document assertion → invariant mapping

##### 📦 Required Outputs
- [ ] SENTINEL_ASSERT macro
- [ ] Assertions for all invariants
- [ ] Mapping doc: assertion → invariant ID
- [ ] Unit tests intentionally violating invariants
- [ ] Verification: work in debug
- [ ] Verification: compiled out in release

##### ✅ Definition of Done (DoD)
- [ ] All invariants have assertions
- [ ] Assertions trigger when violated
- [ ] Debug builds crash on violation
- [ ] Release builds log but don't crash
- [ ] Zero performance impact in release
- [ ] Tests verify behavior
- [ ] Mapping documentation exists

##### 🔗 Dependencies
**Blocking:** None  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-A2, P1-B1 (different files, but touches many)  
**Merge risk:** 🟡 MEDIUM — Touches many modules  
**Coordination:** Coordinate with P1-A4 for init invariants

##### 🚫 Non-Goals
- Do NOT add hot-path assertions
- Do NOT define new invariants
- Do NOT change invariant semantics
- Do NOT leave assertions in release (log only)

---

#### 🧩 Task ID: **P1-D2**
**Title:** Secure Memory Zeroing Audit

##### 🎯 Goal
Verify all cryptographic material is securely zeroed on destruction.

##### �� Scope
**Included:**
- Audit all crypto classes for secure zeroing
- Implement SecureZero if missing
- Verify destructors call SecureZero
- Tests for secure zeroing

**Excluded:**
- Non-cryptographic memory
- Secure memory allocation
- Memory encryption

##### 📂 Files / Modules
- `src/Core/Crypto/` (all files)
- `src/SDK/src/Internal/SafeMemory.cpp/.hpp` (validate SecureZero)
- All classes handling keys, nonces, IVs

##### 🔧 Work Instructions
1. Audit crypto classes:
   - HMAC keys, AES keys, nonces, IVs, session secrets
2. Verify each:
   - Destructor calls SecureZero
   - No compiler optimization (use volatile)
3. If missing, implement:
   ```cpp
   void SecureZero(void* ptr, size_t len) {
       volatile uint8_t* p = (volatile uint8_t*)ptr;
       for (size_t i = 0; i < len; ++i) p[i] = 0;
   }
   ```
4. Test zeroing:
   - Create object with secret
   - Destroy
   - Read memory (if possible)
   - Verify zeroed
5. Document audited classes

##### 📦 Required Outputs
- [ ] Audit report of crypto classes
- [ ] SecureZero implementation (or validated)
- [ ] Destructors updated
- [ ] Test verifying zeroing
- [ ] Documentation of audited classes

##### ✅ Definition of Done (DoD)
- [ ] All crypto classes audited
- [ ] All destructors call SecureZero
- [ ] SecureZero not optimized out
- [ ] Tests verify zeroing
- [ ] Audit report documents all classes
- [ ] No key material in memory after destruction

##### 🔗 Dependencies
**Blocking:** None  
**Phase:** None

##### ⚠️  Merge & Parallelization Notes
**Parallel with:** P1-A3, P1-B3 (different concerns)  
**Merge risk:** 🟢 LOW  
**Coordination:** None

##### 🚫 Non-Goals
- Do NOT zero non-cryptographic memory
- Do NOT implement secure allocation
- Do NOT implement memory encryption
- Do NOT change crypto algorithms

---



### PHASE 2: Architectural Diversification

**Timeline:** Q2 2026 (12 weeks)  
**Primary Objective:** Eliminate "bypass once, win forever" conditions through redundancy, distributed decision points, and runtime variability infrastructure.

**Exit Criteria Summary:**
- [ ] No single function hook can suppress all violation reporting
- [ ] Memory layout differs measurably between sessions
- [ ] 3+ independent validation paths for critical integrity decisions
- [ ] Static analysis cannot enumerate all protection targets
- [ ] Server attestation protocol designed and documented

---

### Phase 2 Tasks (Streamlined Format)

Due to space constraints, Phase 2-4 tasks are presented in streamlined format. Full expansion follows Phase 1 pattern.

---

#### 🧩 **P2-A1: Refactor Check() into Distributed Reporters**
**Goal:** Split monolithic Check() into independent reporter modules with separate output channels.  
**Files:** `src/SDK/src/Detection/*.cpp`, `src/SDK/src/Internal/` (new reporter infrastructure)  
**Risk:** 🔴 CRITICAL — Phase gate, blocks other Phase 2 tasks  
**DoD:** No single hook suppresses all reporters; 2+ independent channels; tests verify isolation  
**Parallel:** P2-B1, P2-B2 | **Serial before:** P2-A2, P2-A4, P2-C2

---

#### 🧩 **P2-A2: Multi-Path Violation Reporting**
**Goal:** Implement 2+ independent violation delivery paths to server.  
**Files:** `src/SDK/src/Network/`, detection modules  
**Depends:** P2-A1  
**DoD:** 2+ network channels; fallback if primary fails; tests verify both paths  
**Parallel:** P2-B1, P2-B2, P2-C1

---

#### 🧩 **P2-A3: Server-Side Aggregation Endpoint Design**
**Goal:** Define API contract for server violation ingestion.  
**Files:** **NEW:** `docs/api/violation_ingestion.md`  
**DoD:** API spec complete; request/response schemas; authentication documented  
**Parallel:** All Phase 2 (documentation only, no conflicts)

---

#### 🧩 **P2-A4: Redundant Integrity Validators**
**Goal:** Implement 2+ independent code integrity verification paths.  
**Files:** `src/SDK/src/Detection/IntegrityCheck.cpp`  
**Depends:** P2-A1  
**DoD:** 2+ validators; different algorithms; both must agree for Critical severity  
**Parallel:** P2-B1, P2-C1

---

#### 🧩 **P2-B1: Structure Field Shuffling**
**Goal:** Implement compile/load-time field order randomization for critical structures.  
**Files:** `src/SDK/src/Internal/*.hpp`  
**Feature Flag:** `SENTINEL_RANDOMIZE_LAYOUT` (default: OFF)  
**DoD:** Struct layouts differ between sessions; verification test; feature flag works  
**Parallel:** P2-A1, P2-A2, P2-C1

---

#### 🧩 **P2-B2: Pointer Obfuscation Layer**
**Goal:** XOR internal pointers with session-derived key.  
**Files:** **NEW:** `src/SDK/src/Internal/PointerGuard.hpp`  
**Feature Flag:** `SENTINEL_OBFUSCATE_POINTERS` (default: OFF)  
**DoD:** All critical pointers obfuscated; performance < 2%; tests verify correctness  
**Depends:** P2-B1  
**Parallel:** P2-A1, P2-A2, P2-C1, P2-C2

---

#### 🧩 **P2-B3: Randomized Allocation Order**
**Goal:** Shuffle initialization order of internal structures at startup.  
**Files:** `src/SDK/src/SentinelSDK.cpp`  
**DoD:** Allocation order randomized; deterministic with fixed seed; tests verify  
**Depends:** P2-B1  
**Parallel:** P2-C1, P2-C2

---

#### 🧩 **P2-B4: Session-Unique Structure Layouts**
**Goal:** Generate per-session layout parameters from secure random.  
**Files:** `src/SDK/src/Internal/`, `src/Core/Crypto/SecureRandom.cpp`  
**DoD:** Layout params unique per session; automated verification; debug mode  
**Depends:** P2-B1, P2-B2  
**Parallel:** P2-C1

---

#### 🧩 **P2-C1: Hash Chain Validation**
**Goal:** Implement chained integrity hashes where each section includes previous hash.  
**Files:** `src/SDK/src/Detection/IntegrityCheck.cpp`  
**DoD:** Hash chain implemented; tampering detection improved; overhead < 5%  
**Depends:** Phase 1 complete  
**Parallel:** P2-A1, P2-B1, P2-B2

---

#### 🧩 **P2-C2: Cross-Subsystem Correlation**
**Goal:** Require multiple detector agreement before Critical severity.  
**Files:** **NEW:** `src/SDK/src/Internal/ViolationAggregator.cpp/.hpp`  
**DoD:** Critical requires 2+ detectors; configurable thresholds; telemetry  
**Depends:** P2-A1  
**Parallel:** P2-A2, P2-B2

---

#### 🧩 **P2-C3: Inline Integrity Macros**
**Goal:** Create SENTINEL_PROTECTED_CALL macro for call-site validation.  
**Files:** **NEW:** `include/Sentinel/SentinelMacros.hpp`  
**DoD:** Macro implemented; example usage documented; tests verify  
**Depends:** P2-C1  
**Parallel:** P2-A1, P2-B1

---

#### 🧩 **P2-C4: Server Attestation Protocol Design**
**Goal:** Document challenge-response attestation protocol.  
**Files:** **NEW:** `docs/protocols/attestation.md`  
**DoD:** Protocol documented; challenge generation; response validation; crypto specified  
**Parallel:** All Phase 2 (documentation only)

---

### PHASE 3: Runtime Variability

**Timeline:** Q3 2026 (12 weeks)  
**Primary Objective:** Make static analysis insufficient via polymorphic detection, server-controlled parameters, per-session uniqueness.

**Exit Criteria Summary:**
- [ ] Same check implemented via 3+ distinct code paths
- [ ] Server can remotely select implementation variant
- [ ] No two sessions produce identical check sequences
- [ ] Static memory dump analysis incomplete/incorrect
- [ ] Remote configuration download operational

---

#### 🧩 **P3-A1: IsDebuggerPresent Variants**
**Goal:** Implement 3+ detection methods for same logical check.  
**Files:** `src/SDK/src/Detection/AntiDebug.cpp`  
**DoD:** 3+ independent implementations; runtime selection; all detect; performance similar  
**Depends:** Phase 2 complete  
**Parallel:** P3-B1, P3-C1

---

#### 🧩 **P3-A2: Multiple Hook Detection Algorithms**
**Goal:** Implement alternative hook detection approaches.  
**Files:** `src/SDK/src/Detection/AntiHook.cpp`  
**DoD:** 3+ algorithms; runtime selection; all detect common hooks; performance acceptable  
**Depends:** Phase 2 complete  
**Parallel:** P3-B1, P3-C1

---

#### 🧩 **P3-A3: Randomized Check Ordering**
**Goal:** Shuffle detection check sequence per-frame using secure RNG.  
**Files:** `src/SDK/src/SentinelSDK.cpp`, detection orchestration  
**Feature Flag:** `SENTINEL_RANDOMIZE_CHECKS` (default: OFF)  
**DoD:** Check order randomized; no two sessions identical; deterministic debug mode  
**Depends:** P3-A1, P3-A2  
**Parallel:** P3-B1, P3-C1, P3-C2

---

#### 🧩 **P3-A4: Server-Controlled Variant Selection**
**Goal:** Server config determines which implementation variant executes.  
**Files:** Network layer, detection modules  
**Feature Flag:** `SENTINEL_SERVER_VARIANT_CONTROL` (default: OFF)  
**DoD:** Server can select variants; client applies config; telemetry on active variants  
**Depends:** P3-A1, P3-A2, P3-A3  
**Parallel:** P3-C1, P3-C2

---

#### 🧩 **P3-B1: Instruction Substitution Evaluation**
**Goal:** Research and document instruction substitution feasibility.  
**Files:** **NEW:** `docs/research/instruction_substitution.md`  
**DoD:** Feasibility assessment; implementation complexity; security benefit; recommendation  
**Parallel:** P3-A1, P3-A2, P3-C1

---

#### 🧩 **P3-B2: Control Flow Flattening Evaluation**
**Goal:** Research CFG flattening applicability, document findings.  
**Files:** **NEW:** `docs/research/cfg_flattening.md`  
**DoD:** Tool evaluation; overhead analysis; security benefit; integration recommendation  
**Parallel:** P3-A1, P3-A2, P3-C1

---

#### 🧩 **P3-B3: Build-Time Diversification**
**Goal:** Implement build variants with different internal constants.  
**Files:** `CMakeLists.txt`, build system  
**DoD:** Multiple build configs; different constants per build; automated testing  
**Depends:** P3-B1, P3-B2 (inform approach)  
**Parallel:** P3-A3, P3-C2

---

#### 🧩 **P3-C1: Attestation Challenge Protocol**
**Goal:** Implement server-to-client challenge-response for memory attestation.  
**Files:** **NEW:** `src/SDK/src/Network/Attestation.cpp/.hpp`  
**DoD:** Challenge-response implemented; crypto correct; protocol matches P2-C4 design  
**Depends:** P2-C4 (design)  
**Parallel:** P3-A1, P3-A2, P3-B1

---

#### 🧩 **P3-C2: Remote Configuration Download**
**Goal:** Client fetches detection parameters from server at session start.  
**Files:** **NEW:** `src/SDK/src/Network/RemoteConfig.cpp/.hpp`  
**DoD:** Config download at startup; fallback to defaults; signature verification; applied correctly  
**Depends:** P3-C1  
**Parallel:** P3-A3, P3-B3

---

#### 🧩 **P3-C3: Behavioral Baseline Collection**
**Goal:** Collect timing/input patterns for server-side analysis.  
**Files:** **NEW:** `src/SDK/src/Telemetry/BehaviorMetrics.cpp/.hpp`  
**DoD:** Metrics collected; sent to server; overhead < 0.5ms; privacy-preserving  
**Depends:** Phase 2 telemetry  
**Parallel:** P3-C1, P3-C2

---

#### 🧩 **P3-C4: Server-Side Anomaly Detection Foundation** *(OUT OF SCOPE)*
**Note:** Backend task for separate repository.

---

### PHASE 4: Telemetry & Server-Side Adjudication

**Timeline:** Q4 2026 (12 weeks)  
**Primary Objective:** Move all enforcement to server; behavioral analysis, delayed ban waves, economic disincentives.

**Exit Criteria Summary:**
- [ ] Client contains no ban-triggering logic
- [ ] Ban decisions require 3+ correlated signals
- [ ] Ban waves delayed minimum 7 days
- [ ] HWID fingerprinting operational
- [ ] Appeal workflow functional

**Note:** P4-A* (server infrastructure) and P4-C* (server analysis) are OUT OF SCOPE for Sentiel-RE. Only client tasks (P4-B*, P4-D1) included.

---

#### 🧩 **P4-B1: Comprehensive Event Capture**
**Goal:** Expand client telemetry to capture all detection events.  
**Files:** `src/SDK/src/Telemetry/`  
**DoD:** All detector events captured; structured format; sent to server; privacy-compliant  
**Depends:** Phase 3 complete

---

#### 🧩 **P4-B2: Behavioral Metric Collection**
**Goal:** Client collects and reports behavioral patterns.  
**Files:** `src/SDK/src/Telemetry/BehaviorMetrics.cpp` (expand from P3-C3)  
**DoD:** Enhanced metrics; timing/input patterns; anonymized; sent to server  
**Depends:** P4-B1

---

#### 🧩 **P4-B3: Hardware Fingerprinting**
**Goal:** Collect HWID components for ban persistence.  
**Files:** **NEW:** `src/SDK/src/Telemetry/HWID.cpp/.hpp`  
**Feature Flag:** `SENTINEL_COLLECT_HWID` (default: OFF)  
**Privacy:** 🔴 **REQUIRES LEGAL REVIEW BEFORE ENABLING**  
**DoD:** HWID collected; hashed; sent to server; privacy disclosure documented; legal review complete  
**Depends:** P4-B1

---

#### 🧩 **P4-B4: Encrypted Telemetry Channel**
**Goal:** End-to-end encryption for all telemetry data.  
**Files:** `src/SDK/src/Network/`, `src/Core/Crypto/`  
**DoD:** All telemetry encrypted; perfect forward secrecy; key rotation; verified  
**Depends:** Phase 1 crypto

---

#### 🧩 **P4-D1: Remove Client-Side Ban Logic**
**Goal:** Audit and remove any client enforcement code.  
**Files:** All SDK modules  
**DoD:** No ban logic in client; violations reported only; audit doc; tests verify no enforcement  
**Depends:** P4-A4 (server ban system operational — coordinate with backend)  
**Risk:** 🔴 CRITICAL — Do not merge until server operational

---

### Backend Tasks (OUT OF SCOPE for Sentiel-RE)

**P4-A1:** Event Ingestion Pipeline  
**P4-A2:** Real-Time Correlation Engine  
**P4-A3:** Historical Pattern Storage  
**P4-A4:** Ban Adjudication Service  
**P4-C1:** Statistical Anomaly Detection  
**P4-C2:** Player Behavior Modeling  
**P4-C3:** Cheat Signature Clustering  
**P4-C4:** Ban Wave Scheduler  
**P4-D2:** Appeal Submission Workflow

---

## SECTION C — PARALLEL EXECUTION MAP

### Agent View: Parallelization Strategy

#### Phase 1: Four Independent Lanes

```
Lane A (Performance):  P1-A1 → P1-A2 ⊕ P1-A3 ⊕ P1-A4
Lane B (Telemetry):    P1-B1 → P1-B2 → P1-B3 → P1-B4
Lane C (Testing):      P1-C1 ⊕ P1-C2 → P1-C3 → P1-C4
Lane D (Security):     P1-D1 ⊕ P1-D2
```

**Fully Independent (Zero Conflicts):** Lanes A, B, C, D proceed simultaneously

#### Phase 2: Phase Gate + Three Lanes

```
🚨 PHASE GATE: P2-A1 (must complete first)

After P2-A1:
Lane A: P2-A2 → P2-A4
Lane B: P2-B1 → P2-B2 → P2-B3 → P2-B4
Lane C: P2-C1 ⊕ P2-C4 → P2-C2 → P2-C3
Lane D: P2-A3 (anytime)
```

#### Phase 3: Three Parallel Streams

```
Lane A: P3-A1 ⊕ P3-A2 → P3-A3 → P3-A4
Lane B: P3-B1 ⊕ P3-B2 → P3-B3
Lane C: P3-C1 → P3-C2 → P3-C3
```

#### Phase 4: Client + Backend Parallel

```
Backend (Separate Repo): P4-A*, P4-C*, P4-D2
Client (Sentiel-RE): P4-B1 → P4-B2 ⊕ P4-B3 ⊕ P4-B4 → P4-D1
```

**Critical:** P4-D1 only after backend P4-A4 operational

### Serial Bottlenecks

1. **P2-A1** — Phase gate, blocks Phase 2 tasks
2. **P4-A4 → P4-D1** — Cross-repo dependency
3. **P1-C4** — Assign senior engineer

### Requires Senior Engineer

- P1-C4 (Bypass Simulation)
- P1-D1 (Security Invariants)
- P2-A1 (Architecture Refactor)
- P4-D1 (Remove Ban Logic)

---

## SECTION D — RISK & VALIDATION FLAGS

### Tasks Requiring Validation

| Task | Assumption | Validation | Risk if Wrong |
|------|------------|------------|---------------|
| P1-A1 | 0.1ms achievable | Profile actual HW | May need relaxed target |
| P1-A3 | SIMD ≥2x speedup | Benchmark target CPU | May reject SIMD |
| P1-B2 | Cert pinning compatible | Platform testing | May need alternative |
| P1-C2 | GH Actions supports VM | Research docs | May need self-hosted |
| P4-B3 | HWID legal | **LEGAL REVIEW** | 🔴 Privacy violation |

### Legal / Compliance Review

| Task | Review Type | Risk Level |
|------|-------------|------------|
| P4-B3 | Privacy / GDPR | 🔴 CRITICAL |
| P4-B1 | Data minimization | 🟡 MEDIUM |
| P4-B2 | Behavioral tracking | 🟡 MEDIUM |

**Required:** Privacy policy, data retention policy, user consent, deletion procedure

### Feature Flag Requirements

All flagged tasks MUST:
- Default OFF for initial merge
- Runtime toggle (no recompilation)
- Zero impact when disabled
- Telemetry on usage
- Documented in RuntimeConfig

**Flags:**
- Phase 2: `SENTINEL_RANDOMIZE_LAYOUT`, `SENTINEL_OBFUSCATE_POINTERS`
- Phase 3: `SENTINEL_RANDOMIZE_CHECKS`, `SENTINEL_SERVER_VARIANT_CONTROL`
- Phase 4: `SENTINEL_COLLECT_HWID` (**LEGAL REVIEW REQUIRED**)

### Sign-Off Requirements

| Phase | Required Sign-Offs |
|-------|-------------------|
| Phase 1 | Performance, QA, Security |
| Phase 2 | Architecture, Security, Performance |
| Phase 3 | Security, Backend lead |
| Phase 4 | **Legal**, Privacy, Security, Product |

**Special:**
- **P4-B3:** Legal, Privacy Officer, GDPR consultant REQUIRED
- **P4-D1:** Backend confirmation, Product, Security
- **P1-C4:** Security review, internal-only

---

## DELIVERABLES CHECKLIST

### Documentation
- [ ] `docs/architecture/ARCHITECTURE.md` — Updated
- [ ] `docs/protocols/attestation.md` — Protocol spec
- [ ] `docs/api/violation_ingestion.md` — API contract
- [ ] `docs/integration/release_notes.md` — Release notes
- [ ] `docs/operations/runbook.md` — Runbooks
- [ ] `docs/performance/` — Profiling reports
- [ ] `docs/research/` — Evaluations

### SDK Artifacts
- [ ] SentinelSDK v2.0 (static, dynamic libs)
- [ ] Updated `include/Sentinel/SentinelSDK.hpp`
- [ ] CMake integration package
- [ ] Updated examples

### Testing
- [ ] Expanded DummyGame scenarios
- [ ] VM-based CI
- [ ] Bypass simulation (internal)
- [ ] Performance benchmarks

### Infrastructure
- [ ] Feature flag system
- [ ] Telemetry pipeline
- [ ] Remote config download
- [ ] Attestation protocol

### Compliance
- [ ] Privacy policy template
- [ ] GDPR/CCPA docs
- [ ] Data retention policy
- [ ] HWID disclosure

---

## INTENTIONALLY OUT OF SCOPE

### Backend Services (Separate Repository)
- Event ingestion (P4-A1)
- Correlation engine (P4-A2)
- Pattern storage (P4-A3)
- Ban adjudication (P4-A4)
- Anomaly detection (P4-C1)
- Behavior modeling (P4-C2)
- Signature clustering (P4-C3)
- Ban wave scheduler (P4-C4)
- Appeal workflow (P4-D2)

### Advanced Techniques (Deferred)
- Kernel-mode driver
- Hypervisor protection
- Code virtualization
- ML-based detection
- Automated appeals
- Multi-region infrastructure
- Third-party intelligence

---

## END OF TASK EXECUTION PACK

**Total Tasks:** 45 (14 Phase 1 + 11 Phase 2 + 10 Phase 3 + 10 Phase 4)  
**Client SDK Tasks:** 35 (10 backend excluded)  
**Timeline:** 48 weeks (Q1-Q4 2026)  
**Phase Gates:** 2 critical (P2-A1, P4-A4→P4-D1)

**Usage:**
1. Convert tasks to GitHub Issues (task ID as title)
2. Assign per parallelization map
3. Use feature flags for architectural changes
4. Require sign-offs per Section D
5. Validate assumptions first

**Version:** 1.0  
**Date:** 2025-12-31  
**Maintained By:** Engineering Program Management

---
*This document operationalizes the Sentinel Anti-Cheat SDK Production Execution Plan into execution-ready, agent-assignable tasks suitable for parallel development with minimal merge conflicts.*
