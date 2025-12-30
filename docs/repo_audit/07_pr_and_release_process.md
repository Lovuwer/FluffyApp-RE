# Step 7: PR and Release Process

**This work assumes testing is authorized by repository owner. Do not run against third-party systems.**

---

## Branch Naming Convention

### Pattern

```
<type>/<scope>/<short-description>
```

**Types:**
- `fix/` - Bug fixes (corresponds to PATCH in semver)
- `feat/` - New features (corresponds to MINOR in semver)
- `refactor/` - Code refactoring (no functional change)
- `perf/` - Performance improvements
- `docs/` - Documentation only
- `test/` - Test additions/modifications
- `chore/` - Build/tooling changes

**Scopes:**
- `crypto/` - Cryptography components
- `detection/` - Anti-cheat detection logic
- `network/` - Network/HTTP/cloud components
- `sdk/` - Public SDK API
- `core/` - Core utilities
- `build/` - CMake/build system
- `ci/` - GitHub Actions/CI

**Examples:**
```
fix/crypto/aes-gcm-nonce-hardening
feat/network/cloud-reporter-implementation
refactor/detection/correlation-engine-optimization
perf/crypto/simd-hash-acceleration
docs/security/threat-model-update
test/crypto/hmac-timing-validation
```

---

## Commit Message Template

### Format

```
<type>(<scope>): <short summary>

<detailed description>

BREAKING CHANGE: <description> (if applicable)
Fixes: #<issue-number>
Related: #<issue-number>
```

### Example 1: Bug Fix (TASK-001)

```
fix(sdk): prevent CorrelationEngine segfault on null module name

Changes DetectionSignal::module_name from raw pointer to std::string
to prevent use-after-free and null pointer dereference.

Root cause: ViolationEvent.module_name.c_str() pointer stored directly
in DetectionSignal, leading to dangling pointer when event destroyed.

Changes:
- DetectionSignal::module_name: const char* → std::string
- ProcessViolation: add empty string check, default to "<unknown>"
- Add defensive tests for null/empty module names

Fixes: #123
```

### Example 2: Feature (TASK-002)

```
feat(network): implement CloudReporter with HTTPS and retry logic

Adds production-ready CloudReporter for violation telemetry:
- HTTPS POST to /api/v1/violations endpoint
- Certificate pinning integration
- HMAC request signing (prevent forgery)
- Batching (max 100 events or 30s interval)
- Exponential backoff retry (3 attempts, max 30s delay)
- Thread-safe queue with mutex protection

Dependencies:
- HttpClient (libcurl-based)
- RequestSigner (HMAC-SHA256)
- CertificatePinning (SHA-256 fingerprints)

Performance: Batching reduces network overhead by 95%.

Related: #456
```

### Example 3: Security Fix (TASK-003)

```
security(crypto): make AES encryptWithNonce() internal to prevent nonce reuse

Public API allowed callers to supply nonces, enabling catastrophic
nonce reuse vulnerability in AES-GCM (breaks confidentiality + authenticity).

Changes:
- Move encryptWithNonce() to private section of AESCipher
- Document nonce uniqueness requirement in code comments
- Add test to verify automatic nonces are unique (1000 iterations)

BREAKING CHANGE: encryptWithNonce() no longer public API.
Callers should use encrypt() which auto-generates random nonces.

Migration:
  Before: cipher.encryptWithNonce(plaintext, my_nonce, aad)
  After:  cipher.encrypt(plaintext, aad)  // Auto nonce

Fixes: #789
```

---

## Pull Request Template

### PR Title Format

```
[<Type>] <Short description>
```

Examples:
- `[Fix] Prevent CorrelationEngine segfault on null module names`
- `[Feature] Add CloudReporter with HTTPS and certificate pinning`
- `[Security] Prevent AES-GCM nonce reuse vulnerability`

### PR Description Template

```markdown
## Summary
<!-- One-paragraph description of what this PR does -->

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security fix (addresses a security vulnerability)
- [ ] Performance improvement
- [ ] Documentation update
- [ ] Refactoring (no functional changes)

## Problem Statement
<!-- Describe the problem this PR solves. Link to issue if applicable. -->

Fixes: #<issue-number>

## Solution
<!-- Describe your approach and key implementation decisions -->

### Changes Made
- 
- 
- 

### Files Modified
<!-- List key files and their changes -->
- `src/...` - 
- `tests/...` - 

## Testing
<!-- Describe how you tested your changes -->

### Unit Tests
- [ ] All existing tests pass
- [ ] New tests added (list below)
  - 
  - 

### Test Results
```
<paste ctest output>
```

### Manual Testing
<!-- Describe any manual testing performed -->

## Performance Impact
<!-- Describe performance impact, if any -->

Benchmarks:
- Before: 
- After: 
- Change: 

## Security Impact
<!-- For security-sensitive changes -->

### Threat Model
<!-- What attacker capabilities does this defend against? -->

### Security Review
- [ ] No new vulnerabilities introduced
- [ ] Follows secure coding practices (RAII, secure zero, constant-time where needed)
- [ ] Input validation added where needed
- [ ] No secrets in code/logs

## Breaking Changes
<!-- List any breaking API changes -->

### Migration Guide
<!-- How should users update their code? -->

Before:
```cpp
// old API
```

After:
```cpp
// new API
```

## Deployment
<!-- Deployment/rollout considerations -->

### Rollout Plan
1. 
2. 
3. 

### Rollback Plan
<!-- How to revert if issues arise -->

### Monitoring
<!-- What should be monitored after deployment? -->
- 
- 

## Checklist
<!-- Check all that apply -->

### Code Quality
- [ ] Code follows project style guide
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] No compiler warnings
- [ ] No TODOs left (or documented in issues)

### Testing
- [ ] Unit tests added/updated
- [ ] All tests pass locally
- [ ] Integration tests pass (if applicable)
- [ ] Manual testing performed

### Documentation
- [ ] README updated (if needed)
- [ ] API documentation updated (if needed)
- [ ] CHANGELOG updated
- [ ] Security documentation updated (if applicable)

### Security
- [ ] No hardcoded secrets/credentials
- [ ] Input validation added
- [ ] Error handling implemented
- [ ] Logging doesn't leak sensitive data

## Additional Notes
<!-- Any other information reviewers should know -->

## Screenshots
<!-- If UI changes, include before/after screenshots -->

---

**Review Checklist for Maintainers:**
- [ ] Code review completed
- [ ] Security review completed (for security-sensitive changes)
- [ ] Performance impact acceptable
- [ ] Breaking changes documented and justified
- [ ] Tests comprehensive and passing
- [ ] Documentation updated
```

---

## Sample PR Bodies for Top 3 Fixes

### Sample PR #1: TASK-001 (CorrelationEngine Segfault)

```markdown
## Summary
Fixes critical segmentation fault in CorrelationEngine when processing violations with null or empty module names. This bug caused 7 unit tests to fail and would crash the SDK in production if a violation event lacked module information.

## Type of Change
- [x] Bug fix (non-breaking change which fixes an issue)
- [ ] Security fix

## Problem Statement
CorrelationEngine stores a raw `const char*` pointer to `ViolationEvent.module_name.c_str()`. When:
1. `module_name` is an empty string (`""`), the pointer is valid but points to empty storage
2. The `ViolationEvent` is destroyed, the pointer becomes dangling
3. Later access (in `GetCorrelationScore()`, `ShouldWhitelist()`, etc.) causes segfault

This affected 7 tests in `test_correlation_enhancements.cpp` which created events with `module_name = nullptr` or `""`.

Fixes: #TASK-001

## Solution
Changed `DetectionSignal::module_name` from `const char*` to `std::string` to own the string data.

### Changes Made
- `src/SDK/src/Internal/CorrelationEngine.hpp`:
  - Line 44: `const char* module_name;` → `std::string module_name;`
- `src/SDK/src/Internal/CorrelationEngine.cpp`:
  - Line 114: `signal.module_name = event.module_name.empty() ? "<unknown>" : event.module_name;`
- `tests/SDK/test_correlation_engine.cpp`:
  - Added `EmptyModuleName_NoSegfault` test
  - Added `ManyEvents_NoMemoryLeak` test

### Files Modified
- `src/SDK/src/Internal/CorrelationEngine.hpp` - DetectionSignal struct
- `src/SDK/src/Internal/CorrelationEngine.cpp` - ProcessViolation logic
- `tests/SDK/test_correlation_engine.cpp` - Null safety tests

## Testing

### Unit Tests
- [x] All existing tests pass
- [x] New tests added:
  - `CorrelationEngineTest.EmptyModuleName_NoSegfault`
  - `CorrelationEngineTest.ManyEvents_NoMemoryLeak`

### Test Results
```
[==========] Running 434 tests from 26 test suites.
...
[  PASSED  ] 434 tests (previously 427, 7 fixed)
```

All 7 previously failing `CorrelationEnhancementTest` tests now pass:
- `NewConfidenceWeights` ✅
- `EnforcementThreshold` ✅
- `CoolingOffPeriod` ✅
- `SubThresholdTelemetry` ✅
- `CloudGamingLatencyNeverEnforces` ✅
- `NoSingleSignalEnforcement` ✅
- `MinimumThreeDistinctSignals` ✅

## Performance Impact
Negligible. `std::string` adds ~32 bytes per DetectionSignal (vs 8 bytes for pointer), but signals are short-lived and limited in count (~10-20 max).

## Security Impact
### Threat Model
Prevents crash-induced denial of service. Attacker could previously trigger segfault by sending violation events with empty module names (if they could control event generation).

### Security Review
- [x] No new vulnerabilities introduced
- [x] Defensive programming (empty string handling)
- [x] Memory safety improved (no raw pointers to temporary data)

## Breaking Changes
None. Internal data structure change only.

## Deployment
### Rollout Plan
1. Merge to main after review
2. Tag as v1.0.1 (patch release)
3. Update SDK binaries for downstream projects

### Rollback Plan
If issues arise, revert commit. No API changes, so rollback is safe.

### Monitoring
None needed (crash fix).

## Checklist
- [x] Code follows project style guide
- [x] Self-review completed
- [x] All tests pass locally
- [x] No compiler warnings
- [x] Documentation updated (N/A - internal fix)
- [x] CHANGELOG updated

## Additional Notes
This fix unblocks SDK v1.0 release. All 434 unit tests now pass.
```

---

### Sample PR #2: TASK-002 (CloudReporter Implementation)

```markdown
## Summary
Implements production-ready CloudReporter for telemetry reporting, including HTTPS support, certificate pinning, request signing, batching, and retry logic with exponential backoff.

## Type of Change
- [x] New feature (non-breaking change which adds functionality)

## Problem Statement
CloudReporter was a stub, blocking production deployment. Without it:
- No violation reporting to cloud backend
- No ban enforcement
- No telemetry analytics
- No anti-cheat effectiveness tracking

Fixes: #TASK-002

## Solution
Implemented CloudReporter with:
- **libcurl-based HttpClient** (TLS 1.3, certificate pinning)
- **HMAC request signing** (prevents API request forgery)
- **Batching** (max 100 events or 30s interval)
- **Exponential backoff** retry (3 attempts, max 30s delay)
- **Thread-safe queue** (mutex-protected)

### Dependencies
- libcurl (added to CMake via `find_package(CURL REQUIRED)`)
- HttpClient implementation (TASK-004)
- RequestSigner implementation (TASK-006)
- CertificatePinning integration (TASK-005)

### Architecture
```
ViolationEvent → Queue (thread-safe)
                   ↓
              Batching (100 events or 30s)
                   ↓
              JSON serialization
                   ↓
              HMAC signing
                   ↓
              HTTPS POST (with cert pinning)
                   ↓
              Retry on failure (3 attempts)
```

## Testing

### Unit Tests
- [x] New tests added:
  - `CloudReporterTest.QueueAndFlush_Success`
  - `CloudReporterTest.Batching_100Events`
  - `CloudReporterTest.Batching_30SecondInterval`
  - `CloudReporterTest.RetryOnFailure_ExponentialBackoff`
  - `CloudReporterTest.CertificatePinning_WrongPin_Rejected`
  - `CloudReporterTest.RequestSigning_ValidSignature`
  - `CloudReporterTest.ThreadSafety_ConcurrentQueue`

### Integration Tests
- [x] Integration test with mock HTTP server (httpbin.org):
  - POST /api/v1/violations ✅
  - Certificate pinning validation ✅
  - Request signature validation ✅

### Test Results
```
[==========] Running 15 tests from 3 test suites.
[  PASSED  ] 15 tests.
```

## Performance Impact
**Batching reduces network overhead by 95%.**

Before (per-event sending):
- 100 events = 100 HTTP requests = ~500ms total

After (batching):
- 100 events = 1 HTTP request = ~25ms total

## Security Impact
### Threat Model
Defends against:
- MITM attacks (certificate pinning)
- API request forgery (HMAC signing)
- Replay attacks (timestamp in signature)

### Security Review
- [x] Certificate pinning prevents MITM
- [x] HMAC prevents request forgery
- [x] No secrets in logs (redacted)
- [x] TLS 1.3 minimum enforced

## Breaking Changes
None. New feature, no API changes.

## Deployment

### Rollout Plan
1. Deploy cloud backend API endpoint first
2. Update SDK with CloudReporter implementation
3. Gradual rollout (10% → 50% → 100% over 1 week)
4. Monitor error rates and latency

### Rollback Plan
If HTTP errors > 5%:
- Fall back to file-based logging (offline mode)
- Queue events locally until backend recovered

### Monitoring
- **Error rate:** Alert if > 1% of requests fail
- **Latency:** Alert if p99 > 5 seconds
- **Queue depth:** Alert if > 1000 events backlogged
- **Certificate pin failures:** Alert if > 0.1% (possible MITM)

## Checklist
- [x] Code follows project style guide
- [x] Self-review completed
- [x] All tests pass locally
- [x] Integration tests with mock server pass
- [x] Documentation updated (SDK usage guide)
- [x] CHANGELOG updated
- [x] Security review completed

## Additional Notes
Unblocks production deployment. SDK can now report violations to cloud backend for ban enforcement and analytics.

Next steps:
- Deploy cloud backend API (separate repo)
- Add dashboard for violation telemetry
- Implement ban enforcement logic server-side
```

---

### Sample PR #3: TASK-003 (AES Nonce Hardening)

```markdown
## Summary
Prevents catastrophic AES-GCM nonce reuse vulnerability by making `encryptWithNonce()` internal-only. Public API now only exposes `encrypt()` which auto-generates random nonces.

## Type of Change
- [x] Security fix (addresses a security vulnerability)
- [x] Breaking change (removes public API)

## Problem Statement
Public `encryptWithNonce()` API allowed callers to supply nonces. If caller reuses nonce:
- **Confidentiality broken:** Two ciphertexts with same (key, nonce) leak plaintext XOR
- **Authenticity broken:** GCM authentication tag becomes predictable
- **Impact:** Complete encryption bypass

This is a **critical vulnerability** (CVSS 9.1 - Critical).

Fixes: #TASK-003

## Solution
Made `encryptWithNonce()` private (internal use only). Callers must use `encrypt()` which:
- Auto-generates random 96-bit nonce via SecureRandom
- Prepends nonce to ciphertext ([IV || CT || TAG])
- Guarantees nonce uniqueness (probability of collision ~2^-48 after 1 trillion encryptions)

### Changes Made
- `include/Sentinel/Core/Crypto.hpp`:
  - Moved `encryptWithNonce()` to `private:` section
  - Added doc comment warning about nonce uniqueness
- `tests/Core/test_aes_nonce_safety.cpp`:
  - Added `AutomaticNonces_AlwaysUnique` test (1000 iterations)
  - Added `TamperingDetection_AllBitsFlipped` test

## Testing

### Unit Tests
- [x] All existing tests pass (no callers of `encryptWithNonce()` in public API)
- [x] New tests added:
  - `AESNonceSafetyTest.AutomaticNonces_AlwaysUnique` (validates 1000 nonces unique)
  - `AESNonceSafetyTest.TamperingDetection_AllBitsFlipped` (validates GCM auth)

### Test Results
```
[  PASSED  ] AESCipherTest.* (18 tests)
[  PASSED  ] AESNonceSafetyTest.* (2 tests)
```

## Performance Impact
None. Internal API unchanged; only visibility changed.

## Security Impact
### Threat Model
Prevents nonce reuse attack:
- **Before:** Attacker could call `encryptWithNonce(msg1, nonce)` and `encryptWithNonce(msg2, nonce)`, recover plaintext via XOR
- **After:** Impossible - caller cannot supply nonce

### Security Review
- [x] No new vulnerabilities introduced
- [x] Nonce uniqueness guaranteed (automatic random generation)
- [x] SecureRandom uses OS CSPRNG (BCryptGenRandom / /dev/urandom)

## Breaking Changes
**YES - `encryptWithNonce()` no longer public API**

### Migration Guide

**Before:**
```cpp
AESCipher cipher(key);
AESNonce my_nonce = GenerateNonce();  // Caller responsible
auto ct = cipher.encryptWithNonce(plaintext, my_nonce, aad);
```

**After:**
```cpp
AESCipher cipher(key);
auto ct = cipher.encrypt(plaintext, aad);  // Nonce auto-generated (safe)
```

**Impact:** No known callers of `encryptWithNonce()` in public API. Internal SDK uses `encrypt()` only.

### Rollback Plan
If external callers need manual nonce control (unlikely):
1. Add compile-time flag `#define SENTINEL_UNSAFE_CRYPTO_API`
2. Re-expose `encryptWithNonce()` with big warning comment
3. Require callers to sign waiver acknowledging risk

## Deployment

### Rollout Plan
1. Merge to `main` after security review
2. Tag as **v2.0.0** (major version bump - breaking change)
3. Update SDK documentation with migration guide
4. Email existing SDK users with upgrade instructions

### Monitoring
Log any crashes related to AES (indicates caller was using removed API).

## Checklist
- [x] Code follows project style guide
- [x] Self-review completed
- [x] Security review completed
- [x] All tests pass locally
- [x] Breaking changes documented
- [x] Migration guide provided
- [x] CHANGELOG updated with BREAKING CHANGE note
- [x] Security advisory published (if external users exist)

## Additional Notes
This is a **security-critical fix** for a critical vulnerability. Breaking change is justified to prevent catastrophic encryption bypass.

**Security Advisory:** CVE-TBD (pending assignment)
```

---

## Labels

**Required Labels:**
- `priority: P0` - Critical/blocking
- `priority: P1` - High priority
- `priority: P2` - Medium priority
- `priority: P3` - Low priority

**Type Labels:**
- `type: bug` - Bug fixes
- `type: feature` - New features
- `type: security` - Security fixes
- `type: performance` - Performance improvements
- `type: documentation` - Documentation updates

**Component Labels:**
- `component: crypto` - Cryptography
- `component: detection` - Anti-cheat detection
- `component: network` - Network/cloud
- `component: sdk` - Public SDK API
- `component: core` - Core utilities

**Review Labels:**
- `needs: review` - Awaiting code review
- `needs: security-review` - Awaiting security review
- `needs: testing` - Awaiting testing
- `approved` - Approved for merge

---

## Reviewers

**Required Reviewers (by component):**
- **Crypto:** @crypto-lead (must review all crypto changes)
- **Security:** @security-lead (must review all security-sensitive changes)
- **SDK API:** @api-lead (must review all public API changes)
- **Breaking Changes:** @project-owner (must approve all breaking changes)

**Minimum Approvals:**
- P0/P1: 2 approvals
- P2/P3: 1 approval
- Security fixes: 2 approvals + security-lead
- Breaking changes: 2 approvals + project-owner

---

## Merge Process

1. **Create PR** from feature branch to `main`
2. **Apply labels** (priority, type, component)
3. **Request reviewers** (based on component)
4. **CI must pass** (build, tests, linting)
5. **Approvals obtained** (minimum based on priority)
6. **Squash and merge** (or rebase if multiple logical commits)
7. **Delete feature branch** after merge
8. **Tag release** if needed (P0/P1 fixes)

---

## Release Tagging

**Semver:** `vMAJOR.MINOR.PATCH`

- **MAJOR:** Breaking changes (API changes, removed features)
- **MINOR:** New features (backward-compatible)
- **PATCH:** Bug fixes (backward-compatible)

**Examples:**
- `v1.0.0` - Initial release
- `v1.0.1` - TASK-001 (CorrelationEngine segfault fix)
- `v1.1.0` - TASK-002 (CloudReporter feature)
- `v2.0.0` - TASK-003 (AES API breaking change)

**Tag Command:**
```bash
git tag -a v1.0.1 -m "Fix: CorrelationEngine segfault on null module names"
git push origin v1.0.1
```

---

**Document Version:** 1.0  
**Generated:** 2025-12-30  
**Process Defined:** Complete PR workflow with 3 sample PRs
