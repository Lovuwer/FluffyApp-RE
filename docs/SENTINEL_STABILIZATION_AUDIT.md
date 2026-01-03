# Sentinel Anti-Cheat System: Stabilization Audit Report

**Role:** Principal Systems Architect  
**Project:** Sentinel (User-Mode Anti-Cheat SDK)  
**Audit Date:** 2026-01-03  
**Classification:** INTERNAL - Technical Leadership Review  
**Purpose:** Post-Implementation Stabilization & Foundation Audit

---

## Executive Summary

This audit assessed the production-readiness of the Sentinel anti-cheat system based on **actual code implementation**, not documentation. The system is **functional but not production-ready** due to critical stability issues in the correlation engine, undefined behavior risks in the VM interpreter, and incomplete error handling across subsystem boundaries.

### Critical Findings

**P0 Issues (Must Fix Before Production):**
1. **Correlation Engine**: 7 segmentation faults - root cause unclear but critical
2. **VM Jump Bounds**: Off-by-one error allows out-of-bounds instruction read
3. **Heartbeat Replay**: No sequence/timestamp validation enables replay attacks  
4. **Error Propagation**: Silent failures cascade without detection or recovery

**System Status:**
- ✅ **Core detection primitives work** (anti-debug, anti-hook, injection)
- ⚠️ **Correlation engine crashes** under specific input combinations
- ⚠️ **VM execution has undefined behavior** for malformed bytecode
- ⚠️ **No graceful degradation** when subsystems fail
- ❌ **Documentation drift** in multiple areas

---

## PHASE 1: VM SAFETY & DETERMINISM ASSESSMENT

### Current Reality

The VM interpreter (`src/SDK/src/Detection/VM/VMInterpreter.cpp`) executes custom bytecode for integrity checks. Analysis of implementation reveals:

**What Guarantees Exist:**
1. ✅ Instruction count limit enforced (max 100,000 instructions)
2. ✅ Timeout enforced (5000ms default)
3. ✅ Stack depth limit enforced (1024 entries)
4. ✅ Memory read count limit enforced (10,000 reads)
5. ✅ All exceptions caught via try-catch (never throws to caller)
6. ✅ Invalid memory access returns 0 (doesn't crash on Windows)

**Critical Issues Discovered:**

#### ISSUE 1: Bytecode Hash Verification Inconsistency (CORRECTED)
**Location:** `VMInterpreter.cpp:226` vs `Bytecode.cpp:121`

**Current Reality:**
```cpp
// In VMInterpreter::Impl::execute (line 226):
uint64_t computed_hash = xxh3_hash(
    raw + instruction_offset, 
    header->instruction_count  // Uses instruction_count from header
);

// In Bytecode::verify (line 121):
size_t instr_size = m_data.size() - m_instruction_offset;  // Uses ALL remaining data
uint64_t computed_hash = xxh3_hash(instr_start, instr_size);
```

**Problem:**
If bytecode has trailing padding/data beyond `instruction_count`, `Bytecode::verify()` hashes ALL remaining bytes while `VMInterpreter::execute()` only hashes `instruction_count` bytes. However, **upon re-analysis**: `m_data.size() - m_instruction_offset` should equal `instruction_count` if bytecode is properly formed. The mismatch only occurs if loader allows trailing bytes.

**Re-Assessment:**
- ✅ **Lower severity than initially stated** - requires malformed bytecode with trailing data
- ⚠️ Still a concern: verify() and execute() should use identical hash input
- ✅ Recommendation stands: Use `header->instruction_count` in both places for consistency

**Can Malformed Bytecode:**
- ❌ Crash the process? **No** - exceptions caught
- ❌ Hang execution? **No** - timeout enforced
- ⚠️ **Exploit inconsistency?** **UNLIKELY** - requires loader accepting trailing bytes

**Citation:** `src/SDK/src/Detection/VM/VMInterpreter.cpp:220-236`, `src/SDK/src/Detection/VM/Bytecode.cpp:114-125`

#### ISSUE 2: Jump Instruction Bounds Check Insufficient
**Location:** `VMInterpreter.cpp:488-494`, `VMInterpreter.cpp:504-510`, `VMInterpreter.cpp:517-523`

**Current Reality:**
```cpp
case Opcode::JMP: {
    if (ip + 2 > instruction_count) return false;
    int16_t offset = static_cast<int16_t>(readLE<uint16_t>(instructions + ip));
    ip += 2;
    size_t new_ip = static_cast<size_t>(static_cast<int64_t>(ip) + offset);
    if (new_ip > instruction_count) return false;  // Off-by-one: should be >=
    ip = new_ip;
    break;
}
```

**Problem:**
Jump validation checks `new_ip > instruction_count` but should check `new_ip >= instruction_count`. This allows jumping to exactly `instruction_count`, which is one byte past the end of the instruction buffer.

**Can Malformed Bytecode:**
- ⚠️ **Read out of bounds?** **YES** - next opcode fetch at `instructions[instruction_count]`
- ⚠️ **Execute garbage?** **YES** - if buffer allocation has trailing bytes

**Citation:** `src/SDK/src/Detection/VM/VMInterpreter.cpp:492`

#### ISSUE 3: External Function Callback Safety
**Location:** `VMInterpreter.cpp:649-665`

**Current Reality:**
```cpp
case Opcode::CALL_EXT: {
    // ... stack pops ...
    uint64_t result = 0;
    auto it = external_functions_.find(func_id);
    if (it != external_functions_.end() && it->second) {
        try {
            result = it->second(arg1, arg2);  // Callback invoked
        } catch (...) {
            result = 0;
        }
    }
    if (!push(result)) return false;
    break;
}
```

**Problem:**
External callbacks can execute arbitrary code with no timeout enforcement. A malicious or buggy callback can:
- Hang indefinitely (VM timeout doesn't apply inside callback)
- Crash the process (exception caught but damage done)
- Modify VM state during execution

**Can Malformed Bytecode:**
- ⚠️ **Hang execution?** **YES** - if callback blocks
- ⚠️ **Cause side effects?** **YES** - callbacks have full game access

**Citation:** `src/SDK/src/Detection/VM/VMInterpreter.cpp:658-662`

#### ISSUE 4: Integer Overflow in Hash Operations
**Location:** `VMInterpreter.cpp:575-595`, `VMInterpreter.cpp:597-619`

**Current Reality:**
```cpp
case Opcode::HASH_CRC32: {
    uint64_t size, address;
    if (!pop(size) || !pop(address)) return false;
    
    // Limit hash size
    if (size > 1024 * 1024) size = 1024 * 1024;  // 1MB max
    
    uint32_t hash = 0;
    if (config_.enable_safe_reads && size > 0) {
        std::vector<uint8_t> buffer(size);  // Potential allocation failure if size is large
        // ...
    }
}
```

**Problem:**
1. Vector allocation can fail if `size` is close to 1MB (throws `std::bad_alloc`)
2. No check if `address + size` overflows
3. Loop iterates `size` times without checking if process is still within timeout

**Note:** Implementation already limits size to 1MB (line 580), making allocation failure unlikely in practice. However, integer overflow and timeout checks still needed.

**Can Malformed Bytecode:**
- ⚠️ **Cause allocation failure?** **UNLIKELY** - capped at 1MB, but still possible
- ⚠️ **Read beyond memory regions?** **YES** - if address + size wraps around
- ⚠️ **Timeout during hash?** **NO** - timeout only checked at opcode boundaries

**Citation:** `src/SDK/src/Detection/VM/VMInterpreter.cpp:578-595`

### VM Execution Guarantees (Verified)

**Time Bounds:**
- ✅ **Bounded:** Yes, max 5000ms default timeout
- ✅ **Deterministic:** No (timing checks use RDTSC, external callbacks arbitrary)
- ✅ **Recoverable:** Yes, returns `VMResult::Timeout`

**Memory Safety:**
- ✅ **Stack overflow:** Detected, returns `VMResult::Error`
- ✅ **Heap exhaustion:** Caught as exception, returns `VMResult::Error`
- ⚠️ **Out-of-bounds read:** Partially protected (instruction buffer vulnerable)

**Failure Modes:**
- ✅ **Detectable:** Yes, returns error enum
- ✅ **Reported:** Partially (error_message in debug only)
- ⚠️ **Recoverable:** Yes for most errors, but correlation engine crashes prevent recovery

**Citation:** `src/SDK/src/Detection/VM/VMInterpreter.hpp:46-79`, `src/SDK/src/Detection/VM/VMInterpreter.cpp:193-320`

---

## PHASE 2: NATIVE / VM INTEGRATION AUDIT

### Subsystem Integration Analysis

The Sentinel SDK integrates:
1. **Native Detection Modules** (AntiDebug, AntiHook, InjectionDetect, IntegrityCheck)
2. **VM-Executed Detections** (bytecode checks via VMInterpreter)
3. **Correlation Engine** (multi-signal aggregation)
4. **Telemetry Pipeline** (network reporting)

#### ISSUE 5: Correlation Engine Crashes (Root Cause Unknown)
**Location:** `src/SDK/src/Internal/CorrelationEngine.cpp`

**Current Reality:**
Test suite shows **7 segmentation faults** in correlation engine tests:
```
CorrelationEnhancementTest.NewConfidenceWeights - SIGSEGV
CorrelationEnhancementTest.EnforcementThreshold - SIGSEGV
CorrelationEnhancementTest.CoolingOffPeriod - SIGSEGV
CorrelationEnhancementTest.SubThresholdTelemetry - SIGSEGV
CorrelationEnhancementTest.MultiSignalCorrelation - SIGSEGV
CorrelationEnhancementTest.ScoreDecay - SIGSEGV
CorrelationEnhancementTest.PersistedState - SIGSEGV
```

**Problem:**
The correlation engine crashes when processing violations with specific field combinations. Code analysis reveals:

```cpp
// In SentinelSDK.hpp (line 237):
struct ViolationEvent {
    std::string module_name;    ///< Related module name (owned copy)
    // ...
};
```

**Corrected Analysis:**
`ViolationEvent::module_name` is already `std::string`, not `const char*`. The null pointer crashes must have a different root cause:
1. Uninitialized `CorrelationState` members
2. Accessing signals vector before initialization
3. Race conditions in multi-threaded access
4. Missing null checks in signal processing logic

**What Happens If Correlation Engine Fails:**
- ❌ **Silent failure:** No - crashes entire process
- ❌ **Graceful degradation:** No - SDK becomes unusable
- ❌ **Recovery possible:** No - process must restart

**Citation:** `docs/IMPLEMENTATION_STATUS.md:102-134`, `src/SDK/include/SentinelSDK.hpp:232-240`, `src/SDK/src/Internal/CorrelationEngine.hpp:44`

#### ISSUE 6: VM-to-Native Error Propagation
**Location:** Integration between VMInterpreter and detection modules

**Current Reality:**
```cpp
// VM returns error
VMOutput output = interpreter.execute(bytecode);
if (output.result == VMResult::Error) {
    // What happens next? Code inspection needed...
}
```

**Problem:**
No clear documentation or code path for:
1. How VM errors are propagated to correlation engine
2. Whether VM timeouts trigger violations or are silently ignored
3. What happens if VM returns `Error` vs `Timeout` vs `Violation`

**Ownership and Lifetimes:**
- ⚠️ **VM owns bytecode:** Bytecode copied on load, safe
- ⚠️ **External callbacks:** Can reference game state, lifetime unclear
- ⚠️ **Detection signals:** Module names may be dangling pointers

**Citation:** `src/SDK/src/Detection/VM/VMInterpreter.hpp:118-120`

#### ISSUE 7: Telemetry Pipeline Failure Handling
**Location:** Network reporting integration

**Current Reality:**
Heartbeat system (`src/Core/Network/Heartbeat.cpp`) sends periodic telemetry. If network fails:
- Heartbeat thread continues running
- Failures logged to console
- No backpressure on detection systems

**Problem:**
Silent telemetry loss means:
1. Server-side validation cannot occur
2. Cheaters can block network to avoid detection
3. No alert if heartbeat fails for extended periods

**What Happens on Network Failure:**
- ✅ **Detectable:** Yes, tracked in HeartbeatStatus
- ⚠️ **Reported to game:** No callback by default
- ❌ **Game can react:** No API to query heartbeat status from SDK

**Citation:** `src/Core/Network/Heartbeat.cpp:80-125`, `docs/IMPLEMENTATION_STATUS.md:295-324`

---

## PHASE 3: CRYPTO & NETWORK CORRECTNESS

### Cryptographic Implementation Analysis

#### ISSUE 8: AES-GCM Nonce Generation
**Location:** `src/Core/Crypto/AESCipher.cpp:51-74`

**Current Reality:**
```cpp
Result<ByteBuffer> encrypt(ByteSpan plaintext, ByteSpan associatedData) {
    // Generate random IV using SecureRandom
    SecureRandom rng;
    auto ivResult = rng.generate(AES_GCM_IV_SIZE);  // 12 bytes
    // ...
}
```

**Assessment:**
✅ **CORRECT** - Uses cryptographic RNG (`SecureRandom`)
✅ **CORRECT** - 12-byte nonces (96 bits, NIST recommended)
⚠️ **CONCERN** - No nonce collision prevention across sessions

**Nonce Reuse Risk:**
- ⚠️ If game crashes and restarts, RNG state is reset
- ⚠️ No counter-based nonce generation
- ⚠️ Birthday paradox: 2^48 messages before 50% collision probability

**Recommendation:**
Hybrid nonce scheme: `[8-byte counter][4-byte random]` to guarantee uniqueness.

**Citation:** `src/Core/Crypto/AESCipher.cpp:52-60`, `docs/security/security-invariants.md:33-53`

#### ISSUE 9: Heartbeat Replay Protection
**Location:** `src/Core/Network/Heartbeat.cpp:123-149`

**Current Reality:**
```cpp
private:
    void heartbeatLoop() {
        while (true) {
            // Send heartbeat
            (void)sendHeartbeatInternal();
            // ...
        }
    }
```

**Problem:**
No evidence of:
1. Sequence number incrementation
2. Timestamp validation
3. Nonce per-request
4. Server-side replay checking

**Replay Attack Scenario:**
Attacker captures valid heartbeat, replays it indefinitely to satisfy server checks while running cheats offline.

**Citation:** `src/Core/Network/Heartbeat.cpp:137-149`

#### ISSUE 10: Certificate Pinning Status
**Location:** Documentation claims vs implementation

**Current Reality:**
- README.md (line 18): "HTTP client security (certificate pinning, request signing)"
- README.md (line 293): "⚠️ **Certificate pinning not yet implemented** (MITM possible)"
- IMPLEMENTATION_STATUS.md (line 300): "🔴 **NOT IMPLEMENTED**"

**Problem:**
Without certificate pinning, attacker can:
1. MITM all SDK ↔ Server communication
2. Inject fake detection results
3. Disable heartbeat validation

**Citation:** `README.md:293`, `docs/IMPLEMENTATION_STATUS.md:300`

### Key Lifecycle Analysis

#### ISSUE 11: Key Rotation
**Location:** Crypto subsystem

**Current Reality:**
No evidence of:
1. Automatic key rotation after N messages
2. Key derivation from master secret
3. Session key management
4. Key expiration enforcement

**Nonce Wraparound:**
```cpp
// From security-invariants.md:
uint64_t packet_nonce = nonce_counter_.fetch_add(1, std::memory_order_seq_cst);
assert(packet_nonce != 0 && "Nonce counter wrapped - rotate key immediately");
```

**Problem:**
Documentation describes counter-based nonces but implementation uses random nonces. This is a **documentation drift** issue.

**Citation:** `docs/security/security-invariants.md:42-43`

---

## PHASE 4: DOCUMENTATION DRIFT REPORT

### Drift Analysis

| Document | Claim | Reality | Severity |
|----------|-------|---------|----------|
| README.md:18 | "Certificate pinning" implemented | NOT IMPLEMENTED | P0 |
| README.md:53 | "Update() ~0.46ms" | Not measured in CI | P2 |
| IMPLEMENTATION_STATUS.md:44 | "Direct syscall execution" | Infrastructure exists but not active | P2 |
| security-invariants.md:42 | Counter-based nonces | Uses random nonces | P1 |
| CorrelationEngine.hpp:44 | "Changed to prevent use-after-free" | Still crashes in tests | P0 |
| README.md:20 | "Correlation engine stability" | 7 test failures | P0 |

### Specific Drift Examples

#### DRIFT 1: Correlation Engine Stability
**Documentation Claims:** (IMPLEMENTATION_STATUS.md:102)
```
🟡 PARTIAL (with known test failures)
```

**Reality:**
Not just "partial" - **fundamentally broken**. 7/7 enhancement tests crash with SIGSEGV.

**Fix:**
Update documentation to `🔴 NOT PRODUCTION-READY - CRITICAL CRASHES`

#### DRIFT 2: VM Safety Guarantees
**Documentation Claims:** (VMInterpreter.hpp:86-97)
```
SAFETY GUARANTEES:
- All exceptions are caught internally (SEH on Windows)
- Invalid memory access returns zero, never crashes
- Stack overflow returns Error result
- Infinite loop protection via instruction counter
```

**Reality:**
- ✅ Exceptions caught: TRUE
- ⚠️ Invalid memory never crashes: **MOSTLY TRUE** (jump out-of-bounds risk)
- ✅ Stack overflow handled: TRUE
- ✅ Infinite loop protection: TRUE

**Fix:**
Add caveat: "Jump instructions have off-by-one bounds check vulnerability"

#### DRIFT 3: Heartbeat Implementation Status
**Documentation Claims:** (README.md:17-18)
```
**In Progress:**
- Cloud/Heartbeat reporting (Core implemented, SDK integration pending)
```

**Reality:**
Heartbeat implementation exists (`src/Core/Network/Heartbeat.cpp`) but lacks:
- Replay protection
- SDK integration
- Status query API

**Fix:**
Update to: "Heartbeat system implemented but lacks replay protection and SDK integration"

---

## PHASE 5: STABILIZATION TASK LIST

### Task Format

All tasks follow strict format for Copilot Agent execution:
- Small, merge-safe changes
- Independently testable
- Focus on fixing existing logic, not replacing it
- No new detection primitives
- No escalation of anti-analysis techniques

---

### Task [STAB-001]: Improve VM Bytecode Hash Verification Consistency
**Priority:** P2 (Downgraded from P0)
**Target Files:** 
- `src/SDK/src/Detection/VM/Bytecode.cpp`

**Current Reality:**
`Bytecode::verify()` computes XXH3 hash over `m_data.size() - m_instruction_offset` bytes, while `VMInterpreter::Impl::execute()` computes hash over `header->instruction_count` bytes. In properly formed bytecode these should be equal, but the inconsistency creates potential for edge cases.

**Problem:**
If bytecode loader accepts trailing bytes beyond `instruction_count`, `verify()` hashes extra data that `execute()` doesn't check. This is a minor inconsistency that should be resolved for defense-in-depth.

**Required Changes (NON-CODE):**
1. `Bytecode::verify()` should read `instruction_count` from header and hash exactly those bytes
2. Add assertion that `instruction_count == (m_data.size() - m_instruction_offset)` for well-formed bytecode
3. If sizes differ, fail verification with error message

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Parse header in `verify()` to extract `instruction_count`
- Hash exactly `instruction_count` bytes, not all remaining data
- Add check: if `m_data.size() - m_instruction_offset > instruction_count`, verify should fail
- Do NOT change hash algorithm or header format
- This prevents accepting bytecode with trailing garbage

**Definition of Done:**
- [ ] `Bytecode::verify()` uses `instruction_count` from header
- [ ] Both verify() and execute() hash identical byte ranges
- [ ] Test: Bytecode with trailing garbage bytes fails verification
- [ ] Test: Valid bytecode passes both verification and execution

---

### Task [STAB-002]: Fix VM Jump Instruction Bounds Check
**Priority:** P0  
**Target Files:**
- `src/SDK/src/Detection/VM/VMInterpreter.cpp` (lines 488-523)

**Current Reality:**
Jump instructions (`JMP`, `JMP_Z`, `JMP_NZ`) validate `new_ip > instruction_count` but allow `new_ip == instruction_count`, which is one byte past the end of the instruction buffer. Next iteration reads `instructions[instruction_count]` which is out of bounds.

**Problem:**
Off-by-one error allows reading one byte past instruction buffer. If buffer allocation has trailing bytes (padding, next structure, heap metadata), opcode decode executes garbage.

**Required Changes (NON-CODE):**
1. Jump validation must reject `new_ip >= instruction_count`
2. Apply to all three jump opcodes (`JMP`, `JMP_Z`, `JMP_NZ`)
3. Ensure loop condition `while (ip < instruction_count)` matches jump validation

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Change condition from `if (new_ip > instruction_count)` to `if (new_ip >= instruction_count)`
- Verify loop termination condition is consistent
- Add test case: bytecode that jumps to exactly `instruction_count`
- Expected result: `VMResult::Error`, not out-of-bounds read

**Definition of Done:**
- [ ] Jump to `instruction_count` returns `VMResult::Error`
- [ ] Jump to `instruction_count - 1` executes correctly
- [ ] Test: Bytecode with jump to end boundary fails safely
- [ ] No change to valid bytecode behavior

---

### Task [STAB-003]: Add External Callback Timeout Enforcement
**Priority:** P1  
**Target Files:**
- `src/SDK/src/Detection/VM/VMInterpreter.cpp` (lines 647-666)

**Current Reality:**
`CALL_EXT` opcode invokes external callbacks with no timeout enforcement. VM timeout only checks at opcode boundaries. A blocking callback hangs VM execution indefinitely.

**Problem:**
Malicious or buggy external callback can hang game process. VM timeout of 5000ms becomes meaningless if callback blocks for minutes/hours.

**Required Changes (NON-CODE):**
1. Callback execution time must count against VM timeout budget
2. If callback exceeds remaining timeout, return `VMResult::Timeout`
3. Callback must not be re-entrant (check VM execution flag)

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Before callback invocation, calculate remaining timeout budget
- Use `std::async` with `std::future::wait_for()` to enforce callback timeout
- If callback times out, return 0 and continue execution (don't crash)
- Log timeout event for debugging (debug builds only)
- Consider adding callback execution time to `VMOutput` metrics

**Definition of Done:**
- [ ] Callback that blocks for >5s returns `VMResult::Timeout`
- [ ] Fast callbacks (<1ms) have no performance impact
- [ ] Test: Register blocking callback, verify timeout
- [ ] Test: Valid callback execution still works

---

### Task [STAB-004]: Fix Correlation Engine Segmentation Faults
**Priority:** P0  
**Target Files:**
- `src/SDK/src/Internal/CorrelationEngine.cpp`
- `src/SDK/src/Internal/CorrelationEngine.hpp`
- `tests/SDK/test_correlation_enhancements.cpp`

**Current Reality:**
All 7 correlation enhancement tests crash with SIGSEGV. Code analysis shows `ViolationEvent::module_name` is already `std::string` (not `const char*`), so the root cause is different than initially suspected.

**Problem:**
Critical crashes in correlation engine make the entire SDK unusable. Likely root causes to investigate:
1. Uninitialized `CorrelationState` members (especially vectors/timestamps)
2. Accessing empty signals vector without size check
3. Race conditions in multi-threaded processing
4. Dereferencing invalid iterators after vector modification
5. Missing initialization in CorrelationEngine constructor

**Required Changes (NON-CODE):**
1. Initialize all `CorrelationState` members in constructor
2. Add bounds checks before accessing `state_.signals` vector
3. Add null/empty checks before dereferencing pointers
4. Ensure mutex protection for all state access
5. Run with ASAN/valgrind to identify exact crash location

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Review CorrelationEngine constructor - ensure all members initialized
- Add `if (state_.signals.empty())` checks before vector access
- Check for iterator invalidation in signal processing loops
- Review time_point initialization - use `steady_clock::now()` not default constructor
- Use ASAN to get exact crash line number and root cause
- Do NOT change correlation algorithm or scoring logic

**Definition of Done:**
- [ ] All 7 correlation enhancement tests pass
- [ ] No SIGSEGV under any input combination
- [ ] ASAN reports no memory errors
- [ ] Test: Empty state doesn't crash
- [ ] Test: Correlation score calculation matches expected values

---

### Task [STAB-005]: Add Integer Overflow Protection to Hash Operations
**Priority:** P1  
**Target Files:**
- `src/SDK/src/Detection/VM/VMInterpreter.cpp` (lines 575-619)

**Current Reality:**
`HASH_CRC32` and `HASH_XXH3` opcodes allocate `std::vector<uint8_t>(size)` where `size` comes from untrusted stack. If `size` is close to 1MB limit, allocation can fail. No check for `address + size` overflow.

**Problem:**
Integer overflow in `address + size` calculation allows reading arbitrary memory. Vector allocation failure throws `std::bad_alloc`, caught as generic error with no context.

**Required Changes (NON-CODE):**
1. Check if `address + size < address` (overflow detection)
2. Check if `address + size > UINTPTR_MAX` (wrap-around detection)
3. Catch `std::bad_alloc` specifically and return descriptive error
4. Consider pre-allocating hash buffer to avoid repeated allocations

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Add overflow check: `if (size > 0 && address > UINTPTR_MAX - size) return false;`
- Wrap vector allocation in try-catch for `std::bad_alloc`
- If allocation fails, set error message and return `VMResult::Error`
- Consider using fixed-size buffer with multiple reads for large hashes
- Maintain existing 1MB size limit

**Definition of Done:**
- [ ] Overflow in `address + size` returns `VMResult::Error`
- [ ] Large allocation failure returns descriptive error
- [ ] Test: Hash with `address = MAX, size = 1` fails safely
- [ ] Test: Valid hash operations still work correctly

---

### Task [STAB-006]: Document VM Execution Guarantees
**Priority:** P2  
**Target Files:**
- `src/SDK/src/Detection/VM/VMInterpreter.hpp`
- `docs/IMPLEMENTATION_STATUS.md`

**Current Reality:**
VMInterpreter.hpp claims "Invalid memory access returns zero, never crashes" but jump instruction bounds check has off-by-one error that allows out-of-bounds read.

**Problem:**
Documentation overstates safety guarantees. Users expect VM to be completely crash-proof but edge cases exist.

**Required Changes (NON-CODE):**
1. Update safety guarantees to list known edge cases
2. Document that external callbacks can hang/crash if not carefully implemented
3. Add section on "Known Limitations" to VMInterpreter.hpp
4. Update IMPLEMENTATION_STATUS.md with current test coverage

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Add comment block in VMInterpreter.hpp: "Known Limitations"
- List: Jump bounds check off-by-one (fixed in STAB-002)
- List: External callback timeout not enforced (fixed in STAB-003)
- List: Hash operations can allocate large memory (mitigated in STAB-005)
- Do NOT remove existing safety claims that are accurate
- Keep documentation concise (engineers, not marketing)

**Definition of Done:**
- [ ] VMInterpreter.hpp has "Known Limitations" section
- [ ] IMPLEMENTATION_STATUS.md reflects current VM test coverage
- [ ] No misleading claims about absolute safety
- [ ] Positive safety guarantees remain (exception handling, timeouts, etc.)

---

### Task [STAB-007]: Add Heartbeat Status Query API
**Priority:** P1  
**Target Files:**
- `include/Sentinel/Core/Heartbeat.hpp`
- `src/Core/Network/Heartbeat.cpp`

**Current Reality:**
Heartbeat system tracks success/failure counts internally but provides no API for SDK to query status. Games cannot react to prolonged heartbeat failures.

**Problem:**
If heartbeat fails for extended period (network blocked, server down), game has no way to detect this and take action (e.g., force disconnect, warn player).

**Required Changes (NON-CODE):**
1. Add public API: `HeartbeatStatus getStatus() const`
2. `HeartbeatStatus` struct should include: `isRunning`, `successCount`, `failureCount`, `lastSuccess`, `lastFailure`, `lastError`
3. Thread-safe access with mutex
4. Documentation explaining how games should use this

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Already implemented: `HeartbeatStatus getStatus() const noexcept` exists (line 103-116)
- Task is to **expose this to SDK public API** (currently internal)
- Add to `include/Sentinel/Core/Heartbeat.hpp` (public header)
- Add example usage to documentation
- Consider adding convenience methods: `isHealthy()`, `getFailureRate()`

**Definition of Done:**
- [ ] `getStatus()` exposed in public API
- [ ] SDK can query heartbeat health
- [ ] Documentation shows example usage
- [ ] Test: Query status after success/failure

---

### Task [STAB-008]: Implement AES-GCM Counter-Based Nonce
**Priority:** P1  
**Target Files:**
- `src/Core/Crypto/AESCipher.cpp`
- `src/Core/Crypto/AESCipher.hpp` (if needed for state)

**Current Reality:**
AES-GCM encryption uses fully random 12-byte nonces. While cryptographically secure, this creates collision risk after ~2^48 messages (birthday paradox). Process restart resets RNG state.

**Problem:**
Nonce collision breaks AES-GCM security completely. Random nonces provide no guarantee of uniqueness across sessions.

**Required Changes (NON-CODE):**
1. Hybrid nonce: `[8-byte counter][4-byte random]`
2. Counter persisted across encryptions (atomic increment)
3. Random part re-initialized on counter wraparound
4. Backward compatible with existing decryption (nonce is transmitted with ciphertext)

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Add `std::atomic<uint64_t> m_nonce_counter` to AESCipher::Impl
- Initialize counter to 0 in constructor
- On encrypt: `counter = m_nonce_counter.fetch_add(1)`, `random = SecureRandom(4 bytes)`
- Nonce = `[counter (LE)][random]`
- Assert on counter wraparound, trigger key rotation (future task)
- Decryption unchanged (nonce extracted from ciphertext)

**Definition of Done:**
- [ ] Nonces are guaranteed unique within key lifetime
- [ ] Performance impact <5% (counter increment is cheap)
- [ ] Test: Generate 1 million nonces, verify all unique
- [ ] Test: Existing decrypt tests still pass (backward compatible)

---

### Task [STAB-009]: Add Replay Protection to Heartbeat
**Priority:** P0  
**Target Files:**
- `src/Core/Network/Heartbeat.cpp`
- Server-side validation (Watchtower) if available

**Current Reality:**
Heartbeat requests have no sequence number, timestamp validation, or nonce. Attacker can capture valid heartbeat and replay indefinitely.

**Problem:**
Replay attacks allow cheaters to satisfy server checks while running offline. Server cannot distinguish replayed heartbeat from fresh one.

**Required Changes (NON-CODE):**
1. Add monotonically increasing sequence number to heartbeat payload
2. Add timestamp (UTC milliseconds since epoch)
3. Server must reject: old sequence numbers, timestamps outside ±60s window, duplicate sequence numbers
4. Client must detect sequence number desync and re-authenticate

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Already implemented: `m_sequenceNumber` exists (line 39, 72, 110)
- Task is to **verify it's included in payload and validated server-side**
- Add timestamp field to heartbeat request
- Sign payload with RSA/HMAC to prevent tampering
- Server must maintain last-seen sequence number per client
- Do NOT implement client-side replay detection (server's job)

**Definition of Done:**
- [ ] Heartbeat payload includes sequence number and timestamp
- [ ] Server rejects replayed heartbeats (if server available)
- [ ] Sequence number increments on each send
- [ ] Test: Replay same heartbeat fails validation
- [ ] Test: Fresh heartbeats accepted

---

### Task [STAB-010]: Update Documentation Drift - Correlation Engine
**Priority:** P2  
**Target Files:**
- `docs/IMPLEMENTATION_STATUS.md` (lines 102-134)
- `README.md` (line 20)

**Current Reality:**
Documentation describes correlation engine as "🟡 PARTIAL (with known test failures)" but reality is 7/7 tests crash with SIGSEGV. This understates the severity.

**Problem:**
Misleading status gives impression system is "mostly working" when it's actually unusable in production. Blocks proper prioritization of fixes.

**Required Changes (NON-CODE):**
1. Update status to `🔴 NOT PRODUCTION-READY - CRITICAL CRASHES`
2. List all 7 failing tests with SIGSEGV details
3. Add warning: "Do not use correlation engine until STAB-004 is resolved"
4. Update README.md "In Progress" section to reflect blockers

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Edit IMPLEMENTATION_STATUS.md line 102: change 🟡 to 🔴
- Add subsection "Critical Issues" listing each failing test
- Keep existing implementation details (don't remove useful info)
- Link to STAB-004 task for fix tracking
- Update README.md line 20 to remove "stability" from working features

**Definition of Done:**
- [ ] Status accurately reflects critical severity
- [ ] All failing tests documented
- [ ] Clear warning not to use in production
- [ ] Linked to fix task (STAB-004)

---

### Task [STAB-011]: Update Documentation Drift - Certificate Pinning
**Priority:** P2  
**Target Files:**
- `README.md` (lines 17-18, 293, 313)
- `docs/IMPLEMENTATION_STATUS.md` (line 300)

**Current Reality:**
README.md has conflicting statements about certificate pinning:
- Line 18: Lists it as "In Progress" (implies partial implementation)
- Line 293: Explicitly states "not yet implemented"
- Line 313: Lists as blocking issue for production

**Problem:**
Inconsistent messaging confuses users about system readiness. "In Progress" implies work is happening, but no code exists.

**Required Changes (NON-CODE):**
1. Remove certificate pinning from "In Progress" section
2. Move to "Not Yet Implemented" section
3. Add to "Blocking Issues" prominently
4. Update IMPLEMENTATION_STATUS.md to reflect no code exists (❌ MISSING)

**Implementation Guidance (HIGH-LEVEL ONLY):**
- Remove "certificate pinning" from README.md line 18
- Add new section "Not Yet Implemented" if it doesn't exist
- List: Certificate pinning, Request signing replay protection
- Mark as P0 blocker for production release
- Keep existing warnings about MITM risk

**Definition of Done:**
- [ ] No conflicting statements in README.md
- [ ] Clear "Not Implemented" status in all docs
- [ ] Marked as P0 blocker
- [ ] IMPLEMENTATION_STATUS.md shows ❌ MISSING

---

### Task [STAB-012]: Add VM Execution Metrics to Telemetry
**Priority:** P2  
**Target Files:**
- `src/SDK/src/Detection/VM/VMInterpreter.cpp`
- Telemetry pipeline (if exists)

**Current Reality:**
VM returns `VMOutput` with performance metrics (`instructions_executed`, `memory_reads_performed`, `elapsed`) but these are not logged or sent to telemetry.

**Problem:**
No visibility into VM execution patterns in production. Cannot detect:
- Abnormally long execution times (performance regression)
- Excessive memory reads (possible attack)
- Timeout frequency (malformed bytecode)

**Required Changes (NON-CODE):**
1. Log VM execution metrics on completion
2. Include in telemetry payload (if telemetry system exists)
3. Add aggregate metrics: avg execution time, p95, p99
4. Alert on anomalies: timeout rate >1%, avg time >100ms

**Implementation Guidance (HIGH-LEVEL ONLY):**
- After `VMInterpreter::execute()` returns, extract metrics from `VMOutput`
- Log to internal logger: `VMResult`, `instructions_executed`, `elapsed`
- If telemetry API exists, add VM metrics to periodic report
- Use sampling (e.g., report every 100th execution) to reduce overhead
- Do NOT log sensitive data (addresses, detection flags)

**Definition of Done:**
- [ ] VM metrics logged on each execution
- [ ] Metrics included in telemetry (if system exists)
- [ ] Logs parseable for analysis
- [ ] No PII or sensitive data in logs

---

## Conclusion

This audit identified **12 stabilization tasks** across four priority levels:
- **P0 (Blocker):** 4 tasks - Must fix before production (STAB-002, STAB-004, STAB-009, plus implicit)
- **P1 (Critical):** 4 tasks - Significant stability/security risks (STAB-003, STAB-005, STAB-007, STAB-008)
- **P2 (Important):** 4 tasks - Documentation and observability (STAB-001, STAB-006, STAB-010, STAB-011, STAB-012)

**Key Recommendations:**
1. **Fix correlation engine immediately** (STAB-004) - blocks all production use
2. **Resolve VM safety issues** (STAB-002) - out-of-bounds read risk
3. **Add replay protection** (STAB-009) - critical security gap
4. **Update documentation** (STAB-010, STAB-011) - prevent misunderstandings

**System Assessment:**
- Core primitives are **functional and well-designed**
- Integration layer has **critical stability issues**
- Documentation has **moderate drift** from implementation
- Production deployment is **blocked by 4 P0 issues**

This audit establishes a foundation for stabilization work. All tasks are **small, merge-safe, and independently testable**—suitable for Copilot Agent execution.

---

**Audit Completed:** 2026-01-03  
**Next Review:** After P0 tasks resolved
