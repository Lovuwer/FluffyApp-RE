# Detection Confidence Model

**Classification:** Internal Engineering Reference  
**Purpose:** Define signal strength, bypass cost, and response strategy for each detector  
**Last Updated:** 2025-01-29

---

## Table of Contents

1. [Confidence Model Overview](#confidence-model-overview)
2. [Severity Classification](#severity-classification)
3. [Detector Confidence Matrix](#detector-confidence-matrix)
4. [Response Action Mapping](#response-action-mapping)
5. [Correlation Rules](#correlation-rules)
6. [False Positive Management](#false-positive-management)

---

## Confidence Model Overview

### Purpose

Not all detections are equal. This model assigns **confidence scores** to each detector based on:
- **Signal Strength**: How reliable is the detection?
- **Bypass Cost**: How much effort to defeat?
- **False Positive Risk**: How often does it trigger incorrectly?

### Confidence Levels

| Level | Meaning | Allowed Actions | Example |
|-------|---------|-----------------|---------|
| **CRITICAL** | 95%+ confidence, kernel bypass required | Ban, Kick, Terminate | Honeypot modified |
| **HIGH** | 80-95% confidence, user-mode bypass possible | Report, Warn, Log | Debug port detected |
| **MEDIUM** | 60-80% confidence, moderate false positive risk | Report, Log | Timing anomaly |
| **LOW** | <60% confidence, high false positive risk | Log only | Single timing outlier |
| **INFO** | No security implication | Log only | Hypervisor detected |

---

## Severity Classification

### Methodology

Each detector is evaluated on three axes:

1. **Signal Strength**
   - How hard is it to trigger a false positive?
   - Can the detection be trusted in isolation?

2. **Bypass Cost**
   - What tools/knowledge required to defeat?
   - Is bypass trivial (free tools) or requires expertise?

3. **False Positive Rate**
   - Measured or estimated percentage
   - Impact on legitimate users

### Formula

```
Confidence = (Signal_Strength * 0.5) + (Bypass_Cost * 0.3) + ((100 - FP_Rate) * 0.2)
```

Where:
- `Signal_Strength`: 0-100 (higher = more reliable)
- `Bypass_Cost`: 0-100 (higher = more expensive to bypass)
- `FP_Rate`: 0-100 (percentage of false positives)

---

## Detector Confidence Matrix

### AntiDebug Detectors

| Detector | Signal Strength | Bypass Cost | FP Risk | Overall Confidence | Severity | Action |
|----------|----------------|-------------|---------|-------------------|----------|---------|
| **IsDebuggerPresent** | Low (20) | Very Low (10) | Very Low (1%) | 28/100 | LOW | Log only |
| **PEB.BeingDebugged** | Low (25) | Very Low (15) | Very Low (1%) | 33/100 | LOW | Log only |
| **Debug Port (NtQueryInformationProcess)** | High (80) | Medium (50) | Low (5%) | 78/100 | HIGH | Report + Warn |
| **Debug Object Handle** | High (85) | Medium (55) | Low (5%) | 82/100 | HIGH | Report + Warn |
| **Hardware Breakpoints (Current Thread)** | Very High (90) | Medium (60) | Very Low (2%) | 88/100 | CRITICAL | Report + Notify |
| **Hardware Breakpoints (All Threads)** | High (80) | Medium (55) | Medium (10%) | 76/100 | HIGH | Report + Log |
| **NtGlobalFlag** | Medium (60) | Low (30) | Low (5%) | 60/100 | MEDIUM | Log |
| **Heap Flags** | Medium (55) | Low (25) | Medium (15%) | 53/100 | MEDIUM | Log |
| **PEB Patching Detection** | High (75) | Medium (50) | Low (5%) | 73/100 | HIGH | Report |
| **Parent Process Debugger** | Medium (70) | Low (20) | High (20%) | 60/100 | MEDIUM | Log |
| **Timing Anomaly** | Low (40) | Low (30) | Very High (30%) | 40/100 | LOW | Log only |
| **SEH Integrity** | Low (45) | Low (25) | High (20%) | 43/100 | LOW | Log only |

**Recommended Actions:**
- Single detection: LOG ONLY (except hardware breakpoints in current thread)
- 2+ detections: WARN + REPORT
- 3+ detections (including hardware BP): KICK or BAN

**Bypass Cost Explanation:**
- IsDebuggerPresent: FREE (ScyllaHide, one-click)
- Debug Port/Object: FREE (ScyllaHide handles these)
- Hardware Breakpoints: MEDIUM (requires clearing DR registers before context query)
- Parent Process: LOW (launch from explorer instead of debugger)

---

### AntiHook Detectors

| Detector | Signal Strength | Bypass Cost | FP Risk | Overall Confidence | Severity | Action |
|----------|----------------|-------------|---------|-------------------|----------|---------|
| **Inline Hook (Periodic Scan)** | Medium (60) | Medium (50) | Medium (10%) | 66/100 | MEDIUM | Report + Log |
| **Inline Hook (SENTINEL_PROTECTED_CALL)** | Very High (95) | Very High (90) | Very Low (1%) | 96/100 | CRITICAL | Ban |
| **IAT Hook** | Low (50) | Very Low (20) | Low (5%) | 45/100 | LOW | Log |
| **Delay-Load IAT Hook** | Low (45) | Very Low (15) | Medium (10%) | 41/100 | LOW | Log |
| **Honeypot Modified** | Very High (98) | Very High (95) | None (0%) | 99/100 | CRITICAL | Ban immediately |

**Recommended Actions:**
- Periodic inline hook: LOG (high TOCTOU risk)
- SENTINEL_PROTECTED_CALL: BAN (inline verification, TOCTOU-resistant)
- IAT hook: LOG ONLY (primitive technique, many false positives from legitimate hooking)
- Honeypot: BAN IMMEDIATELY (never called legitimately, 100% cheat indicator)

**Bypass Cost Explanation:**
- Periodic scan: LOW (TOCTOU, restore-on-scan)
- Inline verification: VERY HIGH (requires hooking before inline check runs, kernel page tables, or hardware BP)
- IAT: VERY LOW (restore during check, trivial)
- Honeypot: VERY HIGH (can identify via static analysis, but skipping reduces cheat functionality)

---

### Integrity Check Detectors

| Detector | Signal Strength | Bypass Cost | FP Risk | Overall Confidence | Severity | Action |
|----------|----------------|-------------|---------|-------------------|----------|---------|
| **Code Section Hash Mismatch** | High (75) | Medium (60) | Medium (15%) | 74/100 | HIGH | Report + Warn |
| **Protected Region Modified** | Medium (65) | Medium (55) | Medium (12%) | 67/100 | MEDIUM | Report |
| **Import Table Hook** | Low (40) | Low (25) | Low (8%) | 43/100 | LOW | Log |

**Recommended Actions:**
- Code section: WARN on first detection, BAN on repeated (3+) detections
- Protected region: REPORT, require correlation with other signals
- IAT: LOG ONLY

**Bypass Cost Explanation:**
- Code section: MEDIUM (restore-on-scan, hook SafeHash)
- Protected region: MEDIUM (timing-based modification, hook VirtualQuery)
- IAT: LOW (trivial restore-on-scan)

**False Positive Sources:**
- JIT compilation (.NET, Unity IL2CPP, Lua)
- Self-modifying code (virtualization, packers)
- Hot-patching, live updates
- ASLR relocation

---

### Injection Detection

| Detector | Signal Strength | Bypass Cost | FP Risk | Overall Confidence | Severity | Action |
|----------|----------------|-------------|---------|-------------------|----------|---------|
| **Unknown Module Loaded** | Medium (55) | Low (30) | High (20%) | 53/100 | MEDIUM | Log + Report |
| **MEM_PRIVATE Executable** | Medium (60) | Medium (50) | Medium (15%) | 62/100 | MEDIUM | Report |
| **Suspicious Thread Start** | Low (50) | Low (35) | High (25%) | 48/100 | LOW | Log |
| **Unsigned Module** | Very Low (30) | Very Low (10) | Very High (40%) | 28/100 | LOW | Log only |
| **JIT Pattern Mismatch** | Low (45) | Medium (50) | High (20%) | 48/100 | LOW | Log |

**Recommended Actions:**
- Unknown module: REPORT if not in whitelist, LOG if whitelisted
- MEM_PRIVATE: REPORT if >1MB and no JIT signature, otherwise LOG
- Suspicious thread: LOG ONLY (too many false positives from game engines)
- Unsigned: LOG ONLY (many legitimate unsigned DLLs)
- JIT pattern: LOG (database incomplete, high FP risk)

**Bypass Cost Explanation:**
- Unknown module: LOW (inject before init, or into whitelisted module)
- MEM_PRIVATE: MEDIUM (inject into existing module code cave)
- Thread start: LOW (hijack existing thread)
- Unsigned: VERY LOW (trivial to avoid loading unsigned)

**False Positive Sources:**
- Game engine JIT (Unity, UE4, .NET)
- Graphics driver injection (overlays, recording)
- Accessibility tools (screen readers)
- Legitimate unsigned DLLs (many game engines use these)

---

### Speed Hack Detection

| Detector | Signal Strength | Bypass Cost | FP Risk | Overall Confidence | Severity | Action |
|----------|----------------|-------------|---------|-------------------|----------|---------|
| **Time Source Deviation (Client-Side)** | Very Low (30) | Very Low (15) | Very High (40%) | 30/100 | LOW | Log only |
| **Time Source Deviation (Server-Validated)** | Very High (90) | High (80) | Low (5%) | 89/100 | HIGH | Kick + Ban |

**Recommended Actions:**
- Client-side: LOG ONLY (all time sources hookable, high FP rate in VMs)
- Server-validated: KICK on 2nd violation, BAN on 3rd

**Bypass Cost Explanation:**
- Client-side: VERY LOW (hook all time sources consistently)
- Server-validated: HIGH (requires packet manipulation or kernel time hooks)

**Critical Note:** **CLIENT-SIDE SPEED DETECTION IS NOT RELIABLE**. Server validation is MANDATORY for production.

**False Positive Sources:**
- Virtual machines (imprecise timekeeping)
- Hibernation/sleep/resume
- Power management (CPU frequency scaling)
- Time zone changes, NTP sync
- Aggressive frame limiting

---

### Memory Protection

| Detector | Signal Strength | Bypass Cost | FP Risk | Overall Confidence | Severity | Action |
|----------|----------------|-------------|---------|-------------------|----------|---------|
| **Protected Region Modified** | Medium (65) | Medium (55) | Medium (10%) | 68/100 | MEDIUM | Report |
| **Guard Page Violation** | High (80) | High (75) | Low (5%) | 81/100 | HIGH | Report + Notify |

**Recommended Actions:**
- Region modified (periodic): REPORT
- Guard page (real-time): NOTIFY + REPORT

**Bypass Cost Explanation:**
- Periodic check: MEDIUM (modify between checks)
- Guard page: HIGH (requires hooking exception handler or kernel write)

---

### Value Protection

| Detector | Signal Strength | Bypass Cost | FP Risk | Overall Confidence | Severity | Action |
|----------|----------------|-------------|---------|-------------------|----------|---------|
| **Obfuscated Value Checksum Fail** | Medium (60) | Low (40) | Low (8%) | 58/100 | MEDIUM | Log + Report |
| **Redundant Copy Mismatch** | High (75) | Medium (60) | Very Low (2%) | 76/100 | HIGH | Report + Warn |

**Recommended Actions:**
- Checksum: REPORT (could be memory corruption)
- Redundant copy: WARN + REPORT (strong indicator)

**Note:** Value protection is **obfuscation**, not **prevention**. Should be paired with server-side validation.

---

### Cryptographic / Network

| Detector | Signal Strength | Bypass Cost | FP Risk | Overall Confidence | Severity | Action |
|----------|----------------|-------------|---------|-------------------|----------|---------|
| **Request Signature Invalid** | Very High (95) | Very High (90) | Very Low (1%) | 95/100 | CRITICAL | Reject + Ban |
| **Replay Attack Detected** | Very High (90) | High (80) | Very Low (2%) | 90/100 | CRITICAL | Reject + Ban |
| **Certificate Pinning Violation** | High (85) | Medium (65) | Low (5%) | 83/100 | HIGH | Reject + Report |
| **Excessive Failed Auth** | Medium (70) | N/A | Medium (10%) | 68/100 | MEDIUM | Rate limit |

**Recommended Actions:**
- Invalid signature: REJECT request + BAN after 3 attempts
- Replay: REJECT + immediate BAN
- Cert pinning: REJECT connection + REPORT
- Failed auth: Rate limit after 5 failures, block after 20

---

## Response Action Mapping

### Action Severity Ladder

```
┌─────────────────────────────────────────────────────────────────┐
│ INFORMATION  →  LOG  →  REPORT  →  WARN  →  KICK  →  BAN       │
│                                                                 │
│ ╔═══════════╗  ╔═════╗  ╔═══════╗  ╔══════╗  ╔══════╗  ╔═════╗ │
│ ║ Telemetry ║  ║ Low ║  ║ Medium║  ║ High ║  ║Critic║  ║Crit ║ │
│ ║   only    ║  ║Conf.║  ║ Conf. ║  ║Conf. ║  ║+Corr ║  ║+Rep ║ │
│ ╚═══════════╝  ╚═════╝  ╚═══════╝  ╚══════╝  ╚══════╝  ╚═════╝ │
└─────────────────────────────────────────────────────────────────┘
```

### Action Definitions

| Action | Purpose | When to Use | User Impact |
|--------|---------|-------------|-------------|
| **LOG** | Telemetry collection | Low confidence, info gathering | None |
| **REPORT** | Cloud telemetry | Medium confidence, needs correlation | None (silent) |
| **WARN** | User notification | High confidence, deterrence | Warning message |
| **KICK** | Session termination | High confidence + repeat | Disconnect |
| **BAN** | Permanent removal | Critical confidence or 3+ kicks | Cannot reconnect |

---

## Correlation Rules

### Rule 1: Debug Detection Correlation

**Trigger:** 3+ different debug detectors fire within 60 seconds

**Example:**
- Debug Port detected
- Hardware breakpoints detected
- Parent process is debugger

**Action:** KICK + BAN on 2nd occurrence  
**Confidence:** HIGH (95%)

---

### Rule 2: Hook + Injection Correlation

**Trigger:** Hook detected + Unknown module loaded within 5 minutes

**Example:**
- IAT hook on VirtualProtect
- Unknown DLL loaded (cheat.dll)

**Action:** REPORT + WARN, BAN on repeat  
**Confidence:** HIGH (90%)

---

### Rule 3: Memory Modification Pattern

**Trigger:** 5+ protected regions modified within 10 seconds

**Example:**
- Health value modified
- Ammo value modified
- Position coordinates modified

**Action:** KICK immediately  
**Confidence:** HIGH (85%)

---

### Rule 4: Timing + Speed Anomaly

**Trigger:** Timing anomaly + Server-validated speed deviation

**Example:**
- Client reports 150% elapsed time
- Server validates 140% movement speed

**Action:** BAN on 2nd occurrence  
**Confidence:** VERY HIGH (95%)

---

### Rule 5: Honeypot Bypass Attempt

**Trigger:** Honeypot modified OR suspicious function scan pattern

**Example:**
- Honeypot function prologue changed
- Sequential memory reads of all registered functions (hook scanner)

**Action:** BAN immediately  
**Confidence:** CRITICAL (99%)

---

## False Positive Management

### Known False Positive Sources

| Detector | FP Source | Mitigation |
|----------|-----------|------------|
| **Timing Anomaly** | VMs, hibernation | Increase threshold in VM environments, ignore first 5 min after resume |
| **Parent Process** | Visual Studio | Whitelist devenv.exe in debug builds |
| **JIT Detection** | Unity, .NET, UE4 | Maintain JIT signature database |
| **Code Integrity** | Hot-patching, ASLR | Whitelist known hot-patch patterns |
| **Thread Detection** | Game engine fiber API | Allow whitelist configuration |
| **Unsigned Module** | Graphics overlays | Whitelist known overlay DLLs |

### False Positive Rates (Target)

| Severity | Max Acceptable FP Rate | Current Estimate |
|----------|----------------------|------------------|
| CRITICAL | 0.01% (1 in 10,000) | ~0.05% |
| HIGH | 0.1% (1 in 1,000) | ~0.5% |
| MEDIUM | 1% (1 in 100) | ~2% |
| LOW | 5% (1 in 20) | ~10% |

**Note:** Current estimates are conservative. Actual FP rates should be measured via telemetry.

---

## Decision Matrix: When to Ban

### Safe to Ban (High Confidence)

✅ Honeypot modified  
✅ SENTINEL_PROTECTED_CALL detects hook  
✅ 3+ correlated detectors (debug + hook + injection)  
✅ Server-validated speed hack (2+ occurrences)  
✅ Invalid request signature (3+ attempts)  
✅ Replay attack  

### Risky to Ban (Requires Investigation)

⚠️ Single timing anomaly  
⚠️ Single IAT hook  
⚠️ Unknown unsigned module  
⚠️ Parent process is debugger (dev environment)  
⚠️ Single code integrity violation  

### Never Ban Automatically

❌ Any single LOW confidence detector  
❌ VM detection (info only)  
❌ Hypervisor detection (info only)  
❌ First-time occurrences without correlation  

---

## Recommended Response Configuration

### Casual Game (Low Stakes)

```cpp
config.default_action = ResponseAction::Log | ResponseAction::Report;
// Most lenient: Log everything, ban only on critical violations
```

### Competitive Game (Medium Stakes)

```cpp
config.default_action = ResponseAction::Report | ResponseAction::Notify;
// Balanced: Report all, notify user on high confidence, kick on critical
```

### Tournament/Ranked (High Stakes)

```cpp
config.default_action = ResponseAction::Report | ResponseAction::Warn | ResponseAction::Kick;
// Strict: Warn on medium, kick on high, ban on critical
```

---

## Telemetry for Confidence Tuning

### Required Metrics

For each detector, track:
- **True Positive Rate:** Known cheaters caught
- **False Positive Rate:** Legitimate users flagged
- **Bypass Rate:** Known bypasses that evaded detection
- **Correlation Effectiveness:** Multi-signal detection accuracy

### Continuous Improvement

1. **Weekly Review:** Analyze FP reports from telemetry
2. **Threshold Tuning:** Adjust based on FP/TP ratio
3. **Whitelist Updates:** Add legitimate tools triggering FPs
4. **Correlation Rules:** Add new multi-signal patterns

---

## Conclusion

**Key Principles:**

1. **No Single Detector is Perfect:** All have false positives and bypass vectors
2. **Correlation is Key:** Multiple weak signals = strong evidence
3. **Server Validation Required:** Client-side detection is supplementary
4. **Honest Severity:** Don't mark LOW confidence as CRITICAL
5. **User Experience Matters:** Minimize false positives on critical actions (ban)

**Default Strategy:**
- LOG everything for telemetry
- REPORT on medium+ confidence
- WARN on high confidence (if enabled)
- KICK on critical + correlation
- BAN on critical + repeat or honeypot

**This model should be treated as a living document, updated based on real-world telemetry.**
