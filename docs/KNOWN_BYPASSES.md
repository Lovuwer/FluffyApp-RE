# Known Bypasses: High-Level Classes

**Classification:** Internal Security Review  
**Purpose:** Document high-level bypass classes without providing implementation details  
**Last Updated:** 2025-01-29

---

## ⚠️ IMPORTANT DISCLAIMER

This document describes **abstract bypass classes**, not step-by-step techniques. It is intended for defensive engineering, not for creating exploits. Do not use this information to develop cheat tools.

**Purpose:** Understanding how security fails helps build stronger defenses.

---

## Table of Contents

1. [Kernel Control Bypasses](#kernel-control-bypasses)
2. [Restore-on-Scan Bypasses](#restore-on-scan-bypasses)
3. [Crash-Based Bypasses](#crash-based-bypasses)
4. [Timing Manipulation Bypasses](#timing-manipulation-bypasses)
5. [Desynchronization Attacks](#desynchronization-attacks)
6. [Memory-Based Bypasses](#memory-based-bypasses)
7. [Network-Based Bypasses](#network-based-bypasses)
8. [Code Analysis Bypasses](#code-analysis-bypasses)

---

## Kernel Control Bypasses

**Class:** Kernel-Mode Privilege Escalation  
**Complexity:** HIGH  
**Cost:** $100-$500 (unsigned driver) or Free (test mode)  
**Detection:** IMPOSSIBLE from user-mode

### Abstract Description

Attacker loads kernel-mode driver (Ring 0) that has full control over system. User-mode anti-cheat (Ring 3) cannot validate kernel state.

### Attack Surface

- All memory reads/writes
- All syscalls (NtQueryInformationProcess, etc.)
- Page table manipulation
- Interrupt handling
- Device driver loading

### Why User-Mode Cannot Defend

- No API to validate kernel memory
- Kernel controls all syscalls that user-mode calls
- PatchGuard can be bypassed
- HVCI/KMCI are optional security features

### Bypass Examples (Abstract)

1. **SSDT Hooking**: Patch System Service Dispatch Table to intercept syscalls
2. **Page Table Manipulation**: Create shadow pages (read vs execute mappings)
3. **Memory Hiding**: Lie to VirtualQuery about memory regions
4. **Debug Object Hiding**: Patch kernel to hide debug objects from queries

### Defense Strategy

**What CANNOT Work:**
- User-mode validation of kernel state
- Any check that uses syscalls (kernel controls syscalls)

**What MIGHT Help:**
- Require Secure Boot + HVCI (reduces kernel driver attack surface)
- Detect known cheat drivers by hash/signature
- Server-side behavioral analysis (kernel can't hide player behavior)
- Frequent security updates (stay ahead of public drivers)

**Honest Assessment:** Kernel drivers defeat all user-mode anti-cheat. Only mitigation is making kernel driver loading harder (HVCI, driver signing enforcement).

---

## Restore-on-Scan Bypasses

**Class:** Timing-Based Evasion  
**Complexity:** MEDIUM  
**Cost:** FREE (requires programming knowledge)  
**Detection:** POSSIBLE but unreliable

### Abstract Description

Attacker monitors when integrity checks run, temporarily restores original bytes during scan, then re-applies patches after scan completes.

### Attack Surface

- Code integrity checks (periodic scanning)
- Memory integrity checks (sampling-based)
- IAT hook detection
- Any check with predictable timing

### Why This Works

- Periodic checks have gaps (time windows between scans)
- Even with jitter, patterns emerge over time
- Check runs slower than patch/restore operation
- No atomic way to read-and-execute from user-mode

### Bypass Examples (Abstract)

1. **VEH Monitoring**: Install Vectored Exception Handler to monitor when checks access memory
2. **Pattern Recognition**: Profile check timing, predict next scan
3. **Hook the Detector**: Hook integrity check function, restore during its execution
4. **Atomic Patch/Restore**: Use fast memory writes, faster than check can detect

### Defense Strategy

**What CANNOT Work:**
- Periodic scanning alone (always has TOCTOU window)

**What MIGHT Help:**
- Inline verification (SENTINEL_PROTECTED_CALL macro) - check immediately before use
- Randomized sampling with unpredictable intervals
- Honeypots (decoy functions that should never be modified)
- Server-side validation (can't restore server state)

**Honest Assessment:** Periodic checks are **DETERRENCE ONLY**. Inline verification at point-of-use is the only TOCTOU-resistant approach.

---

## Crash-Based Bypasses

**Class:** Denial of Service & Recovery  
**Complexity:** LOW  
**Cost:** FREE  
**Detection:** POSSIBLE (crash telemetry)

### Abstract Description

Attacker intentionally crashes anti-cheat process or thread to disable detection, then continues with cheats.

### Attack Surface

- Exception handling
- Resource exhaustion
- Invalid memory access
- Null pointer dereferences

### Why This Works

- User-mode code can trigger exceptions
- If anti-cheat crashes, game may continue
- Recovery mechanisms can be exploited

### Bypass Examples (Abstract)

1. **Exception Storm**: Trigger thousands of exceptions to exhaust handler
2. **Resource Exhaustion**: Allocate all available memory, force OOM
3. **Null Pointer Dereference**: Pass null pointers to API, crash detector
4. **Thread Termination**: Kill anti-cheat threads from kernel driver

### Defense Strategy

**What CANNOT Work:**
- Expecting perfect stability (all software has bugs)

**What MIGHT Help:**
- Graceful degradation (log and continue, don't crash)
- Fail-closed mode (if anti-cheat crashes, game also terminates)
- Exception budgets (abort scan if too many exceptions)
- Watchdog process (external monitor that relaunches or kills game)

**Honest Assessment:** Crashes are hard to prevent. Better to design for graceful failure than perfect robustness.

---

## Timing Manipulation Bypasses

**Class:** Time Source Control  
**Complexity:** LOW (user-mode) to MEDIUM (kernel-mode)  
**Cost:** FREE  
**Detection:** UNRELIABLE without server validation

### Abstract Description

Attacker hooks all time sources to return fake accelerated/decelerated time, defeating speed hack detection.

### Attack Surface

- GetTickCount64
- QueryPerformanceCounter
- RDTSC instruction
- System time APIs

### Why This Works

- All user-mode time APIs are hookable
- RDTSC requires kernel driver to hook, but it's possible
- Cross-validation fails if all sources hooked consistently
- Client has no authoritative time source

### Bypass Examples (Abstract)

1. **Coordinated Hooking**: Hook all time APIs to return consistent fake time
2. **RDTSC Virtualization**: Use kernel driver or hypervisor to intercept RDTSC
3. **Calibration Manipulation**: Hook during calibration to set high baseline thresholds
4. **Selective Acceleration**: Keep anti-cheat at 1x speed, accelerate game at 2x

### Defense Strategy

**What CANNOT Work:**
- Client-side time validation alone (all sources controllable)

**What MIGHT Help:**
- Server-side time validation (authoritative time source)
- Network round-trip time monitoring
- Server validates client action timestamps
- Ban on consistent time deviation patterns

**Honest Assessment:** **CLIENT-SIDE SPEED DETECTION IS FUNDAMENTALLY BROKEN**. Server validation is MANDATORY.

---

## Desynchronization Attacks

**Class:** State Inconsistency Exploitation  
**Complexity:** MEDIUM  
**Cost:** FREE  
**Detection:** POSSIBLE via correlation

### Abstract Description

Attacker creates inconsistent state between different components, exploiting assumption that all state is synchronized.

### Attack Surface

- Multi-threaded state management
- Cache vs. authoritative data
- Client vs. server state
- Redundant value storage

### Why This Works

- Race conditions between state updates
- Assumptions that state is always consistent
- Cache invalidation bugs
- Time-of-check vs. time-of-use

### Bypass Examples (Abstract)

1. **Cache Poisoning**: Corrupt cached hash, integrity check uses cache instead of recomputing
2. **Redundant Copy Desync**: Modify one copy of redundantly-stored value
3. **Thread Race**: Modify state during thread context switch
4. **Client-Server Desync**: Client claims different state than server expects

### Defense Strategy

**What CANNOT Work:**
- Assuming state is always synchronized

**What MIGHT Help:**
- Lock-free data structures
- Atomic operations for state transitions
- Periodic reconciliation of redundant copies
- Server as authoritative source (client state is advisory)

**Honest Assessment:** Desync is hard to prevent in concurrent systems. Design with inconsistency in mind.

---

## Memory-Based Bypasses

**Class:** Direct Memory Manipulation  
**Complexity:** LOW (user-mode) to MEDIUM (kernel-mode)  
**Cost:** FREE  
**Detection:** POSSIBLE with guard pages and correlation

### Abstract Description

Attacker directly reads/writes process memory to extract information or modify values.

### Attack Surface

- Protected values (health, ammo, position)
- Obfuscated data structures
- Encrypted memory regions
- Guard pages

### Why This Works

- All user-mode memory is readable/writable
- Obfuscation is reversible (not encryption)
- Guard pages can be removed (change protection)
- Kernel driver bypasses all protections

### Bypass Examples (Abstract)

1. **Differential Scanning**: Change value in-game, scan for changes (Cheat Engine)
2. **Pointer Chains**: Follow pointer paths to find values
3. **Pattern Scanning**: Search for value patterns despite obfuscation
4. **Guard Page Removal**: Change PAGE_GUARD to PAGE_READWRITE

### Defense Strategy

**What CANNOT Work:**
- Hiding memory (attacker can enumerate all memory)

**What MIGHT Help:**
- Value obfuscation (raises difficulty, not prevention)
- Triple redundancy with checksums (detect modification)
- Server validation (authoritative values)
- Decoy values (honeypots)

**Honest Assessment:** Memory protection in user-mode is **OBFUSCATION**, not **PREVENTION**.

---

## Network-Based Bypasses

**Class:** Communication Interception & Manipulation  
**Complexity:** MEDIUM  
**Cost:** FREE  
**Detection:** POSSIBLE with crypto and replay protection

### Abstract Description

Attacker intercepts, modifies, or replays network traffic between client and server.

### Attack Surface

- Unencrypted traffic
- Weak encryption
- Missing replay protection
- Certificate validation

### Why This Works

- Network is untrusted medium
- User controls network stack
- Can install root CA for MITM
- Can replay captured packets

### Bypass Examples (Abstract)

1. **Packet Sniffing**: Capture unencrypted packets, analyze protocol
2. **MITM with Root CA**: Install CA, decrypt TLS traffic
3. **Replay Attack**: Capture heartbeat, replay indefinitely
4. **Packet Modification**: Change encrypted payloads if no authentication

### Defense Strategy

**What CANNOT Work:**
- Trust in client network stack

**What MIGHT Help:**
- TLS with certificate pinning
- HMAC authentication on all requests
- Nonce + timestamp for replay protection
- Perfect forward secrecy (ephemeral keys)

**Honest Assessment:** Network security is **FEASIBLE** with proper crypto, but all client-side checks are bypassable.

---

## Code Analysis Bypasses

**Class:** Static & Dynamic Reverse Engineering  
**Complexity:** HIGH  
**Cost:** FREE (time investment)  
**Detection:** IMPOSSIBLE

### Abstract Description

Attacker analyzes code to understand detection logic, then targets specific weaknesses.

### Attack Surface

- Disassembly (IDA, Ghidra)
- Dynamic analysis (debuggers, emulators)
- Decompilation
- Symbolic execution

### Why This Works

- All shipped code is analyzable
- Obfuscation only slows analysis, doesn't prevent it
- VM protection can be defeated with patience
- No perfect code hiding

### Bypass Examples (Abstract)

1. **Honeypot Identification**: Analyze call graph, find functions never called
2. **Detection Logic Reversal**: Understand checks, patch them out
3. **Weak Point Discovery**: Find single point of failure, target it
4. **Obfuscation Removal**: Deobfuscate VMs (VMProtect, Themida)

### Defense Strategy

**What CANNOT Work:**
- Perfect code hiding (impossible)

**What MIGHT Help:**
- Obfuscation (raises time cost)
- Frequent updates (reverse engineering takes time, make it obsolete)
- Layered defenses (no single point of failure)
- Server-side logic (can't reverse engineer server)

**Honest Assessment:** All client code is reversible. Design assuming attacker knows everything.

---

## Summary: Bypass Difficulty Matrix

| Bypass Class | Complexity | Cost | User-Mode Detection | Kernel-Mode Detection |
|--------------|-----------|------|--------------------|-----------------------|
| Kernel Control | HIGH | $$$ | IMPOSSIBLE | POSSIBLE (bootkit detection) |
| Restore-on-Scan | MEDIUM | FREE | POSSIBLE (weak) | POSSIBLE |
| Crash-Based | LOW | FREE | POSSIBLE (telemetry) | N/A |
| Timing Manipulation | LOW-MEDIUM | FREE | UNRELIABLE | UNRELIABLE |
| Desync Attacks | MEDIUM | FREE | POSSIBLE (correlation) | POSSIBLE |
| Memory Manipulation | LOW | FREE | POSSIBLE (guard pages) | POSSIBLE |
| Network MITM | MEDIUM | FREE | POSSIBLE (crypto) | POSSIBLE |
| Code Analysis | HIGH | FREE (time) | IMPOSSIBLE | IMPOSSIBLE |

---

## Defense-in-Depth Strategy

Since no single defense stops all bypasses, use layered approach:

### Layer 1: Deterrence (User-Mode)
- Detect basic cheats (free tools, public cheats)
- Raise effort bar for casual attackers
- Collect telemetry for pattern analysis

### Layer 2: Server Validation (Authoritative)
- Validate all critical game state server-side
- Detect impossible actions (teleport, speed)
- Rate limiting, cooldowns enforced server-side

### Layer 3: Behavioral Analysis (Cloud)
- Analyze patterns across many players
- Statistical anomaly detection
- Identify cheat tool signatures

### Layer 4: Economic Disincentives
- HWID bans (make new account costly)
- Delayed ban waves (cheaters unsure when detected)
- Honeypots (wasted cheat development effort)

### Layer 5: Rapid Response
- Weekly security updates
- Cheat signature database updates
- Fast patch turnaround for new bypasses

---

## Conclusion

**Key Insights:**

1. **No Single Bypass Is Unbeatable** - But kernel access defeats most
2. **Client-Side Checks Are Advisory** - Server must be authoritative
3. **Defense-in-Depth Required** - No silver bullet
4. **Economic Model Matters** - Make cheating cost more than value gained
5. **Assume Breach** - Design for detection, not prevention

**Design Principles:**

✅ **DO:** Assume attacker knows your code  
✅ **DO:** Validate everything server-side  
✅ **DO:** Correlate multiple signals  
✅ **DO:** Log everything for pattern analysis  
✅ **DO:** Update frequently  

❌ **DON'T:** Rely on single detector  
❌ **DON'T:** Trust client time/state  
❌ **DON'T:** Assume obfuscation = security  
❌ **DON'T:** Ban on single signal  
❌ **DON'T:** Promise unbreakable security  

**Final Truth:** Every anti-cheat is bypassable. The goal is to make bypass cost exceed cheat value.
