# Defensive Gaps: Honest Security Assessment

**Classification:** Internal Security Review  
**Purpose:** Brutally honest assessment of what cannot be defended in user-mode  
**Last Updated:** 2025-01-29

---

## Executive Summary

This document catalogs the **fundamental limitations** of user-mode anti-cheat protection. These are not implementation bugs—they are **architectural constraints** that cannot be overcome without kernel-mode or hypervisor-level protection.

**Key Principle:** Be honest about what we can and cannot defend against. Do not promise security theater.

---

## Table of Contents

1. [What Cannot Be Reliably Defended](#what-cannot-be-reliably-defended)
2. [What Is Deterrence Only](#what-is-deterrence-only)
3. [What Is Fragile](#what-is-fragile)
4. [What Relies On Hope](#what-relies-on-hope)
5. [Kernel-Mode Bypass Catalog](#kernel-mode-bypass-catalog)
6. [The Trust Boundary Problem](#the-trust-boundary-problem)
7. [Recommendations for Honest Security](#recommendations-for-honest-security)

---

## What Cannot Be Reliably Defended

These attack vectors are **fundamentally impossible** to defend against from user-mode.

### 1. Kernel-Mode Debuggers and Drivers

**Attack:** Attacker loads kernel driver that hides debug objects, patches SSDT, or manipulates page tables.

**Why Undefendable:**
- Kernel code runs at Ring 0, user-mode at Ring 3
- No user-mode API can validate kernel state
- Windows kernel allows driver loading (with test signing or HVCI disabled)
- Even PatchGuard can be bypassed with sufficient effort

**Current Protection:** NONE  
**Mitigation:** Require users to enable HVCI/KMCI, but this is optional  
**Honest Assessment:** **IMPOSSIBLE TO DEFEND**

---

### 2. Page Table Manipulation (Shadow Pages)

**Attack:** Kernel driver creates two mappings of same physical page:
- Read mapping: Shows clean, unmodified code
- Execute mapping: Shows hooked, patched code

**Why Undefendable:**
- User-mode has no access to page tables (CR3 register)
- All integrity checks read from "clean" mapping
- Execution uses "hooked" mapping
- Detection requires comparing virtual to physical memory

**Current Protection:** NONE  
**Mitigation:** None possible from user-mode  
**Honest Assessment:** **IMPOSSIBLE TO DEFEND**

---

### 3. Direct Physical Memory Modification

**Attack:** Use kernel driver to modify physical RAM directly, bypassing all virtual memory protections.

**Why Undefendable:**
- User-mode cannot access physical memory
- Guard pages, VirtualProtect, all memory protections are virtual
- Direct physical write bypasses all user-mode checks

**Current Protection:** NONE  
**Mitigation:** None possible from user-mode  
**Honest Assessment:** **IMPOSSIBLE TO DEFEND**

---

### 4. RDTSC Virtualization

**Attack:** Use hypervisor (VT-x) or kernel driver to intercept RDTSC instructions, return fake CPU cycle count.

**Why Undefendable:**
- RDTSC is privileged operation
- Hypervisor sits below kernel, can intercept all instructions
- No user-mode way to validate RDTSC results

**Current Protection:** Cross-validation with QPC  
**Mitigation:** QPC also hookable via kernel driver  
**Honest Assessment:** **IMPOSSIBLE TO DEFEND** (without Intel PT or AMD SVM monitoring)

---

### 5. System Call Hooking (SSDT/Shadow SSDT Patching)

**Attack:** Patch System Service Dispatch Table to intercept all syscalls (NtQueryInformationProcess, NtReadVirtualMemory, etc.)

**Why Undefendable:**
- SSDT is in kernel memory, user-mode cannot read it
- All our API calls eventually hit syscalls
- Kernel can lie about debug state, memory contents, thread lists

**Current Protection:** Direct syscall attempt (syscall number extraction)  
**Mitigation:** Kernel can hook syscall instruction itself  
**Honest Assessment:** **IMPOSSIBLE TO DEFEND**

---

## What Is Deterrence Only

These protections work against casual attackers but fail against determined adversaries.

### 1. Anti-Debug Checks

**Current Implementation:**
- `IsDebuggerPresent()` check
- PEB.BeingDebugged flag check
- NtGlobalFlag check
- Hardware breakpoint detection
- Timing anomaly detection

**Why Deterrence Only:**
- All checks are user-mode, hookable
- PEB can be patched
- Hardware breakpoints can be cleared before context queries
- Timing can be normalized by hooking QPC/RDTSC
- ScyllaHide, TitanHide defeat all checks

**Bypass Difficulty:** LOW (free tools available)  
**Effectiveness Against:** Script kiddies, casual cheaters  
**Defeated By:** Anyone with x64dbg + ScyllaHide plugin

---

### 2. Inline Hook Detection

**Current Implementation:**
- Compare function prologue with baseline
- Pattern matching for JMP/CALL instructions
- Double-check with memory barrier

**Why Deterrence Only:**
- TOCTOU: Hook installed after check, before call
- Hardware breakpoints: No memory modification to detect
- VEH hooking: No inline patch to detect
- Page table manipulation: Check sees clean page, execution uses hooked page

**Bypass Difficulty:** MEDIUM (requires understanding of detection timing)  
**Effectiveness Against:** Basic hooking tools (MinHook without concealment)  
**Defeated By:** TOCTOU-aware hooks, hardware breakpoints, kernel hooks

---

### 3. IAT Hook Detection

**Current Implementation:**
- Verify IAT pointers resolve to expected modules
- Check for forwards and API set resolution
- Validate against export tables

**Why Deterrence Only:**
- Can hook the IAT check itself
- Can restore IAT during check, re-hook after
- Kernel driver can create fake export tables
- Delay-load IAT can be hooked after load

**Bypass Difficulty:** LOW (simpler than inline hooks)  
**Effectiveness Against:** Basic DLL injection without stealth  
**Defeated By:** Restore-on-scan, kernel hooks, manual export table construction

---

### 4. Memory Injection Detection

**Current Implementation:**
- Scan for MEM_PRIVATE executable regions
- Validate thread start addresses
- Module signature verification
- JIT signature database

**Why Deterrence Only:**
- Manual mapping into existing module's code caves: No new memory region
- Thread hijacking: No new thread
- Injection before SDK init: Becomes part of baseline
- Kernel driver hiding: VirtualQuery lies about memory

**Bypass Difficulty:** MEDIUM (requires manual mapping knowledge)  
**Effectiveness Against:** Basic DLL injection (LoadLibrary)  
**Defeated By:** Manual mapping, code caves, kernel memory hiding

---

### 5. Value Protection (Obfuscation)

**Current Implementation:**
- XOR with rolling key
- Store at non-contiguous memory addresses

**Why Deterrence Only:**
- Obfuscation is not encryption (reversible)
- Key extraction from code analysis
- Differential scanning still works (change value, scan for changes)
- Hook getter/setter to bypass obfuscation entirely

**Bypass Difficulty:** LOW (Cheat Engine handles obfuscation)  
**Effectiveness Against:** First-time memory scanners  
**Defeated By:** Any memory scanner with "unknown initial value" search

---

## What Is Fragile

These protections work but are easily broken by minor implementation mistakes or edge cases.

### 1. Integrity Hashing Without Signing

**Current Implementation:**
- SHA-256 hash of code section
- Compare against baseline taken at init

**Why Fragile:**
- Self-modifying code (JIT): Triggers false positives
- Hook SafeHash: Returns fake hash
- Restore-on-scan: Temporarily restore original bytes
- Initialization race: Attacker patches before baseline captured

**Failure Modes:**
- False positives: JIT, hot-patching, ASLR relocation
- False negatives: Restore-on-scan, hash hook
- Timing: Heavy hashing causes performance drops

**Reliability:** 60% (works if attacker doesn't actively evade)

---

### 2. Timing-Based Detection

**Current Implementation:**
- Compare QPC, RDTSC, GetTickCount64
- Detect >25% deviation as speedhack

**Why Fragile:**
- VMs: Imprecise time, triggers false positives
- Power management: CPU frequency scaling, sleep/resume anomalies
- Time synchronization: NTP adjustments cause spikes
- All time sources hookable together: Coordinated fake timing

**Failure Modes:**
- False positives: 30-40% in VMs
- False negatives: Coordinated hooking of all time sources
- Edge cases: Hibernate/resume, time zone changes

**Reliability:** 50% (too many false positives for Critical severity)

---

### 3. Certificate Pinning Without OCSP

**Current Implementation:**
- (PLANNED) Pin server certificate

**Why Fragile:**
- Certificate rotation: Hard-coded pin breaks on renewal
- Root CA compromise: If attacker compromises CA, can issue valid cert
- No revocation checking: Stolen cert works until expiry
- Hook validation: User-mode pinning check can be bypassed

**Failure Modes:**
- False positives: Certificate rotation breaks all clients
- False negatives: Stolen certificate, root CA compromise
- Maintenance burden: Requires app update to rotate pin

**Reliability:** 70% (works against casual MITM, fails against targeted attacks)

---

### 4. Whitelisting Thread Origins

**Current Implementation:**
- Allow threads from game engine DLLs
- Flag threads from unknown origins

**Why Fragile:**
- Injection into whitelisted module: Bypass
- DLL proxying: Load cheat as dependency of whitelisted DLL
- Thread start address spoofing: Set fake start address
- Whitelist too broad: Game engine threads may include injected code

**Failure Modes:**
- False positives: Custom game threading, fiber APIs
- False negatives: Injection from whitelisted module
- Configuration burden: Every game needs custom whitelist

**Reliability:** 65% (requires careful per-game configuration)

---

## What Relies On Hope

These are mechanisms that sound good but have no enforcement.

### 1. User-Mode Encryption Key Protection

**Current Implementation:**
- Store keys in memory, use DPAPI (planned)

**Why Hope:**
- All keys must be in memory to use
- Memory dumps extract keys immediately
- DPAPI only protects at-rest, not in-use
- No hardware enclave (TPM, SGX) currently used

**Reality Check:** Keys are extractable. Period.  
**What We Hope:** Attacker doesn't bother dumping memory  
**What Actually Happens:** Any attacker with kernel driver dumps keys in 1 second

---

### 2. Network Request Signing Without Replay Protection

**Current Implementation:**
- (PLANNED) HMAC sign requests with license key

**Why Hope:**
- If nonce/timestamp missing: Replay attacks work
- If license key compromised: All signature verification broken
- No key rotation: One compromised key = permanent compromise

**Reality Check:** Signing without replay protection is security theater  
**What We Hope:** Attacker won't capture and replay requests  
**What Actually Happens:** First packet captured is replayed indefinitely

---

### 3. Fail-Closed Without Forced Kill

**Current Implementation:**
- (PLANNED) Disable game if offline >5 minutes

**Why Hope:**
- Hook the timer: Never trigger
- Hook the disable function: Game continues
- No kernel-enforced kill switch

**Reality Check:** User-mode can't enforce fail-closed  
**What We Hope:** Game respects our disable request  
**What Actually Happens:** Attacker hooks disable function, plays offline forever

---

### 4. Honeypot Functions

**Current Implementation:**
- Register decoy functions never called
- Any modification = cheat detected

**Why Hope:**
- Static analysis identifies honeypots (never called)
- Attacker simply avoids hooking identified honeypots
- No runtime polymorphism to hide honeypots

**Reality Check:** Honeypots detectable via static analysis  
**What We Hope:** Attacker blindly hooks everything  
**What Actually Happens:** Sophisticated tools identify and skip honeypots

---

## Kernel-Mode Bypass Catalog

These are the **known, publicly documented** kernel-mode bypass techniques.

### 1. Manual Mapping with Page Table Manipulation

**Tools:** Any kernel driver + basic paging knowledge  
**Technique:**
1. Allocate physical page
2. Map once as RWX (for writing)
3. Map again as RX (for execution)
4. User-mode sees two separate virtual addresses, same physical page
5. Write hook to RWX mapping
6. Execute from RX mapping
7. Integrity check on RX mapping sees clean code
8. Execution uses hooked code from RWX

**Detection:** IMPOSSIBLE from user-mode  
**Mitigation:** Requires Intel PT or AMD SVM hardware tracing

---

### 2. SSDT Hook Evasion

**Tools:** TitanHide, ScyllaHide kernel components  
**Technique:**
1. Patch NtQueryInformationProcess in SSDT
2. Return fake results for debug port/object queries
3. All user-mode checks bypass

**Detection:** Direct syscall attempts (extract syscall number, invoke directly)  
**Counter:** Hook syscall instruction itself at kernel level  
**Verdict:** Detection attempt bypassable

---

### 3. Hypervisor-Based Debugging

**Tools:** Any hypervisor (VT-x, AMD-V)  
**Technique:**
1. Load hypervisor below Windows kernel
2. Intercept all VM exits (CPUID, RDTSC, debug exceptions)
3. Return fake results to VM
4. User-mode and kernel-mode both fooled

**Detection:** IMPOSSIBLE (hypervisor is invisible to guest OS)  
**Mitigation:** Boot with Secure Boot + HVCI, but attacker can disable

---

### 4. DMA Attacks

**Tools:** PCILeech, Inception  
**Technique:**
1. Use DMA-capable device (Thunderbolt, Firewire, PCIe)
2. Read/write physical memory directly
3. Bypass all software protections

**Detection:** IMPOSSIBLE from software  
**Mitigation:** IOMMU/VT-d (requires BIOS configuration)

---

## The Trust Boundary Problem

### Trust Boundaries in the System

```
┌─────────────────────────────────────────────────────────────────┐
│ HYPERVISOR (Ring -1)                                             │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ KERNEL (Ring 0)                                              │ │
│ │ ┌─────────────────────────────────────────────────────────┐ │ │
│ │ │ SENTINEL SDK (Ring 3 - User Mode)                        │ │ │
│ │ │ ┌─────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ GAME (Ring 3 - User Mode)                           │ │ │ │
│ │ │ │                                                       │ │ │ │
│ │ │ │  ❌ NO PROTECTION FROM:                              │ │ │ │
│ │ │ │  - Kernel drivers                                    │ │ │ │
│ │ │ │  - Hypervisors                                       │ │ │ │
│ │ │ │  - Physical memory access                            │ │ │ │
│ │ │ │  - Page table manipulation                           │ │ │ │
│ │ │ └─────────────────────────────────────────────────────┘ │ │ │
│ │ │                                                           │ │ │
│ │ │  ⚠️ LIMITED PROTECTION FROM:                             │ │ │
│ │ │  - User-mode hooks (detectable but bypassable)          │ │ │
│ │ │  - User-mode debuggers (detectable but defeatable)      │ │ │
│ │ └─────────────────────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### The Fundamental Problem

**Axiom:** You cannot secure a system from within the system.

**Corollaries:**
1. User-mode cannot protect against kernel-mode
2. Kernel-mode cannot protect against hypervisor
3. Software cannot protect against hardware (DMA)
4. Any code running at equal or higher privilege can bypass all protections

**Implication for Sentinel SDK:**
- All protections are **advisory**, not **enforced**
- Detection is **best-effort**, not **guaranteed**
- Security model is **deterrence**, not **prevention**

---

## Recommendations for Honest Security

### 1. Set Correct Expectations

**DO:**
- "Sentinel deters casual cheaters and raises the bar for sophisticated attacks"
- "Effective against script kiddies, basic cheats, and public tools"
- "Provides telemetry and behavior analysis for ban decisions"

**DON'T:**
- "Sentinel prevents all cheating"
- "Military-grade protection"
- "Unbypassable security"

### 2. Acknowledge Limitations Publicly

**In README:**
> This is a **user-mode defensive SDK**. It provides **deterrence** against casual attackers but cannot prevent determined adversaries with kernel-mode access. For highest security, combine with server-side validation and behavioral analysis.

**In Documentation:**
> All detections are **best-effort**. Kernel-mode cheats, hypervisor-based tools, and hardware attacks cannot be reliably detected from user-mode.

### 3. Design for Defense-in-Depth

**Strategy:**
- Assume each detector is bypassable
- Correlate multiple weak signals into strong evidence
- Log everything to cloud for pattern analysis
- Make bypass cost exceed cheat value

**Never:**
- Rely on single detector for Critical decisions
- Ban based on client-side detection alone
- Trust user-mode results as ground truth

### 4. Implement Server-Side Validation

**Required for Production:**
- Speed hack detection: Server validates time deltas
- Position/teleport: Server validates movement physics
- Resource modifications: Server is authoritative source
- Action rate limiting: Server enforces cooldowns

**Reality:** Client-side anti-cheat is **supplementary**, not **primary** defense.

---

## Conclusion

### What We CAN Do
✅ Deter casual attackers  
✅ Detect public cheat tools  
✅ Collect telemetry for ban decisions  
✅ Raise the effort bar for basic cheats  
✅ Provide developer-friendly integration  

### What We CANNOT Do
❌ Prevent kernel-mode cheats  
❌ Guarantee detection of any attack  
❌ Protect against determined adversaries  
❌ Enforce security from user-mode  
❌ Replace server-side validation  

### Final Honest Assessment

**Sentinel SDK is a valuable tool for:**
- Casual game protection
- Collecting cheat intelligence
- Deterring opportunistic cheaters
- Supporting server-side ban systems

**Sentinel SDK is NOT:**
- A replacement for server validation
- Protection against APT-level adversaries
- Effective against kernel-mode tools
- A "set and forget" security solution

**Use it wisely. Be honest about its limits. Build defense-in-depth.**
