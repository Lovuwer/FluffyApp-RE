# Sentinel Security Ecosystem

[![Build Status](https://github.com/Lovuwer/Sentiel-RE/actions/workflows/build.yml/badge.svg)](https://github.com/Lovuwer/Sentiel-RE/actions)

**Version:** 1.0.0  
**License:** Proprietary  
**Platform:** Windows x64, Linux (partial support)

---

## ⚠️ Security Notice: Read Before Using

**Sentinel SDK is a USER-MODE defensive toolkit.** It provides **deterrence** against casual attackers but **cannot prevent** determined adversaries with kernel-mode access.

### What This System IS:
✅ A detection and telemetry platform for cheating behaviors  
✅ Effective against public cheat tools and casual attackers  
✅ A framework for collecting security intelligence  
✅ A complement to server-side validation  

### What This System IS NOT:
❌ A guarantee against all cheating  
❌ Protection against kernel-mode exploits  
❌ A replacement for server-side validation  
❌ "Unbreakable" or "military-grade" security  

**For production games:** Combine with server-side validation, behavioral analysis, and economic disincentives (HWID bans, delayed ban waves).

📖 **Read the complete security analysis:** [docs/DEFENSIVE_GAPS.md](docs/DEFENSIVE_GAPS.md)

---

## 🚧 Development Status

This project is in **early development**. Core detection systems are implemented but not all protection features are complete.

**Current Status:**
- ✅ AntiDebug detection (user-mode checks)
- ✅ AntiHook detection (inline + IAT)
- ✅ Integrity checking (code section hashing)
- ✅ Injection detection (DLL + manual mapping)
- 🟡 Speed hack detection (client-side only - **requires server validation**)
- 🔴 Heartbeat/Cloud reporting (stub only)
- 🔴 Memory/Value protection (stub only)

📖 **Detailed status:** [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md)

---

## Overview

Sentinel is a C++ game security ecosystem that detects runtime manipulation, memory hacking, and binary patching. It combines client-side detection, cloud telemetry, and analysis tools.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SENTINEL SECURITY ECOSYSTEM                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│   │ SENTINEL CORTEX │    │  SENTINEL SDK   │    │   WATCHTOWER    │        │
│   │  (Workbench)    │    │   (Shield)      │    │  (Roblox Mod)   │        │
│   │                 │    │                 │    │                 │        │
│   │ • Disassembly   │    │ • Detection     │    │ • Net Fuzzer    │        │
│   │ • Fuzzy Hashing │    │ • Integrity     │    │ • Lua Bridge    │        │
│   │ • Diff Engine   │    │ • Telemetry     │    │ • Event Monitor │        │
│   └────────┬────────┘    └────────┬────────┘    └────────┬────────┘        │
│            │                      │                      │                 │
│            └──────────────────────┼──────────────────────┘                 │
│                                   │                                        │
│                          ┌────────▼────────┐                               │
│                          │ SENTINEL CLOUD  │                               │
│                          │                 │                               │
│                          │ • Threat Intel  │                               │
│                          │ • Telemetry     │                               │
│                          │ • Analytics     │                               │
│                          └─────────────────┘                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Sentinel SDK (Client-Side Detection)

A lightweight C++ library for detecting runtime manipulation.

**Detection Capabilities:**
- **Anti-Debug:** Detects debuggers (x64dbg, WinDbg, etc.)
- **Anti-Hook:** Detects API hooks (inline, IAT, VEH)
- **Integrity Checks:** Verifies code sections haven't been modified
- **Injection Detection:** Detects DLL injection and manual mapping
- **Speed Hack Detection:** Detects time manipulation (requires server validation)

**Important Limitations:**
- All checks are bypassable with kernel-mode access
- TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities in periodic scans
- Speed hack detection requires server-side validation
- No protection against page table manipulation

**Recommended Use:**
- Telemetry collection for pattern analysis
- Deterring casual attackers
- Supporting server-side ban decisions
- NOT as sole anti-cheat solution

### 2. Sentinel Cortex (Analysis Workbench)

A desktop application for binary analysis and forensics.

**Features:**
- Disassembly (Capstone-powered)
- Fuzzy hashing (TLSH/ssdeep)
- Binary diff engine
- VM deobfuscation (planned)

### 3. Sentinel Watchtower (Roblox Module)

Specialized protection for Roblox games (planned).

---

## Quick Start

### Prerequisites

**Linux:**
```bash
sudo apt-get update
sudo apt-get install -y cmake build-essential ninja-build libssl-dev
```

**Windows:**
- Visual Studio 2022+ with C++20 support
- CMake 3.21+
- Qt 6.5+ (optional, for Cortex GUI)

### Building

```bash
# Clone the repository
git clone https://github.com/Lovuwer/Sentiel-RE.git
cd Sentiel-RE

# Configure CMake
cmake -B build -G "Ninja" \
  -DCMAKE_BUILD_TYPE=Release \
  -DSENTINEL_BUILD_CORTEX=OFF \
  -DSENTINEL_BUILD_WATCHTOWER=OFF \
  -DSENTINEL_BUILD_TESTS=ON

# Build
cmake --build build --config Release

# Run tests
cd build && ctest --output-on-failure
```

### SDK Integration Example

**Quick Start:**

```cpp
#include <SentinelSDK.hpp>

int main() {
    using Sentinel::SDK::ErrorCode;
    using Sentinel::SDK::Configuration;
    using Sentinel::SDK::DetectionFeatures;
    using Sentinel::SDK::ResponseAction;
    using Sentinel::SDK::Initialize;
    using Sentinel::SDK::Update;
    using Sentinel::SDK::Shutdown;
    
    // Configure SDK
    Configuration config = Configuration::Default();
    config.license_key = "your-license-key";
    config.game_id = "your-game-id";
    config.features = DetectionFeatures::Standard;
    config.default_action = ResponseAction::Report | ResponseAction::Log;
    
    // Initialize
    if (Initialize(&config) != ErrorCode::Success) {
        fprintf(stderr, "Failed to initialize Sentinel SDK\n");
        return -1;
    }
    
    // Game loop
    while (game_running) {
        // Call once per frame - lightweight checks
        Update();
        
        // Your game logic here
        UpdateGame();
        RenderFrame();
    }
    
    // Cleanup
    Shutdown();
    return 0;
}
```

**Full Integration Example:**

See [examples/DummyGame/](examples/DummyGame/) for a complete, realistic integration test that exercises:
- All crypto components (SecureRandom, HashEngine, AESCipher, HMAC)
- Protected values and memory protection
- Secure timing and packet encryption
- Violation callbacks and error handling
- Proper initialization and shutdown

**Integration Tips:**
- Call `Update()` once per frame (measured: ~0.46ms, target: <0.1ms ⚠️)
- Call `FullScan()` every 5-10 seconds (measured: ~7-10ms, target: <5ms ⚠️)
- Use explicit imports to avoid namespace conflicts
- Configure violation callback for custom responses
- See [docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) for detailed guide

---

## Security Model

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│ HYPERVISOR (Ring -1) - UNTRUSTED                                │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ KERNEL (Ring 0) - PARTIALLY TRUSTED                         │ │
│ │ ┌─────────────────────────────────────────────────────────┐ │ │
│ │ │ SENTINEL SDK (Ring 3) ← YOU ARE HERE                    │ │ │
│ │ │ ⚠️  Can detect user-mode attacks                        │ │ │
│ │ │ ❌ Cannot prevent kernel-mode attacks                   │ │ │
│ │ └─────────────────────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Defense-in-Depth Strategy

Sentinel SDK is **one layer** in a complete security architecture:

1. **Client Detection (Sentinel SDK):** Deter casual attackers, collect telemetry
2. **Server Validation:** Authoritative checks for game state, speed, physics
3. **Behavioral Analysis:** Pattern detection across player base
4. **Economic Disincentives:** HWID bans, delayed ban waves

**Never rely on client-side detection alone.**

---

## Documentation

### Security Documentation (RED TEAM REVIEWED)

- [REDTEAM_ATTACK_SURFACE.md](docs/REDTEAM_ATTACK_SURFACE.md) - Attack strategies per subsystem
- [DEFENSIVE_GAPS.md](docs/DEFENSIVE_GAPS.md) - What cannot be defended
- [DETECTION_CONFIDENCE_MODEL.md](docs/DETECTION_CONFIDENCE_MODEL.md) - Signal strength and bypass cost
- [KNOWN_BYPASSES.md](docs/KNOWN_BYPASSES.md) - High-level bypass classes
- [SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md) - Non-negotiable requirements
- [IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) - What's actually implemented

### Integration & Testing

- [INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) - Complete integration guide with best practices
- [DUMMY_GAME_VALIDATION.md](docs/DUMMY_GAME_VALIDATION.md) - Real-world testing results and red-team observations
- [DummyGame Example](examples/DummyGame/) - Realistic integration test exercising all SDK features

### Architecture & API

- [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) - System architecture with trust boundaries
- [API Documentation](docs/api/) - Detailed API reference (generated with Doxygen)

### Configuration

- [THREAD_WHITELIST_CONFIGURATION.md](docs/THREAD_WHITELIST_CONFIGURATION.md) - Whitelist configuration
- [JIT_SIGNATURE_DATABASE.md](docs/JIT_SIGNATURE_DATABASE.md) - JIT compiler signatures

---

## Performance

**Targets:**
- `Update()` per frame: < 0.1ms
- `FullScan()` periodic: < 5ms
- Memory overhead: ~2MB

**Measured (DummyGame Test on Linux VM):**
- `Update()`: ~0.46ms ⚠️ (4.6× over target - needs optimization)
- `FullScan()`: ~7-10ms ⚠️ (1.4-2× over target)
- Memory overhead: TBD

📖 **See [DUMMY_GAME_VALIDATION.md](docs/DUMMY_GAME_VALIDATION.md) for detailed performance analysis**

**Performance Notes:**
- Current implementation exceeds performance targets
- Measured on VM environment (GitHub Actions)
- Real-world performance may vary by hardware
- Consider increasing scan intervals if frame rate affected

| Operation | Target | Measured (DummyGame) | Status |
|-----------|--------|---------------------|--------|
| `Update()` | < 0.1ms | ~0.46ms | ⚠️ Over budget |
| `FullScan()` | < 5ms | ~7-10ms | ⚠️ Over budget |
| Initialization | < 100ms | TBD | Not measured |
| Memory overhead | ~2MB | TBD | Not measured |

**Note:** Measured on Linux VM (GitHub Actions). Performance optimization needed before production use.

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Detection | C++20 | High-performance core |
| Crypto | OpenSSL / BCrypt | Secure communications |
| Hashing | SHA-256, BLAKE2b | Integrity verification |
| GUI | Qt 6 / QML | Cortex workbench |
| Disassembly | Capstone 5.x | Binary analysis |
| Testing | GTest / CTest | Unit & integration tests |

---

## Known Limitations

### What Works Against:
✅ Public cheat tools (Cheat Engine basic mode)  
✅ Basic DLL injection (LoadLibrary)  
✅ Obvious debugger attachment  
✅ Simple memory patching  

### What Does NOT Work Against:
❌ Kernel-mode drivers  
❌ Page table manipulation (shadow pages)  
❌ Sophisticated restore-on-scan techniques  
❌ Hardware breakpoints exclusively  
❌ Hypervisor-based cheats  

### Critical Gaps:
⚠️ **Speed hack detection requires server validation** (client-side is insufficient)  
⚠️ **Heartbeat/cloud reporting not yet implemented** (critical for production)  
⚠️ **Certificate pinning not yet implemented** (MITM possible)  

See [DEFENSIVE_GAPS.md](docs/DEFENSIVE_GAPS.md) for complete analysis.

---

## Production Readiness

### Current State: 🟡 PARTIAL

**Implemented & Production-Ready:**
- ✅ Anti-Debug (with caveats for VMs)
- ✅ Anti-Hook (periodic scanning + inline macros)
- ✅ Integrity checking (basic hashing)
- ✅ Injection detection (needs JIT whitelist tuning)
- ✅ Cryptography primitives

**Needs Work Before Production:**
- 🔴 Server-side speed validation (mandatory)
- 🔴 Heartbeat/cloud reporting system
- 🔴 Certificate pinning
- 🔴 Request signing and replay protection
- 🔴 Memory/value protection APIs

**Blocking Issues:**
1. Cloud infrastructure not implemented
2. Speed hack detection requires server component
3. Network security features incomplete

📖 **Detailed status:** [IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md)

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Security Contributions:**
- Report vulnerabilities privately to security@sentinel.dev
- Propose detection improvements via pull requests
- Help expand JIT signature database

**Code Review Process:**
- All security-sensitive code requires review
- Run static analysis (CodeQL) before submitting
- Include unit tests for new detectors
- Update documentation

---

## License

Copyright © 2025 Sentinel Security. All rights reserved.

This software is proprietary. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

**Red Team Security Review:** This documentation reflects honest security analysis from an adversarial perspective. No subsystem is treated as "unbreakable."

**Philosophy:** Better to be honest about limitations than promise impossible security. Build defense-in-depth, not security theater.

**Inspiration:** Modern anti-cheat is an arms race. We aim to raise the effort bar, not claim victory.

---

## Roadmap

### Phase 1: Foundation (Current)
- [x] Core detection systems
- [x] Red team security analysis
- [x] Basic SDK API
- [ ] Cloud infrastructure
- [ ] Server-side validation

### Phase 2: Hardening (Q2 2025)
- [ ] Certificate pinning
- [ ] Request signing
- [ ] Behavioral analysis
- [ ] JIT signature expansion
- [ ] Performance optimization

### Phase 3: Advanced Detection (Q3 2025)
- [ ] Memory protection API
- [ ] Value protection API
- [ ] VM deobfuscation (Cortex)
- [ ] Machine learning correlation

### Phase 4: Production Release (Q4 2025)
- [ ] Complete documentation
- [ ] Public SDK release
- [ ] Cloud SaaS platform
- [ ] Commercial licensing

---

## Support

- **Documentation:** [docs/](docs/)
- **Issues:** [GitHub Issues](https://github.com/Lovuwer/Sentiel-RE/issues)
- **Security:** security@sentinelware.store (private disclosure)

---

**Remember:** Anti-cheat is defense-in-depth. No single system is perfect. Be honest about limitations, design for failure, and always validate server-side.
