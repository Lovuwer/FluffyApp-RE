# Sentinel Security Ecosystem

[![Build Status](https://github.com/Lovuwer/Sentiel-RE/actions/workflows/build.yml/badge.svg)](https://github.com/Lovuwer/Sentiel-RE/actions)

## 🚧 Work In Progress - Phase 1: Foundation Setup

This project is currently under active development following a comprehensive production readiness plan. See [Production Readiness Plan](#production-readiness-status) for current status and roadmap.

## Military-Grade Game Security Platform

**Version:** 1.0.0  
**License:** Proprietary  
**Platform:** Windows x64, Linux (partial support)

---

## 🔧 Quick Start

### Prerequisites

**Linux:**
```bash
sudo apt-get update
sudo apt-get install -y cmake build-essential ninja-build libssl-dev
```

**Windows:**
- Visual Studio 2022 (or later) with C++20 support
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
  -DSENTINEL_BUILD_TESTS=OFF

# Build
cmake --build build --config Release

# Install (optional)
sudo cmake --install build
```

### Build Options

- `SENTINEL_BUILD_CORTEX` - Build Sentinel Cortex GUI (requires Qt6, default: ON)
- `SENTINEL_BUILD_SDK` - Build Sentinel SDK library (default: ON)
- `SENTINEL_BUILD_WATCHTOWER` - Build Sentinel Watchtower module (default: ON)
- `SENTINEL_BUILD_TESTS` - Build unit tests (default: ON)
- `SENTINEL_BUILD_DOCS` - Build documentation (default: ON)

### Running Tests

```bash
# Enable tests in CMake configuration
cmake -B build -DSENTINEL_BUILD_TESTS=ON

# Build and run tests
cmake --build build
cd build && ctest --output-on-failure
```

---

## Production Readiness Status

### ✅ Completed (Phase 1 - Foundation)
- [x] Fixed CMake build system errors
- [x] Created stub implementations for Core library modules
- [x] Created stub implementations for SDK modules
- [x] Fixed platform-specific code guards
- [x] Added .gitignore and build infrastructure
- [x] Created GitHub Actions CI/CD workflow
- [x] Created basic test infrastructure
- [x] Project builds successfully on Linux

### 🚧 In Progress
- [ ] Complete Core library implementations (Crypto, Memory, Network, Utils)
- [ ] Complete SDK implementations (Heartbeat, Detection, Protection)
- [ ] Add comprehensive unit tests with 80%+ coverage

### 📋 Planned
- Phase 2: Core Library Implementation (Months 1-3)
- Phase 3: Analysis Engine (Months 4-8)
- Phase 4: SDK Implementation (Months 8-14)
- Phase 5: Cortex GUI (Months 6-10)
- Phase 6+: Watchtower, Cloud Infrastructure, Security Hardening

For detailed roadmap, see the [Production Readiness Plan](docs/PRODUCTION_READINESS.md).

---

## Overview

Sentinel is a comprehensive C++ game security ecosystem that automatically detects and neutralizes cheats at runtime. It combines static binary analysis, live memory monitoring, and cloud-assisted patching into a unified platform.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SENTINEL SECURITY ECOSYSTEM                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│   │ SENTINEL CORTEX │    │  SENTINEL SDK   │    │   WATCHTOWER    │        │
│   │  (Workbench)    │    │   (Shield)      │    │  (Roblox Mod)   │        │
│   │                 │    │                 │    │                 │        │
│   │ • Disassembly   │    │ • Live Patching │    │ • Net Fuzzer    │        │
│   │ • Fuzzy Hashing │    │ • Integrity     │    │ • Lua Bridge    │        │
│   │ • VM Deobfusc   │    │ • Heartbeat     │    │ • Event Monitor │        │
│   │ • Diff Engine   │    │ • Anti-Hook     │    │                 │        │
│   └────────┬────────┘    └────────┬────────┘    └────────┬────────┘        │
│            │                      │                      │                 │
│            └──────────────────────┼──────────────────────┘                 │
│                                   │                                        │
│                          ┌────────▼────────┐                               │
│                          │ SENTINEL CLOUD  │                               │
│                          │                 │                               │
│                          │ • Patch Server  │                               │
│                          │ • Threat Intel  │                               │
│                          │ • Rule Engine   │                               │
│                          │ • Telemetry     │                               │
│                          └─────────────────┘                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Sentinel Cortex (Developer Workbench)
A Windows desktop application built with Qt/QML for forensic analysis of game binaries.

**Features:**
- Drag-and-drop binary analysis
- Capstone-powered disassembly
- TLSH/ssdeep fuzzy hashing
- Automated code diffing ("The Hunter")
- One-click patch generation
- VM Deobfuscation Engine (VMProtect/Themida support)

### 2. Sentinel SDK (In-Game Shield)
A lightweight C++ library integrated into game clients for live protection.

**Features:**
- Heartbeat thread for cloud sync
- Live hot-patching (< 0.01ms overhead)
- Integrity verification
- Anti-hook scanning
- Debugger detection

### 3. Sentinel Watchtower (Roblox Module)
Specialized protection for Roblox games.

**Features:**
- External network fuzzer (WinPcap)
- RemoteEvent vulnerability scanner
- Lua rule enforcement bridge
- Dynamic policy updates

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| GUI | Qt 6 / QML | Cross-platform UI |
| Disassembly | Capstone 5.x | Instruction decoding |
| Fuzzy Hashing | TLSH + ssdeep | Binary fingerprinting |
| Hooking | MinHook | Runtime interception |
| Networking | WinHTTP / libcurl | Cloud communication |
| Crypto | OpenSSL / BCrypt | Secure communications |
| Binary Diff | BSDiff | Patch generation |
| VM Analysis | Intel PIN / DynamoRIO | Dynamic instrumentation |
| Symbolic | Triton / Z3 | Symbolic execution |
| Documentation | Doxygen + Sphinx | API docs |

---

## Quick Start

### Building from Source

```powershell
# Clone and build
git clone https://github.com/sentinel-security/sentinel.git
cd sentinel
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### SDK Integration

```cpp
#include <Sentinel/SDK.hpp>

int main() {
    // Initialize Sentinel SDK
    Sentinel::Config config;
    config.apiKey = "your-api-key";
    config.gameId = "your-game-id";
    config.enableHeartbeat = true;
    config.enableIntegrityChecks = true;
    
    if (!Sentinel::Initialize(config)) {
        // Handle initialization failure
        return -1;
    }
    
    // Your game code here...
    
    Sentinel::Shutdown();
    return 0;
}
```

---

## Directory Structure

```
Sentinel/
├── CMakeLists.txt              # Root CMake configuration
├── README.md                   # This file
├── docs/                       # Documentation
│   ├── architecture/           # Architecture documents
│   ├── api/                    # API reference
│   └── tutorials/              # User guides
├── src/
│   ├── Core/                   # Shared core library
│   │   ├── Crypto/             # Cryptographic utilities
│   │   ├── Memory/             # Memory manipulation
│   │   ├── Network/            # HTTP/TLS client
│   │   └── Utils/              # Common utilities
│   ├── Cortex/                 # Developer workbench
│   │   ├── UI/                 # QML interface
│   │   ├── Analysis/           # Binary analysis engine
│   │   ├── VMDeobfuscator/     # VM deobfuscation
│   │   └── PatchGen/           # Patch generation
│   ├── SDK/                    # In-game shield
│   │   ├── Heartbeat/          # Cloud sync
│   │   ├── Patcher/            # Live patching
│   │   ├── Integrity/          # Code verification
│   │   └── AntiHook/           # Hook detection
│   └── Watchtower/             # Roblox module
│       ├── Fuzzer/             # Network fuzzer
│       └── LuaBridge/          # Lua integration
├── include/                    # Public headers
├── lib/                        # Third-party libraries
├── tests/                      # Unit tests
└── tools/                      # Build tools and scripts
```

---

## Performance Targets

| Operation | Target | Measured |
|-----------|--------|----------|
| SDK Initialization | < 50ms | TBD |
| Patch Application | < 0.01ms | TBD |
| Integrity Scan | < 1ms | TBD |
| Cloud Heartbeat | < 100ms | TBD |
| Memory Scan (1MB) | < 5ms | TBD |

---

## Security Model

- **Defense in Depth:** Multiple layers of protection
- **Zero Trust:** All inputs validated cryptographically
- **Minimal Footprint:** Smallest possible attack surface
- **Fail Secure:** Graceful degradation on failure
- **Audit Trail:** Complete logging for forensics

---

## License

Copyright © 2025 Sentinel Security. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.
