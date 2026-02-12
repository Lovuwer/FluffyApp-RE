# FluffyApp SDK

A user-mode anti-cheat detection and telemetry SDK for Windows games.

## Current Status:  Alpha (Not Production-Ready)

Sentinel is in active development.  Core detection systems work, but cloud 
infrastructure and network security features are incomplete.

**What Works Today:**
- Anti-debug detection (IsDebuggerPresent, PEB, debug ports, timing)
- Anti-hook detection (inline hooks, IAT hooks, honeypots)
- Integrity checking (code section hashing)
- Injection detection (DLL injection, manual mapping)
- Cryptographic primitives (AES-256-GCM, SHA-256, RSA, HMAC)

**In Progress:**
- Cloud/Heartbeat reporting (Core implemented, SDK integration pending)
- Correlation engine (CRITICAL: All tests crash with SIGSEGV - see STAB-004)

**Not Yet Implemented:**
- Certificate pinning (MITM risk - P0 blocker for production)
- Request signing with replay protection
- Memory protection API
- Value protection API
- Server-side speed validation (client-side only)

**Explicitly Out of Scope:**
- Kernel-mode protection
- Hypervisor-based detection
- Hardware-based attestation

## Security Model

Sentinel operates entirely in user-mode (Ring 3). It provides:
- Detection of casual/public cheat tools
- Telemetry for security intelligence
- Deterrence, not prevention

It does NOT provide:
- Protection against kernel-mode attackers
- Guarantees against determined adversaries
- Standalone anti-cheat (requires server-side validation)

See [docs/security/security-invariants.md](docs/security/security-invariants.md) and [docs/security/defensive-gaps.md](docs/security/defensive-gaps.md) for complete analysis.

## Quick Start

[Minimal code example - verified working]

## Performance

**Measured Performance (as of 2026-01-02):**

| Operation | Current Measurement | Target Goal |
|-----------|---------------------|-------------|
| Update() | ~0.46ms | < 0.1ms (optimization in progress) |
| FullScan() | ~7-10ms | < 5ms (optimization in progress) |

*Note: Performance optimization is ongoing. Current measurements are from real-world testing with the DummyGame example.*

## Documentation

- [Documentation Hub](docs/README.md) - **Start here**: Complete documentation index
- [Integration Quickstart](docs/integration/quickstart.md) - 8-line integration guide
- [Advanced Integration](docs/integration/advanced.md) - Complete integration guide
- [Implementation Status](docs/IMPLEMENTATION_STATUS.md) - What's actually implemented
- [Security Documentation](docs/security/) - Security analysis and threat model
- [Platform Quickstarts](docs/platform/) - Windows/Linux specific guides
- [Examples](examples/) - Working code examples

## Building

[Verified build instructions]

## Contributing

[Standard contribution guidance]

## License

Proprietary. See LICENSE. 

---

**Honest Assessment:** Sentinel raises the effort bar for casual attackers. 
It is one layer in a defense-in-depth strategy, not a complete solution. 
```bash
# Configure with anti-debug disabled
cmake -B build -G "Ninja" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DSENTINEL_DISABLE_ANTIDEBUG=ON \
  -DSENTINEL_BUILD_TESTS=ON

# Build
cmake --build build --config Debug
```

This flag:
-  Allows "Just My Code" debugging in Visual Studio without false positives
-  Skips all anti-debug initialization and calibration for better performance
-  Returns empty violation lists from all anti-debug checks
-  Should **NEVER** be used in production/release builds

**Important:** Always build production releases **without** this flag to maintain security.

### SDK Integration Example

**

- [Integration Quickstart](docs/integration/quickstart.md) - 8-line integration guide
- [Advanced Integration Guide](docs/integration/advanced.md) - Complete integration guide with best practices
- [Engine-Specific Guide](docs/integration/engine-specific.md) - Unreal, Unity, Godot integration
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

**Current Measured Performance (DummyGame Test on Linux VM):**
- `Update()`: ~0.46ms (target goal: <0.1ms - optimization in progress)
- `FullScan()`: ~7-10ms (target goal: <5ms - optimization in progress)
- Memory overhead: ~2MB

 **See [DUMMY_GAME_VALIDATION.md](docs/DUMMY_GAME_VALIDATION.md) for detailed performance analysis**

**Performance Notes:**
- Measurements from VM environment (GitHub Actions)
- Real-world performance may vary by hardware
- Performance optimization is ongoing
- Consider increasing scan intervals if frame rate affected 

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

