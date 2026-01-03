# Copilot Instructions for Sentinel Security Ecosystem

## Project Overview

Sentinel is a user-mode anti-cheat detection and telemetry SDK for Windows games, currently in **Alpha phase** (not production-ready). It operates entirely in Ring 3 (user-mode) and provides detection capabilities for casual/public cheat tools, telemetry for security intelligence, and deterrence rather than prevention.

**Key Philosophy:** Be honest about limitations. This is defense-in-depth, not a complete solution. Never rely on client-side detection alone.

## Architecture

```
Sentinel/
├── src/Core/           # Core library (shared utilities)
├── src/SDK/            # In-game SDK (main product)
├── src/Cortex/         # GUI workbench application (Qt-based)
├── src/Watchtower/     # Roblox module
├── include/Sentinel/   # Public API headers
├── tests/              # Unit tests (Google Test)
├── examples/           # Integration examples
│   ├── MinimalIntegration/
│   ├── DummyGame/
│   └── PerformanceMetricsDemo/
└── docs/               # Comprehensive documentation
```

## Build System

**Technology:** CMake 3.21+, C++20, Ninja (preferred generator)

### Standard Build Commands

```bash
# Debug build with tests
cmake -B build -G "Ninja" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DSENTINEL_BUILD_TESTS=ON \
  -DSENTINEL_BUILD_CORTEX=OFF \
  -DSENTINEL_BUILD_WATCHTOWER=OFF

cmake --build build --config Debug

# Run tests
cd build && ctest --output-on-failure
```

### Debug Build (allows debugging without anti-debug false positives)

```bash
cmake -B build -G "Ninja" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DSENTINEL_DISABLE_ANTIDEBUG=ON \
  -DSENTINEL_BUILD_TESTS=ON

cmake --build build --config Debug
```

**Important:** `SENTINEL_DISABLE_ANTIDEBUG` should NEVER be used in production builds.

### Release Build

```bash
cmake -B build -G "Ninja" \
  -DCMAKE_BUILD_TYPE=Release \
  -DSENTINEL_BUILD_TESTS=ON

cmake --build build --config Release
```

### Running Sanitizers (REQUIRED for PRs)

```bash
# AddressSanitizer (memory errors)
cmake -B build -DSENTINEL_ENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=Debug \
  -DSENTINEL_BUILD_TESTS=ON
cmake --build build && cd build && ctest

# ThreadSanitizer (data races)
cmake -B build -DSENTINEL_ENABLE_TSAN=ON -DCMAKE_BUILD_TYPE=Debug \
  -DSENTINEL_BUILD_TESTS=ON
cmake --build build && cd build && ctest
```

**All PRs must pass both ASAN and TSAN checks.**

## Dependencies

- **Required:** CMake 3.21+, C++20 compiler (GCC 11+, Clang 14+, MSVC 19.30+), Ninja
- **Linux:** `libssl-dev`, `libcurl4-openssl-dev`, `build-essential`
- **Optional:** Qt6 (for Cortex GUI), Doxygen (for docs), Valgrind (for memory testing)
- **Third-party (auto-fetched):** Capstone 5.0.1, MinHook 1.3.3, nlohmann/json 3.11.3, spdlog 1.13.0, Google Test 1.14.0

## Coding Standards

### C++ Style

- **Standard:** C++20
- **Naming:**
  - Classes: `PascalCase` (e.g., `MemoryScanner`)
  - Functions: `PascalCase` (e.g., `Initialize()`)
  - Variables: `camelCase` (e.g., `configValue`)
  - Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_BUFFER_SIZE`)
  - Private members: `m_camelCase` or `camelCase_`
- **Headers:** One class per file, forward declarations to reduce dependencies
- **Comments:** Doxygen-style for public APIs, explain "why" not "what"

### Example

```cpp
/**
 * @brief Scans memory for specific patterns
 * @param pattern The byte pattern to search for
 * @param region The memory region to scan
 * @return Vector of matching addresses
 */
std::vector<uintptr_t> ScanMemory(
    const Pattern& pattern,
    const MemoryRegion& region);
```

### CMake Conventions

- Use modern CMake (target-based commands)
- Prefer `target_*` over global `add_*` commands
- Keep platform-specific code isolated with guards

## Testing

- **Framework:** Google Test (GTest/CTest)
- **Coverage Goal:** 80%+
- **Requirements:** Tests must be fast, isolated, and deterministic
- **Location:** `tests/` directory mirrors `src/` structure
- **All new functionality must include unit tests**

## Security Guidelines

### Critical Security Requirements

1. **User-mode only:** No kernel-mode features (Ring 3 only)
2. **Defense-in-depth:** Client detection + server validation + behavioral analysis
3. **Honest limitations:** Document what cannot be defended
4. **Memory safety:** All PRs must pass ASAN and TSAN
5. **Hardening enabled:** Stack protection, ASLR, DEP, Control Flow Guard (CFG/CFI)

### What Sentinel Can Detect

✅ Public cheat tools (Cheat Engine basic mode)
✅ Basic DLL injection (LoadLibrary)
✅ Obvious debugger attachment
✅ Simple memory patching

### What Sentinel CANNOT Defend Against

❌ Kernel-mode drivers
❌ Page table manipulation (shadow pages)
❌ Sophisticated restore-on-scan techniques
❌ Hardware breakpoints exclusively
❌ Hypervisor-based cheats

### Security Review Requirements

- All security-sensitive code requires review
- Run CodeQL static analysis before submitting
- Report vulnerabilities privately to security@sentinelware.store
- See [docs/security/](docs/security/) for detailed security documentation

## Performance Targets

| Operation | Current | Target Goal | Status |
|-----------|---------|-------------|--------|
| `Update()` | ~0.46ms | < 0.1ms | ⚠️ Optimizing |
| `FullScan()` | ~7-10ms | < 5ms | ⚠️ Optimizing |
| Memory overhead | ~2MB | ~2MB | ✅ On target |

**Note:** Measurements from Linux VM (GitHub Actions). Optimization in progress.

## Integration Pattern (8-Line Minimal)

Studios can integrate Sentinel in under 10 lines:

```cpp
#include <SentinelSDK.hpp>

// Lines 1-3: Configure
auto config = Sentinel::SDK::Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";
config.game_id = "your-game-id";
config.violation_callback = OnViolation;  // Line 4

// Line 5: Initialize
if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) return 1;

// Lines 6-7: Game loop
while (game_running) {
    Sentinel::SDK::Update();  // Once per frame (~0.46ms)
    // Your game code...
}

// Line 8: Cleanup
Sentinel::SDK::Shutdown();
```

See [examples/MinimalIntegration/](examples/MinimalIntegration/) for complete example.

## CI/CD Workflow

**Pipeline:** `.github/workflows/build.yml`

### Jobs

1. **build-linux:** Standard Release build + tests
2. **asan-build:** Debug build with AddressSanitizer
3. **tsan-build:** Debug build with ThreadSanitizer

**All PRs must pass all three jobs.**

### Build Artifacts

- `libSentinelCore.a` (static core library)
- `libSentinelSDK.so` (shared SDK library)
- `libSentinelSDK_static.a` (static SDK library)

## Documentation Structure

- [docs/README.md](docs/README.md) - Documentation hub (START HERE)
- [docs/integration/quickstart.md](docs/integration/quickstart.md) - 8-line integration guide
- [docs/integration/advanced.md](docs/integration/advanced.md) - Complete integration guide
- [docs/security/](docs/security/) - Security documentation (RED TEAM REVIEWED)
- [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) - What's implemented
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines

## Current Development Phase

**Phase 1: Foundation (Current)**

**What Works:**
- ✅ Anti-debug detection (IsDebuggerPresent, PEB, debug ports, timing)
- ✅ Anti-hook detection (inline hooks, IAT hooks, honeypots)
- ✅ Integrity checking (code section hashing)
- ✅ Injection detection (DLL injection, manual mapping)
- ✅ Cryptographic primitives (AES-256-GCM, SHA-256, RSA, HMAC)

**In Progress:**
- ⚠️ Cloud/Heartbeat reporting (Core implemented, SDK integration pending)
- ⚠️ Correlation engine (CRITICAL: All tests crash with SIGSEGV - see STAB-004)

**Not Yet Implemented (P0 Blockers):**
- 🔴 Certificate pinning (MITM risk)
- 🔴 Request signing with replay protection
- 🔴 Memory protection API
- 🔴 Value protection API
- 🔴 Server-side speed validation (client-side only)

## Common Tasks

### Adding a New Detector

1. Create header in `include/Sentinel/SDK/Detection/`
2. Create implementation in `src/SDK/Detection/`
3. Add unit tests in `tests/SDK/Detection/`
4. Update documentation
5. Run ASAN and TSAN builds
6. Update `docs/IMPLEMENTATION_STATUS.md`

### Fixing a Security Issue

1. Understand the vulnerability (review security docs)
2. Implement minimal fix
3. Add regression test
4. Run CodeQL static analysis
5. Test with ASAN/TSAN
6. Document limitation if complete fix is not possible

### Performance Optimization

1. Measure current performance (use `PerformanceMetricsDemo`)
2. Profile with appropriate tools
3. Optimize hot paths
4. Verify no security regressions
5. Re-measure and document improvement
6. Update performance targets in docs

## Commit Message Format

```
<type>: <short summary>

<detailed description>

Fixes: #<issue-number>
```

**Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `security`

## Before Submitting PR

- [ ] Code compiles without warnings on both Debug and Release
- [ ] All tests pass (including ASAN and TSAN)
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Code follows style guide
- [ ] Commit messages are clear
- [ ] No sanitizer errors (ASAN/TSAN)
- [ ] CodeQL checks pass (for security-sensitive code)

## Special Considerations

### Platform-Specific Code

- Use `#ifdef _WIN32` for Windows-only code
- Provide Linux alternatives where possible
- Test on both platforms if changes affect both
- Current focus: Linux build (Windows support coming)

### Anti-Debug Development

- Use `SENTINEL_DISABLE_ANTIDEBUG=ON` for development
- NEVER use this flag in production/release builds
- This allows "Just My Code" debugging in IDEs without false positives

### Analysis Resistance

- Enabled by default in Release builds
- Disabled in Debug builds (for debugging experience)
- Can be explicitly disabled with `-DSENTINEL_ENABLE_ANALYSIS_RESISTANCE=OFF`
- Framework automatically enables/disables based on `NDEBUG`

## Known Issues and Limitations

### Build Issues

- Qt6 optional: Cortex GUI disabled if not found
- Requires C++20 compiler (GCC 11+, Clang 14+, MSVC 19.30+)
- Windows build not yet enabled in CI (coming soon)

### Current Blockers

1. **STAB-004:** Correlation engine tests crash with SIGSEGV
2. Certificate pinning not implemented (P0 blocker)
3. Request signing not implemented (P0 blocker)
4. Cloud infrastructure incomplete

## Quick Reference

```bash
# Clean build from scratch
rm -rf build/ && cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Debug \
  -DSENTINEL_BUILD_TESTS=ON && cmake --build build

# Run specific test
cd build && ctest -R TestName --output-on-failure

# Run all tests verbose
cd build && ctest --verbose --output-on-failure

# Build documentation
cmake --build build --target docs

# Generate compile_commands.json for IDE
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

## Contact and Support

- **Issues:** GitHub Issues tracker
- **Security:** security@sentinelware.store (private disclosure)
- **Documentation:** [docs/](docs/) directory

---

**Remember:** Anti-cheat is defense-in-depth. No single system is perfect. Be honest about limitations, design for failure, and always validate server-side.
