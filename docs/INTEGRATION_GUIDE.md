# Sentinel-RE SDK - Integration Guide

## Overview

This guide explains how to integrate the Sentinel-RE SDK into a real game application. It covers initialization, threading requirements, shutdown procedures, and common mistakes to avoid.

**Target Audience:** Game developers integrating Sentinel-RE for anti-cheat protection.

**Philosophy:** Honest integration guidance with no security theater. We'll tell you what works, what doesn't, and what limitations exist.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Basic Integration](#basic-integration)
3. [Initialization](#initialization)
4. [Game Loop Integration](#game-loop-integration)
5. [Shutdown](#shutdown)
6. [Threading Requirements](#threading-requirements)
7. [Memory Management](#memory-management)
8. [Performance Considerations](#performance-considerations)
9. [Common Mistakes](#common-mistakes)
10. [Production vs Test Builds](#production-vs-test-builds)
11. [Debugging Integration Issues](#debugging-integration-issues)
12. [Red-Team Observations](#red-team-observations)

---

## Prerequisites

### Build Requirements

- **C++ Compiler:** C++20 compatible (MSVC 2022+, GCC 13+, Clang 15+)
- **CMake:** 3.21 or later
- **Platform:** Windows x64 (primary), Linux (partial support)
- **Dependencies:** OpenSSL (for cryptography)

### Knowledge Requirements

- Understanding of game loops and frame timing
- Basic cryptography concepts (AES, HMAC, hashing)
- Memory management in C++
- Multi-threading basics

---

## Basic Integration

### Step 1: Link the SDK

**CMake:**

```cmake
# Find or link SentinelSDK
target_link_libraries(YourGame PRIVATE
    SentinelSDK
    SentinelCore
)

# Include directories
target_include_directories(YourGame PRIVATE
    ${SENTINEL_SDK_INCLUDE_DIR}
)
```

**Manual Linking:**

- Link against `libSentinelSDK.so` (Linux) or `SentinelSDK.dll` (Windows)
- Link against `libSentinelCore.so` / `SentinelCore.dll`
- Ensure OpenSSL libraries are available

### Step 2: Include Headers

```cpp
#include <SentinelSDK.hpp>
#include <Sentinel/Core/Crypto.hpp>  // If using crypto features
```

### Step 3: Namespace Usage

**Recommended approach** (avoid ambiguity):

```cpp
// Use explicit imports to avoid conflicts
using Sentinel::SDK::ErrorCode;
using Sentinel::SDK::Configuration;
using Sentinel::SDK::Initialize;
using Sentinel::SDK::Update;
using Sentinel::SDK::Shutdown;
// ... other imports as needed
```

**Avoid:**

```cpp
using namespace Sentinel::SDK;  // Can cause ambiguity with ErrorCode
using namespace Sentinel;       // Too broad
```

---

## Initialization

### Minimal Initialization

```cpp
#include <SentinelSDK.hpp>

int main() {
    using namespace Sentinel::SDK;
    
    // Create default configuration
    Configuration config = Configuration::Default();
    config.license_key = "YOUR-LICENSE-KEY";
    config.game_id = "your-game-id";
    
    // Initialize SDK
    ErrorCode result = Initialize(&config);
    if (result != ErrorCode::Success) {
        fprintf(stderr, "Failed to initialize Sentinel SDK\n");
        fprintf(stderr, "Error: %s\n", GetLastError());
        return 1;
    }
    
    // Your game code here
    
    // Shutdown before exit
    Shutdown();
    return 0;
}
```

### Recommended Configuration

```cpp
Configuration config = Configuration::Default();

// Required fields
config.license_key = "YOUR-LICENSE-KEY";
config.game_id = "your-game-id-v1";

// Detection features
config.features = DetectionFeatures::Standard;  // Recommended for most games
// Or: DetectionFeatures::Full for maximum protection
// Or: DetectionFeatures::Minimal for low overhead

// Response actions
config.default_action = ResponseAction::Log | ResponseAction::Report;

// Callbacks
config.violation_callback = YourViolationHandler;
config.callback_user_data = &your_game_state;

// Performance tuning
config.heartbeat_interval_ms = 1000;        // Heartbeat check interval
config.integrity_scan_interval_ms = 5000;   // Full scan interval

// Debug mode (DISABLE IN RELEASE!)
config.debug_mode = false;
config.log_path = nullptr;
```

### Violation Callback

```cpp
bool SENTINEL_CALL ViolationHandler(
    const Sentinel::SDK::ViolationEvent* event, 
    void* user_data
) {
    if (!event) return true;
    
    // Log the violation
    LogToFile("Violation detected: Type=0x%X, Severity=%d",
              static_cast<uint32_t>(event->type),
              static_cast<int>(event->severity));
    
    // Take action based on severity
    switch (event->severity) {
        case Sentinel::SDK::Severity::Info:
        case Sentinel::SDK::Severity::Warning:
            // Low severity - continue monitoring
            return true;
            
        case Sentinel::SDK::Severity::High:
        case Sentinel::SDK::Severity::Critical:
            // High severity - take action
            // In production: disconnect player, report to server
            ReportToServer(event);
            return true;  // Continue monitoring for more events
    }
    
    return true;
}
```

---

## Game Loop Integration

### Per-Frame Update

Call `Update()` **once per frame** in your main game loop:

```cpp
void GameLoop() {
    while (game_running) {
        // SDK lightweight check (< 0.5ms typically)
        Sentinel::SDK::ErrorCode result = Sentinel::SDK::Update();
        if (result != Sentinel::SDK::ErrorCode::Success) {
            // Log but don't crash - handle gracefully
            LogWarning("SDK Update failed: %d", static_cast<int>(result));
        }
        
        // Your game logic
        UpdateGameLogic(delta_time);
        RenderFrame();
        
        // Frame rate limiting
        WaitForNextFrame();
    }
}
```

**Performance Budget:**
- Target: < 0.1 ms per frame
- Actual: ~0.4-0.5 ms (measured in DummyGame)
- ⚠️ **RED TEAM NOTE:** Current implementation exceeds target budget

### Periodic Full Scans

Call `FullScan()` periodically (every 5-10 seconds):

```cpp
// Track time since last scan
static auto last_scan_time = std::chrono::steady_clock::now();

void GameLoop() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_scan_time
    ).count();
    
    if (elapsed >= 5) {  // Every 5 seconds
        Sentinel::SDK::ErrorCode result = Sentinel::SDK::FullScan();
        if (result != Sentinel::SDK::ErrorCode::Success) {
            LogWarning("SDK FullScan failed: %d", static_cast<int>(result));
        }
        last_scan_time = now;
    }
    
    // Rest of game loop
}
```

**Performance Budget:**
- Target: < 5 ms
- Actual: ~7-10 ms (measured in DummyGame)
- ⚠️ **RED TEAM NOTE:** May cause frame drops on slow hardware

### Pause/Resume During Loading

```cpp
void StartLoadingScreen() {
    // Pause SDK monitoring during intensive operations
    Sentinel::SDK::Pause();
    
    LoadHeavyAssets();
    
    // Resume monitoring
    Sentinel::SDK::Resume();
}
```

**When to Pause:**
- Long loading screens
- Asset streaming
- Level transitions
- ⚠️ **Do NOT abuse:** Pausing disables protection!

---

## Shutdown

### Clean Shutdown

```cpp
void CleanupGame() {
    // Destroy protected values first
    if (protected_gold_handle) {
        Sentinel::SDK::DestroyProtectedValue(protected_gold_handle);
        protected_gold_handle = 0;
    }
    
    // Unprotect memory regions
    if (protected_memory_handle) {
        Sentinel::SDK::UnprotectMemory(protected_memory_handle);
        protected_memory_handle = 0;
    }
    
    // Shutdown SDK (releases all resources)
    Sentinel::SDK::Shutdown();
}
```

**Critical:**
- Call `Shutdown()` before process exit
- Clean up all handles before `Shutdown()`
- Don't call SDK functions after `Shutdown()`

### Crash-Safe Shutdown

```cpp
void SignalHandler(int signal) {
    // Emergency cleanup
    Sentinel::SDK::Shutdown();
    exit(signal);
}

int main() {
    // Register signal handlers
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);
    
    // Initialize SDK
    Initialize(&config);
    
    // Game loop
    RunGame();
    
    // Clean shutdown
    Shutdown();
    return 0;
}
```

---

## Threading Requirements

### Single-Threaded API

⚠️ **The SDK API is NOT thread-safe by default.**

**Rules:**
1. Call `Initialize()`, `Update()`, `FullScan()`, `Shutdown()` from the **same thread**
2. Typically the main game thread
3. Violation callbacks may be invoked from internal SDK threads

### Thread-Safe Operations

✅ **Safe to call from any thread:**
- `GetSecureTime()`
- `GetStatistics()` (read-only)
- Protected value access (if designed for multi-threading)

❌ **NOT safe from multiple threads:**
- `Update()`
- `FullScan()`
- `Initialize()` / `Shutdown()`

### Multi-Threaded Games

If your game has a multi-threaded architecture:

```cpp
// Main thread
void MainThread() {
    while (running) {
        Sentinel::SDK::Update();  // Main thread only
        
        // Dispatch work to worker threads
        DispatchJobs();
        
        WaitForFrame();
    }
}

// Worker threads
void WorkerThread() {
    while (running) {
        ProcessJob();
        // Do NOT call Update() or FullScan() here!
    }
}
```

---

## Memory Management

### Protected Values

```cpp
// Create protected value
uint64_t gold_handle = Sentinel::SDK::CreateProtectedInt(1000);

// Read value
int64_t gold = Sentinel::SDK::GetProtectedInt(gold_handle);

// Modify value
Sentinel::SDK::SetProtectedInt(gold_handle, gold + 100);

// Destroy when done (before shutdown)
Sentinel::SDK::DestroyProtectedValue(gold_handle);
```

**Lifetime:**
- Handles remain valid until `DestroyProtectedValue()` or `Shutdown()`
- Don't use handles after destruction
- Don't leak handles (memory leak)

### Memory Protection

```cpp
// Protect critical data
int critical_data[256] = { /* ... */ };
uint64_t handle = Sentinel::SDK::ProtectMemory(
    critical_data,
    sizeof(critical_data),
    "CriticalGameData"
);

// Verify integrity periodically
bool intact = Sentinel::SDK::VerifyMemory(handle);
if (!intact) {
    // Memory was modified!
    HandleTampering();
}

// Unprotect before freeing memory
Sentinel::SDK::UnprotectMemory(handle);
```

**Limitations:**
- User-mode protection only
- Can be bypassed with kernel access
- TOCTOU vulnerability between checks

---

## Performance Considerations

### Measured Performance (DummyGame Test)

| Operation | Target | Actual | Status |
|-----------|--------|--------|--------|
| `Update()` | < 0.1 ms | ~0.46 ms | ⚠️ Over budget |
| `FullScan()` | < 5 ms | ~7-10 ms | ⚠️ Over budget |
| Memory overhead | ~2 MB | TBD | Unknown |

### Performance Tips

1. **Call `Update()` once per frame, not multiple times**
   ```cpp
   // GOOD
   Update();
   UpdateGame();
   RenderFrame();
   
   // BAD
   Update();
   UpdatePhysics();
   Update();  // Don't call multiple times!
   UpdateAI();
   ```

2. **Adjust scan intervals based on performance**
   ```cpp
   config.heartbeat_interval_ms = 1000;      // Increase if needed
   config.integrity_scan_interval_ms = 10000; // Increase to 10s if slow
   ```

3. **Use `Pause()` during loading screens**
   ```cpp
   Pause();
   LoadLevel();
   Resume();
   ```

4. **Profile your game with SDK enabled**
   - Measure actual impact
   - Adjust intervals if frame rate drops

---

## Common Mistakes

### ❌ Mistake 1: Forgetting to Call `Shutdown()`

```cpp
// BAD
int main() {
    Initialize(&config);
    RunGame();
    return 0;  // Memory leak! Shutdown() not called
}

// GOOD
int main() {
    Initialize(&config);
    RunGame();
    Shutdown();  // Clean shutdown
    return 0;
}
```

**Consequence:** Memory leaks, resource leaks

---

### ❌ Mistake 2: Calling SDK Functions Before `Initialize()`

```cpp
// BAD
uint64_t handle = CreateProtectedInt(100);  // SDK not initialized!
Initialize(&config);

// GOOD
Initialize(&config);
uint64_t handle = CreateProtectedInt(100);
```

**Consequence:** Crash or undefined behavior

---

### ❌ Mistake 3: Using Handles After `Shutdown()`

```cpp
// BAD
Initialize(&config);
uint64_t handle = CreateProtectedInt(100);
Shutdown();
int value = GetProtectedInt(handle);  // Use-after-free!

// GOOD
Initialize(&config);
uint64_t handle = CreateProtectedInt(100);
DestroyProtectedValue(handle);  // Cleanup first
Shutdown();
```

**Consequence:** Crash or corruption

---

### ❌ Mistake 4: Calling `Update()` from Multiple Threads

```cpp
// BAD
void WorkerThread() {
    while (running) {
        Update();  // Race condition!
        DoWork();
    }
}

// GOOD
void MainThread() {
    while (running) {
        Update();  // Main thread only
        DispatchWork();
    }
}
```

**Consequence:** Race conditions, crashes

---

### ❌ Mistake 5: Ignoring `ErrorCode` Return Values

```cpp
// BAD
Initialize(&config);  // Did it succeed?
Update();             // Did it detect anything?

// GOOD
if (Initialize(&config) != ErrorCode::Success) {
    fprintf(stderr, "Failed to initialize: %s\n", GetLastError());
    return 1;
}
```

**Consequence:** Silent failures

---

### ❌ Mistake 6: Enabling Debug Mode in Release Builds

```cpp
// BAD - in release build
config.debug_mode = true;  // Performance hit!
config.log_path = "/tmp/sentinel.log";

// GOOD - in release build
#ifdef DEBUG
    config.debug_mode = true;
    config.log_path = "/tmp/sentinel.log";
#else
    config.debug_mode = false;
    config.log_path = nullptr;
#endif
```

**Consequence:** Performance degradation, log spam

---

### ❌ Mistake 7: Callback Lifetime Issues

```cpp
// BAD
void StartGame() {
    MyGameState state;  // Local variable
    
    Configuration config = Configuration::Default();
    config.callback_user_data = &state;  // Pointer to local!
    Initialize(&config);
    
    RunGame();
    Shutdown();
}  // state destroyed - dangling pointer!

// GOOD
static MyGameState g_game_state;  // Static or global lifetime

void StartGame() {
    Configuration config = Configuration::Default();
    config.callback_user_data = &g_game_state;
    Initialize(&config);
    
    RunGame();
    Shutdown();
}
```

**Consequence:** Use-after-free in callback

---

## Production vs Test Builds

### Test Build Configuration

```cpp
#ifdef DEBUG
    config.debug_mode = true;
    config.log_path = "/tmp/sentinel_debug.log";
    config.features = DetectionFeatures::Full;  // All checks
#endif
```

### Production Build Configuration

```cpp
#ifdef NDEBUG
    config.debug_mode = false;
    config.log_path = nullptr;
    config.features = DetectionFeatures::Standard;  // Balanced
    config.cloud_endpoint = "https://api.yourgame.com/sentinel";  // Enable reporting
#endif
```

### Preprocessor Flags

```cpp
// Compile-time feature selection
#define SENTINEL_ENABLE_TELEMETRY 1   // Enable in release
#define SENTINEL_VERBOSE_LOGGING 0    // Disable in release
```

---

## Debugging Integration Issues

### Problem: SDK Fails to Initialize

**Symptoms:**
- `Initialize()` returns error code
- `GetLastError()` shows specific error

**Solutions:**
1. Check license key validity
2. Ensure OpenSSL libraries are available
3. Verify platform support (Windows/Linux)
4. Check log file if debug mode enabled

---

### Problem: Performance Degradation

**Symptoms:**
- Frame rate drops
- High CPU usage
- Stuttering

**Solutions:**
1. Measure `Update()` and `FullScan()` times
2. Increase scan intervals
3. Use `Pause()` during loading
4. Consider `DetectionFeatures::Minimal`

**Measurement:**

```cpp
auto start = std::chrono::high_resolution_clock::now();
Update();
auto end = std::chrono::high_resolution_clock::now();
auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
printf("Update took %lld µs\n", duration.count());
```

---

### Problem: False Positives

**Symptoms:**
- Violations during legitimate gameplay
- Debugger detected during development
- VM detection on cloud servers

**Solutions:**
1. Use developer-friendly config in debug builds
2. Whitelist known JIT compilers
3. Document and report false positives
4. Adjust detection thresholds

**Example:**

```cpp
#ifdef DEVELOPER_BUILD
    // Allow debugger in dev builds
    config.features = DetectionFeatures::Standard & ~DetectionFeatures::AntiDebug;
#endif
```

---

## Red-Team Observations

### What the SDK CAN Detect

✅ **Low-effort attackers:**
- Cheat Engine (basic mode)
- DLL injection (LoadLibrary)
- Obvious debugger attachment
- Simple memory editing

### What the SDK CANNOT Detect

❌ **Advanced attackers:**
- Kernel-mode drivers
- Page table manipulation (shadow pages)
- Hardware breakpoints exclusively
- Hypervisor-based cheats
- Sophisticated restore-on-scan techniques

### User-Mode Limitations

**TOCTOU Vulnerabilities:**
- Memory can change between `Update()` calls
- Integrity checks have race conditions
- Periodic scans miss fast modifications

**Bypass Techniques:**
- Hook the SDK itself
- Patch SDK in memory
- Disable monitoring threads
- Manipulate SDK data structures

### Defense-in-Depth Strategy

**The SDK is ONE layer:**

```
┌─────────────────────────────────────────────┐
│ 1. Client Detection (Sentinel SDK)         │ ← Deter casual attackers
├─────────────────────────────────────────────┤
│ 2. Server Validation                        │ ← Authoritative checks
├─────────────────────────────────────────────┤
│ 3. Behavioral Analysis                      │ ← Pattern detection
├─────────────────────────────────────────────┤
│ 4. Economic Disincentives                   │ ← HWID bans, ban waves
└─────────────────────────────────────────────┘
```

**Never rely on client-side detection alone.**

---

## Next Steps

1. **Integrate the SDK** following this guide
2. **Test with DummyGame** to understand behavior
3. **Measure performance** in your actual game
4. **Document false positives** you encounter
5. **Implement server-side validation** for critical data
6. **Report issues** to improve the SDK

---

## Support

- **Issues:** [GitHub Issues](https://github.com/Lovuwer/Sentiel-RE/issues)
- **Documentation:** [docs/](../docs/)
- **Example:** [examples/DummyGame/](../examples/DummyGame/)
- **Security:** security@sentinel.dev

---

## Philosophy

> **Anti-cheat is an arms race. Be honest about what you can and cannot protect. Design for failure. Always validate server-side.**

This SDK provides deterrence, not guarantees. Use it as part of a comprehensive security strategy.

---

**Copyright © 2025 Sentinel Security. All rights reserved.**
