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

#### Common Multi-Threading Mistakes

**❌ WRONG - Calling Update() from Render Thread:**
```cpp
// Render thread (separate from game thread)
void RenderThread() {
    while (running) {
        Update();  // 💥 CRASH - race condition with game thread
        RenderFrame();
    }
}
```

**✓ CORRECT - Single Thread Updates:**
```cpp
// Main game thread
void GameThread() {
    while (running) {
        Update();  // ✓ Only one thread calls this
        DispatchRenderCommands();
    }
}

// Render thread
void RenderThread() {
    while (running) {
        ExecuteRenderCommands();  // No SDK calls
    }
}
```

#### Detecting Multi-Threading Issues

> **Correct me if I'm wrong, but** the SDK has no built-in protection against multi-threaded access, making data races possible.

**Add Runtime Detection (Debug Builds):**
```cpp
#ifdef DEBUG
    static std::atomic<std::thread::id> sdk_thread_id{std::thread::id()};
    
    void CheckThreadSafety() {
        auto current = std::this_thread::get_id();
        auto expected = std::thread::id();
        
        if (sdk_thread_id.compare_exchange_strong(expected, current)) {
            // First call - remember this thread
            return;
        }
        
        if (sdk_thread_id.load() != current) {
            fprintf(stderr, "FATAL: SDK called from multiple threads!\n");
            abort();
        }
    }
#endif
```

**Recommendation:** Add this check to `Update()` and `FullScan()` in debug builds.

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

### RAII Wrappers (Recommended)

> **Correct me if I'm wrong, but** manual handle management is error-prone and leads to leaks.

**Problem:**
```cpp
uint64_t handle = CreateProtectedInt(100);
if (error_condition) {
    return;  // 💥 Handle leaked!
}
DestroyProtectedValue(handle);
```

**Solution - RAII Wrapper:**
```cpp
class ProtectedInt {
    uint64_t handle_;
public:
    explicit ProtectedInt(int64_t value) 
        : handle_(Sentinel::SDK::CreateProtectedInt(value)) {}
    
    ~ProtectedInt() {
        if (handle_) {
            Sentinel::SDK::DestroyProtectedValue(handle_);
        }
    }
    
    // Delete copy, allow move
    ProtectedInt(const ProtectedInt&) = delete;
    ProtectedInt& operator=(const ProtectedInt&) = delete;
    
    ProtectedInt(ProtectedInt&& other) noexcept 
        : handle_(other.handle_) {
        other.handle_ = 0;
    }
    
    int64_t get() const {
        return Sentinel::SDK::GetProtectedInt(handle_);
    }
    
    void set(int64_t value) {
        Sentinel::SDK::SetProtectedInt(handle_, value);
    }
};

// Usage
ProtectedInt gold(1000);
gold.set(gold.get() + 100);
// Automatically cleaned up on scope exit
```

---

## Crash Paths and How to Avoid Them

### Crash Path 1: Use-After-Free

**The Crash:**
```cpp
uint64_t handle = CreateProtectedInt(100);
DestroyProtectedValue(handle);
int64_t value = GetProtectedInt(handle);  // 💥 CRASH
```

**How It Happens:**
- Handle points to freed memory
- SDK dereferences invalid pointer
- Segmentation fault or heap corruption

**Prevention:**
```cpp
uint64_t handle = CreateProtectedInt(100);
// ... use handle ...
DestroyProtectedValue(handle);
handle = 0;  // Mark as invalid
// Any future use will use handle=0, which is safer
```

---

### Crash Path 2: Double-Free

**The Crash:**
```cpp
DestroyProtectedValue(handle);
DestroyProtectedValue(handle);  // 💥 CRASH - double free
```

**How It Happens:**
- Same handle destroyed twice
- Heap corruption
- Undefined behavior

**Prevention:**
```cpp
if (handle != 0) {
    DestroyProtectedValue(handle);
    handle = 0;  // Prevent double-free
}
```

---

### Crash Path 3: Shutdown Order Violation

**The Crash:**
```cpp
Shutdown();
GetProtectedInt(handle);  // 💥 CRASH - SDK shut down
```

**How It Happens:**
- SDK resources freed during Shutdown()
- API functions access freed memory
- Crash or corruption

**Prevention:**
```cpp
// CORRECT ORDER:
DestroyProtectedValue(handle);  // 1. Clean up handles
UnprotectMemory(mem_handle);    // 2. Clean up memory protection
Shutdown();                      // 3. Shutdown SDK last
```

---

### Crash Path 4: Null Pointer Dereference

**The Crash:**
```cpp
Configuration* config = nullptr;
Initialize(config);  // 💥 CRASH - null pointer
```

**How It Happens:**
- SDK dereferences null config
- Segmentation fault

**Prevention:**
```cpp
Configuration config = Configuration::Default();
if (Initialize(&config) != ErrorCode::Success) {
    fprintf(stderr, "Init failed\n");
    return 1;
}
```

---

### Crash Path 5: Buffer Overflow

**The Crash:**
```cpp
uint8_t buffer[32];
size_t size = sizeof(buffer);
EncryptPacket(large_data, 1024, buffer, &size);  // 💥 Overflow
```

**How It Happens:**
- SDK writes beyond buffer bounds
- Heap corruption
- Possible code execution

**Prevention:**
```cpp
// Always provide adequate buffer size
uint8_t buffer[2048];  // Large enough for encrypted data + overhead
size_t size = sizeof(buffer);
ErrorCode result = EncryptPacket(data, data_size, buffer, &size);
if (result == ErrorCode::BufferTooSmall) {
    // Handle insufficient buffer
}
```

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
    // Note: Requires DetectionFeatures to support bitwise operations
    config.features = static_cast<DetectionFeatures>(
        static_cast<uint32_t>(DetectionFeatures::Standard) & 
        ~static_cast<uint32_t>(DetectionFeatures::AntiDebug)
    );
#endif
```

---

## Red-Team Observations

### Critical Reality Checks

> **This section uses honest, adversarial thinking to explain what the SDK can and cannot do. If you're integrating this SDK, you need to understand these limitations.**

---

#### Reality Check 1: User-Mode Limitations

> **Correct me if I'm wrong, but** a user-mode SDK fundamentally cannot prevent a determined attacker with kernel-mode access.

**Why This Matters:**
- The SDK runs in Ring 3 (user-mode)
- Attackers with kernel drivers run in Ring 0
- Ring 0 has complete control over Ring 3

**Attack Scenario:**
```
Kernel-mode driver can:
1. Read/write any memory (including SDK state)
2. Hide processes and modules
3. Manipulate page tables
4. Hook at kernel level
5. Disable SDK monitoring threads

The SDK has NO DEFENSE against this.
```

**What This Means for You:**
- SDK is effective against **casual attackers**
- SDK is ineffective against **dedicated attackers with kernel access**
- You MUST combine with server-side validation
- Do not market as "unbreakable" or "kernel-protected"

---

#### Reality Check 2: TOCTOU Is Unavoidable

> **Correct me if I'm wrong, but** the periodic scanning model has inherent Time-of-Check-Time-of-Use vulnerabilities that cannot be eliminated.

**The Problem:**
```
T=0.000s: SDK checks memory → All clean ✓
T=0.001s: Attacker modifies memory
T=0.002s: Cheat executes
T=4.999s: Attacker restores memory
T=5.000s: SDK checks memory → All clean ✓
```

**Attack Window:**
- `Update()` called every ~16ms (60 FPS)
- `FullScan()` called every 5-10 seconds
- Between checks, attacker has free reign

**Mitigation Attempts:**
- ✅ Increase scan frequency (performance cost)
- ✅ Randomize scan timing (small improvement)
- ❌ Eliminate the vulnerability (impossible in user-mode)

**What This Means for You:**
- Accept that sophisticated attackers can bypass periodic checks
- Use SDK for **deterrence and telemetry**, not prevention
- Validate critical state server-side

---

#### Reality Check 3: Protected Values Are Obfuscation, Not Encryption

> **Correct me if I'm wrong, but** the "protected value" system is XOR-based obfuscation that a skilled attacker can reverse in minutes.

**How It (Probably) Works:**
```cpp
// Simplified model
stored_value = actual_value ^ random_key
```

**How Attackers Break It:**
```cpp
// Step 1: Find protected value in memory
uint64_t obfuscated = scan_memory_for_handle();

// Step 2: Get actual value via API
uint64_t actual = hook_GetProtectedInt(handle);

// Step 3: Recover the key
uint64_t key = obfuscated ^ actual;

// Step 4: Modify at will
set_memory(handle_address, new_value ^ key);
```

**Time to Break:** Minutes for a skilled attacker

**What This Means for You:**
- Use for **deterring casual attackers** (effective)
- Do NOT use for **storing credentials** (insecure)
- Do NOT market as "encrypted" (it's obfuscated)
- Always validate critical values server-side

---

#### Reality Check 4: Speed Hack Detection Requires Server Validation

> **Correct me if I'm wrong, but** client-side speed hack detection is fundamentally insufficient and creates a false sense of security.

**The Problem:**
- Client measures time using OS APIs
- Attacker can hook those same APIs
- Attacker returns fake time to both game and SDK
- SDK thinks everything is normal

**Attack Scenario:**
```
// Attacker's hook
ULONGLONG WINAPI Hooked_GetTickCount64() {
    static ULONGLONG fake_time = 0;
    fake_time += 16;  // Pretend 16ms passed
    return fake_time;  // Both game and SDK see this
}
```

**Result:**
- Game runs 10× faster
- SDK's timing checks see "normal" timing
- No detection occurs

**What This Means for You:**
- 🔴 **NEVER trust client-side timing alone**
- 🔴 **ALWAYS validate movement/actions server-side**
- Document clearly that speed detection is a hint, not proof
- Consider removing client-side speedhack detection to avoid false confidence

---

#### Reality Check 5: Anti-Hook Detection Has Blind Spots

> **Correct me if I'm wrong, but** the anti-hook detector scans only 15% of functions per cycle for performance reasons, creating predictable bypass windows.

**The Tradeoff:**
- Scanning 100% of functions: ~30ms per cycle (unacceptable)
- Scanning 15% of functions: ~5ms per cycle (acceptable)

**Attacker's Strategy:**
```
1. Hook a function
2. Use it for several frames (85% chance not scanned each cycle)
3. Remove hook before it gets scanned
4. Re-hook later
```

**Statistical Analysis:**
- Probability of detection in first cycle: 15%
- Probability of detection in 5 cycles: ~56%
- Probability of detection in 10 cycles: ~80%

**What This Means for You:**
- Anti-hook is probabilistic, not deterministic
- Sophisticated attackers can time their hooks
- Document this limitation clearly
- Consider prioritizing critical functions for 100% scan rate

---

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
