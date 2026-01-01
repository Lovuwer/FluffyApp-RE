# Sentinel SDK Troubleshooting Guide

**Version:** 1.0.0  
**Last Updated:** 2025-01-01

---

## Table of Contents

1. [Top 10 Common Issues](#top-10-common-issues)
2. [Installation & Build Issues](#installation--build-issues)
3. [Initialization Errors](#initialization-errors)
4. [Runtime Issues](#runtime-issues)
5. [Performance Problems](#performance-problems)
6. [False Positives](#false-positives)
7. [Integration Issues](#integration-issues)
8. [Network & Cloud Reporting](#network--cloud-reporting)
9. [Platform-Specific Issues](#platform-specific-issues)
10. [Debugging Tips](#debugging-tips)
11. [Getting Support](#getting-support)

---

## Top 10 Common Issues

These are the most frequently encountered issues and their quick fixes.

### Issue #1: SDK Fails to Initialize with "Invalid License"

**Symptoms:**
```
Error: Failed to initialize Sentinel SDK
Error code: 4 (InvalidLicense)
```

**Causes:**
- License key is incorrect or expired
- License key contains extra whitespace or quotes
- Network issue preventing license validation
- License key is for wrong platform/build

**Solutions:**

1. **Verify license key format:**
```cpp
// WRONG - includes quotes from config file
config.license_key = "\"ABC123-DEF456-GHI789\"";

// CORRECT
config.license_key = "ABC123-DEF456-GHI789";
```

2. **Check for whitespace:**
```cpp
// Trim whitespace
std::string license = ReadFromConfig();
license.erase(license.find_last_not_of(" \n\r\t") + 1);
config.license_key = license.c_str();
```

3. **Test with trial key:**
```cpp
// Use trial key for development
config.license_key = "TRIAL-KEY-DEV";
```

4. **Check network connectivity:**
```bash
# Test if license server is reachable
curl -I https://license.sentinel.dev
```

**Workaround for Development:**
```cpp
#ifdef DEBUG
    config.license_key = "TRIAL-KEY-DEV";
#else
    config.license_key = production_key;
#endif
```

---

### Issue #2: Game Crashes on Shutdown

**Symptoms:**
- Game crashes or hangs when closing
- Segmentation fault during cleanup
- "Use-after-free" error in logs

**Causes:**
- SDK functions called after `Shutdown()`
- Protected value handles not destroyed before shutdown
- Memory regions still protected during shutdown
- Violation callback accessing freed memory

**Solutions:**

1. **Proper cleanup order:**
```cpp
void CleanupGame() {
    // 1. Destroy all protected values FIRST
    if (health_handle != 0) {
        DestroyProtectedValue(health_handle);
        health_handle = 0;
    }
    if (gold_handle != 0) {
        DestroyProtectedValue(gold_handle);
        gold_handle = 0;
    }
    
    // 2. Unprotect memory regions
    if (memory_handle != 0) {
        UnprotectMemory(memory_handle);
        memory_handle = 0;
    }
    
    // 3. Shutdown SDK LAST
    Shutdown();
}
```

2. **Avoid SDK calls in destructors:**
```cpp
// BAD - destructor may run after SDK shutdown
class Player {
    ~Player() {
        DestroyProtectedValue(handle);  // May crash!
    }
};

// GOOD - explicit cleanup
class Player {
    void Cleanup() {
        if (handle != 0) {
            DestroyProtectedValue(handle);
            handle = 0;
        }
    }
    ~Player() {
        // Just validate cleanup was called
        assert(handle == 0);
    }
};
```

3. **Check initialization state:**
```cpp
void Shutdown() {
    if (IsInitialized()) {
        Sentinel::SDK::Shutdown();
    }
}
```

---

### Issue #3: High Performance Overhead (Frame Drops)

**Symptoms:**
- Frame rate drops below 60 FPS
- `Update()` takes > 1ms
- Game feels sluggish
- Microstutters during gameplay

**Causes:**
- Scan intervals too aggressive
- Too many protected memory regions
- `FullScan()` called every frame
- Debug mode enabled in release build

**Solutions:**

1. **Measure actual overhead:**
```cpp
#include <chrono>

void MeasureSDKOverhead() {
    using namespace std::chrono;
    
    auto start = high_resolution_clock::now();
    Update();
    auto end = high_resolution_clock::now();
    
    auto duration = duration_cast<microseconds>(end - start);
    printf("Update() took %lld μs\n", duration.count());
}
```

2. **Adjust scan intervals:**
```cpp
// Default (balanced)
config.heartbeat_interval_ms = 1000;
config.integrity_scan_interval_ms = 5000;

// Low-end hardware (lighter)
config.heartbeat_interval_ms = 2000;
config.integrity_scan_interval_ms = 10000;
config.features = DetectionFeatures::Minimal;
```

3. **Disable debug mode:**
```cpp
// CRITICAL: Must be false in release builds!
#ifdef NDEBUG
    config.debug_mode = false;
    config.log_path = nullptr;
#else
    config.debug_mode = true;
    config.log_path = "/tmp/sentinel_debug.log";
#endif
```

4. **Reduce protected regions:**
```cpp
// BAD - too many small regions
for (int i = 0; i < 1000; i++) {
    ProtectMemory(&data[i], sizeof(int), "data");
}

// GOOD - one large region
ProtectMemory(data, sizeof(data), "data_array");
```

5. **Don't call FullScan() every frame:**
```cpp
// BAD
void GameLoop() {
    Update();
    FullScan();  // Don't do this every frame!
}

// GOOD
static float scan_timer = 0.0f;
void GameLoop(float delta) {
    Update();  // Lightweight, every frame
    
    scan_timer += delta;
    if (scan_timer >= 5.0f) {
        FullScan();  // Heavy, every 5 seconds
        scan_timer = 0.0f;
    }
}
```

---

### Issue #4: False Positive - Debugger Detected

**Symptoms:**
- "Debugger detected" violation during legitimate debugging
- Cannot debug game in Visual Studio or GDB
- Anti-debug triggers in VM environments

**Causes:**
- Legitimate debugger attached during development
- Running in virtual machine (VMware, VirtualBox)
- Running under profiler or analysis tool
- Debug features enabled in release build

**Solutions:**

1. **Use development build with anti-debug disabled:**
```bash
# Configure with anti-debug disabled for development
cmake -B build -DSENTINEL_DISABLE_ANTIDEBUG=ON
cmake --build build
```

2. **Conditional anti-debug:**
```cpp
#ifdef DEVELOPER_BUILD
    // Disable anti-debug for developers
    config.features = static_cast<DetectionFeatures>(
        static_cast<uint32_t>(DetectionFeatures::Standard) & 
        ~static_cast<uint32_t>(DetectionFeatures::AntiDebug)
    );
#else
    config.features = DetectionFeatures::Standard;
#endif
```

3. **Handle false positives in callback:**
```cpp
bool ViolationHandler(const ViolationEvent* event, void* user_data) {
    if (event->type == ViolationType::DebuggerAttached) {
        #ifdef DEBUG
            // Ignore debugger in debug builds
            return true;
        #else
            // Only enforce in release builds
            LogWarning("Debugger detected in release build!");
            return true;
        #endif
    }
    return true;
}
```

4. **Whitelist known development tools:**
```cpp
void InitForDevelopment() {
    // Whitelist Visual Studio debugger threads
    WhitelistThreadOrigin("msvsmon.exe", "Visual Studio debugger");
    
    // Initialize with reduced checks
    config.features = DetectionFeatures::Minimal;
}
```

---

### Issue #5: "BufferTooSmall" Error in Packet Encryption

**Symptoms:**
```
Error: EncryptPacket failed
Error code: 105 (BufferTooSmall)
```

**Causes:**
- Output buffer not large enough for encrypted data + overhead
- Not accounting for IV, authentication tag, and padding

**Solutions:**

1. **Use proper buffer size:**
```cpp
// Calculate required size: input_size + IV (16) + tag (16) + padding (16)
size_t input_size = sizeof(packet);
size_t required_size = input_size + 48;  // Add overhead

uint8_t encrypted[2048];  // Make sure this is large enough
size_t encrypted_size = sizeof(encrypted);

ErrorCode result = EncryptPacket(
    &packet, input_size,
    encrypted, &encrypted_size
);
```

2. **Dynamic allocation:**
```cpp
size_t input_size = sizeof(packet);
size_t buffer_size = input_size + 64;  // Extra overhead
std::vector<uint8_t> encrypted(buffer_size);
size_t encrypted_size = buffer_size;

ErrorCode result = EncryptPacket(
    &packet, input_size,
    encrypted.data(), &encrypted_size
);

// encrypted_size now contains actual size used
```

3. **Check returned size:**
```cpp
size_t encrypted_size = sizeof(encrypted);
ErrorCode result = EncryptPacket(
    &packet, sizeof(packet),
    encrypted, &encrypted_size
);

if (result == ErrorCode::Success) {
    printf("Encrypted size: %zu bytes\n", encrypted_size);
    SendToServer(encrypted, encrypted_size);
}
```

**Rule of Thumb:**
> Allocate `input_size + 64` bytes for encrypted output buffer.

---

### Issue #6: Protected Values Return Wrong Value

**Symptoms:**
- `GetProtectedInt()` returns unexpected value
- Protected value seems corrupted
- Value changes unexpectedly

**Causes:**
- Wrong handle used (copy-paste error)
- Handle used after `DestroyProtectedValue()`
- Handle from different SDK instance
- Memory corruption

**Solutions:**

1. **Validate handles:**
```cpp
class ProtectedValue {
    uint64_t handle_ = 0;
    bool valid_ = false;
    
public:
    ProtectedValue(int64_t value) {
        handle_ = CreateProtectedInt(value);
        valid_ = (handle_ != 0);
        if (!valid_) {
            throw std::runtime_error("Failed to create protected value");
        }
    }
    
    ~ProtectedValue() {
        if (valid_ && handle_ != 0) {
            DestroyProtectedValue(handle_);
            handle_ = 0;
            valid_ = false;
        }
    }
    
    int64_t Get() const {
        if (!valid_ || handle_ == 0) {
            throw std::runtime_error("Invalid handle");
        }
        return GetProtectedInt(handle_);
    }
    
    void Set(int64_t value) {
        if (!valid_ || handle_ == 0) {
            throw std::runtime_error("Invalid handle");
        }
        SetProtectedInt(handle_, value);
    }
};
```

2. **Debug logging:**
```cpp
void DebugProtectedValue(uint64_t handle, const char* name) {
    printf("Protected value '%s': handle=0x%llX\n", name, handle);
    
    int64_t value = GetProtectedInt(handle);
    printf("  Current value: %lld\n", value);
}
```

3. **Zero handles after destruction:**
```cpp
DestroyProtectedValue(health_handle);
health_handle = 0;  // Prevent use-after-free

// Later, check before use
if (health_handle != 0) {
    int64_t health = GetProtectedInt(health_handle);
}
```

---

### Issue #7: SDK Not Detecting Known Cheats

**Symptoms:**
- Cheat Engine modifies game values without detection
- DLL injection not detected
- Cheaters bypass protection

**Reality Check:**
> ⚠️ **User-mode SDK cannot prevent determined attackers.** The SDK provides deterrence and telemetry, not bulletproof protection.

**Understanding Limitations:**

1. **What SDK CAN detect:**
   - Cheat Engine (basic mode)
   - Simple DLL injection via LoadLibrary
   - Obvious debugger attachment
   - Basic memory patching

2. **What SDK CANNOT detect:**
   - Kernel-mode drivers
   - Page table manipulation
   - Sophisticated restore-on-scan techniques
   - Hardware breakpoints exclusively
   - Hypervisor-based cheats

**Solutions:**

1. **Implement server-side validation:**
```cpp
// Client-side (SDK)
void MovePlayer(float x, float y, float z) {
    // SDK provides telemetry
    player.position = {x, y, z};
    
    // Send to server
    SendPositionUpdate(x, y, z);
}

// Server-side (authoritative)
void ValidatePlayerPosition(Player* player, float x, float y, float z) {
    // Calculate maximum possible movement
    float max_distance = player->speed * delta_time;
    float actual_distance = Distance(player->position, {x, y, z});
    
    if (actual_distance > max_distance * 1.5f) {
        // Speed hack detected
        BanPlayer(player->id, "Speed hack detected");
        return;
    }
    
    // Accept movement
    player->position = {x, y, z};
}
```

2. **Use SDK for telemetry:**
```cpp
config.violation_callback = [](const ViolationEvent* event, void*) {
    // Don't terminate immediately - collect evidence
    LogToServer("violation", {
        {"type", event->type},
        {"severity", event->severity},
        {"details", event->details}
    });
    
    // Continue monitoring
    return true;
};
```

3. **Defense-in-depth:**
```
┌─────────────────────────────────┐
│ 1. Client Detection (SDK)       │ ← Deter casual attackers
├─────────────────────────────────┤
│ 2. Server Validation            │ ← Authoritative checks
├─────────────────────────────────┤
│ 3. Behavioral Analysis          │ ← Pattern detection
├─────────────────────────────────┤
│ 4. Economic Disincentives       │ ← HWID bans, delayed ban waves
└─────────────────────────────────┘
```

**Key Insight:**
> The best approach is to combine client-side detection (SDK) with server-side validation. Never trust the client alone.

---

### Issue #8: Memory Leak / Growing Memory Usage

**Symptoms:**
- Memory usage grows over time
- Game crashes after extended play (hours)
- Out of memory errors

**Causes:**
- Protected values not destroyed
- Memory regions not unprotected
- Handles leaked in exception paths
- Circular references

**Solutions:**

1. **Use RAII wrappers:**
```cpp
class ScopedProtectedValue {
    uint64_t handle_;
    
public:
    explicit ScopedProtectedValue(int64_t value)
        : handle_(CreateProtectedInt(value)) {}
    
    ~ScopedProtectedValue() {
        if (handle_ != 0) {
            DestroyProtectedValue(handle_);
        }
    }
    
    // Prevent copying
    ScopedProtectedValue(const ScopedProtectedValue&) = delete;
    ScopedProtectedValue& operator=(const ScopedProtectedValue&) = delete;
    
    int64_t Get() const { return GetProtectedInt(handle_); }
    void Set(int64_t v) { SetProtectedInt(handle_, v); }
};

// Usage - automatically cleaned up
{
    ScopedProtectedValue health(100);
    health.Set(health.Get() - 10);
}  // Automatically destroyed here
```

2. **Track handles:**
```cpp
class HandleTracker {
    std::vector<uint64_t> handles_;
    
public:
    uint64_t Create(int64_t value) {
        uint64_t handle = CreateProtectedInt(value);
        if (handle != 0) {
            handles_.push_back(handle);
        }
        return handle;
    }
    
    void DestroyAll() {
        for (uint64_t handle : handles_) {
            DestroyProtectedValue(handle);
        }
        handles_.clear();
    }
    
    ~HandleTracker() {
        DestroyAll();
    }
};
```

3. **Monitor statistics:**
```cpp
void CheckForLeaks() {
    Statistics stats;
    GetStatistics(&stats);
    
    printf("Protected regions: %u\n", stats.protected_regions);
    printf("Protected functions: %u\n", stats.protected_functions);
    printf("Total protected bytes: %llu\n", stats.total_protected_bytes);
    
    // Alert if growing unexpectedly
    static uint32_t last_regions = 0;
    if (stats.protected_regions > last_regions + 100) {
        LogWarning("Possible memory leak - regions growing");
    }
    last_regions = stats.protected_regions;
}
```

---

### Issue #9: Unity Integration - DLL Not Found

**Symptoms:**
- `DllNotFoundException: SentinelSDK`
- Unity crashes on play
- SDK functions not available

**Causes:**
- DLL not in correct location
- Wrong platform (x86 vs x64)
- Missing dependencies (OpenSSL)
- Unity not refreshing assets

**Solutions:**

1. **Correct DLL placement:**
```
Assets/
├── Plugins/
│   ├── x86/          (for 32-bit builds)
│   │   └── SentinelSDK.dll
│   └── x86_64/       (for 64-bit builds - most common)
│       ├── SentinelSDK.dll
│       ├── SentinelCore.dll
│       ├── libcrypto-3-x64.dll    (OpenSSL)
│       └── libssl-3-x64.dll       (OpenSSL)
```

2. **Check Unity platform settings:**
```
Edit > Project Settings > Player > Other Settings
- Architecture: x86_64 (64-bit)
- API Compatibility Level: .NET Standard 2.1
```

3. **Force Unity to refresh:**
```
Assets > Reimport All
```

4. **Test DLL loading:**
```csharp
using System.Runtime.InteropServices;

[DllImport("SentinelSDK", CallingConvention = CallingConvention.StdCall)]
private static extern IntPtr SentinelGetVersion();

void Start() {
    try {
        IntPtr versionPtr = SentinelGetVersion();
        string version = Marshal.PtrToStringAnsi(versionPtr);
        Debug.Log($"SDK Version: {version}");
    } catch (DllNotFoundException e) {
        Debug.LogError($"SDK DLL not found: {e.Message}");
        Debug.LogError("Check Plugins/x86_64/ directory");
    }
}
```

5. **Check dependencies:**
```bash
# Windows - use Dependency Walker
dumpbin /DEPENDENTS SentinelSDK.dll

# Look for missing DLLs
```

---

### Issue #10: Unreal Engine - Link Errors

**Symptoms:**
```
Error LNK2019: unresolved external symbol Initialize
Error LNK2001: unresolved external symbol Update
```

**Causes:**
- SDK not properly linked in .Build.cs
- Wrong library path
- Missing .lib file
- C++ name mangling issues

**Solutions:**

1. **Correct Build.cs configuration:**
```csharp
using UnrealBuildTool;
using System.IO;

public class YourGame : ModuleRules
{
    public YourGame(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        
        PublicDependencyModuleNames.AddRange(new string[] {
            "Core", "CoreUObject", "Engine", "InputCore"
        });
        
        // Add Sentinel SDK
        string SDKPath = Path.Combine(ModuleDirectory, "../../ThirdParty/SentinelSDK");
        string IncludePath = Path.Combine(SDKPath, "include");
        string LibPath = Path.Combine(SDKPath, "lib", "Win64");
        
        PublicIncludePaths.Add(IncludePath);
        
        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            PublicAdditionalLibraries.Add(Path.Combine(LibPath, "SentinelSDK.lib"));
            PublicAdditionalLibraries.Add(Path.Combine(LibPath, "SentinelCore.lib"));
            
            // Copy DLLs to output
            string DLLPath = Path.Combine(SDKPath, "bin", "Win64");
            RuntimeDependencies.Add(Path.Combine(DLLPath, "SentinelSDK.dll"));
            RuntimeDependencies.Add(Path.Combine(DLLPath, "SentinelCore.dll"));
        }
        
        bEnableExceptions = true;
    }
}
```

2. **Verify file structure:**
```
YourProject/
├── Source/
│   └── YourGame/
│       └── YourGame.Build.cs
└── ThirdParty/
    └── SentinelSDK/
        ├── include/
        │   └── SentinelSDK.hpp
        ├── lib/
        │   └── Win64/
        │       ├── SentinelSDK.lib
        │       └── SentinelCore.lib
        └── bin/
            └── Win64/
                ├── SentinelSDK.dll
                └── SentinelCore.dll
```

3. **Clean and rebuild:**
```bash
# Delete intermediate files
rm -rf Intermediate/
rm -rf Binaries/

# Regenerate project files
./GenerateProjectFiles.bat

# Rebuild
msbuild YourGame.sln /t:Rebuild /p:Configuration=Development
```

4. **Check for C++ mangling:**
```cpp
// In your code, use explicit namespace
using namespace Sentinel::SDK;

// NOT
using namespace Sentinel;  // Too broad
```

---

## Installation & Build Issues

### CMake Cannot Find OpenSSL

**Symptoms:**
```
CMake Error: Could not find OpenSSL
```

**Solutions:**

**Linux:**
```bash
sudo apt-get install libssl-dev
```

**Windows:**
```powershell
# Using vcpkg
vcpkg install openssl:x64-windows

# Set environment variable
$env:OPENSSL_ROOT_DIR = "C:\vcpkg\installed\x64-windows"

# Configure CMake
cmake -B build -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
```

**macOS:**
```bash
brew install openssl

# Set CMake variables
cmake -B build -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl
```

### Compiler Version Too Old

**Symptoms:**
```
Error: C++20 features not supported
```

**Solutions:**

**Minimum versions required:**
- MSVC: 19.29+ (Visual Studio 2022)
- GCC: 13.0+
- Clang: 15.0+

**Linux - Update GCC:**
```bash
# Ubuntu 22.04+
sudo apt-get install gcc-13 g++-13

# Set as default
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 60
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 60
```

---

## Initialization Errors

### "License Key Required"

**Solution:**
```cpp
Configuration config = Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";  // Must set!
config.game_id = "your-game-id";          // Must set!

ErrorCode result = Initialize(&config);
```

### "Already Initialized"

**Solution:**
```cpp
// Check before initializing
if (!IsInitialized()) {
    Initialize(&config);
}
```

Or allow re-initialization:
```cpp
if (IsInitialized()) {
    Shutdown();
}
Initialize(&config);
```

---

## Runtime Issues

### Violation Callback Not Called

**Causes:**
- Callback not set in configuration
- `ResponseAction::Notify` not enabled

**Solution:**
```cpp
config.violation_callback = MyViolationHandler;
config.callback_user_data = &game_state;
config.default_action = ResponseAction::Log | 
                        ResponseAction::Report | 
                        ResponseAction::Notify;  // Must include Notify!
```

### SDK Functions Return "NotInitialized"

**Solution:**
```cpp
// Always check initialization
if (!IsInitialized()) {
    ErrorCode result = Initialize(&config);
    if (result != ErrorCode::Success) {
        fprintf(stderr, "Init failed: %s\n", GetLastError());
        return -1;
    }
}

// Now safe to call other functions
Update();
```

---

## Performance Problems

### Frame Time Spikes During FullScan()

**Expected Behavior:**
`FullScan()` is heavier than `Update()` and may take 5-10ms.

**Solutions:**

1. **Increase scan interval:**
```cpp
config.integrity_scan_interval_ms = 10000;  // Every 10 seconds
```

2. **Run on separate thread (advanced):**
```cpp
std::thread scan_thread;
std::atomic<bool> scanning{false};

void PeriodicScan() {
    while (game_running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        if (!scanning.exchange(true)) {
            FullScan();
            scanning = false;
        }
    }
}

// Start background thread
scan_thread = std::thread(PeriodicScan);
```

---

## False Positives

### JIT Compiler Detected as Injection

**Symptoms:**
- .NET JIT compiler flagged
- Unity Mono/IL2CPP flagged
- Browser JavaScript engines flagged

**Solution:**
```cpp
// Whitelist known JIT compilers
WhitelistThreadOrigin("clr.dll", ".NET CLR JIT");
WhitelistThreadOrigin("mono.dll", "Mono runtime");
WhitelistThreadOrigin("UnityPlayer.dll", "Unity engine");
```

### Legitimate DLLs Flagged

**Solution:**
Create whitelist of known good modules in your configuration.

---

## Integration Issues

### Multi-Threading Crashes

**Symptoms:**
- Random crashes
- Data corruption
- Race conditions

**Cause:**
SDK API is not thread-safe by default.

**Solution:**
```cpp
// Call SDK functions from main thread ONLY
std::mutex sdk_mutex;

void ThreadSafeUpdate() {
    std::lock_guard<std::mutex> lock(sdk_mutex);
    Update();
}
```

---

## Network & Cloud Reporting

### "Network Error" When Reporting

**Causes:**
- Cloud endpoint not reachable
- Firewall blocking
- Invalid endpoint URL
- Network timeout

**Solutions:**

1. **Test endpoint:**
```bash
curl -v https://api.yourgame.com/sentinel/report
```

2. **Check configuration:**
```cpp
config.cloud_endpoint = "https://api.yourgame.com/sentinel";
config.report_interval_ms = 30000;  // 30 seconds
```

3. **Handle offline mode:**
```cpp
config.cloud_endpoint = nullptr;  // Disable reporting
// SDK will queue events locally
```

---

## Platform-Specific Issues

### Linux: "Cannot Find libSentinelSDK.so"

**Solution:**
```bash
# Add to library path
export LD_LIBRARY_PATH=/path/to/sentinel/lib:$LD_LIBRARY_PATH

# Or install to system
sudo cp libSentinelSDK.so /usr/local/lib/
sudo ldconfig
```

### Windows: "DLL Not Found"

**Solution:**
```powershell
# Copy DLLs to executable directory
Copy-Item SentinelSDK.dll -Destination ./build/Release/
Copy-Item SentinelCore.dll -Destination ./build/Release/

# Or add to PATH
$env:PATH += ";C:\path\to\sentinel\bin"
```

---

## Debugging Tips

### Enable Debug Logging

```cpp
#ifdef DEBUG
    config.debug_mode = true;
    config.log_path = "/tmp/sentinel_debug.log";
#endif
```

Then check the log:
```bash
tail -f /tmp/sentinel_debug.log
```

### Get Detailed Statistics

```cpp
void PrintDetailedStats() {
    Statistics stats;
    GetStatistics(&stats);
    
    printf("=== Sentinel SDK Statistics ===\n");
    printf("Uptime: %llu ms\n", stats.uptime_ms);
    printf("Updates: %u\n", stats.updates_performed);
    printf("Scans: %u\n", stats.scans_performed);
    printf("Violations: %u detected, %u reported\n",
           stats.violations_detected, stats.violations_reported);
    printf("Performance:\n");
    printf("  Avg Update: %.2f μs\n", stats.avg_update_time_us);
    printf("  Max Update: %.2f μs\n", stats.max_update_time_us);
    printf("  Avg Scan: %.2f ms\n", stats.avg_scan_time_ms);
    printf("Protection:\n");
    printf("  Regions: %u\n", stats.protected_regions);
    printf("  Functions: %u\n", stats.protected_functions);
    printf("  Bytes: %llu\n", stats.total_protected_bytes);
}
```

### Test with Cheat Engine

**Safe testing in controlled environment:**

1. Create test build with logging
2. Attach Cheat Engine to your game
3. Check if SDK detects it
4. Review logs for detection details

**Expected result:**
```
[VIOLATION] Type: DebuggerAttached (0x0010)
[VIOLATION] Severity: High
[VIOLATION] Details: External debugger detected
```

---

## Getting Support

### Before Asking for Help

1. **Check this guide** - Your issue is likely covered here
2. **Read the error message** - It usually tells you what's wrong
3. **Check the logs** - Enable debug mode and review logs
4. **Search existing issues** - Someone may have had the same problem

### Information to Provide

When reporting an issue, include:

```
**Platform:** Windows 10 x64 / Linux Ubuntu 22.04 / etc.
**SDK Version:** 1.0.0
**Compiler:** MSVC 2022 / GCC 13 / etc.
**Game Engine:** Unreal 5.3 / Unity 2022.3 / Custom

**Issue Description:**
Clear description of the problem

**Error Message:**
[Copy exact error message here]

**Configuration:**
```cpp
// Copy your configuration code
```

**Steps to Reproduce:**
1. Initialize SDK
2. Call Update()
3. Crash occurs
```

### Support Channels

- **Documentation:** [docs/](.)
- **GitHub Issues:** [github.com/Lovuwer/Sentiel-RE/issues](https://github.com/Lovuwer/Sentiel-RE/issues)
- **Example Code:** [examples/DummyGame/](../examples/DummyGame/)
- **Technical Support:** support@sentinel.dev
- **Security Issues:** security@sentinel.dev (private disclosure)

---

## Quick Reference - Error Code Meanings

| Code | Name | Meaning | Solution |
|------|------|---------|----------|
| 0 | Success | Operation successful | Continue |
| 1 | NotInitialized | SDK not initialized | Call `Initialize()` |
| 2 | AlreadyInitialized | SDK already initialized | Check `IsInitialized()` |
| 4 | InvalidLicense | License key invalid | Check license key |
| 100 | InvalidParameter | Null/invalid parameter | Check function arguments |
| 102 | OutOfMemory | Memory allocation failed | Reduce protected regions |
| 105 | BufferTooSmall | Output buffer too small | Increase buffer size |
| 200 | TamperingDetected | Tampering detected | Check violation callback |
| 250 | CryptoError | Encryption failed | Check OpenSSL installation |

---

## Summary of Best Practices

✅ **DO:**
- Initialize SDK early in game startup
- Call `Update()` once per frame
- Call `FullScan()` every 5-10 seconds
- Destroy all handles before `Shutdown()`
- Use RAII wrappers for automatic cleanup
- Disable debug mode in release builds
- Combine with server-side validation
- Monitor performance with statistics

❌ **DON'T:**
- Call SDK functions before `Initialize()`
- Call SDK functions after `Shutdown()`
- Call `Update()` from multiple threads
- Enable debug mode in production
- Trust client-side detection alone
- Call `FullScan()` every frame
- Leak protected value handles

---

**Last Updated:** 2025-01-01  
**SDK Version:** 1.0.0  
**Coverage:** Top 10 issues + comprehensive troubleshooting

For more information, see:
- [Integration Guide](integration-guide.md)
- [API Reference](api-reference.md)
- [Example Code](../examples/DummyGame/)
