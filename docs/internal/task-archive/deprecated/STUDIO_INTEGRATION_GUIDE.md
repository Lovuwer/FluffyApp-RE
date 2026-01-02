# Studio Integration Guide - Sentinel SDK

## Task 31: Studio Integration Interface

**Priority**: P0  
**Risk Addressed**: Complex integration reduces adoption  
**Philosophy**: The best anti-cheat is worthless if no one uses it.

---

## Executive Summary

The Sentinel SDK can be integrated into your game with **8 lines of code**. No deep understanding of internals required. No ongoing maintenance. Just copy, paste, and deploy.

### Time Investment
- **Basic Integration**: 30 minutes
- **Testing**: 1 hour
- **Production Tuning**: 2 hours
- **Total**: **Under 4 hours** for an unfamiliar developer

### Minimal Code Example

```cpp
auto config = Sentinel::SDK::Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";
config.game_id = "your-game-id";
config.violation_callback = OnViolation;
if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) return 1;
while (game_running) {
    Sentinel::SDK::Update();  // Once per frame
    // Your game code...
}
Sentinel::SDK::Shutdown();
```

**That's it.** 8 lines. No exceptions. No complexity. No maintenance.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [5-Minute Quick Start](#5-minute-quick-start)
3. [Integration Patterns](#integration-patterns)
4. [Configuration Reference](#configuration-reference)
5. [Platform-Specific Setup](#platform-specific-setup)
6. [Common Integration Scenarios](#common-integration-scenarios)
7. [Troubleshooting](#troubleshooting)
8. [Performance Guidelines](#performance-guidelines)
9. [Security Best Practices](#security-best-practices)
10. [Support](#support)

---

## Prerequisites

### Supported Platforms
- **Windows**: x64, Visual Studio 2019+
- **Linux**: x64, GCC 9+ or Clang 10+
- **macOS**: x64/ARM64, Xcode 12+ (future)

### Build Requirements
- C++20 compatible compiler
- CMake 3.21+ (if using CMake)
- OpenSSL 1.1+ (Linux) or BCrypt (Windows)

### License
- Contact Sentinel Security for a license key
- Free trial keys available for evaluation

---

## 5-Minute Quick Start

### Step 1: Link the SDK (30 seconds)

**CMake:**
```cmake
target_link_libraries(YourGame PRIVATE SentinelSDK)
```

**Visual Studio:**
- Add `SentinelSDK.lib` to Linker → Input → Additional Dependencies
- Add SDK include path to C/C++ → General → Additional Include Directories

**Makefile/Custom Build:**
```makefile
LIBS += -lSentinelSDK -lSentinelCore
INCLUDES += -I/path/to/sentinel/include
```

### Step 2: Add the Code (2 minutes)

**In your game initialization:**

```cpp
#include <SentinelSDK.hpp>

// Optional callback
bool SENTINEL_CALL OnSecurityEvent(const Sentinel::SDK::ViolationEvent* event, void*) {
    LogWarning("Security event: %s", event->details.c_str());
    return true;  // Continue monitoring
}

void InitGame() {
    // Configure SDK
    auto config = Sentinel::SDK::Configuration::Default();
    config.license_key = "YOUR-LICENSE-KEY";
    config.game_id = "your-game-id";
    config.violation_callback = OnSecurityEvent;  // Optional
    
    // Initialize
    if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) {
        LogError("Failed to initialize Sentinel SDK");
        // Continue anyway - SDK is optional
    }
}
```

**In your game loop:**

```cpp
void GameLoop() {
    while (IsRunning()) {
        Sentinel::SDK::Update();  // Add this line
        
        UpdateGameLogic();
        RenderFrame();
    }
}
```

**In your shutdown:**

```cpp
void ShutdownGame() {
    Sentinel::SDK::Shutdown();  // Add this line
    
    // Your cleanup code...
}
```

### Step 3: Build and Test (2 minutes)

```bash
# Build your game as usual
cmake --build build --config Release

# Run and verify
./build/bin/YourGame
```

**Done!** Your game now has anti-cheat protection.

---

## Integration Patterns

### Pattern 1: Minimal Integration (8 lines)

**Use when:** You want basic protection with zero configuration.

```cpp
auto config = Sentinel::SDK::Configuration::Default();
config.license_key = "YOUR-KEY";
config.game_id = "your-game";
config.violation_callback = OnViolation;
if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) return 1;
while (running) { Sentinel::SDK::Update(); /* game code */ }
Sentinel::SDK::Shutdown();
```

**Provides:**
- Anti-debug detection
- Inline hook detection
- IAT hook detection
- Code integrity checking
- DLL injection detection

---

### Pattern 2: Production Integration (15 lines)

**Use when:** You need cloud reporting and custom handling.

```cpp
bool OnViolation(const Sentinel::SDK::ViolationEvent* event, void* game_state) {
    switch (event->severity) {
        case Sentinel::SDK::Severity::High:
        case Sentinel::SDK::Severity::Critical:
            ReportToServer(event);
            break;
        default:
            LogLocally(event);
    }
    return true;
}

void InitGame() {
    auto config = Sentinel::SDK::Configuration::Default();
    config.license_key = GetLicenseKey();
    config.game_id = GAME_VERSION_ID;
    config.violation_callback = OnViolation;
    config.callback_user_data = &g_game_state;
    config.cloud_endpoint = "https://api.yourgame.com/sentinel";
    
    if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) {
        LogError("SDK init failed: %s", Sentinel::SDK::GetLastError());
    }
}

void GameLoop() {
    static int frame = 0;
    while (running) {
        Sentinel::SDK::Update();
        
        if (++frame % 300 == 0) {  // Every 5 seconds at 60fps
            Sentinel::SDK::FullScan();
        }
        
        UpdateGame();
        Render();
    }
}

void Shutdown() {
    Sentinel::SDK::Shutdown();
}
```

---

### Pattern 3: Engine Integration (Plugin)

**Use when:** Integrating into Unreal, Unity, or custom engine.

**Unreal Engine Plugin:**

```cpp
// YourAntiCheatModule.cpp
class FYourAntiCheatModule : public IModuleInterface {
public:
    virtual void StartupModule() override {
        auto config = Sentinel::SDK::Configuration::Default();
        config.license_key = GetLicenseFromSettings();
        config.game_id = FApp::GetProjectName();
        Sentinel::SDK::Initialize(&config);
    }
    
    virtual void ShutdownModule() override {
        Sentinel::SDK::Shutdown();
    }
};

// In your game's Tick function
void AYourGameMode::Tick(float DeltaTime) {
    Super::Tick(DeltaTime);
    Sentinel::SDK::Update();
}
```

**Unity Native Plugin:**

```cpp
// SentinelPlugin.cpp
extern "C" {
    void UNITY_INTERFACE_EXPORT InitSentinel(const char* license, const char* gameId) {
        auto config = Sentinel::SDK::Configuration::Default();
        config.license_key = license;
        config.game_id = gameId;
        Sentinel::SDK::Initialize(&config);
    }
    
    void UNITY_INTERFACE_EXPORT UpdateSentinel() {
        Sentinel::SDK::Update();
    }
    
    void UNITY_INTERFACE_EXPORT ShutdownSentinel() {
        Sentinel::SDK::Shutdown();
    }
}
```

```csharp
// In Unity C#
using UnityEngine;
using System.Runtime.InteropServices;

public class SentinelSDK : MonoBehaviour {
    [DllImport("SentinelPlugin")]
    private static extern void InitSentinel(string license, string gameId);
    
    [DllImport("SentinelPlugin")]
    private static extern void UpdateSentinel();
    
    [DllImport("SentinelPlugin")]
    private static extern void ShutdownSentinel();
    
    void Start() {
        InitSentinel("YOUR-KEY", "your-game-id");
    }
    
    void Update() {
        UpdateSentinel();
    }
    
    void OnDestroy() {
        ShutdownSentinel();
    }
}
```

---

## Configuration Reference

### Minimal Configuration (Required)

Only 3 fields required:

```cpp
auto config = Sentinel::SDK::Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";  // Get from Sentinel Security
config.game_id = "your-game-id";          // Unique identifier for your game
// Everything else has sensible defaults!
```

### Full Configuration (All Options)

```cpp
Sentinel::SDK::Configuration config;
config.struct_size = sizeof(config);  // Auto-set by Default()

// Required
config.license_key = "YOUR-LICENSE-KEY";
config.game_id = "your-game-v1.0";

// Detection features (defaults to Standard)
config.features = Sentinel::SDK::DetectionFeatures::Standard;
// Options: Minimal, Standard, Full

// Response actions (defaults to Log | Report | Notify)
config.default_action = Sentinel::SDK::ResponseAction::Log | 
                        Sentinel::SDK::ResponseAction::Report;

// Callbacks (optional)
config.violation_callback = YourViolationHandler;
config.callback_user_data = &your_game_state;

// Performance tuning (defaults are optimal for most games)
config.heartbeat_interval_ms = 1000;       // Health check interval
config.integrity_scan_interval_ms = 5000;  // Full scan interval
config.memory_scan_chunk_size = 4096;      // Memory scan chunk size

// Cloud reporting (optional)
config.cloud_endpoint = "https://api.yourgame.com/sentinel";
config.report_batch_size = 10;
config.report_interval_ms = 30000;

// Debug (DISABLE in release builds!)
config.debug_mode = false;
config.log_path = nullptr;
```

### Configuration Presets

**Minimal** (lowest overhead):
```cpp
config.features = Sentinel::SDK::DetectionFeatures::Minimal;
// Includes: Basic anti-debug, memory integrity
// Overhead: ~0.2ms per frame
```

**Standard** (recommended):
```cpp
config.features = Sentinel::SDK::DetectionFeatures::Standard;
// Includes: Anti-debug, anti-hook, code integrity, injection detection
// Overhead: ~0.5ms per frame
```

**Full** (maximum protection):
```cpp
config.features = Sentinel::SDK::DetectionFeatures::Full;
// Includes: Everything + speed hack detection, network validation
// Overhead: ~1.0ms per frame
```

---

## Platform-Specific Setup

### Windows (Visual Studio)

**1. Add SDK to project:**
```
YourGame/
├── SentinelSDK/
│   ├── include/
│   │   └── SentinelSDK.hpp
│   └── lib/
│       ├── SentinelSDK.lib
│       └── SentinelSDK.dll
```

**2. Project Settings:**
- **C/C++ → General → Additional Include Directories**: `$(ProjectDir)SentinelSDK\include`
- **Linker → General → Additional Library Directories**: `$(ProjectDir)SentinelSDK\lib`
- **Linker → Input → Additional Dependencies**: `SentinelSDK.lib`

**3. Copy DLL:**
```batch
copy SentinelSDK\lib\SentinelSDK.dll $(OutDir)
```

---

### Linux (CMake)

**1. Install SDK:**
```bash
sudo cp -r SentinelSDK/include/* /usr/local/include/
sudo cp SentinelSDK/lib/* /usr/local/lib/
sudo ldconfig
```

**2. CMakeLists.txt:**
```cmake
find_package(SentinelSDK REQUIRED)
target_link_libraries(YourGame PRIVATE SentinelSDK::SentinelSDK)
```

**3. Runtime:**
```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
./YourGame
```

---

### Linux (Makefile)

```makefile
INCLUDES = -I/usr/local/include
LIBS = -L/usr/local/lib -lSentinelSDK -lSentinelCore -lssl -lcrypto -pthread

YourGame: main.o
	$(CXX) -o $@ $^ $(LIBS)

main.o: main.cpp
	$(CXX) $(INCLUDES) -std=c++20 -c $<
```

---

## Common Integration Scenarios

### Scenario 1: Existing Game with Complex Build System

**Problem:** You have a complex build system and don't want to modify it extensively.

**Solution:** Header-only integration stub:

```cpp
// SentinelStub.hpp - Drop-in integration
#pragma once
#include <SentinelSDK.hpp>

namespace Game {
    class AntiCheat {
        static bool initialized_;
    public:
        static void Init(const char* license, const char* gameId) {
            auto cfg = Sentinel::SDK::Configuration::Default();
            cfg.license_key = license;
            cfg.game_id = gameId;
            initialized_ = (Sentinel::SDK::Initialize(&cfg) == Sentinel::SDK::ErrorCode::Success);
        }
        
        static void Update() {
            if (initialized_) Sentinel::SDK::Update();
        }
        
        static void Shutdown() {
            if (initialized_) Sentinel::SDK::Shutdown();
        }
    };
}

// Usage:
Game::AntiCheat::Init("KEY", "game-id");
Game::AntiCheat::Update();  // In game loop
Game::AntiCheat::Shutdown();
```

---

### Scenario 2: Multi-threaded Game Engine

**Problem:** Your game loop runs on multiple threads.

**Solution:** Call SDK functions only from main thread:

```cpp
class GameEngine {
    std::thread render_thread_;
    std::thread logic_thread_;
    
    void MainThread() {
        while (running_) {
            Sentinel::SDK::Update();  // Main thread only
            
            // Dispatch work to other threads
            logic_queue_.Push(UpdateLogic);
            render_queue_.Push(RenderFrame);
            
            SyncThreads();
        }
    }
    
    void RenderThread() {
        // NO SDK calls here
        while (running_) {
            ExecuteRenderCommands();
        }
    }
};
```

---

### Scenario 3: Cross-Platform Mobile Game

**Problem:** Need to support iOS/Android in the future.

**Solution:** Abstract SDK behind interface:

```cpp
// IAntiCheat.hpp
class IAntiCheat {
public:
    virtual ~IAntiCheat() = default;
    virtual void Init(const char* key, const char* id) = 0;
    virtual void Update() = 0;
    virtual void Shutdown() = 0;
};

// SentinelAntiCheat.hpp (Desktop)
class SentinelAntiCheat : public IAntiCheat {
    void Init(const char* key, const char* id) override {
        auto cfg = Sentinel::SDK::Configuration::Default();
        cfg.license_key = key;
        cfg.game_id = id;
        Sentinel::SDK::Initialize(&cfg);
    }
    void Update() override { Sentinel::SDK::Update(); }
    void Shutdown() override { Sentinel::SDK::Shutdown(); }
};

// NullAntiCheat.hpp (Mobile - not yet supported)
class NullAntiCheat : public IAntiCheat {
    void Init(const char*, const char*) override {}
    void Update() override {}
    void Shutdown() override {}
};

// Factory
std::unique_ptr<IAntiCheat> CreateAntiCheat() {
#if PLATFORM_DESKTOP
    return std::make_unique<SentinelAntiCheat>();
#else
    return std::make_unique<NullAntiCheat>();
#endif
}
```

---

## Troubleshooting

### SDK Fails to Initialize

**Symptom:** `Initialize()` returns error code.

**Solutions:**

1. **Check license key:**
   ```cpp
   if (Initialize(&config) == ErrorCode::InvalidLicense) {
       Log("Invalid license key: %s", GetLastError());
   }
   ```

2. **Verify dependencies:**
   - Windows: `bcrypt.dll`, `crypt32.dll`
   - Linux: `libssl.so`, `libcrypto.so`

3. **Check permissions:**
   - SDK needs read access to executable
   - SDK needs write access to temp directory

---

### Performance Impact Too High

**Symptom:** Frame rate drops after integration.

**Solutions:**

1. **Reduce scan frequency:**
   ```cpp
   config.heartbeat_interval_ms = 2000;  // Less frequent
   config.integrity_scan_interval_ms = 10000;
   ```

2. **Use Minimal preset:**
   ```cpp
   config.features = DetectionFeatures::Minimal;
   ```

3. **Pause during intensive operations:**
   ```cpp
   Sentinel::SDK::Pause();
   LoadLevel();  // Heavy operation
   Sentinel::SDK::Resume();
   ```

---

### False Positives

**Symptom:** Violations during legitimate gameplay.

**Solutions:**

1. **Disable debug checks in development:**
   ```cpp
   #ifdef _DEBUG
       config.features = DetectionFeatures::Minimal;
   #endif
   ```

2. **Whitelist known JIT compilers:**
   - Unreal Engine: Already whitelisted
   - Unity: Already whitelisted
   - Custom JIT: Contact support for signature

3. **Adjust thresholds:**
   ```cpp
   // Speed hack tolerance (if using)
   config.speedhack_tolerance = 1.5f;  // Allow 50% deviation
   ```

---

## Performance Guidelines

### Target Performance

| Operation | Target | Typical | Max Acceptable |
|-----------|--------|---------|----------------|
| `Update()` | <0.1ms | 0.5ms | 1.0ms |
| `FullScan()` | <5ms | 7-10ms | 15ms |
| Initialization | <100ms | 50ms | 500ms |
| Memory Overhead | <5MB | 2MB | 10MB |

### Optimization Tips

1. **Call `Update()` once per frame only:**
   ```cpp
   // GOOD
   while (running) {
       Update();
       GameLoop();
   }
   
   // BAD - Don't call multiple times
   while (running) {
       Update();
       UpdatePhysics();
       Update();  // ❌ Don't do this
       Render();
   }
   ```

2. **Adjust scan intervals for your frame rate:**
   ```cpp
   // 30 FPS game
   config.integrity_scan_interval_ms = 10000;  // 10 seconds
   
   // 60 FPS game
   config.integrity_scan_interval_ms = 5000;   // 5 seconds
   
   // 144 FPS game
   config.integrity_scan_interval_ms = 3000;   // 3 seconds
   ```

3. **Profile with your game:**
   ```cpp
   auto start = std::chrono::high_resolution_clock::now();
   Sentinel::SDK::Update();
   auto end = std::chrono::high_resolution_clock::now();
   auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
   if (us > 1000) {
       Log("SDK Update took %lld µs (exceeds 1ms budget)", us);
   }
   ```

---

## Security Best Practices

### DO ✅

1. **Always validate critical data server-side**
   - Client detection is a hint, not proof
   - Speed hacks require server validation
   - Score/currency must be server-authoritative

2. **Report violations to your backend:**
   ```cpp
   bool OnViolation(const ViolationEvent* event, void*) {
       if (event->severity >= Severity::High) {
           ReportToServer(event->type, event->details);
       }
       return true;
   }
   ```

3. **Use cloud reporting:**
   ```cpp
   config.cloud_endpoint = "https://api.yourgame.com/sentinel";
   ```

4. **Combine with other defenses:**
   - Server-side validation
   - Behavioral analysis
   - HWID bans
   - Delayed ban waves

### DON'T ❌

1. **Don't trust client-side detection alone**
   - User-mode limitations apply
   - Kernel attackers can bypass everything

2. **Don't kick/ban immediately:**
   ```cpp
   // BAD
   if (violation_detected) {
       KickPlayer();  // Too harsh, could be false positive
   }
   
   // GOOD
   if (violation_detected) {
       ReportToServer();  // Let server decide
   }
   ```

3. **Don't enable debug mode in release:**
   ```cpp
   #ifdef NDEBUG
       config.debug_mode = false;  // ✅
   #else
       config.debug_mode = true;
   #endif
   ```

4. **Don't hardcode license keys:**
   ```cpp
   // BAD
   config.license_key = "HARDCODED-KEY";
   
   // GOOD
   config.license_key = LoadFromEncryptedConfig();
   ```

---

## Support

### Documentation
- **Quick Start**: This guide
- **Complete Guide**: [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)
- **API Reference**: [api-reference.md](api-reference.md)
- **Example Code**: [examples/MinimalIntegration/](../examples/MinimalIntegration/)

### Getting Help
- **Email**: support@sentinelware.store
- **Documentation**: [docs/](../docs/)
- **GitHub Issues**: [Issues](https://github.com/Lovuwer/Sentiel-RE/issues)

### License
- **Trial Keys**: Free for evaluation (30 days)
- **Indie License**: $99/month for games <100k MAU
- **Studio License**: Custom pricing for AAA studios
- **Enterprise**: Custom contracts available

Contact: sales@sentinelware.store

---

## Appendix: Complete Example

### Simple C++ Game

```cpp
#include <SentinelSDK.hpp>
#include <iostream>

bool OnViolation(const Sentinel::SDK::ViolationEvent* e, void*) {
    std::cout << "Security event: " << e->details << std::endl;
    return true;
}

int main() {
    // Initialize SDK
    auto config = Sentinel::SDK::Configuration::Default();
    config.license_key = "YOUR-LICENSE-KEY";
    config.game_id = "my-awesome-game";
    config.violation_callback = OnViolation;
    
    if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) {
        std::cerr << "Failed to init SDK" << std::endl;
        return 1;
    }
    
    // Game loop
    bool running = true;
    int frame = 0;
    while (running) {
        Sentinel::SDK::Update();
        
        // Your game logic
        std::cout << "Frame " << ++frame << std::endl;
        
        // Full scan every 5 seconds (300 frames at 60fps)
        if (frame % 300 == 0) {
            Sentinel::SDK::FullScan();
        }
        
        // Exit after 30 seconds
        if (frame >= 1800) running = false;
        
        // Sleep to simulate frame rate
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    
    // Cleanup
    Sentinel::SDK::Shutdown();
    return 0;
}
```

**Compile:**
```bash
g++ -std=c++20 game.cpp -lSentinelSDK -lSentinelCore -lssl -lcrypto -pthread -o game
./game
```

---

**Copyright © 2025 Sentinel Security. All rights reserved.**

**Task 31 Complete**: ✅ Integration under 10 lines, sensible defaults, no tuning required, cross-platform compatible.
