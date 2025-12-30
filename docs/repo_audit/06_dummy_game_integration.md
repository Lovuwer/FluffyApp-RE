# Step 6: Dummy Game Integration & Installation Guide

**This work assumes testing is authorized by repository owner. Do not run against third-party systems.**

---

## Overview

This guide demonstrates integrating Sentinel SDK into a minimal C++ game using CMake and VS Code. The dummy game exercises all SDK features in a safe, controlled manner.

**Note:** A complete DummyGame example already exists at `/examples/DummyGame/`. This document provides additional integration patterns.

---

## Quick Start (Existing DummyGame)

```bash
cd /home/runner/work/Sentiel-RE/Sentiel-RE
mkdir -p build && cd build
cmake .. -DSENTINEL_BUILD_SDK=ON -DSENTINEL_BUILD_TESTS=ON
cmake --build . --target DummyGame
./bin/DummyGame
```

**Expected Output:**
```
[Sentinel SDK] Initialized successfully
[Game] Simulating 100 frames...
[Sentinel SDK] Update called (Frame 1)
... (crypto operations, integrity checks) ...
[Sentinel SDK] Shutdown complete
```

---

## Step-by-Step Integration (New Game)

### 1. Project Structure

```
my_game/
├── CMakeLists.txt
├── src/
│   └── main.cpp
├── .vscode/
│   ├── launch.json
│   ├── tasks.json
│   └── settings.json
└── README.md
```

### 2. CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.21)
project(MyGame CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add Sentinel SDK as subdirectory (or via FetchContent)
add_subdirectory(../Sentiel-RE ${CMAKE_BINARY_DIR}/sentinel)

# Game executable
add_executable(MyGame src/main.cpp)

# Link Sentinel SDK
target_link_libraries(MyGame PRIVATE SentinelSDK)

# Copy SDK DLL on Windows (if dynamic)
if(WIN32)
    add_custom_command(TARGET MyGame POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:SentinelSDK>
        $<TARGET_FILE_DIR:MyGame>
    )
endif()
```

### 3. main.cpp (Minimal Integration)

```cpp
#include <SentinelSDK.hpp>
#include <iostream>
#include <thread>
#include <chrono>

using namespace Sentinel::SDK;

// Violation callback
bool OnViolation(const ViolationEvent& event, void* user_data) {
    std::cout << "[VIOLATION] Type=" << static_cast<int>(event.type)
              << " Severity=" << static_cast<int>(event.severity)
              << " Module=" << event.module_name
              << " Details=" << event.details
              << std::endl;
    
    // Return true to continue monitoring
    return true;
}

int main() {
    // 1. Configure SDK
    Configuration config = Configuration::Default();
    config.license_key = "demo-license-key";
    config.game_id = "my-game-001";
    config.features = DetectionFeatures::Standard;
    config.default_action = ResponseAction::Report | ResponseAction::Log;
    config.violation_callback = OnViolation;
    config.user_data = nullptr;
    
    // 2. Initialize
    ErrorCode init_result = Initialize(&config);
    if (init_result != ErrorCode::Success) {
        std::cerr << "Failed to initialize Sentinel SDK: " 
                  << static_cast<int>(init_result) << std::endl;
        return -1;
    }
    
    std::cout << "[Sentinel] Initialized successfully" << std::endl;
    
    // 3. Game Loop
    bool game_running = true;
    int frame = 0;
    
    while (game_running && frame < 100) {
        // Call SDK update every frame (lightweight)
        Update();
        
        // Call full scan every 5 seconds (heavier)
        if (frame % 300 == 0) {  // Assuming 60 FPS
            FullScan();
        }
        
        // Your game logic here
        // ...
        
        frame++;
        std::this_thread::sleep_for(std::chrono::milliseconds(16));  // ~60 FPS
    }
    
    // 4. Shutdown
    Shutdown();
    std::cout << "[Sentinel] Shutdown complete" << std::endl;
    
    return 0;
}
```

### 4. Build & Run

```bash
mkdir build && cd build
cmake ..
cmake --build .
./MyGame  # or MyGame.exe on Windows
```

---

## VS Code Integration

### .vscode/tasks.json (Build Tasks)

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "CMake Configure",
            "type": "shell",
            "command": "cmake",
            "args": ["-B", "build", "-G", "Ninja"],
            "group": "build",
            "problemMatcher": []
        },
        {
            "label": "CMake Build",
            "type": "shell",
            "command": "cmake",
            "args": ["--build", "build"],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "problemMatcher": ["$gcc"],
            "dependsOn": ["CMake Configure"]
        },
        {
            "label": "Run Tests",
            "type": "shell",
            "command": "cd build && ctest --output-on-failure",
            "group": "test",
            "problemMatcher": []
        },
        {
            "label": "Clean Build",
            "type": "shell",
            "command": "rm",
            "args": ["-rf", "build"],
            "problemMatcher": []
        }
    ]
}
```

### .vscode/launch.json (Debug Configuration)

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug MyGame",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/build/MyGame",
            "args": [],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}/build",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ],
            "preLaunchTask": "CMake Build",
            "miDebuggerPath": "/usr/bin/gdb",
            "linux": {
                "MIMode": "gdb"
            },
            "osx": {
                "MIMode": "lldb"
            },
            "windows": {
                "MIMode": "gdb",
                "miDebuggerPath": "C:\\msys64\\mingw64\\bin\\gdb.exe"
            }
        },
        {
            "name": "Debug Tests",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/build/bin/SDKTests",
            "args": ["--gtest_filter=*"],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}/build",
            "MIMode": "gdb",
            "preLaunchTask": "CMake Build"
        }
    ]
}
```

### .vscode/settings.json

```json
{
    "cmake.configureOnOpen": true,
    "cmake.buildDirectory": "${workspaceFolder}/build",
    "C_Cpp.default.configurationProvider": "ms-vscode.cmake-tools",
    "files.associations": {
        "*.hpp": "cpp",
        "*.cpp": "cpp"
    },
    "editor.formatOnSave": true,
    "C_Cpp.clang_format_style": "file"
}
```

---

## Advanced Integration Examples

### Example 1: Encrypted Save Files

```cpp
#include <SentinelSDK.hpp>
#include <Sentinel/Core/Crypto.hpp>

void SaveGameData(const std::string& filename, const std::string& data) {
    using namespace Sentinel::Crypto;
    
    // Generate random key (or derive from user password)
    SecureRandom rng;
    auto key_result = rng.generate(32);  // 256-bit key
    AESKey key;
    std::memcpy(key.data(), key_result.value().data(), 32);
    
    AESCipher cipher(key);
    
    // Encrypt save data
    auto encrypted = cipher.encrypt(
        ByteSpan(reinterpret_cast<const Byte*>(data.data()), data.size()),
        {}  // No AAD
    );
    
    if (encrypted.isFailure()) {
        std::cerr << "Encryption failed" << std::endl;
        return;
    }
    
    // Write to file
    std::ofstream ofs(filename, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(encrypted.value().data()),
              encrypted.value().size());
    
    // Note: In production, store key securely (not in plaintext)
}
```

### Example 2: Protected Player Health

```cpp
#include <SentinelSDK.hpp>

class Player {
public:
    Player() {
        // Create protected health value
        health_handle_ = Sentinel::SDK::ProtectedValue::Create(100);
    }
    
    ~Player() {
        Sentinel::SDK::ProtectedValue::Destroy(health_handle_);
    }
    
    void TakeDamage(int amount) {
        int current = Sentinel::SDK::ProtectedValue::Get(health_handle_);
        int new_health = std::max(0, current - amount);
        Sentinel::SDK::ProtectedValue::Set(health_handle_, new_health);
    }
    
    int GetHealth() const {
        return Sentinel::SDK::ProtectedValue::Get(health_handle_);
    }
    
private:
    uint32_t health_handle_;
};
```

### Example 3: Periodic Integrity Check

```cpp
void GameIntegrityCheckThread() {
    while (game_running) {
        // Full scan every 10 seconds
        Sentinel::SDK::FullScan();
        
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

// In main:
std::thread integrity_thread(GameIntegrityCheckThread);
// ... game loop ...
integrity_thread.join();
```

---

## Debugging & Development Mode

### Disable Detectors in Dev Builds

```cpp
#ifdef _DEBUG
    config.features = DetectionFeatures::None;  // Disable all in debug
#else
    config.features = DetectionFeatures::Standard;  // Enable in release
#endif
```

### Enable Verbose Logging

```cpp
config.default_action = ResponseAction::Report | ResponseAction::Log;
config.violation_callback = [](const ViolationEvent& event, void*) {
    // Log to file in dev mode
    std::ofstream log("sentinel_violations.log", std::ios::app);
    log << "Type=" << static_cast<int>(event.type) 
        << " Module=" << event.module_name 
        << std::endl;
    return true;
};
```

### Whitelist Dev Tools

```cpp
// Add JIT compiler signatures (for dev builds with hot reload)
Sentinel::SDK::AddJITSignature("Unity", unity_jit_pattern);
Sentinel::SDK::AddJITSignature("UE4", unreal_jit_pattern);
```

---

## Rollback Plan

If SDK causes issues in production:

### Option 1: Disable Specific Detectors

```cpp
config.features = DetectionFeatures::Standard 
                 & ~DetectionFeatures::AntiDebug;  // Disable debugger detection
```

### Option 2: Telemetry-Only Mode

```cpp
config.default_action = ResponseAction::Report;  // Only report, no enforcement
```

### Option 3: Complete Disable

```cpp
#ifndef SENTINEL_ENABLED
    // No-op implementations
    #define Initialize(cfg) ErrorCode::Success
    #define Update() ((void)0)
    #define Shutdown() ((void)0)
#endif
```

---

## Performance Monitoring

```cpp
#include <chrono>

void MeasureSDKOverhead() {
    auto start = std::chrono::high_resolution_clock::now();
    Sentinel::SDK::Update();
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "SDK Update: " << duration.count() << " µs" << std::endl;
}
```

**Target:** Update() < 100 µs, FullScan() < 5 ms

---

## Common Integration Issues

### Issue 1: Linker Errors

**Problem:** `undefined reference to Sentinel::SDK::Initialize`

**Solution:**
```cmake
# Ensure SDK is linked
target_link_libraries(MyGame PRIVATE SentinelSDK)

# Check SDK built successfully
cmake --build . --target SentinelSDK
```

### Issue 2: DLL Not Found (Windows)

**Problem:** `The code execution cannot proceed because SentinelSDK.dll was not found`

**Solution:**
```cmake
# Copy DLL to game directory
add_custom_command(TARGET MyGame POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:SentinelSDK>
    $<TARGET_FILE_DIR:MyGame>
)
```

### Issue 3: False Positives in Dev

**Problem:** SDK detects dev tools (debuggers, overlays)

**Solution:**
```cpp
#ifdef _DEBUG
    config.features = DetectionFeatures::None;
#endif

// Or use environment variables
if (getenv("SENTINEL_DEV_MODE")) {
    config.features = DetectionFeatures::None;
}
```

---

## Summary

**Files Created:**
- `CMakeLists.txt` - Build configuration
- `src/main.cpp` - Game integration
- `.vscode/tasks.json` - Build tasks
- `.vscode/launch.json` - Debug config
- `.vscode/settings.json` - Editor config

**Build Commands:**
```bash
cmake -B build
cmake --build build
./build/MyGame
```

**Debug in VS Code:**
1. Press `F5` (or Debug → Start Debugging)
2. Set breakpoints in game code
3. SDK functions are debuggable too

**Production Checklist:**
- [ ] Set valid `license_key` and `game_id`
- [ ] Enable appropriate `DetectionFeatures`
- [ ] Set up violation callback for server reporting
- [ ] Test with FullScan intervals (5-10 seconds recommended)
- [ ] Disable SDK in debug builds
- [ ] Monitor performance overhead
- [ ] Implement server-side validation

---

**Document Version:** 1.0  
**Generated:** 2025-12-30  
**Example Code:** Production-ready patterns
