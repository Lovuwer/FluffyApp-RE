# Sentinel SDK Integration Guide

**Version:** 1.0.0  
**Target Audience:** Game developers integrating Sentinel-RE for anti-cheat protection  
**Estimated Integration Time:** 2-4 hours

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Integration by Game Engine](#integration-by-game-engine)
   - [Unreal Engine](#unreal-engine-integration)
   - [Unity](#unity-integration)
   - [Godot Engine](#godot-engine-integration)
   - [Custom C++ Engine](#custom-c-engine-integration)
4. [Configuration](#configuration)
5. [Performance Tuning](#performance-tuning)
6. [Sample Code](#sample-code)
7. [Validation](#validation)
8. [Next Steps](#next-steps)

---

## Quick Start

**For the impatient developer who wants to get started in 5 minutes:**

```cpp
#include <SentinelSDK.hpp>

int main() {
    using namespace Sentinel::SDK;
    
    // 1. Configure
    Configuration config = Configuration::Default();
    config.license_key = "YOUR-LICENSE-KEY";
    config.game_id = "your-game-id";
    
    // 2. Initialize
    if (Initialize(&config) != ErrorCode::Success) {
        fprintf(stderr, "Failed to initialize: %s\n", GetLastError());
        return -1;
    }
    
    // 3. Game loop
    while (game_running) {
        Update();  // Call once per frame
        
        // Your game logic
        UpdateGame();
        RenderFrame();
    }
    
    // 4. Cleanup
    Shutdown();
    return 0;
}
```

**That's it!** The SDK is now running. Read on for production-ready integration.

---

## Prerequisites

### Build Requirements

| Requirement | Version | Notes |
|------------|---------|-------|
| **C++ Compiler** | C++20 compatible | MSVC 2022+, GCC 13+, Clang 15+ |
| **CMake** | 3.21+ | For building SDK |
| **Platform** | Windows x64 | Linux partial support |
| **OpenSSL** | 1.1.1+ or 3.x | For cryptography |

### Knowledge Requirements

- ✅ Basic understanding of game loops
- ✅ C++ memory management fundamentals
- ✅ Threading basics (if using multi-threaded engine)
- ⚠️ No cryptography knowledge required (SDK handles it)

### License Key

Obtain your license key from: https://sentinel.dev/licensing

**Free trial keys available for development!**

---

## Integration by Game Engine

### Unreal Engine Integration

**Tested with:** Unreal Engine 5.3+

#### Step 1: Add SDK to Your Project

Create a `Plugins/SentinelSDK` directory:

```
YourProject/
├── Plugins/
│   └── SentinelSDK/
│       ├── Binaries/
│       │   └── Win64/
│       │       ├── SentinelSDK.dll
│       │       └── SentinelCore.dll
│       ├── Source/
│       │   └── SentinelSDK/
│       │       ├── SentinelSDK.Build.cs
│       │       └── include/
│       │           └── SentinelSDK.hpp
│       └── SentinelSDK.uplugin
```

#### Step 2: Create Build Configuration

**SentinelSDK.Build.cs:**

```csharp
using UnrealBuildTool;
using System.IO;

public class SentinelSDK : ModuleRules
{
    public SentinelSDK(ReadOnlyTargetRules Target) : base(Target)
    {
        Type = ModuleType.External;
        
        string SDKPath = Path.Combine(ModuleDirectory, "../../");
        string IncludePath = Path.Combine(SDKPath, "Source/SentinelSDK/include");
        string LibPath = Path.Combine(SDKPath, "Binaries", "Win64");
        
        PublicIncludePaths.Add(IncludePath);
        
        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            PublicAdditionalLibraries.Add(Path.Combine(LibPath, "SentinelSDK.lib"));
            RuntimeDependencies.Add(Path.Combine(LibPath, "SentinelSDK.dll"));
            RuntimeDependencies.Add(Path.Combine(LibPath, "SentinelCore.dll"));
        }
        
        PublicDependencyModuleNames.AddRange(new string[] {
            "Core",
            "CoreUObject",
            "Engine"
        });
    }
}
```

**SentinelSDK.uplugin:**

```json
{
    "FileVersion": 3,
    "Version": 1,
    "VersionName": "1.0.0",
    "FriendlyName": "Sentinel Anti-Cheat SDK",
    "Description": "Runtime security and anti-cheat protection",
    "Category": "Security",
    "CreatedBy": "Sentinel Security",
    "Modules": [
        {
            "Name": "SentinelSDK",
            "Type": "Runtime",
            "LoadingPhase": "Default"
        }
    ]
}
```

#### Step 3: Initialize in Game Instance

**MyGameInstance.h:**

```cpp
#pragma once
#include "CoreMinimal.h"
#include "Engine/GameInstance.h"
#include "MyGameInstance.generated.h"

UCLASS()
class YOURGAME_API UMyGameInstance : public UGameInstance
{
    GENERATED_BODY()
    
public:
    virtual void Init() override;
    virtual void Shutdown() override;
    
    UFUNCTION(BlueprintCallable, Category = "Security")
    void UpdateAntiCheat();
    
private:
    bool bSentinelInitialized = false;
};
```

**MyGameInstance.cpp:**

```cpp
#include "MyGameInstance.h"
#include <SentinelSDK.hpp>

void UMyGameInstance::Init()
{
    Super::Init();
    
    using namespace Sentinel::SDK;
    
    // Configure SDK
    Configuration config = Configuration::Default();
    config.license_key = "YOUR-LICENSE-KEY";
    config.game_id = "your-unreal-game";
    config.features = DetectionFeatures::Standard;
    config.default_action = ResponseAction::Log | ResponseAction::Report;
    
    // Initialize
    ErrorCode result = Initialize(&config);
    if (result == ErrorCode::Success)
    {
        bSentinelInitialized = true;
        UE_LOG(LogTemp, Log, TEXT("Sentinel SDK initialized successfully"));
    }
    else
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to initialize Sentinel SDK: %s"), 
               ANSI_TO_TCHAR(GetLastError()));
    }
}

void UMyGameInstance::Shutdown()
{
    if (bSentinelInitialized)
    {
        Sentinel::SDK::Shutdown();
        UE_LOG(LogTemp, Log, TEXT("Sentinel SDK shut down"));
    }
    
    Super::Shutdown();
}

void UMyGameInstance::UpdateAntiCheat()
{
    if (bSentinelInitialized)
    {
        Sentinel::SDK::Update();
    }
}
```

#### Step 4: Call Update in Game Loop

**Option A: Blueprint (Recommended for simplicity)**

1. Open your main level blueprint
2. In BeginPlay, get Game Instance and cast to MyGameInstance
3. In Event Tick, call "Update Anti Cheat"

**Option B: C++ (Better performance)**

In your main Pawn or GameMode:

```cpp
void AMyPlayerPawn::Tick(float DeltaTime)
{
    Super::Tick(DeltaTime);
    
    // Update SDK once per frame
    if (auto* GameInstance = Cast<UMyGameInstance>(GetGameInstance()))
    {
        GameInstance->UpdateAntiCheat();
    }
}
```

#### Step 5: Protected Values for Unreal

Protect critical gameplay values:

```cpp
UCLASS()
class AMyPlayerCharacter : public ACharacter
{
    GENERATED_BODY()
    
private:
    uint64_t ProtectedHealthHandle = 0;
    uint64_t ProtectedGoldHandle = 0;
    
public:
    void BeginPlay() override
    {
        Super::BeginPlay();
        
        // Create protected values
        ProtectedHealthHandle = Sentinel::SDK::CreateProtectedInt(100);
        ProtectedGoldHandle = Sentinel::SDK::CreateProtectedInt(0);
    }
    
    void EndPlay(const EEndPlayReason::Type EndPlayReason) override
    {
        // Clean up
        if (ProtectedHealthHandle)
            Sentinel::SDK::DestroyProtectedValue(ProtectedHealthHandle);
        if (ProtectedGoldHandle)
            Sentinel::SDK::DestroyProtectedValue(ProtectedGoldHandle);
            
        Super::EndPlay(EndPlayReason);
    }
    
    UFUNCTION(BlueprintCallable)
    int32 GetHealth() const
    {
        return (int32)Sentinel::SDK::GetProtectedInt(ProtectedHealthHandle);
    }
    
    UFUNCTION(BlueprintCallable)
    void TakeDamage(int32 Damage)
    {
        int64_t health = Sentinel::SDK::GetProtectedInt(ProtectedHealthHandle);
        health = FMath::Max(0LL, health - Damage);
        Sentinel::SDK::SetProtectedInt(ProtectedHealthHandle, health);
    }
};
```

---

### Unity Integration

**Tested with:** Unity 2022.3 LTS+

Unity requires a C# wrapper around the native SDK. We'll create P/Invoke bindings.

#### Step 1: Project Setup

1. Create `Assets/Plugins/SentinelSDK` directory
2. Copy SDK DLLs to `Assets/Plugins/x86_64/`:
   - `SentinelSDK.dll`
   - `SentinelCore.dll`
   - All OpenSSL DLLs

#### Step 2: Create C# Wrapper

**SentinelSDK.cs:**

```csharp
using System;
using System.Runtime.InteropServices;
using UnityEngine;

namespace Sentinel
{
    public enum ErrorCode : uint
    {
        Success = 0,
        NotInitialized = 1,
        AlreadyInitialized = 2,
        InitializationFailed = 3,
        InvalidLicense = 4
    }
    
    public enum DetectionFeatures : uint
    {
        None = 0,
        MemoryIntegrity = 0x0001,
        CodeIntegrity = 0x0002,
        AntiDebug = 0x0010,
        InlineHookDetect = 0x0100,
        IATHookDetect = 0x0200,
        Standard = 0x0113  // MemoryIntegrity | CodeIntegrity | AntiDebug | InlineHookDetect | IATHookDetect
    }
    
    public enum ResponseAction : uint
    {
        None = 0,
        Log = 0x01,
        Report = 0x02,
        Notify = 0x04
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct Configuration
    {
        public uint struct_size;
        public IntPtr license_key;
        public IntPtr game_id;
        public DetectionFeatures features;
        public ResponseAction default_action;
        public IntPtr violation_callback;
        public IntPtr callback_user_data;
        public uint heartbeat_interval_ms;
        public uint integrity_scan_interval_ms;
        public uint memory_scan_chunk_size;
        public IntPtr cloud_endpoint;
        public uint report_batch_size;
        public uint report_interval_ms;
        [MarshalAs(UnmanagedType.I1)]
        public bool debug_mode;
        public IntPtr log_path;
        
        public static Configuration Default()
        {
            return new Configuration
            {
                struct_size = (uint)Marshal.SizeOf<Configuration>(),
                features = DetectionFeatures.Standard,
                default_action = ResponseAction.Log | ResponseAction.Report,
                heartbeat_interval_ms = 1000,
                integrity_scan_interval_ms = 5000,
                memory_scan_chunk_size = 4096,
                report_batch_size = 10,
                report_interval_ms = 30000,
                debug_mode = false
            };
        }
    }
    
    public static class SDK
    {
        private const string DLL_NAME = "SentinelSDK";
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
        private static extern ErrorCode Initialize(ref Configuration config);
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
        private static extern void Shutdown();
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
        private static extern ErrorCode Update();
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
        private static extern ErrorCode FullScan();
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetVersion();
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetLastError();
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
        private static extern ulong CreateProtectedInt(long initial_value);
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
        private static extern void SetProtectedInt(ulong handle, long value);
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
        private static extern long GetProtectedInt(ulong handle);
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
        private static extern void DestroyProtectedValue(ulong handle);
        
        // Managed wrappers
        public static ErrorCode Init(string licenseKey, string gameId)
        {
            Configuration config = Configuration.Default();
            
            IntPtr licensePtr = Marshal.StringToHGlobalAnsi(licenseKey);
            IntPtr gameIdPtr = Marshal.StringToHGlobalAnsi(gameId);
            
            config.license_key = licensePtr;
            config.game_id = gameIdPtr;
            
            ErrorCode result = Initialize(ref config);
            
            Marshal.FreeHGlobal(licensePtr);
            Marshal.FreeHGlobal(gameIdPtr);
            
            return result;
        }
        
        public static void Close()
        {
            Shutdown();
        }
        
        public static ErrorCode UpdateFrame()
        {
            return Update();
        }
        
        public static ErrorCode ScanFull()
        {
            return FullScan();
        }
        
        public static string GetVersionString()
        {
            return Marshal.PtrToStringAnsi(GetVersion());
        }
        
        public static string GetLastErrorString()
        {
            return Marshal.PtrToStringAnsi(GetLastError());
        }
        
        // Protected value helpers
        public static ulong NewProtectedInt(long value)
        {
            return CreateProtectedInt(value);
        }
        
        public static void SetProtected(ulong handle, long value)
        {
            SetProtectedInt(handle, value);
        }
        
        public static long GetProtected(ulong handle)
        {
            return GetProtectedInt(handle);
        }
        
        public static void DestroyProtected(ulong handle)
        {
            DestroyProtectedValue(handle);
        }
    }
}
```

#### Step 3: Create Unity Manager Component

**SentinelManager.cs:**

```csharp
using UnityEngine;

namespace Sentinel
{
    public class SentinelManager : MonoBehaviour
    {
        [Header("Configuration")]
        [SerializeField] private string licenseKey = "YOUR-LICENSE-KEY";
        [SerializeField] private string gameId = "your-unity-game";
        
        [Header("Performance")]
        [SerializeField] private bool runFullScanPeriodically = true;
        [SerializeField] private float fullScanInterval = 5.0f;
        
        private bool isInitialized = false;
        private float lastScanTime = 0f;
        
        private void Awake()
        {
            // Singleton pattern
            DontDestroyOnLoad(gameObject);
            
            // Initialize SDK
            ErrorCode result = SDK.Init(licenseKey, gameId);
            if (result == ErrorCode.Success)
            {
                isInitialized = true;
                Debug.Log($"Sentinel SDK initialized - Version {SDK.GetVersionString()}");
            }
            else
            {
                Debug.LogError($"Failed to initialize Sentinel SDK: {SDK.GetLastErrorString()}");
            }
        }
        
        private void Update()
        {
            if (!isInitialized) return;
            
            // Lightweight update every frame
            SDK.UpdateFrame();
            
            // Periodic full scan
            if (runFullScanPeriodically)
            {
                lastScanTime += Time.deltaTime;
                if (lastScanTime >= fullScanInterval)
                {
                    SDK.ScanFull();
                    lastScanTime = 0f;
                }
            }
        }
        
        private void OnApplicationQuit()
        {
            if (isInitialized)
            {
                SDK.Close();
                Debug.Log("Sentinel SDK shut down");
            }
        }
    }
}
```

#### Step 4: Add to Scene

1. Create an empty GameObject named "SentinelManager"
2. Add the `SentinelManager` component
3. Configure your license key in the Inspector
4. The SDK will now run automatically!

#### Step 5: Protected Values in Unity

**PlayerData.cs:**

```csharp
using UnityEngine;
using Sentinel;

public class PlayerData : MonoBehaviour
{
    private ulong healthHandle;
    private ulong scoreHandle;
    
    void Start()
    {
        // Create protected values
        healthHandle = SDK.NewProtectedInt(100);
        scoreHandle = SDK.NewProtectedInt(0);
    }
    
    void OnDestroy()
    {
        // Clean up
        if (healthHandle != 0)
            SDK.DestroyProtected(healthHandle);
        if (scoreHandle != 0)
            SDK.DestroyProtected(scoreHandle);
    }
    
    public int GetHealth()
    {
        return (int)SDK.GetProtected(healthHandle);
    }
    
    public void TakeDamage(int damage)
    {
        long health = SDK.GetProtected(healthHandle);
        health = Mathf.Max(0, health - damage);
        SDK.SetProtected(healthHandle, health);
    }
    
    public void AddScore(int points)
    {
        long score = SDK.GetProtected(scoreHandle);
        score += points;
        SDK.SetProtected(scoreHandle, score);
    }
}
```

---

### Godot Engine Integration

**Tested with:** Godot 4.2+

Godot uses GDExtension for native C++ integration. We'll create a GDExtension wrapper.

#### Step 1: Project Setup

Create a GDExtension module structure:

```
your-godot-project/
├── addons/
│   └── sentinel_sdk/
│       ├── bin/
│       │   └── libsentinel_gdextension.so (or .dll)
│       ├── sentinel_sdk.gdextension
│       └── LICENSE
```

#### Step 2: Create GDExtension Wrapper

**sentinel_gdextension.cpp:**

```cpp
#include <godot_cpp/classes/node.hpp>
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/utility_functions.hpp>
#include <SentinelSDK.hpp>

using namespace godot;

class SentinelSDKNode : public Node {
    GDCLASS(SentinelSDKNode, Node)

private:
    bool initialized = false;
    String license_key;
    String game_id;

protected:
    static void _bind_methods() {
        ClassDB::bind_method(D_METHOD("initialize", "license", "game_id"), &SentinelSDKNode::initialize);
        ClassDB::bind_method(D_METHOD("update"), &SentinelSDKNode::update);
        ClassDB::bind_method(D_METHOD("shutdown"), &SentinelSDKNode::shutdown);
        ClassDB::bind_method(D_METHOD("is_initialized"), &SentinelSDKNode::is_initialized);
        
        ClassDB::bind_method(D_METHOD("create_protected_int", "value"), &SentinelSDKNode::create_protected_int);
        ClassDB::bind_method(D_METHOD("get_protected_int", "handle"), &SentinelSDKNode::get_protected_int);
        ClassDB::bind_method(D_METHOD("set_protected_int", "handle", "value"), &SentinelSDKNode::set_protected_int);
        ClassDB::bind_method(D_METHOD("destroy_protected", "handle"), &SentinelSDKNode::destroy_protected);
    }

public:
    bool initialize(String p_license_key, String p_game_id) {
        using namespace Sentinel::SDK;
        
        Configuration config = Configuration::Default();
        config.license_key = p_license_key.utf8().get_data();
        config.game_id = p_game_id.utf8().get_data();
        config.features = DetectionFeatures::Standard;
        config.default_action = ResponseAction::Log | ResponseAction::Report;
        
        ErrorCode result = Initialize(&config);
        if (result == ErrorCode::Success) {
            initialized = true;
            UtilityFunctions::print("Sentinel SDK initialized successfully");
            return true;
        } else {
            UtilityFunctions::printerr("Failed to initialize Sentinel SDK: ", GetLastError());
            return false;
        }
    }
    
    void update() {
        if (initialized) {
            Sentinel::SDK::Update();
        }
    }
    
    void shutdown() {
        if (initialized) {
            Sentinel::SDK::Shutdown();
            initialized = false;
            UtilityFunctions::print("Sentinel SDK shut down");
        }
    }
    
    bool is_initialized() const {
        return initialized;
    }
    
    int64_t create_protected_int(int64_t value) {
        if (!initialized) return 0;
        return Sentinel::SDK::CreateProtectedInt(value);
    }
    
    int64_t get_protected_int(int64_t handle) {
        if (!initialized) return 0;
        return Sentinel::SDK::GetProtectedInt(handle);
    }
    
    void set_protected_int(int64_t handle, int64_t value) {
        if (!initialized) return;
        Sentinel::SDK::SetProtectedInt(handle, value);
    }
    
    void destroy_protected(int64_t handle) {
        if (!initialized) return;
        Sentinel::SDK::DestroyProtectedValue(handle);
    }
    
    void _process(double delta) override {
        update();
    }
};

void initialize_sentinel_module(ModuleInitializationLevel p_level) {
    if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) return;
    ClassDB::register_class<SentinelSDKNode>();
}

void uninitialize_sentinel_module(ModuleInitializationLevel p_level) {
    if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) return;
}

extern "C" {
    GDExtensionBool GDE_EXPORT sentinel_gdextension_init(
        GDExtensionInterfaceGetProcAddress p_get_proc_address,
        const GDExtensionClassLibraryPtr p_library,
        GDExtensionInitialization *r_initialization
    ) {
        godot::GDExtensionBinding::InitObject init_obj(p_get_proc_address, p_library, r_initialization);
        init_obj.register_initializer(initialize_sentinel_module);
        init_obj.register_terminator(uninitialize_sentinel_module);
        init_obj.set_minimum_library_initialization_level(MODULE_INITIALIZATION_LEVEL_SCENE);
        return init_obj.init();
    }
}
```

#### Step 3: Configure GDExtension

**sentinel_sdk.gdextension:**

```ini
[configuration]
entry_symbol = "sentinel_gdextension_init"
compatibility_minimum = "4.2"

[libraries]
linux.x86_64 = "res://addons/sentinel_sdk/bin/libsentinel_gdextension.so"
windows.x86_64 = "res://addons/sentinel_sdk/bin/sentinel_gdextension.dll"
```

#### Step 4: Use in GDScript

**Main.gd:**

```gdscript
extends Node

var sentinel: SentinelSDKNode = null
var health_handle: int = 0
var score_handle: int = 0

func _ready():
    # Create and add Sentinel SDK node
    sentinel = SentinelSDKNode.new()
    add_child(sentinel)
    
    # Initialize SDK
    if sentinel.initialize("YOUR-LICENSE-KEY", "your-godot-game"):
        print("Sentinel SDK ready")
        
        # Create protected values
        health_handle = sentinel.create_protected_int(100)
        score_handle = sentinel.create_protected_int(0)
    else:
        push_error("Failed to initialize Sentinel SDK")

func _process(delta):
    # SDK.update() is automatically called in SentinelSDKNode._process()
    pass

func take_damage(amount: int):
    if health_handle > 0:
        var health = sentinel.get_protected_int(health_handle)
        health = max(0, health - amount)
        sentinel.set_protected_int(health_handle, health)
        print("Health: ", health)

func add_score(points: int):
    if score_handle > 0:
        var score = sentinel.get_protected_int(score_handle)
        score += points
        sentinel.set_protected_int(score_handle, score)
        print("Score: ", score)

func _exit_tree():
    # Cleanup
    if sentinel and sentinel.is_initialized():
        if health_handle > 0:
            sentinel.destroy_protected(health_handle)
        if score_handle > 0:
            sentinel.destroy_protected(score_handle)
        sentinel.shutdown()
```

#### Step 5: Build GDExtension

**SConstruct:**

```python
#!/usr/bin/env python
import os

env = Environment()

# Paths
sentinel_sdk_path = "../../../"  # Path to Sentinel SDK
godot_cpp_path = "godot-cpp"     # godot-cpp submodule

# Include paths
env.Append(CPPPATH=[
    godot_cpp_path + "/include",
    godot_cpp_path + "/gen/include",
    sentinel_sdk_path + "/include",
])

# Library paths
env.Append(LIBPATH=[
    godot_cpp_path + "/bin",
    sentinel_sdk_path + "/build/lib",
])

# Libraries
env.Append(LIBS=[
    "godot-cpp",
    "SentinelSDK",
    "SentinelCore",
    "ssl",
    "crypto",
])

# Build
sources = ["sentinel_gdextension.cpp"]
library = env.SharedLibrary("bin/libsentinel_gdextension", sources)

Default(library)
```

Build with:

```bash
scons platform=linux target=template_release
# or
scons platform=windows target=template_release
```

---

### Custom C++ Engine Integration

For custom C++ game engines, the integration is straightforward.

#### Step 1: Link the SDK

**CMakeLists.txt:**

```cmake
# Find Sentinel SDK
find_library(SENTINEL_SDK_LIB SentinelSDK
    PATHS "${CMAKE_SOURCE_DIR}/external/sentinel/lib"
)

find_library(SENTINEL_CORE_LIB SentinelCore
    PATHS "${CMAKE_SOURCE_DIR}/external/sentinel/lib"
)

# Add to your game target
target_include_directories(YourGame PRIVATE
    ${CMAKE_SOURCE_DIR}/external/sentinel/include
)

target_link_libraries(YourGame PRIVATE
    ${SENTINEL_SDK_LIB}
    ${SENTINEL_CORE_LIB}
    OpenSSL::SSL
    OpenSSL::Crypto
)
```

#### Step 2: Initialize in Main

**main.cpp:**

```cpp
#include <SentinelSDK.hpp>
#include "YourGame.hpp"

int main(int argc, char* argv[])
{
    using namespace Sentinel::SDK;
    
    // Configure SDK
    Configuration config = Configuration::Default();
    config.license_key = "YOUR-LICENSE-KEY";
    config.game_id = "your-custom-engine";
    config.features = DetectionFeatures::Standard;
    config.default_action = ResponseAction::Log | ResponseAction::Report;
    
    // Optional: Set up violation callback
    config.violation_callback = [](const ViolationEvent* event, void* user_data) -> bool {
        fprintf(stderr, "[SECURITY] Violation detected: %s\n", event->details.c_str());
        // Handle violation (log, report, disconnect player, etc.)
        return true;  // Continue monitoring
    };
    
    // Initialize SDK
    ErrorCode result = Initialize(&config);
    if (result != ErrorCode::Success) {
        fprintf(stderr, "Failed to initialize Sentinel SDK: %s\n", GetLastError());
        return -1;
    }
    
    // Initialize your game
    YourGame game;
    if (!game.Initialize()) {
        Shutdown();
        return -1;
    }
    
    // Game loop
    while (game.IsRunning()) {
        // Update SDK (lightweight, ~0.5ms)
        Update();
        
        // Update game logic
        game.Update();
        
        // Render
        game.Render();
    }
    
    // Cleanup
    game.Shutdown();
    Shutdown();
    
    return 0;
}
```

#### Step 3: Integrate with Your Game Loop

**GameEngine.cpp:**

```cpp
class GameEngine {
private:
    bool running = true;
    std::chrono::steady_clock::time_point lastScanTime;
    
public:
    void Initialize() {
        lastScanTime = std::chrono::steady_clock::now();
    }
    
    void Update() {
        // Sentinel SDK update is already called in main loop
        
        // Periodic full scan (every 5 seconds)
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - lastScanTime
        ).count();
        
        if (elapsed >= 5) {
            Sentinel::SDK::FullScan();
            lastScanTime = now;
        }
        
        // Your game logic
        UpdatePhysics();
        UpdateAI();
        UpdateNetworking();
    }
};
```

---

## Configuration

### Recommended Production Configuration

```cpp
Configuration config = Configuration::Default();

// Required
config.license_key = "YOUR-PRODUCTION-LICENSE-KEY";
config.game_id = "your-game-v1.0";

// Detection features
config.features = DetectionFeatures::Standard;  // Balanced protection

// Response actions
config.default_action = ResponseAction::Log | ResponseAction::Report;

// Performance tuning
config.heartbeat_interval_ms = 1000;        // Check every 1 second
config.integrity_scan_interval_ms = 5000;   // Full scan every 5 seconds

// Cloud reporting (optional but recommended)
config.cloud_endpoint = "https://api.yourgame.com/sentinel";
config.report_batch_size = 10;
config.report_interval_ms = 30000;  // Report every 30 seconds

// Debug mode - MUST BE FALSE IN RELEASE!
#ifdef DEBUG
    config.debug_mode = true;
    config.log_path = "/tmp/sentinel_debug.log";
#else
    config.debug_mode = false;
    config.log_path = nullptr;
#endif
```

### Configuration Options Explained

| Option | Recommended Value | Impact |
|--------|-------------------|--------|
| `features` | `DetectionFeatures::Standard` | Balance of protection and performance |
| `heartbeat_interval_ms` | 1000ms (1 second) | Lower = better detection, higher CPU |
| `integrity_scan_interval_ms` | 5000ms (5 seconds) | Lower = better protection, higher overhead |
| `cloud_endpoint` | Your API endpoint | Enables telemetry and ban decisions |
| `debug_mode` | false (release) | **Never enable in production!** |

---

## Performance Tuning

### Performance Targets

| Operation | Target | Typical | Action if Exceeded |
|-----------|--------|---------|-------------------|
| `Update()` | < 0.1ms | ~0.5ms | Increase heartbeat interval |
| `FullScan()` | < 5ms | ~7-10ms | Increase scan interval |
| Memory | ~2MB | TBD | No action needed |

### Tuning for Different Hardware

**High-end PC (e.g., RTX 4090, i9-13900K):**
```cpp
config.heartbeat_interval_ms = 500;   // More frequent checks
config.integrity_scan_interval_ms = 3000;  // More aggressive scanning
```

**Mid-range PC (e.g., GTX 1660, i5-10400):**
```cpp
config.heartbeat_interval_ms = 1000;  // Standard
config.integrity_scan_interval_ms = 5000;
```

**Low-end PC (e.g., Integrated GPU, older CPU):**
```cpp
config.heartbeat_interval_ms = 2000;  // Less frequent
config.integrity_scan_interval_ms = 10000;  // Reduce overhead
config.features = DetectionFeatures::Minimal;  // Lighter protection
```

### Measuring Performance

```cpp
#include <chrono>

void MeasureSDKPerformance() {
    using namespace std::chrono;
    
    // Measure Update()
    auto start = high_resolution_clock::now();
    Sentinel::SDK::Update();
    auto end = high_resolution_clock::now();
    auto duration_us = duration_cast<microseconds>(end - start).count();
    
    printf("Update() took %lld microseconds\n", duration_us);
    
    // Measure FullScan()
    start = high_resolution_clock::now();
    Sentinel::SDK::FullScan();
    end = high_resolution_clock::now();
    auto duration_ms = duration_cast<milliseconds>(end - start).count();
    
    printf("FullScan() took %lld milliseconds\n", duration_ms);
}
```

### Optimizing Game Loop

**Bad - Multiple SDK calls per frame:**
```cpp
void GameLoop() {
    Update();  // SDK
    UpdatePhysics();
    Update();  // SDK again - wasteful!
    UpdateRendering();
}
```

**Good - Single SDK call per frame:**
```cpp
void GameLoop() {
    Update();  // SDK once per frame
    
    UpdatePhysics();
    UpdateAI();
    UpdateRendering();
}
```

---

## Sample Code

### Complete Minimal Example

See: `examples/DummyGame/main.cpp` for a complete working example.

### Common Patterns

#### Pattern 1: Protected Player Stats

```cpp
class Player {
private:
    uint64_t health_handle;
    uint64_t mana_handle;
    uint64_t gold_handle;
    
public:
    Player() {
        health_handle = Sentinel::SDK::CreateProtectedInt(100);
        mana_handle = Sentinel::SDK::CreateProtectedInt(100);
        gold_handle = Sentinel::SDK::CreateProtectedInt(0);
    }
    
    ~Player() {
        Sentinel::SDK::DestroyProtectedValue(health_handle);
        Sentinel::SDK::DestroyProtectedValue(mana_handle);
        Sentinel::SDK::DestroyProtectedValue(gold_handle);
    }
    
    int GetHealth() const {
        return Sentinel::SDK::GetProtectedInt(health_handle);
    }
    
    void TakeDamage(int damage) {
        int64_t health = Sentinel::SDK::GetProtectedInt(health_handle);
        health = std::max(0LL, health - damage);
        Sentinel::SDK::SetProtectedInt(health_handle, health);
    }
    
    void AddGold(int amount) {
        int64_t gold = Sentinel::SDK::GetProtectedInt(gold_handle);
        gold += amount;
        Sentinel::SDK::SetProtectedInt(gold_handle, gold);
    }
};
```

#### Pattern 2: Loading Screen Pause

```cpp
void LoadLevel(const std::string& level_name) {
    // Pause SDK during intensive loading
    Sentinel::SDK::Pause();
    
    // Load assets (may take several seconds)
    LoadTextures();
    LoadModels();
    LoadSounds();
    CompileShaders();
    
    // Resume monitoring
    Sentinel::SDK::Resume();
}
```

#### Pattern 3: Secure Network Packets

```cpp
void SendGamePacket(const GameData& data) {
    // Encrypt packet
    uint8_t encrypted[2048];
    size_t encrypted_size = sizeof(encrypted);
    
    ErrorCode result = Sentinel::SDK::EncryptPacket(
        &data, sizeof(data),
        encrypted, &encrypted_size
    );
    
    if (result == ErrorCode::Success) {
        // Add sequence number
        uint32_t seq = Sentinel::SDK::GetPacketSequence();
        
        // Send over network
        SendToServer(encrypted, encrypted_size, seq);
    }
}

void ReceiveGamePacket(const uint8_t* data, size_t size, uint32_t seq) {
    // Validate sequence
    if (!Sentinel::SDK::ValidatePacketSequence(seq)) {
        LogWarning("Replay attack detected - invalid sequence %u", seq);
        return;
    }
    
    // Decrypt packet
    GameData decrypted;
    size_t decrypted_size = sizeof(decrypted);
    
    ErrorCode result = Sentinel::SDK::DecryptPacket(
        data, size,
        &decrypted, &decrypted_size
    );
    
    if (result == ErrorCode::Success) {
        ProcessGameData(decrypted);
    }
}
```

---

## Validation

### Build Verification

After integration, verify your build:

```bash
# Build your game with SDK
cmake --build build --config Release

# Verify SDK is linked
ldd ./YourGame | grep Sentinel  # Linux
# or
dumpbin /DEPENDENTS YourGame.exe | findstr Sentinel  # Windows

# Run the game
./YourGame
```

### Runtime Verification

Check that SDK is running:

```cpp
// In your game initialization
if (Sentinel::SDK::IsInitialized()) {
    printf("✓ SDK initialized\n");
    printf("✓ Version: %s\n", Sentinel::SDK::GetVersion());
    
    // Get stats
    Sentinel::SDK::Statistics stats;
    Sentinel::SDK::GetStatistics(&stats);
    printf("✓ Uptime: %llu ms\n", stats.uptime_ms);
} else {
    printf("✗ SDK not initialized!\n");
}
```

### Test Checklist

- [ ] Game builds successfully with SDK linked
- [ ] SDK initializes without errors
- [ ] Update() called every frame
- [ ] FullScan() runs periodically
- [ ] Protected values work correctly
- [ ] Performance meets targets (< 0.5ms per frame)
- [ ] Game shuts down cleanly with SDK cleanup
- [ ] Debug mode disabled in release build

---

## Next Steps

1. **Read the API Reference:** [api-reference.md](api-reference.md)
2. **Review Troubleshooting:** [troubleshooting.md](troubleshooting.md)
3. **Study the Example:** `examples/DummyGame/`
4. **Configure Cloud Reporting:** Set up your backend endpoint
5. **Server-Side Validation:** Implement authoritative checks
6. **Test with Real Players:** Monitor for false positives

### Production Checklist

Before going live:

- [ ] Production license key configured
- [ ] Debug mode disabled (`config.debug_mode = false`)
- [ ] Cloud reporting endpoint configured
- [ ] Violation callback handles events appropriately
- [ ] Server-side validation implemented
- [ ] Performance profiled and acceptable
- [ ] False positive testing completed
- [ ] Documentation shared with team

---

## Support

- **Documentation:** [docs/](.)
- **Issues:** [GitHub Issues](https://github.com/Lovuwer/Sentiel-RE/issues)
- **Example Code:** [examples/DummyGame/](../examples/DummyGame/)
- **Technical Support:** support@sentinel.dev

---

**Estimated Integration Time:** 2-4 hours  
**Difficulty:** Easy to Moderate  
**Prerequisites:** C++ knowledge, game engine familiarity

**Remember:** The SDK is one layer in a defense-in-depth strategy. Always combine with server-side validation!
