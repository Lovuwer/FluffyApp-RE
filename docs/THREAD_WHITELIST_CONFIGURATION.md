# Thread Start Address Validation Whitelist

## Overview

The Sentinel SDK includes sophisticated thread injection detection that monitors all thread creation in the protected process. To reduce false positives from legitimate runtime-created threads, a comprehensive whitelist system has been implemented.

## How It Works

The thread injection detection system (`IsThreadSuspicious()`) checks if a thread's start address is in suspicious memory regions. Threads starting in `MEM_PRIVATE` memory are typically suspicious, as legitimate threads usually start in module code (`MEM_IMAGE`). However, several legitimate scenarios can trigger false positives:

1. **Windows Thread Pool** - Worker threads created by the Windows thread pool API
2. **.NET Managed Threads** - Threads created by the CLR runtime
3. **JIT Compilers** - V8, LuaJIT, Unity IL2CPP, etc.
4. **Game Engine Job Systems** - Custom threading libraries with their own memory allocation
5. **Trampolines** - Small code stubs allocated near modules for optimization

## Built-in Whitelist

The SDK automatically whitelists common legitimate thread origins:

### System DLLs
- **ntdll.dll** - Windows NT kernel layer, thread pool workers
- **kernel32.dll** - Windows kernel, base thread initialization
- **kernelbase.dll** - Windows kernel base, thread infrastructure

### .NET Runtime
- **clr.dll** - .NET Framework CLR runtime
- **coreclr.dll** - .NET Core CLR runtime
- **clrjit.dll** - .NET JIT compiler
- **mscorwks.dll** - .NET Framework CLR workstation
- **mscorsvr.dll** - .NET Framework CLR server

### JIT Compilers
- **v8.dll** / **libv8.dll** - V8 JavaScript engine (Chrome, Electron)
- **gameassembly.dll** - Unity IL2CPP runtime
- **luajit.dll** / **lua51.dll** / **lua52.dll** / **lua53.dll** - Lua JIT compiler

## Custom Whitelist Configuration

Game developers can add their own thread origins to the whitelist using the SDK API.

### C++ API

```cpp
#include <SentinelSDK.hpp>

// Initialize SDK first
Sentinel::SDK::Configuration config = Sentinel::SDK::Configuration::Default();
Sentinel::SDK::Initialize(&config);

// Add your custom job system module to whitelist
ErrorCode result = Sentinel::SDK::WhitelistThreadOrigin(
    "MyGameEngine.dll",
    "Custom game engine job system"
);

if (result != ErrorCode::Success) {
    // Handle error
}

// Later, if needed, remove from whitelist
Sentinel::SDK::RemoveThreadOriginWhitelist("MyGameEngine.dll");
```

### C API

```c
#include <SentinelSDK.hpp>

// Initialize SDK
struct Sentinel::SDK::Configuration config = {0};
config.struct_size = sizeof(config);
// ... configure other fields ...

SentinelInit(&config);

// Add custom whitelist entry
uint32_t result = Sentinel::SDK::WhitelistThreadOrigin(
    "MyGameEngine.dll",
    "Custom game engine job system"
);

// Remove whitelist entry
Sentinel::SDK::RemoveThreadOriginWhitelist("MyGameEngine.dll");
```

## API Reference

### `WhitelistThreadOrigin`

```cpp
ErrorCode WhitelistThreadOrigin(
    const char* module_name,
    const char* reason
);
```

Adds a module to the thread origin whitelist. Threads starting from code within this module will not be flagged as suspicious.

**Parameters:**
- `module_name` - Module name (e.g., "MyEngine.dll"). Case-insensitive.
- `reason` - Description for logging and debugging (e.g., "Game engine job system")

**Returns:**
- `ErrorCode::Success` - Whitelist entry added successfully
- `ErrorCode::NotInitialized` - SDK not initialized
- `ErrorCode::InvalidParameter` - Invalid module_name or reason
- `ErrorCode::InternalError` - Whitelist manager not available

**Thread Safety:** This function is thread-safe and can be called from any thread.

### `RemoveThreadOriginWhitelist`

```cpp
void RemoveThreadOriginWhitelist(const char* module_name);
```

Removes a module from the thread origin whitelist. Built-in whitelist entries cannot be removed.

**Parameters:**
- `module_name` - Module name to remove from whitelist

**Thread Safety:** This function is thread-safe and can be called from any thread.

**Note:** Built-in system DLL and runtime whitelist entries cannot be removed.

## Detection Logic

The thread validation system uses a multi-layered approach:

1. **Memory Type Check** - Threads starting in `MEM_IMAGE` (normal modules) pass immediately
2. **Whitelist Check** - Check if the thread's module is in the whitelist
3. **Thread Pool Detection** - Verify if it's a Windows thread pool worker
4. **CLR Detection** - Check if it's a .NET managed thread
5. **Trampoline Validation** - Check if the memory is a small region adjacent to a known module

Only after all these checks fail is a thread flagged as suspicious.

## Example: Game Engine Integration

```cpp
// game_init.cpp
#include <SentinelSDK.hpp>

void InitializeSecurity() {
    // Configure SDK
    auto config = Sentinel::SDK::Configuration::Default();
    config.license_key = "YOUR_LICENSE_KEY";
    config.game_id = "mygame_v1";
    
    // Initialize
    if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) {
        // Handle initialization failure
        return;
    }
    
    // Whitelist your custom threading systems
    Sentinel::SDK::WhitelistThreadOrigin(
        "GameEngine.dll",
        "Main game engine with custom job system"
    );
    
    Sentinel::SDK::WhitelistThreadOrigin(
        "PhysicsEngine.dll", 
        "Physics simulation thread pool"
    );
    
    Sentinel::SDK::WhitelistThreadOrigin(
        "AudioEngine.dll",
        "Audio processing threads"
    );
}
```

## Best Practices

1. **Add Whitelists Early** - Configure whitelists immediately after SDK initialization, before your threading systems start
2. **Use Specific Names** - Use the exact module name, not a path
3. **Document Reasons** - Provide clear reasons for logging and debugging
4. **Test Thoroughly** - Verify that your custom threads aren't being flagged
5. **Monitor Logs** - Check SDK logs for any unexpected thread detection events

## Troubleshooting

### My threads are still being flagged

1. Verify the module name is correct (use Process Explorer to check)
2. Ensure the whitelist is added before threads are created
3. Check if threads are actually starting from your module code
4. Verify SDK initialization succeeded before adding whitelist entries

### Built-in modules aren't working

The built-in whitelist is automatically loaded during SDK initialization. If you're still seeing false positives:

1. Verify SDK is initialized correctly
2. Check if the module name matches exactly (case-insensitive)
3. Report the issue with module details

## Security Considerations

**Important:** Only whitelist modules you trust. A malicious actor could:

1. Name their malicious DLL the same as a whitelisted module
2. Inject code into a whitelisted module

The SDK performs additional validation:
- Checks code signing for built-in whitelist entries
- Validates trampolines are small and adjacent to legitimate modules
- Monitors for suspicious behavior even from whitelisted sources

## Performance Impact

The whitelist system has minimal performance impact:
- **Whitelist Check**: O(n) lookup, typically < 50 entries
- **Thread Pool Detection**: Single module name check
- **CLR Detection**: Single module name check
- **Trampoline Validation**: Only runs if other checks fail

Total overhead: ~1-5 microseconds per thread creation check.

## Version History

- **v1.0.0** - Initial whitelist implementation
  - Built-in whitelist for Windows system DLLs
  - Built-in whitelist for .NET runtime
  - Built-in whitelist for common JIT engines
  - Public API for custom whitelisting
  - Thread pool detection
  - CLR thread detection
  - Trampoline validation

## Related Documentation

- [SDK Initialization Guide](SDK_INITIALIZATION.md)
- [Detection System Overview](DETECTION_OVERVIEW.md)
- [Thread Injection Detection](THREAD_INJECTION_DETECTION.md)
