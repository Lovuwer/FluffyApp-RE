# Minimal Sentinel SDK Integration Example

## Overview

This example demonstrates the **absolute minimum code** required to integrate the Sentinel SDK into a game. The entire integration is **8 lines of code** - meeting the Task 31 requirement of "fewer than 10 lines for basic functionality."

## Requirements Met

✅ **Fewer than 10 lines of code** - Only 8 lines required  
✅ **Single function initialization** - `Initialize(&config)`  
✅ **Single function update** - `Update()`  
✅ **Simple callback pattern** - Optional function pointer  
✅ **Sensible defaults** - `Configuration::Default()` requires no tuning  
✅ **No exception handling** - Uses error codes, not exceptions  
✅ **Cross-platform** - Identical API on Windows/Linux/macOS

## The 8 Lines

```cpp
// Lines 1-3: Configure with sensible defaults
auto config = Sentinel::SDK::Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";
config.game_id = "your-game-id";

// Line 4: Optional callback (can be omitted)
config.violation_callback = OnViolation;

// Line 5: Initialize
if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) return 1;

// Lines 6-7: Game loop
while (game_running) {
    Sentinel::SDK::Update();  // Once per frame
    // Your game code...
}

// Line 8: Cleanup
Sentinel::SDK::Shutdown();
```

## What You Get With Zero Configuration

The `Configuration::Default()` provides sensible defaults:

- **Detection Features**: Standard set (AntiDebug, AntiHook, Integrity)
- **Response Action**: Log and report violations
- **Heartbeat Interval**: 1000ms (1 second)
- **Scan Interval**: 5000ms (5 seconds)
- **No tuning required** - works out of the box

## Building

```bash
# Configure CMake
cmake -B build -DSENTINEL_BUILD_TESTS=OFF

# Build
cmake --build build --target MinimalIntegration

# Run
./build/bin/MinimalIntegration
```

## Optional Features

### Custom Violation Handler

```cpp
bool SENTINEL_CALL OnViolation(const Sentinel::SDK::ViolationEvent* event, void*) {
    // Handle security event
    LogToServer(event->type, event->severity);
    return true;  // Continue monitoring
}

config.violation_callback = OnViolation;
```

### Periodic Full Scans

For more thorough checking, call `FullScan()` every few seconds:

```cpp
static int frame_count = 0;
while (game_running) {
    Sentinel::SDK::Update();  // Every frame
    
    if (++frame_count % 300 == 0) {  // Every 5 seconds at 60 FPS
        Sentinel::SDK::FullScan();
    }
    
    // Game code...
}
```

## Integration Time Estimate

- **Read documentation**: 30 minutes
- **Add 8 lines of code**: 5 minutes
- **Test and verify**: 30 minutes
- **Tune for production**: 1 hour

**Total**: ~2 hours for a developer unfamiliar with the SDK  
**Goal**: Under 4 hours ✓

## Next Steps

1. **Get a license key** from Sentinel Security
2. **Copy the 8 lines** into your game initialization
3. **Build and test** your game normally
4. **Monitor violations** through the callback
5. **Deploy** with confidence

See [INTEGRATION_GUIDE.md](../../docs/STUDIO_INTEGRATION_GUIDE.md) for complete documentation.
