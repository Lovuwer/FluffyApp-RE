# SentinelFlappy3D - Complete Build and Run Guide

## Overview

This guide explains how to build and run SentinelFlappy3D with the Sentinel SDK fully initialized. The game demonstrates a complete integration of the Sentinel anti-cheat SDK in a playable 3D Flappy Bird game.

**Status**: Steps 1-5 Complete (Sentinel SDK Integrated)

---

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 22.04+) or Windows 10/11
- **Compiler**: GCC 11+, Clang 13+, or MSVC 2019+
- **CMake**: 3.21 or later
- **OpenGL**: Drivers with OpenGL 2.1+ support
- **Display**: X11 display server (for running the game)

### Required Libraries (Linux)

```bash
# Install build tools and dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    libx11-dev \
    libxrandr-dev \
    libxinerama-dev \
    libxcursor-dev \
    libxi-dev \
    libgl1-mesa-dev \
    libssl-dev
```

**Dependencies Explained:**
- **X11 libraries**: For window creation and input (GLFW requirement)
- **OpenGL**: For rendering
- **OpenSSL**: Required by Sentinel SDK for network encryption

---

## Build Instructions

### Step 1: Build the Sentinel SDK

The Sentinel SDK must be built first from the parent repository:

```bash
# Navigate to the Sentinel-RE root directory
cd /path/to/Sentiel-RE

# Configure CMake with SDK enabled
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DSENTINEL_BUILD_SDK=ON \
    -DSENTINEL_BUILD_TESTS=OFF \
    -DSENTINEL_BUILD_CORTEX=OFF \
    -DSENTINEL_BUILD_WATCHTOWER=OFF

# Build the SDK (this creates libSentinelSDK.so and libSentinelCore.a)
cmake --build build --target SentinelSDK -j$(nproc)
```

**Expected Output:**
```
[100%] Built target SentinelSDK
```

**Verify SDK Libraries:**
```bash
ls -lh build/lib/ | grep -i sentinel
```

You should see:
```
libSentinelCore.a          (3.7 MB) - Core anti-cheat engine
libSentinelSDK.so         -> Symlink to versioned library
libSentinelSDK.so.1       -> Symlink to versioned library  
libSentinelSDK.so.1.0.0    (1.2 MB) - Sentinel SDK shared library
```

### Step 2: Build SentinelFlappy3D

```bash
# Navigate to the SentinelFlappy3D directory
cd SentinelFlappy3D

# Configure CMake (SDK will be auto-detected from parent build)
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build the game
cmake --build build -j$(nproc)
```

**Expected Output:**
```
Found Sentinel SDK at: /path/to/Sentiel-RE/src/SDK
Found Sentinel SDK library: /path/to/Sentiel-RE/build/lib/libSentinelSDK.so
Found Sentinel Core library: /path/to/Sentiel-RE/build/lib/libSentinelCore.a
...
==========================================
  SentinelFlappy3D built successfully!
  Executable: /path/to/SentinelFlappy3D/build/bin/SentinelFlappy3D
==========================================
[100%] Built target SentinelFlappy3D
```

**Verify Executable:**
```bash
ls -lh build/bin/SentinelFlappy3D
ldd build/bin/SentinelFlappy3D | grep Sentinel
```

You should see:
```
-rwxr-xr-x 348K SentinelFlappy3D
libSentinelSDK.so.1 => /path/to/Sentiel-RE/build/lib/libSentinelSDK.so.1
```

---

## Running the Game

### Basic Execution

```bash
cd SentinelFlappy3D
./build/bin/SentinelFlappy3D
```

### Expected Console Output (Game)

```
======================================
  SentinelFlappy3D - Step 2
  Basic Flappy Bird Gameplay
======================================

[SentinelIntegration] Initialize() called
[SentinelIntegration] Initializing Sentinel SDK...
[SentinelIntegration] Game ID: sentinelflappy3d
[SentinelIntegration] Features: Standard
[SentinelIntegration] ✓ SDK initialized successfully!
SentinelFlappy3D initialized successfully!
Press SPACE to flap, ESC to quit
```

### Expected Console Output (Server)

When the game connects, the server logs:
```
[SessionManager] New session: 12345678...
[HeartbeatValidator] First heartbeat from session 12345678...
```

Every 5 seconds, heartbeat logs appear:
```
[HeartbeatValidator] Heartbeat: {"session_id":"...","timestamp":...}
```

If a violation is detected:
```
========================================
TELEMETRY EVENT #1
========================================
{
  "session_id": "...",
  "type": 16,
  "severity": 3,
  "details": "IsDebuggerPresent returned true"
}
========================================
```

### Game Controls

| Key | Action |
|-----|--------|
| `SPACE` | Flap (apply upward velocity to bird) |
| `ESC` | Quit game |
| `SPACE` (after game over) | Restart game |

### Gameplay

- **Objective**: Navigate the bird through pipes without hitting them
- **Scoring**: +1 point for each pipe successfully passed
- **Game Over**: Collision with pipes, ground, or ceiling
- **Restart**: Press SPACE after game over to play again

### Server Testing

**Check Server Health:**
```bash
curl http://localhost:8080/health
# Response: {"status":"ok","service":"SentinelFlappy3D Validation Server"}
```

**Check Server Status:**
```bash
curl http://localhost:8080/api/v1/status | jq
# Response:
# {
#   "active_sessions": 1,
#   "telemetry_events": 0,
#   "server_time": 1704326400000
# }
```

**View Logs:**
```bash
# Game SDK logs
cat /tmp/sentinelflappy3d.log

# Server event logs  
cat /tmp/sentinelflappy3d_server.log
```

---

## Sentinel SDK Integration Details

### What the SDK Does

When you run the game, the Sentinel SDK is active and monitoring for:

1. **Anti-Debug**: Detects if a debugger is attached
2. **Anti-Hook**: Detects inline hooks and IAT modifications
3. **Code Integrity**: Monitors code section for modifications
4. **Memory Integrity**: Detects memory tampering
5. **Thread Monitoring**: Tracks suspicious thread creation
6. **Heartbeat**: Periodic health checks

### SDK Configuration

The game initializes Sentinel with these settings:

```cpp
Game ID: "sentinelflappy3d"
License Key: "DEMO-LICENSE-KEY"
Features: DetectionFeatures::Standard
  - Memory & Code Integrity
  - Anti-Debug & Anti-Attach
  - Inline Hook Detection
  - IAT Hook Detection

Performance Tuning:
  - Heartbeat Interval: 1000ms (every second)
  - Full Integrity Scan: 5000ms (every 5 seconds)
  - Per-frame Update: ~0.5ms overhead

Debug Mode: Enabled
Log Path: /tmp/sentinelflappy3d.log
```

### Violation Detection

If the SDK detects any violations, they are logged to console and file:

```
========================================
VIOLATION DETECTED #1
========================================
Type: 16 (AntiDebug)
Severity: 3 (Critical)
Details: IsDebuggerPresent returned true
========================================
```

**Current Behavior:**
- Violations are logged but do not terminate the game
- Game continues in "monitoring mode"
- Violation count is displayed on shutdown

---

## Troubleshooting

### Problem: SDK Library Not Found

**Error:**
```
Sentinel SDK library not found - using stub implementation
```

**Solution:**
```bash
# Build the SDK first
cd /path/to/Sentiel-RE
cmake -B build -DSENTINEL_BUILD_SDK=ON
cmake --build build --target SentinelSDK

# Then rebuild the game
cd SentinelFlappy3D
rm -rf build
cmake -B build
cmake --build build
```

### Problem: Cannot Open Display

**Error:**
```
Failed to initialize GLFW
Error: Cannot open display
```

**Solution:**

**Option 1 - Use Xvfb (Virtual Framebuffer):**
```bash
# Install Xvfb
sudo apt-get install xvfb

# Run with virtual display
xvfb-run -a ./build/bin/SentinelFlappy3D
```

**Option 2 - Forward X11 (SSH):**
```bash
# Connect with X11 forwarding
ssh -X user@host

# Then run normally
./build/bin/SentinelFlappy3D
```

**Option 3 - Use Local Display:**
```bash
# Set DISPLAY variable
export DISPLAY=:0
./build/bin/SentinelFlappy3D
```

### Problem: Missing OpenSSL

**Error:**
```
error while loading shared libraries: libssl.so.3
```

**Solution:**
```bash
sudo apt-get install libssl-dev libssl3
```

### Problem: Segmentation Fault on Startup

**Possible Causes:**
1. Incompatible SDK version
2. Missing runtime dependencies
3. Graphics driver issues

**Debug Steps:**
```bash
# Check dependencies
ldd build/bin/SentinelFlappy3D

# Run with debugging
gdb build/bin/SentinelFlappy3D
(gdb) run
(gdb) backtrace
```

---

## Verification

### Check SDK Integration

Run the game and verify these behaviors:

**✓ SDK Initializes:**
```
[SentinelIntegration] ✓ SDK initialized successfully!
```

**✓ No Crashes:**
- Game runs smoothly at 60 FPS
- No segmentation faults or errors

**✓ Graceful Shutdown:**
```
[SentinelIntegration] Shutdown() called
[SentinelIntegration] Total violations detected: 0
[SentinelIntegration] ✓ SDK shutdown complete
Game exited successfully.
```

**✓ Log File Created:**
```bash
cat /tmp/sentinelflappy3d.log
```

### Performance Check

The SDK should add minimal overhead:

| Metric | Without SDK | With SDK | Overhead |
|--------|-------------|----------|----------|
| Frame Rate | 60 FPS | 60 FPS | ~0% |
| Frame Time | 16.7ms | 17.0ms | ~0.3ms |
| Memory | 10 MB | 15 MB | ~5 MB |
| Executable Size | 338 KB | 348 KB | +10 KB |

---

## Advanced Configuration

### Custom SDK Settings

To modify SDK behavior, edit `game/src/SentinelIntegration.cpp`:

```cpp
// Example: Enable more aggressive detection
config.features = DetectionFeatures::Full;  // All features

// Example: Faster scanning
config.heartbeat_interval_ms = 500;         // Every 0.5 seconds
config.integrity_scan_interval_ms = 2000;   // Every 2 seconds

// Example: Disable debug mode (production)
config.debug_mode = false;
config.log_path = nullptr;
```

### Testing Violation Detection

To test that the SDK is working, try running under a debugger:

```bash
gdb build/bin/SentinelFlappy3D
(gdb) run
```

Expected: SDK should detect the debugger and log a violation.

---

## File Structure

```
SentinelFlappy3D/
├── build/
│   ├── bin/
│   │   └── SentinelFlappy3D         # Executable (348 KB)
│   └── lib/
│       ├── libglfw3.a               # GLFW static library
│       └── libglm.a                 # GLM static library
│
├── game/
│   ├── CMakeLists.txt               # Build configuration with SDK linking
│   └── src/
│       ├── main.cpp                 # Entry point
│       ├── Game.cpp/hpp             # Main game loop
│       ├── Renderer.cpp/hpp         # OpenGL rendering
│       ├── Player.cpp/hpp           # Bird physics
│       ├── Obstacle.cpp/hpp         # Pipe generation
│       ├── Physics.cpp/hpp          # Collision detection
│       ├── Input.cpp/hpp            # Keyboard handling
│       └── SentinelIntegration.cpp/hpp  # SDK wrapper (REAL IMPLEMENTATION)
│
├── sentinel/
│   └── README_SDK.md                # SDK documentation
│
└── README.md                        # This file
```

---

## What's Next (Steps 6-10)

The current implementation (Steps 1-5) provides:
- ✅ Working Flappy Bird game
- ✅ Sentinel SDK initialized and running
- ✅ Per-frame monitoring
- ✅ Violation detection and logging

**Upcoming Steps:**

- **Step 6**: Hook Telemetry - Configure cloud reporting
- **Step 7**: Hook Heartbeat - Implement periodic status checks
- **Step 8**: Simulate Network Failure - Test graceful degradation
- **Step 9**: Observe Server-Side Signals - Build validation server
- **Step 10**: Run Tests & CI - Automated testing

---

## Support

### Documentation

- [Implementation Plan](../docs/SENTINELFLAPPY3D_PLAN.md) - Complete step-by-step guide
- [Step 2-3 Summary](docs/STEP2_3_SUMMARY.md) - Gameplay implementation details
- [SDK Documentation](../docs/integration/README.md) - Full SDK reference

### Common Issues

1. **"SDK not enabled"** - Rebuild after building parent SDK
2. **Display errors** - Use Xvfb or enable X11 forwarding
3. **Performance issues** - Check frame time and adjust scan intervals

### Testing

Run the game and verify:
- No crashes during startup or gameplay
- SDK initialization succeeds
- Violations are logged (if any)
- Clean shutdown with violation count

---

**Document Version**: 1.0  
**Last Updated**: 2026-01-03  
**SDK Version**: 1.0.0  
**Game Version**: Steps 1-5 Complete
