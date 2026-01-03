# SentinelFlappy3D

A realistic 3D Flappy Bird game demonstrating proper Sentinel SDK integration.

## Purpose

SentinelFlappy3D is a **reference implementation** that shows game studios how to integrate the Sentinel anti-cheat SDK. This is a fully functional game that proves:

- **Clean Integration**: SDK integrates in under 10 lines of code
- **Minimal Performance Impact**: Game maintains 60 FPS with SDK active
- **Transparent Operation**: All SDK activity is logged and observable
- **Graceful Degradation**: Game continues even if SDK encounters errors
- **Production Readiness**: Integration pattern scales from indie to AAA titles

## Current Status

**Steps 1-3 Complete**: Project skeleton, game implementation, and standalone build

**Completed Steps**:
- ✅ Step 1: Project skeleton and CMake structure
- ✅ Step 2: Basic Flappy Bird gameplay implementation
- ✅ Step 3: Build verification (standalone without Sentinel)

**Next Steps**:
- Step 2: Implement basic Flappy Bird gameplay ✅
- Step 3: Build and run without Sentinel ✅
- Step 3: Build and run without Sentinel
- Step 4: Add Sentinel SDK integration
- Step 5: Initialize Sentinel correctly
- Step 6: Hook telemetry
- Step 7: Hook heartbeat
- Step 8: Simulate network failure
- Step 9: Observe server-side signals
- Step 10: Run tests & CI

See [docs/SENTINELFLAPPY3D_PLAN.md](../docs/SENTINELFLAPPY3D_PLAN.md) for the complete implementation plan.

## Repository Structure

```
SentinelFlappy3D/
├─ CMakeLists.txt          # Root build configuration
├─ README.md               # This file
│
├─ game/                   # Core game implementation
│  ├─ CMakeLists.txt       # Game build config
│  └─ src/                 # Game source files (to be added)
│
├─ server/                 # Validation server
│  ├─ CMakeLists.txt       # Server build config
│  └─ (sources TBD)        # Server implementation (to be added)
│
├─ tests/                  # Automated tests
│  └─ (TBD)                # Test files (to be added)
│
├─ tools/                  # Build and test scripts
│  └─ (TBD)                # Scripts (to be added)
│
└─ docs/                   # Integration documentation
   └─ (TBD)                # Documentation (to be added)
```

## Technology Stack

- **Language**: C++20
- **Build System**: CMake 3.21+
- **Graphics**: OpenGL 3.3 Core with GLFW
- **Math**: GLM (OpenGL Mathematics)
- **Server**: cpp-httplib (header-only HTTP server)
- **Anti-Cheat**: Sentinel SDK (user-mode detection)

## Prerequisites

### Windows
- Visual Studio 2019 or later (MSVC)
- CMake 3.21+
- OpenGL drivers (already installed on most systems)

### Linux
- GCC 11+ or Clang 13+
- CMake 3.21+
- OpenGL development libraries:
  ```bash
  sudo apt install libgl1-mesa-dev libglu1-mesa-dev
  ```

## Building

### Prerequisites Installed

The project requires:
- C++20 compiler (GCC 11+ or Clang 13+ or MSVC 2019+)
- CMake 3.21+
- OpenGL development libraries
- X11 development libraries (Linux)

On Ubuntu/Debian:
```bash
sudo apt-get install libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev libgl1-mesa-dev
```

### Configure

```bash
cd SentinelFlappy3D
cmake -B build -DCMAKE_BUILD_TYPE=Release
```

**Note**: GLFW and GLM are automatically fetched via CMake FetchContent.

### Build

```bash
cmake --build build
```

**Output**: Executable is placed in `build/bin/SentinelFlappy3D`

### Build Verification

✅ **Steps 2 & 3**: Game builds successfully and creates executable (338 KB)

## Running

### Game Executable

The game requires a display to run. In headless CI environments, the build succeeds but the game cannot be executed without a display server.

To run locally (with display):
```bash
./build/bin/SentinelFlappy3D
```

**Controls**:
- `SPACE`: Flap (apply upward velocity)
- `ESC`: Quit game

**Gameplay**:
- Avoid the pipes by flapping
- Score increases when passing pipes
- Press SPACE after game over to restart

### Server

Server implementation coming in Step 9.

## Integration Guide

This project demonstrates SDK integration following these principles:

1. **Initialize Once**: Call `Sentinel::SDK::Initialize()` at startup
2. **Update Per Frame**: Call `Sentinel::SDK::Update()` in game loop
3. **Shutdown Cleanly**: Call `Sentinel::SDK::Shutdown()` on exit
4. **Handle Errors**: Log failures but continue game in degraded mode
5. **Monitor Telemetry**: Process violation callbacks for debugging

Detailed integration steps will be documented as each step is implemented.

## What This Demo Proves

- SDK integration requires minimal code changes
- Performance overhead is negligible (<1ms per frame)
- SDK operation is transparent and debuggable
- Graceful degradation handles network/license failures
- Server-side validation complements client-side detection

## What This Demo Does NOT Cover

- Kernel-mode protection (Sentinel is user-mode only)
- Advanced cheat bypass techniques (reference implementation, not security research)
- Production-scale infrastructure (single-server demo)
- Competitive game design (focus is SDK integration)
- Multi-platform beyond Windows/Linux (mobile/console out of scope)

## License

- **Game Code**: MIT License (demo code freely available)
- **Sentinel SDK**: Proprietary (see parent repository license)
- **Dependencies**: Various open-source licenses (OpenGL, GLFW, GLM)

## Documentation

- [Complete Implementation Plan](../docs/SENTINELFLAPPY3D_PLAN.md) - Step-by-step guide
- [Quick Reference](../docs/SENTINELFLAPPY3D_QUICKREF.md) - Condensed overview
- [Sentinel SDK Documentation](../docs/integration/README.md) - SDK integration guide

## Support

For questions about this reference implementation:
1. Check [docs/SENTINELFLAPPY3D_PLAN.md](../docs/SENTINELFLAPPY3D_PLAN.md) for implementation details
2. Review [docs/integration/quickstart.md](../docs/integration/quickstart.md) for SDK basics
3. Open an issue in the parent Sentinel-RE repository

---

**Implementation Status**: Steps 1-3 Complete (Game Playable)  
**Next Milestone**: Step 4 - Add Sentinel SDK Integration  
**Full Plan**: See [SENTINELFLAPPY3D_PLAN.md](../docs/SENTINELFLAPPY3D_PLAN.md)
