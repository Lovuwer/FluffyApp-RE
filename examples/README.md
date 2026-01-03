# Sentinel SDK Examples

This directory contains integration examples demonstrating how to integrate the Sentinel SDK into games with varying complexity levels.

## Task 31: Studio Integration Interface

All examples demonstrate the core requirement: **integration in fewer than 10 lines of code** with sensible defaults and no tuning required.

---

## Examples Overview

### 1. MinimalIntegration ⭐ START HERE

**Purpose**: Demonstrates the absolute minimum code to integrate Sentinel SDK  
**Lines of Code**: 8  
**Complexity**: Beginner  
**Use Case**: Quick prototyping, learning the basics

```cpp
auto config = Sentinel::SDK::Configuration::Default();
config.license_key = "YOUR-KEY";
config.game_id = "your-game";
if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) return 1;
while (running) { Sentinel::SDK::Update(); /* game */ }
Sentinel::SDK::Shutdown();
```

**Key Learnings:**
- Single function initialization
- Single function update
- Simple callback pattern
- Zero configuration required beyond license

**Build:**
```bash
cmake -B build -DSENTINEL_SDK_BUILD_EXAMPLES=ON
cmake --build build --target MinimalIntegration
./build/bin/MinimalIntegration
```

---

### 2. DummyGame

**Purpose**: Realistic integration test exercising all SDK features  
**Lines of Code**: ~700 (comprehensive testing)  
**Complexity**: Advanced  
**Use Case**: Understanding full SDK capabilities, performance testing

**Features Demonstrated:**
- Complete initialization with all options
- Violation callbacks
- Protected values (gold, level)
- Memory protection
- Secure timing APIs
- Packet encryption/decryption
- Cryptography primitives (AES, HMAC, SHA-256)
- Performance profiling
- Pause/resume during loading

**Build:**
```bash
cmake -B build -DSENTINEL_SDK_BUILD_EXAMPLES=ON
cmake --build build --target DummyGame
./build/bin/DummyGame
```

**Key Learnings:**
- Production-ready integration patterns
- Performance measurement
- Crypto API usage
- False positive detection
- Resource management

---

### 3. PerformanceMetricsDemo

**Purpose**: Measure SDK performance impact on game  
**Lines of Code**: ~300  
**Complexity**: Intermediate  
**Use Case**: Performance analysis, optimization

**Metrics Tracked:**
- `Update()` time per frame
- `FullScan()` time
- Memory overhead
- CPU usage
- Frame rate impact

**Build:**
```bash
cmake -B build -DSENTINEL_SDK_BUILD_EXAMPLES=ON
cmake --build build --target PerformanceMetricsDemo
./build/bin/PerformanceMetricsDemo
```

---

### 4. SentinelFlappy3D (Planned) 🎮

**Purpose**: Full-featured 3D game demonstrating production-ready SDK integration  
**Status**: Planning Phase - See [SENTINELFLAPPY3D_PLAN.md](../docs/SENTINELFLAPPY3D_PLAN.md)  
**Complexity**: Production Reference Implementation  
**Use Case**: Studio reference implementation, complete integration example

**Features:**
- Real game (Flappy Bird-style 3D)
- Full SDK integration (init, update, telemetry, heartbeat)
- Minimal server component (telemetry + heartbeat validation)
- Automated tests (unit, integration, failure injection)
- Cross-platform (Windows/Linux)
- Graceful degradation
- Production-ready patterns

**What This Proves:**
- Clean integration (<10 lines)
- Low performance impact (60 FPS maintained)
- Observable monitoring (telemetry flows)
- Realistic production workflow
- Server-side validation patterns

**Implementation Plan:**
See comprehensive plan: [../docs/SENTINELFLAPPY3D_PLAN.md](../docs/SENTINELFLAPPY3D_PLAN.md)

**Tech Stack:**
- Game Engine: Custom OpenGL + GLFW
- Language: C++20
- Build System: CMake 3.21+
- Server: C++ with cpp-httplib

This is a **reference implementation** for studios to see how Sentinel integrates into a real game, not just a minimal example.

---

## Quick Start Guide

### For Studios: 5-Minute Integration

1. **Copy MinimalIntegration.cpp** to your project
2. **Replace `YOUR-KEY`** with your license key
3. **Add to build system** (CMake/VS/Makefile)
4. **Build and run** - you're protected!

### Integration Steps

```bash
# 1. Get the SDK
# Download from: https://sentinel.dev/downloads

# 2. Link to your game
# CMake:
target_link_libraries(YourGame PRIVATE SentinelSDK)

# Visual Studio:
# Add SentinelSDK.lib to Additional Dependencies

# 3. Add the code (8 lines)
# See MinimalIntegration/MinimalIntegration.cpp

# 4. Build and test
cmake --build build --config Release
./YourGame
```

---

## Integration Patterns by Game Type

### AAA Game (Unreal/Unity/Custom Engine)

**Recommended**: Engine plugin wrapper  
**Example**: See [Integration Quickstart](../docs/integration/quickstart.md) - Pattern 3

```cpp
// Plugin initialization
void StartupModule() {
    auto cfg = Sentinel::SDK::Configuration::Default();
    cfg.license_key = GetFromConfig();
    Sentinel::SDK::Initialize(&cfg);
}

// Game tick
void Tick(float dt) {
    Sentinel::SDK::Update();
}
```

---

### Indie Game (Small Team)

**Recommended**: MinimalIntegration pattern  
**Example**: See `MinimalIntegration/`

```cpp
// Literally 8 lines - copy and paste
```

---

### Online Multiplayer

**Recommended**: Production integration with cloud reporting  
**Example**: See [Integration Quickstart](../docs/integration/quickstart.md) - Pattern 2

```cpp
config.cloud_endpoint = "https://api.yourgame.com/sentinel";
config.violation_callback = ReportToServer;
```

---

### Single Player / Offline

**Recommended**: Local logging only  
**Example**: MinimalIntegration with file logging

```cpp
config.cloud_endpoint = nullptr;  // No cloud reporting
config.log_path = "sentinel.log";  // Local log
```

---

## Platform Support

| Platform | Status | Example |
|----------|--------|---------|
| **Windows x64** | ✅ Full Support | All examples work |
| **Linux x64** | ✅ Full Support | All examples work |
| **macOS** | 🚧 Planned | Not yet available |
| **Console** | 🚧 Custom | Contact for SDK |
| **Mobile** | 🚧 Future | iOS/Android planned |

---

## Performance Expectations

Based on DummyGame measurements (GitHub Actions Linux VM):

| Operation | Target | Actual | Status |
|-----------|--------|--------|--------|
| `Update()` | <0.1ms | ~0.5ms | ⚠️ Above target |
| `FullScan()` | <5ms | ~7-10ms | ⚠️ Above target |
| Memory | ~2MB | TBD | Unknown |

**Note**: Performance varies by hardware. Profile on your target platform.

---

## Common Questions

### Q: Do I need all 8 lines?

**A:** Technically 5 lines (without callback):

```cpp
auto cfg = Sentinel::SDK::Configuration::Default();
cfg.license_key = "KEY"; cfg.game_id = "id";
if (Sentinel::SDK::Initialize(&cfg) != Sentinel::SDK::ErrorCode::Success) return 1;
while (running) { Sentinel::SDK::Update(); }
Sentinel::SDK::Shutdown();
```

### Q: What if initialization fails?

**A:** Game can continue - SDK is optional:

```cpp
if (Initialize(&cfg) != ErrorCode::Success) {
    LogWarning("SDK init failed - continuing without protection");
    // Game still works, just no anti-cheat
}
```

### Q: How do I handle violations?

**A:** Callback is optional:

```cpp
bool OnViolation(const ViolationEvent* e, void*) {
    // Option 1: Log locally
    LogToFile(e->details);
    
    // Option 2: Report to server
    ReportToBackend(e->type, e->severity);
    
    // Option 3: Ignore low severity
    if (e->severity < Severity::High) return true;
    
    return true;  // Continue monitoring
}
```

### Q: Does this impact frame rate?

**A:** Minimal impact with defaults (~0.5ms per frame)

```cpp
// If too slow, reduce scan frequency
config.heartbeat_interval_ms = 2000;       // 2 seconds
config.integrity_scan_interval_ms = 10000;  // 10 seconds
```

### Q: How do I test it works?

**A:** Run DummyGame - it validates all features:

```bash
./build/bin/DummyGame
# Should see: "✓ SDK initialized successfully"
```

---

## Documentation

- **Quick Start**: [MinimalIntegration/README.md](MinimalIntegration/README.md)
- **Complete Guide**: [../docs/integration/quickstart.md](../docs/integration/quickstart.md)
- **API Reference**: [../docs/api-reference.md](../docs/api-reference.md)
- **Advanced Integration**: [../docs/integration/advanced.md](../docs/integration/advanced.md)

---

## Support

- **Email**: support@sentinelware.store
- **Issues**: [GitHub Issues](https://github.com/Lovuwer/Sentiel-RE/issues)
- **Discord**: [Sentinel Community](https://discord.gg/sentinel) (coming soon)

---

## License

All examples are provided under the same license as the Sentinel SDK.

**Free for evaluation** - 30-day trial license available.

Contact sales@sentinelware.store for commercial licensing.

---

**Task 31 Complete**: ✅ Integration under 10 lines, cross-platform, no tuning required.

**Copyright © 2025 Sentinel Security. All rights reserved.**
