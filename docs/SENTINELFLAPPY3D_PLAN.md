# SentinelFlappy3D - Reference Implementation Plan

**Document Version**: 1.0  
**Date**: 2026-01-03  
**Status**: Planning Phase  
**Author**: Sentinel Security Team

> **Quick Reference**: For a condensed overview, see [SENTINELFLAPPY3D_QUICKREF.md](SENTINELFLAPPY3D_QUICKREF.md)

---

## 1. High-Level Goal of SentinelFlappy3D

### Purpose

SentinelFlappy3D is a **realistic indie-scale 3D game** that serves as a **public reference implementation** demonstrating proper Sentinel SDK integration. This is not a tech demo or proof-of-concept—it is a fully functional game that proves to studios and engineers that:

- **Clean Integration**: Sentinel SDK integrates in under 10 lines of code with minimal disruption to game architecture
- **Correct Initialization**: SDK lifecycle management (init, update, shutdown) is straightforward and foolproof
- **Observable Monitoring**: Telemetry flows and heartbeat systems work transparently with clear debugging capabilities
- **Meaningful Testing**: Integration can be validated through automated tests and manual verification
- **Production Readiness**: The integration pattern scales from indie games to AAA titles

### What This Proves to Studios

1. **Low Integration Burden**: A small studio can integrate Sentinel in a single afternoon
2. **Minimal Performance Impact**: Game maintains 60 FPS target with SDK active
3. **Transparent Operation**: All SDK activity is logged and observable for debugging
4. **Graceful Degradation**: Game continues to function even if SDK encounters errors or network failures
5. **Real-World Validation**: Integration works with actual game loop, physics, rendering, and input handling

### What This Is NOT

- Not a competitive esports title requiring kernel-mode protection
- Not a cheat development framework or bypass testing tool
- Not a security research project exploring anti-anti-cheat techniques
- Not a replacement for comprehensive anti-cheat strategies (server validation, behavioral analysis)

---

## 2. Chosen Tech Stack (With Justification)

### Game Engine: **Custom OpenGL with GLFW**

**Justification**:
- **Simplicity**: No heavyweight engine dependencies—studios see pure SDK integration without framework abstraction
- **Transparency**: Complete control over game loop makes SDK integration points crystal clear
- **Portability**: Works on Windows and Linux without engine-specific licensing or tooling
- **Realistic for Indies**: Many indie studios use lightweight frameworks (SDL, GLFW, raylib) rather than full engines
- **Easy to Build**: CMake-based build with minimal dependencies

**Official Documentation**:
- OpenGL: https://www.opengl.org/documentation/
- GLFW: https://www.glfw.org/documentation.html
- GLEW: http://glew.sourceforge.net/

### Language: **C++20**

**Justification**:
- **SDK Native Language**: Sentinel SDK is C++20—no FFI or language binding complexity
- **Industry Standard**: C++ is dominant in game development (Unity plugins, Unreal, custom engines)
- **Performance**: Zero-cost abstractions ensure SDK overhead is measurable and minimal
- **Compatibility**: Same language as existing DummyGame example for consistency

**Official Documentation**:
- C++20 Standard: https://en.cppreference.com/w/cpp/20
- MSVC Compiler: https://docs.microsoft.com/en-us/cpp/
- GCC/Clang: https://gcc.gnu.org/projects/cxx-status.html

### Build System: **CMake 3.21+**

**Justification**:
- **Sentinel Standard**: Existing SDK uses CMake—integration is native
- **Cross-Platform**: Same build system works on Windows (MSVC/MinGW) and Linux (GCC/Clang)
- **IDE Support**: Visual Studio, CLion, VS Code all have excellent CMake support
- **Package Management**: FetchContent for dependencies (GLM, stb_image) is built-in

**Official Documentation**:
- CMake: https://cmake.org/cmake/help/latest/
- CMake FetchContent: https://cmake.org/cmake/help/latest/module/FetchContent.html

### Graphics/Math Libraries:

- **GLM (OpenGL Mathematics)**: https://github.com/g-truc/glm
  - Vector/matrix math for 3D transformations
  - Header-only library, no linking complexity
  
- **stb_image**: https://github.com/nothings/stb/blob/master/stb_image.h
  - Single-header image loading for textures
  - No external dependencies

- **GLFW**: https://www.glfw.org/
  - Window creation and input handling
  - OpenGL context management

### OS Targets:

- **Primary**: Windows 10/11 x64 (MSVC 2019+)
- **Secondary**: Linux x64 (Ubuntu 22.04+, GCC 11+)
- **Future**: macOS x64/ARM64 (with Metal backend)

**Justification**:
- Windows first because 90% of PC gaming is on Windows
- Linux secondary for server validation components and CI
- Same codebase demonstrates cross-platform SDK integration

### Why This Stack Is Realistic for Indie Studios

1. **No Licensing Costs**: All components are open-source or freely available
2. **Minimal Dependencies**: Only OpenGL drivers (already on every PC), GLFW, and GLM
3. **Fast Build Times**: Small codebase builds in under 60 seconds on modest hardware
4. **No Engine Overhead**: Studios using custom engines or lightweight frameworks see exactly how SDK integrates without Unity/Unreal abstraction
5. **Educational**: Source code is readable and demonstrates best practices for SDK integration

---

## 3. Repository Layout

```
SentinelFlappy3D/
├─ CMakeLists.txt                    # Root build configuration
├─ README.md                         # Quick start guide for studios
├─ LICENSE                           # MIT (demo code) + Sentinel SDK license notice
├─ .gitignore                        # Exclude build artifacts, IDE files
│
├─ game/                             # Core game implementation
│  ├─ CMakeLists.txt                # Game executable build config
│  ├─ src/
│  │  ├─ main.cpp                   # Entry point, SDK initialization
│  │  ├─ Game.cpp                   # Main game class, game loop
│  │  ├─ Game.hpp
│  │  ├─ Player.cpp                 # Flappy bird player controller
│  │  ├─ Player.hpp
│  │  ├─ Obstacle.cpp               # Pipe obstacles
│  │  ├─ Obstacle.hpp
│  │  ├─ Renderer.cpp               # OpenGL rendering
│  │  ├─ Renderer.hpp
│  │  ├─ Input.cpp                  # GLFW input handling
│  │  ├─ Input.hpp
│  │  ├─ Physics.cpp                # Simple gravity and collision
│  │  ├─ Physics.hpp
│  │  └─ SentinelIntegration.cpp    # SDK lifecycle wrapper
│  │     SentinelIntegration.hpp
│  └─ assets/
│     ├─ shaders/
│     │  ├─ basic.vert              # Vertex shader
│     │  └─ basic.frag              # Fragment shader
│     └─ textures/
│        ├─ bird.png                # Bird sprite
│        └─ pipe.png                # Pipe texture
│
├─ sentinel/                         # Sentinel SDK (gitignored, downloaded separately)
│  ├─ include/                      # SDK headers (from Sentinel-RE)
│  ├─ lib/                          # Prebuilt SDK libraries
│  └─ README_SDK.md                 # Instructions for obtaining SDK
│
├─ server/                           # Minimal validation server
│  ├─ CMakeLists.txt                # Server build config
│  ├─ main.cpp                      # HTTP server (cpp-httplib)
│  ├─ TelemetryHandler.cpp          # Process telemetry events
│  ├─ TelemetryHandler.hpp
│  ├─ HeartbeatValidator.cpp        # Validate heartbeat timing
│  ├─ HeartbeatValidator.hpp
│  └─ SessionManager.cpp            # Track connected clients
│     SessionManager.hpp
│
├─ tests/                            # Automated tests
│  ├─ CMakeLists.txt                # Test build config
│  ├─ GameLogicTests.cpp            # Unit tests for game logic
│  ├─ SentinelIntegrationTests.cpp  # SDK integration tests
│  └─ NetworkTests.cpp              # Server communication tests
│
├─ tools/                            # Build and test scripts
│  ├─ build.sh                      # Linux build script
│  ├─ build.bat                     # Windows build script
│  ├─ run_tests.sh                  # Test runner
│  └─ setup_sdk.sh                  # Download and setup Sentinel SDK
│
└─ docs/                             # Integration documentation
   ├─ INTEGRATION_GUIDE.md          # Step-by-step SDK integration
   ├─ BUILDING.md                   # Build instructions
   ├─ ARCHITECTURE.md               # Game architecture overview
   ├─ TESTING.md                    # Testing strategy
   └─ SERVER_SETUP.md               # Server deployment guide
```

### Folder Purpose Explanation

#### `game/`
Core game implementation. Everything needed to build and run the Flappy Bird game, including:
- Game loop and main entry point
- Player controller (flap on spacebar, gravity simulation)
- Obstacle generation and collision detection
- OpenGL rendering pipeline
- **SentinelIntegration**: Wrapper class that manages SDK lifecycle

#### `sentinel/`
This directory is **gitignored**. Studios download the Sentinel SDK separately (demonstrating real-world SDK distribution). Contains:
- SDK headers (`include/`)
- Prebuilt libraries (`lib/`)
- Setup instructions

#### `server/`
Minimal server component that demonstrates server-side validation. Accepts:
- Telemetry events (violations, timing anomalies)
- Heartbeat pings (with timing validation)
- Session management (track active games)

This is **logging only**—no banning logic. Shows studios what server-side validation looks like.

#### `tests/`
Automated tests using Google Test:
- Unit tests for game logic (collision, scoring)
- Integration tests for SDK lifecycle
- Network tests for server communication
- Failure injection tests (network down, server unreachable)

#### `tools/`
Scripts for building, testing, and SDK setup:
- Cross-platform build scripts
- Test runners
- SDK download/setup automation

#### `docs/`
Integration documentation:
- How to integrate Sentinel into your own game
- Build instructions for Windows and Linux
- Architecture diagrams
- Testing strategies

---

## 4. Step-by-Step Implementation Plan

### Step 1: Create the Game Skeleton

**Objective**: Set up CMake project with OpenGL, GLFW, and basic window.

**Files Touched**:
- `CMakeLists.txt` (root)
- `game/CMakeLists.txt`
- `game/src/main.cpp`
- `game/src/Game.cpp/hpp`
- `game/src/Renderer.cpp/hpp`

**Commands**:
```bash
mkdir -p SentinelFlappy3D/game/src
cd SentinelFlappy3D
touch CMakeLists.txt game/CMakeLists.txt
touch game/src/main.cpp game/src/Game.cpp game/src/Game.hpp
```

**Success Criteria**:
- CMake configures without errors
- Window opens with OpenGL context
- Game loop runs at 60 FPS (measured with timing code)
- Clean shutdown on ESC key

**Common Mistakes**:
- Forgetting to initialize GLFW before window creation
- Not setting OpenGL version hints (3.3 Core)
- Missing VSync configuration (causing >1000 FPS)

---

### Step 2: Implement Basic Flappy Gameplay

**Objective**: Add player controller, gravity, obstacles, collision, and scoring.

**Files Touched**:
- `game/src/Player.cpp/hpp`
- `game/src/Obstacle.cpp/hpp`
- `game/src/Physics.cpp/hpp`
- `game/src/Input.cpp/hpp`

**Commands**:
```bash
# No special commands—just implement classes
```

**Success Criteria**:
- Spacebar flaps the bird (applies upward velocity)
- Gravity pulls bird down continuously
- Pipes scroll from right to left
- Collision detection works (bird vs pipe, bird vs ground)
- Score increments when passing pipes
- Game over state on collision

**Common Mistakes**:
- Physics not frame-rate independent (use delta time)
- Collision boxes too tight (frustrating gameplay)
- Obstacles spawning too close together

---

### Step 3: Build & Run Without Sentinel

**Objective**: Verify game works standalone before adding SDK.

**Commands**:
```bash
cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/bin/SentinelFlappy3D
```

**Success Criteria**:
- Game builds with zero warnings
- Runs at stable 60 FPS
- Gameplay is smooth and playable
- No memory leaks (verified with Valgrind on Linux)

**Common Mistakes**:
- Skipping this step and mixing game bugs with SDK integration issues
- Not profiling baseline performance (can't measure SDK impact later)

---

### Step 4: Add Sentinel SDK

**Objective**: Integrate SDK library into CMake build system.

**Files Touched**:
- Root `CMakeLists.txt` (add FetchContent or find_package for Sentinel)
- `game/CMakeLists.txt` (link SentinelSDK)
- `sentinel/README_SDK.md` (document SDK setup)

**Commands**:
```bash
# Option 1: Download prebuilt SDK
curl -L https://sentinel.example.com/sdk/v1.0.0/SentinelSDK-Linux-x64.tar.gz -o sdk.tar.gz
tar -xzf sdk.tar.gz -C sentinel/

# Option 2: Build from source (if SDK is open in this project)
cd ../Sentiel-RE
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSENTINEL_BUILD_SDK=ON
cmake --build build --target SentinelSDK
cp build/lib/libSentinelSDK.* ../SentinelFlappy3D/sentinel/lib/
cp -r include/Sentinel ../SentinelFlappy3D/sentinel/include/
```

**Success Criteria**:
- CMake finds Sentinel SDK headers
- Linking succeeds (SentinelSDK library found)
- Game still builds and runs (SDK not initialized yet)

**Common Mistakes**:
- Incorrect include paths (SDK headers not found)
- Missing runtime dependencies (OpenSSL on Linux)
- Forgetting to copy shared library to executable directory (Windows DLL, Linux .so)

---

### Step 5: Initialize Sentinel Correctly

**Objective**: Add SDK initialization in main() with proper error handling.

**Files Touched**:
- `game/src/SentinelIntegration.cpp/hpp` (create wrapper class)
- `game/src/main.cpp` (call SDK init before game loop)

**Code Pattern** (no full implementation, just structure):
```cpp
// SentinelIntegration.cpp
class SentinelIntegration {
public:
    bool Initialize(const char* license_key, const char* game_id);
    void Update();
    void Shutdown();
    
private:
    bool m_initialized = false;
};
```

**Success Criteria**:
- SDK initializes successfully (returns ErrorCode::Success)
- Violation callback is registered and receives test events
- Error handling logs failures but doesn't crash game
- Game loop continues even if SDK init fails (graceful degradation)

**Common Mistakes**:
- Calling Update() before Initialize()
- Not checking return codes (silent failures)
- Forgetting to call Shutdown() on exit (resource leaks)

---

### Step 6: Hook Telemetry

**Objective**: Configure SDK to report violations to console/log file.

**Files Touched**:
- `game/src/SentinelIntegration.cpp` (violation callback implementation)
- `game/src/main.cpp` (configure log path)

**Success Criteria**:
- Violation callback fires on test events (inject fake violation for testing)
- Events contain: type, severity, timestamp, details, module name
- Events are logged to file: `/tmp/sentinel_flappy3d.log` (Linux) or `C:\Temp\sentinel_flappy3d.log` (Windows)
- Console output shows violations in real-time

**Common Mistakes**:
- Callback doing too much work (blocking game loop)
- Not thread-safe if SDK calls callback from background thread
- Logging sensitive data (player IPs, system info) without consent

---

### Step 7: Hook Heartbeat

**Objective**: Configure SDK heartbeat and verify it triggers periodically.

**Files Touched**:
- `game/src/SentinelIntegration.cpp` (configure heartbeat_interval_ms)
- `server/main.cpp` (add heartbeat endpoint)

**Configuration**:
```cpp
config.heartbeat_interval_ms = 5000; // Every 5 seconds
config.server_url = "http://localhost:8080";
```

**Success Criteria**:
- SDK sends heartbeat every 5 seconds (verified in server logs)
- Heartbeat includes: session_id, uptime, frame_count, SDK version
- Server responds with HTTP 200 OK
- Game continues if server is unreachable (graceful degradation)

**Common Mistakes**:
- Blocking network I/O in game thread (use async HTTP)
- Not handling network timeouts (game freezes on packet loss)
- Sending too much data in heartbeat (bandwidth concerns)

---

### Step 8: Simulate Network Failure

**Objective**: Test graceful degradation when server is unreachable.

**Commands**:
```bash
# Start game
./build/bin/SentinelFlappy3D

# In another terminal, simulate network failure
sudo iptables -A OUTPUT -p tcp --dport 8080 -j DROP  # Linux
# Or just stop the server
```

**Success Criteria**:
- Game continues to run normally
- SDK logs connection failures but doesn't crash
- Heartbeat retry logic kicks in (exponential backoff)
- No stuttering or frame drops during network failures

**Common Mistakes**:
- Synchronous network calls blocking game loop
- No timeout on HTTP requests (game hangs indefinitely)
- Retry logic spamming server (no backoff)

---

### Step 9: Observe Server-Side Signals

**Objective**: Run server and verify telemetry/heartbeat data is received correctly.

**Files Touched**:
- `server/main.cpp` (HTTP server with cpp-httplib)
- `server/TelemetryHandler.cpp` (parse and log telemetry)
- `server/HeartbeatValidator.cpp` (validate heartbeat timing)

**Commands**:
```bash
# Terminal 1: Start server
./build/bin/SentinelFlappy3DServer
# Server listens on http://localhost:8080

# Terminal 2: Start game
./build/bin/SentinelFlappy3D
```

**Success Criteria**:
- Server logs show heartbeat POST requests every 5 seconds
- Server logs show telemetry POST requests when violations occur
- Server validates heartbeat timing (rejects late/early beats)
- Server tracks active sessions (session_id from SDK)

**Common Mistakes**:
- Server not validating request signatures (spoofing possible)
- Server not checking replay attacks (same telemetry sent twice)
- Server not handling concurrent requests (crashes on load)

---

### Step 10: Run Tests & CI

**Objective**: Automate testing to prevent regressions.

**Files Touched**:
- `tests/GameLogicTests.cpp`
- `tests/SentinelIntegrationTests.cpp`
- `tests/NetworkTests.cpp`
- `.github/workflows/build.yml` (CI configuration)

**Commands**:
```bash
# Build tests
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
cmake --build build

# Run tests
cd build
ctest --output-on-failure

# Run with coverage
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DCOVERAGE=ON
cmake --build build
ctest
gcovr -r ..
```

**Success Criteria**:
- All tests pass (green)
- Code coverage >80% for SDK integration code
- CI runs on every commit (GitHub Actions)
- No memory leaks in Valgrind
- No AddressSanitizer errors

**Common Mistakes**:
- Tests depending on external services (flaky tests)
- Tests not isolated (one test affects another)
- Forgetting to test failure cases (network down, invalid config)

---

## 5. Sentinel Integration Details (NON-SECURITY)

This section explains **only** the SDK integration surface—not how Sentinel detects cheats.

### SDK Initialization

**When**: Called once at game startup, before main loop.

**Configuration**:
```cpp
auto config = Sentinel::SDK::Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";          // From Sentinel portal
config.game_id = "sentinelflappy3d";              // Unique game identifier
config.features = DetectionFeatures::Standard;    // Predefined feature set
config.violation_callback = OnViolation;          // Callback for events
config.heartbeat_interval_ms = 5000;             // Heartbeat frequency
config.server_url = "https://api.sentinel.example.com";
config.log_path = "/var/log/sentinel_flappy3d.log";
```

**Return Codes**:
- `ErrorCode::Success`: SDK initialized successfully
- `ErrorCode::InvalidLicense`: License key invalid or expired
- `ErrorCode::AlreadyInitialized`: Initialize() called twice
- `ErrorCode::SystemNotSupported`: OS version too old

**Error Handling**:
```cpp
ErrorCode result = Sentinel::SDK::Initialize(&config);
if (result != ErrorCode::Success) {
    // Log error but continue game (degraded mode)
    log("Sentinel SDK init failed: {}", static_cast<int>(result));
    // Game still playable, just no anti-cheat protection
}
```

---

### Lifecycle Management

**Main Game Loop**:
```cpp
while (game_running) {
    // Per-frame lightweight check (~0.5ms)
    Sentinel::SDK::Update();
    
    // Game logic
    UpdatePhysics(delta_time);
    UpdateInput();
    Render();
    
    // Periodic comprehensive scan (~10ms, every 5 seconds)
    if (frame_count % (60 * 5) == 0) {
        Sentinel::SDK::FullScan();
    }
}
```

**Shutdown**:
```cpp
// Called on game exit (even on crash if possible)
Sentinel::SDK::Shutdown();
```

**Pause/Resume** (optional):
```cpp
// When game is paused (menu, alt-tab)
Sentinel::SDK::Pause();  // Stops background scans, reduces CPU

// When game resumes
Sentinel::SDK::Resume();  // Restarts monitoring
```

---

### Telemetry Flow

**What Gets Sent**:
1. **Violation Events**: When SDK detects anomaly (debugger, hook, injection)
2. **Heartbeat Pings**: Periodic "still alive" signal with basic stats
3. **Crash Reports**: Stack traces on unexpected termination (if enabled)

**Violation Event Structure**:
```cpp
struct ViolationEvent {
    ViolationType type;        // e.g., AntiDebug, AntiHook, Injection
    Severity severity;         // Info, Warning, Critical
    uint64_t timestamp;        // UTC milliseconds
    const char* module_name;   // Which DLL/module involved
    const char* details;       // Human-readable description
    uint64_t address;          // Memory address (if applicable)
};
```

**Network Protocol**:
- Transport: HTTPS (TLS 1.3)
- Format: JSON
- Compression: gzip (optional)
- Authentication: HMAC-SHA256 signature with license key
- Rate Limiting: Max 10 events/second per client

**Example Telemetry Payload**:
```json
{
  "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "game_id": "sentinelflappy3d",
  "timestamp": 1704326400000,
  "event_type": "violation",
  "severity": "critical",
  "violation_type": "anti_debug",
  "details": "IsDebuggerPresent returned true",
  "module": "game.exe",
  "address": "0x7FF6A0001234"
}
```

---

### Heartbeat Monitoring

**Purpose**: Prove game is still running and responsive (not frozen by debugger/speedhack).

**Frequency**: Configurable (default: 5000ms).

**Payload**:
```json
{
  "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "game_id": "sentinelflappy3d",
  "timestamp": 1704326400000,
  "uptime_ms": 125000,
  "frame_count": 7500,
  "sdk_version": "1.0.0",
  "avg_fps": 59.8
}
```

**Server Validation**:
- Check timestamp is within ±10 seconds of server time (prevent replay)
- Validate frame_count increases monotonically
- Validate uptime_ms matches previous heartbeat + interval (detect speedhack)
- If heartbeat stops: session marked as "disconnected" (not banned, just suspicious)

---

### Error Handling

**Philosophy**: Game must **never crash** due to SDK errors.

**Patterns**:

1. **Initialization Failure**: Log error, continue in degraded mode
   ```cpp
   if (!InitializeSentinel()) {
       log("Running without anti-cheat protection");
       // Game still playable
   }
   ```

2. **Update/Scan Failure**: Log warning, skip this frame
   ```cpp
   ErrorCode result = Update();
   if (result != Success) {
       log("SDK update failed: {}", result);
       // Don't crash, just skip protection this frame
   }
   ```

3. **Network Failure**: Queue telemetry, retry later
   ```cpp
   if (!SendTelemetry(event)) {
       telemetry_queue.push(event);  // Retry on next heartbeat
   }
   ```

---

### Graceful Degradation

**Scenarios**:

1. **Server Unreachable**: 
   - SDK continues local detection
   - Telemetry queued locally (up to 1MB)
   - Game logs warning but continues

2. **License Expired**:
   - SDK logs error but doesn't block game launch
   - Studio choice: allow gameplay or show warning modal

3. **Unsupported OS**:
   - Initialize() returns `SystemNotSupported`
   - Game runs without protection

4. **Performance Impact**:
   - If Update() takes >5ms for 10 consecutive frames:
   - SDK automatically reduces scan frequency
   - Log performance warning

---

## 6. Minimal Server Component

### Purpose

The server component demonstrates **server-side validation**—the critical second layer of defense that complements client-side detection.

**This server does NOT**:
- Ban players (logging only)
- Implement EAC/BattlEye-style kernel drivers
- Deploy machine learning models
- Store player data long-term

**This server DOES**:
- Receive telemetry and heartbeat from game clients
- Validate heartbeat timing (detect speedhacks)
- Log all events for manual inspection
- Track active sessions
- Demonstrate graceful failure handling

---

### What the Server Does

#### 1. Receives Telemetry

**Endpoint**: `POST /api/v1/telemetry`

**Request**:
```json
{
  "session_id": "uuid",
  "game_id": "sentinelflappy3d",
  "timestamp": 1704326400000,
  "event_type": "violation",
  "severity": "critical",
  "details": "IsDebuggerPresent returned true"
}
```

**Response**:
```json
{
  "status": "ok",
  "action": "log"
}
```

**Server Action**:
- Parse JSON payload
- Validate HMAC signature (prevent spoofing)
- Log event to file: `/var/log/sentinel/telemetry.log`
- Update session state (last_seen timestamp)
- **No banning logic**—just logging

---

#### 2. Validates Heartbeat

**Endpoint**: `POST /api/v1/heartbeat`

**Request**:
```json
{
  "session_id": "uuid",
  "timestamp": 1704326400000,
  "uptime_ms": 125000,
  "frame_count": 7500
}
```

**Server Validation**:

1. **Timestamp Check**:
   ```cpp
   if (abs(server_time - client_timestamp) > 10000) {
       log("Clock desync detected: session {}", session_id);
       // Flag for manual review, don't ban
   }
   ```

2. **Uptime Check**:
   ```cpp
   expected_uptime = previous_uptime + heartbeat_interval;
   if (abs(current_uptime - expected_uptime) > 1000) {
       log("Speedhack suspected: uptime mismatch for session {}", session_id);
       // Flag for manual review
   }
   ```

3. **Frame Count Check**:
   ```cpp
   expected_frames = (uptime_ms / 1000.0) * 60;  // Assuming 60 FPS
   if (abs(frame_count - expected_frames) > 600) {  // ±10 seconds of frames
       log("Frame rate anomaly: session {}", session_id);
   }
   ```

**Response**:
```json
{
  "status": "ok",
  "next_heartbeat_ms": 5000
}
```

---

#### 3. Logs Data

**Log Format** (JSON Lines):
```json
{"timestamp": "2026-01-03T12:34:56Z", "session": "uuid", "type": "telemetry", "severity": "critical", "details": "..."}
{"timestamp": "2026-01-03T12:35:01Z", "session": "uuid", "type": "heartbeat", "uptime": 125000, "frames": 7500}
```

**Log Rotation**:
- Daily rotation (logrotate on Linux)
- Keep last 30 days
- Compress old logs (gzip)

**Log Analysis**:
- Manual inspection: `grep "severity: critical" telemetry.log`
- Automated alerts: If >10 critical violations/hour from same IP, send email

---

#### 4. Simulates Enforcement (Log Only)

**Example**:
```cpp
if (violation_count > 10) {
    log("ENFORCEMENT: Session {} would be banned in production", session_id);
    log("Reason: {} violations in {} minutes", violation_count, elapsed_minutes);
    // In production: add to ban list, terminate session
    // In demo: just log the decision
}
```

---

### Server Architecture

**Technology**: C++ with cpp-httplib (header-only HTTP server)

**Why cpp-httplib**:
- Single-header library (no dependencies)
- Same language as game and SDK (consistency)
- Sufficient for demo purposes

**Alternative** (for production): Node.js + Express, Python + Flask, Go + Gin

**Components**:

1. **HTTP Server** (`main.cpp`):
   - Listens on port 8080
   - Routes: `/api/v1/telemetry`, `/api/v1/heartbeat`
   - Responds to OPTIONS (CORS preflight)

2. **TelemetryHandler** (`TelemetryHandler.cpp`):
   - Parses JSON payloads
   - Validates HMAC signatures
   - Logs events to file

3. **HeartbeatValidator** (`HeartbeatValidator.cpp`):
   - Tracks session state (last heartbeat time, uptime, frame count)
   - Detects anomalies (speedhack, clock desync)
   - Flags suspicious sessions

4. **SessionManager** (`SessionManager.cpp`):
   - Maps session_id → SessionState
   - Cleans up stale sessions (no heartbeat for 60 seconds)
   - Thread-safe (mutex-protected)

---

## 7. Testing & Validation Plan

### Unit Tests

**Framework**: Google Test (gtest)

**Coverage**:

1. **Game Logic Tests** (`GameLogicTests.cpp`):
   - Player physics (gravity, flap velocity)
   - Collision detection (bird vs pipe, bird vs ground)
   - Scoring (increment on pipe pass)
   - Game state transitions (playing → game_over)

2. **Sentinel Integration Tests** (`SentinelIntegrationTests.cpp`):
   - SDK initialization with valid/invalid license
   - Update() called before Initialize() (should fail gracefully)
   - Shutdown() without Initialize() (should not crash)
   - Violation callback invocation
   - Protected value creation/read/write
   - Memory protection integrity checks

3. **Network Tests** (`NetworkTests.cpp`):
   - Telemetry POST succeeds when server is up
   - Heartbeat POST succeeds when server is up
   - Graceful failure when server is down
   - Retry logic (exponential backoff)
   - HMAC signature validation

**Commands**:
```bash
cd build
ctest --output-on-failure -R GameLogicTests
ctest --output-on-failure -R SentinelIntegrationTests
ctest --output-on-failure -R NetworkTests
```

---

### Integration Tests

**Scenarios**:

1. **Full Game Loop Test**:
   - Start game, play for 60 seconds, verify no crashes
   - SDK Update() called 3600 times (60 FPS × 60 sec)
   - FullScan() called 12 times (every 5 seconds)
   - No memory leaks (Valgrind clean)

2. **Server Communication Test**:
   - Start server in background
   - Start game, play for 30 seconds
   - Verify server received 6 heartbeats (every 5 seconds)
   - Verify server logs show session_id matches game

3. **Pause/Resume Test**:
   - Start game, play for 10 seconds
   - Pause game (ESC), wait 5 seconds
   - Resume game, play for 10 seconds
   - Verify SDK paused during pause state
   - Verify heartbeat continues (game is paused, not crashed)

---

### Failure Injection

**Purpose**: Verify graceful degradation under adverse conditions.

**Tests**:

1. **Network Failure**:
   - Start game with server unreachable
   - Verify game runs normally
   - Verify SDK logs connection errors but doesn't crash
   - Verify telemetry is queued locally

2. **Invalid License**:
   - Initialize SDK with expired license
   - Verify Initialize() returns `InvalidLicense`
   - Verify game continues in degraded mode
   - Verify user sees warning (optional UI)

3. **High CPU Load**:
   - Run CPU stress tool in background (stress-ng)
   - Start game, verify maintains 60 FPS
   - Verify SDK Update() time stays <1ms

4. **High Memory Pressure**:
   - Run memory hog tool (allocate 90% of RAM)
   - Start game, verify no OOM crashes
   - Verify SDK gracefully handles allocation failures

---

### Expected Outcomes

**Success Metrics**:

| Test | Expected Result | Failure Threshold |
|------|-----------------|-------------------|
| Unit Tests | All pass | Any failure |
| Integration Tests | All pass | Any crash or hang |
| Memory Leaks | 0 bytes leaked | >1KB leaked |
| CPU Usage | <5% overhead | >10% overhead |
| Frame Rate | 60 FPS stable | <55 FPS average |
| Network Failure | Game continues | Game crashes |
| Invalid License | Degraded mode | Game blocks launch |

**Performance Baseline**:
- Game without SDK: 60 FPS, 0.16ms per frame
- Game with SDK: 60 FPS, 0.66ms per frame (~0.5ms SDK overhead)
- FullScan(): ~10ms (measured, acceptable if infrequent)

---

## 8. What This Demo Proves to Studios

### Concrete Demonstrations

1. **Ease of Integration**:
   - **Proof**: Main.cpp shows 8-line initialization
   - **Proof**: SentinelIntegration.cpp is <200 lines total
   - **Proof**: CMake integration is 3 lines (`find_package`, `target_link_libraries`)
   - **Takeaway**: "If this indie game can do it in 200 lines, we can do it too"

2. **Low Performance Impact**:
   - **Proof**: Benchmarks show ~0.5ms overhead per frame
   - **Proof**: Game maintains 60 FPS with SDK active
   - **Proof**: FullScan() is 10ms but only every 5 seconds (0.2% of time)
   - **Takeaway**: "SDK won't hurt our frame rate budget"

3. **Transparency**:
   - **Proof**: All SDK activity logged to file
   - **Proof**: Violation callback shows exactly what SDK detected
   - **Proof**: Telemetry payloads are JSON (human-readable)
   - **Takeaway**: "We can debug SDK issues ourselves, not a black box"

4. **Observability**:
   - **Proof**: Server logs show all telemetry and heartbeat events
   - **Proof**: Session tracking shows when clients disconnect
   - **Proof**: Timing anomalies are flagged in real-time
   - **Takeaway**: "We can monitor SDK health in production"

5. **Realistic Production Flow**:
   - **Proof**: Client sends telemetry over HTTPS
   - **Proof**: Server validates heartbeat timing (speedhack detection)
   - **Proof**: Graceful degradation when network fails
   - **Proof**: No crashes even with invalid config
   - **Takeaway**: "This SDK is battle-tested for production edge cases"

---

### Qualitative Benefits

1. **Confidence**: Studios see SDK works in a real game (not just unit tests)
2. **Education**: Source code teaches SDK best practices (error handling, lifecycle)
3. **Template**: Studios can fork SentinelFlappy3D as a starting point
4. **Trust**: Transparent implementation builds confidence (no malware, no spyware)
5. **Support**: Documented integration reduces support tickets

---

## 9. What This Demo Intentionally Does NOT Cover

### Out of Scope

1. **Kernel-Mode Protection**:
   - No driver installation
   - No hypervisor detection
   - No hardware attestation
   - **Reason**: Sentinel is user-mode only (by design)

2. **Advanced Cheat Techniques**:
   - No anti-anti-cheat bypass demonstrations
   - No reverse engineering tutorials
   - No exploit development
   - **Reason**: This is a reference implementation, not a security research project

3. **Production-Scale Infrastructure**:
   - No load balancing (single-server demo)
   - No database (logs to file)
   - No auto-banning (logging only)
   - **Reason**: This is a demo, not a SaaS platform

4. **Competitive Game Design**:
   - No ranked matchmaking
   - No leaderboards
   - No economy (no in-game purchases)
   - **Reason**: Focus is SDK integration, not game design

5. **Multi-Platform Support**:
   - No mobile (Android/iOS)
   - No consoles (PS5/Xbox)
   - No web (WebAssembly)
   - **Reason**: Sentinel SDK targets Windows/Linux desktop games

6. **Advanced Anti-Cheat Features**:
   - No machine learning correlation
   - No behavioral analysis
   - No delayed ban waves
   - **Reason**: These are server-side features beyond SDK scope

---

### Explicitly NOT Included

- **Anti-Debug Bypass Techniques**: We show SDK has anti-debug, not how to bypass it
- **Kernel-Mode Injection**: Out of scope (user-mode SDK cannot detect)
- **Hypervisor Cheats**: Out of scope (Sentinel doesn't claim to detect these)
- **Network Packet Encryption Details**: We use HTTPS, but don't explain TLS internals
- **Server-Side Machine Learning**: Logging only, no ML models
- **Ban Enforcement Logic**: Intentionally left as "log only" for demo

---

## 10. Execution Checklist

### Pre-Development

- [ ] Review Sentinel SDK documentation (docs/integration/)
- [ ] Verify build environment (C++20 compiler, CMake 3.21+, OpenGL drivers)
- [ ] Install dependencies (GLFW, GLM, OpenSSL)
- [ ] Clone or download Sentinel SDK to sentinel/ directory

### Development Phase

#### Week 1: Game Implementation

- [ ] **Day 1**: Set up CMake project, GLFW window, OpenGL context
- [ ] **Day 2**: Implement Player class (gravity, flap, collision box)
- [ ] **Day 3**: Implement Obstacle class (pipe generation, scrolling)
- [ ] **Day 4**: Implement Physics class (collision detection, scoring)
- [ ] **Day 5**: Implement Renderer class (shaders, textures, draw calls)
- [ ] **Day 6-7**: Polish gameplay, test on Windows and Linux

#### Week 2: Sentinel Integration

- [ ] **Day 1**: Integrate SDK into CMake build system
- [ ] **Day 2**: Implement SentinelIntegration wrapper class
- [ ] **Day 3**: Add SDK initialization in main(), test error handling
- [ ] **Day 4**: Configure telemetry and heartbeat
- [ ] **Day 5**: Implement violation callback, test logging
- [ ] **Day 6-7**: Test graceful degradation (network down, invalid license)

#### Week 3: Server Component

- [ ] **Day 1**: Implement HTTP server with cpp-httplib
- [ ] **Day 2**: Implement TelemetryHandler (parse, validate, log)
- [ ] **Day 3**: Implement HeartbeatValidator (timing checks)
- [ ] **Day 4**: Implement SessionManager (track active clients)
- [ ] **Day 5**: Test server communication (game → server)
- [ ] **Day 6-7**: Test server under load (100 concurrent clients)

#### Week 4: Testing & Documentation

- [ ] **Day 1**: Write unit tests (GameLogicTests)
- [ ] **Day 2**: Write integration tests (SentinelIntegrationTests)
- [ ] **Day 3**: Write network tests (NetworkTests)
- [ ] **Day 4**: Write failure injection tests
- [ ] **Day 5**: Write documentation (INTEGRATION_GUIDE.md, BUILDING.md)
- [ ] **Day 6**: Set up CI (GitHub Actions)
- [ ] **Day 7**: Final polish, release v1.0.0

---

### Testing Checklist

#### Functional Tests

- [ ] Game builds on Windows (MSVC 2019+)
- [ ] Game builds on Linux (GCC 11+)
- [ ] Game runs at 60 FPS without SDK
- [ ] Game runs at 60 FPS with SDK
- [ ] SDK initializes successfully with valid license
- [ ] SDK fails gracefully with invalid license
- [ ] Violation callback fires on test event
- [ ] Telemetry is logged to file
- [ ] Heartbeat is sent every 5 seconds
- [ ] Server receives telemetry and heartbeat
- [ ] Server validates heartbeat timing
- [ ] Game continues when server is unreachable

#### Non-Functional Tests

- [ ] No memory leaks (Valgrind clean)
- [ ] No AddressSanitizer errors
- [ ] No ThreadSanitizer errors
- [ ] Code coverage >80%
- [ ] All compiler warnings fixed
- [ ] Documentation complete (INTEGRATION_GUIDE, API docs)

---

### Deployment Checklist

- [ ] Create binary releases (Windows x64, Linux x64)
- [ ] Upload releases to GitHub Releases
- [ ] Update README with download links
- [ ] Create demo video (YouTube, 3-5 minutes)
- [ ] Publish blog post ("How We Integrated Sentinel in 4 Hours")
- [ ] Share with studios (email campaign, Twitter, Reddit)
- [ ] Monitor for issues (GitHub Issues, support tickets)

---

### Studio Onboarding Checklist

When a studio wants to integrate Sentinel using this demo as reference:

- [ ] Studio downloads SentinelFlappy3D source code
- [ ] Studio builds and runs the game (verify it works)
- [ ] Studio reviews SentinelIntegration.cpp (8-line init pattern)
- [ ] Studio copies SDK initialization code to their game
- [ ] Studio configures license key and game ID
- [ ] Studio tests in their game (verify SDK initializes)
- [ ] Studio configures telemetry endpoint (their server)
- [ ] Studio deploys server component (or uses Sentinel SaaS)
- [ ] Studio runs integration tests
- [ ] Studio deploys to production (with monitoring)

**Estimated Time**: 4 hours for experienced developer, 8 hours for first-time integrator.

---

## Appendix A: Technology Stack Links

### Core Technologies

- **OpenGL**: https://www.opengl.org/
- **GLFW**: https://www.glfw.org/
- **GLM**: https://github.com/g-truc/glm
- **stb_image**: https://github.com/nothings/stb

### Build Tools

- **CMake**: https://cmake.org/
- **Ninja**: https://ninja-build.org/
- **MSVC**: https://visualstudio.microsoft.com/
- **GCC**: https://gcc.gnu.org/

### Testing Tools

- **Google Test**: https://github.com/google/googletest
- **Valgrind**: https://valgrind.org/
- **AddressSanitizer**: https://clang.llvm.org/docs/AddressSanitizer.html

### Server Technologies

- **cpp-httplib**: https://github.com/yhirose/cpp-httplib
- **nlohmann/json**: https://github.com/nlohmann/json

### CI/CD

- **GitHub Actions**: https://docs.github.com/en/actions

---

## Appendix B: Estimated Effort

### Development Time

| Phase | Days | FTE |
|-------|------|-----|
| Game Implementation | 7 | 1 |
| SDK Integration | 7 | 1 |
| Server Component | 7 | 1 |
| Testing & Docs | 7 | 1 |
| **Total** | **28** | **1** |

**Assumptions**:
- Developer familiar with C++ and OpenGL
- SDK already built and available
- No scope creep (pure integration demo)

### Studio Integration Time

| Task | Time |
|------|------|
| Review SentinelFlappy3D | 30 min |
| Copy SDK init code | 15 min |
| Configure license key | 5 min |
| Test in their game | 1 hour |
| Deploy server (or use SaaS) | 2 hours |
| **Total** | **4 hours** |

---

## Appendix C: FAQ

### Q: Why not Unity or Unreal?

**A**: Those engines abstract away game loop details. Studios need to see raw SDK integration without engine magic. Also, licensing complexity for demo distribution.

### Q: Why Flappy Bird and not a shooter/MOBA?

**A**: Flappy Bird is:
- Simple enough to implement in 1 week
- Complex enough to have physics, collision, scoring
- Playable (fun for 30 seconds, which is all we need)
- Genre-neutral (not tied to competitive gaming)

### Q: Why not show how Sentinel detects cheats?

**A**: This is a reference implementation, not a security tutorial. Studios don't need to understand detection internals—they need to see clean integration.

### Q: Why no banning logic in server?

**A**: Banning policy is game-specific (instant vs delayed, hardware ID vs account). We show data flow and timing validation—enforcement logic is left to studios.

### Q: Why OpenGL and not Vulkan/DirectX?

**A**: OpenGL is simplest for cross-platform. Vulkan/DX12 add 10x code complexity without demonstrating anything new about SDK integration.

### Q: Can I use this as a game template?

**A**: Yes! SentinelFlappy3D is MIT licensed (game code). Sentinel SDK is proprietary but freely available for evaluation.

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-03 | Initial plan |

---

**END OF DOCUMENT**
