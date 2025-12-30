# Sentinel SDK - Dummy Game

## Overview

This is **NOT** a cheat testing application. This is a **realistic game application** that integrates the Sentinel-RE SDK to discover real-world integration issues, false positives, and performance problems.

## Red-Team Mindset

The purpose of this dummy game is to answer the question:

> **"If I were an attacker, what real-world conditions would accidentally break or trigger this SDK — without cheating?"**

We're looking for:
- False positives from legitimate gameplay
- Performance degradation under realistic load
- Crashes or stability issues
- Integration mistakes that real developers might make
- SDK behavior under edge conditions (VMs, debuggers, lag spikes, etc.)

## What This Game Tests

### SDK Modules Exercised

✅ **Cryptography:**
- `SecureRandom` - Secure random number generation
- `HashEngine` - SHA-256 hashing
- `AESCipher` - AES-256-GCM encryption/decryption
- `HMAC` - Message authentication codes

✅ **Protection Features:**
- `CreateProtectedInt` / `SetProtectedInt` / `GetProtectedInt` - Protected value storage
- `ProtectMemory` / `VerifyMemory` - Memory integrity checking
- `GetSecureTime` / `ValidateTiming` - Speed hack detection
- `EncryptPacket` / `DecryptPacket` - Packet encryption
- `GetPacketSequence` / `ValidatePacketSequence` - Replay attack prevention

✅ **Detection Systems:**
- `Initialize()` - SDK initialization with custom config
- `Update()` - Per-frame lightweight checks
- `FullScan()` - Periodic comprehensive scans
- `Pause()` / `Resume()` - Monitoring pause/resume
- `GetStatistics()` - Performance metrics

### Test Scenarios

The game automatically exercises the following scenarios:

1. **Normal Gameplay** - 60 FPS game loop with realistic CPU load
2. **Pause/Resume** - Simulated menu pauses every 10 seconds
3. **Lag Spikes** - Intentional 150ms delays every 15 seconds
4. **Heavy CPU Contention** - Extreme CPU load simulation every 20 seconds
5. **Protected Values** - Gold and level stored as protected integers
6. **Memory Protection** - Critical game data under integrity monitoring
7. **Secure Timing** - Speed hack detection via timing validation
8. **Packet Encryption** - Simulated network packet encryption
9. **Long Uptime** - Runs for 30 seconds by default (configurable)

### Detection Systems Exercised

The DummyGame exercises these SDK detection systems:

- ✅ **Anti-Debug** - Periodic checks for debugger presence
- ✅ **Anti-Hook** - Scans for API hooks (inline, IAT, VEH)
- ✅ **Integrity Checking** - Code section hash verification
- ✅ **Injection Detection** - Detects unauthorized DLLs
- ✅ **Speed Hack Detection** - Client-side timing validation (requires server validation)
- ⚠️ **Heartbeat/Cloud Reporting** - Stub implementation only

**Red-Team Note:** All detections are user-mode only and bypassable with kernel-mode access. This is documented as expected behavior.

## Building

### Prerequisites

- CMake 3.21+
- C++20 compatible compiler
- Sentinel SDK built and available

### Option 1: Build as Part of Main Project (Recommended)

From the repository root:

```bash
# Configure
cmake -B build -G "Ninja" \
  -DCMAKE_BUILD_TYPE=Release \
  -DSENTINEL_BUILD_CORTEX=OFF \
  -DSENTINEL_BUILD_WATCHTOWER=OFF \
  -DSENTINEL_BUILD_TESTS=ON

# Build everything (includes DummyGame)
cmake --build build --config Release

# Run DummyGame
./build/bin/DummyGame
```

### Option 2: Build Standalone

If the main project is already built:

```bash
cd examples/DummyGame

# Configure
cmake -B build -G "Ninja" \
  -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release

# Run
./build/DummyGame
```

## Running

### Normal Execution

```bash
./build/bin/DummyGame
```

The game will:
1. Initialize Sentinel SDK
2. Test all crypto components
3. Test all protection features
4. Run a 30-second game loop with realistic scenarios
5. Print statistics every 5 seconds
6. Automatically exit after 30 seconds

### Expected Output

```
============================================
  Sentinel SDK - Dummy Game Test
  Version: 1.0.0
============================================

RED-TEAM MINDSET: Looking for false positives,
performance issues, and integration problems.

[INIT] Initializing Sentinel SDK...
✓ SDK initialized successfully
✓ SDK version: 1.0.0

[PHASE 1] Testing Crypto Components...
[TEST] SecureRandom...
  ✓ Generated 32 random bytes
  ✓ Generated random uint64_t: 1234567890
  ✓ Generated AES-256 key

[TEST] HashEngine...
  ✓ SHA-256 hash computed: a1b2c3d4e5f6...

... (more tests)

[PHASE 3] Starting Game Loop...
Target: 60 FPS (16.67ms per frame)

[GAME STATS]
  Frame: 300
  Health: 100
  Score: 50
  Position: (150.0, 75.0)
  Gold (protected): 1300
  Level (protected): 1

[SDK STATS]
  Uptime: 5000 ms
  Updates: 300
  Scans: 1
  Violations: 0
  Avg Update Time: 45.2 µs
  Avg Scan Time: 2.3 ms
  Protected Regions: 1
  Protected Functions: 0
```

## Testing with Debugger

To test SDK behavior when a debugger is attached:

```bash
# Linux
gdb ./build/bin/DummyGame
(gdb) run

# Expected: SDK should detect debugger and report violation
```

## Testing in VM

To test SDK behavior in virtual machine environments:

```bash
# Run in VM
./build/bin/DummyGame

# Expected: May trigger timing anomaly warnings (this is CORRECT behavior)
```

## Known Expected Behaviors

### ✅ Should NOT Trigger

- **Normal execution** - Should complete without violations
- **Pause/Resume** - Should handle game pauses cleanly
- **Lag spikes** - Should tolerate frame timing variations
- **Protected value access** - Should work transparently

### ⚠️ May Trigger (Document if False Positive)

- **Debugger detection** - Will trigger if GDB/LLDB attached (expected)
- **VM timing anomalies** - May trigger in virtual machines (document if problematic)
- **High CPU contention** - May affect timing validation (document if false positive)

### 🔴 Should NEVER Happen

- **Crashes** - Report immediately if SDK causes crashes
- **Memory leaks** - Monitor memory usage during long runs
- **Deadlocks** - Report if game freezes
- **Data corruption** - Protected values should remain consistent

## Performance Expectations

Based on SDK documentation:

| Operation | Expected Budget | Actual (Measured) |
|-----------|----------------|-------------------|
| `Update()` | < 0.1 ms | TBD (document) |
| `FullScan()` | < 5 ms | TBD (document) |
| Memory overhead | ~2 MB | TBD (document) |

**TODO:** Run the game and fill in actual measurements.

## Red-Team Observations

### Questions to Answer

1. **Does the SDK interfere with legitimate gameplay?**
   - Document any false positives
   - Document any performance issues

2. **What happens under stress?**
   - High CPU load
   - Memory pressure
   - Disk I/O contention

3. **What happens in edge conditions?**
   - VM environments
   - Debugger attached (developer scenario)
   - Overlay software (Discord, Steam, etc.)
   - Background processes

4. **What are the crash paths?**
   - Incorrect initialization
   - Missing Shutdown()
   - Invalid handles
   - Race conditions

5. **What are the user-mode limitations?**
   - What can this SDK NOT detect?
   - What would a kernel-mode attacker bypass trivially?
   - What are the TOCTOU vulnerabilities?

## Integration Mistakes to Document

Common mistakes developers might make:

- [ ] Forgetting to call `Shutdown()`
- [ ] Calling `Update()` from multiple threads
- [ ] Using handles after they're destroyed
- [ ] Not checking `ErrorCode` return values
- [ ] Enabling debug mode in release builds
- [ ] Incorrect callback lifetime management

## Files Generated

- `/tmp/sentinel_dummy_game.log` - SDK debug log (if debug mode enabled)
- Console output with test results

## Troubleshooting

### "SentinelSDK library not found"

Build the main Sentinel project first:

```bash
cd ../..  # Go to repo root
cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### "Violations detected during normal gameplay"

**This is valuable feedback!** Document:
- What was happening when the violation occurred
- Violation type and severity
- Whether it's a false positive
- What the expected behavior should be

### Crashes or Errors

Document:
- Stack trace
- Error messages
- Steps to reproduce
- System configuration (OS, debugger, VM, etc.)

## Next Steps

After running this dummy game:

1. Review console output for violations
2. Check `/tmp/sentinel_dummy_game.log` for debug info
3. Document findings in `/docs/DUMMY_GAME_VALIDATION.md`
4. Update `/docs/INTEGRATION_GUIDE.md` with lessons learned
5. File issues for any bugs or false positives discovered

## Philosophy

> **Better to find problems in testing than in production.**
>
> This dummy game is deliberately designed to stress-test the SDK under realistic conditions. Any violation, crash, or performance issue found here is a success — it means we found it before a real game developer did.

## License

Copyright © 2025 Sentinel Security. All rights reserved.

This example is part of the Sentinel SDK and follows the same license terms.
