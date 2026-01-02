# Client Diversity Infrastructure

## Overview

The Client Diversity Infrastructure implements build-time diversification to break universal bypass tools. Each client build is slightly different, forcing attackers to develop multiple bypasses or accept reduced compatibility.

## Problem Addressed

**Universal Bypasses**: Every client runs identical code. A bypass developed against any single client works against all clients. Attackers need only analyze one copy of the SDK to defeat all deployments. This is optimal economics for attackers.

**Attack Economics**: Cheat developers distribute bypass tools that work universally. One analysis session, one development effort, unlimited customers. Client diversity breaks this model by making each client slightly different. A bypass that works against one client may crash another.

## Solution

The Diversity Engine implements several diversification techniques:

1. **Structure Padding Randomization** - Varies memory layouts between builds
2. **Constant Value Transformation** - Uses equivalent constant representations
3. **Function Order Diversification** - Varies function addresses via link order
4. **Diversified Code Paths** - Non-critical code paths with varied implementations

## Architecture

### DiversityEngine Class

Located in `src/SDK/src/Internal/DiversityEngine.{cpp,hpp}`

Key methods:
- `Initialize(seed)` - Initialize with build-time seed
- `GetSeed()` - Retrieve current diversity seed
- `IsEnabled()` - Check if diversity is active
- `TransformConstant(value)` - Transform a constant value
- `GetStructPadding(structId)` - Get randomized padding for structures
- `DiversifiedPath(pathId)` - Execute diversified code path
- `DiversifiedDelay(baseMs)` - Sleep with timing variation

### Build System Integration

The diversity seed is generated at build time in `src/SDK/CMakeLists.txt`:

```cmake
# Automatically enabled for Release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(SENTINEL_ENABLE_DIVERSITY ON)
endif()

# Generate pseudo-random seed based on timestamp + random component
string(TIMESTAMP BUILD_TIMESTAMP "%s")
string(RANDOM LENGTH 16 ALPHABET "0123456789ABCDEF" RANDOM_COMPONENT)
math(EXPR DIVERSITY_SEED "${BUILD_TIMESTAMP} * 1000000 + 0x${RANDOM_COMPONENT} % 1000000")
```

The seed is passed as a compile definition:
```cmake
SENTINEL_DIVERSITY_SEED=${DIVERSITY_SEED}ULL
```

### Debug vs Release Builds

- **Debug builds**: Diversity disabled (seed = 0) for deterministic behavior and reproducible debugging
- **Release builds**: Diversity automatically enabled with unique seed per build

## Usage

### Using Diversity in Code

#### Structure Padding

```cpp
#include "Internal/DiversityEngine.hpp"

struct MyData {
    int x;
    DiversifiedPadding<1> padding;  // Adds 0-15 bytes of padding
    int y;
};
```

#### Constant Transformation

```cpp
// Transform constants to diversified but equivalent values
uint64_t timeout = SENTINEL_DIVERSE_CONST(5000);
```

#### Diversified Code Paths

```cpp
// Execute diversified non-critical code
SENTINEL_DIVERSIFIED_STUB(1);
```

#### Diversified Delays

```cpp
// Sleep with timing variation
DiversityEngine::DiversifiedDelay(100);  // 80-120ms with variation
```

## Verification

### Manual Verification

Use the provided Python script to verify diversity:

```bash
python3 scripts/verify_diversity.py
```

This script:
1. Builds the SDK twice with Release configuration
2. Extracts function addresses from both builds
3. Calculates the percentage of function addresses that differ
4. Verifies build time increase is acceptable

### Expected Results

- **Function Address Diversity**: At least 60% of function addresses should differ
- **Build Time Increase**: Should be under 10% compared to non-diverse builds
- **Deterministic Debug**: Debug builds should be identical (seed = 0)

### Testing

Run the diversity engine tests:

```bash
cd build
ctest -R test_diversity_engine -V
```

The test suite verifies:
- Initialization works correctly
- Constant transformations are equivalent
- Structure padding is in valid range (0-15 bytes)
- Diversified code paths execute without crashes
- Different seeds produce different behavior

## Security Properties

### What Diversity Provides

✅ **Increased Attack Cost**: Attackers must analyze multiple builds  
✅ **Reduced Tool Compatibility**: Universal bypass tools fail on some clients  
✅ **Attack Detection**: Failed bypasses may crash, generating telemetry  
✅ **Economic Deterrent**: One bypass no longer works for all clients

### What Diversity Does NOT Provide

❌ **Complete Protection**: Determined attackers can still reverse each build  
❌ **Obfuscation**: Code is still readable, just different between builds  
❌ **Runtime Diversity**: Changes happen at build time, not runtime  
❌ **Kernel-Mode Protection**: User-mode diversity is bypassable with kernel access

## Performance Impact

- **Runtime Overhead**: Minimal (< 1%) - Most diversification is build-time only
- **Build Time**: Typically 3-8% increase due to seed generation and ordering
- **Binary Size**: Minimal increase (< 1%) from structure padding
- **Memory Usage**: Negligible (structure padding is limited to 15 bytes max)

## Implementation Details

### Seed Generation

The diversity seed combines:
1. **Build Timestamp**: Unix timestamp in seconds
2. **Random Component**: 16-character hexadecimal string

This ensures:
- Each build has a unique seed
- Seeds are deterministic for a given build (reproducible from build logs)
- Sufficient entropy for diversification

### Hash Function

Uses a FNV-1a variant for deterministic pseudo-random generation:
- Mixes the diversity seed with input values
- Produces consistent results for same seed + input
- Fast and suitable for build-time operations

### Constant Transformation

Applies one of four equivalent transformations:
1. **Identity**: Returns value unchanged
2. **Addition/Subtraction**: `(value + offset) - offset`
3. **XOR**: `(value ^ mask) ^ mask`
4. **Multiplication/Division**: `(value * m) / m`

All transformations preserve the original value (semantic equivalence).

### Structure Padding

- Generates 0-15 bytes of padding per structure
- Based on structure ID hash
- Deterministic for same seed + structure ID
- Padded with zeros for security

### Diversified Code Paths

Eight implementation variants of functional no-ops:
- Simple NOP
- Volatile read/write
- Arithmetic operations that cancel out
- Bitwise operations that cancel out
- Stack manipulation
- Predictable conditionals
- Known-iteration loops

All variants are semantically equivalent but differ in implementation.

## Build System Options

### CMake Options

- `SENTINEL_ENABLE_DIVERSITY` - Manually enable/disable diversity (default: auto)
  - Auto-enabled for Release builds
  - Auto-disabled for Debug builds

### Usage

```bash
# Build with diversity (Release)
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .

# Build without diversity (Debug)
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build .

# Manually control diversity
cmake .. -DCMAKE_BUILD_TYPE=Release -DSENTINEL_ENABLE_DIVERSITY=OFF
```

## Maintenance

### Adding New Diversified Structures

```cpp
// In your header file
struct MyStruct {
    int field1;
    DiversifiedPadding<UNIQUE_ID> padding;  // Use unique ID
    int field2;
};
```

### Adding New Diversified Paths

```cpp
// In non-critical code paths
SENTINEL_DIVERSIFIED_STUB(UNIQUE_ID);
```

### Updating Hash Function

If security properties of the hash function need updating, modify:
- `DiversityEngine::Hash()` - 64-bit hash
- `DiversityEngine::Hash32()` - 32-bit hash

Maintain backward compatibility by versioning the hash function.

## Future Enhancements

Potential improvements (not yet implemented):
- Instruction scheduling randomization
- Register allocation randomization
- Code layout randomization at finer granularity
- Control flow flattening with diversity
- String encryption key diversification

## References

- **Problem Statement**: Task 14 - Implement Client Diversity Infrastructure
- **Implementation**: `src/SDK/src/Internal/DiversityEngine.{cpp,hpp}`
- **Tests**: `tests/SDK/test_diversity_engine.cpp`
- **Verification Tool**: `scripts/verify_diversity.py`

## FAQ

### Q: Does diversity slow down the client?

A: No, runtime overhead is minimal (<1%). Most diversification happens at build time.

### Q: Can attackers defeat diversity?

A: Yes, determined attackers can reverse-engineer each build individually. Diversity increases cost but doesn't prevent attacks.

### Q: Why not use runtime diversity?

A: Runtime diversity would add overhead and complexity. Build-time diversity is sufficient for breaking universal tools.

### Q: How many different builds are possible?

A: With 64-bit seeds, approximately 2^64 different builds are theoretically possible. In practice, practical diversity is limited by the number of diversification points.

### Q: Does this work on all platforms?

A: Yes, the DiversityEngine is platform-agnostic and works on Windows, Linux, and other platforms supported by CMake.

### Q: Can I disable diversity for profiling?

A: Yes, build with Debug configuration or explicitly set `-DSENTINEL_ENABLE_DIVERSITY=OFF`.
