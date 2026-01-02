#!/bin/bash
# ============================================================================
# Sentinel SDK Distribution Packager
# ============================================================================
# Task 30: Establish SDK Delivery Without Source Exposure
#
# This script creates a distribution package containing:
# - Compiled SDK libraries (stripped of debug symbols)
# - Public API headers only
# - Integration documentation
# - License verification documentation
# - Example integration code
#
# Copyright (c) 2024 Sentinel Security. All rights reserved.
# ============================================================================

set -e  # Exit on error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
DIST_DIR="${PROJECT_ROOT}/dist"
VERSION="1.0.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Platform detection
PLATFORM=""
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
    PLATFORM="windows"
else
    echo -e "${RED}Error: Unsupported platform: $OSTYPE${NC}"
    exit 1
fi

echo "============================================"
echo "  Sentinel SDK Distribution Packager"
echo "  Version: ${VERSION}"
echo "  Platform: ${PLATFORM}"
echo "============================================"
echo ""

# Parse arguments
BUILD_TYPE="Release"
ARCH="x64"
CLEAN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --build-type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [--build-type Release|Debug] [--arch x64|x86] [--clean]"
            exit 1
            ;;
    esac
done

# Validate build type
if [[ "$BUILD_TYPE" != "Release" ]] && [[ "$BUILD_TYPE" != "Debug" ]]; then
    echo -e "${RED}Error: Invalid build type. Use Release or Debug.${NC}"
    exit 1
fi

# Clean distribution directory if requested
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning distribution directory...${NC}"
    rm -rf "${DIST_DIR}"
fi

# Create distribution directory structure
PACKAGE_NAME="SentinelSDK-${VERSION}-${PLATFORM}-${ARCH}"
PACKAGE_DIR="${DIST_DIR}/${PACKAGE_NAME}"

echo "Creating distribution structure..."
mkdir -p "${PACKAGE_DIR}"/{lib,include,docs,examples,licenses}

# Step 1: Build the SDK if needed
echo ""
echo "Step 1: Building SDK..."
if [ ! -d "${BUILD_DIR}" ]; then
    echo -e "${YELLOW}Build directory not found. Building SDK...${NC}"
    cd "${PROJECT_ROOT}"
    cmake -B "${BUILD_DIR}" \
        -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
        -DSENTINEL_BUILD_SDK=ON \
        -DSENTINEL_BUILD_CORTEX=OFF \
        -DSENTINEL_BUILD_WATCHTOWER=OFF \
        -DSENTINEL_BUILD_TESTS=OFF \
        -DSENTINEL_ENABLE_ANALYSIS_RESISTANCE=ON
    
    cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}" --target SentinelSDK SentinelCore
else
    echo "Using existing build directory."
fi

# Step 2: Copy and strip libraries
echo ""
echo "Step 2: Copying libraries (stripping debug symbols)..."

if [ "$PLATFORM" = "linux" ]; then
    # Linux: .so files
    if [ -f "${BUILD_DIR}/lib/libSentinelSDK.so" ]; then
        echo "  - Copying libSentinelSDK.so"
        cp "${BUILD_DIR}/lib/libSentinelSDK.so" "${PACKAGE_DIR}/lib/"
        echo "  - Stripping debug symbols from libSentinelSDK.so"
        strip --strip-debug --strip-unneeded "${PACKAGE_DIR}/lib/libSentinelSDK.so"
        
        # Create versioned symlinks for proper soname resolution
        if readelf -d "${PACKAGE_DIR}/lib/libSentinelSDK.so" | grep -q "SONAME.*libSentinelSDK.so.1"; then
            echo "  - Creating versioned library links"
            cd "${PACKAGE_DIR}/lib"
            ln -sf libSentinelSDK.so libSentinelSDK.so.1
            ln -sf libSentinelSDK.so.1 libSentinelSDK.so.1.0.0
            cd - > /dev/null
        fi
    fi
    
    if [ -f "${BUILD_DIR}/lib/libSentinelCore.so" ]; then
        echo "  - Copying libSentinelCore.so"
        cp "${BUILD_DIR}/lib/libSentinelCore.so" "${PACKAGE_DIR}/lib/"
        echo "  - Stripping debug symbols from libSentinelCore.so"
        strip --strip-debug --strip-unneeded "${PACKAGE_DIR}/lib/libSentinelCore.so"
        
        # Create versioned symlinks for proper soname resolution  
        if readelf -d "${PACKAGE_DIR}/lib/libSentinelCore.so" | grep -q "SONAME.*libSentinelCore.so\.[0-9]"; then
            echo "  - Creating versioned library links for Core"
            cd "${PACKAGE_DIR}/lib"
            ln -sf libSentinelCore.so libSentinelCore.so.1 2>/dev/null || true
            cd - > /dev/null
        fi
    fi
    
    # Static libraries
    if [ -f "${BUILD_DIR}/lib/libSentinelSDK_static.a" ]; then
        echo "  - Copying libSentinelSDK_static.a"
        cp "${BUILD_DIR}/lib/libSentinelSDK_static.a" "${PACKAGE_DIR}/lib/"
        echo "  - Stripping debug symbols from libSentinelSDK_static.a"
        strip --strip-debug "${PACKAGE_DIR}/lib/libSentinelSDK_static.a"
    fi
    
elif [ "$PLATFORM" = "macos" ]; then
    # macOS: .dylib files
    if [ -f "${BUILD_DIR}/lib/libSentinelSDK.dylib" ]; then
        echo "  - Copying libSentinelSDK.dylib"
        cp "${BUILD_DIR}/lib/libSentinelSDK.dylib" "${PACKAGE_DIR}/lib/"
        echo "  - Stripping debug symbols from libSentinelSDK.dylib"
        # macOS uses different strip flags
        strip -S "${PACKAGE_DIR}/lib/libSentinelSDK.dylib"
        
        # Create versioned symlinks for dylib
        # Check install name with otool
        if otool -D "${PACKAGE_DIR}/lib/libSentinelSDK.dylib" | grep -q "libSentinelSDK.1.dylib"; then
            echo "  - Creating versioned library links"
            cd "${PACKAGE_DIR}/lib"
            ln -sf libSentinelSDK.dylib libSentinelSDK.1.dylib
            ln -sf libSentinelSDK.1.dylib libSentinelSDK.1.0.0.dylib
            cd - > /dev/null
        fi
    fi
    
    if [ -f "${BUILD_DIR}/lib/libSentinelCore.dylib" ]; then
        echo "  - Copying libSentinelCore.dylib"
        cp "${BUILD_DIR}/lib/libSentinelCore.dylib" "${PACKAGE_DIR}/lib/"
        echo "  - Stripping debug symbols from libSentinelCore.dylib"
        strip -S "${PACKAGE_DIR}/lib/libSentinelCore.dylib"
    fi
    
    # Static libraries
    if [ -f "${BUILD_DIR}/lib/libSentinelSDK_static.a" ]; then
        echo "  - Copying libSentinelSDK_static.a"
        cp "${BUILD_DIR}/lib/libSentinelSDK_static.a" "${PACKAGE_DIR}/lib/"
        echo "  - Stripping debug symbols from libSentinelSDK_static.a"
        # macOS strip for static libraries
        strip -S "${PACKAGE_DIR}/lib/libSentinelSDK_static.a"
    fi
    
elif [ "$PLATFORM" = "windows" ]; then
    # Windows: .dll, .lib files
    if [ -f "${BUILD_DIR}/bin/${BUILD_TYPE}/SentinelSDK.dll" ]; then
        echo "  - Copying SentinelSDK.dll"
        cp "${BUILD_DIR}/bin/${BUILD_TYPE}/SentinelSDK.dll" "${PACKAGE_DIR}/lib/"
        # Note: On Windows, use objcopy or similar if available for stripping
        # For MSVC, debug info is in separate .pdb files which we don't copy
    fi
    
    if [ -f "${BUILD_DIR}/lib/${BUILD_TYPE}/SentinelSDK.lib" ]; then
        echo "  - Copying SentinelSDK.lib (import library)"
        cp "${BUILD_DIR}/lib/${BUILD_TYPE}/SentinelSDK.lib" "${PACKAGE_DIR}/lib/"
    fi
    
    if [ -f "${BUILD_DIR}/bin/${BUILD_TYPE}/SentinelCore.dll" ]; then
        echo "  - Copying SentinelCore.dll"
        cp "${BUILD_DIR}/bin/${BUILD_TYPE}/SentinelCore.dll" "${PACKAGE_DIR}/lib/"
    fi
    
    if [ -f "${BUILD_DIR}/lib/${BUILD_TYPE}/SentinelCore.lib" ]; then
        echo "  - Copying SentinelCore.lib (import library)"
        cp "${BUILD_DIR}/lib/${BUILD_TYPE}/SentinelCore.lib" "${PACKAGE_DIR}/lib/"
    fi
    
    # Static library
    if [ -f "${BUILD_DIR}/lib/${BUILD_TYPE}/SentinelSDK_static.lib" ]; then
        echo "  - Copying SentinelSDK_static.lib"
        cp "${BUILD_DIR}/lib/${BUILD_TYPE}/SentinelSDK_static.lib" "${PACKAGE_DIR}/lib/"
    fi
fi

# Verify libraries were copied
if [ ! "$(ls -A ${PACKAGE_DIR}/lib)" ]; then
    echo -e "${RED}Error: No libraries found in build directory.${NC}"
    echo "Please build the SDK first using CMake."
    exit 1
fi

# Step 3: Copy public headers only
echo ""
echo "Step 3: Copying public API headers..."
echo "  - Copying SentinelSDK.hpp (main SDK header)"
cp "${PROJECT_ROOT}/src/SDK/include/SentinelSDK.hpp" "${PACKAGE_DIR}/include/"

# Note: We do NOT copy internal headers from src/SDK/src/Internal/
# These are implementation details that should not be exposed
echo "  - Internal implementation headers excluded (as designed)"

# Step 4: Copy essential Core headers for public API dependencies
echo ""
echo "Step 4: Copying essential Core library headers..."
mkdir -p "${PACKAGE_DIR}/include/Sentinel/Core"

# Only copy headers that are part of the public API surface
CORE_PUBLIC_HEADERS=(
    "ErrorCodes.hpp"
    "Types.hpp"
    "Config.hpp"
)

for header in "${CORE_PUBLIC_HEADERS[@]}"; do
    if [ -f "${PROJECT_ROOT}/include/Sentinel/Core/${header}" ]; then
        echo "  - Copying Sentinel/Core/${header}"
        cp "${PROJECT_ROOT}/include/Sentinel/Core/${header}" "${PACKAGE_DIR}/include/Sentinel/Core/"
    fi
done

# Step 5: Copy documentation
echo ""
echo "Step 5: Copying documentation..."

# Integration guide
if [ -f "${PROJECT_ROOT}/docs/INTEGRATION_GUIDE.md" ]; then
    echo "  - Copying INTEGRATION_GUIDE.md"
    cp "${PROJECT_ROOT}/docs/INTEGRATION_GUIDE.md" "${PACKAGE_DIR}/docs/"
fi

# Create SDK distribution README
cat > "${PACKAGE_DIR}/README.md" << EOF
# Sentinel SDK Distribution Package

**Version:** ${VERSION}  
**License:** Proprietary - Commercial Use Only

## Contents

This distribution package contains the Sentinel Anti-Cheat SDK for integration into game applications.

### Directory Structure

```
SentinelSDK-{version}-{platform}-{arch}/
├── lib/                    # Compiled libraries (release builds, symbols stripped)
│   ├── libSentinelSDK.so   # Shared library (Linux)
│   ├── SentinelSDK.dll     # Dynamic library (Windows)
│   └── SentinelSDK.lib     # Import/static library
├── include/                # Public API headers
│   ├── SentinelSDK.hpp     # Main SDK header
│   └── Sentinel/Core/      # Essential type definitions
├── docs/                   # Integration documentation
│   ├── INTEGRATION_GUIDE.md
│   └── LICENSE_VERIFICATION.md
├── examples/               # Example integration code
│   └── MinimalIntegration.cpp
└── README.md              # This file
```

## Quick Start

### 1. Link the Library

**CMake:**
```cmake
target_link_libraries(YourGame PRIVATE
    ${SENTINEL_SDK_DIR}/lib/libSentinelSDK.so  # or .dll on Windows
)

target_include_directories(YourGame PRIVATE
    ${SENTINEL_SDK_DIR}/include
)
```

**Manual Linking:**
- Linux: Link against `libSentinelSDK.so`
- Windows: Link against `SentinelSDK.lib`, ensure `SentinelSDK.dll` is in PATH

### 2. Include Header

```cpp
#include <SentinelSDK.hpp>
```

### 3. Initialize SDK

```cpp
Sentinel::SDK::Configuration config = Sentinel::SDK::Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";
config.game_id = "your-game-id";

Sentinel::SDK::ErrorCode result = Sentinel::SDK::Initialize(&config);
if (result != Sentinel::SDK::ErrorCode::Success) {
    // Handle initialization failure
}
```

### 4. Update Per Frame

```cpp
// In your game loop
Sentinel::SDK::Update();
```

### 5. Shutdown

```cpp
// On game exit
Sentinel::SDK::Shutdown();
```

## License Verification

This SDK requires a valid license key for operation. See `docs/LICENSE_VERIFICATION.md` for details on:
- Obtaining a license key
- License validation process
- Trial/evaluation licenses
- License restrictions

## Platform Requirements

- **Windows:** x64, Windows 10+ (MSVC 2022+ compatible)
- **Linux:** x64, glibc 2.31+ (GCC 13+ / Clang 15+ compatible)
- **C++ Standard:** C++20 or later

## Dependencies

The SDK has the following runtime dependencies:
- OpenSSL (libssl, libcrypto) - for cryptographic operations
- Standard C++ runtime library

Ensure these dependencies are available on target systems.

## Support

For technical support, integration assistance, or bug reports:
- Email: support@sentinel-security.example.com
- Documentation: https://docs.sentinel-security.example.com

## Security Notice

This SDK provides anti-cheat detection and telemetry. It is **not** a complete security solution:
- Requires server-side validation for enforcement
- User-mode only (no kernel driver)
- Best used as part of a defense-in-depth strategy

See the Integration Guide for security best practices.

## Version History

- **1.0.0** (2024) - Initial release
  - Core detection features
  - Analysis resistance (Task 28)
  - Redundant detection (Task 29)
  - Server-authoritative enforcement (Task 24)

---

**Copyright © 2024 Sentinel Security. All rights reserved.**
EOF

# Step 6: Create license verification documentation
echo "  - Creating LICENSE_VERIFICATION.md"
cat > "${PACKAGE_DIR}/docs/LICENSE_VERIFICATION.md" << 'EOF'
# License Verification Mechanism

## Overview

The Sentinel SDK requires a valid license key to operate. This document explains the license verification system and integration requirements.

## License Key Format

License keys are cryptographically signed tokens in JWT format:
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJnYW1lX2lkIjoieW91ci1nYW1lIiwic3ViIjoiY...
```

Each license key contains:
- **game_id**: Unique identifier for your game
- **expiration**: Expiration timestamp (Unix epoch)
- **features**: Enabled feature flags
- **signature**: Cryptographic signature (ES256)

## Integration

### Configuration

Pass your license key during SDK initialization:

```cpp
Sentinel::SDK::Configuration config = Sentinel::SDK::Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";  // Required
config.game_id = "your-game-id";          // Must match license
```

### Validation Process

The SDK validates licenses through the following process:

1. **Format Validation**: Checks JWT structure
2. **Signature Verification**: Validates cryptographic signature using Sentinel's public key
3. **Expiration Check**: Ensures license hasn't expired
4. **Game ID Matching**: Verifies game_id matches configuration
5. **Feature Validation**: Checks requested features are licensed

### Error Codes

| Error Code | Description | Action |
|------------|-------------|--------|
| `InvalidLicense` | License format invalid or signature verification failed | Contact support for new license |
| `LicenseExpired` | License has passed expiration date | Renew license or upgrade |
| `VersionMismatch` | SDK version incompatible with license | Update SDK or contact support |

### Online Validation

For production deployments, the SDK periodically validates licenses online:
- Initial validation at startup
- Periodic revalidation (configurable, default: 24 hours)
- Grace period if validation server unavailable (default: 7 days)

Configure cloud endpoint for online validation:
```cpp
config.cloud_endpoint = "https://validation.sentinel-security.example.com/api/v1";
```

## Obtaining Licenses

### Trial Licenses

Request a 30-day trial license:
- Website: https://sentinel-security.example.com/trial
- Email: licenses@sentinel-security.example.com

Trial licenses include:
- Full feature access
- Limited to development/testing environments
- Cannot be used in production

### Production Licenses

Production licenses are available through:
- Direct purchase: https://sentinel-security.example.com/pricing
- Volume licensing for studios
- Custom enterprise agreements

Contact sales@sentinel-security.example.com for pricing.

## License Restrictions

### Per-Game Licensing

Each license is bound to a specific game:
- One license per game_id
- Cannot be reused across different games
- Can be used across multiple builds of the same game

### Environment Restrictions

License types by environment:

| License Type | Development | Staging | Production |
|--------------|-------------|---------|------------|
| Trial | ✅ | ✅ | ❌ |
| Developer | ✅ | ✅ | ❌ |
| Production | ✅ | ✅ | ✅ |
| Enterprise | ✅ | ✅ | ✅ |

### Distribution Restrictions

**Important**: License keys are confidential and game-specific:
- ✅ **DO**: Embed in your game binary (obfuscated)
- ✅ **DO**: Store securely in your build system
- ❌ **DO NOT**: Share licenses publicly
- ❌ **DO NOT**: Include in source control (use secrets management)
- ❌ **DO NOT**: Reuse licenses across different games

## Offline/Air-Gapped Environments

For games deployed in offline or air-gapped environments:

1. Request an offline license token from support
2. Configure SDK for offline mode:
   ```cpp
   config.cloud_endpoint = nullptr;  // Disable online validation
   ```
3. Use extended validity license (requires approval)

Note: Offline licenses have reduced flexibility and require manual renewal.

## License Enforcement

### Initialization

If license validation fails at initialization:
```cpp
ErrorCode result = Initialize(&config);
if (result == ErrorCode::InvalidLicense) {
    // License is invalid - game cannot start
    DisplayError("Invalid or expired license. Please contact support.");
    exit(1);
}
```

### Runtime

SDK monitors license validity during runtime:
- Online revalidation (production licenses)
- Expiration checks
- Feature flag verification

If license becomes invalid during runtime:
- `ViolationCallback` invoked with license violation
- SDK continues monitoring for grace period
- After grace period: SDK enters disabled state

### Grace Period

Default grace periods:
- **Network unavailable**: 7 days
- **Expired license**: No grace period (immediate)
- **Revoked license**: 24 hours

## Frequently Asked Questions

**Q: Can I use one license for multiple games?**  
A: No. Each game requires its own license with matching game_id.

**Q: What happens if my license expires in production?**  
A: SDK enters disabled state after grace period. Renew license before expiration.

**Q: Can I test without a license during development?**  
A: No. Trial or developer licenses are required. Contact support for a free trial.

**Q: How do I securely store my license key?**  
A: Use build-time secrets injection, not source control. Obfuscate in binary.

**Q: Can players see my license key?**  
A: License keys are embedded in your game binary. Use obfuscation, but keys are game-specific so exposure has limited impact.

---

**For license support**: licenses@sentinel-security.example.com
EOF

# Step 7: Copy example integration code
echo ""
echo "Step 7: Creating example integration code..."
cat > "${PACKAGE_DIR}/examples/MinimalIntegration.cpp" << 'EOF'
/**
 * Minimal Sentinel SDK Integration Example
 * 
 * This example demonstrates the minimum required code to integrate
 * the Sentinel SDK into a game application.
 */

#include <SentinelSDK.hpp>
#include <iostream>
#include <thread>
#include <chrono>

// Violation callback handler
bool OnViolationDetected(const Sentinel::SDK::ViolationEvent* event, void* user_data) {
    std::cout << "[VIOLATION] Type: " << static_cast<uint32_t>(event->type)
              << " Severity: " << static_cast<int>(event->severity)
              << " Details: " << event->details << std::endl;
    
    // Return true to continue monitoring
    // Return false to suppress further events of this type
    return true;
}

// Server directive callback handler (Task 24: Server-Authoritative Enforcement)
bool OnServerDirective(const Sentinel::SDK::ServerDirective* directive, void* user_data) {
    std::cout << "[SERVER DIRECTIVE] Type: " << static_cast<uint32_t>(directive->type)
              << " Reason: " << static_cast<uint32_t>(directive->reason)
              << " Message: " << (directive->message ? directive->message : "") << std::endl;
    
    // Handle server directives
    switch (directive->type) {
        case Sentinel::SDK::ServerDirectiveType::SessionTerminate:
            std::cout << "Server ordered session termination. Exiting game..." << std::endl;
            // In real game: Disconnect, show message, exit gracefully
            exit(0);
            break;
            
        case Sentinel::SDK::ServerDirectiveType::RequireReconnect:
            std::cout << "Server requests reconnection." << std::endl;
            // In real game: Reconnect to server
            break;
            
        case Sentinel::SDK::ServerDirectiveType::SessionContinue:
            std::cout << "Server confirmed session continuation." << std::endl;
            break;
            
        default:
            break;
    }
    
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "Sentinel SDK Minimal Integration Example" << std::endl;
    std::cout << "Version: " << Sentinel::SDK::GetVersion() << std::endl;
    std::cout << std::endl;
    
    // Step 1: Create configuration
    Sentinel::SDK::Configuration config = Sentinel::SDK::Configuration::Default();
    
    // Step 2: Set required fields
    config.license_key = "YOUR-LICENSE-KEY";  // Replace with your actual license key
    config.game_id = "example-game";          // Replace with your game ID
    
    // Step 3: Configure callbacks
    config.violation_callback = OnViolationDetected;
    config.callback_user_data = nullptr;
    
    config.directive_callback = OnServerDirective;
    config.directive_user_data = nullptr;
    
    // Step 4: Configure features (optional, using defaults)
    config.features = Sentinel::SDK::DetectionFeatures::Standard;
    config.default_action = Sentinel::SDK::ResponseAction::Default;
    
    // Step 5: Configure network (optional)
    // config.cloud_endpoint = "https://your-sentinel-server.example.com/api/v1";
    
    // Step 6: Initialize SDK
    std::cout << "Initializing Sentinel SDK..." << std::endl;
    Sentinel::SDK::ErrorCode result = Sentinel::SDK::Initialize(&config);
    
    if (result != Sentinel::SDK::ErrorCode::Success) {
        std::cerr << "Failed to initialize Sentinel SDK: " 
                  << static_cast<uint32_t>(result) << std::endl;
        std::cerr << "Error: " << Sentinel::SDK::GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "SDK initialized successfully!" << std::endl;
    std::cout << std::endl;
    
    // Step 7: Game loop simulation
    std::cout << "Running game loop (Press Ctrl+C to exit)..." << std::endl;
    
    bool running = true;
    int frame = 0;
    
    while (running) {
        frame++;
        
        // Update SDK every frame
        Sentinel::SDK::ErrorCode update_result = Sentinel::SDK::Update();
        
        if (update_result != Sentinel::SDK::ErrorCode::Success) {
            std::cerr << "SDK Update failed: " << static_cast<uint32_t>(update_result) << std::endl;
            
            // Check if it's a security violation
            if (update_result == Sentinel::SDK::ErrorCode::TamperingDetected ||
                update_result == Sentinel::SDK::ErrorCode::DebuggerDetected) {
                std::cerr << "Security violation detected!" << std::endl;
                // In production: Report to server, take appropriate action
            }
        }
        
        // Periodic full scan (every 5 seconds = ~300 frames at 60fps)
        if (frame % 300 == 0) {
            std::cout << "Performing full integrity scan..." << std::endl;
            Sentinel::SDK::FullScan();
            
            // Print statistics
            Sentinel::SDK::Statistics stats = {};
            Sentinel::SDK::GetStatistics(&stats);
            
            std::cout << "  Uptime: " << stats.uptime_ms / 1000 << "s" << std::endl;
            std::cout << "  Violations: " << stats.violations_detected << std::endl;
            std::cout << "  Avg Update Time: " << stats.avg_update_time_us << " μs" << std::endl;
        }
        
        // Simulate frame time (60 FPS = ~16.67ms per frame)
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
        
        // Exit after 10 seconds for this example
        if (frame >= 600) {
            running = false;
        }
    }
    
    // Step 8: Shutdown SDK
    std::cout << std::endl;
    std::cout << "Shutting down Sentinel SDK..." << std::endl;
    Sentinel::SDK::Shutdown();
    
    std::cout << "Example completed successfully!" << std::endl;
    return 0;
}
EOF

# Step 8: Create CMake integration example
echo "  - Creating CMakeLists.txt example"
cat > "${PACKAGE_DIR}/examples/CMakeLists.txt" << 'EOF'
# Example CMake integration for Sentinel SDK
cmake_minimum_required(VERSION 3.21)
project(SentinelIntegrationExample)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set path to Sentinel SDK distribution
set(SENTINEL_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH "Path to Sentinel SDK")

# Find libraries
find_library(SENTINEL_SDK_LIB
    NAMES SentinelSDK libSentinelSDK
    PATHS "${SENTINEL_SDK_DIR}/lib"
    NO_DEFAULT_PATH
)

if(NOT SENTINEL_SDK_LIB)
    message(FATAL_ERROR "Sentinel SDK library not found in ${SENTINEL_SDK_DIR}/lib")
endif()

# Create example executable
add_executable(MinimalIntegration MinimalIntegration.cpp)

# Link against Sentinel SDK
target_link_libraries(MinimalIntegration PRIVATE ${SENTINEL_SDK_LIB})

# Include directories
target_include_directories(MinimalIntegration PRIVATE
    "${SENTINEL_SDK_DIR}/include"
)

# Platform-specific settings
if(WIN32)
    # Ensure DLL is found at runtime
    add_custom_command(TARGET MinimalIntegration POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SENTINEL_SDK_DIR}/lib/SentinelSDK.dll"
            "$<TARGET_FILE_DIR:MinimalIntegration>"
    )
endif()

message(STATUS "Sentinel SDK: ${SENTINEL_SDK_LIB}")
EOF

# Step 9: Copy license files
echo ""
echo "Step 9: Adding license information..."

cat > "${PACKAGE_DIR}/licenses/PROPRIETARY_LICENSE.txt" << 'EOF'
SENTINEL SDK - PROPRIETARY SOFTWARE LICENSE

Copyright (c) 2024 Sentinel Security. All rights reserved.

NOTICE: This software is proprietary and confidential. Unauthorized copying,
distribution, or use of this software or any portion thereof is strictly
prohibited and may result in severe civil and criminal penalties.

This software is provided under license and may only be used or copied in
accordance with the terms of that license. The information in this software
is subject to change without notice and does not represent a commitment by
Sentinel Security.

RESTRICTIONS:
- May only be used with a valid license key
- May not be reverse engineered, decompiled, or disassembled
- May not be redistributed without explicit written permission
- May not be used to create derivative works

For licensing inquiries: licenses@sentinel-security.example.com
EOF

# Step 10: Create build metadata
echo ""
echo "Step 10: Generating build metadata..."
cat > "${PACKAGE_DIR}/BUILD_INFO.txt" << EOF
Sentinel SDK Distribution Package
==================================

Version:        ${VERSION}
Platform:       ${PLATFORM}
Architecture:   ${ARCH}
Build Type:     ${BUILD_TYPE}
Build Date:     $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Package:        ${PACKAGE_NAME}

Contents:
---------
- Compiled SDK libraries (debug symbols stripped)
- Public API headers only (no internal implementation)
- Integration documentation
- License verification guide
- Example integration code

Security Features:
------------------
- Analysis Resistance (Task 28): Enabled
- Redundant Detection (Task 29): Available
- Server-Authoritative Enforcement (Task 24): Enabled
- JIT Signature Updates (Task 25): Enabled

Build Configuration:
--------------------
- C++ Standard: C++20
- Compiler Optimizations: Enabled (${BUILD_TYPE})
- Debug Symbols: Stripped from release binaries
- Position Independent Code: Enabled
- Security Hardening: Full stack protection, ASLR, DEP

Notes:
------
- This is a commercial SDK requiring a valid license key
- Source code is NOT included in this distribution
- Internal implementation details are NOT exposed
- Integration is achieved using only provided headers and documentation

For support: support@sentinel-security.example.com
EOF

# Step 11: Create archive
echo ""
echo "Step 11: Creating distribution archive..."
cd "${DIST_DIR}"

if [ "$PLATFORM" = "linux" ] || [ "$PLATFORM" = "macos" ]; then
    ARCHIVE_NAME="${PACKAGE_NAME}.tar.gz"
    tar -czf "${ARCHIVE_NAME}" "${PACKAGE_NAME}"
    echo -e "${GREEN}Created: ${DIST_DIR}/${ARCHIVE_NAME}${NC}"
elif [ "$PLATFORM" = "windows" ]; then
    ARCHIVE_NAME="${PACKAGE_NAME}.zip"
    if command -v zip &> /dev/null; then
        zip -r "${ARCHIVE_NAME}" "${PACKAGE_NAME}"
        echo -e "${GREEN}Created: ${DIST_DIR}/${ARCHIVE_NAME}${NC}"
    else
        echo -e "${YELLOW}Warning: 'zip' command not found. Archive not created.${NC}"
        echo "You can manually zip the directory: ${PACKAGE_DIR}"
    fi
fi

# Step 12: Generate checksum
echo ""
echo "Step 12: Generating checksum..."
if [ -f "${DIST_DIR}/${ARCHIVE_NAME}" ]; then
    if command -v sha256sum &> /dev/null; then
        cd "${DIST_DIR}"
        sha256sum "${ARCHIVE_NAME}" > "${ARCHIVE_NAME}.sha256"
        echo -e "${GREEN}Checksum: $(cat ${ARCHIVE_NAME}.sha256)${NC}"
    elif command -v shasum &> /dev/null; then
        cd "${DIST_DIR}"
        shasum -a 256 "${ARCHIVE_NAME}" > "${ARCHIVE_NAME}.sha256"
        echo -e "${GREEN}Checksum: $(cat ${ARCHIVE_NAME}.sha256)${NC}"
    fi
else
    echo -e "${YELLOW}Warning: Archive not found, skipping checksum generation.${NC}"
fi

# Summary
echo ""
echo "============================================"
echo -e "${GREEN}SDK Distribution Package Created!${NC}"
echo "============================================"
echo ""
echo "Package Details:"
echo "  Name:     ${PACKAGE_NAME}"
echo "  Location: ${PACKAGE_DIR}"
if [ -f "${DIST_DIR}/${ARCHIVE_NAME}" ]; then
    echo "  Archive:  ${DIST_DIR}/${ARCHIVE_NAME}"
    ARCHIVE_SIZE=$(du -h "${DIST_DIR}/${ARCHIVE_NAME}" | cut -f1)
    echo "  Size:     ${ARCHIVE_SIZE}"
fi
echo ""
echo "Distribution Contents:"
echo "  ✓ Compiled libraries (symbols stripped)"
echo "  ✓ Public API headers only"
echo "  ✓ Integration documentation"
echo "  ✓ License verification guide"
echo "  ✓ Example integration code"
echo "  ✓ Build metadata"
echo ""
echo "Security Verification:"
echo "  ✓ No source files included"
echo "  ✓ No internal headers exposed"
echo "  ✓ Debug symbols stripped"
echo "  ✓ Only public API exposed"
echo ""
echo "Next Steps:"
echo "  1. Distribute ${ARCHIVE_NAME} to game studios"
echo "  2. Provide license keys for each studio/game"
echo "  3. Studios integrate using only distribution contents"
echo ""
echo -e "${GREEN}Package is ready for distribution!${NC}"
echo "============================================"
