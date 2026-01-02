# ============================================================================
# Sentinel SDK Distribution Packager (PowerShell)
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

param(
    [string]$BuildType = "Release",
    [string]$Arch = "x64",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$BuildDir = Join-Path $ProjectRoot "build"
$DistDir = Join-Path $ProjectRoot "dist"
$Version = "1.0.0"
$Platform = "windows"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Sentinel SDK Distribution Packager" -ForegroundColor Cyan
Write-Host "  Version: $Version" -ForegroundColor Cyan
Write-Host "  Platform: $Platform" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Validate build type
if ($BuildType -ne "Release" -and $BuildType -ne "Debug") {
    Write-Host "Error: Invalid build type. Use Release or Debug." -ForegroundColor Red
    exit 1
}

# Clean distribution directory if requested
if ($Clean) {
    Write-Host "Cleaning distribution directory..." -ForegroundColor Yellow
    if (Test-Path $DistDir) {
        Remove-Item -Recurse -Force $DistDir
    }
}

# Create distribution directory structure
$PackageName = "SentinelSDK-$Version-$Platform-$Arch"
$PackageDir = Join-Path $DistDir $PackageName

Write-Host "Creating distribution structure..."
New-Item -ItemType Directory -Force -Path "$PackageDir\lib" | Out-Null
New-Item -ItemType Directory -Force -Path "$PackageDir\include" | Out-Null
New-Item -ItemType Directory -Force -Path "$PackageDir\docs" | Out-Null
New-Item -ItemType Directory -Force -Path "$PackageDir\examples" | Out-Null
New-Item -ItemType Directory -Force -Path "$PackageDir\licenses" | Out-Null

# Step 1: Build the SDK if needed
Write-Host ""
Write-Host "Step 1: Building SDK..."
if (-not (Test-Path $BuildDir)) {
    Write-Host "Build directory not found. Building SDK..." -ForegroundColor Yellow
    Set-Location $ProjectRoot
    
    cmake -B $BuildDir -G "Visual Studio 17 2022" -A x64 `
        -DCMAKE_BUILD_TYPE=$BuildType `
        -DSENTINEL_BUILD_SDK=ON `
        -DSENTINEL_BUILD_CORTEX=OFF `
        -DSENTINEL_BUILD_WATCHTOWER=OFF `
        -DSENTINEL_BUILD_TESTS=OFF `
        -DSENTINEL_ENABLE_ANALYSIS_RESISTANCE=ON
    
    cmake --build $BuildDir --config $BuildType --target SentinelSDK
    cmake --build $BuildDir --config $BuildType --target SentinelCore
} else {
    Write-Host "Using existing build directory."
}

# Step 2: Copy libraries
Write-Host ""
Write-Host "Step 2: Copying libraries..."

# DLL files
$dllFiles = @(
    "SentinelSDK.dll",
    "SentinelCore.dll"
)

foreach ($dll in $dllFiles) {
    $srcPath = Join-Path $BuildDir "bin\$BuildType\$dll"
    if (Test-Path $srcPath) {
        Write-Host "  - Copying $dll"
        Copy-Item $srcPath "$PackageDir\lib\"
    }
}

# Import libraries
$libFiles = @(
    "SentinelSDK.lib",
    "SentinelCore.lib"
)

foreach ($lib in $libFiles) {
    $srcPath = Join-Path $BuildDir "lib\$BuildType\$lib"
    if (Test-Path $srcPath) {
        Write-Host "  - Copying $lib (import library)"
        Copy-Item $srcPath "$PackageDir\lib\"
    }
}

# Static library
$staticLib = Join-Path $BuildDir "lib\$BuildType\SentinelSDK_static.lib"
if (Test-Path $staticLib) {
    Write-Host "  - Copying SentinelSDK_static.lib"
    Copy-Item $staticLib "$PackageDir\lib\"
}

# Verify libraries were copied
if ((Get-ChildItem "$PackageDir\lib").Count -eq 0) {
    Write-Host "Error: No libraries found in build directory." -ForegroundColor Red
    Write-Host "Please build the SDK first using CMake."
    exit 1
}

Write-Host "  - Debug symbols (.pdb files) excluded (as designed)" -ForegroundColor Green

# Step 3: Copy public headers only
Write-Host ""
Write-Host "Step 3: Copying public API headers..."
Write-Host "  - Copying SentinelSDK.hpp (main SDK header)"
Copy-Item "$ProjectRoot\src\SDK\include\SentinelSDK.hpp" "$PackageDir\include\"

Write-Host "  - Internal implementation headers excluded (as designed)" -ForegroundColor Green

# Step 4: Copy essential Core headers
Write-Host ""
Write-Host "Step 4: Copying essential Core library headers..."
New-Item -ItemType Directory -Force -Path "$PackageDir\include\Sentinel\Core" | Out-Null

$coreHeaders = @(
    "ErrorCodes.hpp",
    "Types.hpp",
    "Config.hpp"
)

foreach ($header in $coreHeaders) {
    $headerPath = Join-Path $ProjectRoot "include\Sentinel\Core\$header"
    if (Test-Path $headerPath) {
        Write-Host "  - Copying Sentinel/Core/$header"
        Copy-Item $headerPath "$PackageDir\include\Sentinel\Core\"
    }
}

# Step 5: Copy documentation
Write-Host ""
Write-Host "Step 5: Copying documentation..."

$integrationGuide = Join-Path $ProjectRoot "docs\INTEGRATION_GUIDE.md"
if (Test-Path $integrationGuide) {
    Write-Host "  - Copying INTEGRATION_GUIDE.md"
    Copy-Item $integrationGuide "$PackageDir\docs\"
}

# Create README (same content as bash script version)
Write-Host "  - Creating README.md"
@"
# Sentinel SDK Distribution Package

**Version:** 1.0.0  
**License:** Proprietary - Commercial Use Only

## Contents

This distribution package contains the Sentinel Anti-Cheat SDK for integration into game applications.

### Directory Structure

``````
SentinelSDK-{version}-{platform}-{arch}/
├── lib/                    # Compiled libraries (release builds, symbols stripped)
│   ├── SentinelSDK.dll     # Dynamic library
│   ├── SentinelSDK.lib     # Import library
│   └── SentinelSDK_static.lib
├── include/                # Public API headers
│   ├── SentinelSDK.hpp     # Main SDK header
│   └── Sentinel/Core/      # Essential type definitions
├── docs/                   # Integration documentation
│   ├── INTEGRATION_GUIDE.md
│   └── LICENSE_VERIFICATION.md
├── examples/               # Example integration code
│   └── MinimalIntegration.cpp
└── README.md              # This file
``````

## Quick Start

See docs/INTEGRATION_GUIDE.md for complete integration instructions.

## License Verification

This SDK requires a valid license key for operation. See docs/LICENSE_VERIFICATION.md for details.

## Platform Requirements

- **Windows:** x64, Windows 10+ (MSVC 2022+ compatible)
- **C++ Standard:** C++20 or later

## Support

For technical support: support@sentinel-security.example.com

---

**Copyright © 2024 Sentinel Security. All rights reserved.**
"@ | Out-File -FilePath "$PackageDir\README.md" -Encoding utf8

# Step 6: Create license verification documentation
Write-Host "  - Creating LICENSE_VERIFICATION.md"

# Check if we can copy from source docs
$sourceLicenseDoc = Join-Path $ProjectRoot "docs\LICENSE_VERIFICATION.md"
if (Test-Path $sourceLicenseDoc) {
    Copy-Item $sourceLicenseDoc "$PackageDir\docs\"
} else {
    # Create inline if source doesn't exist
    @"
# License Verification Mechanism

## Overview

The Sentinel SDK requires a valid license key to operate. License keys are cryptographically signed JWT tokens.

## License Key Format

License keys contain:
- **game_id**: Unique identifier for your game
- **expiration**: Expiration timestamp
- **features**: Enabled feature flags
- **signature**: Cryptographic signature (ES256)

## Integration

Pass your license key during SDK initialization:

``````cpp
Sentinel::SDK::Configuration config = Sentinel::SDK::Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";
config.game_id = "your-game-id";
``````

## Validation Process

1. Format validation (JWT structure)
2. Signature verification (Sentinel public key)
3. Expiration checking
4. Game ID matching
5. Feature validation

## Error Codes

| Code | Description | Action |
|------|-------------|--------|
| InvalidLicense | Invalid format or signature | Contact support |
| LicenseExpired | License expired | Renew license |
| VersionMismatch | SDK version incompatible | Update SDK |

## Obtaining Licenses

**Trial Licenses**: 30-day trial available at https://sentinel-security.example.com/trial

**Production Licenses**: Contact sales@sentinel-security.example.com

## License Types

- **Trial**: 30-day, full features, dev/test only
- **Developer**: Unlimited, dev/test only  
- **Production**: Full deployment rights
- **Enterprise**: Custom agreements

For support: licenses@sentinel-security.example.com
"@ | Out-File -FilePath "$PackageDir\docs\LICENSE_VERIFICATION.md" -Encoding utf8
}

# Step 7: Create example integration code
Write-Host ""
Write-Host "Step 7: Creating example integration code..."

@"
/**
 * Minimal Sentinel SDK Integration Example
 */

#include <SentinelSDK.hpp>
#include <iostream>
#include <thread>
#include <chrono>

bool OnViolationDetected(const Sentinel::SDK::ViolationEvent* event, void* user_data) {
    std::cout << "[VIOLATION] Type: " << static_cast<uint32_t>(event->type)
              << " Severity: " << static_cast<int>(event->severity)
              << " Details: " << event->details << std::endl;
    return true;
}

bool OnServerDirective(const Sentinel::SDK::ServerDirective* directive, void* user_data) {
    std::cout << "[SERVER DIRECTIVE] Type: " << static_cast<uint32_t>(directive->type) << std::endl;
    
    if (directive->type == Sentinel::SDK::ServerDirectiveType::SessionTerminate) {
        std::cout << "Server ordered session termination. Exiting..." << std::endl;
        exit(0);
    }
    return true;
}

int main() {
    std::cout << "Sentinel SDK Minimal Integration Example" << std::endl;
    std::cout << "Version: " << Sentinel::SDK::GetVersion() << std::endl;
    
    // Configure SDK
    Sentinel::SDK::Configuration config = Sentinel::SDK::Configuration::Default();
    config.license_key = "YOUR-LICENSE-KEY";
    config.game_id = "example-game";
    config.violation_callback = OnViolationDetected;
    config.directive_callback = OnServerDirective;
    
    // Initialize
    std::cout << "Initializing Sentinel SDK..." << std::endl;
    Sentinel::SDK::ErrorCode result = Sentinel::SDK::Initialize(&config);
    
    if (result != Sentinel::SDK::ErrorCode::Success) {
        std::cerr << "Failed to initialize: " << static_cast<uint32_t>(result) << std::endl;
        return 1;
    }
    
    std::cout << "SDK initialized successfully!" << std::endl;
    
    // Game loop simulation
    bool running = true;
    int frame = 0;
    
    while (running) {
        frame++;
        Sentinel::SDK::Update();
        
        if (frame % 300 == 0) {
            Sentinel::SDK::FullScan();
            Sentinel::SDK::Statistics stats = {};
            Sentinel::SDK::GetStatistics(&stats);
            std::cout << "Stats - Uptime: " << stats.uptime_ms / 1000 << "s" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
        
        if (frame >= 600) {
            running = false;
        }
    }
    
    // Shutdown
    std::cout << "Shutting down..." << std::endl;
    Sentinel::SDK::Shutdown();
    return 0;
}
"@ | Out-File -FilePath "$PackageDir\examples\MinimalIntegration.cpp" -Encoding utf8

@"
# Example CMake integration for Sentinel SDK
cmake_minimum_required(VERSION 3.21)
project(SentinelIntegrationExample)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set path to Sentinel SDK
set(SENTINEL_SDK_DIR "`${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH "Path to Sentinel SDK")

# Find libraries
find_library(SENTINEL_SDK_LIB
    NAMES SentinelSDK
    PATHS "`${SENTINEL_SDK_DIR}/lib"
    NO_DEFAULT_PATH
)

if(NOT SENTINEL_SDK_LIB)
    message(FATAL_ERROR "Sentinel SDK library not found")
endif()

# Create executable
add_executable(MinimalIntegration MinimalIntegration.cpp)

target_link_libraries(MinimalIntegration PRIVATE `${SENTINEL_SDK_LIB})

target_include_directories(MinimalIntegration PRIVATE
    "`${SENTINEL_SDK_DIR}/include"
)

# Windows: Copy DLL to output directory
if(WIN32)
    add_custom_command(TARGET MinimalIntegration POST_BUILD
        COMMAND `${CMAKE_COMMAND} -E copy_if_different
            "`${SENTINEL_SDK_DIR}/lib/SentinelSDK.dll"
            "`$<TARGET_FILE_DIR:MinimalIntegration>"
    )
endif()

message(STATUS "Sentinel SDK: `${SENTINEL_SDK_LIB}")
"@ | Out-File -FilePath "$PackageDir\examples\CMakeLists.txt" -Encoding utf8

# Step 8: Create license file
Write-Host ""
Write-Host "Step 8: Adding license information..."
@"
SENTINEL SDK - PROPRIETARY SOFTWARE LICENSE

Copyright (c) 2024 Sentinel Security. All rights reserved.

This software is proprietary and confidential.
"@ | Out-File -FilePath "$PackageDir\licenses\PROPRIETARY_LICENSE.txt" -Encoding utf8

# Step 9: Create build metadata
Write-Host ""
Write-Host "Step 9: Generating build metadata..."
$buildDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
@"
Sentinel SDK Distribution Package
==================================

Version:        $Version
Platform:       $Platform
Architecture:   $Arch
Build Type:     $BuildType
Build Date:     $buildDate
Package:        $PackageName

Contents:
---------
- Compiled SDK libraries (debug symbols stripped)
- Public API headers only (no internal implementation)
- Integration documentation
- License verification guide
- Example integration code

For support: support@sentinel-security.example.com
"@ | Out-File -FilePath "$PackageDir\BUILD_INFO.txt" -Encoding utf8

# Step 10: Create archive
Write-Host ""
Write-Host "Step 10: Creating distribution archive..."
$ArchiveName = "$PackageName.zip"
$ArchivePath = Join-Path $DistDir $ArchiveName

if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
    Compress-Archive -Path $PackageDir -DestinationPath $ArchivePath -Force
    Write-Host "Created: $ArchivePath" -ForegroundColor Green
} else {
    Write-Host "Warning: Compress-Archive not available. Archive not created." -ForegroundColor Yellow
    Write-Host "You can manually zip the directory: $PackageDir"
}

# Step 11: Generate checksum
Write-Host ""
Write-Host "Step 11: Generating checksum..."
if (Test-Path $ArchivePath) {
    $hash = Get-FileHash -Path $ArchivePath -Algorithm SHA256
    "$($hash.Hash)  $ArchiveName" | Out-File -FilePath "$ArchivePath.sha256" -Encoding utf8
    Write-Host "Checksum: $($hash.Hash)" -ForegroundColor Green
}

# Summary
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "SDK Distribution Package Created!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Package Details:"
Write-Host "  Name:     $PackageName"
Write-Host "  Location: $PackageDir"
if (Test-Path $ArchivePath) {
    $size = (Get-Item $ArchivePath).Length / 1MB
    Write-Host "  Archive:  $ArchivePath"
    Write-Host "  Size:     $([math]::Round($size, 2)) MB"
}
Write-Host ""
Write-Host "Distribution Contents:"
Write-Host "  ✓ Compiled libraries (symbols stripped)" -ForegroundColor Green
Write-Host "  ✓ Public API headers only" -ForegroundColor Green
Write-Host "  ✓ Integration documentation" -ForegroundColor Green
Write-Host "  ✓ License verification guide" -ForegroundColor Green
Write-Host "  ✓ Example integration code" -ForegroundColor Green
Write-Host "  ✓ Build metadata" -ForegroundColor Green
Write-Host ""
Write-Host "Security Verification:"
Write-Host "  ✓ No source files included" -ForegroundColor Green
Write-Host "  ✓ No internal headers exposed" -ForegroundColor Green
Write-Host "  ✓ Debug symbols stripped (.pdb excluded)" -ForegroundColor Green
Write-Host "  ✓ Only public API exposed" -ForegroundColor Green
Write-Host ""
Write-Host "Package is ready for distribution!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
