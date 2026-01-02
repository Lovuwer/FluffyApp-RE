# SDK Distribution Guide

## Task 30: Establish SDK Delivery Without Source Exposure

This document describes the SDK distribution mechanism that protects intellectual property while providing functional integration capability.

## Distribution Philosophy

The Sentinel SDK is distributed as **compiled libraries and public headers only**:
- ✅ **Included**: Compiled binaries, public API headers, integration documentation
- ❌ **Not Included**: Source code, internal headers, debug symbols
- 🔒 **Protected**: Detection logic remains opaque to integrators

This approach:
1. Prevents source-level understanding of detection mechanisms
2. Enables functional integration without IP exposure
3. Maintains commercial viability of the anti-cheat system
4. Follows industry-standard practices for commercial security SDKs

## Package Contents

### Directory Structure

```
SentinelSDK-{version}-{platform}-{arch}/
├── lib/                           # Compiled libraries
│   ├── SentinelSDK.dll/.so       # Shared library (stripped)
│   ├── SentinelSDK.lib/.a        # Import/static library
│   └── SentinelCore.dll/.so      # Core library dependency
├── include/                       # Public headers only
│   ├── SentinelSDK.hpp           # Main SDK API
│   └── Sentinel/Core/            # Minimal Core type definitions
│       ├── ErrorCodes.hpp
│       ├── Types.hpp
│       └── Config.hpp
├── docs/                          # Documentation
│   ├── INTEGRATION_GUIDE.md      # How to integrate
│   ├── LICENSE_VERIFICATION.md   # License mechanism
│   └── SDK_DISTRIBUTION_GUIDE.md # This file
├── examples/                      # Example code
│   ├── MinimalIntegration.cpp    # Basic integration
│   └── CMakeLists.txt            # Build example
├── licenses/                      # Legal
│   └── PROPRIETARY_LICENSE.txt
└── BUILD_INFO.txt                 # Package metadata
```

### What's Included

✅ **Compiled Libraries (Release Builds)**
- `SentinelSDK.dll` / `libSentinelSDK.so` - Main SDK shared library
- `SentinelCore.dll` / `libSentinelCore.so` - Core utilities library
- `SentinelSDK_static.lib` / `libSentinelSDK_static.a` - Static library variant
- All libraries have debug symbols stripped
- Optimized release builds with security hardening

✅ **Public API Headers**
- `SentinelSDK.hpp` - Complete public API surface
- Essential Core type definitions for API dependencies
- No internal implementation headers
- No exposure of detection logic

✅ **Integration Documentation**
- Integration guide with step-by-step instructions
- License verification mechanism documentation
- Example integration code
- Platform-specific setup instructions

✅ **License Mechanism**
- License key validation (JWT-based)
- Online/offline validation support
- Game-specific licensing
- Trial and production license types

### What's NOT Included

❌ **Source Code**
- No `.cpp` implementation files
- Detection algorithms remain proprietary
- Communication protocols not exposed
- Enforcement logic hidden

❌ **Internal Headers**
- No `src/SDK/src/Internal/*.hpp` files
- No `src/Core/Internal/*.hpp` files
- Implementation details not accessible
- Internal data structures hidden

❌ **Debug Information**
- No `.pdb` files (Windows)
- No debug symbols in binaries (Linux)
- Stripped executables only
- Function names obfuscated where possible

❌ **Build System**
- No CMake build configuration (except examples)
- No compilation instructions
- No internal dependencies exposed
- Pre-compiled only

## Creating Distribution Packages

### Automated Packaging Scripts

Two packaging scripts are provided for different platforms:

#### Linux/macOS: `scripts/package_sdk.sh`

```bash
# Basic usage (defaults to Release build)
./scripts/package_sdk.sh

# Specify build type and architecture
./scripts/package_sdk.sh --build-type Release --arch x64

# Clean previous distributions first
./scripts/package_sdk.sh --clean

# Help
./scripts/package_sdk.sh --help
```

#### Windows: `scripts/package_sdk.ps1`

```powershell
# Basic usage (defaults to Release build)
.\scripts\package_sdk.ps1

# Specify build type and architecture
.\scripts\package_sdk.ps1 -BuildType Release -Arch x64

# Clean previous distributions
.\scripts\package_sdk.ps1 -Clean
```

### Packaging Process

The scripts perform the following steps:

1. **Build Verification**
   - Checks for existing build directory
   - Builds SDK if needed with Release configuration
   - Validates libraries were created

2. **Library Processing**
   - Copies compiled libraries to distribution
   - Strips debug symbols (Linux: `strip --strip-debug`)
   - Excludes `.pdb` files (Windows)
   - Verifies symbol stripping

3. **Header Filtering**
   - Copies only public API header (`SentinelSDK.hpp`)
   - Copies minimal Core type definitions
   - Excludes all internal implementation headers
   - Validates no source exposure

4. **Documentation Packaging**
   - Includes integration guide
   - Includes license verification guide
   - Creates distribution README
   - Adds build metadata

5. **Example Code**
   - Provides minimal integration example
   - Includes CMake build example
   - Demonstrates proper usage
   - No proprietary code exposed

6. **Archive Creation**
   - Creates `.tar.gz` (Linux) or `.zip` (Windows)
   - Generates SHA-256 checksum
   - Names with version/platform/arch
   - Ready for distribution

### Output

After running the packaging script:

```
dist/
├── SentinelSDK-1.0.0-linux-x64/          # Uncompressed package
│   ├── lib/
│   ├── include/
│   ├── docs/
│   ├── examples/
│   └── ...
├── SentinelSDK-1.0.0-linux-x64.tar.gz    # Compressed archive
└── SentinelSDK-1.0.0-linux-x64.tar.gz.sha256  # Checksum
```

## Distribution to Game Studios

### Delivery Process

1. **Package Creation**
   ```bash
   ./scripts/package_sdk.sh --build-type Release --arch x64
   ```

2. **Verification**
   - Verify no source files in package
   - Verify debug symbols stripped
   - Verify only public headers present
   - Test integration with example code

3. **License Issuance**
   - Generate license key for studio/game
   - Configure game_id and features
   - Set expiration date
   - Sign with private key

4. **Delivery**
   - Send package archive to studio
   - Provide license key separately (secure channel)
   - Share integration documentation
   - Offer technical support contact

5. **Studio Integration**
   - Studio downloads/extracts package
   - Follows integration guide
   - Uses only provided headers and libraries
   - Configures license key
   - Tests integration

### Security Considerations

**Package Integrity**
- Always verify SHA-256 checksum
- Use secure delivery channels
- Version packages clearly
- Track distribution to studios

**License Keys**
- Never include in package
- Deliver separately via secure channel
- One key per game/studio
- Rotate keys periodically

**Support Process**
- Provide integration assistance
- Debug issues without exposing source
- Update packages for security fixes
- Maintain backwards compatibility

## Verification Checklist

Before distributing a package, verify:

- [ ] Package created with Release build configuration
- [ ] All libraries present (SentinelSDK, SentinelCore)
- [ ] Debug symbols stripped from all binaries
- [ ] No `.pdb` files included (Windows)
- [ ] Only public header (`SentinelSDK.hpp`) included
- [ ] No internal headers from `src/SDK/src/Internal/`
- [ ] No source files (`.cpp`) included
- [ ] Documentation complete and accurate
- [ ] Example code builds successfully
- [ ] LICENSE file included
- [ ] BUILD_INFO.txt present with metadata
- [ ] Archive created successfully
- [ ] Checksum generated
- [ ] Package tested with example integration

## Testing Distribution Package

### Test Integration (Linux)

```bash
# Extract package
tar -xzf SentinelSDK-1.0.0-linux-x64.tar.gz
cd SentinelSDK-1.0.0-linux-x64

# Build example
cd examples
mkdir build && cd build
cmake .. -DSENTINEL_SDK_DIR=../..
make

# Run example (will fail license validation without key)
./MinimalIntegration
```

### Test Integration (Windows)

```powershell
# Extract package
Expand-Archive SentinelSDK-1.0.0-windows-x64.zip
cd SentinelSDK-1.0.0-windows-x64

# Build example
cd examples
mkdir build
cd build
cmake .. -DSENTINEL_SDK_DIR=..\.. -G "Visual Studio 17 2022"
cmake --build . --config Release

# Run example
.\Release\MinimalIntegration.exe
```

### Verification Points

During test integration, verify:
- ✅ Example builds with only distributed headers
- ✅ Example links against distributed libraries
- ✅ Example runs (license validation expected to fail)
- ✅ No access to internal implementation needed
- ✅ Error messages are helpful
- ✅ Documentation is sufficient

## Updating Distributed Packages

### Version Updates

When releasing new SDK versions:

1. Update version number in:
   - `CMakeLists.txt` (project VERSION)
   - `SentinelSDK.hpp` (SENTINEL_SDK_VERSION_*)
   - Packaging scripts

2. Rebuild and repackage:
   ```bash
   ./scripts/package_sdk.sh --clean --build-type Release
   ```

3. Test new package thoroughly

4. Document changes in release notes

5. Update existing studios if breaking changes

### Security Updates

For security-critical updates:

1. Patch vulnerability in source
2. Build patched version
3. Create emergency distribution package
4. Notify all studios immediately
5. Mandate update with timeline
6. Invalidate old licenses if necessary

## License Mechanism

See `docs/LICENSE_VERIFICATION.md` for complete details on:
- License key format and validation
- Obtaining licenses (trial, production, enterprise)
- Online vs offline validation
- License restrictions and enforcement
- Troubleshooting license issues

## Support and Troubleshooting

### Common Issues

**"License validation failed"**
- Verify license key is correct
- Check game_id matches license
- Ensure license hasn't expired
- Verify network connectivity (online validation)

**"Cannot find SentinelSDK.hpp"**
- Add `include/` directory to include paths
- Verify header exists in package
- Check CMake configuration

**"Undefined reference to Sentinel::SDK functions"**
- Link against libSentinelSDK library
- Ensure library is in linker search path
- Verify library matches architecture (x64/x86)

**"DLL not found" (Windows)**
- Copy DLL to executable directory
- Add DLL directory to PATH
- Use correct build type (Release/Debug)

### Getting Support

For integration assistance:
- **Email**: support@sentinel-security.example.com
- **Documentation**: https://docs.sentinel-security.example.com
- **License Issues**: licenses@sentinel-security.example.com

When reporting issues, provide:
- SDK version (from BUILD_INFO.txt)
- Platform and architecture
- Build error messages
- Integration code snippet
- CMake configuration

## Appendix: Security Architecture

### Why Binary-Only Distribution?

Source code exposure would enable:
- ❌ Complete understanding of detection logic
- ❌ Identification of detection gaps
- ❌ Development of targeted bypasses
- ❌ Reverse engineering of communication protocols
- ❌ Extraction of cryptographic keys/algorithms
- ❌ Analysis of enforcement mechanisms

Binary-only distribution defends against:
- ✅ Source-level analysis (requires reverse engineering)
- ✅ Trivial bypass development
- ✅ Understanding of detection timing
- ✅ Knowledge of detection priorities
- ✅ Exposure of vulnerability mitigations

### Defense in Depth

Binary distribution is ONE layer:
1. **Binary distribution** - This defense (Task 30)
2. **Analysis resistance** - Anti-debug, obfuscation (Task 28)
3. **Signature updates** - JIT detection updates (Task 25)
4. **Server enforcement** - Authority on server (Task 24)
5. **Redundant detection** - Multiple implementations (Task 29)

Together, these create a robust defense against reverse engineering and bypass development.

---

**Copyright © 2024 Sentinel Security. All rights reserved.**
