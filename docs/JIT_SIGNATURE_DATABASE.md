# JIT Signature Database - Maintenance Guide

## Overview

The JIT Signature Database is a critical security feature that prevents module hollowing and spoofing attacks by validating JIT compiler modules using cryptographic hashes instead of module names.

**Attack Vector Addressed:** Attackers can create fake modules with legitimate names (e.g., `clrjit.dll`, `v8.dll`) to bypass detection. The old implementation checked only the module name, which is trivially spoofed.

**Solution:** Hash-based validation of the .text section ensures the actual code matches known-good JIT engines.

## Architecture

### Components

1. **JITSignatureValidator** (`src/SDK/src/Internal/JITSignature.cpp`)
   - Validates memory regions using .text section hashes
   - Cross-references with PE section headers
   - Validates CLR metadata for .NET JIT engines
   - Maintains cache of validated modules

2. **Signature Database** (`JITSignatureValidator::AddBuiltInSignatures()`)
   - Stores SHA-256 hashes of known-good JIT engines
   - Organized by module name and version
   - Indexed by hash for O(1) lookup

3. **Hash Extraction Utility** (`scripts/extract_jit_hashes.py`)
   - Automates hash extraction from DLL files
   - Generates C++ code for easy integration

### Validation Process

```
1. Query memory region → Get allocation base
2. Get module base → Parse PE headers
3. Locate .text section → Read first 4KB
4. Compute SHA-256 hash → Look up in database
5. If .NET: Validate CLR metadata
6. Verify address within JIT heap range
7. Return: whitelisted | suspicious
```

## Adding New JIT Signatures

### Prerequisites

- Windows system with target JIT engines installed
- Python 3.6+ with `pefile` library: `pip install pefile`
- Access to the JIT DLL files

### Step 1: Locate JIT DLLs

Common locations:

**.NET CLR:**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll  (.NET Framework 4.x)
C:\Program Files\dotnet\shared\Microsoft.NETCore.App\6.0.x\clrjit.dll  (.NET 6)
C:\Program Files\dotnet\shared\Microsoft.NETCore.App\7.0.x\clrjit.dll  (.NET 7)
C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.x\clrjit.dll  (.NET 8)
```

**V8 JavaScript (Chromium/Electron):**
```
<electron_app>\v8.dll
<chrome_install>\chrome.dll (embedded V8)
```

**LuaJIT:**
```
<game_directory>\luajit.dll
<game_directory>\lua51.dll, lua52.dll, lua53.dll
```

**Unity IL2CPP:**
```
<unity_game>\GameAssembly.dll
```

### Step 2: Extract Hashes

Run the extraction script for each JIT DLL:

```bash
# .NET 8.0 CLR JIT
python3 scripts/extract_jit_hashes.py \
    "C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.0\clrjit.dll" \
    --version ".NET 8.0" \
    --engine-type DotNetCLR \
    --output signatures/net80_clrjit.cpp

# V8 JavaScript (from Electron app)
python3 scripts/extract_jit_hashes.py \
    "C:\Program Files\MyApp\v8.dll" \
    --version "V8 10.x" \
    --engine-type V8JavaScript \
    --output signatures/v8_10x.cpp

# LuaJIT
python3 scripts/extract_jit_hashes.py \
    "C:\Games\MyGame\luajit.dll" \
    --version "LuaJIT 2.1" \
    --engine-type LuaJIT \
    --output signatures/luajit_21.cpp
```

### Step 3: Integrate Signatures

Copy the generated code into `JITSignature.cpp` in the `AddBuiltInSignatures()` function:

```cpp
void JITSignatureValidator::AddBuiltInSignatures() {
    // .NET 8.0 CLR JIT
    {
        JITSignature sig;
        sig.module_name = L"clrjit.dll";
        sig.engine_type = JITEngineType::DotNetCLR;
        sig.version = L".NET 8.0";
        sig.text_hash = {
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            // ... (32 bytes total)
        };
        AddSignature(sig);
    }
    
    // Add more signatures...
}
```

### Step 4: Test

1. **Build the SDK:**
   ```bash
   cmake --build build --config Release
   ```

2. **Run tests:**
   ```bash
   cd build && ./bin/SDKTests --gtest_filter="InjectionDetectTests.*"
   ```

3. **Test with real application:**
   - Launch an application using the target JIT engine
   - Verify no false positives (legitimate JIT is whitelisted)
   - Verify hollowed modules are detected

## Maintenance Schedule

### When to Update Hashes

1. **New Runtime Versions:** When Microsoft releases new .NET versions
2. **V8 Updates:** When Chromium/Electron versions update
3. **Game Engine Updates:** When Unity or other engines release new versions
4. **User Reports:** When users report false positives

### Update Process

1. Obtain the new JIT DLL
2. Run hash extraction script
3. Add new signature to database
4. Test thoroughly
5. **Keep old signatures:** Old versions may still be in use
6. Document the version in comments

## Security Considerations

### Hash Storage

- Hashes are stored in plaintext in the binary
- This is acceptable because:
  - Hashes are cryptographic - can't reverse to original code
  - Attackers can't forge a matching hash without the exact code
  - Database is read-only at runtime

### Version Coverage

- Maintain signatures for **at least 3 major versions** back
- Example: If .NET 10 is current, support 8, 9, 10
- Remove signatures after 2 years of deprecation

### False Positives

If a legitimate JIT engine is flagged:

1. **Verify the DLL is legitimate** (signed, from official source)
2. **Extract the hash** using the utility
3. **Add to database** following the process above
4. **Document** the specific version/build

### False Negatives

If a hollowed module is not detected:

1. **Verify hash validation is working** (enable debug logs)
2. **Check CLR metadata validation** (for .NET modules)
3. **Verify heap range check** (within 32MB of module)
4. **Review fallback to whitelist** (may override)

## Troubleshooting

### Script Errors

**"No .text section found"**
- The DLL may not be a standard PE file
- Verify it's actually a DLL (not a data file)

**"pefile library not found"**
- Install: `pip install pefile`

**"Permission denied"**
- Run with administrator privileges
- Copy DLL to accessible location

### Runtime Issues

**Legitimate JIT flagged as suspicious:**
1. Enable debug logging to see hash mismatch
2. Extract hash from the actual DLL
3. Compare with database entries
4. Add missing signature

**Hollowed module not detected:**
1. Verify `IsKnownJITRegion()` is being called
2. Check if whitelist override is active
3. Enable verbose logging for validation steps

## Example: Complete Workflow

```bash
# 1. Extract hash from .NET 8.0 CLR JIT
python3 scripts/extract_jit_hashes.py \
    "C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.0\clrjit.dll" \
    --version ".NET 8.0.0" \
    --engine-type DotNetCLR \
    > /tmp/net80_sig.cpp

# 2. Review generated code
cat /tmp/net80_sig.cpp

# 3. Copy into JITSignature.cpp
# ... manual edit ...

# 4. Build
cmake --build build --config Release

# 5. Test with .NET app
./build/bin/SDKTests --gtest_filter="InjectionDetectTests.HollowedJITModuleDetection"

# 6. Verify no false positives
# Launch actual .NET app and check logs
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-01-XX | Initial implementation with placeholder database |
| 1.1.0 | TBD | Populated signatures for .NET 6/7/8, V8, LuaJIT |

## References

- [PE Format Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [.NET Runtime Releases](https://github.com/dotnet/runtime/releases)
- [V8 Version Information](https://v8.dev/docs)
- [Security: Module Hollowing](https://attack.mitre.org/techniques/T1055/011/)
