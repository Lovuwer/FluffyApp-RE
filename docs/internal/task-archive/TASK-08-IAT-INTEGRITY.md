# TASK-08: IAT Integrity Verification Implementation

## Overview

This document describes the implementation of Import Address Table (IAT) integrity verification in the Sentinel SDK. This feature detects IAT hooks that are commonly used to intercept API calls, including hooks on `NtQueryInformationProcess` which can defeat debugger detection.

## Implementation Details

### Files Modified

1. **src/SDK/src/Internal/Detection.hpp**
   - Added `IATEntry` structure to track IAT entries
   - Added `iat_entries_` vector to store baseline IAT state
   - Added `iat_mutex_` for thread-safe access

2. **src/SDK/src/Detection/IntegrityCheck.cpp**
   - Modified `Initialize()` to walk IAT entries for the main module
   - Implemented `VerifyImportTable()` to detect IAT modifications
   - Integrated IAT verification into `QuickCheck()` and `FullScan()`
   - Modified `Shutdown()` to clear IAT entries

3. **tests/SDK/test_integrity.cpp**
   - Added three new test cases for IAT integrity verification
   - Tests verify clean state (no false positives)

### How It Works

#### Initialization (Initialize method)

1. Parse the PE header of the main executable module
2. Locate the import directory in the data directories
3. Iterate through all imported modules
4. For each module:
   - Skip JIT-compiled modules (clrjit.dll) to avoid false positives
   - Walk the Import Address Table (IAT) entries
   - Store each entry with:
     - Module name (e.g., "kernel32.dll")
     - Function name (e.g., "GetProcAddress")
     - Expected address (resolved address at init time)
     - IAT slot address (pointer to the IAT entry)

#### Verification (VerifyImportTable method)

1. Iterate through all stored IAT entries
2. For each entry:
   - Verify the IAT slot is still readable
   - Read the current IAT value
   - Compare against the expected address
   - Return false if any mismatch is found
3. Return true if all entries match

#### Integration

The `VerifyImportTable()` method is called by both:
- `QuickCheck()` - For fast per-frame checks
- `FullScan()` - For comprehensive integrity scans

If IAT modification is detected, a violation event is generated with:
- Type: `ViolationType::IATHook`
- Severity: `Severity::Critical`
- Details: "IAT modification detected"

## Design Decisions

### Main Module Only

The implementation only verifies the IAT of the main executable module, not all loaded DLLs. This is by design to:
- Keep overhead minimal
- Focus on the most critical attack vector
- Avoid false positives from legitimate runtime modifications

### JIT Module Exclusion

The implementation skips modules containing "clrjit" in their name to avoid false positives from .NET JIT compilation. This can be extended to other JIT engines if needed.

### Thread Safety

All access to `iat_entries_` is protected by `iat_mutex_` to ensure thread-safe operation during concurrent checks.

### Fail-Safe Behavior

- If the import directory cannot be read, initialization continues without IAT tracking
- If individual IAT entries cannot be read, they are skipped
- This prevents the feature from causing crashes in edge cases

## Testing

### Unit Tests

Three test cases were added:

1. **TASK08_IATIntegrityCleanState**
   - Verifies no false positives on clean system (QuickCheck)
   
2. **TASK08_IATIntegrityFullScanCleanState**
   - Verifies no false positives on clean system (FullScan)
   
3. **TASK08_IATModificationDetection**
   - Documents how to manually test actual IAT modification detection
   - Note: Automated testing of IAT modifications is unsafe and could crash the test process

### Manual Testing

A manual test program is provided in `tests/SDK/manual_iat_test.cpp`. To use it:

1. Compile on Windows
2. Run the program
3. Observe clean state (no violations)
4. Use a debugger to modify an IAT entry
5. Press Enter to run the check
6. Verify that the IAT modification is detected

Example workflow:
```bash
# Build the manual test
cd build
cmake --build . --target manual_iat_test

# Run on Windows
./bin/manual_iat_test.exe
```

## Performance Impact

- Initialization: O(n) where n is the number of IAT entries (typically <1ms)
- Verification: O(n) memory reads (typically <0.1ms for hundreds of entries)
- Memory overhead: ~50 bytes per IAT entry

## Limitations

1. **Static Analysis Only**: This implementation captures the IAT state at initialization and detects changes. It cannot prevent IAT hooks from being installed before initialization.

2. **No Restoration**: The implementation only detects IAT modifications; it does not restore them.

3. **Windows Only**: IAT is a Windows PE format concept, so this feature only works on Windows platforms.

4. **Race Conditions**: There is a TOCTOU (time-of-check-time-of-use) window between verification and actual API calls. For critical functions, additional protection may be needed.

## Future Enhancements

Potential improvements for future tasks:

1. **Periodic Re-baselining**: Update expected addresses after legitimate module loads
2. **Per-Function Reporting**: Report which specific function was hooked
3. **Delay-Load IAT**: Also verify delay-load import tables
4. **IAT Restoration**: Optionally restore hooked entries
5. **Integration with Anti-Hook**: Coordinate with inline hook detection for comprehensive coverage

## References

- Windows PE Format: [Microsoft PE Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- IAT Hooking: Common technique in game hacks and anti-cheat evasion
- TASK-08 Specification: See problem statement in copilot instructions
