# Sentinel Defensive Virtual Machine

## Overview

The Sentinel Defensive VM is a stack-based bytecode interpreter designed for secure integrity checking and cheat detection. It provides a sandboxed execution environment that **never** crashes the game and returns detection results safely.

## Architecture Philosophy

This is a **DEFENSIVE** virtual machine. It does **NOT**:
- Modify game memory
- Execute arbitrary code
- Crash the game process on failure

It **DOES**:
- Execute sandboxed integrity checks
- Return detection results safely
- Trap all exceptions internally

## Key Features

### 1. Safe Memory Operations
- **VirtualQuery Validation**: All memory reads are validated using VirtualQuery (Windows) before access
- **Exception Handling**: SEH (Structured Exception Handling) catches all memory access violations
- **Zero-on-Error**: Invalid memory access returns zero instead of crashing

### 2. Execution Limits
- **Instruction Limit**: Configurable maximum instruction count (default: 100,000)
- **Stack Depth**: Stack overflow protection (default: 1,024 entries)
- **Memory Read Limit**: Limits number of external memory reads (default: 10,000)
- **Timeout Protection**: Execution timeout (default: 5 seconds)

### 3. Hash Operations
- **CRC32**: Fast 32-bit integrity hashing
- **XXH3**: High-performance 64-bit hashing
- **CHECK_HASH**: Automatic detection flag setting on mismatch

### 4. Polymorphic Opcodes
- **Build-Time Seed**: Opcodes are remapped using a seed value
- **Fisher-Yates Shuffle**: Deterministic permutation of opcode values
- **Anti-Reverse Engineering**: Different builds use different opcode layouts

### 5. External Function Callbacks
- Register up to 256 external functions
- Call game-specific checks from VM bytecode
- Safe execution with timeout protection

## Opcode Reference

### Control Flow
- `NOP` (0x00) - No operation
- `HALT` (0x01) - Stop execution (Clean result)
- `HALT_FAIL` (0x02) - Stop execution (Violation result)

### Stack Operations
- `PUSH_IMM` (0x10) - Push 8-byte immediate value
- `PUSH_CONST` (0x11) - Push from constant pool
- `POP` (0x12) - Discard top of stack
- `DUP` (0x13) - Duplicate top of stack
- `SWAP` (0x14) - Swap top two values

### Arithmetic
- `ADD` (0x20) - Addition
- `SUB` (0x21) - Subtraction
- `MUL` (0x22) - Multiplication
- `XOR` (0x23) - Bitwise XOR
- `AND` (0x24) - Bitwise AND
- `OR` (0x25) - Bitwise OR
- `SHL` (0x26) - Shift left
- `SHR` (0x27) - Shift right
- `ROL` (0x28) - Rotate left
- `ROR` (0x29) - Rotate right

### Comparison
- `CMP_EQ` (0x30) - Equal comparison
- `CMP_NE` (0x31) - Not equal comparison
- `CMP_LT` (0x32) - Less than (unsigned)
- `CMP_GT` (0x33) - Greater than (unsigned)

### Branching
- `JMP` (0x40) - Unconditional jump
- `JMP_Z` (0x41) - Jump if zero
- `JMP_NZ` (0x42) - Jump if not zero

### Safe Memory Reads
- `READ_SAFE_8` (0x50) - Safe 8-byte read
- `READ_SAFE_4` (0x51) - Safe 4-byte read
- `READ_SAFE_2` (0x52) - Safe 2-byte read
- `READ_SAFE_1` (0x53) - Safe 1-byte read

### Integrity Checks
- `HASH_CRC32` (0x60) - CRC32 hash of memory range
- `HASH_XXH3` (0x61) - XXH3 hash of memory range
- `CHECK_HASH` (0x62) - Compare hashes, set flag on mismatch

### Detection Flags
- `SET_FLAG` (0x70) - Set detection flag bit (0-63)
- `GET_FLAGS` (0x71) - Get current detection flags

### External Calls
- `CALL_EXT` (0x80) - Call registered external function

### Anti-Analysis
- `RDTSC_LOW` (0x90) - Read timestamp counter (low 32 bits)
- `OPAQUE_TRUE` (0x91) - Opaque predicate (always 1)
- `OPAQUE_FALSE` (0x92) - Opaque predicate (always 0)

## Bytecode Format

```
[Header (16 bytes)] [Constant Pool] [Instructions]

Header:
  - Magic: 0x53454E54 ("SENT")
  - Version: uint16_t
  - Flags: uint16_t
  - Checksum: uint32_t (CRC32 of instructions)
  - Constant Pool Size: uint32_t (in bytes)

Constant Pool:
  - Array of 8-byte uint64_t constants

Instructions:
  - Raw bytecode (opcodes + operands)
```

## Usage Example

```cpp
#include <Sentinel/VM/VMInterpreter.hpp>
#include <Sentinel/VM/Opcodes.hpp>

using namespace Sentinel::VM;

// Create bytecode
Bytecode bytecode;
std::vector<uint8_t> data = /* load from server or compile */;
if (!bytecode.load(data)) {
    // Invalid bytecode
    return;
}

// Verify integrity
if (!bytecode.verify()) {
    // Checksum mismatch
    return;
}

// Configure VM
VMConfig config;
config.max_instructions = 50000;
config.timeout_ms = 3000;

// Create interpreter
VMInterpreter vm(config);

// Register external function (optional)
vm.registerExternal(1, [](uint64_t arg1, uint64_t arg2) -> uint64_t {
    // Custom game check
    return checkGameIntegrity(arg1, arg2);
});

// Execute
VMOutput output = vm.execute(bytecode);

// Check results
switch (output.result) {
    case VMResult::Clean:
        // No violations detected
        break;
        
    case VMResult::Violation:
        // Cheat detected! Ban player
        banPlayer(output.detection_flags);
        break;
        
    case VMResult::Error:
    case VMResult::Timeout:
        // Treat as clean (defensive approach)
        // Log for investigation
        logVMError(output);
        break;
}
```

## Performance Metrics

From test execution:
- **Basic Arithmetic**: ~1-7 microseconds
- **Stack Operations**: < 1 microsecond
- **External Calls**: ~7 microseconds
- **Detection Flags**: < 1 microsecond

Typical integrity check: **< 100 microseconds**

## Security Guarantees

1. **No Crashes**: All exceptions caught internally
2. **No Memory Writes**: VM is read-only
3. **Bounded Execution**: Hard limits on instructions and time
4. **Safe Failure**: Errors default to "Clean" result
5. **Anti-Debugging**: RDTSC timing checks detect single-stepping

## Testing

Comprehensive test suite covers:
- Opcode map generation (7 tests)
- Bytecode loading and verification (5 tests)
- VM execution (22 tests)
  - Stack operations
  - Arithmetic and logic
  - Control flow and branching
  - Detection flags
  - External calls
  - Safety limits

All 34 tests passing ✅

## Files

- `src/SDK/src/Detection/VM/Opcodes.hpp` - Opcode definitions
- `src/SDK/src/Detection/VM/Opcodes.cpp` - Opcode map generation
- `src/SDK/src/Detection/VM/VMInterpreter.hpp` - VM interface
- `src/SDK/src/Detection/VM/VMInterpreter.cpp` - VM implementation
- `src/SDK/src/Detection/VM/Bytecode.cpp` - Bytecode container
- `tests/SDK/test_vm.cpp` - Comprehensive test suite
- `docs/examples/vm_demo.cpp` - Usage demonstration

## License

Copyright (c) 2026 Sentinel Security. All rights reserved.
