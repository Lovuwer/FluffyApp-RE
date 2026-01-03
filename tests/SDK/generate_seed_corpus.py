#!/usr/bin/env python3
"""
Seed Corpus Generator for VM Fuzzer

This script generates valid bytecode samples to seed the fuzzer.
The fuzzer will mutate these samples to explore edge cases.

BYTECODE FORMAT (from VMInterpreter.hpp):
- Header (24 bytes):
  - magic (4 bytes): 0x53454E54 ("SENT")
  - version (2 bytes): 1
  - flags (2 bytes): 0
  - xxh3_hash (8 bytes): Hash of instructions
  - instruction_count (4 bytes): Number of instruction bytes
  - constant_count (4 bytes): Number of 8-byte constants
- Constant Pool: constant_count * 8 bytes (little-endian uint64_t)
- Instructions: instruction_count bytes

OPCODES (from Opcodes.hpp):
We use basic opcodes that are known to work:
- 0x00: OP_NOP (no operation)
- 0x01: OP_HALT (stop execution)
- 0x02: OP_PUSH_CONST (push constant from pool)
- 0x03: OP_POP (discard top of stack)
- 0x10: OP_ADD (add two values)
- 0x11: OP_SUB (subtract two values)
- 0x12: OP_MUL (multiply two values)
- 0x13: OP_DIV (divide two values)
- 0x20: OP_JMP (unconditional jump)
- 0x21: OP_JZ (jump if zero)
- 0x30: OP_CMP_EQ (compare equal)

Note: We don't use all opcodes to keep corpus simple and focused.
The fuzzer will explore other opcodes through mutation.

USAGE:
  python3 generate_seed_corpus.py <output_directory>

EXAMPLE:
  python3 generate_seed_corpus.py corpus/fuzz_vm/
"""

import struct
import sys
import os
from pathlib import Path

def xxh3_hash(data):
    """
    Simple XXH3-like hash implementation.
    Must match the hash in Bytecode.cpp for bytecode to verify.
    
    This is a simplified version for corpus generation.
    The actual implementation is in src/SDK/src/Detection/VM/Bytecode.cpp
    """
    PRIME64_1 = 0x9E3779B185EBCA87
    PRIME64_2 = 0xC2B2AE3D27D4EB4F
    PRIME64_3 = 0x165667B19E3779F9
    PRIME64_4 = 0x85EBCA77C2B2AE63
    PRIME64_5 = 0x27D4EB2F165667C5
    
    h64 = (PRIME64_5 + len(data)) & 0xFFFFFFFFFFFFFFFF
    
    # Process 8-byte chunks
    i = 0
    while i + 8 <= len(data):
        k1 = struct.unpack('<Q', data[i:i+8])[0]
        k1 = (k1 * PRIME64_2) & 0xFFFFFFFFFFFFFFFF
        k1 = ((k1 << 31) | (k1 >> 33)) & 0xFFFFFFFFFFFFFFFF
        k1 = (k1 * PRIME64_1) & 0xFFFFFFFFFFFFFFFF
        h64 ^= k1
        h64 = (((h64 << 27) | (h64 >> 37)) * PRIME64_1 + PRIME64_4) & 0xFFFFFFFFFFFFFFFF
        i += 8
    
    # Process remaining bytes
    while i < len(data):
        h64 ^= (data[i] * PRIME64_5) & 0xFFFFFFFFFFFFFFFF
        h64 = (((h64 << 11) | (h64 >> 53)) * PRIME64_1) & 0xFFFFFFFFFFFFFFFF
        i += 1
    
    # Avalanche
    h64 ^= h64 >> 33
    h64 = (h64 * PRIME64_2) & 0xFFFFFFFFFFFFFFFF
    h64 ^= h64 >> 29
    h64 = (h64 * PRIME64_3) & 0xFFFFFFFFFFFFFFFF
    h64 ^= h64 >> 32
    
    return h64

def create_bytecode(instructions, constants=[]):
    """
    Create valid bytecode with proper header and hash.
    
    Args:
        instructions: List of instruction bytes
        constants: List of 64-bit constant values
    
    Returns:
        bytes: Complete bytecode blob
    """
    data = bytearray()
    
    # Magic "SENT" (0x53454E54)
    data.extend(struct.pack('<I', 0x53454E54))
    
    # Version (1.0)
    data.extend(struct.pack('<H', 1))
    
    # Flags (0)
    data.extend(struct.pack('<H', 0))
    
    # XXH3 hash placeholder (will be filled later)
    hash_offset = len(data)
    data.extend(struct.pack('<Q', 0))
    
    # Instruction count
    data.extend(struct.pack('<I', len(instructions)))
    
    # Constant count
    data.extend(struct.pack('<I', len(constants)))
    
    # Constants (little-endian, 8 bytes each)
    for c in constants:
        data.extend(struct.pack('<Q', c))
    
    # Instructions
    instruction_offset = len(data)
    data.extend(instructions)
    
    # Calculate XXH3 hash of instructions
    instr_bytes = data[instruction_offset:]
    hash_value = xxh3_hash(bytes(instr_bytes))
    
    # Update hash in header
    struct.pack_into('<Q', data, hash_offset, hash_value)
    
    return bytes(data)

def save_bytecode(filename, bytecode):
    """Save bytecode to file."""
    with open(filename, 'wb') as f:
        f.write(bytecode)
    print(f"Created: {filename} ({len(bytecode)} bytes)")

def generate_corpus(output_dir):
    """Generate seed corpus with diverse bytecode samples."""
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Sample 1: Minimal - just HALT
    # This is the simplest valid bytecode
    bytecode = create_bytecode([0x01])  # OP_HALT
    save_bytecode(f"{output_dir}/seed_01_minimal_halt.bin", bytecode)
    
    # Sample 2: NOP and HALT
    # Tests basic sequential execution
    bytecode = create_bytecode([0x00, 0x00, 0x00, 0x01])  # NOP NOP NOP HALT
    save_bytecode(f"{output_dir}/seed_02_nop_halt.bin", bytecode)
    
    # Sample 3: Push constants and POP
    # Tests constant pool and stack operations
    bytecode = create_bytecode(
        [
            0x02, 0x00, 0x00,  # PUSH_CONST index=0
            0x02, 0x01, 0x00,  # PUSH_CONST index=1
            0x03,              # POP
            0x03,              # POP
            0x01               # HALT
        ],
        constants=[0x1234567890ABCDEF, 0xFEDCBA0987654321]
    )
    save_bytecode(f"{output_dir}/seed_03_push_pop.bin", bytecode)
    
    # Sample 4: Arithmetic operations
    # Tests ADD, SUB, MUL operations
    bytecode = create_bytecode(
        [
            0x02, 0x00, 0x00,  # PUSH_CONST index=0 (10)
            0x02, 0x01, 0x00,  # PUSH_CONST index=1 (20)
            0x10,              # ADD (30)
            0x02, 0x02, 0x00,  # PUSH_CONST index=2 (5)
            0x11,              # SUB (25)
            0x02, 0x03, 0x00,  # PUSH_CONST index=3 (2)
            0x12,              # MUL (50)
            0x03,              # POP
            0x01               # HALT
        ],
        constants=[10, 20, 5, 2]
    )
    save_bytecode(f"{output_dir}/seed_04_arithmetic.bin", bytecode)
    
    # Sample 5: Simple jump forward
    # Tests unconditional jump
    bytecode = create_bytecode(
        [
            0x20, 0x05, 0x00, 0x00, 0x00,  # JMP to offset 5 (skip next instruction)
            0x00,                           # NOP (skipped)
            0x01                            # HALT
        ]
    )
    save_bytecode(f"{output_dir}/seed_05_jump_forward.bin", bytecode)
    
    # Sample 6: Conditional jump (JZ - jump if zero)
    # Tests conditional branching
    bytecode = create_bytecode(
        [
            0x02, 0x00, 0x00,               # PUSH_CONST index=0 (0)
            0x21, 0x09, 0x00, 0x00, 0x00,  # JZ to offset 9 (will jump)
            0x00,                           # NOP (skipped)
            0x01                            # HALT
        ],
        constants=[0]  # Zero value for JZ
    )
    save_bytecode(f"{output_dir}/seed_06_conditional_jump.bin", bytecode)
    
    # Sample 7: Compare equal operation
    # Tests comparison and conditional logic
    bytecode = create_bytecode(
        [
            0x02, 0x00, 0x00,  # PUSH_CONST index=0 (42)
            0x02, 0x01, 0x00,  # PUSH_CONST index=1 (42)
            0x30,              # CMP_EQ (pushes 1 if equal)
            0x03,              # POP result
            0x01               # HALT
        ],
        constants=[42, 42]
    )
    save_bytecode(f"{output_dir}/seed_07_compare.bin", bytecode)
    
    # Sample 8: Division operation
    # Tests DIV opcode
    bytecode = create_bytecode(
        [
            0x02, 0x00, 0x00,  # PUSH_CONST index=0 (100)
            0x02, 0x01, 0x00,  # PUSH_CONST index=1 (10)
            0x13,              # DIV (10)
            0x03,              # POP
            0x01               # HALT
        ],
        constants=[100, 10]
    )
    save_bytecode(f"{output_dir}/seed_08_division.bin", bytecode)
    
    # Sample 9: Complex with multiple constants
    # Tests large constant pool
    bytecode = create_bytecode(
        [
            0x02, 0x00, 0x00,  # PUSH_CONST 0
            0x02, 0x01, 0x00,  # PUSH_CONST 1
            0x02, 0x02, 0x00,  # PUSH_CONST 2
            0x02, 0x03, 0x00,  # PUSH_CONST 3
            0x02, 0x04, 0x00,  # PUSH_CONST 4
            0x03,              # POP
            0x03,              # POP
            0x03,              # POP
            0x03,              # POP
            0x03,              # POP
            0x01               # HALT
        ],
        constants=[1, 2, 3, 4, 5]
    )
    save_bytecode(f"{output_dir}/seed_09_large_constant_pool.bin", bytecode)
    
    # Sample 10: Long instruction sequence
    # Tests instruction limit handling
    nops = [0x00] * 100  # 100 NOPs
    bytecode = create_bytecode(nops + [0x01])  # Many NOPs then HALT
    save_bytecode(f"{output_dir}/seed_10_long_sequence.bin", bytecode)
    
    # Sample 11: Jump to end (testing boundary)
    # Tests jump to valid boundary location
    bytecode = create_bytecode(
        [
            0x20, 0x07, 0x00, 0x00, 0x00,  # JMP to offset 7 (points to HALT)
            0x00,                           # NOP (skipped)
            0x01                            # HALT
        ]
    )
    save_bytecode(f"{output_dir}/seed_11_jump_to_end.bin", bytecode)
    
    # Sample 12: Empty constant pool
    # Tests bytecode with no constants
    bytecode = create_bytecode(
        [
            0x00,  # NOP
            0x00,  # NOP
            0x01   # HALT
        ],
        constants=[]  # No constants
    )
    save_bytecode(f"{output_dir}/seed_12_no_constants.bin", bytecode)
    
    print(f"\nGenerated 12 seed corpus files in {output_dir}")
    print(f"Total corpus size: {sum(os.path.getsize(os.path.join(output_dir, f)) for f in os.listdir(output_dir))} bytes")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 generate_seed_corpus.py <output_directory>")
        print("Example: python3 generate_seed_corpus.py corpus/fuzz_vm/")
        sys.exit(1)
    
    output_dir = sys.argv[1]
    generate_corpus(output_dir)
