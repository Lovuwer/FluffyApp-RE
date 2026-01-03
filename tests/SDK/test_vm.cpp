/**
 * Sentinel SDK - VM Tests
 * 
 * Copyright (c) 2026 Sentinel Security. All rights reserved.
 * 
 * Tests for VM Interpreter, Opcodes, and Bytecode
 */

#include <gtest/gtest.h>
#include "../src/SDK/src/Detection/VM/VMInterpreter.hpp"
#include "../src/SDK/src/Detection/VM/Opcodes.hpp"
#include <vector>
#include <cstring>

using namespace Sentinel::VM;

// ============================================================================
// Helper Functions
// ============================================================================

namespace {
    // Helper to create bytecode with header
    std::vector<uint8_t> createBytecodeWithInstructions(
        const std::vector<uint8_t>& instructions,
        const std::vector<uint64_t>& constants = {}
    ) {
        std::vector<uint8_t> data;
        
        // Magic "SENT" (0x53454E54)
        data.push_back(0x54);
        data.push_back(0x4E);
        data.push_back(0x45);
        data.push_back(0x53);
        
        // Version (1.0)
        data.push_back(0x00);
        data.push_back(0x01);
        
        // Flags (0)
        data.push_back(0x00);
        data.push_back(0x00);
        
        // Checksum placeholder (will be calculated)
        size_t checksum_offset = data.size();
        data.push_back(0x00);
        data.push_back(0x00);
        data.push_back(0x00);
        data.push_back(0x00);
        
        // Constant pool size
        uint32_t pool_size = static_cast<uint32_t>(constants.size() * 8);
        data.push_back(pool_size & 0xFF);
        data.push_back((pool_size >> 8) & 0xFF);
        data.push_back((pool_size >> 16) & 0xFF);
        data.push_back((pool_size >> 24) & 0xFF);
        
        // Constants (little-endian)
        for (uint64_t c : constants) {
            for (int i = 0; i < 8; ++i) {
                data.push_back((c >> (i * 8)) & 0xFF);
            }
        }
        
        // Instructions
        data.insert(data.end(), instructions.begin(), instructions.end());
        
        // Calculate CRC32 of instructions
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 16 + pool_size; i < data.size(); ++i) {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
            }
        }
        crc = ~crc;
        
        // Store checksum
        data[checksum_offset + 0] = crc & 0xFF;
        data[checksum_offset + 1] = (crc >> 8) & 0xFF;
        data[checksum_offset + 2] = (crc >> 16) & 0xFF;
        data[checksum_offset + 3] = (crc >> 24) & 0xFF;
        
        return data;
    }
    
    // Helper to encode uint16_t as little-endian
    std::vector<uint8_t> encodeU16(uint16_t value) {
        return {
            static_cast<uint8_t>(value & 0xFF),
            static_cast<uint8_t>((value >> 8) & 0xFF)
        };
    }
    
    // Helper to encode uint64_t as little-endian
    std::vector<uint8_t> encodeU64(uint64_t value) {
        std::vector<uint8_t> result;
        for (int i = 0; i < 8; ++i) {
            result.push_back((value >> (i * 8)) & 0xFF);
        }
        return result;
    }
}

// ============================================================================
// Opcode Map Tests
// ============================================================================

TEST(OpcodeTests, GenerateOpcodeMapCreatesPermutation) {
    auto map = generateOpcodeMap(12345);
    
    // Check that all values 0-255 appear exactly once
    std::vector<bool> seen(256, false);
    for (uint32_t i = 0; i < 256; ++i) {
        EXPECT_FALSE(seen[map[i]]) << "Duplicate value in opcode map";
        seen[map[i]] = true;
    }
    
    // All values should be seen
    for (uint32_t i = 0; i < 256; ++i) {
        EXPECT_TRUE(seen[i]) << "Value " << i << " missing from opcode map";
    }
}

TEST(OpcodeTests, GenerateOpcodeMapDifferentSeeds) {
    auto map1 = generateOpcodeMap(12345);
    auto map2 = generateOpcodeMap(67890);
    
    // Maps should be different
    bool different = false;
    for (uint32_t i = 0; i < 256; ++i) {
        if (map1[i] != map2[i]) {
            different = true;
            break;
        }
    }
    EXPECT_TRUE(different) << "Different seeds should produce different maps";
}

TEST(OpcodeTests, GenerateOpcodeMapSameSeed) {
    auto map1 = generateOpcodeMap(12345);
    auto map2 = generateOpcodeMap(12345);
    
    // Same seed should produce identical map
    for (uint32_t i = 0; i < 256; ++i) {
        EXPECT_EQ(map1[i], map2[i]) << "Same seed should produce identical map";
    }
}

TEST(OpcodeTests, InvertOpcodeMapCorrect) {
    auto forward = generateOpcodeMap(12345);
    auto inverse = invertOpcodeMap(forward);
    
    // Check that inverse[forward[i]] == i
    for (uint32_t i = 0; i < 256; ++i) {
        EXPECT_EQ(inverse[forward[i]], i) << "Inverse map incorrect at index " << i;
    }
}

TEST(OpcodeTests, OpcodeMetadataStackConsume) {
    EXPECT_EQ(opcodeStackConsume(Opcode::NOP), 0);
    EXPECT_EQ(opcodeStackConsume(Opcode::POP), 1);
    EXPECT_EQ(opcodeStackConsume(Opcode::ADD), 2);
    EXPECT_EQ(opcodeStackConsume(Opcode::READ_SAFE_8), 1);
    EXPECT_EQ(opcodeStackConsume(Opcode::HASH_CRC32), 2);
}

TEST(OpcodeTests, OpcodeMetadataStackProduce) {
    EXPECT_EQ(opcodeStackProduce(Opcode::NOP), 0);
    EXPECT_EQ(opcodeStackProduce(Opcode::POP), 0);
    EXPECT_EQ(opcodeStackProduce(Opcode::PUSH_IMM), 1);
    EXPECT_EQ(opcodeStackProduce(Opcode::DUP), 2);
    EXPECT_EQ(opcodeStackProduce(Opcode::ADD), 1);
}

TEST(OpcodeTests, OpcodeMetadataOperandSize) {
    EXPECT_EQ(opcodeOperandSize(Opcode::NOP), 0);
    EXPECT_EQ(opcodeOperandSize(Opcode::PUSH_IMM), 8);
    EXPECT_EQ(opcodeOperandSize(Opcode::PUSH_CONST), 2);
    EXPECT_EQ(opcodeOperandSize(Opcode::JMP), 2);
    EXPECT_EQ(opcodeOperandSize(Opcode::CALL_EXT), 1);
}

// ============================================================================
// Bytecode Tests
// ============================================================================

TEST(BytecodeTests, LoadValidBytecode) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::NOP),
        static_cast<uint8_t>(Opcode::HALT)
    };
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    EXPECT_TRUE(bytecode.load(data));
    EXPECT_TRUE(bytecode.verify());
    EXPECT_EQ(bytecode.version(), 0x0100);
}

TEST(BytecodeTests, LoadInvalidMagic) {
    std::vector<uint8_t> data(16, 0);
    data[0] = 0xFF;  // Wrong magic
    
    Bytecode bytecode;
    EXPECT_FALSE(bytecode.load(data));
}

TEST(BytecodeTests, LoadTooSmall) {
    std::vector<uint8_t> data(8, 0);
    
    Bytecode bytecode;
    EXPECT_FALSE(bytecode.load(data));
}

TEST(BytecodeTests, GetConstantValid) {
    std::vector<uint64_t> constants = {0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL};
    std::vector<uint8_t> instructions = {static_cast<uint8_t>(Opcode::HALT)};
    auto data = createBytecodeWithInstructions(instructions, constants);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    EXPECT_EQ(bytecode.getConstant(0), 0x1234567890ABCDEFULL);
    EXPECT_EQ(bytecode.getConstant(1), 0xFEDCBA0987654321ULL);
}

TEST(BytecodeTests, GetConstantOutOfBounds) {
    std::vector<uint8_t> instructions = {static_cast<uint8_t>(Opcode::HALT)};
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    EXPECT_EQ(bytecode.getConstant(0), 0);  // No constants, should return 0
    EXPECT_EQ(bytecode.getConstant(100), 0);
}

// ============================================================================
// VM Execution Tests - Basic Operations
// ============================================================================

TEST(VMInterpreterTests, ExecuteNOP) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::NOP),
        static_cast<uint8_t>(Opcode::NOP),
        static_cast<uint8_t>(Opcode::HALT)
    };
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
    EXPECT_GT(output.instructions_executed, 0);
}

TEST(VMInterpreterTests, ExecutePushImmediate) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto imm = encodeU64(0x1234567890ABCDEFULL);
    instructions.insert(instructions.end(), imm.begin(), imm.end());
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

TEST(VMInterpreterTests, ExecutePushConstant) {
    std::vector<uint64_t> constants = {0xDEADBEEFCAFEBABEULL};
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_CONST)
    };
    auto idx = encodeU16(0);
    instructions.insert(instructions.end(), idx.begin(), idx.end());
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions, constants);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

TEST(VMInterpreterTests, ExecuteArithmeticAdd) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto val1 = encodeU64(100);
    instructions.insert(instructions.end(), val1.begin(), val1.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
    auto val2 = encodeU64(200);
    instructions.insert(instructions.end(), val2.begin(), val2.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::ADD));
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

TEST(VMInterpreterTests, ExecuteArithmeticSubtract) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto val1 = encodeU64(300);
    instructions.insert(instructions.end(), val1.begin(), val1.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
    auto val2 = encodeU64(100);
    instructions.insert(instructions.end(), val2.begin(), val2.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::SUB));
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

TEST(VMInterpreterTests, ExecuteBitwiseXOR) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto val1 = encodeU64(0xAAAAAAAAAAAAAAAAULL);
    instructions.insert(instructions.end(), val1.begin(), val1.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
    auto val2 = encodeU64(0x5555555555555555ULL);
    instructions.insert(instructions.end(), val2.begin(), val2.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::XOR));
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

TEST(VMInterpreterTests, ExecuteComparison) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto val1 = encodeU64(42);
    instructions.insert(instructions.end(), val1.begin(), val1.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
    auto val2 = encodeU64(42);
    instructions.insert(instructions.end(), val2.begin(), val2.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::CMP_EQ));
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

TEST(VMInterpreterTests, ExecuteStackDup) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto val = encodeU64(123);
    instructions.insert(instructions.end(), val.begin(), val.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::DUP));
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

TEST(VMInterpreterTests, ExecuteStackSwap) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto val1 = encodeU64(100);
    instructions.insert(instructions.end(), val1.begin(), val1.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
    auto val2 = encodeU64(200);
    instructions.insert(instructions.end(), val2.begin(), val2.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::SWAP));
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

// ============================================================================
// VM Execution Tests - Control Flow
// ============================================================================

TEST(VMInterpreterTests, ExecuteUnconditionalJump) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::JMP)
    };
    // Jump forward by 1 byte (skip the next HALT_FAIL)
    auto offset = encodeU16(1);
    instructions.insert(instructions.end(), offset.begin(), offset.end());
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT_FAIL));  // Should be skipped
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);  // Should reach normal HALT, not HALT_FAIL
}

TEST(VMInterpreterTests, ExecuteConditionalJumpZeroTaken) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto zero = encodeU64(0);
    instructions.insert(instructions.end(), zero.begin(), zero.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::JMP_Z));
    auto offset = encodeU16(1);
    instructions.insert(instructions.end(), offset.begin(), offset.end());
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT_FAIL));  // Should be skipped
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

TEST(VMInterpreterTests, ExecuteConditionalJumpNonZeroTaken) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto nonzero = encodeU64(42);
    instructions.insert(instructions.end(), nonzero.begin(), nonzero.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::JMP_NZ));
    auto offset = encodeU16(1);
    instructions.insert(instructions.end(), offset.begin(), offset.end());
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT_FAIL));  // Should be skipped
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

// ============================================================================
// VM Execution Tests - Detection Flags
// ============================================================================

TEST(VMInterpreterTests, ExecuteSetFlag) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto flag_bit = encodeU64(5);
    instructions.insert(instructions.end(), flag_bit.begin(), flag_bit.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::SET_FLAG));
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
    EXPECT_EQ(output.detection_flags & (1ULL << 5), 1ULL << 5);
}

TEST(VMInterpreterTests, ExecuteGetFlags) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto flag_bit = encodeU64(3);
    instructions.insert(instructions.end(), flag_bit.begin(), flag_bit.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::SET_FLAG));
    instructions.push_back(static_cast<uint8_t>(Opcode::GET_FLAGS));
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
    EXPECT_EQ(output.detection_flags & (1ULL << 3), 1ULL << 3);
}

// ============================================================================
// VM Execution Tests - External Calls
// ============================================================================

TEST(VMInterpreterTests, ExecuteExternalCall) {
    VMInterpreter vm;
    
    // Register external function that adds two numbers
    vm.registerExternal(42, [](uint64_t a, uint64_t b) -> uint64_t {
        return a + b;
    });
    
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::PUSH_IMM)
    };
    auto val1 = encodeU64(10);
    instructions.insert(instructions.end(), val1.begin(), val1.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
    auto val2 = encodeU64(20);
    instructions.insert(instructions.end(), val2.begin(), val2.end());
    
    instructions.push_back(static_cast<uint8_t>(Opcode::CALL_EXT));
    instructions.push_back(42);  // Function ID
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

// ============================================================================
// VM Execution Tests - Limits and Safety
// ============================================================================

TEST(VMInterpreterTests, InstructionLimit) {
    // Create a simple infinite loop
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::JMP)
    };
    // Jump back to start (offset -3: 2 bytes for offset + 1 for opcode)
    auto offset = encodeU16(static_cast<uint16_t>(-3));
    instructions.insert(instructions.end(), offset.begin(), offset.end());
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMConfig config;
    config.max_instructions = 1000;
    VMInterpreter vm(config);
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Timeout);
    EXPECT_GT(output.instructions_executed, 0);
}

TEST(VMInterpreterTests, StackOverflowProtection) {
    VMConfig config;
    config.max_stack_depth = 10;
    VMInterpreter vm(config);
    
    // Push more items than allowed
    std::vector<uint8_t> instructions;
    for (int i = 0; i < 20; ++i) {
        instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
        auto val = encodeU64(i);
        instructions.insert(instructions.end(), val.begin(), val.end());
    }
    instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Error);
}

TEST(VMInterpreterTests, HaltFail) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::HALT_FAIL)
    };
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Violation);
}

// ============================================================================
// VM Execution Tests - Anti-Analysis
// ============================================================================

TEST(VMInterpreterTests, ExecuteRDTSC) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::RDTSC_LOW),
        static_cast<uint8_t>(Opcode::HALT)
    };
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

TEST(VMInterpreterTests, ExecuteOpaquePredicates) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::OPAQUE_TRUE),
        static_cast<uint8_t>(Opcode::OPAQUE_FALSE),
        static_cast<uint8_t>(Opcode::HALT)
    };
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
}

// ============================================================================
// VM Configuration Tests
// ============================================================================

TEST(VMInterpreterTests, GetConfig) {
    VMConfig config;
    config.max_instructions = 50000;
    config.max_stack_depth = 512;
    
    VMInterpreter vm(config);
    
    const VMConfig& retrieved = vm.getConfig();
    EXPECT_EQ(retrieved.max_instructions, 50000);
    EXPECT_EQ(retrieved.max_stack_depth, 512);
}

TEST(VMInterpreterTests, MoveConstructor) {
    VMConfig config;
    VMInterpreter vm1(config);
    
    // Test move constructor
    VMInterpreter vm2(std::move(vm1));
    
    std::vector<uint8_t> instructions = {static_cast<uint8_t>(Opcode::HALT)};
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMOutput output = vm2.execute(bytecode);
    EXPECT_EQ(output.result, VMResult::Halted);
}

// ============================================================================
// OP_TEST_EXCEPTION Tests (Anti-VEH Canary)
// ============================================================================

/**
 * Test that OP_TEST_EXCEPTION returns 1 under normal conditions
 * (no external VEH handlers present)
 */
TEST(VMInterpreterTests, OpTestExceptionNormalConditions) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::OP_TEST_EXCEPTION),
        static_cast<uint8_t>(Opcode::HALT)
    };
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    EXPECT_EQ(output.result, VMResult::Halted);
    // Flag bit 8 should NOT be set (no VEH hijacking)
    EXPECT_EQ(output.detection_flags & (1ULL << 8), 0ULL);
}

#ifdef _WIN32
/**
 * Test that OP_TEST_EXCEPTION detects VEH hijacking when a malicious
 * VEH handler swallows exceptions
 */
TEST(VMInterpreterTests, OpTestExceptionDetectsVehHijacking) {
    // Install a malicious VEH handler that swallows access violations
    // This simulates an attacker's VEH handler
    auto malicious_veh = [](PEXCEPTION_POINTERS ex) -> LONG {
        if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            // Swallow the exception - don't let it propagate
            // Skip past the faulting instruction by a conservative amount
            // In practice, attackers would decode the instruction properly
            #ifdef _WIN64
            ex->ContextRecord->Rip += 8;  // Skip conservatively (mov reg, [mem] can be up to 7 bytes)
            #else
            ex->ContextRecord->Eip += 8;  // Skip conservatively
            #endif
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    };
    
    // Register malicious VEH handler with priority 1 (first)
    PVOID malicious_handler = AddVectoredExceptionHandler(1, malicious_veh);
    ASSERT_NE(malicious_handler, nullptr);
    
    // Create bytecode with OP_TEST_EXCEPTION
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::OP_TEST_EXCEPTION),
        static_cast<uint8_t>(Opcode::HALT)
    };
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    // Clean up malicious handler
    RemoveVectoredExceptionHandler(malicious_handler);
    
    // Should detect VEH hijacking
    EXPECT_EQ(output.result, VMResult::Halted);
    // Flag bit 8 SHOULD be set (VEH hijacking detected)
    EXPECT_NE(output.detection_flags & (1ULL << 8), 0ULL);
}

/**
 * Test that OP_TEST_EXCEPTION still passes when there's a benign VEH
 * handler that doesn't interfere with exception propagation
 */
TEST(VMInterpreterTests, OpTestExceptionWithBenignVeh) {
    // Install a benign VEH handler that logs but doesn't swallow exceptions
    auto benign_veh = [](PEXCEPTION_POINTERS ex) -> LONG {
        if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            // Just log and let it propagate
            return EXCEPTION_CONTINUE_SEARCH;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    };
    
    // Register benign VEH handler
    PVOID benign_handler = AddVectoredExceptionHandler(0, benign_veh);
    ASSERT_NE(benign_handler, nullptr);
    
    // Create bytecode with OP_TEST_EXCEPTION
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::OP_TEST_EXCEPTION),
        static_cast<uint8_t>(Opcode::HALT)
    };
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    // Clean up benign handler
    RemoveVectoredExceptionHandler(benign_handler);
    
    // Should pass - benign handler doesn't interfere
    EXPECT_EQ(output.result, VMResult::Halted);
    // Flag bit 8 should NOT be set
    EXPECT_EQ(output.detection_flags & (1ULL << 8), 0ULL);
}

/**
 * Performance test: OP_TEST_EXCEPTION should complete in < 100μs
 */
TEST(VMInterpreterTests, OpTestExceptionPerformance) {
    std::vector<uint8_t> instructions = {
        static_cast<uint8_t>(Opcode::OP_TEST_EXCEPTION),
        static_cast<uint8_t>(Opcode::HALT)
    };
    auto data = createBytecodeWithInstructions(instructions);
    
    Bytecode bytecode;
    ASSERT_TRUE(bytecode.load(data));
    
    VMInterpreter vm;
    
    // Run multiple times to get average
    const int iterations = 10;
    int64_t total_us = 0;
    
    for (int i = 0; i < iterations; ++i) {
        VMOutput output = vm.execute(bytecode);
        ASSERT_EQ(output.result, VMResult::Halted);
        total_us += output.elapsed.count();
    }
    
    int64_t avg_us = total_us / iterations;
    
    // Should complete in < 100μs on average
    EXPECT_LT(avg_us, 100) << "OP_TEST_EXCEPTION took " << avg_us << "μs (expected < 100μs)";
}
#endif // _WIN32
