/**
 * @file vm_demo.cpp
 * @brief Demonstration of Sentinel VM capabilities
 * 
 * This demo shows how to use the Sentinel VM to execute bytecode
 * that performs integrity checks and detects violations.
 */

#include "../../src/SDK/src/Detection/VM/VMInterpreter.hpp"
#include "../../src/SDK/src/Detection/VM/Opcodes.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>

using namespace Sentinel::VM;

// Helper to create bytecode header
std::vector<uint8_t> createBytecode(const std::vector<uint8_t>& instructions) {
    std::vector<uint8_t> data;
    
    // Magic "SENT"
    data.push_back(0x54);
    data.push_back(0x4E);
    data.push_back(0x45);
    data.push_back(0x53);
    
    // Version
    data.push_back(0x00);
    data.push_back(0x01);
    
    // Flags
    data.push_back(0x00);
    data.push_back(0x00);
    
    // Checksum (will be calculated)
    size_t checksum_offset = data.size();
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x00);
    
    // Constant pool size (0)
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x00);
    
    // Instructions
    size_t instr_start = data.size();
    data.insert(data.end(), instructions.begin(), instructions.end());
    
    // Calculate CRC32
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = instr_start; i < data.size(); ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        }
    }
    crc = ~crc;
    
    data[checksum_offset + 0] = crc & 0xFF;
    data[checksum_offset + 1] = (crc >> 8) & 0xFF;
    data[checksum_offset + 2] = (crc >> 16) & 0xFF;
    data[checksum_offset + 3] = (crc >> 24) & 0xFF;
    
    return data;
}

// Helper to encode uint64_t
std::vector<uint8_t> encodeU64(uint64_t value) {
    std::vector<uint8_t> result;
    for (int i = 0; i < 8; ++i) {
        result.push_back((value >> (i * 8)) & 0xFF);
    }
    return result;
}

void printOutput(const VMOutput& output) {
    std::cout << "VM Execution Results:\n";
    std::cout << "  Result: ";
    switch (output.result) {
        case VMResult::Clean: std::cout << "Clean\n"; break;
        case VMResult::Violation: std::cout << "Violation Detected!\n"; break;
        case VMResult::Error: std::cout << "Error\n"; break;
        case VMResult::Timeout: std::cout << "Timeout\n"; break;
        case VMResult::Halted: std::cout << "Halted\n"; break;
    }
    std::cout << "  Detection Flags: 0x" << std::hex << output.detection_flags << std::dec << "\n";
    std::cout << "  Instructions Executed: " << output.instructions_executed << "\n";
    std::cout << "  Memory Reads: " << output.memory_reads_performed << "\n";
    std::cout << "  Elapsed Time: " << output.elapsed.count() << " microseconds\n";
    if (!output.error_message.empty()) {
        std::cout << "  Error: " << output.error_message << "\n";
    }
    std::cout << "\n";
}

int main() {
    std::cout << "=== Sentinel Defensive VM Demo ===\n\n";
    
    // Demo 1: Basic arithmetic
    {
        std::cout << "Demo 1: Basic Arithmetic (100 + 200)\n";
        std::vector<uint8_t> instructions;
        
        // PUSH_IMM 100
        instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
        auto val1 = encodeU64(100);
        instructions.insert(instructions.end(), val1.begin(), val1.end());
        
        // PUSH_IMM 200
        instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
        auto val2 = encodeU64(200);
        instructions.insert(instructions.end(), val2.begin(), val2.end());
        
        // ADD
        instructions.push_back(static_cast<uint8_t>(Opcode::ADD));
        
        // HALT
        instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
        
        auto data = createBytecode(instructions);
        Bytecode bytecode;
        if (bytecode.load(data)) {
            VMInterpreter vm;
            VMOutput output = vm.execute(bytecode);
            printOutput(output);
        }
    }
    
    // Demo 2: Detection flags
    {
        std::cout << "Demo 2: Setting Detection Flags\n";
        std::vector<uint8_t> instructions;
        
        // Set flag bit 5
        instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
        auto flag = encodeU64(5);
        instructions.insert(instructions.end(), flag.begin(), flag.end());
        instructions.push_back(static_cast<uint8_t>(Opcode::SET_FLAG));
        
        // Set flag bit 10
        instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
        flag = encodeU64(10);
        instructions.insert(instructions.end(), flag.begin(), flag.end());
        instructions.push_back(static_cast<uint8_t>(Opcode::SET_FLAG));
        
        // HALT
        instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
        
        auto data = createBytecode(instructions);
        Bytecode bytecode;
        if (bytecode.load(data)) {
            VMInterpreter vm;
            VMOutput output = vm.execute(bytecode);
            printOutput(output);
        }
    }
    
    // Demo 3: External function call
    {
        std::cout << "Demo 3: External Function Call\n";
        VMInterpreter vm;
        
        // Register external function that multiplies two numbers
        vm.registerExternal(1, [](uint64_t a, uint64_t b) -> uint64_t {
            std::cout << "  External function called with: " << a << " and " << b << "\n";
            return a * b;
        });
        
        std::vector<uint8_t> instructions;
        
        // PUSH_IMM 7
        instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
        auto val1 = encodeU64(7);
        instructions.insert(instructions.end(), val1.begin(), val1.end());
        
        // PUSH_IMM 6
        instructions.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
        auto val2 = encodeU64(6);
        instructions.insert(instructions.end(), val2.begin(), val2.end());
        
        // CALL_EXT 1
        instructions.push_back(static_cast<uint8_t>(Opcode::CALL_EXT));
        instructions.push_back(1);
        
        // HALT
        instructions.push_back(static_cast<uint8_t>(Opcode::HALT));
        
        auto data = createBytecode(instructions);
        Bytecode bytecode;
        if (bytecode.load(data)) {
            VMOutput output = vm.execute(bytecode);
            printOutput(output);
        }
    }
    
    // Demo 4: Violation detection
    {
        std::cout << "Demo 4: Violation Detection (HALT_FAIL)\n";
        std::vector<uint8_t> instructions;
        
        // HALT_FAIL
        instructions.push_back(static_cast<uint8_t>(Opcode::HALT_FAIL));
        
        auto data = createBytecode(instructions);
        Bytecode bytecode;
        if (bytecode.load(data)) {
            VMInterpreter vm;
            VMOutput output = vm.execute(bytecode);
            printOutput(output);
        }
    }
    
    // Demo 5: Polymorphic opcodes
    {
        std::cout << "Demo 5: Polymorphic Opcode Maps\n";
        
        auto map1 = generateOpcodeMap(12345);
        auto map2 = generateOpcodeMap(67890);
        
        std::cout << "  Seed 12345: NOP maps to 0x" 
                  << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(map1[static_cast<uint8_t>(Opcode::NOP)]) << "\n";
        std::cout << "  Seed 67890: NOP maps to 0x" 
                  << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(map2[static_cast<uint8_t>(Opcode::NOP)]) << "\n";
        std::cout << "  Opcode maps differ: " 
                  << (map1[0] != map2[0] ? "Yes" : "No") << "\n\n";
    }
    
    std::cout << "=== Demo Complete ===\n";
    return 0;
}
