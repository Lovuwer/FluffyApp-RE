/**
 * @file Bytecode.cpp
 * @brief Sentinel VM Bytecode Container Implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2026
 * 
 * @copyright Copyright (c) 2026 Sentinel Security. All rights reserved.
 */

#include "VMInterpreter.hpp"
#include <cstring>
#include <algorithm>

namespace Sentinel::VM {

namespace {
    // Read little-endian values
    template<typename T>
    T readLE(const uint8_t* data) noexcept {
        T value = 0;
        for (size_t i = 0; i < sizeof(T); ++i) {
            value |= static_cast<T>(data[i]) << (i * 8);
        }
        return value;
    }
    
    // Simple XXH3-like hash implementation
    uint64_t xxh3_hash(const uint8_t* data, size_t length) noexcept {
        constexpr uint64_t PRIME64_1 = 0x9E3779B185EBCA87ULL;
        constexpr uint64_t PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
        constexpr uint64_t PRIME64_3 = 0x165667B19E3779F9ULL;
        constexpr uint64_t PRIME64_4 = 0x85EBCA77C2B2AE63ULL;
        constexpr uint64_t PRIME64_5 = 0x27D4EB2F165667C5ULL;
        
        uint64_t h64 = PRIME64_5 + length;
        
        // Process 8-byte chunks
        size_t i = 0;
        while (i + 8 <= length) {
            uint64_t k1 = readLE<uint64_t>(data + i);
            k1 *= PRIME64_2;
            k1 = (k1 << 31) | (k1 >> 33);
            k1 *= PRIME64_1;
            h64 ^= k1;
            h64 = ((h64 << 27) | (h64 >> 37)) * PRIME64_1 + PRIME64_4;
            i += 8;
        }
        
        // Process remaining bytes
        while (i < length) {
            h64 ^= static_cast<uint64_t>(data[i]) * PRIME64_5;
            h64 = ((h64 << 11) | (h64 >> 53)) * PRIME64_1;
            ++i;
        }
        
        // Avalanche
        h64 ^= h64 >> 33;
        h64 *= PRIME64_2;
        h64 ^= h64 >> 29;
        h64 *= PRIME64_3;
        h64 ^= h64 >> 32;
        
        return h64;
    }
}

bool Bytecode::load(const std::vector<uint8_t>& data) {
    // Minimum size: 24-byte header (BytecodeHeader)
    if (data.size() < sizeof(BytecodeHeader)) {
        return false;
    }
    
    // Verify magic number "SENT" (0x53454E54)
    uint32_t magic = readLE<uint32_t>(data.data());
    if (magic != 0x53454E54) {
        return false;
    }
    
    // Parse header
    m_version = readLE<uint16_t>(data.data() + 4);
    // uint16_t flags = readLE<uint16_t>(data.data() + 6);  // Reserved for future use
    m_xxh3_hash = readLE<uint64_t>(data.data() + 8);
    uint32_t instruction_count = readLE<uint32_t>(data.data() + 16);
    uint32_t constant_count = readLE<uint32_t>(data.data() + 20);
    
    // Calculate constant pool size
    uint32_t constant_pool_size = constant_count * 8;
    
    // Calculate constant pool offset and instruction offset
    m_constant_pool_offset = sizeof(BytecodeHeader);
    m_instruction_offset = m_constant_pool_offset + constant_pool_size;
    
    // Verify data size
    if (data.size() < m_instruction_offset + instruction_count) {
        return false;
    }
    
    // Store data
    m_data = data;
    
    return true;
}

bool Bytecode::verify() const noexcept {
    if (m_data.size() < m_instruction_offset) {
        return false;
    }
    
    // Calculate XXH3 hash of instructions
    const uint8_t* instr_start = m_data.data() + m_instruction_offset;
    size_t instr_size = m_data.size() - m_instruction_offset;
    
    uint64_t computed_hash = xxh3_hash(instr_start, instr_size);
    return computed_hash == m_xxh3_hash;
}

const uint8_t* Bytecode::instructions() const noexcept {
    if (m_data.size() < m_instruction_offset) {
        return nullptr;
    }
    return m_data.data() + m_instruction_offset;
}

size_t Bytecode::instructionCount() const noexcept {
    if (m_data.size() < m_instruction_offset) {
        return 0;
    }
    return m_data.size() - m_instruction_offset;
}

uint64_t Bytecode::getConstant(uint16_t index) const noexcept {
    // Each constant is 8 bytes
    size_t offset = m_constant_pool_offset + (index * 8);
    
    if (offset + 8 > m_instruction_offset || offset + 8 > m_data.size()) {
        return 0;
    }
    
    return readLE<uint64_t>(m_data.data() + offset);
}

uint16_t Bytecode::version() const noexcept {
    return m_version;
}

const uint8_t* Bytecode::rawData() const noexcept {
    return m_data.data();
}

size_t Bytecode::rawSize() const noexcept {
    return m_data.size();
}

} // namespace Sentinel::VM
