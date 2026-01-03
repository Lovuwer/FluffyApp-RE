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
    // Simple CRC32 implementation
    uint32_t crc32(const uint8_t* data, size_t length) noexcept {
        static constexpr uint32_t polynomial = 0xEDB88320;
        
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < length; ++i) {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
            }
        }
        return ~crc;
    }
    
    // Read little-endian values
    template<typename T>
    T readLE(const uint8_t* data) noexcept {
        T value = 0;
        for (size_t i = 0; i < sizeof(T); ++i) {
            value |= static_cast<T>(data[i]) << (i * 8);
        }
        return value;
    }
}

bool Bytecode::load(const std::vector<uint8_t>& data) {
    // Minimum size: 16-byte header
    if (data.size() < 16) {
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
    m_checksum = readLE<uint32_t>(data.data() + 8);
    uint32_t constant_pool_size = readLE<uint32_t>(data.data() + 12);
    
    // Calculate constant pool offset and instruction offset
    m_constant_pool_offset = 16;
    m_instruction_offset = m_constant_pool_offset + constant_pool_size;
    
    // Verify data size
    if (data.size() < m_instruction_offset) {
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
    
    // Calculate CRC32 of instructions
    const uint8_t* instr_start = m_data.data() + m_instruction_offset;
    size_t instr_size = m_data.size() - m_instruction_offset;
    
    uint32_t computed_crc = crc32(instr_start, instr_size);
    return computed_crc == m_checksum;
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

} // namespace Sentinel::VM
