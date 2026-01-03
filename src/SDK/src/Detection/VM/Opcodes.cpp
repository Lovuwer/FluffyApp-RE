/**
 * @file Opcodes.cpp
 * @brief Sentinel VM Opcode Implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2026
 * 
 * @copyright Copyright (c) 2026 Sentinel Security. All rights reserved.
 */

#include "Opcodes.hpp"
#include <algorithm>
#include <cstring>

namespace Sentinel::VM {

namespace {
    // Simple XXH3-like hash for seed mixing
    constexpr uint64_t xxh3_avalanche(uint64_t h) noexcept {
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= h >> 33;
        return h;
    }
    
    // Simple LCG for deterministic shuffling
    class SimpleRNG {
    public:
        explicit SimpleRNG(uint64_t seed) : state_(xxh3_avalanche(seed)) {}
        
        uint64_t next() noexcept {
            state_ = state_ * 6364136223846793005ULL + 1442695040888963407ULL;
            return state_;
        }
        
        // Get value in range [0, n)
        uint32_t range(uint32_t n) noexcept {
            if (n == 0) return 0;
            return static_cast<uint32_t>(next() % n);
        }
        
    private:
        uint64_t state_;
    };
}

std::array<uint8_t, 256> generateOpcodeMap(uint64_t seed) {
    std::array<uint8_t, 256> map;
    
    // Initialize identity map
    for (uint32_t i = 0; i < 256; ++i) {
        map[i] = static_cast<uint8_t>(i);
    }
    
    // Fisher-Yates shuffle with seeded RNG
    SimpleRNG rng(seed);
    for (uint32_t i = 255; i > 0; --i) {
        uint32_t j = rng.range(i + 1);
        std::swap(map[i], map[j]);
    }
    
    return map;
}

std::array<uint8_t, 256> invertOpcodeMap(const std::array<uint8_t, 256>& forward_map) {
    std::array<uint8_t, 256> inverse;
    
    for (uint32_t i = 0; i < 256; ++i) {
        inverse[forward_map[i]] = static_cast<uint8_t>(i);
    }
    
    return inverse;
}

} // namespace Sentinel::VM
