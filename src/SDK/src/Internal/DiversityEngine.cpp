/**
 * Sentinel SDK - Client Diversity Engine Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "DiversityEngine.hpp"
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

// Build-time diversity seed - injected by build system
// 0 = no diversity (debug builds), non-zero = diversity enabled (release builds)
#ifndef SENTINEL_DIVERSITY_SEED
#define SENTINEL_DIVERSITY_SEED 0ULL
#endif

namespace Sentinel {
namespace SDK {
namespace Internal {

// Static member initialization
uint64_t DiversityEngine::s_seed = SENTINEL_DIVERSITY_SEED;
bool DiversityEngine::s_initialized = false;

void DiversityEngine::Initialize(uint64_t seed) {
    s_seed = seed;
    s_initialized = true;
}

uint64_t DiversityEngine::GetSeed() {
    return s_seed;
}

bool DiversityEngine::IsEnabled() {
    return s_seed != 0;
}

// Simple 64-bit hash function (FNV-1a variant)
uint64_t DiversityEngine::Hash(uint64_t value) {
    constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
    constexpr uint64_t FNV_PRIME = 1099511628211ULL;
    
    uint64_t hash = FNV_OFFSET;
    
    // Mix in the seed
    hash ^= s_seed;
    hash *= FNV_PRIME;
    
    // Mix in the value byte-by-byte
    for (int i = 0; i < 8; ++i) {
        hash ^= (value >> (i * 8)) & 0xFF;
        hash *= FNV_PRIME;
    }
    
    return hash;
}

// 32-bit hash variant
uint32_t DiversityEngine::Hash32(uint32_t value) {
    uint64_t hash64 = Hash(value);
    return static_cast<uint32_t>(hash64 ^ (hash64 >> 32));
}

uint64_t DiversityEngine::TransformConstant(uint64_t value) {
    // Diversity padding - varies function structure
    SENTINEL_DIVERSITY_PADDING(__LINE__);
    
    if (!IsEnabled()) {
        return value;
    }
    
    // Transform the constant using hash-based method
    // Choose transformation based on seed
    uint32_t transformation = Hash32(value) % 4;
    
    switch (transformation) {
        case 0:
            // Identity transformation (return as-is)
            return value;
        
        case 1:
            // Addition/subtraction transformation
            // value = (value + offset) - offset
            {
                uint64_t offset = Hash(value * 2) % 256;
                return (value + offset) - offset;
            }
        
        case 2:
            // XOR transformation (double XOR cancels out)
            // value = (value ^ mask) ^ mask
            {
                uint64_t mask = Hash(value * 3);
                return (value ^ mask) ^ mask;
            }
        
        case 3:
            // Multiplication/division transformation
            // value = (value * multiplier) / multiplier
            // Use small multiplier to avoid overflow
            {
                uint64_t multiplier = (Hash(value * 4) % 7) + 2; // 2-8
                if (value < (UINT64_MAX / multiplier)) {
                    return (value * multiplier) / multiplier;
                }
                return value; // Fallback to identity if overflow risk
            }
        
        default:
            return value;
    }
}

size_t DiversityEngine::GetStructPadding(uint32_t structId) {
    // Diversity padding
    SENTINEL_DIVERSITY_PADDING(__LINE__);
    
    if (!IsEnabled()) {
        return 0;
    }
    
    // Generate pseudo-random padding size (0-15 bytes)
    uint32_t hash = Hash32(structId);
    return hash % 16;
}

void DiversityEngine::DiversifiedPath(uint32_t pathId) {
    // Diversity padding
    SENTINEL_DIVERSITY_PADDING(__LINE__);
    
    if (!IsEnabled()) {
        return;
    }
    
    // Choose a diversified implementation based on seed and pathId
    uint32_t variant = Hash32(pathId) % 8;
    
    // Each variant performs the same logical no-op but with different code
    switch (variant) {
        case 0:
            // Variant 0: Simple NOP
            break;
        
        case 1:
            // Variant 1: Volatile read/write
            {
                volatile int dummy = 0;
                dummy = 1;
                (void)dummy;
            }
            break;
        
        case 2:
            // Variant 2: Arithmetic operations that cancel out
            {
                volatile uint64_t x = pathId;
                x = (x + 42) - 42;
                (void)x;
            }
            break;
        
        case 3:
            // Variant 3: Bitwise operations that cancel out
            {
                volatile uint64_t x = pathId;
                x = (x ^ 0xDEADBEEF) ^ 0xDEADBEEF;
                (void)x;
            }
            break;
        
        case 4:
            // Variant 4: Multiple arithmetic operations
            {
                volatile uint64_t x = pathId;
                x = ((x * 3) / 3) + 0;
                (void)x;
            }
            break;
        
        case 5:
            // Variant 5: Stack manipulation
            {
                volatile char buffer[8];
                for (int i = 0; i < 8; ++i) {
                    buffer[i] = static_cast<char>(i);
                }
                (void)buffer[0];
            }
            break;
        
        case 6:
            // Variant 6: Conditional with predictable outcome
            {
                volatile uint32_t x = Hash32(pathId);
                if (x == x) { // Always true
                    x += 1;
                }
                (void)x;
            }
            break;
        
        case 7:
            // Variant 7: Loop with known iteration count
            {
                volatile int counter = 0;
                for (int i = 0; i < 3; ++i) {
                    counter += 1;
                }
                (void)counter;
            }
            break;
    }
}

void DiversityEngine::DiversifiedDelay(uint32_t baseMs) {
    // Diversity padding
    SENTINEL_DIVERSITY_PADDING(__LINE__);
    
    if (!IsEnabled()) {
        // No diversity, use base delay
        std::this_thread::sleep_for(std::chrono::milliseconds(baseMs));
        return;
    }
    
    // Add small random variation (-20% to +20%)
    uint64_t variation = Hash(baseMs) % 40; // 0-39
    int32_t adjustment = static_cast<int32_t>(variation) - 20; // -20 to +19
    
    int32_t adjustedMs = static_cast<int32_t>(baseMs) + (static_cast<int32_t>(baseMs) * adjustment / 100);
    if (adjustedMs < 0) adjustedMs = 0;
    
    std::this_thread::sleep_for(std::chrono::milliseconds(adjustedMs));
}

} // namespace Internal
} // namespace SDK
} // namespace Sentinel
