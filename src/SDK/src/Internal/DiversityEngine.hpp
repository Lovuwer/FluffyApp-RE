/**
 * Sentinel SDK - Client Diversity Engine
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Purpose: Implement build-time diversification to break universal bypass tools.
 * Each client build is slightly different, forcing attackers to develop multiple
 * bypasses or accept reduced compatibility.
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <array>

namespace Sentinel {
namespace SDK {
namespace Internal {

/**
 * DiversityEngine - Build-time code diversification
 * 
 * Implements several diversification techniques:
 * 1. Structure padding randomization - varies memory layouts
 * 2. Constant transformation - equivalent constant representations
 * 3. Function ordering - varies function addresses via link order
 * 4. Diversified stubs - non-critical code paths with variation
 */
class DiversityEngine {
public:
    /**
     * Initialize the diversity engine with a build-time seed.
     * Seed is generated at build time and embedded in the binary.
     * 
     * @param seed Build-time diversity seed (0 = deterministic, no diversity)
     */
    static void Initialize(uint64_t seed);

    /**
     * Get the current diversity seed (for debugging/verification)
     */
    static uint64_t GetSeed();

    /**
     * Check if diversity is enabled (seed != 0)
     */
    static bool IsEnabled();

    /**
     * Transform a constant value based on diversity seed.
     * Returns an equivalent representation of the constant.
     * 
     * @param value Original constant value
     * @return Diversified but equivalent value
     */
    static uint64_t TransformConstant(uint64_t value);

    /**
     * Get randomized structure padding size (0-15 bytes)
     * Used to vary structure layouts between builds.
     * 
     * The 15-byte maximum limit balances:
     * - Sufficient diversity for meaningful layout variation
     * - Minimal memory overhead (< 1% for typical structures)
     * - Cache-line friendly (stays within 64-byte cache lines)
     * 
     * @param structId Unique identifier for the structure
     * @return Padding size in bytes (0-15)
     */
    static size_t GetStructPadding(uint32_t structId);

    /**
     * Execute a diversified non-critical code path.
     * These are functionally equivalent but differ in implementation.
     * 
     * @param pathId Identifier for the code path
     */
    static void DiversifiedPath(uint32_t pathId);

    /**
     * Diversified sleep/delay function.
     * Introduces timing variation to break timing-based attacks.
     * 
     * @param baseMs Base delay in milliseconds
     */
    static void DiversifiedDelay(uint32_t baseMs);

private:
    static uint64_t s_seed;
    static bool s_initialized;

    // Internal hash function for deterministic pseudo-randomness
    static uint64_t Hash(uint64_t value);
    static uint32_t Hash32(uint32_t value);
};

/**
 * Diversified structure wrapper
 * Adds random padding to structures based on diversity seed
 * 
 * Usage:
 *   struct MyData {
 *       int x;
 *       DiversifiedPadding<1> padding;  // structId = 1
 *       int y;
 *   };
 */
template<uint32_t StructId>
struct DiversifiedPadding {
    DiversifiedPadding() {
        // Zero-initialize padding for security
        std::memset(padding, 0, sizeof(padding));
    }

    // Get the actual padding size for this structure
    static constexpr size_t GetSize() {
        // This will be resolved at compile time
        // In practice, we use runtime to allow seed-based variation
        return 0; // Placeholder, actual implementation uses GetStructPadding
    }

private:
    // Maximum padding is 15 bytes to balance diversity with memory overhead
    uint8_t padding[15];
};

/**
 * Macro to create diversified function stubs
 * These functions are identical in behavior but differ in implementation
 */
#define SENTINEL_DIVERSIFIED_STUB(id) \
    do { \
        ::Sentinel::SDK::Internal::DiversityEngine::DiversifiedPath(id); \
    } while(0)

/**
 * Macro to transform constants with diversity
 */
#define SENTINEL_DIVERSE_CONST(value) \
    ::Sentinel::SDK::Internal::DiversityEngine::TransformConstant(value)

} // namespace Internal
} // namespace SDK
} // namespace Sentinel
