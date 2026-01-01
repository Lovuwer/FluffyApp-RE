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
     * @return Padding size as size_t (0-15 bytes)
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

    // Compile-time padding size based on diversity seed
    // Uses simple hash of seed and struct ID
    static constexpr size_t CalculatePaddingSize() {
#ifndef SENTINEL_DIVERSITY_SEED
        return 0;
#else
        // Simple compile-time hash: (seed + structId) % 16
        constexpr uint64_t seed = SENTINEL_DIVERSITY_SEED;
        constexpr uint64_t hash = ((seed ^ StructId) * 0x9e3779b97f4a7c15ULL) >> 60;
        return static_cast<size_t>(hash & 0xF); // 0-15 bytes
#endif
    }

    static constexpr size_t PaddingSize = CalculatePaddingSize();

private:
    // Padding array sized based on compile-time calculation
    uint8_t padding[PaddingSize > 0 ? PaddingSize : 1]; // At least 1 to avoid zero-size array
};

/**
 * Compile-time diversity padding macro
 * Injects variable-size padding based on diversity seed and line number
 * Uses inline assembly for guaranteed code diversity
 */
#ifndef SENTINEL_DIVERSITY_SEED
#define SENTINEL_DIVERSITY_PADDING(line) 
#else
// Use inline assembly to inject NOPs that vary by line number and seed
// This creates actual code diversity that affects the binary
#if defined(__GNUC__) || defined(__clang__)
#define SENTINEL_DIVERSITY_PADDING(line) \
    __asm__ __volatile__( \
        ".rept %c0\n\t" \
        "nop\n\t" \
        ".endr" \
        : : "i" ((((SENTINEL_DIVERSITY_SEED ^ line) * 0x9e3779b97f4a7c15ULL) >> 56) & 0x1F) \
    )
#elif defined(_MSC_VER) && defined(_M_X64)
// MSVC x64 - use __nop() intrinsic (0-15 NOPs for better compatibility)
#define SENTINEL_DIVERSITY_PADDING(line) \
    do { \
        constexpr int nop_count = (((SENTINEL_DIVERSITY_SEED ^ line) * 0x9e3779b97f4a7c15ULL) >> 60) & 0xF; \
        if constexpr (nop_count >= 1) __nop(); \
        if constexpr (nop_count >= 2) __nop(); \
        if constexpr (nop_count >= 3) __nop(); \
        if constexpr (nop_count >= 4) __nop(); \
        if constexpr (nop_count >= 5) __nop(); \
        if constexpr (nop_count >= 6) __nop(); \
        if constexpr (nop_count >= 7) __nop(); \
        if constexpr (nop_count >= 8) __nop(); \
        if constexpr (nop_count >= 9) __nop(); \
        if constexpr (nop_count >= 10) __nop(); \
        if constexpr (nop_count >= 11) __nop(); \
        if constexpr (nop_count >= 12) __nop(); \
        if constexpr (nop_count >= 13) __nop(); \
        if constexpr (nop_count >= 14) __nop(); \
        if constexpr (nop_count >= 15) __nop(); \
    } while(0)
#else
// Fallback for other compilers
#define SENTINEL_DIVERSITY_PADDING(line) \
    [[maybe_unused]] volatile char __diversity_pad_##line[(((SENTINEL_DIVERSITY_SEED ^ line) * 0x9e3779b97f4a7c15ULL) >> 60) & 0x7] = {}
#endif
#endif

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
