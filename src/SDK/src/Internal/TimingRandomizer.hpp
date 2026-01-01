/**
 * Sentinel SDK - Timing Randomizer
 * 
 * Task 22: Runtime Behavior Variation
 * 
 * Purpose:
 * Provides cryptographically secure timing variation for all SDK operations
 * to prevent timing-based evasion. Uses Sentinel::Crypto::SecureRandom for
 * high-quality randomness.
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#pragma once

#include <Sentinel/Core/Crypto.hpp>
#include <Sentinel/Core/Logger.hpp>
#include <cstdint>
#include <mutex>
#include <memory>

namespace Sentinel {
namespace SDK {

/**
 * Utility class for adding cryptographically secure random jitter to timing values
 * 
 * Provides consistent API for adding variation to any timing parameter while:
 * - Maintaining minimum 50% variation from base value
 * - Using cryptographically secure random source
 * - Internally logging all variation parameters
 * - Ensuring uniform distribution over time
 * 
 * Thread Safety:
 * - All public methods are thread-safe via mutex protection
 * - SecureRandom initialization is deferred until first use
 * - Uses double-checked locking for initialization
 */
class TimingRandomizer {
public:
    TimingRandomizer();
    ~TimingRandomizer() = default;
    
    /**
     * Apply random jitter to a timing value
     * @param base_value_ms Base timing value in milliseconds
     * @param variation_percent Percentage of variation (default 50%, clamped to [10%, 100%])
     * @return Randomized value within [base * (1 - variation/100), base * (1 + variation/100)]
     * 
     * Note: variation_percent is silently clamped to [10%, 100%] to prevent invalid configurations.
     * This ensures a reasonable variation range while preventing extreme values.
     * 
     * Example: AddJitter(1000, 50) returns value in range [500, 1500]
     */
    uint32_t AddJitter(uint32_t base_value_ms, uint32_t variation_percent = 50);
    
    /**
     * Generate random value in specified range
     * @param min_value_ms Minimum value (inclusive)
     * @param max_value_ms Maximum value (inclusive)
     * @return Random value in range [min_value_ms, max_value_ms]
     */
    uint32_t GenerateInRange(uint32_t min_value_ms, uint32_t max_value_ms);
    
    /**
     * Get number of jitter operations performed (for testing)
     * @return Count of timing randomizations
     */
    uint64_t GetOperationCount() const { return operation_count_; }
    
    /**
     * Check if randomizer is initialized and healthy
     * @return true if ready to use
     */
    bool IsHealthy() const;
    
private:
    /**
     * Ensure the secure random generator is initialized
     * @return true if initialization successful
     */
    bool EnsureInitialized();
    
    /**
     * Generate cryptographically secure random number in range
     * @param min Minimum value (inclusive)
     * @param max Maximum value (inclusive)
     * @return Random value in range
     */
    uint32_t GenerateSecureRandom(uint32_t min, uint32_t max);
    
    /**
     * Log timing variation internally (not exposed externally)
     * @param operation_type Type of timing operation
     * @param base_value Base timing value
     * @param actual_value Actual randomized value
     * @param variation_percent Variation percentage applied
     */
    void LogVariation(const char* operation_type, uint32_t base_value, 
                      uint32_t actual_value, uint32_t variation_percent);
    
    std::unique_ptr<Sentinel::Crypto::SecureRandom> secure_random_;
    mutable std::mutex mutex_;
    bool initialized_;
    uint64_t operation_count_;
    
    // Statistics for verification
    uint64_t total_base_value_;
    uint64_t total_actual_value_;
};

} // namespace SDK
} // namespace Sentinel
