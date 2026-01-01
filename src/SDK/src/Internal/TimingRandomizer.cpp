/**
 * Sentinel SDK - Timing Randomizer Implementation
 * 
 * Task 22: Runtime Behavior Variation
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include "TimingRandomizer.hpp"
#include <algorithm>
#include <stdexcept>

namespace Sentinel {
namespace SDK {

TimingRandomizer::TimingRandomizer()
    : initialized_(false)
    , operation_count_(0)
    , total_base_value_(0)
    , total_actual_value_(0)
{
    // Deferred initialization
}

bool TimingRandomizer::EnsureInitialized() {
    // Double-checked locking for thread-safe initialization
    if (initialized_) {
        return true;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_) {
        return true;
    }
    
    try {
        secure_random_ = std::make_unique<Sentinel::Crypto::SecureRandom>();
        
        // Test the random generator
        auto test_result = secure_random_->generateValue<uint32_t>();
        if (test_result.isFailure()) {
            SENTINEL_LOG_ERROR("Failed to initialize SecureRandom for TimingRandomizer");
            return false;
        }
        
        initialized_ = true;
        SENTINEL_LOG_DEBUG("TimingRandomizer initialized successfully");
        return true;
    } catch (const std::exception& e) {
        SENTINEL_LOG_ERROR_F("Exception initializing TimingRandomizer: %s", e.what());
        return false;
    }
}

bool TimingRandomizer::IsHealthy() const {
    if (!initialized_ || !secure_random_) {
        return false;
    }
    return secure_random_->isHealthy();
}

uint32_t TimingRandomizer::GenerateSecureRandom(uint32_t min, uint32_t max) {
    if (!EnsureInitialized()) {
        // Fallback: return midpoint if randomization fails
        SENTINEL_LOG_WARNING("TimingRandomizer not initialized, using midpoint fallback");
        return (min + max) / 2;
    }
    
    if (min > max) {
        std::swap(min, max);
    }
    
    if (min == max) {
        return min;
    }
    
    uint32_t range = max - min + 1;
    
    // Generate random value
    auto result = secure_random_->generateValue<uint32_t>();
    if (result.isFailure()) {
        SENTINEL_LOG_WARNING("Failed to generate random value, using midpoint");
        return (min + max) / 2;
    }
    
    uint32_t random_value = result.value();
    
    // Use rejection sampling to ensure uniform distribution
    // This prevents modulo bias when UINT32_MAX+1 is not divisible by range
    uint32_t limit = UINT32_MAX - (UINT32_MAX % range);
    
    int retry_count = 0;
    while (random_value >= limit && retry_count < 10) {
        // Retry if value would cause bias
        auto retry_result = secure_random_->generateValue<uint32_t>();
        if (retry_result.isFailure()) {
            // If we can't get more randomness, use what we have
            break;
        }
        random_value = retry_result.value();
        retry_count++;
    }
    
    return min + (random_value % range);
}

uint32_t TimingRandomizer::AddJitter(uint32_t base_value_ms, uint32_t variation_percent) {
    if (base_value_ms == 0) {
        return 0;
    }
    
    // Clamp variation percent to reasonable bounds [10%, 100%]
    const uint32_t original_variation = variation_percent;
    variation_percent = std::max(10u, std::min(100u, variation_percent));
    
    // Log if clamping occurred (could indicate a programming error)
    if (original_variation != variation_percent) {
        SENTINEL_LOG_WARNING_F("[TimingRandomizer] Variation percent clamped from %u%% to %u%%",
                                original_variation, variation_percent);
    }
    
    // Calculate bounds: base * (1 - variation/100) to base * (1 + variation/100)
    // Use 64-bit to prevent overflow
    uint64_t base64 = static_cast<uint64_t>(base_value_ms);
    uint64_t min_value = (base64 * (100 - variation_percent)) / 100;
    uint64_t max_value = (base64 * (100 + variation_percent)) / 100;
    
    // Clamp to uint32_t range
    uint32_t min_ms = static_cast<uint32_t>(std::min(min_value, static_cast<uint64_t>(UINT32_MAX)));
    uint32_t max_ms = static_cast<uint32_t>(std::min(max_value, static_cast<uint64_t>(UINT32_MAX)));
    
    // Generate random value in range
    uint32_t actual_value = GenerateSecureRandom(min_ms, max_ms);
    
    // Log the variation
    LogVariation("AddJitter", base_value_ms, actual_value, variation_percent);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(mutex_);
        operation_count_++;
        total_base_value_ += base_value_ms;
        total_actual_value_ += actual_value;
    }
    
    return actual_value;
}

uint32_t TimingRandomizer::GenerateInRange(uint32_t min_value_ms, uint32_t max_value_ms) {
    if (min_value_ms > max_value_ms) {
        std::swap(min_value_ms, max_value_ms);
    }
    
    uint32_t actual_value = GenerateSecureRandom(min_value_ms, max_value_ms);
    
    // Log the variation
    uint32_t midpoint = (min_value_ms + max_value_ms) / 2;
    LogVariation("GenerateInRange", midpoint, actual_value, 0);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(mutex_);
        operation_count_++;
        total_base_value_ += midpoint;
        total_actual_value_ += actual_value;
    }
    
    return actual_value;
}

void TimingRandomizer::LogVariation(const char* operation_type, uint32_t base_value,
                                    uint32_t actual_value, uint32_t variation_percent) {
    // Internal logging only - not exposed externally
    SENTINEL_LOG_DEBUG_F("[TimingVariation] op=%s base=%ums actual=%ums variation=%u%% diff=%dms",
                         operation_type,
                         base_value,
                         actual_value,
                         variation_percent,
                         static_cast<int32_t>(actual_value) - static_cast<int32_t>(base_value));
}

} // namespace SDK
} // namespace Sentinel
