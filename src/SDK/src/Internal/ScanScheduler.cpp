/**
 * Sentinel SDK - Scan Scheduler Implementation
 * 
 * Task 9: Detection Timing Randomization
 * Task 22: Runtime Behavior Variation - Added internal logging
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include "ScanScheduler.hpp"
#include <Sentinel/Core/Logger.hpp>
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <cstring>

#ifdef _WIN32
#include <Windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

namespace Sentinel {
namespace SDK {

ScanScheduler::ScanScheduler() {
    // Initialize scan order with all types
    scan_order_ = {
        ScanType::QuickIntegrity,
        ScanType::HookDetection,
        ScanType::DebugDetection,
        ScanType::SpeedHack,
        ScanType::InjectionScan,
        ScanType::FullIntegrity
    };
}

ScanScheduler::~ScanScheduler() {
    Shutdown();
}

void ScanScheduler::Initialize(const ScanSchedulerConfig& config) {
    if (initialized_.load(std::memory_order_acquire)) {
        return;  // Already initialized
    }
    
    config_ = config;
    
    // Validate configuration
    if (config_.min_interval_ms >= config_.max_interval_ms) {
        throw std::invalid_argument("min_interval_ms must be less than max_interval_ms");
    }
    
    if (config_.mean_interval_ms < config_.min_interval_ms || 
        config_.mean_interval_ms > config_.max_interval_ms) {
        throw std::invalid_argument("mean_interval_ms must be between min and max");
    }
    
    // Verify at least 50% variation from mean as per requirements
    uint32_t required_min = static_cast<uint32_t>(config_.mean_interval_ms * 0.5);
    uint32_t required_max = static_cast<uint32_t>(config_.mean_interval_ms * 1.5);
    if (config_.min_interval_ms > required_min || config_.max_interval_ms < required_max) {
        throw std::invalid_argument("Configuration does not meet 50% variation requirement");
    }
    
    // Task 22: Log configuration parameters internally
    SENTINEL_LOG_DEBUG_F("[ScanScheduler] Initializing with timing variation: "
                         "min=%ums, max=%ums, mean=%ums (%.1f%% variation)",
                         config_.min_interval_ms,
                         config_.max_interval_ms,
                         config_.mean_interval_ms,
                         ((config_.max_interval_ms - config_.min_interval_ms) * 100.0f / config_.mean_interval_ms));
    
    if (config_.enable_burst_scans) {
        SENTINEL_LOG_DEBUG_F("[ScanScheduler] Burst mode enabled: "
                             "min=%ums, max=%ums, duration=%ums, threshold=%.2f",
                             config_.burst_min_interval_ms,
                             config_.burst_max_interval_ms,
                             config_.burst_duration_ms,
                             config_.burst_trigger_threshold);
    }
    
#ifdef _WIN32
    // Initialize Windows Crypto API for CSPRNG
    if (!CryptAcquireContextW(
        reinterpret_cast<HCRYPTPROV*>(&hCryptProv_),
        nullptr,
        nullptr,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        throw std::runtime_error("Failed to initialize cryptographic provider");
    }
#else
    // Open /dev/urandom for cryptographically secure random numbers
    urandom_fd_ = open("/dev/urandom", O_RDONLY);
    if (urandom_fd_ < 0) {
        throw std::runtime_error("Failed to open /dev/urandom");
    }
#endif
    
    // Initialize timing
    last_scan_time_ms_ = GetCurrentTimeMs();
    next_scan_time_ms_ = last_scan_time_ms_ + GenerateInterval();
    
    // Shuffle initial scan order
    if (config_.vary_scan_order) {
        ShuffleScanOrder();
        SENTINEL_LOG_DEBUG("[ScanScheduler] Scan order randomization enabled");
    }
    
    initialized_.store(true, std::memory_order_release);
    SENTINEL_LOG_INFO("[ScanScheduler] Initialized successfully with randomized timing");
}

void ScanScheduler::Shutdown() {
    if (!initialized_.load(std::memory_order_acquire)) {
        return;
    }
    
#ifdef _WIN32
    if (hCryptProv_) {
        CryptReleaseContext(reinterpret_cast<HCRYPTPROV>(hCryptProv_), 0);
        hCryptProv_ = nullptr;
    }
#else
    if (urandom_fd_ >= 0) {
        close(urandom_fd_);
        urandom_fd_ = -1;
    }
#endif
    
    initialized_.store(false, std::memory_order_release);
}

uint32_t ScanScheduler::GenerateSecureRandom(uint32_t min, uint32_t max) {
    if (min > max) {
        std::swap(min, max);
    }
    
    if (min == max) {
        return min;
    }
    
    uint32_t range = max - min + 1;
    uint32_t random_value = 0;
    
#ifdef _WIN32
    // Use Windows Crypto API
    if (!CryptGenRandom(
        reinterpret_cast<HCRYPTPROV>(hCryptProv_),
        sizeof(random_value),
        reinterpret_cast<BYTE*>(&random_value))) {
        // Fallback: this should never happen in production
        throw std::runtime_error("Failed to generate random number");
    }
#else
    // Read from /dev/urandom
    ssize_t bytes_read = read(urandom_fd_, &random_value, sizeof(random_value));
    if (bytes_read != sizeof(random_value)) {
        throw std::runtime_error("Failed to read from /dev/urandom");
    }
#endif
    
    // Ensure uniform distribution using rejection sampling to prevent modulo bias
    // Rejection sampling: If we simply did (random % range), values near 0 would be
    // slightly more likely when UINT32_MAX+1 is not divisible by range. We compute
    // the largest multiple of range that fits in uint32_t and reject values above it.
    // This ensures every value in [0, range) has exactly equal probability.
    uint32_t limit = UINT32_MAX - (UINT32_MAX % range);
    while (random_value >= limit) {
        // Retry if value would cause bias
#ifdef _WIN32
        if (!CryptGenRandom(
            reinterpret_cast<HCRYPTPROV>(hCryptProv_),
            sizeof(random_value),
            reinterpret_cast<BYTE*>(&random_value))) {
            throw std::runtime_error("Failed to generate random number");
        }
#else
        bytes_read = read(urandom_fd_, &random_value, sizeof(random_value));
        if (bytes_read != sizeof(random_value)) {
            throw std::runtime_error("Failed to read from /dev/urandom");
        }
#endif
    }
    
    return min + (random_value % range);
}

uint32_t ScanScheduler::GenerateInterval() {
    uint32_t min_interval, max_interval;
    
    if (burst_mode_.load(std::memory_order_acquire)) {
        min_interval = config_.burst_min_interval_ms;
        max_interval = config_.burst_max_interval_ms;
    } else {
        min_interval = config_.min_interval_ms;
        max_interval = config_.max_interval_ms;
    }
    
    uint32_t interval = GenerateSecureRandom(min_interval, max_interval);
    
    // Task 22: Log generated interval internally
    const char* mode = burst_mode_.load(std::memory_order_acquire) ? "burst" : "normal";
    SENTINEL_LOG_DEBUG_F("[ScanScheduler] Generated %s interval: %ums (range: %u-%u)",
                         mode, interval, min_interval, max_interval);
    
    return interval;
}

uint32_t ScanScheduler::GetNextInterval() {
    if (!initialized_.load(std::memory_order_acquire)) {
        throw std::runtime_error("ScanScheduler not initialized");
    }
    
    return GenerateInterval();
}

bool ScanScheduler::ShouldScan() {
    if (!initialized_.load(std::memory_order_acquire)) {
        return false;
    }
    
    uint64_t current_time = GetCurrentTimeMs();
    
    // Check if burst mode should end
    if (burst_mode_.load(std::memory_order_acquire)) {
        if (current_time >= burst_mode_end_time_ms_) {
            burst_mode_.store(false, std::memory_order_release);
            // Generate new normal interval
            next_scan_time_ms_ = current_time + GenerateInterval();
        }
    }
    
    return current_time >= next_scan_time_ms_;
}

ScanType ScanScheduler::GetNextScanType() {
    if (!initialized_.load(std::memory_order_acquire)) {
        return ScanType::QuickIntegrity;
    }
    
    // Get current scan type
    ScanType scan_type = scan_order_[current_scan_index_];
    
    // Advance to next type
    current_scan_index_ = (current_scan_index_ + 1) % scan_order_.size();
    
    // Periodically reshuffle if configured
    if (config_.vary_scan_order && current_scan_index_ == 0) {
        ShuffleScanOrder();
    }
    
    // Optionally vary scope (quick vs full) for integrity checks
    if (config_.vary_scan_scope) {
        if (scan_type == ScanType::QuickIntegrity || scan_type == ScanType::FullIntegrity) {
            // Randomly choose between quick and full (30% chance of full scan)
            uint32_t random = GenerateSecureRandom(0, 99);
            if (random < 30) {
                scan_type = ScanType::FullIntegrity;
            } else {
                scan_type = ScanType::QuickIntegrity;
            }
        }
    }
    
    return scan_type;
}

void ScanScheduler::TriggerBurstMode(uint32_t duration_ms) {
    if (!initialized_.load(std::memory_order_acquire)) {
        return;
    }
    
    if (!config_.enable_burst_scans) {
        return;  // Burst mode disabled
    }
    
    uint64_t current_time = GetCurrentTimeMs();
    uint32_t burst_duration = duration_ms > 0 ? duration_ms : config_.burst_duration_ms;
    
    burst_mode_.store(true, std::memory_order_release);
    burst_mode_end_time_ms_ = current_time + burst_duration;
    
    // Immediately schedule next scan with burst interval
    next_scan_time_ms_ = current_time + GenerateInterval();
    
    // Task 22: Log burst mode activation
    SENTINEL_LOG_INFO_F("[ScanScheduler] Burst mode activated for %ums", burst_duration);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.burst_scans++;
    }
}

bool ScanScheduler::IsInBurstMode() const {
    return burst_mode_.load(std::memory_order_acquire);
}

void ScanScheduler::RecordBehavioralSignal(float signal_strength) {
    if (!initialized_.load(std::memory_order_acquire)) {
        return;
    }
    
    // Clamp signal strength to [0.0, 1.0]
    signal_strength = std::max(0.0f, std::min(1.0f, signal_strength));
    
    last_signal_strength_.store(signal_strength, std::memory_order_release);
    last_signal_time_ms_ = GetCurrentTimeMs();
    
    // Check if signal strength exceeds threshold
    if (signal_strength >= config_.burst_trigger_threshold) {
        TriggerBurstMode();
    }
}

void ScanScheduler::MarkScanComplete() {
    if (!initialized_.load(std::memory_order_acquire)) {
        return;
    }
    
    uint64_t current_time = GetCurrentTimeMs();
    
    // Calculate interval since last scan
    if (last_scan_time_ms_ > 0) {
        uint32_t interval = static_cast<uint32_t>(current_time - last_scan_time_ms_);
        UpdateStatistics(interval);
    }
    
    // Update timing
    last_scan_time_ms_ = current_time;
    next_scan_time_ms_ = current_time + GenerateInterval();
    
    // Update scan count
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_scans++;
        if (burst_mode_.load(std::memory_order_acquire)) {
            stats_.burst_scans++;
        } else {
            stats_.normal_scans++;
        }
    }
}

void ScanScheduler::GetStatistics(ScanTimingStats& stats) const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats = stats_;
}

void ScanScheduler::ResetStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = ScanTimingStats{};
    interval_history_.clear();
}

uint32_t ScanScheduler::GetTimeUntilNextScan() const {
    if (!initialized_.load(std::memory_order_acquire)) {
        return 0;
    }
    
    uint64_t current_time = GetCurrentTimeMs();
    if (current_time >= next_scan_time_ms_) {
        return 0;
    }
    
    return static_cast<uint32_t>(next_scan_time_ms_ - current_time);
}

void ScanScheduler::UpdateStatistics(uint32_t interval) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    // Update min/max
    if (interval < stats_.min_interval_observed) {
        stats_.min_interval_observed = interval;
    }
    if (interval > stats_.max_interval_observed) {
        stats_.max_interval_observed = interval;
    }
    
    // Store in history (circular buffer)
    if (interval_history_.size() >= MAX_INTERVAL_HISTORY) {
        interval_history_.erase(interval_history_.begin());
    }
    interval_history_.push_back(interval);
    
    stats_.intervals_recorded = interval_history_.size();
    
    // Calculate running mean
    double sum = 0.0;
    for (uint32_t val : interval_history_) {
        sum += val;
    }
    stats_.mean_interval = sum / interval_history_.size();
    
    // Calculate variance
    double variance_sum = 0.0;
    for (uint32_t val : interval_history_) {
        double diff = val - stats_.mean_interval;
        variance_sum += diff * diff;
    }
    stats_.variance = variance_sum / interval_history_.size();
    
    // Update distribution buckets
    constexpr size_t NUM_BUCKETS = 10;  // Match stats_.interval_distribution size
    uint32_t range = config_.max_interval_ms - config_.min_interval_ms;
    if (range > 0 && interval >= config_.min_interval_ms && interval <= config_.max_interval_ms) {
        // Ceiling division to ensure all intervals fit into buckets
        uint32_t bucket_size = (range + NUM_BUCKETS - 1) / NUM_BUCKETS;
        size_t bucket_index = (interval - config_.min_interval_ms) / bucket_size;
        if (bucket_index >= stats_.interval_distribution.size()) {
            bucket_index = stats_.interval_distribution.size() - 1;
        }
        stats_.interval_distribution[bucket_index]++;
    }
}

void ScanScheduler::ShuffleScanOrder() {
    // Fisher-Yates shuffle using cryptographically secure random
    for (size_t i = scan_order_.size() - 1; i > 0; --i) {
        size_t j = static_cast<size_t>(GenerateSecureRandom(0, static_cast<uint32_t>(i)));
        std::swap(scan_order_[i], scan_order_[j]);
    }
    
    // Reset index after shuffle
    current_scan_index_ = 0;
}

uint64_t ScanScheduler::GetCurrentTimeMs() const {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch());
    return static_cast<uint64_t>(duration.count());
}

} // namespace SDK
} // namespace Sentinel
