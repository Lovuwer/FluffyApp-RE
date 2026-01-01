/**
 * Sentinel SDK - Scan Scheduler with Randomized Timing
 * 
 * Task 9: Detection Timing Randomization
 * 
 * Purpose:
 * Prevents predictable detection timing that enables just-in-time cheat deactivation.
 * Implements cryptographically secure randomization with configurable bounds and
 * burst scanning capability.
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#pragma once

#include <cstdint>
#include <atomic>
#include <mutex>
#include <chrono>
#include <vector>
#include <array>

namespace Sentinel {
namespace SDK {

/**
 * Types of scans that can be scheduled
 */
enum class ScanType : uint8_t {
    QuickIntegrity,     ///< Quick integrity check
    FullIntegrity,      ///< Full integrity scan
    HookDetection,      ///< Hook detection scan
    DebugDetection,     ///< Debugger detection
    SpeedHack,          ///< Speed hack validation
    InjectionScan       ///< Injection detection
};

/**
 * Scan priority levels
 */
enum class ScanPriority : uint8_t {
    Normal,             ///< Regular scheduled scan
    Elevated,           ///< Elevated priority (e.g., after behavioral signal)
    Critical            ///< Critical burst scan (immediate execution)
};

/**
 * Configuration for scan scheduling
 */
struct ScanSchedulerConfig {
    // Interval bounds (milliseconds)
    uint32_t min_interval_ms = 500;      ///< Minimum interval between scans
    uint32_t max_interval_ms = 2000;     ///< Maximum interval between scans
    uint32_t mean_interval_ms = 1000;    ///< Target mean interval
    
    // Burst scan configuration
    bool enable_burst_scans = true;      ///< Enable burst scanning
    uint32_t burst_min_interval_ms = 50; ///< Minimum interval during burst
    uint32_t burst_max_interval_ms = 200;///< Maximum interval during burst
    uint32_t burst_duration_ms = 5000;   ///< Duration of burst mode
    
    // Randomization parameters
    bool vary_scan_order = true;         ///< Randomize order of scan types
    bool vary_scan_scope = true;         ///< Vary scope (quick vs full)
    
    // Behavioral triggers
    float burst_trigger_threshold = 0.7f; ///< Correlation score threshold for burst
};

/**
 * Statistics for scan timing analysis
 */
struct ScanTimingStats {
    uint64_t total_scans = 0;
    uint64_t intervals_recorded = 0;
    uint64_t min_interval_observed = UINT64_MAX;
    uint64_t max_interval_observed = 0;
    double mean_interval = 0.0;
    double variance = 0.0;
    uint64_t burst_scans = 0;
    uint64_t normal_scans = 0;
    
    // Distribution buckets for statistical analysis (10 buckets)
    std::array<uint32_t, 10> interval_distribution = {};
};

/**
 * Scan Scheduler with Cryptographically Secure Randomization
 * 
 * Provides unpredictable scan timing to prevent timing-based evasion:
 * - Uses OS-provided CSPRNG for interval generation
 * - Varies scan intervals by at least 50% from mean
 * - Randomizes scan order and scope
 * - Supports burst scanning on behavioral triggers
 * - No observable timing patterns or side-channels
 */
class ScanScheduler {
public:
    ScanScheduler();
    ~ScanScheduler();
    
    /**
     * Initialize the scheduler
     * @param config Configuration parameters
     */
    void Initialize(const ScanSchedulerConfig& config);
    
    /**
     * Shutdown the scheduler
     */
    void Shutdown();
    
    /**
     * Get next scan interval in milliseconds
     * Uses cryptographically secure randomness
     * @return Random interval within configured bounds
     */
    uint32_t GetNextInterval();
    
    /**
     * Check if it's time to perform a scan
     * @return true if scan should be performed now
     */
    bool ShouldScan();
    
    /**
     * Get the next scan type to execute
     * Order is randomized if configured
     * @return Next scan type to perform
     */
    ScanType GetNextScanType();
    
    /**
     * Trigger burst scan mode
     * @param duration_ms Duration to remain in burst mode (0 = use config default)
     */
    void TriggerBurstMode(uint32_t duration_ms = 0);
    
    /**
     * Check if currently in burst mode
     * @return true if in burst scan mode
     */
    bool IsInBurstMode() const;
    
    /**
     * Record a behavioral signal that may trigger burst mode
     * @param signal_strength Strength of the signal (0.0 - 1.0)
     */
    void RecordBehavioralSignal(float signal_strength);
    
    /**
     * Mark that a scan has been completed
     * Updates timing statistics
     */
    void MarkScanComplete();
    
    /**
     * Get current timing statistics
     * @param stats Output statistics structure
     */
    void GetStatistics(ScanTimingStats& stats) const;
    
    /**
     * Reset statistics counters
     */
    void ResetStatistics();
    
    /**
     * Get time until next scan in milliseconds
     * @return Milliseconds until next scheduled scan
     */
    uint32_t GetTimeUntilNextScan() const;
    
private:
    /**
     * Generate cryptographically secure random number in range [min, max]
     * @param min Minimum value (inclusive)
     * @param max Maximum value (inclusive)
     * @return Random value in range
     */
    uint32_t GenerateSecureRandom(uint32_t min, uint32_t max);
    
    /**
     * Generate random interval based on current mode
     * @return Interval in milliseconds
     */
    uint32_t GenerateInterval();
    
    /**
     * Update timing statistics
     * @param interval Last interval duration
     */
    void UpdateStatistics(uint32_t interval);
    
    /**
     * Shuffle scan type order
     */
    void ShuffleScanOrder();
    
    /**
     * Get current time in milliseconds
     * @return Milliseconds since epoch
     */
    uint64_t GetCurrentTimeMs() const;
    
    // Configuration
    ScanSchedulerConfig config_;
    
    // State
    std::atomic<bool> initialized_{false};
    std::atomic<bool> burst_mode_{false};
    
    // Timing
    uint64_t last_scan_time_ms_ = 0;
    uint64_t next_scan_time_ms_ = 0;
    uint64_t burst_mode_end_time_ms_ = 0;
    
    // Scan order randomization
    std::vector<ScanType> scan_order_;
    size_t current_scan_index_ = 0;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    ScanTimingStats stats_;
    std::vector<uint32_t> interval_history_;  // For variance calculation
    
    // Random state (platform-specific)
#ifdef _WIN32
    void* hCryptProv_ = nullptr;  // HCRYPTPROV handle
#else
    int urandom_fd_ = -1;         // /dev/urandom file descriptor
#endif
    
    // Behavioral signal tracking
    std::atomic<float> last_signal_strength_{0.0f};
    uint64_t last_signal_time_ms_ = 0;
    
    // Constants
    static constexpr size_t MAX_INTERVAL_HISTORY = 1000;  ///< Keep last 1000 intervals
    static constexpr uint64_t SIGNAL_TIMEOUT_MS = 10000;  ///< Signal relevance timeout
};

} // namespace SDK
} // namespace Sentinel
