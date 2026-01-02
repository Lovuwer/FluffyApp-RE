/**
 * Sentinel SDK - Runtime Configuration System
 * 
 * Provides server-controllable configuration for rapid response to
 * false positives and production issues. Supports per-detection-type
 * enable/disable flags and dry-run mode.
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#pragma once

#include "TelemetryEmitter.hpp"
#include <string>
#include <map>
#include <mutex>
#include <chrono>
#include <cstdint>

namespace Sentinel {
namespace SDK {

/**
 * Redundancy level for detection categories (Task 29)
 */
enum class RedundancyLevel : uint8_t {
    None = 0,       ///< Single implementation (default, legacy behavior)
    Standard = 1,   ///< Two implementations with different approaches
    High = 2,       ///< Three or more implementations
    Maximum = 3     ///< All available implementations (performance impact)
};

/**
 * Per-detection configuration
 */
struct DetectionConfig {
    bool enabled;                   // Master enable/disable flag
    bool dry_run;                   // Emit telemetry but no enforcement
    float confidence_threshold;     // Minimum confidence for enforcement
    uint32_t exception_count;       // Current exception count
    uint64_t exception_window_start_ms;  // Window start time
    bool auto_disabled;             // Auto-disabled due to exceptions
    
    // Task 29: Redundant detection configuration
    bool redundancy_enabled;        // Enable redundant implementations
    RedundancyLevel redundancy_level;  // Redundancy level for this detection
    
    DetectionConfig()
        : enabled(true)
        , dry_run(false)
        , confidence_threshold(0.7f)
        , exception_count(0)
        , exception_window_start_ms(0)
        , auto_disabled(false)
        , redundancy_enabled(false)
        , redundancy_level(RedundancyLevel::None)
    {}
};

/**
 * Global runtime configuration
 */
struct GlobalConfig {
    bool dry_run_mode;              // Global dry-run mode
    bool auto_degradation_enabled;  // Enable automatic degradation
    uint32_t exception_threshold;   // Exceptions before auto-disable
    uint64_t exception_window_ms;   // Time window for exception counting
    uint64_t config_update_interval_ms;  // How often to check for config updates
    std::string server_endpoint;    // Configuration server endpoint
    uint32_t exception_budget_per_scan;  // Maximum exceptions per scan before stopping
    
    GlobalConfig()
        : dry_run_mode(false)
        , auto_degradation_enabled(true)
        , exception_threshold(5)
        , exception_window_ms(60000)  // 60 seconds
        , config_update_interval_ms(300000)  // 5 minutes
        , exception_budget_per_scan(10)  // Stop scan after 10 exceptions
    {}
};

/**
 * Runtime Configuration Manager
 * 
 * Features:
 * - Per-detection-type enable/disable flags
 * - Server-controllable configuration (5-minute update interval)
 * - Automatic degradation on repeated exceptions (>5 in 60s)
 * - Dry-run mode for safe rollout of new detections
 * - Thread-safe configuration updates
 */
class RuntimeConfig {
public:
    RuntimeConfig();
    ~RuntimeConfig();
    
    /**
     * Initialize runtime configuration
     */
    void Initialize();
    
    /**
     * Shutdown runtime configuration
     */
    void Shutdown();
    
    /**
     * Check if a detection type is enabled
     * Returns false if disabled or auto-disabled
     */
    bool IsDetectionEnabled(DetectionType type) const;
    
    /**
     * Check if a detection type is in dry-run mode
     * In dry-run mode: emit telemetry but don't enforce
     */
    bool IsDetectionDryRun(DetectionType type) const;
    
    /**
     * Enable/disable a detection type
     * Can be called from server config updates
     */
    void SetDetectionEnabled(DetectionType type, bool enabled);
    
    /**
     * Set dry-run mode for a detection type
     */
    void SetDetectionDryRun(DetectionType type, bool dry_run);
    
    /**
     * Set global dry-run mode (affects all detections)
     */
    void SetGlobalDryRun(bool dry_run);
    
    /**
     * Check if global dry-run mode is enabled
     */
    bool IsGlobalDryRun() const;
    
    /**
     * Record an exception for automatic degradation
     * If threshold exceeded, auto-disables the detection
     */
    void RecordException(DetectionType type);
    
    /**
     * Check if detection should be enforced based on confidence
     */
    bool ShouldEnforce(DetectionType type, float confidence) const;
    
    /**
     * Load configuration from server
     * Returns true if successful
     */
    bool LoadFromServer();
    
    /**
     * Load configuration from JSON string
     * Returns true if successful
     */
    bool LoadFromJson(const std::string& json);
    
    /**
     * Get configuration for a detection type
     */
    const DetectionConfig& GetDetectionConfig(DetectionType type) const;
    
    /**
     * Get global configuration
     */
    const GlobalConfig& GetGlobalConfig() const;
    
    /**
     * Reset exception counters (for testing)
     */
    void ResetExceptionCounters();
    
    /**
     * Check for configuration updates (called periodically)
     */
    void CheckForUpdates();
    
    /**
     * Set redundancy configuration for a detection type (Task 29)
     * @param type Detection type
     * @param enabled Enable/disable redundancy
     * @param level Redundancy level to use
     */
    void SetRedundancyConfig(DetectionType type, bool enabled, RedundancyLevel level);
    
    /**
     * Get redundancy configuration for a detection type (Task 29)
     * @param type Detection type
     * @param out_enabled Output: whether redundancy is enabled
     * @param out_level Output: redundancy level
     */
    void GetRedundancyConfig(DetectionType type, bool& out_enabled, RedundancyLevel& out_level) const;

private:
    /**
     * Update exception window tracking
     */
    void UpdateExceptionWindow(DetectionConfig& config);
    
    /**
     * Apply automatic degradation if threshold exceeded
     */
    void ApplyAutoDegradation(DetectionConfig& config, DetectionType type);
    
    /**
     * Get current timestamp in milliseconds
     */
    uint64_t GetCurrentTimeMs() const;
    
    /**
     * Convert detection type to index
     */
    size_t TypeToIndex(DetectionType type) const;
    
    // Configuration storage
    GlobalConfig global_config_;
    // NOTE: NUM_DETECTION_TYPES must be updated when new DetectionType enum values are added
    // Current types: AntiDebug(0), AntiHook(1), MemoryIntegrity(2), SpeedHack(3), 
    //                InjectionDetect(4), NetworkAnomaly(5), Unknown(255)->index 6
    static constexpr size_t NUM_DETECTION_TYPES = 7;  // 6 valid types + 1 for Unknown
    DetectionConfig detection_configs_[NUM_DETECTION_TYPES];
    
    // Thread safety
    mutable std::mutex config_mutex_;
    
    // Last update time
    uint64_t last_update_time_ms_;
    
    // Initialized flag
    bool initialized_;
};

} // namespace SDK
} // namespace Sentinel
