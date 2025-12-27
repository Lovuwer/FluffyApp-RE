/**
 * Sentinel SDK - Detection Correlation Engine
 * 
 * Prevents false-positive bans by correlating multiple independent signals
 * before triggering enforcement actions.
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#pragma once

#include "SentinelSDK.hpp"
#include <unordered_map>
#include <vector>
#include <chrono>
#include <mutex>
#include <string>

namespace Sentinel {
namespace SDK {

/**
 * Detection signal categories for weighting
 */
enum class DetectionCategory : uint8_t {
    Debugger = 0,   // Weight: 0.4
    Timing = 1,     // Weight: 0.2
    Memory = 2,     // Weight: 0.3
    Hooks = 3       // Weight: 0.1
};

/**
 * Individual detection signal record
 */
struct DetectionSignal {
    ViolationType type;
    DetectionCategory category;
    Severity original_severity;
    std::chrono::steady_clock::time_point timestamp;
    std::string details;
    uint64_t address;
    const char* module_name;
};

/**
 * Accumulated correlation state
 */
struct CorrelationState {
    double score;  // Current correlation score (0.0 - 1.0+)
    std::vector<DetectionSignal> signals;  // Recent signals
    std::chrono::steady_clock::time_point last_update;
    uint32_t unique_categories;  // Bitmask of detected categories
};

/**
 * Known environment patterns to whitelist
 */
struct EnvironmentContext {
    bool has_discord_overlay;
    bool has_obs_overlay;
    bool has_steam_overlay;
    bool has_nvidia_overlay;
    bool is_vm_environment;
    bool is_cloud_gaming;
    
    EnvironmentContext() 
        : has_discord_overlay(false)
        , has_obs_overlay(false)
        , has_steam_overlay(false)
        , has_nvidia_overlay(false)
        , is_vm_environment(false)
        , is_cloud_gaming(false)
    {}
};

/**
 * Detection Correlation Engine
 * 
 * Implements multi-signal correlation to prevent false-positive bans.
 * Key features:
 * - Score-based accumulation with time-decay (30-second half-life)
 * - Category-based weighting (debugger > memory > timing > hooks)
 * - Minimum 3+ independent signals for enforcement
 * - Environment-aware whitelisting (overlays, VMs, cloud gaming)
 * - Severity degradation for single signals
 */
class CorrelationEngine {
public:
    CorrelationEngine();
    ~CorrelationEngine();
    
    /**
     * Initialize the correlation engine
     */
    void Initialize();
    
    /**
     * Shutdown the correlation engine
     */
    void Shutdown();
    
    /**
     * Process a violation event through correlation
     * Returns the correlated severity and whether to report
     * 
     * @param event Original violation event
     * @param out_correlated_severity Output severity after correlation
     * @param out_should_report Whether this should be reported
     * @return true if event passed correlation, false if suppressed
     */
    bool ProcessViolation(
        const ViolationEvent& event,
        Severity& out_correlated_severity,
        bool& out_should_report);
    
    /**
     * Check if a response action should be allowed
     * Ban and Terminate actions require multi-signal confirmation
     * 
     * @param action The response action to validate
     * @return true if action is allowed, false if blocked by correlation
     */
    bool ShouldAllowAction(ResponseAction action) const;
    
    /**
     * Get current correlation score (0.0 - 1.0+)
     */
    double GetCorrelationScore() const;
    
    /**
     * Get number of unique detection categories
     */
    uint32_t GetUniqueSignalCount() const;
    
    /**
     * Reset correlation state (for testing)
     */
    void Reset();

private:
    /**
     * Map violation type to detection category
     */
    DetectionCategory MapToCategory(ViolationType type) const;
    
    /**
     * Get weight for detection category
     */
    double GetCategoryWeight(DetectionCategory category) const;
    
    /**
     * Apply time-decay to correlation score
     * Uses 30-second half-life exponential decay
     */
    void ApplyTimeDecay();
    
    /**
     * Update correlation state with new signal
     */
    void UpdateCorrelation(const DetectionSignal& signal);
    
    /**
     * Degrade severity based on correlation rules
     */
    Severity DegradeSeverity(Severity original) const;
    
    /**
     * Detect environment context (overlays, VMs, etc.)
     */
    void DetectEnvironment();
    
    /**
     * Check if violation should be whitelisted based on environment
     */
    bool ShouldWhitelist(const ViolationEvent& event) const;
    
    /**
     * Check for known overlay DLLs
     */
    bool DetectOverlayDLLs();
    
    /**
     * Check for VM environment
     */
    bool DetectVMEnvironment();
    
    /**
     * Check for cloud gaming signatures
     */
    bool DetectCloudGaming();
    
    // Correlation state
    CorrelationState state_;
    
    // Environment context
    EnvironmentContext environment_;
    
    // Thread safety
    mutable std::mutex mutex_;
    
    // Configuration
    static constexpr double HALF_LIFE_SECONDS = 30.0;
    static constexpr double MIN_CORRELATION_THRESHOLD = 0.6;  // Requires ~3 signals
    static constexpr uint32_t MIN_UNIQUE_SIGNALS = 3;
    static constexpr uint32_t MIN_SIGNALS_FOR_CRITICAL = 2;
    
    // Category weights
    static constexpr double WEIGHT_DEBUGGER = 0.4;
    static constexpr double WEIGHT_TIMING = 0.2;
    static constexpr double WEIGHT_MEMORY = 0.3;
    static constexpr double WEIGHT_HOOKS = 0.1;
};

} // namespace SDK
} // namespace Sentinel
