/**
 * Sentinel SDK - Detection Correlation Engine
 * 
 * Prevents false-positive bans by correlating multiple independent signals
 * before triggering enforcement actions.
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
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
    Debugger = 0,        // Weight: 0.3 (reduced - easily spoofed)
    Timing = 1,          // Weight: 0.2
    Memory = 2,          // Weight: 0.3 (general memory)
    MemoryRWX = 3,       // Weight: 0.5 (RWX without signature)
    Hooks = 4,           // Weight: 0.7 (increased - critical functions)
    CorrelatedAnomaly = 5 // Weight: 0.9 (timing + memory correlated)
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
    std::string module_name;  // Changed from const char* to prevent use-after-free
    uint32_t scan_cycle;  // Track which scan cycle detected this
    uint32_t persistence_count;  // How many consecutive scans this signal persisted
};

/**
 * Accumulated correlation state
 */
struct CorrelationState {
    double score;  // Current correlation score (0.0 - 2.0+)
    std::vector<DetectionSignal> signals;  // Recent signals
    std::chrono::steady_clock::time_point last_update;
    uint32_t unique_categories;  // Bitmask of detected categories
    uint32_t current_scan_cycle;  // Current scan cycle counter
    std::chrono::steady_clock::time_point last_scan_time;  // Last scan timestamp
    bool has_correlated_anomaly;  // Track if timing + memory correlation detected
};

/**
 * Verified overlay information
 */
struct VerifiedOverlay {
    std::wstring module_path;
    std::wstring vendor_name;
    bool is_verified;
    
    VerifiedOverlay() 
        : is_verified(false)
    {}
};

/**
 * Known environment patterns to whitelist
 */
struct EnvironmentContext {
    std::vector<VerifiedOverlay> verified_overlays;
    bool is_vm_environment;
    bool is_cloud_gaming;
    
    EnvironmentContext() 
        : is_vm_environment(false)
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
     * Check if signal combination is a known false positive pattern
     */
    bool IsFalsePositivePattern() const;
    
    /**
     * Apply environmental penalty to score (30% reduction for VM/cloud)
     */
    double ApplyEnvironmentalPenalty(double base_score) const;
    
    /**
     * Check if signal has persisted long enough (3 scan cycles minimum)
     */
    bool HasPersistedLongEnough(const DetectionSignal& signal) const;
    
    /**
     * Detect correlated timing + memory anomaly
     */
    bool DetectCorrelatedAnomaly() const;
    
    /**
     * Detect and verify overlay DLLs using signature validation
     */
    void DetectAndVerifyOverlays();
    
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
    static constexpr double MIN_CORRELATION_THRESHOLD = 2.0;  // Requires multiple high-confidence signals
    static constexpr uint32_t MIN_UNIQUE_SIGNALS = 3;
    static constexpr uint32_t MIN_SIGNALS_FOR_CRITICAL = 2;
    static constexpr uint32_t MIN_PERSISTENCE_CYCLES = 3;  // Signals must persist 3 scan cycles
    static constexpr double MIN_SCAN_CYCLE_INTERVAL = 10.0;  // Minimum 10 seconds between scans
    static constexpr double ENVIRONMENTAL_PENALTY_FACTOR = 0.7;  // 30% reduction (multiply by 0.7)
    
    // Category weights (updated per requirements)
    static constexpr double WEIGHT_DEBUGGER = 0.3;  // Reduced - easily spoofed
    static constexpr double WEIGHT_TIMING = 0.2;
    static constexpr double WEIGHT_MEMORY = 0.3;  // General memory violations
    static constexpr double WEIGHT_MEMORY_RWX = 0.5;  // RWX memory without signature
    static constexpr double WEIGHT_HOOKS = 0.7;  // Increased - critical function hooks
    static constexpr double WEIGHT_CORRELATED_ANOMALY = 0.9;  // Timing + memory correlation
};

} // namespace SDK
} // namespace Sentinel
