/**
 * Sentinel SDK - Environment Detection
 * 
 * Detects cloud gaming platforms, VMs, and other environment characteristics
 * to adapt detection thresholds and prevent false positives.
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#pragma once

#include "SentinelSDK.hpp"
#include <cstdint>
#include <string>

namespace Sentinel {
namespace SDK {

/**
 * Environment type classification
 */
enum class EnvironmentType : uint8_t {
    Local = 0,      ///< Local gaming (native hardware)
    VM = 1,         ///< Virtual machine (non-streaming)
    CloudGaming = 2 ///< Cloud gaming platform (streaming)
};

/**
 * Detailed environment information
 */
struct EnvironmentInfo {
    EnvironmentType type;
    
    // Cloud gaming platform detection
    bool is_geforce_now;
    bool is_xbox_cloud_gaming;
    bool is_amazon_luna;
    bool is_playstation_now;
    
    // VM detection
    bool is_hypervisor_present;
    
    // Timing characteristics
    double timing_instability_score;  // 0.0 = stable, 1.0 = highly unstable
    
    // Network characteristics
    bool has_consistent_high_bandwidth_udp;
    
    EnvironmentInfo()
        : type(EnvironmentType::Local)
        , is_geforce_now(false)
        , is_xbox_cloud_gaming(false)
        , is_amazon_luna(false)
        , is_playstation_now(false)
        , is_hypervisor_present(false)
        , timing_instability_score(0.0)
        , has_consistent_high_bandwidth_udp(false)
    {}
};

/**
 * Environment Detection Module
 * 
 * Detects the execution environment to adapt anti-cheat thresholds:
 * - Cloud gaming platforms (GeForce Now, Xbox Cloud, etc.)
 * - Virtual machines (VMware, VirtualBox, Hyper-V, etc.)
 * - Timing instability patterns
 */
class EnvironmentDetector {
public:
    EnvironmentDetector();
    ~EnvironmentDetector();
    
    /**
     * Initialize environment detection
     */
    void Initialize();
    
    /**
     * Shutdown environment detection
     */
    void Shutdown();
    
    /**
     * Detect current environment
     * Performs all detection checks and updates internal state
     */
    void DetectEnvironment();
    
    /**
     * Get current environment information
     */
    const EnvironmentInfo& GetEnvironmentInfo() const;
    
    /**
     * Get environment type
     */
    EnvironmentType GetEnvironmentType() const;
    
    /**
     * Get timing variance threshold for current environment
     * - Local gaming: 15% (0.15)
     * - VM (non-streaming): 35% (0.35)
     * - Cloud gaming: 50% (0.50)
     */
    float GetTimingVarianceThreshold() const;
    
    /**
     * Update timing instability score
     * Called by SpeedHackDetector to track timing variance over time
     * 
     * @param variance_ratio Current timing variance (e.g., 0.05 = 5% variance)
     */
    void UpdateTimingInstability(double variance_ratio);
    
    /**
     * Check if environment is cloud gaming
     */
    bool IsCloudGaming() const;
    
    /**
     * Get environment string for telemetry
     * Returns "local", "vm", or "cloud"
     */
    const char* GetEnvironmentString() const;
    
private:
    /**
     * Detect cloud gaming platforms via process detection
     */
    bool DetectCloudGamingProcesses();
    
    /**
     * Detect cloud gaming via environment variables
     */
    bool DetectCloudGamingEnvironment();
    
    /**
     * Detect cloud gaming via audio device enumeration
     */
    bool DetectCloudGamingAudioDrivers();
    
    /**
     * Detect VM/hypervisor presence
     */
    bool DetectHypervisor();
    
    /**
     * Calculate timing instability score from variance history
     */
    void CalculateTimingInstabilityScore();
    
    // Environment state
    EnvironmentInfo env_info_;
    
    // Timing instability tracking
    static constexpr size_t VARIANCE_HISTORY_SIZE = 100;
    double variance_history_[VARIANCE_HISTORY_SIZE];
    size_t variance_history_index_;
    size_t variance_history_count_;
    
    // Threshold constants
    static constexpr float THRESHOLD_LOCAL = 0.15f;     // 15% for local gaming
    static constexpr float THRESHOLD_VM = 0.35f;        // 35% for VM
    static constexpr float THRESHOLD_CLOUD = 0.50f;     // 50% for cloud gaming
    
    // Timing instability detection
    static constexpr double HIGH_INSTABILITY_THRESHOLD = 0.3;  // 30% average variance
};

} // namespace SDK
} // namespace Sentinel
