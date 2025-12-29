/**
 * Sentinel SDK - Runtime Configuration System Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "Internal/RuntimeConfig.hpp"
#include <chrono>
#include <algorithm>

namespace Sentinel {
namespace SDK {

RuntimeConfig::RuntimeConfig()
    : last_update_time_ms_(0)
    , initialized_(false)
{
    // Initialize detection configs
    for (size_t i = 0; i < NUM_DETECTION_TYPES; ++i) {
        detection_configs_[i] = DetectionConfig();
    }
}

RuntimeConfig::~RuntimeConfig() {
    Shutdown();
}

void RuntimeConfig::Initialize() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    last_update_time_ms_ = GetCurrentTimeMs();
    initialized_ = true;
}

void RuntimeConfig::Shutdown() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    initialized_ = false;
}

bool RuntimeConfig::IsDetectionEnabled(DetectionType type) const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    size_t index = TypeToIndex(type);
    if (index >= NUM_DETECTION_TYPES) {
        return false;
    }
    
    const DetectionConfig& config = detection_configs_[index];
    
    // Check if auto-disabled or manually disabled
    return config.enabled && !config.auto_disabled;
}

bool RuntimeConfig::IsDetectionDryRun(DetectionType type) const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    // Check global dry-run first
    if (global_config_.dry_run_mode) {
        return true;
    }
    
    size_t index = TypeToIndex(type);
    if (index >= NUM_DETECTION_TYPES) {
        return false;
    }
    
    return detection_configs_[index].dry_run;
}

void RuntimeConfig::SetDetectionEnabled(DetectionType type, bool enabled) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    size_t index = TypeToIndex(type);
    if (index >= NUM_DETECTION_TYPES) {
        return;
    }
    
    detection_configs_[index].enabled = enabled;
    
    // Clear auto-disabled flag if manually enabling
    if (enabled) {
        detection_configs_[index].auto_disabled = false;
    }
}

void RuntimeConfig::SetDetectionDryRun(DetectionType type, bool dry_run) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    size_t index = TypeToIndex(type);
    if (index >= NUM_DETECTION_TYPES) {
        return;
    }
    
    detection_configs_[index].dry_run = dry_run;
}

void RuntimeConfig::SetGlobalDryRun(bool dry_run) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    global_config_.dry_run_mode = dry_run;
}

bool RuntimeConfig::IsGlobalDryRun() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return global_config_.dry_run_mode;
}

void RuntimeConfig::RecordException(DetectionType type) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    if (!global_config_.auto_degradation_enabled) {
        return;
    }
    
    size_t index = TypeToIndex(type);
    if (index >= NUM_DETECTION_TYPES) {
        return;
    }
    
    DetectionConfig& config = detection_configs_[index];
    
    // Update exception window
    UpdateExceptionWindow(config);
    
    // Increment exception count
    config.exception_count++;
    
    // Apply auto-degradation if threshold exceeded
    ApplyAutoDegradation(config, type);
}

bool RuntimeConfig::ShouldEnforce(DetectionType type, float confidence) const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    size_t index = TypeToIndex(type);
    if (index >= NUM_DETECTION_TYPES) {
        return false;
    }
    
    const DetectionConfig& config = detection_configs_[index];
    
    // Don't enforce if disabled, auto-disabled, or in dry-run
    if (!config.enabled || config.auto_disabled || config.dry_run || global_config_.dry_run_mode) {
        return false;
    }
    
    // Check confidence threshold
    return confidence >= config.confidence_threshold;
}

bool RuntimeConfig::LoadFromServer() {
    // TODO: Implement server configuration loading
    // For now, this is a stub that would make HTTP request to server_endpoint
    // and parse JSON configuration
    return false;
}

bool RuntimeConfig::LoadFromJson(const std::string& json) {
    // TODO: Implement JSON parsing
    // This would parse JSON and update configuration
    // For minimal implementation, this is a stub
    (void)json;
    return false;
}

const DetectionConfig& RuntimeConfig::GetDetectionConfig(DetectionType type) const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    size_t index = TypeToIndex(type);
    if (index >= NUM_DETECTION_TYPES) {
        static DetectionConfig empty_config;
        return empty_config;
    }
    
    return detection_configs_[index];
}

const GlobalConfig& RuntimeConfig::GetGlobalConfig() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return global_config_;
}

void RuntimeConfig::ResetExceptionCounters() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    for (size_t i = 0; i < NUM_DETECTION_TYPES; ++i) {
        detection_configs_[i].exception_count = 0;
        detection_configs_[i].exception_window_start_ms = GetCurrentTimeMs();
        detection_configs_[i].auto_disabled = false;
    }
}

void RuntimeConfig::CheckForUpdates() {
    uint64_t current_time;
    uint64_t elapsed;
    
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        current_time = GetCurrentTimeMs();
        elapsed = current_time - last_update_time_ms_;
    }
    
    // Check if update interval has passed
    if (elapsed >= global_config_.config_update_interval_ms) {
        // Make network request without holding the lock
        bool update_success = LoadFromServer();
        
        // Update timestamp if successful
        if (update_success) {
            std::lock_guard<std::mutex> lock(config_mutex_);
            last_update_time_ms_ = current_time;
        }
    }
}

void RuntimeConfig::UpdateExceptionWindow(DetectionConfig& config) {
    uint64_t current_time = GetCurrentTimeMs();
    uint64_t elapsed = current_time - config.exception_window_start_ms;
    
    // Reset window if it has expired
    if (elapsed >= global_config_.exception_window_ms) {
        config.exception_window_start_ms = current_time;
        config.exception_count = 0;
    }
}

void RuntimeConfig::ApplyAutoDegradation(DetectionConfig& config, DetectionType type) {
    // Check if threshold exceeded
    if (config.exception_count >= global_config_.exception_threshold) {
        config.auto_disabled = true;
        
        // Log the auto-disable event
        // In production, this would send an alert
        (void)type;  // Suppress unused parameter warning
    }
}

uint64_t RuntimeConfig::GetCurrentTimeMs() const {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto duration = now.time_since_epoch();
    return duration_cast<milliseconds>(duration).count();
}

size_t RuntimeConfig::TypeToIndex(DetectionType type) const {
    size_t index = static_cast<size_t>(type);
    // Validate index is within bounds
    if (index >= NUM_DETECTION_TYPES) {
        // Return 0 (Unknown) for invalid types - safer than returning last index
        return 0;
    }
    return index;
}

} // namespace SDK
} // namespace Sentinel
