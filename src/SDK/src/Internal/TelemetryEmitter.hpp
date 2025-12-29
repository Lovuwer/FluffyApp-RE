/**
 * Sentinel SDK - Production Telemetry Emitter
 * 
 * Provides structured telemetry for production anti-cheat monitoring,
 * false-positive analysis, and rapid response capability.
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#pragma once

#include "SentinelSDK.hpp"
#include "EnvironmentDetection.hpp"
#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <cstdint>

namespace Sentinel {
namespace SDK {

/**
 * Detection type classification for telemetry
 */
enum class DetectionType : uint8_t {
    AntiDebug = 0,
    AntiHook = 1,
    MemoryIntegrity = 2,
    SpeedHack = 3,
    InjectionDetect = 4,
    NetworkAnomaly = 5,
    Unknown = 255
};

/**
 * Correlation state snapshot for telemetry context
 */
struct CorrelationSnapshot {
    double current_score;
    uint32_t unique_categories;
    uint32_t signal_count;
    bool has_correlated_anomaly;
    
    CorrelationSnapshot()
        : current_score(0.0)
        , unique_categories(0)
        , signal_count(0)
        , has_correlated_anomaly(false)
    {}
};

/**
 * Structured telemetry event
 */
struct TelemetryEvent {
    // Core identification
    uint64_t timestamp_ms;              // Milliseconds since epoch
    DetectionType detection_type;
    ViolationType violation_type;
    Severity severity;
    
    // Detection details
    float confidence;                   // 0.0-1.0 confidence score
    uint64_t raw_data_hash;            // Hash of raw detection data (privacy)
    std::string details;               // Additional context
    uint64_t address;                  // Related memory address if applicable
    
    // Environment context
    bool is_vm;
    bool is_cloud_gaming;
    bool has_overlay;
    std::string environment_string;    // "local", "vm", or "cloud"
    
    // Correlation context
    CorrelationSnapshot correlation_state;
    
    // Performance metrics
    uint64_t scan_duration_us;         // Scan duration in microseconds
    size_t memory_scanned_bytes;       // Amount of memory scanned
    
    TelemetryEvent()
        : timestamp_ms(0)
        , detection_type(DetectionType::Unknown)
        , violation_type(ViolationType::None)
        , severity(Severity::Info)
        , confidence(0.0f)
        , raw_data_hash(0)
        , address(0)
        , is_vm(false)
        , is_cloud_gaming(false)
        , has_overlay(false)
        , scan_duration_us(0)
        , memory_scanned_bytes(0)
    {}
};

/**
 * Detection baseline tracking for anomaly detection
 */
struct DetectionBaseline {
    DetectionType type;
    uint64_t total_detections;
    uint64_t baseline_rate_per_hour;   // Normal detection rate
    uint64_t window_start_time_ms;
    uint64_t window_detections;
    bool is_anomalous;
    
    DetectionBaseline()
        : type(DetectionType::Unknown)
        , total_detections(0)
        , baseline_rate_per_hour(0)
        , window_start_time_ms(0)
        , window_detections(0)
        , is_anomalous(false)
    {}
};

/**
 * Production Telemetry Emitter
 * 
 * Features:
 * - Structured telemetry for every detection signal
 * - Environment context tracking (VM, cloud, overlay)
 * - Correlation state snapshots
 * - Performance metrics
 * - Anomaly detection (10x baseline threshold)
 * - Privacy-preserving raw data hashing
 */
class TelemetryEmitter {
public:
    TelemetryEmitter();
    ~TelemetryEmitter();
    
    /**
     * Initialize telemetry system
     */
    void Initialize();
    
    /**
     * Shutdown telemetry system
     */
    void Shutdown();
    
    /**
     * Set environment detector for context tracking
     */
    void SetEnvironmentDetector(EnvironmentDetector* detector);
    
    /**
     * Emit a telemetry event
     */
    void EmitEvent(const TelemetryEvent& event);
    
    /**
     * Create telemetry event from violation
     */
    TelemetryEvent CreateEventFromViolation(
        const ViolationEvent& violation,
        DetectionType detection_type,
        float confidence,
        const void* raw_data,
        size_t raw_data_size);
    
    /**
     * Update correlation state for next events
     */
    void UpdateCorrelationState(const CorrelationSnapshot& state);
    
    /**
     * Set performance metrics for next event
     */
    void SetPerformanceMetrics(uint64_t scan_duration_us, size_t memory_scanned);
    
    /**
     * Check if detection rate is anomalous (>10x baseline)
     */
    bool IsDetectionRateAnomalous(DetectionType type) const;
    
    /**
     * Get baseline for detection type
     */
    const DetectionBaseline& GetBaseline(DetectionType type) const;
    
    /**
     * Get all telemetry events (for testing/debugging)
     */
    std::vector<TelemetryEvent> GetEvents() const;
    
    /**
     * Clear all events (for testing)
     */
    void ClearEvents();
    
private:
    /**
     * Update baseline tracking
     */
    void UpdateBaseline(DetectionType type);
    
    /**
     * Check and flag anomalous detection rates
     */
    void CheckAnomalies(DetectionType type);
    
    /**
     * Compute hash of raw data for privacy
     */
    uint64_t ComputeDataHash(const void* data, size_t size) const;
    
    /**
     * Get current timestamp in milliseconds
     */
    uint64_t GetCurrentTimeMs() const;
    
    // Environment detector (optional, set by SDK)
    EnvironmentDetector* env_detector_;
    
    // Current correlation state
    CorrelationSnapshot current_correlation_state_;
    
    // Performance metrics for next event
    uint64_t current_scan_duration_us_;
    size_t current_memory_scanned_;
    
    // Telemetry event storage
    std::vector<TelemetryEvent> events_;
    mutable std::mutex events_mutex_;
    
    // Baseline tracking (one per detection type)
    // NOTE: NUM_DETECTION_TYPES must be updated when new DetectionType enum values are added
    // Current types: AntiDebug, AntiHook, MemoryIntegrity, SpeedHack, InjectionDetect, NetworkAnomaly
    static constexpr size_t NUM_DETECTION_TYPES = 6;
    DetectionBaseline baselines_[NUM_DETECTION_TYPES];
    
    // Anomaly detection constants
    static constexpr uint64_t BASELINE_WINDOW_MS = 3600000;  // 1 hour
    static constexpr uint64_t ANOMALY_THRESHOLD_MULTIPLIER = 10;  // 10x baseline
    static constexpr size_t MAX_STORED_EVENTS = 10000;  // Limit memory usage
};

} // namespace SDK
} // namespace Sentinel
