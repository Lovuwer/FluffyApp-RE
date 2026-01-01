/**
 * Sentinel SDK - Performance Telemetry
 * 
 * Provides real-time performance monitoring with P50/P95/P99 latency tracking
 * for all major SDK operations. Implements self-throttling to maintain frame
 * time budgets and prevent game performance degradation.
 * 
 * Performance Target: <5ms P95 latency for all operations
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <array>
#include <algorithm>

namespace Sentinel {
namespace SDK {

/**
 * Types of SDK operations tracked for performance monitoring
 */
enum class OperationType : uint8_t {
    Initialize = 0,         ///< SDK initialization
    Update = 1,             ///< Per-frame update
    FullScan = 2,           ///< Full integrity scan
    ProtectMemory = 3,      ///< Memory protection registration
    ProtectFunction = 4,    ///< Function protection registration
    VerifyMemory = 5,       ///< Memory verification
    EncryptPacket = 6,      ///< Packet encryption
    DecryptPacket = 7,      ///< Packet decryption
    MAX_OPERATION_TYPES = 8 ///< Total number of operation types
};

/**
 * Percentile statistics for latency distribution
 */
struct PercentileStats {
    double p50_ms;          ///< 50th percentile (median) latency in milliseconds
    double p95_ms;          ///< 95th percentile latency in milliseconds
    double p99_ms;          ///< 99th percentile latency in milliseconds
    double min_ms;          ///< Minimum latency
    double max_ms;          ///< Maximum latency
    double mean_ms;         ///< Mean latency
    uint64_t sample_count;  ///< Number of samples in statistics
    
    PercentileStats()
        : p50_ms(0.0)
        , p95_ms(0.0)
        , p99_ms(0.0)
        , min_ms(0.0)
        , max_ms(0.0)
        , mean_ms(0.0)
        , sample_count(0)
    {}
};

/**
 * Performance metrics for a specific operation type
 */
struct PerformanceMetrics {
    OperationType operation;
    PercentileStats current_window;  ///< Current measurement window
    PercentileStats lifetime;        ///< Lifetime statistics
    uint64_t total_operations;       ///< Total operations performed
    uint64_t throttled_operations;   ///< Operations skipped due to throttling
    bool is_throttled;               ///< Currently throttling this operation
    
    PerformanceMetrics()
        : operation(OperationType::Initialize)
        , total_operations(0)
        , throttled_operations(0)
        , is_throttled(false)
    {}
};

/**
 * Performance telemetry configuration
 */
struct PerfTelemetryConfig {
    // Latency thresholds (milliseconds)
    double p95_threshold_ms;         ///< P95 latency threshold for alerting (default: 5ms)
    double p99_threshold_ms;         ///< P99 latency threshold for critical alert (default: 10ms)
    
    // Throttling configuration
    bool enable_self_throttling;     ///< Enable automatic throttling on threshold breach
    double throttle_probability;     ///< Probability of skipping operation when throttling (0.0-1.0)
    uint32_t throttle_cooldown_ms;   ///< Time to wait before re-evaluating throttling
    
    // Measurement window configuration
    uint32_t window_size;            ///< Number of samples per measurement window
    uint32_t max_samples;            ///< Maximum samples to retain (for percentile calculation)
    
    // Reporting configuration
    uint32_t report_interval_ms;     ///< How often to aggregate and report metrics
    
    /**
     * Create default configuration
     */
    static PerfTelemetryConfig Default() {
        PerfTelemetryConfig config;
        config.p95_threshold_ms = 5.0;
        config.p99_threshold_ms = 10.0;
        config.enable_self_throttling = true;
        config.throttle_probability = 0.5;  // Skip 50% of operations when throttling
        config.throttle_cooldown_ms = 5000; // 5 seconds cooldown
        config.window_size = 1000;          // 1000 samples per window
        config.max_samples = 10000;         // Keep up to 10k samples for accurate percentiles
        config.report_interval_ms = 60000;  // Report every 60 seconds
        return config;
    }
};

/**
 * Performance alert for threshold breaches
 */
struct PerformanceAlert {
    OperationType operation;
    std::string operation_name;
    double measured_latency_ms;
    double threshold_ms;
    bool is_p95;                     ///< true if P95 threshold, false if P99
    uint64_t timestamp_ms;
    
    PerformanceAlert()
        : operation(OperationType::Initialize)
        , measured_latency_ms(0.0)
        , threshold_ms(0.0)
        , is_p95(true)
        , timestamp_ms(0)
    {}
};

/**
 * RAII timer for automatic operation timing
 */
class ScopedTimer {
public:
    using TimePoint = std::chrono::high_resolution_clock::time_point;
    using Callback = void (*)(OperationType, double);
    
    /**
     * Start timing an operation
     * @param op Operation type being timed
     * @param callback Function to call with timing result (operation, duration_ms)
     */
    ScopedTimer(OperationType op, Callback callback)
        : operation_(op)
        , callback_(callback)
        , start_(std::chrono::high_resolution_clock::now())
    {}
    
    /**
     * Stop timing and report result
     */
    ~ScopedTimer() {
        if (callback_) {
            auto end = std::chrono::high_resolution_clock::now();
            auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start_).count();
            double duration_ms = duration_us / 1000.0;
            callback_(operation_, duration_ms);
        }
    }
    
    // Non-copyable, non-movable
    ScopedTimer(const ScopedTimer&) = delete;
    ScopedTimer& operator=(const ScopedTimer&) = delete;
    
private:
    OperationType operation_;
    Callback callback_;
    TimePoint start_;
};

/**
 * Performance Telemetry System
 * 
 * Tracks latency for all major SDK operations and provides:
 * - Real-time P50/P95/P99 percentile calculations
 * - Automatic self-throttling on threshold breach
 * - Performance data for telemetry reporting
 * - Alerting on performance degradation
 */
class PerformanceTelemetry {
public:
    PerformanceTelemetry();
    ~PerformanceTelemetry();
    
    /**
     * Initialize performance telemetry with configuration
     */
    void Initialize(const PerfTelemetryConfig& config = PerfTelemetryConfig::Default());
    
    /**
     * Shutdown and cleanup
     */
    void Shutdown();
    
    /**
     * Record a timed operation
     * @param operation Operation type
     * @param duration_ms Operation duration in milliseconds
     */
    void RecordOperation(OperationType operation, double duration_ms);
    
    /**
     * Check if an operation should be throttled
     * @param operation Operation type to check
     * @return true if operation should be skipped
     */
    bool ShouldThrottle(OperationType operation);
    
    /**
     * Get current performance metrics for an operation
     * @param operation Operation type
     * @return Performance metrics structure
     */
    PerformanceMetrics GetMetrics(OperationType operation) const;
    
    /**
     * Get all performance metrics
     * @return Vector of metrics for all operation types
     */
    std::vector<PerformanceMetrics> GetAllMetrics() const;
    
    /**
     * Get pending performance alerts
     * @return Vector of alerts since last call
     */
    std::vector<PerformanceAlert> GetAlerts();
    
    /**
     * Force recalculation of percentiles for all operations
     * Normally done automatically, but can be called explicitly
     */
    void RecalculatePercentiles();
    
    /**
     * Reset all statistics (for testing)
     */
    void Reset();
    
    /**
     * Get operation name as string
     * @param operation Operation type
     * @return Human-readable operation name
     */
    static std::string GetOperationName(OperationType operation);
    
    /**
     * Create a scoped timer for automatic timing
     * Usage: auto timer = telemetry.CreateTimer(OperationType::Update);
     */
    ScopedTimer CreateTimer(OperationType operation) {
        return ScopedTimer(operation, [this](OperationType op, double duration_ms) {
            this->RecordOperation(op, duration_ms);
        });
    }
    
private:
    /**
     * Calculate percentiles from sample data
     * @param samples Sorted sample data
     * @return Percentile statistics
     */
    PercentileStats CalculatePercentiles(const std::vector<double>& samples) const;
    
    /**
     * Check thresholds and generate alerts
     * @param operation Operation type
     * @param metrics Current metrics
     */
    void CheckThresholds(OperationType operation, const PerformanceMetrics& metrics);
    
    /**
     * Update throttling state based on current metrics
     * @param operation Operation type
     * @param metrics Current metrics
     */
    void UpdateThrottling(OperationType operation, const PerformanceMetrics& metrics);
    
    /**
     * Get current timestamp in milliseconds
     */
    uint64_t GetCurrentTimeMs() const;
    
    /**
     * Convert operation type to array index
     */
    size_t OperationToIndex(OperationType operation) const {
        return static_cast<size_t>(operation);
    }
    
    // Configuration
    PerfTelemetryConfig config_;
    
    // Per-operation metrics storage
    struct OperationData {
        PerformanceMetrics metrics;
        std::vector<double> samples;  // Recent samples for percentile calculation
        uint64_t window_start_ms;     // Start time of current window
        uint64_t last_throttle_check_ms; // Last time throttling was evaluated
        double sum_duration;          // Sum for mean calculation
        std::mutex mutex;             // Thread-safe access
        
        OperationData() 
            : window_start_ms(0)
            , last_throttle_check_ms(0)
            , sum_duration(0.0)
        {}
    };
    
    std::array<OperationData, static_cast<size_t>(OperationType::MAX_OPERATION_TYPES)> operations_;
    
    // Alert tracking
    std::vector<PerformanceAlert> pending_alerts_;
    mutable std::mutex alerts_mutex_;
    
    // Initialization state
    bool initialized_;
};

} // namespace SDK
} // namespace Sentinel
