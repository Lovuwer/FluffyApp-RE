/**
 * Sentinel SDK - Behavioral Telemetry Collector
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Collects behavioral metrics to detect novel cheats through statistical
 * anomaly detection. Privacy-conscious design with no keystroke logging
 * or screen capture.
 */

#pragma once

#include "SentinelSDK.hpp"
#include <cstdint>
#include <vector>
#include <mutex>
#include <chrono>

namespace Sentinel {
namespace SDK {

// Forward declaration
class CloudReporter;

/**
 * Behavioral metric types for different game genres
 */
enum class BehavioralMetricType : uint8_t {
    InputPattern = 0,      // Input timing and pattern metrics
    Movement = 1,          // Movement velocity and pattern metrics  
    Aim = 2,               // Aim precision and movement metrics
    Custom = 255           // Game-specific custom metrics
};

/**
 * Input pattern metrics (aggregated, not raw keystrokes)
 */
struct InputMetrics {
    uint32_t actions_per_minute;        // Action rate (APM)
    float avg_input_interval_ms;        // Average time between inputs
    float input_variance;               // Variance in input timing
    uint32_t simultaneous_inputs;       // Max simultaneous inputs observed
    float humanness_score;              // 0.0-1.0, higher = more human-like
    
    InputMetrics()
        : actions_per_minute(0)
        , avg_input_interval_ms(0.0f)
        , input_variance(0.0f)
        , simultaneous_inputs(0)
        , humanness_score(1.0f)
    {}
};

/**
 * Movement pattern metrics
 */
struct MovementMetrics {
    float avg_velocity;                 // Average movement speed
    float max_velocity;                 // Peak movement speed
    float velocity_variance;            // Variance in velocity
    float avg_direction_change_rate;    // Direction changes per second
    float path_smoothness;              // 0.0-1.0, higher = smoother
    uint32_t teleport_count;            // Suspicious position jumps
    
    MovementMetrics()
        : avg_velocity(0.0f)
        , max_velocity(0.0f)
        , velocity_variance(0.0f)
        , avg_direction_change_rate(0.0f)
        , path_smoothness(1.0f)
        , teleport_count(0)
    {}
};

/**
 * Aim characteristic metrics
 */
struct AimMetrics {
    float avg_precision;                // Average aim accuracy (0.0-1.0)
    float flick_rate;                   // Rapid aim changes per minute
    float tracking_smoothness;          // 0.0-1.0, higher = smoother tracking
    float reaction_time_ms;             // Average reaction time
    float headshot_percentage;          // Percentage of headshots
    uint32_t snap_count;                // Instant aim snaps detected
    
    AimMetrics()
        : avg_precision(0.0f)
        , flick_rate(0.0f)
        , tracking_smoothness(1.0f)
        , reaction_time_ms(250.0f)
        , headshot_percentage(0.0f)
        , snap_count(0)
    {}
};

/**
 * Custom metric for game-specific data
 */
struct CustomMetric {
    std::string name;                   // Metric name
    float value;                        // Metric value
    std::string unit;                   // Unit description (optional)
    
    CustomMetric()
        : value(0.0f)
    {}
};

/**
 * Aggregated behavioral data payload
 */
struct BehavioralData {
    uint64_t window_start_ms;           // Start of aggregation window
    uint64_t window_end_ms;             // End of aggregation window
    uint32_t sample_count;              // Number of samples in window
    
    // Metric data
    InputMetrics input;
    MovementMetrics movement;
    AimMetrics aim;
    std::vector<CustomMetric> custom;
    
    BehavioralData()
        : window_start_ms(0)
        , window_end_ms(0)
        , sample_count(0)
    {}
};

/**
 * Configuration for behavioral collection
 */
struct BehavioralConfig {
    bool enabled;                       // Enable/disable collection
    uint32_t sample_rate_ms;            // Sample interval in milliseconds
    uint32_t aggregation_window_ms;     // Aggregation window in milliseconds
    bool collect_input;                 // Collect input metrics
    bool collect_movement;              // Collect movement metrics
    bool collect_aim;                   // Collect aim metrics
    
    BehavioralConfig()
        : enabled(true)
        , sample_rate_ms(1000)          // Default: 1 sample per second
        , aggregation_window_ms(60000)  // Default: 1 minute window
        , collect_input(true)
        , collect_movement(true)
        , collect_aim(true)
    {}
};

/**
 * Behavioral Telemetry Collector
 * 
 * Features:
 * - Configurable sample rate for performance
 * - Local aggregation to minimize bandwidth
 * - Privacy-conscious (no raw keystroke/screen data)
 * - Extensible for game-specific metrics
 * - Automatic transmission via CloudReporter
 */
class BehavioralCollector {
public:
    BehavioralCollector();
    ~BehavioralCollector();
    
    /**
     * Initialize collector with configuration
     */
    void Initialize(const BehavioralConfig& config);
    
    /**
     * Shutdown collector
     */
    void Shutdown();
    
    /**
     * Set CloudReporter for transmission
     */
    void SetCloudReporter(CloudReporter* reporter);
    
    /**
     * Record an input action (timing only, no keystrokes)
     */
    void RecordInput(uint64_t timestamp_ms, uint32_t concurrent_inputs = 1);
    
    /**
     * Record movement data
     */
    void RecordMovement(float velocity, float direction_change_rate);
    
    /**
     * Record aim data
     */
    void RecordAim(float precision, float flick_speed, bool is_headshot = false);
    
    /**
     * Record custom game-specific metric
     */
    void RecordCustomMetric(const char* name, float value, const char* unit = nullptr);
    
    /**
     * Manually trigger aggregation and transmission
     */
    void Flush();
    
    /**
     * Get current aggregated data (for testing)
     */
    BehavioralData GetCurrentData() const;
    
    /**
     * Get last transmitted data size in bytes (for bandwidth monitoring)
     */
    size_t GetLastTransmitSize() const { return last_transmit_size_; }
    
private:
    /**
     * Aggregation thread function
     */
    void AggregationThread();
    
    /**
     * Aggregate current samples into behavioral data
     */
    BehavioralData AggregateData();
    
    /**
     * Transmit aggregated data via CloudReporter
     */
    void TransmitData(const BehavioralData& data);
    
    /**
     * Reset current sample accumulation
     */
    void ResetSamples();
    
    /**
     * Get current timestamp in milliseconds
     */
    uint64_t GetCurrentTimeMs() const;
    
    /**
     * Calculate variance of a sample set
     */
    float CalculateVariance(const std::vector<float>& samples, float mean) const;
    
    // Configuration
    BehavioralConfig config_;
    
    // CloudReporter reference
    CloudReporter* cloud_reporter_;
    
    // Threading
    std::thread aggregation_thread_;
    std::mutex data_mutex_;
    std::condition_variable cv_;
    bool running_;
    
    // Current window tracking
    uint64_t window_start_ms_;
    uint32_t sample_count_;
    
    // Input samples
    std::vector<uint64_t> input_timestamps_;
    std::vector<uint32_t> input_concurrent_counts_;
    
    // Movement samples  
    std::vector<float> movement_velocities_;
    std::vector<float> movement_direction_changes_;
    
    // Aim samples
    std::vector<float> aim_precisions_;
    std::vector<float> aim_flick_speeds_;
    uint32_t headshot_count_;
    uint32_t total_shots_;
    
    // Custom metrics (accumulated)
    std::vector<CustomMetric> custom_metrics_;
    
    // Bandwidth tracking
    size_t last_transmit_size_;
    
    // Performance metrics
    static constexpr size_t MAX_SAMPLES_PER_WINDOW = 10000;  // Prevent memory issues
};

} // namespace SDK
} // namespace Sentinel
