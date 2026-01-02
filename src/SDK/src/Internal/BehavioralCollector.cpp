/**
 * Sentinel SDK - Behavioral Telemetry Collector Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Implements behavioral metric collection with efficient aggregation and
 * privacy-conscious design. Detects novel cheats through statistical anomalies.
 */

#include "BehavioralCollector.hpp"
#include "Detection.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <numeric>
#include <cmath>

namespace Sentinel {
namespace SDK {

using json = nlohmann::json;

// ============================================================================
// BehavioralCollector Implementation
// ============================================================================

BehavioralCollector::BehavioralCollector()
    : cloud_reporter_(nullptr)
    , running_(false)
    , window_start_ms_(0)
    , sample_count_(0)
    , headshot_count_(0)
    , total_shots_(0)
    , last_transmit_size_(0)
{
}

BehavioralCollector::~BehavioralCollector() {
    Shutdown();
}

void BehavioralCollector::Initialize(const BehavioralConfig& config) {
    if (running_) {
        return;
    }
    
    config_ = config;
    
    if (!config_.enabled) {
        return;
    }
    
    // Initialize window tracking
    window_start_ms_ = GetCurrentTimeMs();
    sample_count_ = 0;
    
    // Reserve space for samples to avoid frequent reallocations
    input_timestamps_.reserve(1000);
    input_concurrent_counts_.reserve(1000);
    movement_velocities_.reserve(1000);
    movement_direction_changes_.reserve(1000);
    aim_precisions_.reserve(1000);
    aim_flick_speeds_.reserve(1000);
    
    // Start aggregation thread
    running_ = true;
    aggregation_thread_ = std::thread(&BehavioralCollector::AggregationThread, this);
}

void BehavioralCollector::Shutdown() {
    if (!running_) {
        return;
    }
    
    // Signal thread to stop
    running_ = false;
    cv_.notify_all();
    
    // Wait for thread to finish
    if (aggregation_thread_.joinable()) {
        aggregation_thread_.join();
    }
    
    // Flush any remaining data
    if (sample_count_ > 0) {
        auto data = AggregateData();
        TransmitData(data);
    }
}

void BehavioralCollector::SetCloudReporter(CloudReporter* reporter) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    cloud_reporter_ = reporter;
}

void BehavioralCollector::RecordInput(uint64_t timestamp_ms, uint32_t concurrent_inputs) {
    if (!running_ || !config_.enabled || !config_.collect_input) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    // Prevent memory overflow
    if (input_timestamps_.size() >= MAX_SAMPLES_PER_WINDOW) {
        return;
    }
    
    input_timestamps_.push_back(timestamp_ms);
    input_concurrent_counts_.push_back(concurrent_inputs);
    sample_count_++;
}

void BehavioralCollector::RecordMovement(float velocity, float direction_change_rate) {
    if (!running_ || !config_.enabled || !config_.collect_movement) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    // Prevent memory overflow
    if (movement_velocities_.size() >= MAX_SAMPLES_PER_WINDOW) {
        return;
    }
    
    movement_velocities_.push_back(velocity);
    movement_direction_changes_.push_back(direction_change_rate);
    sample_count_++;
}

void BehavioralCollector::RecordAim(float precision, float flick_speed, bool is_headshot) {
    if (!running_ || !config_.enabled || !config_.collect_aim) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    // Prevent memory overflow
    if (aim_precisions_.size() >= MAX_SAMPLES_PER_WINDOW) {
        return;
    }
    
    aim_precisions_.push_back(precision);
    aim_flick_speeds_.push_back(flick_speed);
    
    total_shots_++;
    if (is_headshot) {
        headshot_count_++;
    }
    
    sample_count_++;
}

void BehavioralCollector::RecordCustomMetric(const char* name, float value, const char* unit) {
    if (!running_ || !config_.enabled || !name) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    // Prevent too many custom metrics
    if (custom_metrics_.size() >= 100) {
        return;
    }
    
    CustomMetric metric;
    metric.name = name;
    metric.value = value;
    if (unit) {
        metric.unit = unit;
    }
    
    custom_metrics_.push_back(metric);
}

void BehavioralCollector::Flush() {
    cv_.notify_one();
}

BehavioralData BehavioralCollector::GetCurrentData() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return const_cast<BehavioralCollector*>(this)->AggregateData();
}

void BehavioralCollector::AggregationThread() {
    while (running_) {
        std::unique_lock<std::mutex> lock(data_mutex_);
        
        // Wait for aggregation window or manual flush
        auto timeout = std::chrono::milliseconds(config_.aggregation_window_ms);
        cv_.wait_for(lock, timeout, [this]() {
            return !running_;
        });
        
        if (!running_) {
            break;
        }
        
        // Check if window has elapsed
        uint64_t current_time = GetCurrentTimeMs();
        uint64_t window_elapsed = current_time - window_start_ms_;
        
        if (window_elapsed < config_.aggregation_window_ms && sample_count_ == 0) {
            continue;
        }
        
        // Aggregate data
        BehavioralData data = AggregateData();
        
        lock.unlock();
        
        // Transmit if we have samples
        if (data.sample_count > 0) {
            TransmitData(data);
        }
        
        lock.lock();
        
        // Reset for next window
        ResetSamples();
        window_start_ms_ = GetCurrentTimeMs();
    }
}

BehavioralData BehavioralCollector::AggregateData() {
    BehavioralData data;
    data.window_start_ms = window_start_ms_;
    data.window_end_ms = GetCurrentTimeMs();
    data.sample_count = sample_count_;
    
    // Aggregate input metrics
    if (config_.collect_input && !input_timestamps_.empty()) {
        // Calculate actions per minute using actual event timestamp range
        // This ensures accurate calculation even when GetCurrentData() is called immediately
        uint64_t event_duration_ms = 0;
        if (input_timestamps_.size() > 1) {
            event_duration_ms = input_timestamps_.back() - input_timestamps_.front();
        } else {
            // Single event: use wall-clock duration since window start as fallback
            event_duration_ms = data.window_end_ms - data.window_start_ms;
        }
        
        if (event_duration_ms > 0) {
            data.input.actions_per_minute = static_cast<uint32_t>(
                (input_timestamps_.size() * 60000) / event_duration_ms
            );
        } else {
            // For instantaneous samples or single event at window start,
            // assume 1 second duration to avoid division by zero
            data.input.actions_per_minute = static_cast<uint32_t>(
                input_timestamps_.size() * 60
            );
        }
        
        // Calculate average input interval
        if (input_timestamps_.size() > 1) {
            std::vector<float> intervals;
            for (size_t i = 1; i < input_timestamps_.size(); ++i) {
                float interval = static_cast<float>(
                    input_timestamps_[i] - input_timestamps_[i-1]
                );
                intervals.push_back(interval);
            }
            
            float sum = std::accumulate(intervals.begin(), intervals.end(), 0.0f);
            data.input.avg_input_interval_ms = sum / intervals.size();
            data.input.input_variance = CalculateVariance(intervals, data.input.avg_input_interval_ms);
            
            // Humanness score based on variance (humans have more variance)
            // Perfect bot timing would have low variance
            data.input.humanness_score = std::min(1.0f, data.input.input_variance / 100.0f);
        }
        
        // Max simultaneous inputs
        if (!input_concurrent_counts_.empty()) {
            data.input.simultaneous_inputs = *std::max_element(
                input_concurrent_counts_.begin(), 
                input_concurrent_counts_.end()
            );
        }
    }
    
    // Aggregate movement metrics
    if (config_.collect_movement && !movement_velocities_.empty()) {
        float sum_velocity = std::accumulate(
            movement_velocities_.begin(), 
            movement_velocities_.end(), 
            0.0f
        );
        data.movement.avg_velocity = sum_velocity / movement_velocities_.size();
        
        data.movement.max_velocity = *std::max_element(
            movement_velocities_.begin(), 
            movement_velocities_.end()
        );
        
        data.movement.velocity_variance = CalculateVariance(
            movement_velocities_, 
            data.movement.avg_velocity
        );
        
        // Average direction change rate
        if (!movement_direction_changes_.empty()) {
            float sum_changes = std::accumulate(
                movement_direction_changes_.begin(),
                movement_direction_changes_.end(),
                0.0f
            );
            data.movement.avg_direction_change_rate = sum_changes / movement_direction_changes_.size();
        }
        
        // Detect teleports (velocity spikes > 5x average)
        if (data.movement.avg_velocity > 0) {
            for (float velocity : movement_velocities_) {
                if (velocity > data.movement.avg_velocity * 5.0f) {
                    data.movement.teleport_count++;
                }
            }
        }
        
        // Path smoothness (inverse of direction change rate, normalized)
        data.movement.path_smoothness = 1.0f / (1.0f + data.movement.avg_direction_change_rate);
    }
    
    // Aggregate aim metrics
    if (config_.collect_aim && !aim_precisions_.empty()) {
        float sum_precision = std::accumulate(
            aim_precisions_.begin(),
            aim_precisions_.end(),
            0.0f
        );
        data.aim.avg_precision = sum_precision / aim_precisions_.size();
        
        // Flick rate (rapid aim changes per minute)
        if (!aim_flick_speeds_.empty()) {
            uint64_t window_duration_ms = data.window_end_ms - data.window_start_ms;
            if (window_duration_ms > 0) {
                // Count flicks (speed > threshold)
                uint32_t flick_count = 0;
                for (float speed : aim_flick_speeds_) {
                    if (speed > 100.0f) {  // Arbitrary threshold for "flick"
                        flick_count++;
                    }
                }
                data.aim.flick_rate = (flick_count * 60000.0f) / window_duration_ms;
            }
            
            // Tracking smoothness
            float sum_speeds = std::accumulate(
                aim_flick_speeds_.begin(),
                aim_flick_speeds_.end(),
                0.0f
            );
            float avg_speed = sum_speeds / aim_flick_speeds_.size();
            
            // Smooth tracking has consistent speeds
            float speed_variance = CalculateVariance(aim_flick_speeds_, avg_speed);
            data.aim.tracking_smoothness = 1.0f / (1.0f + speed_variance / 100.0f);
            
            // Count instant snaps (very high speed)
            for (float speed : aim_flick_speeds_) {
                if (speed > 500.0f) {  // Threshold for instant snap
                    data.aim.snap_count++;
                }
            }
        }
        
        // Headshot percentage
        if (total_shots_ > 0) {
            data.aim.headshot_percentage = (headshot_count_ * 100.0f) / total_shots_;
        }
        
        // Estimate reaction time (inverse of precision with normalization)
        data.aim.reaction_time_ms = 250.0f / (0.1f + data.aim.avg_precision);
    }
    
    // Copy custom metrics
    data.custom = custom_metrics_;
    
    return data;
}

void BehavioralCollector::TransmitData(const BehavioralData& data) {
    if (!cloud_reporter_) {
        return;
    }
    
    try {
        // Serialize to JSON
        json j = {
            {"type", "behavioral_telemetry"},
            {"version", "1.0"},
            {"window_start_ms", data.window_start_ms},
            {"window_end_ms", data.window_end_ms},
            {"sample_count", data.sample_count}
        };
        
        // Add input metrics if collected
        if (config_.collect_input) {
            j["input"] = {
                {"actions_per_minute", data.input.actions_per_minute},
                {"avg_input_interval_ms", data.input.avg_input_interval_ms},
                {"input_variance", data.input.input_variance},
                {"simultaneous_inputs", data.input.simultaneous_inputs},
                {"humanness_score", data.input.humanness_score}
            };
        }
        
        // Add movement metrics if collected
        if (config_.collect_movement) {
            j["movement"] = {
                {"avg_velocity", data.movement.avg_velocity},
                {"max_velocity", data.movement.max_velocity},
                {"velocity_variance", data.movement.velocity_variance},
                {"avg_direction_change_rate", data.movement.avg_direction_change_rate},
                {"path_smoothness", data.movement.path_smoothness},
                {"teleport_count", data.movement.teleport_count}
            };
        }
        
        // Add aim metrics if collected
        if (config_.collect_aim) {
            j["aim"] = {
                {"avg_precision", data.aim.avg_precision},
                {"flick_rate", data.aim.flick_rate},
                {"tracking_smoothness", data.aim.tracking_smoothness},
                {"reaction_time_ms", data.aim.reaction_time_ms},
                {"headshot_percentage", data.aim.headshot_percentage},
                {"snap_count", data.aim.snap_count}
            };
        }
        
        // Add custom metrics if any
        if (!data.custom.empty()) {
            json custom_array = json::array();
            for (const auto& metric : data.custom) {
                json metric_obj = {
                    {"name", metric.name},
                    {"value", metric.value}
                };
                if (!metric.unit.empty()) {
                    metric_obj["unit"] = metric.unit;
                }
                custom_array.push_back(metric_obj);
            }
            j["custom"] = custom_array;
        }
        
        std::string json_str = j.dump();
        last_transmit_size_ = json_str.size();
        
        // Transmit via CloudReporter's custom event API
        cloud_reporter_->ReportCustomEvent("behavioral_telemetry", json_str.c_str());
        
    } catch (const std::exception&) {
        // Failed to serialize or transmit - silently fail
        last_transmit_size_ = 0;
    }
}

void BehavioralCollector::ResetSamples() {
    sample_count_ = 0;
    
    input_timestamps_.clear();
    input_concurrent_counts_.clear();
    
    movement_velocities_.clear();
    movement_direction_changes_.clear();
    
    aim_precisions_.clear();
    aim_flick_speeds_.clear();
    headshot_count_ = 0;
    total_shots_ = 0;
    
    custom_metrics_.clear();
}

uint64_t BehavioralCollector::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

float BehavioralCollector::CalculateVariance(const std::vector<float>& samples, float mean) const {
    if (samples.empty()) {
        return 0.0f;
    }
    
    float sum_sq_diff = 0.0f;
    for (float sample : samples) {
        float diff = sample - mean;
        sum_sq_diff += diff * diff;
    }
    
    return sum_sq_diff / samples.size();
}

} // namespace SDK
} // namespace Sentinel
