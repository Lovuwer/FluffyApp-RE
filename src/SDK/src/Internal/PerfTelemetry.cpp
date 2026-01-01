/**
 * Sentinel SDK - Performance Telemetry Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "PerfTelemetry.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <random>

namespace Sentinel {
namespace SDK {

// ==================== PerformanceTelemetry Implementation ====================

PerformanceTelemetry::PerformanceTelemetry()
    : initialized_(false)
{
}

PerformanceTelemetry::~PerformanceTelemetry() {
    Shutdown();
}

void PerformanceTelemetry::Initialize(const PerfTelemetryConfig& config) {
    config_ = config;
    
    // Initialize all operation data
    for (size_t i = 0; i < operations_.size(); ++i) {
        auto& op_data = operations_[i];
        std::lock_guard<std::mutex> lock(op_data.mutex);
        
        op_data.metrics.operation = static_cast<OperationType>(i);
        op_data.metrics.total_operations = 0;
        op_data.metrics.throttled_operations = 0;
        op_data.metrics.is_throttled = false;
        op_data.samples.clear();
        op_data.samples.reserve(config_.max_samples);
        op_data.window_start_ms = GetCurrentTimeMs();
        op_data.last_throttle_check_ms = op_data.window_start_ms;
        op_data.sum_duration = 0.0;
    }
    
    initialized_ = true;
}

void PerformanceTelemetry::Shutdown() {
    initialized_ = false;
    
    // Clear all data
    for (auto& op_data : operations_) {
        std::lock_guard<std::mutex> lock(op_data.mutex);
        op_data.samples.clear();
    }
    
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    pending_alerts_.clear();
}

void PerformanceTelemetry::RecordOperation(OperationType operation, double duration_ms) {
    if (!initialized_) return;
    
    size_t idx = OperationToIndex(operation);
    if (idx >= operations_.size()) return;
    
    auto& op_data = operations_[idx];
    std::lock_guard<std::mutex> lock(op_data.mutex);
    
    // Update counters
    op_data.metrics.total_operations++;
    
    // Add sample to current window
    op_data.samples.push_back(duration_ms);
    op_data.sum_duration += duration_ms;
    
    // Update lifetime min/max
    if (op_data.metrics.lifetime.sample_count == 0) {
        op_data.metrics.lifetime.min_ms = duration_ms;
        op_data.metrics.lifetime.max_ms = duration_ms;
    } else {
        op_data.metrics.lifetime.min_ms = std::min(op_data.metrics.lifetime.min_ms, duration_ms);
        op_data.metrics.lifetime.max_ms = std::max(op_data.metrics.lifetime.max_ms, duration_ms);
    }
    op_data.metrics.lifetime.sample_count++;
    
    // Update current window min/max
    if (op_data.metrics.current_window.sample_count == 0) {
        op_data.metrics.current_window.min_ms = duration_ms;
        op_data.metrics.current_window.max_ms = duration_ms;
    } else {
        op_data.metrics.current_window.min_ms = std::min(op_data.metrics.current_window.min_ms, duration_ms);
        op_data.metrics.current_window.max_ms = std::max(op_data.metrics.current_window.max_ms, duration_ms);
    }
    op_data.metrics.current_window.sample_count++;
    
    // Maintain max sample size
    if (op_data.samples.size() > config_.max_samples) {
        // Remove oldest samples
        size_t to_remove = op_data.samples.size() - config_.max_samples;
        op_data.samples.erase(op_data.samples.begin(), op_data.samples.begin() + to_remove);
    }
    
    // Check if we should recalculate percentiles
    uint64_t current_time = GetCurrentTimeMs();
    bool should_recalculate = false;
    
    // Recalculate if window size reached
    if (op_data.samples.size() >= config_.window_size) {
        should_recalculate = true;
    }
    
    // Recalculate if report interval elapsed
    if (current_time - op_data.window_start_ms >= config_.report_interval_ms) {
        should_recalculate = true;
    }
    
    if (should_recalculate && !op_data.samples.empty()) {
        // Calculate percentiles for current window
        std::vector<double> sorted_samples = op_data.samples;
        std::sort(sorted_samples.begin(), sorted_samples.end());
        
        op_data.metrics.current_window = CalculatePercentiles(sorted_samples);
        
        // Update lifetime mean
        op_data.metrics.lifetime.mean_ms = op_data.sum_duration / op_data.metrics.total_operations;
        
        // Check thresholds and generate alerts
        CheckThresholds(operation, op_data.metrics);
        
        // Update throttling state
        UpdateThrottling(operation, op_data.metrics);
        
        // Start new window if interval elapsed
        if (current_time - op_data.window_start_ms >= config_.report_interval_ms) {
            op_data.window_start_ms = current_time;
            // Keep samples for continuous percentile tracking
        }
    }
}

bool PerformanceTelemetry::ShouldThrottle(OperationType operation) {
    if (!initialized_ || !config_.enable_self_throttling) {
        return false;
    }
    
    size_t idx = OperationToIndex(operation);
    if (idx >= operations_.size()) return false;
    
    auto& op_data = operations_[idx];
    std::lock_guard<std::mutex> lock(op_data.mutex);
    
    if (!op_data.metrics.is_throttled) {
        return false;
    }
    
    // Check if cooldown period has elapsed
    uint64_t current_time = GetCurrentTimeMs();
    if (current_time - op_data.last_throttle_check_ms >= config_.throttle_cooldown_ms) {
        // Re-evaluate throttling after cooldown
        UpdateThrottling(operation, op_data.metrics);
        op_data.last_throttle_check_ms = current_time;
    }
    
    if (!op_data.metrics.is_throttled) {
        return false;
    }
    
    // Probabilistic throttling
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    
    bool should_skip = dist(rng) < config_.throttle_probability;
    if (should_skip) {
        op_data.metrics.throttled_operations++;
    }
    
    return should_skip;
}

PerformanceMetrics PerformanceTelemetry::GetMetrics(OperationType operation) const {
    size_t idx = OperationToIndex(operation);
    if (idx >= operations_.size()) {
        return PerformanceMetrics{};
    }
    
    auto& op_data = operations_[idx];
    std::lock_guard<std::mutex> lock(op_data.mutex);
    return op_data.metrics;
}

std::vector<PerformanceMetrics> PerformanceTelemetry::GetAllMetrics() const {
    std::vector<PerformanceMetrics> all_metrics;
    all_metrics.reserve(operations_.size());
    
    for (const auto& op_data : operations_) {
        std::lock_guard<std::mutex> lock(op_data.mutex);
        all_metrics.push_back(op_data.metrics);
    }
    
    return all_metrics;
}

std::vector<PerformanceAlert> PerformanceTelemetry::GetAlerts() {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    std::vector<PerformanceAlert> alerts = std::move(pending_alerts_);
    pending_alerts_.clear();
    return alerts;
}

void PerformanceTelemetry::RecalculatePercentiles() {
    if (!initialized_) return;
    
    for (auto& op_data : operations_) {
        std::lock_guard<std::mutex> lock(op_data.mutex);
        
        if (op_data.samples.empty()) continue;
        
        std::vector<double> sorted_samples = op_data.samples;
        std::sort(sorted_samples.begin(), sorted_samples.end());
        
        op_data.metrics.current_window = CalculatePercentiles(sorted_samples);
        
        // Update mean
        if (op_data.metrics.total_operations > 0) {
            op_data.metrics.lifetime.mean_ms = op_data.sum_duration / op_data.metrics.total_operations;
        }
    }
}

void PerformanceTelemetry::Reset() {
    for (auto& op_data : operations_) {
        std::lock_guard<std::mutex> lock(op_data.mutex);
        
        op_data.metrics.total_operations = 0;
        op_data.metrics.throttled_operations = 0;
        op_data.metrics.is_throttled = false;
        op_data.metrics.current_window = PercentileStats{};
        op_data.metrics.lifetime = PercentileStats{};
        op_data.samples.clear();
        op_data.sum_duration = 0.0;
        op_data.window_start_ms = GetCurrentTimeMs();
        op_data.last_throttle_check_ms = op_data.window_start_ms;
    }
    
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    pending_alerts_.clear();
}

std::string PerformanceTelemetry::GetOperationName(OperationType operation) {
    switch (operation) {
        case OperationType::Initialize: return "Initialize";
        case OperationType::Update: return "Update";
        case OperationType::FullScan: return "FullScan";
        case OperationType::ProtectMemory: return "ProtectMemory";
        case OperationType::ProtectFunction: return "ProtectFunction";
        case OperationType::VerifyMemory: return "VerifyMemory";
        case OperationType::EncryptPacket: return "EncryptPacket";
        case OperationType::DecryptPacket: return "DecryptPacket";
        default: return "Unknown";
    }
}

PercentileStats PerformanceTelemetry::CalculatePercentiles(const std::vector<double>& samples) const {
    PercentileStats stats;
    
    if (samples.empty()) {
        return stats;
    }
    
    size_t n = samples.size();
    stats.sample_count = n;
    
    // Min and max
    stats.min_ms = samples.front();
    stats.max_ms = samples.back();
    
    // Mean
    stats.mean_ms = std::accumulate(samples.begin(), samples.end(), 0.0) / n;
    
    // Calculate percentile indices
    auto get_percentile = [&samples, n](double percentile) -> double {
        // Use linear interpolation between closest ranks
        double index = (percentile / 100.0) * (n - 1);
        size_t lower = static_cast<size_t>(std::floor(index));
        size_t upper = static_cast<size_t>(std::ceil(index));
        
        if (lower == upper) {
            return samples[lower];
        }
        
        double fraction = index - lower;
        return samples[lower] * (1.0 - fraction) + samples[upper] * fraction;
    };
    
    stats.p50_ms = get_percentile(50.0);
    stats.p95_ms = get_percentile(95.0);
    stats.p99_ms = get_percentile(99.0);
    
    return stats;
}

void PerformanceTelemetry::CheckThresholds(OperationType operation, const PerformanceMetrics& metrics) {
    if (metrics.current_window.sample_count == 0) return;
    
    // Check P95 threshold
    if (metrics.current_window.p95_ms > config_.p95_threshold_ms) {
        PerformanceAlert alert;
        alert.operation = operation;
        alert.operation_name = GetOperationName(operation);
        alert.measured_latency_ms = metrics.current_window.p95_ms;
        alert.threshold_ms = config_.p95_threshold_ms;
        alert.is_p95 = true;
        alert.timestamp_ms = GetCurrentTimeMs();
        
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        pending_alerts_.push_back(alert);
    }
    
    // Check P99 threshold
    if (metrics.current_window.p99_ms > config_.p99_threshold_ms) {
        PerformanceAlert alert;
        alert.operation = operation;
        alert.operation_name = GetOperationName(operation);
        alert.measured_latency_ms = metrics.current_window.p99_ms;
        alert.threshold_ms = config_.p99_threshold_ms;
        alert.is_p95 = false;
        alert.timestamp_ms = GetCurrentTimeMs();
        
        std::lock_guard<std::mutex> lock(alerts_mutex_);
        pending_alerts_.push_back(alert);
    }
}

void PerformanceTelemetry::UpdateThrottling(OperationType operation, const PerformanceMetrics& metrics) {
    if (!config_.enable_self_throttling) return;
    if (metrics.current_window.sample_count == 0) return;
    
    size_t idx = OperationToIndex(operation);
    if (idx >= operations_.size()) return;
    
    auto& op_data = operations_[idx];
    
    // Enable throttling if P95 exceeds threshold
    if (metrics.current_window.p95_ms > config_.p95_threshold_ms) {
        op_data.metrics.is_throttled = true;
    } 
    // Disable throttling if P95 is below threshold (with some hysteresis)
    else if (metrics.current_window.p95_ms < config_.p95_threshold_ms * 0.8) {
        op_data.metrics.is_throttled = false;
    }
}

uint64_t PerformanceTelemetry::GetCurrentTimeMs() const {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

} // namespace SDK
} // namespace Sentinel
