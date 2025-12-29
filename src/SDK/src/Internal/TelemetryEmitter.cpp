/**
 * Sentinel SDK - Production Telemetry Emitter Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "Internal/TelemetryEmitter.hpp"
#include "Internal/Context.hpp"
#include <cstring>

namespace Sentinel {
namespace SDK {

TelemetryEmitter::TelemetryEmitter()
    : env_detector_(nullptr)
    , current_scan_duration_us_(0)
    , current_memory_scanned_(0)
{
    // Initialize baselines - use explicit types instead of loop to avoid Unknown (255) issue
    // The baseline array stores data for valid detection types 0-5, plus Unknown at index 6
    baselines_[0].type = DetectionType::AntiDebug;
    baselines_[1].type = DetectionType::AntiHook;
    baselines_[2].type = DetectionType::MemoryIntegrity;
    baselines_[3].type = DetectionType::SpeedHack;
    baselines_[4].type = DetectionType::InjectionDetect;
    baselines_[5].type = DetectionType::NetworkAnomaly;
    baselines_[6].type = DetectionType::Unknown;  // Dedicated slot for Unknown
    
    for (size_t i = 0; i < NUM_DETECTION_TYPES; ++i) {
        baselines_[i].total_detections = 0;
        baselines_[i].baseline_rate_per_hour = 0;
        baselines_[i].window_start_time_ms = GetCurrentTimeMs();
        baselines_[i].window_detections = 0;
        baselines_[i].is_anomalous = false;
    }
}

TelemetryEmitter::~TelemetryEmitter() {
    Shutdown();
}

void TelemetryEmitter::Initialize() {
    std::lock_guard<std::mutex> lock(events_mutex_);
    events_.clear();
    events_.reserve(1000);  // Pre-allocate for efficiency
}

void TelemetryEmitter::Shutdown() {
    std::lock_guard<std::mutex> lock(events_mutex_);
    events_.clear();
}

void TelemetryEmitter::SetEnvironmentDetector(EnvironmentDetector* detector) {
    env_detector_ = detector;
}

void TelemetryEmitter::EmitEvent(const TelemetryEvent& event) {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    // Update baseline tracking
    UpdateBaseline(event.detection_type);
    
    // Check for anomalies
    CheckAnomalies(event.detection_type);
    
    // Store event (with size limit)
    if (events_.size() < MAX_STORED_EVENTS) {
        events_.push_back(event);
    } else {
        // Ring buffer behavior - remove oldest
        events_.erase(events_.begin());
        events_.push_back(event);
    }
}

TelemetryEvent TelemetryEmitter::CreateEventFromViolation(
    const ViolationEvent& violation,
    DetectionType detection_type,
    float confidence,
    const void* raw_data,
    size_t raw_data_size)
{
    TelemetryEvent event;
    
    // Core identification
    event.timestamp_ms = GetCurrentTimeMs();
    event.detection_type = detection_type;
    event.violation_type = violation.type;
    event.severity = violation.severity;
    
    // Detection details
    event.confidence = confidence;
    event.raw_data_hash = ComputeDataHash(raw_data, raw_data_size);
    event.details = violation.details;
    event.address = violation.address;
    
    // Environment context
    if (env_detector_) {
        const auto& env_info = env_detector_->GetEnvironmentInfo();
        event.is_vm = env_info.is_hypervisor_present;
        event.is_cloud_gaming = env_detector_->IsCloudGaming();
        event.has_overlay = false;  // Would need overlay detection system
        event.environment_string = env_detector_->GetEnvironmentString();
    } else {
        event.is_vm = false;
        event.is_cloud_gaming = false;
        event.has_overlay = false;
        event.environment_string = "unknown";
    }
    
    // Correlation context
    event.correlation_state = current_correlation_state_;
    
    // Performance metrics
    event.scan_duration_us = current_scan_duration_us_;
    event.memory_scanned_bytes = current_memory_scanned_;
    
    // Reset performance metrics after use
    current_scan_duration_us_ = 0;
    current_memory_scanned_ = 0;
    
    return event;
}

void TelemetryEmitter::UpdateCorrelationState(const CorrelationSnapshot& state) {
    current_correlation_state_ = state;
}

void TelemetryEmitter::SetPerformanceMetrics(uint64_t scan_duration_us, size_t memory_scanned) {
    current_scan_duration_us_ = scan_duration_us;
    current_memory_scanned_ = memory_scanned;
}

bool TelemetryEmitter::IsDetectionRateAnomalous(DetectionType type) const {
    size_t index = TypeToIndex(type);
    return baselines_[index].is_anomalous;
}

const DetectionBaseline& TelemetryEmitter::GetBaseline(DetectionType type) const {
    size_t index = TypeToIndex(type);
    return baselines_[index];
}

std::vector<TelemetryEvent> TelemetryEmitter::GetEvents() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    return events_;
}

void TelemetryEmitter::ClearEvents() {
    std::lock_guard<std::mutex> lock(events_mutex_);
    events_.clear();
}

void TelemetryEmitter::UpdateBaseline(DetectionType type) {
    size_t index = TypeToIndex(type);
    
    DetectionBaseline& baseline = baselines_[index];
    baseline.total_detections++;
    baseline.window_detections++;
    
    uint64_t current_time = GetCurrentTimeMs();
    uint64_t elapsed = current_time - baseline.window_start_time_ms;
    
    // Update baseline after 1 hour window
    if (elapsed >= BASELINE_WINDOW_MS) {
        // Calculate baseline rate per hour
        baseline.baseline_rate_per_hour = baseline.window_detections;
        
        // Reset window
        baseline.window_start_time_ms = current_time;
        baseline.window_detections = 0;
    }
}

void TelemetryEmitter::CheckAnomalies(DetectionType type) {
    size_t index = TypeToIndex(type);
    
    DetectionBaseline& baseline = baselines_[index];
    
    // Need at least one baseline window to detect anomalies
    if (baseline.baseline_rate_per_hour == 0) {
        baseline.is_anomalous = false;
        return;
    }
    
    uint64_t current_time = GetCurrentTimeMs();
    uint64_t elapsed = current_time - baseline.window_start_time_ms;
    
    // Calculate current rate (normalize to per-hour)
    uint64_t current_rate_per_hour = 0;
    if (elapsed > 0) {
        current_rate_per_hour = (baseline.window_detections * BASELINE_WINDOW_MS) / elapsed;
    }
    
    // Check if current rate exceeds 10x baseline
    baseline.is_anomalous = (current_rate_per_hour > baseline.baseline_rate_per_hour * ANOMALY_THRESHOLD_MULTIPLIER);
}

uint64_t TelemetryEmitter::ComputeDataHash(const void* data, size_t size) const {
    if (!data || size == 0) {
        return 0;
    }
    
    // Use FNV-1a hash for privacy-preserving data hashing
    return Internal::ComputeHash(data, size);
}

uint64_t TelemetryEmitter::GetCurrentTimeMs() const {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto duration = now.time_since_epoch();
    return duration_cast<milliseconds>(duration).count();
}

size_t TelemetryEmitter::TypeToIndex(DetectionType type) const {
    size_t index = static_cast<size_t>(type);
    // Map Unknown (255) to index 6 (dedicated slot)
    if (type == DetectionType::Unknown) {
        return 6;
    }
    // Valid types are 0-5 (AntiDebug through NetworkAnomaly)
    if (index < 6) {
        return index;
    }
    // Other invalid types also map to Unknown slot
    return 6;
}

} // namespace SDK
} // namespace Sentinel
