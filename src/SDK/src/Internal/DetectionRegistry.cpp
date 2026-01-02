/**
 * Sentinel SDK - Redundant Detection Registry Implementation
 * 
 * Task 29: Implement Redundant Detection Architecture
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "DetectionRegistry.hpp"
#include <chrono>
#include <algorithm>
#include <cmath>

namespace Sentinel {
namespace SDK {

DetectionRegistry::DetectionRegistry() {
    // Initialize default configs for all detection types
    for (uint8_t i = 0; i < static_cast<uint8_t>(DetectionType::Unknown); ++i) {
        DetectionType type = static_cast<DetectionType>(i);
        redundancy_configs_[type] = RedundancyConfig(type, RedundancyLevel::None, false);
        statistics_[type] = RedundancyStatistics();
        statistics_[type].category = type;
    }
}

DetectionRegistry::~DetectionRegistry() {
    ShutdownAll();
}

void DetectionRegistry::RegisterImplementation(std::unique_ptr<IDetectionImplementation> impl) {
    if (!impl) {
        return;
    }
    
    DetectionType category = impl->GetCategory();
    
    std::lock_guard<std::mutex> lock(registry_mutex_);
    implementations_[category].push_back(std::move(impl));
}

void DetectionRegistry::SetRedundancyConfig(const RedundancyConfig& config) {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    redundancy_configs_[config.category] = config;
}

RedundancyConfig DetectionRegistry::GetRedundancyConfig(DetectionType category) const {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    auto it = redundancy_configs_.find(category);
    if (it != redundancy_configs_.end()) {
        return it->second;
    }
    return RedundancyConfig(category, RedundancyLevel::None, false);
}

std::vector<ViolationEvent> DetectionRegistry::ExecuteQuickCheck(DetectionType category) {
    return ExecuteChecks(category, [](IDetectionImplementation* impl) {
        return impl->QuickCheck();
    });
}

std::vector<ViolationEvent> DetectionRegistry::ExecuteFullCheck(DetectionType category) {
    return ExecuteChecks(category, [](IDetectionImplementation* impl) {
        return impl->FullCheck();
    });
}

std::vector<ViolationEvent> DetectionRegistry::ExecuteChecks(
    DetectionType category,
    std::function<std::vector<ViolationEvent>(IDetectionImplementation*)> check_func)
{
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Get active implementations based on redundancy config
    std::vector<IDetectionImplementation*> active_impls = GetActiveImplementations(category);
    
    if (active_impls.empty()) {
        return std::vector<ViolationEvent>();
    }
    
    // Execute checks on all active implementations
    std::vector<std::vector<ViolationEvent>> all_violations;
    all_violations.reserve(active_impls.size());
    
    for (auto* impl : active_impls) {
        try {
            std::vector<ViolationEvent> violations = check_func(impl);
            
            // Tag violations with implementation ID for tracking
            for (auto& v : violations) {
                // Store implementation ID in detection_id upper 16 bits
                // Lower 16 bits remain for category-specific detection ID
                uint32_t impl_hash = std::hash<std::string>{}(impl->GetImplementationId());
                v.detection_id = (impl_hash & 0xFFFF0000) | (v.detection_id & 0x0000FFFF);
            }
            
            all_violations.push_back(std::move(violations));
        } catch (...) {
            // Swallow exceptions from individual implementations
            // Redundancy ensures other implementations still run
        }
    }
    
    // Aggregate and deduplicate violations
    std::vector<ViolationEvent> result = AggregateViolations(all_violations, category);
    
    // Calculate overhead
    auto end_time = std::chrono::high_resolution_clock::now();
    auto overhead_us = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time).count();
    
    // Update statistics
    uint32_t total_violations = 0;
    for (const auto& v : all_violations) {
        total_violations += static_cast<uint32_t>(v.size());
    }
    uint32_t unique_violations = static_cast<uint32_t>(result.size());
    uint32_t duplicates = (total_violations > unique_violations) ? 
                          (total_violations - unique_violations) : 0;
    
    UpdateStatistics(category, static_cast<uint32_t>(active_impls.size()), 
                    static_cast<float>(overhead_us), unique_violations, duplicates);
    
    return result;
}

std::vector<ViolationEvent> DetectionRegistry::AggregateViolations(
    const std::vector<std::vector<ViolationEvent>>& violations,
    DetectionType category)
{
    if (violations.empty()) {
        return std::vector<ViolationEvent>();
    }
    
    if (violations.size() == 1) {
        return violations[0];
    }
    
    // Collect all violations
    std::vector<ViolationEvent> all;
    for (const auto& v : violations) {
        all.insert(all.end(), v.begin(), v.end());
    }
    
    // Deduplicate similar violations
    std::vector<ViolationEvent> unique;
    unique.reserve(all.size());
    
    for (const auto& violation : all) {
        bool is_duplicate = false;
        for (const auto& existing : unique) {
            if (IsDuplicateViolation(violation, existing)) {
                is_duplicate = true;
                break;
            }
        }
        
        if (!is_duplicate) {
            unique.push_back(violation);
        }
    }
    
    return unique;
}

bool DetectionRegistry::IsDuplicateViolation(
    const ViolationEvent& v1, 
    const ViolationEvent& v2) const
{
    // Violations are considered duplicates if they have:
    // 1. Same type
    // 2. Similar timestamp (within 100ms)
    // 3. Same address (if non-zero) OR similar details
    
    if (v1.type != v2.type) {
        return false;
    }
    
    // Check timestamp proximity (100ms window)
    int64_t time_diff = static_cast<int64_t>(v1.timestamp) - static_cast<int64_t>(v2.timestamp);
    if (std::abs(time_diff) > 100) {
        return false;
    }
    
    // If both have addresses, they must match
    if (v1.address != 0 && v2.address != 0) {
        return v1.address == v2.address;
    }
    
    // If both have module names, they must match
    if (!v1.module_name.empty() && !v2.module_name.empty()) {
        return v1.module_name == v2.module_name;
    }
    
    // Otherwise, check if details are similar (exact match for now)
    return v1.details == v2.details;
}

std::vector<IDetectionImplementation*> DetectionRegistry::GetActiveImplementations(
    DetectionType category)
{
    std::lock_guard<std::mutex> lock(registry_mutex_);
    
    std::vector<IDetectionImplementation*> result;
    
    auto impl_it = implementations_.find(category);
    if (impl_it == implementations_.end() || impl_it->second.empty()) {
        return result;
    }
    
    auto config_it = redundancy_configs_.find(category);
    if (config_it == redundancy_configs_.end() || !config_it->second.enabled) {
        // Redundancy disabled - use only first implementation (legacy behavior)
        result.push_back(impl_it->second[0].get());
        return result;
    }
    
    const RedundancyConfig& config = config_it->second;
    size_t available_count = impl_it->second.size();
    size_t max_count = 0;
    
    switch (config.level) {
        case RedundancyLevel::None:
            max_count = 1;
            break;
        case RedundancyLevel::Standard:
            max_count = 2;
            break;
        case RedundancyLevel::High:
            max_count = 3;
            break;
        case RedundancyLevel::Maximum:
            max_count = available_count;
            break;
    }
    
    // Return up to max_count implementations
    size_t count = std::min(max_count, available_count);
    result.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        result.push_back(impl_it->second[i].get());
    }
    
    return result;
}

void DetectionRegistry::UpdateStatistics(
    DetectionType category,
    uint32_t impl_count,
    float overhead_us,
    uint32_t unique_count,
    uint32_t duplicate_count)
{
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    auto& stats = statistics_[category];
    stats.category = category;
    stats.active_implementations = impl_count;
    stats.total_checks_performed++;
    stats.unique_violations_detected += unique_count;
    stats.duplicate_violations_filtered += duplicate_count;
    
    // Update running average for overhead
    float total_overhead = stats.avg_overhead_us * (stats.total_checks_performed - 1);
    stats.avg_overhead_us = (total_overhead + overhead_us) / stats.total_checks_performed;
    
    // Update max overhead
    if (overhead_us > stats.max_overhead_us) {
        stats.max_overhead_us = overhead_us;
    }
}

size_t DetectionRegistry::GetImplementationCount(DetectionType category) const {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    auto it = implementations_.find(category);
    if (it != implementations_.end()) {
        return it->second.size();
    }
    return 0;
}

RedundancyStatistics DetectionRegistry::GetStatistics(DetectionType category) const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto it = statistics_.find(category);
    if (it != statistics_.end()) {
        return it->second;
    }
    return RedundancyStatistics();
}

void DetectionRegistry::ResetStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    for (auto& pair : statistics_) {
        pair.second = RedundancyStatistics();
        pair.second.category = pair.first;
    }
}

void DetectionRegistry::InitializeAll() {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    for (auto& category_impls : implementations_) {
        for (auto& impl : category_impls.second) {
            impl->Initialize();
        }
    }
}

void DetectionRegistry::ShutdownAll() {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    for (auto& category_impls : implementations_) {
        for (auto& impl : category_impls.second) {
            impl->Shutdown();
        }
    }
    implementations_.clear();
}

} // namespace SDK
} // namespace Sentinel
