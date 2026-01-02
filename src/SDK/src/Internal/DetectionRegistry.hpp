/**
 * Sentinel SDK - Redundant Detection Registry
 * 
 * Task 29: Implement Redundant Detection Architecture
 * 
 * Provides infrastructure for registering and managing multiple
 * detection implementations per detection category. Enables defense
 * in depth by requiring attackers to bypass multiple independent
 * implementations.
 * 
 * Key Features:
 * - Multiple implementations per detection category
 * - Violation aggregation with deduplication
 * - Configurable redundancy levels per category
 * - Performance overhead tracking
 * - Zero changes to game integration interface
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#pragma once

#include "SentinelSDK.hpp"
#include "TelemetryEmitter.hpp"
#include <vector>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <cstdint>

namespace Sentinel {
namespace SDK {

/**
 * Redundancy level for detection categories
 */
enum class RedundancyLevel : uint8_t {
    None = 0,       ///< Single implementation (default, legacy behavior)
    Standard = 1,   ///< Two implementations with different approaches
    High = 2,       ///< Three or more implementations
    Maximum = 3     ///< All available implementations (performance impact)
};

/**
 * Configuration for redundant detection per category
 */
struct RedundancyConfig {
    DetectionType category;
    RedundancyLevel level;
    bool enabled;
    
    RedundancyConfig()
        : category(DetectionType::Unknown)
        , level(RedundancyLevel::None)
        , enabled(false)
    {}
    
    RedundancyConfig(DetectionType cat, RedundancyLevel lvl, bool en = true)
        : category(cat)
        , level(lvl)
        , enabled(en)
    {}
};

/**
 * Base interface for detection implementations
 * 
 * Each implementation provides its own approach to detecting
 * violations in a specific category. Multiple implementations
 * can be registered for the same category.
 */
class IDetectionImplementation {
public:
    virtual ~IDetectionImplementation() = default;
    
    /**
     * Get the detection category this implementation handles
     */
    virtual DetectionType GetCategory() const = 0;
    
    /**
     * Get a unique identifier for this implementation
     * Used for tracking and deduplication
     */
    virtual const char* GetImplementationId() const = 0;
    
    /**
     * Get a description of the approach used
     */
    virtual const char* GetDescription() const = 0;
    
    /**
     * Perform lightweight check (for per-frame Update calls)
     */
    virtual std::vector<ViolationEvent> QuickCheck() = 0;
    
    /**
     * Perform comprehensive check (for periodic FullScan calls)
     */
    virtual std::vector<ViolationEvent> FullCheck() = 0;
    
    /**
     * Initialize the implementation (called once at SDK init)
     */
    virtual void Initialize() {}
    
    /**
     * Shutdown the implementation (called at SDK shutdown)
     */
    virtual void Shutdown() {}
};

/**
 * Statistics for redundant detection performance tracking
 */
struct RedundancyStatistics {
    DetectionType category;
    uint32_t active_implementations;
    uint32_t total_checks_performed;
    uint32_t unique_violations_detected;
    uint32_t duplicate_violations_filtered;
    float avg_overhead_us;              ///< Average per-check overhead in microseconds
    float max_overhead_us;              ///< Maximum per-check overhead in microseconds
    
    RedundancyStatistics()
        : category(DetectionType::Unknown)
        , active_implementations(0)
        , total_checks_performed(0)
        , unique_violations_detected(0)
        , duplicate_violations_filtered(0)
        , avg_overhead_us(0.0f)
        , max_overhead_us(0.0f)
    {}
};

/**
 * Detection Registry for managing redundant implementations
 * 
 * Handles registration, execution, and aggregation of multiple
 * detection implementations per category. Provides transparent
 * redundancy without changing the SDK's public interface.
 */
class DetectionRegistry {
public:
    DetectionRegistry();
    ~DetectionRegistry();
    
    /**
     * Register a detection implementation
     * @param impl Unique pointer to implementation (registry takes ownership)
     */
    void RegisterImplementation(std::unique_ptr<IDetectionImplementation> impl);
    
    /**
     * Set redundancy configuration for a category
     * @param config Configuration specifying redundancy level
     */
    void SetRedundancyConfig(const RedundancyConfig& config);
    
    /**
     * Get redundancy configuration for a category
     * @param category Detection category
     * @return Current configuration (default: None/disabled)
     */
    RedundancyConfig GetRedundancyConfig(DetectionType category) const;
    
    /**
     * Execute quick checks for a detection category
     * Runs all active implementations based on redundancy config
     * @param category Detection category to check
     * @return Aggregated and deduplicated violations
     */
    std::vector<ViolationEvent> ExecuteQuickCheck(DetectionType category);
    
    /**
     * Execute full checks for a detection category
     * Runs all active implementations based on redundancy config
     * @param category Detection category to check
     * @return Aggregated and deduplicated violations
     */
    std::vector<ViolationEvent> ExecuteFullCheck(DetectionType category);
    
    /**
     * Get count of registered implementations for a category
     * @param category Detection category
     * @return Number of implementations registered
     */
    size_t GetImplementationCount(DetectionType category) const;
    
    /**
     * Get statistics for redundant detection
     * @param category Detection category
     * @return Performance statistics
     */
    RedundancyStatistics GetStatistics(DetectionType category) const;
    
    /**
     * Reset statistics counters
     */
    void ResetStatistics();
    
    /**
     * Initialize all registered implementations
     */
    void InitializeAll();
    
    /**
     * Shutdown all registered implementations
     */
    void ShutdownAll();

private:
    /**
     * Execute checks with specified function
     * @param category Detection category
     * @param check_func Function to execute on each implementation
     * @return Aggregated and deduplicated violations
     */
    std::vector<ViolationEvent> ExecuteChecks(
        DetectionType category,
        std::function<std::vector<ViolationEvent>(IDetectionImplementation*)> check_func);
    
    /**
     * Aggregate and deduplicate violations from multiple implementations
     * @param violations Vector of violation vectors from each implementation
     * @param category Detection category for statistics
     * @return Deduplicated violation list
     */
    std::vector<ViolationEvent> AggregateViolations(
        const std::vector<std::vector<ViolationEvent>>& violations,
        DetectionType category);
    
    /**
     * Check if two violations are duplicates
     * @param v1 First violation
     * @param v2 Second violation
     * @return true if violations are considered duplicates
     */
    bool IsDuplicateViolation(const ViolationEvent& v1, const ViolationEvent& v2) const;
    
    /**
     * Get active implementations for a category based on redundancy config
     * @param category Detection category
     * @return Vector of active implementation pointers
     */
    std::vector<IDetectionImplementation*> GetActiveImplementations(DetectionType category);
    
    /**
     * Update statistics after check execution
     * @param category Detection category
     * @param impl_count Number of implementations executed
     * @param overhead_us Time overhead in microseconds
     * @param unique_count Number of unique violations
     * @param duplicate_count Number of duplicate violations filtered
     */
    void UpdateStatistics(
        DetectionType category,
        uint32_t impl_count,
        float overhead_us,
        uint32_t unique_count,
        uint32_t duplicate_count);
    
    // Storage for implementations grouped by category
    std::unordered_map<DetectionType, std::vector<std::unique_ptr<IDetectionImplementation>>> implementations_;
    
    // Redundancy configuration per category
    std::unordered_map<DetectionType, RedundancyConfig> redundancy_configs_;
    
    // Performance statistics per category
    std::unordered_map<DetectionType, RedundancyStatistics> statistics_;
    
    // Thread safety
    mutable std::mutex registry_mutex_;
    mutable std::mutex stats_mutex_;
};

} // namespace SDK
} // namespace Sentinel
