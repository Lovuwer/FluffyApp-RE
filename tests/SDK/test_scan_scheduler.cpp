/**
 * Sentinel SDK - Scan Scheduler Tests
 * 
 * Task 9: Detection Timing Randomization Tests
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/ScanScheduler.hpp"

#include <thread>
#include <chrono>
#include <vector>
#include <set>
#include <algorithm>
#include <cmath>
#include <numeric>

using namespace Sentinel::SDK;

/**
 * Test: Basic Initialization
 * Verifies that scheduler initializes correctly with valid configuration
 */
TEST(ScanSchedulerTests, BasicInitialization) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 500;
    config.max_interval_ms = 1500;
    config.mean_interval_ms = 1000;
    
    EXPECT_NO_THROW(scheduler.Initialize(config));
    scheduler.Shutdown();
}

/**
 * Test: Configuration Validation
 * Verifies that invalid configurations are rejected
 */
TEST(ScanSchedulerTests, ConfigurationValidation) {
    ScanScheduler scheduler;
    
    // Test: min >= max should fail
    {
        ScanSchedulerConfig config;
        config.min_interval_ms = 1500;
        config.max_interval_ms = 500;
        config.mean_interval_ms = 1000;
        EXPECT_THROW(scheduler.Initialize(config), std::invalid_argument);
    }
    
    // Test: mean outside bounds should fail
    {
        ScanScheduler scheduler2;
        ScanSchedulerConfig config;
        config.min_interval_ms = 500;
        config.max_interval_ms = 1500;
        config.mean_interval_ms = 2000;  // Outside bounds
        EXPECT_THROW(scheduler2.Initialize(config), std::invalid_argument);
    }
    
    // Test: Less than 50% variation should fail
    {
        ScanScheduler scheduler3;
        ScanSchedulerConfig config;
        config.min_interval_ms = 900;
        config.max_interval_ms = 1100;
        config.mean_interval_ms = 1000;  // Only 10% variation
        EXPECT_THROW(scheduler3.Initialize(config), std::invalid_argument);
    }
}

/**
 * Test: Interval Randomization
 * Verifies that generated intervals vary by at least 50% from mean
 */
TEST(ScanSchedulerTests, IntervalRandomization) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 500;
    config.max_interval_ms = 1500;
    config.mean_interval_ms = 1000;
    
    scheduler.Initialize(config);
    
    // Generate 100 intervals
    std::vector<uint32_t> intervals;
    for (int i = 0; i < 100; i++) {
        uint32_t interval = scheduler.GetNextInterval();
        intervals.push_back(interval);
        
        // Verify within bounds
        EXPECT_GE(interval, config.min_interval_ms);
        EXPECT_LE(interval, config.max_interval_ms);
    }
    
    // Verify at least 50% variation from mean
    uint32_t min_val = *std::min_element(intervals.begin(), intervals.end());
    uint32_t max_val = *std::max_element(intervals.begin(), intervals.end());
    
    EXPECT_LE(min_val, static_cast<uint32_t>(config.mean_interval_ms * 0.7))
        << "Minimum interval should be significantly below mean";
    EXPECT_GE(max_val, static_cast<uint32_t>(config.mean_interval_ms * 1.3))
        << "Maximum interval should be significantly above mean";
    
    scheduler.Shutdown();
}

/**
 * Test: Statistical Distribution
 * Verifies uniform distribution of 1000 scan intervals
 */
TEST(ScanSchedulerTests, StatisticalDistribution) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 500;
    config.max_interval_ms = 1500;
    config.mean_interval_ms = 1000;
    
    scheduler.Initialize(config);
    
    // Generate 1000 intervals as per requirements
    std::vector<uint32_t> intervals;
    for (int i = 0; i < 1000; i++) {
        intervals.push_back(scheduler.GetNextInterval());
    }
    
    // Calculate mean
    double sum = std::accumulate(intervals.begin(), intervals.end(), 0.0);
    double mean = sum / intervals.size();
    
    // Calculate variance
    double variance_sum = 0.0;
    for (uint32_t val : intervals) {
        double diff = val - mean;
        variance_sum += diff * diff;
    }
    double variance = variance_sum / intervals.size();
    double stddev = std::sqrt(variance);
    
    // For uniform distribution [a, b]:
    // Expected mean = (a + b) / 2
    // Expected variance = (b - a)^2 / 12
    double expected_mean = (config.min_interval_ms + config.max_interval_ms) / 2.0;
    double expected_variance = std::pow(config.max_interval_ms - config.min_interval_ms, 2) / 12.0;
    double expected_stddev = std::sqrt(expected_variance);
    
    // Allow 10% tolerance for statistical variation
    EXPECT_NEAR(mean, expected_mean, expected_mean * 0.1)
        << "Mean should be close to expected uniform distribution mean";
    EXPECT_NEAR(stddev, expected_stddev, expected_stddev * 0.15)
        << "Standard deviation should be close to expected uniform distribution";
    
    // Chi-square test for uniformity (simplified)
    // Divide range into 10 buckets and check distribution
    const int num_buckets = 10;
    std::vector<int> buckets(num_buckets, 0);
    uint32_t bucket_size = (config.max_interval_ms - config.min_interval_ms) / num_buckets;
    
    for (uint32_t interval : intervals) {
        int bucket_index = (interval - config.min_interval_ms) / bucket_size;
        if (bucket_index >= num_buckets) bucket_index = num_buckets - 1;
        buckets[bucket_index]++;
    }
    
    // Expected count per bucket for uniform distribution
    double expected_per_bucket = intervals.size() / static_cast<double>(num_buckets);
    
    // Each bucket should have roughly equal counts (allow 30% variation)
    for (int i = 0; i < num_buckets; i++) {
        EXPECT_NEAR(buckets[i], expected_per_bucket, expected_per_bucket * 0.3)
            << "Bucket " << i << " count should be close to expected uniform distribution";
    }
    
    scheduler.Shutdown();
}

/**
 * Test: Scan Timing
 * Verifies ShouldScan() returns true at appropriate times
 */
TEST(ScanSchedulerTests, ScanTiming) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 50;   // 50% variation from mean
    config.max_interval_ms = 150;  // 50% variation from mean
    config.mean_interval_ms = 100;
    
    scheduler.Initialize(config);
    
    // Should not scan immediately after init
    EXPECT_FALSE(scheduler.ShouldScan())
        << "Should not scan immediately after initialization";
    
    // Wait for first interval
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Should scan after waiting
    EXPECT_TRUE(scheduler.ShouldScan())
        << "Should scan after waiting past max interval";
    
    // Mark scan complete
    scheduler.MarkScanComplete();
    
    // Should not scan immediately after completing
    EXPECT_FALSE(scheduler.ShouldScan())
        << "Should not scan immediately after marking scan complete";
    
    scheduler.Shutdown();
}

/**
 * Test: Scan Type Randomization
 * Verifies that scan types are returned in randomized order
 */
TEST(ScanSchedulerTests, ScanTypeRandomization) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 500;
    config.max_interval_ms = 1500;
    config.mean_interval_ms = 1000;
    config.vary_scan_order = true;
    
    scheduler.Initialize(config);
    
    // Get 30 scan types
    std::vector<ScanType> scan_types;
    for (int i = 0; i < 30; i++) {
        scan_types.push_back(scheduler.GetNextScanType());
    }
    
    // Verify we got different types
    std::set<ScanType> unique_types(scan_types.begin(), scan_types.end());
    EXPECT_GT(unique_types.size(), 3)
        << "Should see at least 4 different scan types in 30 calls";
    
    // Verify order changes (not always sequential)
    bool order_changed = false;
    for (size_t i = 1; i < scan_types.size(); i++) {
        if (static_cast<int>(scan_types[i]) != (static_cast<int>(scan_types[i-1]) + 1) % 6) {
            order_changed = true;
            break;
        }
    }
    EXPECT_TRUE(order_changed)
        << "Scan type order should not be strictly sequential";
    
    scheduler.Shutdown();
}

/**
 * Test: Burst Mode Activation
 * Verifies burst mode activates and deactivates correctly
 */
TEST(ScanSchedulerTests, BurstModeActivation) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 500;
    config.max_interval_ms = 1500;
    config.mean_interval_ms = 1000;
    config.burst_min_interval_ms = 50;
    config.burst_max_interval_ms = 150;
    config.burst_duration_ms = 500;
    config.enable_burst_scans = true;
    
    scheduler.Initialize(config);
    
    // Should not be in burst mode initially
    EXPECT_FALSE(scheduler.IsInBurstMode())
        << "Should not be in burst mode initially";
    
    // Trigger burst mode
    scheduler.TriggerBurstMode();
    
    // Should now be in burst mode
    EXPECT_TRUE(scheduler.IsInBurstMode())
        << "Should be in burst mode after triggering";
    
    // Wait for burst duration to expire
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    
    // Check if burst mode expired by calling ShouldScan() which updates mode state
    // ShouldScan() internally checks if burst_mode_end_time_ms_ has passed and
    // transitions out of burst mode if needed
    scheduler.ShouldScan();
    
    // Should exit burst mode after duration
    EXPECT_FALSE(scheduler.IsInBurstMode())
        << "Should exit burst mode after duration expires";
    
    scheduler.Shutdown();
}

/**
 * Test: Burst Mode Intervals
 * Verifies that burst mode uses shorter intervals
 */
TEST(ScanSchedulerTests, BurstModeIntervals) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 500;
    config.max_interval_ms = 1500;
    config.mean_interval_ms = 1000;
    config.burst_min_interval_ms = 50;
    config.burst_max_interval_ms = 150;
    config.enable_burst_scans = true;
    
    scheduler.Initialize(config);
    
    // Trigger burst mode
    scheduler.TriggerBurstMode();
    
    // Generate intervals in burst mode
    std::vector<uint32_t> burst_intervals;
    for (int i = 0; i < 50; i++) {
        uint32_t interval = scheduler.GetNextInterval();
        burst_intervals.push_back(interval);
        
        // Should be within burst bounds
        EXPECT_GE(interval, config.burst_min_interval_ms);
        EXPECT_LE(interval, config.burst_max_interval_ms);
    }
    
    // Average should be much lower than normal mode
    double avg_burst = std::accumulate(burst_intervals.begin(), burst_intervals.end(), 0.0) 
                       / burst_intervals.size();
    EXPECT_LT(avg_burst, 200)
        << "Burst mode average interval should be significantly lower than normal";
    
    scheduler.Shutdown();
}

/**
 * Test: Behavioral Signal Triggering
 * Verifies that high behavioral signals trigger burst mode
 */
TEST(ScanSchedulerTests, BehavioralSignalTriggering) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 500;
    config.max_interval_ms = 1500;
    config.mean_interval_ms = 1000;
    config.enable_burst_scans = true;
    config.burst_trigger_threshold = 0.7f;
    
    scheduler.Initialize(config);
    
    // Record low signal - should not trigger
    scheduler.RecordBehavioralSignal(0.5f);
    EXPECT_FALSE(scheduler.IsInBurstMode())
        << "Low signal should not trigger burst mode";
    
    // Record high signal - should trigger
    scheduler.RecordBehavioralSignal(0.9f);
    EXPECT_TRUE(scheduler.IsInBurstMode())
        << "High signal above threshold should trigger burst mode";
    
    scheduler.Shutdown();
}

/**
 * Test: Statistics Collection
 * Verifies that timing statistics are collected correctly
 */
TEST(ScanSchedulerTests, StatisticsCollection) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 50;   // 50% variation from mean
    config.max_interval_ms = 150;  // 50% variation from mean
    config.mean_interval_ms = 100;
    
    scheduler.Initialize(config);
    
    // Perform multiple scan cycles
    for (int i = 0; i < 10; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        if (scheduler.ShouldScan()) {
            scheduler.MarkScanComplete();
        }
    }
    
    // Get statistics
    ScanTimingStats stats;
    scheduler.GetStatistics(stats);
    
    // Should have recorded some scans
    EXPECT_GT(stats.total_scans, 0)
        << "Should have recorded at least one scan";
    
    // Should have interval statistics
    if (stats.intervals_recorded > 0) {
        EXPECT_GT(stats.mean_interval, 0)
            << "Mean interval should be positive";
        EXPECT_GE(stats.max_interval_observed, stats.min_interval_observed)
            << "Max interval should be >= min interval";
    }
    
    scheduler.Shutdown();
}

/**
 * Test: Performance Overhead
 * Verifies that randomization overhead is negligible
 */
TEST(ScanSchedulerTests, PerformanceOverhead) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 500;
    config.max_interval_ms = 1500;
    config.mean_interval_ms = 1000;
    
    scheduler.Initialize(config);
    
    // Measure time to generate 10000 intervals
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; i++) {
        scheduler.GetNextInterval();
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double avg_us = duration_us / 10000.0;
    
    // Average should be less than 10 microseconds per call
    EXPECT_LT(avg_us, 10.0)
        << "Random interval generation should take less than 10 microseconds on average";
    
    scheduler.Shutdown();
}

/**
 * Test: No Timing Side Channels
 * Verifies that timing patterns are not observable from external state
 */
TEST(ScanSchedulerTests, NoTimingSideChannels) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 500;
    config.max_interval_ms = 1500;
    config.mean_interval_ms = 1000;
    
    scheduler.Initialize(config);
    
    // Generate multiple intervals and measure timing
    std::vector<uint32_t> intervals;
    std::vector<double> generation_times_us;
    
    for (int i = 0; i < 100; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        uint32_t interval = scheduler.GetNextInterval();
        auto end = std::chrono::high_resolution_clock::now();
        
        intervals.push_back(interval);
        generation_times_us.push_back(
            std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count() / 1000.0
        );
    }
    
    // Calculate correlation between interval value and generation time
    // If there's a timing side-channel, these would correlate
    double mean_interval = std::accumulate(intervals.begin(), intervals.end(), 0.0) / intervals.size();
    double mean_time = std::accumulate(generation_times_us.begin(), generation_times_us.end(), 0.0) 
                       / generation_times_us.size();
    
    double covariance = 0.0;
    double var_interval = 0.0;
    double var_time = 0.0;
    
    for (size_t i = 0; i < intervals.size(); i++) {
        double diff_interval = intervals[i] - mean_interval;
        double diff_time = generation_times_us[i] - mean_time;
        covariance += diff_interval * diff_time;
        var_interval += diff_interval * diff_interval;
        var_time += diff_time * diff_time;
    }
    
    // Correlation coefficient
    double correlation = 0.0;
    if (var_interval > 0 && var_time > 0) {
        correlation = std::abs(covariance / std::sqrt(var_interval * var_time));
    }
    
    // Correlation should be very weak (< 0.3)
    EXPECT_LT(correlation, 0.3)
        << "Should not have observable correlation between interval value and generation time";
    
    scheduler.Shutdown();
}

/**
 * Test: Thread Safety
 * Verifies that scheduler can be safely accessed from multiple threads
 */
TEST(ScanSchedulerTests, ThreadSafety) {
    ScanScheduler scheduler;
    
    ScanSchedulerConfig config;
    config.min_interval_ms = 500;
    config.max_interval_ms = 1500;
    config.mean_interval_ms = 1000;
    
    scheduler.Initialize(config);
    
    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;
    
    // Spawn multiple threads calling different methods
    for (int i = 0; i < 4; i++) {
        threads.emplace_back([&scheduler, &stop]() {
            while (!stop.load()) {
                scheduler.GetNextInterval();
                scheduler.ShouldScan();
                scheduler.GetNextScanType();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
    }
    
    // Let them run for a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Stop threads
    stop.store(true);
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Should still be functional
    EXPECT_NO_THROW(scheduler.GetNextInterval());
    
    scheduler.Shutdown();
}
