/**
 * Sentinel SDK - Timing Randomizer Tests
 * 
 * Task 22: Runtime Behavior Variation Tests
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/TimingRandomizer.hpp"

#include <vector>
#include <algorithm>
#include <cmath>
#include <numeric>
#include <set>

using namespace Sentinel::SDK;

/**
 * Test: Basic Initialization
 * Verifies that TimingRandomizer initializes correctly
 */
TEST(TimingRandomizerTests, BasicInitialization) {
    TimingRandomizer randomizer;
    EXPECT_TRUE(randomizer.IsHealthy())
        << "TimingRandomizer should initialize successfully";
}

/**
 * Test: AddJitter Basic Functionality
 * Verifies that AddJitter returns values within expected bounds
 */
TEST(TimingRandomizerTests, AddJitterBasicFunctionality) {
    TimingRandomizer randomizer;
    
    uint32_t base_value = 1000;
    uint32_t variation = 50;  // 50% variation
    
    // Generate 100 values and verify bounds
    for (int i = 0; i < 100; i++) {
        uint32_t value = randomizer.AddJitter(base_value, variation);
        
        // With 50% variation: [500, 1500]
        EXPECT_GE(value, 500u) << "Value should be >= min bound";
        EXPECT_LE(value, 1500u) << "Value should be <= max bound";
    }
}

/**
 * Test: AddJitter Statistical Distribution
 * Verifies uniform distribution over 1000 samples (requirement)
 */
TEST(TimingRandomizerTests, AddJitterStatisticalDistribution) {
    TimingRandomizer randomizer;
    
    uint32_t base_value = 1000;
    uint32_t variation = 50;  // 50% variation: [500, 1500]
    
    // Generate 1000 samples as per requirements
    std::vector<uint32_t> samples;
    for (int i = 0; i < 1000; i++) {
        samples.push_back(randomizer.AddJitter(base_value, variation));
    }
    
    // Calculate mean
    double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    double mean = sum / samples.size();
    
    // Expected mean for uniform distribution [500, 1500] is 1000
    EXPECT_NEAR(mean, 1000.0, 100.0)
        << "Mean should be close to expected value";
    
    // Calculate variance
    double variance_sum = 0.0;
    for (uint32_t val : samples) {
        double diff = val - mean;
        variance_sum += diff * diff;
    }
    double variance = variance_sum / samples.size();
    double stddev = std::sqrt(variance);
    
    // For uniform distribution [a, b]:
    // Expected variance = (b - a)^2 / 12 = 1000^2 / 12 ≈ 83333
    // Expected stddev ≈ 289
    double expected_variance = (1000.0 * 1000.0) / 12.0;
    double expected_stddev = std::sqrt(expected_variance);
    
    EXPECT_NEAR(stddev, expected_stddev, expected_stddev * 0.15)
        << "Standard deviation should match uniform distribution";
    
    // Chi-square test for uniformity
    const int num_buckets = 10;
    std::vector<int> buckets(num_buckets, 0);
    uint32_t bucket_size = (1500 - 500) / num_buckets;  // 100ms per bucket
    
    for (uint32_t value : samples) {
        int bucket_index = (value - 500) / bucket_size;
        if (bucket_index >= num_buckets) bucket_index = num_buckets - 1;
        buckets[bucket_index]++;
    }
    
    // Expected count per bucket for uniform distribution
    double expected_per_bucket = samples.size() / static_cast<double>(num_buckets);
    
    // Each bucket should have roughly equal counts (allow 30% variation)
    for (int i = 0; i < num_buckets; i++) {
        EXPECT_NEAR(buckets[i], expected_per_bucket, expected_per_bucket * 0.3)
            << "Bucket " << i << " count should be close to expected uniform distribution";
    }
}

/**
 * Test: AddJitter Different Variation Percentages
 * Verifies that different variation percentages work correctly
 */
TEST(TimingRandomizerTests, AddJitterVariationPercentages) {
    TimingRandomizer randomizer;
    uint32_t base_value = 1000;
    
    // Test 25% variation
    {
        std::vector<uint32_t> samples;
        for (int i = 0; i < 100; i++) {
            samples.push_back(randomizer.AddJitter(base_value, 25));
        }
        
        uint32_t min_val = *std::min_element(samples.begin(), samples.end());
        uint32_t max_val = *std::max_element(samples.begin(), samples.end());
        
        // With 25% variation: [750, 1250]
        EXPECT_GE(min_val, 750u);
        EXPECT_LE(max_val, 1250u);
    }
    
    // Test 100% variation
    {
        std::vector<uint32_t> samples;
        for (int i = 0; i < 100; i++) {
            samples.push_back(randomizer.AddJitter(base_value, 100));
        }
        
        uint32_t min_val = *std::min_element(samples.begin(), samples.end());
        uint32_t max_val = *std::max_element(samples.begin(), samples.end());
        
        // With 100% variation: [0, 2000]
        EXPECT_GE(min_val, 0u);
        EXPECT_LE(max_val, 2000u);
    }
}

/**
 * Test: GenerateInRange Basic Functionality
 * Verifies that GenerateInRange returns values within specified range
 */
TEST(TimingRandomizerTests, GenerateInRangeBasic) {
    TimingRandomizer randomizer;
    
    uint32_t min_val = 500;
    uint32_t max_val = 1500;
    
    // Generate 100 values
    for (int i = 0; i < 100; i++) {
        uint32_t value = randomizer.GenerateInRange(min_val, max_val);
        
        EXPECT_GE(value, min_val) << "Value should be >= min";
        EXPECT_LE(value, max_val) << "Value should be <= max";
    }
}

/**
 * Test: GenerateInRange Statistical Distribution
 * Verifies uniform distribution for range-based generation
 */
TEST(TimingRandomizerTests, GenerateInRangeDistribution) {
    TimingRandomizer randomizer;
    
    uint32_t min_val = 0;
    uint32_t max_val = 1000;
    
    // Generate 1000 samples
    std::vector<uint32_t> samples;
    for (int i = 0; i < 1000; i++) {
        samples.push_back(randomizer.GenerateInRange(min_val, max_val));
    }
    
    // Calculate mean (should be around 500)
    double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    double mean = sum / samples.size();
    
    EXPECT_NEAR(mean, 500.0, 50.0)
        << "Mean should be close to midpoint";
    
    // Check distribution across buckets
    const int num_buckets = 10;
    std::vector<int> buckets(num_buckets, 0);
    uint32_t bucket_size = (max_val - min_val + 1) / num_buckets;
    
    for (uint32_t value : samples) {
        int bucket_index = (value - min_val) / bucket_size;
        if (bucket_index >= num_buckets) bucket_index = num_buckets - 1;
        buckets[bucket_index]++;
    }
    
    double expected_per_bucket = samples.size() / static_cast<double>(num_buckets);
    
    for (int i = 0; i < num_buckets; i++) {
        EXPECT_NEAR(buckets[i], expected_per_bucket, expected_per_bucket * 0.3)
            << "Bucket " << i << " should have uniform distribution";
    }
}

/**
 * Test: Edge Cases
 * Verifies behavior with edge case inputs
 */
TEST(TimingRandomizerTests, EdgeCases) {
    TimingRandomizer randomizer;
    
    // Zero base value
    {
        uint32_t value = randomizer.AddJitter(0, 50);
        EXPECT_EQ(value, 0u) << "Zero base value should return zero";
    }
    
    // Same min and max
    {
        uint32_t value = randomizer.GenerateInRange(1000, 1000);
        EXPECT_EQ(value, 1000u) << "Same min/max should return that value";
    }
    
    // Swapped min and max (should auto-correct)
    {
        uint32_t value = randomizer.GenerateInRange(1500, 500);
        EXPECT_GE(value, 500u);
        EXPECT_LE(value, 1500u);
    }
    
    // Small base value
    {
        uint32_t value = randomizer.AddJitter(10, 50);
        EXPECT_GE(value, 5u);
        EXPECT_LE(value, 15u);
    }
}

/**
 * Test: No Observable Timing Side Channels
 * Verifies that generation time doesn't correlate with output value
 */
TEST(TimingRandomizerTests, NoTimingSideChannels) {
    TimingRandomizer randomizer;
    
    std::vector<uint32_t> values;
    std::vector<double> generation_times_us;
    
    // Generate 100 samples and measure timing
    for (int i = 0; i < 100; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        uint32_t value = randomizer.AddJitter(1000, 50);
        auto end = std::chrono::high_resolution_clock::now();
        
        values.push_back(value);
        generation_times_us.push_back(
            std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count() / 1000.0
        );
    }
    
    // Calculate correlation between value and generation time
    double mean_value = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    double mean_time = std::accumulate(generation_times_us.begin(), generation_times_us.end(), 0.0) 
                       / generation_times_us.size();
    
    double covariance = 0.0;
    double var_value = 0.0;
    double var_time = 0.0;
    
    for (size_t i = 0; i < values.size(); i++) {
        double diff_value = values[i] - mean_value;
        double diff_time = generation_times_us[i] - mean_time;
        covariance += diff_value * diff_time;
        var_value += diff_value * diff_value;
        var_time += diff_time * diff_time;
    }
    
    double correlation = 0.0;
    if (var_value > 0 && var_time > 0) {
        correlation = std::abs(covariance / std::sqrt(var_value * var_time));
    }
    
    // Correlation should be very weak (< 0.3)
    EXPECT_LT(correlation, 0.3)
        << "Should not have observable correlation between value and generation time";
}

/**
 * Test: Performance
 * Verifies that randomization has minimal overhead
 */
TEST(TimingRandomizerTests, Performance) {
    TimingRandomizer randomizer;
    
    // Measure time to generate 10000 values
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; i++) {
        randomizer.AddJitter(1000, 50);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double avg_us = duration_us / 10000.0;
    
    // Average should be less than 10 microseconds per call
    EXPECT_LT(avg_us, 10.0)
        << "Random jitter generation should take less than 10 microseconds on average";
}

/**
 * Test: Operation Count Tracking
 * Verifies that operation count is tracked correctly
 */
TEST(TimingRandomizerTests, OperationCountTracking) {
    TimingRandomizer randomizer;
    
    EXPECT_EQ(randomizer.GetOperationCount(), 0u)
        << "Initial operation count should be zero";
    
    // Perform some operations
    for (int i = 0; i < 10; i++) {
        randomizer.AddJitter(1000, 50);
    }
    
    EXPECT_EQ(randomizer.GetOperationCount(), 10u)
        << "Operation count should track number of calls";
    
    // Add more operations
    for (int i = 0; i < 5; i++) {
        randomizer.GenerateInRange(500, 1500);
    }
    
    EXPECT_EQ(randomizer.GetOperationCount(), 15u)
        << "Operation count should continue tracking";
}

/**
 * Test: Thread Safety
 * Verifies that TimingRandomizer is thread-safe
 */
TEST(TimingRandomizerTests, ThreadSafety) {
    TimingRandomizer randomizer;
    
    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;
    
    // Spawn multiple threads
    for (int i = 0; i < 4; i++) {
        threads.emplace_back([&randomizer, &stop]() {
            while (!stop.load()) {
                randomizer.AddJitter(1000, 50);
                randomizer.GenerateInRange(500, 1500);
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
    
    // Should have performed many operations without crashing
    EXPECT_GT(randomizer.GetOperationCount(), 0u);
}

/**
 * Test: Consistency Across Multiple Instances
 * Verifies that multiple TimingRandomizer instances work independently
 */
TEST(TimingRandomizerTests, MultipleInstances) {
    TimingRandomizer randomizer1;
    TimingRandomizer randomizer2;
    
    // Both should initialize successfully
    EXPECT_TRUE(randomizer1.IsHealthy());
    EXPECT_TRUE(randomizer2.IsHealthy());
    
    // Generate values from both
    std::vector<uint32_t> values1, values2;
    for (int i = 0; i < 50; i++) {
        values1.push_back(randomizer1.AddJitter(1000, 50));
        values2.push_back(randomizer2.AddJitter(1000, 50));
    }
    
    // Values should be different (not identical sequences)
    EXPECT_NE(values1, values2)
        << "Different instances should generate different random sequences";
    
    // Both should have independent operation counts
    EXPECT_EQ(randomizer1.GetOperationCount(), 50u);
    EXPECT_EQ(randomizer2.GetOperationCount(), 50u);
}
