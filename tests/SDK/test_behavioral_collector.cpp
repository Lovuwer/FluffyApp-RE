/**
 * Sentinel SDK - BehavioralCollector Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 12: Tests for Behavioral Telemetry Collection
 */

#include <gtest/gtest.h>
#include "Internal/BehavioralCollector.hpp"
#include "Internal/Detection.hpp"
#include <thread>
#include <chrono>

using namespace Sentinel::SDK;

/**
 * Test 1: Initialization and Configuration
 */
TEST(BehavioralCollectorTests, Initialization) {
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.sample_rate_ms = 1000;
    config.aggregation_window_ms = 5000;  // Short window for testing
    
    EXPECT_NO_THROW(collector.Initialize(config));
    EXPECT_NO_THROW(collector.Shutdown());
}

/**
 * Test 2: Input Metric Collection
 */
TEST(BehavioralCollectorTests, InputMetricCollection) {
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.sample_rate_ms = 100;
    config.aggregation_window_ms = 1000;
    config.collect_input = true;
    config.collect_movement = false;
    config.collect_aim = false;
    
    collector.Initialize(config);
    
    // Record some input events
    uint64_t base_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    for (int i = 0; i < 10; ++i) {
        collector.RecordInput(base_time + i * 100, 1);
    }
    
    // Get current aggregated data
    auto data = collector.GetCurrentData();
    
    EXPECT_GT(data.sample_count, 0u);
    EXPECT_GT(data.input.actions_per_minute, 0u);
    EXPECT_GT(data.input.avg_input_interval_ms, 0.0f);
    
    collector.Shutdown();
}

/**
 * Test 3: Movement Metric Collection
 */
TEST(BehavioralCollectorTests, MovementMetricCollection) {
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.sample_rate_ms = 100;
    config.aggregation_window_ms = 1000;
    config.collect_input = false;
    config.collect_movement = true;
    config.collect_aim = false;
    
    collector.Initialize(config);
    
    // Record movement samples
    for (int i = 0; i < 10; ++i) {
        float velocity = 10.0f + i * 2.0f;
        float direction_change = 0.5f;
        collector.RecordMovement(velocity, direction_change);
    }
    
    auto data = collector.GetCurrentData();
    
    EXPECT_GT(data.sample_count, 0u);
    EXPECT_GT(data.movement.avg_velocity, 0.0f);
    EXPECT_GT(data.movement.max_velocity, 0.0f);
    EXPECT_LE(data.movement.max_velocity, 100.0f);
    
    collector.Shutdown();
}

/**
 * Test 4: Aim Metric Collection
 */
TEST(BehavioralCollectorTests, AimMetricCollection) {
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.sample_rate_ms = 100;
    config.aggregation_window_ms = 1000;
    config.collect_input = false;
    config.collect_movement = false;
    config.collect_aim = true;
    
    collector.Initialize(config);
    
    // Record aim samples
    for (int i = 0; i < 20; ++i) {
        float precision = 0.7f + (i % 3) * 0.1f;
        float flick_speed = 50.0f + i * 5.0f;
        bool is_headshot = (i % 4 == 0);
        collector.RecordAim(precision, flick_speed, is_headshot);
    }
    
    auto data = collector.GetCurrentData();
    
    EXPECT_GT(data.sample_count, 0u);
    EXPECT_GT(data.aim.avg_precision, 0.0f);
    EXPECT_LE(data.aim.avg_precision, 1.0f);
    EXPECT_GT(data.aim.headshot_percentage, 0.0f);
    EXPECT_LE(data.aim.headshot_percentage, 100.0f);
    
    collector.Shutdown();
}

/**
 * Test 5: Custom Metric Collection
 */
TEST(BehavioralCollectorTests, CustomMetricCollection) {
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.aggregation_window_ms = 1000;
    
    collector.Initialize(config);
    
    // Record custom metrics
    collector.RecordCustomMetric("player_score", 1234.5f, "points");
    collector.RecordCustomMetric("building_count", 42.0f, "buildings");
    collector.RecordCustomMetric("resource_rate", 15.7f, "per_minute");
    
    auto data = collector.GetCurrentData();
    
    EXPECT_EQ(data.custom.size(), 3u);
    EXPECT_EQ(data.custom[0].name, "player_score");
    EXPECT_FLOAT_EQ(data.custom[0].value, 1234.5f);
    EXPECT_EQ(data.custom[0].unit, "points");
    
    collector.Shutdown();
}

/**
 * Test 6: Aggregation Window Trigger
 */
TEST(BehavioralCollectorTests, AggregationWindowTrigger) {
    MockCloudReporter mock_reporter;
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.aggregation_window_ms = 500;  // 500ms window
    config.collect_input = true;
    
    collector.Initialize(config);
    collector.SetCloudReporter(&mock_reporter);
    
    // Record some data
    uint64_t base_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    for (int i = 0; i < 5; ++i) {
        collector.RecordInput(base_time + i * 50, 1);
    }
    
    // Wait for aggregation window to trigger
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    
    // Check that data was transmitted
    EXPECT_GT(mock_reporter.GetEventsReceived(), 0);
    EXPECT_EQ(mock_reporter.GetLastEventType(), "behavioral_telemetry");
    
    collector.Shutdown();
}

/**
 * Test 7: Manual Flush
 */
TEST(BehavioralCollectorTests, ManualFlush) {
    MockCloudReporter mock_reporter;
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.aggregation_window_ms = 60000;  // Long window
    config.collect_input = true;
    
    collector.Initialize(config);
    collector.SetCloudReporter(&mock_reporter);
    
    // Record some data
    uint64_t base_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    collector.RecordInput(base_time, 1);
    collector.RecordInput(base_time + 100, 1);
    
    // Manually flush
    collector.Flush();
    
    // Wait a bit for async processing
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    EXPECT_GT(mock_reporter.GetEventsReceived(), 0);
    
    collector.Shutdown();
}

/**
 * Test 8: Bandwidth Requirements (< 1KB per minute)
 */
TEST(BehavioralCollectorTests, BandwidthRequirements) {
    MockCloudReporter mock_reporter;
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.aggregation_window_ms = 60000;  // 1 minute
    config.collect_input = true;
    config.collect_movement = true;
    config.collect_aim = true;
    
    collector.Initialize(config);
    collector.SetCloudReporter(&mock_reporter);
    
    // Simulate typical 1-minute gameplay
    uint64_t base_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    // ~60 inputs per minute (1 per second)
    for (int i = 0; i < 60; ++i) {
        collector.RecordInput(base_time + i * 1000, 1);
    }
    
    // ~60 movement samples
    for (int i = 0; i < 60; ++i) {
        collector.RecordMovement(15.0f, 0.5f);
    }
    
    // ~30 aim samples
    for (int i = 0; i < 30; ++i) {
        collector.RecordAim(0.75f, 80.0f, i % 5 == 0);
    }
    
    // Add a few custom metrics
    collector.RecordCustomMetric("combat_score", 500.0f);
    collector.RecordCustomMetric("objectives", 3.0f);
    
    // Flush and check size
    collector.Flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    size_t transmitted_size = mock_reporter.GetLastDataSize();
    
    // Should be under 1KB (1024 bytes)
    EXPECT_LT(transmitted_size, 1024u) 
        << "Transmitted size: " << transmitted_size << " bytes";
    
    // Should have some reasonable minimum size
    EXPECT_GT(transmitted_size, 100u)
        << "Transmitted size seems too small: " << transmitted_size << " bytes";
    
    collector.Shutdown();
}

/**
 * Test 9: Privacy Compliance (no raw keystrokes)
 */
TEST(BehavioralCollectorTests, PrivacyCompliance) {
    MockCloudReporter mock_reporter;
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.aggregation_window_ms = 1000;
    config.collect_input = true;
    
    collector.Initialize(config);
    collector.SetCloudReporter(&mock_reporter);
    
    // Record inputs (note: only timestamps, no key data)
    uint64_t base_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    for (int i = 0; i < 10; ++i) {
        collector.RecordInput(base_time + i * 100, 1);
    }
    
    collector.Flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Check transmitted data doesn't contain raw input details
    std::string data = mock_reporter.GetLastEventData();
    
    // Should contain aggregated metrics
    EXPECT_NE(data.find("actions_per_minute"), std::string::npos);
    EXPECT_NE(data.find("avg_input_interval_ms"), std::string::npos);
    
    // Should NOT contain individual timestamps or keys
    EXPECT_EQ(data.find("key"), std::string::npos);
    EXPECT_EQ(data.find("timestamp"), std::string::npos);  // Individual timestamps
    
    collector.Shutdown();
}

/**
 * Test 10: Disabled Collection
 */
TEST(BehavioralCollectorTests, DisabledCollection) {
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = false;  // Disabled
    
    collector.Initialize(config);
    
    // Try to record data
    uint64_t base_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    collector.RecordInput(base_time, 1);
    collector.RecordMovement(10.0f, 0.5f);
    collector.RecordAim(0.8f, 50.0f);
    
    // Should have no samples
    auto data = collector.GetCurrentData();
    EXPECT_EQ(data.sample_count, 0u);
    
    collector.Shutdown();
}

/**
 * Test 11: Selective Metric Collection
 */
TEST(BehavioralCollectorTests, SelectiveMetricCollection) {
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.collect_input = true;
    config.collect_movement = false;  // Disabled
    config.collect_aim = true;
    
    collector.Initialize(config);
    
    uint64_t base_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    // Record all types
    collector.RecordInput(base_time, 1);
    collector.RecordMovement(10.0f, 0.5f);
    collector.RecordAim(0.8f, 50.0f);
    
    auto data = collector.GetCurrentData();
    
    // Input should be collected
    EXPECT_GT(data.input.actions_per_minute, 0u);
    
    // Movement should NOT be collected (should be default values)
    EXPECT_FLOAT_EQ(data.movement.avg_velocity, 0.0f);
    
    // Aim should be collected
    EXPECT_GT(data.aim.avg_precision, 0.0f);
    
    collector.Shutdown();
}

/**
 * Test 12: Memory Overflow Prevention
 */
TEST(BehavioralCollectorTests, MemoryOverflowPrevention) {
    BehavioralCollector collector;
    
    BehavioralConfig config;
    config.enabled = true;
    config.aggregation_window_ms = 60000;  // Long window
    config.collect_input = true;
    
    collector.Initialize(config);
    
    uint64_t base_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    // Try to overflow with many samples
    for (int i = 0; i < 20000; ++i) {
        collector.RecordInput(base_time + i, 1);
    }
    
    // Should cap at max samples
    auto data = collector.GetCurrentData();
    EXPECT_LE(data.sample_count, 10000u);  // MAX_SAMPLES_PER_WINDOW
    
    collector.Shutdown();
}
