/**
 * Sentinel SDK - Performance Telemetry Tests
 * 
 * Tests for performance monitoring and self-throttling features (Task 17).
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/PerfTelemetry.hpp"
#include <thread>
#include <chrono>
#include <cmath>

using namespace Sentinel::SDK;

// ==================== Performance Telemetry Tests ====================

class PerformanceTelemetryTest : public ::testing::Test {
protected:
    void SetUp() override {
        telemetry.Initialize();
    }
    
    void TearDown() override {
        telemetry.Shutdown();
    }
    
    PerformanceTelemetry telemetry;
};

TEST_F(PerformanceTelemetryTest, BasicInitialization) {
    // Test passes if no crash during setup/teardown
    EXPECT_NO_THROW(telemetry.Reset());
}

TEST_F(PerformanceTelemetryTest, RecordSingleOperation) {
    // Record a single operation
    telemetry.RecordOperation(OperationType::Update, 1.5);
    
    // Get metrics
    auto metrics = telemetry.GetMetrics(OperationType::Update);
    
    EXPECT_EQ(metrics.operation, OperationType::Update);
    EXPECT_EQ(metrics.total_operations, 1u);
    EXPECT_EQ(metrics.throttled_operations, 0u);
    EXPECT_FALSE(metrics.is_throttled);
}

TEST_F(PerformanceTelemetryTest, RecordMultipleOperations) {
    // Record multiple operations
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 1.0 + i * 0.1);
    }
    
    auto metrics = telemetry.GetMetrics(OperationType::Update);
    
    EXPECT_EQ(metrics.total_operations, 100u);
    EXPECT_GT(metrics.current_window.sample_count, 0u);
}

TEST_F(PerformanceTelemetryTest, PercentileCalculationAccuracy) {
    // Create a known distribution: 1.0, 2.0, 3.0, ..., 100.0 ms
    for (int i = 1; i <= 1000; i++) {
        telemetry.RecordOperation(OperationType::Update, static_cast<double>(i));
    }
    
    // Force percentile recalculation
    telemetry.RecalculatePercentiles();
    
    auto metrics = telemetry.GetMetrics(OperationType::Update);
    
    // Check that percentiles are in the expected ranges
    // P50 should be around 500ms
    EXPECT_GT(metrics.current_window.p50_ms, 450.0);
    EXPECT_LT(metrics.current_window.p50_ms, 550.0);
    
    // P95 should be around 950ms
    EXPECT_GT(metrics.current_window.p95_ms, 900.0);
    EXPECT_LT(metrics.current_window.p95_ms, 1000.0);
    
    // P99 should be around 990ms
    EXPECT_GT(metrics.current_window.p99_ms, 980.0);
    EXPECT_LT(metrics.current_window.p99_ms, 1000.0);
    
    // Min should be 1.0
    EXPECT_DOUBLE_EQ(metrics.current_window.min_ms, 1.0);
    
    // Max should be 1000.0
    EXPECT_DOUBLE_EQ(metrics.current_window.max_ms, 1000.0);
}

TEST_F(PerformanceTelemetryTest, ThresholdAlerts) {
    // Configure with low thresholds for testing
    PerfTelemetryConfig config = PerfTelemetryConfig::Default();
    config.p95_threshold_ms = 5.0;
    config.p99_threshold_ms = 10.0;
    config.window_size = 100;
    telemetry.Shutdown();
    telemetry.Initialize(config);
    
    // Record operations that exceed threshold
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 6.0);  // Exceeds P95 threshold
    }
    
    // Force recalculation
    telemetry.RecalculatePercentiles();
    
    // Get alerts
    auto alerts = telemetry.GetAlerts();
    
    // Should have at least one alert for P95 threshold breach
    EXPECT_GT(alerts.size(), 0u);
    
    bool found_p95_alert = false;
    for (const auto& alert : alerts) {
        if (alert.operation == OperationType::Update && alert.is_p95) {
            found_p95_alert = true;
            EXPECT_EQ(alert.operation_name, "Update");
            EXPECT_GT(alert.measured_latency_ms, config.p95_threshold_ms);
            break;
        }
    }
    
    EXPECT_TRUE(found_p95_alert);
}

TEST_F(PerformanceTelemetryTest, SelfThrottlingEnabled) {
    // Configure with throttling enabled and low threshold
    PerfTelemetryConfig config = PerfTelemetryConfig::Default();
    config.enable_self_throttling = true;
    config.p95_threshold_ms = 2.0;  // Very low threshold
    config.throttle_probability = 1.0;  // Always throttle when enabled
    config.window_size = 50;
    telemetry.Shutdown();
    telemetry.Initialize(config);
    
    // Record operations that exceed threshold to trigger throttling
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 5.0);
    }
    
    // Force recalculation to update throttling state
    telemetry.RecalculatePercentiles();
    
    auto metrics = telemetry.GetMetrics(OperationType::Update);
    
    // After threshold breach, operation should be throttled
    EXPECT_TRUE(metrics.is_throttled);
}

TEST_F(PerformanceTelemetryTest, SelfThrottlingDisabled) {
    // Configure with throttling disabled
    PerfTelemetryConfig config = PerfTelemetryConfig::Default();
    config.enable_self_throttling = false;
    config.p95_threshold_ms = 2.0;
    telemetry.Shutdown();
    telemetry.Initialize(config);
    
    // Record operations that exceed threshold
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 5.0);
    }
    
    // Force recalculation
    telemetry.RecalculatePercentiles();
    
    auto metrics = telemetry.GetMetrics(OperationType::Update);
    
    // Should not be throttled even though threshold is exceeded
    EXPECT_FALSE(metrics.is_throttled);
}

TEST_F(PerformanceTelemetryTest, ThrottlingProbability) {
    // Configure with 50% throttle probability
    PerfTelemetryConfig config = PerfTelemetryConfig::Default();
    config.enable_self_throttling = true;
    config.p95_threshold_ms = 2.0;
    config.throttle_probability = 0.5;  // 50% probability
    config.window_size = 50;
    telemetry.Shutdown();
    telemetry.Initialize(config);
    
    // Trigger throttling
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 5.0);
    }
    telemetry.RecalculatePercentiles();
    
    // Check throttling many times
    int throttled_count = 0;
    int total_checks = 1000;
    
    for (int i = 0; i < total_checks; i++) {
        if (telemetry.ShouldThrottle(OperationType::Update)) {
            throttled_count++;
        }
    }
    
    // With 50% probability, we expect roughly 40-60% to be throttled
    double throttle_rate = static_cast<double>(throttled_count) / total_checks;
    EXPECT_GT(throttle_rate, 0.3);  // At least 30%
    EXPECT_LT(throttle_rate, 0.7);  // At most 70%
}

TEST_F(PerformanceTelemetryTest, MultipleOperationTypes) {
    // Record different operation types
    telemetry.RecordOperation(OperationType::Initialize, 100.0);
    telemetry.RecordOperation(OperationType::Update, 1.0);
    telemetry.RecordOperation(OperationType::FullScan, 50.0);
    telemetry.RecordOperation(OperationType::ProtectMemory, 2.0);
    
    auto all_metrics = telemetry.GetAllMetrics();
    
    // Should have metrics for all operation types
    EXPECT_EQ(all_metrics.size(), static_cast<size_t>(OperationType::MAX_OPERATION_TYPES));
    
    // Check specific operations were recorded
    auto init_metrics = telemetry.GetMetrics(OperationType::Initialize);
    EXPECT_EQ(init_metrics.total_operations, 1u);
    
    auto update_metrics = telemetry.GetMetrics(OperationType::Update);
    EXPECT_EQ(update_metrics.total_operations, 1u);
    
    auto scan_metrics = telemetry.GetMetrics(OperationType::FullScan);
    EXPECT_EQ(scan_metrics.total_operations, 1u);
}

TEST_F(PerformanceTelemetryTest, OperationNameConversion) {
    EXPECT_EQ(PerformanceTelemetry::GetOperationName(OperationType::Initialize), "Initialize");
    EXPECT_EQ(PerformanceTelemetry::GetOperationName(OperationType::Update), "Update");
    EXPECT_EQ(PerformanceTelemetry::GetOperationName(OperationType::FullScan), "FullScan");
    EXPECT_EQ(PerformanceTelemetry::GetOperationName(OperationType::ProtectMemory), "ProtectMemory");
    EXPECT_EQ(PerformanceTelemetry::GetOperationName(OperationType::ProtectFunction), "ProtectFunction");
    EXPECT_EQ(PerformanceTelemetry::GetOperationName(OperationType::VerifyMemory), "VerifyMemory");
    EXPECT_EQ(PerformanceTelemetry::GetOperationName(OperationType::EncryptPacket), "EncryptPacket");
    EXPECT_EQ(PerformanceTelemetry::GetOperationName(OperationType::DecryptPacket), "DecryptPacket");
}

TEST_F(PerformanceTelemetryTest, ResetClearsState) {
    // Record some operations
    for (int i = 0; i < 50; i++) {
        telemetry.RecordOperation(OperationType::Update, 5.0);
    }
    
    auto metrics_before = telemetry.GetMetrics(OperationType::Update);
    EXPECT_GT(metrics_before.total_operations, 0u);
    
    // Reset
    telemetry.Reset();
    
    auto metrics_after = telemetry.GetMetrics(OperationType::Update);
    EXPECT_EQ(metrics_after.total_operations, 0u);
    EXPECT_EQ(metrics_after.current_window.sample_count, 0u);
    EXPECT_FALSE(metrics_after.is_throttled);
}

TEST_F(PerformanceTelemetryTest, LifetimeVsWindowStats) {
    // Record operations in first window
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 1.0);
    }
    telemetry.RecalculatePercentiles();
    
    // Record operations with different values
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 10.0);
    }
    telemetry.RecalculatePercentiles();
    
    auto metrics = telemetry.GetMetrics(OperationType::Update);
    
    // Total operations should include both batches
    EXPECT_EQ(metrics.total_operations, 200u);
    
    // Lifetime stats should reflect overall distribution
    EXPECT_GT(metrics.lifetime.sample_count, 0u);
}

TEST_F(PerformanceTelemetryTest, ArtificialDelayDemonstration) {
    // Configure with low threshold
    PerfTelemetryConfig config = PerfTelemetryConfig::Default();
    config.p95_threshold_ms = 10.0;
    config.p99_threshold_ms = 20.0;
    config.enable_self_throttling = true;
    config.throttle_probability = 1.0;  // Always throttle
    config.window_size = 100;
    telemetry.Shutdown();
    telemetry.Initialize(config);
    
    // Record fast operations first
    for (int i = 0; i < 50; i++) {
        telemetry.RecordOperation(OperationType::Update, 2.0);
    }
    
    auto metrics_fast = telemetry.GetMetrics(OperationType::Update);
    EXPECT_FALSE(metrics_fast.is_throttled);
    
    // Inject artificial delay to simulate performance degradation
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 25.0);  // Exceeds both thresholds
    }
    
    telemetry.RecalculatePercentiles();
    
    // Should now be throttled
    auto metrics_slow = telemetry.GetMetrics(OperationType::Update);
    EXPECT_TRUE(metrics_slow.is_throttled);
    
    // Verify alerts were generated
    auto alerts = telemetry.GetAlerts();
    EXPECT_GT(alerts.size(), 0u);
    
    // Should have P99 alert since we exceeded it
    bool has_p99_alert = false;
    for (const auto& alert : alerts) {
        if (!alert.is_p95 && alert.operation == OperationType::Update) {
            has_p99_alert = true;
            EXPECT_GT(alert.measured_latency_ms, config.p99_threshold_ms);
        }
    }
    EXPECT_TRUE(has_p99_alert);
}

TEST_F(PerformanceTelemetryTest, ThrottleHysteresis) {
    // Configure with throttling
    PerfTelemetryConfig config = PerfTelemetryConfig::Default();
    config.enable_self_throttling = true;
    config.p95_threshold_ms = 10.0;
    config.window_size = 50;
    telemetry.Shutdown();
    telemetry.Initialize(config);
    
    // Exceed threshold to enable throttling
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 15.0);
    }
    telemetry.RecalculatePercentiles();
    
    auto metrics_high = telemetry.GetMetrics(OperationType::Update);
    EXPECT_TRUE(metrics_high.is_throttled);
    
    // Record better performance (but not below hysteresis threshold)
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 9.0);  // Just below threshold
    }
    telemetry.RecalculatePercentiles();
    
    // Should still be throttled due to hysteresis (threshold * 0.8 = 8.0)
    auto metrics_medium = telemetry.GetMetrics(OperationType::Update);
    EXPECT_TRUE(metrics_medium.is_throttled);
    
    // Record performance well below hysteresis threshold
    for (int i = 0; i < 100; i++) {
        telemetry.RecordOperation(OperationType::Update, 5.0);  // Well below 8.0
    }
    telemetry.RecalculatePercentiles();
    
    // Should no longer be throttled
    auto metrics_low = telemetry.GetMetrics(OperationType::Update);
    EXPECT_FALSE(metrics_low.is_throttled);
}

TEST_F(PerformanceTelemetryTest, ConcurrentRecording) {
    const int num_threads = 4;
    const int operations_per_thread = 100;
    
    std::vector<std::thread> threads;
    
    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, t, operations_per_thread]() {
            for (int i = 0; i < operations_per_thread; i++) {
                telemetry.RecordOperation(OperationType::Update, 1.0 + t);
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    auto metrics = telemetry.GetMetrics(OperationType::Update);
    EXPECT_EQ(metrics.total_operations, num_threads * operations_per_thread);
}
