/**
 * Sentinel SDK - Telemetry and Runtime Config Tests
 * 
 * Tests for production telemetry and graceful degradation features (Task 14).
 * Tests for exception budget enforcement (Task 09).
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/TelemetryEmitter.hpp"
#include "Internal/RuntimeConfig.hpp"
#include "Internal/EnvironmentDetection.hpp"
#include "Internal/SafeMemory.hpp"  // Task 09: For exception budget tests
#include <thread>
#include <chrono>

using namespace Sentinel::SDK;

// ==================== Telemetry Tests ====================

class TelemetryEmitterTest : public ::testing::Test {
protected:
    void SetUp() override {
        emitter.Initialize();
    }
    
    void TearDown() override {
        emitter.Shutdown();
    }
    
    TelemetryEmitter emitter;
};

TEST_F(TelemetryEmitterTest, BasicInitialization) {
    // Test passes if no crash during setup/teardown
    EXPECT_NO_THROW(emitter.ClearEvents());
}

TEST_F(TelemetryEmitterTest, EventCreation) {
    ViolationEvent violation;
    violation.type = ViolationType::DebuggerAttached;
    violation.severity = Severity::High;
    violation.timestamp = 12345;
    violation.address = 0xDEADBEEF;
    violation.module_name = "test.dll";
    violation.details = "Test violation";
    violation.detection_id = 1;
    
    uint32_t raw_data = 0xCAFEBABE;
    TelemetryEvent event = emitter.CreateEventFromViolation(
        violation,
        DetectionType::AntiDebug,
        0.9f,
        &raw_data,
        sizeof(raw_data)
    );
    
    EXPECT_EQ(event.detection_type, DetectionType::AntiDebug);
    EXPECT_EQ(event.violation_type, ViolationType::DebuggerAttached);
    EXPECT_EQ(event.severity, Severity::High);
    EXPECT_EQ(event.confidence, 0.9f);
    EXPECT_EQ(event.address, 0xDEADBEEF);
    EXPECT_EQ(event.details, "Test violation");
    EXPECT_NE(event.raw_data_hash, 0u);  // Hash should be computed
}

TEST_F(TelemetryEmitterTest, EventWithEnvironmentContext) {
    EnvironmentDetector env_detector;
    env_detector.Initialize();
    emitter.SetEnvironmentDetector(&env_detector);
    
    ViolationEvent violation;
    violation.type = ViolationType::DebuggerAttached;
    violation.severity = Severity::High;
    
    uint32_t raw_data = 0xCAFEBABE;
    TelemetryEvent event = emitter.CreateEventFromViolation(
        violation,
        DetectionType::AntiDebug,
        0.9f,
        &raw_data,
        sizeof(raw_data)
    );
    
    EXPECT_FALSE(event.environment_string.empty());
}

TEST_F(TelemetryEmitterTest, EmitAndRetrieveEvents) {
    ViolationEvent violation;
    violation.type = ViolationType::DebuggerAttached;
    violation.severity = Severity::High;
    
    uint32_t raw_data = 0xCAFEBABE;
    TelemetryEvent event = emitter.CreateEventFromViolation(
        violation,
        DetectionType::AntiDebug,
        0.9f,
        &raw_data,
        sizeof(raw_data)
    );
    
    emitter.EmitEvent(event);
    
    auto events = emitter.GetEvents();
    EXPECT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].detection_type, DetectionType::AntiDebug);
}

TEST_F(TelemetryEmitterTest, MultipleEvents) {
    for (int i = 0; i < 10; ++i) {
        ViolationEvent violation;
        violation.type = ViolationType::DebuggerAttached;
        violation.severity = Severity::High;
        
        uint32_t raw_data = i;
        TelemetryEvent event = emitter.CreateEventFromViolation(
            violation,
            DetectionType::AntiDebug,
            0.9f,
            &raw_data,
            sizeof(raw_data)
        );
        
        emitter.EmitEvent(event);
    }
    
    auto events = emitter.GetEvents();
    EXPECT_EQ(events.size(), 10u);
}

TEST_F(TelemetryEmitterTest, ClearEvents) {
    ViolationEvent violation;
    violation.type = ViolationType::DebuggerAttached;
    violation.severity = Severity::High;
    
    uint32_t raw_data = 0xCAFEBABE;
    TelemetryEvent event = emitter.CreateEventFromViolation(
        violation,
        DetectionType::AntiDebug,
        0.9f,
        &raw_data,
        sizeof(raw_data)
    );
    
    emitter.EmitEvent(event);
    EXPECT_EQ(emitter.GetEvents().size(), 1u);
    
    emitter.ClearEvents();
    EXPECT_EQ(emitter.GetEvents().size(), 0u);
}

TEST_F(TelemetryEmitterTest, BaselineTracking) {
    auto baseline = emitter.GetBaseline(DetectionType::AntiDebug);
    EXPECT_EQ(baseline.total_detections, 0u);
    EXPECT_EQ(baseline.baseline_rate_per_hour, 0u);
    EXPECT_FALSE(baseline.is_anomalous);
    
    // Emit some events
    for (int i = 0; i < 5; ++i) {
        ViolationEvent violation;
        violation.type = ViolationType::DebuggerAttached;
        violation.severity = Severity::High;
        
        uint32_t raw_data = i;
        TelemetryEvent event = emitter.CreateEventFromViolation(
            violation,
            DetectionType::AntiDebug,
            0.9f,
            &raw_data,
            sizeof(raw_data)
        );
        
        emitter.EmitEvent(event);
    }
    
    baseline = emitter.GetBaseline(DetectionType::AntiDebug);
    EXPECT_EQ(baseline.total_detections, 5u);
    EXPECT_GE(baseline.window_detections, 5u);
}

TEST_F(TelemetryEmitterTest, PerformanceMetrics) {
    emitter.SetPerformanceMetrics(1234, 4096);
    
    ViolationEvent violation;
    violation.type = ViolationType::DebuggerAttached;
    violation.severity = Severity::High;
    
    uint32_t raw_data = 0xCAFEBABE;
    TelemetryEvent event = emitter.CreateEventFromViolation(
        violation,
        DetectionType::AntiDebug,
        0.9f,
        &raw_data,
        sizeof(raw_data)
    );
    
    EXPECT_EQ(event.scan_duration_us, 1234u);
    EXPECT_EQ(event.memory_scanned_bytes, 4096u);
}

TEST_F(TelemetryEmitterTest, PerformanceMetricsReset) {
    emitter.SetPerformanceMetrics(1234, 4096);
    
    ViolationEvent violation;
    violation.type = ViolationType::DebuggerAttached;
    violation.severity = Severity::High;
    
    uint32_t raw_data = 0xCAFEBABE;
    
    // First event should get the metrics
    TelemetryEvent event1 = emitter.CreateEventFromViolation(
        violation,
        DetectionType::AntiDebug,
        0.9f,
        &raw_data,
        sizeof(raw_data)
    );
    
    EXPECT_EQ(event1.scan_duration_us, 1234u);
    
    // Second event should get zeros (metrics were reset)
    TelemetryEvent event2 = emitter.CreateEventFromViolation(
        violation,
        DetectionType::AntiDebug,
        0.9f,
        &raw_data,
        sizeof(raw_data)
    );
    
    EXPECT_EQ(event2.scan_duration_us, 0u);
}

// ==================== Runtime Config Tests ====================

class RuntimeConfigTest : public ::testing::Test {
protected:
    void SetUp() override {
        config.Initialize();
    }
    
    void TearDown() override {
        config.Shutdown();
    }
    
    RuntimeConfig config;
};

TEST_F(RuntimeConfigTest, BasicInitialization) {
    // Test passes if no crash during setup/teardown
    EXPECT_TRUE(config.IsDetectionEnabled(DetectionType::AntiDebug));
}

TEST_F(RuntimeConfigTest, AllDetectionsEnabledByDefault) {
    EXPECT_TRUE(config.IsDetectionEnabled(DetectionType::AntiDebug));
    EXPECT_TRUE(config.IsDetectionEnabled(DetectionType::AntiHook));
    EXPECT_TRUE(config.IsDetectionEnabled(DetectionType::MemoryIntegrity));
    EXPECT_TRUE(config.IsDetectionEnabled(DetectionType::SpeedHack));
    EXPECT_TRUE(config.IsDetectionEnabled(DetectionType::InjectionDetect));
}

TEST_F(RuntimeConfigTest, DisableSpecificDetection) {
    config.SetDetectionEnabled(DetectionType::AntiDebug, false);
    
    EXPECT_FALSE(config.IsDetectionEnabled(DetectionType::AntiDebug));
    EXPECT_TRUE(config.IsDetectionEnabled(DetectionType::AntiHook));  // Others still enabled
}

TEST_F(RuntimeConfigTest, ReEnableDisabledDetection) {
    config.SetDetectionEnabled(DetectionType::AntiDebug, false);
    EXPECT_FALSE(config.IsDetectionEnabled(DetectionType::AntiDebug));
    
    config.SetDetectionEnabled(DetectionType::AntiDebug, true);
    EXPECT_TRUE(config.IsDetectionEnabled(DetectionType::AntiDebug));
}

TEST_F(RuntimeConfigTest, DryRunDisabledByDefault) {
    EXPECT_FALSE(config.IsDetectionDryRun(DetectionType::AntiDebug));
    EXPECT_FALSE(config.IsGlobalDryRun());
}

TEST_F(RuntimeConfigTest, EnableDryRunForSpecificDetection) {
    config.SetDetectionDryRun(DetectionType::AntiDebug, true);
    
    EXPECT_TRUE(config.IsDetectionDryRun(DetectionType::AntiDebug));
    EXPECT_FALSE(config.IsDetectionDryRun(DetectionType::AntiHook));
}

TEST_F(RuntimeConfigTest, GlobalDryRunMode) {
    config.SetGlobalDryRun(true);
    
    EXPECT_TRUE(config.IsGlobalDryRun());
    // All detections should be in dry run mode
    EXPECT_TRUE(config.IsDetectionDryRun(DetectionType::AntiDebug));
    EXPECT_TRUE(config.IsDetectionDryRun(DetectionType::AntiHook));
}

TEST_F(RuntimeConfigTest, GlobalDryRunOverridesDetectionSpecific) {
    config.SetDetectionDryRun(DetectionType::AntiDebug, false);
    config.SetGlobalDryRun(true);
    
    EXPECT_TRUE(config.IsDetectionDryRun(DetectionType::AntiDebug));
}

TEST_F(RuntimeConfigTest, ExceptionTracking) {
    // Record exceptions below threshold
    for (int i = 0; i < 4; ++i) {
        config.RecordException(DetectionType::AntiDebug);
    }
    
    // Detection should still be enabled
    EXPECT_TRUE(config.IsDetectionEnabled(DetectionType::AntiDebug));
    
    // One more exception should trigger auto-disable
    config.RecordException(DetectionType::AntiDebug);
    
    // Detection should now be auto-disabled
    EXPECT_FALSE(config.IsDetectionEnabled(DetectionType::AntiDebug));
}

TEST_F(RuntimeConfigTest, ExceptionCounterIncrement) {
    // Record exceptions
    for (int i = 0; i < 3; ++i) {
        config.RecordException(DetectionType::AntiDebug);
    }
    
    auto detection_config = config.GetDetectionConfig(DetectionType::AntiDebug);
    EXPECT_EQ(detection_config.exception_count, 3u);
}

TEST_F(RuntimeConfigTest, ResetExceptionCounters) {
    // Trigger auto-disable
    for (int i = 0; i < 5; ++i) {
        config.RecordException(DetectionType::AntiDebug);
    }
    
    EXPECT_FALSE(config.IsDetectionEnabled(DetectionType::AntiDebug));
    
    // Reset counters
    config.ResetExceptionCounters();
    
    // Counter should be reset
    auto detection_config = config.GetDetectionConfig(DetectionType::AntiDebug);
    EXPECT_EQ(detection_config.exception_count, 0u);
}

TEST_F(RuntimeConfigTest, ReEnablingClearsAutoDisable) {
    // Trigger auto-disable
    for (int i = 0; i < 5; ++i) {
        config.RecordException(DetectionType::AntiDebug);
    }
    
    EXPECT_FALSE(config.IsDetectionEnabled(DetectionType::AntiDebug));
    
    // Manually re-enable
    config.SetDetectionEnabled(DetectionType::AntiDebug, true);
    
    // Should be enabled again
    EXPECT_TRUE(config.IsDetectionEnabled(DetectionType::AntiDebug));
}

TEST_F(RuntimeConfigTest, ShouldEnforceWithSufficientConfidence) {
    EXPECT_TRUE(config.ShouldEnforce(DetectionType::AntiDebug, 0.8f));
    EXPECT_TRUE(config.ShouldEnforce(DetectionType::AntiDebug, 1.0f));
}

TEST_F(RuntimeConfigTest, ShouldNotEnforceWithLowConfidence) {
    EXPECT_FALSE(config.ShouldEnforce(DetectionType::AntiDebug, 0.5f));
}

TEST_F(RuntimeConfigTest, ShouldNotEnforceWhenDisabled) {
    config.SetDetectionEnabled(DetectionType::AntiDebug, false);
    EXPECT_FALSE(config.ShouldEnforce(DetectionType::AntiDebug, 1.0f));
}

TEST_F(RuntimeConfigTest, ShouldNotEnforceInDryRun) {
    config.SetDetectionDryRun(DetectionType::AntiDebug, true);
    EXPECT_FALSE(config.ShouldEnforce(DetectionType::AntiDebug, 1.0f));
}

TEST_F(RuntimeConfigTest, ShouldNotEnforceWhenAutoDisabled) {
    // Trigger auto-disable
    for (int i = 0; i < 5; ++i) {
        config.RecordException(DetectionType::AntiDebug);
    }
    
    EXPECT_FALSE(config.ShouldEnforce(DetectionType::AntiDebug, 1.0f));
}

TEST_F(RuntimeConfigTest, GetDetectionConfig) {
    auto detection_config = config.GetDetectionConfig(DetectionType::AntiDebug);
    
    EXPECT_TRUE(detection_config.enabled);
    EXPECT_FALSE(detection_config.dry_run);
    EXPECT_FALSE(detection_config.auto_disabled);
    EXPECT_EQ(detection_config.exception_count, 0u);
}

TEST_F(RuntimeConfigTest, GetGlobalConfig) {
    auto global_config = config.GetGlobalConfig();
    
    EXPECT_FALSE(global_config.dry_run_mode);
    EXPECT_TRUE(global_config.auto_degradation_enabled);
    EXPECT_EQ(global_config.exception_threshold, 5u);
    EXPECT_EQ(global_config.exception_window_ms, 60000u);
}

// ==================== Integration Tests ====================

TEST(TelemetryConfigIntegration, DryRunPreventsEnforcementButEmitsTelemetry) {
    TelemetryEmitter emitter;
    RuntimeConfig config;
    
    emitter.Initialize();
    config.Initialize();
    
    config.SetGlobalDryRun(true);
    
    ViolationEvent violation;
    violation.type = ViolationType::DebuggerAttached;
    violation.severity = Severity::High;
    
    uint32_t raw_data = 0xCAFEBABE;
    TelemetryEvent event = emitter.CreateEventFromViolation(
        violation,
        DetectionType::AntiDebug,
        0.9f,
        &raw_data,
        sizeof(raw_data)
    );
    
    emitter.EmitEvent(event);
    
    // Telemetry should be recorded
    EXPECT_EQ(emitter.GetEvents().size(), 1u);
    
    // But enforcement should be disabled
    EXPECT_FALSE(config.ShouldEnforce(DetectionType::AntiDebug, 0.9f));
    
    emitter.Shutdown();
    config.Shutdown();
}

// ==================== Exception Budget Tests (Task 09) ====================

TEST(ExceptionBudgetTest, DefaultBudgetConfiguration) {
    RuntimeConfig config;
    config.Initialize();
    
    auto global_config = config.GetGlobalConfig();
    EXPECT_EQ(global_config.exception_budget_per_scan, 10u);
    
    config.Shutdown();
}

TEST(ExceptionBudgetTest, ExceptionStatsResetBetweenScans) {
    SafeMemory::ResetExceptionStats();
    
    auto& stats1 = SafeMemory::GetExceptionStats();
    EXPECT_EQ(stats1.GetTotalExceptions(), 0u);
    
    // Simulate some exceptions
    stats1.access_violations = 5;
    EXPECT_EQ(stats1.GetTotalExceptions(), 5u);
    
    // Reset for next scan
    SafeMemory::ResetExceptionStats();
    
    auto& stats2 = SafeMemory::GetExceptionStats();
    EXPECT_EQ(stats2.GetTotalExceptions(), 0u);
}

TEST(ExceptionBudgetTest, ExceptionLimitEnforcement) {
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(10);
    
    auto& stats = SafeMemory::GetExceptionStats();
    
    // Under budget
    stats.access_violations = 5;
    EXPECT_FALSE(SafeMemory::IsExceptionLimitExceeded());
    
    // At budget
    stats.access_violations = 10;
    EXPECT_TRUE(SafeMemory::IsExceptionLimitExceeded());
    
    // Over budget
    stats.access_violations = 15;
    EXPECT_TRUE(SafeMemory::IsExceptionLimitExceeded());
}

TEST(ExceptionBudgetTest, BudgetUsesConfiguredValue) {
    SafeMemory::ResetExceptionStats();
    
    // Set a custom budget of 5
    SafeMemory::SetExceptionBudget(5);
    
    auto& stats = SafeMemory::GetExceptionStats();
    stats.access_violations = 5;
    
    // Should be exceeded with budget of 5
    EXPECT_TRUE(SafeMemory::IsExceptionLimitExceeded());
    
    // Reset and set a higher budget
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(20);
    
    stats.access_violations = 5;
    // Should not be exceeded with budget of 20
    EXPECT_FALSE(SafeMemory::IsExceptionLimitExceeded());
}
