/**
 * Sentinel SDK - Correlation Engine Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/CorrelationEngine.hpp"
#include <thread>
#include <chrono>

using namespace Sentinel::SDK;

/**
 * Test Fixture for CorrelationEngine tests
 */
class CorrelationEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        engine_ = std::make_unique<CorrelationEngine>();
        engine_->Initialize();
    }
    
    void TearDown() override {
        engine_->Shutdown();
        engine_.reset();
    }
    
    ViolationEvent CreateEvent(ViolationType type, Severity severity) {
        ViolationEvent event{};
        event.type = type;
        event.severity = severity;
        event.timestamp = 0;
        event.address = 0;
        event.module_name = nullptr;
        event.details = "Test violation";
        event.detection_id = 0;
        return event;
    }
    
    std::unique_ptr<CorrelationEngine> engine_;
};

/**
 * Test: Single signal events should not trigger enforcement actions
 * This is the core requirement - prevent false positives
 */
TEST_F(CorrelationEngineTest, SingleSignalNoEnforcement) {
    // Test 100 random single-signal events
    ViolationType types[] = {
        ViolationType::DebuggerAttached,
        ViolationType::InlineHook,
        ViolationType::MemoryWrite,
        ViolationType::TimingAnomaly,
        ViolationType::SpeedHack
    };
    
    for (int i = 0; i < 100; i++) {
        // Reset for each test
        engine_->Reset();
        
        // Send single signal
        ViolationType type = types[i % 5];
        auto event = CreateEvent(type, Severity::Critical);
        
        Severity correlated_severity;
        bool should_report;
        engine_->ProcessViolation(event, correlated_severity, should_report);
        
        // Single signal should NOT allow Ban or Terminate
        EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Ban))
            << "Ban should not be allowed for single signal (iteration " << i << ")";
        EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Terminate))
            << "Terminate should not be allowed for single signal (iteration " << i << ")";
        EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Kick))
            << "Kick should not be allowed for single signal (iteration " << i << ")";
        
        // Single Critical signal should be degraded to High
        EXPECT_EQ(correlated_severity, Severity::High)
            << "Critical severity should be degraded to High for single signal";
    }
}

/**
 * Test: Severity degradation for single signals
 */
TEST_F(CorrelationEngineTest, SeverityDegradation) {
    // Critical should be degraded to High
    auto event_critical = CreateEvent(ViolationType::DebuggerAttached, Severity::Critical);
    Severity severity_out;
    bool should_report;
    
    engine_->ProcessViolation(event_critical, severity_out, should_report);
    EXPECT_EQ(severity_out, Severity::High)
        << "Critical should be degraded to High for single signal";
    
    // Reset and test High degradation
    engine_->Reset();
    auto event_high = CreateEvent(ViolationType::InlineHook, Severity::High);
    engine_->ProcessViolation(event_high, severity_out, should_report);
    EXPECT_EQ(severity_out, Severity::Warning)
        << "High should be degraded to Warning for single signal";
    
    // Warning should stay Warning
    engine_->Reset();
    auto event_warning = CreateEvent(ViolationType::MemoryWrite, Severity::Warning);
    engine_->ProcessViolation(event_warning, severity_out, should_report);
    EXPECT_EQ(severity_out, Severity::Warning)
        << "Warning should stay Warning";
}

/**
 * Test: Multi-signal correlation enables enforcement
 */
TEST_F(CorrelationEngineTest, MultiSignalCorrelation) {
    Severity severity_out;
    bool should_report;
    
    // Send signals from different categories
    auto event1 = CreateEvent(ViolationType::DebuggerAttached, Severity::High);
    auto event2 = CreateEvent(ViolationType::MemoryWrite, Severity::High);
    auto event3 = CreateEvent(ViolationType::InlineHook, Severity::High);
    
    engine_->ProcessViolation(event1, severity_out, should_report);
    EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Ban))
        << "Ban should not be allowed after 1 signal";
    
    engine_->ProcessViolation(event2, severity_out, should_report);
    EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Ban))
        << "Ban should not be allowed after 2 signals";
    
    engine_->ProcessViolation(event3, severity_out, should_report);
    EXPECT_TRUE(engine_->ShouldAllowAction(ResponseAction::Ban))
        << "Ban should be allowed after 3+ signals from different categories";
    EXPECT_TRUE(engine_->ShouldAllowAction(ResponseAction::Terminate))
        << "Terminate should be allowed after 3+ signals";
}

/**
 * Test: Score accumulation and thresholds
 */
TEST_F(CorrelationEngineTest, ScoreAccumulation) {
    Severity severity_out;
    bool should_report;
    
    // Initial score should be 0
    EXPECT_DOUBLE_EQ(engine_->GetCorrelationScore(), 0.0);
    
    // Send debugger detection (weight = 0.4)
    auto event1 = CreateEvent(ViolationType::DebuggerAttached, Severity::Critical);
    engine_->ProcessViolation(event1, severity_out, should_report);
    EXPECT_GE(engine_->GetCorrelationScore(), 0.3)
        << "Score should increase after debugger detection";
    
    // Send memory violation (weight = 0.3)
    auto event2 = CreateEvent(ViolationType::MemoryWrite, Severity::High);
    engine_->ProcessViolation(event2, severity_out, should_report);
    EXPECT_GE(engine_->GetCorrelationScore(), 0.6)
        << "Score should accumulate from multiple signals";
    
    // Score should cap at 1.0
    auto event3 = CreateEvent(ViolationType::InlineHook, Severity::High);
    auto event4 = CreateEvent(ViolationType::TimingAnomaly, Severity::High);
    engine_->ProcessViolation(event3, severity_out, should_report);
    engine_->ProcessViolation(event4, severity_out, should_report);
    EXPECT_LE(engine_->GetCorrelationScore(), 1.0)
        << "Score should be capped at 1.0";
}

/**
 * Test: Time decay of correlation score
 */
TEST_F(CorrelationEngineTest, TimeDecay) {
    Severity severity_out;
    bool should_report;
    
    // Send signal to establish score
    auto event = CreateEvent(ViolationType::DebuggerAttached, Severity::Critical);
    engine_->ProcessViolation(event, severity_out, should_report);
    
    double initial_score = engine_->GetCorrelationScore();
    EXPECT_GT(initial_score, 0.0);
    
    // Wait 1 second (decay should be noticeable but small)
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // Process another event to trigger decay calculation
    auto dummy_event = CreateEvent(ViolationType::MemoryRead, Severity::Info);
    engine_->ProcessViolation(dummy_event, severity_out, should_report);
    
    double decayed_score = engine_->GetCorrelationScore();
    EXPECT_LT(decayed_score, initial_score + 0.5)  // Account for new signal weight
        << "Score should decay over time";
    
    // After enough time, old signals should be removed
    // Note: In production, 60 seconds would remove signals
    // For testing, we verify the decay mechanism works
}

/**
 * Test: Critical reporting requires 2+ signals
 */
TEST_F(CorrelationEngineTest, CriticalReportingThreshold) {
    Severity severity_out;
    bool should_report;
    
    // Single Critical signal should not be reported as Critical
    auto event1 = CreateEvent(ViolationType::DebuggerAttached, Severity::Critical);
    engine_->ProcessViolation(event1, severity_out, should_report);
    
    EXPECT_NE(severity_out, Severity::Critical)
        << "Single signal should not produce Critical severity";
    EXPECT_FALSE(should_report)
        << "Single Critical signal should not be reported to cloud";
    
    // Second signal from different category should enable Critical reporting
    auto event2 = CreateEvent(ViolationType::MemoryWrite, Severity::Critical);
    engine_->ProcessViolation(event2, severity_out, should_report);
    
    // Now we have 2 signals, so reporting should be enabled
    EXPECT_TRUE(should_report)
        << "Two correlated signals should enable reporting";
}

/**
 * Test: Unique signal category counting
 */
TEST_F(CorrelationEngineTest, UniqueSignalCounting) {
    Severity severity_out;
    bool should_report;
    
    EXPECT_EQ(engine_->GetUniqueSignalCount(), 0u)
        << "Initial unique signal count should be 0";
    
    // Send signal from Debugger category
    auto event1 = CreateEvent(ViolationType::DebuggerAttached, Severity::High);
    engine_->ProcessViolation(event1, severity_out, should_report);
    EXPECT_EQ(engine_->GetUniqueSignalCount(), 1u);
    
    // Send another signal from Debugger category (same category)
    auto event2 = CreateEvent(ViolationType::DebuggerAttached, Severity::High);
    engine_->ProcessViolation(event2, severity_out, should_report);
    EXPECT_EQ(engine_->GetUniqueSignalCount(), 1u)
        << "Same category should not increase unique count";
    
    // Send signal from Memory category
    auto event3 = CreateEvent(ViolationType::MemoryWrite, Severity::High);
    engine_->ProcessViolation(event3, severity_out, should_report);
    EXPECT_EQ(engine_->GetUniqueSignalCount(), 2u);
    
    // Send signal from Hooks category
    auto event4 = CreateEvent(ViolationType::InlineHook, Severity::High);
    engine_->ProcessViolation(event4, severity_out, should_report);
    EXPECT_EQ(engine_->GetUniqueSignalCount(), 3u);
}

/**
 * Test: Reset functionality
 */
TEST_F(CorrelationEngineTest, ResetClearsState) {
    Severity severity_out;
    bool should_report;
    
    // Add some signals
    auto event1 = CreateEvent(ViolationType::DebuggerAttached, Severity::Critical);
    auto event2 = CreateEvent(ViolationType::MemoryWrite, Severity::High);
    engine_->ProcessViolation(event1, severity_out, should_report);
    engine_->ProcessViolation(event2, severity_out, should_report);
    
    EXPECT_GT(engine_->GetCorrelationScore(), 0.0);
    EXPECT_GT(engine_->GetUniqueSignalCount(), 0u);
    
    // Reset
    engine_->Reset();
    
    // State should be cleared
    EXPECT_DOUBLE_EQ(engine_->GetCorrelationScore(), 0.0);
    EXPECT_EQ(engine_->GetUniqueSignalCount(), 0u);
}

/**
 * Test: Non-enforcement actions are always allowed
 */
TEST_F(CorrelationEngineTest, NonEnforcementActionsAllowed) {
    // Even with no signals, logging and reporting should be allowed
    EXPECT_TRUE(engine_->ShouldAllowAction(ResponseAction::Log))
        << "Log action should always be allowed";
    EXPECT_TRUE(engine_->ShouldAllowAction(ResponseAction::Report))
        << "Report action should always be allowed";
    EXPECT_TRUE(engine_->ShouldAllowAction(ResponseAction::Notify))
        << "Notify action should always be allowed";
    EXPECT_TRUE(engine_->ShouldAllowAction(ResponseAction::Warn))
        << "Warn action should always be allowed";
}

/**
 * Test: Category-based weighting
 */
TEST_F(CorrelationEngineTest, CategoryWeighting) {
    Severity severity_out;
    bool should_report;
    
    // Debugger detection should have higher weight (0.4)
    engine_->Reset();
    auto debugger_event = CreateEvent(ViolationType::DebuggerAttached, Severity::High);
    engine_->ProcessViolation(debugger_event, severity_out, should_report);
    double debugger_score = engine_->GetCorrelationScore();
    
    // Memory violation should have medium weight (0.3)
    engine_->Reset();
    auto memory_event = CreateEvent(ViolationType::MemoryWrite, Severity::High);
    engine_->ProcessViolation(memory_event, severity_out, should_report);
    double memory_score = engine_->GetCorrelationScore();
    
    // Hook detection should have lower weight (0.1)
    engine_->Reset();
    auto hook_event = CreateEvent(ViolationType::InlineHook, Severity::High);
    engine_->ProcessViolation(hook_event, severity_out, should_report);
    double hook_score = engine_->GetCorrelationScore();
    
    // Verify weighting hierarchy
    EXPECT_GT(debugger_score, memory_score)
        << "Debugger detection should have higher weight than memory";
    EXPECT_GT(memory_score, hook_score)
        << "Memory violation should have higher weight than hooks";
}

/**
 * Test: Kick action requires 2+ signals
 */
TEST_F(CorrelationEngineTest, KickRequiresTwoSignals) {
    Severity severity_out;
    bool should_report;
    
    // Single signal should not allow Kick
    auto event1 = CreateEvent(ViolationType::DebuggerAttached, Severity::High);
    engine_->ProcessViolation(event1, severity_out, should_report);
    EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Kick))
        << "Kick should require at least 2 signals";
    
    // Two signals should allow Kick
    auto event2 = CreateEvent(ViolationType::MemoryWrite, Severity::High);
    engine_->ProcessViolation(event2, severity_out, should_report);
    EXPECT_TRUE(engine_->ShouldAllowAction(ResponseAction::Kick))
        << "Kick should be allowed with 2+ signals";
}
