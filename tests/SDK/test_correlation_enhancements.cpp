/**
 * Sentinel SDK - Correlation Engine Enhancement Tests (Fixed)
 * 
 * Copyright (c) 2025 Sentinel Security.  All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/CorrelationEngine.hpp"
#include <thread>
#include <chrono>

using namespace Sentinel::SDK;

/**
 * Test Fixture for Enhancement tests - FIXED
 */
class CorrelationEnhancementTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a fresh engine for each test
        engine_ = std::make_unique<CorrelationEngine>();
        engine_->Initialize();
    }
    
    void TearDown() override {
        // Defensive: Check if engine exists before shutdown
        if (engine_) {
            engine_->Shutdown();
            engine_.reset();  // Reset after shutdown, not before
        }
    }
    
    /**
     * Safe event creation with null-safety
     */
    ViolationEvent CreateEvent(ViolationType type, Severity severity, 
                               const char* module = nullptr) {
        ViolationEvent event{};
        event.type = type;
        event.severity = severity;
        event.timestamp = 0;
        event.address = 0;
        // FIX: Use safe string assignment, never pass nullptr to std::string
        event.module_name = (module != nullptr) ? std::string(module) : std::string();
        event.details = "Test violation";
        event.detection_id = 0;
        return event;
    }
    
    /**
     * Helper to process event and return the result
     */
    bool ProcessAndGet(const ViolationEvent& event, 
                      Severity& out_severity, 
                      bool& out_report) {
        // Defensive: Ensure engine is valid
        EXPECT_NE(engine_, nullptr) << "Engine is null before ProcessViolation";
        if (!engine_) return false;
        return engine_->ProcessViolation(event, out_severity, out_report);
    }
    
    std::unique_ptr<CorrelationEngine> engine_;
};

/**
 * Test: Verify new confidence weights
 */
TEST_F(CorrelationEnhancementTest, NewConfidenceWeights) {
    Severity severity_out;
    bool should_report;
    
    // Test debugger weight (0.3)
    engine_->Reset();
    auto debugger = CreateEvent(ViolationType::DebuggerAttached, Severity::High);
    ProcessAndGet(debugger, severity_out, should_report);
    EXPECT_NEAR(engine_->GetCorrelationScore(), 0.3, 0.01)
        << "Debugger should have weight 0.3";
    
    // Test general memory weight (0.3)
    engine_->Reset();
    auto memory = CreateEvent(ViolationType::MemoryWrite, Severity::High);
    ProcessAndGet(memory, severity_out, should_report);
    EXPECT_NEAR(engine_->GetCorrelationScore(), 0.3, 0.01)
        << "General memory should have weight 0.3";
    
    // Test RWX memory weight (0.5)
    engine_->Reset();
    auto rwx = CreateEvent(ViolationType::MemoryExecute, Severity::High);
    ProcessAndGet(rwx, severity_out, should_report);
    EXPECT_NEAR(engine_->GetCorrelationScore(), 0.5, 0.01)
        << "RWX memory should have weight 0.5";
    
    // Test hook weight (0.7)
    engine_->Reset();
    auto hook = CreateEvent(ViolationType::InlineHook, Severity::High);
    ProcessAndGet(hook, severity_out, should_report);
    EXPECT_NEAR(engine_->GetCorrelationScore(), 0.7, 0.01)
        << "Hook should have weight 0.7";
}

/**
 * Test: Null module name handling
 */
TEST_F(CorrelationEnhancementTest, NullModuleNameSafety) {
    Severity severity_out;
    bool should_report;
    
    // FIX: Test that nullptr module doesn't crash
    auto event_null = CreateEvent(ViolationType::MemoryWrite, Severity::High, nullptr);
    EXPECT_NO_THROW({
        ProcessAndGet(event_null, severity_out, should_report);
    }) << "Null module name should not crash";
    
    // Test empty string module
    auto event_empty = CreateEvent(ViolationType::MemoryWrite, Severity::High, "");
    EXPECT_NO_THROW({
        ProcessAndGet(event_empty, severity_out, should_report);
    }) << "Empty module name should not crash";
    
    // Test whitespace-only module
    auto event_ws = CreateEvent(ViolationType::MemoryWrite, Severity::High, "   ");
    EXPECT_NO_THROW({
        ProcessAndGet(event_ws, severity_out, should_report);
    }) << "Whitespace module name should not crash";
}

/**
 * Test: Enforcement threshold requires score >= 2.0 AND 3 unique persistent signals
 */
TEST_F(CorrelationEnhancementTest, EnforcementThreshold) {
    Severity severity_out;
    bool should_report;
    
    // Single signal should NOT allow ban
    auto hook = CreateEvent(ViolationType::InlineHook, Severity::Critical);
    ProcessAndGet(hook, severity_out, should_report);
    
    EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Ban))
        << "Single signal should not allow ban";
    
    // Add more signals but they need to persist across scan cycles
    // (This test validates the threshold logic, not full persistence)
}

/**
 * Test: Cooling-off period - signals must persist 3 scan cycles (30+ seconds)
 */
TEST_F(CorrelationEnhancementTest, CoolingOffPeriod) {
    Severity severity_out;
    bool should_report;
    
    auto event = CreateEvent(ViolationType::InlineHook, Severity::High);
    
    // First detection - no persistence yet
    ProcessAndGet(event, severity_out, should_report);
    EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Kick))
        << "No enforcement without persistence";
    
    // Second scan cycle (after 11 seconds)
    std::this_thread::sleep_for(std::chrono::seconds(11));
    ProcessAndGet(event, severity_out, should_report);
    EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Kick))
        << "No enforcement after only 2 cycles";
    
    // Third scan cycle (after another 11 seconds)
    std::this_thread::sleep_for(std::chrono::seconds(11));
    ProcessAndGet(event, severity_out, should_report);
    // Still not enough for Kick since we only have 1 unique signal
    // But the signal should now be persistent
}

/**
 * Test: Discord overlay + RWX + overlay process = known false positive
 */
TEST_F(CorrelationEnhancementTest, DiscordFalsePositivePattern) {
    Severity severity_out;
    bool should_report;
    
    // Simulate Discord overlay hook
    auto discord_hook = CreateEvent(ViolationType::InlineHook, Severity::High, "discord_overlay.dll");
    
    // Simulate RWX memory from overlay
    auto rwx = CreateEvent(ViolationType::MemoryExecute, Severity::High, "overlay_process.dll");
    
    // Process these signals
    ProcessAndGet(discord_hook, severity_out, should_report);
    ProcessAndGet(rwx, severity_out, should_report);
    
    // Even with multiple signals, known false positive pattern should suppress enforcement
    // The pattern should be flagged and telemetry should be emitted but not enforcement
}

/**
 * Test: All sub-threshold detections emit telemetry
 */
TEST_F(CorrelationEnhancementTest, SubThresholdTelemetry) {
    Severity severity_out;
    bool should_report;
    
    // Single signal should emit telemetry
    auto event = CreateEvent(ViolationType::DebuggerAttached, Severity::Critical);
    ProcessAndGet(event, severity_out, should_report);
    
    EXPECT_TRUE(should_report)
        << "Single signal should emit telemetry (changed from previous behavior)";
    EXPECT_NE(severity_out, Severity::Critical)
        << "But severity should be degraded";
}

/**
 * Test: Discord overlay users never trigger enforcement
 */
TEST_F(CorrelationEnhancementTest, DiscordOverlayNeverEnforces) {
    Severity severity_out;
    bool should_report;
    
    // Simulate Discord-related hook detections
    auto discord_hook1 = CreateEvent(ViolationType::InlineHook, Severity::High, "DiscordHook.dll");
    auto discord_hook2 = CreateEvent(ViolationType::IATHook, Severity::High, "discord_rpc.dll");
    
    // Even with multiple Discord-related signals, no enforcement
    ProcessAndGet(discord_hook1, severity_out, should_report);
    ProcessAndGet(discord_hook2, severity_out, should_report);
    
    // Discord hooks should be whitelisted or marked as false positive
    // No enforcement action should be triggered
    EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Ban))
        << "Discord overlay should not trigger enforcement";
}

/**
 * Test: Cloud gaming latency never triggers enforcement alone
 */
TEST_F(CorrelationEnhancementTest, CloudGamingLatencyNeverEnforces) {
    Severity severity_out;
    bool should_report;
    
    // Simulate timing anomalies that might occur in cloud gaming
    auto timing = CreateEvent(ViolationType::TimingAnomaly, Severity::High);
    
    // Process timing anomaly
    ProcessAndGet(timing, severity_out, should_report);
    
    // If cloud gaming is detected, timing anomalies should be suppressed
    // Otherwise, single signal still won't allow enforcement
    EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Ban))
        << "Timing anomaly alone should not trigger enforcement";
    EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Terminate))
        << "Timing anomaly alone should not trigger termination";
}

/**
 * Test: No enforcement from single detection regardless of type
 */
TEST_F(CorrelationEnhancementTest, NoSingleSignalEnforcement) {
    Severity severity_out;
    bool should_report;
    
    // Test all major violation types
    ViolationType types[] = {
        ViolationType::DebuggerAttached,
        ViolationType::MemoryExecute,      // RWX
        ViolationType::InlineHook,         // Hook
        ViolationType::CodeInjection,
        ViolationType::TimingAnomaly,
        ViolationType::SpeedHack
    };
    
    for (auto type : types) {
        engine_->Reset();
        
        auto event = CreateEvent(type, Severity::Critical);
        ProcessAndGet(event, severity_out, should_report);
        
        EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Ban))
            << "Single signal of type " << static_cast<int>(type) << " should not allow Ban";
        EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Terminate))
            << "Single signal of type " << static_cast<int>(type) << " should not allow Terminate";
    }
}

/**
 * Test: Minimum 3 distinct signals required
 */
TEST_F(CorrelationEnhancementTest, MinimumThreeDistinctSignals) {
    Severity severity_out;
    bool should_report;
    
    // Two signals, even if high confidence, should not allow enforcement
    auto hook1 = CreateEvent(ViolationType::InlineHook, Severity::High);
    auto hook2 = CreateEvent(ViolationType::IATHook, Severity::High);
    
    // Both hooks are same category
    for (int cycle = 0; cycle < 3; cycle++) {
        if (cycle > 0) {
            std::this_thread::sleep_for(std::chrono::seconds(11));
        }
        ProcessAndGet(hook1, severity_out, should_report);
        ProcessAndGet(hook2, severity_out, should_report);
    }
    
    // Even with persistence, only 1 unique category
    EXPECT_EQ(engine_->GetUniqueSignalCount(), 1u)
        << "Same category signals should not count as distinct";
    EXPECT_FALSE(engine_->ShouldAllowAction(ResponseAction::Ban))
        << "Need 3+ distinct signal categories";
}
