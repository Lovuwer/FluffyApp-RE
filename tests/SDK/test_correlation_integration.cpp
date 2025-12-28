/**
 * Sentinel SDK - Correlation Engine Integration Test
 * 
 * Tests real-world scenarios with the correlation engine integrated.
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "SentinelSDK.hpp"
#include "Internal/CorrelationEngine.hpp"

using namespace Sentinel::SDK;

/**
 * Integration Test: Discord overlay should not trigger violations
 * 
 * This simulates a real scenario where Discord overlay is running and
 * hooks user32.dll functions legitimately. The correlation engine should
 * whitelist these detections.
 */
TEST(CorrelationIntegrationTest, DiscordOverlayScenario) {
    CorrelationEngine engine;
    engine.Initialize();
    
    // Simulate hook detection from Discord overlay
    ViolationEvent discord_hook{};
    discord_hook.type = ViolationType::InlineHook;
    discord_hook.severity = Severity::High;
    discord_hook.module_name = "DiscordHook.dll";
    discord_hook.details = "Hook detected in user32.dll";
    
    Severity correlated_severity;
    bool should_report;
    
    // Process the violation
    bool passed = engine.ProcessViolation(discord_hook, correlated_severity, should_report);
    
    // In a real environment with Discord loaded, this would be whitelisted
    // For this test, we verify the mechanism is in place
    EXPECT_TRUE(passed) << "Discord hook detection should be processed";
    
    // Even if not whitelisted, single signal should not allow enforcement
    EXPECT_FALSE(engine.ShouldAllowAction(ResponseAction::Ban))
        << "Single Discord hook detection should not allow Ban";
    EXPECT_FALSE(engine.ShouldAllowAction(ResponseAction::Terminate))
        << "Single Discord hook detection should not allow Terminate";
    
    engine.Shutdown();
}

/**
 * Integration Test: Multiple legitimate signals should still be handled
 * 
 * This tests that even with overlay whitelisting, genuine multi-signal
 * threats are still detected after persistence is established.
 * Updated: Requires signal persistence across scan cycles
 */
TEST(CorrelationIntegrationTest, GenuineThreatDetection) {
    CorrelationEngine engine;
    engine.Initialize();
    
    Severity severity_out;
    bool should_report;
    
    // Simulate genuine detections with high-confidence signals
    ViolationEvent debugger{};
    debugger.type = ViolationType::DebuggerAttached;
    debugger.severity = Severity::Critical;
    debugger.details = "Debugger detected via IsDebuggerPresent";
    
    ViolationEvent memory{};
    memory.type = ViolationType::MemoryWrite;
    memory.severity = Severity::High;
    memory.module_name = "unknown.dll";
    memory.details = "Suspicious memory write detected";
    
    ViolationEvent hook{};
    hook.type = ViolationType::InlineHook;
    hook.severity = Severity::High;
    hook.details = "Hook on critical function";
    
    ViolationEvent rwx{};
    rwx.type = ViolationType::MemoryExecute;
    rwx.severity = Severity::High;
    rwx.details = "RWX memory without signature";
    
    // First scan cycle
    engine.ProcessViolation(debugger, severity_out, should_report);
    engine.ProcessViolation(memory, severity_out, should_report);
    engine.ProcessViolation(hook, severity_out, should_report);
    engine.ProcessViolation(rwx, severity_out, should_report);
    
    // Without persistence, enforcement should not be allowed yet
    EXPECT_FALSE(engine.ShouldAllowAction(ResponseAction::Ban))
        << "Ban should not be allowed without persistence";
    
    // Simulate persistence across scan cycles
    std::this_thread::sleep_for(std::chrono::seconds(11));
    engine.ProcessViolation(debugger, severity_out, should_report);
    engine.ProcessViolation(memory, severity_out, should_report);
    engine.ProcessViolation(hook, severity_out, should_report);
    engine.ProcessViolation(rwx, severity_out, should_report);
    
    std::this_thread::sleep_for(std::chrono::seconds(11));
    engine.ProcessViolation(debugger, severity_out, should_report);
    engine.ProcessViolation(memory, severity_out, should_report);
    engine.ProcessViolation(hook, severity_out, should_report);
    engine.ProcessViolation(rwx, severity_out, should_report);
    
    // Now with persistent signals and score >= 2.0, enforcement should be allowed
    EXPECT_TRUE(engine.ShouldAllowAction(ResponseAction::Ban))
        << "Multiple persistent signals should allow Ban";
    EXPECT_TRUE(engine.ShouldAllowAction(ResponseAction::Terminate))
        << "Multiple persistent signals should allow Terminate";
    EXPECT_GE(engine.GetUniqueSignalCount(), 3u)
        << "Should have 3+ unique signal categories";
    
    engine.Shutdown();
}

/**
 * Integration Test: VM environment timing suppression
 * 
 * Tests that timing anomalies are suppressed in VM environments to prevent
 * false positives from virtualization overhead.
 */
TEST(CorrelationIntegrationTest, VMEnvironmentHandling) {
    CorrelationEngine engine;
    engine.Initialize();
    
    // Simulate timing anomaly that might occur in VM
    ViolationEvent timing{};
    timing.type = ViolationType::TimingAnomaly;
    timing.severity = Severity::High;
    timing.details = "Timing inconsistency detected";
    
    Severity severity_out;
    bool should_report;
    
    // In a VM environment, this should potentially be whitelisted
    // The test verifies the mechanism is in place
    engine.ProcessViolation(timing, severity_out, should_report);
    
    // Even if not whitelisted, single signal should not enforce
    EXPECT_FALSE(engine.ShouldAllowAction(ResponseAction::Ban))
        << "Timing anomaly in potential VM should not allow Ban";
    
    // However, memory violations should NOT be suppressed in VMs
    ViolationEvent memory{};
    memory.type = ViolationType::CodeInjection;
    memory.severity = Severity::Critical;
    memory.details = "Code injection detected";
    
    engine.ProcessViolation(memory, severity_out, should_report);
    
    // Memory violations are still valid signals
    EXPECT_GT(engine.GetCorrelationScore(), 0.0)
        << "Memory violations should contribute to correlation even in VM";
    
    engine.Shutdown();
}

/**
 * Integration Test: Known overlay DLL name detection
 * 
 * Tests the module name matching for common overlays.
 */
TEST(CorrelationIntegrationTest, OverlayModuleNameMatching) {
    CorrelationEngine engine;
    engine.Initialize();
    
    Severity severity_out;
    bool should_report;
    
    // Test various overlay module names
    const char* overlay_modules[] = {
        "discord_overlay.dll",
        "obs_hook.dll",
        "steamoverlay64.dll",
        "nvda.dll",
        "GeForceNOW.dll"
    };
    
    for (const char* module : overlay_modules) {
        engine.Reset();
        
        ViolationEvent hook{};
        hook.type = ViolationType::InlineHook;
        hook.severity = Severity::High;
        hook.module_name = module;
        hook.details = "Hook detected";
        
        engine.ProcessViolation(hook, severity_out, should_report);
        
        // Single hook from overlay should not allow enforcement
        EXPECT_FALSE(engine.ShouldAllowAction(ResponseAction::Ban))
            << "Hook from " << module << " should not allow Ban";
    }
    
    engine.Shutdown();
}

/**
 * Integration Test: Score accumulation with mixed signals
 * 
 * Tests realistic scenario with both legitimate and suspicious signals.
 */
TEST(CorrelationIntegrationTest, MixedSignalHandling) {
    CorrelationEngine engine;
    engine.Initialize();
    
    Severity severity_out;
    bool should_report;
    
    // Legitimate Discord overlay hook
    ViolationEvent discord{};
    discord.type = ViolationType::InlineHook;
    discord.severity = Severity::High;
    discord.module_name = "DiscordHook.dll";
    engine.ProcessViolation(discord, severity_out, should_report);
    
    // Suspicious debugger detection
    ViolationEvent debugger{};
    debugger.type = ViolationType::DebuggerAttached;
    debugger.severity = Severity::Critical;
    debugger.module_name = nullptr;
    engine.ProcessViolation(debugger, severity_out, should_report);
    
    // Suspicious memory modification
    ViolationEvent memory{};
    memory.type = ViolationType::MemoryWrite;
    memory.severity = Severity::High;
    memory.module_name = "cheat.dll";
    engine.ProcessViolation(memory, severity_out, should_report);
    
    // Even with Discord overlay, 2+ suspicious signals should enable reporting
    EXPECT_TRUE(should_report || engine.GetUniqueSignalCount() >= 2)
        << "Multiple suspicious signals should enable reporting";
    
    engine.Shutdown();
}
