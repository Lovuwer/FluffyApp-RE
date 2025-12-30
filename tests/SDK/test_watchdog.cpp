/**
 * Sentinel SDK - Watchdog Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * TASK-07: Heartbeat Thread Watchdog Tests
 */

#include <gtest/gtest.h>
#include "Internal/Watchdog.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <thread>
#include <chrono>

using namespace Sentinel::SDK;

/**
 * Test: Normal Operation
 * Verifies that watchdog reports alive when pings occur within threshold
 */
TEST(WatchdogTests, NormalOperation) {
    Watchdog watchdog;
    
    // Test with regular pings - should always be alive
    for (int i = 0; i < 10; i++) {
        watchdog.Ping();
        
        // Check immediately - should be alive
        EXPECT_TRUE(watchdog.IsAlive(1000))
            << "Watchdog should be alive immediately after ping";
        
        // Small delay
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Check after 100ms - should still be alive
        EXPECT_TRUE(watchdog.IsAlive(1000))
            << "Watchdog should be alive 100ms after ping with 1000ms threshold";
    }
}

/**
 * Test: Thread Death Detection
 * Verifies that watchdog detects when thread stops pinging
 */
TEST(WatchdogTests, ThreadDeathDetection) {
    Watchdog watchdog;
    
    // Initial ping
    watchdog.Ping();
    
    // Should be alive immediately
    EXPECT_TRUE(watchdog.IsAlive(1000))
        << "Watchdog should be alive immediately after ping";
    
    // Wait longer than threshold without pinging
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    
    // Should now be dead
    EXPECT_FALSE(watchdog.IsAlive(1000))
        << "Watchdog should detect death after 1200ms without ping (threshold: 1000ms)";
}

/**
 * Test: Multiple Threshold Values
 * Verifies that IsAlive works correctly with different threshold values
 */
TEST(WatchdogTests, MultipleThresholds) {
    Watchdog watchdog;
    
    watchdog.Ping();
    
    // Wait 500ms
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Should be alive with 1000ms threshold
    EXPECT_TRUE(watchdog.IsAlive(1000))
        << "Should be alive with 1000ms threshold after 500ms delay";
    
    // Should be dead with 300ms threshold
    EXPECT_FALSE(watchdog.IsAlive(300))
        << "Should be dead with 300ms threshold after 500ms delay";
}

/**
 * Test: Time Since Last Ping
 * Verifies that GetTimeSinceLastPing returns accurate values
 */
TEST(WatchdogTests, TimeSinceLastPing) {
    Watchdog watchdog;
    
    watchdog.Ping();
    
    // Immediately after ping
    uint64_t time_since = watchdog.GetTimeSinceLastPing();
    EXPECT_LT(time_since, 50)
        << "Time since last ping should be very small immediately after ping";
    
    // Wait 200ms
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    time_since = watchdog.GetTimeSinceLastPing();
    EXPECT_GE(time_since, 180)
        << "Time since last ping should be at least 180ms";
    EXPECT_LE(time_since, 250)
        << "Time since last ping should be at most 250ms (accounting for timing variance)";
}

/**
 * Test: Simulated Heartbeat Thread
 * Simulates a heartbeat thread running and verifies watchdog tracks it correctly
 */
TEST(WatchdogTests, SimulatedHeartbeatThread) {
    Watchdog watchdog;
    std::atomic<bool> thread_running{true};
    
    // Start a simulated heartbeat thread
    std::thread heartbeat_thread([&]() {
        while (thread_running.load()) {
            watchdog.Ping();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    
    // Let thread run for a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Watchdog should report alive (3x interval = 300ms threshold)
    EXPECT_TRUE(watchdog.IsAlive(300))
        << "Watchdog should detect thread as alive while it's pinging every 100ms";
    
    // Stop the thread (simulating TerminateThread)
    thread_running.store(false);
    heartbeat_thread.join();
    
    // Wait longer than threshold
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    
    // Watchdog should now detect thread as dead
    EXPECT_FALSE(watchdog.IsAlive(300))
        << "Watchdog should detect thread death after it stops pinging";
}

/**
 * Test: Recovery After Death Detection
 * Verifies that watchdog can recover if thread resumes pinging
 */
TEST(WatchdogTests, RecoveryAfterDeath) {
    Watchdog watchdog;
    
    // Initial ping
    watchdog.Ping();
    
    // Wait to simulate death
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    
    // Should be dead
    EXPECT_FALSE(watchdog.IsAlive(500))
        << "Watchdog should detect death";
    
    // Resume pinging (simulating thread restart)
    watchdog.Ping();
    
    // Should be alive again
    EXPECT_TRUE(watchdog.IsAlive(500))
        << "Watchdog should detect recovery after new ping";
}
