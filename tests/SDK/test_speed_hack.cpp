/**
 * Sentinel SDK - Speed Hack Detection Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/Detection.hpp"

#ifdef _WIN32
#include <windows.h>
#include <thread>
#include <chrono>
#endif

#include <cmath>
#include <vector>

using namespace Sentinel::SDK;

/**
 * Test: Normal Operation
 * This test verifies that ValidateFrame() returns true 100 times with normal delays.
 */
TEST(SpeedHackTests, NormalOperation) {
    SpeedHackDetector detector;
    detector.Initialize();
    
    int successCount = 0;
    for (int i = 0; i < 100; i++) {
        bool result = detector.ValidateFrame();
        if (result) {
            successCount++;
        }
        
        // Small delay between frames to simulate normal operation
        #ifdef _WIN32
        Sleep(10);  // 10ms delay
        #else
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        #endif
    }
    
    // All frames should pass validation in normal operation
    EXPECT_EQ(successCount, 100)
        << "Expected all 100 frames to validate successfully, got " << successCount;
    
    detector.Shutdown();
}

/**
 * Test: Time Scale Reporting
 * This test verifies that GetTimeScale() returns approximately 1.0 (within 0.05).
 */
TEST(SpeedHackTests, TimeScaleReporting) {
    SpeedHackDetector detector;
    detector.Initialize();
    
    // Run several frames to stabilize the time scale estimate
    for (int i = 0; i < 50; i++) {
        detector.ValidateFrame();
        
        #ifdef _WIN32
        Sleep(10);  // 10ms delay
        #else
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        #endif
    }
    
    float timeScale = detector.GetTimeScale();
    
    // Time scale should be close to 1.0 (within 5% tolerance)
    EXPECT_NEAR(timeScale, 1.0f, 0.05f)
        << "Time scale should be approximately 1.0, got " << timeScale;
    
    detector.Shutdown();
}

/**
 * Test: Baseline Reset
 * This test verifies that UpdateBaseline() resets the anomaly count.
 */
TEST(SpeedHackTests, BaselineReset) {
    SpeedHackDetector detector;
    detector.Initialize();
    
    // Run some frames
    for (int i = 0; i < 10; i++) {
        detector.ValidateFrame();
        #ifdef _WIN32
        Sleep(10);
        #else
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        #endif
    }
    
    // Reset baseline
    detector.UpdateBaseline();
    
    // After reset, GetTimeScale should still be approximately 1.0
    float timeScale = detector.GetTimeScale();
    EXPECT_NEAR(timeScale, 1.0f, 0.1f)
        << "After baseline reset, time scale should be 1.0, got " << timeScale;
    
    // Validate frames should continue to work
    for (int i = 0; i < 10; i++) {
        bool result = detector.ValidateFrame();
        EXPECT_TRUE(result)
            << "ValidateFrame should return true after baseline reset";
        
        #ifdef _WIN32
        Sleep(10);
        #else
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        #endif
    }
    
    detector.Shutdown();
}

/**
 * Test: Performance - ValidateFrame execution time < 1ms
 * This test measures the execution time of ValidateFrame() to ensure it's fast enough.
 */
TEST(SpeedHackTests, Performance) {
#ifdef _WIN32
    SpeedHackDetector detector;
    detector.Initialize();
    
    // Warmup
    for (int i = 0; i < 10; i++) {
        detector.ValidateFrame();
        Sleep(10);
    }
    
    // Measure execution time more accurately without sleep interference
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    
    const int iterations = 1000;
    
    // Measure just the ValidateFrame calls without any sleep
    QueryPerformanceCounter(&start);
    for (int i = 0; i < iterations; i++) {
        detector.ValidateFrame();
    }
    QueryPerformanceCounter(&end);
    
    // Calculate average time per ValidateFrame call
    double totalElapsedMs = static_cast<double>(end.QuadPart - start.QuadPart) 
                           * 1000.0 / static_cast<double>(freq.QuadPart);
    double avgTimePerCall = totalElapsedMs / iterations;
    
    // Each call should take less than 1ms on average
    EXPECT_LT(avgTimePerCall, 1.0)
        << "ValidateFrame should execute in < 1ms, got " << avgTimePerCall << "ms average";
    
    detector.Shutdown();
#else
    GTEST_SKIP() << "Performance test only available on Windows";
#endif
}

/**
 * Test: No false positives in 10000 normal frames
 * This test runs 10000 frames to verify there are no false positives with 25% threshold.
 */
TEST(SpeedHackTests, NoFalsePositives) {
    SpeedHackDetector detector;
    detector.Initialize();
    
    int falsePositives = 0;
    
    for (int i = 0; i < 10000; i++) {
        bool result = detector.ValidateFrame();
        if (!result) {
            falsePositives++;
        }
        
        // Normal frame delay
        #ifdef _WIN32
        Sleep(16);  // ~60 FPS
        #else
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
        #endif
    }
    
    // Definition of Done requires no false positives in 10000 normal frames
    EXPECT_EQ(falsePositives, 0)
        << "Detected " << falsePositives << " false positives in 10000 frames";
    
    detector.Shutdown();
}

/**
 * Test: Multiple Initialize/Shutdown cycles
 * This test verifies that the detector can be reinitialized properly.
 */
TEST(SpeedHackTests, ReinitializationWorks) {
    SpeedHackDetector detector;
    
    for (int cycle = 0; cycle < 3; cycle++) {
        detector.Initialize();
        
        // Run some frames
        for (int i = 0; i < 10; i++) {
            bool result = detector.ValidateFrame();
            EXPECT_TRUE(result)
                << "ValidateFrame should return true in cycle " << cycle;
            
            #ifdef _WIN32
            Sleep(10);
            #else
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            #endif
        }
        
        detector.Shutdown();
    }
}

/**
 * Test: Wall clock validation activates periodically
 * This test verifies that the wall clock check is called every 60 frames.
 */
TEST(SpeedHackTests, WallClockValidationPeriodic) {
    SpeedHackDetector detector;
    detector.Initialize();
    
    // Run 120 frames to trigger wall clock validation at least twice
    for (int i = 0; i < 120; i++) {
        bool result = detector.ValidateFrame();
        EXPECT_TRUE(result)
            << "ValidateFrame should return true at frame " << i;
        
        #ifdef _WIN32
        Sleep(20);  // 20ms to accumulate > 1 second for wall clock check
        #else
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        #endif
    }
    
    detector.Shutdown();
}

/**
 * Test: Calibration Variance
 * This test verifies that calibration variance is <2% across 10 consecutive measurements.
 * This ensures the calibration is robust and not easily poisoned.
 */
TEST(SpeedHackTests, CalibrationVariance) {
    // This test needs access to internal calibration, so we'll test indirectly
    // by verifying that multiple Initialize() calls produce consistent results
    
    const int num_calibrations = 10;
    std::vector<float> time_scales;
    
    for (int i = 0; i < num_calibrations; i++) {
        SpeedHackDetector detector;
        detector.Initialize();
        
        // Run a few frames to stabilize
        for (int j = 0; j < 20; j++) {
            detector.ValidateFrame();
            #ifdef _WIN32
            Sleep(10);
            #else
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            #endif
        }
        
        time_scales.push_back(detector.GetTimeScale());
        detector.Shutdown();
    }
    
    // Calculate mean and variance
    double mean = 0.0;
    for (float ts : time_scales) {
        mean += ts;
    }
    mean /= num_calibrations;
    
    double variance = 0.0;
    for (float ts : time_scales) {
        double diff = ts - mean;
        variance += diff * diff;
    }
    variance /= num_calibrations;
    double stddev = std::sqrt(variance);
    
    // Coefficient of variation (CV) = stddev / mean
    // CV < 0.02 means variance < 2%
    double cv = stddev / mean;
    
    EXPECT_LT(cv, 0.02)
        << "Calibration variance should be < 2%, got CV=" << cv 
        << " (mean=" << mean << ", stddev=" << stddev << ")";
}

/**
 * Test: No Memory Leaks - 100 Initialize/Shutdown cycles
 * This test verifies that repeated Initialize/Shutdown cycles don't leak memory.
 * With the RAII fix (unique_ptr), env_detector_ is automatically cleaned up.
 */
TEST(SpeedHackTests, NoMemoryLeaksIn100Cycles) {
    SpeedHackDetector detector;
    
    // Run 100 init/shutdown cycles
    for (int cycle = 0; cycle < 100; cycle++) {
        detector.Initialize();
        
        // Run a few validation frames
        for (int i = 0; i < 5; i++) {
            detector.ValidateFrame();
            #ifdef _WIN32
            Sleep(5);
            #else
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            #endif
        }
        
        detector.Shutdown();
    }
    
    // Test passes if it completes without crashing
    // Memory leak detection requires Valgrind/ASan for verification
    SUCCEED() << "Completed 100 init/shutdown cycles without issues";
}

/**
 * Manual test instructions (not automated):
 * 
 * Adversarial Test - Simulated Speed Hack:
 * To manually test speed hack detection with Cheat Engine:
 * 1. Build the test executable in Release mode
 * 2. Open Cheat Engine
 * 3. Attach to the test process
 * 4. Enable Speedhack (e.g., 2.0x speed)
 * 5. Run the NormalOperation or NoFalsePositives test
 * 6. Verify that detection triggers within 3 seconds (ValidateFrame returns false)
 * 
 * Expected behavior with 2.0x speed hack:
 * - ValidateFrame() should detect the speed difference
 * - Detection should occur within 3 seconds (~180 frames at 60 FPS)
 * - After 3+ anomalies, ValidateFrame() should return false
 * - The test should fail due to detected speed manipulation
 * 
 * Adversarial Test - Hooked Sleep():
 * To test that calibration survives Sleep() hooking:
 * 1. Build the test executable in Release mode
 * 2. Hook Sleep() to return 10x faster (e.g., Sleep(100) returns after 10ms)
 * 3. Run the CalibrationVariance or NormalOperation test
 * 4. Verify that the calibration is still accurate and detection still works
 * 5. The calibration now uses busy-wait with QueryPerformanceCounter, so Sleep() hooks have no effect
 * 
 * Definition of Done criteria:
 * - Detects 2x speed acceleration within 3 seconds
 * - Zero false positives in 10000 normal frames (25% threshold)
 * - Time scale estimation accurate ±5%
 * - ValidateFrame() executes in < 1ms
 * - RDTSC integrated as third time source
 * - Monotonicity checks detect time going backwards
 * - Calibration variance <2% across 10 consecutive measurements
 * - Detection survives Sleep() being hooked
 * 
 * Severity Level:
 * - Speed hack detection severity is "High" (not "Critical")
 * - Without server-side validation, confidence is inherently limited
 * - See SpeedHack.cpp header comments for server-side protocol documentation
 */
