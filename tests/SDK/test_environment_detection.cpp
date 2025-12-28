/**
 * Sentinel SDK - Environment Detection Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/EnvironmentDetection.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

using namespace Sentinel::SDK;

/**
 * Test: Environment detector initialization
 */
TEST(EnvironmentDetectionTests, Initialization) {
    EnvironmentDetector detector;
    detector.Initialize();
    
    // Should initialize without crashing
    const EnvironmentInfo& info = detector.GetEnvironmentInfo();
    
    // Default environment type should be set
    EXPECT_TRUE(info.type == EnvironmentType::Local || 
                info.type == EnvironmentType::VM || 
                info.type == EnvironmentType::CloudGaming);
    
    detector.Shutdown();
}

/**
 * Test: Timing variance threshold for local environment
 */
TEST(EnvironmentDetectionTests, LocalEnvironmentThreshold) {
    EnvironmentDetector detector;
    detector.Initialize();
    
    // In a non-cloud, non-VM environment, threshold should be 15%
    if (detector.GetEnvironmentType() == EnvironmentType::Local) {
        float threshold = detector.GetTimingVarianceThreshold();
        EXPECT_FLOAT_EQ(threshold, 0.15f);
    }
    
    detector.Shutdown();
}

/**
 * Test: Timing variance threshold for VM environment
 */
TEST(EnvironmentDetectionTests, VMEnvironmentThreshold) {
    EnvironmentDetector detector;
    detector.Initialize();
    
    // If VM is detected, threshold should be 35%
    if (detector.GetEnvironmentType() == EnvironmentType::VM) {
        float threshold = detector.GetTimingVarianceThreshold();
        EXPECT_FLOAT_EQ(threshold, 0.35f);
    }
    
    detector.Shutdown();
}

/**
 * Test: Simulated cloud gaming environment (via environment variable)
 */
TEST(EnvironmentDetectionTests, CloudGamingDetection) {
#ifdef _WIN32
    // Set GeForce NOW environment variable
    SetEnvironmentVariableA("GFN_SDK_VERSION", "1.0");
    
    EnvironmentDetector detector;
    detector.Initialize();
    
    // Should detect cloud gaming
    EXPECT_EQ(detector.GetEnvironmentType(), EnvironmentType::CloudGaming);
    EXPECT_TRUE(detector.IsCloudGaming());
    EXPECT_TRUE(detector.GetEnvironmentInfo().is_geforce_now);
    
    // Threshold should be 50%
    float threshold = detector.GetTimingVarianceThreshold();
    EXPECT_FLOAT_EQ(threshold, 0.50f);
    
    // Environment string should be "cloud"
    EXPECT_STREQ(detector.GetEnvironmentString(), "cloud");
    
    detector.Shutdown();
    
    // Clean up environment variable
    SetEnvironmentVariableA("GFN_SDK_VERSION", nullptr);
#else
    GTEST_SKIP() << "Cloud gaming detection test only available on Windows";
#endif
}

/**
 * Test: Timing instability score tracking
 */
TEST(EnvironmentDetectionTests, TimingInstabilityTracking) {
    EnvironmentDetector detector;
    detector.Initialize();
    
    // Initially, timing instability should be 0
    EXPECT_FLOAT_EQ(detector.GetEnvironmentInfo().timing_instability_score, 0.0);
    
    // Simulate some timing variance
    for (int i = 0; i < 50; i++) {
        // 5% variance
        detector.UpdateTimingInstability(0.05);
    }
    
    // Instability score should be updated
    double score = detector.GetEnvironmentInfo().timing_instability_score;
    EXPECT_GT(score, 0.0);
    EXPECT_LT(score, 1.0);
    
    detector.Shutdown();
}

/**
 * Test: High timing instability detection
 */
TEST(EnvironmentDetectionTests, HighTimingInstability) {
    EnvironmentDetector detector;
    detector.Initialize();
    
    // Simulate high timing variance (30% average)
    for (int i = 0; i < 100; i++) {
        detector.UpdateTimingInstability(0.30);
    }
    
    // Instability score should be high (approaching 1.0)
    double score = detector.GetEnvironmentInfo().timing_instability_score;
    EXPECT_GE(score, 0.9);
    
    detector.Shutdown();
}

/**
 * Test: Environment string for different types
 */
TEST(EnvironmentDetectionTests, EnvironmentStrings) {
    EnvironmentDetector detector;
    detector.Initialize();
    
    const char* env_str = detector.GetEnvironmentString();
    
    // Should be one of the expected values
    EXPECT_TRUE(strcmp(env_str, "local") == 0 || 
                strcmp(env_str, "vm") == 0 || 
                strcmp(env_str, "cloud") == 0);
    
    detector.Shutdown();
}

/**
 * Test: Multiple Initialize/Shutdown cycles
 */
TEST(EnvironmentDetectionTests, ReinitializationWorks) {
    EnvironmentDetector detector;
    
    for (int cycle = 0; cycle < 3; cycle++) {
        detector.Initialize();
        
        // Should work properly each time
        const EnvironmentInfo& info = detector.GetEnvironmentInfo();
        EXPECT_TRUE(info.type == EnvironmentType::Local || 
                    info.type == EnvironmentType::VM || 
                    info.type == EnvironmentType::CloudGaming);
        
        detector.Shutdown();
    }
}
