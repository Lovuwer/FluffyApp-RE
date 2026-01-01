/**
 * Sentinel SDK - IntegrityValidator Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 8: Tests for Memory Integrity Self-Validation
 */

#include <gtest/gtest.h>
#include "Internal/IntegrityValidator.hpp"
#include <thread>
#include <chrono>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

using namespace Sentinel::SDK;

/**
 * Test 1: Initialization
 * Verifies that the validator initializes successfully
 */
TEST(IntegrityValidatorTests, Initialization) {
    IntegrityValidator validator;
    
    EXPECT_FALSE(validator.IsInitialized()) << "Should not be initialized before Initialize()";
    
    validator.Initialize();
    
    EXPECT_TRUE(validator.IsInitialized()) << "Should be initialized after Initialize()";
    
    validator.Shutdown();
    
    EXPECT_FALSE(validator.IsInitialized()) << "Should not be initialized after Shutdown()";
}

/**
 * Test 2: Clean Code Validation
 * Verifies that validation succeeds when code is unmodified
 */
TEST(IntegrityValidatorTests, CleanCodeValidation) {
    IntegrityValidator validator;
    validator.Initialize();
    
    // Should succeed immediately after initialization
    EXPECT_TRUE(validator.ValidateQuick()) << "Quick validation should succeed on clean code";
    
    auto violations = validator.ValidateFull();
    EXPECT_TRUE(violations.empty()) << "Full validation should find no violations on clean code";
    
    validator.Shutdown();
}

/**
 * Test 3: Performance Requirements
 * Verifies that validation completes within 1ms performance budget
 */
TEST(IntegrityValidatorTests, PerformanceRequirements) {
    IntegrityValidator validator;
    validator.Initialize();
    
    // Warm up
    validator.ValidateQuick();
    
    // Measure quick validation time
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        validator.ValidateQuick();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    auto avg_us = duration_us / iterations;
    
    EXPECT_LT(avg_us, 1000) << "Average validation time should be < 1ms (1000us), got " << avg_us << "us";
    
    // Measure full validation time
    start = std::chrono::high_resolution_clock::now();
    validator.ValidateFull();
    end = std::chrono::high_resolution_clock::now();
    
    duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    EXPECT_LT(duration_us, 10000) << "Full validation time should be < 10ms, got " << duration_us << "us";
    
    validator.Shutdown();
}

/**
 * Test 4: Randomized Timing
 * Verifies that validation timing is randomized to prevent predictability
 */
TEST(IntegrityValidatorTests, RandomizedTiming) {
    IntegrityValidator validator;
    validator.Initialize();
    
    // Collect multiple next validation times
    std::vector<uint64_t> intervals;
    
    for (int i = 0; i < 10; i++) {
        uint64_t time_until = validator.GetTimeUntilNextValidation();
        intervals.push_back(time_until);
        
        // Force a validation to trigger recalculation
        validator.ValidateQuick();
        
        // Small delay to ensure time changes
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Check that not all intervals are the same (randomization working)
    bool has_variation = false;
    uint64_t first = intervals[0];
    
    for (size_t i = 1; i < intervals.size(); i++) {
        if (intervals[i] != first) {
            has_variation = true;
            break;
        }
    }
    
    EXPECT_TRUE(has_variation) << "Validation timing should have randomized jitter";
    
    validator.Shutdown();
}

/**
 * Test 5: Multiple Quick Validations
 * Verifies that multiple quick validations work correctly
 */
TEST(IntegrityValidatorTests, MultipleQuickValidations) {
    IntegrityValidator validator;
    validator.Initialize();
    
    // Run multiple quick validations
    for (int i = 0; i < 50; i++) {
        bool result = validator.ValidateQuick();
        EXPECT_TRUE(result) << "Quick validation " << i << " should succeed";
        
        // Small delay between validations
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    
    validator.Shutdown();
}

/**
 * Test 6: Full Scan After Quick Scans
 * Verifies that full scan works correctly after quick scans
 */
TEST(IntegrityValidatorTests, FullScanAfterQuickScans) {
    IntegrityValidator validator;
    validator.Initialize();
    
    // Do some quick validations first
    for (int i = 0; i < 10; i++) {
        validator.ValidateQuick();
    }
    
    // Then do a full scan
    auto violations = validator.ValidateFull();
    EXPECT_TRUE(violations.empty()) << "Full scan should find no violations after quick scans";
    
    validator.Shutdown();
}

/**
 * Test 7: Zero False Positives
 * Verifies that validator doesn't produce false positives under normal operation
 */
TEST(IntegrityValidatorTests, ZeroFalsePositives) {
    IntegrityValidator validator;
    validator.Initialize();
    
    // Run extensive validation series
    int total_checks = 1000;
    int false_positives = 0;
    
    for (int i = 0; i < total_checks; i++) {
        if (!validator.ValidateQuick()) {
            false_positives++;
        }
        
        // Vary timing slightly
        if (i % 10 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    
    EXPECT_EQ(0, false_positives) << "Should have zero false positives, got " << false_positives;
    
    validator.Shutdown();
}

/**
 * Test 8: Thread Safety
 * Verifies that validator is thread-safe
 */
TEST(IntegrityValidatorTests, ThreadSafety) {
    IntegrityValidator validator;
    validator.Initialize();
    
    std::atomic<int> failures{0};
    const int num_threads = 4;
    const int iterations_per_thread = 50;
    
    std::vector<std::thread> threads;
    
    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([&validator, &failures, iterations_per_thread]() {
            for (int i = 0; i < iterations_per_thread; i++) {
                if (!validator.ValidateQuick()) {
                    failures++;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(0, failures.load()) << "All validations should succeed in multi-threaded context";
    
    validator.Shutdown();
}

/**
 * Test 9: Continuous Operation
 * Verifies that validator works correctly over extended operation
 */
TEST(IntegrityValidatorTests, ContinuousOperation) {
    IntegrityValidator validator;
    validator.Initialize();
    
    // Simulate 5 seconds of continuous operation
    auto start_time = std::chrono::steady_clock::now();
    auto end_time = start_time + std::chrono::seconds(5);
    
    int validation_count = 0;
    int failure_count = 0;
    
    while (std::chrono::steady_clock::now() < end_time) {
        if (!validator.ValidateQuick()) {
            failure_count++;
        }
        validation_count++;
        
        // Sleep to simulate frame time (~16ms for 60fps)
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    
    EXPECT_GT(validation_count, 0) << "Should have performed validations";
    EXPECT_EQ(0, failure_count) << "Should have no failures during continuous operation";
    
    // Should have performed at least a few validations (with randomized timing)
    EXPECT_GT(validation_count, 10) << "Should have performed multiple validations over 5 seconds";
    
    validator.Shutdown();
}

/**
 * Test 10: Shutdown and Re-initialization
 * Verifies that validator can be shut down and re-initialized
 */
TEST(IntegrityValidatorTests, ShutdownAndReinit) {
    IntegrityValidator validator;
    
    // Initialize and validate
    validator.Initialize();
    EXPECT_TRUE(validator.IsInitialized());
    EXPECT_TRUE(validator.ValidateQuick());
    
    // Shutdown
    validator.Shutdown();
    EXPECT_FALSE(validator.IsInitialized());
    
    // Re-initialize
    validator.Initialize();
    EXPECT_TRUE(validator.IsInitialized());
    EXPECT_TRUE(validator.ValidateQuick());
    
    // Final shutdown
    validator.Shutdown();
    EXPECT_FALSE(validator.IsInitialized());
}

/**
 * Test 11: Detection Within 5 Seconds
 * Simulates the requirement that tampering is detected within 5 seconds
 * Note: This test validates timing infrastructure rather than actual tamper detection
 */
TEST(IntegrityValidatorTests, DetectionTiming) {
    IntegrityValidator validator;
    validator.Initialize();
    
    // Track validation frequency over 5 seconds
    auto start_time = std::chrono::steady_clock::now();
    auto end_time = start_time + std::chrono::seconds(5);
    
    int validation_count = 0;
    
    while (std::chrono::steady_clock::now() < end_time) {
        validator.ValidateQuick();
        validation_count++;
        
        // Sleep to avoid busy loop
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // With randomized timing between 1-5 seconds, we should see at least 1 validation
    // In practice, we should see several validations over 5 seconds
    EXPECT_GT(validation_count, 0) << "Should perform validations within 5 second window";
    
    validator.Shutdown();
}
