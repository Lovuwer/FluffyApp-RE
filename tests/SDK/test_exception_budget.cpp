/**
 * Sentinel SDK - Exception Budget Tests (Task 09)
 * 
 * Tests for exception budget enforcement during detection scans.
 * Verifies that scans stop after configured number of exceptions
 * and that budget resets between scans.
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/RuntimeConfig.hpp"
#include "Internal/SafeMemory.hpp"
#include "Internal/Detection.hpp"
#include <thread>
#include <chrono>
#include <vector>

using namespace Sentinel::SDK;

// ==================== Integration Tests ====================

class ExceptionBudgetIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        config_.Initialize();
    }
    
    void TearDown() override {
        config_.Shutdown();
    }
    
    RuntimeConfig config_;
};

TEST_F(ExceptionBudgetIntegrationTest, DefaultBudgetIs10) {
    auto global_config = config_.GetGlobalConfig();
    EXPECT_EQ(global_config.exception_budget_per_scan, 10u);
}

TEST_F(ExceptionBudgetIntegrationTest, SafeMemoryRespectsConfiguredBudget) {
    // Set budget to 5
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(5);
    
    auto& stats = SafeMemory::GetExceptionStats();
    
    // Simulate 4 exceptions - should not exceed
    stats.access_violations = 4;
    EXPECT_FALSE(SafeMemory::IsExceptionLimitExceeded());
    
    // Add one more to reach 5 - should now be exceeded
    stats.access_violations = 5;
    EXPECT_TRUE(SafeMemory::IsExceptionLimitExceeded());
}

TEST_F(ExceptionBudgetIntegrationTest, BudgetResetsForEachScan) {
    // First scan
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(10);
    
    auto& stats = SafeMemory::GetExceptionStats();
    stats.access_violations = 10;
    EXPECT_TRUE(SafeMemory::IsExceptionLimitExceeded());
    
    // Second scan - reset
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(10);
    
    auto& stats2 = SafeMemory::GetExceptionStats();
    EXPECT_EQ(stats2.GetTotalExceptions(), 0u);
    EXPECT_FALSE(SafeMemory::IsExceptionLimitExceeded());
    
    // Can accumulate exceptions again
    stats2.access_violations = 5;
    EXPECT_FALSE(SafeMemory::IsExceptionLimitExceeded());
}

TEST_F(ExceptionBudgetIntegrationTest, MultipleExceptionTypesCountTowardBudget) {
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(10);
    
    auto& stats = SafeMemory::GetExceptionStats();
    stats.access_violations = 3;
    stats.guard_page_hits = 3;
    stats.stack_overflows = 2;
    stats.other_exceptions = 2;
    
    // Total is 10, should be at limit
    EXPECT_EQ(stats.GetTotalExceptions(), 10u);
    EXPECT_TRUE(SafeMemory::IsExceptionLimitExceeded());
}

TEST_F(ExceptionBudgetIntegrationTest, BudgetZeroUsesDefaultFromParameter) {
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(0);  // 0 means use default
    
    auto& stats = SafeMemory::GetExceptionStats();
    
    // With default of 10 in IsExceptionLimitExceeded parameter
    stats.access_violations = 9;
    EXPECT_FALSE(SafeMemory::IsExceptionLimitExceeded(10));
    
    stats.access_violations = 10;
    EXPECT_TRUE(SafeMemory::IsExceptionLimitExceeded(10));
}

// ==================== Simulated Scan Tests ====================

TEST_F(ExceptionBudgetIntegrationTest, SimulatedScanStopsAtBudget) {
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(10);
    
    // Simulate scanning 20 regions, but stop at budget
    int regions_scanned = 0;
    auto& stats = SafeMemory::GetExceptionStats();
    
    for (int i = 0; i < 20; i++) {
        if (SafeMemory::IsExceptionLimitExceeded()) {
            break;  // Stop scanning - budget exceeded
        }
        
        // Simulate exception on each region
        stats.access_violations++;
        regions_scanned++;
    }
    
    // Should have scanned exactly 10 regions before stopping
    EXPECT_EQ(regions_scanned, 10);
    EXPECT_EQ(stats.GetTotalExceptions(), 10u);
}

TEST_F(ExceptionBudgetIntegrationTest, SecondScanGetsFullBudget) {
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(10);
    
    auto& stats = SafeMemory::GetExceptionStats();
    
    // First scan exhausts budget
    for (int i = 0; i < 20; i++) {
        if (SafeMemory::IsExceptionLimitExceeded()) {
            break;
        }
        stats.access_violations++;
    }
    EXPECT_EQ(stats.GetTotalExceptions(), 10u);
    
    // Second scan - reset and get full budget again
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(10);
    
    auto& stats2 = SafeMemory::GetExceptionStats();
    int regions_scanned = 0;
    
    for (int i = 0; i < 20; i++) {
        if (SafeMemory::IsExceptionLimitExceeded()) {
            break;
        }
        stats2.access_violations++;
        regions_scanned++;
    }
    
    // Should get full 10 regions again
    EXPECT_EQ(regions_scanned, 10);
    EXPECT_EQ(stats2.GetTotalExceptions(), 10u);
}

// ==================== Edge Cases ====================

TEST_F(ExceptionBudgetIntegrationTest, ZeroExceptionsAllowsScanToComplete) {
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(10);
    
    auto& stats = SafeMemory::GetExceptionStats();
    
    // Simulate scanning 20 regions with no exceptions
    int regions_scanned = 0;
    for (int i = 0; i < 20; i++) {
        if (SafeMemory::IsExceptionLimitExceeded()) {
            break;
        }
        // No exception simulation
        regions_scanned++;
    }
    
    // Should scan all 20 regions
    EXPECT_EQ(regions_scanned, 20);
    EXPECT_EQ(stats.GetTotalExceptions(), 0u);
}

TEST_F(ExceptionBudgetIntegrationTest, CustomBudgetWorks) {
    auto global_config = config_.GetGlobalConfig();
    uint32_t custom_budget = 3;
    
    SafeMemory::ResetExceptionStats();
    SafeMemory::SetExceptionBudget(custom_budget);
    
    auto& stats = SafeMemory::GetExceptionStats();
    int regions_scanned = 0;
    
    for (int i = 0; i < 20; i++) {
        if (SafeMemory::IsExceptionLimitExceeded()) {
            break;
        }
        stats.access_violations++;
        regions_scanned++;
    }
    
    // Should stop at custom budget of 3
    EXPECT_EQ(regions_scanned, 3);
    EXPECT_EQ(stats.GetTotalExceptions(), 3u);
}
