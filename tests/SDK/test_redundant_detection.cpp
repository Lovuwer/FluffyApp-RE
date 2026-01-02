/**
 * Sentinel SDK - Redundant Detection Tests
 * 
 * Task 29: Test redundant detection architecture
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "SentinelSDK.hpp"
#include "Internal/DetectionRegistry.hpp"
#include "Internal/RedundantAntiDebug.hpp"
#include "Internal/TelemetryEmitter.hpp"

using namespace Sentinel::SDK;

class RedundantDetectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        registry = std::make_unique<DetectionRegistry>();
    }
    
    void TearDown() override {
        registry.reset();
    }
    
    std::unique_ptr<DetectionRegistry> registry;
};

// Test 1: Registry can register multiple implementations
TEST_F(RedundantDetectionTest, RegisterMultipleImplementations) {
    // Register primary implementation
    auto primary = std::make_unique<AntiDebugPrimaryImpl>();
    registry->RegisterImplementation(std::move(primary));
    
    // Register alternative implementation
    auto alt = std::make_unique<AntiDebugAlternativeImpl>();
    registry->RegisterImplementation(std::move(alt));
    
    // Should have 2 implementations registered
    EXPECT_EQ(2u, registry->GetImplementationCount(DetectionType::AntiDebug));
}

// Test 2: Redundancy configuration defaults to disabled
TEST_F(RedundantDetectionTest, RedundancyDefaultsToDisabled) {
    // Register implementations
    auto primary = std::make_unique<AntiDebugPrimaryImpl>();
    registry->RegisterImplementation(std::move(primary));
    
    auto alt = std::make_unique<AntiDebugAlternativeImpl>();
    registry->RegisterImplementation(std::move(alt));
    
    // Get config - should default to None/disabled
    auto config = registry->GetRedundancyConfig(DetectionType::AntiDebug);
    EXPECT_FALSE(config.enabled);
    EXPECT_EQ(RedundancyLevel::None, config.level);
}

// Test 3: Setting redundancy level to Standard uses 2 implementations
TEST_F(RedundantDetectionTest, StandardLevelUsesTwoImplementations) {
    // Register implementations
    auto primary = std::make_unique<AntiDebugPrimaryImpl>();
    registry->RegisterImplementation(std::move(primary));
    
    auto alt = std::make_unique<AntiDebugAlternativeImpl>();
    registry->RegisterImplementation(std::move(alt));
    
    // Enable redundancy at Standard level
    RedundancyConfig config(DetectionType::AntiDebug, RedundancyLevel::Standard, true);
    registry->SetRedundancyConfig(config);
    
    // Initialize implementations
    registry->InitializeAll();
    
    // Execute a quick check - should use both implementations
    auto violations = registry->ExecuteQuickCheck(DetectionType::AntiDebug);
    
    // Get statistics
    auto stats = registry->GetStatistics(DetectionType::AntiDebug);
    EXPECT_EQ(2u, stats.active_implementations);
    EXPECT_EQ(1u, stats.total_checks_performed);
}

// Test 4: None level uses only 1 implementation (legacy behavior)
TEST_F(RedundantDetectionTest, NoneLevelUsesOneImplementation) {
    // Register implementations
    auto primary = std::make_unique<AntiDebugPrimaryImpl>();
    registry->RegisterImplementation(std::move(primary));
    
    auto alt = std::make_unique<AntiDebugAlternativeImpl>();
    registry->RegisterImplementation(std::move(alt));
    
    // Set redundancy to None (disabled)
    RedundancyConfig config(DetectionType::AntiDebug, RedundancyLevel::None, false);
    registry->SetRedundancyConfig(config);
    
    // Initialize implementations
    registry->InitializeAll();
    
    // Execute a check
    auto violations = registry->ExecuteQuickCheck(DetectionType::AntiDebug);
    
    // Get statistics - should only use 1 implementation
    auto stats = registry->GetStatistics(DetectionType::AntiDebug);
    EXPECT_EQ(1u, stats.active_implementations);
}

// Test 5: Violation deduplication works
TEST_F(RedundantDetectionTest, ViolationDeduplication) {
    // Create a mock implementation that always reports the same violation
    class MockDetector : public IDetectionImplementation {
    public:
        DetectionType GetCategory() const override { return DetectionType::AntiDebug; }
        const char* GetImplementationId() const override { return "mock"; }
        const char* GetDescription() const override { return "Mock detector"; }
        
        std::vector<ViolationEvent> QuickCheck() override {
            std::vector<ViolationEvent> violations;
            ViolationEvent event;
            event.type = ViolationType::DebuggerAttached;
            event.severity = Severity::High;
            event.timestamp = 1000;
            event.address = 0x12345678;
            event.details = "Test violation";
            violations.push_back(event);
            return violations;
        }
        
        std::vector<ViolationEvent> FullCheck() override { return QuickCheck(); }
    };
    
    // Register two identical mock detectors
    registry->RegisterImplementation(std::make_unique<MockDetector>());
    registry->RegisterImplementation(std::make_unique<MockDetector>());
    
    // Enable redundancy
    RedundancyConfig config(DetectionType::AntiDebug, RedundancyLevel::Standard, true);
    registry->SetRedundancyConfig(config);
    
    // Execute check - should get 2 violations but deduplicate to 1
    auto violations = registry->ExecuteQuickCheck(DetectionType::AntiDebug);
    
    // Should have deduplicated to 1 violation
    EXPECT_EQ(1u, violations.size());
    
    // Check statistics
    auto stats = registry->GetStatistics(DetectionType::AntiDebug);
    EXPECT_EQ(1u, stats.duplicate_violations_filtered);
}

// Test 6: Statistics are tracked correctly
TEST_F(RedundantDetectionTest, StatisticsTracking) {
    // Register implementations
    auto primary = std::make_unique<AntiDebugPrimaryImpl>();
    registry->RegisterImplementation(std::move(primary));
    
    auto alt = std::make_unique<AntiDebugAlternativeImpl>();
    registry->RegisterImplementation(std::move(alt));
    
    // Enable redundancy
    RedundancyConfig config(DetectionType::AntiDebug, RedundancyLevel::Standard, true);
    registry->SetRedundancyConfig(config);
    
    registry->InitializeAll();
    
    // Execute multiple checks
    registry->ExecuteQuickCheck(DetectionType::AntiDebug);
    registry->ExecuteQuickCheck(DetectionType::AntiDebug);
    registry->ExecuteFullCheck(DetectionType::AntiDebug);
    
    // Check statistics
    auto stats = registry->GetStatistics(DetectionType::AntiDebug);
    EXPECT_EQ(3u, stats.total_checks_performed);
    // avg_overhead_us might be 0 on fast systems, so just check it's not negative
    EXPECT_GE(stats.avg_overhead_us, 0.0f);
}

// Test 7: Statistics can be reset
TEST_F(RedundantDetectionTest, StatisticsReset) {
    // Register implementation
    auto primary = std::make_unique<AntiDebugPrimaryImpl>();
    registry->RegisterImplementation(std::move(primary));
    
    // Enable redundancy
    RedundancyConfig config(DetectionType::AntiDebug, RedundancyLevel::None, false);
    registry->SetRedundancyConfig(config);
    
    registry->InitializeAll();
    
    // Execute some checks
    registry->ExecuteQuickCheck(DetectionType::AntiDebug);
    
    // Reset statistics
    registry->ResetStatistics();
    
    // Check statistics are reset
    auto stats = registry->GetStatistics(DetectionType::AntiDebug);
    EXPECT_EQ(0u, stats.total_checks_performed);
    EXPECT_EQ(0.0f, stats.avg_overhead_us);
}

// Test 8: Empty category returns empty violations
TEST_F(RedundantDetectionTest, EmptyCategoryReturnsEmpty) {
    // Don't register any implementations for MemoryIntegrity
    
    // Try to execute check - should return empty
    auto violations = registry->ExecuteQuickCheck(DetectionType::MemoryIntegrity);
    
    EXPECT_TRUE(violations.empty());
}
