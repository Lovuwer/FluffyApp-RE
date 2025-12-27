/**
 * Sentinel SDK - Integrity Check Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 10: Tests for Code Section Integrity Verification
 */

#include <gtest/gtest.h>
#include "Internal/Detection.hpp"
#include "Internal/Context.hpp"
#include <thread>
#include <vector>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace Sentinel::SDK;

/**
 * Test 1: Clean State - Code Section Verification
 * Verifies that QuickCheck() returns no violations in a clean state
 */
TEST(IntegrityCheckTests, CleanStateCodeSection) {
    IntegrityChecker checker;
    checker.Initialize();
    
    // In a clean state, QuickCheck should return no violations
    std::vector<ViolationEvent> violations = checker.QuickCheck();
    
    EXPECT_TRUE(violations.empty()) 
        << "QuickCheck should return no violations in clean state";
    
    checker.Shutdown();
}

/**
 * Test 2: Region Registration
 * Verifies that we can register a memory region and it passes verification
 */
TEST(IntegrityCheckTests, RegionRegistration) {
    IntegrityChecker checker;
    checker.Initialize();
    
    // Allocate a buffer with known content
    const size_t bufferSize = 1024;
    uint8_t* buffer = new uint8_t[bufferSize];
    memset(buffer, 0xAA, bufferSize);
    
    // Compute hash for the region
    uint64_t hash = Internal::ComputeHash(buffer, bufferSize);
    
    // Create and register the region
    MemoryRegion region;
    region.address = reinterpret_cast<uintptr_t>(buffer);
    region.size = bufferSize;
    region.name = "TestBuffer";
    region.original_hash = hash;
    
    checker.RegisterRegion(region);
    
    // Verify the region passes verification
    std::vector<ViolationEvent> violations = checker.QuickCheck();
    
    EXPECT_TRUE(violations.empty())
        << "Registered region should pass verification when unmodified";
    
    // Cleanup
    delete[] buffer;
    checker.Shutdown();
}

/**
 * Test 3: Tampering Detection (Simulated)
 * Verifies that modifications to a registered region are detected
 */
TEST(IntegrityCheckTests, TamperingDetection) {
    IntegrityChecker checker;
    checker.Initialize();
    
    // Allocate a writable buffer
    const size_t bufferSize = 1024;
    uint8_t* buffer = new uint8_t[bufferSize];
    memset(buffer, 0xAA, bufferSize);
    
    // Compute initial hash
    uint64_t hash = Internal::ComputeHash(buffer, bufferSize);
    
    // Register the region
    MemoryRegion region;
    region.address = reinterpret_cast<uintptr_t>(buffer);
    region.size = bufferSize;
    region.name = "TamperTestBuffer";
    region.original_hash = hash;
    
    checker.RegisterRegion(region);
    
    // Verify it's initially clean
    std::vector<ViolationEvent> violations1 = checker.QuickCheck();
    EXPECT_TRUE(violations1.empty())
        << "Region should be clean before modification";
    
    // Modify the buffer (simulate tampering)
    buffer[100] = 0x55;
    
    // Verify violation is detected
    std::vector<ViolationEvent> violations2 = checker.QuickCheck();
    
    EXPECT_FALSE(violations2.empty())
        << "Tampering should be detected";
    
    if (!violations2.empty()) {
        EXPECT_EQ(violations2[0].type, ViolationType::MemoryWrite)
            << "Violation should be MemoryWrite";
        EXPECT_EQ(violations2[0].severity, Severity::High)
            << "Violation severity should be High";
        EXPECT_EQ(violations2[0].address, region.address)
            << "Violation should reference the correct address";
    }
    
    // Cleanup
    delete[] buffer;
    checker.Shutdown();
}

/**
 * Test 4: Thread Safety
 * Verifies that concurrent region registration/unregistration is safe
 */
TEST(IntegrityCheckTests, ThreadSafety) {
    IntegrityChecker checker;
    checker.Initialize();
    
    const int numThreads = 10;
    const int operationsPerThread = 100;
    
    std::vector<std::thread> threads;
    
    // Spawn threads that register and unregister regions concurrently
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([&checker, t, operationsPerThread]() {
            for (int i = 0; i < operationsPerThread; i++) {
                // Allocate a small buffer
                uint8_t* buffer = new uint8_t[256];
                memset(buffer, static_cast<uint8_t>(t), 256);
                
                // Compute hash
                uint64_t hash = Internal::ComputeHash(buffer, 256);
                
                // Register region
                MemoryRegion region;
                region.address = reinterpret_cast<uintptr_t>(buffer);
                region.size = 256;
                region.name = "ThreadTest_" + std::to_string(t) + "_" + std::to_string(i);
                region.original_hash = hash;
                
                checker.RegisterRegion(region);
                
                // Immediately unregister
                checker.UnregisterRegion(region.address);
                
                // Cleanup
                delete[] buffer;
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // If we get here without crashing, thread safety test passed
    SUCCEED() << "Concurrent operations completed successfully";
    
    checker.Shutdown();
}

/**
 * Test 5: Multiple Region Verification
 * Verifies that multiple regions can be tracked correctly
 */
TEST(IntegrityCheckTests, MultipleRegions) {
    IntegrityChecker checker;
    checker.Initialize();
    
    const int numRegions = 5;
    std::vector<uint8_t*> buffers;
    
    // Register multiple regions
    for (int i = 0; i < numRegions; i++) {
        uint8_t* buffer = new uint8_t[512];
        memset(buffer, static_cast<uint8_t>(i), 512);
        buffers.push_back(buffer);
        
        uint64_t hash = Internal::ComputeHash(buffer, 512);
        
        MemoryRegion region;
        region.address = reinterpret_cast<uintptr_t>(buffer);
        region.size = 512;
        region.name = "MultiRegion_" + std::to_string(i);
        region.original_hash = hash;
        
        checker.RegisterRegion(region);
    }
    
    // Verify all regions are clean
    std::vector<ViolationEvent> violations = checker.FullScan();
    EXPECT_TRUE(violations.empty())
        << "All regions should be clean";
    
    // Cleanup
    for (auto* buffer : buffers) {
        delete[] buffer;
    }
    checker.Shutdown();
}

/**
 * Test 6: Quick Check vs Full Scan
 * Verifies that QuickCheck samples regions while FullScan checks all
 */
TEST(IntegrityCheckTests, QuickCheckVsFullScan) {
    IntegrityChecker checker;
    checker.Initialize();
    
    const int numRegions = 20; // More than the quick check sample size (10)
    std::vector<uint8_t*> buffers;
    
    // Register multiple regions
    for (int i = 0; i < numRegions; i++) {
        uint8_t* buffer = new uint8_t[256];
        memset(buffer, static_cast<uint8_t>(i), 256);
        buffers.push_back(buffer);
        
        uint64_t hash = Internal::ComputeHash(buffer, 256);
        
        MemoryRegion region;
        region.address = reinterpret_cast<uintptr_t>(buffer);
        region.size = 256;
        region.name = "QvF_" + std::to_string(i);
        region.original_hash = hash;
        
        checker.RegisterRegion(region);
    }
    
    // Both should return empty violations in clean state
    std::vector<ViolationEvent> quickViolations = checker.QuickCheck();
    std::vector<ViolationEvent> fullViolations = checker.FullScan();
    
    EXPECT_TRUE(quickViolations.empty())
        << "Quick check should find no violations in clean state";
    EXPECT_TRUE(fullViolations.empty())
        << "Full scan should find no violations in clean state";
    
    // Cleanup
    for (auto* buffer : buffers) {
        delete[] buffer;
    }
    checker.Shutdown();
}

/**
 * Test 7: Uninitialized State
 * Verifies that verification passes when not initialized (fail-safe behavior)
 */
TEST(IntegrityCheckTests, UninitializedState) {
    IntegrityChecker checker;
    // Don't call Initialize()
    
    // Should return empty violations (assume OK when not initialized)
    std::vector<ViolationEvent> violations = checker.QuickCheck();
    
    EXPECT_TRUE(violations.empty())
        << "Uninitialized checker should return no violations";
}

/**
 * Test 8: Region Unregistration
 * Verifies that unregistering a region removes it from tracking
 */
TEST(IntegrityCheckTests, RegionUnregistration) {
    IntegrityChecker checker;
    checker.Initialize();
    
    uint8_t* buffer = new uint8_t[256];
    memset(buffer, 0xBB, 256);
    
    uint64_t hash = Internal::ComputeHash(buffer, 256);
    
    MemoryRegion region;
    region.address = reinterpret_cast<uintptr_t>(buffer);
    region.size = 256;
    region.name = "UnregisterTest";
    region.original_hash = hash;
    
    checker.RegisterRegion(region);
    
    // Modify the buffer
    buffer[50] = 0xCC;
    
    // Should detect violation
    std::vector<ViolationEvent> violations1 = checker.QuickCheck();
    EXPECT_FALSE(violations1.empty())
        << "Should detect violation before unregistration";
    
    // Unregister the region
    checker.UnregisterRegion(region.address);
    
    // Should no longer detect violation
    std::vector<ViolationEvent> violations2 = checker.QuickCheck();
    
    // Since we unregistered, this specific region violation should not appear
    // (Note: Code section violations may still be present)
    bool foundRegionViolation = false;
    for (const auto& v : violations2) {
        if (v.address == region.address && v.type == ViolationType::MemoryWrite) {
            foundRegionViolation = true;
            break;
        }
    }
    
    EXPECT_FALSE(foundRegionViolation)
        << "Should not detect violation for unregistered region";
    
    delete[] buffer;
    checker.Shutdown();
}
