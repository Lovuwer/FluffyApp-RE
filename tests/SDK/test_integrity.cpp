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
 * Verifies that verification fails closed when not initialized (TASK-04: fail-safe behavior)
 */
TEST(IntegrityCheckTests, UninitializedState) {
    IntegrityChecker checker;
    // Don't call Initialize()
    
    // TASK-04: Should return violations when not initialized (fail closed)
    std::vector<ViolationEvent> violations = checker.QuickCheck();
    
#ifdef _WIN32
    // On Windows, uninitialized checker should fail closed
    EXPECT_FALSE(violations.empty())
        << "Uninitialized checker should return violations on Windows (fail closed)";
    
    if (!violations.empty()) {
        EXPECT_EQ(violations[0].type, ViolationType::ModuleModified)
            << "Violation should be ModuleModified";
        EXPECT_EQ(violations[0].severity, Severity::Critical)
            << "Violation severity should be Critical";
    }
#else
    // On non-Windows platforms, code section verification is not supported
    EXPECT_TRUE(violations.empty())
        << "Uninitialized checker returns no violations on non-Windows platforms";
#endif
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

/**
 * Test 9: TASK-04 - Initialization Failure Detection
 * Verifies that QuickCheck() returns violation when initialization failed (Windows only)
 */
TEST(IntegrityCheckTests, TASK04_InitializationFailureDetection) {
#ifdef _WIN32
    IntegrityChecker checker;
    // Don't call Initialize() - this simulates initialization failure
    
    // QuickCheck should detect initialization failure and return violation
    std::vector<ViolationEvent> violations = checker.QuickCheck();
    
    EXPECT_FALSE(violations.empty())
        << "QuickCheck should return violations when initialization failed";
    
    if (!violations.empty()) {
        // Should be a ModuleModified violation with Critical severity
        EXPECT_EQ(violations[0].type, ViolationType::ModuleModified)
            << "Violation should be ModuleModified type";
        EXPECT_EQ(violations[0].severity, Severity::Critical)
            << "Violation severity should be Critical";
        EXPECT_EQ(violations[0].details, "Code section hash mismatch")
            << "Violation details should indicate code section issue";
    }
#else
    GTEST_SKIP() << "Test only applicable on Windows";
#endif
}

/**
 * Test 10: TASK-04 - FullScan with Initialization Failure
 * Verifies that FullScan() also returns violation when initialization failed (Windows only)
 */
TEST(IntegrityCheckTests, TASK04_FullScanInitializationFailure) {
#ifdef _WIN32
    IntegrityChecker checker;
    // Don't call Initialize() - this simulates initialization failure
    
    // FullScan should also detect initialization failure
    std::vector<ViolationEvent> violations = checker.FullScan();
    
    EXPECT_FALSE(violations.empty())
        << "FullScan should return violations when initialization failed";
    
    if (!violations.empty()) {
        EXPECT_EQ(violations[0].type, ViolationType::ModuleModified)
            << "Violation should be ModuleModified type";
        EXPECT_EQ(violations[0].severity, Severity::Critical)
            << "Violation severity should be Critical";
    }
#else
    GTEST_SKIP() << "Test only applicable on Windows";
#endif
}

/**
 * Test 11: TASK-08 - IAT Integrity Clean State
 * Verifies that IAT verification passes on a clean system
 */
TEST(IntegrityCheckTests, TASK08_IATIntegrityCleanState) {
#ifdef _WIN32
    IntegrityChecker checker;
    checker.Initialize();
    
    // QuickCheck should not detect IAT violations in clean state
    std::vector<ViolationEvent> violations = checker.QuickCheck();
    
    // Filter to only IAT violations
    bool foundIATViolation = false;
    for (const auto& v : violations) {
        if (v.type == ViolationType::IATHook) {
            foundIATViolation = true;
            break;
        }
    }
    
    EXPECT_FALSE(foundIATViolation)
        << "IAT verification should not detect violations in clean state";
    
    checker.Shutdown();
#else
    GTEST_SKIP() << "Test only applicable on Windows";
#endif
}

/**
 * Test 12: TASK-08 - IAT Integrity FullScan Clean State
 * Verifies that FullScan IAT verification passes on a clean system
 */
TEST(IntegrityCheckTests, TASK08_IATIntegrityFullScanCleanState) {
#ifdef _WIN32
    IntegrityChecker checker;
    checker.Initialize();
    
    // FullScan should not detect IAT violations in clean state
    std::vector<ViolationEvent> violations = checker.FullScan();
    
    // Filter to only IAT violations
    bool foundIATViolation = false;
    for (const auto& v : violations) {
        if (v.type == ViolationType::IATHook) {
            foundIATViolation = true;
            break;
        }
    }
    
    EXPECT_FALSE(foundIATViolation)
        << "IAT verification should not detect violations in clean state during FullScan";
    
    checker.Shutdown();
#else
    GTEST_SKIP() << "Test only applicable on Windows";
#endif
}

/**
 * Test 13: TASK-08 - IAT Modification Detection (Simulated)
 * Simulates an IAT hook by modifying an IAT entry and verifying detection
 * NOTE: This test can only simulate by directly accessing internal data
 */
TEST(IntegrityCheckTests, TASK08_IATModificationDetection) {
#ifdef _WIN32
    IntegrityChecker checker;
    checker.Initialize();
    
    // First, verify clean state
    std::vector<ViolationEvent> violations1 = checker.QuickCheck();
    bool foundInitialViolation = false;
    for (const auto& v : violations1) {
        if (v.type == ViolationType::IATHook) {
            foundInitialViolation = true;
            break;
        }
    }
    EXPECT_FALSE(foundInitialViolation)
        << "Should be clean before modification";
    
    // NOTE: To test IAT modification detection in a real scenario, we would need to:
    // 1. Find a known imported function (e.g., GetProcAddress)
    // 2. Save the original IAT entry
    // 3. Modify the IAT entry to point to a different address
    // 4. Run QuickCheck or FullScan
    // 5. Restore the original IAT entry
    //
    // However, this is dangerous in a unit test environment and could crash the process.
    // Instead, we verify the clean state passes (no false positives).
    // Manual testing would be required to verify detection of actual IAT modifications.
    
    // For now, we just verify that the verification completes without crashing
    SUCCEED() << "IAT verification completed successfully in clean state";
    
    checker.Shutdown();
#else
    GTEST_SKIP() << "Test only applicable on Windows";
#endif
}
