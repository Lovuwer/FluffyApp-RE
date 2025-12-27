/**
 * Sentinel SDK - Anti-Debug Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/Detection.hpp"

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#endif

using namespace Sentinel::SDK;

/**
 * Test: No debugger detected in CI environment
 * This test verifies that Check() returns an empty vector when no debugger is attached.
 */
TEST(AntiDebugTests, NoDebuggerInCIEnvironment) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    std::vector<ViolationEvent> violations = detector.Check();
    
    // In a non-debugged environment, we should not detect any violations
    EXPECT_TRUE(violations.empty()) 
        << "Detected " << violations.size() << " violations in non-debugged environment";
    
    detector.Shutdown();
}

/**
 * Test: PEB structure access validation
 * This test verifies that we can read the PEB correctly by comparing
 * ImageBaseAddress with GetModuleHandle(NULL).
 */
TEST(AntiDebugTests, PEBStructureAccess) {
#ifdef _WIN32
    // Read PEB
    #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
    #else
        PPEB peb = (PPEB)__readfsdword(0x30);
    #endif
    
    // Verify PEB access is working correctly
    ASSERT_NE(peb, nullptr) << "Failed to read PEB";
    
    // Verify ImageBaseAddress matches GetModuleHandle(NULL)
    void* expectedBase = GetModuleHandle(NULL);
    void* actualBase = peb->ImageBaseAddress;
    
    EXPECT_EQ(expectedBase, actualBase) 
        << "PEB ImageBaseAddress does not match GetModuleHandle(NULL)";
#else
    GTEST_SKIP() << "PEB tests only available on Windows";
#endif
}

/**
 * Test: Individual check methods return bool
 * This test verifies that the Check() method works correctly.
 * Individual check methods are private, so we test the public API.
 */
TEST(AntiDebugTests, CheckMethodReturnsCorrectly) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Check() should return a vector (may be empty in non-debugged environment)
    std::vector<ViolationEvent> violations = detector.Check();
    
    // In CI without debugger, should be empty
    EXPECT_TRUE(violations.empty())
        << "Unexpected violations detected in non-debugged environment";
    
    detector.Shutdown();
}

/**
 * Test: Full check returns same as quick check
 * This test verifies that FullCheck() produces the same results as Check().
 */
TEST(AntiDebugTests, FullCheckEquivalence) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    std::vector<ViolationEvent> quickCheck = detector.Check();
    std::vector<ViolationEvent> fullCheck = detector.FullCheck();
    
    EXPECT_EQ(quickCheck.size(), fullCheck.size())
        << "Quick check and full check returned different numbers of violations";
    
    detector.Shutdown();
}

/**
 * Manual test instructions (not automated):
 * 
 * To manually test with a debugger:
 * 1. Build the test executable in Debug mode
 * 2. Attach a debugger (Visual Studio, WinDbg, x64dbg, etc.)
 * 3. Run this test manually
 * 4. Verify that at least one violation is reported
 * 
 * Expected behavior:
 * - CheckIsDebuggerPresent() should return true
 * - Check() should return at least one ViolationEvent
 * - The violation should have type ViolationType::DebuggerAttached
 * - The violation should have severity Severity::Critical or Severity::High
 */
