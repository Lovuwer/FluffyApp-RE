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
    
    // FullCheck includes additional checks (hardware BP, debug port)
    // So it should have >= violations compared to quick check
    EXPECT_GE(fullCheck.size(), quickCheck.size())
        << "Full check should include at least as many violations as quick check";
    
    detector.Shutdown();
}

/**
 * Test: Hardware breakpoint detection returns false without debugger
 * This test verifies that hardware breakpoint detection returns false
 * when no debugger is attached and no hardware breakpoints are set.
 */
TEST(AntiDebugTests, NoHardwareBreakpointsDetected) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Run full check which includes hardware breakpoint detection
    std::vector<ViolationEvent> violations = detector.FullCheck();
    
    // In a clean environment, we should not detect hardware breakpoints
    // Check for violations with Critical severity and DebuggerAttached type
    // that contain hardware breakpoint-related details
    bool hardwareBPDetected = false;
    for (const auto& violation : violations) {
        if (violation.type == ViolationType::DebuggerAttached &&
            violation.severity == Severity::Critical &&
            violation.details && 
            std::string(violation.details).find("Hardware breakpoints") != std::string::npos) {
            hardwareBPDetected = true;
            break;
        }
    }
    
    EXPECT_FALSE(hardwareBPDetected)
        << "Hardware breakpoints should not be detected in clean environment";
    
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
 * 
 * To manually test hardware breakpoint detection:
 * 1. Build the test executable in Debug mode
 * 2. Attach a debugger (x64dbg, WinDbg, or Visual Studio)
 * 3. Set a hardware breakpoint on any memory address or register
 *    - In x64dbg: Right-click on an address -> Breakpoint -> Hardware, Access -> Byte
 *    - In WinDbg: Use "ba" command (e.g., "ba r1 <address>")
 *    - In Visual Studio: Debug -> New Breakpoint -> Data Breakpoint
 * 4. Run the NoHardwareBreakpointsDetected test
 * 5. Verify that the test detects the hardware breakpoint and reports a violation
 * 
 * Expected behavior with hardware breakpoint:
 * - FullCheck() should detect hardware breakpoint
 * - A ViolationEvent with details "Hardware breakpoints detected in debug registers" should be present
 * - The violation should have type ViolationType::DebuggerAttached
 * - The violation should have severity Severity::Critical
 */
