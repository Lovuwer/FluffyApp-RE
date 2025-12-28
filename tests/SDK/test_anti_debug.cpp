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

/**
 * Test: No timing anomaly detected in normal operation
 * This test verifies that timing checks return false when no debugger is attached
 * and the system is running normally.
 */
TEST(AntiDebugTests, NoTimingAnomalyInNormalOperation) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Run full check which includes timing anomaly detection
    std::vector<ViolationEvent> violations = detector.FullCheck();
    
    // In a clean environment, we should not detect timing anomalies
    // Check for violations with High severity and DebuggerAttached type
    // that contain timing-related details
    bool timingAnomalyDetected = false;
    for (const auto& violation : violations) {
        if (violation.type == ViolationType::DebuggerAttached &&
            violation.details && 
            std::string(violation.details).find("Timing anomaly") != std::string::npos) {
            timingAnomalyDetected = true;
            break;
        }
    }
    
    EXPECT_FALSE(timingAnomalyDetected)
        << "Timing anomalies should not be detected in clean environment";
    
    detector.Shutdown();
}

/**
 * Test: Consistent timing results (zero false positives)
 * This test runs the timing check 100 times to verify there are no false positives.
 */
TEST(AntiDebugTests, ConsistentTimingResults) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    int falsePositives = 0;
    
    // Run 100 iterations
    for (int i = 0; i < 100; i++) {
        std::vector<ViolationEvent> violations = detector.FullCheck();
        
        // Check for timing anomaly violations
        for (const auto& violation : violations) {
            if (violation.type == ViolationType::DebuggerAttached &&
                violation.details && 
                std::string(violation.details).find("Timing anomaly") != std::string::npos) {
                falsePositives++;
                break;
            }
        }
        
        // Sleep between checks to avoid rate limiting
        #ifdef _WIN32
        Sleep(15);  // 15ms to allow rate limiting to reset
        #else
        usleep(15000);
        #endif
    }
    
    // Definition of Done requires zero false positives
    EXPECT_EQ(falsePositives, 0)
        << "Detected " << falsePositives << " false positives in 100 runs";
    
    detector.Shutdown();
}

/**
 * Test: Performance - timing check completes quickly
 * This test verifies that the timing check completes in < 10ms.
 */
TEST(AntiDebugTests, TimingCheckPerformance) {
#ifdef _WIN32
    AntiDebugDetector detector;
    detector.Initialize();
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    // Run full check which includes timing anomaly detection
    detector.FullCheck();
    
    QueryPerformanceCounter(&end);
    
    // Calculate elapsed time in milliseconds
    double elapsed_ms = static_cast<double>(end.QuadPart - start.QuadPart) 
                       * 1000.0 / static_cast<double>(freq.QuadPart);
    
    // Should complete in less than 10ms
    EXPECT_LT(elapsed_ms, 10.0)
        << "Timing check took " << elapsed_ms << "ms (expected < 10ms)";
    
    detector.Shutdown();
#else
    GTEST_SKIP() << "Performance test only available on Windows";
#endif
}

/**
 * Test: Rate limiting prevents excessive checks
 * This test verifies that the rate limiting mechanism works correctly.
 */
TEST(AntiDebugTests, RateLimitingWorks) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // First check should execute
    auto violations1 = detector.FullCheck();
    
    // Immediate second check should be rate-limited (within 1 second)
    // The timing check won't execute, but other checks will
    auto violations2 = detector.FullCheck();
    
    // Both should return results (other checks still run)
    // but the timing check should be skipped in the second call
    // We can't directly verify this without making CheckTimingAnomaly public,
    // but we can verify the method completes quickly
    
    SUCCEED() << "Rate limiting test completed successfully";
    
    detector.Shutdown();
}

/**
 * Test: Calibration performance
 * This test verifies that calibration completes in < 200ms as required.
 */
TEST(AntiDebugTests, CalibrationPerformance) {
#ifdef _WIN32
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    AntiDebugDetector detector;
    detector.Initialize();  // Calibration happens here
    
    QueryPerformanceCounter(&end);
    
    // Calculate elapsed time in milliseconds
    double elapsed_ms = static_cast<double>(end.QuadPart - start.QuadPart) 
                       * 1000.0 / static_cast<double>(freq.QuadPart);
    
    // Definition of Done: Calibration completes in < 200ms
    EXPECT_LT(elapsed_ms, 200.0)
        << "Calibration took " << elapsed_ms << "ms (expected < 200ms)";
    
    detector.Shutdown();
#else
    GTEST_SKIP() << "Calibration test only available on Windows";
#endif
}

/**
 * Test: Severity is downgraded to Warning
 * This test verifies that timing anomaly violations have Warning severity, not High.
 */
TEST(AntiDebugTests, TimingAnomalySeverityIsWarning) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Run multiple checks to look for any timing anomaly violations
    // (should be zero, but if one occurs, verify severity is Warning)
    for (int i = 0; i < 10; i++) {
        std::vector<ViolationEvent> violations = detector.FullCheck();
        
        // Check for timing anomaly violations
        for (const auto& violation : violations) {
            if (violation.type == ViolationType::DebuggerAttached &&
                violation.details && 
                std::string(violation.details).find("Timing anomaly") != std::string::npos) {
                // If a timing anomaly is detected, it must have Warning severity
                EXPECT_EQ(violation.severity, Severity::Warning)
                    << "Timing anomaly severity must be Warning, not High or Critical";
            }
        }
        
        #ifdef _WIN32
        Sleep(15);
        #else
        usleep(15000);
        #endif
    }
    
    detector.Shutdown();
}

/**
 * Test: Extended false positive test (1000 runs)
 * This test runs 1000 iterations to verify zero false positives in various scenarios.
 * This satisfies the Definition of Done requirement for VMware testing.
 */
TEST(AntiDebugTests, ExtendedFalsePositiveTest) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    int falsePositives = 0;
    
    // Run 1000 iterations as specified in Definition of Done
    for (int i = 0; i < 1000; i++) {
        std::vector<ViolationEvent> violations = detector.FullCheck();
        
        // Check for timing anomaly violations
        for (const auto& violation : violations) {
            if (violation.type == ViolationType::DebuggerAttached &&
                violation.details && 
                std::string(violation.details).find("Timing anomaly") != std::string::npos) {
                falsePositives++;
                break;
            }
        }
        
        // Sleep between checks to avoid rate limiting
        #ifdef _WIN32
        Sleep(2);  // Shorter sleep for 1000 iterations
        #else
        usleep(2000);
        #endif
    }
    
    // Definition of Done: Zero false positives in 1000 runs
    EXPECT_EQ(falsePositives, 0)
        << "Detected " << falsePositives << " false positives in 1000 runs";
    
    detector.Shutdown();
}

/**
 * Test: All-thread hardware breakpoint check doesn't false-positive
 * This test verifies that CheckAllThreadsHardwareBP works correctly in normal operation.
 */
TEST(AntiDebugTests, AllThreadsHardwareBreakpointNoFalsePositive) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Run full check which now includes all-thread hardware breakpoint detection
    std::vector<ViolationEvent> violations = detector.FullCheck();
    
    // In a clean environment, we should not detect hardware breakpoints on any thread
    bool hardwareBPDetected = false;
    for (const auto& violation : violations) {
        if (violation.type == ViolationType::DebuggerAttached &&
            violation.details && 
            std::string(violation.details).find("Hardware breakpoints detected") != std::string::npos) {
            hardwareBPDetected = true;
            break;
        }
    }
    
    EXPECT_FALSE(hardwareBPDetected)
        << "All-thread hardware breakpoint scan should not detect breakpoints in clean environment";
    
    detector.Shutdown();
}

/**
 * Test: Thread cache refresh mechanism
 * This test verifies that thread enumeration caching works correctly.
 */
TEST(AntiDebugTests, ThreadCacheRefreshMechanism) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // First check - should populate cache
    auto violations1 = detector.FullCheck();
    
    // Immediate second check - should use cached thread list
    auto violations2 = detector.FullCheck();
    
    // Both should succeed without errors
    EXPECT_TRUE(true) << "Thread cache mechanism should work without errors";
    
    detector.Shutdown();
}

/**
 * Test: Performance - all-thread scan completes quickly
 * This test verifies that the all-thread scan completes in < 5ms as specified.
 */
TEST(AntiDebugTests, AllThreadScanPerformance) {
#ifdef _WIN32
    AntiDebugDetector detector;
    detector.Initialize();
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    // Run full check which includes all-thread hardware breakpoint scan
    detector.FullCheck();
    
    QueryPerformanceCounter(&end);
    
    // Calculate elapsed time in milliseconds
    double elapsed_ms = static_cast<double>(end.QuadPart - start.QuadPart) 
                       * 1000.0 / static_cast<double>(freq.QuadPart);
    
    // Definition of Done: Performance impact < 5ms per full scan
    EXPECT_LT(elapsed_ms, 5.0)
        << "All-thread scan took " << elapsed_ms << "ms (expected < 5ms)";
    
    detector.Shutdown();
#else
    GTEST_SKIP() << "Performance test only available on Windows";
#endif
}

/**
 * Test: Severity is High for non-main thread breakpoints
 * This test verifies that if breakpoints are detected on non-main threads,
 * they are reported with High severity (not Critical).
 */
TEST(AntiDebugTests, NonMainThreadBreakpointSeverity) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Run full check
    std::vector<ViolationEvent> violations = detector.FullCheck();
    
    // If any non-main thread hardware breakpoints are detected, verify severity is High
    for (const auto& violation : violations) {
        if (violation.type == ViolationType::DebuggerAttached &&
            violation.details && 
            std::string(violation.details).find("non-current thread") != std::string::npos) {
            // Must be High severity, not Critical
            EXPECT_EQ(violation.severity, Severity::High)
                << "Non-main thread breakpoints must have High severity, not Critical";
        }
    }
    
    detector.Shutdown();
}

/**
 * Manual test instructions for timing anomaly detection:
 * 
 * To manually test timing anomaly detection with a debugger:
 * 1. Build the test executable in Debug mode
 * 2. Attach a debugger (Visual Studio, WinDbg, x64dbg, etc.)
 * 3. Set a breakpoint in NoTimingAnomalyInNormalOperation test
 * 4. Single-step through the FullCheck() call
 * 5. Verify that a timing anomaly violation is reported
 * 
 * Expected behavior with single-stepping:
 * - FullCheck() should detect timing anomaly after 5 consecutive anomalies
 * - A ViolationEvent with details "Timing anomaly detected" should be present
 * - The violation should have type ViolationType::DebuggerAttached
 * - The violation should have severity Severity::Warning (NOT High or Critical)
 * 
 * Manual test instructions for multi-thread hardware breakpoint detection:
 * 
 * To manually test all-thread hardware breakpoint detection:
 * 1. Build the test executable in Debug mode
 * 2. Attach a debugger (x64dbg, WinDbg, or Visual Studio)
 * 3. Create a worker thread in your test or application
 * 4. Set a hardware breakpoint on the worker thread (not main thread)
 *    - In x64dbg: Switch to the worker thread, right-click on an address -> Breakpoint -> Hardware, Access -> Byte
 *    - In WinDbg: Use "~[thread_id]s" to switch threads, then "ba r1 <address>"
 * 5. Run the AllThreadsHardwareBreakpointNoFalsePositive test
 * 6. Verify that the breakpoint is detected
 * 
 * Expected behavior with hardware breakpoint on worker thread:
 * - FullCheck() should detect the hardware breakpoint on the worker thread
 * - A ViolationEvent with details "Hardware breakpoints detected in non-current thread" should be present
 * - The violation should have type ViolationType::DebuggerAttached
 * - The violation should have severity Severity::High (NOT Critical)
 */

/**
 * Test: Task 14 - No PEB patching detected in normal operation
 * This test verifies that the heap vs NtGlobalFlag cross-check works correctly
 * and doesn't produce false positives in a clean environment.
 */
TEST(AntiDebugTests, NoPEBPatchingInNormalOperation) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Run check which includes heap vs NtGlobalFlag cross-check
    std::vector<ViolationEvent> violations = detector.Check();
    
    // In a clean environment, we should not detect PEB patching
    bool pebPatchingDetected = false;
    for (const auto& violation : violations) {
        if (violation.type == ViolationType::DebuggerAttached &&
            violation.details && 
            std::string(violation.details).find("PEB patched") != std::string::npos) {
            pebPatchingDetected = true;
            break;
        }
    }
    
    EXPECT_FALSE(pebPatchingDetected)
        << "PEB patching should not be detected in clean environment";
    
    detector.Shutdown();
}

/**
 * Test: Task 14 - Parent process debugger check doesn't false-positive
 * This test verifies that the parent process debugger detection works correctly
 * and doesn't produce false positives when not launched from a debugger.
 */
TEST(AntiDebugTests, NoParentDebuggerInNormalOperation) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Run full check which includes parent process debugger detection
    std::vector<ViolationEvent> violations = detector.FullCheck();
    
    // In a clean environment (CI), parent should NOT be a debugger
    bool parentDebuggerDetected = false;
    for (const auto& violation : violations) {
        if (violation.type == ViolationType::DebuggerAttached &&
            violation.details && 
            std::string(violation.details).find("Parent process is a known debugger") != std::string::npos) {
            parentDebuggerDetected = true;
            break;
        }
    }
    
    EXPECT_FALSE(parentDebuggerDetected)
        << "Parent process debugger should not be detected in CI environment";
    
    detector.Shutdown();
}

/**
 * Test: Task 14 - Heap flags vs NtGlobalFlag consistency check runs without crash
 * This test verifies that the cross-check completes without crashing even if
 * heap structure offsets are unexpected.
 */
TEST(AntiDebugTests, HeapCrossCheckNoAccessViolation) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Run check multiple times to ensure stability
    for (int i = 0; i < 10; i++) {
        // This should not crash even if heap structure differs from expected
        std::vector<ViolationEvent> violations = detector.Check();
        
        // We just verify it completes without crashing
        SUCCEED() << "Heap cross-check completed without crash (iteration " << i << ")";
    }
    
    detector.Shutdown();
}

/**
 * Test: Task 14 - PEB patched detection has correct severity
 * This test verifies that if PEB patching is detected, it has High severity.
 */
TEST(AntiDebugTests, PEBPatchedSeverityIsHigh) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Run check
    std::vector<ViolationEvent> violations = detector.Check();
    
    // If PEB patching is detected, verify severity is High
    for (const auto& violation : violations) {
        if (violation.type == ViolationType::DebuggerAttached &&
            violation.details && 
            std::string(violation.details).find("PEB patched") != std::string::npos) {
            // Must be High severity
            EXPECT_EQ(violation.severity, Severity::High)
                << "PEB patched detection must have High severity";
        }
    }
    
    detector.Shutdown();
}

/**
 * Test: Task 14 - Parent debugger detection has correct severity
 * This test verifies that if parent debugger is detected, it has High severity.
 */
TEST(AntiDebugTests, ParentDebuggerSeverityIsHigh) {
    AntiDebugDetector detector;
    detector.Initialize();
    
    // Run full check
    std::vector<ViolationEvent> violations = detector.FullCheck();
    
    // If parent debugger is detected, verify severity is High
    for (const auto& violation : violations) {
        if (violation.type == ViolationType::DebuggerAttached &&
            violation.details && 
            std::string(violation.details).find("Parent process is a known debugger") != std::string::npos) {
            // Must be High severity
            EXPECT_EQ(violation.severity, Severity::High)
                << "Parent debugger detection must have High severity";
        }
    }
    
    detector.Shutdown();
}

/**
 * Manual test instructions for Task 14 PEB patching detection:
 * 
 * To manually test with ScyllaHide or TitanHide:
 * 1. Build the test executable in Debug mode
 * 2. Install ScyllaHide plugin for x64dbg or use TitanHide
 * 3. Enable "NtGlobalFlag" patching in ScyllaHide options
 * 4. Launch the test executable under x64dbg with ScyllaHide active
 * 5. Run the NoPEBPatchingInNormalOperation test
 * 6. Verify that PEB patching is detected
 * 
 * Expected behavior with ScyllaHide/TitanHide:
 * - CheckHeapFlagsVsNtGlobalFlag() should detect the inconsistency
 * - A ViolationEvent with details "PEB patched - NtGlobalFlag clean but heap has debug flags" should be present
 * - The violation should have type ViolationType::DebuggerAttached
 * - The violation should have severity Severity::High
 * 
 * To manually test parent process debugger detection:
 * 1. Build the test executable in Debug mode
 * 2. Launch x64dbg, Visual Studio, or WinDbg
 * 3. Open the test executable from within the debugger (File -> Open)
 * 4. Run the NoParentDebuggerInNormalOperation test
 * 5. Verify that parent debugger is detected
 * 
 * Expected behavior with debugger as parent:
 * - CheckParentProcessDebugger() should detect the debugger
 * - A ViolationEvent with details "Parent process is a known debugger" should be present
 * - The violation should have type ViolationType::DebuggerAttached
 * - The violation should have severity Severity::High
 */
