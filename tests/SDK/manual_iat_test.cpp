/**
 * Sentinel SDK - Manual IAT Integrity Test
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * TASK-08: Manual test for IAT integrity verification
 * 
 * This program demonstrates:
 * 1. Normal execution with no IAT modifications (should pass)
 * 2. Simulated IAT hook detection (manual modification required)
 * 
 * Instructions for manual testing:
 * 1. Compile and run on Windows
 * 2. Observe clean state (no violations)
 * 3. Use a debugger or memory editor to modify an IAT entry
 * 4. Press Enter to run the check again
 * 5. Verify that the IAT modification is detected
 */

#include "Internal/Detection.hpp"
#include "Internal/Context.hpp"
#include <iostream>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace Sentinel::SDK;

void PrintViolations(const std::vector<ViolationEvent>& violations) {
    if (violations.empty()) {
        std::cout << "  [OK] No violations detected." << std::endl;
        return;
    }
    
    std::cout << "  [ALERT] " << violations.size() << " violation(s) detected:" << std::endl;
    for (const auto& v : violations) {
        std::cout << "    - Type: ";
        switch (v.type) {
            case ViolationType::IATHook:
                std::cout << "IATHook";
                break;
            case ViolationType::ModuleModified:
                std::cout << "ModuleModified";
                break;
            case ViolationType::MemoryWrite:
                std::cout << "MemoryWrite";
                break;
            default:
                std::cout << "Other (" << static_cast<uint32_t>(v.type) << ")";
                break;
        }
        std::cout << " | Severity: ";
        switch (v.severity) {
            case Severity::Critical:
                std::cout << "Critical";
                break;
            case Severity::High:
                std::cout << "High";
                break;
            case Severity::Warning:
                std::cout << "Warning";
                break;
            case Severity::Info:
                std::cout << "Info";
                break;
        }
        std::cout << " | Details: " << v.details << std::endl;
    }
}

int main() {
    std::cout << "==================================================" << std::endl;
    std::cout << "  Sentinel SDK - IAT Integrity Manual Test" << std::endl;
    std::cout << "  TASK-08: IAT Modification Detection" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << std::endl;
    
#ifdef _WIN32
    // Initialize the integrity checker
    std::cout << "Initializing IntegrityChecker..." << std::endl;
    IntegrityChecker checker;
    checker.Initialize();
    std::cout << "  [OK] Initialized." << std::endl;
    std::cout << std::endl;
    
    // Run initial scan
    std::cout << "Running initial QuickCheck (clean state)..." << std::endl;
    auto violations = checker.QuickCheck();
    PrintViolations(violations);
    std::cout << std::endl;
    
    // Run FullScan
    std::cout << "Running initial FullScan (clean state)..." << std::endl;
    violations = checker.FullScan();
    PrintViolations(violations);
    std::cout << std::endl;
    
    // Instructions for manual testing
    std::cout << "==================================================" << std::endl;
    std::cout << "  Manual Testing Instructions:" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "1. Attach a debugger to this process" << std::endl;
    std::cout << "2. Locate the IAT in memory (use Process Explorer or similar)" << std::endl;
    std::cout << "3. Find an imported function (e.g., GetProcAddress)" << std::endl;
    std::cout << "4. Modify the IAT entry to point to a different address" << std::endl;
    std::cout << "5. Press Enter to run the detection check" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Press Enter to run detection check...";
    std::cin.get();
    std::cout << std::endl;
    
    // Run check after potential modification
    std::cout << "Running QuickCheck after potential modification..." << std::endl;
    violations = checker.QuickCheck();
    PrintViolations(violations);
    std::cout << std::endl;
    
    std::cout << "Running FullScan after potential modification..." << std::endl;
    violations = checker.FullScan();
    PrintViolations(violations);
    std::cout << std::endl;
    
    // Continuous monitoring
    std::cout << "==================================================" << std::endl;
    std::cout << "  Continuous Monitoring (press Ctrl+C to stop)" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << std::endl;
    
    int iteration = 1;
    while (true) {
        std::cout << "Iteration " << iteration << ": ";
        violations = checker.QuickCheck();
        
        bool hasIATViolation = false;
        for (const auto& v : violations) {
            if (v.type == ViolationType::IATHook) {
                hasIATViolation = true;
                break;
            }
        }
        
        if (hasIATViolation) {
            std::cout << "[DETECTED] IAT Hook!" << std::endl;
        } else {
            std::cout << "[OK] Clean" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        iteration++;
    }
    
    checker.Shutdown();
#else
    std::cout << "This test is only supported on Windows." << std::endl;
    return 1;
#endif
    
    return 0;
}
