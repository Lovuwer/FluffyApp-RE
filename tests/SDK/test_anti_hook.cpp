/**
 * Sentinel SDK - Anti-Hook Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 11: Tests for Inline Hook Detection
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
 * Dummy function for testing
 */
static void DummyFunction1() {
    // Simple function that can be hooked
    volatile int x = 42;
    (void)x;
}

static void DummyFunction2() {
    // Another simple function
    volatile int y = 100;
    (void)y;
}

/**
 * Test 1: Clean Function
 * Verifies that CheckFunction() returns false for a clean function
 */
TEST(AntiHookTests, CleanFunction) {
    AntiHookDetector detector;
    detector.Initialize();
    
    // Get the address of a clean function from our module
    uintptr_t funcAddr = reinterpret_cast<uintptr_t>(&DummyFunction1);
    
    // Read original bytes
    FunctionProtection func;
    func.address = funcAddr;
    func.name = "DummyFunction1";
    func.prologue_size = 16;
    memcpy(func.original_prologue.data(), 
           reinterpret_cast<const void*>(funcAddr), 
           func.prologue_size);
    
    // Register the function
    detector.RegisterFunction(func);
    
    // Check should return false (not hooked)
    bool isHooked = detector.CheckFunction(funcAddr);
    
    EXPECT_FALSE(isHooked)
        << "Clean function should not be detected as hooked";
    
    detector.Shutdown();
}

/**
 * Test 2: Pattern Matching
 * Verifies that hook patterns are detected correctly
 */
TEST(AntiHookTests, PatternMatching) {
    AntiHookDetector detector;
    detector.Initialize();
    
    // Test JMP rel32 pattern (E9 XX XX XX XX)
    {
        uint8_t jmpPattern[16] = {0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 
                                   0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        
        FunctionProtection func;
        func.address = reinterpret_cast<uintptr_t>(jmpPattern);
        func.name = "JmpPattern";
        func.prologue_size = 16;
        memset(func.original_prologue.data(), 0x90, 16); // Original was NOPs
        
        detector.RegisterFunction(func);
        
        bool isHooked = detector.CheckFunction(func.address);
        EXPECT_TRUE(isHooked)
            << "JMP rel32 pattern should be detected";
        
        detector.UnregisterFunction(func.address);
    }
    
    // Test INT 3 pattern (CC)
    {
        uint8_t int3Pattern[16] = {0xCC, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        
        FunctionProtection func;
        func.address = reinterpret_cast<uintptr_t>(int3Pattern);
        func.name = "Int3Pattern";
        func.prologue_size = 16;
        memset(func.original_prologue.data(), 0x90, 16); // Original was NOPs
        
        detector.RegisterFunction(func);
        
        bool isHooked = detector.CheckFunction(func.address);
        EXPECT_TRUE(isHooked)
            << "INT 3 pattern should be detected";
        
        detector.UnregisterFunction(func.address);
    }
    
    // Test MOV RAX, imm64; JMP RAX pattern
    {
        uint8_t movJmpPattern[16] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                      0x00, 0x00, 0xFF, 0xE0, 0x90, 0x90, 0x90, 0x90};
        
        FunctionProtection func;
        func.address = reinterpret_cast<uintptr_t>(movJmpPattern);
        func.name = "MovJmpPattern";
        func.prologue_size = 16;
        memset(func.original_prologue.data(), 0x90, 16); // Original was NOPs
        
        detector.RegisterFunction(func);
        
        bool isHooked = detector.CheckFunction(func.address);
        EXPECT_TRUE(isHooked)
            << "MOV RAX, imm64; JMP RAX pattern should be detected";
        
        detector.UnregisterFunction(func.address);
    }
    
    detector.Shutdown();
}

/**
 * Test 3: Registration/Unregistration
 * Verifies that functions can be registered and unregistered correctly
 */
TEST(AntiHookTests, RegistrationUnregistration) {
    AntiHookDetector detector;
    detector.Initialize();
    
    std::vector<FunctionProtection> functions;
    
    // Register 100 functions
    for (int i = 0; i < 100; i++) {
        FunctionProtection func;
        func.address = 0x1000 + (i * 0x100);  // Dummy addresses
        func.name = "Function_" + std::to_string(i);
        func.prologue_size = 16;
        memset(func.original_prologue.data(), 0x90, 16);
        
        functions.push_back(func);
        detector.RegisterFunction(func);
    }
    
    // Unregister 50 functions (every other one)
    for (int i = 0; i < 100; i += 2) {
        detector.UnregisterFunction(functions[i].address);
    }
    
    // FullScan should check remaining 50 functions
    // Since they all have NOP patterns and we're checking against the same pattern,
    // they shouldn't be detected as hooked
    std::vector<ViolationEvent> violations = detector.FullScan();
    
    // All should be clean (same bytes as original)
    EXPECT_TRUE(violations.empty())
        << "Remaining registered functions should not be hooked";
    
    detector.Shutdown();
}

/**
 * Test 4: Thread Safety
 * Verifies that concurrent registration/checking from multiple threads is safe
 */
TEST(AntiHookTests, ThreadSafety) {
    AntiHookDetector detector;
    detector.Initialize();
    
    const int numThreads = 10;
    const int operationsPerThread = 100;
    
    std::vector<std::thread> threads;
    
    // Spawn threads that register and check concurrently
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([&detector, t, operationsPerThread]() {
            for (int i = 0; i < operationsPerThread; i++) {
                FunctionProtection func;
                func.address = 0x10000 + (t * 10000) + (i * 100);
                func.name = "ThreadFunc_" + std::to_string(t) + "_" + std::to_string(i);
                func.prologue_size = 16;
                memset(func.original_prologue.data(), 0x55, 16);
                
                detector.RegisterFunction(func);
                
                // Try to check the function
                detector.CheckFunction(func.address);
                
                // Unregister
                detector.UnregisterFunction(func.address);
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // If we get here without crashing, thread safety test passed
    SUCCEED() << "Concurrent operations completed successfully";
    
    detector.Shutdown();
}

/**
 * Test 5: QuickCheck vs FullScan
 * Verifies that QuickCheck samples while FullScan checks all
 */
TEST(AntiHookTests, QuickCheckVsFullScan) {
    AntiHookDetector detector;
    detector.Initialize();
    
    // Register 20 functions (more than QuickCheck sample size of 10)
    for (int i = 0; i < 20; i++) {
        FunctionProtection func;
        func.address = 0x20000 + (i * 0x100);
        func.name = "ScanFunc_" + std::to_string(i);
        func.prologue_size = 16;
        memset(func.original_prologue.data(), 0x90, 16);
        
        detector.RegisterFunction(func);
    }
    
    // Both should return empty in clean state
    std::vector<ViolationEvent> quickViolations = detector.QuickCheck();
    std::vector<ViolationEvent> fullViolations = detector.FullScan();
    
    EXPECT_TRUE(quickViolations.empty())
        << "Quick check should find no violations in clean state";
    EXPECT_TRUE(fullViolations.empty())
        << "Full scan should find no violations in clean state";
    
    detector.Shutdown();
}

/**
 * Test 6: HasSuspiciousJump
 * Verifies that suspicious jump instructions are detected
 */
TEST(AntiHookTests, SuspiciousJump) {
    AntiHookDetector detector;
    detector.Initialize();
    
    // Test various suspicious patterns
    {
        uint8_t jmpRel32[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
        bool isSuspicious = detector.HasSuspiciousJump(jmpRel32);
        EXPECT_TRUE(isSuspicious) << "JMP rel32 should be suspicious";
    }
    
    {
        uint8_t callRel32[5] = {0xE8, 0x00, 0x00, 0x00, 0x00};
        bool isSuspicious = detector.HasSuspiciousJump(callRel32);
        EXPECT_TRUE(isSuspicious) << "CALL rel32 should be suspicious";
    }
    
    {
        uint8_t int3[1] = {0xCC};
        bool isSuspicious = detector.HasSuspiciousJump(int3);
        EXPECT_TRUE(isSuspicious) << "INT 3 should be suspicious";
    }
    
    {
        uint8_t movRax[2] = {0x48, 0xB8};
        bool isSuspicious = detector.HasSuspiciousJump(movRax);
        EXPECT_TRUE(isSuspicious) << "MOV RAX, imm64 should be suspicious";
    }
    
    // Test normal prologue
    {
        uint8_t normalPrologue[5] = {0x55, 0x48, 0x89, 0xE5, 0x53};  // push rbp; mov rbp, rsp; push rbx
        bool isSuspicious = detector.HasSuspiciousJump(normalPrologue);
        EXPECT_FALSE(isSuspicious) << "Normal prologue should not be suspicious";
    }
    
    detector.Shutdown();
}

/**
 * Test 7: Modified Bytes Detection
 * Verifies that any modification to function prologue is detected
 */
TEST(AntiHookTests, ModifiedBytesDetection) {
    AntiHookDetector detector;
    detector.Initialize();
    
    // Create a writable buffer to simulate a function
    uint8_t buffer[32];
    memset(buffer, 0x90, 32);  // Fill with NOPs
    
    FunctionProtection func;
    func.address = reinterpret_cast<uintptr_t>(buffer);
    func.name = "ModifiedFunction";
    func.prologue_size = 16;
    memcpy(func.original_prologue.data(), buffer, 16);
    
    detector.RegisterFunction(func);
    
    // Verify it's clean
    EXPECT_FALSE(detector.CheckFunction(func.address))
        << "Function should be clean initially";
    
    // Modify the buffer (simulate tampering)
    buffer[0] = 0xE9;  // Change to JMP
    
    // Now it should be detected
    EXPECT_TRUE(detector.CheckFunction(func.address))
        << "Modified function should be detected";
    
    detector.Shutdown();
}

/**
 * Test 8: Multiple Patterns Detection
 * Verifies detection of different hook patterns
 */
TEST(AntiHookTests, MultiplePatterns) {
    AntiHookDetector detector;
    detector.Initialize();
    
    struct PatternTest {
        std::vector<uint8_t> bytes;
        const char* name;
    };
    
    std::vector<PatternTest> patterns = {
        {{0xE9, 0x00, 0x00, 0x00, 0x00}, "JMP rel32"},
        {{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}, "JMP [rip+0]"},
        {{0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0}, "MOV RAX; JMP RAX"},
        {{0x68, 0x00, 0x00, 0x00, 0x00, 0xC3}, "PUSH; RET"},
        {{0xCC}, "INT 3"},
    };
    
    for (const auto& pattern : patterns) {
        uint8_t buffer[32];
        memset(buffer, 0x90, 32);
        
        // Copy pattern to buffer
        memcpy(buffer, pattern.bytes.data(), pattern.bytes.size());
        
        FunctionProtection func;
        func.address = reinterpret_cast<uintptr_t>(buffer);
        func.name = std::string("Pattern_") + pattern.name;
        func.prologue_size = 16;
        memset(func.original_prologue.data(), 0x90, 16);  // Original was all NOPs
        
        detector.RegisterFunction(func);
        
        bool isHooked = detector.CheckFunction(func.address);
        EXPECT_TRUE(isHooked)
            << "Pattern " << pattern.name << " should be detected";
        
        detector.UnregisterFunction(func.address);
    }
    
    detector.Shutdown();
}

/**
 * Test 9: Unregistered Function Check
 * Verifies that checking an unregistered function uses HasSuspiciousJump
 */
TEST(AntiHookTests, UnregisteredFunctionCheck) {
    AntiHookDetector detector;
    detector.Initialize();
    
    // Create a suspicious pattern
    uint8_t suspiciousBuffer[16];
    memset(suspiciousBuffer, 0x90, 16);
    suspiciousBuffer[0] = 0xE9;  // JMP
    
    uintptr_t suspiciousAddr = reinterpret_cast<uintptr_t>(suspiciousBuffer);
    
    // Check without registering - should use HasSuspiciousJump
    bool isHooked = detector.CheckFunction(suspiciousAddr);
    
    EXPECT_TRUE(isHooked)
        << "Unregistered function with suspicious pattern should be detected";
    
    // Create a normal pattern
    uint8_t normalBuffer[16];
    normalBuffer[0] = 0x55;  // PUSH RBP
    normalBuffer[1] = 0x48;  // REX.W
    memset(normalBuffer + 2, 0x90, 14);
    
    uintptr_t normalAddr = reinterpret_cast<uintptr_t>(normalBuffer);
    
    bool isNormalHooked = detector.CheckFunction(normalAddr);
    
    EXPECT_FALSE(isNormalHooked)
        << "Unregistered function with normal pattern should not be detected";
    
    detector.Shutdown();
}

/**
 * Test 10: Empty Detector
 * Verifies behavior when no functions are registered
 */
TEST(AntiHookTests, EmptyDetector) {
    AntiHookDetector detector;
    detector.Initialize();
    
    // QuickCheck and FullScan should return empty when nothing is registered
    std::vector<ViolationEvent> quickViolations = detector.QuickCheck();
    std::vector<ViolationEvent> fullViolations = detector.FullScan();
    
    EXPECT_TRUE(quickViolations.empty())
        << "QuickCheck should return empty when no functions registered";
    EXPECT_TRUE(fullViolations.empty())
        << "FullScan should return empty when no functions registered";
    
    detector.Shutdown();
}
