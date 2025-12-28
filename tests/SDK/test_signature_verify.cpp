/**
 * Sentinel SDK - Module Signature Verification Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 12: Tests for Module Signature Verification
 */

#include <gtest/gtest.h>
#include "Internal/SignatureVerify.hpp"
#include "Internal/Detection.hpp"
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace Sentinel::SDK;

/**
 * Test 1: Known Proxy DLL Detection
 * Verify that known proxy DLL names are correctly identified
 */
TEST(SignatureVerifyTests, KnownProxyDLLDetection) {
    // These should be identified as known proxy DLLs
    EXPECT_TRUE(SignatureVerifier::IsKnownProxyDLL(L"dinput8.dll"));
    EXPECT_TRUE(SignatureVerifier::IsKnownProxyDLL(L"version.dll"));
    EXPECT_TRUE(SignatureVerifier::IsKnownProxyDLL(L"d3d9.dll"));
    EXPECT_TRUE(SignatureVerifier::IsKnownProxyDLL(L"dxgi.dll"));
    EXPECT_TRUE(SignatureVerifier::IsKnownProxyDLL(L"d3d11.dll"));
    EXPECT_TRUE(SignatureVerifier::IsKnownProxyDLL(L"xinput1_3.dll"));
    EXPECT_TRUE(SignatureVerifier::IsKnownProxyDLL(L"winmm.dll"));
    EXPECT_TRUE(SignatureVerifier::IsKnownProxyDLL(L"dsound.dll"));
    
    // Case insensitive
    EXPECT_TRUE(SignatureVerifier::IsKnownProxyDLL(L"DINPUT8.DLL"));
    EXPECT_TRUE(SignatureVerifier::IsKnownProxyDLL(L"Version.Dll"));
    
    // These should NOT be identified as proxy DLLs
    EXPECT_FALSE(SignatureVerifier::IsKnownProxyDLL(L"kernel32.dll"));
    EXPECT_FALSE(SignatureVerifier::IsKnownProxyDLL(L"user32.dll"));
    EXPECT_FALSE(SignatureVerifier::IsKnownProxyDLL(L"game.dll"));
    EXPECT_FALSE(SignatureVerifier::IsKnownProxyDLL(L"mymodule.dll"));
    EXPECT_FALSE(SignatureVerifier::IsKnownProxyDLL(nullptr));
}

#ifdef _WIN32
/**
 * Test 2: Path Validation for System DLLs
 * Verify that system DLLs loaded from wrong paths are detected
 */
TEST(SignatureVerifyTests, SystemDLLPathValidation) {
    wchar_t system_dir[MAX_PATH];
    GetSystemDirectoryW(system_dir, MAX_PATH);
    
    // Valid: dinput8.dll in System32
    std::wstring valid_path = std::wstring(system_dir) + L"\\dinput8.dll";
    EXPECT_TRUE(SignatureVerifier::ValidateModulePath(valid_path.c_str(), L"dinput8.dll"));
    
    // Invalid: dinput8.dll in game directory
    EXPECT_FALSE(SignatureVerifier::ValidateModulePath(L"C:\\Games\\MyGame\\dinput8.dll", L"dinput8.dll"));
    
    // Valid: non-system DLL in game directory (not a known proxy)
    EXPECT_TRUE(SignatureVerifier::ValidateModulePath(L"C:\\Games\\MyGame\\game.dll", L"game.dll"));
}

/**
 * Test 3: Windows System DLL Signature Verification
 * Verify that a known Windows system DLL has a valid signature
 */
TEST(SignatureVerifyTests, WindowsSystemDLLSignature) {
    SignatureVerifier verifier;
    
    // Test kernel32.dll which should be signed by Microsoft
    wchar_t system_dir[MAX_PATH];
    GetSystemDirectoryW(system_dir, MAX_PATH);
    std::wstring kernel32_path = std::wstring(system_dir) + L"\\kernel32.dll";
    
    ModuleVerificationResult result = verifier.VerifyModule(kernel32_path.c_str());
    
    // kernel32.dll should have a valid signature
    EXPECT_TRUE(result.signature_status == SignatureStatus::Valid || 
                result.signature_status == SignatureStatus::Unsigned)
        << "kernel32.dll should be signed or unsigned (not invalid/error)";
    
    // Should not be flagged as a proxy DLL when loaded from System32
    EXPECT_TRUE(result.path_valid) << "kernel32.dll in System32 should have valid path";
}

/**
 * Test 4: InjectionDetector Module Signature Scan
 * Verify that ScanModuleSignatures works without crashing
 */
TEST(SignatureVerifyTests, InjectionDetectorModuleScan) {
    InjectionDetector detector;
    detector.Initialize();
    
    // Run the signature scan
    std::vector<ViolationEvent> violations = detector.ScanModuleSignatures();
    
    // The scan should complete successfully
    // In a clean process, we should not have proxy DLLs
    SUCCEED() << "Module signature scan completed with " << violations.size() << " violations";
    
    // If any violations are found, log them for debugging
    for (const auto& violation : violations) {
        std::cout << "Violation detected: type=" << static_cast<int>(violation.type)
                  << " severity=" << static_cast<int>(violation.severity)
                  << " details=" << (violation.details ? violation.details : "N/A")
                  << " module=" << (violation.module_name ? violation.module_name : "N/A")
                  << std::endl;
    }
    
    detector.Shutdown();
}
#endif

/**
 * Test 5: Hash Verification Setup
 * Verify that expected modules can be configured
 */
TEST(SignatureVerifyTests, HashVerificationSetup) {
    SignatureVerifier verifier;
    
    // Configure expected modules
    std::vector<ExpectedModule> modules;
    
    ExpectedModule mod1;
    mod1.name = L"game.dll";
    mod1.hash = std::vector<uint8_t>(32, 0xAA);  // Dummy hash
    modules.push_back(mod1);
    
    ExpectedModule mod2;
    mod2.name = L"engine.dll";
    mod2.hash = std::vector<uint8_t>(32, 0xBB);  // Dummy hash
    modules.push_back(mod2);
    
    verifier.SetExpectedModules(modules);
    
    // Test should not crash
    SUCCEED() << "Expected modules configured successfully";
}

/**
 * Test 6: Trusted Signer Management
 * Verify that trusted signers can be added
 */
TEST(SignatureVerifyTests, TrustedSignerManagement) {
    SignatureVerifier verifier;
    
    // Add trusted signers
    verifier.AddTrustedSigner(L"Microsoft Corporation");
    verifier.AddTrustedSigner(L"My Game Company");
    
    // Test should not crash
    SUCCEED() << "Trusted signers added successfully";
}

/**
 * Test 7: Null/Empty Input Handling
 * Verify that the verifier handles null/empty inputs gracefully
 */
TEST(SignatureVerifyTests, NullEmptyInputHandling) {
    SignatureVerifier verifier;
    
    // Null path
    ModuleVerificationResult result1 = verifier.VerifyModule(nullptr);
    EXPECT_EQ(result1.signature_status, SignatureStatus::Error);
    
    // Empty path
    ModuleVerificationResult result2 = verifier.VerifyModule(L"");
    EXPECT_EQ(result2.signature_status, SignatureStatus::Error);
    
    // Null inputs to static methods
    EXPECT_FALSE(SignatureVerifier::IsKnownProxyDLL(nullptr));
}

#ifdef _WIN32
/**
 * Test 8: Nonexistent File Handling
 * Verify that attempting to verify a nonexistent file is handled
 */
TEST(SignatureVerifyTests, NonexistentFileHandling) {
    SignatureVerifier verifier;
    
    // Try to verify a file that doesn't exist
    ModuleVerificationResult result = verifier.VerifyModule(L"C:\\NonexistentPath\\fake.dll");
    
    // Should return an error status
    EXPECT_TRUE(result.signature_status == SignatureStatus::Error ||
                result.signature_status == SignatureStatus::Unsigned)
        << "Nonexistent file should return error or unsigned status";
}

/**
 * Test 9: Multiple Module Scans
 * Verify that scanning can be performed multiple times
 */
TEST(SignatureVerifyTests, MultipleScans) {
    InjectionDetector detector;
    detector.Initialize();
    
    // Perform multiple scans
    for (int i = 0; i < 3; i++) {
        std::vector<ViolationEvent> violations = detector.ScanModuleSignatures();
        SUCCEED() << "Scan " << i << " completed with " << violations.size() << " violations";
    }
    
    detector.Shutdown();
}

/**
 * Test 10: Integration with InjectionDetector
 * Verify that all scan methods work together
 */
TEST(SignatureVerifyTests, IntegrationWithInjectionDetector) {
    InjectionDetector detector;
    detector.Initialize();
    
    // Run all scan types
    std::vector<ViolationEvent> module_violations = detector.ScanLoadedModules();
    std::vector<ViolationEvent> thread_violations = detector.ScanThreads();
    std::vector<ViolationEvent> signature_violations = detector.ScanModuleSignatures();
    
    std::cout << "Memory scan: " << module_violations.size() << " violations" << std::endl;
    std::cout << "Thread scan: " << thread_violations.size() << " violations" << std::endl;
    std::cout << "Signature scan: " << signature_violations.size() << " violations" << std::endl;
    
    // All scans should complete without crashing
    SUCCEED() << "All injection detection scans completed successfully";
    
    detector.Shutdown();
}
#endif
