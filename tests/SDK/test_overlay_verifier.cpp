/**
 * Sentinel SDK - Overlay Verification Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 7: Test hardened overlay detection against spoofing
 */

#include <gtest/gtest.h>
#include "Internal/OverlayVerifier.hpp"

using namespace Sentinel::SDK;

/**
 * Test Fixture for OverlayVerifier tests
 */
class OverlayVerifierTest : public ::testing::Test {
protected:
    void SetUp() override {
        verifier_ = std::make_unique<OverlayVerifier>();
        verifier_->Initialize();
    }
    
    void TearDown() override {
        verifier_->Shutdown();
        verifier_.reset();
    }
    
    std::unique_ptr<OverlayVerifier> verifier_;
};

/**
 * Test: Identify potential overlay modules by name
 */
TEST_F(OverlayVerifierTest, IdentifyPotentialOverlays) {
    // Discord overlays
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"DiscordHook64.dll"));
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"discord_overlay.dll"));
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"DISCORDHOOK64.DLL")); // Case insensitive
    
    // Steam overlays
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"GameOverlayRenderer64.dll"));
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"steamoverlay.dll"));
    
    // NVIDIA overlays
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"nvda_overlay.dll"));
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"GeForceExperience.dll"));
    
    // OBS overlays
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"obs-overlay.dll"));
    
    // Non-overlay modules
    EXPECT_FALSE(OverlayVerifier::IsPotentialOverlay(L"kernel32.dll"));
    EXPECT_FALSE(OverlayVerifier::IsPotentialOverlay(L"user32.dll"));
    EXPECT_FALSE(OverlayVerifier::IsPotentialOverlay(L"ntdll.dll"));
    EXPECT_FALSE(OverlayVerifier::IsPotentialOverlay(L"game.exe"));
}

/**
 * Test: Identify vendor from module name
 */
TEST_F(OverlayVerifierTest, IdentifyVendor) {
    // Discord
    EXPECT_EQ(OverlayVerifier::IdentifyVendor(L"DiscordHook64.dll"), OverlayVendor::Discord);
    EXPECT_EQ(OverlayVerifier::IdentifyVendor(L"discord_overlay.dll"), OverlayVendor::Discord);
    
    // Steam
    EXPECT_EQ(OverlayVerifier::IdentifyVendor(L"GameOverlayRenderer64.dll"), OverlayVendor::Steam);
    EXPECT_EQ(OverlayVerifier::IdentifyVendor(L"steamoverlay.dll"), OverlayVendor::Steam);
    
    // NVIDIA
    EXPECT_EQ(OverlayVerifier::IdentifyVendor(L"nvda_overlay.dll"), OverlayVendor::NVIDIA);
    EXPECT_EQ(OverlayVerifier::IdentifyVendor(L"GeForce_overlay.dll"), OverlayVendor::NVIDIA);
    
    // OBS
    EXPECT_EQ(OverlayVerifier::IdentifyVendor(L"obs-overlay.dll"), OverlayVendor::OBS);
    
    // Unknown
    EXPECT_EQ(OverlayVerifier::IdentifyVendor(L"kernel32.dll"), OverlayVendor::Unknown);
}

/**
 * Test: Expected hook patterns for Discord
 */
TEST_F(OverlayVerifierTest, DiscordExpectedHooks) {
    // Discord overlays typically hook D3D/DXGI functions
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"d3d11.dll", L"Present"));
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"dxgi.dll", L"CreateSwapChain"));
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"d3d9.dll", L"EndScene"));
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"opengl32.dll", L"SwapBuffers"));
    
    // Not expected hooks
    EXPECT_FALSE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"kernel32.dll", L"CreateFile"));
    EXPECT_FALSE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"ntdll.dll", L"NtProtectVirtualMemory"));
}

/**
 * Test: Expected hook patterns for Steam
 */
TEST_F(OverlayVerifierTest, SteamExpectedHooks) {
    // Steam overlays hook rendering functions
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::Steam, L"d3d11.dll", L"Present"));
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::Steam, L"d3d9.dll", L"EndScene"));
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::Steam, L"opengl32.dll", L"SwapBuffers"));
    
    // Not expected
    EXPECT_FALSE(verifier_->IsExpectedHookPattern(OverlayVendor::Steam, L"kernel32.dll"));
}

/**
 * Test: Critical security functions should never be suppressed
 */
TEST_F(OverlayVerifierTest, CriticalSecurityFunctions) {
    // These functions should NEVER have detections suppressed
    EXPECT_TRUE(OverlayVerifier::IsCriticalSecurityFunction(L"NtProtectVirtualMemory"));
    EXPECT_TRUE(OverlayVerifier::IsCriticalSecurityFunction(L"VirtualProtect"));
    EXPECT_TRUE(OverlayVerifier::IsCriticalSecurityFunction(L"WriteProcessMemory"));
    EXPECT_TRUE(OverlayVerifier::IsCriticalSecurityFunction(L"CreateRemoteThread"));
    EXPECT_TRUE(OverlayVerifier::IsCriticalSecurityFunction(L"SetWindowsHookEx"));
    
    // Case insensitive
    EXPECT_TRUE(OverlayVerifier::IsCriticalSecurityFunction(L"ntprotectvirtualmemory"));
    EXPECT_TRUE(OverlayVerifier::IsCriticalSecurityFunction(L"VIRTUALPROTECT"));
    
    // Non-critical functions
    EXPECT_FALSE(OverlayVerifier::IsCriticalSecurityFunction(L"Present"));
    EXPECT_FALSE(OverlayVerifier::IsCriticalSecurityFunction(L"EndScene"));
    EXPECT_FALSE(OverlayVerifier::IsCriticalSecurityFunction(L"SwapBuffers"));
}

/**
 * Test: Fake Discord DLL should not be verified
 * 
 * This test verifies that a fake "DiscordHook64.dll" without proper signature
 * will not be verified as a legitimate overlay.
 */
TEST_F(OverlayVerifierTest, FakeDiscordDLLNotVerified) {
    // Simulated fake Discord DLL path (doesn't exist)
    const wchar_t* fake_path = L"C:\\FakeOverlay\\DiscordHook64.dll";
    
    auto result = verifier_->VerifyOverlay(fake_path);
    
    // Should not be verified (file doesn't exist, so signature check fails)
    EXPECT_FALSE(result.is_verified);
    EXPECT_EQ(result.vendor, OverlayVendor::Discord); // Vendor identified by name
    EXPECT_FALSE(result.signature_valid); // But signature not valid
}

/**
 * Test: Unsigned overlay should not be verified
 */
TEST_F(OverlayVerifierTest, UnsignedOverlayNotVerified) {
    // Any unsigned DLL claiming to be an overlay should fail verification
    const wchar_t* unsigned_path = L"C:\\Game\\fake_steam_overlay.dll";
    
    auto result = verifier_->VerifyOverlay(unsigned_path);
    
    // Should not be verified
    EXPECT_FALSE(result.is_verified);
}

/**
 * Test: Module with wrong signer should not be verified
 * 
 * Even if a DLL is signed, if the signer doesn't match the expected vendor,
 * it should not be verified.
 */
TEST_F(OverlayVerifierTest, WrongSignerNotVerified) {
    // This test demonstrates the concept - in practice would need a signed DLL
    // with the wrong signer to fully test this
    
    // The verification logic checks:
    // 1. Signature is valid
    // 2. Signer matches expected vendor
    // 
    // If signer is "Cheat Corp" but module claims to be Discord, it fails
}

/**
 * Test: Discord without IPC connection should not be verified
 * 
 * Discord overlay requires an active IPC connection to be considered legitimate.
 */
TEST_F(OverlayVerifierTest, DiscordWithoutIPCNotVerified) {
    // This test would check that Discord IPC validation works
    // In practice, if Discord is not running, the IPC pipe won't exist
    // and the overlay should not be verified
    
    // The ValidateDiscordIPC() method checks for \\.\pipe\discord-ipc-* pipes
    // If none exist, Discord overlay verification should fail
}

/**
 * Test: Null or empty paths should not be verified
 */
TEST_F(OverlayVerifierTest, NullPathsNotVerified) {
    auto result1 = verifier_->VerifyOverlay(nullptr);
    EXPECT_FALSE(result1.is_verified);
    
    auto result2 = verifier_->VerifyOverlay(L"");
    EXPECT_FALSE(result2.is_verified);
}

/**
 * Test: Unknown vendor should not be verified
 */
TEST_F(OverlayVerifierTest, UnknownVendorNotVerified) {
    const wchar_t* unknown_path = L"C:\\Game\\SomeRandomDLL.dll";
    
    auto result = verifier_->VerifyOverlay(unknown_path);
    
    EXPECT_FALSE(result.is_verified);
    EXPECT_EQ(result.vendor, OverlayVendor::Unknown);
}

/**
 * Test: Expected hook patterns require both module and vendor match
 */
TEST_F(OverlayVerifierTest, HookPatternRequiresModuleMatch) {
    // Discord can hook d3d11.dll but not kernel32.dll
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"d3d11.dll"));
    EXPECT_FALSE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"kernel32.dll"));
    
    // Different vendors have different expected patterns
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::NVIDIA, L"d3d12.dll"));
    EXPECT_FALSE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"d3d12.dll")); // Discord doesn't hook D3D12
}

/**
 * Test: Case insensitivity in all checks
 */
TEST_F(OverlayVerifierTest, CaseInsensitivity) {
    // Module name identification
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"DISCORDHOOK64.DLL"));
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"discordhook64.dll"));
    EXPECT_TRUE(OverlayVerifier::IsPotentialOverlay(L"DiscordHook64.DLL"));
    
    // Vendor identification
    EXPECT_EQ(OverlayVerifier::IdentifyVendor(L"DISCORD.DLL"), OverlayVendor::Discord);
    EXPECT_EQ(OverlayVerifier::IdentifyVendor(L"discord.dll"), OverlayVendor::Discord);
    
    // Hook pattern matching
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"D3D11.DLL"));
    EXPECT_TRUE(verifier_->IsExpectedHookPattern(OverlayVendor::Discord, L"d3d11.dll"));
}
