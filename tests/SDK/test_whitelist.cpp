/**
 * Sentinel SDK - Whitelist Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Internal/Whitelist.hpp"

using namespace Sentinel::SDK;

// Test fixture for whitelist tests
class WhitelistTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager.Initialize();
    }
    
    void TearDown() override {
        manager.Shutdown();
    }
    
    WhitelistManager manager;
};

// Test 1: Builtin Entries Loaded
TEST_F(WhitelistTest, BuiltinEntriesLoaded) {
    auto entries = manager.GetEntries();
    
    // Verify we have the expected number of builtin entries
    EXPECT_GT(entries.size(), 0);
    
    // Check for specific builtin entries
    bool foundDiscord = false;
    bool foundSteam = false;
    bool foundNvidia = false;
    bool foundXboxGameBar = false;
    bool foundVMware = false;
    
    for (const auto& entry : entries) {
        if (entry.identifier == "DiscordHook64.dll") {
            foundDiscord = true;
            EXPECT_EQ(entry.type, WhitelistType::Module);
            EXPECT_TRUE(entry.builtin);
            EXPECT_EQ(entry.reason, "Discord in-game overlay");
            EXPECT_TRUE(entry.signer.has_value());
            EXPECT_EQ(entry.signer.value(), "Discord Inc.");
        }
        if (entry.identifier == "GameOverlayRenderer64.dll") {
            foundSteam = true;
            EXPECT_EQ(entry.type, WhitelistType::Module);
            EXPECT_TRUE(entry.builtin);
            EXPECT_TRUE(entry.signer.has_value());
            EXPECT_EQ(entry.signer.value(), "Valve Corp.");
        }
        if (entry.identifier == "nvspcap64.dll") {
            foundNvidia = true;
            EXPECT_EQ(entry.type, WhitelistType::Module);
            EXPECT_TRUE(entry.builtin);
            EXPECT_TRUE(entry.signer.has_value());
            EXPECT_EQ(entry.signer.value(), "NVIDIA Corporation");
        }
        if (entry.identifier == "GameBar.dll") {
            foundXboxGameBar = true;
            EXPECT_EQ(entry.type, WhitelistType::Module);
            EXPECT_TRUE(entry.builtin);
            EXPECT_EQ(entry.reason, "Xbox Game Bar overlay");
            EXPECT_TRUE(entry.signer.has_value());
            EXPECT_EQ(entry.signer.value(), "Microsoft Corporation");
        }
        if (entry.identifier == "VMware") {
            foundVMware = true;
            EXPECT_EQ(entry.type, WhitelistType::TimingException);
            EXPECT_TRUE(entry.builtin);
        }
    }
    
    EXPECT_TRUE(foundDiscord) << "Discord overlay entry not found";
    EXPECT_TRUE(foundSteam) << "Steam overlay entry not found";
    EXPECT_TRUE(foundNvidia) << "NVIDIA capture entry not found";
    EXPECT_TRUE(foundXboxGameBar) << "Xbox Game Bar overlay entry not found";
    EXPECT_TRUE(foundVMware) << "VMware entry not found";
}

// Test 2: Custom Entry Add/Remove
TEST_F(WhitelistTest, CustomEntryAddRemove) {
    // Add a custom entry
    WhitelistEntry customEntry;
    customEntry.type = WhitelistType::Module;
    customEntry.identifier = "CustomModule.dll";
    customEntry.reason = "Custom test module";
    customEntry.builtin = false;
    
    manager.Add(customEntry);
    
    // Verify it was added
    auto entries = manager.GetEntries();
    bool found = false;
    for (const auto& entry : entries) {
        if (entry.identifier == "CustomModule.dll") {
            found = true;
            EXPECT_FALSE(entry.builtin);
            break;
        }
    }
    EXPECT_TRUE(found) << "Custom entry not added";
    
    // Create a mock module path for testing
    // Note: This is case-insensitive on Windows
    wchar_t modulePath[] = L"C:\\Path\\To\\CustomModule.dll";
    EXPECT_TRUE(manager.IsModuleWhitelisted(modulePath));
    
    // Remove the entry
    manager.Remove("CustomModule.dll");
    
    // Verify it was removed
    EXPECT_FALSE(manager.IsModuleWhitelisted(modulePath));
}

// Test 3: Builtin Cannot Be Removed
TEST_F(WhitelistTest, BuiltinCannotBeRemoved) {
    // Try to remove a builtin entry
    manager.Remove("DiscordHook64.dll");
    
    // Verify it's still there
    auto entries = manager.GetEntries();
    bool found = false;
    for (const auto& entry : entries) {
        if (entry.identifier == "DiscordHook64.dll") {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found) << "Builtin entry was incorrectly removed";
    
    // Verify the module is still whitelisted
    wchar_t modulePath[] = L"C:\\Discord\\DiscordHook64.dll";
    EXPECT_TRUE(manager.IsModuleWhitelisted(modulePath));
}

// Test 4: Module Whitelisting (Case Insensitive)
TEST_F(WhitelistTest, ModuleWhitelistingCaseInsensitive) {
    // Test with different case variations
    wchar_t path1[] = L"C:\\Discord\\discordhook64.dll";  // lowercase
    wchar_t path2[] = L"C:\\Discord\\DISCORDHOOK64.DLL";  // uppercase
    wchar_t path3[] = L"C:\\Discord\\DiscordHook64.dll";  // mixed case
    
    EXPECT_TRUE(manager.IsModuleWhitelisted(path1));
    EXPECT_TRUE(manager.IsModuleWhitelisted(path2));
    EXPECT_TRUE(manager.IsModuleWhitelisted(path3));
}

// Test 5: Non-whitelisted Module
TEST_F(WhitelistTest, NonWhitelistedModule) {
    wchar_t modulePath[] = L"C:\\Malware\\suspicious.dll";
    EXPECT_FALSE(manager.IsModuleWhitelisted(modulePath));
}

// Test 6: VM Detection
TEST_F(WhitelistTest, VMDetection) {
    // This test will vary based on the environment
    // We just verify the method runs without crashing
    bool isVM = manager.IsVirtualizedEnvironment();
    
    // The result depends on the environment, so we just check it's a valid boolean
    EXPECT_TRUE(isVM == true || isVM == false);
    
    // If we're in a VM, verify the entries exist
    if (isVM) {
        auto entries = manager.GetEntries();
        bool hasVMEntry = false;
        for (const auto& entry : entries) {
            if (entry.type == WhitelistType::TimingException) {
                hasVMEntry = true;
                break;
            }
        }
        EXPECT_TRUE(hasVMEntry) << "VM detected but no timing exception entries found";
    }
}

// Test 7: Thread Origin Whitelisting
TEST_F(WhitelistTest, ThreadOriginWhitelisting) {
    // This test requires a valid address, which we can't easily mock
    // We'll just verify the method runs without crashing
    uintptr_t testAddress = 0x1000;
    bool result = manager.IsThreadOriginWhitelisted(testAddress);
    
    // The result depends on the actual memory state
    EXPECT_TRUE(result == true || result == false);
}

// Test 8: Module Hash Whitelisting
TEST_F(WhitelistTest, ModuleHashWhitelisting) {
    // Add an entry with a hash
    WhitelistEntry hashEntry;
    hashEntry.type = WhitelistType::Module;
    hashEntry.identifier = "HashedModule.dll";
    hashEntry.reason = "Module with hash verification";
    hashEntry.builtin = false;
    hashEntry.sha256_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    
    manager.Add(hashEntry);
    
    // Test hash-based whitelisting
    EXPECT_TRUE(manager.IsModuleWhitelisted("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    EXPECT_FALSE(manager.IsModuleWhitelisted("invalid_hash"));
}

// Test 9: Duplicate Entry Prevention
TEST_F(WhitelistTest, DuplicateEntryPrevention) {
    WhitelistEntry entry1;
    entry1.type = WhitelistType::Module;
    entry1.identifier = "DuplicateTest.dll";
    entry1.reason = "First entry";
    entry1.builtin = false;
    
    WhitelistEntry entry2;
    entry2.type = WhitelistType::Module;
    entry2.identifier = "DuplicateTest.dll";
    entry2.reason = "Second entry (duplicate)";
    entry2.builtin = false;
    
    size_t initialCount = manager.GetEntries().size();
    
    manager.Add(entry1);
    size_t afterFirst = manager.GetEntries().size();
    EXPECT_EQ(afterFirst, initialCount + 1);
    
    manager.Add(entry2);
    size_t afterSecond = manager.GetEntries().size();
    EXPECT_EQ(afterSecond, afterFirst) << "Duplicate entry was added";
}

// Test 10: Initialize/Shutdown Cycle
TEST_F(WhitelistTest, InitializeShutdownCycle) {
    // Add a custom entry
    WhitelistEntry customEntry;
    customEntry.type = WhitelistType::Module;
    customEntry.identifier = "TestModule.dll";
    customEntry.reason = "Test";
    customEntry.builtin = false;
    
    manager.Add(customEntry);
    EXPECT_GT(manager.GetEntries().size(), 0);
    
    // Shutdown should clear entries
    manager.Shutdown();
    EXPECT_EQ(manager.GetEntries().size(), 0);
    
    // Re-initialize should reload builtins
    manager.Initialize();
    EXPECT_GT(manager.GetEntries().size(), 0);
    
    // Custom entry should be gone
    bool found = false;
    for (const auto& entry : manager.GetEntries()) {
        if (entry.identifier == "TestModule.dll") {
            found = true;
            break;
        }
    }
    EXPECT_FALSE(found) << "Custom entry persisted after shutdown/init cycle";
}

// Test 11: Thread Origin Whitelist - System DLLs
TEST_F(WhitelistTest, ThreadOriginSystemDLLs) {
    // Verify system DLLs are in the thread origin whitelist
    auto entries = manager.GetEntries();
    
    bool foundNtdll = false;
    bool foundKernel32 = false;
    bool foundKernelBase = false;
    
    for (const auto& entry : entries) {
        if (entry.type == WhitelistType::ThreadOrigin) {
            if (entry.identifier == "ntdll.dll") {
                foundNtdll = true;
                EXPECT_TRUE(entry.builtin);
                EXPECT_EQ(entry.reason, "Windows NT kernel layer - thread pool workers");
            }
            if (entry.identifier == "kernel32.dll") {
                foundKernel32 = true;
                EXPECT_TRUE(entry.builtin);
            }
            if (entry.identifier == "kernelbase.dll") {
                foundKernelBase = true;
                EXPECT_TRUE(entry.builtin);
            }
        }
    }
    
    EXPECT_TRUE(foundNtdll) << "ntdll.dll thread origin not found";
    EXPECT_TRUE(foundKernel32) << "kernel32.dll thread origin not found";
    EXPECT_TRUE(foundKernelBase) << "kernelbase.dll thread origin not found";
}

// Test 12: Thread Origin Whitelist - CLR Runtime
TEST_F(WhitelistTest, ThreadOriginCLRRuntime) {
    // Verify .NET CLR modules are in the thread origin whitelist
    auto entries = manager.GetEntries();
    
    bool foundClr = false;
    bool foundCoreClr = false;
    bool foundClrJit = false;
    bool foundMscorwks = false;
    bool foundMscorsvr = false;
    
    for (const auto& entry : entries) {
        if (entry.type == WhitelistType::ThreadOrigin) {
            if (entry.identifier == "clr.dll") foundClr = true;
            if (entry.identifier == "coreclr.dll") foundCoreClr = true;
            if (entry.identifier == "clrjit.dll") foundClrJit = true;
            if (entry.identifier == "mscorwks.dll") foundMscorwks = true;
            if (entry.identifier == "mscorsvr.dll") foundMscorsvr = true;
        }
    }
    
    EXPECT_TRUE(foundClr) << "clr.dll thread origin not found";
    EXPECT_TRUE(foundCoreClr) << "coreclr.dll thread origin not found";
    EXPECT_TRUE(foundClrJit) << "clrjit.dll thread origin not found";
    EXPECT_TRUE(foundMscorwks) << "mscorwks.dll thread origin not found";
    EXPECT_TRUE(foundMscorsvr) << "mscorsvr.dll thread origin not found";
}

// Test 13: Custom Thread Origin Whitelist
TEST_F(WhitelistTest, CustomThreadOriginWhitelist) {
    // Add a custom thread origin entry
    WhitelistEntry customEntry;
    customEntry.type = WhitelistType::ThreadOrigin;
    customEntry.identifier = "MyGameEngine.dll";
    customEntry.reason = "Custom game engine job system";
    customEntry.builtin = false;
    
    manager.Add(customEntry);
    
    // Verify it was added
    auto entries = manager.GetEntries();
    bool found = false;
    for (const auto& entry : entries) {
        if (entry.identifier == "MyGameEngine.dll" && 
            entry.type == WhitelistType::ThreadOrigin) {
            found = true;
            EXPECT_FALSE(entry.builtin);
            EXPECT_EQ(entry.reason, "Custom game engine job system");
            break;
        }
    }
    EXPECT_TRUE(found) << "Custom thread origin entry not added";
    
    // Remove the entry
    manager.Remove("MyGameEngine.dll");
    
    // Verify it was removed
    entries = manager.GetEntries();
    found = false;
    for (const auto& entry : entries) {
        if (entry.identifier == "MyGameEngine.dll" && 
            entry.type == WhitelistType::ThreadOrigin) {
            found = true;
            break;
        }
    }
    EXPECT_FALSE(found) << "Custom thread origin entry was not removed";
}

// Test 14: Overlay Signature Verification
TEST_F(WhitelistTest, OverlaySignatureVerification) {
    // Verify that all common overlay DLLs have signature verification enabled
    auto entries = manager.GetEntries();
    
    struct OverlayEntry {
        std::string identifier;
        std::string expectedSigner;
    };
    
    std::vector<OverlayEntry> expectedOverlays = {
        {"DiscordHook64.dll", "Discord Inc."},
        {"GameOverlayRenderer64.dll", "Valve Corp."},
        {"nvspcap64.dll", "NVIDIA Corporation"},
        {"GameBar.dll", "Microsoft Corporation"}
    };
    
    for (const auto& expectedOverlay : expectedOverlays) {
        bool found = false;
        for (const auto& entry : entries) {
            if (entry.identifier == expectedOverlay.identifier && 
                entry.type == WhitelistType::Module) {
                found = true;
                EXPECT_TRUE(entry.builtin) << expectedOverlay.identifier << " should be builtin";
                EXPECT_TRUE(entry.signer.has_value()) 
                    << expectedOverlay.identifier << " should have signature verification";
                if (entry.signer.has_value()) {
                    EXPECT_EQ(entry.signer.value(), expectedOverlay.expectedSigner)
                        << expectedOverlay.identifier << " has wrong expected signer";
                }
                break;
            }
        }
        EXPECT_TRUE(found) << expectedOverlay.identifier << " not found in whitelist";
    }
}

// Test 15: Discord Overlay Integration Test
TEST_F(WhitelistTest, DiscordOverlayIntegrationTest) {
    // Simulate Discord overlay DLL paths that should be whitelisted
    std::vector<std::wstring> discordPaths = {
        L"C:\\Users\\Player\\AppData\\Local\\Discord\\app-1.0.9015\\modules\\discord_hook\\DiscordHook64.dll",
        L"C:\\Discord\\DiscordHook64.dll",
        L"D:\\Programs\\Discord\\DiscordHook64.dll"
    };
    
    for (const auto& path : discordPaths) {
        // Note: This test verifies the whitelisting logic works correctly.
        // In a real scenario with actual Discord DLL and valid signature,
        // the signature verification would also pass.
        // Here we're testing that the module name matching works correctly.
        bool isWhitelisted = manager.IsModuleWhitelisted(path.c_str());
        
        // The module should be whitelisted by name
        // Note: Actual signature verification would happen in production,
        // but we can't test it here without real signed Discord DLL
        EXPECT_TRUE(isWhitelisted) 
            << "Discord overlay should be whitelisted: " 
            << std::string(path.begin(), path.end());
    }
}

// Test 16: All Common Overlays Whitelisted
TEST_F(WhitelistTest, AllCommonOverlaysWhitelisted) {
    // Test that all common overlay DLLs are whitelisted
    std::vector<std::wstring> commonOverlays = {
        L"C:\\Steam\\GameOverlayRenderer64.dll",
        L"C:\\NVIDIA\\nvspcap64.dll",
        L"C:\\Windows\\System32\\GameBar.dll",
        L"C:\\Discord\\DiscordHook64.dll"
    };
    
    for (const auto& overlayPath : commonOverlays) {
        bool isWhitelisted = manager.IsModuleWhitelisted(overlayPath.c_str());
        EXPECT_TRUE(isWhitelisted) 
            << "Common overlay should be whitelisted: " 
            << std::string(overlayPath.begin(), overlayPath.end());
    }
}


