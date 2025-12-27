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
    bool foundVMware = false;
    
    for (const auto& entry : entries) {
        if (entry.identifier == "DiscordHook64.dll") {
            foundDiscord = true;
            EXPECT_EQ(entry.type, WhitelistType::Module);
            EXPECT_TRUE(entry.builtin);
            EXPECT_EQ(entry.reason, "Discord in-game overlay");
        }
        if (entry.identifier == "GameOverlayRenderer64.dll") {
            foundSteam = true;
            EXPECT_EQ(entry.type, WhitelistType::Module);
            EXPECT_TRUE(entry.builtin);
        }
        if (entry.identifier == "nvspcap64.dll") {
            foundNvidia = true;
            EXPECT_EQ(entry.type, WhitelistType::Module);
            EXPECT_TRUE(entry.builtin);
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
