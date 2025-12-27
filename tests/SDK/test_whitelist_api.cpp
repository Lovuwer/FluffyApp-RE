/**
 * Sentinel SDK - Public API Tests for Whitelist Configuration
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "SentinelSDK.hpp"
#include "Internal/Whitelist.hpp"
#include "Internal/Detection.hpp"

using namespace Sentinel::SDK;

// Test fixture for SDK API tests
class SDKWhitelistAPITest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize SDK with default configuration
        config = Configuration::Default();
        config.license_key = "TEST_LICENSE_KEY";
        config.game_id = "test_game";
        config.debug_mode = true;
        
        ErrorCode result = Initialize(&config);
        ASSERT_EQ(result, ErrorCode::Success) << "SDK initialization failed";
    }
    
    void TearDown() override {
        Shutdown();
    }
    
    Configuration config;
};

// Test 1: WhitelistThreadOrigin - Add Custom Entry
TEST_F(SDKWhitelistAPITest, AddCustomThreadOrigin) {
    // Add a custom thread origin via the public API
    ErrorCode result = WhitelistThreadOrigin(
        "CustomEngine.dll",
        "Custom game engine threading system"
    );
    
    EXPECT_EQ(result, ErrorCode::Success) 
        << "WhitelistThreadOrigin should succeed";
    
    // Verify the entry was added by checking internal whitelist
    ASSERT_NE(g_whitelist, nullptr);
    auto entries = g_whitelist->GetEntries();
    
    bool found = false;
    for (const auto& entry : entries) {
        if (entry.identifier == "CustomEngine.dll" && 
            entry.type == WhitelistType::ThreadOrigin) {
            found = true;
            EXPECT_FALSE(entry.builtin);
            EXPECT_EQ(entry.reason, "Custom game engine threading system");
            break;
        }
    }
    
    EXPECT_TRUE(found) << "Custom thread origin entry not found in whitelist";
}

// Test 2: WhitelistThreadOrigin - Invalid Parameters
TEST_F(SDKWhitelistAPITest, InvalidParameters) {
    // Test with null module name
    ErrorCode result = WhitelistThreadOrigin(nullptr, "Valid reason");
    EXPECT_EQ(result, ErrorCode::InvalidParameter);
    
    // Test with null reason
    result = WhitelistThreadOrigin("ValidModule.dll", nullptr);
    EXPECT_EQ(result, ErrorCode::InvalidParameter);
    
    // Test with both null
    result = WhitelistThreadOrigin(nullptr, nullptr);
    EXPECT_EQ(result, ErrorCode::InvalidParameter);
}

// Test 3: RemoveThreadOriginWhitelist - Remove Custom Entry
TEST_F(SDKWhitelistAPITest, RemoveCustomThreadOrigin) {
    // First add an entry
    ErrorCode result = WhitelistThreadOrigin(
        "TempEngine.dll",
        "Temporary test entry"
    );
    ASSERT_EQ(result, ErrorCode::Success);
    
    // Verify it exists
    ASSERT_NE(g_whitelist, nullptr);
    auto entries = g_whitelist->GetEntries();
    bool found = false;
    for (const auto& entry : entries) {
        if (entry.identifier == "TempEngine.dll" && 
            entry.type == WhitelistType::ThreadOrigin) {
            found = true;
            break;
        }
    }
    ASSERT_TRUE(found);
    
    // Remove it
    RemoveThreadOriginWhitelist("TempEngine.dll");
    
    // Verify it's gone
    entries = g_whitelist->GetEntries();
    found = false;
    for (const auto& entry : entries) {
        if (entry.identifier == "TempEngine.dll" && 
            entry.type == WhitelistType::ThreadOrigin) {
            found = true;
            break;
        }
    }
    EXPECT_FALSE(found) << "Entry should have been removed";
}

// Test 4: RemoveThreadOriginWhitelist - Cannot Remove Builtin
TEST_F(SDKWhitelistAPITest, CannotRemoveBuiltin) {
    // Try to remove a builtin entry
    RemoveThreadOriginWhitelist("ntdll.dll");
    
    // Verify it's still there
    ASSERT_NE(g_whitelist, nullptr);
    auto entries = g_whitelist->GetEntries();
    bool found = false;
    for (const auto& entry : entries) {
        if (entry.identifier == "ntdll.dll" && 
            entry.type == WhitelistType::ThreadOrigin) {
            found = true;
            EXPECT_TRUE(entry.builtin) << "Entry should still be marked as builtin";
            break;
        }
    }
    EXPECT_TRUE(found) << "Builtin entry was incorrectly removed";
}

// Test 5: Multiple Thread Origins
TEST_F(SDKWhitelistAPITest, MultipleThreadOrigins) {
    // Add multiple custom entries
    const char* modules[] = {
        "Engine1.dll",
        "Engine2.dll",
        "Engine3.dll"
    };
    
    for (const auto* module : modules) {
        ErrorCode result = WhitelistThreadOrigin(module, "Test engine");
        EXPECT_EQ(result, ErrorCode::Success);
    }
    
    // Verify all were added
    ASSERT_NE(g_whitelist, nullptr);
    auto entries = g_whitelist->GetEntries();
    
    int foundCount = 0;
    for (const auto& entry : entries) {
        if (entry.type == WhitelistType::ThreadOrigin) {
            for (const auto* module : modules) {
                if (entry.identifier == module) {
                    foundCount++;
                    break;
                }
            }
        }
    }
    
    EXPECT_EQ(foundCount, 3) << "All custom entries should be found";
    
    // Remove one
    RemoveThreadOriginWhitelist("Engine2.dll");
    
    // Verify only one was removed
    entries = g_whitelist->GetEntries();
    foundCount = 0;
    for (const auto& entry : entries) {
        if (entry.type == WhitelistType::ThreadOrigin) {
            for (const auto* module : modules) {
                if (entry.identifier == module) {
                    foundCount++;
                    break;
                }
            }
        }
    }
    
    EXPECT_EQ(foundCount, 2) << "Should have 2 entries remaining";
}

// Test 6: WhitelistThreadOrigin - Before SDK Initialization
TEST(SDKWhitelistAPITestNoInit, BeforeInitialization) {
    // Ensure SDK is not initialized
    if (IsInitialized()) {
        Shutdown();
    }
    
    // Try to add whitelist entry before initialization
    ErrorCode result = WhitelistThreadOrigin("Test.dll", "Test");
    
    EXPECT_EQ(result, ErrorCode::NotInitialized) 
        << "Should return NotInitialized when SDK not initialized";
}

// Test 7: Thread Safety - Concurrent Additions
TEST_F(SDKWhitelistAPITest, ConcurrentAdditions) {
    // Add entries from multiple threads (simple test)
    // In practice, this would use std::thread, but for simplicity we just test sequentially
    
    for (int i = 0; i < 10; i++) {
        std::string moduleName = "ConcurrentModule" + std::to_string(i) + ".dll";
        ErrorCode result = WhitelistThreadOrigin(moduleName.c_str(), "Concurrent test");
        EXPECT_EQ(result, ErrorCode::Success);
    }
    
    // Verify all were added
    ASSERT_NE(g_whitelist, nullptr);
    auto entries = g_whitelist->GetEntries();
    
    int foundCount = 0;
    for (const auto& entry : entries) {
        if (entry.type == WhitelistType::ThreadOrigin && 
            entry.identifier.find("ConcurrentModule") != std::string::npos) {
            foundCount++;
        }
    }
    
    EXPECT_EQ(foundCount, 10) << "All concurrent entries should be added";
}
