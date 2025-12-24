/**
 * Sentinel SDK - Test Main
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include <SentinelSDK.hpp>

// Basic SDK tests

TEST(SDKTests, VersionCheck) {
    const char* version = Sentinel::SDK::GetVersion();
    EXPECT_STREQ(version, "1.0.0");
}

TEST(SDKTests, NotInitializedByDefault) {
    // SDK should not be initialized by default
    EXPECT_FALSE(Sentinel::SDK::IsInitialized());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
