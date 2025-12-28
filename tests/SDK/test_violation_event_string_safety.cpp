/**
 * Sentinel SDK - ViolationEvent String Safety Tests
 * 
 * Task 6: Tests to ensure ViolationEvent strings are owned copies,
 * preventing use-after-free vulnerabilities after DLL unload.
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "SentinelSDK.hpp"
#include <string>
#include <cstring>

using namespace Sentinel::SDK;

/**
 * Test: ViolationEvent strings are owned copies
 * Verifies that strings in ViolationEvent are deep copies, not pointers
 * to external data that could become invalid.
 */
TEST(ViolationEventStringTests, StringsAreOwnedCopies) {
    ViolationEvent event;
    
    // Create temporary strings in a scope that will be destroyed
    {
        std::string temp_details = "Temporary details string";
        std::string temp_module = "Temporary module name";
        
        // Assign from temporary strings
        event.details = temp_details;
        event.module_name = temp_module;
        
        // Modify the temp strings to verify event has its own copy
        temp_details = "Modified";
        temp_module = "Modified";
    }
    // temp_details and temp_module are now out of scope
    
    // Event should still have valid strings (owned copies)
    EXPECT_EQ(event.details, "Temporary details string");
    EXPECT_EQ(event.module_name, "Temporary module name");
}

/**
 * Test: ViolationEvent can be copied safely
 * Verifies that copying ViolationEvent creates independent copies
 * of the strings, not shared references.
 */
TEST(ViolationEventStringTests, CopiesAreSafe) {
    ViolationEvent event1;
    event1.type = ViolationType::DebuggerAttached;
    event1.severity = Severity::High;
    event1.details = "Original details";
    event1.module_name = "Original module";
    event1.timestamp = 12345;
    event1.address = 0xABCD;
    event1.detection_id = 999;
    
    // Copy construct
    ViolationEvent event2 = event1;
    
    // Modify original
    event1.details = "Modified details";
    event1.module_name = "Modified module";
    
    // Copy should be unchanged
    EXPECT_EQ(event2.details, "Original details");
    EXPECT_EQ(event2.module_name, "Original module");
    EXPECT_EQ(event2.type, ViolationType::DebuggerAttached);
    EXPECT_EQ(event2.severity, Severity::High);
    EXPECT_EQ(event2.timestamp, 12345u);
    EXPECT_EQ(event2.address, 0xABCDu);
    EXPECT_EQ(event2.detection_id, 999u);
}

/**
 * Test: ViolationEvent can be moved safely
 * Verifies that moving ViolationEvent transfers ownership properly.
 */
TEST(ViolationEventStringTests, MoveSemantics) {
    ViolationEvent event1;
    event1.details = "Movable details";
    event1.module_name = "Movable module";
    event1.type = ViolationType::InlineHook;
    
    // Move construct
    ViolationEvent event2 = std::move(event1);
    
    // event2 should have the strings
    EXPECT_EQ(event2.details, "Movable details");
    EXPECT_EQ(event2.module_name, "Movable module");
    EXPECT_EQ(event2.type, ViolationType::InlineHook);
    
    // event1 should be in a valid but unspecified state
    // We can still access it without crashing
    (void)event1.details;
    (void)event1.module_name;
}

/**
 * Test: Empty strings work correctly
 * Verifies that empty strings don't cause issues.
 */
TEST(ViolationEventStringTests, EmptyStringsWork) {
    ViolationEvent event;
    event.details = "";
    event.module_name = "";
    
    EXPECT_TRUE(event.details.empty());
    EXPECT_TRUE(event.module_name.empty());
    EXPECT_EQ(event.details.length(), 0u);
    EXPECT_EQ(event.module_name.length(), 0u);
}

/**
 * Test: String assignment from C string literals
 * Verifies that assigning from string literals creates owned copies.
 */
TEST(ViolationEventStringTests, LiteralAssignment) {
    ViolationEvent event;
    
    // Assign from string literals
    event.details = "Debugger detected";
    event.module_name = "kernel32.dll";
    
    // Should have created owned copies
    EXPECT_EQ(event.details, "Debugger detected");
    EXPECT_EQ(event.module_name, "kernel32.dll");
    
    // Length should be correct
    EXPECT_EQ(event.details.length(), strlen("Debugger detected"));
    EXPECT_EQ(event.module_name.length(), strlen("kernel32.dll"));
}

/**
 * Test: Long strings don't cause buffer overflow
 * Verifies that std::string handles long strings safely.
 */
TEST(ViolationEventStringTests, LongStringsAreSafe) {
    ViolationEvent event;
    
    // Create a very long string
    std::string long_details(1000, 'A');
    std::string long_module(500, 'B');
    
    event.details = long_details;
    event.module_name = long_module;
    
    // Should store full strings
    EXPECT_EQ(event.details.length(), 1000u);
    EXPECT_EQ(event.module_name.length(), 500u);
    EXPECT_EQ(event.details, long_details);
    EXPECT_EQ(event.module_name, long_module);
}

/**
 * Test: ViolationEvent in vector (simulating CloudReporter queue)
 * Verifies that ViolationEvents can be safely stored in containers.
 */
TEST(ViolationEventStringTests, VectorStorage) {
    std::vector<ViolationEvent> queue;
    
    // Add events with different strings
    for (int i = 0; i < 10; i++) {
        ViolationEvent event;
        event.details = "Event " + std::to_string(i);
        event.module_name = "Module " + std::to_string(i);
        queue.push_back(event);
    }
    
    // Verify all events have correct strings
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(queue[i].details, "Event " + std::to_string(i));
        EXPECT_EQ(queue[i].module_name, "Module " + std::to_string(i));
    }
    
    // Clear and verify no memory issues
    queue.clear();
    EXPECT_TRUE(queue.empty());
}

/**
 * Test: String lifetime outlives local scope
 * This test simulates the scenario where an event is created in a function
 * and then queued for later processing.
 */
TEST(ViolationEventStringTests, LifetimeOutlivesScope) {
    ViolationEvent event;
    
    // Simulate event creation in a function scope
    auto create_event = [](const char* msg) -> ViolationEvent {
        ViolationEvent evt;
        // Local string that will be destroyed when lambda returns
        std::string local_string = msg;
        evt.details = local_string;
        evt.module_name = "test.dll";
        return evt;  // Return by value
    };
    
    event = create_event("Test message");
    
    // Event strings should still be valid
    EXPECT_EQ(event.details, "Test message");
    EXPECT_EQ(event.module_name, "test.dll");
}
