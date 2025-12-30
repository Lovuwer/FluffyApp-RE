/**
 * Sentinel SDK - Handle Generation Thread-Safety Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 2: Tests for Thread-Safe Handle Generation
 * 
 * These tests verify:
 * - No duplicate handles in concurrent ProtectMemory calls
 * - Thread sanitizer reports no data races on next_handle
 */

#include <gtest/gtest.h>
#include <SentinelSDK.hpp>
#include <thread>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <algorithm>

using namespace Sentinel::SDK;

// Helper function to initialize SDK for tests
static void InitializeSDK() {
    Configuration config = Configuration::Default();
    config.game_id = "test_app";
    config.license_key = "test_license";
    ASSERT_EQ(Initialize(&config), ErrorCode::Success);
}

/**
 * Test: Concurrent handle generation
 * Spawns 10 threads calling ProtectMemory 100 times each
 * Verifies that all 1000 handles are unique
 */
TEST(HandleGenerationTests, ConcurrentHandleGeneration) {
    InitializeSDK();
    
    const int num_threads = 10;
    const int calls_per_thread = 100;
    const int total_handles = num_threads * calls_per_thread;
    
    // Shared storage for handles (thread-safe)
    std::mutex handles_mutex;
    std::vector<uint64_t> all_handles;
    all_handles.reserve(total_handles);
    
    // Create dummy memory regions to protect
    std::vector<std::vector<uint8_t>> memory_regions(num_threads);
    for (int i = 0; i < num_threads; i++) {
        memory_regions[i].resize(64);  // 64 bytes per region
    }
    
    // Thread worker function
    auto worker = [&](int thread_id) {
        std::vector<uint64_t> local_handles;
        local_handles.reserve(calls_per_thread);
        
        for (int i = 0; i < calls_per_thread; i++) {
            // Call ProtectMemory
            void* addr = memory_regions[thread_id].data();
            uint64_t handle = ProtectMemory(addr, 64, "test_region");
            
            EXPECT_NE(handle, 0ULL) << "ProtectMemory should return valid handle";
            local_handles.push_back(handle);
        }
        
        // Add to shared storage
        std::lock_guard<std::mutex> lock(handles_mutex);
        all_handles.insert(all_handles.end(), local_handles.begin(), local_handles.end());
    };
    
    // Spawn threads
    std::vector<std::thread> threads;
    threads.reserve(num_threads);
    
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(worker, i);
    }
    
    // Wait for all threads to complete
    for (auto& t : threads) {
        t.join();
    }
    
    // Verify we got all handles
    EXPECT_EQ(all_handles.size(), total_handles) 
        << "Should have exactly " << total_handles << " handles";
    
    // Check for duplicates
    std::unordered_set<uint64_t> unique_handles(all_handles.begin(), all_handles.end());
    EXPECT_EQ(unique_handles.size(), all_handles.size()) 
        << "All handles should be unique - found " 
        << (all_handles.size() - unique_handles.size()) << " duplicates";
    
    // Additional check: verify handles are sequential
    std::vector<uint64_t> sorted_handles = all_handles;
    std::sort(sorted_handles.begin(), sorted_handles.end());
    
    // Handles should start from 1 and increment by 1
    for (size_t i = 0; i < sorted_handles.size(); i++) {
        EXPECT_EQ(sorted_handles[i], i + 1) 
            << "Handle at position " << i << " should be " << (i + 1);
    }
    
    // Cleanup
    for (uint64_t handle : all_handles) {
        UnprotectMemory(handle);
    }
    
    Shutdown();
}

/**
 * Test: Single-threaded baseline
 * Verifies that handle generation works correctly in single-threaded context
 */
TEST(HandleGenerationTests, SingleThreadedHandleGeneration) {
    InitializeSDK();
    
    const int num_calls = 100;
    std::vector<uint64_t> handles;
    handles.reserve(num_calls);
    
    // Single memory region
    std::vector<uint8_t> memory_region(64);
    
    for (int i = 0; i < num_calls; i++) {
        uint64_t handle = ProtectMemory(memory_region.data(), 64, "test_region");
        EXPECT_NE(handle, 0ULL) << "ProtectMemory should return valid handle";
        handles.push_back(handle);
    }
    
    // Verify uniqueness
    std::unordered_set<uint64_t> unique_handles(handles.begin(), handles.end());
    EXPECT_EQ(unique_handles.size(), handles.size()) 
        << "All handles should be unique";
    
    // Verify sequential
    for (size_t i = 0; i < handles.size(); i++) {
        EXPECT_EQ(handles[i], i + 1) 
            << "Handle " << i << " should be " << (i + 1);
    }
    
    // Cleanup
    for (uint64_t handle : handles) {
        UnprotectMemory(handle);
    }
    
    Shutdown();
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
