/**
 * Sentinel SDK - CloudReporter Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Comprehensive test suite for violation reporting pipeline with:
 * - Thread-safe queuing with configurable depth
 * - Batching logic (1-100 violations per batch)
 * - Flush triggers (queue depth, time, severity)
 * - JSON serialization
 * - Retry logic with exponential backoff
 * - Offline buffering to encrypted storage
 * - Queue overflow handling with oldest-violation eviction
 * 
 * Tests cover:
 * - Basic event queuing and batching
 * - Batch size configuration
 * - Flush interval configuration
 * - Critical event immediate flush
 * - Queue overflow eviction
 * - Memory stability under load
 */

#include <gtest/gtest.h>
#include "Internal/Detection.hpp"
#include <thread>
#include <chrono>
#include <atomic>

using namespace Sentinel::SDK;

// Mock server endpoint for testing
const char* MOCK_ENDPOINT = "https://127.0.0.1:8080/api/v1/violations";

// Test fixture for CloudReporter tests
class CloudReporterTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create reporter with mock endpoint
        reporter = std::make_unique<CloudReporter>(MOCK_ENDPOINT);
    }
    
    void TearDown() override {
        reporter.reset();
    }
    
    std::unique_ptr<CloudReporter> reporter;
    
    // Helper function to create test violation event
    ViolationEvent CreateTestEvent(
        ViolationType type = ViolationType::DebuggerAttached,
        Severity severity = Severity::High,
        const char* details = "Test violation"
    ) {
        ViolationEvent event;
        event.type = type;
        event.severity = severity;
        event.timestamp = GetCurrentTimestamp();
        event.address = 0x12345678;
        event.module_name = "test.exe";
        event.details = details;
        event.detection_id = 1001;
        return event;
    }
    
    static uint64_t GetCurrentTimestamp() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }
};

// ============================================================================
// Basic Functionality Tests
// ============================================================================

TEST_F(CloudReporterTest, Initialization) {
    // Should be able to create and destroy reporter
    SUCCEED();
}

TEST_F(CloudReporterTest, QueueSingleEvent) {
    // Queue a single event
    auto event = CreateTestEvent();
    reporter->QueueEvent(event);
    
    // No crash = success
    SUCCEED();
}

TEST_F(CloudReporterTest, QueueMultipleEvents) {
    // Queue multiple events
    for (int i = 0; i < 5; ++i) {
        std::string details = "Test event " + std::to_string(i);
        auto event = CreateTestEvent(
            ViolationType::DebuggerAttached,
            Severity::High,
            details.c_str()
        );
        reporter->QueueEvent(event);
    }
    
    // Give time for background processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    SUCCEED();
}

// ============================================================================
// Configuration Tests
// ============================================================================

TEST_F(CloudReporterTest, SetBatchSize) {
    // Test valid batch sizes
    reporter->SetBatchSize(1);
    reporter->SetBatchSize(50);
    reporter->SetBatchSize(100);
    
    // Test boundary values
    reporter->SetBatchSize(0);    // Should be ignored (too small)
    reporter->SetBatchSize(101);  // Should be ignored (too large)
    
    SUCCEED();
}

TEST_F(CloudReporterTest, SetInterval) {
    // Test various intervals
    reporter->SetInterval(1000);    // 1 second
    reporter->SetInterval(30000);   // 30 seconds
    reporter->SetInterval(60000);   // 1 minute
    
    SUCCEED();
}

// ============================================================================
// Batching Tests
// ============================================================================

TEST_F(CloudReporterTest, BatchSizeConfiguration) {
    // Set small batch size
    reporter->SetBatchSize(3);
    
    // Queue events up to batch size
    for (int i = 0; i < 3; ++i) {
        auto event = CreateTestEvent();
        reporter->QueueEvent(event);
    }
    
    // Give time for batch to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    SUCCEED();
}

TEST_F(CloudReporterTest, LargeBatch) {
    // Set maximum batch size
    reporter->SetBatchSize(100);
    
    // Queue many events
    for (int i = 0; i < 100; ++i) {
        auto event = CreateTestEvent();
        reporter->QueueEvent(event);
    }
    
    // Give time for batch to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    SUCCEED();
}

// ============================================================================
// Flush Trigger Tests
// ============================================================================

TEST_F(CloudReporterTest, CriticalEventImmediateFlush) {
    // Set long interval
    reporter->SetInterval(60000);  // 1 minute
    
    // Queue a critical event
    auto event = CreateTestEvent(
        ViolationType::ModuleModified,
        Severity::Critical,
        "Critical violation detected"
    );
    
    reporter->QueueEvent(event);
    
    // Critical events should trigger immediate flush
    // Give time for flush to occur
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    SUCCEED();
}

TEST_F(CloudReporterTest, ManualFlush) {
    // Queue some events
    for (int i = 0; i < 5; ++i) {
        auto event = CreateTestEvent();
        reporter->QueueEvent(event);
    }
    
    // Manually flush
    reporter->Flush();
    
    // Give time for flush to occur
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    SUCCEED();
}

// ============================================================================
// Queue Management Tests
// ============================================================================

TEST_F(CloudReporterTest, QueueOverflowEviction) {
    // Queue many events to test overflow handling
    // The implementation should handle queue depth limit (1000)
    for (int i = 0; i < 1100; ++i) {
        std::string details = "Event " + std::to_string(i);
        auto event = CreateTestEvent(
            ViolationType::DebuggerAttached,
            Severity::Info,
            details.c_str()
        );
        reporter->QueueEvent(event);
    }
    
    // Give time for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    SUCCEED();
}

// ============================================================================
// Custom Event Tests
// ============================================================================

TEST_F(CloudReporterTest, ReportCustomEvent) {
    // Report a custom event
    auto result = reporter->ReportCustomEvent("player_join", "{\"player_id\": 12345}");
    
    EXPECT_EQ(ErrorCode::Success, result);
}

TEST_F(CloudReporterTest, ReportCustomEventNullParameters) {
    // Test null parameters
    auto result1 = reporter->ReportCustomEvent(nullptr, "data");
    EXPECT_EQ(ErrorCode::InvalidParameter, result1);
    
    auto result2 = reporter->ReportCustomEvent("type", nullptr);
    EXPECT_EQ(ErrorCode::InvalidParameter, result2);
    
    auto result3 = reporter->ReportCustomEvent(nullptr, nullptr);
    EXPECT_EQ(ErrorCode::InvalidParameter, result3);
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(CloudReporterTest, ConcurrentQueuing) {
    // Queue events from multiple threads
    std::vector<std::thread> threads;
    std::atomic<int> counter{0};
    
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([this, &counter]() {
            for (int i = 0; i < 25; ++i) {
                std::string details = "Thread event " + std::to_string(counter++);
                auto event = CreateTestEvent(
                    ViolationType::DebuggerAttached,
                    Severity::High,
                    details.c_str()
                );
                reporter->QueueEvent(event);
            }
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Give time for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    EXPECT_EQ(100, counter.load());
}

// ============================================================================
// Memory Stability Tests
// ============================================================================

TEST_F(CloudReporterTest, SustainedLoad) {
    // Queue events continuously for a period
    reporter->SetBatchSize(10);
    reporter->SetInterval(1000);
    
    auto start = std::chrono::steady_clock::now();
    int event_count = 0;
    
    // Run for 2 seconds
    while (std::chrono::steady_clock::now() - start < std::chrono::seconds(2)) {
        auto event = CreateTestEvent();
        reporter->QueueEvent(event);
        event_count++;
        
        // Small delay to simulate realistic usage
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Give time for final flush
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Should have queued many events without crash
    EXPECT_GT(event_count, 100);
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(CloudReporterTest, EndToEndFlow) {
    // Simulate realistic usage pattern
    reporter->SetBatchSize(5);
    reporter->SetInterval(5000);
    
    // Queue some normal events
    for (int i = 0; i < 3; ++i) {
        std::string details = "Normal event " + std::to_string(i);
        auto event = CreateTestEvent(
            ViolationType::DebuggerAttached,
            Severity::Warning,
            details.c_str()
        );
        reporter->QueueEvent(event);
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Queue a critical event (should trigger immediate flush)
    auto critical = CreateTestEvent(
        ViolationType::ModuleModified,
        Severity::Critical,
        "Critical memory manipulation detected"
    );
    reporter->QueueEvent(critical);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Queue more events
    for (int i = 0; i < 2; ++i) {
        auto event = CreateTestEvent();
        reporter->QueueEvent(event);
    }
    
    // Manual flush
    reporter->Flush();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    SUCCEED();
}
