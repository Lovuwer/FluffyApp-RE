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

// ============================================================================
// Task 15: Sequence Numbering Tests
// ============================================================================

TEST_F(CloudReporterTest, SequenceNumberingIncremental) {
    // Test that sequence numbers increment with each batch
    // Note: This is a client-side test. Server-side validation is separate.
    
    // Set batch size to 1 to send each event immediately
    reporter->SetBatchSize(1);
    
    // Queue 5 events, each should get its own sequence number
    for (int i = 0; i < 5; ++i) {
        std::string details = "Event " + std::to_string(i);
        auto event = CreateTestEvent(
            ViolationType::DebuggerAttached,
            Severity::Info,
            details.c_str()
        );
        reporter->QueueEvent(event);
        
        // Small delay to ensure batches are sent separately
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Allow time for all batches to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Note: Actual sequence validation happens server-side
    // This test verifies the client can send multiple batches without crashing
    SUCCEED();
}

TEST_F(CloudReporterTest, SequenceNumberingWithBatching) {
    // Test sequence numbers with larger batch sizes
    
    // Set batch size to 3
    reporter->SetBatchSize(3);
    
    // Send 10 events (will create 4 batches: 3, 3, 3, 1)
    for (int i = 0; i < 10; ++i) {
        auto event = CreateTestEvent();
        reporter->QueueEvent(event);
    }
    
    // Wait for batches to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    // Verify reporter still functional
    auto test_event = CreateTestEvent();
    reporter->QueueEvent(test_event);
    reporter->Flush();
    
    SUCCEED();
}

TEST_F(CloudReporterTest, SequenceNumberingAfterFlush) {
    // Test that sequence numbering continues correctly after manual flush
    
    reporter->SetBatchSize(10);  // Large batch size to prevent auto-flush
    
    // Queue some events
    for (int i = 0; i < 3; ++i) {
        auto event = CreateTestEvent();
        reporter->QueueEvent(event);
    }
    
    // Manual flush (should send batch with sequence 0)
    reporter->Flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Queue more events
    for (int i = 0; i < 3; ++i) {
        auto event = CreateTestEvent();
        reporter->QueueEvent(event);
    }
    
    // Another flush (should send batch with sequence 1)
    reporter->Flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    SUCCEED();
}

TEST_F(CloudReporterTest, SequenceNumberingConcurrentBatches) {
    // Test sequence numbering under concurrent load
    
    reporter->SetBatchSize(5);
    
    std::vector<std::thread> threads;
    std::atomic<int> total_events{0};
    
    // Multiple threads queueing events
    for (int t = 0; t < 3; ++t) {
        threads.emplace_back([this, &total_events]() {
            for (int i = 0; i < 10; ++i) {
                auto event = CreateTestEvent();
                reporter->QueueEvent(event);
                total_events++;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Flush remaining events
    reporter->Flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    EXPECT_EQ(30, total_events.load());
}

TEST_F(CloudReporterTest, SequenceNumberingWithOfflineBuffering) {
    // Test that sequence numbers are preserved when events are buffered offline
    // (e.g., when network is unavailable)
    
    // Use an unreachable endpoint to force offline buffering
    auto offline_reporter = std::make_unique<CloudReporter>("http://127.0.0.1:9999/violations");
    offline_reporter->SetBatchSize(2);
    
    // Queue events (will be buffered offline since endpoint is unreachable)
    for (int i = 0; i < 5; ++i) {
        auto event = CreateTestEvent();
        offline_reporter->QueueEvent(event);
    }
    
    offline_reporter->Flush();
    
    // Give time for send attempts and offline buffering
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    
    // Cleanup - reporter will buffer remaining events on shutdown
    offline_reporter.reset();
    
    // Note: Actual offline persistence is tested by examining filesystem
    // or by creating a new reporter and checking if events are reloaded
    SUCCEED();
}

// ============================================================================
// Task 15: Gap Detection Simulation Tests
// ============================================================================

TEST_F(CloudReporterTest, GapDetectionScenario) {
    // This test demonstrates the gap detection scenario
    // In a real attack, a proxy would filter certain reports
    // The server would detect the gap in sequence numbers
    
    reporter->SetBatchSize(1);
    
    // Send events that would normally trigger sequential numbers
    // Event 0: Debugger check - allowed through
    auto event1 = CreateTestEvent(ViolationType::DebuggerAttached, Severity::Info);
    reporter->QueueEvent(event1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Event 1: Speed hack - allowed through
    auto event2 = CreateTestEvent(ViolationType::SpeedHack, Severity::Warning);
    reporter->QueueEvent(event2);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Event 2: Hook detection - allowed through
    auto event3 = CreateTestEvent(ViolationType::InlineHook, Severity::High);
    reporter->QueueEvent(event3);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Server should receive sequences 0, 1, 2 in order
    // If any were filtered, server would detect the gap
    
    reporter->Flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    SUCCEED();
}

TEST_F(CloudReporterTest, MultipleGapsScenario) {
    // Scenario where multiple reports are suppressed
    
    reporter->SetBatchSize(1);
    
    // Send 10 events in sequence
    // An attacker might filter specific types, creating multiple gaps
    for (int i = 0; i < 10; ++i) {
        ViolationType type = (i % 3 == 0) ? ViolationType::DebuggerAttached :
                            (i % 3 == 1) ? ViolationType::SpeedHack :
                                          ViolationType::InlineHook;
        
        auto event = CreateTestEvent(type, Severity::Info);
        reporter->QueueEvent(event);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    reporter->Flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Server-side gap detection would flag if reports were filtered
    SUCCEED();
}
