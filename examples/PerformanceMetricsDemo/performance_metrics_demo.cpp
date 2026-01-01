/**
 * Sentinel SDK - Performance Metrics Demo
 * 
 * Demonstrates how to collect and display SDK performance metrics
 * in real-time, showing P50/P95/P99 latencies and throttling status.
 * 
 * This example showcases:
 * - Automatic performance telemetry collection
 * - Real-time metrics retrieval
 * - Performance alert monitoring
 * - Self-throttling behavior
 * - Dashboard-style output formatting
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "SentinelSDK.hpp"
#include "Internal/PerfTelemetry.hpp"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cmath>

using namespace Sentinel::SDK;

/**
 * ANSI color codes for terminal output
 */
namespace Color {
    const char* Reset = "\033[0m";
    const char* Bold = "\033[1m";
    const char* Green = "\033[32m";
    const char* Yellow = "\033[33m";
    const char* Red = "\033[31m";
    const char* Cyan = "\033[36m";
    const char* Gray = "\033[90m";
}

/**
 * Format time in milliseconds with color coding based on threshold
 */
std::string FormatLatency(double ms, double threshold_ms) {
    std::ostringstream oss;
    
    // Color code based on threshold
    if (ms > threshold_ms) {
        oss << Color::Red;
    } else if (ms > threshold_ms * 0.8) {
        oss << Color::Yellow;
    } else {
        oss << Color::Green;
    }
    
    oss << std::fixed << std::setprecision(2) << ms << "ms" << Color::Reset;
    return oss.str();
}

/**
 * Display a simple ASCII-art dashboard for performance metrics
 */
void DisplayPerformanceDashboard(PerformanceTelemetry* perf_telemetry) {
    // Clear screen (ANSI escape code)
    std::cout << "\033[2J\033[1;1H";
    
    // Header
    std::cout << Color::Bold << Color::Cyan 
              << "┌─────────────────────────────────────────────────────────────────────────┐\n"
              << "│" << std::setw(40) << "Sentinel SDK Performance Dashboard" << std::setw(35) << "│\n"
              << "├─────────────────────────────────────────────────────────────────────────┤"
              << Color::Reset << "\n";
    
    // Get all metrics
    auto all_metrics = perf_telemetry->GetAllMetrics();
    
    // Calculate overall health status
    bool has_throttled = false;
    bool has_warnings = false;
    
    for (const auto& metrics : all_metrics) {
        if (metrics.is_throttled) has_throttled = true;
        if (metrics.current_window.p95_ms > 5.0) has_warnings = true;
    }
    
    // Health status
    std::cout << "│ Overall Health: ";
    if (has_throttled) {
        std::cout << Color::Yellow << "⚠ THROTTLED" << Color::Reset;
    } else if (has_warnings) {
        std::cout << Color::Yellow << "⚠ WARNING" << Color::Reset;
    } else {
        std::cout << Color::Green << "✓ HEALTHY" << Color::Reset;
    }
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::cout << std::string(26, ' ') 
              << "Last Update: " << std::put_time(std::localtime(&time_t), "%H:%M:%S")
              << " │\n";
    std::cout << "├─────────────────────────────────────────────────────────────────────────┤\n";
    
    // Table header
    std::cout << "│ " << Color::Bold 
              << std::left << std::setw(16) << "Operation"
              << std::right << std::setw(9) << "P50" 
              << std::setw(9) << "P95"
              << std::setw(9) << "P99"
              << std::setw(10) << "Calls"
              << std::setw(12) << "Throttled"
              << Color::Reset << " │\n";
    std::cout << "├─────────────────────────────────────────────────────────────────────────┤\n";
    
    // Display metrics for each operation
    for (const auto& metrics : all_metrics) {
        if (metrics.total_operations == 0) continue;  // Skip unused operations
        
        std::string op_name = PerformanceTelemetry::GetOperationName(metrics.operation);
        
        std::cout << "│ " << std::left << std::setw(16) << op_name;
        
        // P50
        std::cout << std::right << std::setw(9);
        if (metrics.current_window.sample_count > 0) {
            std::cout << FormatLatency(metrics.current_window.p50_ms, 2.5);
        } else {
            std::cout << Color::Gray << "-" << Color::Reset;
        }
        
        // P95
        std::cout << std::setw(9);
        if (metrics.current_window.sample_count > 0) {
            std::cout << FormatLatency(metrics.current_window.p95_ms, 5.0);
        } else {
            std::cout << Color::Gray << "-" << Color::Reset;
        }
        
        // P99
        std::cout << std::setw(9);
        if (metrics.current_window.sample_count > 0) {
            std::cout << FormatLatency(metrics.current_window.p99_ms, 10.0);
        } else {
            std::cout << Color::Gray << "-" << Color::Reset;
        }
        
        // Total calls
        std::cout << std::setw(10);
        if (metrics.total_operations >= 1000) {
            std::cout << (metrics.total_operations / 1000) << "K";
        } else {
            std::cout << metrics.total_operations;
        }
        
        // Throttled percentage
        std::cout << std::setw(12);
        if (metrics.is_throttled) {
            double throttle_pct = (metrics.throttled_operations * 100.0) / 
                                 std::max(static_cast<uint64_t>(1), metrics.total_operations);
            std::cout << Color::Yellow << std::fixed << std::setprecision(1) 
                      << throttle_pct << "%" << Color::Reset;
        } else {
            std::cout << Color::Green << "0%" << Color::Reset;
        }
        
        std::cout << " │\n";
    }
    
    std::cout << "├─────────────────────────────────────────────────────────────────────────┤\n";
    
    // Performance alerts
    auto alerts = perf_telemetry->GetAlerts();
    
    std::cout << "│ " << Color::Bold << "Performance Alerts (Recent)" 
              << Color::Reset << std::string(44, ' ') << "│\n";
    std::cout << "├─────────────────────────────────────────────────────────────────────────┤\n";
    
    if (alerts.empty()) {
        std::cout << "│ " << Color::Green << "✓ No alerts in the current window" 
                  << Color::Reset << std::string(37, ' ') << "│\n";
    } else {
        // Show up to 3 most recent alerts
        int count = 0;
        for (auto it = alerts.rbegin(); it != alerts.rend() && count < 3; ++it, ++count) {
            const auto& alert = *it;
            
            std::cout << "│ " << (alert.is_p95 ? Color::Yellow : Color::Red) 
                      << (alert.is_p95 ? "⚠️ " : "🔴");
            
            std::cout << alert.operation_name << " "
                      << (alert.is_p95 ? "P95" : "P99") << " exceeded: "
                      << std::fixed << std::setprecision(2) << alert.measured_latency_ms 
                      << "ms (>" << alert.threshold_ms << "ms)"
                      << Color::Reset;
            
            // Pad to 70 characters
            int padding = 70 - (alert.operation_name.length() + 30);
            std::cout << std::string(std::max(0, padding), ' ') << "│\n";
        }
    }
    
    std::cout << "└─────────────────────────────────────────────────────────────────────────┘\n";
    std::cout << Color::Gray << "Press Ctrl+C to exit..." << Color::Reset << std::endl;
}

/**
 * Simulate game workload with varying performance characteristics
 */
void SimulateGameWorkload(int iteration) {
    // Simulate different performance scenarios
    
    // Every 10 iterations, inject a performance spike
    if (iteration % 10 == 0) {
        std::this_thread::sleep_for(std::chrono::microseconds(500));
    }
    
    // Normal workload variation
    int base_work = 100 + (iteration % 50);
    volatile int dummy = 0;
    for (int i = 0; i < base_work; ++i) {
        dummy += i * i;
    }
}

/**
 * Main demonstration
 */
int main() {
    std::cout << Color::Bold << Color::Cyan 
              << "\n=== Sentinel SDK Performance Metrics Demo ===\n" 
              << Color::Reset << std::endl;
    
    // Initialize SDK
    std::cout << "Initializing Sentinel SDK...\n";
    
    Configuration config = Configuration::Default();
    config.license_key = "DEMO-LICENSE-KEY-12345";
    config.game_id = "performance-demo";
    config.features = DetectionFeatures::Standard;
    config.debug_mode = false;
    
    auto result = Initialize(&config);
    if (result != ErrorCode::Success) {
        std::cerr << "Failed to initialize SDK: " << static_cast<int>(result) << std::endl;
        return 1;
    }
    
    std::cout << Color::Green << "✓ SDK initialized successfully\n" << Color::Reset;
    std::cout << "\nStarting performance monitoring...\n";
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Create performance telemetry instance for demonstration
    // Note: In production, this is managed internally by the SDK
    PerformanceTelemetry demo_telemetry;
    PerfTelemetryConfig perf_config = PerfTelemetryConfig::Default();
    perf_config.p95_threshold_ms = 5.0;
    perf_config.p99_threshold_ms = 10.0;
    perf_config.enable_self_throttling = true;
    perf_config.window_size = 100;  // Smaller window for demo
    demo_telemetry.Initialize(perf_config);
    
    // Simulate game loop with performance monitoring
    int iteration = 0;
    auto last_dashboard_update = std::chrono::steady_clock::now();
    
    while (iteration < 500) {  // Run for 500 iterations
        auto frame_start = std::chrono::high_resolution_clock::now();
        
        // Simulate Update() call
        Update();
        SimulateGameWorkload(iteration);
        
        auto frame_end = std::chrono::high_resolution_clock::now();
        auto frame_time_us = std::chrono::duration_cast<std::chrono::microseconds>(
            frame_end - frame_start).count();
        double frame_time_ms = frame_time_us / 1000.0;
        
        // Record performance for demo telemetry
        demo_telemetry.RecordOperation(OperationType::Update, frame_time_ms);
        
        // Periodically record other operations
        if (iteration % 5 == 0) {
            demo_telemetry.RecordOperation(OperationType::VerifyMemory, 0.5 + (rand() % 100) / 100.0);
        }
        
        if (iteration % 20 == 0) {
            demo_telemetry.RecordOperation(OperationType::FullScan, 15.0 + (rand() % 1000) / 100.0);
        }
        
        // Update dashboard every second
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_dashboard_update).count() >= 1000) {
            
            DisplayPerformanceDashboard(&demo_telemetry);
            last_dashboard_update = now;
        }
        
        iteration++;
        
        // Frame limiting (simulate 60 FPS)
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    
    // Final dashboard
    DisplayPerformanceDashboard(&demo_telemetry);
    
    std::cout << "\n" << Color::Cyan << "Demo complete!" << Color::Reset << "\n";
    std::cout << "This demonstration showed:\n";
    std::cout << "  ✓ Real-time performance metric collection\n";
    std::cout << "  ✓ P50/P95/P99 percentile tracking\n";
    std::cout << "  ✓ Performance alert generation\n";
    std::cout << "  ✓ Self-throttling mechanism\n";
    std::cout << "  ✓ Dashboard-style visualization\n\n";
    
    // Cleanup
    demo_telemetry.Shutdown();
    Shutdown();
    
    std::cout << Color::Green << "✓ SDK shutdown successfully\n" << Color::Reset;
    
    return 0;
}
