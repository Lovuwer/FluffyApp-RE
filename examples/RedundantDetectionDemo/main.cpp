/**
 * Sentinel SDK - Redundant Detection Example
 * 
 * Task 29: Demonstrates how to use redundant detection architecture
 * 
 * This example shows how to:
 * - Enable redundant detection for specific categories
 * - Query redundancy configuration
 * - Monitor performance statistics
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <SentinelSDK.hpp>
#include <stdio.h>

using namespace Sentinel::SDK;

int main() {
    printf("=== Sentinel SDK Redundant Detection Example ===\n\n");
    
    // Step 1: Initialize SDK with standard configuration
    Configuration config = Configuration::Default();
    config.license_key = "demo-license-key";
    config.game_id = "redundancy-demo";
    config.features = DetectionFeatures::Standard;
    config.debug_mode = true;
    
    printf("Initializing Sentinel SDK...\n");
    ErrorCode result = Initialize(&config);
    if (result != ErrorCode::Success) {
        fprintf(stderr, "Failed to initialize SDK\n");
        return -1;
    }
    printf("SDK initialized successfully\n\n");
    
    // Step 2: Check current redundancy configuration
    printf("=== Checking Default Redundancy Configuration ===\n");
    
    // AntiDebug is registered with 2 implementations but disabled by default
    uint8_t antidebug_category = static_cast<uint8_t>(DetectionType::AntiDebug);
    
    RedundancyLevel level = GetRedundancy(antidebug_category);
    uint32_t impl_count = GetImplementationCount(antidebug_category);
    
    printf("AntiDebug Category:\n");
    printf("  Available implementations: %u\n", impl_count);
    printf("  Current redundancy level: %s\n", 
           level == RedundancyLevel::None ? "None (disabled)" :
           level == RedundancyLevel::Standard ? "Standard" :
           level == RedundancyLevel::High ? "High" : "Maximum");
    printf("\n");
    
    // Step 3: Run detections with redundancy disabled (baseline)
    printf("=== Running Baseline Detection (Redundancy Disabled) ===\n");
    
    Update();
    FullScan();
    
    RedundancyStatistics stats_baseline;
    if (GetRedundancyStatistics(antidebug_category, &stats_baseline)) {
        printf("Baseline Stats:\n");
        printf("  Active implementations: %u\n", stats_baseline.active_implementations);
        printf("  Total checks performed: %u\n", stats_baseline.total_checks_performed);
        printf("  Unique violations: %u\n", stats_baseline.unique_violations_detected);
        printf("  Average overhead: %.2f µs\n", stats_baseline.avg_overhead_us);
    }
    printf("\n");
    
    // Step 4: Enable redundancy at Standard level
    printf("=== Enabling Redundant Detection ===\n");
    
    ErrorCode set_result = SetRedundancy(antidebug_category, RedundancyLevel::Standard);
    if (set_result == ErrorCode::Success) {
        printf("Redundancy enabled successfully\n");
        
        level = GetRedundancy(antidebug_category);
        printf("New redundancy level: %s\n", 
               level == RedundancyLevel::Standard ? "Standard (2 implementations)" : "Unknown");
    } else {
        fprintf(stderr, "Failed to enable redundancy\n");
    }
    printf("\n");
    
    // Step 5: Run detections with redundancy enabled
    printf("=== Running Detection with Redundancy Enabled ===\n");
    
    Update();
    FullScan();
    
    RedundancyStatistics stats_redundant;
    if (GetRedundancyStatistics(antidebug_category, &stats_redundant)) {
        printf("Redundant Stats:\n");
        printf("  Active implementations: %u\n", stats_redundant.active_implementations);
        printf("  Total checks performed: %u\n", stats_redundant.total_checks_performed);
        printf("  Unique violations: %u\n", stats_redundant.unique_violations_detected);
        printf("  Duplicate violations filtered: %u\n", stats_redundant.duplicate_violations_filtered);
        printf("  Average overhead: %.2f µs\n", stats_redundant.avg_overhead_us);
        printf("  Maximum overhead: %.2f µs\n", stats_redundant.max_overhead_us);
    }
    printf("\n");
    
    // Step 6: Compare overhead
    if (stats_redundant.avg_overhead_us > 0) {
        float overhead_increase = stats_redundant.avg_overhead_us - stats_baseline.avg_overhead_us;
        printf("Performance Impact:\n");
        printf("  Baseline overhead: %.2f µs\n", stats_baseline.avg_overhead_us);
        printf("  Redundant overhead: %.2f µs\n", stats_redundant.avg_overhead_us);
        printf("  Additional cost: %.2f µs (%.1f%% increase)\n", 
               overhead_increase,
               stats_baseline.avg_overhead_us > 0 ? 
                   (overhead_increase / stats_baseline.avg_overhead_us * 100.0f) : 0.0f);
    } else {
        printf("Note: Overhead measurements < 1 µs (too fast to measure accurately)\n");
    }
    printf("\n");
    
    // Step 7: Demonstrate different redundancy levels
    printf("=== Testing Different Redundancy Levels ===\n");
    
    const char* level_names[] = {"None", "Standard", "High", "Maximum"};
    RedundancyLevel levels[] = {
        RedundancyLevel::None,
        RedundancyLevel::Standard,
        RedundancyLevel::High,
        RedundancyLevel::Maximum
    };
    
    for (int i = 0; i < 4; i++) {
        SetRedundancy(antidebug_category, levels[i]);
        Update();
        
        RedundancyStatistics level_stats;
        if (GetRedundancyStatistics(antidebug_category, &level_stats)) {
            printf("%s Level: %u implementations active\n", 
                   level_names[i], level_stats.active_implementations);
        }
    }
    printf("\n");
    
    // Step 8: Cleanup
    printf("Shutting down SDK...\n");
    Shutdown();
    
    printf("\n=== Example Complete ===\n");
    printf("\nKey Takeaways:\n");
    printf("- Redundancy is disabled by default (opt-in)\n");
    printf("- Standard level uses 2 implementations with different approaches\n");
    printf("- Overhead is minimal (typically < 10 µs per check)\n");
    printf("- Violation deduplication prevents duplicate reports\n");
    printf("- Configure per detection category based on risk assessment\n");
    
    return 0;
}
