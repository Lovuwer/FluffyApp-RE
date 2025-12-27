/**
 * Sentinel SDK - Speed Hack Detection Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Detects speed manipulation by cross-validating multiple independent time sources.
 */

#include "Internal/Detection.hpp"

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#endif

#include <chrono>
#include <cmath>

namespace Sentinel {
namespace SDK {

void SpeedHackDetector::Initialize() {
    UpdateBaseline();
}

void SpeedHackDetector::Shutdown() {
    // Nothing to clean up
}

uint64_t SpeedHackDetector::GetSystemTime() {
#ifdef _WIN32
    // GetTickCount64 - millisecond resolution
    return GetTickCount64();
#else
    // Linux fallback: use steady_clock
    auto now = std::chrono::steady_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
#endif
}

uint64_t SpeedHackDetector::GetPerformanceCounter() {
#ifdef _WIN32
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return counter.QuadPart;
#else
    // Linux fallback: use high_resolution_clock
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
#endif
}

uint64_t SpeedHackDetector::GetRDTSC() {
#ifdef _WIN32
    // CPU timestamp counter - cycle resolution
    return __rdtsc();
#else
    // Linux: use inline assembly
#ifdef __x86_64__
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    // Fallback for non-x86: use high_resolution_clock
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
#endif
#endif
}

void SpeedHackDetector::UpdateBaseline() {
    baseline_system_time_ = GetSystemTime();
    baseline_perf_counter_ = GetPerformanceCounter();
    baseline_rdtsc_ = GetRDTSC();
    
    last_system_time_ = baseline_system_time_;
    last_perf_counter_ = baseline_perf_counter_;
    
    current_time_scale_ = 1.0f;
    anomaly_count_ = 0;
}

bool SpeedHackDetector::ValidateSourceRatios() {
    // Get current values from all sources
    uint64_t currentSystemTime = GetSystemTime();
    uint64_t currentPerfCounter = GetPerformanceCounter();
    
    // Calculate elapsed time from each source
    uint64_t elapsedSystem = currentSystemTime - last_system_time_;
    uint64_t elapsedPerf = currentPerfCounter - last_perf_counter_;
    
#ifdef _WIN32
    // Get performance counter frequency
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    
    // Convert perf counter to milliseconds
    double elapsedPerfMs = (double)elapsedPerf * 1000.0 / (double)freq.QuadPart;
#else
    // On Linux, performance counter is already in nanoseconds
    double elapsedPerfMs = (double)elapsedPerf / 1000000.0;
#endif
    
    // Calculate ratio between time sources
    // Ideally this should be ~1.0
    if (elapsedSystem > 10) {  // Avoid division by very small numbers
        double ratio = elapsedPerfMs / (double)elapsedSystem;
        
        // Update running time scale estimate
        current_time_scale_ = (current_time_scale_ * 0.9f) + (float)(ratio * 0.1f);
        
        // Check for significant deviation
        if (std::abs(ratio - 1.0) > MAX_TIME_SCALE_DEVIATION) {
            anomaly_count_++;
            
            // Require multiple anomalies to avoid false positives
            if (anomaly_count_ >= 3) {
                // Speed hack detected
                return false;
            }
        } else {
            // Reset anomaly counter on good frame
            if (anomaly_count_ > 0) {
                anomaly_count_--;
            }
        }
    }
    
    // Update last values
    last_system_time_ = currentSystemTime;
    last_perf_counter_ = currentPerfCounter;
    
    return true;
}

bool SpeedHackDetector::ValidateAgainstWallClock() {
#ifdef _WIN32
    // Get UTC file time (very hard to hook without breaking TLS)
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    
    uint64_t wallTime = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    // Convert to milliseconds (FILETIME is 100ns intervals)
    wallTime /= 10000;
#else
    // Linux: use system_clock (wall clock)
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    uint64_t wallTime = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
#endif
    
    // Compare with QPC-derived time
    static uint64_t baselineWallTime = 0;
    static uint64_t baselineQPC = 0;
    
    if (baselineWallTime == 0) {
        baselineWallTime = wallTime;
        baselineQPC = GetPerformanceCounter();
        return true;
    }
    
    uint64_t elapsedWall = wallTime - baselineWallTime;
    uint64_t elapsedQPC = GetPerformanceCounter() - baselineQPC;
    
#ifdef _WIN32
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    double elapsedQPCMs = (double)elapsedQPC * 1000.0 / (double)freq.QuadPart;
#else
    // On Linux, QPC is in nanoseconds
    double elapsedQPCMs = (double)elapsedQPC / 1000000.0;
#endif
    
    // Wall clock is trusted (breaking it breaks SSL/network)
    // QPC may be hooked
    if (elapsedWall > 1000) {  // Only check after 1 second
        double ratio = elapsedQPCMs / (double)elapsedWall;
        
        // Speed hack would cause ratio > 1.0 (QPC advancing faster than wall)
        if (ratio > 1.0 + MAX_TIME_SCALE_DEVIATION) {
            return false;  // Speed hack detected
        }
    }
    
    return true;
}

bool SpeedHackDetector::ValidateFrame() {
    // Basic source comparison
    if (!ValidateSourceRatios()) {
        return false;
    }
    
    // Periodic wall-clock validation (expensive, do less often)
    static int frameCounter = 0;
    if (++frameCounter % 60 == 0) {  // Every 60 frames
        if (!ValidateAgainstWallClock()) {
            return false;
        }
    }
    
    return true;
}

} // namespace SDK
} // namespace Sentinel
