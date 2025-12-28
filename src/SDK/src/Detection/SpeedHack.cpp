/**
 * Sentinel SDK - Speed Hack Detection Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Detects speed manipulation by cross-validating multiple independent time sources.
 * 
 * IMPORTANT: Client-Side Detection Limitations
 * --------------------------------------------
 * This implementation provides "High" severity detection (not "Critical") because:
 * - All user-mode time sources (QPC, GetTickCount64, RDTSC) can be hooked
 * - Kernel-mode speedhacks (HyperV-based) can defeat all user-mode checks
 * - Without server validation, confidence is inherently limited
 * 
 * Server-Side Validation Protocol (RECOMMENDED)
 * ---------------------------------------------
 * For production anti-cheat, implement server-side time validation:
 * 
 * 1. Client timestamps:
 *    - Include client timestamp in each network packet
 *    - Use GetSystemTime() or equivalent wall clock time
 *    - Sign timestamp with packet encryption to prevent tampering
 * 
 * 2. Server validation:
 *    - Track expected time delta between packets based on game tick rate
 *    - Compare client-reported time with server elapsed time
 *    - Flag clients with consistent time acceleration (e.g., >1.5x speed)
 * 
 * 3. Detection criteria:
 *    - Single packet deviation: May be network jitter (ignore)
 *    - Consistent deviation >25% over 100+ packets: Likely speedhack
 *    - Time going backwards: Clear manipulation (ban immediately)
 * 
 * 4. Implementation example:
 *    ```cpp
 *    struct GamePacket {
 *        uint64_t client_timestamp;  // Client wall clock time (ms)
 *        uint32_t sequence;           // Packet sequence number
 *        // ... game data ...
 *    };
 *    
 *    // Server-side validation
 *    void ValidateClientTime(ClientSession* session, const GamePacket* packet) {
 *        uint64_t server_now = GetServerTime();
 *        uint64_t expected_client_time = session->last_validated_time + 
 *                                         (server_now - session->last_server_time);
 *        
 *        double time_ratio = (double)packet->client_timestamp / expected_client_time;
 *        
 *        if (time_ratio > 1.25 || time_ratio < 0.75) {
 *            session->time_anomaly_count++;
 *            if (session->time_anomaly_count > 10) {
 *                // Ban client for speedhack
 *            }
 *        }
 *    }
 *    ```
 * 
 * Time Source Strategy
 * --------------------
 * This implementation uses three independent time sources:
 * 1. GetTickCount64 / steady_clock - Monotonic system time
 * 2. QueryPerformanceCounter - High-resolution performance counter
 * 3. RDTSC - CPU timestamp counter (calibrated dynamically)
 * 
 * Cross-correlation detects when multiple sources show deviation, improving
 * confidence. RDTSC is harder to hook without kernel access.
 * 
 * Threshold: 25% tolerance
 * - Real speedhacks typically use 2x-10x acceleration
 * - 25% threshold eliminates most false positives from:
 *   - Aggressive power management (CPU frequency scaling)
 *   - Virtual machines with imprecise timekeeping
 *   - System time synchronization (NTP adjustments)
 */

#include "Internal/Detection.hpp"

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#endif

#include <chrono>
#include <thread>
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
    last_rdtsc_ = baseline_rdtsc_;
    
    current_time_scale_ = 1.0f;
    anomaly_count_ = 0;
    
    // Reset wall clock baseline
    wall_clock_baseline_time_ = 0;
    wall_clock_baseline_qpc_ = 0;
    frame_counter_ = 0;
    
    // Calibrate RDTSC frequency (measure over ~100ms)
    uint64_t calibration_start_tsc = GetRDTSC();
    uint64_t calibration_start_time = GetSystemTime();
    
#ifdef _WIN32
    Sleep(100);
#else
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
#endif
    
    uint64_t calibration_end_tsc = GetRDTSC();
    uint64_t calibration_end_time = GetSystemTime();
    
    uint64_t elapsed_tsc = calibration_end_tsc - calibration_start_tsc;
    uint64_t elapsed_ms = calibration_end_time - calibration_start_time;
    
    if (elapsed_ms > 0) {
        // Calculate TSC frequency in MHz (cycles per microsecond)
        rdtsc_frequency_mhz_ = (double)elapsed_tsc / ((double)elapsed_ms * 1000.0);
    } else {
        // Fallback to typical CPU frequency if calibration failed
        rdtsc_frequency_mhz_ = 2400.0;  // Assume 2.4 GHz
    }
    
    rdtsc_calibration_time_ = GetSystemTime();
}

bool SpeedHackDetector::ValidateSourceRatios() {
    // Get current values from all sources
    uint64_t currentSystemTime = GetSystemTime();
    uint64_t currentPerfCounter = GetPerformanceCounter();
    uint64_t currentRDTSC = GetRDTSC();
    
    // Monotonicity check: time must always increase
    if (currentSystemTime < last_system_time_ || 
        currentPerfCounter < last_perf_counter_ ||
        currentRDTSC < last_rdtsc_) {
        // Time went backwards - clear manipulation
        anomaly_count_ += 2;  // More severe than just deviation
        
        if (anomaly_count_ >= 3) {
            return false;  // Speed hack detected (time manipulation)
        }
    }
    
    // Calculate elapsed time from each source
    uint64_t elapsedSystem = currentSystemTime - last_system_time_;
    uint64_t elapsedPerf = currentPerfCounter - last_perf_counter_;
    uint64_t elapsedRDTSC = currentRDTSC - last_rdtsc_;
    
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
    
    // Convert RDTSC to milliseconds using calibrated frequency
    double elapsedRDTSCMs = 0.0;
    if (rdtsc_frequency_mhz_ > 0.0) {
        elapsedRDTSCMs = (double)elapsedRDTSC / (rdtsc_frequency_mhz_ * 1000.0);
    }
    
    // Calculate ratios between time sources
    // Ideally these should be ~1.0
    if (elapsedSystem > 10) {  // Avoid division by very small numbers (10ms threshold)
        double ratioQPCtoSystem = elapsedPerfMs / (double)elapsedSystem;
        double ratioRDTSCtoSystem = elapsedRDTSCMs / (double)elapsedSystem;
        
        // Update running time scale estimate (weighted average of QPC and RDTSC)
        double avgRatio = (ratioQPCtoSystem + ratioRDTSCtoSystem) / 2.0;
        current_time_scale_ = (current_time_scale_ * 0.9f) + (float)(avgRatio * 0.1f);
        
        // Check for significant deviation in QPC vs System time
        bool qpcDeviation = std::abs(ratioQPCtoSystem - 1.0) > MAX_TIME_SCALE_DEVIATION;
        
        // Check for significant deviation in RDTSC vs System time
        bool rdtscDeviation = false;
        if (rdtsc_frequency_mhz_ > 0.0 && elapsedRDTSCMs > 0.0) {
            rdtscDeviation = std::abs(ratioRDTSCtoSystem - 1.0) > MAX_TIME_SCALE_DEVIATION;
        }
        
        // Require both sources to show deviation for higher confidence
        // (reduces false positives from single-source issues)
        if (qpcDeviation && rdtscDeviation) {
            anomaly_count_++;
            
            // Require multiple anomalies to avoid false positives
            if (anomaly_count_ >= 3) {
                // Speed hack detected
                return false;
            }
        } else if (qpcDeviation || rdtscDeviation) {
            // Only one source shows deviation - count as partial anomaly
            anomaly_count_++;
            
            // Require more anomalies if only one source is suspicious
            if (anomaly_count_ >= 5) {
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
    last_rdtsc_ = currentRDTSC;
    
    return true;
}

bool SpeedHackDetector::ValidateAgainstWallClock() {
#ifdef _WIN32
    // Get UTC file time (very hard to hook without breaking TLS)
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    
    uint64_t wallTime = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    // Convert to milliseconds (FILETIME is 100-nanosecond intervals since January 1, 1601)
    wallTime /= 10000;
#else
    // Linux: use system_clock (wall clock)
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    uint64_t wallTime = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
#endif
    
    // Compare with QPC-derived time
    if (wall_clock_baseline_time_ == 0) {
        wall_clock_baseline_time_ = wallTime;
        wall_clock_baseline_qpc_ = GetPerformanceCounter();
        return true;
    }
    
    uint64_t elapsedWall = wallTime - wall_clock_baseline_time_;
    uint64_t elapsedQPC = GetPerformanceCounter() - wall_clock_baseline_qpc_;
    
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
    if (++frame_counter_ % 60 == 0) {  // Every 60 frames
        if (!ValidateAgainstWallClock()) {
            return false;
        }
    }
    
    return true;
}

} // namespace SDK
} // namespace Sentinel
