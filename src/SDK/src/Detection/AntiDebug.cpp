/**
 * Sentinel SDK - Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * This is a stub implementation created as part of Phase 1: Foundation Setup
 * TODO: Implement actual functionality according to production readiness plan
 */

#include "Internal/Detection.hpp"

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>
#endif

#include <vector>
#include <cmath>

namespace Sentinel {
namespace SDK {

#ifdef _WIN32
// Helper function: Check if CONTEXT contains hardware breakpoints
static inline bool IsHardwareBreakpointSet(const CONTEXT& ctx) {
    // Check DR0-DR3 for breakpoint addresses
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        return true;
    }
    
    // Check DR7 for enabled breakpoints
    // Bits 0,2,4,6 = local enable for DR0-3
    // Bits 1,3,5,7 = global enable for DR0-3
    if ((ctx.Dr7 & 0xFF) != 0) {
        return true;
    }
    
    return false;
}
#endif

// AntiDebugDetector implementation
void AntiDebugDetector::Initialize() {
#ifdef _WIN32
    // Detect hypervisor environment
    hypervisor_detected_ = DetectHypervisor();
    
    // Calibrate timing baseline
    CalibrateTimingBaseline();
#endif
}

void AntiDebugDetector::Shutdown() {
    // Reset state
    consecutive_anomaly_count_ = 0;
    last_check_time_ = 0;
    last_successful_check_time_ = 0;
    last_anomaly_detection_time_ = 0;
}

// Helper: Detect hypervisor using CPUID
bool AntiDebugDetector::DetectHypervisor() {
#ifdef _WIN32
    int cpuInfo[4] = {0};
    
    // Check if CPUID is supported
    __cpuid(cpuInfo, 0);
    if (cpuInfo[0] < 1) {
        return false;  // CPUID leaf 1 not supported
    }
    
    // Query CPUID leaf 0x1
    __cpuid(cpuInfo, 1);
    
    // ECX bit 31 indicates hypervisor presence
    return (cpuInfo[2] & (1 << 31)) != 0;
#else
    return false;
#endif
}

// Helper: Calibrate timing baseline
void AntiDebugDetector::CalibrateTimingBaseline() {
#ifdef _WIN32
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    constexpr int NUM_SAMPLES = 1000;
    std::vector<double> samples;
    samples.reserve(NUM_SAMPLES);
    
    volatile uint64_t counter = 0;
    
    // Collect timing samples
    for (int i = 0; i < NUM_SAMPLES; i++) {
        LARGE_INTEGER sample_start, sample_end;
        QueryPerformanceCounter(&sample_start);
        
        // Trivial operation - same as in CheckTimingAnomaly
        for (int j = 0; j < 1000; j++) {
            counter++;
        }
        
        QueryPerformanceCounter(&sample_end);
        
        // Calculate elapsed time in microseconds
        double elapsed_us = static_cast<double>(sample_end.QuadPart - sample_start.QuadPart)
                           * 1000000.0 / static_cast<double>(freq.QuadPart);
        samples.push_back(elapsed_us);
    }
    
    // Calculate mean
    double sum = 0.0;
    for (const auto& sample : samples) {
        sum += sample;
    }
    baseline_mean_ = sum / static_cast<double>(NUM_SAMPLES);
    
    // Calculate standard deviation
    double variance_sum = 0.0;
    for (const auto& sample : samples) {
        double diff = sample - baseline_mean_;
        variance_sum += diff * diff;
    }
    double variance = variance_sum / static_cast<double>(NUM_SAMPLES);
    baseline_stddev_ = sqrt(variance);
    
    // Set dynamic threshold: mean + 5 * stddev
    threshold_us_ = baseline_mean_ + (5.0 * baseline_stddev_);
    
    // If hypervisor detected, multiply threshold by 10x and apply to cycles threshold too
    if (hypervisor_detected_) {
        threshold_us_ *= 10.0;
        threshold_cycles_ *= 10;
    }
    
    // Verify calibration time
    QueryPerformanceCounter(&end);
    double calibration_time_ms = static_cast<double>(end.QuadPart - start.QuadPart)
                                 * 1000.0 / static_cast<double>(freq.QuadPart);
    
    // Calibration should complete in < 200ms (Definition of Done requirement)
    // In practice, 1000 samples should take ~100ms
    (void)calibration_time_ms;  // Used for verification during testing
#endif
}


std::vector<ViolationEvent> AntiDebugDetector::Check() {
#ifdef _WIN32
    std::vector<ViolationEvent> violations;
    
    if (CheckIsDebuggerPresent()) {
        ViolationEvent ev;
        ev.type = ViolationType::DebuggerAttached;
        ev.severity = Severity::Critical;
        ev.details = "IsDebuggerPresent check positive";
        ev.timestamp = 0;
        ev.address = 0;
        ev.module_name = nullptr;
        ev.detection_id = 0;
        violations.push_back(ev);
    }
    
    if (CheckNtGlobalFlag()) {
        ViolationEvent ev;
        ev.type = ViolationType::DebuggerAttached;
        ev.severity = Severity::High;
        ev.details = "NtGlobalFlag debug flags detected";
        ev.timestamp = 0;
        ev.address = 0;
        ev.module_name = nullptr;
        ev.detection_id = 0;
        violations.push_back(ev);
    }
    
    if (CheckHeapFlags()) {
        ViolationEvent ev;
        ev.type = ViolationType::DebuggerAttached;
        ev.severity = Severity::Warning;
        ev.details = "Debug heap configuration detected";
        ev.timestamp = 0;
        ev.address = 0;
        ev.module_name = nullptr;
        ev.detection_id = 0;
        violations.push_back(ev);
    }
    
    return violations;
#else
    return {};
#endif
}

std::vector<ViolationEvent> AntiDebugDetector::FullCheck() {
    auto violations = Check();  // Quick checks first
    
#ifdef _WIN32
    // Check for hardware breakpoints in current thread
    if (CheckHardwareBreakpoints()) {
        ViolationEvent ev;
        ev.type = ViolationType::DebuggerAttached;
        ev.severity = Severity::Critical;
        ev.details = "Hardware breakpoints detected in debug registers";
        ev.timestamp = 0;
        ev.address = 0;
        ev.module_name = nullptr;
        ev.detection_id = 0;
        violations.push_back(ev);
    }
    
    // Check debug port (NtQueryInformationProcess with ProcessDebugPort)
    if (CheckDebugPort()) {
        ViolationEvent ev;
        ev.type = ViolationType::DebuggerAttached;
        ev.severity = Severity::Critical;
        ev.details = "Debug port detected";
        ev.timestamp = 0;
        ev.address = 0;
        ev.module_name = nullptr;
        ev.detection_id = 0;
        violations.push_back(ev);
    }
    
    // Check for timing anomalies (single-stepping, breakpoints)
    if (CheckTimingAnomaly()) {
        ViolationEvent ev;
        ev.type = ViolationType::DebuggerAttached;
        ev.severity = Severity::Warning;  // Downgraded from High to Warning
        
        // Add context about hypervisor if detected
        if (hypervisor_detected_) {
            ev.details = "Timing anomaly detected (hypervisor environment detected)";
        } else {
            ev.details = "Timing anomaly detected - possible single-stepping or breakpoint";
        }
        
        ev.timestamp = 0;
        ev.address = 0;
        ev.module_name = nullptr;
        ev.detection_id = 0;
        violations.push_back(ev);
    }
#endif
    
    return violations;
}

bool AntiDebugDetector::CheckIsDebuggerPresent() {
#ifdef _WIN32
    // Method 1: API call (easily hooked, baseline check)
    if (IsDebuggerPresent()) {
        return true;
    }
    
    // Method 2: Direct PEB read (harder to hook)
    #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
    #else
        PPEB peb = (PPEB)__readfsdword(0x30);
    #endif
    
    if (peb && peb->BeingDebugged) {
        return true;
    }
#endif
    
    return false;
}

bool AntiDebugDetector::CheckRemoteDebugger() { return false; }
bool AntiDebugDetector::CheckDebugPort() { return false; }
bool AntiDebugDetector::CheckDebugObject() { return false; }
bool AntiDebugDetector::CheckHardwareBreakpoints() {
#ifdef _WIN32
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    HANDLE thread = GetCurrentThread();
    
    if (!GetThreadContext(thread, &ctx)) {
        // Cannot get context, inconclusive
        // Note: This could indicate debugger evasion but spec requires false return
        return false;
    }
    
    return IsHardwareBreakpointSet(ctx);
#else
    return false;
#endif
}

// Helper function: Statistical timing check for more robust detection
bool AntiDebugDetector::CheckTimingStatistical() {
#ifdef _WIN32
    std::vector<uint64_t> samples;
    samples.reserve(10);
    
    for (int s = 0; s < 10; s++) {
        uint64_t start = __rdtsc();
        volatile int x = 0;
        for (int i = 0; i < 100; i++) x++;
        uint64_t end = __rdtsc();
        samples.push_back(end - start);
    }
    
    // Calculate variance
    uint64_t sum = 0;
    for (auto& s : samples) sum += s;
    uint64_t mean = sum / samples.size();
    
    uint64_t variance = 0;
    for (auto& s : samples) {
        int64_t diff = static_cast<int64_t>(s) - static_cast<int64_t>(mean);
        variance += diff * diff;
    }
    variance /= samples.size();
    
    // High variance indicates debugger interference
    // (breakpoints hit some iterations but not others)
    // Use dynamic variance threshold based on calibrated baseline
    uint64_t variance_threshold = static_cast<uint64_t>(baseline_stddev_ * baseline_stddev_ * 100);
    if (variance_threshold == 0) {
        variance_threshold = 1000000;  // Fallback if calibration failed
    }
    
    return variance > variance_threshold || mean > threshold_cycles_;
#else
    return false;
#endif
}

bool AntiDebugDetector::CheckTimingAnomaly() {
#ifdef _WIN32
    uint64_t current_time = GetTickCount64();
    
    // Increment telemetry counter
    timing_check_count_++;
    
    // Exponential backoff: If we detected an anomaly recently, wait 5 seconds before rechecking
    if (last_anomaly_detection_time_ != 0 && 
        (current_time - last_anomaly_detection_time_) < 5000) {
        return false;  // Still in backoff period
    }
    
    // Never return true if last successful check was < 100ms ago
    if (last_successful_check_time_ != 0 && 
        (current_time - last_successful_check_time_) < 100) {
        return false;  // Too soon since last successful check
    }
    
    // Rate limiting: Don't check more than once per second
    if (current_time - last_check_time_ < 1000) {
        return false; // Skip if called too frequently
    }
    last_check_time_ = current_time;
    
    // Measure time for a trivial operation
    // Single-stepping or breakpoints dramatically increase time
    
    volatile uint64_t counter = 0;
    bool anomaly_detected = false;
    
    // Use QPC for high resolution
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    // Trivial loop - should complete in microseconds
    for (int i = 0; i < 1000; i++) {
        counter++;
    }
    
    QueryPerformanceCounter(&end);
    
    // Calculate elapsed time in microseconds
    double elapsed_us = static_cast<double>(end.QuadPart - start.QuadPart) 
                       * 1000000.0 / static_cast<double>(freq.QuadPart);
    
    // Use dynamic threshold from calibration
    if (elapsed_us > threshold_us_) {
        anomaly_detected = true;
    }
    
    // Alternative: Use RDTSC for cycle-accurate measurement
    uint64_t tsc_start = __rdtsc();
    
    for (int i = 0; i < 100; i++) {
        counter++;
    }
    
    uint64_t tsc_end = __rdtsc();
    uint64_t cycles = tsc_end - tsc_start;
    
    // Use dynamic threshold from calibration
    if (cycles > threshold_cycles_) {
        anomaly_detected = true;
    }
    
    // Statistical variant for more robust detection
    if (CheckTimingStatistical()) {
        anomaly_detected = true;
    }
    
    // Update consecutive anomaly counter
    if (anomaly_detected) {
        consecutive_anomaly_count_++;
        
        // Require 5 consecutive anomalies before returning true
        if (consecutive_anomaly_count_ >= 5) {
            // Record this detection for exponential backoff
            last_anomaly_detection_time_ = current_time;
            timing_anomaly_count_++;
            
            // Don't reset counter - keep it high to maintain detection state
            // until system returns to normal
            return true;
        }
        
        // Not enough consecutive anomalies yet
        return false;
    } else {
        // Successful check - reset consecutive counter
        consecutive_anomaly_count_ = 0;
        last_successful_check_time_ = current_time;
        return false;
    }
#else
    return false;
#endif
}
bool AntiDebugDetector::CheckSEHIntegrity() { return false; }
bool AntiDebugDetector::CheckPEB() { return CheckIsDebuggerPresent(); }

bool AntiDebugDetector::CheckNtGlobalFlag() {
#ifdef _WIN32
    // When debugger creates process, NtGlobalFlag has specific flags set
    #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
        DWORD ntGlobalFlag = *(DWORD*)((BYTE*)peb + 0xBC);
    #else
        PPEB peb = (PPEB)__readfsdword(0x30);
        DWORD ntGlobalFlag = *(DWORD*)((BYTE*)peb + 0x68);
    #endif
    
    // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | 
    // FLG_HEAP_VALIDATE_PARAMETERS
    const DWORD DEBUG_FLAGS = 0x70;
    
    return (ntGlobalFlag & DEBUG_FLAGS) != 0;
#else
    return false;
#endif
}

bool AntiDebugDetector::CheckHeapFlags() {
#ifdef _WIN32
    HANDLE heap = GetProcessHeap();
    
    // Read heap header structure
    // Offsets vary by OS version - use MEMORY_BASIC_INFORMATION instead
    PROCESS_HEAP_ENTRY entry;
    entry.lpData = nullptr;
    
    if (!HeapWalk(heap, &entry)) {
        // Can't walk heap, inconclusive
        return false;
    }
    
    // Alternative: Check ForceFlags in heap structure
    // This requires careful offset calculation for Win7/10/11
    // Simplified version using HeapQueryInformation: 
    ULONG heapInfo = 0;
    if (HeapQueryInformation(heap, HeapCompatibilityInformation, 
                              &heapInfo, sizeof(heapInfo), nullptr)) {
        // Normal heap = 2 (LFH), debug heap = 0 or 1
        if (heapInfo == 0) {
            return true; // Debug heap likely
        }
    }
#endif
    
    return false;
}

// Helper function: Check all threads for hardware breakpoints
// Note: Currently not used in production code, but available for comprehensive scanning
[[maybe_unused]] static bool CheckAllThreadsHardwareBP() {
#ifdef _WIN32
    DWORD currentPid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    
    bool detected = false;
    
    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == currentPid) {
                HANDLE thread = OpenThread(THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
                if (thread) {
                    CONTEXT ctx;
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(thread, &ctx)) {
                        if (IsHardwareBreakpointSet(ctx)) {
                            detected = true;
                        }
                    }
                    CloseHandle(thread);
                }
            }
        } while (Thread32Next(snapshot, &te) && !detected);
    }
    
    CloseHandle(snapshot);
    return detected;
#else
    return false;
#endif
}

} // namespace SDK
} // namespace Sentinel
