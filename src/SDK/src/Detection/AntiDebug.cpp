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

// AntiDebugDetector stub implementation
void AntiDebugDetector::Initialize() {}
void AntiDebugDetector::Shutdown() {}

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
        ev.severity = Severity::High;
        ev.details = "Timing anomaly detected - possible single-stepping or breakpoint";
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
[[maybe_unused]] static bool CheckTimingStatistical() {
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
    constexpr uint64_t VARIANCE_THRESHOLD = 1000000;
    
    return variance > VARIANCE_THRESHOLD || mean > 10000;
#else
    return false;
#endif
}

bool AntiDebugDetector::CheckTimingAnomaly() {
#ifdef _WIN32
    // Rate limiting: Don't check more than once per second
    // Store last_check_time_ and check_count_ as member variables
    if (GetTickCount64() - last_check_time_ < 1000) {
        return false; // Skip if called too frequently
    }
    last_check_time_ = GetTickCount64();
    
    // Measure time for a trivial operation
    // Single-stepping or breakpoints dramatically increase time
    
    volatile uint64_t counter = 0;
    
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
    
    // Threshold: Normal < 100us, Debugged with stepping > 1000us
    // Use conservative threshold to avoid false positives
    constexpr double THRESHOLD_US = 500.0;
    
    if (elapsed_us > THRESHOLD_US) {
        return true;
    }
    
    // Alternative: Use RDTSC for cycle-accurate measurement
    uint64_t tsc_start = __rdtsc();
    
    for (int i = 0; i < 100; i++) {
        counter++;
    }
    
    uint64_t tsc_end = __rdtsc();
    uint64_t cycles = tsc_end - tsc_start;
    
    // Normal:  < 1000 cycles, Single-stepped: millions
    constexpr uint64_t CYCLE_THRESHOLD = 10000;
    
    if (cycles > CYCLE_THRESHOLD) {
        return true;
    }
    
    // Statistical variant for more robust detection
    return CheckTimingStatistical();
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
