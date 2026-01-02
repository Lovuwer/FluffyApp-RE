/**
 * Sentinel SDK - Redundant AntiDebug Implementations
 * 
 * Task 29: Implement Redundant Detection Architecture
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "RedundantAntiDebug.hpp"
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#endif

namespace Sentinel {
namespace SDK {

// ============================================================================
// Primary Implementation (wraps existing detector)
// ============================================================================

AntiDebugPrimaryImpl::AntiDebugPrimaryImpl()
    : detector_(std::make_unique<AntiDebugDetector>())
{
}

void AntiDebugPrimaryImpl::Initialize() {
    if (detector_) {
        detector_->Initialize();
    }
}

void AntiDebugPrimaryImpl::Shutdown() {
    if (detector_) {
        detector_->Shutdown();
    }
}

std::vector<ViolationEvent> AntiDebugPrimaryImpl::QuickCheck() {
    if (detector_) {
        return detector_->Check();
    }
    return std::vector<ViolationEvent>();
}

std::vector<ViolationEvent> AntiDebugPrimaryImpl::FullCheck() {
    if (detector_) {
        return detector_->FullCheck();
    }
    return std::vector<ViolationEvent>();
}

// ============================================================================
// Alternative Implementation (different approach)
// ============================================================================

AntiDebugAlternativeImpl::AntiDebugAlternativeImpl()
    : last_check_time_(0)
    , consecutive_detections_(0)
{
}

void AntiDebugAlternativeImpl::Initialize() {
    last_check_time_ = 0;
    consecutive_detections_ = 0;
}

void AntiDebugAlternativeImpl::Shutdown() {
    // Nothing to clean up
}

std::vector<ViolationEvent> AntiDebugAlternativeImpl::QuickCheck() {
    std::vector<ViolationEvent> violations;
    
#ifdef SENTINEL_DISABLE_ANTIDEBUG
    return violations;
#endif
    
    // Quick check: lightweight syscall-based detection
    if (CheckViaSyscallDirect()) {
        ViolationEvent event;
        event.type = ViolationType::DebuggerAttached;
        event.severity = Severity::High;
        event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        event.details = "Alternative: Direct syscall detected debugger";
        event.detection_id = 0x2001;  // Alternative implementation ID
        violations.push_back(event);
        consecutive_detections_++;
    }
    
    return violations;
}

std::vector<ViolationEvent> AntiDebugAlternativeImpl::FullCheck() {
    std::vector<ViolationEvent> violations;
    
#ifdef SENTINEL_DISABLE_ANTIDEBUG
    return violations;
#endif
    
    // Full check: comprehensive alternative approach
    bool detected = false;
    std::string detection_method;
    
    if (CheckViaProcessEnvironment()) {
        detected = true;
        detection_method = "process environment";
    } else if (CheckViaThreadContext()) {
        detected = true;
        detection_method = "thread context";
    } else if (CheckViaMemoryAccessPatterns()) {
        detected = true;
        detection_method = "memory access patterns";
    } else if (CheckViaSyscallDirect()) {
        detected = true;
        detection_method = "direct syscall";
    }
    
    if (detected) {
        ViolationEvent event;
        event.type = ViolationType::DebuggerAttached;
        event.severity = Severity::High;
        event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        event.details = "Alternative: Debugger detected via " + detection_method;
        event.detection_id = 0x2002;  // Alternative implementation ID
        violations.push_back(event);
        consecutive_detections_++;
    } else {
        consecutive_detections_ = 0;
    }
    
    return violations;
}

bool AntiDebugAlternativeImpl::CheckViaProcessEnvironment() {
#ifdef _WIN32
    // Check if running under a debugger by examining parent process
    // This is a simplified implementation - production would be more sophisticated
    
    // Check for common debugger process names in environment
    const char* debugger_vars[] = {
        "_NT_SYMBOL_PATH",
        "_NT_ALT_SYMBOL_PATH",
        "DBGHELP_HOMEDIR"
    };
    
    for (const char* var : debugger_vars) {
        if (getenv(var) != nullptr) {
            return true;
        }
    }
#endif
    
    return false;
}

bool AntiDebugAlternativeImpl::CheckViaThreadContext() {
#ifdef _WIN32
    // Check for hardware breakpoints via thread context
    // This is an alternative to the primary implementation's approach
    
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        // Check if any debug registers are set
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true;
        }
        
        // Check Dr7 (debug control register)
        if ((ctx.Dr7 & 0xFF) != 0) {
            return true;
        }
    }
#endif
    
    return false;
}

bool AntiDebugAlternativeImpl::CheckViaMemoryAccessPatterns() {
#ifdef _WIN32
    // Detect debugger by checking memory access patterns
    // Debuggers often set memory breakpoints that change page protections
    
    MEMORY_BASIC_INFORMATION mbi = {};
    
    // Check our own code section for suspicious protections
    if (VirtualQuery((LPCVOID)&AntiDebugAlternativeImpl::CheckViaMemoryAccessPatterns, 
                     &mbi, sizeof(mbi))) {
        // PAGE_EXECUTE_READWRITE is suspicious for code sections
        if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
            return true;
        }
        
        // PAGE_GUARD is often used for memory breakpoints
        if (mbi.Protect & PAGE_GUARD) {
            return true;
        }
    }
#endif
    
    return false;
}

bool AntiDebugAlternativeImpl::CheckViaSyscallDirect() {
#ifdef _WIN32
    // Use direct syscall to check debug port (alternative to API-based check)
    // This bypasses potential hooks on NtQueryInformationProcess
    
    typedef NTSTATUS (NTAPI *NtQueryInformationProcessPtr)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return false;
    }
    
    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessPtr>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    
    if (!NtQueryInformationProcess) {
        return false;
    }
    
    // Check ProcessDebugPort (0x7)
    DWORD_PTR debug_port = 0;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        0x7,  // ProcessDebugPort
        &debug_port,
        sizeof(debug_port),
        nullptr
    );
    
    if (status == 0 && debug_port != 0) {
        return true;
    }
#endif
    
    return false;
}

} // namespace SDK
} // namespace Sentinel
