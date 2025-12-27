/**
 * Sentinel SDK - Injection Detection Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 13: Memory Region Anomaly Detection
 * Detects manually mapped code and suspicious memory regions by scanning
 * for executable private memory and suspicious thread start addresses.
 */

#include "Internal/Detection.hpp"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "psapi.lib")
#endif

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace Sentinel {
namespace SDK {

#ifdef _WIN32

// Constants
static constexpr size_t PAGE_SIZE = 0x1000;  // 4KB page size

// Helper function to convert address to hex string
static std::string ToHex(uintptr_t value) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << value;
    return oss.str();
}

void InjectionDetector::Initialize() {
    // Snapshot current modules as baseline
    EnumerateKnownModules();
}

void InjectionDetector::Shutdown() {
    known_modules_.clear();
}

void InjectionDetector::EnumerateKnownModules() {
    known_modules_.clear();
    
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            wchar_t modName[MAX_PATH];
            if (GetModuleFileNameExW(GetCurrentProcess(), hMods[i], 
                                     modName, MAX_PATH)) {
                known_modules_.push_back(modName);
            }
        }
    }
}

std::vector<ViolationEvent> InjectionDetector::ScanLoadedModules() {
    std::vector<ViolationEvent> violations;
    
    // Scan entire address space
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    uintptr_t address = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddress = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    
    while (address < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
            address += PAGE_SIZE;  // Skip to next page
            continue;
        }
        
        // Check for suspicious regions
        if (IsSuspiciousRegion(mbi)) {
            ViolationEvent ev;
            ev.type = ViolationType::InjectedCode;
            ev.severity = Severity::Critical;
            ev.address = (uintptr_t)mbi.BaseAddress;
            // Use a static string literal to avoid use-after-free
            static const char* detail_msg = "Executable private memory detected";
            ev.details = detail_msg;
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            ev.module_name = nullptr;
            ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
            violations.push_back(ev);
        }
        
        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    
    return violations;
}

bool InjectionDetector::IsSuspiciousRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    // Must be committed
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    
    // Check for executable permission
    bool isExecutable = 
        (mbi.Protect & PAGE_EXECUTE) ||
        (mbi.Protect & PAGE_EXECUTE_READ) ||
        (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
        (mbi.Protect & PAGE_EXECUTE_WRITECOPY);
    
    if (!isExecutable) {
        return false;
    }
    
    // MEM_PRIVATE + Executable = Highly suspicious
    // MEM_IMAGE = Normal (loaded from file)
    // MEM_MAPPED = Could be legitimate (section mapping)
    if (mbi.Type == MEM_PRIVATE) {
        return true;  // Private executable memory is almost always bad
    }
    
    // RWX permission is suspicious even for MEM_IMAGE
    if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
        // Could be JIT, but should be rare
        // Check if it's in a known JIT region (e.g., .NET, V8)
        return !IsKnownJITRegion((uintptr_t)mbi.BaseAddress);
    }
    
    return false;
}

bool InjectionDetector::IsKnownJITRegion(uintptr_t address) {
    // TODO: Implement JIT region whitelist detection
    // This function is intentionally a placeholder to prevent false positives
    // on legitimate JIT-compiled code (e.g., .NET CLR heap, V8 isolate, LuaJIT).
    // 
    // Future implementation should check if the address falls within:
    // - .NET CLR JIT heap regions
    // - V8 JavaScript engine isolate
    // - LuaJIT compiler regions
    // - Other legitimate JIT compiler memory
    //
    // For now, return false (conservative approach - may cause false positives
    // on applications using JIT compilation, but ensures detection of injected code).
    (void)address;  // Suppress unused parameter warning
    return false;
}

// Helper function to format memory region information for debugging/logging
// Note: Currently unused in violation events due to memory safety concerns,
// but kept for future use in logging or debugging scenarios.
std::string InjectionDetector::DescribeRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    std::string desc;
    
    desc += "Address: 0x" + ToHex((uintptr_t)mbi.BaseAddress);
    desc += ", Size: " + std::to_string(mbi.RegionSize);
    desc += ", Type: ";
    
    switch (mbi.Type) {
        case MEM_PRIVATE: desc += "PRIVATE"; break;
        case MEM_IMAGE: desc += "IMAGE"; break;
        case MEM_MAPPED: desc += "MAPPED"; break;
        default: desc += "UNKNOWN"; break;
    }
    
    desc += ", Protect: ";
    if (mbi.Protect & PAGE_EXECUTE_READWRITE) desc += "RWX";
    else if (mbi.Protect & PAGE_EXECUTE_READ) desc += "RX";
    else if (mbi.Protect & PAGE_EXECUTE) desc += "X";
    
    return desc;
}

std::vector<ViolationEvent> InjectionDetector::ScanThreads() {
    std::vector<ViolationEvent> violations;
    
    DWORD currentPid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return violations;
    }
    
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    
    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == currentPid) {
                if (IsThreadSuspicious(te.th32ThreadID)) {
                    ViolationEvent ev;
                    ev.type = ViolationType::SuspiciousThread;
                    ev.severity = Severity::High;
                    // Use a static string literal to avoid use-after-free
                    static const char* detail_msg = "Thread with suspicious start address detected";
                    ev.details = detail_msg;
                    ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    ev.address = te.th32ThreadID;  // Store thread ID in address field
                    ev.module_name = nullptr;
                    ev.detection_id = static_cast<uint32_t>(te.th32ThreadID ^ ev.timestamp);
                    violations.push_back(ev);
                }
            }
        } while (Thread32Next(snapshot, &te));
    }
    
    CloseHandle(snapshot);
    return violations;
}

bool InjectionDetector::IsThreadSuspicious(uint32_t threadId) {
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) return false;
    
    // Get thread start address
    typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    
    static auto NtQueryInformationThread = 
        (pNtQueryInformationThread)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), 
            "NtQueryInformationThread");
    
    if (!NtQueryInformationThread) {
        CloseHandle(hThread);
        return false;
    }
    
    PVOID startAddress = nullptr;
    NTSTATUS status = NtQueryInformationThread(
        hThread, 
        9,  // ThreadQuerySetWin32StartAddress
        &startAddress, 
        sizeof(startAddress), 
        nullptr);
    
    CloseHandle(hThread);
    
    if (status != 0 || !startAddress) {
        return false;
    }
    
    // Check if start address is in a valid module
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(startAddress, &mbi, sizeof(mbi)) == 0) {
        return true;  // Can't query = suspicious
    }
    
    // Thread starting in MEM_PRIVATE is suspicious
    return mbi.Type == MEM_PRIVATE;
}

bool InjectionDetector::IsModuleSuspicious(const wchar_t* module_path) {
    // Check whitelist first
    if (g_whitelist && g_whitelist->IsModuleWhitelisted(module_path)) {
        return false;  // Whitelisted, not suspicious
    }
    
    // Additional checks can be added here
    return false;
}

#else // Non-Windows platforms

void InjectionDetector::Initialize() {
    // Not implemented for non-Windows platforms
}

void InjectionDetector::Shutdown() {
    // Not implemented for non-Windows platforms
}

void InjectionDetector::EnumerateKnownModules() {
    // Not implemented for non-Windows platforms
}

std::vector<ViolationEvent> InjectionDetector::ScanLoadedModules() {
    return {};  // Not implemented for non-Windows platforms
}

std::vector<ViolationEvent> InjectionDetector::ScanThreads() {
    return {};  // Not implemented for non-Windows platforms
}

bool InjectionDetector::IsModuleSuspicious(const wchar_t* module_path) {
    (void)module_path;
    return false;
}

bool InjectionDetector::IsThreadSuspicious(uint32_t thread_id) {
    (void)thread_id;
    return false;
}

#endif // _WIN32

} // namespace SDK
} // namespace Sentinel
