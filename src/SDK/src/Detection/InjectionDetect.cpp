/**
 * Sentinel SDK - Injection Detection Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 13: Memory Region Anomaly Detection
 * Detects manually mapped code and suspicious memory regions by scanning
 * for executable private memory and suspicious thread start addresses.
 * 
 * Task 12: Module Signature Verification
 * Verifies Authenticode signatures, module hashes, and detects DLL proxying.
 */

#include "Internal/Detection.hpp"
#include "Internal/SafeMemory.hpp"
#include "Internal/SignatureVerify.hpp"

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
    // Capture baseline memory regions (RWX regions at startup)
#ifdef _WIN32
    CaptureBaseline();
#endif
}

void InjectionDetector::Shutdown() {
    known_modules_.clear();
#ifdef _WIN32
    baseline_regions_.clear();
#endif
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
        
        // Safely query memory - check if address is accessible first
        size_t queryResult = 0;
        __try {
            queryResult = VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // VirtualQuery failed with exception, skip to next page
            address += PAGE_SIZE;
            continue;
        }
        
        if (queryResult == 0) {
            address += PAGE_SIZE;  // Skip to next page
            continue;
        }
        
        // Check for suspicious regions using heuristic scoring
        if (IsSuspiciousRegion(mbi)) {
            // Calculate suspicion score
            float score = CalculateSuspicionScore(mbi);
            
            // Only report if score exceeds threshold
            if (score > 0.5f) {
                ViolationEvent ev;
                ev.type = ViolationType::InjectedCode;
                ev.severity = GetSeverityFromScore(score);
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
    // Check if address is in a JIT compiler memory region
    // Query the memory information for this address
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    
    // Get module at this allocation base (if any)
    wchar_t modulePath[MAX_PATH] = {0};
    if (mbi.AllocationBase && 
        GetModuleFileNameW((HMODULE)mbi.AllocationBase, modulePath, MAX_PATH) > 0) {
        
        // Extract module name from path
        const wchar_t* moduleName = wcsrchr(modulePath, L'\\');
        if (moduleName) {
            moduleName++; // Skip the backslash
        } else {
            moduleName = modulePath;
        }
        
        // Use case-insensitive comparison for known JIT modules
        // Check for .NET CLR JIT
        if (_wcsicmp(moduleName, L"clrjit.dll") == 0 ||
            _wcsicmp(moduleName, L"clr.dll") == 0 ||
            _wcsicmp(moduleName, L"coreclr.dll") == 0) {
            return true;
        }
        
        // Check for V8 JavaScript engine
        if (_wcsicmp(moduleName, L"v8.dll") == 0 ||
            _wcsicmp(moduleName, L"libv8.dll") == 0) {
            return true;
        }
        
        // Check for Unity IL2CPP
        if (_wcsicmp(moduleName, L"gameassembly.dll") == 0) {
            return true;
        }
        
        // Check for LuaJIT
        if (_wcsicmp(moduleName, L"luajit.dll") == 0 ||
            _wcsicmp(moduleName, L"lua51.dll") == 0 ||
            _wcsicmp(moduleName, L"lua52.dll") == 0 ||
            _wcsicmp(moduleName, L"lua53.dll") == 0) {
            return true;
        }
    }
    
    // Check against whitelist for thread origins (also covers JIT regions)
    if (g_whitelist && g_whitelist->IsThreadOriginWhitelisted(address)) {
        return true;
    }
    
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

// Helper function to check if a thread starts in Windows thread pool
bool InjectionDetector::IsWindowsThreadPoolThread(uintptr_t startAddress) {
    // Get module info for the start address
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)startAddress, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    
    // Get module name if this is in a module
    wchar_t modulePath[MAX_PATH];
    if (mbi.AllocationBase && 
        GetModuleFileNameW((HMODULE)mbi.AllocationBase, modulePath, MAX_PATH) > 0) {
        
        // Extract module name from path
        const wchar_t* moduleName = wcsrchr(modulePath, L'\\');
        if (moduleName) {
            moduleName++; // Skip the backslash
        } else {
            moduleName = modulePath;
        }
        
        // Check for ntdll.dll or kernel32.dll (thread pool infrastructure)
        if (_wcsicmp(moduleName, L"ntdll.dll") == 0 ||
            _wcsicmp(moduleName, L"kernel32.dll") == 0 ||
            _wcsicmp(moduleName, L"kernelbase.dll") == 0) {
            
            // Check proximity to thread pool functions in ntdll
            // We use TpReleaseWork as a reference point for thread pool APIs
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                FARPROC pTpFunc = GetProcAddress(hNtdll, "TpReleaseWork");
                // If we're within ~64KB of thread pool functions, likely a worker thread
                if (pTpFunc) {
                    uintptr_t tpFunc = (uintptr_t)pTpFunc;
                    uintptr_t distance = (startAddress > tpFunc) ? 
                        (startAddress - tpFunc) : (tpFunc - startAddress);
                    if (distance < 65536) {  // Within 64KB
                        return true;
                    }
                }
            }
            
            // Check for BaseThreadInitThunk (common trampoline)
            HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
            if (hKernel32) {
                FARPROC pBaseThreadInitThunk = GetProcAddress(hKernel32, "BaseThreadInitThunk");
                if (pBaseThreadInitThunk && (uintptr_t)pBaseThreadInitThunk == startAddress) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

// Helper function to check if a thread belongs to CLR (.NET)
bool InjectionDetector::IsCLRThread(uintptr_t startAddress) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)startAddress, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    
    // Get module name
    wchar_t modulePath[MAX_PATH];
    if (mbi.AllocationBase && 
        GetModuleFileNameW((HMODULE)mbi.AllocationBase, modulePath, MAX_PATH) > 0) {
        
        const wchar_t* moduleName = wcsrchr(modulePath, L'\\');
        if (moduleName) {
            moduleName++;
        } else {
            moduleName = modulePath;
        }
        
        // Check for .NET CLR modules
        if (_wcsicmp(moduleName, L"clr.dll") == 0 ||
            _wcsicmp(moduleName, L"coreclr.dll") == 0 ||
            _wcsicmp(moduleName, L"clrjit.dll") == 0 ||
            _wcsicmp(moduleName, L"mscorwks.dll") == 0 ||
            _wcsicmp(moduleName, L"mscorsvr.dll") == 0) {
            return true;
        }
    }
    
    return false;
}

// Helper function to check if memory region is a legitimate trampoline
bool InjectionDetector::IsLegitimateTrampoline(uintptr_t address, 
                                                const MEMORY_BASIC_INFORMATION& mbi) {
    // If it's not private memory, not a trampoline case we care about
    if (mbi.Type != MEM_PRIVATE) {
        return false;
    }
    
    // Check if this private memory is adjacent to a known module
    // Trampolines are often allocated close to the module they serve
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(GetCurrentProcess(), hMods[i], 
                                    &modInfo, sizeof(modInfo))) {
                uintptr_t modBase = (uintptr_t)modInfo.lpBaseOfDll;
                uintptr_t modEnd = modBase + modInfo.SizeOfImage;
                
                // Check if the address is within 64KB before or after the module
                // This is a common pattern for trampolines and delay-loaded code
                const uintptr_t trampoline_threshold = 64 * 1024;
                
                if (address >= modEnd && (address - modEnd) < trampoline_threshold) {
                    // Verify the memory region is small (trampolines are typically small)
                    if (mbi.RegionSize <= 16 * 1024) {  // 16KB max for trampoline
                        return true;
                    }
                }
                if (address < modBase && (modBase - address) < trampoline_threshold) {
                    if (mbi.RegionSize <= 16 * 1024) {
                        return true;
                    }
                }
            }
        }
    }
    
    return false;
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
    
    uintptr_t startAddr = (uintptr_t)startAddress;
    
    // Safely query memory information about thread start address
    MEMORY_BASIC_INFORMATION mbi;
    size_t queryResult = 0;
    __try {
        queryResult = VirtualQuery(startAddress, &mbi, sizeof(mbi));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Failed to query, assume suspicious
        return true;
    }
    
    if (queryResult == 0) {
        return true;  // Can't query = suspicious
    }
    
    // If thread starts in MEM_IMAGE or MEM_MAPPED, it's likely legitimate
    if (mbi.Type != MEM_PRIVATE) {
        return false;
    }
    
    // Check whitelist for thread origins (covers JIT compilers, game engines, etc.)
    if (g_whitelist && g_whitelist->IsThreadOriginWhitelisted(startAddr)) {
        return false;
    }
    
    // Check for Windows thread pool threads
    if (IsWindowsThreadPoolThread(startAddr)) {
        return false;
    }
    
    // Check for CLR managed threads
    if (IsCLRThread(startAddr)) {
        return false;
    }
    
    // Check if this is a legitimate trampoline near a known module
    if (IsLegitimateTrampoline(startAddr, mbi)) {
        return false;
    }
    
    // Thread starting in MEM_PRIVATE without whitelist match is suspicious
    return true;
}

void InjectionDetector::CaptureBaseline() {
    baseline_regions_.clear();
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    uintptr_t address = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddress = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    
    while (address < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        
        size_t queryResult = 0;
        __try {
            queryResult = VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            address += PAGE_SIZE;
            continue;
        }
        
        if (queryResult == 0) {
            address += PAGE_SIZE;
            continue;
        }
        
        // Record all executable private memory in baseline
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            bool isExecutable = 
                (mbi.Protect & PAGE_EXECUTE) ||
                (mbi.Protect & PAGE_EXECUTE_READ) ||
                (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                (mbi.Protect & PAGE_EXECUTE_WRITECOPY);
            
            if (isExecutable) {
                MemoryBaseline baseline;
                baseline.base_address = (uintptr_t)mbi.BaseAddress;
                baseline.region_size = mbi.RegionSize;
                baseline_regions_.push_back(baseline);
            }
        }
        
        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
}

bool InjectionDetector::IsInBaseline(uintptr_t address, size_t size) const {
    // Check if this region was in the baseline snapshot
    for (const auto& baseline : baseline_regions_) {
        // Check for overlap with baseline region
        uintptr_t baseline_end = baseline.base_address + baseline.region_size;
        uintptr_t region_end = address + size;
        
        if (address >= baseline.base_address && address < baseline_end) {
            return true;
        }
        if (region_end > baseline.base_address && region_end <= baseline_end) {
            return true;
        }
        if (address <= baseline.base_address && region_end >= baseline_end) {
            return true;
        }
    }
    return false;
}

float InjectionDetector::CalculateSuspicionScore(const MEMORY_BASIC_INFORMATION& mbi) const {
    float score = 0.0f;
    
    uintptr_t address = (uintptr_t)mbi.BaseAddress;
    size_t size = mbi.RegionSize;
    
    // MEM_PRIVATE + RWX = 0.3 score
    if (mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_EXECUTE_READWRITE) {
        score += 0.3f;
    }
    // MEM_PRIVATE + RX (no W) = 0.2 score
    else if (mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_EXECUTE_READ) {
        score += 0.2f;
    }
    // MEM_PRIVATE + X only = 0.2 score
    else if (mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_EXECUTE) {
        score += 0.2f;
    }
    
    // Size < 4KB = +0.1 (shellcode-sized)
    if (size < 4096) {
        score += 0.1f;
    }
    // Size > 1MB = -0.1 (likely legitimate allocator)
    else if (size > 1024 * 1024) {
        score -= 0.1f;
    }
    
    // Contains PE header signature = +0.3
    if (HasPEHeader(address)) {
        score += 0.3f;
    }
    
    // Near known module = -0.2
    if (IsNearKnownModule(address)) {
        score -= 0.2f;
    }
    
    // In baseline = -0.5 (significantly reduce score for baseline regions)
    if (IsInBaseline(address, size)) {
        score -= 0.5f;
    }
    
    // Known JIT region = -0.5
    if (IsKnownJITRegion(address)) {
        score -= 0.5f;
    }
    
    return score;
}

bool InjectionDetector::HasPEHeader(uintptr_t address) const {
    // Check for PE header signature (MZ followed by PE)
    __try {
        const uint8_t* ptr = (const uint8_t*)address;
        
        // Check for MZ signature
        if (ptr[0] != 'M' || ptr[1] != 'Z') {
            return false;
        }
        
        // Get PE header offset (at 0x3C)
        uint32_t peOffset = *(uint32_t*)(ptr + 0x3C);
        
        // Verify PE offset is reasonable and within bounds
        // Leave room for PE signature (4 bytes)
        if (peOffset > 0x1000 - 4) {
            return false;
        }
        
        // Check for PE signature
        const uint8_t* pePtr = ptr + peOffset;
        if (pePtr[0] == 'P' && pePtr[1] == 'E' && 
            pePtr[2] == 0 && pePtr[3] == 0) {
            return true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Access violation - not a valid PE
        return false;
    }
    
    return false;
}

bool InjectionDetector::IsNearKnownModule(uintptr_t address) const {
    // Check if address is within 64KB of a known module
    const uintptr_t proximity_threshold = 64 * 1024;
    
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(GetCurrentProcess(), hMods[i], 
                                    &modInfo, sizeof(modInfo))) {
                uintptr_t modBase = (uintptr_t)modInfo.lpBaseOfDll;
                uintptr_t modEnd = modBase + modInfo.SizeOfImage;
                
                // Check if address is within the module or within proximity_threshold
                // Address is "near" if it's within module or within threshold of module boundaries
                if (address >= modBase && address < modEnd) {
                    return true;  // Inside module
                }
                // Before module start
                if (address < modBase && (modBase - address) <= proximity_threshold) {
                    return true;
                }
                // After module end
                if (address >= modEnd && (address - modEnd) < proximity_threshold) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

Severity InjectionDetector::GetSeverityFromScore(float score) const {
    // 0.5-0.7 = Warning
    if (score >= 0.5f && score < 0.7f) {
        return Severity::Warning;
    }
    // 0.7-0.9 = High
    else if (score >= 0.7f && score < 0.9f) {
        return Severity::High;
    }
    // 0.9+ = Critical
    else if (score >= 0.9f) {
        return Severity::Critical;
    }
    
    // Below 0.5 should not be reported (filtered in ScanLoadedModules)
    return Severity::Info;
}

bool InjectionDetector::IsModuleSuspicious(const wchar_t* module_path) {
    // Check whitelist first
    if (g_whitelist && g_whitelist->IsModuleWhitelisted(module_path)) {
        return false;  // Whitelisted, not suspicious
    }
    
    // Additional checks can be added here
    return false;
}

std::vector<ViolationEvent> InjectionDetector::ScanModuleSignatures() {
    std::vector<ViolationEvent> violations;

#ifdef _WIN32
    SignatureVerifier verifier;
    
    // Enumerate all loaded modules
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        return violations;
    }
    
    DWORD count = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        wchar_t modPath[MAX_PATH];
        if (!GetModuleFileNameExW(GetCurrentProcess(), hMods[i], modPath, MAX_PATH)) {
            continue;
        }
        
        // Verify the module
        ModuleVerificationResult result = verifier.VerifyModule(modPath);
        
        // Check for DLL proxy (system DLL loaded from wrong path)
        if (result.is_proxy_dll && !result.path_valid) {
            ViolationEvent ev;
            ev.type = ViolationType::CodeInjection;
            ev.severity = Severity::Critical;  // Proxy DLLs are high risk
            ev.address = reinterpret_cast<uintptr_t>(hMods[i]);
            static const char* proxy_msg = "System DLL loaded from game directory (possible DLL proxy)";
            ev.details = proxy_msg;
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            
            // Convert module path to UTF-8
            char module_name_utf8[256];
            WideCharToMultiByte(CP_UTF8, 0, modPath, -1, module_name_utf8, sizeof(module_name_utf8), NULL, NULL);
            
            // Store in a dynamically allocated string to avoid lifetime issues
            static std::vector<std::string> module_name_storage;
            module_name_storage.push_back(module_name_utf8);
            ev.module_name = module_name_storage.back().c_str();
            ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
            violations.push_back(ev);
            continue;
        }
        
        // Check for unsigned DLL in game directory (exclude Windows system DLLs)
        if (result.signature_status == SignatureStatus::Unsigned && !result.is_proxy_dll) {
            // Check if the DLL is in the game directory (not System32)
            std::wstring path_lower = modPath;
            std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(),
                [](wchar_t c) { return std::towlower(c); });
            
            wchar_t system_dir[MAX_PATH];
            GetSystemDirectoryW(system_dir, MAX_PATH);
            std::wstring system_dir_lower = system_dir;
            std::transform(system_dir_lower.begin(), system_dir_lower.end(), system_dir_lower.begin(),
                [](wchar_t c) { return std::towlower(c); });
            
            // If not in System32, flag as suspicious
            if (path_lower.find(system_dir_lower) != 0) {
                ViolationEvent ev;
                ev.type = ViolationType::SignatureInvalid;
                ev.severity = Severity::High;  // Unsigned DLLs are suspicious but not necessarily malicious
                ev.address = reinterpret_cast<uintptr_t>(hMods[i]);
                static const char* unsigned_msg = "Unsigned DLL loaded in game process";
                ev.details = unsigned_msg;
                ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                
                char module_name_utf8[256];
                WideCharToMultiByte(CP_UTF8, 0, modPath, -1, module_name_utf8, sizeof(module_name_utf8), NULL, NULL);
                
                static std::vector<std::string> module_name_storage;
                module_name_storage.push_back(module_name_utf8);
                ev.module_name = module_name_storage.back().c_str();
                ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
                violations.push_back(ev);
            }
        }
        
        // Check for hash mismatch (modified game DLLs)
        if (!result.hash_match) {
            ViolationEvent ev;
            ev.type = ViolationType::ModuleModified;
            ev.severity = Severity::Critical;  // Hash mismatch is definitive proof of tampering
            ev.address = reinterpret_cast<uintptr_t>(hMods[i]);
            static const char* hash_msg = "Module hash mismatch - file has been modified";
            ev.details = hash_msg;
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            
            char module_name_utf8[256];
            WideCharToMultiByte(CP_UTF8, 0, modPath, -1, module_name_utf8, sizeof(module_name_utf8), NULL, NULL);
            
            static std::vector<std::string> module_name_storage;
            module_name_storage.push_back(module_name_utf8);
            ev.module_name = module_name_storage.back().c_str();
            ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
            violations.push_back(ev);
        }
        
        // Check for invalid signature (tampered signed DLL)
        if (result.signature_status == SignatureStatus::Invalid) {
            ViolationEvent ev;
            ev.type = ViolationType::SignatureInvalid;
            ev.severity = Severity::High;  // Invalid signature indicates tampering
            ev.address = reinterpret_cast<uintptr_t>(hMods[i]);
            static const char* invalid_sig_msg = "Invalid or tampered digital signature";
            ev.details = invalid_sig_msg;
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            
            char module_name_utf8[256];
            WideCharToMultiByte(CP_UTF8, 0, modPath, -1, module_name_utf8, sizeof(module_name_utf8), NULL, NULL);
            
            static std::vector<std::string> module_name_storage;
            module_name_storage.push_back(module_name_utf8);
            ev.module_name = module_name_storage.back().c_str();
            ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
            violations.push_back(ev);
        }
    }
#endif

    return violations;
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

std::vector<ViolationEvent> InjectionDetector::ScanModuleSignatures() {
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
