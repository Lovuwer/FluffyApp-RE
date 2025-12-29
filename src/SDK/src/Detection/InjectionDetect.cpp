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
#include "Internal/JITSignature.hpp"

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
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
    // Initialize JIT signature validator
    jit_validator_.Initialize();
    
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
    
    // Task 5: Reset exception statistics at start of scan cycle
    SafeMemory::ResetExceptionStats();
    
    // Scan entire address space
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    uintptr_t address = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddress = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    
    // Task 5: Track scan iterations for canary validation
    int scan_iteration = 0;
    const int CANARY_CHECK_INTERVAL = 100;  // Validate canary every 100 regions
    
    while (address < maxAddress) {
        // Task 5: Check exception limit - abort if exceeded
        if (SafeMemory::IsExceptionLimitExceeded(10)) {
            #ifdef _DEBUG
            fprintf(stderr, "[InjectionDetect] Exception limit exceeded - aborting scan (active attack detected)\n");
            #endif
            
            ViolationEvent ev;
            ev.type = ViolationType::InjectedCode;
            ev.severity = Severity::Critical;
            ev.address = address;
            ev.details = "Memory scan aborted - exception limit exceeded (active attack)";
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            ev.module_name = "";
            ev.detection_id = static_cast<uint32_t>(0xDEADC0DE ^ ev.timestamp);
            violations.push_back(ev);
            break;
        }
        
        // Task 5: Periodically validate scan canary to detect VEH tampering
        if ((scan_iteration % CANARY_CHECK_INTERVAL) == 0) {
            if (!SafeMemory::ValidateScanCanary()) {
                #ifdef _DEBUG
                fprintf(stderr, "[InjectionDetect] Scan canary validation failed - VEH tampering detected\n");
                #endif
                
                ViolationEvent ev;
                ev.type = ViolationType::InjectedCode;
                ev.severity = Severity::Critical;
                ev.address = 0;
                ev.details = "VEH tampering detected during memory scan";
                ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                ev.module_name = "";
                ev.detection_id = static_cast<uint32_t>(0xBADCA9A7 ^ ev.timestamp);
                violations.push_back(ev);
                break;
            }
        }
        scan_iteration++;
        
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
                ev.details = "Executable private memory detected";
                ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                ev.module_name = "";
                ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
                violations.push_back(ev);
            }
        }
        
        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    
    // Task 5: Log exception statistics for this scan cycle
    #ifdef _DEBUG
    auto& stats = SafeMemory::GetExceptionStats();
    if (stats.GetTotalExceptions() > 0) {
        fprintf(stderr, "[InjectionDetect] Scan completed with %u exceptions: "
                "AV=%u, Guard=%u, StackOv=%u, Other=%u\n",
                stats.GetTotalExceptions(),
                stats.access_violations,
                stats.guard_page_hits,
                stats.stack_overflows,
                stats.other_exceptions);
    }
    #endif
    
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
    // Task 1: Use hash-based validation instead of name-based checks
    // This prevents module hollowing/spoofing attacks where attackers
    // create fake modules with legitimate names
    
    // First, try the new hash-based JIT signature validation
    if (jit_validator_.ValidateJITRegion(address)) {
        // Successfully validated using code signature hash
        return true;
    }
    
    // Fallback: Check against whitelist for thread origins
    // This provides an additional layer for user-configured whitelists
    // 
    // SECURITY NOTE: This fallback is necessary for flexibility but could
    // potentially be exploited if the whitelist is misconfigured or if it
    // uses weaker validation methods. Ensure the whitelist implementation
    // also uses strong validation (not just name-based checks).
    // 
    // The whitelist should only be used for:
    // - Custom JIT engines not in the signature database
    // - Temporary workarounds during signature database population
    // - User-specific scenarios that require manual configuration
    if (g_whitelist && g_whitelist->IsThreadOriginWhitelisted(address)) {
        return true;
    }
    
    // All validation methods failed - not a known JIT region
    // This is the secure default: unknown = suspicious
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
                    ev.details = "Thread with suspicious start address detected";
                    ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    ev.address = te.th32ThreadID;  // Store thread ID in address field
                    ev.module_name = "";
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
    // This is now a wrapper that calls the enhanced validation
    // We need to open the thread to perform full validation
    // However, we don't have the thread handle here, so we do basic checks
    
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
            
            // TASK 8: Reduced proximity window from 64KB to 4KB (one page)
            // This prevents attackers from using arbitrary code in ntdll
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                FARPROC pTpFunc = GetProcAddress(hNtdll, "TpReleaseWork");
                // Strict proximity check: within 4KB of thread pool functions
                if (pTpFunc) {
                    uintptr_t tpFunc = (uintptr_t)pTpFunc;
                    uintptr_t distance = (startAddress > tpFunc) ? 
                        (startAddress - tpFunc) : (tpFunc - startAddress);
                    if (distance < 4096) {  // Within 4KB (one page)
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
    
    // Basic check failed - not a recognized thread pool pattern
    // For full validation, use IsWindowsThreadPoolThreadEnhanced with thread handle
    return false;
}

// Enhanced thread pool validation with stack walk and TLS verification
bool InjectionDetector::IsWindowsThreadPoolThreadEnhanced(HANDLE hThread, uintptr_t startAddress) {
    // First, check basic proximity to thread pool functions (already reduced to 4KB)
    if (!IsWindowsThreadPoolThread(startAddress)) {
        return false;  // Not even in the right module/proximity
    }
    
    // TASK 8: Perform stack walk validation
    // Legitimate thread pool threads have consistent call stack patterns
    if (!ValidateThreadPoolStackWalk(hThread)) {
        return false;  // Stack doesn't match expected thread pool pattern
    }
    
    // TASK 8: Verify TEB ThreadLocalStoragePointer contains expected thread pool TLS data
    if (!ValidateThreadPoolTLS(hThread)) {
        return false;  // TLS data doesn't match thread pool expectations
    }
    
    // TASK 8: Check if this is a known submitted work item
    // This correlates the executing thread with registered work items
    if (!IsKnownThreadPoolWorkItem(startAddress)) {
        // Unknown work item - could be hijacked
        // However, we may not have visibility into all work items,
        // so we treat this as "suspicious but not definitive"
        // The other checks (stack walk, TLS) provide the main defense
        return true;  // Still accept if stack/TLS checks passed
    }
    
    // All validations passed - this is a legitimate thread pool thread
    return true;
}

// Validate thread pool thread stack walk
bool InjectionDetector::ValidateThreadPoolStackWalk(HANDLE hThread) {
    // TASK 8: Implement full stack walk validation
    // Legitimate thread pool threads have consistent call stack patterns
    
    // Get thread context
    CONTEXT context;
    memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_CONTROL;
    
    // Suspend thread to get consistent context
    DWORD suspendCount = SuspendThread(hThread);
    if (suspendCount == (DWORD)-1) {
        return false;  // Failed to suspend - suspicious
    }
    
    BOOL contextResult = GetThreadContext(hThread, &context);
    ResumeThread(hThread);
    
    if (!contextResult) {
        return false;  // Failed to get context
    }
    
#ifdef _WIN64
    uintptr_t stackPointer = context.Rsp;
    uintptr_t instructionPointer = context.Rip;
#else
    uintptr_t stackPointer = context.Esp;
    uintptr_t instructionPointer = context.Eip;
#endif
    
    // Validate instruction pointer is in legitimate code
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)instructionPointer, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    
    // IP must be in MEM_IMAGE (not private memory)
    if (mbi.Type != MEM_IMAGE) {
        return false;  // Executing from non-image memory is suspicious
    }
    
    // Walk the stack and verify return addresses
    // Thread pool threads should have return addresses in ntdll/kernel32/kernelbase
    const int MAX_STACK_FRAMES = 16;
    int validFramesFound = 0;
    int suspiciousFramesFound = 0;
    
    uintptr_t currentStackPtr = stackPointer;
    for (int i = 0; i < MAX_STACK_FRAMES; i++) {
        // Read potential return address from stack
        uintptr_t returnAddress = 0;
        SIZE_T bytesRead = 0;
        
        __try {
            if (!ReadProcessMemory(GetCurrentProcess(), 
                                  (LPCVOID)currentStackPtr, 
                                  &returnAddress, 
                                  sizeof(returnAddress), 
                                  &bytesRead)) {
                break;  // Can't read further
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        
        if (bytesRead != sizeof(returnAddress) || returnAddress == 0) {
            break;
        }
        
        // Check if this looks like a valid return address
        if (VirtualQuery((LPCVOID)returnAddress, &mbi, sizeof(mbi)) != 0) {
            wchar_t modulePath[MAX_PATH];
            if (mbi.AllocationBase && 
                GetModuleFileNameW((HMODULE)mbi.AllocationBase, modulePath, MAX_PATH) > 0) {
                
                const wchar_t* moduleName = wcsrchr(modulePath, L'\\');
                moduleName = moduleName ? moduleName + 1 : modulePath;
                
                // Count frames in thread pool infrastructure
                if (_wcsicmp(moduleName, L"ntdll.dll") == 0 ||
                    _wcsicmp(moduleName, L"kernel32.dll") == 0 ||
                    _wcsicmp(moduleName, L"kernelbase.dll") == 0) {
                    validFramesFound++;
                }
                // Frames in private memory are suspicious
                else if (mbi.Type == MEM_PRIVATE) {
                    suspiciousFramesFound++;
                }
            }
        }
        
        currentStackPtr += sizeof(uintptr_t);
    }
    
    // Thread pool threads should have at least 2-3 frames in thread pool infrastructure
    // and minimal frames in private memory
    if (validFramesFound < 2) {
        return false;  // Not enough thread pool frames
    }
    
    if (suspiciousFramesFound > 1) {
        return false;  // Too many suspicious frames
    }
    
    return true;
}

// Validate thread pool TLS data
bool InjectionDetector::ValidateThreadPoolTLS(HANDLE hThread) {
    // TASK 8: Verify TEB.ThreadLocalStoragePointer contains expected thread pool TLS data
    
    // Get thread TEB (Thread Environment Block)
    typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    
    static auto NtQueryInformationThread = 
        (pNtQueryInformationThread)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), 
            "NtQueryInformationThread");
    
    if (!NtQueryInformationThread) {
        return true;  // Can't validate, assume OK (fail open for compatibility)
    }
    
    // Query ThreadBasicInformation to get TEB address
    struct THREAD_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        PVOID TebBaseAddress;
        PVOID ClientId[2];
        KAFFINITY AffinityMask;
        LONG Priority;
        LONG BasePriority;
    } tbi;
    
    memset(&tbi, 0, sizeof(tbi));
    NTSTATUS status = NtQueryInformationThread(
        hThread,
        0,  // ThreadBasicInformation
        &tbi,
        sizeof(tbi),
        nullptr);
    
    if (status != 0 || !tbi.TebBaseAddress) {
        return true;  // Can't get TEB, fail open
    }
    
    // Read TLS pointer from TEB
    // TEB structure has ThreadLocalStoragePointer at a known offset
    // For x64: offset 0x58, for x86: offset 0x2C
#ifdef _WIN64
    const size_t TLS_POINTER_OFFSET = 0x58;
#else
    const size_t TLS_POINTER_OFFSET = 0x2C;
#endif
    
    uintptr_t tlsPointer = 0;
    SIZE_T bytesRead = 0;
    
    __try {
        if (!ReadProcessMemory(GetCurrentProcess(),
                              (LPCVOID)((uintptr_t)tbi.TebBaseAddress + TLS_POINTER_OFFSET),
                              &tlsPointer,
                              sizeof(tlsPointer),
                              &bytesRead)) {
            return true;  // Can't read TLS, fail open
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;  // Exception, fail open
    }
    
    if (bytesRead != sizeof(tlsPointer)) {
        return true;  // Partial read, fail open
    }
    
    // Thread pool threads typically have non-NULL TLS pointer
    // Injected threads often have NULL or invalid TLS
    if (tlsPointer == 0) {
        return false;  // NULL TLS is suspicious for thread pool threads
    }
    
    // Validate the TLS pointer points to valid memory
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)tlsPointer, &mbi, sizeof(mbi)) == 0) {
        return false;  // Invalid TLS pointer
    }
    
    // TLS should be in committed readable memory
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    
    if (!(mbi.Protect & PAGE_READONLY) && 
        !(mbi.Protect & PAGE_READWRITE) &&
        !(mbi.Protect & PAGE_EXECUTE_READ) &&
        !(mbi.Protect & PAGE_EXECUTE_READWRITE)) {
        return false;  // TLS should be readable
    }
    
    // TLS validation passed
    return true;
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

// TASK 8: Thread pool work item tracking
void InjectionDetector::RegisterThreadPoolWorkItem(uintptr_t work_function) {
    std::lock_guard<std::mutex> lock(work_items_mutex_);
    
    // Clean up expired items first
    CleanupExpiredWorkItems();
    
    ThreadPoolWorkItem item;
    item.work_function = work_function;
    item.submit_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    item.thread_id = 0;
    
    thread_pool_work_items_.push_back(item);
}

void InjectionDetector::UnregisterThreadPoolWorkItem(uintptr_t work_function) {
    std::lock_guard<std::mutex> lock(work_items_mutex_);
    
    thread_pool_work_items_.erase(
        std::remove_if(thread_pool_work_items_.begin(), thread_pool_work_items_.end(),
            [work_function](const ThreadPoolWorkItem& item) {
                return item.work_function == work_function;
            }),
        thread_pool_work_items_.end());
}

bool InjectionDetector::IsKnownThreadPoolWorkItem(uintptr_t address) const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(work_items_mutex_));
    
    // Check if this address is a known work item
    for (const auto& item : thread_pool_work_items_) {
        // Check if address is within reasonable proximity of work function
        // Work items may have trampolines or wrapper functions
        const uintptr_t proximity = 1024;  // 1KB proximity
        if (address >= item.work_function && 
            address < item.work_function + proximity) {
            return true;
        }
    }
    
    return false;
}

void InjectionDetector::CleanupExpiredWorkItems() {
    // Remove work items older than timeout
    // This function assumes the caller holds work_items_mutex_
    uint64_t currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    thread_pool_work_items_.erase(
        std::remove_if(thread_pool_work_items_.begin(), thread_pool_work_items_.end(),
            [currentTime](const ThreadPoolWorkItem& item) {
                return (currentTime - item.submit_time) > WORK_ITEM_TIMEOUT_MS;
            }),
        thread_pool_work_items_.end());
}

bool InjectionDetector::IsThreadSuspicious(uint32_t threadId) {
    // TASK 8: Enhanced thread validation with proper thread handle management
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
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
    
    if (status != 0 || !startAddress) {
        CloseHandle(hThread);
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
        CloseHandle(hThread);
        return true;
    }
    
    if (queryResult == 0) {
        CloseHandle(hThread);
        return true;  // Can't query = suspicious
    }
    
    // If thread starts in MEM_IMAGE or MEM_MAPPED, it's likely legitimate
    if (mbi.Type != MEM_PRIVATE) {
        CloseHandle(hThread);
        return false;
    }
    
    // Check whitelist for thread origins (covers JIT compilers, game engines, etc.)
    if (g_whitelist && g_whitelist->IsThreadOriginWhitelisted(startAddr)) {
        CloseHandle(hThread);
        return false;
    }
    
    // TASK 8: Use enhanced thread pool validation with stack walk and TLS checks
    // If basic check passes, perform full validation
    if (IsWindowsThreadPoolThread(startAddr)) {
        // Perform enhanced validation
        bool isLegitimate = IsWindowsThreadPoolThreadEnhanced(hThread, startAddr);
        CloseHandle(hThread);
        
        if (isLegitimate) {
            return false;  // Validated as legitimate thread pool thread
        } else {
            // Failed enhanced validation - likely hijacked thread pool thread
            return true;  // TASK 8: Detect hijacked thread pool threads
        }
    }
    
    // Check for CLR managed threads
    if (IsCLRThread(startAddr)) {
        CloseHandle(hThread);
        return false;
    }
    
    // Check if this is a legitimate trampoline near a known module
    if (IsLegitimateTrampoline(startAddr, mbi)) {
        CloseHandle(hThread);
        return false;
    }
    
    CloseHandle(hThread);
    
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
            ev.details = "System DLL loaded from game directory (possible DLL proxy)";
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            
            // Convert module path to UTF-8
            char module_name_utf8[256];
            WideCharToMultiByte(CP_UTF8, 0, modPath, -1, module_name_utf8, sizeof(module_name_utf8), NULL, NULL);
            
            ev.module_name = module_name_utf8;
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
                ev.details = "Unsigned DLL loaded in game process";
                ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                
                char module_name_utf8[256];
                WideCharToMultiByte(CP_UTF8, 0, modPath, -1, module_name_utf8, sizeof(module_name_utf8), NULL, NULL);
                
                ev.module_name = module_name_utf8;
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
            ev.details = "Module hash mismatch - file has been modified";
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            
            char module_name_utf8[256];
            WideCharToMultiByte(CP_UTF8, 0, modPath, -1, module_name_utf8, sizeof(module_name_utf8), NULL, NULL);
            
            ev.module_name = module_name_utf8;
            ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
            violations.push_back(ev);
        }
        
        // Check for invalid signature (tampered signed DLL)
        if (result.signature_status == SignatureStatus::Invalid) {
            ViolationEvent ev;
            ev.type = ViolationType::SignatureInvalid;
            ev.severity = Severity::High;  // Invalid signature indicates tampering
            ev.address = reinterpret_cast<uintptr_t>(hMods[i]);
            ev.details = "Invalid or tampered digital signature";
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            
            char module_name_utf8[256];
            WideCharToMultiByte(CP_UTF8, 0, modPath, -1, module_name_utf8, sizeof(module_name_utf8), NULL, NULL);
            
            ev.module_name = module_name_utf8;
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

void InjectionDetector::RegisterThreadPoolWorkItem(uintptr_t work_function) {
    (void)work_function;
}

void InjectionDetector::UnregisterThreadPoolWorkItem(uintptr_t work_function) {
    (void)work_function;
}

bool InjectionDetector::IsKnownThreadPoolWorkItem(uintptr_t address) const {
    (void)address;
    return false;
}

void InjectionDetector::CleanupExpiredWorkItems() {
    // Not implemented for non-Windows platforms
}

#endif // _WIN32

} // namespace SDK
} // namespace Sentinel
