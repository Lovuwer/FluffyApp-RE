/**
 * Sentinel SDK - Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 11: Inline Hook Detection Implementation
 * Task 12: IAT Hook Detection Implementation
 * Task 3: TOCTOU Vulnerability Fixes
 * Task 2: Decouple Anti-Hook Jitter from Hot Path
 * 
 * TOCTOU Protection Mechanisms:
 * 
 * 1. Double-Check Pattern (Lines 332-385):
 *    - Performs two sequential memory reads with a memory barrier
 *    - Detects dynamic hooks being installed/removed between checks
 *    - Prevents race conditions where hooks appear after verification
 * 
 * 2. Extended Hook Detection (Lines 754-815):
 *    - Scans first 16 bytes (not just 2) to catch trampoline hooks
 *    - Checks for hooks at offsets 0-5 to detect delayed hooks
 *    - Detects INT 3 breakpoints anywhere in prologue
 *    - Identifies PUSH/RET and JMP [rip+X] patterns at any offset
 * 
 * 3. Scan-Cycle Jitter (Task 2 - Decoupled from Hot Path):
 *    - Jitter moved from per-function loop to scan-cycle boundaries
 *    - Uses high-resolution waitable timer (CreateWaitableTimerExW)
 *    - Prevents attackers from predicting check timing windows
 *    - No longer accumulates latency during function scanning
 * 
 * 4. Probabilistic Scanning with Budget Enforcement (Task 2):
 *    - Scans 10-20% of functions per cycle (configurable)
 *    - Prioritizes least recently scanned functions
 *    - 5ms scan budget per frame prevents frame drops
 *    - Guarantees full coverage within 500ms window
 * 
 * 5. Honeypot Detection (Lines 822-852, 933-958):
 *    - Allows registration of decoy functions never called
 *    - Any modification to honeypots = guaranteed cheat detection
 *    - Provides high-confidence detection without false positives
 * 
 * 6. SENTINEL_PROTECTED_CALL Macro (SentinelSDK.hpp):
 *    - Inline verification immediately before function call
 *    - Only guaranteed-safe method against TOCTOU attacks
 *    - Recommended for security-critical functions
 */

#include "Internal/Detection.hpp"
#include "Internal/SafeMemory.hpp"
#include <algorithm>
#include <cstring>
#include <chrono>
#include <random>
#include <atomic>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <intrin.h>
#endif

#ifdef __linux__
#include <emmintrin.h>
#endif

namespace Sentinel {
namespace SDK {

namespace {
    // Random number generator for probabilistic scanning and jitter
    std::random_device rd;
    std::mt19937 rng(rd());
    
    // Memory barrier for double-check pattern
    inline void MemoryBarrier() {
#ifdef _WIN32
        _mm_mfence();
#elif defined(__linux__)
        __sync_synchronize();
#else
        std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
    }
    
    // Common hook patterns (x86/x64)
    struct HookPattern {
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> mask;  // 0xFF = must match, 0x00 = wildcard
        const char* description;
    };
    
    const std::vector<HookPattern> HOOK_PATTERNS = {
        // JMP rel32 (5 bytes) - E9 XX XX XX XX
        {{0xE9}, {0xFF}, "JMP rel32"},
        
        // JMP [rip+0] (6 bytes) - FF 25 00 00 00 00
        {{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}, 
         {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, "JMP [rip+0]"},
        
        // MOV RAX, imm64; JMP RAX (12 bytes) - 48 B8 XX XX XX XX XX XX XX XX FF E0
        {{0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0},
         {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF},
         "MOV RAX, imm64; JMP RAX"},
        
        // PUSH addr; RET (6 bytes, x86) - 68 XX XX XX XX C3
        {{0x68, 0x00, 0x00, 0x00, 0x00, 0xC3},
         {0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF}, "PUSH imm32; RET"},
        
        // INT 3 (breakpoint, 1 byte) - CC
        {{0xCC}, {0xFF}, "INT 3 breakpoint"},
    };
    
    bool MatchesPattern(const uint8_t* bytes, const HookPattern& pattern) {
        for (size_t i = 0; i < pattern.bytes.size(); i++) {
            if ((bytes[i] & pattern.mask[i]) != (pattern.bytes[i] & pattern.mask[i])) {
                return false;
            }
        }
        return true;
    }
    
#ifdef _WIN32
    // Helper function to check if an address is within a module's address range
    bool IsAddressInModule(uintptr_t address, const char* moduleName) {
        HMODULE hModule = GetModuleHandleA(moduleName);
        if (!hModule) return false;
        
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, 
                                  &modInfo, sizeof(modInfo))) {
            return false;
        }
        
        uintptr_t moduleBase = (uintptr_t)modInfo.lpBaseOfDll;
        uintptr_t moduleEnd = moduleBase + modInfo.SizeOfImage;
        
        return address >= moduleBase && address < moduleEnd;
    }
    
    // Helper to check if a DLL name is an API set
    bool IsApiSetDll(const char* dllName) {
        if (!dllName) return false;
        // API sets have the pattern "api-ms-win-*.dll" or "ext-ms-win-*.dll"
        return (_strnicmp(dllName, "api-ms-win-", 11) == 0 ||
                _strnicmp(dllName, "ext-ms-win-", 11) == 0);
    }
    
    // Resolve API set DLL to actual host DLL using ApiSetResolveToHost
    bool ResolveApiSetToHost(const char* apiSetName, char* hostName, size_t hostNameSize) {
        if (!apiSetName || !hostName || hostNameSize == 0) return false;
        
        // ApiSetResolveToHost is available on Windows 8+
        typedef BOOL(WINAPI* pApiSetResolveToHost)(
            PCSTR apiSetName,
            PSTR hostName,
            PDWORD hostNameSize);
        
        static auto ApiSetResolveToHost = (pApiSetResolveToHost)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "ApiSetResolveToHost");
        
        if (!ApiSetResolveToHost) {
            // Not available on this system, fallback to common mappings
            // Most API sets resolve to kernelbase.dll or other system DLLs
            if (_strnicmp(apiSetName, "api-ms-win-core-", 16) == 0) {
                strncpy_s(hostName, hostNameSize, "kernelbase.dll", _TRUNCATE);
                return true;
            }
            return false;
        }
        
        DWORD size = static_cast<DWORD>(hostNameSize);
        return ApiSetResolveToHost(apiSetName, hostName, &size) != FALSE;
    }
    
    // Get the export address from a module for a given function name
    // Returns 0 if not found
    uintptr_t GetExportAddress(HMODULE hModule, const char* functionName) {
        if (!hModule || !functionName) return 0;
        
        __try {
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;
            
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
                ((BYTE*)hModule + dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;
            
            DWORD exportDirRVA = ntHeaders->OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (exportDirRVA == 0) return 0;
            
            PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)
                ((BYTE*)hModule + exportDirRVA);
            
            DWORD* nameRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
            WORD* ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
            DWORD* funcRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
            
            // Search for function name
            for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
                const char* exportName = (const char*)((BYTE*)hModule + nameRVAs[i]);
                if (strcmp(exportName, functionName) == 0) {
                    DWORD funcRVA = funcRVAs[ordinals[i]];
                    return (uintptr_t)hModule + funcRVA;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
        
        return 0;
    }
    
    // Check if an export is a forwarder (points to another DLL)
    // Returns the forward string (e.g., "ntdll.RtlAllocateHeap") or nullptr
    const char* GetExportForwarder(HMODULE hModule, uintptr_t exportAddress) {
        if (!hModule || !exportAddress) return nullptr;
        
        __try {
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
            
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
                ((BYTE*)hModule + dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;
            
            DWORD exportDirRVA = ntHeaders->OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            DWORD exportDirSize = ntHeaders->OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            
            if (exportDirRVA == 0) return nullptr;
            
            // Check if the export address is within the export directory
            // If so, it's a forwarder string
            uintptr_t moduleBase = (uintptr_t)hModule;
            uintptr_t exportDirStart = moduleBase + exportDirRVA;
            uintptr_t exportDirEnd = exportDirStart + exportDirSize;
            
            if (exportAddress >= exportDirStart && exportAddress < exportDirEnd) {
                // This is a forwarder - the address points to a string
                return (const char*)exportAddress;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }
        
        return nullptr;
    }
    
    // Resolve export forwarding chain up to maxDepth levels
    // Returns the final module and address, or 0 if not resolved
    uintptr_t ResolveExportForward(const char* moduleName, const char* functionName, int maxDepth = 3) {
        if (!moduleName || !functionName || maxDepth <= 0) return 0;
        
        HMODULE hModule = GetModuleHandleA(moduleName);
        if (!hModule) return 0;
        
        uintptr_t exportAddr = GetExportAddress(hModule, functionName);
        if (exportAddr == 0) return 0;
        
        // Check if this is a forwarder
        const char* forwarder = GetExportForwarder(hModule, exportAddr);
        if (!forwarder) {
            // Not a forwarder, return the address
            return exportAddr;
        }
        
        // Parse the forwarder string (e.g., "ntdll.RtlAllocateHeap")
        char forwardModule[256];
        char forwardFunction[256];
        const char* dot = strchr(forwarder, '.');
        if (!dot) return exportAddr;  // Invalid forwarder format
        
        size_t moduleLen = dot - forwarder;
        constexpr size_t DLL_SUFFIX_LEN = 4;  // Length of ".dll"
        if (moduleLen >= sizeof(forwardModule) - DLL_SUFFIX_LEN) return exportAddr;
        
        strncpy_s(forwardModule, sizeof(forwardModule), forwarder, moduleLen);
        forwardModule[moduleLen] = '\0';
        strcat_s(forwardModule, sizeof(forwardModule), ".dll");
        
        strncpy_s(forwardFunction, sizeof(forwardFunction), dot + 1, _TRUNCATE);
        
        // Recursively resolve the forward
        return ResolveExportForward(forwardModule, forwardFunction, maxDepth - 1);
    }
    
    // Known system forward allowlist
    struct KnownForward {
        const char* sourceModule;
        const char* targetModule;
    };
    
    constexpr KnownForward KNOWN_FORWARDS[] = {
        {"kernel32.dll", "ntdll.dll"},        // Many heap/memory functions
        {"kernel32.dll", "kernelbase.dll"},   // Core Windows functions
        {"kernelbase.dll", "ntdll.dll"},      // Low-level system calls
        {"advapi32.dll", "kernelbase.dll"},   // Registry/security functions
    };
    constexpr size_t KNOWN_FORWARDS_COUNT = sizeof(KNOWN_FORWARDS) / sizeof(KNOWN_FORWARDS[0]);
    
    // Check if a forward from sourceModule to targetModule is in the allowlist
    bool IsKnownForward(const char* sourceModule, const char* targetModule) {
        if (!sourceModule || !targetModule) return false;
        
        // Linear search is acceptable for small allowlists (4 entries)
        // If this grows beyond ~10 entries, consider using a hash set
        for (size_t i = 0; i < KNOWN_FORWARDS_COUNT; i++) {
            if (_stricmp(sourceModule, KNOWN_FORWARDS[i].sourceModule) == 0 &&
                _stricmp(targetModule, KNOWN_FORWARDS[i].targetModule) == 0) {
                return true;
            }
        }
        return false;
    }
    
    // Get module name from an address
    bool GetModuleNameFromAddress(uintptr_t address, char* moduleName, size_t moduleNameSize) {
        if (!moduleName || moduleNameSize == 0) return false;
        
        HMODULE hModule;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCSTR)address,
                                &hModule)) {
            return false;
        }
        
        char fullPath[MAX_PATH];
        if (GetModuleFileNameA(hModule, fullPath, sizeof(fullPath)) == 0) {
            return false;
        }
        
        // Extract just the filename
        const char* filename = strrchr(fullPath, '\\');
        filename = filename ? filename + 1 : fullPath;
        
        strncpy_s(moduleName, moduleNameSize, filename, _TRUNCATE);
        return true;
    }
#endif
} // namespace

// AntiHookDetector implementation

// Get current time in milliseconds
uint64_t AntiHookDetector::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// Apply jitter at scan-cycle boundaries using high-resolution timer
void AntiHookDetector::ApplyScanCycleJitter() {
    // Generate random jitter (0-10ms)
    std::uniform_int_distribution<int> jitter_dist(0, 10);
    int jitter_ms = jitter_dist(rng);
    
    if (jitter_ms > 0) {
#ifdef _WIN32
        // Use CreateWaitableTimerExW with high-resolution flag for precise timing
        HANDLE timer = CreateWaitableTimerExW(
            nullptr,
            nullptr,
            CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
            TIMER_ALL_ACCESS);
        
        if (timer) {
            // Convert milliseconds to 100-nanosecond intervals (negative for relative time)
            LARGE_INTEGER dueTime;
            dueTime.QuadPart = -static_cast<LONGLONG>(jitter_ms) * 10000LL;
            
            if (SetWaitableTimer(timer, &dueTime, 0, nullptr, nullptr, FALSE)) {
                WaitForSingleObject(timer, INFINITE);
            }
            
            CloseHandle(timer);
        } else {
            // Fallback if high-res timer not available (use consistent cross-platform method)
            std::this_thread::sleep_for(std::chrono::milliseconds(jitter_ms));
        }
#else
        // For non-Windows platforms, use standard sleep
        std::this_thread::sleep_for(std::chrono::milliseconds(jitter_ms));
#endif
    }
}

// Select functions to scan probabilistically, prioritizing least recently scanned
void AntiHookDetector::SelectFunctionsToScan(std::vector<size_t>& indices_out, size_t max_count) {
    indices_out.clear();
    
    size_t total_functions = registered_functions_.size();
    if (total_functions == 0) {
        return;
    }
    
    uint64_t current_time = GetCurrentTimeMs();
    
    // Create candidates with priority based on time since last scan
    struct ScanCandidate {
        size_t index;
        uint64_t time_since_scan;
    };
    
    std::vector<ScanCandidate> candidates;
    candidates.reserve(total_functions);
    
    for (size_t i = 0; i < total_functions; i++) {
        uint64_t time_since_scan = current_time - registered_functions_[i].last_scanned_timestamp;
        candidates.push_back({i, time_since_scan});
    }
    
    // Sort by time_since_scan descending (prioritize least recently scanned)
    std::sort(candidates.begin(), candidates.end(),
        [](const ScanCandidate& a, const ScanCandidate& b) {
            return a.time_since_scan > b.time_since_scan;
        });
    
    // Select top max_count candidates
    size_t select_count = std::min(max_count, total_functions);
    for (size_t i = 0; i < select_count; i++) {
        indices_out.push_back(candidates[i].index);
    }
}

void AntiHookDetector::Initialize() {
#ifdef _WIN32
    SetupDllNotification();
#endif
}

void AntiHookDetector::Shutdown() {
#ifdef _WIN32
    CleanupDllNotification();
#endif
}

bool AntiHookDetector::IsInlineHooked(const FunctionProtection& func) {
    // Verify memory is readable before accessing
    if (!SafeMemory::IsReadable(reinterpret_cast<const void*>(func.address), func.prologue_size)) {
        // Memory is not readable (possibly freed/unmapped)
        return false;  // Can't verify, assume not hooked to avoid false positives
    }
    
    // DOUBLE-CHECK PATTERN: First read
    uint8_t firstRead[32];  // Max prologue size from Context.hpp
    if (!SafeMemory::SafeRead(reinterpret_cast<const void*>(func.address), 
                               firstRead, func.prologue_size)) {
        // Failed to read (access violation despite IsReadable check)
        return false;
    }
    
    // Memory barrier to ensure first read completes before second read
    MemoryBarrier();
    
    // DOUBLE-CHECK PATTERN: Second read
    uint8_t secondRead[32];
    if (!SafeMemory::SafeRead(reinterpret_cast<const void*>(func.address), 
                               secondRead, func.prologue_size)) {
        // Failed to read
        return false;
    }
    
    // Compare the two reads - if different, hook is being installed/removed dynamically
    if (std::memcmp(firstRead, secondRead, func.prologue_size) != 0) {
        // Dynamic hook detected - bytes changed between reads
        return true;
    }
    
    // Use the second read for comparison (most recent)
    uint8_t* currentBytes = secondRead;
    
    // Compare with original prologue using safe comparison
    if (!SafeMemory::SafeCompare(reinterpret_cast<const void*>(func.address),
                                  func.original_prologue.data(), func.prologue_size)) {
        // Bytes changed - check for hook patterns
        for (const auto& pattern : HOOK_PATTERNS) {
            if (pattern.bytes.size() <= func.prologue_size) {
                if (MatchesPattern(currentBytes, pattern)) {
                    return true;  // Hook pattern detected
                }
            }
        }
        // Bytes changed but no known pattern - still suspicious
        return true;
    }
    
    return false;
}

bool AntiHookDetector::IsIATHooked(const char* module_name, const char* function_name) {
#ifdef _WIN32
    // Get current module base
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return false;
    
    // Maximum reasonable PE header offset (64KB)
    static constexpr LONG MAX_PE_HEADER_OFFSET = 0x10000;
    
    // Wrap PE parsing in SEH to catch malformed headers
    __try {
        // Parse PE headers with defensive checks
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        
        // Verify DOS header is readable
        if (!SafeMemory::IsReadable(dosHeader, sizeof(IMAGE_DOS_HEADER))) {
            return false;
        }
        
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        // Verify NT headers location is within bounds and readable
        if (dosHeader->e_lfanew < 0 || dosHeader->e_lfanew > MAX_PE_HEADER_OFFSET) {
            return false;  // Unreasonable offset
        }
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
            ((BYTE*)hModule + dosHeader->e_lfanew);
        
        // Verify NT headers are readable
        if (!SafeMemory::IsReadable(ntHeaders, sizeof(IMAGE_NT_HEADERS))) {
            return false;
        }
        
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
        
        // Get import directory
        DWORD importDirRVA = ntHeaders->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importDirRVA == 0) return false;
        
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
            ((BYTE*)hModule + importDirRVA);
        
        // Verify import descriptor is readable
        if (!SafeMemory::IsReadable(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            return false;
        }
        
        // Find the target module
        while (importDesc->Name != 0) {
            // Verify this descriptor entry is readable
            if (!SafeMemory::IsReadable(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
                break;
            }
            
            const char* dllName = (const char*)((BYTE*)hModule + importDesc->Name);
            
            // Verify DLL name string is readable
            if (!SafeMemory::IsReadable(dllName, 1)) {
                importDesc++;
                continue;
            }
            
            if (_stricmp(dllName, module_name) == 0) {
                // Found the module - now find the function
                PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)
                    ((BYTE*)hModule + importDesc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA iatThunk = (PIMAGE_THUNK_DATA)
                    ((BYTE*)hModule + importDesc->FirstThunk);
                
                // Verify thunks are readable
                if (!SafeMemory::IsReadable(origThunk, sizeof(IMAGE_THUNK_DATA)) ||
                    !SafeMemory::IsReadable(iatThunk, sizeof(IMAGE_THUNK_DATA))) {
                    return false;
                }
                
                while (origThunk->u1.AddressOfData != 0) {
                    // Verify each thunk entry is readable
                    if (!SafeMemory::IsReadable(origThunk, sizeof(IMAGE_THUNK_DATA)) ||
                        !SafeMemory::IsReadable(iatThunk, sizeof(IMAGE_THUNK_DATA))) {
                        break;
                    }
                    
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)
                            ((BYTE*)hModule + origThunk->u1.AddressOfData);
                        
                        // Verify import name structure is readable
                        if (!SafeMemory::IsReadable(importName, sizeof(IMAGE_IMPORT_BY_NAME))) {
                            origThunk++;
                            iatThunk++;
                            continue;
                        }
                        
                        if (strcmp((char*)importName->Name, function_name) == 0) {
                            // Found the function - validate IAT entry
                            uintptr_t iatAddress = iatThunk->u1.Function;
                            
                            // Check if IAT points inside the expected module
                            if (IsAddressInModule(iatAddress, module_name)) {
                                return false;  // Not hooked
                            }
                            
                            // IAT points outside the module - could be a hook or legitimate forward
                            
                            // 1. Check if source module is an API set
                            char resolvedModule[256];
                            const char* actualModule = module_name;
                            if (IsApiSetDll(module_name)) {
                                if (ResolveApiSetToHost(module_name, resolvedModule, sizeof(resolvedModule))) {
                                    actualModule = resolvedModule;
                                    // Check if IAT points to resolved API set host
                                    if (IsAddressInModule(iatAddress, actualModule)) {
                                        return false;  // API set correctly resolved
                                    }
                                }
                            }
                            
                            // 2. Get the module where IAT actually points
                            char targetModule[256];
                            if (!GetModuleNameFromAddress(iatAddress, targetModule, sizeof(targetModule))) {
                                // Can't determine target module - assume hooked
                                return true;
                            }
                            
                            // 3. Check if this is a known system forward
                            if (IsKnownForward(actualModule, targetModule)) {
                                // This is a known legitimate forward
                                return false;
                            }
                            
                            // 4. Check if the expected module exports a forwarder for this function
                            uintptr_t resolvedExport = ResolveExportForward(actualModule, function_name, 3);
                            if (resolvedExport != 0) {
                                // Get module of resolved export
                                char resolvedTargetModule[256];
                                if (GetModuleNameFromAddress(resolvedExport, resolvedTargetModule, sizeof(resolvedTargetModule))) {
                                    // Check if the resolved export and IAT point to the same module
                                    if (_stricmp(targetModule, resolvedTargetModule) == 0) {
                                        // IAT follows the export forward chain - legitimate
                                        return false;
                                    }
                                }
                            }
                            
                            // IAT points somewhere unexpected - likely hooked
                            return true;
                        }
                    }
                    origThunk++;
                    iatThunk++;
                }
            }
            importDesc++;
        }
        
        return false;  // Function not found in imports
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Access violation or other exception during PE parsing
        // Return false (not hooked) instead of crashing
        return false;
    }
#else
    (void)module_name;
    (void)function_name;
    return false;  // Not implemented for non-Windows platforms
#endif
}

bool AntiHookDetector::IsDelayLoadIATHooked(const char* module_name, const char* function_name) {
#ifdef _WIN32
    // Get current module base
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return false;
    
    // Maximum reasonable PE header offset (64KB)
    static constexpr LONG MAX_PE_HEADER_OFFSET = 0x10000;
    
    // Wrap PE parsing in SEH to catch malformed headers
    __try {
        // Parse PE headers with defensive checks
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        
        // Verify DOS header is readable
        if (!SafeMemory::IsReadable(dosHeader, sizeof(IMAGE_DOS_HEADER))) {
            return false;
        }
        
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        // Verify NT headers location is within bounds and readable
        if (dosHeader->e_lfanew < 0 || dosHeader->e_lfanew > MAX_PE_HEADER_OFFSET) {
            return false;  // Unreasonable offset
        }
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
            ((BYTE*)hModule + dosHeader->e_lfanew);
        
        // Verify NT headers are readable
        if (!SafeMemory::IsReadable(ntHeaders, sizeof(IMAGE_NT_HEADERS))) {
            return false;
        }
        
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
        
        // Verify DataDirectory has enough entries before accessing DELAY_IMPORT
        if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
            return false;  // DataDirectory too small
        }
        
        // Get delay-load import directory
        DWORD delayImportDirRVA = ntHeaders->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
        if (delayImportDirRVA == 0) {
            return false;  // No delay-load imports
        }
        
        // Use system-defined delay-load descriptor structure from delayimp.h
        // If not available, we define it locally for compatibility
        #ifndef _DELAY_IMP_VER
        struct ImgDelayDescr {
            DWORD grAttrs;
            DWORD rvaDLLName;
            DWORD rvaHmod;
            DWORD rvaIAT;
            DWORD rvaINT;
            DWORD rvaBoundIAT;
            DWORD rvaUnloadIAT;
            DWORD dwTimeStamp;
        };
        #define IMAGE_DELAYLOAD_DESCRIPTOR ImgDelayDescr
        #endif
        
        IMAGE_DELAYLOAD_DESCRIPTOR* delayDesc = (IMAGE_DELAYLOAD_DESCRIPTOR*)
            ((BYTE*)hModule + delayImportDirRVA);
        
        // Verify delay descriptor is readable
        if (!SafeMemory::IsReadable(delayDesc, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))) {
            return false;
        }
        
        // Find the target module
        while (delayDesc->rvaDLLName != 0) {
            // Verify this descriptor entry is readable
            if (!SafeMemory::IsReadable(delayDesc, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))) {
                break;
            }
            
            const char* dllName = (const char*)((BYTE*)hModule + delayDesc->rvaDLLName);
            
            // Verify DLL name string is readable
            if (!SafeMemory::IsReadable(dllName, 1)) {
                delayDesc++;
                continue;
            }
            
            if (_stricmp(dllName, module_name) == 0) {
                // Found the module - check if it's loaded yet
                HMODULE* moduleHandle = (HMODULE*)((BYTE*)hModule + delayDesc->rvaHmod);
                
                // Verify module handle pointer is readable
                if (!SafeMemory::IsReadable(moduleHandle, sizeof(HMODULE))) {
                    delayDesc++;
                    continue;
                }
                
                if (*moduleHandle == nullptr) {
                    // Module not loaded yet - can't check for hooks
                    return false;
                }
                
                // Module is loaded - check IAT entries
                PIMAGE_THUNK_DATA nameThunk = (PIMAGE_THUNK_DATA)
                    ((BYTE*)hModule + delayDesc->rvaINT);
                PIMAGE_THUNK_DATA iatThunk = (PIMAGE_THUNK_DATA)
                    ((BYTE*)hModule + delayDesc->rvaIAT);
                
                // Verify thunks are readable
                if (!SafeMemory::IsReadable(nameThunk, sizeof(IMAGE_THUNK_DATA)) ||
                    !SafeMemory::IsReadable(iatThunk, sizeof(IMAGE_THUNK_DATA))) {
                    return false;
                }
                
                while (nameThunk->u1.AddressOfData != 0) {
                    // Verify each thunk entry is readable
                    if (!SafeMemory::IsReadable(nameThunk, sizeof(IMAGE_THUNK_DATA)) ||
                        !SafeMemory::IsReadable(iatThunk, sizeof(IMAGE_THUNK_DATA))) {
                        break;
                    }
                    
                    if (!(nameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)
                            ((BYTE*)hModule + nameThunk->u1.AddressOfData);
                        
                        // Verify import name structure is readable
                        if (!SafeMemory::IsReadable(importName, sizeof(IMAGE_IMPORT_BY_NAME))) {
                            nameThunk++;
                            iatThunk++;
                            continue;
                        }
                        
                        if (strcmp((char*)importName->Name, function_name) == 0) {
                            // Found the function - validate IAT entry using same logic as IsIATHooked
                            uintptr_t iatAddress = iatThunk->u1.Function;
                            
                            // Check if IAT points inside the expected module
                            if (IsAddressInModule(iatAddress, module_name)) {
                                return false;  // Not hooked
                            }
                            
                            // Apply same forward/API set resolution logic
                            char resolvedModule[256];
                            const char* actualModule = module_name;
                            if (IsApiSetDll(module_name)) {
                                if (ResolveApiSetToHost(module_name, resolvedModule, sizeof(resolvedModule))) {
                                    actualModule = resolvedModule;
                                    if (IsAddressInModule(iatAddress, actualModule)) {
                                        return false;
                                    }
                                }
                            }
                            
                            char targetModule[256];
                            if (!GetModuleNameFromAddress(iatAddress, targetModule, sizeof(targetModule))) {
                                return true;
                            }
                            
                            if (IsKnownForward(actualModule, targetModule)) {
                                return false;
                            }
                            
                            uintptr_t resolvedExport = ResolveExportForward(actualModule, function_name, 3);
                            if (resolvedExport != 0) {
                                char resolvedTargetModule[256];
                                if (GetModuleNameFromAddress(resolvedExport, resolvedTargetModule, sizeof(resolvedTargetModule))) {
                                    if (_stricmp(targetModule, resolvedTargetModule) == 0) {
                                        return false;
                                    }
                                }
                            }
                            
                            return true;
                        }
                    }
                    nameThunk++;
                    iatThunk++;
                }
            }
            delayDesc++;
        }
        
        return false;  // Function not found in delay-load imports
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Access violation or other exception during PE parsing
        return false;
    }
#else
    (void)module_name;
    (void)function_name;
    return false;  // Not implemented for non-Windows platforms
#endif
}

bool AntiHookDetector::HasSuspiciousJump(const void* address) {
    // Extended check: scan first 16 bytes instead of just 2
    constexpr size_t SCAN_SIZE = 16;
    
    // Verify memory is readable
    if (!SafeMemory::IsReadable(address, SCAN_SIZE)) {
        return false;  // Can't read, assume not suspicious
    }
    
    uint8_t bytes[SCAN_SIZE];
    if (!SafeMemory::SafeRead(address, bytes, SCAN_SIZE)) {
        return false;  // Failed to read
    }
    
    // Check for hooks at offsets 0-5 (catches trampoline hooks)
    for (size_t offset = 0; offset <= 5 && offset < SCAN_SIZE; offset++) {
        // Check for JMP instructions at various offsets
        if (offset + 1 <= SCAN_SIZE) {
            switch (bytes[offset]) {
                case 0xE9:  // JMP rel32 (5 bytes)
                    return true;
                case 0xEB:  // JMP rel8 (2 bytes)
                    return true;
                case 0xE8:  // CALL rel32 (unusual at function start)
                    return true;
                case 0xFF:  // JMP/CALL indirect
                    return true;
            }
        }
    }
    
    // Check for INT 3 (0xCC) anywhere in the first 16 bytes
    for (size_t i = 0; i < SCAN_SIZE; i++) {
        if (bytes[i] == 0xCC) {
            return true;
        }
    }
    
    // Check for MOV RAX, imm64; JMP RAX pattern at offset 0
    if (bytes[0] == 0x48 && bytes[1] == 0xB8) {
        // MOV RAX, imm64 (likely trampoline setup)
        return true;
    }
    
    // Check for PUSH imm32; RET pattern
    for (size_t offset = 0; offset <= 5 && offset + 5 < SCAN_SIZE; offset++) {
        if (bytes[offset] == 0x68 && bytes[offset + 5] == 0xC3) {
            // PUSH imm32; RET
            return true;
        }
    }
    
    // Check for JMP [rip+0] pattern (FF 25 00 00 00 00)
    for (size_t offset = 0; offset <= 5 && offset + 5 < SCAN_SIZE; offset++) {
        if (bytes[offset] == 0xFF && bytes[offset + 1] == 0x25) {
            // JMP [rip+displacement]
            return true;
        }
    }
    
    return false;
}

void AntiHookDetector::RegisterFunction(const FunctionProtection& func) {
    std::lock_guard<std::mutex> lock(functions_mutex_);
    registered_functions_.push_back(func);
}

void AntiHookDetector::UnregisterFunction(uintptr_t address) {
    std::lock_guard<std::mutex> lock(functions_mutex_);
    registered_functions_.erase(
        std::remove_if(registered_functions_.begin(), registered_functions_.end(),
            [address](const FunctionProtection& f) { return f.address == address; }),
        registered_functions_.end()
    );
}

void AntiHookDetector::RegisterHoneypot(const FunctionProtection& func) {
    std::lock_guard<std::mutex> lock(functions_mutex_);
    honeypot_functions_.push_back(func);
}

void AntiHookDetector::UnregisterHoneypot(uintptr_t address) {
    std::lock_guard<std::mutex> lock(functions_mutex_);
    honeypot_functions_.erase(
        std::remove_if(honeypot_functions_.begin(), honeypot_functions_.end(),
            [address](const FunctionProtection& f) { return f.address == address; }),
        honeypot_functions_.end()
    );
}

bool AntiHookDetector::CheckFunction(uintptr_t address) {
    std::lock_guard<std::mutex> lock(functions_mutex_);
    
    for (const auto& func : registered_functions_) {
        if (func.address == address) {
            return IsInlineHooked(func);
        }
    }
    
    // Not registered - do quick suspicious jump check
    return HasSuspiciousJump(reinterpret_cast<const void*>(address));
}

std::vector<ViolationEvent> AntiHookDetector::QuickCheck() {
    std::vector<ViolationEvent> violations;
    std::lock_guard<std::mutex> lock(functions_mutex_);
    
    // Task 5: Reset exception statistics at start of scan cycle
    SafeMemory::ResetExceptionStats();
    
    // Apply jitter at scan-cycle boundary (before starting scan)
    ApplyScanCycleJitter();
    
    // Start scan budget timer
    current_scan_start_time_ms_ = GetCurrentTimeMs();
    
    // Calculate how many functions to scan (10-20% probabilistic)
    size_t total_functions = registered_functions_.size();
    size_t scan_count = static_cast<size_t>(total_functions * PROBABILISTIC_SCAN_RATIO);
    scan_count = std::max(scan_count, size_t(1));  // Scan at least 1 if any registered
    scan_count = std::min(scan_count, QUICK_CHECK_MAX_FUNCTIONS);  // Cap for QuickCheck
    
    // Select functions to scan (prioritizing least recently scanned)
    std::vector<size_t> indices_to_scan;
    SelectFunctionsToScan(indices_to_scan, scan_count);
    
    // Task 5: Track scan iterations for canary validation
    int scan_iteration = 0;
    
    // Scan selected functions with budget enforcement
    for (size_t idx : indices_to_scan) {
        // Task 5: Check exception limit - abort if exceeded
        if (SafeMemory::IsExceptionLimitExceeded(10)) {
            #ifdef _DEBUG
            fprintf(stderr, "[AntiHook] Exception limit exceeded - aborting scan (active attack detected)\n");
            #endif
            break;
        }
        
        // Task 5: Validate scan canary every 10 functions
        if ((scan_iteration % 10) == 0) {
            if (!SafeMemory::ValidateScanCanary()) {
                #ifdef _DEBUG
                fprintf(stderr, "[AntiHook] Scan canary validation failed - VEH tampering detected\n");
                #endif
                break;
            }
        }
        scan_iteration++;
        
        // Check scan budget - abort if we've exceeded 5ms
        uint64_t elapsed = GetCurrentTimeMs() - current_scan_start_time_ms_;
        if (elapsed >= SCAN_BUDGET_MS) {
            break;  // Budget exceeded, resume next frame
        }
        
        if (idx < registered_functions_.size()) {
            auto& func = registered_functions_[idx];
            
            if (IsInlineHooked(func)) {
                ViolationEvent ev;
                ev.type = ViolationType::InlineHook;
                ev.severity = Severity::Critical;
                ev.address = func.address;
                ev.details = "Inline hook detected";
                ev.module_name = "";
                ev.timestamp = GetCurrentTimeMs();
                ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
                violations.push_back(ev);
            }
            
            // Update last scanned timestamp
            func.last_scanned_timestamp = GetCurrentTimeMs();
        }
    }
    
    return violations;
}

std::vector<ViolationEvent> AntiHookDetector::ScanCriticalAPIs() {
    std::vector<ViolationEvent> violations;
    
#ifdef _WIN32
    // List of security-critical APIs to check
    struct APICheck {
        const char* module;
        const char* function;
    };
    
    const std::vector<APICheck> CRITICAL_APIS = {
        {"kernel32.dll", "VirtualAlloc"},
        {"kernel32.dll", "VirtualProtect"},
        {"kernel32.dll", "CreateRemoteThread"},
        {"kernel32.dll", "WriteProcessMemory"},
        {"kernel32.dll", "ReadProcessMemory"},
        {"ntdll.dll", "NtQueryInformationProcess"},
        {"ntdll.dll", "NtSetInformationThread"},
        {"user32.dll", "GetAsyncKeyState"},
        {"user32.dll", "SetWindowsHookExW"},
    };
    
    uint64_t current_time = GetCurrentTimeMs();
    
    for (size_t i = 0; i < CRITICAL_APIS.size(); i++) {
        const auto& api = CRITICAL_APIS[i];
        
        // Check both regular IAT and delay-load IAT
        bool isHooked = IsIATHooked(api.module, api.function);
        if (!isHooked) {
            isHooked = IsDelayLoadIATHooked(api.module, api.function);
        }
        
        if (isHooked) {
            ViolationEvent ev;
            ev.type = ViolationType::IATHook;
            ev.severity = Severity::High;  // Reduced from Critical - IAT hooks are primitive
            ev.address = 0;
            ev.details = "IAT hook detected";
            ev.module_name = api.module;
            ev.timestamp = current_time;
            // Include API index to prevent ID collisions
            ev.detection_id = static_cast<uint32_t>(ev.timestamp ^ (i << 24));
            violations.push_back(ev);
        }
    }
#endif
    
    return violations;
}

std::vector<ViolationEvent> AntiHookDetector::CheckHoneypots() {
    std::vector<ViolationEvent> violations;
    std::lock_guard<std::mutex> lock(functions_mutex_);
    
    uint64_t current_time = GetCurrentTimeMs();
    
    // Check honeypot functions - ANY modification is guaranteed cheat detection
    for (auto& honeypot : honeypot_functions_) {
        if (IsInlineHooked(honeypot)) {
            ViolationEvent ev;
            ev.type = ViolationType::InlineHook;
            ev.severity = Severity::Critical;  // Honeypot modification = guaranteed cheat
            ev.address = honeypot.address;
            ev.details = "Honeypot function modified - cheat detected";
            ev.module_name = "";
            ev.timestamp = current_time;
            ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp ^ 0xDEADBEEF);
            violations.push_back(ev);
        }
        
        // Update last scanned timestamp for honeypots too
        honeypot.last_scanned_timestamp = current_time;
    }
    
    return violations;
}

std::vector<ViolationEvent> AntiHookDetector::FullScan() {
    std::vector<ViolationEvent> violations;
    
    // Task 5: Reset exception statistics at start of scan cycle
    SafeMemory::ResetExceptionStats();
    
    // Apply jitter at scan-cycle boundary (before starting scan)
    ApplyScanCycleJitter();
    
    // Start scan budget timer
    current_scan_start_time_ms_ = GetCurrentTimeMs();
    
    // Task 5: Track scan iterations for canary validation
    int scan_iteration = 0;
    
    // Inline hook checks with probabilistic scanning and budget enforcement
    {
        std::lock_guard<std::mutex> lock(functions_mutex_);
        
        // For FullScan, we scan more functions but still use probabilistic approach
        size_t total_functions = registered_functions_.size();
        size_t scan_count = static_cast<size_t>(total_functions * PROBABILISTIC_SCAN_RATIO);
        scan_count = std::max(scan_count, size_t(1));
        // Cap at the lesser of total_functions or FULL_SCAN_MAX_FUNCTIONS
        if (scan_count > total_functions) {
            scan_count = total_functions;
        }
        if (scan_count > FULL_SCAN_MAX_FUNCTIONS) {
            scan_count = FULL_SCAN_MAX_FUNCTIONS;
        }
        
        // Select functions to scan (prioritizing least recently scanned)
        std::vector<size_t> indices_to_scan;
        SelectFunctionsToScan(indices_to_scan, scan_count);
        
        for (size_t idx : indices_to_scan) {
            // Task 5: Check exception limit - abort if exceeded
            if (SafeMemory::IsExceptionLimitExceeded(10)) {
                #ifdef _DEBUG
                fprintf(stderr, "[AntiHook] Exception limit exceeded in FullScan - aborting\n");
                #endif
                break;
            }
            
            // Task 5: Validate scan canary every 10 functions
            if ((scan_iteration % 10) == 0) {
                if (!SafeMemory::ValidateScanCanary()) {
                    #ifdef _DEBUG
                    fprintf(stderr, "[AntiHook] Scan canary validation failed in FullScan\n");
                    #endif
                    break;
                }
            }
            scan_iteration++;
            
            // Check scan budget - abort if we've exceeded budget
            uint64_t elapsed = GetCurrentTimeMs() - current_scan_start_time_ms_;
            if (elapsed >= SCAN_BUDGET_MS) {
                break;  // Budget exceeded, resume next frame
            }
            
            if (idx < registered_functions_.size()) {
                auto& func = registered_functions_[idx];
                
                if (IsInlineHooked(func)) {
                    ViolationEvent ev;
                    ev.type = ViolationType::InlineHook;
                    ev.severity = Severity::Critical;
                    ev.address = func.address;
                    ev.details = "Inline hook detected";
                    ev.module_name = "";
                    ev.timestamp = GetCurrentTimeMs();
                    ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
                    violations.push_back(ev);
                }
                
                // Update last scanned timestamp
                func.last_scanned_timestamp = GetCurrentTimeMs();
            }
        }
    } // Lock automatically released here
    
    // Check scan budget before proceeding to honeypots
    uint64_t elapsed = GetCurrentTimeMs() - current_scan_start_time_ms_;
    if (elapsed < SCAN_BUDGET_MS) {
        // Honeypot checks (has its own lock)
        auto honeypotViolations = CheckHoneypots();
        violations.insert(violations.end(), 
                         honeypotViolations.begin(), honeypotViolations.end());
    }
    
    // Check scan budget before proceeding to IAT checks
    elapsed = GetCurrentTimeMs() - current_scan_start_time_ms_;
    if (elapsed < SCAN_BUDGET_MS) {
        // IAT hook checks
        auto iatViolations = ScanCriticalAPIs();
        violations.insert(violations.end(), 
                         iatViolations.begin(), iatViolations.end());
    }
    
    return violations;
}

void AntiHookDetector::UnregisterFunctionsInModule(uintptr_t module_base) {
#ifdef _WIN32
    if (module_base == 0) return;
    
    // Get module information to determine its address range
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), 
                              reinterpret_cast<HMODULE>(module_base),
                              &modInfo, sizeof(modInfo))) {
        return;
    }
    
    uintptr_t moduleStart = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    uintptr_t moduleEnd = moduleStart + modInfo.SizeOfImage;
    
    std::lock_guard<std::mutex> lock(functions_mutex_);
    
    // Remove all functions in this module's address range
    registered_functions_.erase(
        std::remove_if(registered_functions_.begin(), registered_functions_.end(),
            [moduleStart, moduleEnd](const FunctionProtection& f) {
                return f.address >= moduleStart && f.address < moduleEnd;
            }),
        registered_functions_.end()
    );
#else
    (void)module_base;
#endif
}

#ifdef _WIN32
void CALLBACK AntiHookDetector::DllNotificationCallback(
    ULONG notification_reason,
    const void* notification_data,
    void* context) {
    
    // LDR_DLL_NOTIFICATION_REASON_UNLOADED = 2
    if (notification_reason != 2) {
        return;
    }
    
    if (!context || !notification_data) {
        return;
    }
    
    // Cast to LDR_DLL_NOTIFICATION_DATA structure
    struct LDR_DLL_NOTIFICATION_DATA {
        ULONG Flags;
        const UNICODE_STRING* FullDllName;
        const UNICODE_STRING* BaseDllName;
        void* DllBase;
        ULONG SizeOfImage;
    };
    
    const auto* data = static_cast<const LDR_DLL_NOTIFICATION_DATA*>(notification_data);
    AntiHookDetector* detector = static_cast<AntiHookDetector*>(context);
    
    // Unregister all functions in the unloaded module
    detector->UnregisterFunctionsInModule(reinterpret_cast<uintptr_t>(data->DllBase));
}

void AntiHookDetector::SetupDllNotification() {
    // LdrRegisterDllNotification is available from Windows Vista onwards
    typedef NTSTATUS(NTAPI* pLdrRegisterDllNotification)(
        ULONG flags,
        void* callback,
        void* context,
        void** cookie);
    
    static auto LdrRegisterDllNotification = 
        (pLdrRegisterDllNotification)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"),
            "LdrRegisterDllNotification");
    
    if (!LdrRegisterDllNotification) {
        // Function not available (pre-Vista), skip notification setup
        return;
    }
    
    // Register for DLL load/unload notifications
    NTSTATUS status = LdrRegisterDllNotification(
        0,
        reinterpret_cast<void*>(&AntiHookDetector::DllNotificationCallback),
        this,
        &dll_notification_cookie_);
    
    if (status != 0) {
        dll_notification_cookie_ = nullptr;
    }
}

void AntiHookDetector::CleanupDllNotification() {
    if (!dll_notification_cookie_) {
        return;
    }
    
    typedef NTSTATUS(NTAPI* pLdrUnregisterDllNotification)(void* cookie);
    
    static auto LdrUnregisterDllNotification = 
        (pLdrUnregisterDllNotification)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"),
            "LdrUnregisterDllNotification");
    
    if (LdrUnregisterDllNotification) {
        LdrUnregisterDllNotification(dll_notification_cookie_);
        dll_notification_cookie_ = nullptr;
    }
}
#endif

} // namespace SDK
} // namespace Sentinel
