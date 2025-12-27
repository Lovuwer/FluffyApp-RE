/**
 * Sentinel SDK - Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 11: Inline Hook Detection Implementation
 * Task 12: IAT Hook Detection Implementation
 */

#include "Internal/Detection.hpp"
#include "Internal/SafeMemory.hpp"
#include <algorithm>
#include <cstring>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace Sentinel {
namespace SDK {

namespace {
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
#endif
}

// AntiHookDetector implementation
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
    
    // Read current bytes at function address using safe access
    uint8_t currentBytes[32];  // Max prologue size from Context.hpp
    if (!SafeMemory::SafeRead(reinterpret_cast<const void*>(func.address), 
                               currentBytes, func.prologue_size)) {
        // Failed to read (access violation despite IsReadable check)
        return false;
    }
    
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
        if (dosHeader->e_lfanew < 0 || dosHeader->e_lfanew > 0x10000) {
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
                            return !IsAddressInModule(iatAddress, module_name);
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

bool AntiHookDetector::HasSuspiciousJump(const void* address) {
    // Verify memory is readable
    if (!SafeMemory::IsReadable(address, 2)) {
        return false;  // Can't read, assume not suspicious
    }
    
    uint8_t bytes[2];
    if (!SafeMemory::SafeRead(address, bytes, 2)) {
        return false;  // Failed to read
    }
    
    // Check first byte for immediate jump/call indicators
    switch (bytes[0]) {
        case 0xE9:  // JMP rel32
        case 0xE8:  // CALL rel32 (unusual at function start)
        case 0xEB:  // JMP rel8
        case 0xFF:  // JMP/CALL indirect
        case 0xCC:  // INT 3
            return true;
    }
    
    // Check for 2-byte prefixes (x64)
    if (bytes[0] == 0x48 && bytes[1] == 0xB8) {
        // MOV RAX, imm64 (likely trampoline setup)
        return true;
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
    
    // Check subset for performance (first 10)
    size_t checkCount = std::min(registered_functions_.size(), size_t(10));
    for (size_t i = 0; i < checkCount; i++) {
        if (IsInlineHooked(registered_functions_[i])) {
            ViolationEvent ev;
            ev.type = ViolationType::InlineHook;
            ev.severity = Severity::Critical;
            ev.address = registered_functions_[i].address;
            static const char* detail_msg = "Inline hook detected";
            ev.details = detail_msg;
            ev.module_name = nullptr;
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
            violations.push_back(ev);
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
    
    for (size_t i = 0; i < CRITICAL_APIS.size(); i++) {
        const auto& api = CRITICAL_APIS[i];
        if (IsIATHooked(api.module, api.function)) {
            ViolationEvent ev;
            ev.type = ViolationType::IATHook;
            ev.severity = Severity::Critical;
            ev.address = 0;
            static const char* detail_msg = "IAT hook detected";
            ev.details = detail_msg;
            ev.module_name = api.module;
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            // Include API index to prevent ID collisions
            ev.detection_id = static_cast<uint32_t>(ev.timestamp ^ (i << 24));
            violations.push_back(ev);
        }
    }
#endif
    
    return violations;
}

std::vector<ViolationEvent> AntiHookDetector::FullScan() {
    std::vector<ViolationEvent> violations;
    std::lock_guard<std::mutex> lock(functions_mutex_);
    
    // Inline hook checks
    for (const auto& func : registered_functions_) {
        if (IsInlineHooked(func)) {
            ViolationEvent ev;
            ev.type = ViolationType::InlineHook;
            ev.severity = Severity::Critical;
            ev.address = func.address;
            static const char* detail_msg = "Inline hook detected";
            ev.details = detail_msg;
            ev.module_name = nullptr;
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
            violations.push_back(ev);
        }
    }
    
    // IAT hook checks
    auto iatViolations = ScanCriticalAPIs();
    violations.insert(violations.end(), 
                     iatViolations.begin(), iatViolations.end());
    
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
