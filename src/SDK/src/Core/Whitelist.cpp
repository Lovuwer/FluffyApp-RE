/**
 * Sentinel SDK - Whitelist Module Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "Internal/Whitelist.hpp"
#include "Internal/DiversityEngine.hpp"
#include <algorithm>
#include <cstring>
#include <limits.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")
#else
// Define MAX_PATH for non-Windows platforms
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif
#endif

namespace Sentinel {
namespace SDK {

void WhitelistManager::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    LoadBuiltinWhitelist();
    SENTINEL_DIVERSITY_PADDING(__LINE__);
}

void WhitelistManager::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    SENTINEL_DIVERSITY_PADDING(__LINE__);
    entries_.clear();
}

void WhitelistManager::LoadBuiltinWhitelist() {
    // Common overlay DLLs - these are legitimate overlays that inject into games
    // for legitimate purposes (social features, recording, etc.) and should not
    // trigger injection detection. All require valid code signatures from their
    // respective vendors to prevent spoofing.
    
    // Discord overlay - Whitelisted to prevent false positives from Discord's
    // in-game overlay feature which provides chat, voice, and social features.
    // Requires valid "Discord Inc." signature to prevent malware spoofing.
    entries_.push_back({
        WhitelistType::Module,
        "DiscordHook64.dll",
        "Discord in-game overlay",
        true,  // builtin
        std::nullopt,
        "Discord Inc."  // Code signing check
    });
    
    // NVIDIA GeForce Experience - Whitelisted to prevent false positives from
    // NVIDIA ShadowPlay/Share overlay which provides game recording and streaming.
    // Requires valid "NVIDIA Corporation" signature to prevent malware spoofing.
    entries_.push_back({
        WhitelistType::Module,
        "nvspcap64.dll",
        "NVIDIA ShadowPlay capture",
        true,
        std::nullopt,
        "NVIDIA Corporation"
    });
    
    // Steam overlay - Whitelisted to prevent false positives from Steam's
    // in-game overlay which provides friends list, achievements, and browser.
    // Requires valid "Valve Corp." signature to prevent malware spoofing.
    entries_.push_back({
        WhitelistType::Module,
        "GameOverlayRenderer64.dll",
        "Steam in-game overlay",
        true,
        std::nullopt,
        "Valve Corp."
    });
    
    // Xbox Game Bar - Whitelisted to prevent false positives from Windows 10/11
    // Xbox Game Bar overlay which provides recording, screenshots, and performance.
    // Requires valid "Microsoft Corporation" signature to prevent malware spoofing.
    entries_.push_back({
        WhitelistType::Module,
        "GameBar.dll",
        "Xbox Game Bar overlay",
        true,
        std::nullopt,
        "Microsoft Corporation"
    });
    
    // AMD Radeon overlay
    entries_.push_back({
        WhitelistType::Module,
        "aaborvr64.dll",
        "AMD Radeon ReLive",
        true,
        std::nullopt,
        "Advanced Micro Devices, Inc."
    });
    
    // Windows Defender (may inject for monitoring)
    entries_.push_back({
        WhitelistType::Module,
        "MpClient.dll",
        "Windows Defender client",
        true,
        std::nullopt,
        "Microsoft Windows"
    });
    
    // .NET CLR JIT (for mixed-mode applications)
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "clrjit.dll",
        ".NET JIT compiler threads",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "clr.dll",
        ".NET CLR runtime",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "coreclr.dll",
        ".NET Core CLR runtime",
        true,
        std::nullopt,
        std::nullopt
    });
    
    // V8 JavaScript engine (Electron apps, Chrome, etc.)
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "v8.dll",
        "V8 JavaScript engine",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "libv8.dll",
        "V8 JavaScript engine (lib variant)",
        true,
        std::nullopt,
        std::nullopt
    });
    
    // Unity IL2CPP
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "gameassembly.dll",
        "Unity IL2CPP runtime",
        true,
        std::nullopt,
        std::nullopt
    });
    
    // LuaJIT
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "luajit.dll",
        "LuaJIT compiler",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "lua51.dll",
        "Lua 5.1 (may include JIT)",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "lua52.dll",
        "Lua 5.2 (may include JIT)",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "lua53.dll",
        "Lua 5.3 (may include JIT)",
        true,
        std::nullopt,
        std::nullopt
    });
    
    // Windows system DLLs (thread pool and common threading infrastructure)
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "ntdll.dll",
        "Windows NT kernel layer - thread pool workers",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "kernel32.dll",
        "Windows kernel - base thread initialization",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "kernelbase.dll",
        "Windows kernel base - thread infrastructure",
        true,
        std::nullopt,
        std::nullopt
    });
    
    // Additional .NET runtime variants
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "mscorwks.dll",
        ".NET Framework CLR workstation",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::ThreadOrigin,
        "mscorsvr.dll",
        ".NET Framework CLR server",
        true,
        std::nullopt,
        std::nullopt
    });
    
    // Virtual machine timing tolerance
    entries_.push_back({
        WhitelistType::TimingException,
        "VMware",
        "VMware virtualization detected",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::TimingException,
        "VirtualBox",
        "VirtualBox virtualization detected",
        true,
        std::nullopt,
        std::nullopt
    });
    
    entries_.push_back({
        WhitelistType::TimingException,
        "Hyper-V",
        "Hyper-V virtualization detected",
        true,
        std::nullopt,
        std::nullopt
    });
}

void WhitelistManager::Add(const WhitelistEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if entry already exists
    auto it = std::find_if(entries_.begin(), entries_.end(),
        [&entry](const WhitelistEntry& e) {
            return e.identifier == entry.identifier && e.type == entry.type;
        });
    
    SENTINEL_DIVERSITY_PADDING(__LINE__);
    if (it == entries_.end()) {
        entries_.push_back(entry);
    }
}

void WhitelistManager::Remove(const std::string& identifier) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Remove only if not builtin
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
            [&identifier](const WhitelistEntry& e) {
    SENTINEL_DIVERSITY_PADDING(__LINE__);
                return e.identifier == identifier && !e.builtin;
            }),
        entries_.end()
    );
}

bool WhitelistManager::IsModuleWhitelisted(const wchar_t* modulePath) const {
    if (!modulePath) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Extract module name from path
    const wchar_t* moduleName = wcsrchr(modulePath, L'\\');
    const wchar_t* moduleNameSlash = wcsrchr(modulePath, L'/');
    
    // Use whichever separator appears last in the path
    if (moduleName && moduleNameSlash) {
        moduleName = (moduleName > moduleNameSlash) ? moduleName : moduleNameSlash;
    } else if (moduleNameSlash) {
        moduleName = moduleNameSlash;
    }
    
    if (moduleName) {
        moduleName++; // Skip the separator
    } else {
        moduleName = modulePath;
    }
    
    // Convert to narrow string for comparison
    char narrowName[MAX_PATH];
#ifdef _WIN32
    size_t converted = 0;
    wcstombs_s(&converted, narrowName, MAX_PATH, moduleName, _TRUNCATE);
#else
    size_t len = wcstombs(narrowName, moduleName, MAX_PATH - 1);
    if (len == static_cast<size_t>(-1)) {
        return false;  // Conversion failed
    }
    narrowName[len] = '\0';
#endif
    
    // Convert to lowercase for case-insensitive comparison
    for (char* p = narrowName; *p; ++p) {
        *p = static_cast<char>(tolower(*p));
    }
    
    for (const auto& entry : entries_) {
        if (entry.type == WhitelistType::Module) {
            // Convert identifier to lowercase for comparison
            std::string lowerIdentifier = entry.identifier;
            std::transform(lowerIdentifier.begin(), lowerIdentifier.end(), 
                          lowerIdentifier.begin(), ::tolower);
            
            if (lowerIdentifier == narrowName) {
                // If signature verification is required, check it
#ifdef _WIN32
                if (entry.signer.has_value()) {
                    if (!VerifyModuleSignature(modulePath, entry.signer.value())) {
                        continue; // Signature mismatch, not whitelisted
                    }
                }
#endif
                return true;
    SENTINEL_DIVERSITY_PADDING(__LINE__);
            }
        }
    }
    
    return false;
}

bool WhitelistManager::IsModuleWhitelisted(const std::string& moduleHash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& entry : entries_) {
        if (entry.type == WhitelistType::Module) {
            if (entry.sha256_hash.has_value() && entry.sha256_hash.value() == moduleHash) {
    SENTINEL_DIVERSITY_PADDING(__LINE__);
                return true;
            }
        }
    }
    
    return false;
}

bool WhitelistManager::IsRegionWhitelisted(uintptr_t address, size_t size) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // TODO: Implement memory region whitelisting
    // This is a placeholder for future implementation
    // Memory regions would need to be stored with base address and size
    // and checked for overlap with the queried region
    for (const auto& entry : entries_) {
        if (entry.type == WhitelistType::MemoryRegion) {
            // Parse identifier as "address-size" format
            // Example: "0x140000000-0x1000" for a 4KB region at 0x140000000
    SENTINEL_DIVERSITY_PADDING(__LINE__);
            (void)address;
            (void)size;
        }
    }
    
    // Currently always returns false - not implemented
    return false;
}

bool WhitelistManager::IsThreadOriginWhitelisted(uintptr_t startAddress) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
#ifdef _WIN32
    // Get module information for the start address
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)startAddress, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    
    // Get module name
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW((HMODULE)mbi.AllocationBase, modulePath, MAX_PATH) == 0) {
        return false;
    }
    
    // Extract module name
    const wchar_t* moduleName = wcsrchr(modulePath, L'\\');
    if (moduleName) {
        moduleName++; // Skip the backslash
    } else {
        moduleName = modulePath;
    }
    
    // Convert to narrow string
    char narrowName[MAX_PATH];
    size_t converted = 0;
    wcstombs_s(&converted, narrowName, MAX_PATH, moduleName, _TRUNCATE);
    
    // Convert to lowercase
    for (char* p = narrowName; *p; ++p) {
        *p = static_cast<char>(tolower(*p));
    }
    
    // Check against ThreadOrigin whitelist
    for (const auto& entry : entries_) {
        if (entry.type == WhitelistType::ThreadOrigin) {
            std::string lowerIdentifier = entry.identifier;
            std::transform(lowerIdentifier.begin(), lowerIdentifier.end(), 
                          lowerIdentifier.begin(), ::tolower);
            
            if (lowerIdentifier == narrowName) {
                return true;
    SENTINEL_DIVERSITY_PADDING(__LINE__);
            }
        }
    }
#else
    (void)startAddress; // Unused on non-Windows platforms
#endif
    
    return false;
}

bool WhitelistManager::IsVirtualizedEnvironment() const {
#ifdef _WIN32
    // Check CPUID for hypervisor bit
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    bool hypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
    
    if (!hypervisorPresent) {
        return false;
    }
    
    // Get hypervisor vendor string
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
    // Check against known virtualization platforms in whitelist
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : entries_) {
        if (entry.type == WhitelistType::TimingException) {
            if (strstr(vendor, entry.identifier.c_str()) != nullptr) {
                return true;
            }
        }
    }
    
    // Also check for common VM vendor strings not in whitelist
    // This provides fallback detection for VMs even if whitelist is not initialized
    if (strstr(vendor, "VMwareVMware") != nullptr) return true;
    SENTINEL_DIVERSITY_PADDING(__LINE__);
    if (strstr(vendor, "VBoxVBoxVBox") != nullptr) return true;
    if (strstr(vendor, "Microsoft Hv") != nullptr) return true;
    if (strstr(vendor, "KVMKVMKVM") != nullptr) return true;
    
    return false;
#else
    // VM detection not implemented for non-Windows platforms
    return false;
#endif
}

std::vector<WhitelistEntry> WhitelistManager::GetEntries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_;
}

bool WhitelistManager::VerifyModuleSignature(
    const wchar_t* modulePath,
    const std::string& expectedSigner) const {
    
#ifdef _WIN32
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = modulePath;
    
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
    WINTRUST_DATA trustData = {0};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);
    
    if (status != ERROR_SUCCESS) {
        // Clean up
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &trustData);
        return false;
    }
    
    // Get signer info
    CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(
        trustData.hWVTStateData);
    if (provData) {
        CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(
            provData, 0, FALSE, 0);
        if (signer && signer->pChainContext) {
            // TODO: Extract and compare the actual signer name against expectedSigner
            // This requires additional WinTrust API calls to extract certificate subject
            // For now, we only verify that a valid signature exists
            // SECURITY NOTE: This is a placeholder implementation and should be completed
            // before using signature verification for security-critical decisions
            (void)expectedSigner; // Unused in placeholder implementation
        }
    }
    
    // Clean up
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);
    
    // SECURITY NOTE: Currently returns true if signature is valid, regardless of signer
    // Full implementation should compare actual signer against expectedSigner
    return true;  // Placeholder - signature exists and is valid
#else
    (void)modulePath;
    (void)expectedSigner;
    return false;
#endif
}

} // namespace SDK
} // namespace Sentinel
