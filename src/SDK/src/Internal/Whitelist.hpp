/**
 * Sentinel SDK - Whitelist Module Interface
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#pragma once

#include <string>
#include <vector>
#include <optional>
#include <mutex>

namespace Sentinel {
namespace SDK {

enum class WhitelistType {
    Module,          // DLL/EXE by name or hash
    MemoryRegion,    // Address range
    ThreadOrigin,    // Thread start address pattern
    TimingException, // Known slow environments (VMs)
    ProcessName      // Parent/sibling process
};

struct WhitelistEntry {
    WhitelistType type;
    std::string identifier;      // Name, hash, or pattern
    std::string reason;          // Documentation
    bool builtin = false;        // Cannot be removed by user
    
    // For Module type
    std::optional<std::string> sha256_hash;  // Optional hash verification
    std::optional<std::string> signer;       // Optional code signing check
};

class WhitelistManager {
public:
    void Initialize();
    void Shutdown();
    
    // Add custom whitelist entry
    void Add(const WhitelistEntry& entry);
    
    // Remove entry (fails silently for builtins)
    void Remove(const std::string& identifier);
    
    // Check if item is whitelisted
    bool IsModuleWhitelisted(const wchar_t* modulePath) const;
    bool IsModuleWhitelisted(const std::string& moduleHash) const;
    bool IsRegionWhitelisted(uintptr_t address, size_t size) const;
    bool IsThreadOriginWhitelisted(uintptr_t startAddress) const;
    bool IsVirtualizedEnvironment() const;
    
    // Get all entries (for debugging/UI)
    std::vector<WhitelistEntry> GetEntries() const;
    
private:
    void LoadBuiltinWhitelist();
    bool VerifyModuleSignature(const wchar_t* modulePath, 
                               const std::string& expectedSigner) const;
    
    mutable std::mutex mutex_;
    std::vector<WhitelistEntry> entries_;
};

} // namespace SDK
} // namespace Sentinel
