/**
 * Sentinel SDK - Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 10: Implement Code Section Integrity Verification
 * Detects modifications to the executable code section (.text) to identify inline hooks and patches.
 */

#include "Internal/Detection.hpp"
#include "Internal/Context.hpp"
#include "Internal/SafeMemory.hpp"
#include <mutex>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

namespace Sentinel {
namespace SDK {

void IntegrityChecker::Initialize() {
#ifdef _WIN32
    // Get module base
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) {
        initialization_failed_ = true;
        return;
    }
    
    // Parse PE header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    
    // Verify DOS header is readable
    if (!SafeMemory::IsReadable(dosHeader, sizeof(IMAGE_DOS_HEADER))) {
        initialization_failed_ = true;
        return;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
        ((BYTE*)hModule + dosHeader->e_lfanew);
    
    // Verify NT headers are readable
    if (!SafeMemory::IsReadable(ntHeaders, sizeof(IMAGE_NT_HEADERS))) {
        initialization_failed_ = true;
        return;
    }
    
    // Find .text section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    bool textSectionFound = false;
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Verify section header is readable
        if (!SafeMemory::IsReadable(section, sizeof(IMAGE_SECTION_HEADER))) {
            section++;
            continue;
        }
        
        if (memcmp(section->Name, ".text", 5) == 0) {
            code_section_base_ = (uintptr_t)hModule + section->VirtualAddress;
            code_section_size_ = section->Misc.VirtualSize;
            
            // Verify code section is readable before hashing
            if (!SafeMemory::IsReadable((void*)code_section_base_, code_section_size_)) {
                code_section_base_ = 0;
                code_section_size_ = 0;
                initialization_failed_ = true;
                return;
            }
            
            // Compute initial hash using safe hash function
            if (!SafeMemory::SafeHash((void*)code_section_base_, 
                                       code_section_size_, 
                                       &code_section_hash_)) {
                // Failed to hash, reset
                code_section_base_ = 0;
                code_section_size_ = 0;
                code_section_hash_ = 0;
                initialization_failed_ = true;
                return;
            }
            textSectionFound = true;
            break;
        }
        section++;
    }
    
    // If we didn't find .text section at all, mark as initialization failed
    if (!textSectionFound) {
        initialization_failed_ = true;
        return;
    }
    
    // Task 08: Walk IAT entries for main module
    // Get import directory from data directory
    DWORD importDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    
    if (importDirRVA == 0 || importDirSize == 0) {
        // No import table - this is valid for some executables
        return;
    }
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importDirRVA);
    
    // Verify import descriptor is readable
    if (!SafeMemory::IsReadable(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
        // Cannot read IAT, but code section is initialized - continue without IAT tracking
        return;
    }
    
    // Iterate through imported modules
    while (importDesc->Name != 0) {
        // Verify this descriptor is still readable
        if (!SafeMemory::IsReadable(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            break;
        }
        
        const char* moduleName = (const char*)((BYTE*)hModule + importDesc->Name);
        
        // Verify module name is readable
        if (!SafeMemory::IsReadable((void*)moduleName, 1)) {
            importDesc++;
            continue;
        }
        
        // Skip JIT-compiled modules (clrjit.dll) to avoid false positives
        std::string moduleNameStr = moduleName;
        std::transform(moduleNameStr.begin(), moduleNameStr.end(), moduleNameStr.begin(), ::tolower);
        if (moduleNameStr.find("clrjit") != std::string::npos) {
            importDesc++;
            continue;
        }
        
        // Get the IAT (FirstThunk) and INT (OriginalFirstThunk)
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);
        
        // Verify thunks are readable
        if (!SafeMemory::IsReadable(thunk, sizeof(IMAGE_THUNK_DATA)) ||
            !SafeMemory::IsReadable(originalThunk, sizeof(IMAGE_THUNK_DATA))) {
            importDesc++;
            continue;
        }
        
        // Iterate through imports from this module
        while (originalThunk->u1.AddressOfData != 0) {
            // Verify we can still read the thunks
            if (!SafeMemory::IsReadable(thunk, sizeof(IMAGE_THUNK_DATA)) ||
                !SafeMemory::IsReadable(originalThunk, sizeof(IMAGE_THUNK_DATA))) {
                break;
            }
            
            std::string functionName;
            
            // Check if import is by ordinal
            if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal)) {
                // Import by ordinal - store ordinal as function name
                functionName = "Ordinal#" + std::to_string(IMAGE_ORDINAL(originalThunk->u1.Ordinal));
            } else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME importByName = 
                    (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + originalThunk->u1.AddressOfData);
                
                // Verify import name structure is readable
                if (SafeMemory::IsReadable(importByName, sizeof(IMAGE_IMPORT_BY_NAME))) {
                    functionName = (const char*)importByName->Name;
                }
            }
            
            // Only track if we have a valid function name
            if (!functionName.empty()) {
                IATEntry entry;
                entry.module_name = moduleName;
                entry.function_name = functionName;
                entry.expected_address = (uintptr_t)thunk->u1.Function;
                entry.iat_slot_address = (uintptr_t*)&thunk->u1.Function;
                
                std::lock_guard<std::mutex> lock(iat_mutex_);
                iat_entries_.push_back(entry);
            }
            
            thunk++;
            originalThunk++;
        }
        
        importDesc++;
    }
#endif
}

void IntegrityChecker::Shutdown() {
    {
        std::lock_guard<std::mutex> lock(regions_mutex_);
        registered_regions_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(iat_mutex_);
        iat_entries_.clear();
    }
}

void IntegrityChecker::RegisterRegion(const MemoryRegion& region) {
    std::lock_guard<std::mutex> lock(regions_mutex_);
    registered_regions_.push_back(region);
}

void IntegrityChecker::UnregisterRegion(uintptr_t address) {
    std::lock_guard<std::mutex> lock(regions_mutex_);
    registered_regions_.erase(
        std::remove_if(registered_regions_.begin(), registered_regions_.end(),
            [address](const MemoryRegion& r) { return r.address == address; }),
        registered_regions_.end()
    );
}

void IntegrityChecker::UnregisterRegionsInModule(uintptr_t module_base) {
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
    
    std::lock_guard<std::mutex> lock(regions_mutex_);
    
    // Remove all regions in this module's address range
    registered_regions_.erase(
        std::remove_if(registered_regions_.begin(), registered_regions_.end(),
            [moduleStart, moduleEnd](const MemoryRegion& r) {
                return r.address >= moduleStart && r.address < moduleEnd;
            }),
        registered_regions_.end()
    );
#else
    (void)module_base;
#endif
}

std::vector<ViolationEvent> IntegrityChecker::QuickCheck() {
    std::vector<ViolationEvent> violations;
    
    if (!VerifyCodeSection()) {
        ViolationEvent ev;
        ev.type = ViolationType::ModuleModified;
        ev.severity = Severity::Critical;
        ev.address = code_section_base_;
        ev.details = "Code section hash mismatch";
        ev.module_name = "";
        ev.timestamp = 0;
        ev.detection_id = 0;
        violations.push_back(ev);
    }
    
    // Task 08: Check IAT integrity
    if (!VerifyImportTable()) {
        ViolationEvent ev;
        ev.type = ViolationType::IATHook;
        ev.severity = Severity::Critical;
        ev.address = 0;
        ev.details = "IAT modification detected";
        ev.module_name = "";
        ev.timestamp = 0;
        ev.detection_id = 0;
        violations.push_back(ev);
    }
    
    // Quick check registered regions (sample up to 10)
    {
        std::lock_guard<std::mutex> lock(regions_mutex_);
        size_t checkCount = std::min(registered_regions_.size(), size_t(10));
        for (size_t i = 0; i < checkCount; i++) {
            if (!VerifyRegion(registered_regions_[i])) {
                ViolationEvent ev;
                ev.type = ViolationType::MemoryWrite;
                ev.severity = Severity::High;
                ev.address = registered_regions_[i].address;
                ev.details = "Protected region modified";
                ev.module_name = "";
                ev.timestamp = 0;
                ev.detection_id = 0;
                violations.push_back(ev);
            }
        }
    }
    
    return violations;
}

std::vector<ViolationEvent> IntegrityChecker::FullScan() {
    std::vector<ViolationEvent> violations;
    
    if (!VerifyCodeSection()) {
        ViolationEvent ev;
        ev.type = ViolationType::ModuleModified;
        ev.severity = Severity::Critical;
        ev.address = code_section_base_;
        ev.details = "Code section hash mismatch";
        ev.module_name = "";
        ev.timestamp = 0;
        ev.detection_id = 0;
        violations.push_back(ev);
    }
    
    // Task 08: Check IAT integrity
    if (!VerifyImportTable()) {
        ViolationEvent ev;
        ev.type = ViolationType::IATHook;
        ev.severity = Severity::Critical;
        ev.address = 0;
        ev.details = "IAT modification detected";
        ev.module_name = "";
        ev.timestamp = 0;
        ev.detection_id = 0;
        violations.push_back(ev);
    }
    
    // Full scan - check all registered regions
    {
        std::lock_guard<std::mutex> lock(regions_mutex_);
        for (const auto& region : registered_regions_) {
            if (!VerifyRegion(region)) {
                ViolationEvent ev;
                ev.type = ViolationType::MemoryWrite;
                ev.severity = Severity::High;
                ev.address = region.address;
                ev.details = "Protected region modified";
                ev.module_name = "";
                ev.timestamp = 0;
                ev.detection_id = 0;
                violations.push_back(ev);
            }
        }
    }
    
    return violations;
}

bool IntegrityChecker::VerifyRegion(const MemoryRegion& region) {
    // Verify memory is readable before hashing
    if (!SafeMemory::IsReadable((void*)region.address, region.size)) {
        return false;  // Memory not accessible
    }
    
    uint64_t currentHash;
    if (!SafeMemory::SafeHash((void*)region.address, region.size, &currentHash)) {
        return false;  // Failed to compute hash
    }
    
    return currentHash == region.original_hash;
}

bool IntegrityChecker::VerifyCodeSection() {
    if (initialization_failed_) {
        // Initialization failed - report as violation to trigger alert
        return false;
    }
    if (code_section_base_ == 0 || code_section_size_ == 0) {
#ifdef _WIN32
        // On Windows, this should have been initialized - fail closed
        return false;
#else
        // On non-Windows platforms, code section verification is not supported
        return true;
#endif
    }
    
    // Verify memory is readable before hashing
    if (!SafeMemory::IsReadable((void*)code_section_base_, code_section_size_)) {
        return false;  // Code section no longer accessible
    }
    
    uint64_t currentHash;
    if (!SafeMemory::SafeHash((void*)code_section_base_, 
                               code_section_size_, 
                               &currentHash)) {
        return false;  // Failed to compute hash
    }
    
    return currentHash == code_section_hash_;
}

bool IntegrityChecker::VerifyImportTable() {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(iat_mutex_);
    
    // If no IAT entries were stored, return true (no IAT to verify)
    if (iat_entries_.empty()) {
        return true;
    }
    
    // Check each IAT entry
    for (const auto& entry : iat_entries_) {
        // Verify the IAT slot is still readable
        if (!SafeMemory::IsReadable(entry.iat_slot_address, sizeof(uintptr_t))) {
            // IAT slot is not readable - potential tampering
            return false;
        }
        
        // Read current IAT value
        uintptr_t currentAddress = *entry.iat_slot_address;
        
        // Compare against expected address
        if (currentAddress != entry.expected_address) {
            // IAT hook detected - address has been modified
            return false;
        }
    }
    
    // All IAT entries match expected values
    return true;
#else
    // IAT verification only supported on Windows
    return true;
#endif
}

} // namespace SDK
} // namespace Sentinel
