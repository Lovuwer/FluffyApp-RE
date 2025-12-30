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
            }
            break;
        }
        section++;
    }
    
    // If we didn't find .text section at all, mark as initialization failed
    if (code_section_base_ == 0 || code_section_size_ == 0) {
        initialization_failed_ = true;
    }
#endif
}

void IntegrityChecker::Shutdown() {
    std::lock_guard<std::mutex> lock(regions_mutex_);
    registered_regions_.clear();
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
        return false;  // Not initialized = fail closed
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
    // Stub implementation - out of scope for Task 10
    return true;
}

} // namespace SDK
} // namespace Sentinel
