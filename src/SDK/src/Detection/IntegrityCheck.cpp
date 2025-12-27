/**
 * Sentinel SDK - Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 10: Implement Code Section Integrity Verification
 * Detects modifications to the executable code section (.text) to identify inline hooks and patches.
 */

#include "Internal/Detection.hpp"
#include <mutex>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

namespace Sentinel {
namespace SDK {

namespace {
    // FNV-1a hash function for fast integrity checking
    uint64_t ComputeHash(const void* data, size_t size) {
        // FNV-1a constants
        const uint64_t FNV_OFFSET = 14695981039346656037ULL;
        const uint64_t FNV_PRIME = 1099511628211ULL;
        
        uint64_t hash = FNV_OFFSET;
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        
        for (size_t i = 0; i < size; i++) {
            hash ^= bytes[i];
            hash *= FNV_PRIME;
        }
        
        return hash;
    }
}

// Mutex for thread-safe region management
static std::mutex regions_mutex_;

void IntegrityChecker::Initialize() {
#ifdef _WIN32
    // Get module base
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return;
    
    // Parse PE header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
        ((BYTE*)hModule + dosHeader->e_lfanew);
    
    // Find .text section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            code_section_base_ = (uintptr_t)hModule + section->VirtualAddress;
            code_section_size_ = section->Misc.VirtualSize;
            
            // Compute initial hash
            code_section_hash_ = ComputeHash(
                (void*)code_section_base_, 
                code_section_size_
            );
            break;
        }
        section++;
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

std::vector<ViolationEvent> IntegrityChecker::QuickCheck() {
    std::vector<ViolationEvent> violations;
    
    if (!VerifyCodeSection()) {
        ViolationEvent ev;
        ev.type = ViolationType::ModuleModified;
        ev.severity = Severity::Critical;
        ev.address = code_section_base_;
        ev.details = "Code section hash mismatch";
        ev.module_name = nullptr;
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
                ev.details = ("Protected region modified: " + registered_regions_[i].name).c_str();
                ev.module_name = nullptr;
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
        ev.module_name = nullptr;
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
                ev.details = ("Protected region modified: " + region.name).c_str();
                ev.module_name = nullptr;
                ev.timestamp = 0;
                ev.detection_id = 0;
                violations.push_back(ev);
            }
        }
    }
    
    return violations;
}

bool IntegrityChecker::VerifyRegion(const MemoryRegion& region) {
    uint64_t currentHash = ComputeHash(
        (void*)region.address,
        region.size
    );
    return currentHash == region.original_hash;
}

bool IntegrityChecker::VerifyCodeSection() {
    if (code_section_base_ == 0 || code_section_size_ == 0) {
        return true; // Not initialized, assume OK
    }
    
    uint64_t currentHash = ComputeHash(
        (void*)code_section_base_,
        code_section_size_
    );
    
    return currentHash == code_section_hash_;
}

bool IntegrityChecker::VerifyImportTable() {
    // Stub implementation - out of scope for Task 10
    return true;
}

} // namespace SDK
} // namespace Sentinel
