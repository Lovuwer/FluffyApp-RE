/**
 * Sentinel SDK - Memory Integrity Self-Validation Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 8: Implement Memory Integrity Self-Validation
 */

#include "IntegrityValidator.hpp"
#include "SafeMemory.hpp"
#include <chrono>
#include <algorithm>
#include <cstring>
#include <cstdio>  // Task 23: For snprintf in detailed reporting

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <dlfcn.h>
#include <link.h>
#endif

namespace Sentinel {
namespace SDK {

// Anonymous namespace for internal helpers
namespace {

/**
 * Get module handle for this DLL/SO
 */
#ifdef _WIN32
HMODULE GetCurrentModule() {
    HMODULE hModule = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&GetCurrentModule),
        &hModule);
    return hModule;
}
#else
// Helper function to get address in this module (for dladdr)
void* GetModuleSymbol() {
    return reinterpret_cast<void*>(&GetModuleSymbol);
}
#endif

} // anonymous namespace

void IntegrityValidator::Initialize() {
    if (initialized_) {
        return;
    }
    
    // Initialize RNG for jitter
    std::random_device rd;
    rng_.seed(rd());
    
    // Discover and register critical code sections
    DiscoverCodeSections();
    
    // Calculate initial validation time
    next_validation_time_ = CalculateNextValidationTime();
    
    initialized_ = true;
}

void IntegrityValidator::Shutdown() {
    std::lock_guard<std::mutex> lock(sections_mutex_);
    sections_.clear();
    initialized_ = false;
}

void IntegrityValidator::DiscoverCodeSections() {
#ifdef _WIN32
    HMODULE hModule = GetCurrentModule();
    if (!hModule) {
        return;
    }
    
    // Parse PE header to find code sections
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    
    // Verify DOS header is readable
    if (!SafeMemory::IsReadable(dosHeader, sizeof(IMAGE_DOS_HEADER))) {
        return;
    }
    
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
    
    // Verify NT headers are readable
    if (!SafeMemory::IsReadable(ntHeaders, sizeof(IMAGE_NT_HEADERS))) {
        return;
    }
    
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }
    
    // Iterate through sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Verify section header is readable
        if (!SafeMemory::IsReadable(section, sizeof(IMAGE_SECTION_HEADER))) {
            section++;
            continue;
        }
        
        // Register executable sections (.text, .rdata with code)
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
            (memcmp(section->Name, ".text", 5) == 0)) {
            
            uintptr_t base = reinterpret_cast<uintptr_t>(hModule) + section->VirtualAddress;
            size_t size = section->Misc.VirtualSize;
            
            // Verify section is readable before registering
            if (SafeMemory::IsReadable(reinterpret_cast<void*>(base), size)) {
                char name[9] = {0};
                memcpy(name, section->Name, 8);
                RegisterSection(base, size, name);
            }
        }
        
        section++;
    }
#else
    // Linux/Unix: Use dl_iterate_phdr to find our own module
    // For simplicity, use a static function address
    // This would need platform-specific implementation with ELF parsing for production
    
    Dl_info info;
    if (dladdr(GetModuleSymbol(), &info)) {
        // Register approximate text section - would need ELF parsing for accuracy
        // This is a simplified implementation
        uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
        // Estimate size - in production would parse ELF headers
        size_t size = 0x100000; // 1MB estimate
        RegisterSection(base, size, ".text");
    }
#endif
}

void IntegrityValidator::RegisterSection(uintptr_t base, size_t size, const char* name) {
    // Compute initial hash
    uint64_t hash = ComputeHash(reinterpret_cast<void*>(base), size);
    
    // Generate random XOR key for obfuscation
    uint64_t xor_key = GenerateXorKey();
    
    // Obfuscate the hash
    uint64_t obfuscated = ObfuscateHash(hash, xor_key);
    
    // Create section entry
    CodeSection section;
    section.base_address = base;
    section.size = size;
    section.name = name;
    section.obfuscated_hash = obfuscated;
    section.xor_key = xor_key;
    section.last_validated = GetCurrentTimeMs();
    
    // Add to protected sections
    std::lock_guard<std::mutex> lock(sections_mutex_);
    sections_.push_back(section);
}

uint64_t IntegrityValidator::ComputeHash(const void* data, size_t size) {
    // Use SafeHash if available for crash-safe hashing
    uint64_t hash = 0;
    if (SafeMemory::SafeHash(const_cast<void*>(data), size, &hash)) {
        return hash;
    }
    
    // Task 23: Optimized FNV-1a with unrolled loop for better performance
    // Target: < 0.5ms per validation cycle
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    hash = 0xcbf29ce484222325ULL; // FNV offset basis
    const uint64_t FNV_PRIME = 0x100000001b3ULL;
    
    // Process 8 bytes at a time for better cache utilization
    size_t i = 0;
    const size_t unroll_limit = size - (size % 8);
    
    for (; i < unroll_limit; i += 8) {
        hash ^= bytes[i];     hash *= FNV_PRIME;
        hash ^= bytes[i + 1]; hash *= FNV_PRIME;
        hash ^= bytes[i + 2]; hash *= FNV_PRIME;
        hash ^= bytes[i + 3]; hash *= FNV_PRIME;
        hash ^= bytes[i + 4]; hash *= FNV_PRIME;
        hash ^= bytes[i + 5]; hash *= FNV_PRIME;
        hash ^= bytes[i + 6]; hash *= FNV_PRIME;
        hash ^= bytes[i + 7]; hash *= FNV_PRIME;
    }
    
    // Handle remaining bytes
    for (; i < size; i++) {
        hash ^= bytes[i];
        hash *= FNV_PRIME;
    }
    
    return hash;
}

uint64_t IntegrityValidator::ObfuscateHash(uint64_t hash, uint64_t key) {
    // Simple XOR obfuscation - prevents trivial hash comparison
    return hash ^ key;
}

uint64_t IntegrityValidator::DeobfuscateHash(uint64_t obfuscated, uint64_t key) {
    // XOR is reversible
    return obfuscated ^ key;
}

uint64_t IntegrityValidator::GenerateXorKey() {
    std::uniform_int_distribution<uint64_t> dist(1, UINT64_MAX);
    return dist(rng_);
}

uint64_t IntegrityValidator::GetCurrentTimeMs() const {
    auto now = std::chrono::steady_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

uint64_t IntegrityValidator::CalculateNextValidationTime() {
    // Base interval with random jitter
    std::uniform_int_distribution<int64_t> dist(
        -static_cast<int64_t>(VALIDATION_JITTER_MS),
        static_cast<int64_t>(VALIDATION_JITTER_MS)
    );
    
    uint64_t base_interval = (MIN_VALIDATION_INTERVAL_MS + MAX_VALIDATION_INTERVAL_MS) / 2;
    int64_t jitter = dist(rng_);
    
    uint64_t interval = base_interval + jitter;
    
    // Clamp to valid range
    interval = std::max(MIN_VALIDATION_INTERVAL_MS, 
                       std::min(MAX_VALIDATION_INTERVAL_MS, interval));
    
    return GetCurrentTimeMs() + interval;
}

bool IntegrityValidator::ValidateQuick() {
    if (!initialized_) {
        return true; // Not initialized yet, no validation
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::lock_guard<std::mutex> lock(sections_mutex_);
    
    if (sections_.empty()) {
        return true; // No sections to validate
    }
    
    // Check if it's time for validation
    uint64_t current_time = GetCurrentTimeMs();
    if (current_time < next_validation_time_) {
        return true; // Not time yet
    }
    
    // Select a subset of sections for quick check
    size_t check_count = std::min(QUICK_CHECK_SECTION_COUNT, sections_.size());
    
    // Use round-robin selection to ensure all sections get checked over time
    static size_t last_checked_index = 0;
    
    bool all_valid = true;
    for (size_t i = 0; i < check_count; i++) {
        // Task 23: Enforce performance budget during validation
        auto current = std::chrono::high_resolution_clock::now();
        auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
            current - start_time).count();
        
        if (static_cast<uint64_t>(elapsed_us) > MAX_QUICK_VALIDATION_TIME_US) {
            break; // Stop if exceeding 0.5ms budget
        }
        
        size_t index = (last_checked_index + i) % sections_.size();
        if (!ValidateSection(sections_[index])) {
            all_valid = false;
            break; // Stop on first tamper detection
        }
        sections_[index].last_validated = current_time;
    }
    
    last_checked_index = (last_checked_index + check_count) % sections_.size();
    
    // Update next validation time
    next_validation_time_ = CalculateNextValidationTime();
    
    // Track performance
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time).count();
    
    total_validations_++;
    total_validation_time_us_ += duration_us;
    
    return all_valid;
}

std::vector<ViolationEvent> IntegrityValidator::ValidateFull() {
    std::vector<ViolationEvent> violations;
    
    if (!initialized_) {
        return violations;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::lock_guard<std::mutex> lock(sections_mutex_);
    
    uint64_t current_time = GetCurrentTimeMs();
    
    // Validate all sections
    for (auto& section : sections_) {
        if (!ValidateSection(section)) {
            violations.push_back(CreateTamperEvent(section));
        }
        section.last_validated = current_time;
        
        // Respect performance budget for full scans (10ms)
        auto current = std::chrono::high_resolution_clock::now();
        auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
            current - start_time).count();
        
        if (static_cast<uint64_t>(elapsed_us) > MAX_FULL_VALIDATION_TIME_US) {
            break; // Stop if exceeding time budget
        }
    }
    
    // Track performance
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time).count();
    
    total_validations_++;
    total_validation_time_us_ += duration_us;
    
    return violations;
}

bool IntegrityValidator::ValidateSection(const CodeSection& section) {
    // Recompute hash of current memory
    uint64_t current_hash = ComputeHash(
        reinterpret_cast<void*>(section.base_address),
        section.size);
    
    // Deobfuscate stored hash
    uint64_t expected_hash = DeobfuscateHash(
        section.obfuscated_hash,
        section.xor_key);
    
    // Compare
    return current_hash == expected_hash;
}

ViolationEvent IntegrityValidator::CreateTamperEvent(const CodeSection& section) {
    ViolationEvent event;
    event.type = ViolationType::ModuleModified;
    event.severity = Severity::Critical;
    event.timestamp = GetCurrentTimeMs();
    event.address = section.base_address;
    event.module_name = "SentinelSDK";
    
    // Task 23: Enhanced reporting with detailed identifying information
    // Include section name, address range, size, and hash mismatch indication
    char details[512];
    snprintf(details, sizeof(details),
             "SDK code integrity violation detected - "
             "Section: '%s', Address: 0x%016llx, Size: %zu bytes, "
             "Last valid: %llu ms ago, Detection timestamp: %llu ms",
             section.name.c_str(),
             static_cast<unsigned long long>(section.base_address),
             section.size,
             static_cast<unsigned long long>(GetCurrentTimeMs() - section.last_validated),
             static_cast<unsigned long long>(GetCurrentTimeMs()));
    event.details = details;
    
    // Generate unique detection ID based on section name and address
    // This helps with debugging and correlation of specific section tampering
    uint64_t section_hash = ComputeHash(section.name.c_str(), section.name.length());
    section_hash ^= section.base_address;
    event.detection_id = static_cast<uint32_t>(SELF_INTEGRITY_DETECTION_ID_BASE ^ section_hash);
    
    return event;
}

uint64_t IntegrityValidator::GetTimeUntilNextValidation() const {
    if (!initialized_) {
        return 0;
    }
    
    uint64_t current = GetCurrentTimeMs();
    if (current >= next_validation_time_) {
        return 0;
    }
    
    return next_validation_time_ - current;
}

ViolationEvent IntegrityValidator::CreateGenericTamperEvent() {
    ViolationEvent event;
    event.type = ViolationType::ModuleModified;
    event.severity = Severity::Critical;
    event.timestamp = 0; // Will be set by caller
    event.address = 0;
    event.module_name = "SentinelSDK";
    event.details = "SDK code tampered - detection bypass attempt";
    event.detection_id = SELF_INTEGRITY_DETECTION_ID_BASE;
    return event;
}

} // namespace SDK
} // namespace Sentinel
