/**
 * Sentinel SDK - Memory Integrity Self-Validation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 8: Implement Memory Integrity Self-Validation
 * Detects modifications to the SDK's own code sections to identify runtime patching.
 * 
 * Problem: Detection code can be patched in memory to always return clean.
 * Solution: SDK validates its own code integrity continuously with obfuscated hashes.
 */

#pragma once

#include "SentinelSDK.hpp"
#include <cstdint>
#include <vector>
#include <mutex>
#include <string>
#include <random>

namespace Sentinel {
namespace SDK {

/**
 * Tracks a protected code section with obfuscated hash
 */
struct CodeSection {
    uintptr_t base_address;       ///< Start address of section
    size_t size;                  ///< Size in bytes
    std::string name;             ///< Section name for reporting
    uint64_t obfuscated_hash;     ///< XOR-obfuscated hash for storage
    uint64_t xor_key;             ///< XOR key for hash obfuscation
    uint64_t last_validated;      ///< Timestamp of last validation (ms)
};

/**
 * Memory Integrity Self-Validation Module
 * 
 * Continuously validates that the SDK's own code has not been modified
 * in memory by attackers attempting to patch detection routines.
 * 
 * Features:
 * - Computes hashes of critical code sections at initialization
 * - Stores hashes in obfuscated form (XOR encrypted)
 * - Periodically recomputes and compares hashes
 * - Randomized validation timing to prevent timing-based evasion
 * - Distributed validation across multiple code paths
 * - Performance: < 1ms per validation cycle
 * - Zero false positives under normal operation
 */
class IntegrityValidator {
public:
    /**
     * Initialize the integrity validator
     * Discovers and hashes critical code sections
     */
    void Initialize();
    
    /**
     * Shutdown and cleanup
     */
    void Shutdown();
    
    /**
     * Validate code integrity (quick check)
     * Checks a subset of sections for performance
     * @return true if all checked sections are intact
     */
    bool ValidateQuick();
    
    /**
     * Validate code integrity (full check)
     * Checks all registered sections
     * @return Violation events for any detected tampering
     */
    std::vector<ViolationEvent> ValidateFull();
    
    /**
     * Get time until next validation (for scheduling)
     * @return Milliseconds until next validation
     */
    uint64_t GetTimeUntilNextValidation() const;
    
    /**
     * Check if validator is initialized
     * @return true if initialized
     */
    bool IsInitialized() const { return initialized_; }
    
    /**
     * Create a violation event for generic self-integrity failure
     * Use this for quick checks where specific section info is not available
     * @return Violation event
     */
    static ViolationEvent CreateGenericTamperEvent();
    
private:
    /**
     * Discover and register critical code sections
     */
    void DiscoverCodeSections();
    
    /**
     * Register a code section for protection
     * @param base Base address
     * @param size Size in bytes
     * @param name Section name
     */
    void RegisterSection(uintptr_t base, size_t size, const char* name);
    
    /**
     * Compute hash of a memory region
     * Uses FNV-1a hash for speed
     * @param data Memory address
     * @param size Size in bytes
     * @return Hash value
     */
    uint64_t ComputeHash(const void* data, size_t size);
    
    /**
     * Obfuscate hash value for storage
     * Uses XOR encryption with random key
     * @param hash Original hash
     * @param key XOR key (generated randomly)
     * @return Obfuscated hash
     */
    uint64_t ObfuscateHash(uint64_t hash, uint64_t key);
    
    /**
     * Deobfuscate hash value
     * @param obfuscated Obfuscated hash
     * @param key XOR key
     * @return Original hash
     */
    uint64_t DeobfuscateHash(uint64_t obfuscated, uint64_t key);
    
    /**
     * Generate random XOR key for hash obfuscation
     * @return Random 64-bit key
     */
    uint64_t GenerateXorKey();
    
    /**
     * Get current time in milliseconds
     * @return Current time
     */
    uint64_t GetCurrentTimeMs() const;
    
    /**
     * Calculate next validation time with jitter
     * Randomizes timing to prevent predictable checks
     * @return Next validation timestamp
     */
    uint64_t CalculateNextValidationTime();
    
    /**
     * Validate a single code section
     * @param section Section to validate
     * @return true if section is intact
     */
    bool ValidateSection(const CodeSection& section);
    
    /**
     * Create violation event for detected tampering
     * @param section Tampered section
     * @return Violation event
     */
    ViolationEvent CreateTamperEvent(const CodeSection& section);
    
    // Protected sections
    std::vector<CodeSection> sections_;
    mutable std::mutex sections_mutex_;
    
    // State
    bool initialized_ = false;
    uint64_t next_validation_time_ = 0;
    
    // Random number generator for jitter
    std::mt19937_64 rng_;
    
    // Performance tracking
    uint64_t total_validations_ = 0;
    uint64_t total_validation_time_us_ = 0;
    
    // Constants
    // Task 23: Stricter timing requirements - guarantee 5-second detection window
    static constexpr uint64_t MIN_VALIDATION_INTERVAL_MS = 500;    // 0.5 second minimum
    static constexpr uint64_t MAX_VALIDATION_INTERVAL_MS = 4000;   // 4 seconds maximum (ensures detection within 5s)
    static constexpr uint64_t VALIDATION_JITTER_MS = 1500;         // +/- 1.5 seconds jitter
    static constexpr size_t QUICK_CHECK_SECTION_COUNT = 2;         // Sections per quick check
    // Task 23: Tighter performance budget - 0.5ms per validation cycle
    static constexpr uint64_t MAX_QUICK_VALIDATION_TIME_US = 500;  // 0.5ms limit for quick checks
    static constexpr uint64_t MAX_FULL_VALIDATION_TIME_US = 10000; // 10ms limit for full scans
    static constexpr uint32_t SELF_INTEGRITY_DETECTION_ID_BASE = 0xDEADBEEF; // Base ID for self-integrity violations
};

} // namespace SDK
} // namespace Sentinel
