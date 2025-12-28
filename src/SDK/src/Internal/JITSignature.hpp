/**
 * Sentinel SDK - JIT Signature Database
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 1: Eliminate Module Name-Based JIT Whitelisting
 * Provides hash-based validation of JIT compiler modules to prevent
 * module hollowing/spoofing attacks.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace Sentinel {
namespace SDK {

/**
 * JIT engine type classification
 */
enum class JITEngineType {
    Unknown,
    DotNetCLR,      ///< .NET CLR JIT (clrjit.dll, clr.dll, coreclr.dll)
    V8JavaScript,   ///< V8 JavaScript engine (v8.dll, libv8.dll)
    LuaJIT,         ///< LuaJIT (luajit.dll, lua5x.dll)
    UnityIL2CPP     ///< Unity IL2CPP (gameassembly.dll)
};

/**
 * Known JIT engine signature entry
 */
struct JITSignature {
    std::wstring module_name;       ///< Module name (e.g., L"clrjit.dll")
    JITEngineType engine_type;      ///< Type of JIT engine
    std::wstring version;           ///< Version string (e.g., L".NET 6.0", L"V8 10.x")
    std::vector<uint8_t> text_hash; ///< SHA-256 hash of first 4KB of .text section
    size_t max_heap_distance;       ///< Maximum distance from module base for JIT heap (bytes)
    
    // Constructor with default heap distance
    JITSignature() : max_heap_distance(32 * 1024 * 1024) {} // Default 32MB
};

/**
 * JIT signature database and validator
 * Validates JIT modules using code section hashing instead of name-based checks
 */
class JITSignatureValidator {
public:
    JITSignatureValidator();
    ~JITSignatureValidator();

    /**
     * Initialize the validator with known-good JIT signatures
     */
    void Initialize();

    /**
     * Validate a memory region as belonging to a legitimate JIT engine
     * @param address Memory address to validate
     * @return True if the address belongs to a verified JIT region
     */
    bool ValidateJITRegion(uintptr_t address);

    /**
     * Check if an allocation base contains CLR metadata (for .NET validation)
     * @param module_base Base address of the module
     * @return True if CLR metadata structures are present
     */
    bool HasCLRMetadata(uintptr_t module_base);

private:
    /**
     * Hash the first 4KB of a module's .text section
     * @param module_base Base address of the module
     * @param hash_out Output buffer (32 bytes)
     * @return True if hash was computed successfully
     */
    bool HashTextSection(uintptr_t module_base, uint8_t* hash_out);

    /**
     * Get the .text section header from a PE module
     * @param module_base Base address of the module
     * @param text_section_start Output: start of .text section
     * @param text_section_size Output: size of .text section
     * @return True if .text section was found
     */
    bool GetTextSectionInfo(uintptr_t module_base, uintptr_t& text_section_start, size_t& text_section_size);

    /**
     * Verify that an RWX region is within expected JIT heap ranges
     * @param address Address to check
     * @param module_base Base address of the parent module
     * @param max_distance Maximum allowed distance from module (bytes)
     * @return True if the region is within valid JIT heap range
     */
    bool IsWithinJITHeapRange(uintptr_t address, uintptr_t module_base, size_t max_distance);

    /**
     * Add built-in signatures for known JIT engines
     */
    void AddBuiltInSignatures();

    /**
     * Add signature for a specific JIT engine
     */
    void AddSignature(const JITSignature& signature);

    // Database of known-good JIT signatures indexed by hash
    std::unordered_map<std::string, JITSignature> signature_database_;
    
    // Cache of validated modules to avoid repeated validation
    struct ValidatedModule {
        uintptr_t base_address;
        JITEngineType engine_type;
        size_t max_heap_distance;
        uint64_t validation_time;
    };
    std::vector<ValidatedModule> validated_cache_;
};

} // namespace SDK
} // namespace Sentinel
