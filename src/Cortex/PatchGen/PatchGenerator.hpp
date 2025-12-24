/**
 * PatchGenerator.hpp
 * Sentinel Cortex - Automated Patch Generation Engine
 * 
 * Generates security patches and runtime fixes for protected games
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#pragma once

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <optional>
#include <map>
#include <variant>

namespace Sentinel::Cortex {

// Forward declarations
class Disassembler;
class BinaryDiffer;

/**
 * Type of patch to generate
 */
enum class PatchType {
    Inline,             ///< Direct inline code modification
    Detour,             ///< Function detour/hook
    Import,             ///< Import table modification
    VTable,             ///< Virtual table modification
    Signature,          ///< Pattern-based signature patch
    Trampoline,         ///< Trampoline-style hook
    Codecave           ///< Code cave injection
};

/**
 * Target architecture for patch
 */
enum class PatchArchitecture {
    x86,
    x64,
    ARM32,
    ARM64,
    Auto                ///< Auto-detect from binary
};

/**
 * Patch application method
 */
enum class PatchMethod {
    FileModification,   ///< Modify file on disk
    RuntimeInjection,   ///< Inject at runtime via DLL
    MemoryPatch,        ///< Direct memory modification
    Loader              ///< Custom loader with patches
};

/**
 * Represents a single patch operation
 */
struct PatchOperation {
    std::string id;                 ///< Unique identifier
    std::string name;               ///< Human-readable name
    std::string description;        ///< Description of what patch does
    
    PatchType type;
    PatchArchitecture arch;
    
    // Target information
    uint64_t target_address;        ///< Address to patch (runtime or file offset)
    std::string target_module;      ///< Target module name (for DLL patches)
    std::string target_function;    ///< Target function name (for hooks)
    
    // Pattern matching (for signature patches)
    std::string pattern;            ///< Byte pattern to find
    std::string mask;               ///< Pattern mask
    int pattern_offset;             ///< Offset from pattern match to patch location
    
    // Patch data
    std::vector<uint8_t> original_bytes;    ///< Original bytes being replaced
    std::vector<uint8_t> patch_bytes;       ///< New bytes to write
    
    // For hook/detour patches
    std::vector<uint8_t> hook_code;         ///< Hook handler code
    std::vector<uint8_t> trampoline_code;   ///< Trampoline for calling original
    
    // Metadata
    bool enabled = true;
    bool verified = false;          ///< Has been tested
    std::string category;           ///< Category (anti-cheat, protection, etc.)
    std::vector<std::string> tags;
    
    // Conditions
    std::string condition_pattern;  ///< Only apply if pattern found
    std::string version_min;        ///< Minimum version to apply
    std::string version_max;        ///< Maximum version
};

/**
 * Complete patch set for a target
 */
struct PatchSet {
    std::string id;
    std::string name;
    std::string target_name;        ///< Target game/application
    std::string target_version;
    std::string author;
    std::string description;
    
    std::vector<PatchOperation> patches;
    
    // Dependencies
    std::vector<std::string> required_modules;
    std::vector<std::string> incompatible_with;
    
    // Metadata
    uint64_t created_timestamp;
    uint64_t modified_timestamp;
    int priority;                   ///< Application order priority
};

/**
 * Result of patch application
 */
struct PatchApplicationResult {
    bool success;
    std::string patch_id;
    std::string message;
    
    // Details
    uint64_t address_patched;
    size_t bytes_modified;
    
    // For verification
    std::vector<uint8_t> bytes_before;
    std::vector<uint8_t> bytes_after;
};

/**
 * Generated output format
 */
enum class PatchOutputFormat {
    Binary,             ///< Raw binary patch file
    IPS,                ///< IPS patch format
    UPS,                ///< UPS patch format
    BPS,                ///< BPS patch format
    XDelta,             ///< xdelta3 format
    CppSource,          ///< C++ source code
    Assembly,           ///< Assembly source
    CheatEngine,        ///< Cheat Engine CT file
    JSON,               ///< JSON descriptor
    Lua                 ///< Lua script for injection
};

/**
 * Configuration for patch generator
 */
struct PatchGeneratorConfig {
    PatchArchitecture default_arch = PatchArchitecture::Auto;
    PatchMethod default_method = PatchMethod::MemoryPatch;
    
    // Code generation settings
    bool generate_trampoline = true;        ///< Generate trampolines for hooks
    bool preserve_registers = true;         ///< Preserve all registers in hooks
    bool add_safety_checks = true;          ///< Add null/bounds checks
    size_t codecave_min_size = 64;          ///< Minimum codecave size
    size_t trampoline_size = 32;            ///< Trampoline allocation size
    
    // Verification settings
    bool verify_original_bytes = true;      ///< Verify bytes before patching
    bool create_backup = true;              ///< Create backup of original
    
    // Output settings
    PatchOutputFormat output_format = PatchOutputFormat::Binary;
    bool include_metadata = true;
    bool compress_output = false;
};

/**
 * Callback for patch generation progress
 */
using PatchProgressCallback = std::function<void(float progress, const std::string& operation)>;

/**
 * Patch generation engine
 */
class PatchGenerator {
public:
    /**
     * Constructor
     */
    explicit PatchGenerator(const PatchGeneratorConfig& config = PatchGeneratorConfig{});
    
    /**
     * Destructor
     */
    ~PatchGenerator();
    
    // Non-copyable
    PatchGenerator(const PatchGenerator&) = delete;
    PatchGenerator& operator=(const PatchGenerator&) = delete;
    
    // Movable
    PatchGenerator(PatchGenerator&&) noexcept;
    PatchGenerator& operator=(PatchGenerator&&) noexcept;
    
    /**
     * Initialize the generator
     */
    Sentinel::Core::Result<void> Initialize();
    
    /**
     * Shutdown
     */
    void Shutdown();
    
    // ==================== Patch Creation ====================
    
    /**
     * Create an inline byte patch
     * @param address Target address
     * @param original Original bytes (for verification)
     * @param replacement Replacement bytes
     * @param name Patch name
     * @return Patch operation or error
     */
    Sentinel::Core::Result<PatchOperation> CreateInlinePatch(
        uint64_t address,
        const std::vector<uint8_t>& original,
        const std::vector<uint8_t>& replacement,
        const std::string& name = "");
    
    /**
     * Create a function hook/detour
     * @param target_address Address of function to hook
     * @param hook_handler Hook handler code
     * @param name Patch name
     * @return Patch operation with trampoline
     */
    Sentinel::Core::Result<PatchOperation> CreateDetourPatch(
        uint64_t target_address,
        const std::vector<uint8_t>& hook_handler,
        const std::string& name = "");
    
    /**
     * Create a signature-based patch
     * @param pattern Byte pattern to search
     * @param mask Pattern mask (x = match, ? = wildcard)
     * @param replacement Replacement bytes
     * @param offset Offset from pattern to patch
     * @param name Patch name
     */
    Sentinel::Core::Result<PatchOperation> CreateSignaturePatch(
        const std::string& pattern,
        const std::string& mask,
        const std::vector<uint8_t>& replacement,
        int offset = 0,
        const std::string& name = "");
    
    /**
     * Create a NOP patch (fill with NOPs)
     * @param address Start address
     * @param size Number of bytes to NOP
     * @param name Patch name
     */
    Sentinel::Core::Result<PatchOperation> CreateNopPatch(
        uint64_t address,
        size_t size,
        const std::string& name = "");
    
    /**
     * Create a return patch (force function return)
     * @param address Function address
     * @param return_value Optional return value
     * @param name Patch name
     */
    Sentinel::Core::Result<PatchOperation> CreateReturnPatch(
        uint64_t address,
        std::optional<uint64_t> return_value = std::nullopt,
        const std::string& name = "");
    
    /**
     * Create codecave injection patch
     * @param target_address Address to redirect from
     * @param cave_code Code to execute in cave
     * @param name Patch name
     */
    Sentinel::Core::Result<PatchOperation> CreateCodecavePatch(
        uint64_t target_address,
        const std::vector<uint8_t>& cave_code,
        const std::string& name = "");
    
    // ==================== Automatic Patch Generation ====================
    
    /**
     * Generate patches from binary diff
     * @param source_path Original binary
     * @param target_path Modified binary
     * @param progress Optional progress callback
     * @return Patch set or error
     */
    Sentinel::Core::Result<PatchSet> GenerateFromDiff(
        const std::string& source_path,
        const std::string& target_path,
        PatchProgressCallback progress = nullptr);
    
    /**
     * Generate anti-tampering bypass patches
     * @param binary_path Path to protected binary
     * @return Patch set for bypassing protections
     */
    Sentinel::Core::Result<PatchSet> GenerateBypassPatches(
        const std::string& binary_path);
    
    /**
     * Generate integrity check bypass
     * @param check_address Address of integrity check
     * @return Patch to bypass the check
     */
    Sentinel::Core::Result<PatchOperation> GenerateIntegrityBypass(
        uint64_t check_address);
    
    // ==================== Code Generation ====================
    
    /**
     * Generate hook handler assembly
     * @param callback_address Address of callback function
     * @param arch Target architecture
     * @return Generated assembly bytes
     */
    Sentinel::Core::Result<std::vector<uint8_t>> GenerateHookHandler(
        uint64_t callback_address,
        PatchArchitecture arch);
    
    /**
     * Generate trampoline code
     * @param original_bytes Original function bytes
     * @param original_address Original address
     * @param arch Target architecture
     * @return Trampoline bytes
     */
    Sentinel::Core::Result<std::vector<uint8_t>> GenerateTrampoline(
        const std::vector<uint8_t>& original_bytes,
        uint64_t original_address,
        PatchArchitecture arch);
    
    /**
     * Generate jump instruction
     * @param from Source address
     * @param to Destination address
     * @param arch Target architecture
     * @return Jump instruction bytes
     */
    Sentinel::Core::Result<std::vector<uint8_t>> GenerateJump(
        uint64_t from,
        uint64_t to,
        PatchArchitecture arch);
    
    /**
     * Generate call instruction
     * @param from Source address
     * @param to Destination address
     * @param arch Target architecture
     * @return Call instruction bytes
     */
    Sentinel::Core::Result<std::vector<uint8_t>> GenerateCall(
        uint64_t from,
        uint64_t to,
        PatchArchitecture arch);
    
    // ==================== Patch Management ====================
    
    /**
     * Create a new patch set
     * @param name Name of the set
     * @param target Target application name
     * @return New patch set
     */
    PatchSet CreatePatchSet(
        const std::string& name,
        const std::string& target);
    
    /**
     * Add patch to set
     * @param set Patch set to modify
     * @param patch Patch to add
     */
    void AddPatchToSet(PatchSet& set, const PatchOperation& patch);
    
    /**
     * Remove patch from set
     * @param set Patch set to modify
     * @param patch_id ID of patch to remove
     */
    Sentinel::Core::Result<void> RemovePatchFromSet(PatchSet& set, const std::string& patch_id);
    
    /**
     * Validate patch set
     * @param set Patch set to validate
     * @return Validation errors (empty if valid)
     */
    std::vector<std::string> ValidatePatchSet(const PatchSet& set);
    
    // ==================== Export ====================
    
    /**
     * Export patch set to file
     * @param set Patch set to export
     * @param output_path Output file path
     * @param format Output format
     */
    Sentinel::Core::Result<void> ExportPatchSet(
        const PatchSet& set,
        const std::string& output_path,
        PatchOutputFormat format);
    
    /**
     * Export as C++ source code
     * @param set Patch set
     * @param output_path Output file path
     */
    Sentinel::Core::Result<void> ExportAsCpp(
        const PatchSet& set,
        const std::string& output_path);
    
    /**
     * Export as assembly source
     * @param set Patch set
     * @param output_path Output file path
     */
    Sentinel::Core::Result<void> ExportAsAssembly(
        const PatchSet& set,
        const std::string& output_path);
    
    /**
     * Export as DLL injector
     * @param set Patch set
     * @param output_path Output directory
     */
    Sentinel::Core::Result<void> ExportAsDLL(
        const PatchSet& set,
        const std::string& output_path);
    
    /**
     * Export as Cheat Engine table
     * @param set Patch set
     * @param output_path Output file path
     */
    Sentinel::Core::Result<void> ExportAsCheatEngine(
        const PatchSet& set,
        const std::string& output_path);
    
    // ==================== Import ====================
    
    /**
     * Import patch set from file
     * @param input_path Input file path
     * @return Patch set or error
     */
    Sentinel::Core::Result<PatchSet> ImportPatchSet(const std::string& input_path);
    
    /**
     * Import from IDA script
     * @param script_path Path to IDAPython script
     * @return Patch set or error
     */
    Sentinel::Core::Result<PatchSet> ImportFromIDAScript(const std::string& script_path);
    
    // ==================== Application ====================
    
    /**
     * Apply patch set to binary file
     * @param set Patch set to apply
     * @param target_path Target file path
     * @return Results for each patch
     */
    Sentinel::Core::Result<std::vector<PatchApplicationResult>> ApplyToFile(
        const PatchSet& set,
        const std::string& target_path);
    
    /**
     * Apply patch set to running process
     * @param set Patch set to apply
     * @param process_id Target process ID
     * @return Results for each patch
     */
    Sentinel::Core::Result<std::vector<PatchApplicationResult>> ApplyToProcess(
        const PatchSet& set,
        uint32_t process_id);
    
    /**
     * Revert applied patches
     * @param results Previous application results
     * @param target_path Target file path
     */
    Sentinel::Core::Result<void> RevertPatches(
        const std::vector<PatchApplicationResult>& results,
        const std::string& target_path);
    
    // ==================== Configuration ====================
    
    const PatchGeneratorConfig& GetConfig() const { return config_; }
    void SetConfig(const PatchGeneratorConfig& config) { config_ = config; }
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    
    PatchGeneratorConfig config_;
    
    // Internal helpers
    std::string GeneratePatchId();
    PatchArchitecture DetectArchitecture(const std::string& binary_path);
    size_t GetMinPatchSize(PatchArchitecture arch) const;
    
    Sentinel::Core::Result<std::vector<uint8_t>> AssembleX86(const std::string& code);
    Sentinel::Core::Result<std::vector<uint8_t>> AssembleX64(const std::string& code);
    
    std::vector<uint8_t> GenerateNops(size_t count, PatchArchitecture arch);
};

/**
 * Utility functions for patch generation
 */
namespace PatchUtils {
    
    /**
     * Parse pattern string to bytes
     * Example: "48 8B 05 ?? ?? ?? ??" 
     */
    std::pair<std::vector<uint8_t>, std::string> ParsePattern(const std::string& pattern);
    
    /**
     * Format bytes as hex string
     */
    std::string BytesToHex(const std::vector<uint8_t>& bytes);
    
    /**
     * Parse hex string to bytes
     */
    std::vector<uint8_t> HexToBytes(const std::string& hex);
    
    /**
     * Get patch type string
     */
    std::string PatchTypeToString(PatchType type);
    
    /**
     * Get architecture string
     */
    std::string ArchToString(PatchArchitecture arch);
    
    /**
     * Calculate relative offset for jump
     */
    int32_t CalculateRelativeOffset(uint64_t from, uint64_t to, size_t instruction_size);
    
    /**
     * Check if address is in valid range
     */
    bool IsValidAddress(uint64_t address, PatchArchitecture arch);
    
    /**
     * Check if relative jump is possible
     */
    bool IsRelativeJumpPossible(uint64_t from, uint64_t to);
    
} // namespace PatchUtils

} // namespace Sentinel::Cortex
