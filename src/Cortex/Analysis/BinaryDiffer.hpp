/**
 * BinaryDiffer.hpp
 * Sentinel Cortex - Binary Diffing and Comparison Engine
 * 
 * Provides structural and semantic binary comparison capabilities
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
#include <set>

namespace Sentinel::Cortex {

// Forward declarations
class Disassembler;

/**
 * Type of difference detected
 */
enum class DiffType {
    Added,          ///< New content in target
    Removed,        ///< Content removed from source
    Modified,       ///< Content changed between versions
    Moved,          ///< Content relocated to different address
    Identical       ///< No change detected
};

/**
 * Granularity level for diffing
 */
enum class DiffGranularity {
    Byte,           ///< Byte-by-byte comparison
    Instruction,    ///< Instruction-level comparison
    BasicBlock,     ///< Basic block level
    Function,       ///< Function level
    Section         ///< Section level
};

/**
 * Represents a single byte-level difference
 */
struct ByteDiff {
    uint64_t offset;        ///< Offset in file
    uint8_t source_byte;    ///< Original byte value
    uint8_t target_byte;    ///< Modified byte value
    DiffType type;          ///< Type of change
};

/**
 * Represents an instruction-level difference
 */
struct InstructionDiff {
    uint64_t source_address;    ///< Address in source binary
    uint64_t target_address;    ///< Address in target binary
    std::string source_mnemonic;
    std::string target_mnemonic;
    std::string source_operands;
    std::string target_operands;
    std::vector<uint8_t> source_bytes;
    std::vector<uint8_t> target_bytes;
    DiffType type;
    float similarity;           ///< 0.0 - 1.0 similarity score
};

/**
 * Represents a basic block difference
 */
struct BasicBlockDiff {
    uint64_t source_start;
    uint64_t source_end;
    uint64_t target_start;
    uint64_t target_end;
    
    std::vector<InstructionDiff> instruction_diffs;
    
    size_t source_instruction_count;
    size_t target_instruction_count;
    
    DiffType type;
    float similarity;
    
    // Control flow changes
    std::vector<uint64_t> added_successors;
    std::vector<uint64_t> removed_successors;
};

/**
 * Represents a function-level difference
 */
struct FunctionDiff {
    std::string source_name;
    std::string target_name;
    
    uint64_t source_address;
    uint64_t target_address;
    
    size_t source_size;
    size_t target_size;
    
    std::vector<BasicBlockDiff> block_diffs;
    
    DiffType type;
    float similarity;
    
    // Metrics
    int added_blocks;
    int removed_blocks;
    int modified_blocks;
    int matched_blocks;
    
    // Call graph changes
    std::vector<std::string> added_calls;
    std::vector<std::string> removed_calls;
    std::vector<std::string> modified_calls;
};

/**
 * Complete diff result between two binaries
 */
struct BinaryDiffResult {
    std::string source_path;
    std::string target_path;
    
    // Overall metrics
    float overall_similarity;
    size_t total_bytes_changed;
    size_t total_functions;
    size_t matched_functions;
    size_t added_functions;
    size_t removed_functions;
    size_t modified_functions;
    
    // Detailed diffs at various granularities
    std::vector<ByteDiff> byte_diffs;
    std::vector<FunctionDiff> function_diffs;
    
    // Section-level summary
    struct SectionDiff {
        std::string name;
        uint64_t source_offset;
        uint64_t target_offset;
        size_t source_size;
        size_t target_size;
        float similarity;
        size_t bytes_changed;
    };
    std::vector<SectionDiff> section_diffs;
    
    // String differences
    std::vector<std::string> added_strings;
    std::vector<std::string> removed_strings;
    
    // Import/Export changes
    std::vector<std::string> added_imports;
    std::vector<std::string> removed_imports;
    std::vector<std::string> added_exports;
    std::vector<std::string> removed_exports;
};

/**
 * Match confidence levels for function matching
 */
struct FunctionMatch {
    std::string source_name;
    std::string target_name;
    uint64_t source_address;
    uint64_t target_address;
    float confidence;
    
    enum class MatchType {
        ExactName,      ///< Identical exported name
        ExactHash,      ///< Identical instruction hash
        StructuralSim,  ///< Similar CFG structure
        SemanticSim,    ///< Similar semantics
        AddressSim,     ///< Similar relative address
        Unmatched       ///< No match found
    } match_type;
};

/**
 * Configuration for the binary differ
 */
struct BinaryDifferConfig {
    // Diff settings
    DiffGranularity granularity = DiffGranularity::Function;
    float similarity_threshold = 0.5f;      ///< Minimum similarity to consider a match
    float exact_match_threshold = 0.95f;    ///< Threshold for exact matches
    
    // Function matching settings
    bool use_name_matching = true;          ///< Match by exported names
    bool use_hash_matching = true;          ///< Match by instruction hash
    bool use_structural_matching = true;    ///< Match by CFG structure
    bool use_semantic_matching = true;      ///< Match by instruction semantics
    
    // Performance settings
    size_t max_diff_size = 10 * 1024 * 1024;   ///< Max size for byte diff (10MB)
    bool parallel_processing = true;
    int max_threads = 0;  // 0 = auto
    
    // Output settings
    bool include_byte_diffs = false;        ///< Include raw byte differences
    bool include_strings = true;            ///< Include string differences
    bool include_imports = true;            ///< Include import/export changes
    size_t max_string_length = 1000;        ///< Max string length to include
};

/**
 * Progress callback for long operations
 */
using DiffProgressCallback = std::function<void(float progress, const std::string& stage)>;

/**
 * Binary diffing engine
 */
class BinaryDiffer {
public:
    /**
     * Constructor
     * @param config Configuration options
     */
    explicit BinaryDiffer(const BinaryDifferConfig& config = BinaryDifferConfig{});
    
    /**
     * Destructor
     */
    ~BinaryDiffer();
    
    // Non-copyable
    BinaryDiffer(const BinaryDiffer&) = delete;
    BinaryDiffer& operator=(const BinaryDiffer&) = delete;
    
    // Movable
    BinaryDiffer(BinaryDiffer&&) noexcept;
    BinaryDiffer& operator=(BinaryDiffer&&) noexcept;
    
    /**
     * Initialize the differ
     * @return Success or error
     */
    Core::Result<void> Initialize();
    
    /**
     * Shutdown and cleanup
     */
    void Shutdown();
    
    // ==================== Diff Operations ====================
    
    /**
     * Compare two binary files
     * @param source_path Path to source (original) binary
     * @param target_path Path to target (modified) binary
     * @param progress Optional progress callback
     * @return Complete diff result or error
     */
    Core::Result<BinaryDiffResult> DiffBinaries(
        const std::string& source_path,
        const std::string& target_path,
        DiffProgressCallback progress = nullptr);
    
    /**
     * Compare two binary buffers
     * @param source Source binary data
     * @param target Target binary data
     * @param progress Optional progress callback
     * @return Complete diff result or error
     */
    Core::Result<BinaryDiffResult> DiffBuffers(
        const Core::ByteBuffer& source,
        const Core::ByteBuffer& target,
        DiffProgressCallback progress = nullptr);
    
    /**
     * Quick similarity check (faster than full diff)
     * @param source_path Path to source binary
     * @param target_path Path to target binary
     * @return Similarity score (0.0 - 1.0) or error
     */
    Core::Result<float> QuickSimilarity(
        const std::string& source_path,
        const std::string& target_path);
    
    // ==================== Function Matching ====================
    
    /**
     * Match functions between two binaries
     * @param source_path Source binary path
     * @param target_path Target binary path
     * @return List of function matches or error
     */
    Core::Result<std::vector<FunctionMatch>> MatchFunctions(
        const std::string& source_path,
        const std::string& target_path);
    
    /**
     * Find a function in target that matches source function
     * @param source_func Function info from source
     * @param target_path Target binary path
     * @return Best match or nullopt if none found
     */
    std::optional<FunctionMatch> FindMatchingFunction(
        const FunctionDiff& source_func,
        const std::string& target_path);
    
    // ==================== Patch Generation ====================
    
    /**
     * Generate binary patch from diff result
     * @param diff Diff result to convert
     * @return Patch data in IPS format or error
     */
    Core::Result<Core::ByteBuffer> GeneratePatch(const BinaryDiffResult& diff);
    
    /**
     * Generate patch instructions (human-readable)
     * @param diff Diff result
     * @return List of patch instructions
     */
    std::vector<std::string> GeneratePatchInstructions(const BinaryDiffResult& diff);
    
    /**
     * Apply patch to binary
     * @param binary_path Path to binary to patch
     * @param patch_data Patch data (IPS format)
     * @return Success or error
     */
    Core::Result<void> ApplyPatch(
        const std::string& binary_path,
        const Core::ByteBuffer& patch_data);
    
    // ==================== Export ====================
    
    /**
     * Export diff as HTML report
     * @param diff Diff result
     * @param output_path Output file path
     * @return Success or error
     */
    Core::Result<void> ExportHTML(
        const BinaryDiffResult& diff,
        const std::string& output_path);
    
    /**
     * Export diff as JSON
     * @param diff Diff result
     * @param output_path Output file path
     * @return Success or error
     */
    Core::Result<void> ExportJSON(
        const BinaryDiffResult& diff,
        const std::string& output_path);
    
    /**
     * Export diff as BinDiff format (for IDA Pro compatibility)
     * @param diff Diff result
     * @param output_path Output file path
     * @return Success or error
     */
    Core::Result<void> ExportBinDiff(
        const BinaryDiffResult& diff,
        const std::string& output_path);
    
    // ==================== Configuration ====================
    
    /**
     * Get current configuration
     */
    const BinaryDifferConfig& GetConfig() const { return config_; }
    
    /**
     * Update configuration
     */
    void SetConfig(const BinaryDifferConfig& config) { config_ = config; }
    
    /**
     * Set diff granularity
     */
    void SetGranularity(DiffGranularity granularity) { config_.granularity = granularity; }
    
    /**
     * Set similarity threshold
     */
    void SetSimilarityThreshold(float threshold) { config_.similarity_threshold = threshold; }
    
    // ==================== Utilities ====================
    
    /**
     * Get statistics about the last diff operation
     */
    struct DiffStatistics {
        double diff_time_ms;
        size_t bytes_compared;
        size_t functions_compared;
        size_t instructions_compared;
        size_t matches_found;
    };
    
    DiffStatistics GetStatistics() const { return stats_; }
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    
    BinaryDifferConfig config_;
    DiffStatistics stats_;
    
    // Internal methods
    Core::Result<std::vector<ByteDiff>> ComputeByteDiffs(
        const Core::ByteBuffer& source,
        const Core::ByteBuffer& target);
    
    Core::Result<std::vector<FunctionDiff>> ComputeFunctionDiffs(
        const std::string& source_path,
        const std::string& target_path);
    
    float ComputeInstructionSimilarity(
        const std::vector<uint8_t>& source,
        const std::vector<uint8_t>& target);
    
    float ComputeBlockSimilarity(
        const BasicBlockDiff& block);
    
    float ComputeFunctionSimilarity(
        const FunctionDiff& func);
    
    std::string ComputeFunctionHash(
        const std::vector<uint8_t>& instructions);
    
    std::vector<std::string> ExtractStrings(
        const Core::ByteBuffer& data);
};

/**
 * Utility functions for binary diffing
 */
namespace BinaryDiffUtils {
    
    /**
     * Get human-readable diff type string
     */
    std::string DiffTypeToString(DiffType type);
    
    /**
     * Get human-readable granularity string
     */
    std::string GranularityToString(DiffGranularity granularity);
    
    /**
     * Calculate Levenshtein distance between byte sequences
     */
    int LevenshteinDistance(
        const std::vector<uint8_t>& a,
        const std::vector<uint8_t>& b);
    
    /**
     * Calculate longest common subsequence
     */
    std::vector<uint8_t> LongestCommonSubsequence(
        const std::vector<uint8_t>& a,
        const std::vector<uint8_t>& b);
    
    /**
     * Format byte difference for display
     */
    std::string FormatByteDiff(const ByteDiff& diff);
    
    /**
     * Format instruction difference for display
     */
    std::string FormatInstructionDiff(const InstructionDiff& diff);
    
    /**
     * Generate unified diff format output
     */
    std::string GenerateUnifiedDiff(
        const BinaryDiffResult& result,
        int context_lines = 3);
    
} // namespace BinaryDiffUtils

} // namespace Sentinel::Cortex
