/**
 * FuzzyHasher.hpp
 * Sentinel Cortex - Fuzzy Hashing Engine
 * 
 * Uses TLSH and ssdeep algorithms for similarity-based cheat family detection
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
#include <unordered_map>
#include <optional>
#include <future>

namespace Sentinel::Cortex {

/**
 * Fuzzy hash type enumeration
 */
enum class FuzzyHashType {
    TLSH,           ///< Trend Micro Locality Sensitive Hash
    SSDEEP,         ///< Context-Triggered Piecewise Hashing
    COMBINED        ///< Weighted combination of both algorithms
};

/**
 * Represents a fuzzy hash with metadata
 */
struct FuzzyHash {
    std::string hash;           ///< The computed hash string
    FuzzyHashType type;         ///< Type of hash algorithm
    std::string filename;       ///< Source filename
    size_t file_size;           ///< Original file size
    uint64_t timestamp;         ///< When the hash was computed
    
    // Additional metadata
    std::string family_name;    ///< Detected cheat family (if known)
    float confidence;           ///< Confidence score (0.0 - 1.0)
    
    /**
     * Check if the hash is valid
     */
    bool IsValid() const {
        return !hash.empty() && hash.length() >= 16;
    }
};

/**
 * Result of a similarity comparison
 */
struct SimilarityResult {
    std::string hash_a;         ///< First hash
    std::string hash_b;         ///< Second hash
    float similarity_score;     ///< Similarity score (0.0 - 1.0)
    int distance;               ///< Raw distance value
    bool is_match;              ///< Whether it meets threshold
    
    // Match details
    std::string family_name;    ///< Matched family name
    std::vector<std::string> variants;  ///< Known variants
};

/**
 * Database entry for known cheat signatures
 */
struct CheatSignature {
    std::string id;             ///< Unique identifier
    std::string name;           ///< Cheat name
    std::string family;         ///< Family classification
    std::string tlsh_hash;      ///< TLSH hash
    std::string ssdeep_hash;    ///< ssdeep hash
    
    // Metadata
    std::string description;    ///< Description
    std::string first_seen;     ///< First detection date
    std::string last_seen;      ///< Last detection date
    int detection_count;        ///< Number of detections
    std::vector<std::string> tags;  ///< Classification tags
    
    // Technical details
    std::vector<std::string> known_filenames;
    std::vector<std::string> known_hashes_md5;
    std::vector<std::string> known_hashes_sha256;
    std::string target_game;    ///< Target game
    std::string category;       ///< Cheat category (aimbot, wallhack, etc.)
};

/**
 * Configuration for the fuzzy hasher
 */
struct FuzzyHasherConfig {
    // TLSH settings
    int tlsh_threshold = 100;           ///< TLSH distance threshold (lower = stricter)
    bool tlsh_force_include_small = true;  ///< Hash files smaller than 50 bytes
    
    // ssdeep settings
    int ssdeep_threshold = 50;          ///< ssdeep match threshold (percentage)
    size_t ssdeep_block_size = 3;       ///< Block size for ssdeep
    
    // Combined settings
    float tlsh_weight = 0.6f;           ///< Weight for TLSH in combined score
    float ssdeep_weight = 0.4f;         ///< Weight for ssdeep in combined score
    float match_threshold = 0.7f;       ///< Combined match threshold
    
    // Performance settings
    size_t max_file_size = 100 * 1024 * 1024;  ///< Maximum file size (100 MB)
    bool parallel_processing = true;    ///< Enable parallel hashing
    int max_threads = 0;                ///< 0 = auto-detect
};

/**
 * Callback for batch processing progress
 */
using BatchProgressCallback = std::function<void(size_t processed, size_t total, const std::string& current_file)>;

/**
 * Fuzzy hashing engine for malware family detection
 */
class FuzzyHasher {
public:
    /**
     * Constructor
     * @param config Configuration options
     */
    explicit FuzzyHasher(const FuzzyHasherConfig& config = FuzzyHasherConfig{});
    
    /**
     * Destructor
     */
    ~FuzzyHasher();
    
    // Non-copyable
    FuzzyHasher(const FuzzyHasher&) = delete;
    FuzzyHasher& operator=(const FuzzyHasher&) = delete;
    
    // Movable
    FuzzyHasher(FuzzyHasher&&) noexcept;
    FuzzyHasher& operator=(FuzzyHasher&&) noexcept;
    
    /**
     * Initialize the hasher engine
     * @return Success or error code
     */
    Core::Result<void> Initialize();
    
    /**
     * Shutdown the hasher engine
     */
    void Shutdown();
    
    // ==================== Hash Computation ====================
    
    /**
     * Compute TLSH hash from data
     * @param data Input data
     * @return TLSH hash string or error
     */
    Core::Result<std::string> ComputeTLSH(const Core::ByteBuffer& data);
    
    /**
     * Compute TLSH hash from file
     * @param filepath Path to file
     * @return Fuzzy hash with metadata or error
     */
    Core::Result<FuzzyHash> ComputeTLSHFromFile(const std::string& filepath);
    
    /**
     * Compute ssdeep hash from data
     * @param data Input data
     * @return ssdeep hash string or error
     */
    Core::Result<std::string> ComputeSSDeep(const Core::ByteBuffer& data);
    
    /**
     * Compute ssdeep hash from file
     * @param filepath Path to file
     * @return Fuzzy hash with metadata or error
     */
    Core::Result<FuzzyHash> ComputeSSDeepFromFile(const std::string& filepath);
    
    /**
     * Compute both hashes for a file
     * @param filepath Path to file
     * @return Pair of (TLSH, ssdeep) hashes or error
     */
    Core::Result<std::pair<FuzzyHash, FuzzyHash>> ComputeBothHashes(const std::string& filepath);
    
    /**
     * Batch compute hashes for multiple files
     * @param filepaths List of file paths
     * @param type Hash type to compute
     * @param progress_callback Optional progress callback
     * @return Map of filepath to hash or error
     */
    Core::Result<std::unordered_map<std::string, FuzzyHash>> ComputeHashesBatch(
        const std::vector<std::string>& filepaths,
        FuzzyHashType type,
        BatchProgressCallback progress_callback = nullptr);
    
    // ==================== Similarity Comparison ====================
    
    /**
     * Compare two TLSH hashes
     * @param hash_a First TLSH hash
     * @param hash_b Second TLSH hash
     * @return Similarity result or error
     */
    Core::Result<SimilarityResult> CompareTLSH(
        const std::string& hash_a,
        const std::string& hash_b);
    
    /**
     * Compare two ssdeep hashes
     * @param hash_a First ssdeep hash
     * @param hash_b Second ssdeep hash
     * @return Similarity result or error
     */
    Core::Result<SimilarityResult> CompareSSDeep(
        const std::string& hash_a,
        const std::string& hash_b);
    
    /**
     * Compare using combined algorithm
     * @param tlsh_a First TLSH hash
     * @param ssdeep_a First ssdeep hash
     * @param tlsh_b Second TLSH hash
     * @param ssdeep_b Second ssdeep hash
     * @return Combined similarity result
     */
    Core::Result<SimilarityResult> CompareCombined(
        const std::string& tlsh_a,
        const std::string& ssdeep_a,
        const std::string& tlsh_b,
        const std::string& ssdeep_b);
    
    /**
     * Compare a hash against all signatures in database
     * @param hash Hash to search for
     * @param type Hash type
     * @param max_results Maximum results to return
     * @return List of matching signatures sorted by similarity
     */
    Core::Result<std::vector<SimilarityResult>> SearchSimilar(
        const std::string& hash,
        FuzzyHashType type,
        size_t max_results = 10);
    
    /**
     * Find similar files in a directory
     * @param filepath Reference file
     * @param directory Directory to search
     * @param type Hash type to use
     * @param recursive Search recursively
     * @return List of similar files
     */
    Core::Result<std::vector<SimilarityResult>> FindSimilarFiles(
        const std::string& filepath,
        const std::string& directory,
        FuzzyHashType type,
        bool recursive = true);
    
    // ==================== Database Management ====================
    
    /**
     * Load signature database from file
     * @param filepath Path to database file (JSON format)
     * @return Success or error
     */
    Core::Result<void> LoadSignatureDatabase(const std::string& filepath);
    
    /**
     * Save signature database to file
     * @param filepath Path to save database
     * @return Success or error
     */
    Core::Result<void> SaveSignatureDatabase(const std::string& filepath);
    
    /**
     * Add a signature to the database
     * @param signature Signature to add
     * @return Success or error (duplicate ID)
     */
    Core::Result<void> AddSignature(const CheatSignature& signature);
    
    /**
     * Remove a signature from the database
     * @param signature_id ID of signature to remove
     * @return Success or error (not found)
     */
    Core::Result<void> RemoveSignature(const std::string& signature_id);
    
    /**
     * Update a signature in the database
     * @param signature Updated signature
     * @return Success or error
     */
    Core::Result<void> UpdateSignature(const CheatSignature& signature);
    
    /**
     * Get a signature by ID
     * @param signature_id Signature ID
     * @return Signature or nullopt if not found
     */
    std::optional<CheatSignature> GetSignature(const std::string& signature_id) const;
    
    /**
     * Get all signatures in a family
     * @param family_name Family name
     * @return List of signatures
     */
    std::vector<CheatSignature> GetSignaturesByFamily(const std::string& family_name) const;
    
    /**
     * Search signatures by name or tag
     * @param query Search query
     * @return Matching signatures
     */
    std::vector<CheatSignature> SearchSignatures(const std::string& query) const;
    
    /**
     * Get total number of signatures
     * @return Signature count
     */
    size_t GetSignatureCount() const;
    
    /**
     * Get list of all families
     * @return Family names
     */
    std::vector<std::string> GetFamilyNames() const;
    
    // ==================== Classification ====================
    
    /**
     * Classify a file against the signature database
     * @param filepath Path to file
     * @return Classification result with family and confidence
     */
    Core::Result<FuzzyHash> ClassifyFile(const std::string& filepath);
    
    /**
     * Classify multiple files
     * @param filepaths List of file paths
     * @param progress_callback Optional progress callback
     * @return Map of filepath to classification
     */
    Core::Result<std::unordered_map<std::string, FuzzyHash>> ClassifyFilesBatch(
        const std::vector<std::string>& filepaths,
        BatchProgressCallback progress_callback = nullptr);
    
    // ==================== Configuration ====================
    
    /**
     * Get current configuration
     * @return Configuration reference
     */
    const FuzzyHasherConfig& GetConfig() const { return config_; }
    
    /**
     * Update configuration
     * @param config New configuration
     */
    void SetConfig(const FuzzyHasherConfig& config) { config_ = config; }
    
    /**
     * Set TLSH threshold
     * @param threshold New threshold value
     */
    void SetTLSHThreshold(int threshold) { config_.tlsh_threshold = threshold; }
    
    /**
     * Set ssdeep threshold
     * @param threshold New threshold value (percentage)
     */
    void SetSSDeepThreshold(int threshold) { config_.ssdeep_threshold = threshold; }
    
    /**
     * Set match threshold for combined algorithm
     * @param threshold New threshold value (0.0 - 1.0)
     */
    void SetMatchThreshold(float threshold) { config_.match_threshold = threshold; }
    
    // ==================== Statistics ====================
    
    /**
     * Get statistics about hash computations
     */
    struct Statistics {
        uint64_t hashes_computed = 0;
        uint64_t comparisons_made = 0;
        uint64_t matches_found = 0;
        uint64_t classifications_performed = 0;
        double avg_hash_time_ms = 0.0;
        double avg_comparison_time_us = 0.0;
    };
    
    /**
     * Get current statistics
     * @return Statistics structure
     */
    Statistics GetStatistics() const { return stats_; }
    
    /**
     * Reset statistics
     */
    void ResetStatistics();
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    
    FuzzyHasherConfig config_;
    Statistics stats_;
    
    // Signature database
    std::unordered_map<std::string, CheatSignature> signatures_;
    
    // Internal methods
    Core::Result<Core::ByteBuffer> ReadFile(const std::string& filepath);
    float NormalizeTLSHDistance(int distance) const;
    float NormalizeSSDeepScore(int score) const;
    std::string GenerateSignatureId() const;
};

/**
 * Utility functions for fuzzy hashing
 */
namespace FuzzyHashUtils {
    
    /**
     * Convert TLSH distance to similarity percentage
     * @param distance TLSH distance
     * @return Similarity percentage (0-100)
     */
    float TLSHDistanceToSimilarity(int distance);
    
    /**
     * Get human-readable similarity description
     * @param similarity Similarity score (0.0 - 1.0)
     * @return Description string
     */
    std::string GetSimilarityDescription(float similarity);
    
    /**
     * Validate TLSH hash format
     * @param hash Hash string to validate
     * @return True if valid format
     */
    bool ValidateTLSHHash(const std::string& hash);
    
    /**
     * Validate ssdeep hash format
     * @param hash Hash string to validate
     * @return True if valid format
     */
    bool ValidateSSDeepHash(const std::string& hash);
    
    /**
     * Parse hash type from string
     * @param type_str Type string
     * @return Hash type or nullopt
     */
    std::optional<FuzzyHashType> ParseHashType(const std::string& type_str);
    
    /**
     * Get hash type as string
     * @param type Hash type
     * @return String representation
     */
    std::string HashTypeToString(FuzzyHashType type);
    
} // namespace FuzzyHashUtils

} // namespace Sentinel::Cortex
