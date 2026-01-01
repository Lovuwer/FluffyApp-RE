/**
 * Sentinel SDK - Signature Manager
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 13: Implement Detection Signature Update Mechanism
 * Provides dynamic signature updates without requiring game restarts.
 */

#pragma once

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>

namespace Sentinel {
namespace SDK {

/**
 * Signature type classification
 */
enum class SignatureType : uint8_t {
    MemoryPattern,      ///< Memory pattern signature (byte pattern)
    HashSignature,      ///< Hash-based signature (SHA-256)
    BehaviorSignature,  ///< Behavioral detection signature
    ModuleSignature     ///< Module validation signature
};

/**
 * Detection signature entry
 * Format designed for secure transmission and validation
 */
struct DetectionSignature {
    std::string id;                     ///< Unique signature ID (e.g., "CHEAT_001")
    std::string name;                   ///< Human-readable name
    SignatureType type;                 ///< Type of signature
    uint32_t version;                   ///< Signature version number
    std::string threat_family;          ///< Threat family/category
    ThreatLevel severity;               ///< Threat severity level
    
    // Pattern data (varies by type)
    ByteBuffer pattern_data;            ///< Pattern bytes or hash
    ByteBuffer pattern_mask;            ///< Mask for wildcard matching (optional)
    
    // Metadata
    std::string description;            ///< Detailed description
    std::chrono::system_clock::time_point created_at;  ///< Creation timestamp
    std::chrono::system_clock::time_point expires_at;  ///< Expiration timestamp
    
    // Validation
    Signature signature;                ///< RSA signature of signature data
    
    /**
     * Check if signature has expired
     */
    [[nodiscard]] bool isExpired() const noexcept {
        return std::chrono::system_clock::now() >= expires_at;
    }
    
    /**
     * Get age of signature in hours
     */
    [[nodiscard]] int getAgeHours() const noexcept {
        auto now = std::chrono::system_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::hours>(now - created_at);
        return static_cast<int>(age.count());
    }
};

/**
 * Signature set with versioning
 * A versioned collection of signatures that can be atomically applied
 */
struct SignatureSet {
    uint32_t set_version;                           ///< Version of this signature set
    std::vector<DetectionSignature> signatures;     ///< All signatures in set
    std::chrono::system_clock::time_point deployed_at;  ///< Deployment timestamp
    Signature set_signature;                        ///< Signature of entire set
    
    /**
     * Calculate set hash for integrity verification
     */
    [[nodiscard]] Result<SHA256Hash> calculateSetHash() const;
};

/**
 * Signature update callback
 * Called when new signatures are loaded
 */
using SignatureUpdateCallback = std::function<void(const SignatureSet&)>;

/**
 * Signature manager
 * Manages detection signatures with dynamic updates, caching, and rollback
 */
class SignatureManager {
public:
    SignatureManager();
    ~SignatureManager();
    
    // Non-copyable
    SignatureManager(const SignatureManager&) = delete;
    SignatureManager& operator=(const SignatureManager&) = delete;
    
    /**
     * Initialize the signature manager
     * @param cache_dir Directory for signature cache
     * @param public_key RSA public key for signature verification
     * @return Success or error
     */
    Result<void> initialize(
        const std::string& cache_dir,
        ByteSpan public_key
    );
    
    /**
     * Load signatures from JSON format
     * @param json_data JSON-encoded signature data
     * @param verify_signature Whether to verify RSA signature
     * @return Success or error
     */
    Result<SignatureSet> loadSignaturesFromJson(
        const std::string& json_data,
        bool verify_signature = true
    );
    
    /**
     * Apply a signature set (atomic operation)
     * @param sig_set Signature set to apply
     * @param force Force application even if version is not newer
     * @return Success or error
     */
    Result<void> applySignatureSet(
        const SignatureSet& sig_set,
        bool force = false
    );
    
    /**
     * Rollback to previous signature set
     * @return Success or error
     */
    Result<void> rollbackToPrevious();
    
    /**
     * Get current active signature set
     * @return Current signature set or error
     */
    Result<SignatureSet> getCurrentSignatureSet() const;
    
    /**
     * Get signature by ID
     * @param id Signature ID
     * @return Signature or error
     */
    Result<DetectionSignature> getSignatureById(const std::string& id) const;
    
    /**
     * Get all signatures of a specific type
     * @param type Signature type filter
     * @return Vector of signatures
     */
    std::vector<DetectionSignature> getSignaturesByType(SignatureType type) const;
    
    /**
     * Save current signature set to cache
     * @return Success or error
     */
    Result<void> saveToCache();
    
    /**
     * Load signature set from cache
     * @param max_age_hours Maximum age in hours (0 = no limit)
     * @return Success or error
     */
    Result<SignatureSet> loadFromCache(int max_age_hours = 24);
    
    /**
     * Clear expired signatures from current set
     * @return Number of signatures removed
     */
    int cleanupExpiredSignatures();
    
    /**
     * Set update callback
     * @param callback Callback function to invoke on updates
     */
    void setUpdateCallback(SignatureUpdateCallback callback);
    
    /**
     * Get signature statistics
     */
    struct Statistics {
        uint32_t current_version;
        size_t total_signatures;
        size_t expired_signatures;
        std::chrono::system_clock::time_point last_update;
        std::chrono::system_clock::time_point cache_timestamp;
    };
    
    [[nodiscard]] Statistics getStatistics() const;
    
    /**
     * Validate signature set integrity
     * @param sig_set Signature set to validate
     * @return true if valid, false otherwise
     */
    [[nodiscard]] Result<bool> validateSignatureSet(const SignatureSet& sig_set) const;

private:
    /**
     * Parse signature from JSON object
     * Sandboxed parsing - malformed input cannot crash SDK
     */
    Result<DetectionSignature> parseSignatureFromJson(const std::string& json_obj);
    
    /**
     * Verify RSA signature of signature set
     */
    Result<bool> verifySignatureSetSignature(const SignatureSet& sig_set) const;
    
    /**
     * Serialize signature set to JSON
     */
    Result<std::string> serializeSignatureSet(const SignatureSet& sig_set) const;
    
    /**
     * Get cache file path
     */
    std::string getCacheFilePath() const;
    
    /**
     * Get rollback cache file path
     */
    std::string getRollbackCacheFilePath() const;

private:
    // Current active signature set
    SignatureSet m_current_set;
    
    // Previous signature set (for rollback)
    std::optional<SignatureSet> m_previous_set;
    
    // RSA public key for verification
    std::unique_ptr<Crypto::RSASigner> m_verifier;
    
    // Cache directory path
    std::string m_cache_dir;
    
    // Update callback
    SignatureUpdateCallback m_update_callback;
    
    // Thread safety
    mutable std::mutex m_mutex;
    
    // Initialization flag
    bool m_initialized;
};

} // namespace SDK
} // namespace Sentinel
