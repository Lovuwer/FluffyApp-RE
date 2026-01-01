/**
 * Sentinel SDK - Signature Manager Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 13: Implement Detection Signature Update Mechanism
 */

#include "Internal/SignatureManager.hpp"
#include <Sentinel/Core/Crypto.hpp>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <filesystem>

// Simple JSON parsing (minimal implementation for signature parsing)
// Production code should use a proper JSON library like nlohmann/json
namespace {

// Helper to extract JSON string value
std::string extractJsonString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    
    pos = json.find("\"", pos + search.length());
    if (pos == std::string::npos) return "";
    
    size_t end = json.find("\"", pos + 1);
    if (end == std::string::npos) return "";
    
    return json.substr(pos + 1, end - pos - 1);
}

// Helper to extract JSON integer value
int64_t extractJsonInt(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return 0;
    
    pos += search.length();
    while (pos < json.length() && std::isspace(json[pos])) pos++;
    
    std::string num_str;
    while (pos < json.length() && (std::isdigit(json[pos]) || json[pos] == '-')) {
        num_str += json[pos++];
    }
    
    if (num_str.empty()) return 0;
    return std::stoll(num_str);
}

// Helper to decode hex string to bytes
Sentinel::Result<Sentinel::ByteBuffer> hexToBytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        return Sentinel::ErrorCode::InvalidHexString;
    }
    
    Sentinel::ByteBuffer result;
    result.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        try {
            int value = std::stoi(hex.substr(i, 2), nullptr, 16);
            result.push_back(static_cast<Sentinel::Byte>(value));
        } catch (...) {
            return Sentinel::ErrorCode::InvalidHexString;
        }
    }
    
    return result;
}

// Helper to encode bytes to hex string
std::string bytesToHex(Sentinel::ByteSpan bytes) {
    std::ostringstream oss;
    for (auto byte : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(byte);
    }
    return oss.str();
}

// Parse timestamp from ISO 8601 string
std::chrono::system_clock::time_point parseTimestamp(const std::string& iso_timestamp) {
    // Simplified parser - production should use proper date parsing
    std::tm tm = {};
    std::istringstream ss(iso_timestamp);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    
    if (ss.fail()) {
        // Return current time if parsing fails
        return std::chrono::system_clock::now();
    }
    
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
}

// Helper to convert SignatureType enum to string
std::string signatureTypeToString(Sentinel::SDK::SignatureType type) {
    using Sentinel::SDK::SignatureType;
    switch (type) {
        case SignatureType::MemoryPattern:
            return "MemoryPattern";
        case SignatureType::HashSignature:
            return "HashSignature";
        case SignatureType::BehaviorSignature:
            return "BehaviorSignature";
        case SignatureType::ModuleSignature:
            return "ModuleSignature";
        default:
            return "Unknown";
    }
}

} // anonymous namespace

namespace Sentinel {
namespace SDK {

// ============================================================================
// SignatureSet Implementation
// ============================================================================

Result<SHA256Hash> SignatureSet::calculateSetHash() const {
    Crypto::HashEngine hasher(Crypto::HashAlgorithm::SHA256);
    
    SENTINEL_TRY(hasher.init());
    
    // Hash version
    uint32_t ver = set_version;
    SENTINEL_TRY(hasher.update(reinterpret_cast<const Byte*>(&ver), sizeof(ver)));
    
    // Hash each signature in order
    for (const auto& sig : signatures) {
        SENTINEL_TRY(hasher.update(
            reinterpret_cast<const Byte*>(sig.id.data()), 
            sig.id.size()
        ));
        SENTINEL_TRY(hasher.update(sig.pattern_data));
    }
    
    auto hash_result = hasher.finalize();
    if (hash_result.isFailure()) {
        return hash_result.error();
    }
    
    auto& hash_vec = hash_result.value();
    if (hash_vec.size() != 32) {
        return ErrorCode::HashFailed;
    }
    
    SHA256Hash hash;
    std::copy(hash_vec.begin(), hash_vec.end(), hash.begin());
    return hash;
}

// ============================================================================
// SignatureManager Implementation
// ============================================================================

SignatureManager::SignatureManager()
    : m_verifier(nullptr)
    , m_initialized(false)
{
    m_current_set.set_version = 0;
}

SignatureManager::~SignatureManager() {
    // Cleanup
}

Result<void> SignatureManager::initialize(
    const std::string& cache_dir,
    ByteSpan public_key)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    // Create cache directory if it doesn't exist
    try {
        std::filesystem::create_directories(cache_dir);
    } catch (...) {
        return ErrorCode::DirectoryNotFound;
    }
    
    m_cache_dir = cache_dir;
    
    // Initialize RSA verifier
    m_verifier = std::make_unique<Crypto::RSASigner>();
    SENTINEL_TRY(m_verifier->loadPublicKey(public_key));
    
    // Try to load from cache
    auto cache_result = loadFromCache(24);
    if (cache_result.isSuccess()) {
        m_current_set = cache_result.value();
    }
    
    m_initialized = true;
    return Result<void>::Success();
}

Result<SignatureSet> SignatureManager::loadSignaturesFromJson(
    const std::string& json_data,
    bool verify_signature)
{
    // Sandboxed parsing - malformed input cannot crash SDK
    try {
        SignatureSet sig_set;
        
        // Extract version
        sig_set.set_version = static_cast<uint32_t>(extractJsonInt(json_data, "version"));
        
        // Extract deployed_at timestamp
        std::string timestamp = extractJsonString(json_data, "deployed_at");
        sig_set.deployed_at = parseTimestamp(timestamp);
        
        // Extract signature
        std::string sig_hex = extractJsonString(json_data, "signature");
        if (!sig_hex.empty()) {
            auto sig_bytes = hexToBytes(sig_hex);
            if (sig_bytes.isFailure()) {
                return ErrorCode::ParseError;
            }
            sig_set.set_signature = sig_bytes.value();
        }
        
        // Parse signatures array
        size_t sig_start = json_data.find("\"signatures\":");
        if (sig_start != std::string::npos) {
            size_t array_start = json_data.find("[", sig_start);
            size_t array_end = json_data.find("]", array_start);
            
            if (array_start != std::string::npos && array_end != std::string::npos) {
                // Extract each signature object
                size_t pos = array_start + 1;
                while (pos < array_end) {
                    size_t obj_start = json_data.find("{", pos);
                    if (obj_start >= array_end) break;
                    
                    size_t obj_end = json_data.find("}", obj_start);
                    if (obj_end >= array_end) break;
                    
                    std::string sig_obj = json_data.substr(obj_start, obj_end - obj_start + 1);
                    auto sig_result = parseSignatureFromJson(sig_obj);
                    
                    if (sig_result.isSuccess()) {
                        sig_set.signatures.push_back(sig_result.value());
                    } else {
                        // Log error but continue - don't let one bad signature fail everything
                        // Production: proper logging here
                    }
                    
                    pos = obj_end + 1;
                }
            }
        }
        
        // Verify signature if requested
        if (verify_signature && !sig_set.set_signature.empty()) {
            auto verify_result = verifySignatureSetSignature(sig_set);
            if (verify_result.isFailure() || !verify_result.value()) {
                return ErrorCode::SignatureInvalid;
            }
        }
        
        return sig_set;
        
    } catch (...) {
        // Sandboxed - any exception during parsing is caught
        return ErrorCode::ParseError;
    }
}

Result<DetectionSignature> SignatureManager::parseSignatureFromJson(
    const std::string& json_obj)
{
    try {
        DetectionSignature sig;
        
        // Required fields
        sig.id = extractJsonString(json_obj, "id");
        sig.name = extractJsonString(json_obj, "name");
        sig.version = static_cast<uint32_t>(extractJsonInt(json_obj, "version"));
        sig.threat_family = extractJsonString(json_obj, "threat_family");
        
        // Type
        std::string type_str = extractJsonString(json_obj, "type");
        if (type_str == "memory_pattern") {
            sig.type = SignatureType::MemoryPattern;
        } else if (type_str == "hash") {
            sig.type = SignatureType::HashSignature;
        } else if (type_str == "behavior") {
            sig.type = SignatureType::BehaviorSignature;
        } else if (type_str == "module") {
            sig.type = SignatureType::ModuleSignature;
        } else {
            sig.type = SignatureType::MemoryPattern;
        }
        
        // Severity
        int severity_val = static_cast<int>(extractJsonInt(json_obj, "severity"));
        sig.severity = static_cast<ThreatLevel>(severity_val);
        
        // Pattern data
        std::string pattern_hex = extractJsonString(json_obj, "pattern");
        if (!pattern_hex.empty()) {
            auto pattern_result = hexToBytes(pattern_hex);
            if (pattern_result.isFailure()) {
                return pattern_result.error();
            }
            sig.pattern_data = pattern_result.value();
        }
        
        // Optional mask
        std::string mask_hex = extractJsonString(json_obj, "mask");
        if (!mask_hex.empty()) {
            auto mask_result = hexToBytes(mask_hex);
            if (mask_result.isSuccess()) {
                sig.pattern_mask = mask_result.value();
            }
        }
        
        // Metadata
        sig.description = extractJsonString(json_obj, "description");
        sig.created_at = parseTimestamp(extractJsonString(json_obj, "created_at"));
        sig.expires_at = parseTimestamp(extractJsonString(json_obj, "expires_at"));
        
        // Signature
        std::string sig_hex = extractJsonString(json_obj, "signature");
        if (!sig_hex.empty()) {
            auto sig_result = hexToBytes(sig_hex);
            if (sig_result.isSuccess()) {
                sig.signature = sig_result.value();
            }
        }
        
        return sig;
        
    } catch (...) {
        return ErrorCode::ParseError;
    }
}

Result<void> SignatureManager::applySignatureSet(
    const SignatureSet& sig_set,
    bool force)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    // Check version - new version should be higher unless forced
    if (!force && sig_set.set_version <= m_current_set.set_version) {
        return ErrorCode::PatchVersionMismatch;
    }
    
    // Validate signature set
    auto valid_result = validateSignatureSet(sig_set);
    if (valid_result.isFailure() || !valid_result.value()) {
        return ErrorCode::SignatureInvalid;
    }
    
    // Save current set for rollback
    m_previous_set = m_current_set;
    
    // Apply new set atomically
    m_current_set = sig_set;
    
    // Save to cache
    SENTINEL_TRY(saveToCache());
    
    // Notify listeners
    if (m_update_callback) {
        m_update_callback(m_current_set);
    }
    
    return Result<void>::Success();
}

Result<void> SignatureManager::rollbackToPrevious() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    if (!m_previous_set.has_value()) {
        return ErrorCode::PatchNotFound;
    }
    
    // Rollback to previous
    m_current_set = m_previous_set.value();
    m_previous_set.reset();
    
    // Save rolled-back version to cache
    SENTINEL_TRY(saveToCache());
    
    // Notify listeners
    if (m_update_callback) {
        m_update_callback(m_current_set);
    }
    
    return Result<void>::Success();
}

Result<SignatureSet> SignatureManager::getCurrentSignatureSet() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    return m_current_set;
}

Result<DetectionSignature> SignatureManager::getSignatureById(
    const std::string& id) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (const auto& sig : m_current_set.signatures) {
        if (sig.id == id) {
            return sig;
        }
    }
    
    return ErrorCode::SignatureNotFound;
}

std::vector<DetectionSignature> SignatureManager::getSignaturesByType(
    SignatureType type) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<DetectionSignature> result;
    for (const auto& sig : m_current_set.signatures) {
        if (sig.type == type) {
            result.push_back(sig);
        }
    }
    
    return result;
}

Result<void> SignatureManager::saveToCache() {
    if (!m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    try {
        auto json_result = serializeSignatureSet(m_current_set);
        if (json_result.isFailure()) {
            return json_result.error();
        }
        
        std::string cache_path = getCacheFilePath();
        std::ofstream file(cache_path, std::ios::binary);
        if (!file) {
            return ErrorCode::FileWriteError;
        }
        
        file << json_result.value();
        file.close();
        
        // Save previous set as rollback
        if (m_previous_set.has_value()) {
            auto prev_json = serializeSignatureSet(m_previous_set.value());
            if (prev_json.isSuccess()) {
                std::string rollback_path = getRollbackCacheFilePath();
                std::ofstream rollback_file(rollback_path, std::ios::binary);
                if (rollback_file) {
                    rollback_file << prev_json.value();
                }
            }
        }
        
        return Result<void>::Success();
        
    } catch (...) {
        return ErrorCode::FileWriteError;
    }
}

Result<SignatureSet> SignatureManager::loadFromCache(int max_age_hours) {
    if (!m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    try {
        std::string cache_path = getCacheFilePath();
        std::ifstream file(cache_path, std::ios::binary);
        if (!file) {
            return ErrorCode::FileNotFound;
        }
        
        // Check file age
        if (max_age_hours > 0) {
            auto file_time = std::filesystem::last_write_time(cache_path);
            auto now = std::filesystem::file_time_type::clock::now();
            auto age = std::chrono::duration_cast<std::chrono::hours>(now - file_time);
            
            if (age.count() > max_age_hours) {
                return ErrorCode::Timeout;  // Cache too old
            }
        }
        
        // Read file content
        std::string json_data((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
        file.close();
        
        // Parse and return
        return loadSignaturesFromJson(json_data, false);  // Don't verify from cache
        
    } catch (...) {
        return ErrorCode::FileReadError;
    }
}

int SignatureManager::cleanupExpiredSignatures() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::system_clock::now();
    size_t original_count = m_current_set.signatures.size();
    
    m_current_set.signatures.erase(
        std::remove_if(
            m_current_set.signatures.begin(),
            m_current_set.signatures.end(),
            [now](const DetectionSignature& sig) {
                return sig.expires_at < now;
            }
        ),
        m_current_set.signatures.end()
    );
    
    return static_cast<int>(original_count - m_current_set.signatures.size());
}

void SignatureManager::setUpdateCallback(SignatureUpdateCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_update_callback = callback;
}

SignatureManager::Statistics SignatureManager::getStatistics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    Statistics stats;
    stats.current_version = m_current_set.set_version;
    stats.total_signatures = m_current_set.signatures.size();
    stats.last_update = m_current_set.deployed_at;
    
    // Count expired signatures
    auto now = std::chrono::system_clock::now();
    stats.expired_signatures = std::count_if(
        m_current_set.signatures.begin(),
        m_current_set.signatures.end(),
        [now](const DetectionSignature& sig) {
            return sig.expires_at < now;
        }
    );
    
    // Get cache timestamp
    try {
        std::string cache_path = getCacheFilePath();
        if (std::filesystem::exists(cache_path)) {
            auto file_time = std::filesystem::last_write_time(cache_path);
            stats.cache_timestamp = std::chrono::file_clock::to_sys(file_time);
        }
    } catch (...) {
        // Ignore errors
    }
    
    return stats;
}

Result<bool> SignatureManager::validateSignatureSet(
    const SignatureSet& sig_set) const
{
    // Check basic validity
    if (sig_set.signatures.empty()) {
        return false;  // Empty set not allowed
    }
    
    // Verify set signature if present
    if (!sig_set.set_signature.empty()) {
        auto verify_result = verifySignatureSetSignature(sig_set);
        if (verify_result.isFailure()) {
            return verify_result.error();
        }
        if (!verify_result.value()) {
            return false;
        }
    }
    
    // Validate each signature
    for (const auto& sig : sig_set.signatures) {
        // Check required fields
        if (sig.id.empty() || sig.pattern_data.empty()) {
            return false;
        }
        
        // Check mask length matches pattern if present
        if (!sig.pattern_mask.empty() && 
            sig.pattern_mask.size() != sig.pattern_data.size()) {
            return false;
        }
    }
    
    return true;
}

Result<bool> SignatureManager::verifySignatureSetSignature(
    const SignatureSet& sig_set) const
{
    if (!m_verifier) {
        return ErrorCode::KeyNotLoaded;
    }
    
    // Calculate hash of signature set
    auto hash_result = sig_set.calculateSetHash();
    if (hash_result.isFailure()) {
        return hash_result.error();
    }
    
    // Verify RSA signature
    ByteBuffer hash_vec(hash_result.value().begin(), hash_result.value().end());
    return m_verifier->verify(hash_vec, sig_set.set_signature);
}

Result<std::string> SignatureManager::serializeSignatureSet(
    const SignatureSet& sig_set) const
{
    // Minimal JSON serialization
    // Production should use proper JSON library
    std::ostringstream oss;
    
    oss << "{\n";
    oss << "  \"version\": " << sig_set.set_version << ",\n";
    
    // Timestamp
    auto time_t_val = std::chrono::system_clock::to_time_t(sig_set.deployed_at);
    std::tm tm = *std::gmtime(&time_t_val);
    oss << "  \"deployed_at\": \"" 
        << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << "Z\",\n";
    
    // Signatures array
    oss << "  \"signatures\": [\n";
    for (size_t i = 0; i < sig_set.signatures.size(); i++) {
        const auto& sig = sig_set.signatures[i];
        
        oss << "    {\n";
        oss << "      \"id\": \"" << sig.id << "\",\n";
        oss << "      \"name\": \"" << sig.name << "\",\n";
        oss << "      \"version\": " << sig.version << ",\n";
        oss << "      \"type\": \"" << signatureTypeToString(sig.type) << "\",\n";
        oss << "      \"threat_family\": \"" << sig.threat_family << "\",\n";
        oss << "      \"severity\": " << static_cast<int>(sig.severity) << ",\n";
        oss << "      \"pattern\": \"" << bytesToHex(sig.pattern_data) << "\",\n";
        oss << "      \"description\": \"" << sig.description << "\"\n";
        oss << "    }";
        
        if (i < sig_set.signatures.size() - 1) {
            oss << ",";
        }
        oss << "\n";
    }
    oss << "  ],\n";
    
    // Set signature
    oss << "  \"signature\": \"" << bytesToHex(sig_set.set_signature) << "\"\n";
    oss << "}\n";
    
    return oss.str();
}

std::string SignatureManager::getCacheFilePath() const {
    return m_cache_dir + "/signatures_current.json";
}

std::string SignatureManager::getRollbackCacheFilePath() const {
    return m_cache_dir + "/signatures_rollback.json";
}

} // namespace SDK
} // namespace Sentinel
