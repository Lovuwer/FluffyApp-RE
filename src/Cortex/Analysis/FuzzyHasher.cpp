/**
 * FuzzyHasher.cpp
 * Sentinel Cortex - Fuzzy Hashing Engine Implementation
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include "FuzzyHasher.hpp"

#include <fstream>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <thread>
#include <mutex>
#include <random>
#include <sstream>
#include <iomanip>
#include <regex>

// Third-party includes
// Note: In a real implementation, these would be the actual TLSH and ssdeep libraries
// #include <tlsh.h>
// #include <fuzzy.h>

namespace fs = std::filesystem;

namespace Sentinel::Cortex {

// ==================== Implementation Details ====================

struct FuzzyHasher::Impl {
    std::mutex mutex;
    bool initialized = false;
    
    // TLSH context (placeholder for actual implementation)
    struct TLSHContext {
        bool initialized = false;
    } tlsh_ctx;
    
    // ssdeep context
    struct SSDeepContext {
        bool initialized = false;
    } ssdeep_ctx;
};

// ==================== Constructor / Destructor ====================

FuzzyHasher::FuzzyHasher(const FuzzyHasherConfig& config)
    : impl_(std::make_unique<Impl>())
    , config_(config) {
}

FuzzyHasher::~FuzzyHasher() {
    Shutdown();
}

FuzzyHasher::FuzzyHasher(FuzzyHasher&&) noexcept = default;
FuzzyHasher& FuzzyHasher::operator=(FuzzyHasher&&) noexcept = default;

// ==================== Initialization ====================

Core::Result<void> FuzzyHasher::Initialize() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    if (impl_->initialized) {
        return Core::Result<void>::Ok();
    }
    
    // Initialize TLSH
    // In a real implementation:
    // tlsh_init(&impl_->tlsh_ctx);
    impl_->tlsh_ctx.initialized = true;
    
    // Initialize ssdeep
    // In a real implementation:
    // ssdeep_init(&impl_->ssdeep_ctx);
    impl_->ssdeep_ctx.initialized = true;
    
    impl_->initialized = true;
    return Core::Result<void>::Ok();
}

void FuzzyHasher::Shutdown() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    if (!impl_->initialized) {
        return;
    }
    
    // Cleanup TLSH
    impl_->tlsh_ctx.initialized = false;
    
    // Cleanup ssdeep
    impl_->ssdeep_ctx.initialized = false;
    
    impl_->initialized = false;
}

// ==================== Hash Computation ====================

Core::Result<std::string> FuzzyHasher::ComputeTLSH(const Core::ByteBuffer& data) {
    auto start = std::chrono::high_resolution_clock::now();
    
    if (data.size() < 50) {
        if (!config_.tlsh_force_include_small) {
            return Core::Result<std::string>::Err(Core::ErrorCode::InvalidArgument, 
                "Data too small for TLSH (minimum 50 bytes)");
        }
    }
    
    // In a real implementation, this would use the TLSH library:
    // Tlsh tlsh;
    // tlsh.update(data.data(), data.size());
    // tlsh.final();
    // return tlsh.getHash();
    
    // Placeholder: Generate a fake TLSH hash for demonstration
    std::stringstream ss;
    ss << "T1";  // TLSH version
    
    // Generate deterministic hash based on data
    std::hash<std::string> hasher;
    size_t h1 = hasher(std::string(reinterpret_cast<const char*>(data.data()), 
                                    std::min(data.size(), size_t(100))));
    size_t h2 = hasher(std::string(reinterpret_cast<const char*>(data.data()), data.size()));
    
    ss << std::hex << std::setfill('0');
    ss << std::setw(8) << (h1 & 0xFFFFFFFF);
    ss << std::setw(8) << ((h1 >> 32) & 0xFFFFFFFF);
    ss << std::setw(8) << (h2 & 0xFFFFFFFF);
    ss << std::setw(8) << ((h2 >> 32) & 0xFFFFFFFF);
    
    // Pad to standard TLSH length (70 chars)
    std::string hash = ss.str();
    while (hash.length() < 70) {
        hash += "0";
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Update statistics
    stats_.hashes_computed++;
    stats_.avg_hash_time_ms = (stats_.avg_hash_time_ms * (stats_.hashes_computed - 1) + elapsed) 
                              / stats_.hashes_computed;
    
    return Core::Result<std::string>::Ok(hash);
}

Core::Result<FuzzyHash> FuzzyHasher::ComputeTLSHFromFile(const std::string& filepath) {
    auto data_result = ReadFile(filepath);
    if (!data_result) {
        return Core::Result<FuzzyHash>::Err(data_result.GetError());
    }
    
    auto hash_result = ComputeTLSH(data_result.Value());
    if (!hash_result) {
        return Core::Result<FuzzyHash>::Err(hash_result.GetError());
    }
    
    FuzzyHash result;
    result.hash = hash_result.Value();
    result.type = FuzzyHashType::TLSH;
    result.filename = fs::path(filepath).filename().string();
    result.file_size = data_result.Value().size();
    result.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    result.confidence = 0.0f;
    
    return Core::Result<FuzzyHash>::Ok(result);
}

Core::Result<std::string> FuzzyHasher::ComputeSSDeep(const Core::ByteBuffer& data) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // In a real implementation, this would use the ssdeep library:
    // char hash[FUZZY_MAX_RESULT];
    // fuzzy_hash_buf(data.data(), data.size(), hash);
    // return std::string(hash);
    
    // Placeholder: Generate a fake ssdeep hash for demonstration
    size_t block_size = config_.ssdeep_block_size;
    while (block_size * 64 < data.size() && block_size < 1073741824) {
        block_size *= 2;
    }
    
    std::stringstream ss;
    ss << block_size << ":";
    
    // Generate two signature parts
    std::hash<std::string> hasher;
    std::string data_str(reinterpret_cast<const char*>(data.data()), data.size());
    
    size_t h1 = hasher(data_str.substr(0, data_str.length() / 2));
    size_t h2 = hasher(data_str.substr(data_str.length() / 2));
    
    // Base64-like encoding for signatures
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string sig1, sig2;
    for (int i = 0; i < 32; i++) {
        sig1 += alphabet[(h1 >> (i * 2)) % 64];
        sig2 += alphabet[(h2 >> (i * 2)) % 64];
    }
    
    ss << sig1 << ":" << sig2;
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double, std::milli>(end - start).count();
    
    stats_.hashes_computed++;
    stats_.avg_hash_time_ms = (stats_.avg_hash_time_ms * (stats_.hashes_computed - 1) + elapsed) 
                              / stats_.hashes_computed;
    
    return Core::Result<std::string>::Ok(ss.str());
}

Core::Result<FuzzyHash> FuzzyHasher::ComputeSSDeepFromFile(const std::string& filepath) {
    auto data_result = ReadFile(filepath);
    if (!data_result) {
        return Core::Result<FuzzyHash>::Err(data_result.GetError());
    }
    
    auto hash_result = ComputeSSDeep(data_result.Value());
    if (!hash_result) {
        return Core::Result<FuzzyHash>::Err(hash_result.GetError());
    }
    
    FuzzyHash result;
    result.hash = hash_result.Value();
    result.type = FuzzyHashType::SSDEEP;
    result.filename = fs::path(filepath).filename().string();
    result.file_size = data_result.Value().size();
    result.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    result.confidence = 0.0f;
    
    return Core::Result<FuzzyHash>::Ok(result);
}

Core::Result<std::pair<FuzzyHash, FuzzyHash>> FuzzyHasher::ComputeBothHashes(const std::string& filepath) {
    auto data_result = ReadFile(filepath);
    if (!data_result) {
        return Core::Result<std::pair<FuzzyHash, FuzzyHash>>::Err(data_result.GetError());
    }
    
    const auto& data = data_result.Value();
    
    // Compute TLSH
    auto tlsh_result = ComputeTLSH(data);
    if (!tlsh_result) {
        return Core::Result<std::pair<FuzzyHash, FuzzyHash>>::Err(tlsh_result.GetError());
    }
    
    // Compute ssdeep
    auto ssdeep_result = ComputeSSDeep(data);
    if (!ssdeep_result) {
        return Core::Result<std::pair<FuzzyHash, FuzzyHash>>::Err(ssdeep_result.GetError());
    }
    
    std::string filename = fs::path(filepath).filename().string();
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    FuzzyHash tlsh_hash;
    tlsh_hash.hash = tlsh_result.Value();
    tlsh_hash.type = FuzzyHashType::TLSH;
    tlsh_hash.filename = filename;
    tlsh_hash.file_size = data.size();
    tlsh_hash.timestamp = timestamp;
    
    FuzzyHash ssdeep_hash;
    ssdeep_hash.hash = ssdeep_result.Value();
    ssdeep_hash.type = FuzzyHashType::SSDEEP;
    ssdeep_hash.filename = filename;
    ssdeep_hash.file_size = data.size();
    ssdeep_hash.timestamp = timestamp;
    
    return Core::Result<std::pair<FuzzyHash, FuzzyHash>>::Ok({tlsh_hash, ssdeep_hash});
}

Core::Result<std::unordered_map<std::string, FuzzyHash>> FuzzyHasher::ComputeHashesBatch(
    const std::vector<std::string>& filepaths,
    FuzzyHashType type,
    BatchProgressCallback progress_callback) {
    
    std::unordered_map<std::string, FuzzyHash> results;
    std::mutex results_mutex;
    
    auto process_file = [&](const std::string& filepath) {
        Core::Result<FuzzyHash> result = (type == FuzzyHashType::TLSH) ?
            ComputeTLSHFromFile(filepath) : ComputeSSDeepFromFile(filepath);
        
        if (result) {
            std::lock_guard<std::mutex> lock(results_mutex);
            results[filepath] = result.Value();
        }
    };
    
    if (config_.parallel_processing && filepaths.size() > 1) {
        unsigned int num_threads = config_.max_threads > 0 ? 
            config_.max_threads : std::thread::hardware_concurrency();
        num_threads = std::min(num_threads, static_cast<unsigned int>(filepaths.size()));
        
        std::vector<std::thread> threads;
        std::atomic<size_t> next_index(0);
        std::atomic<size_t> processed(0);
        
        for (unsigned int t = 0; t < num_threads; t++) {
            threads.emplace_back([&]() {
                while (true) {
                    size_t idx = next_index.fetch_add(1);
                    if (idx >= filepaths.size()) break;
                    
                    process_file(filepaths[idx]);
                    
                    size_t current = processed.fetch_add(1) + 1;
                    if (progress_callback) {
                        progress_callback(current, filepaths.size(), filepaths[idx]);
                    }
                }
            });
        }
        
        for (auto& t : threads) {
            t.join();
        }
    } else {
        for (size_t i = 0; i < filepaths.size(); i++) {
            process_file(filepaths[i]);
            if (progress_callback) {
                progress_callback(i + 1, filepaths.size(), filepaths[i]);
            }
        }
    }
    
    return Core::Result<std::unordered_map<std::string, FuzzyHash>>::Ok(std::move(results));
}

// ==================== Similarity Comparison ====================

Core::Result<SimilarityResult> FuzzyHasher::CompareTLSH(
    const std::string& hash_a,
    const std::string& hash_b) {
    
    auto start = std::chrono::high_resolution_clock::now();
    
    if (!FuzzyHashUtils::ValidateTLSHHash(hash_a) || !FuzzyHashUtils::ValidateTLSHHash(hash_b)) {
        return Core::Result<SimilarityResult>::Err(Core::ErrorCode::InvalidArgument,
            "Invalid TLSH hash format");
    }
    
    // In a real implementation:
    // Tlsh tlsh_a, tlsh_b;
    // tlsh_a.fromTlshStr(hash_a.c_str());
    // tlsh_b.fromTlshStr(hash_b.c_str());
    // int distance = tlsh_a.totalDiff(&tlsh_b);
    
    // Placeholder: Compute simple character difference
    int distance = 0;
    for (size_t i = 0; i < std::min(hash_a.length(), hash_b.length()); i++) {
        if (hash_a[i] != hash_b[i]) {
            distance++;
        }
    }
    distance += static_cast<int>(std::abs(
        static_cast<int>(hash_a.length()) - static_cast<int>(hash_b.length())));
    
    SimilarityResult result;
    result.hash_a = hash_a;
    result.hash_b = hash_b;
    result.distance = distance;
    result.similarity_score = NormalizeTLSHDistance(distance);
    result.is_match = distance <= config_.tlsh_threshold;
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double, std::micro>(end - start).count();
    
    stats_.comparisons_made++;
    stats_.avg_comparison_time_us = (stats_.avg_comparison_time_us * (stats_.comparisons_made - 1) + elapsed) 
                                    / stats_.comparisons_made;
    if (result.is_match) {
        stats_.matches_found++;
    }
    
    return Core::Result<SimilarityResult>::Ok(result);
}

Core::Result<SimilarityResult> FuzzyHasher::CompareSSDeep(
    const std::string& hash_a,
    const std::string& hash_b) {
    
    auto start = std::chrono::high_resolution_clock::now();
    
    if (!FuzzyHashUtils::ValidateSSDeepHash(hash_a) || !FuzzyHashUtils::ValidateSSDeepHash(hash_b)) {
        return Core::Result<SimilarityResult>::Err(Core::ErrorCode::InvalidArgument,
            "Invalid ssdeep hash format");
    }
    
    // In a real implementation:
    // int score = fuzzy_compare(hash_a.c_str(), hash_b.c_str());
    
    // Placeholder: Parse and compare
    auto parse_ssdeep = [](const std::string& hash) -> std::tuple<size_t, std::string, std::string> {
        size_t colon1 = hash.find(':');
        size_t colon2 = hash.find(':', colon1 + 1);
        
        size_t block_size = std::stoull(hash.substr(0, colon1));
        std::string sig1 = hash.substr(colon1 + 1, colon2 - colon1 - 1);
        std::string sig2 = hash.substr(colon2 + 1);
        
        return {block_size, sig1, sig2};
    };
    
    auto [bs_a, sig1_a, sig2_a] = parse_ssdeep(hash_a);
    auto [bs_b, sig1_b, sig2_b] = parse_ssdeep(hash_b);
    
    // Block sizes must be compatible (same, double, or half)
    if (bs_a != bs_b && bs_a != bs_b * 2 && bs_a * 2 != bs_b) {
        SimilarityResult result;
        result.hash_a = hash_a;
        result.hash_b = hash_b;
        result.distance = 100;
        result.similarity_score = 0.0f;
        result.is_match = false;
        return Core::Result<SimilarityResult>::Ok(result);
    }
    
    // Calculate edit distance ratio
    auto edit_distance = [](const std::string& s1, const std::string& s2) -> int {
        int m = static_cast<int>(s1.length());
        int n = static_cast<int>(s2.length());
        std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));
        
        for (int i = 0; i <= m; i++) dp[i][0] = i;
        for (int j = 0; j <= n; j++) dp[0][j] = j;
        
        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                if (s1[i-1] == s2[j-1]) {
                    dp[i][j] = dp[i-1][j-1];
                } else {
                    dp[i][j] = 1 + std::min({dp[i-1][j], dp[i][j-1], dp[i-1][j-1]});
                }
            }
        }
        return dp[m][n];
    };
    
    int dist1 = edit_distance(sig1_a, sig1_b);
    int dist2 = edit_distance(sig2_a, sig2_b);
    
    int max_len = static_cast<int>(std::max({sig1_a.length(), sig1_b.length(), 
                                              sig2_a.length(), sig2_b.length()}));
    int score = 100 - (dist1 + dist2) * 100 / (2 * max_len + 1);
    score = std::max(0, std::min(100, score));
    
    SimilarityResult result;
    result.hash_a = hash_a;
    result.hash_b = hash_b;
    result.distance = 100 - score;
    result.similarity_score = NormalizeSSDeepScore(score);
    result.is_match = score >= config_.ssdeep_threshold;
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double, std::micro>(end - start).count();
    
    stats_.comparisons_made++;
    stats_.avg_comparison_time_us = (stats_.avg_comparison_time_us * (stats_.comparisons_made - 1) + elapsed) 
                                    / stats_.comparisons_made;
    if (result.is_match) {
        stats_.matches_found++;
    }
    
    return Core::Result<SimilarityResult>::Ok(result);
}

Core::Result<SimilarityResult> FuzzyHasher::CompareCombined(
    const std::string& tlsh_a,
    const std::string& ssdeep_a,
    const std::string& tlsh_b,
    const std::string& ssdeep_b) {
    
    auto tlsh_result = CompareTLSH(tlsh_a, tlsh_b);
    auto ssdeep_result = CompareSSDeep(ssdeep_a, ssdeep_b);
    
    if (!tlsh_result && !ssdeep_result) {
        return Core::Result<SimilarityResult>::Err(Core::ErrorCode::InternalError,
            "Both hash comparisons failed");
    }
    
    float tlsh_score = tlsh_result ? tlsh_result.Value().similarity_score : 0.0f;
    float ssdeep_score = ssdeep_result ? ssdeep_result.Value().similarity_score : 0.0f;
    
    // Weighted combination
    float combined_score;
    if (tlsh_result && ssdeep_result) {
        combined_score = tlsh_score * config_.tlsh_weight + ssdeep_score * config_.ssdeep_weight;
    } else if (tlsh_result) {
        combined_score = tlsh_score;
    } else {
        combined_score = ssdeep_score;
    }
    
    SimilarityResult result;
    result.hash_a = tlsh_a + "|" + ssdeep_a;
    result.hash_b = tlsh_b + "|" + ssdeep_b;
    result.similarity_score = combined_score;
    result.distance = static_cast<int>((1.0f - combined_score) * 100);
    result.is_match = combined_score >= config_.match_threshold;
    
    return Core::Result<SimilarityResult>::Ok(result);
}

Core::Result<std::vector<SimilarityResult>> FuzzyHasher::SearchSimilar(
    const std::string& hash,
    FuzzyHashType type,
    size_t max_results) {
    
    std::vector<SimilarityResult> results;
    
    for (const auto& [id, sig] : signatures_) {
        const std::string& sig_hash = (type == FuzzyHashType::TLSH) ? 
            sig.tlsh_hash : sig.ssdeep_hash;
        
        if (sig_hash.empty()) continue;
        
        auto cmp_result = (type == FuzzyHashType::TLSH) ?
            CompareTLSH(hash, sig_hash) : CompareSSDeep(hash, sig_hash);
        
        if (cmp_result && cmp_result.Value().similarity_score > 0.3f) {
            auto result = cmp_result.Value();
            result.family_name = sig.family;
            result.variants.push_back(sig.name);
            results.push_back(result);
        }
    }
    
    // Sort by similarity (descending)
    std::sort(results.begin(), results.end(), 
        [](const SimilarityResult& a, const SimilarityResult& b) {
            return a.similarity_score > b.similarity_score;
        });
    
    if (results.size() > max_results) {
        results.resize(max_results);
    }
    
    return Core::Result<std::vector<SimilarityResult>>::Ok(results);
}

Core::Result<std::vector<SimilarityResult>> FuzzyHasher::FindSimilarFiles(
    const std::string& filepath,
    const std::string& directory,
    FuzzyHashType type,
    bool recursive) {
    
    // Compute hash of reference file
    auto ref_hash = (type == FuzzyHashType::TLSH) ?
        ComputeTLSHFromFile(filepath) : ComputeSSDeepFromFile(filepath);
    
    if (!ref_hash) {
        return Core::Result<std::vector<SimilarityResult>>::Err(ref_hash.GetError());
    }
    
    std::vector<SimilarityResult> results;
    
    auto iterator = recursive ? 
        fs::recursive_directory_iterator(directory) :
        fs::recursive_directory_iterator(directory, fs::directory_options::none);
    
    for (const auto& entry : fs::recursive_directory_iterator(directory)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().string() == filepath) continue;
        
        auto target_hash = (type == FuzzyHashType::TLSH) ?
            ComputeTLSHFromFile(entry.path().string()) : 
            ComputeSSDeepFromFile(entry.path().string());
        
        if (!target_hash) continue;
        
        auto cmp_result = (type == FuzzyHashType::TLSH) ?
            CompareTLSH(ref_hash.Value().hash, target_hash.Value().hash) :
            CompareSSDeep(ref_hash.Value().hash, target_hash.Value().hash);
        
        if (cmp_result && cmp_result.Value().is_match) {
            auto result = cmp_result.Value();
            result.hash_b = entry.path().string();
            results.push_back(result);
        }
    }
    
    std::sort(results.begin(), results.end(),
        [](const SimilarityResult& a, const SimilarityResult& b) {
            return a.similarity_score > b.similarity_score;
        });
    
    return Core::Result<std::vector<SimilarityResult>>::Ok(results);
}

// ==================== Database Management ====================

Core::Result<void> FuzzyHasher::LoadSignatureDatabase(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return Core::Result<void>::Err(Core::ErrorCode::FileNotFound,
            "Could not open signature database: " + filepath);
    }
    
    // In a real implementation, this would parse JSON/binary format
    // For now, just clear and mark as loaded
    signatures_.clear();
    
    // Placeholder: Add some example signatures
    CheatSignature sig1;
    sig1.id = "sig_001";
    sig1.name = "SpeedHack_Generic";
    sig1.family = "SpeedHack";
    sig1.tlsh_hash = "T1A1B2C3D4E5F6789012345678901234567890123456789012345678901234567890";
    sig1.ssdeep_hash = "192:ABCDEFGHIJ:KLMNOPQRST";
    sig1.description = "Generic speed hack signature";
    sig1.category = "timing";
    signatures_[sig1.id] = sig1;
    
    return Core::Result<void>::Ok();
}

Core::Result<void> FuzzyHasher::SaveSignatureDatabase(const std::string& filepath) {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        return Core::Result<void>::Err(Core::ErrorCode::IOError,
            "Could not open file for writing: " + filepath);
    }
    
    // In a real implementation, this would serialize to JSON/binary format
    file << "# Sentinel Signature Database\n";
    file << "# Total signatures: " << signatures_.size() << "\n";
    
    for (const auto& [id, sig] : signatures_) {
        file << "\n[" << id << "]\n";
        file << "name=" << sig.name << "\n";
        file << "family=" << sig.family << "\n";
        file << "tlsh=" << sig.tlsh_hash << "\n";
        file << "ssdeep=" << sig.ssdeep_hash << "\n";
    }
    
    return Core::Result<void>::Ok();
}

Core::Result<void> FuzzyHasher::AddSignature(const CheatSignature& signature) {
    if (signatures_.count(signature.id) > 0) {
        return Core::Result<void>::Err(Core::ErrorCode::AlreadyExists,
            "Signature with ID already exists: " + signature.id);
    }
    
    signatures_[signature.id] = signature;
    return Core::Result<void>::Ok();
}

Core::Result<void> FuzzyHasher::RemoveSignature(const std::string& signature_id) {
    auto it = signatures_.find(signature_id);
    if (it == signatures_.end()) {
        return Core::Result<void>::Err(Core::ErrorCode::NotFound,
            "Signature not found: " + signature_id);
    }
    
    signatures_.erase(it);
    return Core::Result<void>::Ok();
}

Core::Result<void> FuzzyHasher::UpdateSignature(const CheatSignature& signature) {
    auto it = signatures_.find(signature.id);
    if (it == signatures_.end()) {
        return Core::Result<void>::Err(Core::ErrorCode::NotFound,
            "Signature not found: " + signature.id);
    }
    
    it->second = signature;
    return Core::Result<void>::Ok();
}

std::optional<CheatSignature> FuzzyHasher::GetSignature(const std::string& signature_id) const {
    auto it = signatures_.find(signature_id);
    if (it != signatures_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<CheatSignature> FuzzyHasher::GetSignaturesByFamily(const std::string& family_name) const {
    std::vector<CheatSignature> results;
    for (const auto& [id, sig] : signatures_) {
        if (sig.family == family_name) {
            results.push_back(sig);
        }
    }
    return results;
}

std::vector<CheatSignature> FuzzyHasher::SearchSignatures(const std::string& query) const {
    std::vector<CheatSignature> results;
    std::string query_lower = query;
    std::transform(query_lower.begin(), query_lower.end(), query_lower.begin(), ::tolower);
    
    for (const auto& [id, sig] : signatures_) {
        std::string name_lower = sig.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        
        if (name_lower.find(query_lower) != std::string::npos) {
            results.push_back(sig);
            continue;
        }
        
        for (const auto& tag : sig.tags) {
            std::string tag_lower = tag;
            std::transform(tag_lower.begin(), tag_lower.end(), tag_lower.begin(), ::tolower);
            if (tag_lower.find(query_lower) != std::string::npos) {
                results.push_back(sig);
                break;
            }
        }
    }
    
    return results;
}

size_t FuzzyHasher::GetSignatureCount() const {
    return signatures_.size();
}

std::vector<std::string> FuzzyHasher::GetFamilyNames() const {
    std::vector<std::string> families;
    std::unordered_map<std::string, bool> seen;
    
    for (const auto& [id, sig] : signatures_) {
        if (!seen[sig.family]) {
            families.push_back(sig.family);
            seen[sig.family] = true;
        }
    }
    
    std::sort(families.begin(), families.end());
    return families;
}

// ==================== Classification ====================

Core::Result<FuzzyHash> FuzzyHasher::ClassifyFile(const std::string& filepath) {
    auto hashes = ComputeBothHashes(filepath);
    if (!hashes) {
        return Core::Result<FuzzyHash>::Err(hashes.GetError());
    }
    
    const auto& [tlsh_hash, ssdeep_hash] = hashes.Value();
    
    // Search for similar signatures
    float best_score = 0.0f;
    std::string best_family;
    
    for (const auto& [id, sig] : signatures_) {
        auto result = CompareCombined(tlsh_hash.hash, ssdeep_hash.hash,
                                      sig.tlsh_hash, sig.ssdeep_hash);
        
        if (result && result.Value().similarity_score > best_score) {
            best_score = result.Value().similarity_score;
            best_family = sig.family;
        }
    }
    
    FuzzyHash classification = tlsh_hash;
    classification.type = FuzzyHashType::COMBINED;
    classification.family_name = best_family;
    classification.confidence = best_score;
    
    stats_.classifications_performed++;
    
    return Core::Result<FuzzyHash>::Ok(classification);
}

Core::Result<std::unordered_map<std::string, FuzzyHash>> FuzzyHasher::ClassifyFilesBatch(
    const std::vector<std::string>& filepaths,
    BatchProgressCallback progress_callback) {
    
    std::unordered_map<std::string, FuzzyHash> results;
    
    for (size_t i = 0; i < filepaths.size(); i++) {
        auto result = ClassifyFile(filepaths[i]);
        if (result) {
            results[filepaths[i]] = result.Value();
        }
        
        if (progress_callback) {
            progress_callback(i + 1, filepaths.size(), filepaths[i]);
        }
    }
    
    return Core::Result<std::unordered_map<std::string, FuzzyHash>>::Ok(std::move(results));
}

// ==================== Private Methods ====================

Core::Result<Core::ByteBuffer> FuzzyHasher::ReadFile(const std::string& filepath) {
    if (!fs::exists(filepath)) {
        return Core::Result<Core::ByteBuffer>::Err(Core::ErrorCode::FileNotFound,
            "File not found: " + filepath);
    }
    
    size_t file_size = fs::file_size(filepath);
    if (file_size > config_.max_file_size) {
        return Core::Result<Core::ByteBuffer>::Err(Core::ErrorCode::InvalidArgument,
            "File exceeds maximum size limit");
    }
    
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        return Core::Result<Core::ByteBuffer>::Err(Core::ErrorCode::IOError,
            "Could not open file: " + filepath);
    }
    
    Core::ByteBuffer data(file_size);
    file.read(reinterpret_cast<char*>(data.data()), file_size);
    
    return Core::Result<Core::ByteBuffer>::Ok(std::move(data));
}

float FuzzyHasher::NormalizeTLSHDistance(int distance) const {
    // TLSH distance: 0 = identical, higher = more different
    // Normalize to 0.0 (different) - 1.0 (identical)
    if (distance <= 0) return 1.0f;
    if (distance >= 300) return 0.0f;
    return 1.0f - (distance / 300.0f);
}

float FuzzyHasher::NormalizeSSDeepScore(int score) const {
    // ssdeep score: 0 = different, 100 = identical
    return score / 100.0f;
}

std::string FuzzyHasher::GenerateSignatureId() const {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << "sig_";
    for (int i = 0; i < 16; i++) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

void FuzzyHasher::ResetStatistics() {
    stats_ = Statistics{};
}

// ==================== Utility Functions ====================

namespace FuzzyHashUtils {

float TLSHDistanceToSimilarity(int distance) {
    if (distance <= 0) return 100.0f;
    if (distance >= 300) return 0.0f;
    return 100.0f * (1.0f - distance / 300.0f);
}

std::string GetSimilarityDescription(float similarity) {
    if (similarity >= 0.95f) return "Exact match";
    if (similarity >= 0.85f) return "Very similar";
    if (similarity >= 0.70f) return "Similar";
    if (similarity >= 0.50f) return "Somewhat similar";
    if (similarity >= 0.30f) return "Low similarity";
    return "No match";
}

bool ValidateTLSHHash(const std::string& hash) {
    if (hash.length() < 70) return false;
    if (hash.substr(0, 2) != "T1") return false;
    
    for (size_t i = 2; i < hash.length(); i++) {
        char c = hash[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool ValidateSSDeepHash(const std::string& hash) {
    // Format: blocksize:sig1:sig2
    size_t colon1 = hash.find(':');
    if (colon1 == std::string::npos) return false;
    
    size_t colon2 = hash.find(':', colon1 + 1);
    if (colon2 == std::string::npos) return false;
    
    // Validate block size is numeric
    std::string block_size = hash.substr(0, colon1);
    for (char c : block_size) {
        if (!isdigit(c)) return false;
    }
    
    return true;
}

std::optional<FuzzyHashType> ParseHashType(const std::string& type_str) {
    std::string lower = type_str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower == "tlsh") return FuzzyHashType::TLSH;
    if (lower == "ssdeep") return FuzzyHashType::SSDEEP;
    if (lower == "combined") return FuzzyHashType::COMBINED;
    
    return std::nullopt;
}

std::string HashTypeToString(FuzzyHashType type) {
    switch (type) {
        case FuzzyHashType::TLSH: return "TLSH";
        case FuzzyHashType::SSDEEP: return "ssdeep";
        case FuzzyHashType::COMBINED: return "Combined";
    }
    return "Unknown";
}

} // namespace FuzzyHashUtils

} // namespace Sentinel::Cortex
