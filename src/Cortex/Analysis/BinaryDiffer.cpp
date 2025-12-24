/**
 * BinaryDiffer.cpp
 * Sentinel Cortex - Binary Diffing and Comparison Engine
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include "BinaryDiffer.hpp"
#include "Disassembler.hpp"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <chrono>

namespace Sentinel::Cortex {

// ============================================================================
// BinaryDiffer::Impl
// ============================================================================

struct BinaryDiffer::Impl {
    BinaryDifferConfig config;
    
    explicit Impl(const BinaryDifferConfig& cfg) : config(cfg) {}
};

// ============================================================================
// BinaryDiffer Implementation
// ============================================================================

BinaryDiffer::BinaryDiffer(const BinaryDifferConfig& config)
    : impl_(std::make_unique<Impl>(config))
    , config_(config)
    , stats_{} {}

BinaryDiffer::~BinaryDiffer() = default;

BinaryDiffer::BinaryDiffer(BinaryDiffer&&) noexcept = default;
BinaryDiffer& BinaryDiffer::operator=(BinaryDiffer&&) noexcept = default;

Core::Result<void> BinaryDiffer::Initialize() {
    return Core::Result<void>::Ok();
}

void BinaryDiffer::Shutdown() {
    // Cleanup if needed
}

Core::Result<BinaryDiffResult> BinaryDiffer::DiffBinaries(
    const std::string& source_path,
    const std::string& target_path,
    DiffProgressCallback progress
) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Read files
    std::ifstream source_file(source_path, std::ios::binary);
    std::ifstream target_file(target_path, std::ios::binary);
    
    if (!source_file || !target_file) {
        return Core::Result<BinaryDiffResult>::Err(
            Core::ErrorCode::FileNotFound, "Failed to open binary files");
    }
    
    Core::ByteBuffer source_data(
        (std::istreambuf_iterator<char>(source_file)),
        std::istreambuf_iterator<char>());
    Core::ByteBuffer target_data(
        (std::istreambuf_iterator<char>(target_file)),
        std::istreambuf_iterator<char>());
    
    auto result = DiffBuffers(source_data, target_data, progress);
    
    if (result.isSuccess()) {
        auto& diff = result.value();
        diff.source_path = source_path;
        diff.target_path = target_path;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    stats_.diff_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    return result;
}

Core::Result<BinaryDiffResult> BinaryDiffer::DiffBuffers(
    const Core::ByteBuffer& source,
    const Core::ByteBuffer& target,
    DiffProgressCallback progress
) {
    BinaryDiffResult result;
    
    // Compute byte diffs
    if (config_.include_byte_diffs || source.size() <= config_.max_diff_size) {
        auto byte_diffs_result = ComputeByteDiffs(source, target);
        if (byte_diffs_result.isSuccess()) {
            result.byte_diffs = byte_diffs_result.value();
            result.total_bytes_changed = result.byte_diffs.size();
        }
    }
    
    // Calculate overall similarity
    size_t common_size = std::min(source.size(), target.size());
    size_t identical_bytes = 0;
    
    for (size_t i = 0; i < common_size; ++i) {
        if (source[i] == target[i]) {
            identical_bytes++;
        }
    }
    
    result.overall_similarity = common_size > 0 ?
        static_cast<float>(identical_bytes) / static_cast<float>(common_size) : 0.0f;
    
    stats_.bytes_compared = common_size;
    
    return Core::Result<BinaryDiffResult>::Ok(std::move(result));
}

Core::Result<float> BinaryDiffer::QuickSimilarity(
    const std::string& source_path,
    const std::string& target_path
) {
    // Simple hash-based similarity check
    std::ifstream source_file(source_path, std::ios::binary);
    std::ifstream target_file(target_path, std::ios::binary);
    
    if (!source_file || !target_file) {
        return Core::Result<float>::Err(
            Core::ErrorCode::FileNotFound, "Failed to open files");
    }
    
    Core::ByteBuffer source_data(
        (std::istreambuf_iterator<char>(source_file)),
        std::istreambuf_iterator<char>());
    Core::ByteBuffer target_data(
        (std::istreambuf_iterator<char>(target_file)),
        std::istreambuf_iterator<char>());
    
    float similarity = ComputeInstructionSimilarity(source_data, target_data);
    
    return Core::Result<float>::Ok(similarity);
}

Core::Result<std::vector<FunctionMatch>> BinaryDiffer::MatchFunctions(
    const std::string& source_path,
    const std::string& target_path
) {
    std::vector<FunctionMatch> matches;
    // Placeholder implementation
    return Core::Result<std::vector<FunctionMatch>>::Ok(std::move(matches));
}

std::optional<FunctionMatch> BinaryDiffer::FindMatchingFunction(
    const FunctionDiff& source_func,
    const std::string& target_path
) {
    // Placeholder implementation
    return std::nullopt;
}

Core::Result<Core::ByteBuffer> BinaryDiffer::GeneratePatch(
    const BinaryDiffResult& diff
) {
    Core::ByteBuffer patch_data;
    
    // Simple IPS-like format
    // Header: "PATCH"
    patch_data.insert(patch_data.end(), {'P', 'A', 'T', 'C', 'H'});
    
    // Write byte diffs
    for (const auto& byte_diff : diff.byte_diffs) {
        if (byte_diff.type == DiffType::Modified) {
            // Offset (3 bytes)
            patch_data.push_back(static_cast<uint8_t>(byte_diff.offset >> 16));
            patch_data.push_back(static_cast<uint8_t>(byte_diff.offset >> 8));
            patch_data.push_back(static_cast<uint8_t>(byte_diff.offset));
            // Length (2 bytes)
            patch_data.push_back(0);
            patch_data.push_back(1);
            // Data
            patch_data.push_back(byte_diff.target_byte);
        }
    }
    
    // EOF marker
    patch_data.insert(patch_data.end(), {'E', 'O', 'F'});
    
    return Core::Result<Core::ByteBuffer>::Ok(std::move(patch_data));
}

std::vector<std::string> BinaryDiffer::GeneratePatchInstructions(
    const BinaryDiffResult& diff
) {
    std::vector<std::string> instructions;
    
    for (const auto& byte_diff : diff.byte_diffs) {
        std::ostringstream oss;
        oss << "PATCH 0x" << std::hex << byte_diff.offset 
            << ": 0x" << std::setw(2) << std::setfill('0') 
            << static_cast<int>(byte_diff.source_byte)
            << " -> 0x" << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte_diff.target_byte);
        instructions.push_back(oss.str());
    }
    
    return instructions;
}

Core::Result<void> BinaryDiffer::ApplyPatch(
    const std::string& binary_path,
    const Core::ByteBuffer& patch_data
) {
    // Placeholder implementation
    return Core::Result<void>::Ok();
}

Core::Result<void> BinaryDiffer::ExportHTML(
    const BinaryDiffResult& diff,
    const std::string& output_path
) {
    std::ofstream out(output_path);
    if (!out) {
        return Core::Result<void>::Err(
            Core::ErrorCode::IOError, "Failed to create output file");
    }
    
    out << "<html><head><title>Binary Diff Report</title></head><body>\n";
    out << "<h1>Binary Diff Report</h1>\n";
    out << "<p>Source: " << diff.source_path << "</p>\n";
    out << "<p>Target: " << diff.target_path << "</p>\n";
    out << "<p>Similarity: " << (diff.overall_similarity * 100.0f) << "%</p>\n";
    out << "<p>Bytes Changed: " << diff.total_bytes_changed << "</p>\n";
    out << "</body></html>\n";
    
    return Core::Result<void>::Ok();
}

Core::Result<void> BinaryDiffer::ExportJSON(
    const BinaryDiffResult& diff,
    const std::string& output_path
) {
    std::ofstream out(output_path);
    if (!out) {
        return Core::Result<void>::Err(
            Core::ErrorCode::IOError, "Failed to create output file");
    }
    
    out << "{\n";
    out << "  \"source\": \"" << diff.source_path << "\",\n";
    out << "  \"target\": \"" << diff.target_path << "\",\n";
    out << "  \"similarity\": " << diff.overall_similarity << ",\n";
    out << "  \"bytes_changed\": " << diff.total_bytes_changed << "\n";
    out << "}\n";
    
    return Core::Result<void>::Ok();
}

Core::Result<void> BinaryDiffer::ExportBinDiff(
    const BinaryDiffResult& diff,
    const std::string& output_path
) {
    // Placeholder for BinDiff format export
    return Core::Result<void>::Ok();
}

// ============================================================================
// Private Methods
// ============================================================================

Core::Result<std::vector<ByteDiff>> BinaryDiffer::ComputeByteDiffs(
    const Core::ByteBuffer& source,
    const Core::ByteBuffer& target
) {
    std::vector<ByteDiff> diffs;
    
    size_t common_size = std::min(source.size(), target.size());
    
    for (size_t i = 0; i < common_size; ++i) {
        if (source[i] != target[i]) {
            ByteDiff diff;
            diff.offset = i;
            diff.source_byte = source[i];
            diff.target_byte = target[i];
            diff.type = DiffType::Modified;
            diffs.push_back(diff);
        }
    }
    
    return Core::Result<std::vector<ByteDiff>>::Ok(std::move(diffs));
}

Core::Result<std::vector<FunctionDiff>> BinaryDiffer::ComputeFunctionDiffs(
    const std::string& source_path,
    const std::string& target_path
) {
    std::vector<FunctionDiff> diffs;
    // Placeholder implementation
    return Core::Result<std::vector<FunctionDiff>>::Ok(std::move(diffs));
}

float BinaryDiffer::ComputeInstructionSimilarity(
    const std::vector<uint8_t>& source,
    const std::vector<uint8_t>& target
) {
    if (source.empty() && target.empty()) return 1.0f;
    if (source.empty() || target.empty()) return 0.0f;
    
    size_t common_size = std::min(source.size(), target.size());
    size_t identical = 0;
    
    for (size_t i = 0; i < common_size; ++i) {
        if (source[i] == target[i]) {
            identical++;
        }
    }
    
    return static_cast<float>(identical) / static_cast<float>(std::max(source.size(), target.size()));
}

float BinaryDiffer::ComputeBlockSimilarity(const BasicBlockDiff& block) {
    return block.similarity;
}

float BinaryDiffer::ComputeFunctionSimilarity(const FunctionDiff& func) {
    return func.similarity;
}

std::string BinaryDiffer::ComputeFunctionHash(
    const std::vector<uint8_t>& instructions
) {
    uint64_t hash = 0;
    for (uint8_t byte : instructions) {
        hash = hash * 31 + byte;
    }
    
    std::ostringstream oss;
    oss << std::hex << hash;
    return oss.str();
}

std::vector<std::string> BinaryDiffer::ExtractStrings(
    const Core::ByteBuffer& data
) {
    std::vector<std::string> strings;
    std::string current;
    
    for (uint8_t byte : data) {
        if (byte >= 32 && byte <= 126) {
            current += static_cast<char>(byte);
        } else {
            if (current.length() >= 4) {
                strings.push_back(current);
            }
            current.clear();
        }
    }
    
    return strings;
}

// ============================================================================
// Utility Functions
// ============================================================================

namespace BinaryDiffUtils {

std::string DiffTypeToString(DiffType type) {
    switch (type) {
        case DiffType::Added: return "Added";
        case DiffType::Removed: return "Removed";
        case DiffType::Modified: return "Modified";
        case DiffType::Moved: return "Moved";
        case DiffType::Identical: return "Identical";
    }
    return "Unknown";
}

std::string GranularityToString(DiffGranularity granularity) {
    switch (granularity) {
        case DiffGranularity::Byte: return "Byte";
        case DiffGranularity::Instruction: return "Instruction";
        case DiffGranularity::BasicBlock: return "BasicBlock";
        case DiffGranularity::Function: return "Function";
        case DiffGranularity::Section: return "Section";
    }
    return "Unknown";
}

int LevenshteinDistance(
    const std::vector<uint8_t>& a,
    const std::vector<uint8_t>& b
) {
    int m = static_cast<int>(a.size());
    int n = static_cast<int>(b.size());
    
    std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));
    
    for (int i = 0; i <= m; ++i) dp[i][0] = i;
    for (int j = 0; j <= n; ++j) dp[0][j] = j;
    
    for (int i = 1; i <= m; ++i) {
        for (int j = 1; j <= n; ++j) {
            if (a[i-1] == b[j-1]) {
                dp[i][j] = dp[i-1][j-1];
            } else {
                dp[i][j] = 1 + std::min({dp[i-1][j], dp[i][j-1], dp[i-1][j-1]});
            }
        }
    }
    
    return dp[m][n];
}

std::vector<uint8_t> LongestCommonSubsequence(
    const std::vector<uint8_t>& a,
    const std::vector<uint8_t>& b
) {
    // Simplified LCS implementation
    std::vector<uint8_t> lcs;
    size_t min_len = std::min(a.size(), b.size());
    
    for (size_t i = 0; i < min_len; ++i) {
        if (a[i] == b[i]) {
            lcs.push_back(a[i]);
        }
    }
    
    return lcs;
}

std::string FormatByteDiff(const ByteDiff& diff) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(8) << std::setfill('0') << diff.offset
        << ": 0x" << std::setw(2) << static_cast<int>(diff.source_byte)
        << " -> 0x" << std::setw(2) << static_cast<int>(diff.target_byte)
        << " [" << DiffTypeToString(diff.type) << "]";
    return oss.str();
}

std::string FormatInstructionDiff(const InstructionDiff& diff) {
    std::ostringstream oss;
    oss << "0x" << std::hex << diff.source_address
        << ": " << diff.source_mnemonic << " " << diff.source_operands
        << " -> " << diff.target_mnemonic << " " << diff.target_operands
        << " (similarity: " << std::fixed << std::setprecision(2) 
        << (diff.similarity * 100.0f) << "%)";
    return oss.str();
}

std::string GenerateUnifiedDiff(
    const BinaryDiffResult& result,
    int context_lines
) {
    std::ostringstream oss;
    oss << "--- " << result.source_path << "\n";
    oss << "+++ " << result.target_path << "\n";
    oss << "@@ Similarity: " << (result.overall_similarity * 100.0f) << "% @@\n";
    
    for (const auto& diff : result.byte_diffs) {
        oss << FormatByteDiff(diff) << "\n";
    }
    
    return oss.str();
}

} // namespace BinaryDiffUtils

} // namespace Sentinel::Cortex
