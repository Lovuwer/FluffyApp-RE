/**
 * @file PatternScanner.hpp
 * @brief IDA-style pattern scanning for memory search operations
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * This module provides IDA-style pattern scanning with wildcards for
 * efficient memory searching. Integrates with SafeMemory for crash-safe operation.
 */

#pragma once

#ifndef SENTINEL_CORE_PATTERN_SCANNER_HPP
#define SENTINEL_CORE_PATTERN_SCANNER_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <string>
#include <vector>
#include <optional>

namespace Sentinel {
namespace Core {
namespace Memory {

/**
 * @brief IDA-style pattern scanner
 * 
 * Supports patterns like:
 * - "48 8B ? ? 90" (? = wildcard)
 * - "48 8B ?? ?? 90" (?? = wildcard byte)
 * - "48 8B 5C 24 10" (exact match)
 * 
 * Integrates with SafeMemory for crash-proof scanning.
 */
class PatternScanner {
public:
    /**
     * @brief Represents a compiled pattern for efficient scanning
     */
    struct CompiledPattern {
        ByteBuffer bytes;          ///< Pattern bytes
        std::vector<bool> mask;    ///< Mask (true = must match, false = wildcard)
        std::string original;      ///< Original pattern string
        
        /// Check if pattern is valid
        [[nodiscard]] bool isValid() const noexcept {
            return !bytes.empty() && bytes.size() == mask.size();
        }
        
        /// Get pattern size
        [[nodiscard]] size_t size() const noexcept {
            return bytes.size();
        }
    };
    
    /**
     * @brief Scan result
     */
    struct ScanResult {
        Address address;           ///< Address where pattern was found
        ByteBuffer matchedBytes;   ///< Actual bytes that matched
        std::string regionName;    ///< Region/module name if available
    };
    
    /**
     * @brief Compile an IDA-style pattern string
     * @param pattern Pattern string (e.g., "48 8B ? ? 90")
     * @return Compiled pattern or error
     * 
     * @example
     * auto compiled = PatternScanner::compilePattern("48 8B ? ? 90");
     */
    [[nodiscard]] static Result<CompiledPattern> compilePattern(const std::string& pattern);
    
    /**
     * @brief Scan memory range for pattern
     * @param baseAddress Start address
     * @param size Size of range
     * @param pattern Compiled pattern
     * @param maxResults Maximum results to return (0 = unlimited)
     * @return Vector of scan results or error
     */
    [[nodiscard]] static Result<std::vector<ScanResult>> scan(
        Address baseAddress,
        size_t size,
        const CompiledPattern& pattern,
        size_t maxResults = 0
    );
    
    /**
     * @brief Find first occurrence of pattern
     * @param baseAddress Start address
     * @param size Size of range
     * @param pattern Compiled pattern
     * @return First match or nullopt if not found
     */
    [[nodiscard]] static Result<std::optional<ScanResult>> findFirst(
        Address baseAddress,
        size_t size,
        const CompiledPattern& pattern
    );
    
    /**
     * @brief Scan with pattern string (convenience method)
     * @param baseAddress Start address
     * @param size Size of range
     * @param patternString Pattern string
     * @param maxResults Maximum results
     * @return Vector of scan results or error
     */
    [[nodiscard]] static Result<std::vector<ScanResult>> scanWithString(
        Address baseAddress,
        size_t size,
        const std::string& patternString,
        size_t maxResults = 0
    );

private:
    /**
     * @brief Check if pattern matches at specific location
     * @param data Pointer to data
     * @param dataSize Size of data buffer
     * @param pattern Pattern to match
     * @return true if matches
     */
    static bool matchesAt(
        const Byte* data,
        size_t dataSize,
        const CompiledPattern& pattern
    ) noexcept;
};

} // namespace Memory
} // namespace Core
} // namespace Sentinel

#endif // SENTINEL_CORE_PATTERN_SCANNER_HPP
