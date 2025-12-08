/**
 * @file MemoryScanner.hpp
 * @brief High-performance memory scanning and pattern matching
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This module provides fast memory scanning capabilities with support for
 * wildcard patterns, SIMD acceleration, and multi-threaded scanning.
 */

#pragma once

#ifndef SENTINEL_CORE_MEMORY_SCANNER_HPP
#define SENTINEL_CORE_MEMORY_SCANNER_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <mutex>
#include <atomic>

namespace Sentinel::Memory {

// ============================================================================
// Pattern Definition
// ============================================================================

/**
 * @brief Represents a byte pattern with optional wildcards
 * 
 * Patterns can be specified in various formats:
 * - Hex string: "48 89 5C 24 ?? 48 89 74"
 * - IDA-style: "48 89 5C 24 ? 48 89 74"
 * - Byte array with mask
 * 
 * @example
 * ```cpp
 * // Create pattern from hex string (? = wildcard)
 * Pattern pattern = Pattern::fromString("48 89 5C 24 ?? 48 89 74 24");
 * 
 * // Create pattern from bytes with mask
 * std::vector<uint8_t> bytes = {0x48, 0x89, 0x5C, 0x24, 0x00};
 * std::string mask = "xxxx?";
 * Pattern pattern2(bytes, mask);
 * ```
 */
class Pattern {
public:
    /// Default constructor creates empty pattern
    Pattern() = default;
    
    /**
     * @brief Construct pattern from bytes and mask
     * @param bytes The byte values to match
     * @param mask The mask string ('x' = match, '?' = wildcard)
     */
    Pattern(const ByteBuffer& bytes, const std::string& mask);
    
    /**
     * @brief Construct pattern from bytes and mask
     * @param bytes The byte values to match
     * @param mask The mask (true = match, false = wildcard)
     */
    Pattern(const ByteBuffer& bytes, const std::vector<bool>& mask);
    
    /**
     * @brief Create pattern from hex string
     * @param hexPattern Hex string with optional wildcards (?, ??)
     * @return Pattern object
     * 
     * @example "48 89 5C 24 ?? 48 89 74 24 10"
     */
    [[nodiscard]] static Result<Pattern> fromString(const std::string& hexPattern);
    
    /**
     * @brief Create pattern from IDA-style signature
     * @param idaSig IDA signature string
     * @return Pattern object
     * 
     * @example "48 89 5C 24 ? 48 89 74 24 10"
     */
    [[nodiscard]] static Result<Pattern> fromIDA(const std::string& idaSig);
    
    /// Check if pattern is valid (non-empty)
    [[nodiscard]] bool isValid() const noexcept { return !m_bytes.empty(); }
    
    /// Get pattern size in bytes
    [[nodiscard]] size_t size() const noexcept { return m_bytes.size(); }
    
    /// Get the byte values
    [[nodiscard]] const ByteBuffer& bytes() const noexcept { return m_bytes; }
    
    /// Get the mask
    [[nodiscard]] const std::vector<bool>& mask() const noexcept { return m_mask; }
    
    /**
     * @brief Check if pattern matches at given address
     * @param data Pointer to data to check
     * @param dataSize Size of data buffer
     * @return true if pattern matches
     */
    [[nodiscard]] bool matches(const Byte* data, size_t dataSize) const noexcept;
    
    /// Convert pattern to string representation
    [[nodiscard]] std::string toString() const;

private:
    ByteBuffer m_bytes;        ///< Byte values
    std::vector<bool> m_mask;  ///< Mask (true = must match)
    
    // Precomputed for SIMD optimization
    ByteBuffer m_simdBytes;
    ByteBuffer m_simdMask;
    bool m_canUseSIMD = false;
    
    void prepareSIMD();
};

// ============================================================================
// Scan Result
// ============================================================================

/**
 * @brief Result of a memory scan operation
 */
struct ScanResult {
    Address address;           ///< Address where pattern was found
    std::string moduleName;    ///< Module containing the match
    RVA rva;                   ///< Relative virtual address within module
    ByteBuffer matchedBytes;   ///< The actual bytes that matched
    
    /// Compare by address
    bool operator<(const ScanResult& other) const noexcept {
        return address < other.address;
    }
};

/// Collection of scan results
using ScanResults = std::vector<ScanResult>;

// ============================================================================
// Scan Options
// ============================================================================

/**
 * @brief Configuration options for memory scanning
 */
struct ScanOptions {
    /// Scan only executable regions
    bool executableOnly = false;
    
    /// Scan only writable regions
    bool writableOnly = false;
    
    /// Include only specific modules (empty = all)
    std::vector<std::string> moduleFilter;
    
    /// Exclude these modules
    std::vector<std::string> moduleExclude;
    
    /// Maximum number of results (0 = unlimited)
    size_t maxResults = 0;
    
    /// Alignment for pattern matching (1 = any alignment)
    size_t alignment = 1;
    
    /// Enable SIMD acceleration
    bool useSIMD = true;
    
    /// Enable multi-threaded scanning
    bool useMultiThread = true;
    
    /// Number of threads (0 = auto-detect)
    size_t threadCount = 0;
    
    /// Progress callback
    ProgressCallback progressCallback;
    
    /// Cancellation token
    std::atomic<bool>* cancellationToken = nullptr;
};

// ============================================================================
// Memory Scanner Class
// ============================================================================

/**
 * @brief High-performance memory scanner
 * 
 * Provides efficient memory pattern scanning with support for:
 * - Wildcard patterns
 * - SIMD acceleration (SSE4.2/AVX2)
 * - Multi-threaded scanning
 * - Module filtering
 * - Progress reporting
 * 
 * @example
 * ```cpp
 * MemoryScanner scanner;
 * 
 * // Create pattern
 * auto pattern = Pattern::fromString("48 89 5C 24 ?? 48 89 74 24").value();
 * 
 * // Configure scan
 * ScanOptions options;
 * options.executableOnly = true;
 * options.moduleFilter = {"game.exe"};
 * 
 * // Perform scan
 * auto results = scanner.scan(pattern, options);
 * if (results.isSuccess()) {
 *     for (const auto& result : results.value()) {
 *         std::cout << "Found at: 0x" << std::hex << result.address << std::endl;
 *     }
 * }
 * ```
 */
class MemoryScanner {
public:
    /**
     * @brief Construct scanner for current process
     */
    MemoryScanner();
    
    /**
     * @brief Construct scanner for specific process
     * @param processId Target process ID
     */
    explicit MemoryScanner(ProcessId processId);
    
    /// Destructor
    ~MemoryScanner();
    
    // Non-copyable
    MemoryScanner(const MemoryScanner&) = delete;
    MemoryScanner& operator=(const MemoryScanner&) = delete;
    
    // Movable
    MemoryScanner(MemoryScanner&&) noexcept;
    MemoryScanner& operator=(MemoryScanner&&) noexcept;
    
    /**
     * @brief Scan memory for a pattern
     * @param pattern The pattern to search for
     * @param options Scan configuration options
     * @return Vector of scan results or error
     */
    [[nodiscard]] Result<ScanResults> scan(
        const Pattern& pattern,
        const ScanOptions& options = {}
    );
    
    /**
     * @brief Scan a specific memory range
     * @param pattern The pattern to search for
     * @param startAddress Start of range to scan
     * @param endAddress End of range to scan
     * @param options Scan configuration options
     * @return Vector of scan results or error
     */
    [[nodiscard]] Result<ScanResults> scanRange(
        const Pattern& pattern,
        Address startAddress,
        Address endAddress,
        const ScanOptions& options = {}
    );
    
    /**
     * @brief Scan a specific module
     * @param pattern The pattern to search for
     * @param moduleName Name of the module to scan
     * @param options Scan configuration options
     * @return Vector of scan results or error
     */
    [[nodiscard]] Result<ScanResults> scanModule(
        const Pattern& pattern,
        const std::string& moduleName,
        const ScanOptions& options = {}
    );
    
    /**
     * @brief Find first occurrence of pattern
     * @param pattern The pattern to search for
     * @param options Scan configuration options
     * @return First match or nullopt if not found
     */
    [[nodiscard]] Result<std::optional<ScanResult>> findFirst(
        const Pattern& pattern,
        const ScanOptions& options = {}
    );
    
    /**
     * @brief Read memory at address
     * @param address Address to read from
     * @param size Number of bytes to read
     * @return Bytes read or error
     */
    [[nodiscard]] Result<ByteBuffer> read(Address address, size_t size);
    
    /**
     * @brief Read value at address
     * @tparam T Type of value to read
     * @param address Address to read from
     * @return Value or error
     */
    template<typename T>
    [[nodiscard]] Result<T> readValue(Address address) {
        auto bytes = read(address, sizeof(T));
        if (bytes.isFailure()) return bytes.error();
        
        T value;
        std::memcpy(&value, bytes.value().data(), sizeof(T));
        return value;
    }
    
    /**
     * @brief Get all memory regions
     * @return Vector of memory regions or error
     */
    [[nodiscard]] Result<std::vector<MemoryRegion>> getRegions();
    
    /**
     * @brief Get memory region containing address
     * @param address Address to look up
     * @return Memory region or error
     */
    [[nodiscard]] Result<MemoryRegion> getRegionAt(Address address);
    
    /**
     * @brief Get base address of a module
     * @param moduleName Name of the module
     * @return Base address or error
     */
    [[nodiscard]] Result<Address> getModuleBase(const std::string& moduleName);
    
    /**
     * @brief Get size of a module
     * @param moduleName Name of the module
     * @return Module size or error
     */
    [[nodiscard]] Result<size_t> getModuleSize(const std::string& moduleName);
    
    /**
     * @brief Check if process is still valid
     * @return true if process is accessible
     */
    [[nodiscard]] bool isValid() const noexcept;
    
    /**
     * @brief Get process ID
     * @return Process ID being scanned
     */
    [[nodiscard]] ProcessId getProcessId() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// SIMD-Accelerated Scanning Functions
// ============================================================================

namespace SIMD {

/**
 * @brief Check if SSE4.2 is available
 * @return true if SSE4.2 is supported
 */
[[nodiscard]] bool hasSSE42() noexcept;

/**
 * @brief Check if AVX2 is available
 * @return true if AVX2 is supported
 */
[[nodiscard]] bool hasAVX2() noexcept;

/**
 * @brief Scan buffer using SIMD instructions
 * @param buffer Buffer to scan
 * @param bufferSize Size of buffer
 * @param pattern Pattern bytes
 * @param mask Pattern mask
 * @param patternSize Pattern size
 * @param results Output vector for results
 * @param maxResults Maximum results to find (0 = unlimited)
 * @return Number of matches found
 */
size_t scanBuffer(
    const Byte* buffer,
    size_t bufferSize,
    const Byte* pattern,
    const Byte* mask,
    size_t patternSize,
    std::vector<size_t>& results,
    size_t maxResults = 0
);

} // namespace SIMD

} // namespace Sentinel::Memory

#endif // SENTINEL_CORE_MEMORY_SCANNER_HPP
