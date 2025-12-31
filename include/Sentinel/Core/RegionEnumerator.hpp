/**
 * @file RegionEnumerator.hpp
 * @brief Memory region enumeration and filtering
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * This module provides VirtualQueryEx-based memory region enumeration with
 * flexible filtering capabilities for scanning and analysis.
 */

#pragma once

#ifndef SENTINEL_CORE_REGION_ENUMERATOR_HPP
#define SENTINEL_CORE_REGION_ENUMERATOR_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <functional>
#include <vector>

namespace Sentinel {
namespace Core {
namespace Memory {

/**
 * @brief Extended memory region information
 */
struct ExtendedMemoryRegion : public MemoryRegion {
    Address allocationBase;     ///< Base address of allocation
    size_t allocationSize;      ///< Total size of allocation
    bool isGuarded;             ///< Has PAGE_GUARD flag
    bool isNoCache;             ///< Has PAGE_NOCACHE flag
    bool isWriteCombine;        ///< Has PAGE_WRITECOMBINE flag
};

/**
 * @brief Filter predicate for region enumeration
 */
using RegionFilter = std::function<bool(const ExtendedMemoryRegion&)>;

/**
 * @brief Memory region enumerator
 * 
 * Provides efficient enumeration of process memory regions with filtering.
 * Uses VirtualQueryEx internally for accurate region information.
 */
class RegionEnumerator {
public:
    /**
     * @brief Construct enumerator for current process
     */
    RegionEnumerator();
    
    /**
     * @brief Construct enumerator for specific process
     * @param processId Target process ID
     */
    explicit RegionEnumerator(ProcessId processId);
    
    /// Destructor
    ~RegionEnumerator();
    
    // Non-copyable
    RegionEnumerator(const RegionEnumerator&) = delete;
    RegionEnumerator& operator=(const RegionEnumerator&) = delete;
    
    // Movable
    RegionEnumerator(RegionEnumerator&&) noexcept;
    RegionEnumerator& operator=(RegionEnumerator&&) noexcept;
    
    /**
     * @brief Enumerate all committed memory regions
     * @return Vector of regions or error
     */
    [[nodiscard]] Result<std::vector<ExtendedMemoryRegion>> enumerateAll();
    
    /**
     * @brief Enumerate regions matching filter
     * @param filter Predicate function to filter regions
     * @return Vector of matching regions or error
     */
    [[nodiscard]] Result<std::vector<ExtendedMemoryRegion>> enumerateFiltered(
        RegionFilter filter
    );
    
    /**
     * @brief Find region containing address
     * @param address Address to look up
     * @return Region containing address or error
     */
    [[nodiscard]] Result<ExtendedMemoryRegion> findRegionContaining(Address address);
    
    /**
     * @brief Get all executable regions
     * @return Vector of executable regions or error
     */
    [[nodiscard]] Result<std::vector<ExtendedMemoryRegion>> getExecutableRegions();
    
    /**
     * @brief Get all writable regions
     * @return Vector of writable regions or error
     */
    [[nodiscard]] Result<std::vector<ExtendedMemoryRegion>> getWritableRegions();
    
    /**
     * @brief Get all regions belonging to a module
     * @param moduleName Name of module (e.g., "game.exe")
     * @return Vector of module regions or error
     */
    [[nodiscard]] Result<std::vector<ExtendedMemoryRegion>> getModuleRegions(
        const std::string& moduleName
    );
    
    /**
     * @brief Get .text (code) section of a module
     * @param moduleName Name of module
     * @return .text region or error
     */
    [[nodiscard]] Result<ExtendedMemoryRegion> getTextSection(
        const std::string& moduleName
    );
    
    /**
     * @brief Get all IMAGE (PE file) regions
     * @return Vector of image regions or error
     */
    [[nodiscard]] Result<std::vector<ExtendedMemoryRegion>> getImageRegions();
    
    /**
     * @brief Get all PRIVATE (heap/stack) regions
     * @return Vector of private regions or error
     */
    [[nodiscard]] Result<std::vector<ExtendedMemoryRegion>> getPrivateRegions();
    
    /**
     * @brief Check if process is still valid
     * @return true if process is accessible
     */
    [[nodiscard]] bool isValid() const noexcept;
    
    /**
     * @brief Get process ID being enumerated
     * @return Process ID
     */
    [[nodiscard]] ProcessId getProcessId() const noexcept;
    
    // ========================================================================
    // Built-in Filter Functions
    // ========================================================================
    
    /**
     * @brief Filter for executable regions
     */
    static bool filterExecutable(const ExtendedMemoryRegion& region) noexcept;
    
    /**
     * @brief Filter for writable regions
     */
    static bool filterWritable(const ExtendedMemoryRegion& region) noexcept;
    
    /**
     * @brief Filter for readable regions
     */
    static bool filterReadable(const ExtendedMemoryRegion& region) noexcept;
    
    /**
     * @brief Filter for IMAGE type regions
     */
    static bool filterImage(const ExtendedMemoryRegion& region) noexcept;
    
    /**
     * @brief Filter for PRIVATE type regions
     */
    static bool filterPrivate(const ExtendedMemoryRegion& region) noexcept;
    
    /**
     * @brief Create module name filter
     * @param moduleName Module name to match (case-insensitive)
     * @return Filter function
     */
    static RegionFilter createModuleFilter(const std::string& moduleName);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Memory
} // namespace Core
} // namespace Sentinel

#endif // SENTINEL_CORE_REGION_ENUMERATOR_HPP
