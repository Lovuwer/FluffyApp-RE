/**
 * @file ProtectionManager.hpp
 * @brief Memory protection and guard page management
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * This module provides PAGE_GUARD trap installation and VEH (Vectored Exception Handler)
 * management for detecting memory access attempts.
 */

#pragma once

#ifndef SENTINEL_CORE_PROTECTION_MANAGER_HPP
#define SENTINEL_CORE_PROTECTION_MANAGER_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <functional>
#include <memory>

namespace Sentinel {
namespace Core {
namespace Memory {

/**
 * @brief Guard page access information
 */
struct GuardPageAccess {
    Address address;              ///< Address that was accessed
    bool isWrite;                 ///< true if write access, false if read
    bool isExecute;               ///< true if execute access
    ThreadId threadId;            ///< Thread that triggered the access
    TimePoint timestamp;          ///< When access occurred
};

/**
 * @brief Callback for guard page access events
 */
using GuardPageCallback = std::function<void(const GuardPageAccess&)>;

/**
 * @brief Memory protection manager
 * 
 * Provides capabilities for:
 * - Installing PAGE_GUARD protection on memory regions
 * - Registering VEH (Vectored Exception Handler) for guard page exceptions
 * - Tracking and logging guard page accesses
 */
class ProtectionManager {
public:
    /**
     * @brief Construct protection manager
     */
    ProtectionManager();
    
    /**
     * @brief Destructor - cleans up VEH and restores protections
     */
    ~ProtectionManager();
    
    // Non-copyable
    ProtectionManager(const ProtectionManager&) = delete;
    ProtectionManager& operator=(const ProtectionManager&) = delete;
    
    // Movable
    ProtectionManager(ProtectionManager&&) noexcept;
    ProtectionManager& operator=(ProtectionManager&&) noexcept;
    
    /**
     * @brief Install PAGE_GUARD on a memory region
     * @param address Base address of region
     * @param size Size of region
     * @return Success or error code
     * 
     * Note: The guard page will trigger an exception on first access,
     * then be automatically removed by Windows. Use callback to reinstall.
     */
    [[nodiscard]] Result<void> installGuardPage(Address address, size_t size);
    
    /**
     * @brief Remove PAGE_GUARD from a memory region
     * @param address Base address of region
     * @param size Size of region
     * @return Success or error code
     */
    [[nodiscard]] Result<void> removeGuardPage(Address address, size_t size);
    
    /**
     * @brief Register callback for guard page access events
     * @param callback Function to call when guard page is accessed
     * 
     * The callback will be invoked from the VEH handler context.
     * Keep callback execution minimal and avoid heavy operations.
     */
    void setGuardPageCallback(GuardPageCallback callback);
    
    /**
     * @brief Get number of guard page accesses detected
     * @return Total access count since creation
     */
    [[nodiscard]] size_t getAccessCount() const noexcept;
    
    /**
     * @brief Clear access count
     */
    void resetAccessCount() noexcept;
    
    /**
     * @brief Check if protection manager is active
     * @return true if VEH is registered
     */
    [[nodiscard]] bool isActive() const noexcept;
    
    /**
     * @brief Get original protection flags for an address
     * @param address Address to query
     * @return Original protection flags or error
     */
    [[nodiscard]] Result<MemoryProtection> getOriginalProtection(Address address) const;

private:
    struct Impl; // Forward declaration for pimpl idiom
    std::unique_ptr<Impl> m_impl;
};

} // namespace Memory
} // namespace Core
} // namespace Sentinel

#endif // SENTINEL_CORE_PROTECTION_MANAGER_HPP
