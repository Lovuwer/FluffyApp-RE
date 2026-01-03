/**
 * @file ProtectionManager.cpp
 * @brief Memory protection and guard page management implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/ProtectionManager.hpp>

#ifdef _WIN32
#include <windows.h>
#include <mutex>
#include <unordered_map>
#include <atomic>

namespace Sentinel {
namespace Core {
namespace Memory {

// Forward declaration for friend
static LONG WINAPI vehHandler(EXCEPTION_POINTERS* exceptionInfo);

// Global state for VEH handler
namespace {
    std::mutex g_handlerMutex;
    ProtectionManager::Impl* g_activeManager = nullptr;
    void* g_vehHandle = nullptr;
}

/**
 * @brief Implementation class for ProtectionManager
 */
class ProtectionManager::Impl {
public:
    // Friend declaration to allow VEH handler access
    friend LONG WINAPI vehHandler(EXCEPTION_POINTERS*);
    Impl() {
        installVEH();
    }
    
    ~Impl() {
        removeVEH();
        restoreAllProtections();
    }
    
    Result<void> installGuardPage(Address address, size_t size) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Align address to page boundary
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        Address alignedAddr = address & ~static_cast<Address>(si.dwPageSize - 1);
        size_t alignedSize = ((address + size - alignedAddr) + si.dwPageSize - 1) & ~static_cast<size_t>(si.dwPageSize - 1);
        
        // Query current protection
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(alignedAddr), &mbi, sizeof(mbi)) == 0) {
            return ErrorCode::MemoryError;
        }
        
        if (mbi.State != MEM_COMMIT) {
            return ErrorCode::InvalidAddress;
        }
        
        // Store original protection
        ProtectionInfo info;
        info.address = alignedAddr;
        info.size = alignedSize;
        info.originalProtection = static_cast<MemoryProtection>(mbi.Protect);
        
        // Add PAGE_GUARD flag
        DWORD newProtect = mbi.Protect | PAGE_GUARD;
        DWORD oldProtect;
        
        if (!VirtualProtect(reinterpret_cast<LPVOID>(alignedAddr), alignedSize, 
                           newProtect, &oldProtect)) {
            return ErrorCode::ProtectionChangeFailed;
        }
        
        m_protectedRegions[alignedAddr] = info;
        return Result<void>::Success();
    }
    
    Result<void> removeGuardPage(Address address, size_t size) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Align address to page boundary
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        Address alignedAddr = address & ~static_cast<Address>(si.dwPageSize - 1);
        size_t alignedSize = ((address + size - alignedAddr) + si.dwPageSize - 1) & ~static_cast<size_t>(si.dwPageSize - 1);
        
        auto it = m_protectedRegions.find(alignedAddr);
        if (it == m_protectedRegions.end()) {
            return ErrorCode::RegionNotFound;
        }
        
        // Restore original protection
        DWORD oldProtect;
        DWORD originalProt = static_cast<DWORD>(it->second.originalProtection);
        
        if (!VirtualProtect(reinterpret_cast<LPVOID>(alignedAddr), alignedSize,
                           originalProt, &oldProtect)) {
            return ErrorCode::ProtectionChangeFailed;
        }
        
        m_protectedRegions.erase(it);
        return Result<void>::Success();
    }
    
    void setGuardPageCallback(GuardPageCallback callback) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_callback = std::move(callback);
    }
    
    size_t getAccessCount() const noexcept {
        return m_accessCount.load();
    }
    
    void resetAccessCount() noexcept {
        m_accessCount.store(0);
    }
    
    bool isActive() const noexcept {
        return m_vehInstalled.load();
    }
    
    Result<MemoryProtection> getOriginalProtection(Address address) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Find the protected region containing this address
        for (const auto& [baseAddr, info] : m_protectedRegions) {
            if (address >= baseAddr && address < baseAddr + info.size) {
                return info.originalProtection;
            }
        }
        
        return ErrorCode::RegionNotFound;
    }
    
    // Called from VEH handler
    bool handleException(EXCEPTION_POINTERS* exceptionInfo) {
        if (exceptionInfo->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION) {
            return false;
        }
        
        m_accessCount.fetch_add(1);
        
        GuardPageAccess access;
        access.address = static_cast<Address>(exceptionInfo->ExceptionRecord->ExceptionInformation[1]);
        access.isWrite = (exceptionInfo->ExceptionRecord->ExceptionInformation[0] == 1);
        access.isExecute = (exceptionInfo->ExceptionRecord->ExceptionInformation[0] == 8);
        access.threadId = GetCurrentThreadId();
        access.timestamp = Sentinel::Clock::now();
        
        // Invoke callback if set
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_callback) {
            m_callback(access);
        }
        
        // Return true to continue search (let system remove guard page)
        // Callback can reinstall guard page if desired
        return false;
    }

private:
    struct ProtectionInfo {
        Address address;
        size_t size;
        MemoryProtection originalProtection;
    };
    
    void installVEH() {
        std::lock_guard<std::mutex> lock(g_handlerMutex);
        
        if (!g_vehHandle) {
            g_vehHandle = AddVectoredExceptionHandler(1, vehHandler);
            if (g_vehHandle) {
                m_vehInstalled.store(true);
            }
        }
        
        g_activeManager = this;
    }
    
    void removeVEH() {
        std::lock_guard<std::mutex> lock(g_handlerMutex);
        
        if (g_activeManager == this) {
            g_activeManager = nullptr;
        }
        
        if (g_vehHandle && g_activeManager == nullptr) {
            RemoveVectoredExceptionHandler(g_vehHandle);
            g_vehHandle = nullptr;
            m_vehInstalled.store(false);
        }
    }
    
    void restoreAllProtections() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        for (const auto& [addr, info] : m_protectedRegions) {
            DWORD oldProtect;
            VirtualProtect(reinterpret_cast<LPVOID>(addr), info.size,
                          static_cast<DWORD>(info.originalProtection), &oldProtect);
        }
        
        m_protectedRegions.clear();
    }
    
    mutable std::mutex m_mutex;
    std::unordered_map<Address, ProtectionInfo> m_protectedRegions;
    GuardPageCallback m_callback;
    std::atomic<size_t> m_accessCount{0};
    std::atomic<bool> m_vehInstalled{false};
};

// Static VEH handler function (outside of class)
static LONG WINAPI vehHandler(EXCEPTION_POINTERS* exceptionInfo) {
    std::lock_guard<std::mutex> lock(g_handlerMutex);
    
    if (g_activeManager && 
        g_activeManager->handleException(exceptionInfo)) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

// ============================================================================
// ProtectionManager Public Interface
// ============================================================================

ProtectionManager::ProtectionManager() 
    : m_impl(std::make_unique<Impl>()) {
}

ProtectionManager::~ProtectionManager() = default;

ProtectionManager::ProtectionManager(ProtectionManager&&) noexcept = default;
ProtectionManager& ProtectionManager::operator=(ProtectionManager&&) noexcept = default;

Result<void> ProtectionManager::installGuardPage(Address address, size_t size) {
    return m_impl->installGuardPage(address, size);
}

Result<void> ProtectionManager::removeGuardPage(Address address, size_t size) {
    return m_impl->removeGuardPage(address, size);
}

void ProtectionManager::setGuardPageCallback(GuardPageCallback callback) {
    m_impl->setGuardPageCallback(std::move(callback));
}

size_t ProtectionManager::getAccessCount() const noexcept {
    return m_impl->getAccessCount();
}

void ProtectionManager::resetAccessCount() noexcept {
    m_impl->resetAccessCount();
}

bool ProtectionManager::isActive() const noexcept {
    return m_impl->isActive();
}

Result<MemoryProtection> ProtectionManager::getOriginalProtection(Address address) const {
    return m_impl->getOriginalProtection(address);
}

} // namespace Memory
} // namespace Core
} // namespace Sentinel

#else // !_WIN32

// Stub implementations for non-Windows platforms

namespace Sentinel {
namespace Core {
namespace Memory {

// Stub Impl class for non-Windows
class ProtectionManager::Impl {
public:
    Impl() = default;
    ~Impl() = default;
};

ProtectionManager::ProtectionManager() : m_impl(std::make_unique<Impl>()) {}
ProtectionManager::~ProtectionManager() = default;
ProtectionManager::ProtectionManager(ProtectionManager&&) noexcept = default;
ProtectionManager& ProtectionManager::operator=(ProtectionManager&&) noexcept = default;

Result<void> ProtectionManager::installGuardPage(Address, size_t) {
    return ErrorCode::NotSupported;
}

Result<void> ProtectionManager::removeGuardPage(Address, size_t) {
    return ErrorCode::NotSupported;
}

void ProtectionManager::setGuardPageCallback(GuardPageCallback) {
}

size_t ProtectionManager::getAccessCount() const noexcept {
    return 0;
}

void ProtectionManager::resetAccessCount() noexcept {
}

bool ProtectionManager::isActive() const noexcept {
    return false;
}

Result<MemoryProtection> ProtectionManager::getOriginalProtection(Address) const {
    return ErrorCode::NotSupported;
}

} // namespace Memory
} // namespace Core
} // namespace Sentinel

#endif // _WIN32
