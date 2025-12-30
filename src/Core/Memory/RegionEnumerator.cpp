/**
 * @file RegionEnumerator.cpp
 * @brief Memory region enumeration implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/RegionEnumerator.hpp>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "Psapi.lib")

namespace Sentinel {
namespace Core {
namespace Memory {

/**
 * @brief Implementation class for RegionEnumerator
 */
class RegionEnumerator::Impl {
public:
    Impl() : m_processId(GetCurrentProcessId()), m_processHandle(GetCurrentProcess()) {
    }
    
    explicit Impl(ProcessId processId) : m_processId(processId) {
        if (processId == GetCurrentProcessId()) {
            m_processHandle = GetCurrentProcess();
        } else {
            m_processHandle = OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                FALSE,
                processId
            );
        }
    }
    
    ~Impl() {
        if (m_processHandle && m_processHandle != GetCurrentProcess()) {
            CloseHandle(m_processHandle);
        }
    }
    
    bool isValid() const noexcept {
        return m_processHandle != nullptr;
    }
    
    ProcessId getProcessId() const noexcept {
        return m_processId;
    }
    
    Result<std::vector<ExtendedMemoryRegion>> enumerateAll() {
        if (!isValid()) {
            return ErrorCode::InvalidHandle;
        }
        
        std::vector<ExtendedMemoryRegion> regions;
        MEMORY_BASIC_INFORMATION mbi;
        Address address = 0;
        
        while (VirtualQueryEx(m_processHandle, reinterpret_cast<LPCVOID>(address), 
                             &mbi, sizeof(mbi)) != 0) {
            // Only include committed regions
            if (mbi.State == MEM_COMMIT) {
                ExtendedMemoryRegion region;
                region.baseAddress = reinterpret_cast<Address>(mbi.BaseAddress);
                region.regionSize = mbi.RegionSize;
                region.protection = static_cast<MemoryProtection>(mbi.Protect);
                region.state = static_cast<MemoryState>(mbi.State);
                region.type = static_cast<MemoryType>(mbi.Type);
                region.allocationBase = reinterpret_cast<Address>(mbi.AllocationBase);
                region.allocationSize = mbi.RegionSize;
                
                // Parse protection flags
                region.isGuarded = (mbi.Protect & PAGE_GUARD) != 0;
                region.isNoCache = (mbi.Protect & PAGE_NOCACHE) != 0;
                region.isWriteCombine = (mbi.Protect & PAGE_WRITECOMBINE) != 0;
                
                // Get module name for IMAGE regions
                if (mbi.Type == MEM_IMAGE) {
                    char moduleName[MAX_PATH];
                    if (GetModuleFileNameExA(m_processHandle,
                                            reinterpret_cast<HMODULE>(mbi.AllocationBase),
                                            moduleName, MAX_PATH)) {
                        region.moduleName = moduleName;
                        // Extract just the filename
                        size_t pos = region.moduleName.find_last_of("\\/");
                        if (pos != std::string::npos) {
                            region.moduleName = region.moduleName.substr(pos + 1);
                        }
                    }
                }
                
                regions.push_back(std::move(region));
            }
            
            // Move to next region
            address = reinterpret_cast<Address>(mbi.BaseAddress) + mbi.RegionSize;
            if (address == 0) break; // Overflow check
        }
        
        return regions;
    }
    
    Result<std::vector<ExtendedMemoryRegion>> enumerateFiltered(RegionFilter filter) {
        auto allRegions = enumerateAll();
        if (allRegions.isFailure()) {
            return allRegions.error();
        }
        
        std::vector<ExtendedMemoryRegion> filtered;
        for (const auto& region : allRegions.value()) {
            if (filter(region)) {
                filtered.push_back(region);
            }
        }
        
        return filtered;
    }
    
    Result<ExtendedMemoryRegion> findRegionContaining(Address address) {
        if (!isValid()) {
            return ErrorCode::InvalidHandle;
        }
        
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(m_processHandle, reinterpret_cast<LPCVOID>(address),
                          &mbi, sizeof(mbi)) == 0) {
            return ErrorCode::RegionNotFound;
        }
        
        if (mbi.State != MEM_COMMIT) {
            return ErrorCode::RegionNotFound;
        }
        
        ExtendedMemoryRegion region;
        region.baseAddress = reinterpret_cast<Address>(mbi.BaseAddress);
        region.regionSize = mbi.RegionSize;
        region.protection = static_cast<MemoryProtection>(mbi.Protect);
        region.state = static_cast<MemoryState>(mbi.State);
        region.type = static_cast<MemoryType>(mbi.Type);
        region.allocationBase = reinterpret_cast<Address>(mbi.AllocationBase);
        region.allocationSize = mbi.RegionSize;
        region.isGuarded = (mbi.Protect & PAGE_GUARD) != 0;
        region.isNoCache = (mbi.Protect & PAGE_NOCACHE) != 0;
        region.isWriteCombine = (mbi.Protect & PAGE_WRITECOMBINE) != 0;
        
        // Get module name
        if (mbi.Type == MEM_IMAGE) {
            char moduleName[MAX_PATH];
            if (GetModuleFileNameExA(m_processHandle,
                                    reinterpret_cast<HMODULE>(mbi.AllocationBase),
                                    moduleName, MAX_PATH)) {
                region.moduleName = moduleName;
                size_t pos = region.moduleName.find_last_of("\\/");
                if (pos != std::string::npos) {
                    region.moduleName = region.moduleName.substr(pos + 1);
                }
            }
        }
        
        return region;
    }
    
    Result<std::vector<ExtendedMemoryRegion>> getModuleRegions(const std::string& moduleName) {
        return enumerateFiltered(createModuleFilter(moduleName));
    }
    
    Result<ExtendedMemoryRegion> getTextSection(const std::string& moduleName) {
        auto moduleRegions = getModuleRegions(moduleName);
        if (moduleRegions.isFailure()) {
            return moduleRegions.error();
        }
        
        // Find the first executable region (typically .text)
        for (const auto& region : moduleRegions.value()) {
            if (region.isExecutable() && !region.isWritable()) {
                return region;
            }
        }
        
        return ErrorCode::SectionNotFound;
    }

private:
    ProcessId m_processId;
    HANDLE m_processHandle;
};

// ============================================================================
// RegionEnumerator Public Interface
// ============================================================================

RegionEnumerator::RegionEnumerator()
    : m_impl(std::make_unique<Impl>()) {
}

RegionEnumerator::RegionEnumerator(ProcessId processId)
    : m_impl(std::make_unique<Impl>(processId)) {
}

RegionEnumerator::~RegionEnumerator() = default;

RegionEnumerator::RegionEnumerator(RegionEnumerator&&) noexcept = default;
RegionEnumerator& RegionEnumerator::operator=(RegionEnumerator&&) noexcept = default;

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::enumerateAll() {
    return m_impl->enumerateAll();
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::enumerateFiltered(
    RegionFilter filter
) {
    return m_impl->enumerateFiltered(std::move(filter));
}

Result<ExtendedMemoryRegion> RegionEnumerator::findRegionContaining(Address address) {
    return m_impl->findRegionContaining(address);
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::getExecutableRegions() {
    return enumerateFiltered(filterExecutable);
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::getWritableRegions() {
    return enumerateFiltered(filterWritable);
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::getModuleRegions(
    const std::string& moduleName
) {
    return m_impl->getModuleRegions(moduleName);
}

Result<ExtendedMemoryRegion> RegionEnumerator::getTextSection(
    const std::string& moduleName
) {
    return m_impl->getTextSection(moduleName);
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::getImageRegions() {
    return enumerateFiltered(filterImage);
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::getPrivateRegions() {
    return enumerateFiltered(filterPrivate);
}

bool RegionEnumerator::isValid() const noexcept {
    return m_impl->isValid();
}

ProcessId RegionEnumerator::getProcessId() const noexcept {
    return m_impl->getProcessId();
}

// ============================================================================
// Filter Functions
// ============================================================================

bool RegionEnumerator::filterExecutable(const ExtendedMemoryRegion& region) noexcept {
    return region.isExecutable();
}

bool RegionEnumerator::filterWritable(const ExtendedMemoryRegion& region) noexcept {
    return region.isWritable();
}

bool RegionEnumerator::filterReadable(const ExtendedMemoryRegion& region) noexcept {
    uint32_t prot = static_cast<uint32_t>(region.protection);
    return (prot & static_cast<uint32_t>(MemoryProtection::NoAccess)) == 0;
}

bool RegionEnumerator::filterImage(const ExtendedMemoryRegion& region) noexcept {
    return region.type == MemoryType::Image;
}

bool RegionEnumerator::filterPrivate(const ExtendedMemoryRegion& region) noexcept {
    return region.type == MemoryType::Private;
}

RegionFilter RegionEnumerator::createModuleFilter(const std::string& moduleName) {
    return [moduleName](const ExtendedMemoryRegion& region) -> bool {
        if (region.moduleName.empty()) {
            return false;
        }
        
        // Case-insensitive comparison
        std::string regionName = region.moduleName;
        std::string targetName = moduleName;
        
        std::transform(regionName.begin(), regionName.end(), regionName.begin(),
                      [](unsigned char c) { return std::tolower(c); });
        std::transform(targetName.begin(), targetName.end(), targetName.begin(),
                      [](unsigned char c) { return std::tolower(c); });
        
        return regionName == targetName;
    };
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
class RegionEnumerator::Impl {
public:
    Impl() = default;
    explicit Impl(ProcessId) {}
    ~Impl() = default;
    bool isValid() const noexcept { return false; }
    ProcessId getProcessId() const noexcept { return 0; }
};

RegionEnumerator::RegionEnumerator() : m_impl(std::make_unique<Impl>()) {}
RegionEnumerator::RegionEnumerator(ProcessId pid) : m_impl(std::make_unique<Impl>(pid)) {}
RegionEnumerator::~RegionEnumerator() = default;
RegionEnumerator::RegionEnumerator(RegionEnumerator&&) noexcept = default;
RegionEnumerator& RegionEnumerator::operator=(RegionEnumerator&&) noexcept = default;

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::enumerateAll() {
    return ErrorCode::NotSupported;
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::enumerateFiltered(RegionFilter) {
    return ErrorCode::NotSupported;
}

Result<ExtendedMemoryRegion> RegionEnumerator::findRegionContaining(Address) {
    return ErrorCode::NotSupported;
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::getExecutableRegions() {
    return ErrorCode::NotSupported;
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::getWritableRegions() {
    return ErrorCode::NotSupported;
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::getModuleRegions(const std::string&) {
    return ErrorCode::NotSupported;
}

Result<ExtendedMemoryRegion> RegionEnumerator::getTextSection(const std::string&) {
    return ErrorCode::NotSupported;
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::getImageRegions() {
    return ErrorCode::NotSupported;
}

Result<std::vector<ExtendedMemoryRegion>> RegionEnumerator::getPrivateRegions() {
    return ErrorCode::NotSupported;
}

bool RegionEnumerator::isValid() const noexcept {
    return false;
}

ProcessId RegionEnumerator::getProcessId() const noexcept {
    return 0;
}

bool RegionEnumerator::filterExecutable(const ExtendedMemoryRegion&) noexcept {
    return false;
}

bool RegionEnumerator::filterWritable(const ExtendedMemoryRegion&) noexcept {
    return false;
}

bool RegionEnumerator::filterReadable(const ExtendedMemoryRegion&) noexcept {
    return false;
}

bool RegionEnumerator::filterImage(const ExtendedMemoryRegion&) noexcept {
    return false;
}

bool RegionEnumerator::filterPrivate(const ExtendedMemoryRegion&) noexcept {
    return false;
}

RegionFilter RegionEnumerator::createModuleFilter(const std::string&) {
    return [](const ExtendedMemoryRegion&) { return false; };
}

} // namespace Memory
} // namespace Core
} // namespace Sentinel

#endif // _WIN32
