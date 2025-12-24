/**
 * @file MemoryScanner.cpp
 * @brief Implementation of high-performance memory scanning
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#ifdef _WIN32

#include <Sentinel/Core/MemoryScanner.hpp>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <algorithm>
#include <thread>
#include <future>
#include <sstream>
#include <iomanip>
#include <cctype>

#pragma comment(lib, "Psapi.lib")

namespace Sentinel::Memory {

// ============================================================================
// Pattern Implementation
// ============================================================================

Pattern::Pattern(const ByteBuffer& bytes, const std::string& mask)
    : m_bytes(bytes)
{
    m_mask.reserve(mask.size());
    for (char c : mask) {
        m_mask.push_back(c == 'x' || c == 'X');
    }
    
    // Ensure mask matches bytes size
    if (m_mask.size() < m_bytes.size()) {
        m_mask.resize(m_bytes.size(), true);
    }
    
    prepareSIMD();
}

Pattern::Pattern(const ByteBuffer& bytes, const std::vector<bool>& mask)
    : m_bytes(bytes)
    , m_mask(mask)
{
    if (m_mask.size() < m_bytes.size()) {
        m_mask.resize(m_bytes.size(), true);
    }
    prepareSIMD();
}

Result<Pattern> Pattern::fromString(const std::string& hexPattern) {
    ByteBuffer bytes;
    std::vector<bool> mask;
    
    std::istringstream stream(hexPattern);
    std::string token;
    
    while (stream >> token) {
        if (token == "?" || token == "??" || token == "**") {
            bytes.push_back(0x00);
            mask.push_back(false);
        } else {
            // Check for single wildcard character
            if (token.length() == 1 && !std::isxdigit(token[0])) {
                bytes.push_back(0x00);
                mask.push_back(false);
                continue;
            }
            
            // Parse hex byte
            char* end;
            unsigned long value = std::strtoul(token.c_str(), &end, 16);
            if (*end != '\0' || value > 255) {
                return ErrorCode::InvalidHexString;
            }
            bytes.push_back(static_cast<Byte>(value));
            mask.push_back(true);
        }
    }
    
    if (bytes.empty()) {
        return ErrorCode::InvalidArgument;
    }
    
    return Pattern(bytes, mask);
}

Result<Pattern> Pattern::fromIDA(const std::string& idaSig) {
    // IDA format is similar but uses single ? for wildcards
    return fromString(idaSig);
}

bool Pattern::matches(const Byte* data, size_t dataSize) const noexcept {
    if (dataSize < m_bytes.size()) return false;
    
    for (size_t i = 0; i < m_bytes.size(); ++i) {
        if (m_mask[i] && data[i] != m_bytes[i]) {
            return false;
        }
    }
    
    return true;
}

std::string Pattern::toString() const {
    std::ostringstream ss;
    for (size_t i = 0; i < m_bytes.size(); ++i) {
        if (i > 0) ss << " ";
        if (m_mask[i]) {
            ss << std::uppercase << std::setfill('0') << std::setw(2) 
               << std::hex << static_cast<int>(m_bytes[i]);
        } else {
            ss << "??";
        }
    }
    return ss.str();
}

void Pattern::prepareSIMD() {
    // Prepare data for SIMD operations
    if (m_bytes.size() >= 16 && SIMD::hasSSE42()) {
        m_canUseSIMD = true;
        
        // Pad to 16-byte boundary
        size_t paddedSize = (m_bytes.size() + 15) & ~15;
        m_simdBytes.resize(paddedSize, 0);
        m_simdMask.resize(paddedSize, 0);
        
        for (size_t i = 0; i < m_bytes.size(); ++i) {
            m_simdBytes[i] = m_bytes[i];
            m_simdMask[i] = m_mask[i] ? 0xFF : 0x00;
        }
    }
}

// ============================================================================
// SIMD Namespace Implementation
// ============================================================================

namespace SIMD {

bool hasSSE42() noexcept {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 20)) != 0;
}

bool hasAVX2() noexcept {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    if (cpuInfo[0] >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        return (cpuInfo[1] & (1 << 5)) != 0;
    }
    return false;
}

size_t scanBuffer(
    const Byte* buffer,
    size_t bufferSize,
    const Byte* pattern,
    const Byte* mask,
    size_t patternSize,
    std::vector<size_t>& results,
    size_t maxResults
) {
    size_t found = 0;
    
    // Simple scanning implementation (SSE4.2 can be added for optimization)
    if (bufferSize < patternSize) return 0;
    
    size_t limit = bufferSize - patternSize + 1;
    
    for (size_t i = 0; i < limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < patternSize; ++j) {
            if (mask[j] && buffer[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        
        if (match) {
            results.push_back(i);
            ++found;
            if (maxResults > 0 && found >= maxResults) {
                break;
            }
        }
    }
    
    return found;
}

} // namespace SIMD

// ============================================================================
// MemoryScanner Implementation
// ============================================================================

class MemoryScanner::Impl {
public:
    Impl() : m_processId(GetCurrentProcessId()), m_processHandle(GetCurrentProcess()) {}
    
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
    
    Result<std::vector<MemoryRegion>> getRegions() {
        if (!isValid()) return ErrorCode::InvalidHandle;
        
        std::vector<MemoryRegion> regions;
        MEMORY_BASIC_INFORMATION mbi;
        Address address = 0;
        
        while (VirtualQueryEx(m_processHandle, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT) {
                MemoryRegion region;
                region.baseAddress = reinterpret_cast<Address>(mbi.BaseAddress);
                region.regionSize = mbi.RegionSize;
                region.protection = static_cast<MemoryProtection>(mbi.Protect);
                region.state = static_cast<MemoryState>(mbi.State);
                region.type = static_cast<MemoryType>(mbi.Type);
                
                // Get module name if applicable
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
            
            address = reinterpret_cast<Address>(mbi.BaseAddress) + mbi.RegionSize;
            if (address == 0) break; // Overflow check
        }
        
        return regions;
    }
    
    Result<ByteBuffer> read(Address address, size_t size) {
        if (!isValid()) return ErrorCode::InvalidHandle;
        
        ByteBuffer buffer(size);
        SIZE_T bytesRead;
        
        if (!ReadProcessMemory(m_processHandle, 
                reinterpret_cast<LPCVOID>(address),
                buffer.data(), size, &bytesRead)) {
            return ErrorCode::MemoryReadFailed;
        }
        
        buffer.resize(bytesRead);
        return buffer;
    }
    
    Result<ScanResults> scan(const Pattern& pattern, const ScanOptions& options) {
        if (!pattern.isValid()) return ErrorCode::InvalidArgument;
        
        auto regionsResult = getRegions();
        if (regionsResult.isFailure()) return regionsResult.error();
        
        auto& regions = regionsResult.value();
        ScanResults results;
        
        // Filter regions
        std::vector<MemoryRegion> filteredRegions;
        for (const auto& region : regions) {
            if (options.executableOnly && !region.isExecutable()) continue;
            if (options.writableOnly && !region.isWritable()) continue;
            
            if (!options.moduleFilter.empty()) {
                bool found = false;
                for (const auto& mod : options.moduleFilter) {
                    if (_stricmp(region.moduleName.c_str(), mod.c_str()) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found) continue;
            }
            
            bool excluded = false;
            for (const auto& mod : options.moduleExclude) {
                if (_stricmp(region.moduleName.c_str(), mod.c_str()) == 0) {
                    excluded = true;
                    break;
                }
            }
            if (excluded) continue;
            
            filteredRegions.push_back(region);
        }
        
        // Calculate total size for progress
        size_t totalSize = 0;
        for (const auto& region : filteredRegions) {
            totalSize += region.regionSize;
        }
        
        size_t scannedSize = 0;
        
        // Scan each region
        for (const auto& region : filteredRegions) {
            if (options.cancellationToken && options.cancellationToken->load()) {
                return ErrorCode::Cancelled;
            }
            
            auto bufferResult = read(region.baseAddress, region.regionSize);
            if (bufferResult.isFailure()) {
                scannedSize += region.regionSize;
                continue;
            }
            
            const auto& buffer = bufferResult.value();
            
            // Scan buffer
            for (size_t offset = 0; offset + pattern.size() <= buffer.size(); offset += options.alignment) {
                if (pattern.matches(buffer.data() + offset, buffer.size() - offset)) {
                    ScanResult result;
                    result.address = region.baseAddress + offset;
                    result.moduleName = region.moduleName;
                    result.rva = static_cast<RVA>(offset);
                    result.matchedBytes.assign(
                        buffer.data() + offset,
                        buffer.data() + offset + pattern.size()
                    );
                    
                    results.push_back(std::move(result));
                    
                    if (options.maxResults > 0 && results.size() >= options.maxResults) {
                        return results;
                    }
                }
            }
            
            scannedSize += region.regionSize;
            
            if (options.progressCallback) {
                options.progressCallback(scannedSize, totalSize);
            }
        }
        
        return results;
    }
    
    Result<Address> getModuleBase(const std::string& moduleName) {
        auto regions = getRegions();
        if (regions.isFailure()) return regions.error();
        
        for (const auto& region : regions.value()) {
            if (_stricmp(region.moduleName.c_str(), moduleName.c_str()) == 0) {
                return region.baseAddress;
            }
        }
        
        return ErrorCode::RegionNotFound;
    }

private:
    ProcessId m_processId;
    HANDLE m_processHandle;
};

MemoryScanner::MemoryScanner() : m_impl(std::make_unique<Impl>()) {}

MemoryScanner::MemoryScanner(ProcessId processId) 
    : m_impl(std::make_unique<Impl>(processId)) {}

MemoryScanner::~MemoryScanner() = default;

MemoryScanner::MemoryScanner(MemoryScanner&&) noexcept = default;
MemoryScanner& MemoryScanner::operator=(MemoryScanner&&) noexcept = default;

Result<ScanResults> MemoryScanner::scan(const Pattern& pattern, const ScanOptions& options) {
    return m_impl->scan(pattern, options);
}

Result<ScanResults> MemoryScanner::scanRange(
    const Pattern& pattern,
    Address startAddress,
    Address endAddress,
    const ScanOptions& options
) {
    if (startAddress >= endAddress) return ErrorCode::InvalidArgument;
    
    auto bufferResult = m_impl->read(startAddress, endAddress - startAddress);
    if (bufferResult.isFailure()) return bufferResult.error();
    
    const auto& buffer = bufferResult.value();
    ScanResults results;
    
    for (size_t offset = 0; offset + pattern.size() <= buffer.size(); offset += options.alignment) {
        if (pattern.matches(buffer.data() + offset, buffer.size() - offset)) {
            ScanResult result;
            result.address = startAddress + offset;
            result.rva = static_cast<RVA>(offset);
            result.matchedBytes.assign(
                buffer.data() + offset,
                buffer.data() + offset + pattern.size()
            );
            
            results.push_back(std::move(result));
            
            if (options.maxResults > 0 && results.size() >= options.maxResults) {
                break;
            }
        }
    }
    
    return results;
}

Result<ScanResults> MemoryScanner::scanModule(
    const Pattern& pattern,
    const std::string& moduleName,
    const ScanOptions& options
) {
    ScanOptions moduleOptions = options;
    moduleOptions.moduleFilter = {moduleName};
    return scan(pattern, moduleOptions);
}

Result<std::optional<ScanResult>> MemoryScanner::findFirst(
    const Pattern& pattern,
    const ScanOptions& options
) {
    ScanOptions firstOptions = options;
    firstOptions.maxResults = 1;
    
    auto results = scan(pattern, firstOptions);
    if (results.isFailure()) return results.error();
    
    if (results.value().empty()) {
        return std::optional<ScanResult>{};
    }
    
    return std::optional<ScanResult>{results.value()[0]};
}

Result<ByteBuffer> MemoryScanner::read(Address address, size_t size) {
    return m_impl->read(address, size);
}

Result<std::vector<MemoryRegion>> MemoryScanner::getRegions() {
    return m_impl->getRegions();
}

Result<Address> MemoryScanner::getModuleBase(const std::string& moduleName) {
    return m_impl->getModuleBase(moduleName);
}

bool MemoryScanner::isValid() const noexcept {
    return m_impl->isValid();
}

ProcessId MemoryScanner::getProcessId() const noexcept {
    return m_impl->getProcessId();
}

} // namespace Sentinel::Memory
#endif // _WIN32
