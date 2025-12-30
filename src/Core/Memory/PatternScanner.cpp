/**
 * @file PatternScanner.cpp
 * @brief IDA-style pattern scanning implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/PatternScanner.hpp>
#include <sstream>
#include <cctype>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>

// Include SafeMemory for crash-safe reading
// Note: We'll use direct memory access with SEH for now
// Full SafeMemory integration would require SDK dependency

namespace Sentinel {
namespace Core {
namespace Memory {

namespace {
    /**
     * @brief Safe memory read with exception handling
     */
    bool safeMemcmp(const void* ptr1, const void* ptr2, size_t size) noexcept {
#ifdef _WIN32
        __try {
            return std::memcmp(ptr1, ptr2, size) == 0;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
#else
        return std::memcmp(ptr1, ptr2, size) == 0;
#endif
    }
    
    /**
     * @brief Safe memory access check
     */
    bool isMemoryReadable(const void* address, size_t size) noexcept {
#ifdef _WIN32
        if (!address || size == 0) return false;
        
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
            return false;
        }
        
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & PAGE_GUARD) return false;
        if (mbi.Protect == PAGE_NOACCESS) return false;
        
        return true;
#else
        (void)address;
        (void)size;
        return true;
#endif
    }
}

Result<PatternScanner::CompiledPattern> PatternScanner::compilePattern(
    const std::string& pattern
) {
    CompiledPattern compiled;
    compiled.original = pattern;
    
    std::istringstream stream(pattern);
    std::string token;
    
    while (stream >> token) {
        // Check for wildcard
        if (token == "?" || token == "??") {
            compiled.bytes.push_back(0x00);
            compiled.mask.push_back(false);
            continue;
        }
        
        // Check for single character wildcard
        if (token.length() == 1 && token[0] == '?') {
            compiled.bytes.push_back(0x00);
            compiled.mask.push_back(false);
            continue;
        }
        
        // Parse hex byte
        if (token.length() != 2) {
            return ErrorCode::InvalidHexString;
        }
        
        // Check if both characters are hex digits
        if (!std::isxdigit(static_cast<unsigned char>(token[0])) || 
            !std::isxdigit(static_cast<unsigned char>(token[1]))) {
            return ErrorCode::InvalidHexString;
        }
        
        char* end;
        unsigned long value = std::strtoul(token.c_str(), &end, 16);
        if (*end != '\0' || value > 255) {
            return ErrorCode::InvalidHexString;
        }
        
        compiled.bytes.push_back(static_cast<Byte>(value));
        compiled.mask.push_back(true);
    }
    
    if (compiled.bytes.empty()) {
        return ErrorCode::InvalidArgument;
    }
    
    return compiled;
}

bool PatternScanner::matchesAt(
    const Byte* data,
    size_t dataSize,
    const CompiledPattern& pattern
) noexcept {
    if (dataSize < pattern.size()) {
        return false;
    }
    
    // Check if memory is readable before comparing
    if (!isMemoryReadable(data, pattern.size())) {
        return false;
    }
    
    // Compare with SEH protection
#ifdef _WIN32
    __try {
#endif
        for (size_t i = 0; i < pattern.size(); ++i) {
            if (pattern.mask[i] && data[i] != pattern.bytes[i]) {
                return false;
            }
        }
        return true;
#ifdef _WIN32
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#endif
}

Result<std::vector<PatternScanner::ScanResult>> PatternScanner::scan(
    Address baseAddress,
    size_t size,
    const CompiledPattern& pattern,
    size_t maxResults
) {
    if (!pattern.isValid()) {
        return ErrorCode::InvalidArgument;
    }
    
    if (size < pattern.size()) {
        return std::vector<ScanResult>{};
    }
    
    std::vector<ScanResult> results;
    const Byte* base = reinterpret_cast<const Byte*>(baseAddress);
    const size_t searchLimit = size - pattern.size() + 1;
    
    // Scan memory region
    for (size_t offset = 0; offset < searchLimit; ++offset) {
        const Byte* current = base + offset;
        
        if (matchesAt(current, size - offset, pattern)) {
            ScanResult result;
            result.address = baseAddress + offset;
            
            // Safely copy matched bytes
            result.matchedBytes.resize(pattern.size());
#ifdef _WIN32
            __try {
#endif
                std::memcpy(result.matchedBytes.data(), current, pattern.size());
#ifdef _WIN32
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // Memory became inaccessible, skip this result
                continue;
            }
#endif
            
            results.push_back(std::move(result));
            
            if (maxResults > 0 && results.size() >= maxResults) {
                break;
            }
        }
    }
    
    return results;
}

Result<std::optional<PatternScanner::ScanResult>> PatternScanner::findFirst(
    Address baseAddress,
    size_t size,
    const CompiledPattern& pattern
) {
    auto results = scan(baseAddress, size, pattern, 1);
    if (results.isFailure()) {
        return results.error();
    }
    
    if (results.value().empty()) {
        return std::optional<ScanResult>{};
    }
    
    return std::optional<ScanResult>{results.value()[0]};
}

Result<std::vector<PatternScanner::ScanResult>> PatternScanner::scanWithString(
    Address baseAddress,
    size_t size,
    const std::string& patternString,
    size_t maxResults
) {
    auto compiledResult = compilePattern(patternString);
    if (compiledResult.isFailure()) {
        return compiledResult.error();
    }
    
    return scan(baseAddress, size, compiledResult.value(), maxResults);
}

} // namespace Memory
} // namespace Core
} // namespace Sentinel

#else // !_WIN32

// Stub implementations for non-Windows platforms

namespace Sentinel {
namespace Core {
namespace Memory {

Result<PatternScanner::CompiledPattern> PatternScanner::compilePattern(
    const std::string& pattern
) {
    CompiledPattern compiled;
    compiled.original = pattern;
    
    std::istringstream stream(pattern);
    std::string token;
    
    while (stream >> token) {
        // Check for wildcard
        if (token == "?" || token == "??") {
            compiled.bytes.push_back(0x00);
            compiled.mask.push_back(false);
            continue;
        }
        
        if (token.length() == 1 && token[0] == '?') {
            compiled.bytes.push_back(0x00);
            compiled.mask.push_back(false);
            continue;
        }
        
        if (token.length() != 2) {
            return ErrorCode::InvalidHexString;
        }
        
        if (!std::isxdigit(token[0]) || !std::isxdigit(token[1])) {
            return ErrorCode::InvalidHexString;
        }
        
        char* end;
        unsigned long value = std::strtoul(token.c_str(), &end, 16);
        if (*end != '\0' || value > 255) {
            return ErrorCode::InvalidHexString;
        }
        
        compiled.bytes.push_back(static_cast<Byte>(value));
        compiled.mask.push_back(true);
    }
    
    if (compiled.bytes.empty()) {
        return ErrorCode::InvalidArgument;
    }
    
    return compiled;
}

bool PatternScanner::matchesAt(
    const Byte* data,
    size_t dataSize,
    const CompiledPattern& pattern
) noexcept {
    if (dataSize < pattern.size()) {
        return false;
    }
    
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (pattern.mask[i] && data[i] != pattern.bytes[i]) {
            return false;
        }
    }
    return true;
}

Result<std::vector<PatternScanner::ScanResult>> PatternScanner::scan(
    Address baseAddress,
    size_t size,
    const CompiledPattern& pattern,
    size_t maxResults
) {
    if (!pattern.isValid()) {
        return ErrorCode::InvalidArgument;
    }
    
    if (size < pattern.size()) {
        return std::vector<ScanResult>{};
    }
    
    std::vector<ScanResult> results;
    const Byte* base = reinterpret_cast<const Byte*>(baseAddress);
    const size_t searchLimit = size - pattern.size() + 1;
    
    for (size_t offset = 0; offset < searchLimit; ++offset) {
        const Byte* current = base + offset;
        
        if (matchesAt(current, size - offset, pattern)) {
            ScanResult result;
            result.address = baseAddress + offset;
            result.matchedBytes.assign(current, current + pattern.size());
            results.push_back(std::move(result));
            
            if (maxResults > 0 && results.size() >= maxResults) {
                break;
            }
        }
    }
    
    return results;
}

Result<std::optional<PatternScanner::ScanResult>> PatternScanner::findFirst(
    Address baseAddress,
    size_t size,
    const CompiledPattern& pattern
) {
    auto results = scan(baseAddress, size, pattern, 1);
    if (results.isFailure()) {
        return results.error();
    }
    
    if (results.value().empty()) {
        return std::optional<ScanResult>{};
    }
    
    return std::optional<ScanResult>{results.value()[0]};
}

Result<std::vector<PatternScanner::ScanResult>> PatternScanner::scanWithString(
    Address baseAddress,
    size_t size,
    const std::string& patternString,
    size_t maxResults
) {
    auto compiledResult = compilePattern(patternString);
    if (compiledResult.isFailure()) {
        return compiledResult.error();
    }
    
    return scan(baseAddress, size, compiledResult.value(), maxResults);
}

} // namespace Memory
} // namespace Core
} // namespace Sentinel

#endif // !_WIN32
