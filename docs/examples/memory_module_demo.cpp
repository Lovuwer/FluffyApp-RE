/**
 * Memory Module Usage Examples
 * 
 * This file demonstrates how to use the PatternScanner, ProtectionManager,
 * and RegionEnumerator modules from the Sentinel Core library.
 */

#include <Sentinel/Core/PatternScanner.hpp>
#include <Sentinel/Core/ProtectionManager.hpp>
#include <Sentinel/Core/RegionEnumerator.hpp>
#include <iostream>
#include <iomanip>

using namespace Sentinel::Core::Memory;

// Example 1: Pattern Scanning
void demonstratePatternScanning() {
    std::cout << "=== Pattern Scanning Demo ===" << std::endl;
    
    // Compile an IDA-style pattern
    auto pattern = PatternScanner::compilePattern("48 8B ? ? 90");
    if (pattern.isFailure()) {
        std::cout << "Failed to compile pattern" << std::endl;
        return;
    }
    
    std::cout << "Pattern compiled: " << pattern.value().original << std::endl;
    std::cout << "Pattern size: " << pattern.value().size() << " bytes" << std::endl;
    std::cout << "Mask: ";
    for (bool m : pattern.value().mask) {
        std::cout << (m ? "X" : "?");
    }
    std::cout << std::endl;
    
    // Example: Search in a buffer
    uint8_t buffer[] = {
        0x90, 0x90, 0x48, 0x8B, 0x01, 0x02, 0x90, // Pattern at offset 2
        0x90, 0x48, 0x8B, 0xFF, 0xFF, 0x90, 0x00  // Pattern at offset 8
    };
    
    auto results = PatternScanner::scan(
        reinterpret_cast<Sentinel::Address>(buffer),
        sizeof(buffer),
        pattern.value()
    );
    
    if (results.isSuccess()) {
        std::cout << "Found " << results.value().size() << " matches" << std::endl;
        for (const auto& result : results.value()) {
            std::cout << "  Match at offset: " 
                      << (result.address - reinterpret_cast<Sentinel::Address>(buffer))
                      << std::endl;
        }
    }
    
    std::cout << std::endl;
}

// Example 2: Region Enumeration
void demonstrateRegionEnumeration() {
    std::cout << "=== Region Enumeration Demo ===" << std::endl;
    
    RegionEnumerator enumerator;
    
    if (!enumerator.isValid()) {
        std::cout << "Note: Region enumeration not supported on this platform" << std::endl;
        std::cout << std::endl;
        return;
    }
    
    // Enumerate all regions
    auto allRegions = enumerator.enumerateAll();
    if (allRegions.isSuccess()) {
        std::cout << "Total regions: " << allRegions.value().size() << std::endl;
    }
    
    // Get executable regions
    auto execRegions = enumerator.getExecutableRegions();
    if (execRegions.isSuccess()) {
        std::cout << "Executable regions: " << execRegions.value().size() << std::endl;
        
        // Show first few executable regions
        for (size_t i = 0; i < std::min(size_t(3), execRegions.value().size()); ++i) {
            const auto& region = execRegions.value()[i];
            std::cout << "  Region #" << i << ": "
                      << std::hex << std::setw(16) << std::setfill('0') 
                      << region.baseAddress
                      << " Size: " << std::dec << (region.regionSize / 1024) << " KB";
            if (!region.moduleName.empty()) {
                std::cout << " (" << region.moduleName << ")";
            }
            std::cout << std::endl;
        }
    }
    
    std::cout << std::endl;
}

// Example 3: Protection Manager
void demonstrateProtectionManager() {
    std::cout << "=== Protection Manager Demo ===" << std::endl;
    
    ProtectionManager manager;
    
    std::cout << "Protection manager active: " 
              << (manager.isActive() ? "Yes" : "No") << std::endl;
    std::cout << "Access count: " << manager.getAccessCount() << std::endl;
    
#ifdef _WIN32
    // On Windows, we can actually install guard pages
    std::cout << "\nNote: Guard page installation is Windows-specific" << std::endl;
    std::cout << "Use PAGE_GUARD to detect when memory is accessed" << std::endl;
    std::cout << "VEH (Vectored Exception Handler) catches guard page violations" << std::endl;
#else
    std::cout << "\nNote: Guard pages not supported on this platform" << std::endl;
#endif
    
    std::cout << std::endl;
}

// Example 4: Integration - Scan executable regions for patterns
void demonstrateIntegration() {
    std::cout << "=== Integration Demo ===" << std::endl;
    
    RegionEnumerator enumerator;
    
    if (!enumerator.isValid()) {
        std::cout << "Region enumeration not supported on this platform" << std::endl;
        std::cout << std::endl;
        return;
    }
    
    // Get executable regions
    auto execRegions = enumerator.getExecutableRegions();
    if (execRegions.isFailure()) {
        std::cout << "Failed to enumerate executable regions" << std::endl;
        return;
    }
    
    // Compile a simple pattern (NOP instruction)
    auto pattern = PatternScanner::compilePattern("90");
    if (pattern.isFailure()) {
        std::cout << "Failed to compile pattern" << std::endl;
        return;
    }
    
    std::cout << "Scanning executable regions for NOP (0x90) instruction..." << std::endl;
    
    size_t totalMatches = 0;
    for (const auto& region : execRegions.value()) {
        // Limit scan size to avoid long scans
        size_t scanSize = std::min(region.regionSize, size_t(4096));
        
        auto results = PatternScanner::scan(
            region.baseAddress,
            scanSize,
            pattern.value(),
            10  // Max 10 results per region
        );
        
        if (results.isSuccess() && !results.value().empty()) {
            totalMatches += results.value().size();
            std::cout << "  Found " << results.value().size() 
                      << " matches in region at 0x" << std::hex << region.baseAddress;
            if (!region.moduleName.empty()) {
                std::cout << " (" << region.moduleName << ")";
            }
            std::cout << std::dec << std::endl;
        }
    }
    
    std::cout << "Total matches found: " << totalMatches << std::endl;
    std::cout << std::endl;
}

int main() {
    std::cout << "Sentinel Memory Module Demonstration" << std::endl;
    std::cout << "=====================================" << std::endl;
    std::cout << std::endl;
    
    demonstratePatternScanning();
    demonstrateRegionEnumeration();
    demonstrateProtectionManager();
    demonstrateIntegration();
    
    std::cout << "Demo complete!" << std::endl;
    
    return 0;
}
