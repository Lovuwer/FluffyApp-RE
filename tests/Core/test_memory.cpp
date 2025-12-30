/**
 * Sentinel Core Library - Memory Module Tests
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Tests for PatternScanner, ProtectionManager, and RegionEnumerator
 */

#include <gtest/gtest.h>
#include <Sentinel/Core/PatternScanner.hpp>
#include <Sentinel/Core/ProtectionManager.hpp>
#include <Sentinel/Core/RegionEnumerator.hpp>
#include <vector>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace Sentinel::Core::Memory;

// ============================================================================
// PatternScanner Tests
// ============================================================================

TEST(PatternScannerTests, CompileValidPattern) {
    auto result = PatternScanner::compilePattern("48 8B 5C 24 10");
    
    ASSERT_TRUE(result.isSuccess()) << "Pattern compilation should succeed";
    EXPECT_TRUE(result.value().isValid());
    EXPECT_EQ(result.value().size(), 5);
    EXPECT_EQ(result.value().bytes[0], 0x48);
    EXPECT_EQ(result.value().bytes[1], 0x8B);
    EXPECT_EQ(result.value().bytes[2], 0x5C);
    EXPECT_EQ(result.value().bytes[3], 0x24);
    EXPECT_EQ(result.value().bytes[4], 0x10);
}

TEST(PatternScannerTests, CompilePatternWithWildcards) {
    auto result = PatternScanner::compilePattern("48 8B ? ? 90");
    
    ASSERT_TRUE(result.isSuccess()) << "Pattern with wildcards should compile";
    EXPECT_TRUE(result.value().isValid());
    EXPECT_EQ(result.value().size(), 5);
    EXPECT_TRUE(result.value().mask[0]);  // 48 - must match
    EXPECT_TRUE(result.value().mask[1]);  // 8B - must match
    EXPECT_FALSE(result.value().mask[2]); // ? - wildcard
    EXPECT_FALSE(result.value().mask[3]); // ? - wildcard
    EXPECT_TRUE(result.value().mask[4]);  // 90 - must match
}

TEST(PatternScannerTests, CompilePatternWithDoubleQuestionMarks) {
    auto result = PatternScanner::compilePattern("48 ?? 5C ?? 90");
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_EQ(result.value().size(), 5);
    EXPECT_TRUE(result.value().mask[0]);
    EXPECT_FALSE(result.value().mask[1]);
    EXPECT_TRUE(result.value().mask[2]);
    EXPECT_FALSE(result.value().mask[3]);
    EXPECT_TRUE(result.value().mask[4]);
}

TEST(PatternScannerTests, CompileInvalidPattern) {
    auto result = PatternScanner::compilePattern("48 8B ZZ");
    
    EXPECT_TRUE(result.isFailure()) << "Invalid hex should fail";
}

TEST(PatternScannerTests, CompileEmptyPattern) {
    auto result = PatternScanner::compilePattern("");
    
    EXPECT_TRUE(result.isFailure()) << "Empty pattern should fail";
}

TEST(PatternScannerTests, ScanFindsKnownBytes) {
    // Create a test buffer with known pattern
    std::vector<uint8_t> buffer(1024);
    
    // Insert pattern at offset 100: 48 8B 5C 24 10
    buffer[100] = 0x48;
    buffer[101] = 0x8B;
    buffer[102] = 0x5C;
    buffer[103] = 0x24;
    buffer[104] = 0x10;
    
    auto pattern = PatternScanner::compilePattern("48 8B 5C 24 10");
    ASSERT_TRUE(pattern.isSuccess());
    
    auto results = PatternScanner::scan(
        reinterpret_cast<Sentinel::Address>(buffer.data()),
        buffer.size(),
        pattern.value()
    );
    
    ASSERT_TRUE(results.isSuccess()) << "Scan should succeed";
    ASSERT_FALSE(results.value().empty()) << "Should find at least one match";
    EXPECT_EQ(results.value()[0].address, 
              reinterpret_cast<Sentinel::Address>(buffer.data()) + 100);
}

TEST(PatternScannerTests, ScanWithWildcardFindsPattern) {
    std::vector<uint8_t> buffer(1024);
    
    // Insert pattern: 48 8B [anything] [anything] 90
    buffer[200] = 0x48;
    buffer[201] = 0x8B;
    buffer[202] = 0xAA; // wildcard
    buffer[203] = 0xBB; // wildcard
    buffer[204] = 0x90;
    
    auto pattern = PatternScanner::compilePattern("48 8B ? ? 90");
    ASSERT_TRUE(pattern.isSuccess());
    
    auto results = PatternScanner::scan(
        reinterpret_cast<Sentinel::Address>(buffer.data()),
        buffer.size(),
        pattern.value()
    );
    
    ASSERT_TRUE(results.isSuccess());
    ASSERT_FALSE(results.value().empty()) << "Should find pattern with wildcards";
    EXPECT_EQ(results.value()[0].address,
              reinterpret_cast<Sentinel::Address>(buffer.data()) + 200);
}

TEST(PatternScannerTests, FindFirstReturnsFirstMatch) {
    std::vector<uint8_t> buffer(1024);
    
    // Insert pattern twice
    buffer[50] = 0x90;
    buffer[100] = 0x90;
    
    auto pattern = PatternScanner::compilePattern("90");
    ASSERT_TRUE(pattern.isSuccess());
    
    auto result = PatternScanner::findFirst(
        reinterpret_cast<Sentinel::Address>(buffer.data()),
        buffer.size(),
        pattern.value()
    );
    
    ASSERT_TRUE(result.isSuccess());
    ASSERT_TRUE(result.value().has_value()) << "Should find a match";
    EXPECT_EQ(result.value()->address,
              reinterpret_cast<Sentinel::Address>(buffer.data()) + 50);
}

TEST(PatternScannerTests, ScanWithMaxResultsLimits) {
    std::vector<uint8_t> buffer(1024, 0x90); // Fill with 0x90
    
    auto pattern = PatternScanner::compilePattern("90");
    ASSERT_TRUE(pattern.isSuccess());
    
    auto results = PatternScanner::scan(
        reinterpret_cast<Sentinel::Address>(buffer.data()),
        buffer.size(),
        pattern.value(),
        10 // Max 10 results
    );
    
    ASSERT_TRUE(results.isSuccess());
    EXPECT_LE(results.value().size(), 10) << "Should respect max results limit";
}

// ============================================================================
// ProtectionManager Tests
// ============================================================================

#ifdef _WIN32
TEST(ProtectionManagerTests, ConstructionAndDestruction) {
    ProtectionManager manager;
    
    EXPECT_TRUE(manager.isActive()) << "Manager should be active after construction";
    EXPECT_EQ(manager.getAccessCount(), 0) << "Access count should start at 0";
}

TEST(ProtectionManagerTests, InstallGuardPageOnValidMemory) {
    ProtectionManager manager;
    
    // Allocate a page
    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr) << "Failed to allocate memory";
    
    auto result = manager.installGuardPage(
        reinterpret_cast<Sentinel::Address>(page),
        4096
    );
    
    EXPECT_TRUE(result.isSuccess()) << "Installing guard page should succeed";
    
    // Clean up
    manager.removeGuardPage(reinterpret_cast<Sentinel::Address>(page), 4096);
    VirtualFree(page, 0, MEM_RELEASE);
}

TEST(ProtectionManagerTests, GuardPageTriggersVEHOnAccess) {
    ProtectionManager manager;
    
    // Allocate a page
    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);
    
    std::atomic<bool> callbackInvoked{false};
    std::atomic<Sentinel::Address> accessedAddress{0};
    
    manager.setGuardPageCallback([&](const GuardPageAccess& access) {
        callbackInvoked.store(true, std::memory_order_release);
        accessedAddress.store(access.address, std::memory_order_release);
    });
    
    auto result = manager.installGuardPage(
        reinterpret_cast<Sentinel::Address>(page),
        4096
    );
    ASSERT_TRUE(result.isSuccess());
    
    // Access the page (should trigger guard page exception)
    volatile uint8_t* ptr = static_cast<volatile uint8_t*>(page);
    uint8_t value = *ptr; // This will trigger the guard page
    (void)value;
    
    // Poll for callback completion with timeout
    for (int i = 0; i < 100 && !callbackInvoked.load(std::memory_order_acquire); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    EXPECT_TRUE(callbackInvoked.load(std::memory_order_acquire)) 
        << "Guard page callback should be invoked";
    EXPECT_EQ(manager.getAccessCount(), 1) << "Access count should be incremented";
    
    // Clean up
    VirtualFree(page, 0, MEM_RELEASE);
}

TEST(ProtectionManagerTests, RemoveGuardPageRestoresProtection) {
    ProtectionManager manager;
    
    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);
    
    auto installResult = manager.installGuardPage(
        reinterpret_cast<Sentinel::Address>(page),
        4096
    );
    ASSERT_TRUE(installResult.isSuccess());
    
    auto removeResult = manager.removeGuardPage(
        reinterpret_cast<Sentinel::Address>(page),
        4096
    );
    EXPECT_TRUE(removeResult.isSuccess()) << "Removing guard page should succeed";
    
    VirtualFree(page, 0, MEM_RELEASE);
}

TEST(ProtectionManagerTests, ResetAccessCount) {
    ProtectionManager manager;
    
    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);
    
    manager.installGuardPage(reinterpret_cast<Sentinel::Address>(page), 4096);
    
    // Trigger access
    volatile uint8_t* ptr = static_cast<volatile uint8_t*>(page);
    uint8_t value = *ptr;
    (void)value;
    
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    EXPECT_GT(manager.getAccessCount(), 0);
    
    manager.resetAccessCount();
    EXPECT_EQ(manager.getAccessCount(), 0) << "Access count should be reset";
    
    VirtualFree(page, 0, MEM_RELEASE);
}
#endif // _WIN32

// ============================================================================
// RegionEnumerator Tests
// ============================================================================

TEST(RegionEnumeratorTests, ConstructionForCurrentProcess) {
    RegionEnumerator enumerator;
    
    EXPECT_TRUE(enumerator.isValid()) << "Enumerator should be valid";
}

TEST(RegionEnumeratorTests, EnumerateAllReturnsRegions) {
    RegionEnumerator enumerator;
    
    auto result = enumerator.enumerateAll();
    
    ASSERT_TRUE(result.isSuccess()) << "Enumeration should succeed";
    EXPECT_FALSE(result.value().empty()) << "Should find at least some regions";
}

TEST(RegionEnumeratorTests, GetExecutableRegions) {
    RegionEnumerator enumerator;
    
    auto result = enumerator.getExecutableRegions();
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_FALSE(result.value().empty()) << "Should find executable regions";
    
    // Verify all regions are actually executable
    for (const auto& region : result.value()) {
        EXPECT_TRUE(region.isExecutable()) << "Region should be executable";
    }
}

TEST(RegionEnumeratorTests, GetWritableRegions) {
    RegionEnumerator enumerator;
    
    auto result = enumerator.getWritableRegions();
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_FALSE(result.value().empty()) << "Should find writable regions";
    
    // Verify all regions are actually writable
    for (const auto& region : result.value()) {
        EXPECT_TRUE(region.isWritable()) << "Region should be writable";
    }
}

TEST(RegionEnumeratorTests, FindTextSection) {
    RegionEnumerator enumerator;
    
    // Try to find .text section of current executable
    // On Windows, use the executable name
#ifdef _WIN32
    char moduleName[MAX_PATH];
    GetModuleFileNameA(nullptr, moduleName, MAX_PATH);
    std::string exeName = moduleName;
    size_t pos = exeName.find_last_of("\\/");
    if (pos != std::string::npos) {
        exeName = exeName.substr(pos + 1);
    }
    
    auto result = enumerator.getTextSection(exeName);
    
    if (result.isSuccess()) {
        EXPECT_TRUE(result.value().isExecutable()) 
            << ".text section should be executable";
        EXPECT_FALSE(result.value().isWritable())
            << ".text section should not be writable";
    }
#endif
}

TEST(RegionEnumeratorTests, GetImageRegions) {
    RegionEnumerator enumerator;
    
    auto result = enumerator.getImageRegions();
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_FALSE(result.value().empty()) << "Should find at least one IMAGE region";
    
    // Verify all regions are IMAGE type
    for (const auto& region : result.value()) {
        EXPECT_EQ(region.type, Sentinel::MemoryType::Image);
    }
}

TEST(RegionEnumeratorTests, FindRegionContainingAddress) {
    RegionEnumerator enumerator;
    
    // Use address of enumerator object (stack variable)
    Sentinel::Address testAddress = reinterpret_cast<Sentinel::Address>(&enumerator);
    
    auto result = enumerator.findRegionContaining(testAddress);
    
    ASSERT_TRUE(result.isSuccess()) << "Should find region containing test data";
    EXPECT_LE(result.value().baseAddress, testAddress);
    EXPECT_GT(result.value().baseAddress + result.value().regionSize, testAddress);
}

TEST(RegionEnumeratorTests, FilterFunctions) {
    RegionEnumerator enumerator;
    
    auto allRegions = enumerator.enumerateAll();
    ASSERT_TRUE(allRegions.isSuccess());
    
    // Test filter functions
    int execCount = 0, writeCount = 0, readCount = 0;
    for (const auto& region : allRegions.value()) {
        if (RegionEnumerator::filterExecutable(region)) execCount++;
        if (RegionEnumerator::filterWritable(region)) writeCount++;
        if (RegionEnumerator::filterReadable(region)) readCount++;
    }
    
    EXPECT_GT(execCount, 0) << "Should have executable regions";
    EXPECT_GT(writeCount, 0) << "Should have writable regions";
    EXPECT_GT(readCount, 0) << "Should have readable regions";
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST(MemoryIntegrationTests, PatternScanWithRegionEnumeration) {
    RegionEnumerator enumerator;
    
    // Get executable regions
    auto regions = enumerator.getExecutableRegions();
    ASSERT_TRUE(regions.isSuccess());
    ASSERT_FALSE(regions.value().empty());
    
    // Try to scan for a NOP instruction (0x90) in first executable region
    const auto& region = regions.value()[0];
    
    auto pattern = PatternScanner::compilePattern("90");
    ASSERT_TRUE(pattern.isSuccess());
    
    auto results = PatternScanner::scan(
        region.baseAddress,
        std::min(region.regionSize, size_t(4096)), // Limit scan size
        pattern.value(),
        5 // Max 5 results
    );
    
    // We don't assert finding results as it depends on the actual code,
    // but the scan itself should not crash or fail
    EXPECT_TRUE(results.isSuccess());
}
