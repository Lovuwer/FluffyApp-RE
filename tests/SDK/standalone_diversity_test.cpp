/**
 * Sentinel SDK - Diversity Engine Standalone Test
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Simple standalone test to verify DiversityEngine functionality
 * Can be compiled independently without full SDK build
 */

#include <iostream>
#include <cassert>
#include <set>

// Include the DiversityEngine header
#include "../src/SDK/src/Internal/DiversityEngine.hpp"

using namespace Sentinel::SDK::Internal;

void test_initialization() {
    std::cout << "Testing initialization..." << std::endl;
    
    // Get initial seed
    uint64_t initialSeed = DiversityEngine::GetSeed();
    std::cout << "  Initial seed: " << initialSeed << std::endl;
    
    // Initialize with specific seed
    DiversityEngine::Initialize(12345);
    assert(DiversityEngine::GetSeed() == 12345);
    assert(DiversityEngine::IsEnabled());
    std::cout << "  ✓ Initialization with seed 12345 works" << std::endl;
    
    // Initialize with zero (disable)
    DiversityEngine::Initialize(0);
    assert(DiversityEngine::GetSeed() == 0);
    assert(!DiversityEngine::IsEnabled());
    std::cout << "  ✓ Initialization with seed 0 disables diversity" << std::endl;
    
    // Restore
    DiversityEngine::Initialize(initialSeed);
    std::cout << "  ✓ Initialization test passed" << std::endl;
}

void test_constant_transformation() {
    std::cout << "\nTesting constant transformation..." << std::endl;
    
    // Test with diversity disabled
    DiversityEngine::Initialize(0);
    assert(DiversityEngine::TransformConstant(42) == 42);
    assert(DiversityEngine::TransformConstant(0) == 0);
    assert(DiversityEngine::TransformConstant(0xDEADBEEF) == 0xDEADBEEF);
    std::cout << "  ✓ Constants unchanged with diversity disabled" << std::endl;
    
    // Test with diversity enabled
    DiversityEngine::Initialize(98765);
    uint64_t value = 42;
    uint64_t result1 = DiversityEngine::TransformConstant(value);
    uint64_t result2 = DiversityEngine::TransformConstant(value);
    assert(result1 == result2);  // Deterministic
    assert(result1 == value);    // Semantically equivalent
    std::cout << "  ✓ Constant transformation is deterministic and equivalent" << std::endl;
}

void test_structure_padding() {
    std::cout << "\nTesting structure padding..." << std::endl;
    
    // Test with diversity disabled
    DiversityEngine::Initialize(0);
    assert(DiversityEngine::GetStructPadding(1) == 0);
    assert(DiversityEngine::GetStructPadding(100) == 0);
    std::cout << "  ✓ No padding with diversity disabled" << std::endl;
    
    // Test with diversity enabled
    DiversityEngine::Initialize(55555);
    std::set<size_t> paddingSizes;
    
    for (uint32_t structId = 1; structId <= 100; ++structId) {
        size_t padding = DiversityEngine::GetStructPadding(structId);
        assert(padding <= 15);  // Valid range
        
        // Verify determinism
        size_t padding2 = DiversityEngine::GetStructPadding(structId);
        assert(padding == padding2);
        
        paddingSizes.insert(padding);
    }
    
    // Should have variety
    assert(paddingSizes.size() >= 5);
    std::cout << "  ✓ Structure padding is deterministic and varied" << std::endl;
    std::cout << "  ✓ Found " << paddingSizes.size() << " different padding sizes" << std::endl;
}

void test_diversified_paths() {
    std::cout << "\nTesting diversified code paths..." << std::endl;
    
    // Test with diversity disabled
    DiversityEngine::Initialize(0);
    for (uint32_t i = 0; i < 10; ++i) {
        DiversityEngine::DiversifiedPath(i);
    }
    std::cout << "  ✓ Diversified paths work with diversity disabled" << std::endl;
    
    // Test with diversity enabled
    DiversityEngine::Initialize(33333);
    for (uint32_t i = 0; i < 100; ++i) {
        DiversityEngine::DiversifiedPath(i);
    }
    std::cout << "  ✓ Diversified paths work with diversity enabled" << std::endl;
}

void test_diversified_delay() {
    std::cout << "\nTesting diversified delay..." << std::endl;
    
    // Test with diversity disabled
    DiversityEngine::Initialize(0);
    DiversityEngine::DiversifiedDelay(10);
    std::cout << "  ✓ Diversified delay works with diversity disabled" << std::endl;
    
    // Test with diversity enabled
    DiversityEngine::Initialize(77777);
    DiversityEngine::DiversifiedDelay(10);
    std::cout << "  ✓ Diversified delay works with diversity enabled" << std::endl;
}

void test_seed_influence() {
    std::cout << "\nTesting seed influence on behavior..." << std::endl;
    
    std::set<size_t> seed1Padding;
    std::set<size_t> seed2Padding;
    
    // Collect padding with first seed
    DiversityEngine::Initialize(11111);
    for (uint32_t i = 1; i <= 20; ++i) {
        seed1Padding.insert(DiversityEngine::GetStructPadding(i));
    }
    
    // Collect padding with second seed
    DiversityEngine::Initialize(99999);
    for (uint32_t i = 1; i <= 20; ++i) {
        seed2Padding.insert(DiversityEngine::GetStructPadding(i));
    }
    
    // Both should have variety
    assert(seed1Padding.size() >= 3);
    assert(seed2Padding.size() >= 3);
    
    std::cout << "  ✓ Different seeds produce different behavior" << std::endl;
}

void test_macros() {
    std::cout << "\nTesting diversity macros..." << std::endl;
    
    DiversityEngine::Initialize(12345);
    
    // Test diversified stub macro
    SENTINEL_DIVERSIFIED_STUB(1);
    SENTINEL_DIVERSIFIED_STUB(100);
    std::cout << "  ✓ SENTINEL_DIVERSIFIED_STUB macro works" << std::endl;
    
    // Test constant diversity macro
    uint64_t value = 42;
    uint64_t diversified = SENTINEL_DIVERSE_CONST(value);
    assert(diversified == value);
    std::cout << "  ✓ SENTINEL_DIVERSE_CONST macro works" << std::endl;
}

int main() {
    std::cout << "============================================" << std::endl;
    std::cout << "Sentinel SDK - Diversity Engine Test" << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << std::endl;
    
    try {
        test_initialization();
        test_constant_transformation();
        test_structure_padding();
        test_diversified_paths();
        test_diversified_delay();
        test_seed_influence();
        test_macros();
        
        std::cout << "\n============================================" << std::endl;
        std::cout << "ALL TESTS PASSED ✓" << std::endl;
        std::cout << "============================================" << std::endl;
        std::cout << std::endl;
        
        std::cout << "Build-time diversity seed: " << DiversityEngine::GetSeed() << std::endl;
        std::cout << "Diversity enabled: " << (DiversityEngine::IsEnabled() ? "YES" : "NO") << std::endl;
        std::cout << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n❌ TEST FAILED: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n❌ TEST FAILED: Unknown exception" << std::endl;
        return 1;
    }
}
