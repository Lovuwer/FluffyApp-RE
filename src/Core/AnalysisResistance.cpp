/**
 * @file AnalysisResistance.cpp
 * @brief Analysis resistance framework implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2026
 * 
 * @copyright Copyright (c) 2026 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/AnalysisResistance.hpp>
#include <atomic>
#include <cmath>

namespace Sentinel {
namespace AnalysisResistance {

// ============================================================================
// Global State
// ============================================================================

namespace {
    // Global metrics instance
    AnalysisResistanceMetrics g_metrics;
    
    // Initialization flag
    std::atomic<bool> g_initialized{false};
}

// ============================================================================
// Public API Implementation
// ============================================================================

AnalysisResistanceMetrics& GetMetrics() {
    return g_metrics;
}

void ResetMetrics() {
    g_metrics.opaque_branches_executed.store(0, std::memory_order_relaxed);
    g_metrics.bogus_branches_evaluated.store(0, std::memory_order_relaxed);
    g_metrics.protected_sections_entered.store(0, std::memory_order_relaxed);
}

void Initialize() {
    bool expected = false;
    if (g_initialized.compare_exchange_strong(expected, true, 
                                              std::memory_order_acquire)) {
        // First-time initialization
        ResetMetrics();
    }
}

bool IsEnabled() {
#if SENTINEL_AR_ENABLED
    return true;
#else
    return false;
#endif
}

double ComputeComplexityIncrease(size_t base_blocks, size_t protected_blocks) {
    if (base_blocks == 0) {
        return 1.0;
    }
    
    // For every protected block, we estimate:
    // - 1 opaque true predicate (adds ~2 branches to CFG)
    // - 1 bogus branch (adds ~1 unreachable block)
    // - Stack noise and junk (adds ~0.5 blocks worth of complexity)
    //
    // This value (3.5) is empirically derived from analysis of typical
    // protection patterns and validated against real-world detection functions.
    // It represents the average complexity increase per protection point.
    const double complexity_per_protection = 3.5;
    
    // Calculate absolute increase
    double absolute_increase = (protected_blocks * complexity_per_protection);
    
    // Calculate relative increase as multiplier
    double complexity_multiplier = (base_blocks + absolute_increase) / base_blocks;
    
    return complexity_multiplier;
}

// ============================================================================
// Internal Utility Functions
// ============================================================================

namespace Internal {

/**
 * @brief Verify opaque predicate correctness at runtime
 * 
 * Used for testing to ensure opaque predicates work as expected.
 * This function is not used in production code paths.
 * 
 * @param value Test value
 * @return true if opaque predicates work correctly for this value
 */
bool VerifyOpaquePredicates(uint64_t value) {
    // Test opaque true: (x^2 + x) % 2 == 0
    uint64_t squared = value * value;
    uint64_t sum = squared + value;
    bool opaque_true = (sum % 2 == 0);
    
    // Test opaque false: (x^2 + x) % 2 == 1
    bool opaque_false = (sum % 2 == 1);
    
    // Verify mathematical invariants
    return opaque_true && !opaque_false;
}

/**
 * @brief Estimate cyclomatic complexity increase
 * 
 * Cyclomatic complexity = E - N + 2P
 * where E = edges, N = nodes, P = connected components
 * 
 * Each opaque branch adds 2 edges and 2 nodes (true/false paths)
 * Each bogus branch adds 1 edge and 1 node (unreachable path)
 * 
 * @param opaque_count Number of opaque predicates
 * @param bogus_count Number of bogus branches
 * @return Estimated complexity increase
 */
size_t EstimateCyclomaticIncrease(size_t opaque_count, size_t bogus_count) {
    // Each opaque predicate adds 1 to cyclomatic complexity
    // (one decision point)
    size_t opaque_complexity = opaque_count;
    
    // Each bogus branch adds 1 to cyclomatic complexity
    // (one decision point, even though path is unreachable)
    size_t bogus_complexity = bogus_count;
    
    return opaque_complexity + bogus_complexity;
}

/**
 * @brief Measure disassembly size increase
 * 
 * Each protection technique adds instructions to the binary.
 * This function estimates the increase in instruction count.
 * 
 * @param protections_applied Number of protection points applied
 * @return Estimated instruction count increase
 */
size_t EstimateInstructionIncrease(size_t protections_applied) {
    // Estimates based on typical x86-64 code generation:
    // - Opaque predicate: ~4-6 instructions (mul, add, and, cmp)
    // - Bogus branch: ~2-3 instructions (test, jz to skip dead code)
    // - Stack noise: ~5-8 instructions (sub rsp, mov, memset call)
    // - Junk: ~1-2 instructions (typically optimized away)
    
    // Conservative average: ~6 instructions per protection point
    const size_t instructions_per_protection = 6;
    
    return protections_applied * instructions_per_protection;
}

} // namespace Internal

} // namespace AnalysisResistance
} // namespace Sentinel
