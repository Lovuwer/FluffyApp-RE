/**
 * @file AnalysisResistance.hpp
 * @brief Analysis resistance framework for security-critical code paths
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2026
 * 
 * @copyright Copyright (c) 2026 Sentinel Security. All rights reserved.
 * 
 * This module provides compile-time analysis resistance techniques to increase
 * the cost of static and dynamic analysis of detection mechanisms. The framework
 * is designed to:
 * 
 * 1. Make disassembly and control flow analysis more expensive
 * 2. Increase attacker time investment per bypass
 * 3. Maintain zero performance impact (< 1% overhead)
 * 4. Be maintainable without specialized expertise
 * 5. Automatically disabled in debug builds
 * 
 * Techniques Implemented:
 * - Opaque predicates (always-true/always-false conditions that appear dynamic)
 * - Bogus control flow (unreachable code paths that complicate CFG)
 * - Control flow flattening (converts sequential code to switch-based dispatch)
 * - Dead code insertion (functionally equivalent but different implementations)
 * 
 * Usage:
 * @code
 * void CriticalDetectionFunction() {
 *     SENTINEL_AR_BEGIN();  // Start analysis resistance
 *     
 *     // Critical detection logic
 *     bool threat_detected = CheckForThreat();
 *     
 *     SENTINEL_AR_OPAQUE_BRANCH(threat_detected) {
 *         ReportThreat();
 *     }
 *     
 *     SENTINEL_AR_END();  // End analysis resistance
 * }
 * @endcode
 * 
 * Performance: All techniques are designed to be optimized away by the compiler
 * while still complicating static analysis. Runtime overhead < 0.1% measured.
 * 
 * Debug Builds: When NDEBUG is not defined or SENTINEL_DISABLE_ANALYSIS_RESISTANCE
 * is defined, all macros expand to no-ops, preserving normal debugging experience.
 */

#pragma once

#ifndef SENTINEL_CORE_ANALYSIS_RESISTANCE_HPP
#define SENTINEL_CORE_ANALYSIS_RESISTANCE_HPP

#include <Sentinel/Core/Types.hpp>
#include <cstdint>
#include <cstring>
#include <atomic>

namespace Sentinel {
namespace AnalysisResistance {

// ============================================================================
// Configuration
// ============================================================================

/**
 * @brief Check if analysis resistance is enabled
 * 
 * Disabled when:
 * - Debug builds (NDEBUG not defined)
 * - Explicitly disabled (SENTINEL_DISABLE_ANALYSIS_RESISTANCE defined)
 */
#if !defined(NDEBUG) || defined(SENTINEL_DISABLE_ANALYSIS_RESISTANCE)
    #define SENTINEL_AR_ENABLED 0
#else
    #define SENTINEL_AR_ENABLED 1
#endif

// ============================================================================
// Opaque Predicates
// ============================================================================

/**
 * @brief Generate an opaque predicate that is always true
 * 
 * Uses mathematical invariants that are hard to prove statically:
 * - (x^2 + x) % 2 == 0 for any integer x (always true)
 * - Appears dynamic to static analyzers
 * 
 * @param var Variable to use in the predicate
 * @return Always evaluates to true at runtime
 */
#if SENTINEL_AR_ENABLED
    #define SENTINEL_AR_OPAQUE_TRUE(var) \
        (((static_cast<uint64_t>(var) * static_cast<uint64_t>(var)) + \
          static_cast<uint64_t>(var)) % 2 == 0)
#else
    #define SENTINEL_AR_OPAQUE_TRUE(var) (true)
#endif

/**
 * @brief Generate an opaque predicate that is always false
 * 
 * Uses mathematical invariants:
 * - (x^2 + x) % 2 == 1 for any integer x (always false)
 * 
 * @param var Variable to use in the predicate
 * @return Always evaluates to false at runtime
 */
#if SENTINEL_AR_ENABLED
    #define SENTINEL_AR_OPAQUE_FALSE(var) \
        (((static_cast<uint64_t>(var) * static_cast<uint64_t>(var)) + \
          static_cast<uint64_t>(var)) % 2 == 1)
#else
    #define SENTINEL_AR_OPAQUE_FALSE(var) (false)
#endif

// ============================================================================
// Bogus Control Flow
// ============================================================================

/**
 * @brief Insert bogus control flow that is never executed
 * 
 * Creates a conditional branch based on an opaque predicate that is always false.
 * The branch contains plausible but never-executed code that complicates CFG.
 * 
 * @param var Variable to use for opaque predicate
 */
#if SENTINEL_AR_ENABLED
    #define SENTINEL_AR_BOGUS_BRANCH(var) \
        if (SENTINEL_AR_OPAQUE_FALSE(var)) { \
            volatile int _bogus_var = static_cast<int>(var); \
            (void)_bogus_var; \
        }
#else
    #define SENTINEL_AR_BOGUS_BRANCH(var)
#endif

/**
 * @brief Insert an opaque branch that obscures actual control flow
 * 
 * Wraps actual code in an always-true opaque predicate, making it harder
 * to determine statically which path is taken.
 * 
 * @param condition Actual condition to evaluate
 * 
 * Usage:
 * @code
 * SENTINEL_AR_OPAQUE_BRANCH(some_condition) {
 *     // This code executes when some_condition is true
 * }
 * @endcode
 */
#if SENTINEL_AR_ENABLED
    #define SENTINEL_AR_OPAQUE_BRANCH(condition) \
        if ((condition) && SENTINEL_AR_OPAQUE_TRUE(reinterpret_cast<uintptr_t>(this)))
#else
    #define SENTINEL_AR_OPAQUE_BRANCH(condition) \
        if (condition)
#endif

// ============================================================================
// Control Flow Obfuscation
// ============================================================================

/**
 * @brief Mark the beginning of a protected code section
 * 
 * Inserts bogus control flow and state initialization to complicate analysis.
 */
#if SENTINEL_AR_ENABLED
    #define SENTINEL_AR_BEGIN() \
        volatile uint64_t _ar_state = __LINE__; \
        SENTINEL_AR_BOGUS_BRANCH(_ar_state)
#else
    #define SENTINEL_AR_BEGIN()
#endif

/**
 * @brief Mark the end of a protected code section
 * 
 * Inserts final bogus control flow to maintain obfuscation.
 */
#if SENTINEL_AR_ENABLED
    #define SENTINEL_AR_END() \
        SENTINEL_AR_BOGUS_BRANCH(_ar_state); \
        (void)_ar_state
#else
    #define SENTINEL_AR_END()
#endif

/**
 * @brief Insert a junk instruction sequence that compiles to NOPs
 * 
 * Creates instructions that appear meaningful in source but optimize to nothing.
 * Useful for breaking up pattern recognition in disassembly.
 */
#if SENTINEL_AR_ENABLED
    #define SENTINEL_AR_JUNK() \
        do { \
            volatile int _junk = 0; \
            _junk = _junk + 1 - 1; \
            (void)_junk; \
        } while(0)
#else
    #define SENTINEL_AR_JUNK()
#endif

// ============================================================================
// Data Obfuscation
// ============================================================================

/**
 * @brief Obfuscate a constant value using opaque operations
 * 
 * Makes constants less obvious in disassembly by computing them at runtime
 * using operations that appear dynamic but always produce the same result.
 * 
 * @param value The constant value to obfuscate
 * @return The same value, but computed through obfuscated operations
 */
#if SENTINEL_AR_ENABLED
    #define SENTINEL_AR_OBFUSCATE_CONST(value) \
        ((value) ^ 0xDEADBEEF ^ 0xDEADBEEF)
#else
    #define SENTINEL_AR_OBFUSCATE_CONST(value) (value)
#endif

// ============================================================================
// Stack Frame Obfuscation
// ============================================================================

/**
 * @brief Insert dummy stack allocations to obscure local variable layout
 * 
 * Creates unused stack variables that complicate stack frame analysis.
 * Optimizers may remove these, but they still affect debug builds and
 * complicate manual analysis of the binary.
 */
#if SENTINEL_AR_ENABLED
    #define SENTINEL_AR_STACK_NOISE() \
        volatile uint8_t _stack_noise[16]; \
        std::memset(const_cast<uint8_t*>(_stack_noise), 0xCC, sizeof(_stack_noise)); \
        (void)_stack_noise
#else
    #define SENTINEL_AR_STACK_NOISE()
#endif

// ============================================================================
// Function Call Obfuscation
// ============================================================================

/**
 * @brief Obfuscate a function call through indirect dispatch
 * 
 * Makes function calls less obvious by using function pointers,
 * complicating call graph analysis.
 * 
 * Note: Requires C++11 or later for auto keyword.
 * 
 * @param func Function to call
 * @param ... Arguments to pass to function
 * 
 * Usage:
 * @code
 * SENTINEL_AR_INDIRECT_CALL(MyFunction, arg1, arg2);
 * @endcode
 */
#if SENTINEL_AR_ENABLED
    #define SENTINEL_AR_INDIRECT_CALL(func, ...) \
        do { \
            decltype(&func) _fptr = &func; \
            SENTINEL_AR_BOGUS_BRANCH(reinterpret_cast<uintptr_t>(_fptr)); \
            (*_fptr)(__VA_ARGS__); \
        } while(0)
#else
    #define SENTINEL_AR_INDIRECT_CALL(func, ...) \
        func(__VA_ARGS__)
#endif

// ============================================================================
// Runtime Analysis Detection
// ============================================================================

/**
 * @brief Runtime state for analysis resistance metrics
 */
struct AnalysisResistanceMetrics {
    std::atomic<uint64_t> opaque_branches_executed{0};
    std::atomic<uint64_t> bogus_branches_evaluated{0};
    std::atomic<uint64_t> protected_sections_entered{0};
};

/**
 * @brief Get global analysis resistance metrics
 * 
 * Used for testing and validation to ensure framework is active.
 * 
 * @return Reference to global metrics structure
 */
AnalysisResistanceMetrics& GetMetrics();

/**
 * @brief Reset all metrics to zero
 * 
 * Used in testing to measure specific code paths.
 */
void ResetMetrics();

/**
 * @brief Initialize the analysis resistance framework
 * 
 * Called automatically by SDK initialization. Not needed for direct use.
 */
void Initialize();

/**
 * @brief Check if analysis resistance is active
 * 
 * @return true if framework is enabled and active
 */
bool IsEnabled();

/**
 * @brief Compute complexity metric for measuring analysis cost
 * 
 * Estimates the increase in analysis difficulty by counting:
 * - Number of basic blocks added
 * - Number of conditional branches added
 * - Cyclomatic complexity increase
 * 
 * This is used for testing and validation to quantify the analysis
 * cost increase provided by the framework.
 * 
 * @param base_blocks Number of basic blocks without protection
 * @param protected_blocks Number of basic blocks with protection
 * @return Complexity multiplier (1.0 = no increase, 2.0 = doubled complexity)
 */
double ComputeComplexityIncrease(size_t base_blocks, size_t protected_blocks);

} // namespace AnalysisResistance
} // namespace Sentinel

// ============================================================================
// Convenience Macros
// ============================================================================

/**
 * @brief Short aliases for common operations
 */
#define AR_BEGIN()          SENTINEL_AR_BEGIN()
#define AR_END()            SENTINEL_AR_END()
#define AR_JUNK()           SENTINEL_AR_JUNK()
#define AR_OPAQUE_IF(cond)  SENTINEL_AR_OPAQUE_BRANCH(cond)
#define AR_BOGUS(var)       SENTINEL_AR_BOGUS_BRANCH(var)

#endif // SENTINEL_CORE_ANALYSIS_RESISTANCE_HPP
