/**
 * Sentinel SDK - Redundant AntiDebug Implementations
 * 
 * Task 29: Implement Redundant Detection Architecture
 * 
 * Provides multiple independent anti-debug implementations using
 * different detection approaches to increase attacker cost.
 * 
 * Primary Implementation: Uses existing comprehensive approach
 * Alternative Implementation: Uses different technique set
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#pragma once

#include "DetectionRegistry.hpp"
#include "Detection.hpp"
#include <memory>

namespace Sentinel {
namespace SDK {

/**
 * Primary AntiDebug Implementation
 * 
 * Wraps the existing AntiDebugDetector with comprehensive checks:
 * - PEB checks (BeingDebugged, NtGlobalFlag, heap flags)
 * - Debug port and debug object handles
 * - Hardware breakpoint detection
 * - Timing anomaly detection
 * - SEH integrity checks
 */
class AntiDebugPrimaryImpl : public IDetectionImplementation {
public:
    AntiDebugPrimaryImpl();
    ~AntiDebugPrimaryImpl() override = default;
    
    DetectionType GetCategory() const override {
        return DetectionType::AntiDebug;
    }
    
    const char* GetImplementationId() const override {
        return "antidebug_primary_comprehensive";
    }
    
    const char* GetDescription() const override {
        return "Comprehensive anti-debug using PEB, debug ports, timing, and SEH checks";
    }
    
    std::vector<ViolationEvent> QuickCheck() override;
    std::vector<ViolationEvent> FullCheck() override;
    void Initialize() override;
    void Shutdown() override;
    
private:
    std::unique_ptr<AntiDebugDetector> detector_;
};

/**
 * Alternative AntiDebug Implementation
 * 
 * Uses a different approach focusing on:
 * - Direct syscall verification (bypassing API hooks)
 * - Process environment inspection
 * - Thread context analysis
 * - Memory access pattern detection
 * 
 * This alternative approach complements the primary implementation
 * by using different detection techniques that require separate bypasses.
 */
class AntiDebugAlternativeImpl : public IDetectionImplementation {
public:
    AntiDebugAlternativeImpl();
    ~AntiDebugAlternativeImpl() override = default;
    
    DetectionType GetCategory() const override {
        return DetectionType::AntiDebug;
    }
    
    const char* GetImplementationId() const override {
        return "antidebug_alternative_syscall";
    }
    
    const char* GetDescription() const override {
        return "Alternative anti-debug using direct syscalls and process environment checks";
    }
    
    std::vector<ViolationEvent> QuickCheck() override;
    std::vector<ViolationEvent> FullCheck() override;
    void Initialize() override;
    void Shutdown() override;
    
private:
    // Alternative detection methods
    bool CheckViaProcessEnvironment();
    bool CheckViaThreadContext();
    bool CheckViaMemoryAccessPatterns();
    bool CheckViaSyscallDirect();
    
    // State tracking
    uint64_t last_check_time_;
    int consecutive_detections_;
};

} // namespace SDK
} // namespace Sentinel
