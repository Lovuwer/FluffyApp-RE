/**
 * Sentinel SDK - Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 11: Inline Hook Detection Implementation
 */

#include "Internal/Detection.hpp"
#include <algorithm>
#include <cstring>
#include <chrono>

namespace Sentinel {
namespace SDK {

namespace {
    // Common hook patterns (x86/x64)
    struct HookPattern {
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> mask;  // 0xFF = must match, 0x00 = wildcard
        const char* description;
    };
    
    const std::vector<HookPattern> HOOK_PATTERNS = {
        // JMP rel32 (5 bytes) - E9 XX XX XX XX
        {{0xE9}, {0xFF}, "JMP rel32"},
        
        // JMP [rip+0] (6 bytes) - FF 25 00 00 00 00
        {{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}, 
         {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, "JMP [rip+0]"},
        
        // MOV RAX, imm64; JMP RAX (12 bytes) - 48 B8 XX XX XX XX XX XX XX XX FF E0
        {{0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0},
         {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF},
         "MOV RAX, imm64; JMP RAX"},
        
        // PUSH addr; RET (6 bytes, x86) - 68 XX XX XX XX C3
        {{0x68, 0x00, 0x00, 0x00, 0x00, 0xC3},
         {0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF}, "PUSH imm32; RET"},
        
        // INT 3 (breakpoint, 1 byte) - CC
        {{0xCC}, {0xFF}, "INT 3 breakpoint"},
    };
    
    bool MatchesPattern(const uint8_t* bytes, const HookPattern& pattern) {
        for (size_t i = 0; i < pattern.bytes.size(); i++) {
            if ((bytes[i] & pattern.mask[i]) != (pattern.bytes[i] & pattern.mask[i])) {
                return false;
            }
        }
        return true;
    }
}

// AntiHookDetector implementation
void AntiHookDetector::Initialize() {}

void AntiHookDetector::Shutdown() {}

bool AntiHookDetector::IsInlineHooked(const FunctionProtection& func) {
    // Read current bytes at function address
    const uint8_t* currentBytes = reinterpret_cast<const uint8_t*>(func.address);
    
    // Compare with original prologue
    if (memcmp(currentBytes, func.original_prologue.data(), func.prologue_size) != 0) {
        // Bytes changed - check for hook patterns
        for (const auto& pattern : HOOK_PATTERNS) {
            if (pattern.bytes.size() <= func.prologue_size) {
                if (MatchesPattern(currentBytes, pattern)) {
                    return true;  // Hook pattern detected
                }
            }
        }
        // Bytes changed but no known pattern - still suspicious
        return true;
    }
    
    return false;
}

bool AntiHookDetector::IsIATHooked(const char*, const char*) { 
    return false; 
}

bool AntiHookDetector::HasSuspiciousJump(const void* address) {
    const uint8_t* bytes = static_cast<const uint8_t*>(address);
    
    // Check first byte for immediate jump/call indicators
    switch (bytes[0]) {
        case 0xE9:  // JMP rel32
        case 0xE8:  // CALL rel32 (unusual at function start)
        case 0xEB:  // JMP rel8
        case 0xFF:  // JMP/CALL indirect
        case 0xCC:  // INT 3
            return true;
    }
    
    // Check for 2-byte prefixes (x64)
    if (bytes[0] == 0x48 && bytes[1] == 0xB8) {
        // MOV RAX, imm64 (likely trampoline setup)
        return true;
    }
    
    return false;
}

void AntiHookDetector::RegisterFunction(const FunctionProtection& func) {
    std::lock_guard<std::mutex> lock(functions_mutex_);
    registered_functions_.push_back(func);
}

void AntiHookDetector::UnregisterFunction(uintptr_t address) {
    std::lock_guard<std::mutex> lock(functions_mutex_);
    registered_functions_.erase(
        std::remove_if(registered_functions_.begin(), registered_functions_.end(),
            [address](const FunctionProtection& f) { return f.address == address; }),
        registered_functions_.end()
    );
}

bool AntiHookDetector::CheckFunction(uintptr_t address) {
    std::lock_guard<std::mutex> lock(functions_mutex_);
    
    for (const auto& func : registered_functions_) {
        if (func.address == address) {
            return IsInlineHooked(func);
        }
    }
    
    // Not registered - do quick suspicious jump check
    return HasSuspiciousJump(reinterpret_cast<const void*>(address));
}

std::vector<ViolationEvent> AntiHookDetector::QuickCheck() {
    std::vector<ViolationEvent> violations;
    std::lock_guard<std::mutex> lock(functions_mutex_);
    
    // Check subset for performance (first 10)
    size_t checkCount = std::min(registered_functions_.size(), size_t(10));
    for (size_t i = 0; i < checkCount; i++) {
        if (IsInlineHooked(registered_functions_[i])) {
            ViolationEvent ev;
            ev.type = ViolationType::InlineHook;
            ev.severity = Severity::Critical;
            ev.address = registered_functions_[i].address;
            static const char* detail_msg = "Inline hook detected";
            ev.details = detail_msg;
            ev.module_name = nullptr;
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
            violations.push_back(ev);
        }
    }
    
    return violations;
}

std::vector<ViolationEvent> AntiHookDetector::FullScan() {
    std::vector<ViolationEvent> violations;
    std::lock_guard<std::mutex> lock(functions_mutex_);
    
    // Check all registered functions
    for (const auto& func : registered_functions_) {
        if (IsInlineHooked(func)) {
            ViolationEvent ev;
            ev.type = ViolationType::InlineHook;
            ev.severity = Severity::Critical;
            ev.address = func.address;
            static const char* detail_msg = "Inline hook detected";
            ev.details = detail_msg;
            ev.module_name = nullptr;
            ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            ev.detection_id = static_cast<uint32_t>(ev.address ^ ev.timestamp);
            violations.push_back(ev);
        }
    }
    
    return violations;
}

} // namespace SDK
} // namespace Sentinel
