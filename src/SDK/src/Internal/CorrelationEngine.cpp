/**
 * Sentinel SDK - Detection Correlation Engine Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "CorrelationEngine.hpp"
#include <cmath>
#include <algorithm>

#ifdef _WIN32
#include <Windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <psapi.h>
#else
#include <unistd.h>
#include <sys/utsname.h>
#endif

namespace Sentinel {
namespace SDK {

// Portable popcount implementation
namespace {
    inline uint32_t popcount(uint32_t x) {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_popcount(x);
#elif defined(_MSC_VER)
        return __popcnt(x);
#else
        // Fallback implementation
        uint32_t count = 0;
        while (x) {
            count += x & 1;
            x >>= 1;
        }
        return count;
#endif
    }
}

CorrelationEngine::CorrelationEngine()
    : state_{}
    , environment_{}
{
    state_.score = 0.0;
    state_.unique_categories = 0;
    state_.last_update = std::chrono::steady_clock::now();
}

CorrelationEngine::~CorrelationEngine() {
    Shutdown();
}

void CorrelationEngine::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Detect environment once at initialization
    DetectEnvironment();
    
    // Initialize correlation state
    state_.score = 0.0;
    state_.unique_categories = 0;
    state_.signals.clear();
    state_.last_update = std::chrono::steady_clock::now();
}

void CorrelationEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.signals.clear();
}

bool CorrelationEngine::ProcessViolation(
    const ViolationEvent& event,
    Severity& out_correlated_severity,
    bool& out_should_report)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Apply time decay before processing new signal
    ApplyTimeDecay();
    
    // Check if this violation should be whitelisted
    if (ShouldWhitelist(event)) {
        out_correlated_severity = Severity::Info;
        out_should_report = false;
        return false;  // Suppressed
    }
    
    // Create detection signal
    DetectionSignal signal;
    signal.type = event.type;
    signal.category = MapToCategory(event.type);
    signal.original_severity = event.severity;
    signal.timestamp = std::chrono::steady_clock::now();
    signal.details = event.details ? event.details : "";
    signal.address = event.address;
    signal.module_name = event.module_name;
    
    // Update correlation state
    UpdateCorrelation(signal);
    
    // Determine correlated severity
    out_correlated_severity = DegradeSeverity(event.severity);
    
    // Determine if should report to cloud
    // Cloud reporting requires 2+ signals minimum
    uint32_t signal_count = static_cast<uint32_t>(state_.signals.size());
    
    if (signal_count < 2) {
        // Single signal: never report to cloud, only log locally
        out_should_report = false;
    } else if (out_correlated_severity == Severity::Critical) {
        // Critical requires 2+ signals
        out_should_report = (signal_count >= MIN_SIGNALS_FOR_CRITICAL);
    } else {
        // Non-critical events can be reported with 2+ signals
        out_should_report = (out_correlated_severity >= Severity::Warning);
    }
    
    return true;  // Event passed correlation
}

bool CorrelationEngine::ShouldAllowAction(ResponseAction action) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if action requires multi-signal confirmation
    uint32_t action_bits = static_cast<uint32_t>(action);
    bool is_ban = (action_bits & static_cast<uint32_t>(ResponseAction::Ban)) != 0;
    bool is_terminate = (action_bits & static_cast<uint32_t>(ResponseAction::Terminate)) != 0;
    bool is_kick = (action_bits & static_cast<uint32_t>(ResponseAction::Kick)) != 0;
    
    if (is_ban || is_terminate) {
        // Ban and Terminate require explicit multi-signal confirmation
        uint32_t unique_count = popcount(state_.unique_categories);
        return (unique_count >= MIN_UNIQUE_SIGNALS) && 
               (state_.score >= MIN_CORRELATION_THRESHOLD);
    }
    
    if (is_kick) {
        // Kick requires at least 2 signals
        return state_.signals.size() >= 2;
    }
    
    // Other actions (Log, Report, Notify, Warn) are allowed
    return true;
}

double CorrelationEngine::GetCorrelationScore() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_.score;
}

uint32_t CorrelationEngine::GetUniqueSignalCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return popcount(state_.unique_categories);
}

void CorrelationEngine::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.score = 0.0;
    state_.unique_categories = 0;
    state_.signals.clear();
    state_.last_update = std::chrono::steady_clock::now();
}

DetectionCategory CorrelationEngine::MapToCategory(ViolationType type) const {
    switch (type) {
        // Debugger-related
        case ViolationType::DebuggerAttached:
            return DetectionCategory::Debugger;
        
        // Timing-related
        case ViolationType::TimingAnomaly:
        case ViolationType::SpeedHack:
            return DetectionCategory::Timing;
        
        // Memory-related
        case ViolationType::MemoryRead:
        case ViolationType::MemoryWrite:
        case ViolationType::MemoryExecute:
        case ViolationType::CodeInjection:
        case ViolationType::InjectedCode:
        case ViolationType::ModuleModified:
        case ViolationType::ChecksumMismatch:
            return DetectionCategory::Memory;
        
        // Hook-related
        case ViolationType::InlineHook:
        case ViolationType::IATHook:
        case ViolationType::VTableHook:
        case ViolationType::SyscallHook:
            return DetectionCategory::Hooks;
        
        // Default to memory for unknown types
        default:
            return DetectionCategory::Memory;
    }
}

double CorrelationEngine::GetCategoryWeight(DetectionCategory category) const {
    switch (category) {
        case DetectionCategory::Debugger: return WEIGHT_DEBUGGER;
        case DetectionCategory::Timing: return WEIGHT_TIMING;
        case DetectionCategory::Memory: return WEIGHT_MEMORY;
        case DetectionCategory::Hooks: return WEIGHT_HOOKS;
        default: return 0.1;
    }
}

void CorrelationEngine::ApplyTimeDecay() {
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - state_.last_update).count();
    
    if (elapsed <= 0.0) {
        return;
    }
    
    // Exponential decay with 30-second half-life
    // score = score * (0.5)^(elapsed / half_life)
    double decay_factor = std::pow(0.5, elapsed / HALF_LIFE_SECONDS);
    state_.score *= decay_factor;
    
    // Remove old signals (older than 60 seconds)
    state_.signals.erase(
        std::remove_if(state_.signals.begin(), state_.signals.end(),
            [now](const DetectionSignal& sig) {
                auto age = std::chrono::duration<double>(now - sig.timestamp).count();
                return age > 60.0;
            }),
        state_.signals.end()
    );
    
    // Recalculate unique categories from remaining signals
    state_.unique_categories = 0;
    for (const auto& sig : state_.signals) {
        state_.unique_categories |= (1u << static_cast<uint8_t>(sig.category));
    }
    
    state_.last_update = now;
}

void CorrelationEngine::UpdateCorrelation(const DetectionSignal& signal) {
    // Add signal to history
    state_.signals.push_back(signal);
    
    // Mark category as detected
    state_.unique_categories |= (1u << static_cast<uint8_t>(signal.category));
    
    // Add weighted score contribution
    double weight = GetCategoryWeight(signal.category);
    state_.score += weight;
    
    // Cap score at 1.0
    if (state_.score > 1.0) {
        state_.score = 1.0;
    }
}

Severity CorrelationEngine::DegradeSeverity(Severity original) const {
    uint32_t signal_count = static_cast<uint32_t>(state_.signals.size());
    
    // Single signal degradation rules
    if (signal_count <= 1) {
        if (original == Severity::Critical) {
            return Severity::High;
        } else if (original == Severity::High) {
            return Severity::Warning;
        }
    }
    
    return original;
}

void CorrelationEngine::DetectEnvironment() {
    environment_.has_discord_overlay = DetectOverlayDLLs();
    environment_.is_vm_environment = DetectVMEnvironment();
    environment_.is_cloud_gaming = DetectCloudGaming();
}

bool CorrelationEngine::ShouldWhitelist(const ViolationEvent& event) const {
    // Whitelist hook detections if we have known overlays
    if (event.type == ViolationType::InlineHook || 
        event.type == ViolationType::IATHook) {
        
        if (environment_.has_discord_overlay ||
            environment_.has_obs_overlay ||
            environment_.has_steam_overlay ||
            environment_.has_nvidia_overlay) {
            
            // Check if the module name matches known overlays
            if (event.module_name) {
                std::string module(event.module_name);
                std::transform(module.begin(), module.end(), module.begin(), ::tolower);
                
                if (module.find("discord") != std::string::npos ||
                    module.find("obs") != std::string::npos ||
                    module.find("steam") != std::string::npos ||
                    module.find("overlay") != std::string::npos ||
                    module.find("nvidia") != std::string::npos ||
                    module.find("geforce") != std::string::npos) {
                    return true;
                }
            }
        }
    }
    
    // Suppress timing checks in VM environments (but NOT memory checks)
    if (event.type == ViolationType::TimingAnomaly && 
        environment_.is_vm_environment) {
        return true;
    }
    
    // Suppress timing checks in cloud gaming
    if (event.type == ViolationType::TimingAnomaly && 
        environment_.is_cloud_gaming) {
        return true;
    }
    
    return false;
}

bool CorrelationEngine::DetectOverlayDLLs() {
#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    bool found_overlay = false;
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    
    if (Module32FirstW(snapshot, &me)) {
        do {
            std::wstring module_name(me.szModule);
            std::transform(module_name.begin(), module_name.end(), module_name.begin(), ::towlower);
            
            // Check for known overlay DLLs
            if (module_name.find(L"discord") != std::wstring::npos) {
                environment_.has_discord_overlay = true;
                found_overlay = true;
            }
            if (module_name.find(L"obs") != std::wstring::npos || 
                module_name.find(L"gameoverlayrenderer") != std::wstring::npos) {
                environment_.has_obs_overlay = true;
                found_overlay = true;
            }
            if (module_name.find(L"steam") != std::wstring::npos) {
                environment_.has_steam_overlay = true;
                found_overlay = true;
            }
            if (module_name.find(L"nvidia") != std::wstring::npos ||
                module_name.find(L"geforce") != std::wstring::npos ||
                module_name.find(L"nvda") != std::wstring::npos) {
                environment_.has_nvidia_overlay = true;
                found_overlay = true;
            }
        } while (Module32NextW(snapshot, &me));
    }
    
    CloseHandle(snapshot);
    return found_overlay;
#else
    // On Linux, check /proc/self/maps for loaded libraries
    // Simplified implementation
    return false;
#endif
}

bool CorrelationEngine::DetectVMEnvironment() {
#ifdef _WIN32
    // Check for common VM indicators
    // Method 1: Check for VM-specific registry keys or hardware IDs
    // Method 2: Check CPUID for hypervisor bit
    
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    
    // Check hypervisor present bit (bit 31 of ECX)
    bool hypervisor_present = (cpuInfo[2] & (1 << 31)) != 0;
    
    if (hypervisor_present) {
        return true;
    }
    
    // Check for VM-specific system info
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    // VMs often have specific processor counts or characteristics
    // This is a heuristic and not definitive
    
    return false;
#else
    // On Linux, check for VM indicators
    struct utsname buffer;
    if (uname(&buffer) == 0) {
        std::string release(buffer.release);
        std::transform(release.begin(), release.end(), release.begin(), ::tolower);
        
        if (release.find("vbox") != std::string::npos ||
            release.find("qemu") != std::string::npos ||
            release.find("kvm") != std::string::npos) {
            return true;
        }
    }
    return false;
#endif
}

bool CorrelationEngine::DetectCloudGaming() {
    // Detect cloud gaming platforms by checking for:
    // 1. GeForce NOW signatures
    // 2. Xbox Cloud Gaming (xCloud) signatures
    // 3. Other cloud gaming platform indicators
    
#ifdef _WIN32
    // Check for GeForce NOW specific processes or environment variables
    if (GetEnvironmentVariableA("GFN_SDK_VERSION", nullptr, 0) > 0) {
        return true;
    }
    
    // Check for xCloud/Xbox Cloud Gaming
    if (GetEnvironmentVariableA("XBOX_CLOUD_GAMING", nullptr, 0) > 0) {
        return true;
    }
#endif
    
    // Additional heuristics could be added here
    return false;
}

} // namespace SDK
} // namespace Sentinel
