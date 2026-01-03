/**
 * Sentinel SDK - Detection Correlation Engine Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "CorrelationEngine.hpp"
#include "OverlayVerifier.hpp"
#include <cmath>
#include <algorithm>
#include <cctype>

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
    
    /**
     * Normalize module name to prevent use-after-free and handle edge cases
     * - Empty strings → "unknown-module"
     * - Whitespace-only → "unknown-module"
     * - Valid strings → trimmed and returned
     */
    std::string NormalizeModuleName(const std::string& module_name) {
        // Handle empty string
        if (module_name.empty()) {
            return "unknown-module";
        }
        
        // Find first non-whitespace character
        size_t start = 0;
        while (start < module_name.size() && std::isspace(static_cast<unsigned char>(module_name[start]))) {
            ++start;
        }
        
        // If all whitespace, treat as empty
        if (start == module_name.size()) {
            return "unknown-module";
        }
        
        // Find last non-whitespace character
        size_t end = module_name.size();
        while (end > start && std::isspace(static_cast<unsigned char>(module_name[end - 1]))) {
            --end;
        }
        
        // Return trimmed string
        return module_name.substr(start, end - start);
    }
}

CorrelationEngine::CorrelationEngine()
    : state_{}
    , environment_{}
{
    state_.score = 0.0;
    state_.unique_categories = 0;
    state_.last_update = std::chrono::steady_clock::now();
    state_.current_scan_cycle = 0;
    state_.last_scan_time = std::chrono::steady_clock::now();
    state_.has_correlated_anomaly = false;
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
    state_.current_scan_cycle = 0;
    state_.last_scan_time = std::chrono::steady_clock::now();
    state_.has_correlated_anomaly = false;
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
    
    // Update scan cycle if enough time has passed
    auto now = std::chrono::steady_clock::now();
    double time_since_last_scan = std::chrono::duration<double>(now - state_.last_scan_time).count();
    if (time_since_last_scan >= MIN_SCAN_CYCLE_INTERVAL) {
        state_.current_scan_cycle++;
        state_.last_scan_time = now;
    }
    
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
    signal.timestamp = now;
    signal.details = event.details;
    signal.address = event.address;
    signal.module_name = NormalizeModuleName(event.module_name);
    signal.scan_cycle = state_.current_scan_cycle;
    signal.persistence_count = 1;  // Initial persistence
    
    // Check if we already have this signal type - update persistence instead of adding duplicate
    bool signal_updated = false;
    for (auto& existing_signal : state_.signals) {
        if (existing_signal.type == signal.type && 
            existing_signal.category == signal.category) {
            // Update the existing signal with new timestamp and increment persistence
            existing_signal.timestamp = now;
            existing_signal.scan_cycle = state_.current_scan_cycle;
            existing_signal.persistence_count++;
            signal_updated = true;
            
            // Add weight again for this re-detection
            double weight = GetCategoryWeight(signal.category);
            state_.score += weight;
            break;
        }
    }
    
    // If this is a new signal type, add it
    if (!signal_updated) {
        // Update correlation state
        UpdateCorrelation(signal);
    }
    
    // Check for correlated timing + memory anomaly
    if (DetectCorrelatedAnomaly()) {
        state_.has_correlated_anomaly = true;
    }
    
    // Check for known false positive patterns
    if (IsFalsePositivePattern()) {
        out_correlated_severity = Severity::Info;
        out_should_report = true;  // Report as telemetry with FP flag
        return false;  // Suppressed for enforcement
    }
    
    // Determine correlated severity
    out_correlated_severity = DegradeSeverity(event.severity);
    
    // Determine if should report to cloud
    // Always emit telemetry for sub-threshold detections
    uint32_t signal_count = static_cast<uint32_t>(state_.signals.size());
    
    if (signal_count < 2) {
        // Single signal: telemetry only, no enforcement
        out_should_report = true;  // Emit telemetry
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
    
    // Defensive: Empty signals vector means no detections - allow only non-enforcement actions
    // This is a safety check, though the vector should always be managed correctly
    if (state_.signals.empty()) {
        // No signals means no enforcement actions should be allowed
        uint32_t action_bits = static_cast<uint32_t>(action);
        bool is_enforcement = (action_bits & (static_cast<uint32_t>(ResponseAction::Ban) | 
                                              static_cast<uint32_t>(ResponseAction::Terminate) |
                                              static_cast<uint32_t>(ResponseAction::Kick))) != 0;
        return !is_enforcement;  // Only allow non-enforcement actions
    }
    
    // Check if action requires multi-signal confirmation
    uint32_t action_bits = static_cast<uint32_t>(action);
    bool is_ban = (action_bits & static_cast<uint32_t>(ResponseAction::Ban)) != 0;
    bool is_terminate = (action_bits & static_cast<uint32_t>(ResponseAction::Terminate)) != 0;
    bool is_kick = (action_bits & static_cast<uint32_t>(ResponseAction::Kick)) != 0;
    
    if (is_ban || is_terminate) {
        // Count only persistent signals (3+ scan cycles)
        uint32_t persistent_signals = 0;
        uint32_t persistent_categories = 0;
        
        for (const auto& signal : state_.signals) {
            if (HasPersistedLongEnough(signal)) {
                persistent_signals++;
                persistent_categories |= (1u << static_cast<uint8_t>(signal.category));
            }
        }
        
        uint32_t unique_persistent_count = popcount(persistent_categories);
        
        // Apply environmental penalty to score
        double adjusted_score = ApplyEnvironmentalPenalty(state_.score);
        
        // Ban and Terminate require:
        // - 3+ unique persistent signal categories
        // - Score >= 2.0 (after environmental penalty)
        return (unique_persistent_count >= MIN_UNIQUE_SIGNALS) && 
               (adjusted_score >= MIN_CORRELATION_THRESHOLD);
    }
    
    if (is_kick) {
        // Kick requires at least 2 persistent signals
        uint32_t persistent_signals = 0;
        for (const auto& signal : state_.signals) {
            if (HasPersistedLongEnough(signal)) {
                persistent_signals++;
            }
        }
        return persistent_signals >= 2;
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
    state_.current_scan_cycle = 0;
    state_.last_scan_time = std::chrono::steady_clock::now();
    state_.has_correlated_anomaly = false;
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
        
        // Memory-related (RWX specifically)
        case ViolationType::MemoryExecute:
            return DetectionCategory::MemoryRWX;  // RWX memory
        
        // Memory-related (general)
        case ViolationType::MemoryRead:
        case ViolationType::MemoryWrite:
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
        case DetectionCategory::MemoryRWX: return WEIGHT_MEMORY_RWX;
        case DetectionCategory::Hooks: return WEIGHT_HOOKS;
        case DetectionCategory::CorrelatedAnomaly: return WEIGHT_CORRELATED_ANOMALY;
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
    
    // Defensive: Only process signals if vector is not empty
    if (!state_.signals.empty()) {
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
    } else {
        // No signals, ensure categories bitmask is cleared
        state_.unique_categories = 0;
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
    
    // Don't cap score - we need scores up to 2.0+ for enforcement threshold
    // Score naturally accumulates from multiple high-confidence signals
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
    DetectAndVerifyOverlays();
    environment_.is_vm_environment = DetectVMEnvironment();
    environment_.is_cloud_gaming = DetectCloudGaming();
}

bool CorrelationEngine::ShouldWhitelist(const ViolationEvent& event) const {
    // NEVER suppress hook detections on critical security functions
    // This prevents overlays from masking critical security violations
    if (event.type == ViolationType::InlineHook || 
        event.type == ViolationType::IATHook) {
        
        // Check if this is a critical security function
        if (!event.module_name.empty()) {
            std::string module = event.module_name;
            std::wstring module_wide(module.begin(), module.end());
            
            if (OverlayVerifier::IsCriticalSecurityFunction(module_wide.c_str())) {
                return false; // Never suppress critical security function hooks
            }
        }
        
        // Check if we have any verified overlays
        if (!environment_.verified_overlays.empty()) {
            // Check if the module name matches a verified overlay or expected hook pattern
            if (!event.module_name.empty()) {
                std::string module = event.module_name;
                std::transform(module.begin(), module.end(), module.begin(), ::tolower);
                
                // Check if module is a graphics DLL (expected hook target for overlays)
                if (module.find("d3d") != std::string::npos ||
                    module.find("dxgi") != std::string::npos ||
                    module.find("opengl") != std::string::npos ||
                    module.find("vulkan") != std::string::npos) {
                    // Only suppress if we have a verified overlay
                    // (overlay hooking graphics APIs is expected)
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

void CorrelationEngine::DetectAndVerifyOverlays() {
#ifdef _WIN32
    environment_.verified_overlays.clear();
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    OverlayVerifier verifier;
    verifier.Initialize();
    
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    
    if (Module32FirstW(snapshot, &me)) {
        do {
            std::wstring module_name(me.szModule);
            std::wstring module_path(me.szExePath);
            
            // Check if this could be an overlay module
            if (OverlayVerifier::IsPotentialOverlay(module_name.c_str())) {
                // Verify the overlay
                auto result = verifier.VerifyOverlay(module_path.c_str());
                
                if (result.is_verified) {
                    // This is a verified overlay - add to list
                    VerifiedOverlay overlay;
                    overlay.module_path = result.module_path;
                    overlay.is_verified = true;
                    
                    // Map vendor to name
                    switch (result.vendor) {
                        case OverlayVendor::Discord:
                            overlay.vendor_name = L"Discord";
                            break;
                        case OverlayVendor::Steam:
                            overlay.vendor_name = L"Steam";
                            break;
                        case OverlayVendor::NVIDIA:
                            overlay.vendor_name = L"NVIDIA";
                            break;
                        case OverlayVendor::OBS:
                            overlay.vendor_name = L"OBS";
                            break;
                        default:
                            overlay.vendor_name = L"Unknown";
                            break;
                    }
                    
                    environment_.verified_overlays.push_back(overlay);
                } else {
                    // Potential overlay but not verified - log as suspicious
                    // Don't suppress detections for this
                    // Future: could emit telemetry event about unsigned overlay
                }
            }
        } while (Module32NextW(snapshot, &me));
    }
    
    CloseHandle(snapshot);
    verifier.Shutdown();
#else
    environment_.verified_overlays.clear();
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

bool CorrelationEngine::IsFalsePositivePattern() const {
    // Check for known false positive pattern: Verified Discord overlay + RWX + overlay hook
    bool has_verified_discord = false;
    for (const auto& overlay : environment_.verified_overlays) {
        if (overlay.vendor_name == L"Discord") {
            has_verified_discord = true;
            break;
        }
    }
    
    bool has_rwx_detection = false;
    bool has_overlay_hook = false;
    
    for (const auto& signal : state_.signals) {
        if (signal.category == DetectionCategory::MemoryRWX) {
            has_rwx_detection = true;
        }
        if (signal.category == DetectionCategory::Hooks && !signal.module_name.empty()) {
            std::string module = signal.module_name;
            std::transform(module.begin(), module.end(), module.begin(), ::tolower);
            if (module.find("overlay") != std::string::npos ||
                module.find("discord") != std::string::npos) {
                has_overlay_hook = true;
            }
        }
    }
    
    // Known false positive: Verified Discord overlay + RWX memory + overlay hook
    if (has_verified_discord && has_rwx_detection && has_overlay_hook) {
        return true;
    }
    
    return false;
}

double CorrelationEngine::ApplyEnvironmentalPenalty(double base_score) const {
    // Apply 30% penalty (multiply by 0.7) when VM or cloud gaming detected
    // VM detection: CPUID hypervisor bit, system characteristics
    // Cloud gaming: Environment variables (GFN_SDK_VERSION, XBOX_CLOUD_GAMING)
    // These flags are set once during Initialize() via DetectEnvironment()
    if (environment_.is_vm_environment || environment_.is_cloud_gaming) {
        return base_score * ENVIRONMENTAL_PENALTY_FACTOR;
    }
    return base_score;
}

bool CorrelationEngine::HasPersistedLongEnough(const DetectionSignal& signal) const {
    // Signal must have persisted for at least MIN_PERSISTENCE_CYCLES scan cycles
    return signal.persistence_count >= MIN_PERSISTENCE_CYCLES;
}

bool CorrelationEngine::DetectCorrelatedAnomaly() const {
    // Detect if we have both timing and memory anomalies within recent signals
    bool has_timing = false;
    bool has_memory = false;
    
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& signal : state_.signals) {
        // Only consider signals from recent scan cycles (within last 60 seconds)
        double age = std::chrono::duration<double>(now - signal.timestamp).count();
        if (age > 60.0) {
            continue;
        }
        
        if (signal.category == DetectionCategory::Timing) {
            has_timing = true;
        }
        if (signal.category == DetectionCategory::Memory || 
            signal.category == DetectionCategory::MemoryRWX) {
            has_memory = true;
        }
    }
    
    // Correlated anomaly detected if both timing and memory signals present
    return has_timing && has_memory;
}

} // namespace SDK
} // namespace Sentinel
