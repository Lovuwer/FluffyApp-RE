/**
 * Sentinel SDK - Core Implementation
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include "SentinelSDK.hpp"
#include "Internal/Context.hpp"
#include "Internal/Detection.hpp"
#include "Internal/Protection.hpp"
#include "Internal/CorrelationEngine.hpp"
#include "Internal/Whitelist.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <memory>
#include <string>
#include <cstring>
#include <algorithm>
#include <unordered_map>

#ifdef _WIN32
#include <Windows.h>
#include <intrin.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#endif

namespace Sentinel {
namespace SDK {

// ==================== Global Context ====================

struct SDKContext {
    std::atomic<bool> initialized{false};
    std::atomic<bool> active{false};
    std::atomic<bool> shutdown_requested{false};
    
    Configuration config;
    std::string last_error;
    
    // Heartbeat thread
    std::unique_ptr<std::thread> heartbeat_thread;
    
    // Protection tracking
    std::mutex protection_mutex;
    std::unordered_map<uint64_t, MemoryRegion> protected_regions;
    std::unordered_map<uint64_t, FunctionProtection> protected_functions;
    std::unordered_map<uint64_t, ProtectedValue> protected_values;
    uint64_t next_handle{1};
    
    // Timing
    std::chrono::steady_clock::time_point init_time;
    std::chrono::steady_clock::time_point last_update;
    
    // Statistics
    Statistics stats{};
    
    // Detection modules
    std::unique_ptr<AntiDebugDetector> anti_debug;
    std::unique_ptr<AntiHookDetector> anti_hook;
    std::unique_ptr<IntegrityChecker> integrity;
    std::unique_ptr<SpeedHackDetector> speed_hack;
    
    // Correlation engine
    std::unique_ptr<CorrelationEngine> correlation;
    
    // Network
    std::unique_ptr<PacketEncryption> packet_crypto;
    std::unique_ptr<CloudReporter> reporter;
    
    // Session info
    std::string session_token;
    std::string hardware_id;
};

static std::unique_ptr<SDKContext> g_context;

// ==================== Internal Helpers ====================

namespace {

void SetLastError(const std::string& error) {
    if (g_context) {
        g_context->last_error = error;
    }
}

uint64_t GenerateHandle() {
    return g_context->next_handle++;
}

void HeartbeatThreadFunc() {
    while (g_context && !g_context->shutdown_requested.load()) {
        if (g_context->active.load()) {
            // Perform background integrity checks
            if (g_context->integrity) {
                g_context->integrity->QuickCheck();
            }
            
            // Check for debuggers
            if (g_context->anti_debug) {
                g_context->anti_debug->Check();
            }
            
            // Update timing
            if (g_context->speed_hack) {
                g_context->speed_hack->UpdateBaseline();
            }
        }
        
        std::this_thread::sleep_for(
            std::chrono::milliseconds(g_context->config.heartbeat_interval_ms));
    }
}

void ReportViolation(const ViolationEvent& event) {
    if (!g_context) return;
    
    // Route through correlation engine if available
    if (g_context->correlation) {
        Severity correlated_severity;
        bool should_report;
        
        if (!g_context->correlation->ProcessViolation(event, correlated_severity, should_report)) {
            // Event was suppressed by correlation (e.g., whitelisted)
            return;
        }
        
        // Create correlated event with adjusted severity
        ViolationEvent correlated_event = event;
        correlated_event.severity = correlated_severity;
        
        g_context->stats.violations_detected++;
        
        // Call user callback if registered (with correlated severity)
        if (g_context->config.violation_callback) {
            g_context->config.violation_callback(&correlated_event, g_context->config.callback_user_data);
        }
        
        // Only report to cloud if correlation engine approves
        if (should_report && g_context->reporter && 
            (static_cast<uint32_t>(g_context->config.default_action) & 
             static_cast<uint32_t>(ResponseAction::Report))) {
            g_context->reporter->QueueEvent(correlated_event);
            g_context->stats.violations_reported++;
        }
    } else {
        // Fallback to original behavior if no correlation engine
        g_context->stats.violations_detected++;
        
        // Call user callback if registered
        if (g_context->config.violation_callback) {
            g_context->config.violation_callback(&event, g_context->config.callback_user_data);
        }
        
        // Report to cloud if configured
        if (g_context->reporter && 
            (static_cast<uint32_t>(g_context->config.default_action) & 
             static_cast<uint32_t>(ResponseAction::Report))) {
            g_context->reporter->QueueEvent(event);
            g_context->stats.violations_reported++;
        }
    }
}

} // anonymous namespace

// ==================== Core API Implementation ====================

SENTINEL_API ErrorCode SENTINEL_CALL Initialize(const Configuration* config) {
    if (!config) {
        return ErrorCode::InvalidParameter;
    }
    
    if (g_context && g_context->initialized.load()) {
        return ErrorCode::AlreadyInitialized;
    }
    
    // Create context
    g_context = std::make_unique<SDKContext>();
    g_context->config = *config;
    g_context->init_time = std::chrono::steady_clock::now();
    g_context->last_update = g_context->init_time;
    
    // Validate license (placeholder)
    if (config->license_key == nullptr || strlen(config->license_key) == 0) {
        SetLastError("Invalid license key");
        g_context.reset();
        return ErrorCode::InvalidLicense;
    }
    
    // Generate session info
    g_context->hardware_id = Internal::GenerateHardwareId();
    g_context->session_token = Internal::GenerateSessionToken();
    
    // Initialize detection modules based on features
    auto features = static_cast<uint32_t>(config->features);
    
    if (features & static_cast<uint32_t>(DetectionFeatures::AntiDebug)) {
        g_context->anti_debug = std::make_unique<AntiDebugDetector>();
        g_context->anti_debug->Initialize();
    }
    
    if (features & (static_cast<uint32_t>(DetectionFeatures::InlineHookDetect) |
                    static_cast<uint32_t>(DetectionFeatures::IATHookDetect))) {
        g_context->anti_hook = std::make_unique<AntiHookDetector>();
        g_context->anti_hook->Initialize();
    }
    
    if (features & (static_cast<uint32_t>(DetectionFeatures::MemoryIntegrity) |
                    static_cast<uint32_t>(DetectionFeatures::CodeIntegrity))) {
        g_context->integrity = std::make_unique<IntegrityChecker>();
        g_context->integrity->Initialize();
    }
    
    if (features & static_cast<uint32_t>(DetectionFeatures::SpeedHackDetect)) {
        g_context->speed_hack = std::make_unique<SpeedHackDetector>();
        g_context->speed_hack->Initialize();
    }
    
    // Initialize correlation engine (always enabled for false-positive prevention)
    g_context->correlation = std::make_unique<CorrelationEngine>();
    g_context->correlation->Initialize();
    
    // Initialize network if cloud endpoint provided
    if (config->cloud_endpoint && strlen(config->cloud_endpoint) > 0) {
        g_context->packet_crypto = std::make_unique<PacketEncryption>();
        g_context->reporter = std::make_unique<CloudReporter>(config->cloud_endpoint);
        g_context->reporter->SetBatchSize(config->report_batch_size);
        g_context->reporter->SetInterval(config->report_interval_ms);
    }
    
    // Start heartbeat thread
    g_context->heartbeat_thread = std::make_unique<std::thread>(HeartbeatThreadFunc);
    
    g_context->initialized.store(true);
    g_context->active.store(true);
    
    return ErrorCode::Success;
}

SENTINEL_API void SENTINEL_CALL Shutdown() {
    if (!g_context) return;
    
    // Signal shutdown
    g_context->shutdown_requested.store(true);
    g_context->active.store(false);
    
    // Wait for heartbeat thread
    if (g_context->heartbeat_thread && g_context->heartbeat_thread->joinable()) {
        g_context->heartbeat_thread->join();
    }
    
    // Cleanup modules
    g_context->anti_debug.reset();
    g_context->anti_hook.reset();
    g_context->integrity.reset();
    g_context->speed_hack.reset();
    g_context->correlation.reset();
    g_context->packet_crypto.reset();
    g_context->reporter.reset();
    
    // Clear protected items
    g_context->protected_regions.clear();
    g_context->protected_functions.clear();
    g_context->protected_values.clear();
    
    g_context->initialized.store(false);
    g_context.reset();
}

SENTINEL_API bool SENTINEL_CALL IsInitialized() {
    return g_context && g_context->initialized.load();
}

SENTINEL_API const char* SENTINEL_CALL GetVersion() {
    return SENTINEL_SDK_VERSION_STRING;
}

SENTINEL_API const char* SENTINEL_CALL GetLastError() {
    if (g_context) {
        return g_context->last_error.c_str();
    }
    return "SDK not initialized";
}

// ==================== Runtime Control ====================

SENTINEL_API ErrorCode SENTINEL_CALL Update() {
    if (!g_context || !g_context->initialized.load()) {
        return ErrorCode::NotInitialized;
    }
    
    if (!g_context->active.load()) {
        return ErrorCode::Success;  // Paused, skip checks
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    ErrorCode result = ErrorCode::Success;
    
    // Quick integrity check
    if (g_context->integrity) {
        auto violations = g_context->integrity->QuickCheck();
        for (const auto& v : violations) {
            ReportViolation(v);
            result = ErrorCode::IntegrityViolation;
        }
    }
    
    // Hook check (sampling)
    if (g_context->anti_hook && (g_context->stats.updates_performed % 10 == 0)) {
        auto violations = g_context->anti_hook->QuickCheck();
        for (const auto& v : violations) {
            ReportViolation(v);
            result = ErrorCode::HookDetected;
        }
    }
    
    // Speed hack check
    if (g_context->speed_hack) {
        if (!g_context->speed_hack->ValidateFrame()) {
            ViolationEvent event{};
            event.type = ViolationType::SpeedHack;
            event.severity = Severity::High;
            event.timestamp = GetSecureTime();
            event.details = "Speed manipulation detected";
            ReportViolation(event);
            result = ErrorCode::TamperingDetected;
        }
    }
    
    // Update statistics
    auto end = std::chrono::high_resolution_clock::now();
    float elapsed_us = std::chrono::duration<float, std::micro>(end - start).count();
    
    g_context->stats.updates_performed++;
    g_context->stats.avg_update_time_us = 
        (g_context->stats.avg_update_time_us * (g_context->stats.updates_performed - 1) + elapsed_us) /
        g_context->stats.updates_performed;
    
    if (elapsed_us > g_context->stats.max_update_time_us) {
        g_context->stats.max_update_time_us = elapsed_us;
    }
    
    g_context->last_update = std::chrono::steady_clock::now();
    
    return result;
}

SENTINEL_API ErrorCode SENTINEL_CALL FullScan() {
    if (!g_context || !g_context->initialized.load()) {
        return ErrorCode::NotInitialized;
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    ErrorCode result = ErrorCode::Success;
    
    // Full integrity scan
    if (g_context->integrity) {
        auto violations = g_context->integrity->FullScan();
        for (const auto& v : violations) {
            ReportViolation(v);
            result = ErrorCode::IntegrityViolation;
        }
    }
    
    // Full hook scan
    if (g_context->anti_hook) {
        auto violations = g_context->anti_hook->FullScan();
        for (const auto& v : violations) {
            ReportViolation(v);
            result = ErrorCode::HookDetected;
        }
    }
    
    // Debug check
    if (g_context->anti_debug) {
        auto violations = g_context->anti_debug->FullCheck();
        for (const auto& v : violations) {
            ReportViolation(v);
            result = ErrorCode::DebuggerDetected;
        }
    }
    
    // Update statistics
    auto end = std::chrono::high_resolution_clock::now();
    float elapsed_ms = std::chrono::duration<float, std::milli>(end - start).count();
    
    g_context->stats.scans_performed++;
    g_context->stats.avg_scan_time_ms = 
        (g_context->stats.avg_scan_time_ms * (g_context->stats.scans_performed - 1) + elapsed_ms) /
        g_context->stats.scans_performed;
    
    return result;
}

SENTINEL_API void SENTINEL_CALL Pause() {
    if (g_context) {
        g_context->active.store(false);
    }
}

SENTINEL_API void SENTINEL_CALL Resume() {
    if (g_context) {
        g_context->active.store(true);
    }
}

SENTINEL_API bool SENTINEL_CALL IsActive() {
    return g_context && g_context->active.load();
}

// ==================== Memory Protection ====================

SENTINEL_API uint64_t SENTINEL_CALL ProtectMemory(void* address, size_t size, const char* name) {
    if (!g_context || !g_context->initialized.load()) {
        return 0;
    }
    
    if (!address || size == 0) {
        SetLastError("Invalid address or size");
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(g_context->protection_mutex);
    
    uint64_t handle = GenerateHandle();
    
    MemoryRegion region;
    region.address = reinterpret_cast<uintptr_t>(address);
    region.size = size;
    region.name = name ? name : "";
    region.original_hash = Internal::ComputeHash(address, size);
    region.protected_time = std::chrono::steady_clock::now();
    
    g_context->protected_regions[handle] = region;
    g_context->stats.protected_regions++;
    g_context->stats.total_protected_bytes += size;
    
    // Register with integrity checker
    if (g_context->integrity) {
        g_context->integrity->RegisterRegion(region);
    }
    
    return handle;
}

SENTINEL_API void SENTINEL_CALL UnprotectMemory(uint64_t handle) {
    if (!g_context) return;
    
    std::lock_guard<std::mutex> lock(g_context->protection_mutex);
    
    auto it = g_context->protected_regions.find(handle);
    if (it != g_context->protected_regions.end()) {
        if (g_context->integrity) {
            g_context->integrity->UnregisterRegion(it->second.address);
        }
        g_context->stats.total_protected_bytes -= it->second.size;
        g_context->stats.protected_regions--;
        g_context->protected_regions.erase(it);
    }
}

SENTINEL_API bool SENTINEL_CALL VerifyMemory(uint64_t handle) {
    if (!g_context) return false;
    
    std::lock_guard<std::mutex> lock(g_context->protection_mutex);
    
    auto it = g_context->protected_regions.find(handle);
    if (it == g_context->protected_regions.end()) {
        return false;
    }
    
    uint64_t current_hash = Internal::ComputeHash(
        reinterpret_cast<void*>(it->second.address),
        it->second.size);
    
    return current_hash == it->second.original_hash;
}

// ==================== Function Protection ====================

SENTINEL_API uint64_t SENTINEL_CALL ProtectFunction(void* function_address, const char* name) {
    if (!g_context || !g_context->initialized.load()) {
        return 0;
    }
    
    if (!function_address) {
        SetLastError("Invalid function address");
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(g_context->protection_mutex);
    
    uint64_t handle = GenerateHandle();
    
    FunctionProtection protection;
    protection.address = reinterpret_cast<uintptr_t>(function_address);
    protection.name = name ? name : "";
    
    // Store first N bytes for hook detection
    protection.prologue_size = std::min(size_t(16), Internal::GetPrologueSize(function_address));
    memcpy(protection.original_prologue.data(), function_address, protection.prologue_size);
    
    g_context->protected_functions[handle] = protection;
    g_context->stats.protected_functions++;
    
    // Register with hook detector
    if (g_context->anti_hook) {
        g_context->anti_hook->RegisterFunction(protection);
    }
    
    return handle;
}

SENTINEL_API void SENTINEL_CALL UnprotectFunction(uint64_t handle) {
    if (!g_context) return;
    
    std::lock_guard<std::mutex> lock(g_context->protection_mutex);
    
    auto it = g_context->protected_functions.find(handle);
    if (it != g_context->protected_functions.end()) {
        if (g_context->anti_hook) {
            g_context->anti_hook->UnregisterFunction(it->second.address);
        }
        g_context->stats.protected_functions--;
        g_context->protected_functions.erase(it);
    }
}

SENTINEL_API bool SENTINEL_CALL IsHooked(void* function_address) {
    if (!g_context || !function_address) return false;
    
    if (g_context->anti_hook) {
        return g_context->anti_hook->CheckFunction(reinterpret_cast<uintptr_t>(function_address));
    }
    
    return false;
}

// ==================== Value Protection ====================

SENTINEL_API uint64_t SENTINEL_CALL CreateProtectedInt(int64_t initial_value) {
    if (!g_context || !g_context->initialized.load()) {
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(g_context->protection_mutex);
    
    uint64_t handle = GenerateHandle();
    
    ProtectedValue pv;
    pv.SetValue(initial_value);
    
    g_context->protected_values[handle] = pv;
    
    return handle;
}

SENTINEL_API void SENTINEL_CALL SetProtectedInt(uint64_t handle, int64_t value) {
    if (!g_context) return;
    
    std::lock_guard<std::mutex> lock(g_context->protection_mutex);
    
    auto it = g_context->protected_values.find(handle);
    if (it != g_context->protected_values.end()) {
        it->second.SetValue(value);
    }
}

SENTINEL_API int64_t SENTINEL_CALL GetProtectedInt(uint64_t handle) {
    if (!g_context) return 0;
    
    std::lock_guard<std::mutex> lock(g_context->protection_mutex);
    
    auto it = g_context->protected_values.find(handle);
    if (it != g_context->protected_values.end()) {
        return it->second.GetValue();
    }
    
    return 0;
}

SENTINEL_API void SENTINEL_CALL DestroyProtectedValue(uint64_t handle) {
    if (!g_context) return;
    
    std::lock_guard<std::mutex> lock(g_context->protection_mutex);
    g_context->protected_values.erase(handle);
}

// ==================== Secure Timing ====================

SENTINEL_API uint64_t SENTINEL_CALL GetSecureTime() {
    if (!g_context) return 0;
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - g_context->init_time);
    
    return elapsed.count();
}

SENTINEL_API float SENTINEL_CALL GetSecureDeltaTime() {
    if (!g_context) return 0.0f;
    
    auto now = std::chrono::steady_clock::now();
    auto delta = std::chrono::duration<float>(now - g_context->last_update);
    
    // Clamp to reasonable range to prevent speed hacks from using extreme deltas
    float dt = delta.count();
    return std::min(std::max(dt, 0.0001f), 0.5f);
}

SENTINEL_API bool SENTINEL_CALL ValidateTiming(
    uint64_t start_time,
    uint64_t end_time,
    uint32_t expected_min,
    uint32_t expected_max) {
    
    if (end_time < start_time) return false;
    
    uint64_t elapsed = end_time - start_time;
    
    // Allow some tolerance
    uint32_t min_tolerance = expected_min > 10 ? expected_min - 10 : 0;
    uint32_t max_tolerance = expected_max + 50;
    
    return elapsed >= min_tolerance && elapsed <= max_tolerance;
}

// ==================== Network ====================

SENTINEL_API ErrorCode SENTINEL_CALL EncryptPacket(
    const void* data,
    size_t size,
    void* out_buffer,
    size_t* out_size) {
    
    if (!g_context || !g_context->packet_crypto) {
        return ErrorCode::NotInitialized;
    }
    
    return g_context->packet_crypto->Encrypt(data, size, out_buffer, out_size);
}

SENTINEL_API ErrorCode SENTINEL_CALL DecryptPacket(
    const void* data,
    size_t size,
    void* out_buffer,
    size_t* out_size) {
    
    if (!g_context || !g_context->packet_crypto) {
        return ErrorCode::NotInitialized;
    }
    
    return g_context->packet_crypto->Decrypt(data, size, out_buffer, out_size);
}

SENTINEL_API uint32_t SENTINEL_CALL GetPacketSequence() {
    if (!g_context || !g_context->packet_crypto) {
        return 0;
    }
    
    return g_context->packet_crypto->GetNextSequence();
}

SENTINEL_API bool SENTINEL_CALL ValidatePacketSequence(uint32_t sequence) {
    if (!g_context || !g_context->packet_crypto) {
        return false;
    }
    
    return g_context->packet_crypto->ValidateSequence(sequence);
}

// ==================== Reporting ====================

SENTINEL_API ErrorCode SENTINEL_CALL ReportEvent(
    const char* event_type,
    const char* data) {
    
    if (!g_context || !g_context->reporter) {
        return ErrorCode::NotInitialized;
    }
    
    return g_context->reporter->ReportCustomEvent(event_type, data);
}

SENTINEL_API const char* SENTINEL_CALL GetSessionToken() {
    if (!g_context) return "";
    return g_context->session_token.c_str();
}

SENTINEL_API const char* SENTINEL_CALL GetHardwareId() {
    if (!g_context) return "";
    return g_context->hardware_id.c_str();
}

// ==================== Statistics ====================

SENTINEL_API void SENTINEL_CALL GetStatistics(Statistics* stats) {
    if (!g_context || !stats) return;
    
    *stats = g_context->stats;
    stats->uptime_ms = GetSecureTime();
}

SENTINEL_API void SENTINEL_CALL ResetStatistics() {
    if (!g_context) return;
    
    g_context->stats = Statistics{};
}

// ==================== Whitelist Configuration ====================

SENTINEL_API ErrorCode SENTINEL_CALL WhitelistThreadOrigin(
    const char* module_name,
    const char* reason) {
    
    if (!g_context) {
        return ErrorCode::NotInitialized;
    }
    
    if (!module_name || !reason) {
        SetLastError("Invalid parameters for WhitelistThreadOrigin");
        return ErrorCode::InvalidParameter;
    }
    
    if (!g_whitelist) {
        SetLastError("Whitelist manager not initialized");
        return ErrorCode::InternalError;
    }
    
    WhitelistEntry entry;
    entry.type = WhitelistType::ThreadOrigin;
    entry.identifier = module_name;
    entry.reason = reason;
    entry.builtin = false;
    
    g_whitelist->Add(entry);
    
    return ErrorCode::Success;
}

SENTINEL_API void SENTINEL_CALL RemoveThreadOriginWhitelist(const char* module_name) {
    if (!g_context || !g_whitelist || !module_name) {
        return;
    }
    
    g_whitelist->Remove(module_name);
}

} // namespace SDK
} // namespace Sentinel

// ==================== C API ====================

extern "C" {

SENTINEL_API uint32_t SENTINEL_CALL SentinelInit(const Sentinel::SDK::Configuration* config) {
    return static_cast<uint32_t>(Sentinel::SDK::Initialize(config));
}

SENTINEL_API void SENTINEL_CALL SentinelShutdown() {
    Sentinel::SDK::Shutdown();
}

SENTINEL_API uint32_t SENTINEL_CALL SentinelUpdate() {
    return static_cast<uint32_t>(Sentinel::SDK::Update());
}

SENTINEL_API uint32_t SENTINEL_CALL SentinelFullScan() {
    return static_cast<uint32_t>(Sentinel::SDK::FullScan());
}

SENTINEL_API const char* SENTINEL_CALL SentinelGetVersion() {
    return Sentinel::SDK::GetVersion();
}

}
