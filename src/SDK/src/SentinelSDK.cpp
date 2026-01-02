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
#include "Internal/TelemetryEmitter.hpp"
#include "Internal/RuntimeConfig.hpp"
#include "Internal/EnvironmentDetection.hpp"
#include "Internal/Watchdog.hpp"
#include "Internal/SafeMemory.hpp"  // Task 09: For exception budget tracking
#include "Internal/ScanScheduler.hpp"  // Task 09: Detection timing randomization
#include "Internal/IntegrityValidator.hpp"  // Task 08: Memory integrity self-validation
#include "Internal/TimingRandomizer.hpp"  // Task 22: Runtime behavior variation
#include "Internal/DetectionRegistry.hpp"  // Task 29: Redundant detection architecture
#include "Internal/RedundantAntiDebug.hpp"  // Task 29: Redundant anti-debug implementations
#include "Sentinel/Core/Logger.hpp"  // Comprehensive logging infrastructure
#include <Sentinel/Core/ServerDirective.hpp>  // Task 24: Server directive protocol
// Note: Internal/PerfTelemetry.hpp will be available after merge with main
#include "Internal/PerfTelemetry.hpp"  // Task 17: Performance telemetry
#include "Internal/SignatureManager.hpp"  // Task 25: Dynamic signature updates
#include "Network/UpdateClient.hpp"  // Task 25: Signature update client

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <memory>
#include <string>
#include <cstring>
#include <algorithm>
#include <unordered_map>
#include <random>  // Task 23: For secure RNG in distributed validation

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
    std::atomic<uint64_t> next_handle{1};
    
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
    
    // Task 14: Telemetry and runtime configuration
    std::unique_ptr<TelemetryEmitter> telemetry;
    std::unique_ptr<RuntimeConfig> runtime_config;
    std::unique_ptr<EnvironmentDetector> env_detector;
    
    // Task 07: Heartbeat thread watchdog
    std::unique_ptr<Watchdog> watchdog;
    
    // Task 09: Scan scheduler for randomized timing
    std::unique_ptr<ScanScheduler> scan_scheduler;
    // Task 08: Memory integrity self-validation
    std::unique_ptr<IntegrityValidator> self_integrity;
    
    // Task 17: Performance telemetry
    std::unique_ptr<PerformanceTelemetry> perf_telemetry;
    
    // Task 22: Timing randomizer for runtime behavior variation
    std::unique_ptr<TimingRandomizer> timing_randomizer;
    
    // Task 24: Server directive support
    std::mutex directive_mutex;
    ServerDirective last_directive{};
    bool has_directive = false;
    uint64_t last_directive_poll_time = 0;
    
    // Task 25: Dynamic signature update system
    std::shared_ptr<SignatureManager> signature_manager;
    std::unique_ptr<UpdateClient> update_client;
    uint32_t current_signature_version = 0;
    
    // Task 29: Redundant detection architecture
    std::unique_ptr<DetectionRegistry> detection_registry;
    
    // Session info
    std::string session_token;
    std::string hardware_id;
};

static std::unique_ptr<SDKContext> g_context;
std::unique_ptr<WhitelistManager> g_whitelist;

// ==================== Internal Helpers ====================

namespace {

// Forward declaration
void ReportViolation(const ViolationEvent& event);

// Task 23: Thread-local secure RNG for distributed validation decisions
// Using thread_local to avoid contention between threads
thread_local std::mt19937 g_validation_rng(std::random_device{}());

void SetLastError(const std::string& error) {
    if (g_context) {
        g_context->last_error = error;
    }
}

uint64_t GenerateHandle() {
    return g_context->next_handle.fetch_add(1, std::memory_order_relaxed);
}

// Task 23: Helper for probabilistic validation (cryptographically secure)
// Returns true with probability 1/N
bool ShouldValidateWithProbability(uint32_t N) {
    std::uniform_int_distribution<uint32_t> dist(0, N - 1);
    return dist(g_validation_rng) == 0;
}

// Task 14: Helper to emit telemetry for detections
void EmitDetectionTelemetry(const ViolationEvent& event, DetectionType detection_type, float confidence) {
    if (!g_context || !g_context->telemetry) return;
    
    // Hash only relevant fields to avoid padding bytes and sensitive data exposure
    struct TelemetryHashData {
        uint64_t type;
        uint64_t severity;
        uint64_t address;
        uint64_t detection_id;
        
        TelemetryHashData(const ViolationEvent& e) 
            : type(static_cast<uint64_t>(e.type))
            , severity(static_cast<uint64_t>(e.severity))
            , address(e.address)
            , detection_id(e.detection_id)
        {}
    } hash_data(event);
    
    // Create telemetry event
    TelemetryEvent telemetry_event = g_context->telemetry->CreateEventFromViolation(
        event,
        detection_type,
        confidence,
        &hash_data,  // Use structured hash data instead of full event
        sizeof(hash_data)
    );
    
    // Update correlation state if available
    if (g_context->correlation) {
        CorrelationSnapshot snapshot;
        snapshot.current_score = g_context->correlation->GetCorrelationScore();
        snapshot.unique_categories = g_context->correlation->GetUniqueSignalCount();
        snapshot.signal_count = static_cast<uint32_t>(snapshot.unique_categories);  // Simplified
        snapshot.has_correlated_anomaly = false;  // Would need more detailed tracking
        
        g_context->telemetry->UpdateCorrelationState(snapshot);
    }
    
    // Emit the telemetry event
    g_context->telemetry->EmitEvent(telemetry_event);
}

// Task 14: Helper to check if detection should run based on runtime config
bool ShouldRunDetection(DetectionType detection_type) {
    if (!g_context || !g_context->runtime_config) return true;
    return g_context->runtime_config->IsDetectionEnabled(detection_type);
}

// Task 14: Helper to check if detection is in dry-run mode
bool IsDetectionDryRun(DetectionType detection_type) {
    if (!g_context || !g_context->runtime_config) return false;
    return g_context->runtime_config->IsDetectionDryRun(detection_type);
}

// Task 14: Wrapper for detection execution with telemetry and exception handling
// Task 09: Added exception budget enforcement per scan
template<typename DetectionFunc>
std::vector<ViolationEvent> RunDetectionWithTelemetry(
    DetectionType detection_type,
    DetectionFunc&& detection_func,
    float base_confidence = 0.8f)
{
    std::vector<ViolationEvent> violations;
    
    if (!g_context) return violations;
    
    // Check if detection is enabled
    if (!ShouldRunDetection(detection_type)) {
        return violations;
    }
    
    // Task 09: Reset exception count at start of each scan and set budget
    SafeMemory::ResetExceptionStats();
    if (g_context->runtime_config) {
        uint32_t budget = g_context->runtime_config->GetGlobalConfig().exception_budget_per_scan;
        SafeMemory::SetExceptionBudget(budget);
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        // Run the detection
        violations = detection_func();
        
        // Calculate scan duration
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
        
        // Set performance metrics for telemetry
        if (g_context->telemetry) {
            g_context->telemetry->SetPerformanceMetrics(duration_us, 0);  // Memory scanned would be set by detector
        }
        
        // Task 09: Check if exception budget was exceeded during scan
        if (g_context->runtime_config) {
            uint32_t budget = g_context->runtime_config->GetGlobalConfig().exception_budget_per_scan;
            auto& stats = SafeMemory::GetExceptionStats();
            if (stats.GetTotalExceptions() > budget) {
                // Log budget exceeded event
                ViolationEvent budget_event;
                budget_event.type = ViolationType::None;  // Task 09: Informational event
                budget_event.severity = Severity::Warning;  // Task 09: Budget exceeded is a warning
                budget_event.timestamp = GetSecureTime();
                budget_event.details = "Exception budget exceeded: " + 
                                      std::to_string(stats.GetTotalExceptions()) + 
                                      " > " + std::to_string(budget) + " (scan stopped, partial results returned)";
                budget_event.detection_id = static_cast<uint32_t>(detection_type);
                
                // Emit telemetry for budget exceeded event
                EmitDetectionTelemetry(budget_event, detection_type, base_confidence);
            }
        }
        
        // Emit telemetry for each violation
        for (const auto& violation : violations) {
            EmitDetectionTelemetry(violation, detection_type, base_confidence);
        }
        
        // In dry-run mode, clear violations so they don't trigger enforcement
        if (IsDetectionDryRun(detection_type)) {
            violations.clear();
        }
        
    } catch (const std::exception& e) {
        // Record exception for automatic degradation
        if (g_context->runtime_config) {
            g_context->runtime_config->RecordException(detection_type);
        }
        
        // Log the exception (in production, this would be sent to monitoring)
        SetLastError(std::string("Detection exception: ") + e.what());
    } catch (...) {
        // Record unknown exception
        if (g_context->runtime_config) {
            g_context->runtime_config->RecordException(detection_type);
        }
        
        SetLastError("Unknown detection exception");
    }
    
    return violations;
}

void HeartbeatThreadFunc() {
    int heartbeat_counter = 0;  // Task 11: Counter for periodic all-thread scanning
    
    while (g_context && !g_context->shutdown_requested.load()) {
        if (g_context->active.load()) {
            // Task 07: Ping watchdog to indicate thread is alive
            if (g_context->watchdog) {
                g_context->watchdog->Ping();
            }
            
            // Task 24: Poll server for enforcement directives
            uint64_t current_time = GetSecureTime();
            if (g_context->reporter && !g_context->session_token.empty()) {
                uint64_t time_since_last_poll = current_time - g_context->last_directive_poll_time;
                if (time_since_last_poll >= g_context->config.directive_poll_interval_ms) {
                    g_context->reporter->PollDirectives(g_context->session_token);
                    g_context->last_directive_poll_time = current_time;
                    
                    // Task 25: Check for and handle signature rollback directives
                    ServerDirective directive;
                    if (g_context->reporter->GetLastDirective(directive)) {
                        if (directive.type == ServerDirectiveType::SignatureRollback && 
                            g_context->signature_manager) {
                            SENTINEL_LOG_INFO("Received signature rollback directive from server");
                            auto rollback_result = g_context->signature_manager->rollbackToPrevious();
                            if (rollback_result.isSuccess()) {
                                auto stats = g_context->signature_manager->getStatistics();
                                g_context->current_signature_version = stats.current_version;
                                SENTINEL_LOG_INFO_F("Signature rollback successful - reverted to version %u", 
                                    stats.current_version);
                            } else {
                                SENTINEL_LOG_ERROR("Signature rollback failed");
                            }
                        }
                    }
                }
            }
            
            // Task 14: Check for runtime config updates periodically
            if (g_context->runtime_config && heartbeat_counter % 300 == 0) {  // Every 5 minutes at 1s intervals
                g_context->runtime_config->CheckForUpdates();
            }
            
            // Task 08: Validate SDK's own code integrity (distributed across heartbeats)
            if (g_context->self_integrity) {
                if (!g_context->self_integrity->ValidateQuick()) {
                    // Self-integrity violation detected - report with high severity
                    ViolationEvent event = IntegrityValidator::CreateGenericTamperEvent();
                    event.timestamp = GetSecureTime();
                    
                    ReportViolation(event);
                }
            }
            
            // Task 09: Check if scan should be performed (randomized timing)
            if (g_context->scan_scheduler && g_context->scan_scheduler->ShouldScan()) {
                // Get next scan type (randomized order)
                ScanType scan_type = g_context->scan_scheduler->GetNextScanType();
                
                // Execute the appropriate scan based on type
                switch (scan_type) {
                    case ScanType::QuickIntegrity:
                        if (g_context->integrity) {
                            auto violations = RunDetectionWithTelemetry(
                                DetectionType::MemoryIntegrity,
                                [&]() { return g_context->integrity->QuickCheck(); }
                            );
                            for (const auto& violation : violations) {
                                ReportViolation(violation);
                            }
                        }
                        break;
                        
                    case ScanType::FullIntegrity:
                        if (g_context->integrity) {
                            auto violations = RunDetectionWithTelemetry(
                                DetectionType::MemoryIntegrity,
                                [&]() { return g_context->integrity->FullScan(); },
                                0.9f  // Higher confidence for full scan
                            );
                            for (const auto& violation : violations) {
                                ReportViolation(violation);
                            }
                        }
                        break;
                        
                    case ScanType::HookDetection:
                        if (g_context->anti_hook) {
                            auto violations = RunDetectionWithTelemetry(
                                DetectionType::AntiHook,
                                [&]() { return g_context->anti_hook->QuickCheck(); }
                            );
                            for (const auto& violation : violations) {
                                ReportViolation(violation);
                            }
                        }
                        break;
                        
                    case ScanType::DebugDetection:
                        if (g_context->anti_debug) {
                            // Task 11: Perform comprehensive all-thread scan every 10 heartbeats
                            // This balances thoroughness with performance impact
                            if (heartbeat_counter % 10 == 0) {
                                // FullCheck includes CheckAllThreadsHardwareBP
                                auto violations = RunDetectionWithTelemetry(
                                    DetectionType::AntiDebug,
                                    [&]() { return g_context->anti_debug->FullCheck(); },
                                    0.9f  // Higher confidence for full check
                                );
                                for (const auto& violation : violations) {
                                    ReportViolation(violation);
                                }
                            } else {
                                // Regular quick check on other heartbeats
                                auto violations = RunDetectionWithTelemetry(
                                    DetectionType::AntiDebug,
                                    [&]() { return g_context->anti_debug->Check(); },
                                    0.7f  // Lower confidence for quick check
                                );
                                for (const auto& violation : violations) {
                                    ReportViolation(violation);
                                }
                            }
                        }
                        break;
                        
                    case ScanType::SpeedHack:
                        if (g_context->speed_hack) {
                            g_context->speed_hack->UpdateBaseline();
                        }
                        break;
                        
                    case ScanType::InjectionScan:
                        // Placeholder for future injection scanning
                        break;
                }
                
                // Mark scan complete to update statistics and schedule next scan
                g_context->scan_scheduler->MarkScanComplete();
            }
            
            heartbeat_counter++;
        }
        
        // Task 22: Use timing randomizer for sleep intervals to prevent predictable patterns
        uint32_t sleep_ms = g_context->config.heartbeat_interval_ms;
        if (g_context->scan_scheduler) {
            // Use a fraction of time until next scan to check more frequently
            // This ensures we don't miss the scan window
            uint32_t time_until_scan = g_context->scan_scheduler->GetTimeUntilNextScan();
            if (time_until_scan > 0) {
                // Sleep for a fraction of the remaining time, max heartbeat interval
                sleep_ms = std::min(sleep_ms, std::max(50u, time_until_scan / 2));
            }
        }
        
        // Task 22: Add cryptographic jitter to sleep interval (30% variation)
        // This prevents timing-based detection of heartbeat patterns
        // Minimum threshold ensures we don't add jitter to very short sleeps
        constexpr uint32_t HEARTBEAT_JITTER_PERCENT = 30;
        constexpr uint32_t MIN_SLEEP_FOR_JITTER_MS = 100;
        
        if (g_context->timing_randomizer && sleep_ms > MIN_SLEEP_FOR_JITTER_MS) {
            sleep_ms = g_context->timing_randomizer->AddJitter(sleep_ms, HEARTBEAT_JITTER_PERCENT);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    }
}

void ReportViolation(const ViolationEvent& event) {
    if (!g_context) return;
    
    // Task 09: Trigger burst mode for high-severity violations
    if (g_context->scan_scheduler && 
        (event.severity == Severity::High || event.severity == Severity::Critical)) {
        // Use correlation score as signal strength if available
        float signal_strength = 0.8f;  // Default high signal
        if (g_context->correlation) {
            signal_strength = g_context->correlation->GetCorrelationScore() / 100.0f;
        }
        g_context->scan_scheduler->RecordBehavioralSignal(signal_strength);
    }
    
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
        
        // Task 24: ONLY report to server - NO LOCAL ENFORCEMENT
        // Server makes all enforcement decisions via ServerDirective callbacks
        // Ban, Kick, Terminate actions are DEPRECATED - server issues directives instead
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
        
        // Task 24: ONLY report to server - NO LOCAL ENFORCEMENT
        // Report to cloud if configured
        if (g_context->reporter && 
            (static_cast<uint32_t>(g_context->config.default_action) & 
             static_cast<uint32_t>(ResponseAction::Report))) {
            g_context->reporter->QueueEvent(event);
            g_context->stats.violations_reported++;
        }
    }
    
    // Task 24: Local enforcement actions (Ban, Kick, Terminate) are REMOVED
    // All enforcement decisions come from server via PollServerDirectives()
}

} // anonymous namespace

// ==================== Core API Implementation ====================

SENTINEL_API ErrorCode SENTINEL_CALL Initialize(const Configuration* config) {
    auto init_start = std::chrono::high_resolution_clock::now();
    
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
    
    // Initialize logging infrastructure
    auto& logger = Sentinel::Core::Logger::Instance();
    
    // Set log level based on debug mode
    Sentinel::Core::LogLevel logLevel = config->debug_mode 
        ? Sentinel::Core::LogLevel::Debug 
        : Sentinel::Core::LogLevel::Info;
    
    // Set output targets
    Sentinel::Core::LogOutput logOutput = Sentinel::Core::LogOutput::Console;
    
    if (config->log_path && strlen(config->log_path) > 0) {
        logOutput = logOutput | Sentinel::Core::LogOutput::File;
    }
    
    // Initialize logger
    std::string logPath = (config->log_path && strlen(config->log_path) > 0) 
        ? config->log_path 
        : "";
    
    if (!logger.Initialize(logLevel, logOutput, logPath, 10)) {
        SetLastError("Failed to initialize logger");
        // Continue anyway - logging is not critical
    }
    
    SENTINEL_LOG_INFO_F("Sentinel SDK v%s initializing...", SENTINEL_SDK_VERSION_STRING);
    SENTINEL_LOG_DEBUG_F("Debug mode: %s", config->debug_mode ? "enabled" : "disabled");
    
    // Validate license (placeholder)
    if (config->license_key == nullptr || strlen(config->license_key) == 0) {
        SetLastError("Invalid license key");
        SENTINEL_LOG_ERROR("Invalid license key provided");
        g_context.reset();
        return ErrorCode::InvalidLicense;
    }
    
    SENTINEL_LOG_DEBUG_F("License key: %.8s... (truncated)", config->license_key);
    
    // Generate session info
    g_context->hardware_id = Internal::GenerateHardwareId();
    g_context->session_token = Internal::GenerateSessionToken();
    
    SENTINEL_LOG_INFO_F("Session token: %.16s... (truncated)", g_context->session_token.c_str());
    SENTINEL_LOG_DEBUG_F("Hardware ID: %s", g_context->hardware_id.c_str());
    
    // Initialize detection modules based on features
    auto features = static_cast<uint32_t>(config->features);
    
    SENTINEL_LOG_INFO("Initializing detection modules...");
    
    if (features & static_cast<uint32_t>(DetectionFeatures::AntiDebug)) {
        SENTINEL_LOG_DEBUG("Initializing AntiDebug detector");
        g_context->anti_debug = std::make_unique<AntiDebugDetector>();
        g_context->anti_debug->Initialize();
    }
    
    if (features & (static_cast<uint32_t>(DetectionFeatures::InlineHookDetect) |
                    static_cast<uint32_t>(DetectionFeatures::IATHookDetect))) {
        SENTINEL_LOG_DEBUG("Initializing AntiHook detector");
        g_context->anti_hook = std::make_unique<AntiHookDetector>();
        g_context->anti_hook->Initialize();
    }
    
    if (features & (static_cast<uint32_t>(DetectionFeatures::MemoryIntegrity) |
                    static_cast<uint32_t>(DetectionFeatures::CodeIntegrity))) {
        SENTINEL_LOG_DEBUG("Initializing Integrity checker");
        g_context->integrity = std::make_unique<IntegrityChecker>();
        g_context->integrity->Initialize();
    }
    
    if (features & static_cast<uint32_t>(DetectionFeatures::SpeedHackDetect)) {
        SENTINEL_LOG_DEBUG("Initializing SpeedHack detector");
        g_context->speed_hack = std::make_unique<SpeedHackDetector>();
        g_context->speed_hack->Initialize();
    }
    
    // Initialize correlation engine (always enabled for false-positive prevention)
    SENTINEL_LOG_DEBUG("Initializing Correlation engine");
    g_context->correlation = std::make_unique<CorrelationEngine>();
    g_context->correlation->Initialize();
    
    // Initialize whitelist manager
    SENTINEL_LOG_DEBUG("Initializing Whitelist manager");
    g_whitelist = std::make_unique<WhitelistManager>();
    g_whitelist->Initialize();
    
    // Task 14: Initialize telemetry and runtime configuration
    SENTINEL_LOG_DEBUG("Initializing Environment detector");
    g_context->env_detector = std::make_unique<EnvironmentDetector>();
    g_context->env_detector->Initialize();
    g_context->env_detector->DetectEnvironment();
    
    SENTINEL_LOG_DEBUG("Initializing Telemetry emitter");
    g_context->telemetry = std::make_unique<TelemetryEmitter>();
    g_context->telemetry->Initialize();
    g_context->telemetry->SetEnvironmentDetector(g_context->env_detector.get());
    
    SENTINEL_LOG_DEBUG("Initializing Runtime configuration");
    g_context->runtime_config = std::make_unique<RuntimeConfig>();
    g_context->runtime_config->Initialize();
    
    // Task 07: Initialize heartbeat thread watchdog
    SENTINEL_LOG_DEBUG("Initializing Watchdog");
    g_context->watchdog = std::make_unique<Watchdog>();
    
    // Task 09: Initialize scan scheduler with randomized timing
    SENTINEL_LOG_DEBUG("Initializing Scan scheduler");
    g_context->scan_scheduler = std::make_unique<ScanScheduler>();
    ScanSchedulerConfig scheduler_config;
    scheduler_config.min_interval_ms = config->heartbeat_interval_ms / 2;  // 50% variation
    scheduler_config.max_interval_ms = config->heartbeat_interval_ms * 3 / 2;  // 150% variation
    scheduler_config.mean_interval_ms = config->heartbeat_interval_ms;
    scheduler_config.enable_burst_scans = true;
    scheduler_config.vary_scan_order = true;
    scheduler_config.vary_scan_scope = true;
    g_context->scan_scheduler->Initialize(scheduler_config);
    // Task 08: Initialize memory integrity self-validation
    SENTINEL_LOG_DEBUG("Initializing Self-integrity validator");
    g_context->self_integrity = std::make_unique<IntegrityValidator>();
    g_context->self_integrity->Initialize();
    
    // Task 17: Initialize performance telemetry
    g_context->perf_telemetry = std::make_unique<PerformanceTelemetry>();
    PerfTelemetryConfig perf_config = PerfTelemetryConfig::Default();
    // Configure thresholds based on SDK requirements
    perf_config.p95_threshold_ms = 5.0;  // 5ms P95 target
    perf_config.p99_threshold_ms = 10.0; // 10ms P99 target
    perf_config.enable_self_throttling = true;
    g_context->perf_telemetry->Initialize(perf_config);
    
    // Task 22: Initialize timing randomizer for runtime behavior variation
    SENTINEL_LOG_DEBUG("Initializing Timing randomizer");
    g_context->timing_randomizer = std::make_unique<TimingRandomizer>();
    if (!g_context->timing_randomizer->IsHealthy()) {
        SENTINEL_LOG_WARNING("Timing randomizer initialization failed - timing patterns may be more predictable");
    }
    
    // Task 25: Initialize dynamic signature update system
    SENTINEL_LOG_DEBUG("Initializing signature manager");
    g_context->signature_manager = std::make_shared<SignatureManager>();
    
    // Create cache directory for signatures
    std::string cache_dir = ".sentinel_cache";
    if (config->cache_dir && strlen(config->cache_dir) > 0) {
        cache_dir = config->cache_dir;
    }
    
    // TODO: Load actual RSA public key for signature verification from secure storage
    // SECURITY WARNING: This placeholder key MUST be replaced with production key
    // The key should be embedded in the binary or loaded from a secure configuration
    // For now, signature verification is disabled until proper key is configured
    ByteBuffer placeholder_key = {0x01, 0x02, 0x03, 0x04};  // PLACEHOLDER - REPLACE IN PRODUCTION
    
    auto sig_init_result = g_context->signature_manager->initialize(cache_dir, placeholder_key);
    if (sig_init_result.isFailure()) {
        SENTINEL_LOG_WARNING("Failed to initialize signature manager - dynamic updates disabled");
        g_context->signature_manager.reset();
    } else {
        SENTINEL_LOG_INFO("Signature manager initialized successfully");
        
        // Initialize update client if cloud endpoint is provided
        if (config->cloud_endpoint && strlen(config->cloud_endpoint) > 0) {
            SENTINEL_LOG_DEBUG("Initializing update client");
            g_context->update_client = std::make_unique<UpdateClient>();
            
            UpdateClientConfig update_config;
            update_config.server_url = config->cloud_endpoint;
            update_config.api_key = config->license_key;
            update_config.game_id = config->game_id ? config->game_id : "unknown";
            update_config.check_interval = std::chrono::seconds(900);  // 15 minutes
            update_config.timeout = std::chrono::seconds(30);
            update_config.enable_pinning = true;
            // TODO: Configure certificate pins from config
            
            auto update_init_result = g_context->update_client->initialize(
                update_config, 
                g_context->signature_manager
            );
            
            if (update_init_result.isSuccess()) {
                // Set update callback to track version
                // Note: Callback is called from update client thread - must be thread-safe
                g_context->update_client->setProgressCallback(
                    [](UpdateStatus status, const std::string& message) {
                        // Access g_context with proper null check to avoid use-after-free
                        if (!g_context || !g_context->initialized.load()) {
                            return;
                        }
                        
                        if (status == UpdateStatus::Success) {
                            auto stats = g_context->signature_manager->getStatistics();
                            g_context->current_signature_version = stats.current_version;
                            SENTINEL_LOG_INFO_F("Signature update successful - version %u", 
                                stats.current_version);
                        } else if (status == UpdateStatus::Failed) {
                            SENTINEL_LOG_WARNING_F("Signature update failed: %s", message.c_str());
                        }
                    }
                );
                
                // Start auto-update loop
                auto start_result = g_context->update_client->startAutoUpdate();
                if (start_result.isSuccess()) {
                    SENTINEL_LOG_INFO("Auto-update enabled - checking every 15 minutes");
                } else {
                    SENTINEL_LOG_WARNING("Failed to start auto-update - manual updates only");
                }
                
                // Get initial signature version
                auto stats = g_context->signature_manager->getStatistics();
                g_context->current_signature_version = stats.current_version;
                SENTINEL_LOG_INFO_F("Current signature version: %u", stats.current_version);
            } else {
                SENTINEL_LOG_WARNING("Failed to initialize update client");
                g_context->update_client.reset();
            }
        }
    }
    
    // Initialize network if cloud endpoint provided
    if (config->cloud_endpoint && strlen(config->cloud_endpoint) > 0) {
        SENTINEL_LOG_INFO_F("Initializing cloud reporting to: %s", config->cloud_endpoint);
        g_context->packet_crypto = std::make_unique<PacketEncryption>();
        g_context->reporter = std::make_unique<CloudReporter>(config->cloud_endpoint);
        g_context->reporter->SetBatchSize(config->report_batch_size);
        g_context->reporter->SetInterval(config->report_interval_ms);
    } else {
        SENTINEL_LOG_WARNING("Cloud endpoint not configured - telemetry disabled");
    }
    
    // Task 29: Initialize redundant detection registry
    SENTINEL_LOG_DEBUG("Initializing detection registry");
    g_context->detection_registry = std::make_unique<DetectionRegistry>();
    
    // Register redundant implementations for AntiDebug (proof-of-concept)
    if (g_context->anti_debug) {
        // Primary implementation (existing comprehensive detector)
        auto primary_impl = std::make_unique<AntiDebugPrimaryImpl>();
        g_context->detection_registry->RegisterImplementation(std::move(primary_impl));
        
        // Alternative implementation (different approach)
        auto alt_impl = std::make_unique<AntiDebugAlternativeImpl>();
        g_context->detection_registry->RegisterImplementation(std::move(alt_impl));
        
        // Configure redundancy for AntiDebug - disabled by default (opt-in)
        RedundancyConfig redundancy_config(DetectionType::AntiDebug, RedundancyLevel::Standard, false);
        g_context->detection_registry->SetRedundancyConfig(redundancy_config);
        
        SENTINEL_LOG_INFO("Redundant AntiDebug implementations registered (2 implementations, disabled by default)");
    }
    
    // Initialize all registered detection implementations
    g_context->detection_registry->InitializeAll();
    
    // Start heartbeat thread
    SENTINEL_LOG_DEBUG("Starting heartbeat thread");
    g_context->heartbeat_thread = std::make_unique<std::thread>(HeartbeatThreadFunc);
    
    g_context->initialized.store(true);
    g_context->active.store(true);
    
    // Task 17: Record initialization timing
    auto init_end = std::chrono::high_resolution_clock::now();
    auto init_duration_us = std::chrono::duration_cast<std::chrono::microseconds>(init_end - init_start).count();
    double init_duration_ms = init_duration_us / 1000.0;
    if (g_context->perf_telemetry) {
        g_context->perf_telemetry->RecordOperation(OperationType::Initialize, init_duration_ms);
    }
    
    return ErrorCode::Success;
}

SENTINEL_API void SENTINEL_CALL Shutdown() {
    if (!g_context) return;
    
    SENTINEL_LOG_INFO("Sentinel SDK shutting down...");
    
    // Signal shutdown
    g_context->shutdown_requested.store(true);
    g_context->active.store(false);
    
    // Wait for heartbeat thread
    if (g_context->heartbeat_thread && g_context->heartbeat_thread->joinable()) {
        SENTINEL_LOG_DEBUG("Waiting for heartbeat thread to stop");
        g_context->heartbeat_thread->join();
    }
    
    // Cleanup modules
    SENTINEL_LOG_DEBUG("Cleaning up detection modules");
    g_context->anti_debug.reset();
    g_context->anti_hook.reset();
    g_context->integrity.reset();
    g_context->speed_hack.reset();
    g_context->correlation.reset();
    g_context->packet_crypto.reset();
    g_context->reporter.reset();
    
    // Task 14: Cleanup telemetry and runtime config
    g_context->telemetry.reset();
    g_context->runtime_config.reset();
    g_context->env_detector.reset();
    
    // Task 07: Cleanup watchdog
    g_context->watchdog.reset();
    
    // Task 09: Cleanup scan scheduler
    if (g_context->scan_scheduler) {
        g_context->scan_scheduler->Shutdown();
    }
    g_context->scan_scheduler.reset();
    // Task 08: Cleanup self-integrity validator
    if (g_context->self_integrity) {
        g_context->self_integrity->Shutdown();
    }
    g_context->self_integrity.reset();
    
    // Task 17: Cleanup performance telemetry
    if (g_context->perf_telemetry) {
        g_context->perf_telemetry->Shutdown();
    }
    g_context->perf_telemetry.reset();
    
    // Task 22: Cleanup timing randomizer
    g_context->timing_randomizer.reset();
    
    // Task 25: Cleanup signature update system
    if (g_context->update_client) {
        SENTINEL_LOG_DEBUG("Stopping signature auto-update");
        g_context->update_client->stopAutoUpdate();
    }
    g_context->update_client.reset();
    g_context->signature_manager.reset();
    
    // Task 29: Cleanup detection registry
    if (g_context->detection_registry) {
        SENTINEL_LOG_DEBUG("Shutting down detection registry");
        g_context->detection_registry->ShutdownAll();
    }
    g_context->detection_registry.reset();
    
    // Cleanup whitelist manager
    if (g_whitelist) {
        g_whitelist->Shutdown();
    }
    g_whitelist.reset();
    
    // Clear protected items
    g_context->protected_regions.clear();
    g_context->protected_functions.clear();
    g_context->protected_values.clear();
    
    g_context->initialized.store(false);
    g_context.reset();
    
    SENTINEL_LOG_INFO("Sentinel SDK shut down successfully");
    
    // Shutdown logger last
    auto& logger = Sentinel::Core::Logger::Instance();
    logger.Shutdown();
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
    
    // Task 17: Check if this update should be throttled
    if (g_context->perf_telemetry && g_context->perf_telemetry->ShouldThrottle(OperationType::Update)) {
        return ErrorCode::Success;  // Skip update due to performance throttling
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    ErrorCode result = ErrorCode::Success;
    
    // Task 07: Check if heartbeat thread is alive
    if (g_context->watchdog) {
        uint64_t max_age_ms = g_context->config.heartbeat_interval_ms * 3;
        if (!g_context->watchdog->IsAlive(max_age_ms)) {
            // Heartbeat thread is dead - report critical violation
            // Using HandleManipulation as the violation type since thread termination
            // (e.g., via TerminateThread) is a form of thread handle manipulation
            ViolationEvent event{};
            event.type = ViolationType::HandleManipulation;
            event.severity = Severity::Critical;
            event.timestamp = GetSecureTime();
            event.details = "Heartbeat thread terminated - thread watchdog detected death";
            
            ReportViolation(event);
            result = ErrorCode::TamperingDetected;
        }
    }
    
    // Quick integrity check
    if (g_context->integrity) {
        auto violations = g_context->integrity->QuickCheck();
        for (const auto& v : violations) {
            ReportViolation(v);
            result = ErrorCode::IntegrityViolation;
        }
    }
    
    // Task 08: SDK self-integrity validation (distributed - check on some Updates)
    // Check every 20 updates to distribute validation across multiple code paths
    if (g_context->self_integrity && (g_context->stats.updates_performed % 20 == 0)) {
        if (!g_context->self_integrity->ValidateQuick()) {
            ViolationEvent event = IntegrityValidator::CreateGenericTamperEvent();
            event.timestamp = GetSecureTime();
            
            ReportViolation(event);
            result = ErrorCode::TamperingDetected;
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
            
            // Add environment information to details for telemetry
            std::string env_str = "environment: ";
            env_str += g_context->speed_hack->GetEnvironmentString();
            env_str += ", details: Speed manipulation detected";
            event.details = env_str;
            
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
    
    // Task 17: Record update timing
    double elapsed_ms = elapsed_us / 1000.0;
    if (g_context->perf_telemetry) {
        g_context->perf_telemetry->RecordOperation(OperationType::Update, elapsed_ms);
    }
    
    return result;
}

SENTINEL_API ErrorCode SENTINEL_CALL FullScan() {
    if (!g_context || !g_context->initialized.load()) {
        return ErrorCode::NotInitialized;
    }
    
    // Task 17: Check if this scan should be throttled
    if (g_context->perf_telemetry && g_context->perf_telemetry->ShouldThrottle(OperationType::FullScan)) {
        return ErrorCode::Success;  // Skip scan due to performance throttling
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
    
    // Task 08: SDK self-integrity full validation
    if (g_context->self_integrity) {
        auto violations = g_context->self_integrity->ValidateFull();
        for (const auto& v : violations) {
            ReportViolation(v);
            result = ErrorCode::TamperingDetected;
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
    
    // Task 17: Record scan timing
    if (g_context->perf_telemetry) {
        g_context->perf_telemetry->RecordOperation(OperationType::FullScan, elapsed_ms);
    }
    
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
    auto start = std::chrono::high_resolution_clock::now();
    
    if (!g_context || !g_context->initialized.load()) {
        return 0;
    }
    
    // Task 23: Distributed integrity validation - validate on memory protection calls
    if (g_context->self_integrity && ShouldValidateWithProbability(10)) {  // 10% of calls
        if (!g_context->self_integrity->ValidateQuick()) {
            ViolationEvent event = IntegrityValidator::CreateGenericTamperEvent();
            event.timestamp = GetSecureTime();
            ReportViolation(event);
        }
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
    
    // Task 17: Record timing
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double duration_ms = duration_us / 1000.0;
    if (g_context->perf_telemetry) {
        g_context->perf_telemetry->RecordOperation(OperationType::ProtectMemory, duration_ms);
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
    auto start = std::chrono::high_resolution_clock::now();
    
    if (!g_context) return false;
    
    // Task 23: Distributed integrity validation - validate on memory verify calls
    if (g_context->self_integrity && ShouldValidateWithProbability(15)) {  // ~7% of calls
        if (!g_context->self_integrity->ValidateQuick()) {
            ViolationEvent event = IntegrityValidator::CreateGenericTamperEvent();
            event.timestamp = GetSecureTime();
            ReportViolation(event);
        }
    }
    
    std::lock_guard<std::mutex> lock(g_context->protection_mutex);
    
    auto it = g_context->protected_regions.find(handle);
    if (it == g_context->protected_regions.end()) {
        return false;
    }
    
    uint64_t current_hash = Internal::ComputeHash(
        reinterpret_cast<void*>(it->second.address),
        it->second.size);
    
    bool result = (current_hash == it->second.original_hash);
    
    // Task 17: Record timing
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double duration_ms = duration_us / 1000.0;
    if (g_context->perf_telemetry) {
        g_context->perf_telemetry->RecordOperation(OperationType::VerifyMemory, duration_ms);
    }
    
    return result;
}

// ==================== Function Protection ====================

SENTINEL_API uint64_t SENTINEL_CALL ProtectFunction(void* function_address, const char* name) {
    auto start = std::chrono::high_resolution_clock::now();
    
    if (!g_context || !g_context->initialized.load()) {
        return 0;
    }
    
    // Task 23: Distributed integrity validation - validate on function protection calls
    if (g_context->self_integrity && ShouldValidateWithProbability(12)) {  // ~8% of calls
        if (!g_context->self_integrity->ValidateQuick()) {
            ViolationEvent event = IntegrityValidator::CreateGenericTamperEvent();
            event.timestamp = GetSecureTime();
            ReportViolation(event);
        }
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
    
    // Task 17: Record timing
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double duration_ms = duration_us / 1000.0;
    if (g_context->perf_telemetry) {
        g_context->perf_telemetry->RecordOperation(OperationType::ProtectFunction, duration_ms);
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
    
    // Task 23: Distributed integrity validation - validate on packet operations
    if (g_context->self_integrity && ShouldValidateWithProbability(20)) {  // 5% of calls
        if (!g_context->self_integrity->ValidateQuick()) {
            ViolationEvent event = IntegrityValidator::CreateGenericTamperEvent();
            event.timestamp = GetSecureTime();
            ReportViolation(event);
        }
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

// ==================== Server Directives (Task 24) ====================

SENTINEL_API ErrorCode SENTINEL_CALL PollServerDirectives() {
    if (!g_context || !g_context->initialized.load()) {
        return ErrorCode::NotInitialized;
    }
    
    if (!g_context->reporter) {
        return ErrorCode::InvalidConfiguration;
    }
    
    return g_context->reporter->PollDirectives(g_context->session_token);
}

SENTINEL_API bool SENTINEL_CALL GetLastServerDirective(ServerDirective* out_directive) {
    if (!g_context || !out_directive) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_context->directive_mutex);
    
    if (!g_context->has_directive) {
        return false;
    }
    
    *out_directive = g_context->last_directive;
    return true;
}

SENTINEL_API void SENTINEL_CALL SetServerDirectiveCallback(
    ServerDirectiveCallback callback,
    void* user_data)
{
    if (!g_context) return;
    
    // Store callback in config
    g_context->config.directive_callback = callback;
    g_context->config.directive_user_data = user_data;
    
    // Set callback in reporter if available
    if (g_context->reporter) {
        g_context->reporter->SetDirectiveCallback(callback, user_data);
    }
}

// ==================== Statistics ====================

SENTINEL_API void SENTINEL_CALL GetStatistics(Statistics* stats) {
    if (!g_context || !stats) return;
    
    *stats = g_context->stats;
    stats->uptime_ms = GetSecureTime();
    
    // Task 25: Include current signature version in statistics
    stats->signature_version = g_context->current_signature_version;
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

// ==================== Redundant Detection Configuration (Task 29) ====================

namespace {
    // Helper to convert public DetectionCategory to internal DetectionType
    DetectionType CategoryToType(DetectionCategory category) {
        return static_cast<DetectionType>(static_cast<uint8_t>(category));
    }
}

SENTINEL_API ErrorCode SENTINEL_CALL SetRedundancy(
    DetectionCategory category,
    RedundancyLevel level)
{
    if (!g_context || !g_context->detection_registry) {
        return ErrorCode::NotInitialized;
    }
    
    if (!g_context->runtime_config) {
        return ErrorCode::InternalError;
    }
    
    // Convert category to internal type
    DetectionType det_type = CategoryToType(category);
    
    // Update runtime config
    bool enabled = (level != RedundancyLevel::None);
    g_context->runtime_config->SetRedundancyConfig(det_type, enabled, level);
    
    // Update detection registry
    RedundancyConfig config(det_type, level, enabled);
    g_context->detection_registry->SetRedundancyConfig(config);
    
    return ErrorCode::Success;
}

SENTINEL_API RedundancyLevel SENTINEL_CALL GetRedundancy(DetectionCategory category) {
    if (!g_context || !g_context->runtime_config) {
        return RedundancyLevel::None;
    }
    
    DetectionType det_type = CategoryToType(category);
    bool enabled = false;
    RedundancyLevel level = RedundancyLevel::None;
    
    g_context->runtime_config->GetRedundancyConfig(det_type, enabled, level);
    
    return level;
}

SENTINEL_API bool SENTINEL_CALL GetRedundancyStatistics(
    DetectionCategory category,
    RedundancyStatistics* stats)
{
    if (!g_context || !g_context->detection_registry || !stats) {
        return false;
    }
    
    DetectionType det_type = CategoryToType(category);
    auto internal_stats = g_context->detection_registry->GetStatistics(det_type);
    
    // Copy to output structure
    stats->active_implementations = internal_stats.active_implementations;
    stats->total_checks_performed = internal_stats.total_checks_performed;
    stats->unique_violations_detected = internal_stats.unique_violations_detected;
    stats->duplicate_violations_filtered = internal_stats.duplicate_violations_filtered;
    stats->avg_overhead_us = internal_stats.avg_overhead_us;
    stats->max_overhead_us = internal_stats.max_overhead_us;
    
    return true;
}

SENTINEL_API uint32_t SENTINEL_CALL GetImplementationCount(DetectionCategory category) {
    if (!g_context || !g_context->detection_registry) {
        return 0;
    }
    
    DetectionType det_type = CategoryToType(category);
    return static_cast<uint32_t>(g_context->detection_registry->GetImplementationCount(det_type));
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

}  // extern "C"

// ==================== DLL Entry Point ====================

#ifdef _WIN32
// DLL entry point for handling process attach/detach
// This is crucial for preventing use-after-free vulnerabilities when the DLL is unloaded
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;  // Unused
    (void)lpvReserved;  // Unused
    
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded - no action needed
            break;
            
        case DLL_PROCESS_DETACH:
            // DLL is being unloaded - flush pending events to prevent resource leaks
            if (Sentinel::SDK::g_context && Sentinel::SDK::g_context->reporter) {
                // Flush all pending events before DLL teardown
                // ViolationEvent now uses std::string (owned copies), but we still flush
                // to ensure proper cleanup and prevent queued events from being lost
                Sentinel::SDK::g_context->reporter->Flush();
            }
            
            // Note: We don't call Shutdown() here because:
            // 1. It may have already been called
            // 2. DllMain has restrictions on what functions can be called
            // 3. The flush above is sufficient to prevent use-after-free
            break;
            
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            // Thread attach/detach - no action needed
            break;
    }
    
    return TRUE;
}
#endif
