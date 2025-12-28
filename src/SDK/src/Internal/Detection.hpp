/**
 * Sentinel SDK - Detection Module Interfaces
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#pragma once

#include "SentinelSDK.hpp"
#include "Context.hpp"
#include "Whitelist.hpp"
#include "JITSignature.hpp"

#include <vector>
#include <cstdint>
#include <mutex>
#include <string>

namespace Sentinel {
namespace SDK {

// Forward declaration of global whitelist manager
extern WhitelistManager* g_whitelist;

/**
 * Anti-debugging detection module
 */
class AntiDebugDetector {
public:
    void Initialize();
    void Shutdown();
    
    std::vector<ViolationEvent> Check();
    std::vector<ViolationEvent> FullCheck();
    
private:
    bool CheckIsDebuggerPresent();
    bool CheckRemoteDebugger();
    bool CheckDebugPort();
    bool CheckDebugObject();
    bool CheckHardwareBreakpoints();
    bool CheckTimingAnomaly();
    bool CheckSEHIntegrity();
    bool CheckPEB();
    bool CheckNtGlobalFlag();
    bool CheckHeapFlags();
    
    // Helper methods
    void CalibrateTimingBaseline();
    bool DetectHypervisor();
    bool CheckTimingStatistical();
    bool CheckAllThreadsHardwareBP();
    
    // Task 14: PEB patching detection helpers
    bool CheckHeapFlagsVsNtGlobalFlag();
    bool CheckParentProcessDebugger();
    
    // Rate limiting
    uint64_t last_check_time_ = 0;
    int check_count_ = 0;
    
    // Calibration data
    double baseline_mean_ = 0.0;
    double baseline_stddev_ = 0.0;
    double threshold_us_ = 500.0;          // Default threshold in microseconds
    uint64_t threshold_cycles_ = 10000;     // Default threshold in CPU cycles
    
    // Environment detection
    bool hypervisor_detected_ = false;
    
    // Timing anomaly tracking
    int consecutive_anomaly_count_ = 0;
    uint64_t last_successful_check_time_ = 0;
    uint64_t last_anomaly_detection_time_ = 0;
    
    // Telemetry
    uint64_t timing_check_count_ = 0;
    uint64_t timing_anomaly_count_ = 0;
    
    // Thread enumeration caching
    uint64_t last_thread_cache_time_ = 0;
    std::vector<uint32_t> cached_thread_ids_;
    static constexpr uint64_t THREAD_CACHE_REFRESH_MS = 5000;  // 5 seconds
};

/**
 * Hook detection module
 */
class AntiHookDetector {
public:
    void Initialize();
    void Shutdown();
    
    void RegisterFunction(const FunctionProtection& func);
    void UnregisterFunction(uintptr_t address);
    void UnregisterFunctionsInModule(uintptr_t module_base);
    
    // Honeypot function registration
    void RegisterHoneypot(const FunctionProtection& func);
    void UnregisterHoneypot(uintptr_t address);
    
    bool CheckFunction(uintptr_t address);
    bool IsIATHooked(const char* module_name, const char* function_name);
    bool IsDelayLoadIATHooked(const char* module_name, const char* function_name);
    std::vector<ViolationEvent> QuickCheck();
    std::vector<ViolationEvent> FullScan();
    
private:
    bool IsInlineHooked(const FunctionProtection& func);
    bool HasSuspiciousJump(const void* address);
    std::vector<ViolationEvent> ScanCriticalAPIs();
    std::vector<ViolationEvent> CheckHoneypots();
    
    // Probabilistic scanning helpers
    void SelectFunctionsToScan(std::vector<size_t>& indices_out, size_t max_count);
    void ApplyScanCycleJitter();
    uint64_t GetCurrentTimeMs() const;
    
#ifdef _WIN32
    static void CALLBACK DllNotificationCallback(
        ULONG notification_reason,
        const void* notification_data,
        void* context);
    void SetupDllNotification();
    void CleanupDllNotification();
    void* dll_notification_cookie_ = nullptr;
    void* scan_timer_handle_ = nullptr;  // High-resolution waitable timer
#endif
    
    std::vector<FunctionProtection> registered_functions_;
    std::vector<FunctionProtection> honeypot_functions_;
    std::mutex functions_mutex_;
    
    // Scan state tracking for budget enforcement
    uint64_t current_scan_start_time_ms_ = 0;
    static constexpr uint64_t SCAN_BUDGET_MS = 5;  // 5ms max per scan cycle
    static constexpr uint64_t FULL_COVERAGE_WINDOW_MS = 500;  // 500ms coverage guarantee
    static constexpr float PROBABILISTIC_SCAN_RATIO = 0.15f;  // 15% of functions per cycle (10-20% range)
};

/**
 * Memory integrity checking module
 */
class IntegrityChecker {
public:
    void Initialize();
    void Shutdown();
    
    void RegisterRegion(const MemoryRegion& region);
    void UnregisterRegion(uintptr_t address);
    void UnregisterRegionsInModule(uintptr_t module_base);
    
    std::vector<ViolationEvent> QuickCheck();
    std::vector<ViolationEvent> FullScan();
    
private:
    bool VerifyRegion(const MemoryRegion& region);
    bool VerifyCodeSection();
    bool VerifyImportTable();
    
    std::vector<MemoryRegion> registered_regions_;
    uint64_t code_section_hash_ = 0;
    uintptr_t code_section_base_ = 0;
    size_t code_section_size_ = 0;
    std::mutex regions_mutex_;
};

/**
 * Speed hack detection module
 */
class SpeedHackDetector {
public:
    void Initialize();
    void Shutdown();
    
    void UpdateBaseline();
    bool ValidateFrame();
    
    float GetTimeScale() const { return current_time_scale_; }
    
private:
    uint64_t GetSystemTime();
    uint64_t GetPerformanceCounter();
    uint64_t GetRDTSC();
    bool ValidateSourceRatios();
    bool ValidateAgainstWallClock();
    void RecalibrateRDTSC();
    bool DetectHypervisor();
    bool IsFrequencyPlausible(double frequency_mhz);
    
    // Multiple time sources for cross-validation
    uint64_t baseline_system_time_ = 0;
    uint64_t baseline_perf_counter_ = 0;
    uint64_t baseline_rdtsc_ = 0;
    
    uint64_t last_system_time_ = 0;
    uint64_t last_perf_counter_ = 0;
    uint64_t last_rdtsc_ = 0;
    
    float current_time_scale_ = 1.0f;
    int anomaly_count_ = 0;
    
    // Wall clock validation state
    uint64_t wall_clock_baseline_time_ = 0;
    uint64_t wall_clock_baseline_qpc_ = 0;
    int frame_counter_ = 0;
    
    // RDTSC calibration
    double rdtsc_frequency_mhz_ = 0.0;
    uint64_t rdtsc_calibration_time_ = 0;
    static constexpr int CALIBRATION_HISTORY_SIZE = 10;
    double calibration_history_[CALIBRATION_HISTORY_SIZE] = {0};
    int calibration_history_index_ = 0;
    bool hypervisor_detected_ = false;
    
    // Detection thresholds and constants
    static constexpr float MAX_TIME_SCALE_DEVIATION = 0.25f;  // 25% tolerance
    static constexpr int MONOTONICITY_VIOLATION_PENALTY = 2;  // Extra anomaly points for time going backwards
    static constexpr double FALLBACK_CPU_FREQUENCY_MHZ = 2400.0;  // Conservative fallback if calibration fails
    static constexpr double MIN_CPU_FREQUENCY_MHZ = 500.0;  // Minimum plausible CPU frequency
    static constexpr double MAX_CPU_FREQUENCY_MHZ = 6000.0;  // Maximum plausible CPU frequency
    static constexpr double MAX_FREQUENCY_JUMP_PERCENT = 0.10;  // 10% max jump between calibrations
    static constexpr uint64_t RECALIBRATION_INTERVAL_MS = 60000;  // 60 seconds
};

/**
 * Injection detection module
 */
class InjectionDetector {
public:
    void Initialize();
    void Shutdown();
    
    std::vector<ViolationEvent> ScanLoadedModules();
    std::vector<ViolationEvent> ScanThreads();
    
    /**
     * Scan loaded modules with signature verification
     * @return Vector of violations for unsigned, tampered, or proxy DLLs
     */
    std::vector<ViolationEvent> ScanModuleSignatures();
    
private:
    void EnumerateKnownModules();
    bool IsModuleSuspicious(const wchar_t* module_path);
    bool IsThreadSuspicious(uint32_t thread_id);
    
    // Baseline tracking
    struct MemoryBaseline {
        uintptr_t base_address;
        size_t region_size;
    };
    
#ifdef _WIN32
    bool IsSuspiciousRegion(const MEMORY_BASIC_INFORMATION& mbi);
    bool IsKnownJITRegion(uintptr_t address);
    std::string DescribeRegion(const MEMORY_BASIC_INFORMATION& mbi);
    
    void CaptureBaseline();
    bool IsInBaseline(uintptr_t address, size_t size) const;
    
    // Heuristic scoring
    float CalculateSuspicionScore(const MEMORY_BASIC_INFORMATION& mbi) const;
    bool HasPEHeader(uintptr_t address) const;
    bool IsNearKnownModule(uintptr_t address) const;
    Severity GetSeverityFromScore(float score) const;
    
    // Thread validation helpers
    bool IsWindowsThreadPoolThread(uintptr_t startAddress);
    bool IsCLRThread(uintptr_t startAddress);
    bool IsLegitimateTrampoline(uintptr_t address, const MEMORY_BASIC_INFORMATION& mbi);
#endif
    
    std::vector<std::wstring> known_modules_;
    std::vector<MemoryBaseline> baseline_regions_;
    JITSignatureValidator jit_validator_;
};

/**
 * Network packet encryption
 */
class PacketEncryption {
public:
    void Initialize();
    void Shutdown();
    
    /**
     * Set key derivation parameters (must be called before first use)
     * @param hardware_id Hardware fingerprint
     * @param session_token Session authentication token
     * @param server_nonce Server-provided random nonce (32 bytes)
     * @param server_salt Server-provided random salt (32 bytes)
     */
    void SetKeyDerivationParams(
        const char* hardware_id,
        const char* session_token,
        const uint8_t* server_nonce,
        const uint8_t* server_salt);
    
    ErrorCode Encrypt(const void* data, size_t size, void* out_buffer, size_t* out_size);
    ErrorCode Decrypt(const void* data, size_t size, void* out_buffer, size_t* out_size);
    
    uint32_t GetNextSequence();
    bool ValidateSequence(uint32_t sequence);
    
private:
    void DeriveSessionKey();
    void RotateKeyIfNeeded();
    bool ValidateTimestamp(uint64_t timestamp);
    ErrorCode ComputeHMAC(const void* data, size_t size, uint8_t* hmac_out);
    ErrorCode VerifyHMAC(const void* data, size_t size, const uint8_t* expected_hmac);
    
    uint8_t session_key_[32];
    uint8_t hmac_key_[32];
    uint32_t current_sequence_ = 0;
    uint32_t expected_sequence_ = 0;
    
    // Key rotation
    uint32_t packets_since_rotation_ = 0;
    static constexpr uint32_t KEY_ROTATION_INTERVAL = 10000;
    
    // Replay detection with sliding window
    static constexpr uint32_t SEQUENCE_WINDOW = 1000;
    uint32_t window_base_ = 0;
    uint8_t window_bitmap_[125];  // 1000 bits / 8 = 125 bytes
    
    // Timestamp validation
    uint64_t session_start_time_ = 0;
    static constexpr uint64_t TIMESTAMP_TOLERANCE_MS = 30000;  // 30 seconds
    
    // Key derivation parameters
    std::string hardware_id_;
    std::string session_token_;
    uint8_t server_nonce_[32];
    uint8_t server_salt_[32];
    bool params_set_ = false;
};

/**
 * Cloud event reporter
 */
class CloudReporter {
public:
    explicit CloudReporter(const char* endpoint);
    ~CloudReporter();
    
    void SetBatchSize(uint32_t size) { batch_size_ = size; }
    void SetInterval(uint32_t ms) { interval_ms_ = ms; }
    
    void QueueEvent(const ViolationEvent& event);
    ErrorCode ReportCustomEvent(const char* type, const char* data);
    
    void Flush();
    
private:
    void ReportThread();
    ErrorCode SendBatch();
    
    std::string endpoint_;
    uint32_t batch_size_ = 10;
    uint32_t interval_ms_ = 30000;
    
    std::vector<ViolationEvent> event_queue_;
    bool running_ = false;
};

} // namespace SDK
} // namespace Sentinel
