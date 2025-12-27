/**
 * Sentinel SDK - In-Game Security Shield
 * 
 * Lightweight, high-performance anti-cheat library for game developers
 * Performance target: < 0.01ms overhead per frame
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#pragma once

// SDK Version
#define SENTINEL_SDK_VERSION_MAJOR 1
#define SENTINEL_SDK_VERSION_MINOR 0
#define SENTINEL_SDK_VERSION_PATCH 0
#define SENTINEL_SDK_VERSION_STRING "1.0.0"

// Platform detection
#ifdef _WIN32
    #define SENTINEL_PLATFORM_WINDOWS 1
    #ifdef _WIN64
        #define SENTINEL_PLATFORM_X64 1
    #else
        #define SENTINEL_PLATFORM_X86 1
    #endif
#elif defined(__linux__)
    #define SENTINEL_PLATFORM_LINUX 1
#elif defined(__APPLE__)
    #define SENTINEL_PLATFORM_MACOS 1
#endif

// Export/Import macros
#ifdef SENTINEL_SDK_EXPORTS
    #ifdef _WIN32
        #define SENTINEL_API __declspec(dllexport)
    #else
        #define SENTINEL_API __attribute__((visibility("default")))
    #endif
#else
    #ifdef _WIN32
        #define SENTINEL_API __declspec(dllimport)
    #else
        #define SENTINEL_API
    #endif
#endif

#ifdef _WIN32
    #define SENTINEL_CALL __stdcall
#else
    #define SENTINEL_CALL
#endif

#include <cstdint>
#include <cstddef>

namespace Sentinel {
namespace SDK {

// ==================== Error Codes ====================

/**
 * SDK error codes
 */
enum class ErrorCode : uint32_t {
    Success = 0,
    
    // Initialization errors (1-99)
    NotInitialized = 1,
    AlreadyInitialized = 2,
    InitializationFailed = 3,
    InvalidLicense = 4,
    LicenseExpired = 5,
    VersionMismatch = 6,
    
    // Runtime errors (100-199)
    InvalidParameter = 100,
    InternalError = 101,
    OutOfMemory = 102,
    Timeout = 103,
    NetworkError = 104,
    
    // Security events (200-299)
    TamperingDetected = 200,
    DebuggerDetected = 201,
    InjectionDetected = 202,
    HookDetected = 203,
    MemoryManipulation = 204,
    ProcessManipulation = 205,
    SignatureMismatch = 206,
    IntegrityViolation = 207,
    
    // Configuration errors (300-399)
    InvalidConfiguration = 300,
    MissingConfiguration = 301,
    ConfigurationParseError = 302
};

// ==================== Security Events ====================

/**
 * Types of security violations
 */
enum class ViolationType : uint32_t {
    None = 0,
    
    // Memory violations
    MemoryRead = 0x0001,
    MemoryWrite = 0x0002,
    MemoryExecute = 0x0004,
    CodeInjection = 0x0008,
    InjectedCode = 0x0009,          ///< Manually mapped or injected code detected
    
    // Process violations
    DebuggerAttached = 0x0010,
    RemoteThread = 0x0020,
    ProcessHollow = 0x0040,
    HandleManipulation = 0x0080,
    SuspiciousThread = 0x0081,      ///< Thread with suspicious start address
    
    // Hook violations
    InlineHook = 0x0100,
    IATHook = 0x0200,
    VTableHook = 0x0400,
    SyscallHook = 0x0800,
    
    // Integrity violations
    ModuleModified = 0x1000,
    ChecksumMismatch = 0x2000,
    SignatureInvalid = 0x4000,
    TimingAnomaly = 0x8000,
    
    // Network violations
    PacketManipulation = 0x10000,
    InvalidPacket = 0x20000,
    ReplayAttack = 0x40000,
    SpeedHack = 0x80000
};

/**
 * Severity levels for violations
 */
enum class Severity : uint8_t {
    Info = 0,       ///< Informational, no action needed
    Warning = 1,    ///< Suspicious, log and monitor
    High = 2,       ///< Likely cheat, take action
    Critical = 3    ///< Confirmed cheat, immediate action
};

/**
 * Security violation event data
 */
struct ViolationEvent {
    ViolationType type;         ///< Type of violation
    Severity severity;          ///< Severity level
    uint64_t timestamp;         ///< Event timestamp (ms since init)
    uint64_t address;           ///< Related memory address (if applicable)
    const char* module_name;    ///< Related module name
    const char* details;        ///< Additional details
    uint32_t detection_id;      ///< Unique detection identifier
};

/**
 * Callback for security violations
 * @param event Violation event data
 * @param user_data User-provided context
 * @return true to continue monitoring, false to suppress further events of this type
 */
typedef bool (SENTINEL_CALL *ViolationCallback)(const ViolationEvent* event, void* user_data);

// ==================== Configuration ====================

/**
 * Detection features to enable
 */
enum class DetectionFeatures : uint32_t {
    None = 0,
    
    // Memory protection
    MemoryIntegrity = 0x0001,        ///< Monitor memory modifications
    CodeIntegrity = 0x0002,          ///< Monitor code section changes
    StackProtection = 0x0004,        ///< Stack corruption detection
    HeapProtection = 0x0008,         ///< Heap corruption detection
    
    // Process protection
    AntiDebug = 0x0010,              ///< Debugger detection
    AntiAttach = 0x0020,             ///< Prevent debugger attachment
    ThreadMonitor = 0x0040,          ///< Monitor thread creation
    HandleProtection = 0x0080,       ///< Protect process handles
    
    // Hook detection
    InlineHookDetect = 0x0100,       ///< Detect inline hooks
    IATHookDetect = 0x0200,          ///< Detect IAT hooks
    VTableProtect = 0x0400,          ///< VTable modification detection
    
    // Timing protection
    SpeedHackDetect = 0x1000,        ///< Speed manipulation detection
    TimingIntegrity = 0x2000,        ///< Timing consistency checks
    
    // Network protection
    PacketValidation = 0x4000,       ///< Validate network packets
    RateLimiting = 0x8000,           ///< Detect unusual packet rates
    
    // Recommended preset combinations
    Minimal = MemoryIntegrity | AntiDebug,
    Standard = Minimal | CodeIntegrity | InlineHookDetect | IATHookDetect,
    Full = 0xFFFF                    ///< All features enabled
};

/**
 * Response actions for violations
 */
enum class ResponseAction : uint32_t {
    None = 0,           ///< No automatic action
    Log = 0x01,         ///< Log the event
    Report = 0x02,      ///< Report to cloud
    Notify = 0x04,      ///< Notify callback
    Warn = 0x08,        ///< Display warning to user
    Kick = 0x10,        ///< Disconnect from server
    Ban = 0x20,         ///< Request ban
    Terminate = 0x40,   ///< Terminate process
    
    // Presets
    Silent = Log | Report,
    Default = Log | Report | Notify,
    Aggressive = Log | Report | Notify | Kick
};

/**
 * SDK initialization configuration
 */
struct Configuration {
    // Version info (set automatically)
    uint32_t struct_size;           ///< Size of this struct for versioning
    
    // License
    const char* license_key;        ///< License key for validation
    const char* game_id;            ///< Unique game identifier
    
    // Features
    DetectionFeatures features;     ///< Detection features to enable
    ResponseAction default_action;  ///< Default action for violations
    
    // Callbacks
    ViolationCallback violation_callback;   ///< Violation event callback
    void* callback_user_data;               ///< User data for callbacks
    
    // Performance tuning
    uint32_t heartbeat_interval_ms; ///< Heartbeat check interval (default: 1000)
    uint32_t integrity_scan_interval_ms;  ///< Full integrity scan interval (default: 5000)
    uint32_t memory_scan_chunk_size;      ///< Memory scan chunk size (default: 4096)
    
    // Network (optional cloud reporting)
    const char* cloud_endpoint;     ///< Cloud reporting endpoint (NULL to disable)
    uint32_t report_batch_size;     ///< Events to batch before reporting
    uint32_t report_interval_ms;    ///< Report interval in milliseconds
    
    // Debug (disable in release!)
    bool debug_mode;                ///< Enable debug logging
    const char* log_path;           ///< Path for debug log file
    
    /**
     * Create configuration with defaults
     */
    static Configuration Default() {
        Configuration config = {};
        config.struct_size = sizeof(Configuration);
        config.features = DetectionFeatures::Standard;
        config.default_action = ResponseAction::Default;
        config.heartbeat_interval_ms = 1000;
        config.integrity_scan_interval_ms = 5000;
        config.memory_scan_chunk_size = 4096;
        config.report_batch_size = 10;
        config.report_interval_ms = 30000;
        config.debug_mode = false;
        return config;
    }
};

// ==================== Core API ====================

/**
 * Initialize the Sentinel SDK
 * Must be called before any other SDK functions
 * @param config Configuration options
 * @return Error code
 */
SENTINEL_API ErrorCode SENTINEL_CALL Initialize(const Configuration* config);

/**
 * Shutdown the SDK and release resources
 */
SENTINEL_API void SENTINEL_CALL Shutdown();

/**
 * Check if SDK is initialized
 * @return true if initialized
 */
SENTINEL_API bool SENTINEL_CALL IsInitialized();

/**
 * Get SDK version string
 * @return Version string (e.g., "1.0.0")
 */
SENTINEL_API const char* SENTINEL_CALL GetVersion();

/**
 * Get last error message
 * @return Error message string
 */
SENTINEL_API const char* SENTINEL_CALL GetLastError();

// ==================== Runtime Control ====================

/**
 * Called once per game frame
 * Performs lightweight integrity checks
 * @return Error code (Success if no violations)
 */
SENTINEL_API ErrorCode SENTINEL_CALL Update();

/**
 * Force a full integrity scan
 * More thorough but slower than Update()
 * @return Error code
 */
SENTINEL_API ErrorCode SENTINEL_CALL FullScan();

/**
 * Pause all monitoring
 * Use sparingly (e.g., during loading screens)
 */
SENTINEL_API void SENTINEL_CALL Pause();

/**
 * Resume monitoring after Pause()
 */
SENTINEL_API void SENTINEL_CALL Resume();

/**
 * Check if monitoring is currently active
 * @return true if active
 */
SENTINEL_API bool SENTINEL_CALL IsActive();

// ==================== Memory Protection ====================

/**
 * Register a memory region for protection
 * @param address Start address
 * @param size Size in bytes
 * @param name Optional name for logging
 * @return Region handle or 0 on failure
 */
SENTINEL_API uint64_t SENTINEL_CALL ProtectMemory(
    void* address,
    size_t size,
    const char* name);

/**
 * Unprotect a previously protected region
 * @param handle Region handle from ProtectMemory
 */
SENTINEL_API void SENTINEL_CALL UnprotectMemory(uint64_t handle);

/**
 * Verify integrity of a protected region
 * @param handle Region handle
 * @return true if integrity intact
 */
SENTINEL_API bool SENTINEL_CALL VerifyMemory(uint64_t handle);

// ==================== Function Protection ====================

/**
 * Protect a function from hooking
 * @param function_address Address of function to protect
 * @param name Optional function name
 * @return Protection handle or 0 on failure
 */
SENTINEL_API uint64_t SENTINEL_CALL ProtectFunction(
    void* function_address,
    const char* name);

/**
 * Remove function protection
 * @param handle Protection handle
 */
SENTINEL_API void SENTINEL_CALL UnprotectFunction(uint64_t handle);

/**
 * Check if a function is hooked
 * @param function_address Function address to check
 * @return true if hook detected
 */
SENTINEL_API bool SENTINEL_CALL IsHooked(void* function_address);

// ==================== Value Protection ====================

/**
 * Create a protected integer value
 * Obfuscated storage resistant to memory scanning
 * @param initial_value Initial value
 * @return Handle to protected value
 */
SENTINEL_API uint64_t SENTINEL_CALL CreateProtectedInt(int64_t initial_value);

/**
 * Set a protected integer value
 * @param handle Value handle
 * @param value New value
 */
SENTINEL_API void SENTINEL_CALL SetProtectedInt(uint64_t handle, int64_t value);

/**
 * Get a protected integer value
 * @param handle Value handle
 * @return Current value
 */
SENTINEL_API int64_t SENTINEL_CALL GetProtectedInt(uint64_t handle);

/**
 * Destroy a protected value
 * @param handle Value handle
 */
SENTINEL_API void SENTINEL_CALL DestroyProtectedValue(uint64_t handle);

// ==================== Secure Timing ====================

/**
 * Get secure timestamp (resistant to time manipulation)
 * @return Milliseconds since SDK initialization
 */
SENTINEL_API uint64_t SENTINEL_CALL GetSecureTime();

/**
 * Get frame delta time with speed hack detection
 * @return Delta time in seconds
 */
SENTINEL_API float SENTINEL_CALL GetSecureDeltaTime();

/**
 * Validate a time interval
 * @param start_time Start timestamp
 * @param end_time End timestamp
 * @param expected_min Expected minimum duration (ms)
 * @param expected_max Expected maximum duration (ms)
 * @return true if timing is valid
 */
SENTINEL_API bool SENTINEL_CALL ValidateTiming(
    uint64_t start_time,
    uint64_t end_time,
    uint32_t expected_min,
    uint32_t expected_max);

// ==================== Network Validation ====================

/**
 * Encrypt game packet for transmission
 * @param data Packet data
 * @param size Data size
 * @param out_buffer Output buffer
 * @param out_size Output buffer size (updated with actual size)
 * @return Error code
 */
SENTINEL_API ErrorCode SENTINEL_CALL EncryptPacket(
    const void* data,
    size_t size,
    void* out_buffer,
    size_t* out_size);

/**
 * Decrypt received game packet
 * @param data Encrypted packet data
 * @param size Data size
 * @param out_buffer Output buffer
 * @param out_size Output buffer size (updated with actual size)
 * @return Error code
 */
SENTINEL_API ErrorCode SENTINEL_CALL DecryptPacket(
    const void* data,
    size_t size,
    void* out_buffer,
    size_t* out_size);

/**
 * Generate packet sequence number
 * @return Next sequence number
 */
SENTINEL_API uint32_t SENTINEL_CALL GetPacketSequence();

/**
 * Validate incoming packet sequence
 * @param sequence Received sequence number
 * @return true if sequence is valid
 */
SENTINEL_API bool SENTINEL_CALL ValidatePacketSequence(uint32_t sequence);

// ==================== Reporting ====================

/**
 * Report a custom event to the cloud
 * @param event_type Custom event type identifier
 * @param data Event data (JSON string)
 * @return Error code
 */
SENTINEL_API ErrorCode SENTINEL_CALL ReportEvent(
    const char* event_type,
    const char* data);

/**
 * Get current session token
 * @return Session token string
 */
SENTINEL_API const char* SENTINEL_CALL GetSessionToken();

/**
 * Get hardware fingerprint
 * @return Hardware ID string
 */
SENTINEL_API const char* SENTINEL_CALL GetHardwareId();

// ==================== Statistics ====================

/**
 * Runtime statistics
 */
struct Statistics {
    uint64_t uptime_ms;             ///< Time since initialization
    uint32_t updates_performed;     ///< Number of Update() calls
    uint32_t scans_performed;       ///< Number of FullScan() calls
    uint32_t violations_detected;   ///< Total violations detected
    uint32_t violations_reported;   ///< Violations reported to cloud
    
    // Performance metrics
    float avg_update_time_us;       ///< Average Update() time in microseconds
    float avg_scan_time_ms;         ///< Average FullScan() time in milliseconds
    float max_update_time_us;       ///< Maximum Update() time
    
    // Memory protection stats
    uint32_t protected_regions;     ///< Number of protected memory regions
    uint32_t protected_functions;   ///< Number of protected functions
    uint64_t total_protected_bytes; ///< Total bytes under protection
};

/**
 * Get current statistics
 * @param stats Output statistics structure
 */
SENTINEL_API void SENTINEL_CALL GetStatistics(Statistics* stats);

/**
 * Reset statistics counters
 */
SENTINEL_API void SENTINEL_CALL ResetStatistics();

// ==================== Helper Macros ====================

// Inline operator overloads for flags
inline DetectionFeatures operator|(DetectionFeatures a, DetectionFeatures b) {
    return static_cast<DetectionFeatures>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline DetectionFeatures operator&(DetectionFeatures a, DetectionFeatures b) {
    return static_cast<DetectionFeatures>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline ResponseAction operator|(ResponseAction a, ResponseAction b) {
    return static_cast<ResponseAction>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline ResponseAction operator&(ResponseAction a, ResponseAction b) {
    return static_cast<ResponseAction>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline ViolationType operator|(ViolationType a, ViolationType b) {
    return static_cast<ViolationType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

} // namespace SDK
} // namespace Sentinel

// C API for non-C++ integration
extern "C" {
    SENTINEL_API uint32_t SENTINEL_CALL SentinelInit(const Sentinel::SDK::Configuration* config);
    SENTINEL_API void SENTINEL_CALL SentinelShutdown();
    SENTINEL_API uint32_t SENTINEL_CALL SentinelUpdate();
    SENTINEL_API uint32_t SENTINEL_CALL SentinelFullScan();
    SENTINEL_API const char* SENTINEL_CALL SentinelGetVersion();
}
