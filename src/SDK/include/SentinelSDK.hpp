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
#elif defined(SENTINEL_SDK_STATIC)
    // For static libraries, mark API functions as used to prevent unused function warnings
    // Windows MSVC doesn't flag exported functions as unused, but GCC/Clang do
    #ifdef _WIN32
        #define SENTINEL_API
    #else
        #define SENTINEL_API __attribute__((used))
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

// ==================== Anti-Hook Protection Macros ====================

/**
 * SENTINEL_PROTECTED_CALL - Inline hook verification macro
 * 
 * Verifies function prologue immediately before calling the function.
 * This is the only guaranteed-safe method to prevent TOCTOU attacks.
 * 
 * Usage:
 *   // Register function first
 *   FunctionProtection func;
 *   func.address = reinterpret_cast<uintptr_t>(&MyFunction);
 *   func.name = "MyFunction";
 *   func.prologue_size = 16;
 *   memcpy(func.original_prologue.data(), &MyFunction, 16);
 *   detector.RegisterFunction(func);
 *   
 *   // Then call with protection
 *   SENTINEL_PROTECTED_CALL(detector, &MyFunction, result = MyFunction(arg1, arg2));
 * 
 * Task 11 - Expanded Hook Detection:
 * ===================================
 * For critical security functions (NtProtectVirtualMemory, etc.), use 64-byte scanning:
 * 
 *   // Get function address from Windows API
 *   auto NtProtectVirtualMemory = GetProcAddress(
 *       GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
 *   
 *   FunctionProtection criticalFunc;
 *   criticalFunc.address = reinterpret_cast<uintptr_t>(NtProtectVirtualMemory);
 *   criticalFunc.name = "NtProtectVirtualMemory";
 *   criticalFunc.prologue_size = 64;  // Scan full 64 bytes for critical functions
 *   criticalFunc.is_critical = true;  // Mark as critical for prioritization
 *   memcpy(criticalFunc.original_prologue.data(), NtProtectVirtualMemory, 64);
 *   detector.RegisterFunction(criticalFunc);
 * 
 * Detection Capabilities:
 * - Detects mid-function hooks at offsets >16 bytes (e.g., offset +20, +32, +50)
 * - Detects exception-based hooks: INT 3 (0xCC), INT 1 (0xF1), UD2 (0x0F 0x0B)
 * - Detects trampolines, jump tables, and return address modifications
 * - Scans entire prologue for patterns at any offset (not just beginning)
 * 
 * Performance:
 * - Average scan time: ~4-5ms per cycle (includes jitter)
 * - Budget-enforced: 5ms max per scan cycle
 * - Probabilistic: 15% of functions scanned per cycle for efficiency
 * 
 * @param detector The AntiHookDetector instance
 * @param func_ptr Pointer to the function to verify
 * @param call_expr The actual function call expression
 */
#define SENTINEL_PROTECTED_CALL(detector, func_ptr, call_expr) \
    do { \
        if ((detector).CheckFunction(reinterpret_cast<uintptr_t>(func_ptr))) { \
            /* Hook detected - handle error */ \
            throw std::runtime_error("Hook detected in protected function call"); \
        } \
        call_expr; \
    } while(0)

#include <cstdint>
#include <cstddef>
#include <string>

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
    InvalidArgument = 100,  // Alias for compatibility
    InternalError = 101,
    OutOfMemory = 102,
    Timeout = 103,
    NetworkError = 104,
    BufferTooSmall = 105,
    InvalidInput = 106,
    
    // Security events (200-299)
    TamperingDetected = 200,
    DebuggerDetected = 201,
    InjectionDetected = 202,
    HookDetected = 203,
    MemoryManipulation = 204,
    ProcessManipulation = 205,
    SignatureMismatch = 206,
    IntegrityViolation = 207,
    ReplayDetected = 208,
    AuthenticationFailed = 209,
    
    // Cryptographic errors (250-299)
    CryptoError = 250,
    
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
 * 
 * NOTE: Uses std::string for module_name and details to prevent use-after-free
 * vulnerabilities when the SDK DLL is unloaded. All strings are owned copies.
 */
struct ViolationEvent {
    ViolationType type;         ///< Type of violation
    Severity severity;          ///< Severity level
    uint64_t timestamp;         ///< Event timestamp (ms since init)
    uint64_t address;           ///< Related memory address (if applicable)
    std::string module_name;    ///< Related module name (owned copy)
    std::string details;        ///< Additional details (owned copy)
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
 * 
 * Task 24: Server-Authoritative Enforcement
 * 
 * IMPORTANT: Kick, Ban, and Terminate actions are DEPRECATED for client-side use.
 * The SDK should ONLY detect and report. Enforcement decisions must be made by
 * the server and delivered via ServerDirective callbacks.
 * 
 * Recommended client actions: Log | Report | Notify
 * Server-enforced actions: Received via ServerDirective (SessionTerminate, etc.)
 */
enum class ResponseAction : uint32_t {
    None = 0,           ///< No automatic action
    Log = 0x01,         ///< Log the event
    Report = 0x02,      ///< Report to cloud
    Notify = 0x04,      ///< Notify callback
    Warn = 0x08,        ///< Display warning to user
    Kick = 0x10,        ///< [DEPRECATED] Disconnect from server (use ServerDirective instead)
    Ban = 0x20,         ///< [DEPRECATED] Request ban (use ServerDirective instead)
    Terminate = 0x40,   ///< [DEPRECATED] Terminate process (use ServerDirective instead)
    
    // Presets
    Silent = Log | Report,
    Default = Log | Report | Notify,
    Aggressive = Log | Report | Notify | Kick  // Note: Kick is deprecated, use for compatibility only
};

// ==================== Server Directives (Task 24) ====================

/**
 * Server enforcement directive types
 * 
 * Task 24: Server-Authoritative Enforcement Model
 * SDK detects and reports only. Server issues authoritative directives.
 */
enum class ServerDirectiveType : uint32_t {
    None = 0,                   ///< No directive
    SessionContinue = 1,        ///< Continue playing (explicit approval)
    SessionTerminate = 2,       ///< Session must be terminated
    SessionSuspend = 3,         ///< Temporary suspension
    RequireReconnect = 4,       ///< Force reconnection
    UpdateRequired = 5          ///< Client update required
};

/**
 * Reason codes for server directives
 */
enum class ServerDirectiveReason : uint32_t {
    None = 0,
    CheatDetected = 1,
    PolicyViolation = 2,
    SystemError = 3,
    MaintenanceMode = 4,
    AccountBanned = 5,
    SessionExpired = 6
};

/**
 * Server enforcement directive
 * 
 * Task 24: Server-Authoritative Enforcement
 * 
 * Server directives are cryptographically signed and cannot be forged or replayed.
 * The game MUST implement these directives as authoritative. The client SDK
 * has zero enforcement authority - only detection and reporting.
 */
struct ServerDirective {
    ServerDirectiveType type;   ///< Directive type
    ServerDirectiveReason reason; ///< Reason code
    uint64_t sequence;          ///< Monotonic sequence (replay protection)
    uint64_t timestamp;         ///< Unix timestamp in milliseconds
    const char* session_id;     ///< Session identifier
    const char* message;        ///< Human-readable message
};

/**
 * Callback for server directives
 * 
 * Game must implement this to receive and act on server directives.
 * The callback MUST respect directives as authoritative.
 * 
 * @param directive Server directive to process
 * @param user_data User-provided context
 * @return true if directive was processed
 */
typedef bool (SENTINEL_CALL *ServerDirectiveCallback)(
    const ServerDirective* directive,
    void* user_data);

// ==================== Configuration ====================

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
    
    // Task 24: Server directive callback
    ServerDirectiveCallback directive_callback; ///< Server directive callback
    void* directive_user_data;              ///< User data for directive callback
    uint32_t directive_poll_interval_ms;    ///< Server directive poll interval (default: 5000)
    
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
    const char* cache_dir;          ///< Task 25: Directory for signature cache (NULL for default)
    
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
        config.directive_poll_interval_ms = 5000;  // Task 24: Poll every 5 seconds
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

// ==================== Server Directive Polling (Task 24) ====================

/**
 * Poll for server directives
 * 
 * Task 24: Server-Authoritative Enforcement
 * 
 * Checks for new directives from server. Games should call this periodically
 * (e.g., once per second) to receive enforcement decisions. However, automatic
 * polling is enabled by default in the heartbeat thread based on
 * directive_poll_interval_ms configuration.
 * 
 * @return Error code
 */
SENTINEL_API ErrorCode SENTINEL_CALL PollServerDirectives();

/**
 * Get last received server directive
 * 
 * @param out_directive Output directive structure
 * @return true if a directive is available
 */
SENTINEL_API bool SENTINEL_CALL GetLastServerDirective(ServerDirective* out_directive);

/**
 * Set server directive callback
 * 
 * Register a callback to be notified when directives arrive.
 * Recommended over polling for lower latency.
 * 
 * @param callback Callback function
 * @param user_data User context pointer
 */
SENTINEL_API void SENTINEL_CALL SetServerDirectiveCallback(
    ServerDirectiveCallback callback,
    void* user_data);

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
    
    // Task 25: Signature update stats
    uint32_t signature_version;     ///< Current detection signature version
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

// ==================== Whitelist Configuration ====================

/**
 * Add a thread origin to the whitelist
 * Allows threads starting from the specified module to bypass MEM_PRIVATE checks
 * Useful for game engines with custom job systems or threading libraries
 * 
 * @param module_name Module name (e.g., "MyGameEngine.dll")
 * @param reason Description for logging (e.g., "Game engine job system")
 * @return Error code
 */
SENTINEL_API ErrorCode SENTINEL_CALL WhitelistThreadOrigin(
    const char* module_name,
    const char* reason);

/**
 * Remove a thread origin from the whitelist
 * Note: Cannot remove built-in whitelist entries
 * 
 * @param module_name Module name to remove
 */
SENTINEL_API void SENTINEL_CALL RemoveThreadOriginWhitelist(const char* module_name);

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
