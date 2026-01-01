# Sentinel SDK API Reference

**Version:** 1.0.0  
**Coverage:** 100% of public API  
**Last Updated:** 2025-01-01

---

## Table of Contents

1. [Core API](#core-api)
2. [Configuration](#configuration)
3. [Error Handling](#error-handling)
4. [Security Events](#security-events)
5. [Memory Protection](#memory-protection)
6. [Function Protection](#function-protection)
7. [Value Protection](#value-protection)
8. [Secure Timing](#secure-timing)
9. [Network Validation](#network-validation)
10. [Statistics & Monitoring](#statistics--monitoring)
11. [Whitelist Configuration](#whitelist-configuration)
12. [C API](#c-api)

---

## Core API

### Initialize

```cpp
SENTINEL_API ErrorCode SENTINEL_CALL Initialize(const Configuration* config);
```

**Description:**  
Initializes the Sentinel SDK. Must be called before any other SDK functions.

**Parameters:**
- `config` - Pointer to configuration structure (must not be null)

**Returns:**
- `ErrorCode::Success` - Initialization successful
- `ErrorCode::AlreadyInitialized` - SDK already initialized
- `ErrorCode::InvalidParameter` - Config is null or invalid
- `ErrorCode::InvalidLicense` - License key is invalid or expired
- `ErrorCode::InitializationFailed` - Internal initialization error

**Example:**
```cpp
using namespace Sentinel::SDK;

Configuration config = Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";
config.game_id = "my-game-v1";

ErrorCode result = Initialize(&config);
if (result != ErrorCode::Success) {
    fprintf(stderr, "Failed to initialize: %s\n", GetLastError());
    return -1;
}
```

**Thread Safety:** Not thread-safe. Must be called from main thread only.

**Performance:** ~10-50ms depending on enabled features.

**Notes:**
- License key is validated during initialization
- OpenSSL must be available for cryptographic features
- Call `Shutdown()` before process exit to release resources

---

### Shutdown

```cpp
SENTINEL_API void SENTINEL_CALL Shutdown();
```

**Description:**  
Shuts down the SDK and releases all resources. All handles become invalid.

**Parameters:** None

**Returns:** None (void)

**Example:**
```cpp
// Clean up handles first
DestroyProtectedValue(health_handle);
UnprotectMemory(memory_handle);

// Then shutdown SDK
Shutdown();
```

**Thread Safety:** Not thread-safe. Must be called from main thread only.

**Performance:** ~5-10ms

**Notes:**
- Automatically destroys all protected values and memory regions
- All SDK function calls after `Shutdown()` will fail
- Do not call SDK functions from destructors that may run after shutdown

---

### IsInitialized

```cpp
SENTINEL_API bool SENTINEL_CALL IsInitialized();
```

**Description:**  
Checks if the SDK is currently initialized.

**Parameters:** None

**Returns:**
- `true` - SDK is initialized and ready
- `false` - SDK is not initialized

**Example:**
```cpp
if (IsInitialized()) {
    Update();  // Safe to call
} else {
    fprintf(stderr, "SDK not initialized\n");
}
```

**Thread Safety:** Thread-safe (read-only check)

**Performance:** < 1μs

---

### GetVersion

```cpp
SENTINEL_API const char* SENTINEL_CALL GetVersion();
```

**Description:**  
Returns the SDK version string.

**Parameters:** None

**Returns:**  
Null-terminated version string (e.g., "1.0.0")

**Example:**
```cpp
printf("Sentinel SDK v%s\n", GetVersion());
// Output: Sentinel SDK v1.0.0
```

**Thread Safety:** Thread-safe

**Performance:** < 1μs

**Notes:**  
Returned pointer is valid for the lifetime of the process.

---

### GetLastError

```cpp
SENTINEL_API const char* SENTINEL_CALL GetLastError();
```

**Description:**  
Returns a human-readable description of the last error that occurred.

**Parameters:** None

**Returns:**  
Null-terminated error message string

**Example:**
```cpp
ErrorCode result = Initialize(&config);
if (result != ErrorCode::Success) {
    fprintf(stderr, "Error: %s\n", GetLastError());
}
```

**Thread Safety:** Thread-local (each thread has its own last error)

**Performance:** < 1μs

**Notes:**
- Error message is cleared on next successful operation
- Message may be overwritten by subsequent SDK calls

---

## Runtime Control

### Update

```cpp
SENTINEL_API ErrorCode SENTINEL_CALL Update();
```

**Description:**  
Performs lightweight integrity checks. Call once per game frame.

**Parameters:** None

**Returns:**
- `ErrorCode::Success` - No violations detected
- `ErrorCode::NotInitialized` - SDK not initialized
- `ErrorCode::TamperingDetected` - Tampering detected (check violation callback)

**Example:**
```cpp
void GameLoop() {
    while (running) {
        ErrorCode result = Update();
        if (result != ErrorCode::Success) {
            LogWarning("SDK update failed: %d", static_cast<int>(result));
        }
        
        UpdateGameLogic();
        RenderFrame();
    }
}
```

**Thread Safety:** Not thread-safe. Call from main thread only.

**Performance:** Target < 0.1ms, typical ~0.5ms

**Notes:**
- Performs anti-debug, anti-hook, and basic integrity checks
- Does NOT perform full memory scan (use `FullScan()` for that)
- Violations trigger the configured callback

---

### FullScan

```cpp
SENTINEL_API ErrorCode SENTINEL_CALL FullScan();
```

**Description:**  
Performs comprehensive integrity scan. More thorough but slower than `Update()`.

**Parameters:** None

**Returns:**
- `ErrorCode::Success` - No violations detected
- `ErrorCode::NotInitialized` - SDK not initialized
- `ErrorCode::TamperingDetected` - Tampering detected

**Example:**
```cpp
// Run full scan every 5 seconds
static auto last_scan = std::chrono::steady_clock::now();

auto now = std::chrono::steady_clock::now();
auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_scan);

if (elapsed.count() >= 5) {
    FullScan();
    last_scan = now;
}
```

**Thread Safety:** Not thread-safe. Call from main thread only.

**Performance:** Target < 5ms, typical ~7-10ms

**Notes:**
- Scans all protected memory regions
- Checks all registered function hooks
- May cause frame drops if called too frequently

---

### Pause

```cpp
SENTINEL_API void SENTINEL_CALL Pause();
```

**Description:**  
Pauses all monitoring temporarily. Use sparingly (e.g., during loading screens).

**Parameters:** None

**Returns:** None (void)

**Example:**
```cpp
void LoadLevel() {
    Pause();  // Pause during loading
    
    LoadAssets();
    CompileShaders();
    
    Resume();  // Resume monitoring
}
```

**Thread Safety:** Not thread-safe.

**Performance:** < 1ms

**Warning:**  
⚠️ Pausing disables protection! Attackers can exploit during pause.

---

### Resume

```cpp
SENTINEL_API void SENTINEL_CALL Resume();
```

**Description:**  
Resumes monitoring after `Pause()`.

**Parameters:** None

**Returns:** None (void)

**Example:**
```cpp
Pause();
HeavyOperation();
Resume();
```

**Thread Safety:** Not thread-safe.

**Performance:** < 1ms

---

### IsActive

```cpp
SENTINEL_API bool SENTINEL_CALL IsActive();
```

**Description:**  
Checks if monitoring is currently active (not paused).

**Parameters:** None

**Returns:**
- `true` - Monitoring is active
- `false` - Monitoring is paused

**Example:**
```cpp
if (!IsActive()) {
    printf("SDK monitoring is paused\n");
}
```

**Thread Safety:** Thread-safe (read-only check)

**Performance:** < 1μs

---

## Configuration

### Configuration Structure

```cpp
struct Configuration {
    uint32_t struct_size;
    const char* license_key;
    const char* game_id;
    DetectionFeatures features;
    ResponseAction default_action;
    ViolationCallback violation_callback;
    void* callback_user_data;
    uint32_t heartbeat_interval_ms;
    uint32_t integrity_scan_interval_ms;
    uint32_t memory_scan_chunk_size;
    const char* cloud_endpoint;
    uint32_t report_batch_size;
    uint32_t report_interval_ms;
    bool debug_mode;
    const char* log_path;
    
    static Configuration Default();
};
```

**Fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `struct_size` | `uint32_t` | `sizeof(Configuration)` | Size of structure for versioning |
| `license_key` | `const char*` | `nullptr` | **Required.** Your license key |
| `game_id` | `const char*` | `nullptr` | **Required.** Unique game identifier |
| `features` | `DetectionFeatures` | `Standard` | Detection features to enable |
| `default_action` | `ResponseAction` | `Default` | Default action for violations |
| `violation_callback` | `ViolationCallback` | `nullptr` | Optional callback for violations |
| `callback_user_data` | `void*` | `nullptr` | User data passed to callback |
| `heartbeat_interval_ms` | `uint32_t` | `1000` | Heartbeat check interval (ms) |
| `integrity_scan_interval_ms` | `uint32_t` | `5000` | Full scan interval (ms) |
| `memory_scan_chunk_size` | `uint32_t` | `4096` | Memory scan chunk size |
| `cloud_endpoint` | `const char*` | `nullptr` | Cloud reporting endpoint URL |
| `report_batch_size` | `uint32_t` | `10` | Events to batch before reporting |
| `report_interval_ms` | `uint32_t` | `30000` | Report interval (ms) |
| `debug_mode` | `bool` | `false` | **Must be false in release!** |
| `log_path` | `const char*` | `nullptr` | Debug log file path |

**Example:**
```cpp
Configuration config = Configuration::Default();
config.license_key = "YOUR-LICENSE-KEY";
config.game_id = "my-game-v1";
config.features = DetectionFeatures::Full;
config.default_action = ResponseAction::Log | ResponseAction::Report;
config.heartbeat_interval_ms = 1000;
config.integrity_scan_interval_ms = 5000;
```

---

### DetectionFeatures Enum

```cpp
enum class DetectionFeatures : uint32_t {
    None = 0,
    MemoryIntegrity = 0x0001,
    CodeIntegrity = 0x0002,
    StackProtection = 0x0004,
    HeapProtection = 0x0008,
    AntiDebug = 0x0010,
    AntiAttach = 0x0020,
    ThreadMonitor = 0x0040,
    HandleProtection = 0x0080,
    InlineHookDetect = 0x0100,
    IATHookDetect = 0x0200,
    VTableProtect = 0x0400,
    SpeedHackDetect = 0x1000,
    TimingIntegrity = 0x2000,
    PacketValidation = 0x4000,
    RateLimiting = 0x8000,
    Minimal = MemoryIntegrity | AntiDebug,
    Standard = Minimal | CodeIntegrity | InlineHookDetect | IATHookDetect,
    Full = 0xFFFF
};
```

**Presets:**

| Preset | Features | Use Case |
|--------|----------|----------|
| `Minimal` | Memory integrity, anti-debug | Lowest overhead, basic protection |
| `Standard` | Minimal + code integrity + hook detection | **Recommended** for most games |
| `Full` | All features | Maximum protection, highest overhead |

**Example:**
```cpp
// Combine features with bitwise OR
config.features = DetectionFeatures::AntiDebug | 
                  DetectionFeatures::InlineHookDetect |
                  DetectionFeatures::MemoryIntegrity;

// Or use preset
config.features = DetectionFeatures::Standard;
```

---

### ResponseAction Enum

```cpp
enum class ResponseAction : uint32_t {
    None = 0,
    Log = 0x01,
    Report = 0x02,
    Notify = 0x04,
    Warn = 0x08,
    Kick = 0x10,
    Ban = 0x20,
    Terminate = 0x40,
    Silent = Log | Report,
    Default = Log | Report | Notify,
    Aggressive = Log | Report | Notify | Kick
};
```

**Actions:**

| Action | Description |
|--------|-------------|
| `None` | No automatic action |
| `Log` | Write to log file (if debug mode enabled) |
| `Report` | Send to cloud endpoint |
| `Notify` | Trigger violation callback |
| `Warn` | Display warning message (not implemented) |
| `Kick` | Disconnect from server (application must implement) |
| `Ban` | Request player ban (application must implement) |
| `Terminate` | Terminate process immediately |

**Example:**
```cpp
// Recommended for production
config.default_action = ResponseAction::Log | ResponseAction::Report | ResponseAction::Notify;

// Silent monitoring
config.default_action = ResponseAction::Silent;
```

---

## Error Handling

### ErrorCode Enum

```cpp
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
    InvalidArgument = 100,
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
```

**Error Handling Pattern:**
```cpp
ErrorCode result = SomeSDKFunction();
switch (result) {
    case ErrorCode::Success:
        // Operation successful
        break;
    case ErrorCode::InvalidParameter:
        fprintf(stderr, "Invalid parameter: %s\n", GetLastError());
        break;
    case ErrorCode::TamperingDetected:
        LogSecurityEvent("Tampering detected");
        DisconnectPlayer();
        break;
    default:
        fprintf(stderr, "Unknown error: %d\n", static_cast<int>(result));
        break;
}
```

---

## Security Events

### ViolationType Enum

```cpp
enum class ViolationType : uint32_t {
    None = 0,
    
    // Memory violations
    MemoryRead = 0x0001,
    MemoryWrite = 0x0002,
    MemoryExecute = 0x0004,
    CodeInjection = 0x0008,
    InjectedCode = 0x0009,
    
    // Process violations
    DebuggerAttached = 0x0010,
    RemoteThread = 0x0020,
    ProcessHollow = 0x0040,
    HandleManipulation = 0x0080,
    SuspiciousThread = 0x0081,
    
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
```

### Severity Enum

```cpp
enum class Severity : uint8_t {
    Info = 0,
    Warning = 1,
    High = 2,
    Critical = 3
};
```

### ViolationEvent Structure

```cpp
struct ViolationEvent {
    ViolationType type;
    Severity severity;
    uint64_t timestamp;
    uint64_t address;
    std::string module_name;
    std::string details;
    uint32_t detection_id;
};
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `type` | `ViolationType` | Type of violation detected |
| `severity` | `Severity` | Severity level (Info/Warning/High/Critical) |
| `timestamp` | `uint64_t` | Milliseconds since SDK initialization |
| `address` | `uint64_t` | Related memory address (if applicable) |
| `module_name` | `std::string` | Related module name |
| `details` | `std::string` | Human-readable details |
| `detection_id` | `uint32_t` | Unique identifier for this detection |

### ViolationCallback

```cpp
typedef bool (SENTINEL_CALL *ViolationCallback)(
    const ViolationEvent* event,
    void* user_data
);
```

**Parameters:**
- `event` - Violation event data
- `user_data` - User-provided context from `Configuration::callback_user_data`

**Returns:**
- `true` - Continue monitoring
- `false` - Suppress further events of this type

**Example:**
```cpp
bool SENTINEL_CALL MyViolationHandler(
    const ViolationEvent* event,
    void* user_data
) {
    if (!event) return true;
    
    // Log violation
    LogSecurity("Violation type=0x%X, severity=%d, details=%s",
                static_cast<uint32_t>(event->type),
                static_cast<int>(event->severity),
                event->details.c_str());
    
    // Take action based on severity
    switch (event->severity) {
        case Severity::Info:
        case Severity::Warning:
            // Log and monitor
            return true;
            
        case Severity::High:
        case Severity::Critical:
            // Disconnect player, report to server
            ReportToServer(*event);
            DisconnectPlayer();
            return true;
    }
    
    return true;
}

// Set callback in configuration
config.violation_callback = MyViolationHandler;
config.callback_user_data = &my_game_state;
```

---

## Memory Protection

### ProtectMemory

```cpp
SENTINEL_API uint64_t SENTINEL_CALL ProtectMemory(
    void* address,
    size_t size,
    const char* name
);
```

**Description:**  
Registers a memory region for integrity monitoring.

**Parameters:**
- `address` - Start address of region to protect
- `size` - Size in bytes
- `name` - Optional descriptive name for logging (can be null)

**Returns:**
- Handle to protected region (non-zero on success)
- `0` on failure

**Example:**
```cpp
struct CriticalData {
    int player_health;
    int player_score;
    float position[3];
};

CriticalData data = {100, 0, {0.0f, 0.0f, 0.0f}};

uint64_t handle = ProtectMemory(&data, sizeof(data), "PlayerData");
if (handle == 0) {
    fprintf(stderr, "Failed to protect memory\n");
}
```

**Thread Safety:** Not thread-safe.

**Performance:** ~100μs per region

**Notes:**
- Takes snapshot of memory at registration time
- Periodic integrity checks during `Update()` and `FullScan()`
- Does not prevent modification (user-mode limitation)
- Detects modifications after-the-fact

---

### UnprotectMemory

```cpp
SENTINEL_API void SENTINEL_CALL UnprotectMemory(uint64_t handle);
```

**Description:**  
Removes protection from a previously protected memory region.

**Parameters:**
- `handle` - Handle returned by `ProtectMemory()`

**Returns:** None (void)

**Example:**
```cpp
UnprotectMemory(handle);
handle = 0;  // Invalidate handle
```

**Thread Safety:** Not thread-safe.

**Performance:** < 10μs

---

### VerifyMemory

```cpp
SENTINEL_API bool SENTINEL_CALL VerifyMemory(uint64_t handle);
```

**Description:**  
Manually verifies integrity of a protected memory region.

**Parameters:**
- `handle` - Handle returned by `ProtectMemory()`

**Returns:**
- `true` - Integrity intact
- `false` - Memory has been modified

**Example:**
```cpp
if (!VerifyMemory(handle)) {
    LogWarning("Protected memory was modified!");
    HandleTampering();
}
```

**Thread Safety:** Thread-safe (can be called from any thread)

**Performance:** ~50μs per region

**Notes:**
- Compares current memory against original snapshot
- Does not trigger violation callback
- Use for manual checks between `Update()` calls

---

## Function Protection

### ProtectFunction

```cpp
SENTINEL_API uint64_t SENTINEL_CALL ProtectFunction(
    void* function_address,
    const char* name
);
```

**Description:**  
Registers a function for hook detection.

**Parameters:**
- `function_address` - Address of function to protect
- `name` - Optional function name for logging

**Returns:**
- Handle to protected function (non-zero on success)
- `0` on failure

**Example:**
```cpp
void CriticalGameFunction() {
    // Important game logic
}

uint64_t handle = ProtectFunction(
    reinterpret_cast<void*>(&CriticalGameFunction),
    "CriticalGameFunction"
);
```

**Thread Safety:** Not thread-safe.

**Performance:** ~100μs per function

---

### UnprotectFunction

```cpp
SENTINEL_API void SENTINEL_CALL UnprotectFunction(uint64_t handle);
```

**Description:**  
Removes protection from a function.

**Parameters:**
- `handle` - Handle returned by `ProtectFunction()`

**Returns:** None (void)

**Example:**
```cpp
UnprotectFunction(handle);
```

**Thread Safety:** Not thread-safe.

**Performance:** < 10μs

---

### IsHooked

```cpp
SENTINEL_API bool SENTINEL_CALL IsHooked(void* function_address);
```

**Description:**  
Checks if a function is currently hooked.

**Parameters:**
- `function_address` - Address of function to check

**Returns:**
- `true` - Hook detected
- `false` - No hook detected

**Example:**
```cpp
if (IsHooked(reinterpret_cast<void*>(&CriticalFunction))) {
    LogWarning("Function is hooked!");
    return ErrorCode::HookDetected;
}

// Safe to call function
CriticalFunction();
```

**Thread Safety:** Thread-safe

**Performance:** ~10μs

---

## Value Protection

### CreateProtectedInt

```cpp
SENTINEL_API uint64_t SENTINEL_CALL CreateProtectedInt(int64_t initial_value);
```

**Description:**  
Creates an obfuscated integer value resistant to memory scanning.

**Parameters:**
- `initial_value` - Initial value

**Returns:**
- Handle to protected value (non-zero on success)
- `0` on failure

**Example:**
```cpp
uint64_t health_handle = CreateProtectedInt(100);
uint64_t gold_handle = CreateProtectedInt(0);
```

**Thread Safety:** Not thread-safe.

**Performance:** ~5μs

**Notes:**
- Value is stored obfuscated in memory (XOR-based)
- Resistant to basic memory scanning
- NOT cryptographically secure (see INTEGRATION_GUIDE.md for limitations)

---

### SetProtectedInt

```cpp
SENTINEL_API void SENTINEL_CALL SetProtectedInt(uint64_t handle, int64_t value);
```

**Description:**  
Updates a protected integer value.

**Parameters:**
- `handle` - Handle returned by `CreateProtectedInt()`
- `value` - New value

**Returns:** None (void)

**Example:**
```cpp
// Take damage
int64_t health = GetProtectedInt(health_handle);
health -= 20;
SetProtectedInt(health_handle, health);
```

**Thread Safety:** Not thread-safe (unless designed for multi-threading).

**Performance:** ~2μs

---

### GetProtectedInt

```cpp
SENTINEL_API int64_t SENTINEL_CALL GetProtectedInt(uint64_t handle);
```

**Description:**  
Retrieves a protected integer value.

**Parameters:**
- `handle` - Handle returned by `CreateProtectedInt()`

**Returns:**
- Current value
- `0` if handle is invalid

**Example:**
```cpp
int64_t health = GetProtectedInt(health_handle);
if (health <= 0) {
    PlayerDied();
}
```

**Thread Safety:** Not thread-safe (unless designed for multi-threading).

**Performance:** ~2μs

---

### DestroyProtectedValue

```cpp
SENTINEL_API void SENTINEL_CALL DestroyProtectedValue(uint64_t handle);
```

**Description:**  
Destroys a protected value and frees resources.

**Parameters:**
- `handle` - Handle returned by `CreateProtectedInt()`

**Returns:** None (void)

**Example:**
```cpp
// Cleanup before shutdown
DestroyProtectedValue(health_handle);
DestroyProtectedValue(gold_handle);
health_handle = 0;
gold_handle = 0;
```

**Thread Safety:** Not thread-safe.

**Performance:** ~5μs

**Notes:**
- Must be called before `Shutdown()`
- Double-free protection: safe to call with handle=0

---

## Secure Timing

### GetSecureTime

```cpp
SENTINEL_API uint64_t SENTINEL_CALL GetSecureTime();
```

**Description:**  
Returns secure timestamp resistant to time manipulation.

**Parameters:** None

**Returns:**  
Milliseconds since SDK initialization

**Example:**
```cpp
uint64_t start_time = GetSecureTime();

// Do something
PerformAction();

uint64_t end_time = GetSecureTime();
uint64_t elapsed = end_time - start_time;

printf("Action took %llu ms\n", elapsed);
```

**Thread Safety:** Thread-safe

**Performance:** ~1μs

**Notes:**
- Uses high-resolution timer
- Cross-references multiple time sources
- NOT foolproof against kernel-level manipulation (see INTEGRATION_GUIDE.md)

---

### GetSecureDeltaTime

```cpp
SENTINEL_API float SENTINEL_CALL GetSecureDeltaTime();
```

**Description:**  
Returns frame delta time with speed hack detection.

**Parameters:** None

**Returns:**  
Delta time in seconds since last call

**Example:**
```cpp
void GameLoop() {
    while (running) {
        float delta = GetSecureDeltaTime();
        
        // Update with verified delta time
        UpdatePhysics(delta);
        UpdateAnimation(delta);
        
        Render();
    }
}
```

**Thread Safety:** Not thread-safe (call from main thread only).

**Performance:** ~2μs

**Notes:**
- Detects abnormal delta times
- Clamps extreme values
- Requires server-side validation for multiplayer games

---

### ValidateTiming

```cpp
SENTINEL_API bool SENTINEL_CALL ValidateTiming(
    uint64_t start_time,
    uint64_t end_time,
    uint32_t expected_min,
    uint32_t expected_max
);
```

**Description:**  
Validates that a time interval falls within expected bounds.

**Parameters:**
- `start_time` - Start timestamp (from `GetSecureTime()`)
- `end_time` - End timestamp (from `GetSecureTime()`)
- `expected_min` - Minimum expected duration (ms)
- `expected_max` - Maximum expected duration (ms)

**Returns:**
- `true` - Timing is valid
- `false` - Timing is suspicious (too fast or too slow)

**Example:**
```cpp
uint64_t start = GetSecureTime();

// Perform action that should take 100-500ms
LoadAssets();

uint64_t end = GetSecureTime();

if (!ValidateTiming(start, end, 100, 500)) {
    LogWarning("Suspicious timing detected!");
    // Possible speed hack or debugger
}
```

**Thread Safety:** Thread-safe

**Performance:** ~1μs

---

## Network Validation

### EncryptPacket

```cpp
SENTINEL_API ErrorCode SENTINEL_CALL EncryptPacket(
    const void* data,
    size_t size,
    void* out_buffer,
    size_t* out_size
);
```

**Description:**  
Encrypts game packet data for secure transmission.

**Parameters:**
- `data` - Plaintext packet data
- `size` - Size of input data
- `out_buffer` - Output buffer for encrypted data
- `out_size` - [in/out] Size of output buffer; updated with actual encrypted size

**Returns:**
- `ErrorCode::Success` - Encryption successful
- `ErrorCode::InvalidParameter` - Null pointer or invalid size
- `ErrorCode::BufferTooSmall` - Output buffer too small
- `ErrorCode::CryptoError` - Encryption failed

**Example:**
```cpp
struct GamePacket {
    uint32_t player_id;
    float position[3];
    uint32_t action;
};

GamePacket packet = {/* ... */};

uint8_t encrypted[2048];
size_t encrypted_size = sizeof(encrypted);

ErrorCode result = EncryptPacket(
    &packet, sizeof(packet),
    encrypted, &encrypted_size
);

if (result == ErrorCode::Success) {
    SendToServer(encrypted, encrypted_size);
}
```

**Thread Safety:** Thread-safe

**Performance:** ~50μs per packet (depends on size)

**Notes:**
- Uses AES-256-GCM
- Includes authentication tag
- Automatically adds nonce/IV

---

### DecryptPacket

```cpp
SENTINEL_API ErrorCode SENTINEL_CALL DecryptPacket(
    const void* data,
    size_t size,
    void* out_buffer,
    size_t* out_size
);
```

**Description:**  
Decrypts received game packet.

**Parameters:**
- `data` - Encrypted packet data
- `size` - Size of encrypted data
- `out_buffer` - Output buffer for decrypted data
- `out_size` - [in/out] Size of output buffer; updated with actual decrypted size

**Returns:**
- `ErrorCode::Success` - Decryption successful
- `ErrorCode::InvalidParameter` - Null pointer or invalid size
- `ErrorCode::BufferTooSmall` - Output buffer too small
- `ErrorCode::CryptoError` - Decryption/authentication failed

**Example:**
```cpp
GamePacket decrypted;
size_t decrypted_size = sizeof(decrypted);

ErrorCode result = DecryptPacket(
    encrypted_data, encrypted_size,
    &decrypted, &decrypted_size
);

if (result == ErrorCode::Success) {
    ProcessPacket(decrypted);
} else {
    LogWarning("Packet decryption failed - possible tampering");
}
```

**Thread Safety:** Thread-safe

**Performance:** ~50μs per packet

---

### GetPacketSequence

```cpp
SENTINEL_API uint32_t SENTINEL_CALL GetPacketSequence();
```

**Description:**  
Generates next packet sequence number for replay attack prevention.

**Parameters:** None

**Returns:**  
Next sequence number

**Example:**
```cpp
// Send packet with sequence
uint32_t seq = GetPacketSequence();
SendPacket(data, size, seq);
```

**Thread Safety:** Thread-safe (atomic increment)

**Performance:** < 1μs

**Notes:**
- Sequence numbers are monotonically increasing
- Wraps around at `UINT32_MAX`
- Client and server must synchronize sequences

---

### ValidatePacketSequence

```cpp
SENTINEL_API bool SENTINEL_CALL ValidatePacketSequence(uint32_t sequence);
```

**Description:**  
Validates incoming packet sequence number.

**Parameters:**
- `sequence` - Received sequence number

**Returns:**
- `true` - Sequence is valid
- `false` - Sequence is invalid (replay attack, packet loss, or out-of-order)

**Example:**
```cpp
void ReceivePacket(const uint8_t* data, size_t size, uint32_t seq) {
    if (!ValidatePacketSequence(seq)) {
        LogWarning("Invalid packet sequence %u - replay attack?", seq);
        return;  // Discard packet
    }
    
    ProcessPacket(data, size);
}
```

**Thread Safety:** Thread-safe

**Performance:** ~1μs

**Notes:**
- Allows small reordering window (configurable)
- Detects replay attacks
- May reject legitimate packets if network has high packet loss

---

## Statistics & Monitoring

### Statistics Structure

```cpp
struct Statistics {
    uint64_t uptime_ms;
    uint32_t updates_performed;
    uint32_t scans_performed;
    uint32_t violations_detected;
    uint32_t violations_reported;
    float avg_update_time_us;
    float avg_scan_time_ms;
    float max_update_time_us;
    uint32_t protected_regions;
    uint32_t protected_functions;
    uint64_t total_protected_bytes;
};
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `uptime_ms` | `uint64_t` | Milliseconds since initialization |
| `updates_performed` | `uint32_t` | Number of `Update()` calls |
| `scans_performed` | `uint32_t` | Number of `FullScan()` calls |
| `violations_detected` | `uint32_t` | Total violations detected |
| `violations_reported` | `uint32_t` | Violations reported to cloud |
| `avg_update_time_us` | `float` | Average `Update()` time (μs) |
| `avg_scan_time_ms` | `float` | Average `FullScan()` time (ms) |
| `max_update_time_us` | `float` | Maximum `Update()` time (μs) |
| `protected_regions` | `uint32_t` | Number of protected memory regions |
| `protected_functions` | `uint32_t` | Number of protected functions |
| `total_protected_bytes` | `uint64_t` | Total bytes under protection |

---

### GetStatistics

```cpp
SENTINEL_API void SENTINEL_CALL GetStatistics(Statistics* stats);
```

**Description:**  
Retrieves current SDK statistics.

**Parameters:**
- `stats` - Pointer to Statistics structure to fill

**Returns:** None (void)

**Example:**
```cpp
Statistics stats;
GetStatistics(&stats);

printf("SDK Uptime: %llu ms\n", stats.uptime_ms);
printf("Updates: %u\n", stats.updates_performed);
printf("Violations: %u\n", stats.violations_detected);
printf("Avg Update Time: %.2f μs\n", stats.avg_update_time_us);
printf("Avg Scan Time: %.2f ms\n", stats.avg_scan_time_ms);
```

**Thread Safety:** Thread-safe

**Performance:** ~5μs

---

### ResetStatistics

```cpp
SENTINEL_API void SENTINEL_CALL ResetStatistics();
```

**Description:**  
Resets all statistics counters to zero.

**Parameters:** None

**Returns:** None (void)

**Example:**
```cpp
// Reset stats after level load
ResetStatistics();
```

**Thread Safety:** Not thread-safe.

**Performance:** < 1μs

**Notes:**
- Does not reset uptime
- Does not affect protection state

---

## Whitelist Configuration

### WhitelistThreadOrigin

```cpp
SENTINEL_API ErrorCode SENTINEL_CALL WhitelistThreadOrigin(
    const char* module_name,
    const char* reason
);
```

**Description:**  
Adds a module to the thread origin whitelist, allowing threads from that module to bypass certain checks.

**Parameters:**
- `module_name` - Module name (e.g., "MyEngine.dll")
- `reason` - Description for logging (e.g., "Game engine job system")

**Returns:**
- `ErrorCode::Success` - Whitelist entry added
- `ErrorCode::InvalidParameter` - Null module name

**Example:**
```cpp
// Whitelist game engine threads
ErrorCode result = WhitelistThreadOrigin(
    "UnrealEngine.dll",
    "Unreal Engine task system threads"
);

if (result == ErrorCode::Success) {
    printf("Whitelisted UnrealEngine.dll threads\n");
}
```

**Thread Safety:** Not thread-safe.

**Performance:** ~10μs

**Notes:**
- Useful for game engines with custom threading
- Reduces false positives
- Be careful not to whitelist attacker modules

---

### RemoveThreadOriginWhitelist

```cpp
SENTINEL_API void SENTINEL_CALL RemoveThreadOriginWhitelist(const char* module_name);
```

**Description:**  
Removes a module from the thread origin whitelist.

**Parameters:**
- `module_name` - Module name to remove

**Returns:** None (void)

**Example:**
```cpp
RemoveThreadOriginWhitelist("TestModule.dll");
```

**Thread Safety:** Not thread-safe.

**Performance:** ~10μs

**Notes:**
- Cannot remove built-in whitelist entries
- Silently ignores if module not whitelisted

---

## Reporting

### ReportEvent

```cpp
SENTINEL_API ErrorCode SENTINEL_CALL ReportEvent(
    const char* event_type,
    const char* data
);
```

**Description:**  
Reports a custom event to the cloud endpoint.

**Parameters:**
- `event_type` - Event type identifier
- `data` - Event data (JSON string recommended)

**Returns:**
- `ErrorCode::Success` - Event queued for reporting
- `ErrorCode::InvalidParameter` - Null parameters
- `ErrorCode::NetworkError` - Cloud endpoint not configured

**Example:**
```cpp
// Report custom game event
ReportEvent("player_achievement", 
            "{\"achievement_id\": 123, \"timestamp\": 1234567890}");
```

**Thread Safety:** Thread-safe

**Performance:** ~50μs (queued, not synchronous)

---

### GetSessionToken

```cpp
SENTINEL_API const char* SENTINEL_CALL GetSessionToken();
```

**Description:**  
Returns current session token for this game session.

**Parameters:** None

**Returns:**  
Null-terminated session token string

**Example:**
```cpp
const char* token = GetSessionToken();
printf("Session: %s\n", token);
```

**Thread Safety:** Thread-safe

**Performance:** < 1μs

---

### GetHardwareId

```cpp
SENTINEL_API const char* SENTINEL_CALL GetHardwareId();
```

**Description:**  
Returns hardware fingerprint for this machine.

**Parameters:** None

**Returns:**  
Null-terminated hardware ID string

**Example:**
```cpp
const char* hwid = GetHardwareId();
printf("HWID: %s\n", hwid);

// Use for ban enforcement
if (IsBanned(hwid)) {
    ExitGame();
}
```

**Thread Safety:** Thread-safe

**Performance:** < 1μs

**Notes:**
- Based on CPU, motherboard, and disk information
- Stable across reboots
- Changes if hardware is upgraded

---

## C API

For integration with non-C++ languages (C, C#, etc.), use the C API:

```cpp
extern "C" {
    SENTINEL_API uint32_t SENTINEL_CALL SentinelInit(const Sentinel::SDK::Configuration* config);
    SENTINEL_API void SENTINEL_CALL SentinelShutdown();
    SENTINEL_API uint32_t SENTINEL_CALL SentinelUpdate();
    SENTINEL_API uint32_t SENTINEL_CALL SentinelFullScan();
    SENTINEL_API const char* SENTINEL_CALL SentinelGetVersion();
}
```

**Example (C):**
```c
#include <stdio.h>
#include <SentinelSDK.h>

int main() {
    // C API uses uint32_t for error codes
    uint32_t result = SentinelInit(NULL);  // Uses defaults
    if (result != 0) {
        fprintf(stderr, "Init failed: %u\n", result);
        return -1;
    }
    
    printf("SDK v%s\n", SentinelGetVersion());
    
    // Game loop
    while (game_running) {
        SentinelUpdate();
        // ... game logic ...
    }
    
    SentinelShutdown();
    return 0;
}
```

---

## Appendix: Complete API Summary

### Initialization & Control
- `Initialize()` - Initialize SDK
- `Shutdown()` - Shut down SDK
- `IsInitialized()` - Check initialization status
- `GetVersion()` - Get version string
- `GetLastError()` - Get last error message
- `Update()` - Frame update
- `FullScan()` - Full integrity scan
- `Pause()` - Pause monitoring
- `Resume()` - Resume monitoring
- `IsActive()` - Check if active

### Memory Protection
- `ProtectMemory()` - Protect memory region
- `UnprotectMemory()` - Unprotect region
- `VerifyMemory()` - Verify integrity

### Function Protection
- `ProtectFunction()` - Protect function
- `UnprotectFunction()` - Unprotect function
- `IsHooked()` - Check for hooks

### Value Protection
- `CreateProtectedInt()` - Create protected value
- `SetProtectedInt()` - Set protected value
- `GetProtectedInt()` - Get protected value
- `DestroyProtectedValue()` - Destroy protected value

### Secure Timing
- `GetSecureTime()` - Get secure timestamp
- `GetSecureDeltaTime()` - Get frame delta
- `ValidateTiming()` - Validate time interval

### Network Validation
- `EncryptPacket()` - Encrypt packet
- `DecryptPacket()` - Decrypt packet
- `GetPacketSequence()` - Get sequence number
- `ValidatePacketSequence()` - Validate sequence

### Statistics & Reporting
- `GetStatistics()` - Get runtime statistics
- `ResetStatistics()` - Reset statistics
- `ReportEvent()` - Report custom event
- `GetSessionToken()` - Get session token
- `GetHardwareId()` - Get hardware ID

### Whitelist Configuration
- `WhitelistThreadOrigin()` - Add thread whitelist
- `RemoveThreadOriginWhitelist()` - Remove whitelist

---

**Total API Functions:** 40+  
**Coverage:** 100% of public API documented  
**Examples:** Provided for every function

For integration examples, see [integration-guide.md](integration-guide.md)  
For common issues, see [troubleshooting.md](troubleshooting.md)
