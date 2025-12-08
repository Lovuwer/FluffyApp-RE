/**
 * Sentinel Watchtower - Roblox Security Module
 * 
 * Specialized anti-cheat for Roblox games with Luau script protection,
 * exploit detection, and network security.
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>

// Version info
#define WATCHTOWER_VERSION_MAJOR 1
#define WATCHTOWER_VERSION_MINOR 0
#define WATCHTOWER_VERSION_PATCH 0
#define WATCHTOWER_VERSION_STRING "1.0.0"

// Export macros
#ifdef WATCHTOWER_EXPORTS
    #define WATCHTOWER_API __declspec(dllexport)
#else
    #define WATCHTOWER_API __declspec(dllimport)
#endif

#define WATCHTOWER_CALL __stdcall

namespace Sentinel {
namespace Watchtower {

// ==================== Error Codes ====================

enum class ErrorCode : uint32_t {
    Success = 0,
    
    // Initialization
    NotInitialized = 1,
    AlreadyInitialized = 2,
    InvalidConfiguration = 3,
    LuauBridgeError = 4,
    
    // Runtime
    InternalError = 100,
    Timeout = 101,
    NetworkError = 102,
    
    // Security
    ExploitDetected = 200,
    ScriptInjection = 201,
    RemoteManipulation = 202,
    SpeedExploit = 203,
    TeleportExploit = 204,
    WalkspeedExploit = 205,
    JumpPowerExploit = 206,
    NoClipDetected = 207,
    FlyHackDetected = 208,
    AimbotDetected = 209,
    ESPDetected = 210,
    ExecutorDetected = 211
};

// ==================== Exploit Types ====================

/**
 * Types of exploits to detect
 */
enum class ExploitType : uint32_t {
    None = 0,
    
    // Movement exploits
    SpeedHack = 0x0001,
    Teleport = 0x0002,
    NoClip = 0x0004,
    FlyHack = 0x0008,
    JumpPower = 0x0010,
    
    // Combat exploits
    Aimbot = 0x0020,
    SilentAim = 0x0040,
    AutoFire = 0x0080,
    Killaura = 0x0100,
    GodMode = 0x0200,
    
    // Visual exploits
    ESP = 0x0400,
    Wallhack = 0x0800,
    Xray = 0x1000,
    Chams = 0x2000,
    
    // Script exploits
    ScriptInjection = 0x4000,
    RemoteSpam = 0x8000,
    FireServer = 0x10000,
    InvokeServer = 0x20000,
    
    // Client exploits
    ExecutorDetected = 0x40000,
    MemoryManipulation = 0x80000,
    HookDetected = 0x100000,
    
    // All exploits
    All = 0xFFFFFFFF
};

/**
 * Severity of exploit detection
 */
enum class Severity : uint8_t {
    Info = 0,       // Suspicious but may be legitimate
    Warning = 1,    // Likely exploit, monitor closely
    High = 2,       // Confirmed exploit, take action
    Critical = 3    // Severe exploit, immediate action
};

/**
 * Action to take on exploit detection
 */
enum class Action : uint32_t {
    None = 0,
    Log = 0x01,
    Report = 0x02,
    Warn = 0x04,
    Kick = 0x08,
    Ban = 0x10,
    
    // Presets
    Silent = Log | Report,
    Standard = Log | Report | Warn,
    Strict = Log | Report | Kick
};

// ==================== Event Data ====================

/**
 * Exploit detection event
 */
struct ExploitEvent {
    ExploitType type;
    Severity severity;
    Action action_taken;
    
    uint64_t timestamp;         // Server timestamp
    uint64_t player_id;         // Roblox UserId
    std::string player_name;    // Player display name
    
    // Detection details
    std::string description;
    std::string evidence;       // JSON formatted evidence
    
    // Position data (if applicable)
    struct {
        float x, y, z;
    } position;
    
    // Movement data (if applicable)
    float velocity;
    float acceleration;
    
    // Script data (if applicable)
    std::string script_source;
    std::string remote_name;
};

/**
 * Callback for exploit detection
 */
using ExploitCallback = std::function<bool(const ExploitEvent& event)>;

// ==================== Configuration ====================

/**
 * Watchtower configuration
 */
struct Configuration {
    // Detection settings
    ExploitType enabled_detections = ExploitType::All;
    Action default_action = Action::Standard;
    
    // Movement validation
    struct {
        float max_walkspeed = 16.0f;    // Default Roblox walkspeed
        float max_jumppower = 50.0f;     // Default Roblox jumppower
        float max_velocity = 100.0f;     // Maximum reasonable velocity
        float teleport_threshold = 50.0f; // Distance for teleport detection
        float position_tolerance = 5.0f;  // Position validation tolerance
    } movement;
    
    // Combat validation
    struct {
        float max_fire_rate = 20.0f;    // Max shots per second
        float aim_snap_threshold = 45.0f; // Degrees for aimbot detection
        float reaction_time_min = 0.1f;  // Minimum human reaction time
    } combat;
    
    // Remote validation
    struct {
        int max_remote_calls_per_second = 60;
        int max_args_per_call = 20;
        size_t max_arg_size = 1024;
        bool validate_remote_signatures = true;
    } remotes;
    
    // Callbacks
    ExploitCallback exploit_callback;
    
    // Cloud reporting
    const char* api_key = nullptr;
    const char* game_id = nullptr;
    const char* server_endpoint = nullptr;
    
    // Debug
    bool debug_mode = false;
    bool verbose_logging = false;
    
    static Configuration Default() {
        return Configuration{};
    }
};

// ==================== Player Tracking ====================

/**
 * Player movement state for validation
 */
struct PlayerState {
    uint64_t player_id;
    
    // Position history
    struct PositionSample {
        float x, y, z;
        uint64_t timestamp;
    };
    std::vector<PositionSample> position_history;
    
    // Current state
    float current_walkspeed;
    float current_jumppower;
    bool is_grounded;
    bool is_sitting;
    bool is_dead;
    
    // Statistics
    int violation_count;
    uint64_t last_violation_time;
    float suspicion_level;  // 0.0 - 1.0
};

// ==================== Core API ====================

class Watchtower;

/**
 * Initialize Watchtower module
 * @param config Configuration options
 * @return Error code
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL Initialize(const Configuration& config);

/**
 * Shutdown Watchtower module
 */
WATCHTOWER_API void WATCHTOWER_CALL Shutdown();

/**
 * Check if initialized
 */
WATCHTOWER_API bool WATCHTOWER_CALL IsInitialized();

/**
 * Get version string
 */
WATCHTOWER_API const char* WATCHTOWER_CALL GetVersion();

// ==================== Player Management ====================

/**
 * Register a player for monitoring
 * @param player_id Roblox UserId
 * @param player_name Display name
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL RegisterPlayer(
    uint64_t player_id,
    const char* player_name);

/**
 * Unregister a player (on leave)
 * @param player_id Roblox UserId
 */
WATCHTOWER_API void WATCHTOWER_CALL UnregisterPlayer(uint64_t player_id);

/**
 * Update player position (call from heartbeat)
 * @param player_id Player ID
 * @param x, y, z World position
 * @param timestamp Server timestamp
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL UpdatePlayerPosition(
    uint64_t player_id,
    float x, float y, float z,
    uint64_t timestamp);

/**
 * Validate player movement
 * @param player_id Player ID
 * @param walkspeed Current walkspeed
 * @param jumppower Current jumppower
 * @return Error code (Success if valid)
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL ValidateMovement(
    uint64_t player_id,
    float walkspeed,
    float jumppower);

/**
 * Get player state
 * @param player_id Player ID
 * @param out_state Output state structure
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL GetPlayerState(
    uint64_t player_id,
    PlayerState* out_state);

// ==================== Remote Validation ====================

/**
 * Register a RemoteEvent/RemoteFunction for validation
 * @param remote_name Name of the remote
 * @param expected_args Expected argument types (JSON schema)
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL RegisterRemote(
    const char* remote_name,
    const char* expected_args);

/**
 * Validate a remote call before processing
 * @param player_id Calling player
 * @param remote_name Remote name
 * @param args Serialized arguments
 * @return Error code (Success if valid)
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL ValidateRemoteCall(
    uint64_t player_id,
    const char* remote_name,
    const char* args);

/**
 * Check remote call rate limiting
 * @param player_id Player ID
 * @return true if within limits
 */
WATCHTOWER_API bool WATCHTOWER_CALL CheckRemoteRateLimit(uint64_t player_id);

// ==================== Combat Validation ====================

/**
 * Validate weapon fire event
 * @param player_id Shooter ID
 * @param target_id Target ID (0 if no target)
 * @param origin Shot origin position
 * @param direction Shot direction
 * @param timestamp Event timestamp
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL ValidateWeaponFire(
    uint64_t player_id,
    uint64_t target_id,
    float origin_x, float origin_y, float origin_z,
    float dir_x, float dir_y, float dir_z,
    uint64_t timestamp);

/**
 * Validate damage event
 * @param attacker_id Attacker player ID
 * @param victim_id Victim player ID
 * @param damage Damage amount
 * @param damage_type Type of damage
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL ValidateDamage(
    uint64_t attacker_id,
    uint64_t victim_id,
    float damage,
    const char* damage_type);

// ==================== Script Security ====================

/**
 * Validate Lua/Luau script source
 * @param source Script source code
 * @return Error code (Success if safe)
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL ValidateScript(const char* source);

/**
 * Check for known executor signatures
 * @param player_id Player to check
 * @return Error code
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL CheckForExecutor(uint64_t player_id);

/**
 * Scan client for injected scripts
 * @param player_id Player to scan
 */
WATCHTOWER_API ErrorCode WATCHTOWER_CALL ScanForInjection(uint64_t player_id);

// ==================== Network Fuzzer ====================

/**
 * Enable network packet fuzzing mode
 * This sends malformed packets to test client security
 */
WATCHTOWER_API void WATCHTOWER_CALL EnableNetworkFuzzer();

/**
 * Disable network fuzzer
 */
WATCHTOWER_API void WATCHTOWER_CALL DisableNetworkFuzzer();

/**
 * Run fuzzing test
 * @param test_type Type of fuzz test to run
 * @return Number of vulnerabilities found
 */
WATCHTOWER_API int WATCHTOWER_CALL RunFuzzTest(const char* test_type);

// ==================== Luau Bridge ====================

/**
 * Lua binding for Watchtower module
 * Call this to expose Watchtower functions to Lua
 * @param L Lua state
 */
WATCHTOWER_API int WATCHTOWER_CALL LuaOpen(void* L);

/**
 * Helper macro for Luau integration
 * Usage in ModuleScript:
 *   local Watchtower = require(path.to.WatchtowerModule)
 *   Watchtower.Initialize(config)
 */

// ==================== Statistics ====================

/**
 * Detection statistics
 */
struct Statistics {
    uint64_t uptime_ms;
    uint32_t players_monitored;
    uint32_t total_detections;
    uint32_t kicks_issued;
    uint32_t bans_issued;
    
    // By exploit type
    uint32_t speedhack_detections;
    uint32_t teleport_detections;
    uint32_t aimbot_detections;
    uint32_t executor_detections;
    uint32_t remote_abuse_detections;
    
    // Performance
    float avg_validation_time_us;
    float max_validation_time_us;
};

/**
 * Get current statistics
 */
WATCHTOWER_API void WATCHTOWER_CALL GetStatistics(Statistics* stats);

/**
 * Reset statistics
 */
WATCHTOWER_API void WATCHTOWER_CALL ResetStatistics();

// ==================== Utility Functions ====================

/**
 * Convert error code to string
 */
WATCHTOWER_API const char* WATCHTOWER_CALL ErrorCodeToString(ErrorCode code);

/**
 * Convert exploit type to string
 */
WATCHTOWER_API const char* WATCHTOWER_CALL ExploitTypeToString(ExploitType type);

/**
 * Parse exploit type from string
 */
WATCHTOWER_API ExploitType WATCHTOWER_CALL ParseExploitType(const char* str);

// Operator overloads for flags
inline ExploitType operator|(ExploitType a, ExploitType b) {
    return static_cast<ExploitType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline ExploitType operator&(ExploitType a, ExploitType b) {
    return static_cast<ExploitType>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline Action operator|(Action a, Action b) {
    return static_cast<Action>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

} // namespace Watchtower
} // namespace Sentinel
