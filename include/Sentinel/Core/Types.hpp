/**
 * @file Types.hpp
 * @brief Core type definitions for the Sentinel Security Ecosystem
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This file contains fundamental type definitions, constants, and aliases
 * used throughout the Sentinel codebase. All components should include
 * this header for consistent type usage.
 */

#pragma once

#ifndef SENTINEL_CORE_TYPES_HPP
#define SENTINEL_CORE_TYPES_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <span>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>

namespace Sentinel {

// ============================================================================
// Version Information
// ============================================================================

/// Major version number
constexpr uint32_t VERSION_MAJOR = 1;

/// Minor version number
constexpr uint32_t VERSION_MINOR = 0;

/// Patch version number
constexpr uint32_t VERSION_PATCH = 0;

/// Full version string
constexpr const char* VERSION_STRING = "1.0.0";

/// Build timestamp (set at compile time)
constexpr const char* BUILD_DATE = __DATE__;
constexpr const char* BUILD_TIME = __TIME__;

// ============================================================================
// Fundamental Type Aliases
// ============================================================================

/// Byte type for raw memory operations
using Byte = uint8_t;

/// Span of bytes (non-owning view)
using ByteSpan = std::span<const Byte>;

/// Mutable span of bytes
using MutableByteSpan = std::span<Byte>;

/// Owning byte buffer
using ByteBuffer = std::vector<Byte>;

/// Memory address type (platform-specific)
using Address = uintptr_t;

/// Relative Virtual Address
using RVA = uint32_t;

/// Process identifier
using ProcessId = uint32_t;

/// Thread identifier
using ThreadId = uint32_t;

/// Module handle
using ModuleHandle = void*;

/// File handle
using FileHandle = void*;

// ============================================================================
// Time Types
// ============================================================================

/// High-resolution clock for performance measurements
using Clock = std::chrono::high_resolution_clock;

/// Time point type
using TimePoint = Clock::time_point;

/// Duration in nanoseconds
using Nanoseconds = std::chrono::nanoseconds;

/// Duration in microseconds
using Microseconds = std::chrono::microseconds;

/// Duration in milliseconds
using Milliseconds = std::chrono::milliseconds;

/// Duration in seconds
using Seconds = std::chrono::seconds;

// ============================================================================
// String Types
// ============================================================================

/// Wide string type for Windows APIs
using WString = std::wstring;

/// String view for efficient string passing
using StringView = std::string_view;

/// Wide string view
using WStringView = std::wstring_view;

// ============================================================================
// Memory Region Types
// ============================================================================

/**
 * @brief Memory protection flags
 * 
 * Matches Windows PAGE_* constants for easy conversion
 */
enum class MemoryProtection : uint32_t {
    NoAccess          = 0x01,
    ReadOnly          = 0x02,
    ReadWrite         = 0x04,
    WriteCopy         = 0x08,
    Execute           = 0x10,
    ExecuteRead       = 0x20,
    ExecuteReadWrite  = 0x40,
    ExecuteWriteCopy  = 0x80,
    Guard             = 0x100,
    NoCache           = 0x200,
    WriteCombine      = 0x400
};

/**
 * @brief Memory region state
 */
enum class MemoryState : uint32_t {
    Commit   = 0x1000,
    Reserve  = 0x2000,
    Free     = 0x10000
};

/**
 * @brief Memory region type
 */
enum class MemoryType : uint32_t {
    Private = 0x20000,
    Mapped  = 0x40000,
    Image   = 0x1000000
};

/**
 * @brief Describes a memory region in a process
 */
struct MemoryRegion {
    Address baseAddress;        ///< Base address of the region
    size_t regionSize;          ///< Size in bytes
    MemoryProtection protection;///< Current protection
    MemoryState state;          ///< Commit/Reserve/Free
    MemoryType type;            ///< Private/Mapped/Image
    std::string moduleName;     ///< Associated module name (if any)
    
    /// Check if region is executable
    [[nodiscard]] bool isExecutable() const noexcept {
        return static_cast<uint32_t>(protection) & 
               (static_cast<uint32_t>(MemoryProtection::Execute) |
                static_cast<uint32_t>(MemoryProtection::ExecuteRead) |
                static_cast<uint32_t>(MemoryProtection::ExecuteReadWrite) |
                static_cast<uint32_t>(MemoryProtection::ExecuteWriteCopy));
    }
    
    /// Check if region is writable
    [[nodiscard]] bool isWritable() const noexcept {
        return static_cast<uint32_t>(protection) &
               (static_cast<uint32_t>(MemoryProtection::ReadWrite) |
                static_cast<uint32_t>(MemoryProtection::WriteCopy) |
                static_cast<uint32_t>(MemoryProtection::ExecuteReadWrite) |
                static_cast<uint32_t>(MemoryProtection::ExecuteWriteCopy));
    }
    
    /// Check if region is committed
    [[nodiscard]] bool isCommitted() const noexcept {
        return state == MemoryState::Commit;
    }
};

// ============================================================================
// Hash Types
// ============================================================================

/// SHA-256 hash (32 bytes)
using SHA256Hash = std::array<Byte, 32>;

/// SHA-512 hash (64 bytes)
using SHA512Hash = std::array<Byte, 64>;

/// MD5 hash (16 bytes) - for legacy/compatibility only
using MD5Hash = std::array<Byte, 16>;

/// TLSH fuzzy hash string
using TLSHHash = std::string;

/// ssdeep fuzzy hash string
using SsdeepHash = std::string;

// ============================================================================
// Cryptographic Types
// ============================================================================

/// AES-256 key (32 bytes)
using AESKey = std::array<Byte, 32>;

/// AES IV/Nonce (12 bytes for GCM)
using AESNonce = std::array<Byte, 12>;

/// AES-GCM authentication tag (16 bytes)
using AESTag = std::array<Byte, 16>;

/// RSA public key in DER format
using RSAPublicKey = ByteBuffer;

/// RSA private key in DER format
using RSAPrivateKey = ByteBuffer;

/// Digital signature
using Signature = ByteBuffer;

// ============================================================================
// Disassembly Types
// ============================================================================

/**
 * @brief CPU architecture type
 */
enum class Architecture : uint8_t {
    Unknown = 0,
    X86_32  = 1,
    X86_64  = 2,
    ARM32   = 3,
    ARM64   = 4
};

/**
 * @brief Disassembled instruction representation
 */
struct Instruction {
    Address address;            ///< Instruction address
    ByteBuffer bytes;           ///< Raw instruction bytes
    std::string mnemonic;       ///< Instruction mnemonic (e.g., "mov")
    std::string operands;       ///< Operand string (e.g., "rax, rbx")
    size_t size;                ///< Instruction size in bytes
    
    /// Full instruction string
    [[nodiscard]] std::string toString() const {
        return mnemonic + " " + operands;
    }
};

/**
 * @brief Collection of disassembled instructions
 */
using InstructionList = std::vector<Instruction>;

// ============================================================================
// Patch Types
// ============================================================================

/**
 * @brief Type of patch operation
 */
enum class PatchType : uint8_t {
    ByteReplace,    ///< Simple byte replacement
    NOP,            ///< Replace with NOP instructions
    Jump,           ///< Insert a JMP instruction
    Call,           ///< Insert a CALL instruction
    Hook,           ///< Install a function hook
    Restore         ///< Restore original bytes
};

/**
 * @brief Represents a single patch operation
 */
struct PatchEntry {
    std::string id;             ///< Unique patch identifier
    std::string description;    ///< Human-readable description
    std::string module;         ///< Target module name
    RVA rva;                    ///< Relative virtual address
    PatchType type;             ///< Type of patch
    ByteBuffer originalBytes;   ///< Original bytes (for restoration)
    ByteBuffer patchBytes;      ///< Bytes to write
    bool active;                ///< Whether patch should be applied
    
    /// Priority for ordering (higher = apply first)
    int priority = 0;
};

/**
 * @brief Collection of patches
 */
using PatchList = std::vector<PatchEntry>;

// ============================================================================
// Threat Types
// ============================================================================

/**
 * @brief Threat severity level
 */
enum class ThreatLevel : uint8_t {
    None     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4
};

/**
 * @brief Type of detected threat
 */
enum class ThreatType : uint8_t {
    Unknown           = 0,
    MemoryModification = 1,
    FunctionHook      = 2,
    DebuggerAttached  = 3,
    InjectedModule    = 4,
    SignatureMismatch = 5,
    IntegrityFailure  = 6,
    SuspiciousProcess = 7
};

/**
 * @brief Detected threat information
 */
struct ThreatInfo {
    ThreatType type;            ///< Type of threat
    ThreatLevel level;          ///< Severity level
    Address address;            ///< Address where threat was detected
    std::string module;         ///< Associated module
    std::string description;    ///< Detailed description
    TimePoint detectedAt;       ///< When threat was detected
    ByteBuffer evidence;        ///< Raw bytes as evidence
    
    /// Convert threat level to string
    [[nodiscard]] static const char* levelToString(ThreatLevel level) {
        switch (level) {
            case ThreatLevel::None:     return "None";
            case ThreatLevel::Low:      return "Low";
            case ThreatLevel::Medium:   return "Medium";
            case ThreatLevel::High:     return "High";
            case ThreatLevel::Critical: return "Critical";
            default:                    return "Unknown";
        }
    }
    
    /// Convert threat type to string
    [[nodiscard]] static const char* typeToString(ThreatType type) {
        switch (type) {
            case ThreatType::MemoryModification: return "Memory Modification";
            case ThreatType::FunctionHook:       return "Function Hook";
            case ThreatType::DebuggerAttached:   return "Debugger Attached";
            case ThreatType::InjectedModule:     return "Injected Module";
            case ThreatType::SignatureMismatch:  return "Signature Mismatch";
            case ThreatType::IntegrityFailure:   return "Integrity Failure";
            case ThreatType::SuspiciousProcess:  return "Suspicious Process";
            default:                             return "Unknown";
        }
    }
};

// ============================================================================
// Callback Types
// ============================================================================

/// Callback for threat detection
using ThreatCallback = std::function<void(const ThreatInfo&)>;

/// Callback for progress reporting
using ProgressCallback = std::function<void(size_t current, size_t total)>;

/// Callback for logging
using LogCallback = std::function<void(int level, const std::string& message)>;

// ============================================================================
// Smart Pointer Aliases
// ============================================================================

/// Unique pointer alias
template<typename T>
using UniquePtr = std::unique_ptr<T>;

/// Shared pointer alias
template<typename T>
using SharedPtr = std::shared_ptr<T>;

/// Weak pointer alias
template<typename T>
using WeakPtr = std::weak_ptr<T>;

// ============================================================================
// Optional and Variant Aliases
// ============================================================================

/// Optional type alias
template<typename T>
using Optional = std::optional<T>;

/// Nullable reference (optional reference_wrapper)
template<typename T>
using OptionalRef = std::optional<std::reference_wrapper<T>>;

// ============================================================================
// Configuration Types
// ============================================================================

/**
 * @brief SDK initialization configuration
 */
struct SDKConfig {
    std::string apiKey;              ///< API key for cloud authentication
    std::string gameId;              ///< Unique game identifier
    std::string cloudEndpoint;       ///< Cloud API endpoint URL
    
    bool enableHeartbeat = true;     ///< Enable periodic cloud sync
    bool enableIntegrityChecks = true; ///< Enable memory integrity checking
    bool enableAntiDebug = true;     ///< Enable anti-debugger checks
    bool enableAntiHook = true;      ///< Enable hook detection
    bool enableTelemetry = true;     ///< Enable telemetry reporting
    
    Milliseconds heartbeatInterval{30000};  ///< Heartbeat interval (default 30s)
    Milliseconds scanInterval{5000};        ///< Integrity scan interval (default 5s)
    
    LogCallback logCallback;         ///< Optional logging callback
    ThreatCallback threatCallback;   ///< Optional threat detection callback
};

/**
 * @brief Cortex application configuration
 */
struct CortexConfig {
    std::string workspacePath;       ///< Path to workspace directory
    std::string databasePath;        ///< Path to signature database
    std::string cloudEndpoint;       ///< Cloud API endpoint URL
    std::string apiKey;              ///< API key for cloud authentication
    
    bool darkMode = true;            ///< Enable dark mode UI
    bool expertMode = false;         ///< Enable expert mode features
    bool autoUpload = false;         ///< Auto-upload analysis results
    
    Architecture defaultArch = Architecture::X86_64; ///< Default architecture
};

} // namespace Sentinel

#endif // SENTINEL_CORE_TYPES_HPP
