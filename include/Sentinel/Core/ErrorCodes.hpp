/**
 * @file ErrorCodes.hpp
 * @brief Error codes and result types for the Sentinel Security Ecosystem
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This file defines all error codes used throughout Sentinel, along with
 * a Result type for error handling without exceptions.
 */

#pragma once

#ifndef SENTINEL_CORE_ERROR_CODES_HPP
#define SENTINEL_CORE_ERROR_CODES_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <optional>
#include <type_traits>

namespace Sentinel {

// ============================================================================
// Error Category Enumeration
// ============================================================================

/**
 * @brief Error categories for grouping related errors
 */
enum class ErrorCategory : uint8_t {
    None        = 0x00,  ///< No error
    System      = 0x01,  ///< Operating system errors
    Memory      = 0x02,  ///< Memory operation errors
    Crypto      = 0x03,  ///< Cryptographic errors
    Network     = 0x04,  ///< Network communication errors
    Analysis    = 0x05,  ///< Binary analysis errors
    Patch       = 0x06,  ///< Patch application errors
    Integrity   = 0x07,  ///< Integrity check errors
    Config      = 0x08,  ///< Configuration errors
    IO          = 0x09,  ///< File I/O errors
    Parse       = 0x0A,  ///< Parsing errors
    Auth        = 0x0B,  ///< Authentication errors
    Cloud       = 0x0C,  ///< Cloud service errors
    Internal    = 0xFF   ///< Internal/unknown errors
};

// ============================================================================
// Error Code Enumeration
// ============================================================================

/**
 * @brief Comprehensive error codes for all Sentinel operations
 * 
 * Error codes are structured as:
 * - 0x0000: Success
 * - 0x0100-0x01FF: System errors
 * - 0x0200-0x02FF: Memory errors
 * - 0x0300-0x03FF: Crypto errors
 * - 0x0400-0x04FF: Network errors
 * - 0x0500-0x05FF: Analysis errors
 * - 0x0600-0x06FF: Patch errors
 * - 0x0700-0x07FF: Integrity errors
 * - 0x0800-0x08FF: Config errors
 * - 0x0900-0x09FF: I/O errors
 * - 0x0A00-0x0AFF: Parse errors
 * - 0x0B00-0x0BFF: Auth errors
 * - 0x0C00-0x0CFF: Cloud errors
 * - 0xFF00-0xFFFF: Internal errors
 */
enum class ErrorCode : uint16_t {
    // ========================================================================
    // Success (0x0000)
    // ========================================================================
    
    /// Operation completed successfully
    Success = 0x0000,
    
    // ========================================================================
    // System Errors (0x0100-0x01FF)
    // ========================================================================
    
    /// Generic system error
    SystemError = 0x0100,
    
    /// Failed to get process handle
    ProcessAccessDenied = 0x0101,
    
    /// Failed to allocate memory
    AllocationFailed = 0x0102,
    
    /// Thread creation failed
    ThreadCreationFailed = 0x0103,
    
    /// Mutex/synchronization error
    SynchronizationError = 0x0104,
    
    /// Operation timed out
    Timeout = 0x0105,
    
    /// Operation was cancelled
    Cancelled = 0x0106,
    
    /// Feature not supported on this platform
    NotSupported = 0x0107,
    
    /// Invalid handle
    InvalidHandle = 0x0108,
    
    /// Insufficient privileges
    InsufficientPrivileges = 0x0109,
    
    // ========================================================================
    // Memory Errors (0x0200-0x02FF)
    // ========================================================================
    
    /// Generic memory error
    MemoryError = 0x0200,
    
    /// Failed to read memory
    MemoryReadFailed = 0x0201,
    
    /// Failed to write memory
    MemoryWriteFailed = 0x0202,
    
    /// Invalid memory address
    InvalidAddress = 0x0203,
    
    /// Memory region not found
    RegionNotFound = 0x0204,
    
    /// Failed to change memory protection
    ProtectionChangeFailed = 0x0205,
    
    /// Pattern not found in memory
    PatternNotFound = 0x0206,
    
    /// Memory region is protected
    RegionProtected = 0x0207,
    
    /// Buffer too small
    BufferTooSmall = 0x0208,
    
    /// Memory scan was interrupted
    ScanInterrupted = 0x0209,
    
    // ========================================================================
    // Cryptographic Errors (0x0300-0x03FF)
    // ========================================================================
    
    /// Generic cryptographic error
    CryptoError = 0x0300,
    
    /// Encryption failed
    EncryptionFailed = 0x0301,
    
    /// Decryption failed
    DecryptionFailed = 0x0302,
    
    /// Hash computation failed
    HashFailed = 0x0303,
    
    /// Signature generation failed
    SigningFailed = 0x0304,
    
    /// Signature verification failed
    SignatureInvalid = 0x0305,
    
    /// Invalid key format or size
    InvalidKey = 0x0306,
    
    /// Random number generation failed
    RandomGenerationFailed = 0x0307,
    
    /// Key derivation failed
    KeyDerivationFailed = 0x0308,
    
    /// Certificate validation failed
    CertificateInvalid = 0x0309,
    
    /// Weak cryptographic key detected (< 2048 bits or e != 65537)
    WeakKey = 0x030A,
    
    /// Key not loaded (operation requires key to be loaded first)
    KeyNotLoaded = 0x030B,
    
    /// Signature file not found
    SignatureNotFound = 0x030C,
    
    // ========================================================================
    // Network Errors (0x0400-0x04FF)
    // ========================================================================
    
    /// Generic network error
    NetworkError = 0x0400,
    
    /// Failed to connect to server
    ConnectionFailed = 0x0401,
    
    /// Connection was reset
    ConnectionReset = 0x0402,
    
    /// DNS resolution failed
    DnsResolutionFailed = 0x0403,
    
    /// TLS handshake failed
    TlsHandshakeFailed = 0x0404,
    
    /// Certificate pinning failed
    CertificatePinningFailed = 0x0405,
    
    /// HTTP request failed
    HttpRequestFailed = 0x0406,
    
    /// Invalid HTTP response
    HttpResponseInvalid = 0x0407,
    
    /// Server returned error status
    ServerError = 0x0408,
    
    /// Request rate limited
    RateLimited = 0x0409,
    
    /// Network unreachable
    NetworkUnreachable = 0x040A,
    
    /// TLS version too old (minimum TLS 1.2 required, TLS 1.3 preferred)
    TlsVersionTooOld = 0x040B,
    
    /// cURL initialization failed
    CurlInitFailed = 0x040C,
    
    // ========================================================================
    // Analysis Errors (0x0500-0x05FF)
    // ========================================================================
    
    /// Generic analysis error
    AnalysisError = 0x0500,
    
    /// Disassembly failed
    DisassemblyFailed = 0x0501,
    
    /// Invalid binary format
    InvalidBinaryFormat = 0x0502,
    
    /// Unsupported architecture
    UnsupportedArchitecture = 0x0503,
    
    /// Fuzzy hash computation failed
    FuzzyHashFailed = 0x0504,
    
    /// Binary diff failed
    DiffFailed = 0x0505,
    
    /// Function not found
    FunctionNotFound = 0x0506,
    
    /// Invalid PE header
    InvalidPEHeader = 0x0507,
    
    /// Section not found
    SectionNotFound = 0x0508,
    
    /// Import table corrupted
    ImportTableCorrupted = 0x0509,
    
    // ========================================================================
    // Patch Errors (0x0600-0x06FF)
    // ========================================================================
    
    /// Generic patch error
    PatchError = 0x0600,
    
    /// Patch application failed
    PatchApplicationFailed = 0x0601,
    
    /// Invalid patch format
    InvalidPatchFormat = 0x0602,
    
    /// Patch signature invalid
    PatchSignatureInvalid = 0x0603,
    
    /// Patch version mismatch
    PatchVersionMismatch = 0x0604,
    
    /// Target module not found
    TargetModuleNotFound = 0x0605,
    
    /// Target address invalid
    TargetAddressInvalid = 0x0606,
    
    /// Original bytes mismatch
    OriginalBytesMismatch = 0x0607,
    
    /// Patch already applied
    PatchAlreadyApplied = 0x0608,
    
    /// Patch not found
    PatchNotFound = 0x0609,
    
    // ========================================================================
    // Integrity Errors (0x0700-0x07FF)
    // ========================================================================
    
    /// Generic integrity error
    IntegrityError = 0x0700,
    
    /// Code integrity check failed
    CodeIntegrityFailed = 0x0701,
    
    /// Hook detected in protected function
    HookDetected = 0x0702,
    
    /// Debugger detected
    DebuggerDetected = 0x0703,
    
    /// Suspicious module detected
    SuspiciousModuleDetected = 0x0704,
    
    /// Checksum mismatch
    ChecksumMismatch = 0x0705,
    
    /// Tampering detected
    TamperingDetected = 0x0706,
    
    /// IAT modification detected
    IATModified = 0x0707,
    
    /// Code section modified
    CodeSectionModified = 0x0708,
    
    /// Anti-debug check failed
    AntiDebugFailed = 0x0709,
    
    // ========================================================================
    // Configuration Errors (0x0800-0x08FF)
    // ========================================================================
    
    /// Generic configuration error
    ConfigError = 0x0800,
    
    /// Missing required configuration
    ConfigMissing = 0x0801,
    
    /// Invalid configuration value
    ConfigInvalid = 0x0802,
    
    /// Configuration file not found
    ConfigFileNotFound = 0x0803,
    
    /// Configuration parse error
    ConfigParseFailed = 0x0804,
    
    /// Invalid API key
    InvalidApiKey = 0x0805,
    
    /// Invalid game ID
    InvalidGameId = 0x0806,
    
    /// Configuration version mismatch
    ConfigVersionMismatch = 0x0807,
    
    // ========================================================================
    // I/O Errors (0x0900-0x09FF)
    // ========================================================================
    
    /// Generic I/O error
    IOError = 0x0900,
    
    /// File not found
    FileNotFound = 0x0901,
    
    /// File access denied
    FileAccessDenied = 0x0902,
    
    /// File already exists
    FileAlreadyExists = 0x0903,
    
    /// Directory not found
    DirectoryNotFound = 0x0904,
    
    /// Disk full
    DiskFull = 0x0905,
    
    /// File read error
    FileReadError = 0x0906,
    
    /// File write error
    FileWriteError = 0x0907,
    
    /// Invalid file format
    InvalidFileFormat = 0x0908,
    
    /// File too large
    FileTooLarge = 0x0909,
    
    /// Invalid file path
    InvalidPath = 0x090A,
    
    /// Access denied
    AccessDenied = 0x090B,
    
    // ========================================================================
    // Parse Errors (0x0A00-0x0AFF)
    // ========================================================================
    
    /// Generic parse error
    ParseError = 0x0A00,
    
    /// JSON parse error
    JsonParseFailed = 0x0A01,
    
    /// Invalid JSON structure
    JsonInvalid = 0x0A02,
    
    /// Missing required field
    MissingField = 0x0A03,
    
    /// Invalid field type
    InvalidFieldType = 0x0A04,
    
    /// Invalid hex string
    InvalidHexString = 0x0A05,
    
    /// Invalid base64 string
    InvalidBase64 = 0x0A06,
    
    // ========================================================================
    // Authentication Errors (0x0B00-0x0BFF)
    // ========================================================================
    
    /// Generic authentication error
    AuthError = 0x0B00,
    
    /// Authentication failed
    AuthenticationFailed = 0x0B01,
    
    /// Token expired
    TokenExpired = 0x0B02,
    
    /// Token invalid
    TokenInvalid = 0x0B03,
    
    /// Permission denied
    PermissionDenied = 0x0B04,
    
    /// Account suspended
    AccountSuspended = 0x0B05,
    
    /// API key revoked
    ApiKeyRevoked = 0x0B06,
    
    // ========================================================================
    // Cloud Errors (0x0C00-0x0CFF)
    // ========================================================================
    
    /// Generic cloud error
    CloudError = 0x0C00,
    
    /// Cloud service unavailable
    CloudUnavailable = 0x0C01,
    
    /// Cloud sync failed
    CloudSyncFailed = 0x0C02,
    
    /// Upload failed
    UploadFailed = 0x0C03,
    
    /// Download failed
    DownloadFailed = 0x0C04,
    
    /// Resource not found
    ResourceNotFound = 0x0C05,
    
    /// Quota exceeded
    QuotaExceeded = 0x0C06,
    
    // ========================================================================
    // Internal Errors (0xFF00-0xFFFF)
    // ========================================================================
    
    /// Unknown internal error
    InternalError = 0xFF00,
    
    /// Assertion failed
    AssertionFailed = 0xFF01,
    
    /// Not implemented
    NotImplemented = 0xFF02,
    
    /// Invalid state
    InvalidState = 0xFF03,
    
    /// Null pointer
    NullPointer = 0xFF04,
    
    /// Invalid argument
    InvalidArgument = 0xFF05,
    
    /// Out of range
    OutOfRange = 0xFF06,
    
    /// Logic error
    LogicError = 0xFF07
};

// ============================================================================
// Error Code Utilities
// ============================================================================

/**
 * @brief Get the category of an error code
 * @param code The error code
 * @return The error category
 */
[[nodiscard]] constexpr ErrorCategory getErrorCategory(ErrorCode code) noexcept {
    uint16_t value = static_cast<uint16_t>(code);
    if (value == 0) return ErrorCategory::None;
    uint8_t category = static_cast<uint8_t>((value >> 8) & 0xFF);
    return static_cast<ErrorCategory>(category);
}

/**
 * @brief Check if an error code represents success
 * @param code The error code
 * @return true if success, false otherwise
 */
[[nodiscard]] constexpr bool isSuccess(ErrorCode code) noexcept {
    return code == ErrorCode::Success;
}

/**
 * @brief Check if an error code represents failure
 * @param code The error code
 * @return true if failure, false otherwise
 */
[[nodiscard]] constexpr bool isFailure(ErrorCode code) noexcept {
    return code != ErrorCode::Success;
}

/**
 * @brief Get human-readable error message
 * @param code The error code
 * @return Error message string
 */
[[nodiscard]] std::string_view getErrorMessage(ErrorCode code) noexcept;

/**
 * @brief Get error category name
 * @param category The error category
 * @return Category name string
 */
[[nodiscard]] std::string_view getCategoryName(ErrorCategory category) noexcept;

// ============================================================================
// Result Type
// ============================================================================

/**
 * @brief Result type for operations that can fail
 * 
 * This is a discriminated union that holds either a value of type T
 * or an ErrorCode. Use this for error handling without exceptions.
 * 
 * @tparam T The success value type
 * 
 * @example
 * ```cpp
 * Result<int> divide(int a, int b) {
 *     if (b == 0) return ErrorCode::InvalidArgument;
 *     return a / b;
 * }
 * 
 * auto result = divide(10, 2);
 * if (result.isSuccess()) {
 *     std::cout << "Result: " << result.value() << std::endl;
 * } else {
 *     std::cout << "Error: " << getErrorMessage(result.error()) << std::endl;
 * }
 * ```
 */
template<typename T>
class Result {
public:
    /// Default constructor creates a failed result
    Result() : m_data(ErrorCode::InternalError) {}
    
    /// Construct from success value
    Result(const T& value) : m_data(value) {}
    
    /// Construct from success value (move)
    Result(T&& value) : m_data(std::move(value)) {}
    
    /// Construct from error code
    Result(ErrorCode error) : m_data(error) {}
    
    /// Copy constructor
    Result(const Result&) = default;
    
    /// Move constructor
    Result(Result&&) noexcept = default;
    
    /// Copy assignment
    Result& operator=(const Result&) = default;
    
    /// Move assignment
    Result& operator=(Result&&) noexcept = default;
    
    /// Static method to create success result (for API compatibility)
    [[nodiscard]] static Result Success(T value) {
        return Result(std::move(value));
    }
    
    /// Static method to create error result (for API compatibility)
    [[nodiscard]] static Result Error(ErrorCode code, const std::string& message = "") {
        (void)message; // Message not stored in this implementation
        return Result(code);
    }
    
    /// Check if result is success
    [[nodiscard]] bool isSuccess() const noexcept {
        return std::holds_alternative<T>(m_data);
    }
    
    /// Check if result is failure
    [[nodiscard]] bool isFailure() const noexcept {
        return std::holds_alternative<ErrorCode>(m_data);
    }
    
    /// Implicit conversion to bool (true if success)
    [[nodiscard]] explicit operator bool() const noexcept {
        return isSuccess();
    }
    
    /// Get the success value (throws if failure)
    [[nodiscard]] T& value() & {
        if (isFailure()) {
            throw std::runtime_error("Attempted to access value of failed Result");
        }
        return std::get<T>(m_data);
    }
    
    /// Get the success value (const, throws if failure)
    [[nodiscard]] const T& value() const & {
        if (isFailure()) {
            throw std::runtime_error("Attempted to access value of failed Result");
        }
        return std::get<T>(m_data);
    }
    
    /// Get the success value (rvalue, throws if failure)
    [[nodiscard]] T&& value() && {
        if (isFailure()) {
            throw std::runtime_error("Attempted to access value of failed Result");
        }
        return std::get<T>(std::move(m_data));
    }
    
    /// Get the error code (throws if success)
    [[nodiscard]] ErrorCode error() const {
        if (isSuccess()) {
            throw std::runtime_error("Attempted to access error of successful Result");
        }
        return std::get<ErrorCode>(m_data);
    }
    
    /// Get value or default if failure
    [[nodiscard]] T valueOr(const T& defaultValue) const & {
        return isSuccess() ? std::get<T>(m_data) : defaultValue;
    }
    
    /// Get value or default if failure (move)
    [[nodiscard]] T valueOr(T&& defaultValue) && {
        return isSuccess() ? std::get<T>(std::move(m_data)) : std::move(defaultValue);
    }
    
    /// Get error or Success if no error
    [[nodiscard]] ErrorCode errorOr(ErrorCode defaultError = ErrorCode::Success) const noexcept {
        return isFailure() ? std::get<ErrorCode>(m_data) : defaultError;
    }
    
    /// Transform success value using a function
    template<typename F>
    [[nodiscard]] auto map(F&& func) const -> Result<decltype(func(std::declval<T>()))> {
        using U = decltype(func(std::declval<T>()));
        if (isSuccess()) {
            return Result<U>(func(std::get<T>(m_data)));
        }
        return Result<U>(std::get<ErrorCode>(m_data));
    }
    
    /// Chain with another Result-returning function
    template<typename F>
    [[nodiscard]] auto flatMap(F&& func) const -> decltype(func(std::declval<T>())) {
        using ResultType = decltype(func(std::declval<T>()));
        if (isSuccess()) {
            return func(std::get<T>(m_data));
        }
        return ResultType(std::get<ErrorCode>(m_data));
    }

private:
    std::variant<T, ErrorCode> m_data;
};

/**
 * @brief Specialization of Result for void (no return value)
 * 
 * Used for operations that can fail but don't return a value.
 */
template<>
class Result<void> {
public:
    /// Construct success result
    Result() : m_error(ErrorCode::Success) {}
    
    /// Construct from error code
    Result(ErrorCode error) : m_error(error) {}
    
    /// Static method to create success result (for API compatibility)
    [[nodiscard]] static Result Success() {
        return Result();
    }
    
    /// Static method to create error result (for API compatibility)
    [[nodiscard]] static Result Error(ErrorCode code, const std::string& message = "") {
        (void)message; // Message not stored in this implementation
        return Result(code);
    }
    
    /// Check if result is success
    [[nodiscard]] bool isSuccess() const noexcept {
        return m_error == ErrorCode::Success;
    }
    
    /// Check if result is failure
    [[nodiscard]] bool isFailure() const noexcept {
        return m_error != ErrorCode::Success;
    }
    
    /// Implicit conversion to bool
    [[nodiscard]] explicit operator bool() const noexcept {
        return isSuccess();
    }
    
    /// Get the error code
    [[nodiscard]] ErrorCode error() const noexcept {
        return m_error;
    }

private:
    ErrorCode m_error;
};

/// Alias for Result<void>
using VoidResult = Result<void>;

// ============================================================================
// Convenience Macros
// ============================================================================

/**
 * @brief Return early if result is failure
 * 
 * Usage:
 * ```cpp
 * SENTINEL_TRY(someOperation());
 * ```
 */
#define SENTINEL_TRY(expr) \
    do { \
        auto _result = (expr); \
        if (_result.isFailure()) return _result.error(); \
    } while (0)

/**
 * @brief Assign value or return early on failure
 * 
 * Usage:
 * ```cpp
 * SENTINEL_TRY_ASSIGN(value, someOperation());
 * ```
 */
#define SENTINEL_TRY_ASSIGN(var, expr) \
    auto _result_##var = (expr); \
    if (_result_##var.isFailure()) return _result_##var.error(); \
    var = std::move(_result_##var.value())

} // namespace Sentinel

#endif // SENTINEL_CORE_ERROR_CODES_HPP
