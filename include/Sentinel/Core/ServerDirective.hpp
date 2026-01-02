/**
 * @file ServerDirective.hpp
 * @brief Server-Authoritative Enforcement Directive Protocol
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 24: Server-Authoritative Enforcement Model
 * 
 * This module implements the protocol for server-issued enforcement directives.
 * The SDK reports detections but NEVER enforces locally. Only the server can
 * issue authoritative directives that the game must respect.
 * 
 * Security Features:
 * - HMAC-SHA256 signature authentication
 * - Monotonic sequence numbers prevent replay attacks
 * - Timestamp validation with 60-second tolerance
 * - Directive expiration to prevent stale directive replay
 * 
 * Enforcement Authority:
 * - Client: Detect and report only (zero enforcement)
 * - Server: Receive reports, decide, issue directives
 * - Game: Implement server directives as authoritative
 */

#pragma once

#ifndef SENTINEL_CORE_SERVER_DIRECTIVE_HPP
#define SENTINEL_CORE_SERVER_DIRECTIVE_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <string>
#include <cstdint>
#include <memory>
#include <optional>

namespace Sentinel::Network {

// Forward declarations
class RequestSigner;

/**
 * @brief Types of server directives
 * 
 * Server controls all enforcement decisions. Client has no authority
 * to take action without explicit server directive.
 */
enum class DirectiveType : uint32_t {
    None = 0,                   ///< No directive (default state)
    SessionContinue = 1,        ///< Explicit approval to continue playing
    SessionTerminate = 2,       ///< Session must be terminated
    SessionSuspend = 3,         ///< Temporary suspension (future use)
    RequireReconnect = 4,       ///< Force client reconnection
    UpdateRequired = 5,         ///< Client version update required
    SignatureRollback = 6       ///< Task 25: Rollback to previous signature set
};

/**
 * @brief Severity/reason for termination
 */
enum class DirectiveReason : uint32_t {
    None = 0,
    CheatDetected = 1,
    PolicyViolation = 2,
    SystemError = 3,
    MaintenanceMode = 4,
    AccountBanned = 5,
    SessionExpired = 6
};

/**
 * @brief Server enforcement directive
 * 
 * Directives are cryptographically signed by server and cannot be forged
 * or replayed. Each directive includes:
 * - Monotonic sequence number (prevents replay)
 * - Timestamp (limits validity window)
 * - HMAC signature (prevents forgery)
 * - Expiration time (prevents stale directive reuse)
 */
struct ServerDirective {
    DirectiveType type;         ///< Type of directive
    DirectiveReason reason;     ///< Reason for directive
    uint64_t sequence;          ///< Monotonic sequence number
    int64_t timestamp;          ///< Unix timestamp in milliseconds
    int64_t expires_at;         ///< Expiration timestamp
    std::string session_id;     ///< Session identifier
    std::string message;        ///< Human-readable message
    std::string signature;      ///< Base64-encoded HMAC-SHA256 signature
    
    /**
     * @brief Check if directive has expired
     * @return true if directive is past expiration time
     */
    bool isExpired() const {
        int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        return now > expires_at;
    }
    
    /**
     * @brief Check if directive is within valid time window
     * @param max_skew_seconds Maximum allowed time skew
     * @return true if timestamp is within tolerance
     */
    bool isTimestampValid(int max_skew_seconds = 60) const {
        int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        int64_t skew_ms = max_skew_seconds * 1000;
        return (now - timestamp) <= skew_ms && (now - timestamp) >= -skew_ms;
    }
};

/**
 * @brief Callback for server directives
 * 
 * Game must implement this callback to receive and act on server directives.
 * The game MUST respect these directives as authoritative.
 * 
 * @param directive Server directive to process
 * @param user_data User-provided context
 * @return true if directive was processed successfully
 */
typedef bool (*DirectiveCallback)(const ServerDirective& directive, void* user_data);

/**
 * @brief Server directive validator
 * 
 * Validates server directives for authenticity and freshness.
 * Prevents replay attacks, forgery, and expired directive execution.
 */
class DirectiveValidator {
public:
    /**
     * @brief Construct validator with shared secret
     * @param signer Request signer for HMAC validation
     * @param session_id Current session identifier
     */
    explicit DirectiveValidator(
        std::shared_ptr<RequestSigner> signer,
        const std::string& session_id
    );
    
    ~DirectiveValidator();
    
    // Non-copyable
    DirectiveValidator(const DirectiveValidator&) = delete;
    DirectiveValidator& operator=(const DirectiveValidator&) = delete;
    
    // Movable
    DirectiveValidator(DirectiveValidator&&) noexcept;
    DirectiveValidator& operator=(DirectiveValidator&&) noexcept;
    
    /**
     * @brief Validate a server directive
     * @param directive Directive to validate
     * @return Success if valid, error otherwise
     * 
     * Validation checks:
     * 1. Signature is valid (HMAC matches)
     * 2. Timestamp is within tolerance window
     * 3. Sequence number is higher than last seen (prevents replay)
     * 4. Directive has not expired
     * 5. Session ID matches current session
     */
    Result<bool> validate(const ServerDirective& directive);
    
    /**
     * @brief Get last processed directive sequence number
     * @return Sequence number of last valid directive
     */
    uint64_t getLastSequence() const;
    
    /**
     * @brief Reset sequence tracking (e.g., on reconnect)
     */
    void resetSequence();
    
    /**
     * @brief Update session ID (e.g., on reconnect)
     * @param session_id New session identifier
     */
    void updateSessionId(const std::string& session_id);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

/**
 * @brief Parse server directive from JSON
 * @param json JSON string containing directive
 * @return Parsed directive or error
 */
Result<ServerDirective> parseDirective(const std::string& json);

/**
 * @brief Serialize directive to JSON (for testing/debugging)
 * @param directive Directive to serialize
 * @return JSON string
 */
std::string serializeDirective(const ServerDirective& directive);

} // namespace Sentinel::Network

#endif // SENTINEL_CORE_SERVER_DIRECTIVE_HPP
