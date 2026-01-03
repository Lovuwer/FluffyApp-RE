/**
 * @file Heartbeat.hpp
 * @brief Client heartbeat system for liveness detection
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * This module provides periodic heartbeat transmission to the server
 * to defend against:
 * - Process termination attacks (anti-cheat process killed)
 * - Thread suspension attacks (anti-cheat threads frozen)
 * - Silent client disablement
 */

#pragma once

#ifndef SENTINEL_CORE_HEARTBEAT_HPP
#define SENTINEL_CORE_HEARTBEAT_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <string>
#include <memory>
#include <chrono>
#include <functional>

namespace Sentinel::Network {

// Forward declarations
class HttpClient;
class RequestSigner;

/**
 * @brief Heartbeat configuration
 */
struct HeartbeatConfig {
    /// Base interval between heartbeats (default: 60 seconds)
    Milliseconds interval{60000};
    
    /// Maximum random jitter to add (default: 5 seconds)
    /// Prevents synchronized heartbeat floods from many clients
    Milliseconds jitterMax{5000};
    
    /// Server endpoint URL for heartbeat
    std::string serverUrl;
    
    /// Client identifier
    std::string clientId;
    
    /// Session token for authentication
    std::string sessionToken;
    
    /// Maximum retry attempts on transient network failure
    int maxRetries = 3;
    
    /// Delay between retry attempts
    Milliseconds retryDelay{1000};
    
    /// HTTP request timeout
    Milliseconds requestTimeout{5000};
    
    /// Enable detailed logging
    bool enableLogging = true;
};

/**
 * @brief Heartbeat status information
 * 
 * Contains metrics and state for replay protection and monitoring.
 */
struct HeartbeatStatus {
    /// Whether heartbeat thread is running
    bool isRunning = false;
    
    /// Number of successful heartbeats sent
    uint64_t successCount = 0;
    
    /// Number of failed heartbeat attempts
    uint64_t failureCount = 0;
    
    /// Current sequence number (REPLAY PROTECTION)
    /// This monotonically increasing counter is included in each heartbeat.
    /// Server must reject heartbeats with sequence <= last_seen_sequence.
    uint64_t sequenceNumber = 0;
    
    /// Timestamp of last successful heartbeat
    TimePoint lastSuccess{};
    
    /// Timestamp of last failed heartbeat
    TimePoint lastFailure{};
    
    /// Last error code
    ErrorCode lastError = ErrorCode::Success;
};

/**
 * @brief Client heartbeat system
 * 
 * Provides periodic heartbeat transmission to detect client liveness.
 * Critical for detecting process termination and thread suspension attacks.
 * 
 * REPLAY PROTECTION (STAB-009):
 * ==============================
 * Each heartbeat includes:
 * 1. Sequence Number: Monotonically increasing counter that prevents
 *    replay of old heartbeats. Server must reject sequence <= last_seen.
 * 2. Timestamp: UTC milliseconds since epoch for freshness validation.
 *    Server should reject timestamps outside ±60s window.
 * 3. Session Token: Authentication token (signed via RequestSigner).
 * 
 * Server-Side Requirements:
 * - Maintain last-seen sequence number per client
 * - Reject duplicate or old sequence numbers
 * - Validate timestamp freshness (±60s window)
 * - Verify cryptographic signature
 * 
 * Client-Side Behavior:
 * - Sequence resets to 0 on start() (new session)
 * - Sequence increments on every send attempt (success or failure)
 * - Timestamp generated fresh for each heartbeat
 * - No client-side replay detection (server's responsibility)
 * 
 * Features:
 * - Configurable interval with random jitter
 * - Automatic retry on transient network failure
 * - Graceful failure handling (no game crash)
 * - Sequence number tracking
 * - Thread-safe operation
 * - Minimal CPU and memory overhead
 * 
 * @example
 * ```cpp
 * // Initialize heartbeat
 * HeartbeatConfig config;
 * config.interval = Milliseconds{60000};  // 60 seconds
 * config.jitterMax = Milliseconds{5000};   // 0-5 seconds jitter
 * config.serverUrl = "https://api.sentinel.com/v1/heartbeat";
 * config.clientId = "client-12345";
 * config.sessionToken = "session-token-xyz";
 * 
 * auto httpClient = std::make_shared<HttpClient>();
 * auto signer = std::make_shared<RequestSigner>(secretKey);
 * 
 * Heartbeat heartbeat(config, httpClient, signer);
 * 
 * // Start heartbeat
 * auto result = heartbeat.start();
 * if (result.isSuccess()) {
 *     // Heartbeat running in background
 * }
 * 
 * // Check status
 * auto status = heartbeat.getStatus();
 * std::cout << "Heartbeats sent: " << status.successCount << std::endl;
 * 
 * // Stop heartbeat
 * heartbeat.stop();
 * ```
 */
class Heartbeat {
public:
    /**
     * @brief Construct heartbeat system
     * @param config Heartbeat configuration
     * @param httpClient Shared HTTP client for network communication
     * @param signer Optional request signer for authentication
     */
    Heartbeat(
        const HeartbeatConfig& config,
        std::shared_ptr<HttpClient> httpClient,
        std::shared_ptr<RequestSigner> signer = nullptr
    );
    
    /**
     * @brief Destructor - stops heartbeat thread if running
     */
    ~Heartbeat();
    
    // Non-copyable
    Heartbeat(const Heartbeat&) = delete;
    Heartbeat& operator=(const Heartbeat&) = delete;
    
    // Movable
    Heartbeat(Heartbeat&&) noexcept;
    Heartbeat& operator=(Heartbeat&&) noexcept;
    
    /**
     * @brief Start heartbeat transmission
     * @return Success or error code
     * 
     * Starts a background thread that sends periodic heartbeats.
     * Returns immediately after starting the thread.
     */
    Result<void> start();
    
    /**
     * @brief Stop heartbeat transmission
     * 
     * Signals the heartbeat thread to stop and waits for it to finish.
     * Safe to call multiple times. Does not throw exceptions.
     */
    void stop() noexcept;
    
    /**
     * @brief Check if heartbeat is running
     * @return true if heartbeat thread is active
     */
    [[nodiscard]] bool isRunning() const noexcept;
    
    /**
     * @brief Get heartbeat status
     * @return Current status information
     */
    [[nodiscard]] HeartbeatStatus getStatus() const noexcept;
    
    /**
     * @brief Update configuration
     * @param config New configuration
     * 
     * Updates configuration while heartbeat is running.
     * Changes take effect after the next heartbeat cycle.
     */
    void updateConfig(const HeartbeatConfig& config) noexcept;
    
    /**
     * @brief Send a single heartbeat immediately
     * @return Success or error code
     * 
     * Sends a heartbeat outside the normal schedule.
     * Useful for testing or on-demand health checks.
     */
    Result<void> sendHeartbeat();
    
    /**
     * @brief Set callback for heartbeat events
     * @param onSuccess Callback for successful heartbeat
     * @param onFailure Callback for failed heartbeat
     * 
     * Callbacks are invoked from the heartbeat thread.
     * Keep callback execution time minimal to avoid delays.
     */
    void setCallbacks(
        std::function<void(uint64_t sequence)> onSuccess,
        std::function<void(ErrorCode error, uint64_t sequence)> onFailure
    );

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Sentinel::Network

#endif // SENTINEL_CORE_HEARTBEAT_HPP
