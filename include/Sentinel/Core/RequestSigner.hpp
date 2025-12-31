/**
 * @file RequestSigner.hpp
 * @brief HMAC-SHA256 request signing for API authentication
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * This module provides request authentication to defend against:
 * - Replay attacks (via timestamp validation)
 * - Request forgery (via HMAC signatures)
 * - Request tampering (via body hash inclusion)
 * - Timing attacks (via constant-time comparison)
 */

#pragma once

#ifndef SENTINEL_CORE_REQUEST_SIGNER_HPP
#define SENTINEL_CORE_REQUEST_SIGNER_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <string>
#include <memory>
#include <chrono>

namespace Sentinel::Network {

// Forward declaration
enum class HttpMethod;

/**
 * @brief Request signer using HMAC-SHA256
 * 
 * Provides cryptographic signing of HTTP requests to prevent replay attacks,
 * forgery, and tampering. Each request includes:
 * - X-Signature: HMAC-SHA256(method + path + timestamp + bodyHash)
 * - X-Timestamp: Unix timestamp in milliseconds
 * 
 * Security Features:
 * - Client-specific signing keys (not shared across clients)
 * - Timestamp validation with 60-second skew tolerance
 * - Constant-time signature comparison (timing attack resistant)
 * - Body hash inclusion (prevents tampering)
 * 
 * @example
 * ```cpp
 * // Initialize with client-specific secret
 * ByteBuffer clientSecret = deriveClientSecret(clientId, masterKey);
 * RequestSigner signer(clientSecret);
 * 
 * // Sign a request
 * HttpRequest request;
 * request.method = HttpMethod::POST;
 * request.url = "https://api.sentinel.com/v1/heartbeat";
 * request.body = jsonPayload;
 * 
 * auto result = signer.signRequest(request);
 * // Request now has X-Signature and X-Timestamp headers
 * 
 * // Verify a request (server-side)
 * auto valid = signer.verifyRequest(request);
 * ```
 */
class RequestSigner {
public:
    /**
     * @brief Construct request signer with client secret
     * @param clientSecret Client-specific secret key for signing
     * 
     * The client secret should be derived from initialization parameters,
     * not hardcoded in the binary. Example derivation:
     * HMAC-SHA256(masterKey, clientId + deviceId + timestamp)
     */
    explicit RequestSigner(ByteSpan clientSecret);
    
    /**
     * @brief Construct request signer with hex-encoded secret
     * @param hexSecret Client secret as hex string
     */
    explicit RequestSigner(const std::string& hexSecret);
    
    ~RequestSigner();
    
    // Non-copyable (contains sensitive key material)
    RequestSigner(const RequestSigner&) = delete;
    RequestSigner& operator=(const RequestSigner&) = delete;
    
    // Movable
    RequestSigner(RequestSigner&&) noexcept;
    RequestSigner& operator=(RequestSigner&&) noexcept;
    
    /**
     * @brief Sign an HTTP request
     * @param method HTTP method (GET, POST, etc.)
     * @param path Request path (e.g., "/v1/heartbeat")
     * @param body Request body (empty for GET requests)
     * @param timestamp Optional timestamp (defaults to current time)
     * @return Signature and timestamp to add as headers
     * 
     * Generates:
     * - signature: HMAC-SHA256(method + path + timestamp + SHA256(body))
     * - timestamp: Unix timestamp in milliseconds
     */
    struct SignedData {
        std::string signature;  ///< Base64-encoded HMAC signature
        int64_t timestamp;      ///< Unix timestamp in milliseconds
    };
    
    Result<SignedData> sign(
        HttpMethod method,
        const std::string& path,
        ByteSpan body = {},
        std::optional<int64_t> timestamp = std::nullopt
    );
    
    /**
     * @brief Verify a signed request
     * @param method HTTP method
     * @param path Request path
     * @param body Request body
     * @param signature Base64-encoded signature from X-Signature header
     * @param timestamp Timestamp from X-Timestamp header
     * @param maxSkewSeconds Maximum allowed time skew (default: 60 seconds)
     * @return true if signature is valid and timestamp is within window
     * 
     * Verification process:
     * 1. Check timestamp is within maxSkewSeconds of current time
     * 2. Compute expected signature from request data
     * 3. Compare using constant-time comparison (timing attack resistant)
     */
    Result<bool> verify(
        HttpMethod method,
        const std::string& path,
        ByteSpan body,
        const std::string& signature,
        int64_t timestamp,
        int maxSkewSeconds = 60
    );
    
    /**
     * @brief Update the signing key
     * @param newSecret New client secret
     * 
     * Useful for key rotation without recreating the signer instance.
     */
    void updateKey(ByteSpan newSecret);
    
    /**
     * @brief Get current Unix timestamp in milliseconds
     * @return Milliseconds since epoch
     */
    static int64_t getCurrentTimestamp();
    
    /**
     * @brief Extract path from full URL
     * @param url Full URL (e.g., "https://api.example.com/v1/endpoint?param=value")
     * @return Path component (e.g., "/v1/endpoint")
     * 
     * Extracts the path component from a URL for signing.
     * Query parameters are excluded from the signature.
     */
    static std::string extractPath(const std::string& url);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Sentinel::Network

#endif // SENTINEL_CORE_REQUEST_SIGNER_HPP
