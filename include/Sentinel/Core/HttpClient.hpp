/**
 * @file HttpClient.hpp
 * @brief HTTPS client with TLS 1.3 and certificate pinning
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This module provides a secure HTTP client for cloud communication.
 */

#pragma once

#ifndef SENTINEL_CORE_HTTP_CLIENT_HPP
#define SENTINEL_CORE_HTTP_CLIENT_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <string>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sentinel::Network {

// ============================================================================
// HTTP Types
// ============================================================================

/**
 * @brief HTTP methods
 */
enum class HttpMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE_,  // DELETE is a reserved word
    HEAD,
    OPTIONS
};

/**
 * @brief HTTP header map
 */
using HttpHeaders = std::map<std::string, std::string>;

/**
 * @brief HTTP request configuration
 */
struct HttpRequest {
    HttpMethod method = HttpMethod::GET;
    std::string url;
    HttpHeaders headers;
    ByteBuffer body;
    
    /// Timeout for the request
    Milliseconds timeout{30000};
    
    /// Enable certificate pinning
    bool enablePinning = true;
    
    /// Follow redirects
    bool followRedirects = true;
    
    /// Maximum redirects
    int maxRedirects = 5;
    
    /// User agent string
    std::string userAgent = "Sentinel/1.0";
};

/**
 * @brief HTTP response
 */
struct HttpResponse {
    /// HTTP status code
    int statusCode = 0;
    
    /// Status message
    std::string statusMessage;
    
    /// Response headers
    HttpHeaders headers;
    
    /// Response body
    ByteBuffer body;
    
    /// Total time taken
    Milliseconds elapsed{0};
    
    /// Check if request was successful (2xx)
    [[nodiscard]] bool isSuccess() const noexcept {
        return statusCode >= 200 && statusCode < 300;
    }
    
    /// Check if request was redirected (3xx)
    [[nodiscard]] bool isRedirect() const noexcept {
        return statusCode >= 300 && statusCode < 400;
    }
    
    /// Check if request had client error (4xx)
    [[nodiscard]] bool isClientError() const noexcept {
        return statusCode >= 400 && statusCode < 500;
    }
    
    /// Check if request had server error (5xx)
    [[nodiscard]] bool isServerError() const noexcept {
        return statusCode >= 500 && statusCode < 600;
    }
    
    /// Get body as string
    [[nodiscard]] std::string bodyAsString() const {
        return std::string(body.begin(), body.end());
    }
    
    /// Get header value (case-insensitive)
    [[nodiscard]] std::string getHeader(const std::string& name) const;
};

// ============================================================================
// Certificate Pinning
// ============================================================================

/**
 * @brief Certificate pin entry
 */
struct CertificatePin {
    std::string hostname;          ///< Hostname pattern (supports wildcards)
    std::vector<SHA256Hash> pins;  ///< SHA-256 hashes of public keys
    bool includeSubdomains = true; ///< Pin applies to subdomains
};

/**
 * @brief Certificate pinner for HTTPS connections
 */
class CertPinner {
public:
    CertPinner();
    ~CertPinner();
    
    /**
     * @brief Add a certificate pin
     * @param pin Certificate pin entry
     */
    void addPin(const CertificatePin& pin);
    
    /**
     * @brief Add multiple pins
     * @param pins Vector of pins
     */
    void addPins(const std::vector<CertificatePin>& pins);
    
    /**
     * @brief Remove all pins for hostname
     * @param hostname Hostname to unpin
     */
    void removePin(const std::string& hostname);
    
    /**
     * @brief Clear all pins
     */
    void clearPins();
    
    /**
     * @brief Check if a certificate chain is pinned
     * @param hostname Hostname being connected to
     * @param certChain Certificate chain (DER encoded)
     * @return true if pinned and valid, false otherwise
     */
    [[nodiscard]] bool verify(
        const std::string& hostname,
        const std::vector<ByteBuffer>& certChain
    ) const;
    
    /**
     * @brief Get all pins
     * @return Vector of all registered pins
     */
    [[nodiscard]] const std::vector<CertificatePin>& getPins() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// HTTP Client
// ============================================================================

/**
 * @brief Progress callback for uploads/downloads
 */
using ProgressCallback = std::function<void(size_t current, size_t total)>;

/**
 * @brief HTTPS client with TLS 1.3 and certificate pinning
 * 
 * @example
 * ```cpp
 * HttpClient client;
 * 
 * // Add certificate pins
 * client.addCertificatePin({
 *     .hostname = "api.sentinel.com",
 *     .pins = {sha256OfPublicKey}
 * });
 * 
 * // Make request
 * HttpRequest request;
 * request.url = "https://api.sentinel.com/v1/patches";
 * request.headers["Authorization"] = "Bearer " + apiKey;
 * 
 * auto response = client.send(request);
 * if (response.isSuccess() && response.value().isSuccess()) {
 *     auto json = parseJson(response.value().bodyAsString());
 * }
 * ```
 */
class HttpClient {
public:
    HttpClient();
    ~HttpClient();
    
    // Non-copyable
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;
    
    // Movable
    HttpClient(HttpClient&&) noexcept;
    HttpClient& operator=(HttpClient&&) noexcept;
    
    /**
     * @brief Send HTTP request
     * @param request Request configuration
     * @return Response or error
     */
    Result<HttpResponse> send(const HttpRequest& request);
    
    /**
     * @brief Send GET request
     * @param url Request URL
     * @param headers Optional headers
     * @return Response or error
     */
    Result<HttpResponse> get(
        const std::string& url,
        const HttpHeaders& headers = {}
    );
    
    /**
     * @brief Send POST request
     * @param url Request URL
     * @param body Request body
     * @param headers Optional headers
     * @return Response or error
     */
    Result<HttpResponse> post(
        const std::string& url,
        const ByteBuffer& body,
        const HttpHeaders& headers = {}
    );
    
    /**
     * @brief Send POST request with JSON body
     * @param url Request URL
     * @param json JSON string body
     * @param headers Optional headers
     * @return Response or error
     */
    Result<HttpResponse> postJson(
        const std::string& url,
        const std::string& json,
        const HttpHeaders& headers = {}
    );
    
    /**
     * @brief Download file to buffer
     * @param url File URL
     * @param progress Optional progress callback
     * @return File data or error
     */
    Result<ByteBuffer> download(
        const std::string& url,
        ProgressCallback progress = nullptr
    );
    
    /**
     * @brief Upload file
     * @param url Upload URL
     * @param data File data
     * @param filename Filename for multipart
     * @param progress Optional progress callback
     * @return Response or error
     */
    Result<HttpResponse> upload(
        const std::string& url,
        const ByteBuffer& data,
        const std::string& filename,
        ProgressCallback progress = nullptr
    );
    
    /**
     * @brief Set default headers for all requests
     * @param headers Headers to add to all requests
     */
    void setDefaultHeaders(const HttpHeaders& headers);
    
    /**
     * @brief Add a default header
     * @param name Header name
     * @param value Header value
     */
    void addDefaultHeader(const std::string& name, const std::string& value);
    
    /**
     * @brief Set default timeout
     * @param timeout Timeout duration
     */
    void setDefaultTimeout(Milliseconds timeout);
    
    /**
     * @brief Add certificate pin
     * @param pin Certificate pin entry
     */
    void addCertificatePin(const CertificatePin& pin);
    
    /**
     * @brief Set certificate pinner
     * @param pinner Certificate pinner instance
     */
    void setCertificatePinner(std::shared_ptr<CertPinner> pinner);
    
    /**
     * @brief Enable/disable certificate pinning
     * @param enabled Whether to enable pinning
     */
    void setPinningEnabled(bool enabled);
    
    /**
     * @brief Set proxy server
     * @param proxyUrl Proxy URL (e.g., "http://proxy:8080")
     */
    void setProxy(const std::string& proxyUrl);
    
    /**
     * @brief Clear proxy setting
     */
    void clearProxy();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Request Builder
// ============================================================================

/**
 * @brief Fluent builder for HTTP requests
 * 
 * @example
 * ```cpp
 * auto response = RequestBuilder(client)
 *     .url("https://api.example.com/data")
 *     .method(HttpMethod::POST)
 *     .header("Content-Type", "application/json")
 *     .header("Authorization", "Bearer token")
 *     .body(jsonData)
 *     .timeout(Milliseconds{5000})
 *     .send();
 * ```
 */
class RequestBuilder {
public:
    explicit RequestBuilder(HttpClient& client);
    
    RequestBuilder& url(const std::string& url);
    RequestBuilder& method(HttpMethod method);
    RequestBuilder& header(const std::string& name, const std::string& value);
    RequestBuilder& headers(const HttpHeaders& headers);
    RequestBuilder& body(const ByteBuffer& body);
    RequestBuilder& body(const std::string& body);
    RequestBuilder& jsonBody(const std::string& json);
    RequestBuilder& timeout(Milliseconds timeout);
    RequestBuilder& followRedirects(bool follow);
    RequestBuilder& enablePinning(bool enable);
    
    Result<HttpResponse> send();
    
private:
    HttpClient& m_client;
    HttpRequest m_request;
};

} // namespace Sentinel::Network

#endif // SENTINEL_CORE_HTTP_CLIENT_HPP
