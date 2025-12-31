/**
 * @file HttpClientImpl.cpp
 * @brief Production-grade HTTP client implementation using libcurl
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/RequestSigner.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <Sentinel/Core/Network.hpp>
#include <Sentinel/Core/Crypto.hpp>

#ifdef SENTINEL_USE_CURL
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <mutex>
#include <thread>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <iostream>
#endif

namespace Sentinel::Network {

#ifdef SENTINEL_USE_CURL

// Forward declarations for TLS configuration
ErrorCode configureTlsVersion(CURL* curl);
ErrorCode configureTlsVerification(CURL* curl, bool verifyPeer, bool verifyHost);

// ============================================================================
// Global cURL initialization
// ============================================================================

namespace {
    std::once_flag g_curlInitFlag;
    bool g_curlInitialized = false;
    
    void initializeCurl() {
        std::call_once(g_curlInitFlag, []() {
            CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
            g_curlInitialized = (res == CURLE_OK);
        });
    }
    
    // Note: curl_global_cleanup() is intentionally not called
    // It's not thread-safe and cleanup happens automatically at process exit
}

// ============================================================================
// cURL callbacks
// ============================================================================

namespace {
    // Callback for writing response body
    size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t realsize = size * nmemb;
        auto* buffer = static_cast<ByteBuffer*>(userp);
        
        try {
            const Byte* data = static_cast<const Byte*>(contents);
            buffer->insert(buffer->end(), data, data + realsize);
            return realsize;
        } catch (...) {
            return 0; // Error occurred
        }
    }
    
    // Callback for reading request body
    size_t readCallback(char* buffer, size_t size, size_t nmemb, void* userp) {
        size_t maxBytes = size * nmemb;
        auto* data = static_cast<std::pair<const ByteBuffer*, size_t>*>(userp);
        
        const ByteBuffer& body = *data->first;
        size_t& offset = data->second;
        
        size_t remaining = body.size() - offset;
        size_t toRead = std::min(maxBytes, remaining);
        
        if (toRead > 0) {
            std::memcpy(buffer, body.data() + offset, toRead);
            offset += toRead;
        }
        
        return toRead;
    }
    
    // Callback for writing response headers
    size_t headerCallback(char* buffer, size_t size, size_t nmemb, void* userp) {
        size_t realsize = size * nmemb;
        auto* headers = static_cast<HttpHeaders*>(userp);
        
        std::string header(buffer, realsize);
        
        // Parse header (format: "Name: Value\r\n")
        size_t colonPos = header.find(':');
        if (colonPos != std::string::npos && colonPos > 0) {
            std::string name = header.substr(0, colonPos);
            std::string value = header.substr(colonPos + 1);
            
            // Trim whitespace
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t\r\n") + 1);
            
            // Convert name to lowercase for case-insensitive lookup
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            
            (*headers)[name] = value;
        }
        
        return realsize;
    }
    
    // SSL context callback for certificate pinning
    CURLcode sslContextCallback(CURL* curl, void* sslctx, void* userdata) {
        (void)curl; // Unused
        
        auto* pinner = static_cast<CertificatePinner*>(userdata);
        if (!pinner) {
            return CURLE_OK; // No pinner configured
        }
        
        SSL_CTX* ctx = static_cast<SSL_CTX*>(sslctx);
        
        // Set the pinner instance for callback use
        CertificatePinner::setInstance(pinner);
        
        // Set up the certificate verification callback
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, CertificatePinner::verifyCallback);
        
        return CURLE_OK;
    }
}

// ============================================================================
// HttpClient::Impl
// ============================================================================

class HttpClient::Impl {
public:
    Impl() {
        initializeCurl();
    }
    
    ~Impl() = default;
    
    Result<HttpResponse> send(const HttpRequest& request) {
        if (!g_curlInitialized) {
            return ErrorCode::CurlInitFailed;
        }
        
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Create a mutable copy of the request to add signature headers
        HttpRequest signedRequest = request;
        
        // Add signature headers if signer is configured
        if (m_requestSigner) {
            // Extract path from URL
            std::string path = RequestSigner::extractPath(request.url);
            
            // Sign the request
            auto signResult = m_requestSigner->sign(
                request.method,
                path,
                ByteSpan(request.body.data(), request.body.size())
            );
            
            if (signResult.isSuccess()) {
                const auto& signedData = signResult.value();
                signedRequest.headers["X-Signature"] = signedData.signature;
                signedRequest.headers["X-Timestamp"] = std::to_string(signedData.timestamp);
            }
            // If signing fails, proceed without signature (could also return error)
        }
        
        // Create cURL handle
        CURL* curl = curl_easy_init();
        if (!curl) {
            return ErrorCode::CurlInitFailed;
        }
        
        // RAII wrapper for cURL handle
        struct CurlGuard {
            CURL* handle;
            ~CurlGuard() { if (handle) curl_easy_cleanup(handle); }
        } guard{curl};
        
        // Configure TLS
        ErrorCode tlsResult = configureTlsVersion(curl);
        if (tlsResult != ErrorCode::Success) {
            return tlsResult;
        }
        
        configureTlsVerification(curl, true, true);
        
        // Configure certificate pinning if enabled
        if (signedRequest.enablePinning && m_pinningEnabled && m_certificatePinner) {
            curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslContextCallback);
            curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, m_certificatePinner.get());
        }
        
        // Set URL
        curl_easy_setopt(curl, CURLOPT_URL, signedRequest.url.c_str());
        
        // Set method
        switch (signedRequest.method) {
            case HttpMethod::GET:
                curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
                break;
            case HttpMethod::POST:
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                break;
            case HttpMethod::PUT:
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                break;
            case HttpMethod::PATCH:
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
                break;
            case HttpMethod::DELETE_:
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
                break;
            case HttpMethod::HEAD:
                curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
                break;
            case HttpMethod::OPTIONS:
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");
                break;
        }
        
        // Set headers
        struct curl_slist* headerList = nullptr;
        auto allHeaders = m_defaultHeaders;
        allHeaders.insert(signedRequest.headers.begin(), signedRequest.headers.end());
        
        for (const auto& [name, value] : allHeaders) {
            std::string header = name + ": " + value;
            headerList = curl_slist_append(headerList, header.c_str());
        }
        
        if (headerList) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
        }
        
        // Set body for POST/PUT/PATCH
        std::pair<const ByteBuffer*, size_t> readData{&signedRequest.body, 0};
        if ((signedRequest.method == HttpMethod::POST || 
             signedRequest.method == HttpMethod::PUT || 
             signedRequest.method == HttpMethod::PATCH) && !signedRequest.body.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(signedRequest.body.size()));
            curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCallback);
            curl_easy_setopt(curl, CURLOPT_READDATA, &readData);
        }
        
        // Set timeouts (in milliseconds)
        // Use the request timeout for both connection and total
        long timeoutMs = signedRequest.timeout.count();
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeoutMs);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMs);
        
        // Set follow redirects
        if (signedRequest.followRedirects) {
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_MAXREDIRS, static_cast<long>(signedRequest.maxRedirects));
        }
        
        // Set user agent
        curl_easy_setopt(curl, CURLOPT_USERAGENT, signedRequest.userAgent.c_str());
        
        // Prepare response
        HttpResponse response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
        
        // Perform request with retry logic for transient network errors
        CURLcode res = CURLE_OK;
        int maxRetries = 3;
        int retryDelay = 1000; // 1 second initial delay
        
        auto startTime = Clock::now();
        
        for (int attempt = 0; attempt < maxRetries; ++attempt) {
            res = curl_easy_perform(curl);
            
            // Break on success
            if (res == CURLE_OK) {
                break;
            }
            
            // Check if error is transient (but not timeout - don't retry timeouts)
            bool isTransient = (res == CURLE_COULDNT_CONNECT ||
                              res == CURLE_RECV_ERROR ||
                              res == CURLE_SEND_ERROR ||
                              res == CURLE_PARTIAL_FILE ||
                              res == CURLE_GOT_NOTHING);
            
            // Don't retry on non-transient errors or timeouts
            if (!isTransient || attempt == maxRetries - 1) {
                break;
            }
            
            // Exponential backoff
            std::this_thread::sleep_for(Milliseconds(retryDelay));
            retryDelay *= 2;
        }
        
        auto endTime = Clock::now();
        response.elapsed = std::chrono::duration_cast<Milliseconds>(endTime - startTime);
        
        // Clean up header list
        if (headerList) {
            curl_slist_free_all(headerList);
        }
        
        // Check for errors
        if (res != CURLE_OK) {
            // Map cURL error to Sentinel error code
            switch (res) {
                case CURLE_COULDNT_RESOLVE_HOST:
                    return ErrorCode::DnsResolutionFailed;
                case CURLE_COULDNT_CONNECT:
                    return ErrorCode::ConnectionFailed;
                case CURLE_OPERATION_TIMEDOUT:
                    return ErrorCode::Timeout;
                case CURLE_SSL_CONNECT_ERROR:
                case CURLE_SSL_CERTPROBLEM:
                case CURLE_SSL_CIPHER:
                    return ErrorCode::TlsHandshakeFailed;
                case CURLE_PEER_FAILED_VERIFICATION:
                    return ErrorCode::CertificateInvalid;
                default:
                    return ErrorCode::NetworkError;
            }
        }
        
        // Get response code
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        response.statusCode = static_cast<int>(httpCode);
        
        return response;
    }
    
    void setDefaultHeaders(const HttpHeaders& headers) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_defaultHeaders = headers;
    }
    
    void addDefaultHeader(const std::string& name, const std::string& value) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_defaultHeaders[name] = value;
    }
    
    void setDefaultTimeout(Milliseconds timeout) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_defaultTimeout = timeout;
    }
    
    Milliseconds getDefaultTimeout() const {
        return m_defaultTimeout;
    }
    
    void setRequestSigner(std::shared_ptr<RequestSigner> signer) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_requestSigner = std::move(signer);
    }
    
    void clearRequestSigner() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_requestSigner.reset();
    }
    
    void setCertificatePinner(std::shared_ptr<CertificatePinner> pinner) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_certificatePinner = std::move(pinner);
    }
    
    void setPinningEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pinningEnabled = enabled;
    }
    
    std::shared_ptr<CertificatePinner> getCertificatePinner() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_certificatePinner;
    }
    
private:
    mutable std::mutex m_mutex;
    HttpHeaders m_defaultHeaders;
    Milliseconds m_defaultTimeout{30000};
    std::shared_ptr<RequestSigner> m_requestSigner;
    std::shared_ptr<CertificatePinner> m_certificatePinner;
    bool m_pinningEnabled{true};
};

#else // !SENTINEL_USE_CURL

// Stub implementation when cURL is not available
class HttpClient::Impl {
public:
    Result<HttpResponse> send(const HttpRequest&) {
        return ErrorCode::NotImplemented;
    }
    
    void setDefaultHeaders(const HttpHeaders&) {}
    void addDefaultHeader(const std::string&, const std::string&) {}
    void setDefaultTimeout(Milliseconds) {}
    Milliseconds getDefaultTimeout() const { return Milliseconds{30000}; }
    void setRequestSigner(std::shared_ptr<RequestSigner>) {}
    void clearRequestSigner() {}
    void setCertificatePinner(std::shared_ptr<CertificatePinner>) {}
    void setPinningEnabled(bool) {}
    std::shared_ptr<CertificatePinner> getCertificatePinner() const { return nullptr; }
};

#endif // SENTINEL_USE_CURL

// ============================================================================
// HttpClient public interface
// ============================================================================

HttpClient::HttpClient() : m_impl(std::make_unique<Impl>()) {}

HttpClient::~HttpClient() = default;

HttpClient::HttpClient(HttpClient&&) noexcept = default;
HttpClient& HttpClient::operator=(HttpClient&&) noexcept = default;

Result<HttpResponse> HttpClient::send(const HttpRequest& request) {
    return m_impl->send(request);
}

Result<HttpResponse> HttpClient::get(const std::string& url, const HttpHeaders& headers) {
    HttpRequest request;
    request.method = HttpMethod::GET;
    request.url = url;
    request.headers = headers;
    request.timeout = m_impl->getDefaultTimeout();
    return send(request);
}

Result<HttpResponse> HttpClient::post(
    const std::string& url,
    const ByteBuffer& body,
    const HttpHeaders& headers
) {
    HttpRequest request;
    request.method = HttpMethod::POST;
    request.url = url;
    request.body = body;
    request.headers = headers;
    request.timeout = m_impl->getDefaultTimeout();
    return send(request);
}

Result<HttpResponse> HttpClient::postJson(
    const std::string& url,
    const std::string& json,
    const HttpHeaders& headers
) {
    ByteBuffer body(json.begin(), json.end());
    auto allHeaders = headers;
    allHeaders["Content-Type"] = "application/json";
    return post(url, body, allHeaders);
}

Result<ByteBuffer> HttpClient::download(
    const std::string& url,
    [[maybe_unused]] ProgressCallback progress
) {
    auto response = get(url);
    if (!response.isSuccess()) {
        return response.error();
    }
    
    if (!response.value().isSuccess()) {
        return ErrorCode::HttpRequestFailed;
    }
    
    return response.value().body;
}

Result<HttpResponse> HttpClient::upload(
    const std::string& url,
    const ByteBuffer& data,
    [[maybe_unused]] const std::string& filename,
    [[maybe_unused]] ProgressCallback progress
) {
    // Simple implementation - for multipart/form-data, more work needed
    return post(url, data);
}

void HttpClient::setDefaultHeaders(const HttpHeaders& headers) {
    m_impl->setDefaultHeaders(headers);
}

void HttpClient::addDefaultHeader(const std::string& name, const std::string& value) {
    m_impl->addDefaultHeader(name, value);
}

void HttpClient::setDefaultTimeout(Milliseconds timeout) {
    m_impl->setDefaultTimeout(timeout);
}

void HttpClient::addCertificatePin(const CertificatePin& pin) {
    // Convert CertificatePin to PinningConfig and add to internal pinner
    auto pinner = m_impl->getCertificatePinner();
    if (!pinner) {
        pinner = std::make_shared<CertificatePinner>();
        m_impl->setCertificatePinner(pinner);
    }
    
    // Convert CertificatePin to PinningConfig format
    PinningConfig config;
    config.hostname = pin.hostname;
    config.enforce = true;
    
    // Convert SHA256Hash to base64 strings
    for (const auto& hash : pin.pins) {
        std::string base64Hash = Crypto::toBase64(hash);
        config.pins.push_back({base64Hash, "Pin"});
    }
    
    pinner->addPins(config);
}

void HttpClient::setCertificatePinner(std::shared_ptr<CertPinner> pinner) {
    // Create an internal CertificatePinner from CertPinner
    auto internalPinner = std::make_shared<CertificatePinner>();
    
    if (pinner) {
        // Convert all pins from CertPinner to CertificatePinner
        for (const auto& pin : pinner->getPins()) {
            PinningConfig config;
            config.hostname = pin.hostname;
            config.enforce = true;
            
            for (const auto& hash : pin.pins) {
                std::string base64Hash = Crypto::toBase64(hash);
                config.pins.push_back({base64Hash, "Pin"});
            }
            
            internalPinner->addPins(config);
        }
    }
    
    m_impl->setCertificatePinner(internalPinner);
}

void HttpClient::setPinningEnabled(bool enabled) {
    m_impl->setPinningEnabled(enabled);
}

void HttpClient::setProxy([[maybe_unused]] const std::string& proxyUrl) {
    // TODO: Implement proxy support
}

void HttpClient::clearProxy() {
    // TODO: Implement proxy support
}

void HttpClient::setRequestSigner(std::shared_ptr<RequestSigner> signer) {
    m_impl->setRequestSigner(std::move(signer));
}

void HttpClient::clearRequestSigner() {
    m_impl->clearRequestSigner();
}

// ============================================================================
// HttpResponse helper methods
// ============================================================================

std::string HttpResponse::getHeader(const std::string& name) const {
    // Convert to lowercase for case-insensitive lookup
    std::string lowerName = name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    
    auto it = headers.find(lowerName);
    if (it != headers.end()) {
        return it->second;
    }
    return "";
}

// ============================================================================
// RequestBuilder
// ============================================================================

RequestBuilder::RequestBuilder(HttpClient& client) 
    : m_client(client) {}

RequestBuilder& RequestBuilder::url(const std::string& url) {
    m_request.url = url;
    return *this;
}

RequestBuilder& RequestBuilder::method(HttpMethod method) {
    m_request.method = method;
    return *this;
}

RequestBuilder& RequestBuilder::header(const std::string& name, const std::string& value) {
    m_request.headers[name] = value;
    return *this;
}

RequestBuilder& RequestBuilder::headers(const HttpHeaders& headers) {
    m_request.headers = headers;
    return *this;
}

RequestBuilder& RequestBuilder::body(const ByteBuffer& body) {
    m_request.body = body;
    return *this;
}

RequestBuilder& RequestBuilder::body(const std::string& body) {
    m_request.body = ByteBuffer(body.begin(), body.end());
    return *this;
}

RequestBuilder& RequestBuilder::jsonBody(const std::string& json) {
    m_request.body = ByteBuffer(json.begin(), json.end());
    m_request.headers["Content-Type"] = "application/json";
    return *this;
}

RequestBuilder& RequestBuilder::timeout(Milliseconds timeout) {
    m_request.timeout = timeout;
    return *this;
}

RequestBuilder& RequestBuilder::followRedirects(bool follow) {
    m_request.followRedirects = follow;
    return *this;
}

RequestBuilder& RequestBuilder::enablePinning(bool enable) {
    m_request.enablePinning = enable;
    return *this;
}

Result<HttpResponse> RequestBuilder::send() {
    return m_client.send(m_request);
}

} // namespace Sentinel::Network
