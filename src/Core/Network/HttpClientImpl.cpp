/**
 * @file HttpClientImpl.cpp
 * @brief Production-grade HTTP client implementation
 * @author Sentinel Security Team
 * @version 1.1.0 - Added WinHTTP fallback
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/RequestSigner.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <Sentinel/Core/Network.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <Sentinel/Core/Logger.hpp>

#ifdef SENTINEL_USE_CURL
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <mutex>
#include <thread>
#include <chrono>
#include <cstring>
#include <algorithm>
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
// Helper Functions
// ============================================================================

namespace {
    const char* httpMethodToString(HttpMethod method) {
        switch (method) {
            case HttpMethod::GET:      return "GET";
            case HttpMethod::POST:     return "POST";
            case HttpMethod::PUT:      return "PUT";
            case HttpMethod::PATCH:    return "PATCH";
            case HttpMethod::DELETE_:  return "DELETE";
            case HttpMethod::HEAD:     return "HEAD";
            case HttpMethod::OPTIONS:  return "OPTIONS";
            default:                   return "UNKNOWN";
        }
    }
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
            SENTINEL_LOG_ERROR("cURL library not initialized");
            return ErrorCode::CurlInitFailed;
        }
        
        SENTINEL_LOG_DEBUG_F("HTTP %s request to: %s", 
                            httpMethodToString(request.method), 
                            request.url.c_str());
        
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
                SENTINEL_LOG_DEBUG("Request signed successfully");
            } else {
                SENTINEL_LOG_WARNING("Request signing failed, proceeding without signature");
            }
            // If signing fails, proceed without signature (could also return error)
        }
        
        // Create cURL handle
        CURL* curl = curl_easy_init();
        if (!curl) {
            SENTINEL_LOG_ERROR("Failed to create cURL handle");
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
            CURLcode res1 = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslContextCallback);
            CURLcode res2 = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, m_certificatePinner.get());
            
            if (res1 != CURLE_OK || res2 != CURLE_OK) {
                SENTINEL_LOG_WARNING("Failed to configure SSL context callback for certificate pinning");
                // Continue anyway - standard TLS verification will still occur
            } else {
                SENTINEL_LOG_DEBUG("Certificate pinning enabled for request");
            }
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
                if (attempt > 0) {
                    SENTINEL_LOG_INFO_F("Request succeeded after %d retries", attempt);
                }
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
                if (attempt > 0) {
                    SENTINEL_LOG_ERROR_F("Request failed after %d retries: %s", 
                                        attempt + 1, curl_easy_strerror(res));
                }
                break;
            }
            
            SENTINEL_LOG_WARNING_F("Transient error on attempt %d: %s - retrying", 
                                  attempt + 1, curl_easy_strerror(res));
            
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
            SENTINEL_LOG_ERROR_F("HTTP request failed: %s", curl_easy_strerror(res));
            
            // Map cURL error to Sentinel error code
            switch (res) {
                case CURLE_COULDNT_RESOLVE_HOST:
                    SENTINEL_LOG_ERROR("DNS resolution failed");
                    return ErrorCode::DnsResolutionFailed;
                case CURLE_COULDNT_CONNECT:
                    SENTINEL_LOG_ERROR("Connection failed");
                    return ErrorCode::ConnectionFailed;
                case CURLE_OPERATION_TIMEDOUT:
                    SENTINEL_LOG_ERROR("Request timeout");
                    return ErrorCode::Timeout;
                case CURLE_SSL_CONNECT_ERROR:
                case CURLE_SSL_CERTPROBLEM:
                case CURLE_SSL_CIPHER:
                    SENTINEL_LOG_ERROR("TLS handshake failed");
                    return ErrorCode::TlsHandshakeFailed;
                case CURLE_PEER_FAILED_VERIFICATION:
                    SENTINEL_LOG_ERROR("Certificate verification failed");
                    return ErrorCode::CertificateInvalid;
                default:
                    SENTINEL_LOG_ERROR("Network error");
                    return ErrorCode::NetworkError;
            }
        }
        
        // Get response code
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        response.statusCode = static_cast<int>(httpCode);
        
        SENTINEL_LOG_DEBUG_F("HTTP response: %d (%.0fms)", 
                            response.statusCode, 
                            static_cast<double>(response.elapsed.count()));
        
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

#elif defined(_WIN32)
// ============================================================================
// WinHTTP Implementation (Windows fallback when cURL is not available)
// ============================================================================

#include <windows.h>
#include <winhttp.h>
#include <mutex>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")

namespace {
    // RAII wrapper for WinHTTP session handle
    class WinHttpSession {
    public:
        WinHttpSession() : m_session(nullptr) {
            m_session = WinHttpOpen(
                L"Sentinel-SDK/1.0",
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0
            );
            
            if (m_session) {
                // Enforce TLS 1.2+ only
                DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | 
                                  WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
                WinHttpSetOption(m_session, WINHTTP_OPTION_SECURE_PROTOCOLS, 
                                 &protocols, sizeof(protocols));
            }
        }
        
        ~WinHttpSession() {
            if (m_session) {
                WinHttpCloseHandle(m_session);
            }
        }
        
        HINTERNET get() const { return m_session; }
        bool isValid() const { return m_session != nullptr; }
        
    private:
        HINTERNET m_session;
    };
    
    // RAII wrapper for WinHTTP connection handle
    class WinHttpConnection {
    public:
        WinHttpConnection(HINTERNET session, const std::wstring& host, INTERNET_PORT port)
            : m_connection(nullptr) {
            if (session) {
                m_connection = WinHttpConnect(session, host.c_str(), port, 0);
            }
        }
        
        ~WinHttpConnection() {
            if (m_connection) {
                WinHttpCloseHandle(m_connection);
            }
        }
        
        HINTERNET get() const { return m_connection; }
        bool isValid() const { return m_connection != nullptr; }
        
    private:
        HINTERNET m_connection;
    };
    
    // RAII wrapper for WinHTTP request handle
    class WinHttpRequest {
    public:
        WinHttpRequest(HINTERNET connection, const std::wstring& verb, 
                       const std::wstring& path, bool secure)
            : m_request(nullptr) {
            if (connection) {
                DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
                m_request = WinHttpOpenRequest(
                    connection, 
                    verb.c_str(), 
                    path.c_str(),
                    nullptr,  // HTTP/1.1
                    WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                    flags
                );
            }
        }
        
        ~WinHttpRequest() {
            if (m_request) {
                WinHttpCloseHandle(m_request);
            }
        }
        
        HINTERNET get() const { return m_request; }
        bool isValid() const { return m_request != nullptr; }
        
    private:
        HINTERNET m_request;
    };
    
    // Parse URL into components
    struct UrlComponents {
        std::wstring host;
        std::wstring path;
        INTERNET_PORT port;
        bool secure;
    };
    
    bool parseUrl(const std::string& url, UrlComponents& out) {
        // Convert to wide string using proper Windows API
        int wideLength = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
        if (wideLength <= 0) {
            return false;
        }
        
        std::wstring wurl(wideLength - 1, L'\0');  // -1 to exclude null terminator
        if (MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, &wurl[0], wideLength) == 0) {
            return false;
        }
        
        URL_COMPONENTS components = {};
        components.dwStructSize = sizeof(components);
        
        // Use dynamic buffers with larger sizes
        std::vector<wchar_t> hostBuffer(1024);
        std::vector<wchar_t> pathBuffer(4096);
        
        components.lpszHostName = hostBuffer.data();
        components.dwHostNameLength = static_cast<DWORD>(hostBuffer.size());
        components.lpszUrlPath = pathBuffer.data();
        components.dwUrlPathLength = static_cast<DWORD>(pathBuffer.size());
        
        if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &components)) {
            return false;
        }
        
        out.host = components.lpszHostName;
        out.path = components.lpszUrlPath[0] ? components.lpszUrlPath : L"/";
        out.port = components.nPort;
        out.secure = (components.nScheme == INTERNET_SCHEME_HTTPS);
        
        return true;
    }
    
    std::wstring httpMethodToWString(HttpMethod method) {
        switch (method) {
            case HttpMethod::GET:      return L"GET";
            case HttpMethod::POST:     return L"POST";
            case HttpMethod::PUT:      return L"PUT";
            case HttpMethod::PATCH:    return L"PATCH";
            case HttpMethod::DELETE_:  return L"DELETE";
            case HttpMethod::HEAD:     return L"HEAD";
            case HttpMethod::OPTIONS:  return L"OPTIONS";
            default:                   return L"GET";
        }
    }
}

// ============================================================================
// HttpClient::Impl (WinHTTP)
// ============================================================================

class HttpClient::Impl {
public: 
    Impl() : m_pinningEnabled(true) {
        // Session is lazily initialized on first request
    }
    
    ~Impl() = default;
    
    Result<HttpResponse> send(const HttpRequest& request) {
        // Ensure session is initialized
        if (!m_session.isValid()) {
            m_session = WinHttpSession();
            if (!m_session.isValid()) {
                SENTINEL_LOG_ERROR("Failed to initialize WinHTTP session");
                return ErrorCode::NetworkError;
            }
        }
        
        // Parse URL
        UrlComponents urlParts;
        if (!parseUrl(request.url, urlParts)) {
            SENTINEL_LOG_ERROR("Failed to parse URL");
            return ErrorCode::InvalidArgument;
        }
        
        // Create connection
        WinHttpConnection connection(m_session.get(), urlParts.host, urlParts.port);
        if (!connection.isValid()) {
            SENTINEL_LOG_ERROR("Failed to connect to host");
            return ErrorCode::ConnectionFailed;
        }
        
        // Create request
        std::wstring verb = httpMethodToWString(request.method);
        WinHttpRequest httpRequest(connection.get(), verb, urlParts.path, urlParts.secure);
        if (!httpRequest.isValid()) {
            SENTINEL_LOG_ERROR("Failed to create HTTP request");
            return ErrorCode::NetworkError;
        }
        
        // Set timeouts
        DWORD timeout = static_cast<DWORD>(request.timeout.count());
        if (!WinHttpSetOption(httpRequest.get(), WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout))) {
            SENTINEL_LOG_WARNING("Failed to set connect timeout");
        }
        if (!WinHttpSetOption(httpRequest.get(), WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout))) {
            SENTINEL_LOG_WARNING("Failed to set send timeout");
        }
        if (!WinHttpSetOption(httpRequest.get(), WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout))) {
            SENTINEL_LOG_WARNING("Failed to set receive timeout");
        }
        
        // Build headers string
        std::wostringstream headerStream;
        auto allHeaders = m_defaultHeaders;
        allHeaders.insert(request.headers.begin(), request.headers.end());
        
        for (const auto& [name, value] : allHeaders) {
            // Proper UTF-8 to UTF-16 conversion
            int nameLen = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, nullptr, 0);
            int valueLen = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
            
            if (nameLen > 0 && valueLen > 0) {
                std::wstring wname(nameLen - 1, L'\0');
                std::wstring wvalue(valueLen - 1, L'\0');
                
                if (MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, &wname[0], nameLen) > 0 &&
                    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &wvalue[0], valueLen) > 0) {
                    headerStream << wname << L": " << wvalue << L"\r\n";
                }
            }
        }
        std::wstring headers = headerStream.str();
        
        // Add headers
        if (!headers.empty()) {
            if (!WinHttpAddRequestHeaders(httpRequest.get(), headers.c_str(), 
                                          static_cast<DWORD>(headers.length()),
                                          WINHTTP_ADDREQ_FLAG_ADD)) {
                SENTINEL_LOG_WARNING("Failed to add request headers");
            }
        }
        
        // Send request
        auto startTime = Clock::now();
        
        LPVOID bodyPtr = request.body.empty() ? WINHTTP_NO_REQUEST_DATA 
                                              : const_cast<Byte*>(request.body.data());
        DWORD bodyLen = static_cast<DWORD>(request.body.size());
        
        if (!WinHttpSendRequest(httpRequest.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                bodyPtr, bodyLen, bodyLen, 0)) {
            DWORD error = GetLastError();
            SENTINEL_LOG_ERROR_F("WinHttpSendRequest failed: %lu", error);
            return ErrorCode::NetworkError;
        }
        
        // Receive response
        if (!WinHttpReceiveResponse(httpRequest.get(), nullptr)) {
            DWORD error = GetLastError();
            if (error == ERROR_WINHTTP_TIMEOUT) {
                return ErrorCode::Timeout;
            }
            SENTINEL_LOG_ERROR_F("WinHttpReceiveResponse failed: %lu", error);
            return ErrorCode::NetworkError;
        }
        
        // Get status code
        HttpResponse response;
        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(httpRequest.get(), 
                           WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX,
                           &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);
        response.statusCode = static_cast<int>(statusCode);
        
        // Read response body
        DWORD bytesAvailable = 0;
        do {
            bytesAvailable = 0;
            if (!WinHttpQueryDataAvailable(httpRequest.get(), &bytesAvailable)) {
                break;
            }
            
            if (bytesAvailable > 0) {
                std::vector<Byte> buffer(bytesAvailable);
                DWORD bytesRead = 0;
                
                if (WinHttpReadData(httpRequest.get(), buffer.data(), 
                                    bytesAvailable, &bytesRead)) {
                    response.body.insert(response.body.end(), 
                                        buffer.begin(), buffer.begin() + bytesRead);
                }
            }
        } while (bytesAvailable > 0);
        
        auto endTime = Clock::now();
        response.elapsed = std::chrono::duration_cast<Milliseconds>(endTime - startTime);
        
        SENTINEL_LOG_DEBUG_F("HTTP response: %d (%.0fms)", 
                            response.statusCode, 
                            static_cast<double>(response.elapsed.count()));
        
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
    WinHttpSession m_session;
    HttpHeaders m_defaultHeaders;
    Milliseconds m_defaultTimeout{30000};
    std::shared_ptr<RequestSigner> m_requestSigner;
    std::shared_ptr<CertificatePinner> m_certificatePinner;
    bool m_pinningEnabled;
};

#else // !SENTINEL_USE_CURL && !_WIN32

// ============================================================================
// Stub implementation for non-Windows platforms without cURL
// ============================================================================

class HttpClient::Impl {
public:
    Result<HttpResponse> send(const HttpRequest&) {
        SENTINEL_LOG_ERROR("HTTP client not available: Build with SENTINEL_USE_CURL or on Windows");
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

#endif // Platform selection

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
