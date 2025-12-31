/**
 * @file RequestSigner.cpp
 * @brief HMAC-SHA256 request signing implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/RequestSigner.hpp>
#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <chrono>
#include <sstream>
#include <algorithm>

namespace Sentinel::Network {

// ============================================================================
// RequestSigner::Impl - Implementation details
// ============================================================================

class RequestSigner::Impl {
public:
    explicit Impl(ByteSpan clientSecret) {
        // Store key securely
        m_key.assign(clientSecret.begin(), clientSecret.end());
    }
    
    ~Impl() {
        // Secure erase key
        Crypto::secureZero(m_key.data(), m_key.size());
    }
    
    Result<RequestSigner::SignedData> sign(
        HttpMethod method,
        const std::string& path,
        ByteSpan body,
        std::optional<int64_t> timestamp
    ) {
        // Use provided timestamp or current time
        int64_t ts = timestamp.value_or(getCurrentTimestamp());
        
        // Build signing string: method + path + timestamp + bodyHash
        auto signingString = buildSigningString(method, path, ts, body);
        if (signingString.isFailure()) {
            return signingString.error();
        }
        
        // Compute HMAC-SHA256
        Crypto::HMAC hmac(ByteSpan(m_key.data(), m_key.size()), 
                         Crypto::HashAlgorithm::SHA256);
        auto macResult = hmac.compute(ByteSpan(
            reinterpret_cast<const Byte*>(signingString.value().data()),
            signingString.value().size()
        ));
        
        if (macResult.isFailure()) {
            return macResult.error();
        }
        
        // Convert to base64
        std::string signature = Crypto::toBase64(ByteSpan(
            macResult.value().data(),
            macResult.value().size()
        ));
        
        return SignedData{signature, ts};
    }
    
    Result<bool> verify(
        HttpMethod method,
        const std::string& path,
        ByteSpan body,
        const std::string& signature,
        int64_t timestamp,
        int maxSkewSeconds
    ) {
        // Check timestamp freshness
        int64_t now = getCurrentTimestamp();
        int64_t skewMs = std::abs(now - timestamp);
        int64_t maxSkewMs = static_cast<int64_t>(maxSkewSeconds) * 1000;
        
        if (skewMs > maxSkewMs) {
            // Timestamp outside acceptable window
            return false;
        }
        
        // Build expected signing string
        auto signingString = buildSigningString(method, path, timestamp, body);
        if (signingString.isFailure()) {
            return signingString.error();
        }
        
        // Compute expected HMAC
        Crypto::HMAC hmac(ByteSpan(m_key.data(), m_key.size()), 
                         Crypto::HashAlgorithm::SHA256);
        auto expectedMacResult = hmac.compute(ByteSpan(
            reinterpret_cast<const Byte*>(signingString.value().data()),
            signingString.value().size()
        ));
        
        if (expectedMacResult.isFailure()) {
            return expectedMacResult.error();
        }
        
        // Decode provided signature from base64
        auto providedMacResult = Crypto::fromBase64(signature);
        if (providedMacResult.isFailure()) {
            return false;  // Invalid base64
        }
        
        // CRITICAL: Use constant-time comparison to prevent timing attacks
        bool valid = Crypto::constantTimeCompare(
            ByteSpan(expectedMacResult.value().data(), expectedMacResult.value().size()),
            ByteSpan(providedMacResult.value().data(), providedMacResult.value().size())
        );
        
        return valid;
    }
    
    void updateKey(ByteSpan newSecret) {
        // Secure erase old key
        Crypto::secureZero(m_key.data(), m_key.size());
        
        // Store new key
        m_key.assign(newSecret.begin(), newSecret.end());
    }
    
    static int64_t getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()
        );
        return ms.count();
    }

private:
    ByteBuffer m_key;
    
    Result<std::string> buildSigningString(
        HttpMethod method,
        const std::string& path,
        int64_t timestamp,
        ByteSpan body
    ) {
        std::ostringstream ss;
        
        // Add HTTP method
        ss << httpMethodToString(method);
        ss << '\n';
        
        // Add path
        ss << path;
        ss << '\n';
        
        // Add timestamp
        ss << timestamp;
        ss << '\n';
        
        // Add body hash (SHA-256 of body)
        Crypto::HashEngine hasher(Crypto::HashAlgorithm::SHA256);
        auto bodyHashResult = hasher.hash(body);
        if (bodyHashResult.isFailure()) {
            return bodyHashResult.error();
        }
        
        // Convert body hash to hex
        std::string bodyHash = Crypto::toHex(ByteSpan(
            bodyHashResult.value().data(),
            bodyHashResult.value().size()
        ));
        ss << bodyHash;
        
        return ss.str();
    }
    
    std::string httpMethodToString(HttpMethod method) {
        switch (method) {
            case HttpMethod::GET:     return "GET";
            case HttpMethod::POST:    return "POST";
            case HttpMethod::PUT:     return "PUT";
            case HttpMethod::PATCH:   return "PATCH";
            case HttpMethod::DELETE_: return "DELETE";
            case HttpMethod::HEAD:    return "HEAD";
            case HttpMethod::OPTIONS: return "OPTIONS";
            default:                  return "UNKNOWN";
        }
    }
};

// ============================================================================
// RequestSigner - Public API
// ============================================================================

RequestSigner::RequestSigner(ByteSpan clientSecret)
    : m_impl(std::make_unique<Impl>(clientSecret)) {
}

RequestSigner::RequestSigner(const std::string& hexSecret) {
    auto secretBytes = Crypto::fromHex(hexSecret);
    if (secretBytes.isFailure()) {
        // Invalid hex string - create with empty key
        // In production, this should throw or return an error
        m_impl = std::make_unique<Impl>(ByteSpan{});
    } else {
        m_impl = std::make_unique<Impl>(ByteSpan(
            secretBytes.value().data(),
            secretBytes.value().size()
        ));
    }
}

RequestSigner::~RequestSigner() = default;

RequestSigner::RequestSigner(RequestSigner&&) noexcept = default;
RequestSigner& RequestSigner::operator=(RequestSigner&&) noexcept = default;

Result<RequestSigner::SignedData> RequestSigner::sign(
    HttpMethod method,
    const std::string& path,
    ByteSpan body,
    std::optional<int64_t> timestamp
) {
    return m_impl->sign(method, path, body, timestamp);
}

Result<bool> RequestSigner::verify(
    HttpMethod method,
    const std::string& path,
    ByteSpan body,
    const std::string& signature,
    int64_t timestamp,
    int maxSkewSeconds
) {
    return m_impl->verify(method, path, body, signature, timestamp, maxSkewSeconds);
}

void RequestSigner::updateKey(ByteSpan newSecret) {
    m_impl->updateKey(newSecret);
}

int64_t RequestSigner::getCurrentTimestamp() {
    return Impl::getCurrentTimestamp();
}

std::string RequestSigner::extractPath(const std::string& url) {
    // Find the start of the path (after protocol and host)
    // URL format: [protocol://][host[:port]]/path[?query][#fragment]
    
    // Skip protocol if present
    size_t pathStart = 0;
    size_t protocolEnd = url.find("://");
    if (protocolEnd != std::string::npos) {
        pathStart = protocolEnd + 3;  // Skip "://"
        
        // Find the first '/' after the host
        size_t slashPos = url.find('/', pathStart);
        if (slashPos != std::string::npos) {
            pathStart = slashPos;
        } else {
            // No path, just host
            return "/";
        }
    } else {
        // No protocol, check if it starts with '/'
        if (!url.empty() && url[0] == '/') {
            pathStart = 0;
        } else {
            // Assume it's just a path
            pathStart = 0;
        }
    }
    
    // Find the end of the path (before query or fragment)
    size_t pathEnd = url.find('?', pathStart);
    if (pathEnd == std::string::npos) {
        pathEnd = url.find('#', pathStart);
    }
    
    if (pathEnd == std::string::npos) {
        pathEnd = url.length();
    }
    
    std::string path = url.substr(pathStart, pathEnd - pathStart);
    
    // Ensure path starts with '/'
    if (path.empty() || path[0] != '/') {
        path = "/" + path;
    }
    
    return path;
}

} // namespace Sentinel::Network
