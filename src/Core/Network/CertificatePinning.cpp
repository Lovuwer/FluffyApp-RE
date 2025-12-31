/**
 * @file CertificatePinning.cpp
 * @brief TLS Certificate Pinning (SPKI) implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/Network.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <map>
#include <mutex>
#include <atomic>
#include <iostream>

namespace Sentinel::Network {

class CertificatePinner::Impl {
public:
    std::map<std::string, PinningConfig> configs_;
    std::mutex mutex_;
};

static std::atomic<CertificatePinner*> g_pinnerInstance{nullptr};

CertificatePinner::CertificatePinner() 
    : m_impl(std::make_unique<Impl>()) {}

CertificatePinner::~CertificatePinner() = default;

void CertificatePinner::setInstance(CertificatePinner* instance) {
    g_pinnerInstance.store(instance, std::memory_order_release);
}

void CertificatePinner::addPins(const PinningConfig& config) {
    std::lock_guard<std::mutex> lock(m_impl->mutex_);
    m_impl->configs_[config.hostname] = config;
}

void CertificatePinner::updatePins(const PinningConfig& config) {
    std::lock_guard<std::mutex> lock(m_impl->mutex_);
    m_impl->configs_[config.hostname] = config;
}

void CertificatePinner::removePins(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(m_impl->mutex_);
    m_impl->configs_.erase(hostname);
}

void CertificatePinner::clearAllPins() {
    std::lock_guard<std::mutex> lock(m_impl->mutex_);
    m_impl->configs_.clear();
}

Result<bool> CertificatePinner::verify(
    const std::string& hostname,
    const std::vector<ByteBuffer>& cert_chain) {
    
    std::lock_guard<std::mutex> lock(m_impl->mutex_);
    
    // Find config for hostname
    auto it = m_impl->configs_.find(hostname);
    if (it == m_impl->configs_.end()) {
        // No pins configured - allow (or could default to reject)
        return true;
    }
    
    const PinningConfig& config = it->second;
    
    if (cert_chain.empty()) {
        std::cerr << "[SECURITY EVENT] Certificate pinning failed for host: " << hostname << std::endl;
        std::cerr << "  Empty certificate chain received" << std::endl;
        std::cerr << "  Connection REJECTED" << std::endl;
        return false;
    }
    
    // Compute SPKI hash of leaf certificate
    auto hashResult = computeSPKIHash(cert_chain[0]);
    if (hashResult.isFailure()) {
        std::cerr << "[SECURITY EVENT] Certificate pinning failed for host: " << hostname << std::endl;
        std::cerr << "  Failed to compute SPKI hash from certificate" << std::endl;
        std::cerr << "  Connection REJECTED" << std::endl;
        return hashResult.error();
    }
    
    const std::string& certHash = hashResult.value();
    
    // Check if any pin matches
    for (const auto& pin : config.pins) {
        if (pin.sha256_hash == certHash) {
            return true;  // Pin matched
        }
    }
    
    // No pin matched - log security event
    std::cerr << "[SECURITY EVENT] Certificate pinning failed for host: " << hostname << std::endl;
    std::cerr << "  Expected one of " << config.pins.size() << " pinned certificate(s)" << std::endl;
    std::cerr << "  Received certificate SPKI hash: " << certHash << std::endl;
    
    for (size_t i = 0; i < config.pins.size(); ++i) {
        std::cerr << "  Pin " << (i + 1) << " (" << config.pins[i].description << "): " 
                  << config.pins[i].sha256_hash << std::endl;
    }
    
    if (config.enforce) {
        std::cerr << "  Connection REJECTED (enforce=true)" << std::endl;
        return false;  // Reject connection
    } else {
        std::cerr << "  Connection ALLOWED (enforce=false - monitoring mode)" << std::endl;
        return true;
    }
}

Result<std::string> computeSPKIHash(ByteSpan cert_der) {
    // Parse DER certificate
    const unsigned char* p = cert_der.data();
    X509* cert = d2i_X509(nullptr, &p, cert_der.size());
    if (!cert) {
        return ErrorCode::CertificateInvalid;
    }
    
    // Extract public key
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) {
        X509_free(cert);
        return ErrorCode::CertificateInvalid;
    }
    
    // Get SPKI in DER format
    int spki_len = i2d_PUBKEY(pkey, nullptr);
    if (spki_len <= 0) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return ErrorCode::CryptoError;
    }
    
    ByteBuffer spki_der(spki_len);
    unsigned char* spki_ptr = spki_der.data();
    i2d_PUBKEY(pkey, &spki_ptr);
    
    EVP_PKEY_free(pkey);
    X509_free(cert);
    
    // Compute SHA-256 hash
    auto hashResult = Crypto::HashEngine::sha256(spki_der);
    if (hashResult.isFailure()) {
        return hashResult.error();
    }
    
    // Encode as Base64
    std::string base64 = Crypto::toBase64(hashResult.value());
    
    return base64;
}

int CertificatePinner::verifyCallback(int preverify_ok, X509_STORE_CTX* ctx) {
    if (!preverify_ok) {
        return 0;  // Standard verification failed
    }
    
    CertificatePinner* pinner = g_pinnerInstance.load(std::memory_order_acquire);
    if (!pinner) {
        return preverify_ok;  // No pinner configured
    }
    
    // Only check at depth 0 (leaf certificate)
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    if (depth != 0) {
        return 1;  // Allow intermediate certs
    }
    
    // Get certificate
    X509* cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert) {
        return 0;
    }
    
    // Convert to DER
    int der_len = i2d_X509(cert, nullptr);
    if (der_len <= 0) {
        return 0;
    }
    
    ByteBuffer cert_der(der_len);
    unsigned char* der_ptr = cert_der.data();
    i2d_X509(cert, &der_ptr);
    
    // Get hostname from SSL context
    SSL* ssl = static_cast<SSL*>(
        X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    if (!ssl) {
        return 0;
    }
    
    const char* hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!hostname) {
        return 1;  // No SNI, can't verify pins
    }
    
    // Verify against pins
    std::vector<ByteBuffer> chain = {cert_der};
    auto result = pinner->verify(hostname, chain);
    
    if (result.isFailure() || !result.value()) {
        return 0;  // Pin verification failed
    }
    
    return 1;  // All checks passed
}

} // namespace Sentinel::Network
