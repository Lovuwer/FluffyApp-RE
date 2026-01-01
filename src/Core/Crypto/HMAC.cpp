/**
 * @file HMAC.cpp
 * @brief HMAC (Hash-based Message Authentication Code) implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Provides message authentication for network packets, integrity tokens,
 * and API request signing with constant-time verification to prevent
 * timing side-channel attacks.
 */

#include <Sentinel/Core/Crypto.hpp>
#include "OpenSSLRAII.hpp"
#include <openssl/evp.h>
#include <openssl/core_names.h>

namespace Sentinel::Crypto {

// ============================================================================
// HMAC::Impl - Implementation details
// ============================================================================

class HMAC::Impl {
public:
    explicit Impl(ByteSpan key, HashAlgorithm algorithm)
        : m_algorithm(algorithm) {
        // Store key securely
        m_key.assign(key.begin(), key.end());
    }
    
    ~Impl() {
        // Secure erase key
        secureZero(m_key.data(), m_key.size());
    }
    
    Result<ByteBuffer> compute(ByteSpan data) {
        EVPMACPtr mac(EVP_MAC_fetch(NULL, "HMAC", NULL));
        if (!mac) {
            return ErrorCode::CryptoError;
        }
        
        EVPMACCtxPtr ctx(EVP_MAC_CTX_new(mac));
        if (!ctx) {
            return ErrorCode::CryptoError;
        }
        
        // Set parameters
        const char* digest_name = getDigestName(m_algorithm);
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(
                OSSL_MAC_PARAM_DIGEST, 
                const_cast<char*>(digest_name), 
                0
            ),
            OSSL_PARAM_construct_end()
        };
        
        // Handle empty key - OpenSSL's EVP_MAC_init requires a non-NULL pointer
        // even when key size is 0. We provide a valid pointer to a dummy byte,
        // but the actual key size (0) is what's used in the computation.
        unsigned char dummy_key = 0;
        const unsigned char* key_ptr = m_key.empty() ? &dummy_key : m_key.data();
        
        if (!EVP_MAC_init(ctx, key_ptr, m_key.size(), params)) {
            return ErrorCode::CryptoError;
        }
        
        if (!EVP_MAC_update(ctx, data.data(), data.size())) {
            return ErrorCode::CryptoError;
        }
        
        size_t mac_size = 0;
        if (!EVP_MAC_final(ctx, NULL, &mac_size, 0)) {
            return ErrorCode::CryptoError;
        }
        
        ByteBuffer result(mac_size);
        if (!EVP_MAC_final(ctx, result.data(), &mac_size, result.size())) {
            return ErrorCode::CryptoError;
        }
        
        return result;
    }
    
    Result<bool> verify(ByteSpan data, ByteSpan expectedMac) {
        auto computedResult = compute(data);
        if (computedResult.isFailure()) {
            return computedResult.error();
        }
        
        ByteBuffer& computed = computedResult.value();
        
        // CRITICAL: Use constant-time comparison
        bool valid = constantTimeCompare(
            ByteSpan(computed.data(), computed.size()),
            expectedMac
        );
        
        // Secure erase computed MAC (defense in depth)
        secureZero(computed.data(), computed.size());
        
        return valid;
    }
    
private: 
    ByteBuffer m_key;
    HashAlgorithm m_algorithm;
    
    const char* getDigestName(HashAlgorithm alg) {
        switch (alg) {
            case HashAlgorithm::SHA256: return "SHA256";
            case HashAlgorithm::SHA384: return "SHA384";
            case HashAlgorithm::SHA512: return "SHA512";
            default:  return "SHA256";
        }
    }
};

// ============================================================================
// HMAC - Public API
// ============================================================================

HMAC::HMAC(ByteSpan key, HashAlgorithm algorithm)
    : m_impl(std::make_unique<Impl>(key, algorithm)) {
}

HMAC::~HMAC() = default;

Result<ByteBuffer> HMAC::compute(ByteSpan data) {
    return m_impl->compute(data);
}

Result<bool> HMAC::verify(ByteSpan data, ByteSpan mac) {
    return m_impl->verify(data, mac);
}

Result<ByteBuffer> HMAC::sha256(ByteSpan key, ByteSpan data) {
    HMAC hmac(key, HashAlgorithm::SHA256);
    return hmac.compute(data);
}

} // namespace Sentinel::Crypto
