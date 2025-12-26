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
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

namespace Sentinel::Crypto {

// ============================================================================
// HMAC::Impl - Implementation details
// ============================================================================

class HMAC::Impl {
public:
    explicit Impl(ByteSpan key, HashAlgorithm algorithm)
        : m_key(key.begin(), key.end())
        , m_algorithm(algorithm) {
        
        // Select the appropriate EVP_MD based on algorithm
        switch (algorithm) {
            case HashAlgorithm::SHA256:
                m_evp_md = EVP_sha256();
                break;
            case HashAlgorithm::SHA384:
                m_evp_md = EVP_sha384();
                break;
            case HashAlgorithm::SHA512:
                m_evp_md = EVP_sha512();
                break;
            case HashAlgorithm::MD5:
                m_evp_md = EVP_md5();
                break;
            default:
                m_evp_md = EVP_sha256(); // Default to SHA256
                break;
        }
    }
    
    Result<ByteBuffer> compute(ByteSpan data) {
        // Validate key size is reasonable
        // HMAC allows any key size, but keys larger than the hash block size
        // are hashed anyway. Practical maximum is 2048 bytes (more than enough).
        constexpr size_t MAX_REASONABLE_KEY_SIZE = 2048;
        if (m_key.size() > MAX_REASONABLE_KEY_SIZE) {
            return ErrorCode::InvalidKey;
        }
        
        // Also ensure the key size fits in int for OpenSSL API
        if (m_key.size() > INT_MAX) {
            return ErrorCode::InvalidKey;
        }
        
        unsigned int len = 0;
        ByteBuffer result(EVP_MAX_MD_SIZE);
        
        unsigned char* hmac_result = ::HMAC(
            m_evp_md,
            m_key.data(),
            static_cast<int>(m_key.size()),
            data.data(),
            data.size(),
            result.data(),
            &len
        );
        
        if (hmac_result == nullptr) {
            return ErrorCode::CryptoError;
        }
        
        result.resize(len);
        return result;
    }
    
    Result<bool> verify(ByteSpan data, ByteSpan mac) {
        auto computed = compute(data);
        if (computed.isFailure()) {
            return computed.error();
        }
        
        return constantTimeCompare(computed.value(), mac);
    }
    
private:
    ByteBuffer m_key;
    HashAlgorithm m_algorithm;
    const EVP_MD* m_evp_md;
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
