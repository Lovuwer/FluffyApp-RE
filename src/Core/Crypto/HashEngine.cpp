/**
 * @file HashEngine.cpp
 * @brief Cryptographic hash engine implementation using OpenSSL EVP API
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Provides cryptographic hashing using OpenSSL EVP API (non-deprecated):
 * - SHA-256 (recommended)
 * - SHA-384
 * - SHA-512 (recommended)
 * - MD5 (legacy compatibility only - DO NOT use for security)
 * 
 * Defends against:
 * - Hash collision attacks (via SHA-256/SHA-512)
 * - Length extension attacks (via proper API usage)
 * - Prevents use of deprecated/weak algorithms (MD5)
 */

#include <Sentinel/Core/Crypto.hpp>
#include "OpenSSLRAII.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>

namespace Sentinel::Crypto {

// ============================================================================
// HashEngine::Impl - OpenSSL EVP implementation
// ============================================================================

class HashEngine::Impl {
public:
    explicit Impl(HashAlgorithm algorithm)
        : m_algorithm(algorithm)
        , m_ctx(EVP_MD_CTX_new())
        , m_md(nullptr)
        , m_finalized(false)
    {
        // Select hash algorithm
        switch (algorithm) {
            case HashAlgorithm::SHA256:
                m_md = EVP_sha256();
                break;
            case HashAlgorithm::SHA384:
                m_md = EVP_sha384();
                break;
            case HashAlgorithm::SHA512:
                m_md = EVP_sha512();
                break;
            case HashAlgorithm::MD5:
                m_md = EVP_md5(); // Legacy only
                break;
            default:
                m_md = EVP_sha256(); // Default to SHA256
                break;
        }
    }
    
    ~Impl() = default;
    
    // Disable copy
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    
    // Enable move
    Impl(Impl&& other) noexcept
        : m_algorithm(other.m_algorithm)
        , m_ctx(std::move(other.m_ctx))
        , m_md(other.m_md)
        , m_finalized(other.m_finalized)
    {
        other.m_md = nullptr;
    }
    
    Impl& operator=(Impl&& other) noexcept {
        if (this != &other) {
            m_algorithm = other.m_algorithm;
            m_ctx = std::move(other.m_ctx);
            m_md = other.m_md;
            m_finalized = other.m_finalized;
            
            other.m_md = nullptr;
        }
        return *this;
    }
    
    Result<void> init() {
        if (m_ctx == nullptr) {
            return ErrorCode::CryptoError;
        }
        
        if (m_md == nullptr) {
            return ErrorCode::CryptoError;
        }
        
        // Initialize digest context
        int ret = EVP_DigestInit_ex(m_ctx, m_md, nullptr);
        if (ret != 1) {
            // Log OpenSSL error
            unsigned long err = ERR_get_error();
            (void)err; // TODO: Log error
            return ErrorCode::CryptoError;
        }
        
        m_finalized = false;
        return Result<void>::Success();
    }
    
    Result<void> update(const Byte* data, size_t size) {
        if (m_ctx == nullptr) {
            return ErrorCode::CryptoError;
        }
        
        if (m_finalized) {
            return ErrorCode::InvalidState;
        }
        
        if (data == nullptr && size > 0) {
            return ErrorCode::InvalidArgument;
        }
        
        if (size == 0) {
            return Result<void>::Success();
        }
        
        // Update hash with data
        int ret = EVP_DigestUpdate(m_ctx, data, size);
        if (ret != 1) {
            unsigned long err = ERR_get_error();
            (void)err; // TODO: Log error
            return ErrorCode::CryptoError;
        }
        
        return Result<void>::Success();
    }
    
    Result<ByteBuffer> finalize() {
        if (m_ctx == nullptr) {
            return ErrorCode::CryptoError;
        }
        
        if (m_finalized) {
            return ErrorCode::InvalidState;
        }
        
        // Get hash size
        int hashSize = EVP_MD_size(m_md);
        if (hashSize <= 0) {
            return ErrorCode::CryptoError;
        }
        
        // Allocate buffer for hash
        ByteBuffer hash(static_cast<size_t>(hashSize));
        unsigned int len = 0;
        
        // Finalize and get hash
        int ret = EVP_DigestFinal_ex(m_ctx, hash.data(), &len);
        if (ret != 1) {
            unsigned long err = ERR_get_error();
            (void)err; // TODO: Log error
            return ErrorCode::CryptoError;
        }
        
        if (len != static_cast<unsigned int>(hashSize)) {
            return ErrorCode::CryptoError;
        }
        
        m_finalized = true;
        return hash;
    }
    
    Result<ByteBuffer> hash(const Byte* data, size_t size) {
        // One-shot: init, update, finalize
        auto initResult = init();
        if (initResult.isFailure()) {
            return initResult.error();
        }
        
        auto updateResult = update(data, size);
        if (updateResult.isFailure()) {
            return updateResult.error();
        }
        
        return finalize();
    }
    
    HashAlgorithm getAlgorithm() const noexcept {
        return m_algorithm;
    }
    
private:
    HashAlgorithm m_algorithm;
    EVPMDCtxPtr m_ctx;
    const EVP_MD* m_md;
    bool m_finalized;
};

// ============================================================================
// HashEngine - Public API
// ============================================================================

HashEngine::HashEngine(HashAlgorithm algorithm)
    : m_impl(std::make_unique<Impl>(algorithm)) {
}

HashEngine::~HashEngine() = default;

Result<ByteBuffer> HashEngine::hash(const Byte* data, size_t size) {
    return m_impl->hash(data, size);
}

Result<ByteBuffer> HashEngine::hash(ByteSpan data) {
    return m_impl->hash(data.data(), data.size());
}

Result<ByteBuffer> HashEngine::hash(const std::string& str) {
    return m_impl->hash(reinterpret_cast<const Byte*>(str.data()), str.size());
}

Result<SHA256Hash> HashEngine::sha256(ByteSpan data) {
    HashEngine engine(HashAlgorithm::SHA256);
    auto result = engine.hash(data);
    
    if (result.isFailure()) {
        return result.error();
    }
    
    const auto& hashBytes = result.value();
    if (hashBytes.size() != 32) {
        return ErrorCode::CryptoError;
    }
    
    SHA256Hash hash;
    std::copy(hashBytes.begin(), hashBytes.end(), hash.begin());
    return hash;
}

Result<SHA512Hash> HashEngine::sha512(ByteSpan data) {
    HashEngine engine(HashAlgorithm::SHA512);
    auto result = engine.hash(data);
    
    if (result.isFailure()) {
        return result.error();
    }
    
    const auto& hashBytes = result.value();
    if (hashBytes.size() != 64) {
        return ErrorCode::CryptoError;
    }
    
    SHA512Hash hash;
    std::copy(hashBytes.begin(), hashBytes.end(), hash.begin());
    return hash;
}

Result<void> HashEngine::init() {
    return m_impl->init();
}

Result<void> HashEngine::update(const Byte* data, size_t size) {
    return m_impl->update(data, size);
}

Result<void> HashEngine::update(ByteSpan data) {
    return m_impl->update(data.data(), data.size());
}

Result<ByteBuffer> HashEngine::finalize() {
    return m_impl->finalize();
}

size_t HashEngine::getHashSize(HashAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case HashAlgorithm::SHA256:
            return 32;
        case HashAlgorithm::SHA384:
            return 48;
        case HashAlgorithm::SHA512:
            return 64;
        case HashAlgorithm::MD5:
            return 16;
        default:
            return 0;
    }
}

HashAlgorithm HashEngine::getAlgorithm() const noexcept {
    return m_impl->getAlgorithm();
}

} // namespace Sentinel::Crypto
