/**
 * @file RSASigner.cpp
 * @brief RSA-PSS digital signature implementation using OpenSSL 3.0 EVP API
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Implements RSA-PSS probabilistic signatures using OpenSSL 3.0 Provider API.
 * Defends against:
 * - Bleichenbacher padding oracle attacks (1998)
 * - Coppersmith attacks on low public exponent
 * - Signature forgery via deterministic padding
 * - Weak key attacks (< 2048 bits, e != 65537)
 */

#include <Sentinel/Core/Crypto.hpp>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <cstring>

namespace Sentinel::Crypto {

// ============================================================================
// RSASigner::Impl - Implementation class
// ============================================================================

class RSASigner::Impl {
public:
    Impl() : m_pkey(nullptr) {}
    
    ~Impl() {
        if (m_pkey) {
            EVP_PKEY_free(m_pkey);
            m_pkey = nullptr;
        }
    }
    
    Result<void> loadPrivateKey(ByteSpan derKey) {
        const unsigned char* p = derKey.data();
        EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, derKey.size());
        if (!pkey) {
            return ErrorCode::InvalidKey;
        }
        
        // Validate key parameters
        if (!validateKeyParams(pkey)) {
            EVP_PKEY_free(pkey);
            return ErrorCode::WeakKey;
        }
        
        if (m_pkey) {
            EVP_PKEY_free(m_pkey);
        }
        m_pkey = pkey;
        return ErrorCode::Success;
    }
    
    Result<void> loadPublicKey(ByteSpan derKey) {
        const unsigned char* p = derKey.data();
        EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, derKey.size());
        if (!pkey) {
            return ErrorCode::InvalidKey;
        }
        
        // Validate key parameters
        if (!validateKeyParams(pkey)) {
            EVP_PKEY_free(pkey);
            return ErrorCode::WeakKey;
        }
        
        if (m_pkey) {
            EVP_PKEY_free(m_pkey);
        }
        m_pkey = pkey;
        return ErrorCode::Success;
    }
    
    Result<Signature> sign(ByteSpan data) {
        if (!m_pkey) {
            return ErrorCode::KeyNotLoaded;
        }
        
        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
            return ErrorCode::CryptoError;
        }
        
        EVP_PKEY_CTX* pkeyCtx = nullptr;
        
        // Initialize signing with SHA-256 hash
        if (EVP_DigestSignInit(mdCtx, &pkeyCtx, EVP_sha256(), 
                                nullptr, m_pkey) != 1) {
            EVP_MD_CTX_free(mdCtx);
            return ErrorCode::CryptoError;
        }
        
        // Set PSS padding
        if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) != 1) {
            EVP_MD_CTX_free(mdCtx);
            return ErrorCode::CryptoError;
        }
        
        // Set salt length to hash length (SHA-256 = 32 bytes)
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, RSA_PSS_SALTLEN_DIGEST) != 1) {
            EVP_MD_CTX_free(mdCtx);
            return ErrorCode::CryptoError;
        }
        
        // Update with data
        if (EVP_DigestSignUpdate(mdCtx, data.data(), data.size()) != 1) {
            EVP_MD_CTX_free(mdCtx);
            return ErrorCode::CryptoError;
        }
        
        // Get signature size
        size_t sigLen = 0;
        if (EVP_DigestSignFinal(mdCtx, nullptr, &sigLen) != 1) {
            EVP_MD_CTX_free(mdCtx);
            return ErrorCode::CryptoError;
        }
        
        // Sign
        Signature signature(sigLen);
        if (EVP_DigestSignFinal(mdCtx, signature.data(), &sigLen) != 1) {
            EVP_MD_CTX_free(mdCtx);
            return ErrorCode::CryptoError;
        }
        
        signature.resize(sigLen);
        EVP_MD_CTX_free(mdCtx);
        return signature;
    }
    
    Result<bool> verify(ByteSpan data, ByteSpan signature) {
        if (!m_pkey) {
            return ErrorCode::KeyNotLoaded;
        }
        
        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
            return ErrorCode::CryptoError;
        }
        
        EVP_PKEY_CTX* pkeyCtx = nullptr;
        
        // Initialize verification with SHA-256 hash
        if (EVP_DigestVerifyInit(mdCtx, &pkeyCtx, EVP_sha256(), 
                                  nullptr, m_pkey) != 1) {
            EVP_MD_CTX_free(mdCtx);
            return ErrorCode::CryptoError;
        }
        
        // Set PSS padding
        if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) != 1) {
            EVP_MD_CTX_free(mdCtx);
            return ErrorCode::CryptoError;
        }
        
        // Set salt length to hash length (SHA-256 = 32 bytes)
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, RSA_PSS_SALTLEN_DIGEST) != 1) {
            EVP_MD_CTX_free(mdCtx);
            return ErrorCode::CryptoError;
        }
        
        // Update with data
        if (EVP_DigestVerifyUpdate(mdCtx, data.data(), data.size()) != 1) {
            EVP_MD_CTX_free(mdCtx);
            return ErrorCode::CryptoError;
        }
        
        // Verify signature
        int verifyResult = EVP_DigestVerifyFinal(mdCtx, signature.data(), signature.size());
        EVP_MD_CTX_free(mdCtx);
        
        if (verifyResult == 1) {
            return true;  // Signature valid
        } else {
            return false; // Signature invalid (not an error, just failed verification)
        }
    }
    
    bool hasPrivateKey() const noexcept {
        // Check if we have a private key loaded
        if (!m_pkey) {
            return false;
        }
        
        // For OpenSSL 3.0+, check if the key has the private exponent 'd' parameter
        // If we loaded a private key, this will succeed
        // If we loaded only a public key, this will fail
        BIGNUM* d = nullptr;
        int result = EVP_PKEY_get_bn_param(m_pkey, OSSL_PKEY_PARAM_RSA_D, &d);
        if (result == 1 && d != nullptr) {
            BN_free(d);
            return true;
        }
        return false;
    }
    
    bool hasPublicKey() const noexcept {
        return m_pkey != nullptr;
    }

private:
    EVP_PKEY* m_pkey;
    
    bool validateKeyParams(EVP_PKEY* pkey) {
        // Require minimum 2048-bit key
        int keyBits = EVP_PKEY_bits(pkey);
        if (keyBits < 2048) {
            return false;
        }
        
        // Require public exponent = 65537
        BIGNUM* e = nullptr;
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
            return false;
        }
        
        if (!e) {
            return false;
        }
        
        bool validE = BN_is_word(e, 65537);
        BN_free(e);
        
        return validE;
    }
};

// ============================================================================
// RSASigner - Public interface
// ============================================================================

RSASigner::RSASigner() : m_impl(std::make_unique<Impl>()) {}

RSASigner::~RSASigner() = default;

Result<void> RSASigner::generateKeyPair() {
    // Not implemented per requirements
    return ErrorCode::NotImplemented;
}

Result<void> RSASigner::loadPrivateKey(ByteSpan derKey) {
    return m_impl->loadPrivateKey(derKey);
}

Result<void> RSASigner::loadPublicKey(ByteSpan derKey) {
    return m_impl->loadPublicKey(derKey);
}

Result<void> RSASigner::loadPrivateKeyPEM(const std::string& /* pemKey */) {
    // Not implemented per requirements
    return ErrorCode::NotImplemented;
}

Result<void> RSASigner::loadPublicKeyPEM(const std::string& /* pemKey */) {
    // Not implemented per requirements
    return ErrorCode::NotImplemented;
}

Result<ByteBuffer> RSASigner::exportPrivateKey() {
    // Not implemented per requirements
    return ErrorCode::NotImplemented;
}

Result<ByteBuffer> RSASigner::exportPublicKey() {
    // Not implemented per requirements
    return ErrorCode::NotImplemented;
}

Result<Signature> RSASigner::sign(ByteSpan data) {
    return m_impl->sign(data);
}

Result<bool> RSASigner::verify(ByteSpan data, ByteSpan signature) {
    return m_impl->verify(data, signature);
}

bool RSASigner::hasPrivateKey() const noexcept {
    return m_impl->hasPrivateKey();
}

bool RSASigner::hasPublicKey() const noexcept {
    return m_impl->hasPublicKey();
}

} // namespace Sentinel::Crypto
