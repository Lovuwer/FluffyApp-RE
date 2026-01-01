/**
 * Sentinel SDK - RSA Test Helpers
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Helper functions for generating RSA keys in tests.
 * Note: generateKeyPair() is intentionally NOT implemented in production code
 * for security reasons. These helpers are for testing only.
 */

#pragma once

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>

namespace Sentinel {
namespace Testing {

/**
 * Generate RSA key pair for testing
 * @param bits Key size in bits (default 2048)
 * @param e Public exponent (default 65537)
 * @return EVP_PKEY* containing the key pair (caller must free)
 */
inline EVP_PKEY* generateTestKey(int bits = 2048, unsigned long e = 65537) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        return nullptr;
    }
    
    if (EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    // Set public exponent
    BIGNUM* bn_e = BN_new();
    if (!bn_e || !BN_set_word(bn_e, e)) {
        BN_free(bn_e);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn_e) != 1) {
        BN_free(bn_e);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    BN_free(bn_e);
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/**
 * Export private key to DER format
 */
inline ByteBuffer exportPrivateKeyDER(EVP_PKEY* pkey) {
    unsigned char* der = nullptr;
    int len = i2d_PrivateKey(pkey, &der);
    if (len <= 0) {
        return ByteBuffer();
    }
    
    ByteBuffer result(der, der + len);
    OPENSSL_free(der);
    return result;
}

/**
 * Export public key to DER format
 */
inline ByteBuffer exportPublicKeyDER(EVP_PKEY* pkey) {
    unsigned char* der = nullptr;
    int len = i2d_PUBKEY(pkey, &der);
    if (len <= 0) {
        return ByteBuffer();
    }
    
    ByteBuffer result(der, der + len);
    OPENSSL_free(der);
    return result;
}

/**
 * Generate and load a test RSA key pair into an RSASigner
 * Returns the public key DER for distribution/verification
 */
inline Result<ByteBuffer> setupTestRSAKey(Crypto::RSASigner& signer) {
    // Generate key pair
    EVP_PKEY* pkey = generateTestKey(2048);
    if (!pkey) {
        return ErrorCode::CryptoError;
    }
    
    // Export keys
    ByteBuffer privateKeyDer = exportPrivateKeyDER(pkey);
    ByteBuffer publicKeyDer = exportPublicKeyDER(pkey);
    
    // Clean up OpenSSL key
    EVP_PKEY_free(pkey);
    
    if (privateKeyDer.empty() || publicKeyDer.empty()) {
        return ErrorCode::CryptoError;
    }
    
    // Load into signer
    auto loadResult = signer.loadPrivateKey(privateKeyDer);
    if (loadResult.isFailure()) {
        return loadResult.error();
    }
    
    return publicKeyDer;
}

} // namespace Testing
} // namespace Sentinel
