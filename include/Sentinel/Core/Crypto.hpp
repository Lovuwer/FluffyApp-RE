/**
 * @file Crypto.hpp
 * @brief Cryptographic utilities for the Sentinel Security Ecosystem
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This module provides cryptographic operations including:
 * - AES-256-GCM encryption/decryption
 * - RSA-4096 signing/verification
 * - SHA-256/SHA-512 hashing
 * - Secure random number generation
 * - HMAC computation
 */

#pragma once

#ifndef SENTINEL_CORE_CRYPTO_HPP
#define SENTINEL_CORE_CRYPTO_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <memory>
#include <string>

namespace Sentinel::Crypto {

// ============================================================================
// Secure Random Number Generator
// ============================================================================

/**
 * @brief Cryptographically secure random number generator
 * 
 * Uses Windows BCryptGenRandom for secure randomness.
 */
class SecureRandom {
public:
    SecureRandom();
    ~SecureRandom();
    
    /**
     * @brief Generate random bytes
     * @param buffer Buffer to fill with random bytes
     * @param size Number of bytes to generate
     * @return Result indicating success or failure
     */
    Result<void> generate(Byte* buffer, size_t size);
    
    /**
     * @brief Generate random byte buffer
     * @param size Number of bytes to generate
     * @return Random bytes or error
     */
    Result<ByteBuffer> generate(size_t size);
    
    /**
     * @brief Generate random value of type T
     * @tparam T Type of value to generate
     * @return Random value or error
     */
    template<typename T>
    Result<T> generateValue() {
        T value;
        auto result = generate(reinterpret_cast<Byte*>(&value), sizeof(T));
        if (result.isFailure()) return result.error();
        return value;
    }
    
    /**
     * @brief Generate random AES key
     * @return Random AES-256 key or error
     */
    Result<AESKey> generateAESKey();
    
    /**
     * @brief Generate random AES nonce
     * @return Random 12-byte nonce or error
     */
    Result<AESNonce> generateNonce();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Hash Engine
// ============================================================================

/**
 * @brief Hash algorithm types
 */
enum class HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
    MD5  // For legacy compatibility only
};

/**
 * @brief Cryptographic hash engine
 * 
 * Provides one-shot and streaming hash computation.
 * 
 * @example
 * ```cpp
 * HashEngine hasher(HashAlgorithm::SHA256);
 * 
 * // One-shot
 * auto hash = hasher.hash(data);
 * 
 * // Streaming
 * hasher.init();
 * hasher.update(chunk1);
 * hasher.update(chunk2);
 * auto hash = hasher.finalize();
 * ```
 */
class HashEngine {
public:
    /**
     * @brief Construct hash engine with algorithm
     * @param algorithm Hash algorithm to use
     */
    explicit HashEngine(HashAlgorithm algorithm = HashAlgorithm::SHA256);
    
    ~HashEngine();
    
    /**
     * @brief Compute hash of data (one-shot)
     * @param data Data to hash
     * @param size Size of data
     * @return Hash bytes or error
     */
    Result<ByteBuffer> hash(const Byte* data, size_t size);
    
    /**
     * @brief Compute hash of data (one-shot)
     * @param data Data to hash
     * @return Hash bytes or error
     */
    Result<ByteBuffer> hash(ByteSpan data);
    
    /**
     * @brief Compute hash of string
     * @param str String to hash
     * @return Hash bytes or error
     */
    Result<ByteBuffer> hash(const std::string& str);
    
    /**
     * @brief Compute SHA-256 hash
     * @param data Data to hash
     * @return SHA256Hash or error
     */
    static Result<SHA256Hash> sha256(ByteSpan data);
    
    /**
     * @brief Compute SHA-512 hash
     * @param data Data to hash
     * @return SHA512Hash or error
     */
    static Result<SHA512Hash> sha512(ByteSpan data);
    
    /**
     * @brief Initialize streaming hash
     * @return Result indicating success or failure
     */
    Result<void> init();
    
    /**
     * @brief Update hash with data
     * @param data Data to add
     * @param size Size of data
     * @return Result indicating success or failure
     */
    Result<void> update(const Byte* data, size_t size);
    
    /**
     * @brief Update hash with data
     * @param data Data to add
     * @return Result indicating success or failure
     */
    Result<void> update(ByteSpan data);
    
    /**
     * @brief Finalize and get hash
     * @return Hash bytes or error
     */
    Result<ByteBuffer> finalize();
    
    /**
     * @brief Get hash size for algorithm
     * @param algorithm Hash algorithm
     * @return Size in bytes
     */
    static size_t getHashSize(HashAlgorithm algorithm) noexcept;
    
    /**
     * @brief Get current algorithm
     * @return Hash algorithm
     */
    HashAlgorithm getAlgorithm() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// AES Cipher
// ============================================================================

/**
 * @brief AES-256-GCM cipher for authenticated encryption
 * 
 * Provides authenticated encryption with associated data (AEAD).
 * 
 * **Security guarantees:**
 * - Automatic nonce generation ensures nonce uniqueness within a single process
 * - Keys MUST be ephemeral (single process lifetime) to prevent nonce reuse
 * - Nonce reuse with the same key is CATASTROPHIC in AES-GCM and breaks all security
 * - NEVER reuse keys across process restarts without implementing stateful nonce management
 * 
 * **Key lifetime requirements:**
 * - Keys should be generated fresh for each process or session
 * - If persistent keys are required, implement counter-based or HKDF-derived nonces
 * - Random nonces are only safe when keys are ephemeral
 * 
 * @example
 * ```cpp
 * // Generate ephemeral key
 * SecureRandom rng;
 * auto keyResult = rng.generateAESKey();
 * AESCipher cipher(keyResult.value());
 * 
 * // Encrypt (nonce generated automatically)
 * auto encrypted = cipher.encrypt(plaintext);
 * 
 * // Decrypt
 * auto decrypted = cipher.decrypt(encrypted.value());
 * ```
 * 
 * @warning Key reuse across process restarts with random nonces can lead to nonce collision!
 * @warning Nonce reuse breaks ALL security properties of AES-GCM (confidentiality and authenticity)!
 */
class AESCipher {
public:
    /**
     * @brief Construct cipher with key
     * @param key AES-256 key (32 bytes)
     */
    explicit AESCipher(const AESKey& key);
    
    /**
     * @brief Construct cipher with key from buffer
     * @param key Key bytes (must be 32 bytes)
     */
    explicit AESCipher(ByteSpan key);
    
    ~AESCipher();
    
    /**
     * @brief Encrypt data with AES-256-GCM
     * 
     * Automatically generates a cryptographically secure random nonce for each encryption.
     * The nonce is prepended to the output.
     * 
     * @param plaintext Data to encrypt
     * @param associatedData Additional authenticated data (optional)
     * @return Encrypted data (nonce + ciphertext + tag) or error
     * 
     * @note This is the ONLY safe public encryption method - it prevents nonce reuse
     */
    Result<ByteBuffer> encrypt(
        ByteSpan plaintext,
        ByteSpan associatedData = {}
    );
    
    /**
     * @brief Decrypt data with AES-256-GCM
     * 
     * Extracts the nonce from the input and verifies the authentication tag.
     * 
     * @param ciphertext Encrypted data (nonce + ciphertext + tag)
     * @param associatedData Additional authenticated data (optional)
     * @return Decrypted data or error
     * 
     * @note Returns error on authentication failure - NO plaintext is exposed
     */
    Result<ByteBuffer> decrypt(
        ByteSpan ciphertext,
        ByteSpan associatedData = {}
    );
    
    /**
     * @brief Change the encryption key
     * @param key New AES-256 key
     * 
     * @warning When changing keys, ensure the new key is also ephemeral
     */
    void setKey(const AESKey& key);

private:
    /**
     * @brief Encrypt with explicit nonce (INTERNAL USE ONLY)
     * 
     * @warning DANGEROUS: This method allows nonce reuse if called improperly
     * @warning Only use for testing with NIST test vectors
     * @warning NEVER expose this method to production code
     * 
     * @param plaintext Data to encrypt
     * @param nonce 12-byte nonce (must be unique per encryption with this key)
     * @param associatedData Additional authenticated data (optional)
     * @return Ciphertext + tag (without nonce) or error
     */
    Result<ByteBuffer> encryptWithNonce(
        ByteSpan plaintext,
        const AESNonce& nonce,
        ByteSpan associatedData = {}
    );
    
    /**
     * @brief Decrypt with explicit nonce (INTERNAL USE ONLY)
     * 
     * @param ciphertext Ciphertext + tag
     * @param nonce 12-byte nonce used for encryption
     * @param associatedData Additional authenticated data (optional)
     * @return Decrypted data or error
     */
    Result<ByteBuffer> decryptWithNonce(
        ByteSpan ciphertext,
        const AESNonce& nonce,
        ByteSpan associatedData = {}
    );

    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Test-only accessor class for validating NIST test vectors
    // Defined in tests/Core/test_crypto.cpp to access private methods via friend mechanism
    friend class AESCipherTestAccessor;
};

// ============================================================================
// RSA Signer
// ============================================================================

/**
 * @brief RSA-4096 digital signature with PSS padding
 * 
 * @example
 * ```cpp
 * RSASigner signer;
 * signer.loadPrivateKey(privateKeyDer);
 * 
 * auto signature = signer.sign(data);
 * 
 * // Verification
 * RSASigner verifier;
 * verifier.loadPublicKey(publicKeyDer);
 * auto valid = verifier.verify(data, signature.value());
 * ```
 */
class RSASigner {
public:
    RSASigner();
    ~RSASigner();
    
    /**
     * @brief Generate new RSA-4096 key pair
     * @return Result indicating success or failure
     */
    Result<void> generateKeyPair();
    
    /**
     * @brief Load private key from DER format
     * @param derKey Private key in DER format
     * @return Result indicating success or failure
     */
    Result<void> loadPrivateKey(ByteSpan derKey);
    
    /**
     * @brief Load public key from DER format
     * @param derKey Public key in DER format
     * @return Result indicating success or failure
     */
    Result<void> loadPublicKey(ByteSpan derKey);
    
    /**
     * @brief Load private key from PEM format
     * @param pemKey Private key in PEM format
     * @return Result indicating success or failure
     */
    Result<void> loadPrivateKeyPEM(const std::string& pemKey);
    
    /**
     * @brief Load public key from PEM format
     * @param pemKey Public key in PEM format
     * @return Result indicating success or failure
     */
    Result<void> loadPublicKeyPEM(const std::string& pemKey);
    
    /**
     * @brief Export private key in DER format
     * @return Private key bytes or error
     */
    Result<ByteBuffer> exportPrivateKey();
    
    /**
     * @brief Export public key in DER format
     * @return Public key bytes or error
     */
    Result<ByteBuffer> exportPublicKey();
    
    /**
     * @brief Sign data with RSA-PSS
     * @param data Data to sign
     * @return Signature bytes or error
     */
    Result<Signature> sign(ByteSpan data);
    
    /**
     * @brief Verify signature with RSA-PSS
     * @param data Original data
     * @param signature Signature to verify
     * @return true if valid, false if invalid, or error
     */
    Result<bool> verify(ByteSpan data, ByteSpan signature);
    
    /**
     * @brief Check if private key is loaded
     * @return true if private key is available
     */
    bool hasPrivateKey() const noexcept;
    
    /**
     * @brief Check if public key is loaded
     * @return true if public key is available
     */
    bool hasPublicKey() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// HMAC
// ============================================================================

/**
 * @brief HMAC (Hash-based Message Authentication Code)
 */
class HMAC {
public:
    /**
     * @brief Construct HMAC with key
     * @param key HMAC key
     * @param algorithm Hash algorithm (default: SHA256)
     */
    explicit HMAC(ByteSpan key, HashAlgorithm algorithm = HashAlgorithm::SHA256);
    
    ~HMAC();
    
    /**
     * @brief Compute HMAC of data (one-shot)
     * @param data Data to authenticate
     * @return HMAC bytes or error
     */
    Result<ByteBuffer> compute(ByteSpan data);
    
    /**
     * @brief Compute HMAC-SHA256 (static helper)
     * @param key HMAC key
     * @param data Data to authenticate
     * @return HMAC bytes or error
     */
    static Result<ByteBuffer> sha256(ByteSpan key, ByteSpan data);
    
    /**
     * @brief Verify HMAC
     * @param data Original data
     * @param mac HMAC to verify
     * @return true if valid, false if invalid
     */
    Result<bool> verify(ByteSpan data, ByteSpan mac);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Convert bytes to hex string
 * @param data Bytes to convert
 * @return Hex string
 */
std::string toHex(ByteSpan data);

/**
 * @brief Convert hex string to bytes
 * @param hex Hex string
 * @return Bytes or error
 */
Result<ByteBuffer> fromHex(const std::string& hex);

/**
 * @brief Convert bytes to base64 string
 * @param data Bytes to convert
 * @return Base64 string
 */
std::string toBase64(ByteSpan data);

/**
 * @brief Convert base64 string to bytes
 * @param base64 Base64 string
 * @return Bytes or error
 */
Result<ByteBuffer> fromBase64(const std::string& base64);

/**
 * @brief Constant-time comparison of byte arrays
 * 
 * This function is provided for comparing non-AEAD authentication values
 * (e.g., HMAC tags, password hashes) in constant time to prevent timing attacks.
 * 
 * @param a First array
 * @param b Second array
 * @return true if equal
 * 
 * @warning DO NOT use this for AEAD (AES-GCM) tag comparison!
 * @warning OpenSSL's EVP_DecryptFinal_ex already performs constant-time tag verification.
 * @warning Manual AEAD tag comparison bypasses cryptographic library guarantees and is unsafe.
 * 
 * @note For AEAD operations, always use the decrypt() method which handles tag verification internally.
 */
bool constantTimeCompare(ByteSpan a, ByteSpan b) noexcept;

/**
 * @brief Securely zero memory
 * @param data Memory to zero
 * @param size Size of memory
 */
void secureZero(void* data, size_t size) noexcept;

} // namespace Sentinel::Crypto

#endif // SENTINEL_CORE_CRYPTO_HPP
