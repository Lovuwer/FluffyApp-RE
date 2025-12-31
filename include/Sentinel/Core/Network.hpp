/**
 * @file Network.hpp
 * @brief Network security utilities for the Sentinel Security Ecosystem
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This module provides network security features including:
 * - TLS certificate pinning (SPKI)
 * - Certificate validation
 */

#pragma once

#ifndef SENTINEL_CORE_NETWORK_HPP
#define SENTINEL_CORE_NETWORK_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <string>
#include <vector>
#include <memory>

// Forward declarations for OpenSSL types
typedef struct x509_store_ctx_st X509_STORE_CTX;

namespace Sentinel::Network {

/**
 * SPKI (Subject Public Key Info) pin
 */
struct SPKIPin {
    std::string sha256_hash;  // Base64-encoded SHA-256 of SPKI
    std::string description;  // Optional description (e.g., "Primary", "Backup")
};

/**
 * Certificate pinning configuration
 */
struct PinningConfig {
    std::string hostname;
    std::vector<SPKIPin> pins;  // At least one must match
    bool enforce = true;        // If false, log but don't fail
};

/**
 * Certificate pinning verifier
 */
class CertificatePinner {
public: 
    CertificatePinner();
    ~CertificatePinner();
    
    /**
     * Add pinning configuration for a host
     */
    void addPins(const PinningConfig& config);
    
    /**
     * Update pins for a host (replaces existing pins)
     */
    void updatePins(const PinningConfig& config);
    
    /**
     * Remove pins for a host
     */
    void removePins(const std::string& hostname);
    
    /**
     * Clear all pins
     */
    void clearAllPins();
    
    /**
     * Verify certificate chain against pins
     * @param hostname The hostname being connected to
     * @param cert_chain DER-encoded certificate chain
     * @return Result indicating if pin matched
     */
    Result<bool> verify(const std::string& hostname,
                       const std::vector<ByteBuffer>& cert_chain);
    
    /**
     * OpenSSL verification callback (for use with SSL_CTX_set_verify)
     * Returns 1 if valid, 0 if invalid
     */
    static int verifyCallback(int preverify_ok, X509_STORE_CTX* ctx);
    
    /**
     * Set the pinner instance for callback use
     */
    static void setInstance(CertificatePinner* instance);
    
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

/**
 * Compute SPKI hash from certificate
 * @param cert_der DER-encoded certificate
 * @return Base64-encoded SHA-256 hash of SPKI
 */
Result<std::string> computeSPKIHash(ByteSpan cert_der);

} // namespace Sentinel::Network

#endif // SENTINEL_CORE_NETWORK_HPP
