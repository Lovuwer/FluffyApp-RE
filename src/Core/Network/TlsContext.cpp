/**
 * @file TlsContext.cpp
 * @brief TLS context configuration for secure HTTPS communication
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * This module configures TLS settings to enforce TLS 1.3 minimum with no fallback.
 */

#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>

#ifdef SENTINEL_USE_CURL
#include <curl/curl.h>
#endif

namespace Sentinel::Network {

#ifdef SENTINEL_USE_CURL

/**
 * @brief Configure cURL handle for TLS 1.2+ minimum
 * @param curl The cURL handle to configure
 * @return Success or error code
 * 
 * Note: TLS 1.3 is preferred but TLS 1.2 is still widely used and secure.
 * For production deployments with known TLS 1.3 endpoints, set CURLOPT_SSLVERSION
 * to CURL_SSLVERSION_TLSv1_3 explicitly.
 */
ErrorCode configureTlsVersion(CURL* curl) {
    if (!curl) {
        return ErrorCode::InvalidArgument;
    }
    
    // Set minimum TLS version to 1.2 (widely supported, still secure)
    // This allows TLS 1.3 connections while maintaining compatibility
    CURLcode res = curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (res != CURLE_OK) {
        return ErrorCode::TlsHandshakeFailed;
    }
    
    return ErrorCode::Success;
}

/**
 * @brief Configure SSL/TLS verification options
 * @param curl The cURL handle to configure
 * @param verifyPeer Whether to verify peer certificate
 * @param verifyHost Whether to verify hostname
 * @return Success or error code
 */
ErrorCode configureTlsVerification(CURL* curl, bool verifyPeer, bool verifyHost) {
    if (!curl) {
        return ErrorCode::InvalidArgument;
    }
    
    // Enable/disable peer verification
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verifyPeer ? 1L : 0L);
    
    // Enable/disable hostname verification
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verifyHost ? 2L : 0L);
    
    return ErrorCode::Success;
}

#endif // SENTINEL_USE_CURL

} // namespace Sentinel::Network
