/**
 * @file CryptoUtils.cpp
 * @brief Cryptographic utility functions
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Provides utility functions for cryptographic operations:
 * - Hex encoding/decoding
 * - Base64 encoding/decoding
 */

#include <Sentinel/Core/Crypto.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace Sentinel::Crypto {

// ============================================================================
// Hex Encoding/Decoding
// ============================================================================

std::string toHex(ByteSpan data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (Byte b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    
    return oss.str();
}

Result<ByteBuffer> fromHex(const std::string& hex) {
    // Hex string must have even length
    if (hex.length() % 2 != 0) {
        return ErrorCode::InvalidHexString;
    }
    
    ByteBuffer result;
    result.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        char high = hex[i];
        char low = hex[i + 1];
        
        // Validate hex characters
        auto hexValue = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        
        int highVal = hexValue(high);
        int lowVal = hexValue(low);
        
        if (highVal == -1 || lowVal == -1) {
            return ErrorCode::InvalidHexString;
        }
        
        result.push_back(static_cast<Byte>((highVal << 4) | lowVal));
    }
    
    return result;
}

// ============================================================================
// Base64 Encoding/Decoding
// ============================================================================

std::string toBase64(ByteSpan data) {
    if (data.empty()) {
        return "";
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    
    // No newlines in output
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    
    BIO_free_all(bio);
    
    return result;
}

Result<ByteBuffer> fromBase64(const std::string& base64) {
    if (base64.empty()) {
        return ByteBuffer{};
    }
    
    BIO* bio = BIO_new_mem_buf(base64.data(), static_cast<int>(base64.length()));
    BIO* b64 = BIO_new(BIO_f_base64());
    
    // No newlines in input
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    bio = BIO_push(b64, bio);
    
    // Calculate maximum possible output size
    size_t maxLength = (base64.length() * 3) / 4 + 1;
    ByteBuffer result(maxLength);
    
    int length = BIO_read(bio, result.data(), static_cast<int>(maxLength));
    
    BIO_free_all(bio);
    
    if (length < 0) {
        return ErrorCode::InvalidBase64;
    }
    
    result.resize(length);
    return result;
}

} // namespace Sentinel::Crypto
