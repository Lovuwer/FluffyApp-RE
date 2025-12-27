/**
 * @file Base64.cpp
 * @brief Base64 encoding/decoding implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/Crypto.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstring>

namespace Sentinel::Crypto {

std::string toBase64(ByteSpan data) {
    if (data.empty()) {
        return "";
    }
    
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    std::string result(bptr->data, bptr->length);
    
    BIO_free_all(b64);
    
    return result;
}

Result<ByteBuffer> fromBase64(const std::string& base64) {
    if (base64.empty()) {
        return ByteBuffer{};
    }
    
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(base64.data(), static_cast<int>(base64.length()));
    bmem = BIO_push(b64, bmem);
    
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    
    // Allocate buffer for decoded data
    ByteBuffer buffer(base64.length());
    int decoded_length = BIO_read(bmem, buffer.data(), static_cast<int>(base64.length()));
    
    BIO_free_all(bmem);
    
    if (decoded_length < 0) {
        return ErrorCode::InvalidBase64;
    }
    
    buffer.resize(decoded_length);
    return buffer;
}

} // namespace Sentinel::Crypto
