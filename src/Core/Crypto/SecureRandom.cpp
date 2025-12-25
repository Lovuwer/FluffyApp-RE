/**
 * @file SecureRandom.cpp
 * @brief Cryptographically secure random number generator implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * Provides cryptographically secure random number generation using:
 * - Windows: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG
 * - Linux: /dev/urandom with retry on EINTR
 */

#include <Sentinel/Core/Crypto.hpp>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fstream>
#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <mutex>
#endif

namespace Sentinel::Crypto {

// ============================================================================
// SecureRandom::Impl - Platform-specific implementation
// ============================================================================

class SecureRandom::Impl {
public:
    Impl() {
#ifndef _WIN32
        // Linux: Open /dev/urandom
        m_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (m_fd < 0) {
            throw std::runtime_error("Failed to open /dev/urandom");
        }
#endif
    }
    
    ~Impl() {
#ifndef _WIN32
        if (m_fd >= 0) {
            close(m_fd);
        }
#endif
    }
    
    Result<void> generate(Byte* buffer, size_t size) {
        if (buffer == nullptr && size > 0) {
            return ErrorCode::InvalidArgument;
        }
        
        if (size == 0) {
            return Result<void>::Success();
        }
        
#ifdef _WIN32
        // Windows: Use BCryptGenRandom
        NTSTATUS status = BCryptGenRandom(
            nullptr,
            buffer,
            static_cast<ULONG>(size),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
        
        if (!BCRYPT_SUCCESS(status)) {
            return ErrorCode::CryptoError;
        }
        
        return Result<void>::Success();
#else
        // Linux: Read from /dev/urandom with retry on EINTR
        std::lock_guard<std::mutex> lock(m_mutex);
        
        size_t total = 0;
        while (total < size) {
            ssize_t n = read(m_fd, buffer + total, size - total);
            
            if (n < 0) {
                if (errno == EINTR) {
                    continue; // Interrupted, retry
                }
                return ErrorCode::CryptoError;
            }
            
            if (n == 0) {
                // Unexpected EOF
                return ErrorCode::CryptoError;
            }
            
            total += n;
        }
        
        return Result<void>::Success();
#endif
    }
    
private:
#ifndef _WIN32
    int m_fd = -1;
    std::mutex m_mutex; // Thread safety for Linux
#endif
};

// ============================================================================
// SecureRandom - Public API
// ============================================================================

SecureRandom::SecureRandom()
    : m_impl(std::make_unique<Impl>()) {
}

SecureRandom::~SecureRandom() = default;

Result<void> SecureRandom::generate(Byte* buffer, size_t size) {
    return m_impl->generate(buffer, size);
}

Result<ByteBuffer> SecureRandom::generate(size_t size) {
    ByteBuffer buffer(size);
    auto result = m_impl->generate(buffer.data(), size);
    
    if (result.isFailure()) {
        return result.error();
    }
    
    return buffer;
}

Result<AESKey> SecureRandom::generateAESKey() {
    AESKey key;
    auto result = m_impl->generate(key.data(), key.size());
    
    if (result.isFailure()) {
        return result.error();
    }
    
    return key;
}

Result<AESNonce> SecureRandom::generateNonce() {
    AESNonce nonce;
    auto result = m_impl->generate(nonce.data(), nonce.size());
    
    if (result.isFailure()) {
        return result.error();
    }
    
    return nonce;
}

} // namespace Sentinel::Crypto
