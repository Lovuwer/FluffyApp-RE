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
 *   Thread Safety: BCryptGenRandom is thread-safe per Microsoft documentation
 *   (https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)
 * - Linux: /dev/urandom with retry on EINTR, fallback to getrandom() syscall
 */

#include <Sentinel/Core/Crypto.hpp>

#include <cstring>
#include <algorithm>
#include <mutex>
#include <atomic>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#ifdef __linux__
#include <sys/syscall.h>
#include <linux/random.h>
#endif
#endif

namespace Sentinel::Crypto {

// ============================================================================
// SecureRandom::Impl - Platform-specific implementation
// ============================================================================

class SecureRandom::Impl {
public:
    Impl() noexcept 
        : m_initialized(false)
        , m_healthStatus(RandomHealthStatus::Uninitialized)
        , m_usingFallback(false)
#ifndef _WIN32
        , m_fd(-1)
#endif
    {
        // Deferred initialization - no work done in constructor
    }
    
    ~Impl() {
#ifndef _WIN32
        if (m_fd >= 0) {
            close(m_fd);
        }
#endif
    }
    
    Result<void> ensureInitialized() {
        // Double-checked locking pattern for thread-safe initialization
        if (m_initialized.load(std::memory_order_acquire)) {
            return Result<void>::Success();
        }
        
        std::lock_guard<std::mutex> lock(m_initMutex);
        
        if (m_initialized.load(std::memory_order_relaxed)) {
            return Result<void>::Success();
        }
        
        // Platform-specific initialization
        auto initResult = platformInit();
        if (initResult.isFailure()) {
            m_healthStatus = RandomHealthStatus::Unhealthy;
            return initResult;
        }
        
        // Run self-test
        auto testResult = selfTest();
        if (testResult.isFailure()) {
            m_healthStatus = RandomHealthStatus::Unhealthy;
            return ErrorCode::CryptoError;
        }
        
        m_healthStatus = m_usingFallback ? RandomHealthStatus::Degraded : RandomHealthStatus::Healthy;
        m_initialized.store(true, std::memory_order_release);
        
        return Result<void>::Success();
    }
    
    Result<void> platformInit() {
#ifdef _WIN32
        // Windows: BCryptGenRandom requires no initialization
        // The API is stateless and thread-safe
        return Result<void>::Success();
#else
        // Linux: Try to open /dev/urandom
        m_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (m_fd < 0) {
            // Try fallback to getrandom() syscall
#ifdef __linux__
            if (SYS_getrandom != 0) {
                // getrandom() is available, we can use it as fallback
                m_usingFallback = true;
                m_fd = -1; // Mark as using getrandom
                return Result<void>::Success();
            }
#endif
            return ErrorCode::CryptoError;
        }
        return Result<void>::Success();
#endif
    }
    
    Result<void> selfTest() {
        // Generate test data and verify basic randomness properties
        constexpr size_t testSize = 256;
        Byte testData[testSize];
        
        auto result = generateInternal(testData, testSize);
        if (result.isFailure()) {
            return result;
        }
        
        // Test 1: Not all zeros
        bool allZeros = true;
        for (size_t i = 0; i < testSize; ++i) {
            if (testData[i] != 0) {
                allZeros = false;
                break;
            }
        }
        if (allZeros) {
            return ErrorCode::CryptoError;
        }
        
        // Test 2: Not all ones
        bool allOnes = true;
        for (size_t i = 0; i < testSize; ++i) {
            if (testData[i] != 0xFF) {
                allOnes = false;
                break;
            }
        }
        if (allOnes) {
            return ErrorCode::CryptoError;
        }
        
        // Test 3: Basic entropy check - count unique bytes
        // At least 64 different byte values in 256 bytes (25% unique)
        bool seen[256] = {false};
        size_t uniqueCount = 0;
        for (size_t i = 0; i < testSize; ++i) {
            if (!seen[testData[i]]) {
                seen[testData[i]] = true;
                uniqueCount++;
            }
        }
        if (uniqueCount < 64) {
            return ErrorCode::CryptoError;
        }
        
        // Test 4: Check for repeating patterns (no 8-byte sequence repeats)
        for (size_t i = 0; i < testSize - 16; ++i) {
            bool repeating = true;
            for (size_t j = 0; j < 8; ++j) {
                if (testData[i + j] != testData[i + j + 8]) {
                    repeating = false;
                    break;
                }
            }
            if (repeating) {
                return ErrorCode::CryptoError;
            }
        }
        
        return Result<void>::Success();
    }
    
    Result<void> generate(Byte* buffer, size_t size) {
        if (buffer == nullptr && size > 0) {
            return ErrorCode::InvalidArgument;
        }
        
        if (size == 0) {
            return Result<void>::Success();
        }
        
        // Ensure initialized and healthy
        auto initResult = ensureInitialized();
        if (initResult.isFailure()) {
            return initResult;
        }
        
        return generateInternal(buffer, size);
    }
    
    Result<void> generateInternal(Byte* buffer, size_t size) {
#ifdef _WIN32
        // Windows: Use BCryptGenRandom
        // Thread Safety: BCryptGenRandom is documented as thread-safe
        // https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
        // "This function can be called from multiple threads simultaneously."
        
        // Handle size overflow by splitting into multiple calls if needed
        constexpr size_t maxChunkSize = static_cast<size_t>(ULONG_MAX);
        size_t offset = 0;
        
        while (offset < size) {
            size_t chunkSize = (size - offset > maxChunkSize) ? maxChunkSize : (size - offset);
            
            NTSTATUS status = BCryptGenRandom(
                nullptr,
                buffer + offset,
                static_cast<ULONG>(chunkSize),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG
            );
            
            if (!BCRYPT_SUCCESS(status)) {
                m_healthStatus = RandomHealthStatus::Unhealthy;
                return ErrorCode::CryptoError;
            }
            
            offset += chunkSize;
        }
        
        return Result<void>::Success();
#else
        // Linux: Read from /dev/urandom or use getrandom()
        
        if (m_fd >= 0) {
            // Use /dev/urandom
            std::lock_guard<std::mutex> lock(m_mutex);
            
            size_t total = 0;
            while (total < size) {
                ssize_t n = read(m_fd, buffer + total, size - total);
                
                if (n < 0) {
                    if (errno == EINTR) {
                        continue; // Interrupted, retry
                    }
                    m_healthStatus = RandomHealthStatus::Unhealthy;
                    return ErrorCode::CryptoError;
                }
                
                if (n == 0) {
                    // Unexpected EOF
                    m_healthStatus = RandomHealthStatus::Unhealthy;
                    return ErrorCode::CryptoError;
                }
                
                total += n;
            }
            
            return Result<void>::Success();
        }
#ifdef __linux__
        else {
            // Fallback to getrandom() syscall
            size_t total = 0;
            while (total < size) {
                ssize_t n = syscall(SYS_getrandom, buffer + total, size - total, 0);
                
                if (n < 0) {
                    if (errno == EINTR) {
                        continue; // Interrupted, retry
                    }
                    m_healthStatus = RandomHealthStatus::Unhealthy;
                    return ErrorCode::CryptoError;
                }
                
                total += n;
            }
            
            return Result<void>::Success();
        }
#else
        m_healthStatus = RandomHealthStatus::Unhealthy;
        return ErrorCode::CryptoError;
#endif
#endif
    }
    
    RandomHealthStatus getHealthStatus() const noexcept {
        return m_healthStatus;
    }
    
    bool isHealthy() const noexcept {
        return m_initialized.load(std::memory_order_acquire) && 
               (m_healthStatus == RandomHealthStatus::Healthy || 
                m_healthStatus == RandomHealthStatus::Degraded);
    }
    
private:
    std::atomic<bool> m_initialized;
    std::mutex m_initMutex;
    std::atomic<RandomHealthStatus> m_healthStatus;
    bool m_usingFallback;
    
#ifndef _WIN32
    int m_fd;
    std::mutex m_mutex; // Thread safety for Linux file operations
#endif
};

// ============================================================================
// SecureRandom - Public API
// ============================================================================

SecureRandom::SecureRandom() noexcept
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

RandomHealthStatus SecureRandom::getHealthStatus() const noexcept {
    return m_impl->getHealthStatus();
}

bool SecureRandom::isHealthy() const noexcept {
    return m_impl->isHealthy();
}

} // namespace Sentinel::Crypto
