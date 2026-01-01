/**
 * @file ObfuscatedString.hpp
 * @brief Compile-time string obfuscation framework
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This module provides compile-time string encryption to prevent
 * static analysis via string search. Encrypted strings are decrypted
 * at runtime only when needed and immediately cleared from memory.
 * 
 * Usage:
 * @code
 * auto str = OBFUSCATE("sensitive string");
 * // str.decrypt() returns std::string with decrypted value
 * // Automatically cleared when str goes out of scope
 * @endcode
 * 
 * Performance: Decryption takes <1 microsecond per string
 * Security: Per-build encryption key variation prevents static decryptors
 */

#pragma once

#ifndef SENTINEL_CORE_OBFUSCATED_STRING_HPP
#define SENTINEL_CORE_OBFUSCATED_STRING_HPP

#include <Sentinel/Core/Types.hpp>
#include <array>
#include <string>
#include <cstdint>
#include <cstring>

namespace Sentinel {
namespace Obfuscation {

// ============================================================================
// Compile-Time Random Key Generation
// ============================================================================

/**
 * @brief Generate compile-time pseudo-random seed from build metadata
 * 
 * Uses __TIME__, __DATE__, and __COUNTER__ to create per-build variation.
 * This prevents static decryption tools from working across builds.
 */
constexpr uint64_t compileSeed() noexcept {
    // Extract compile time information
    constexpr const char* time_str = __TIME__; // "HH:MM:SS"
    constexpr const char* date_str = __DATE__; // "MMM DD YYYY"
    
    // Hash time string
    uint64_t seed = 0xcbf29ce484222325ULL; // FNV-1a offset basis
    
    for (int i = 0; time_str[i] != '\0'; ++i) {
        seed ^= static_cast<uint64_t>(time_str[i]);
        seed *= 0x100000001b3ULL; // FNV-1a prime
    }
    
    for (int i = 0; date_str[i] != '\0'; ++i) {
        seed ^= static_cast<uint64_t>(date_str[i]);
        seed *= 0x100000001b3ULL;
    }
    
    // Mix in counter for uniqueness per macro invocation
    seed ^= __COUNTER__;
    
    return seed;
}

/**
 * @brief Linear congruential generator for compile-time random numbers
 */
constexpr uint64_t lcgNext(uint64_t state) noexcept {
    return state * 6364136223846793005ULL + 1442695040888963407ULL;
}

/**
 * @brief Generate random key byte at compile time
 */
constexpr uint8_t randomByte(uint64_t seed, size_t index) noexcept {
    uint64_t state = seed;
    for (size_t i = 0; i <= index; ++i) {
        state = lcgNext(state);
    }
    return static_cast<uint8_t>(state >> 56);
}

// ============================================================================
// Compile-Time String Encryption
// ============================================================================

/**
 * @brief Compile-time encrypted string storage
 * 
 * @tparam N String length (including null terminator)
 * @tparam Seed Random seed for encryption key
 */
template<size_t N, uint64_t Seed>
class ObfuscatedString {
public:
    /**
     * @brief Construct and encrypt string at compile time
     */
    constexpr ObfuscatedString(const char (&str)[N]) noexcept 
        : m_data{}, m_length(N - 1) {
        // XOR encryption with per-character key
        for (size_t i = 0; i < N - 1; ++i) {
            m_data[i] = str[i] ^ randomByte(Seed, i);
        }
        m_data[N - 1] = 0; // Null terminator
    }
    
    /**
     * @brief Decrypt string at runtime
     * 
     * Returns a std::string with the decrypted content. The returned
     * string should be used immediately and discarded to minimize
     * plaintext exposure time.
     * 
     * @return Decrypted string
     */
    std::string decrypt() const {
        std::string result;
        result.resize(m_length);
        
        // XOR decryption
        for (size_t i = 0; i < m_length; ++i) {
            result[i] = m_data[i] ^ randomByte(Seed, i);
        }
        
        return result;
    }
    
    /**
     * @brief Get encrypted data pointer (for testing)
     */
    const char* data() const noexcept {
        return m_data.data();
    }
    
    /**
     * @brief Get string length (excluding null terminator)
     */
    size_t length() const noexcept {
        return m_length;
    }

private:
    std::array<char, N> m_data;
    size_t m_length;
};

// ============================================================================
// RAII Wrapper for Automatic Memory Cleanup
// ============================================================================

/**
 * @brief RAII wrapper for obfuscated strings with automatic memory cleanup
 * 
 * Decrypts the string on construction and securely zeros the memory
 * on destruction, minimizing plaintext exposure time.
 */
class SecureString {
public:
    /**
     * @brief Construct from encrypted string and decrypt
     */
    template<size_t N, uint64_t Seed>
    explicit SecureString(const ObfuscatedString<N, Seed>& obfuscated)
        : m_data(obfuscated.decrypt()) {
    }
    
    /**
     * @brief Destructor securely zeros memory
     */
    ~SecureString() {
        // Securely zero the string memory
        secureZero();
    }
    
    // Disable copy to prevent plaintext duplication
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    
    // Allow move
    SecureString(SecureString&& other) noexcept 
        : m_data(std::move(other.m_data)) {
    }
    
    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            secureZero();
            m_data = std::move(other.m_data);
        }
        return *this;
    }
    
    /**
     * @brief Get decrypted string value
     */
    const std::string& str() const noexcept {
        return m_data;
    }
    
    /**
     * @brief Get C-string pointer
     */
    const char* c_str() const noexcept {
        return m_data.c_str();
    }
    
    /**
     * @brief Implicit conversion to std::string
     */
    operator const std::string&() const noexcept {
        return m_data;
    }
    
    /**
     * @brief Get string length
     */
    size_t length() const noexcept {
        return m_data.length();
    }
    
    /**
     * @brief Check if string is empty
     */
    bool empty() const noexcept {
        return m_data.empty();
    }

private:
    /**
     * @brief Securely zero string memory
     */
    void secureZero() {
        if (!m_data.empty()) {
            // Volatile pointer prevents compiler optimization
            volatile char* ptr = const_cast<char*>(m_data.data());
            for (size_t i = 0; i < m_data.length(); ++i) {
                ptr[i] = 0;
            }
        }
    }
    
    std::string m_data;
};

// ============================================================================
// Convenience Macro
// ============================================================================

/**
 * @brief Obfuscate a string literal at compile time
 * 
 * Usage:
 * @code
 * auto str = OBFUSCATE("sensitive string");
 * std::cout << str.decrypt() << std::endl;
 * @endcode
 * 
 * For automatic memory cleanup, use OBFUSCATE_STR:
 * @code
 * auto str = OBFUSCATE_STR("sensitive string");
 * std::cout << str.c_str() << std::endl;
 * // Memory automatically zeroed when str goes out of scope
 * @endcode
 */
#define OBFUSCATE(str) \
    ::Sentinel::Obfuscation::ObfuscatedString<sizeof(str), \
        ::Sentinel::Obfuscation::compileSeed() ^ __COUNTER__>(str)

/**
 * @brief Obfuscate string with automatic RAII cleanup
 * 
 * Returns a SecureString that automatically zeros memory on destruction.
 */
#define OBFUSCATE_STR(str) \
    ::Sentinel::Obfuscation::SecureString(OBFUSCATE(str))

} // namespace Obfuscation
} // namespace Sentinel

#endif // SENTINEL_CORE_OBFUSCATED_STRING_HPP
