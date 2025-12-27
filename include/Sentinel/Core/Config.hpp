/**
 * @file Config.hpp
 * @brief Secure configuration loading for Sentinel Security Ecosystem
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This module provides secure configuration loading with protection against:
 * - TOCTOU (Time-Of-Check-To-Time-Of-Use) attacks
 * - Path traversal attacks
 * - Symlink attacks
 * - File size DoS attacks
 * - Signature tampering
 */

#pragma once

#ifndef SENTINEL_CORE_CONFIG_HPP
#define SENTINEL_CORE_CONFIG_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <string>
#include <map>
#include <variant>

namespace Sentinel::Config {

using ConfigValue = std::variant<
    bool,
    int64_t,
    double,
    std::string,
    ByteBuffer
>;

using ConfigMap = std::map<std::string, ConfigValue>;

/**
 * @brief Secure configuration loader
 * 
 * Security features:
 * - Atomic file operations (no TOCTOU)
 * - Path canonicalization
 * - Size limits
 * - Optional signature verification
 */
class SecureConfigLoader {
public:
    struct Options {
        size_t max_file_size = 1024 * 1024;  // 1MB default
        bool verify_signature = false;
        ByteBuffer signature_public_key;
        std::string allowed_directory;       // Restrict to directory
    };
    
    explicit SecureConfigLoader(const Options& options = {});
    ~SecureConfigLoader();
    
    /**
     * @brief Load configuration from file
     * @param path Path to configuration file
     * @return Parsed configuration or error
     */
    Result<ConfigMap> load(const std::string& path);
    
    /**
     * @brief Load configuration from memory
     * @param data Configuration data
     * @param signature Optional signature for verification
     * @return Parsed configuration or error
     */
    Result<ConfigMap> loadFromMemory(
        ByteSpan data,
        ByteSpan signature = {});
    
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Sentinel::Config

#endif // SENTINEL_CORE_CONFIG_HPP
