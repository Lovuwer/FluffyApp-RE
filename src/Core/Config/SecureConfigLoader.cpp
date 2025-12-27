/**
 * @file SecureConfigLoader.cpp
 * @brief Implementation of secure configuration loading
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/Config.hpp>
#include <Sentinel/Core/Crypto.hpp>

#ifdef _WIN32
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#endif

#include <fstream>
#include <filesystem>
#include <sstream>

namespace Sentinel::Config {

class SecureConfigLoader::Impl {
public:
    Options options;
    
    explicit Impl(const Options& opts) : options(opts) {}
    
    Result<std::string> canonicalizePath(const std::string& path) {
        #ifdef _WIN32
        wchar_t fullPath[MAX_PATH];
        wchar_t widePath[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, widePath, MAX_PATH);
        
        if (!PathCanonicalizeW(fullPath, widePath)) {
            return ErrorCode::InvalidPath;
        }
        
        // Convert back to UTF-8
        char narrowPath[MAX_PATH * 3];
        WideCharToMultiByte(CP_UTF8, 0, fullPath, -1, 
                           narrowPath, sizeof(narrowPath), nullptr, nullptr);
        
        return std::string(narrowPath);
        #else
        char* resolved = realpath(path.c_str(), nullptr);
        if (!resolved) {
            return ErrorCode::InvalidPath;
        }
        std::string result(resolved);
        free(resolved);
        return result;
        #endif
    }
    
    Result<bool> isPathAllowed(const std::string& canonicalPath) {
        if (options.allowed_directory.empty()) {
            return true;  // No restriction
        }
        
        auto allowedResult = canonicalizePath(options.allowed_directory);
        if (allowedResult.isFailure()) {
            return allowedResult.error();
        }
        
        const std::string& allowed = allowedResult.value();
        
        // Check if path starts with allowed directory
        if (canonicalPath.length() < allowed.length()) {
            return false;
        }
        
        #ifdef _WIN32
        // Case-insensitive on Windows
        if (_strnicmp(canonicalPath.c_str(), allowed.c_str(), 
                     allowed.length()) != 0) {
            return false;
        }
        #else
        if (canonicalPath.compare(0, allowed.length(), allowed) != 0) {
            return false;
        }
        #endif
        
        return true;
    }
    
    Result<ByteBuffer> readFileSecurely(const std::string& path) {
        // Canonicalize path first
        auto canonResult = canonicalizePath(path);
        if (canonResult.isFailure()) {
            return canonResult.error();
        }
        const std::string& canonPath = canonResult.value();
        
        // Check path restriction
        auto allowedResult = isPathAllowed(canonPath);
        if (allowedResult.isFailure()) {
            return allowedResult.error();
        }
        if (!allowedResult.value()) {
            return ErrorCode::AccessDenied;
        }
        
        #ifdef _WIN32
        // Windows: Use CreateFile for atomic open-and-read
        HANDLE hFile = CreateFileA(
            canonPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,  // Allow other readers, but not writers
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr
        );
        
        if (hFile == INVALID_HANDLE_VALUE) {
            return ErrorCode::FileNotFound;
        }
        
        // Get file size
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
            CloseHandle(hFile);
            return ErrorCode::IOError;
        }
        
        if (static_cast<size_t>(fileSize.QuadPart) > options.max_file_size) {
            CloseHandle(hFile);
            return ErrorCode::FileTooLarge;
        }
        
        // Read entire file
        ByteBuffer data(static_cast<size_t>(fileSize.QuadPart));
        DWORD bytesRead;
        if (!ReadFile(hFile, data.data(), 
                     static_cast<DWORD>(data.size()), &bytesRead, nullptr)) {
            CloseHandle(hFile);
            return ErrorCode::IOError;
        }
        
        CloseHandle(hFile);
        
        if (bytesRead != data.size()) {
            return ErrorCode::IOError;
        }
        
        return data;
        
        #else
        // POSIX: Use open() with O_NOFOLLOW to prevent symlink attacks
        int fd = open(canonPath.c_str(), O_RDONLY | O_NOFOLLOW);
        if (fd < 0) {
            return ErrorCode::FileNotFound;
        }
        
        // Get file size via fstat (on the open fd, not path)
        struct stat st;
        if (fstat(fd, &st) < 0) {
            close(fd);
            return ErrorCode::IOError;
        }
        
        if (static_cast<size_t>(st.st_size) > options.max_file_size) {
            close(fd);
            return ErrorCode::FileTooLarge;
        }
        
        // Read entire file
        ByteBuffer data(st.st_size);
        ssize_t bytesRead = read(fd, data.data(), data.size());
        close(fd);
        
        if (bytesRead != static_cast<ssize_t>(data.size())) {
            return ErrorCode::IOError;
        }
        
        return data;
        #endif
    }
    
    Result<bool> verifySignature(ByteSpan data, ByteSpan signature) {
        if (!options.verify_signature) {
            return true;  // Verification not required
        }
        
        if (options.signature_public_key.empty()) {
            return ErrorCode::KeyNotLoaded;
        }
        
        Crypto::RSASigner verifier;
        auto loadResult = verifier.loadPublicKey(options.signature_public_key);
        if (loadResult.isFailure()) {
            return loadResult.error();
        }
        
        return verifier.verify(data, signature);
    }
    
    Result<ConfigMap> parseConfig(ByteSpan data) {
        // Simple key=value parser (could be replaced with JSON/TOML)
        ConfigMap config;
        
        std::string content(reinterpret_cast<const char*>(data.data()), 
                           data.size());
        std::istringstream stream(content);
        std::string line;
        
        while (std::getline(stream, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#' || line[0] == ';') {
                continue;
            }
            
            // Find key=value separator
            size_t pos = line.find('=');
            if (pos == std::string::npos) {
                continue;
            }
            
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t\r\n") + 1);
            
            // Store as string (type inference could be added)
            config[key] = value;
        }
        
        return config;
    }
};

SecureConfigLoader::SecureConfigLoader(const Options& options)
    : m_impl(std::make_unique<Impl>(options)) {}

SecureConfigLoader::~SecureConfigLoader() = default;

Result<ConfigMap> SecureConfigLoader::load(const std::string& path) {
    // Read file securely
    auto dataResult = m_impl->readFileSecurely(path);
    if (dataResult.isFailure()) {
        return dataResult.error();
    }
    
    // Load signature file if verification required
    ByteBuffer signature;
    if (m_impl->options.verify_signature) {
        std::string sigPath = path + ".sig";
        auto sigResult = m_impl->readFileSecurely(sigPath);
        if (sigResult.isSuccess()) {
            signature = sigResult.value();
        } else {
            return ErrorCode::SignatureNotFound;
        }
    }
    
    return loadFromMemory(dataResult.value(), signature);
}

Result<ConfigMap> SecureConfigLoader::loadFromMemory(
    ByteSpan data, 
    ByteSpan signature) {
    
    // Verify signature if required
    if (m_impl->options.verify_signature) {
        auto verifyResult = m_impl->verifySignature(data, signature);
        if (verifyResult.isFailure()) {
            return verifyResult.error();
        }
        if (!verifyResult.value()) {
            return ErrorCode::SignatureInvalid;
        }
    }
    
    // Parse configuration
    return m_impl->parseConfig(data);
}

} // namespace Sentinel::Config
