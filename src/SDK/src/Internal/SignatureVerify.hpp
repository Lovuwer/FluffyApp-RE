/**
 * Sentinel SDK - Module Signature Verification
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 12: Implement Module Signature Verification
 * Provides Authenticode signature verification, hash verification,
 * and DLL proxy detection to prevent fake/modified DLLs.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace Sentinel {
namespace SDK {

/**
 * Result of signature verification
 */
enum class SignatureStatus {
    Valid,              ///< Signature is valid and trusted
    Invalid,            ///< Signature is invalid or tampered
    Unsigned,           ///< Module is not signed
    Untrusted,          ///< Signature is valid but signer is not trusted
    Error               ///< Error occurred during verification
};

/**
 * Module verification result
 */
struct ModuleVerificationResult {
    SignatureStatus signature_status;
    bool hash_match;           ///< True if hash matches expected value
    bool path_valid;           ///< True if loaded from expected path
    bool is_proxy_dll;         ///< True if known proxy DLL name detected
    std::wstring signer_name;  ///< Name of the code signer (if signed)
    std::wstring actual_path;  ///< Actual path the module was loaded from
};

/**
 * Expected module configuration for hash verification
 */
struct ExpectedModule {
    std::wstring name;         ///< Module name (e.g., L"game.dll")
    std::vector<uint8_t> hash; ///< Expected SHA-256 hash (32 bytes)
};

/**
 * Module signature verification and integrity checker
 */
class SignatureVerifier {
public:
    SignatureVerifier();
    ~SignatureVerifier();

    /**
     * Configure expected game modules with their hashes
     * @param modules List of expected modules with hashes
     */
    void SetExpectedModules(const std::vector<ExpectedModule>& modules);

    /**
     * Add an expected signer for system DLLs
     * @param signer_name Expected signer name (e.g., L"Microsoft Corporation")
     */
    void AddTrustedSigner(const std::wstring& signer_name);

    /**
     * Verify a loaded module
     * @param module_path Full path to the module
     * @return Verification result with signature status, hash match, and path validity
     */
    ModuleVerificationResult VerifyModule(const wchar_t* module_path);

    /**
     * Check if a module name is a known proxy DLL
     * @param module_name Module name (e.g., L"dinput8.dll")
     * @return True if it's a known proxy DLL name
     */
    static bool IsKnownProxyDLL(const wchar_t* module_name);

    /**
     * Check if a system DLL is loaded from the correct path
     * @param module_path Full path to the module
     * @param module_name Module name
     * @return True if path is valid for this module type
     */
    static bool ValidateModulePath(const wchar_t* module_path, const wchar_t* module_name);

private:
    /**
     * Verify Authenticode signature using WinVerifyTrust
     * @param file_path Path to the file to verify
     * @param signer_name Output: Name of the signer (if successful)
     * @return Signature verification status
     */
    SignatureStatus VerifyAuthenticodeSignature(const wchar_t* file_path, std::wstring& signer_name);

    /**
     * Compute SHA-256 hash of a file
     * @param file_path Path to the file
     * @param hash_out Output buffer (32 bytes)
     * @return True if hash was computed successfully
     */
    bool ComputeFileHash(const wchar_t* file_path, uint8_t* hash_out);

    /**
     * Extract module name from full path
     * @param path Full path
     * @return Module name (lowercase)
     */
    static std::wstring ExtractModuleName(const wchar_t* path);

    /**
     * Get Windows System32 directory path
     * @return System32 directory path (e.g., C:\Windows\System32)
     */
    static std::wstring GetSystem32Path();

    // Expected modules and their hashes
    std::unordered_map<std::wstring, std::vector<uint8_t>> expected_modules_;
    
    // Trusted signers for system DLLs
    std::vector<std::wstring> trusted_signers_;
};

} // namespace SDK
} // namespace Sentinel
