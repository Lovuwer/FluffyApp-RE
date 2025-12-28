/**
 * Sentinel SDK - Module Signature Verification Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 12: Implement Module Signature Verification
 */

#include "Internal/SignatureVerify.hpp"

#ifdef _WIN32
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <bcrypt.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "bcrypt.lib")
#endif

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>

namespace Sentinel {
namespace SDK {

// Known proxy DLL names commonly used for DLL proxying attacks
static const wchar_t* KNOWN_PROXY_DLLS[] = {
    L"dinput8.dll",
    L"version.dll",
    L"d3d9.dll",
    L"dxgi.dll",
    L"d3d11.dll",
    L"xinput1_3.dll",
    L"winmm.dll",
    L"dsound.dll",
    nullptr
};

SignatureVerifier::SignatureVerifier() {
#ifdef _WIN32
    // Add default trusted signers for Windows system DLLs
    trusted_signers_.push_back(L"Microsoft Corporation");
    trusted_signers_.push_back(L"Microsoft Windows");
#endif
}

SignatureVerifier::~SignatureVerifier() {
    expected_modules_.clear();
    trusted_signers_.clear();
}

void SignatureVerifier::SetExpectedModules(const std::vector<ExpectedModule>& modules) {
    expected_modules_.clear();
    for (const auto& module : modules) {
        // Store module name in lowercase for case-insensitive comparison
        std::wstring name_lower = module.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
            [](wchar_t c) { return std::towlower(c); });
        expected_modules_[name_lower] = module.hash;
    }
}

void SignatureVerifier::AddTrustedSigner(const std::wstring& signer_name) {
    trusted_signers_.push_back(signer_name);
}

ModuleVerificationResult SignatureVerifier::VerifyModule(const wchar_t* module_path) {
    ModuleVerificationResult result = {};
    result.signature_status = SignatureStatus::Error;
    result.hash_match = true;  // Default to true if no hash to check
    result.path_valid = true;   // Default to true
    result.is_proxy_dll = false;
    result.actual_path = module_path;

    if (!module_path || module_path[0] == L'\0') {
        return result;
    }

    // Extract module name
    std::wstring module_name = ExtractModuleName(module_path);

    // Check if this is a known proxy DLL
    result.is_proxy_dll = IsKnownProxyDLL(module_name.c_str());

    // Validate module path (system DLLs should be in System32)
    result.path_valid = ValidateModulePath(module_path, module_name.c_str());

    // Verify Authenticode signature
    result.signature_status = VerifyAuthenticodeSignature(module_path, result.signer_name);

    // Check if module hash matches expected value
    std::wstring name_lower = module_name;
    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
        [](wchar_t c) { return std::towlower(c); });

    auto it = expected_modules_.find(name_lower);
    if (it != expected_modules_.end()) {
        // We have an expected hash for this module
        uint8_t computed_hash[32];
        if (ComputeFileHash(module_path, computed_hash)) {
            const auto& expected_hash = it->second;
            if (expected_hash.size() == 32) {
                result.hash_match = (memcmp(computed_hash, expected_hash.data(), 32) == 0);
            }
        } else {
            result.hash_match = false;
        }
    }

    return result;
}

bool SignatureVerifier::IsKnownProxyDLL(const wchar_t* module_name) {
    if (!module_name) return false;

    // Convert to lowercase for comparison
    std::wstring name_lower = module_name;
    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
        [](wchar_t c) { return std::towlower(c); });

    // Check against known proxy DLL list
    for (int i = 0; KNOWN_PROXY_DLLS[i] != nullptr; i++) {
        if (name_lower == KNOWN_PROXY_DLLS[i]) {
            return true;
        }
    }

    return false;
}

bool SignatureVerifier::ValidateModulePath(const wchar_t* module_path, const wchar_t* module_name) {
    if (!module_path || !module_name) return true;  // Can't validate, assume ok

#ifdef _WIN32
    // If it's a known proxy DLL or system DLL, it should be in System32
    if (IsKnownProxyDLL(module_name)) {
        std::wstring system32_path = GetSystem32Path();
        std::wstring path_lower = module_path;
        std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(),
            [](wchar_t c) { return std::towlower(c); });
        
        std::wstring system32_lower = system32_path;
        std::transform(system32_lower.begin(), system32_lower.end(), system32_lower.begin(),
            [](wchar_t c) { return std::towlower(c); });

        // Check if the module is loaded from System32
        if (path_lower.find(system32_lower) == 0) {
            return true;  // Loaded from System32, valid
        } else {
            return false;  // Known system DLL loaded from wrong directory
        }
    }
#endif

    return true;  // Not a system DLL, path is acceptable
}

#ifdef _WIN32
SignatureStatus SignatureVerifier::VerifyAuthenticodeSignature(const wchar_t* file_path, std::wstring& signer_name) {
    signer_name.clear();

    if (!file_path || file_path[0] == L'\0') {
        return SignatureStatus::Error;
    }

    // Initialize WinVerifyTrust structures
    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = file_path;
    file_info.hFile = NULL;
    file_info.pgKnownSubject = NULL;

    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct = sizeof(WINTRUST_DATA);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;  // Skip revocation check for performance
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    // Verify the signature
    LONG status = WinVerifyTrust(NULL, &policy_guid, &trust_data);

    // Clean up
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy_guid, &trust_data);

    SignatureStatus result;
    switch (status) {
        case ERROR_SUCCESS:
            result = SignatureStatus::Valid;
            // TODO: Extract signer name from certificate (requires additional code)
            signer_name = L"Signed";
            break;

        case TRUST_E_NOSIGNATURE:
            result = SignatureStatus::Unsigned;
            break;

        case TRUST_E_SUBJECT_NOT_TRUSTED:
        case TRUST_E_EXPLICIT_DISTRUST:
        case CRYPT_E_SECURITY_SETTINGS:
            result = SignatureStatus::Untrusted;
            break;

        case TRUST_E_BAD_DIGEST:
        case TRUST_E_CERT_SIGNATURE:
            result = SignatureStatus::Invalid;
            break;

        default:
            result = SignatureStatus::Error;
            break;
    }

    return result;
}
#else
SignatureStatus SignatureVerifier::VerifyAuthenticodeSignature(const wchar_t* file_path, std::wstring& signer_name) {
    (void)file_path;
    signer_name.clear();
    return SignatureStatus::Error;  // Not implemented on non-Windows platforms
}
#endif

bool SignatureVerifier::ComputeFileHash(const wchar_t* file_path, uint8_t* hash_out) {
    if (!file_path || !hash_out) return false;

#ifdef _WIN32
    // Open the file
    HANDLE hFile = CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Initialize BCrypt for SHA-256
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0;
    DWORD cbData = 0;
    PBYTE pbHashObject = NULL;
    bool success = false;

    do {
        // Open algorithm provider
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
            break;
        }

        // Get hash object size
        if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
            (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
            break;
        }

        // Allocate hash object
        pbHashObject = new BYTE[cbHashObject];
        if (!pbHashObject) {
            break;
        }

        // Create hash
        if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
            break;
        }

        // Read file and hash it in chunks
        const DWORD BUFFER_SIZE = 64 * 1024;  // 64KB buffer
        BYTE* buffer = new BYTE[BUFFER_SIZE];
        if (!buffer) {
            break;
        }

        DWORD bytesRead;
        while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0) {
            if (!BCRYPT_SUCCESS(BCryptHashData(hHash, buffer, bytesRead, 0))) {
                delete[] buffer;
                break;
            }
        }
        delete[] buffer;

        // Finish the hash
        if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, hash_out, 32, 0))) {
            break;
        }

        success = true;
    } while (false);

    // Clean up
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) delete[] pbHashObject;
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);

    return success;
#else
    // Use OpenSSL on non-Windows platforms (not implemented here)
    (void)file_path;
    memset(hash_out, 0, 32);
    return false;
#endif
}

std::wstring SignatureVerifier::ExtractModuleName(const wchar_t* path) {
    if (!path) return L"";

    std::wstring path_str = path;
    size_t last_slash = path_str.find_last_of(L"\\/");
    if (last_slash != std::wstring::npos) {
        return path_str.substr(last_slash + 1);
    }
    return path_str;
}

std::wstring SignatureVerifier::GetSystem32Path() {
#ifdef _WIN32
    wchar_t system_dir[MAX_PATH];
    if (GetSystemDirectoryW(system_dir, MAX_PATH) > 0) {
        return std::wstring(system_dir);
    }
    return L"C:\\Windows\\System32";  // Fallback
#else
    return L"";
#endif
}

} // namespace SDK
} // namespace Sentinel
