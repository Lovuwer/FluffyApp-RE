/**
 * Sentinel SDK - Overlay Verification Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 7: Harden overlay detection against spoofing
 */

#include "Internal/OverlayVerifier.hpp"

#ifdef _WIN32
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
#include <wincrypt.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#endif

#include <algorithm>
#include <cctype>
#include <cstring>

namespace Sentinel {
namespace SDK {

// Expected signers for overlay vendors
static const wchar_t* DISCORD_SIGNERS[] = {
    L"Discord Inc.",
    L"Discord Inc",
    nullptr
};

static const wchar_t* VALVE_SIGNERS[] = {
    L"Valve Corp.",
    L"Valve Corporation",
    L"Valve",
    nullptr
};

static const wchar_t* NVIDIA_SIGNERS[] = {
    L"NVIDIA Corporation",
    L"NVIDIA",
    nullptr
};

static const wchar_t* OBS_SIGNERS[] = {
    L"OBS Project",
    L"Hugh Bailey",
    nullptr
};

// Critical security functions that should NEVER have detections suppressed
static const wchar_t* CRITICAL_SECURITY_FUNCTIONS[] = {
    L"NtProtectVirtualMemory",
    L"VirtualProtect",
    L"VirtualProtectEx",
    L"WriteProcessMemory",
    L"ReadProcessMemory",
    L"NtWriteVirtualMemory",
    L"NtReadVirtualMemory",
    L"CreateRemoteThread",
    L"NtCreateThreadEx",
    L"SetWindowsHookEx",
    L"NtSetInformationThread",
    nullptr
};

OverlayVerifier::OverlayVerifier() {
}

OverlayVerifier::~OverlayVerifier() {
    Shutdown();
}

void OverlayVerifier::Initialize() {
    known_good_hashes_.clear();
    hook_patterns_.clear();

    // Initialize expected hook patterns for legitimate overlays
    
    // Discord overlay typically hooks D3D/DXGI for rendering
    OverlayHookPattern discord_pattern;
    discord_pattern.vendor = OverlayVendor::Discord;
    discord_pattern.expected_hook_modules = {
        L"d3d9.dll",
        L"d3d10.dll",
        L"d3d11.dll",
        L"dxgi.dll",
        L"opengl32.dll"
    };
    discord_pattern.expected_hook_functions = {
        L"Present",
        L"EndScene",
        L"SwapBuffers",
        L"CreateSwapChain"
    };
    hook_patterns_.push_back(discord_pattern);

    // Steam overlay hooks
    OverlayHookPattern steam_pattern;
    steam_pattern.vendor = OverlayVendor::Steam;
    steam_pattern.expected_hook_modules = {
        L"d3d9.dll",
        L"d3d10.dll",
        L"d3d11.dll",
        L"dxgi.dll",
        L"opengl32.dll"
    };
    steam_pattern.expected_hook_functions = {
        L"Present",
        L"EndScene",
        L"SwapBuffers"
    };
    hook_patterns_.push_back(steam_pattern);

    // NVIDIA overlay hooks
    OverlayHookPattern nvidia_pattern;
    nvidia_pattern.vendor = OverlayVendor::NVIDIA;
    nvidia_pattern.expected_hook_modules = {
        L"d3d9.dll",
        L"d3d10.dll",
        L"d3d11.dll",
        L"d3d12.dll",
        L"dxgi.dll",
        L"vulkan-1.dll"
    };
    nvidia_pattern.expected_hook_functions = {
        L"Present",
        L"EndScene"
    };
    hook_patterns_.push_back(nvidia_pattern);
}

void OverlayVerifier::Shutdown() {
    known_good_hashes_.clear();
    hook_patterns_.clear();
}

OverlayVerificationResult OverlayVerifier::VerifyOverlay(const wchar_t* module_path) {
    OverlayVerificationResult result = {};
    result.is_verified = false;
    result.vendor = OverlayVendor::Unknown;
    result.signature_valid = false;
    result.signer_match = false;
    result.hash_match = false;
    result.ipc_connection_valid = false;

    if (!module_path || module_path[0] == L'\0') {
        return result;
    }

    result.module_path = module_path;

    // Extract module name from path
    const wchar_t* module_name = wcsrchr(module_path, L'\\');
    if (module_name) {
        module_name++; // Skip the backslash
    } else {
        module_name = module_path;
    }

    // Identify vendor from module name
    result.vendor = IdentifyVendor(module_name);
    if (result.vendor == OverlayVendor::Unknown) {
        return result; // Not a recognized overlay
    }

    // Verify Authenticode signature
    result.signature_valid = VerifySignature(module_path, result.signer_name);
    if (!result.signature_valid) {
        return result; // Unsigned or invalid signature
    }

    // Verify signer matches expected vendor
    result.signer_match = VerifySignerForVendor(result.signer_name, result.vendor);
    if (!result.signer_match) {
        return result; // Valid signature but wrong signer
    }

    // Check Discord IPC connection if this is Discord
    if (result.vendor == OverlayVendor::Discord) {
        result.ipc_connection_valid = ValidateDiscordIPC();
        if (!result.ipc_connection_valid) {
            return result; // Discord overlay without IPC connection is suspicious
        }
    } else {
        result.ipc_connection_valid = true; // Not required for other overlays
    }

    // Check hash against known-good database (if available)
    std::wstring name_lower = module_name;
    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::towlower);
    
    auto it = known_good_hashes_.find(name_lower);
    if (it != known_good_hashes_.end()) {
        uint8_t computed_hash[32];
        if (ComputeFileHash(module_path, computed_hash)) {
            result.hash_match = (memcmp(computed_hash, it->second.data(), 32) == 0);
            if (!result.hash_match) {
                return result; // Hash mismatch
            }
        }
    } else {
        // No known hash - rely on signature verification
        result.hash_match = true;
    }

    // All checks passed
    result.is_verified = true;
    return result;
}

bool OverlayVerifier::IsPotentialOverlay(const wchar_t* module_name) {
    if (!module_name) return false;

    std::wstring name_lower = module_name;
    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::towlower);

    // Check for common overlay keywords
    if (name_lower.find(L"discord") != std::wstring::npos) return true;
    if (name_lower.find(L"steam") != std::wstring::npos) return true;
    if (name_lower.find(L"overlay") != std::wstring::npos) return true;
    if (name_lower.find(L"nvidia") != std::wstring::npos) return true;
    if (name_lower.find(L"geforce") != std::wstring::npos) return true;
    if (name_lower.find(L"obs") != std::wstring::npos) return true;
    if (name_lower.find(L"gameoverlayrenderer") != std::wstring::npos) return true;

    return false;
}

OverlayVendor OverlayVerifier::IdentifyVendor(const wchar_t* module_name) {
    if (!module_name) return OverlayVendor::Unknown;

    std::wstring name_lower = module_name;
    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::towlower);

    if (name_lower.find(L"discord") != std::wstring::npos) {
        return OverlayVendor::Discord;
    }
    if (name_lower.find(L"steam") != std::wstring::npos || 
        name_lower.find(L"gameoverlayrenderer") != std::wstring::npos) {
        return OverlayVendor::Steam;
    }
    if (name_lower.find(L"nvidia") != std::wstring::npos || 
        name_lower.find(L"geforce") != std::wstring::npos) {
        return OverlayVendor::NVIDIA;
    }
    if (name_lower.find(L"obs") != std::wstring::npos) {
        return OverlayVendor::OBS;
    }

    return OverlayVendor::Unknown;
}

bool OverlayVerifier::IsExpectedHookPattern(OverlayVendor vendor, const wchar_t* module_name, const wchar_t* function_name) {
    if (!module_name) return false;

    // Find hook pattern for this vendor
    for (const auto& pattern : hook_patterns_) {
        if (pattern.vendor != vendor) continue;

        // Check if module is in expected list
        std::wstring mod_lower = module_name;
        std::transform(mod_lower.begin(), mod_lower.end(), mod_lower.begin(), ::towlower);

        bool module_match = false;
        for (const auto& expected_mod : pattern.expected_hook_modules) {
            if (mod_lower == expected_mod) {
                module_match = true;
                break;
            }
        }

        if (!module_match) continue;

        // If function name not provided, just check module
        if (!function_name) return true;

        // Check if function is in expected list
        std::wstring func_lower = function_name;
        std::transform(func_lower.begin(), func_lower.end(), func_lower.begin(), ::towlower);

        for (const auto& expected_func : pattern.expected_hook_functions) {
            std::wstring exp_lower = expected_func;
            std::transform(exp_lower.begin(), exp_lower.end(), exp_lower.begin(), ::towlower);
            if (func_lower.find(exp_lower) != std::wstring::npos) {
                return true;
            }
        }
    }

    return false;
}

bool OverlayVerifier::IsCriticalSecurityFunction(const wchar_t* function_name) {
    if (!function_name) return false;

    std::wstring func_lower = function_name;
    std::transform(func_lower.begin(), func_lower.end(), func_lower.begin(), ::towlower);

    for (int i = 0; CRITICAL_SECURITY_FUNCTIONS[i] != nullptr; i++) {
        std::wstring critical_lower = CRITICAL_SECURITY_FUNCTIONS[i];
        std::transform(critical_lower.begin(), critical_lower.end(), critical_lower.begin(), ::towlower);
        
        if (func_lower == critical_lower) {
            return true;
        }
    }

    return false;
}

#ifdef _WIN32
bool OverlayVerifier::VerifySignature(const wchar_t* file_path, std::wstring& signer_name) {
    signer_name.clear();

    if (!file_path || file_path[0] == L'\0') {
        return false;
    }

    // First, verify the signature is valid
    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = file_path;
    file_info.hFile = NULL;
    file_info.pgKnownSubject = NULL;

    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct = sizeof(WINTRUST_DATA);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(NULL, &policy_guid, &trust_data);

    // Clean up
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy_guid, &trust_data);

    if (status != ERROR_SUCCESS) {
        return false; // Signature invalid or not present
    }

    // Extract certificate subject name
    if (!ExtractCertificateSubject(file_path, signer_name)) {
        signer_name = L"Valid Signature"; // Fallback
    }

    return true;
}
#else
bool OverlayVerifier::VerifySignature(const wchar_t* file_path, std::wstring& signer_name) {
    (void)file_path;
    signer_name.clear();
    return false; // Not implemented on non-Windows platforms
}
#endif

bool OverlayVerifier::VerifySignerForVendor(const std::wstring& signer_name, OverlayVendor vendor) {
    if (signer_name.empty()) return false;

    const wchar_t** expected_signers = nullptr;
    
    switch (vendor) {
        case OverlayVendor::Discord:
            expected_signers = DISCORD_SIGNERS;
            break;
        case OverlayVendor::Steam:
            expected_signers = VALVE_SIGNERS;
            break;
        case OverlayVendor::NVIDIA:
            expected_signers = NVIDIA_SIGNERS;
            break;
        case OverlayVendor::OBS:
            expected_signers = OBS_SIGNERS;
            break;
        default:
            return false;
    }

    if (!expected_signers) return false;

    // Check if signer matches any expected signer
    for (int i = 0; expected_signers[i] != nullptr; i++) {
        if (signer_name.find(expected_signers[i]) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

#ifdef _WIN32
bool OverlayVerifier::ComputeFileHash(const wchar_t* file_path, uint8_t* hash_out) {
    if (!file_path || !hash_out) return false;

    HANDLE hFile = CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0;
    DWORD cbData = 0;
    PBYTE pbHashObject = NULL;
    bool success = false;

    do {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
            break;
        }

        if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
            break;
        }

        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        if (!pbHashObject) break;

        if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
            break;
        }

        const DWORD BUFFER_SIZE = 4096;
        BYTE buffer[BUFFER_SIZE];
        DWORD bytesRead = 0;

        while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0) {
            if (!BCRYPT_SUCCESS(BCryptHashData(hHash, buffer, bytesRead, 0))) {
                goto cleanup;
            }
        }

        if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, hash_out, 32, 0))) {
            break;
        }

        success = true;
    } while (false);

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);

    return success;
}
#else
bool OverlayVerifier::ComputeFileHash(const wchar_t* file_path, uint8_t* hash_out) {
    (void)file_path;
    (void)hash_out;
    return false;
}
#endif

#ifdef _WIN32
bool OverlayVerifier::ValidateDiscordIPC() {
    // Discord creates named pipes for IPC: \\.\pipe\discord-ipc-0, discord-ipc-1, etc.
    // Try to find any Discord IPC pipe
    for (int i = 0; i < 10; i++) {
        wchar_t pipe_name[64];
        swprintf_s(pipe_name, L"\\\\.\\pipe\\discord-ipc-%d", i);
        
        HANDLE hPipe = CreateFileW(
            pipe_name,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
            return true; // Found Discord IPC pipe
        }
    }

    return false; // No Discord IPC pipe found
}
#else
bool OverlayVerifier::ValidateDiscordIPC() {
    return false;
}
#endif

#ifdef _WIN32
bool OverlayVerifier::ExtractCertificateSubject(const wchar_t* file_path, std::wstring& subject_name) {
    subject_name.clear();

    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    DWORD dwSignerInfo = 0;
    bool success = false;

    // Get message handle and store handle from the signed file
    DWORD dwEncoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    
    if (!CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        file_path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &hStore,
        &hMsg,
        NULL)) {
        return false;
    }

    // Get signer information size
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo)) {
        goto cleanup;
    }

    pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
    if (!pSignerInfo) goto cleanup;

    // Get signer information
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo)) {
        goto cleanup;
    }

    // Find certificate in store
    CERT_INFO CertInfo = {};
    CertInfo.Issuer = pSignerInfo->Issuer;
    CertInfo.SerialNumber = pSignerInfo->SerialNumber;

    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
        hStore,
        dwEncoding,
        0,
        CERT_FIND_SUBJECT_CERT,
        (PVOID)&CertInfo,
        NULL);

    if (pCertContext) {
        // Get subject name
        DWORD dwData = CertGetNameStringW(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            NULL,
            0);

        if (dwData > 1) {
            wchar_t* szName = new wchar_t[dwData];
            CertGetNameStringW(
                pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                NULL,
                szName,
                dwData);
            subject_name = szName;
            delete[] szName;
            success = true;
        }

        CertFreeCertificateContext(pCertContext);
    }

cleanup:
    if (pSignerInfo) LocalFree(pSignerInfo);
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);

    return success;
}
#else
bool OverlayVerifier::ExtractCertificateSubject(const wchar_t* file_path, std::wstring& subject_name) {
    (void)file_path;
    subject_name.clear();
    return false;
}
#endif

} // namespace SDK
} // namespace Sentinel
