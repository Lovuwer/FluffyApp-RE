/**
 * Sentinel SDK - Overlay Verification
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 7: Harden overlay detection against spoofing.
 * Provides signature-based overlay verification, hash verification,
 * and IPC connection validation to prevent fake overlays from suppressing detections.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace Sentinel {
namespace SDK {

/**
 * Known overlay vendors with expected signers
 */
enum class OverlayVendor {
    Discord,
    Steam,
    NVIDIA,
    OBS,
    Unknown
};

/**
 * Result of overlay verification
 */
struct OverlayVerificationResult {
    bool is_verified;              ///< True if overlay is verified as legitimate
    OverlayVendor vendor;          ///< Identified vendor
    bool signature_valid;          ///< True if Authenticode signature is valid
    bool signer_match;             ///< True if signer matches expected vendor
    bool hash_match;               ///< True if hash matches known-good (if available)
    bool ipc_connection_valid;     ///< True if IPC connection is valid (Discord only)
    std::wstring module_path;      ///< Full path to the module
    std::wstring signer_name;      ///< Actual signer name from certificate
};

/**
 * Expected hook patterns for legitimate overlays
 */
struct OverlayHookPattern {
    OverlayVendor vendor;
    std::vector<std::wstring> expected_hook_modules;  ///< Modules that may be hooked
    std::vector<std::wstring> expected_hook_functions; ///< Functions that may be hooked
};

/**
 * Overlay verification module
 * 
 * Implements secure overlay detection:
 * - Signature-based verification (Authenticode)
 * - Signer name validation (Discord Inc., Valve Corp., etc.)
 * - Hash verification against known-good database
 * - IPC connection validation (Discord)
 * - Hook pattern correlation
 */
class OverlayVerifier {
public:
    OverlayVerifier();
    ~OverlayVerifier();

    /**
     * Initialize the overlay verifier
     */
    void Initialize();

    /**
     * Shutdown the overlay verifier
     */
    void Shutdown();

    /**
     * Verify an overlay module
     * @param module_path Full path to the overlay DLL
     * @return Verification result
     */
    OverlayVerificationResult VerifyOverlay(const wchar_t* module_path);

    /**
     * Check if a module name could be an overlay
     * @param module_name Module name (case-insensitive)
     * @return True if module name suggests it might be an overlay
     */
    static bool IsPotentialOverlay(const wchar_t* module_name);

    /**
     * Identify overlay vendor from module name
     * @param module_name Module name
     * @return Overlay vendor or Unknown
     */
    static OverlayVendor IdentifyVendor(const wchar_t* module_name);

    /**
     * Check if a hook pattern is expected for a verified overlay
     * @param vendor Overlay vendor
     * @param module_name Module containing the hook
     * @param function_name Hooked function name (can be nullptr)
     * @return True if hook pattern is expected for this overlay
     */
    bool IsExpectedHookPattern(OverlayVendor vendor, const wchar_t* module_name, const wchar_t* function_name = nullptr);

    /**
     * Check if function is critical (should never be suppressed)
     * @param function_name Function name
     * @return True if function is critical security function
     */
    static bool IsCriticalSecurityFunction(const wchar_t* function_name);

private:
    /**
     * Verify Authenticode signature and extract signer name
     * @param file_path Path to the file
     * @param signer_name Output: signer name
     * @return True if signature is valid
     */
    bool VerifySignature(const wchar_t* file_path, std::wstring& signer_name);

    /**
     * Check if signer matches expected vendor
     * @param signer_name Signer name from certificate
     * @param vendor Expected vendor
     * @return True if signer matches
     */
    bool VerifySignerForVendor(const std::wstring& signer_name, OverlayVendor vendor);

    /**
     * Compute SHA-256 hash of a file
     * @param file_path Path to the file
     * @param hash_out Output buffer (32 bytes)
     * @return True if hash was computed successfully
     */
    bool ComputeFileHash(const wchar_t* file_path, uint8_t* hash_out);

    /**
     * Check if Discord IPC connection exists
     * @return True if Discord IPC pipe is found
     */
    bool ValidateDiscordIPC();

    /**
     * Extract subject name from certificate signer
     * @param file_path Path to signed file
     * @param subject_name Output: certificate subject name
     * @return True if subject was extracted
     */
    bool ExtractCertificateSubject(const wchar_t* file_path, std::wstring& subject_name);

    // Known-good hashes for overlay DLLs (can be updated)
    std::unordered_map<std::wstring, std::vector<uint8_t>> known_good_hashes_;

    // Expected hook patterns for legitimate overlays
    std::vector<OverlayHookPattern> hook_patterns_;
};

} // namespace SDK
} // namespace Sentinel
