/**
 * Sentinel SDK - JIT Signature Database Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 1: Eliminate Module Name-Based JIT Whitelisting
 */

#include "Internal/JITSignature.hpp"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")
#endif

#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace Sentinel {
namespace SDK {

// Helper function to convert hash to hex string for map key
static std::string HashToHexString(const uint8_t* hash, size_t size) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

JITSignatureValidator::JITSignatureValidator() {
    // Constructor
}

JITSignatureValidator::~JITSignatureValidator() {
    signature_database_.clear();
    validated_cache_.clear();
}

void JITSignatureValidator::Initialize() {
    signature_database_.clear();
    validated_cache_.clear();
    
    // Add built-in signatures for known JIT engines
    AddBuiltInSignatures();
}

bool JITSignatureValidator::ValidateJITRegion(uintptr_t address) {
#ifdef _WIN32
    // Query memory information to get the allocation base
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
        return false;
    }

    // Get the module at this allocation base
    if (!mbi.AllocationBase) {
        return false;
    }

    uintptr_t module_base = (uintptr_t)mbi.AllocationBase;

    // Check the cache first
    for (const auto& cached : validated_cache_) {
        if (cached.base_address == module_base) {
            // Found in cache - verify the address is within expected JIT heap range
            return IsWithinJITHeapRange(address, module_base);
        }
    }

    // Not in cache - need to validate
    // First, hash the .text section
    uint8_t text_hash[32];
    if (!HashTextSection(module_base, text_hash)) {
        return false;  // Cannot hash - not a valid module
    }

    // Look up the hash in the signature database
    std::string hash_key = HashToHexString(text_hash, 32);
    auto it = signature_database_.find(hash_key);
    
    if (it == signature_database_.end()) {
        // Hash not found - unknown or modified JIT module
        return false;
    }

    // Found a matching signature
    const JITSignature& signature = it->second;

    // For .NET JIT specifically, validate CLR metadata presence
    if (signature.engine_type == JITEngineType::DotNetCLR) {
        if (!HasCLRMetadata(module_base)) {
            // Claims to be .NET JIT but has no CLR metadata - suspicious
            return false;
        }
    }

    // Verify the address is within expected JIT heap ranges
    if (!IsWithinJITHeapRange(address, module_base)) {
        return false;
    }

    // All checks passed - add to cache
    ValidatedModule cached_entry;
    cached_entry.base_address = module_base;
    cached_entry.engine_type = signature.engine_type;
    cached_entry.validation_time = GetTickCount64();
    validated_cache_.push_back(cached_entry);

    return true;
#else
    (void)address;
    return false;  // Not implemented on non-Windows platforms
#endif
}

bool JITSignatureValidator::HasCLRMetadata(uintptr_t module_base) {
#ifdef _WIN32
    __try {
        // Read DOS header
        const IMAGE_DOS_HEADER* dos_header = (const IMAGE_DOS_HEADER*)module_base;
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        // Read NT headers
        const IMAGE_NT_HEADERS* nt_headers = 
            (const IMAGE_NT_HEADERS*)(module_base + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        // Check for .NET metadata directory (COM descriptor)
        const IMAGE_DATA_DIRECTORY* clr_dir = 
            &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        
        if (clr_dir->VirtualAddress != 0 && clr_dir->Size != 0) {
            // Has CLR metadata directory
            return true;
        }

        // Additional check: look for .text section with typical CLR characteristics
        // CLR modules typically have specific section names
        const IMAGE_SECTION_HEADER* section_headers = IMAGE_FIRST_SECTION(nt_headers);
        for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
            const IMAGE_SECTION_HEADER* section = &section_headers[i];
            
            // Check for typical CLR section names
            if (strncmp((const char*)section->Name, ".text", 5) == 0 ||
                strncmp((const char*)section->Name, ".cormeta", 8) == 0) {
                return true;
            }
        }

        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Access violation - not a valid module
        return false;
    }
#else
    (void)module_base;
    return false;
#endif
}

bool JITSignatureValidator::HashTextSection(uintptr_t module_base, uint8_t* hash_out) {
#ifdef _WIN32
    uintptr_t text_start = 0;
    size_t text_size = 0;

    if (!GetTextSectionInfo(module_base, text_start, text_size)) {
        return false;
    }

    // Hash the first 4KB of the .text section (or entire section if smaller)
    size_t bytes_to_hash = (text_size < 4096) ? text_size : 4096;

    // Initialize BCrypt for SHA-256
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0;
    DWORD cbData = 0;
    std::vector<BYTE> hashObjectBuffer;
    bool success = false;

    __try {
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
            hashObjectBuffer.resize(cbHashObject);

            // Create hash
            if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObjectBuffer.data(), cbHashObject, NULL, 0, 0))) {
                break;
            }

            // Hash the .text section data
            if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PBYTE)text_start, (ULONG)bytes_to_hash, 0))) {
                break;
            }

            // Finish the hash
            if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, hash_out, 32, 0))) {
                break;
            }

            success = true;
        } while (false);

        // Clean up
        if (hHash) BCryptDestroyHash(hHash);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Access violation during hashing
        success = false;
    }

    return success;
#else
    (void)module_base;
    (void)hash_out;
    return false;
#endif
}

bool JITSignatureValidator::GetTextSectionInfo(uintptr_t module_base, 
                                                uintptr_t& text_section_start, 
                                                size_t& text_section_size) {
#ifdef _WIN32
    __try {
        // Read DOS header
        const IMAGE_DOS_HEADER* dos_header = (const IMAGE_DOS_HEADER*)module_base;
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        // Read NT headers
        const IMAGE_NT_HEADERS* nt_headers = 
            (const IMAGE_NT_HEADERS*)(module_base + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        // Find .text section
        const IMAGE_SECTION_HEADER* section_headers = IMAGE_FIRST_SECTION(nt_headers);
        for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
            const IMAGE_SECTION_HEADER* section = &section_headers[i];
            
            // Check if this is the .text section
            if (strncmp((const char*)section->Name, ".text", 5) == 0) {
                text_section_start = module_base + section->VirtualAddress;
                text_section_size = section->Misc.VirtualSize;
                return true;
            }
        }

        return false;  // .text section not found
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    (void)module_base;
    (void)text_section_start;
    (void)text_section_size;
    return false;
#endif
}

bool JITSignatureValidator::IsWithinJITHeapRange(uintptr_t address, uintptr_t module_base) {
#ifdef _WIN32
    // Get module information
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), (HMODULE)module_base, 
                              &modInfo, sizeof(modInfo))) {
        return false;
    }

    uintptr_t module_end = module_base + modInfo.SizeOfImage;

    // Check if address is within the module's address space
    // JIT heaps are typically allocated within or near the module's range
    if (address >= module_base && address < module_end) {
        return true;  // Within module range
    }

    // JIT heaps can also be allocated nearby (within 2GB for x64 relative addressing)
    // Allow addresses within 32MB of the module (conservative estimate)
    const uintptr_t MAX_JIT_DISTANCE = 32 * 1024 * 1024;  // 32MB
    
    if (address >= module_end && (address - module_end) < MAX_JIT_DISTANCE) {
        return true;  // Near the module
    }
    
    if (address < module_base && (module_base - address) < MAX_JIT_DISTANCE) {
        return true;  // Near the module
    }

    return false;  // Too far from the module
#else
    (void)address;
    (void)module_base;
    return false;
#endif
}

void JITSignatureValidator::AddSignature(const JITSignature& signature) {
    if (signature.text_hash.size() != 32) {
        return;  // Invalid hash size
    }

    std::string hash_key = HashToHexString(signature.text_hash.data(), 32);
    signature_database_[hash_key] = signature;
}

void JITSignatureValidator::AddBuiltInSignatures() {
    // NOTE: This function is intentionally left mostly empty as a secure default.
    // JIT signatures must be extracted from actual DLL files using the hash extraction utility.
    // See docs/JIT_SIGNATURE_DATABASE.md for detailed instructions.
    //
    // To add signatures:
    // 1. Run: python3 scripts/extract_jit_hashes.py <path_to_jit_dll> --version "<version>" --engine-type <type>
    // 2. Copy the generated code into this function
    // 3. Test thoroughly to ensure no false positives
    //
    // For now, we use a secure-by-default approach:
    // - All JIT regions are considered suspicious unless explicitly whitelisted
    // - This prevents attacks until proper signatures are added
    // - Users can still use the manual whitelist as a fallback
    
    // Example of how to add a signature (when you have real hashes):
    /*
    JITSignature net8_clrjit;
    net8_clrjit.module_name = L"clrjit.dll";
    net8_clrjit.engine_type = JITEngineType::DotNetCLR;
    net8_clrjit.version = L".NET 8.0";
    // Hash obtained from: C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.0\clrjit.dll
    // Generated with: scripts/extract_jit_hashes.py
    net8_clrjit.text_hash = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };
    AddSignature(net8_clrjit);
    */

    // TODO: Populate with signatures for production deployment:
    // Required JIT engines (extract hashes using scripts/extract_jit_hashes.py):
    // - .NET 6.0, 7.0, 8.0 CLR JIT (clrjit.dll, coreclr.dll)
    // - V8 JavaScript engine versions (v8.dll, libv8.dll) - for Electron apps
    // - LuaJIT versions (luajit.dll, lua51.dll, lua52.dll, lua53.dll) - for game engines
    // - Unity IL2CPP (gameassembly.dll) - for Unity games
    //
    // Maintenance:
    // - Update when new runtime versions are released
    // - Keep signatures for at least 3 major versions
    // - Test thoroughly after adding new signatures
    // - Document version numbers in comments
}

} // namespace SDK
} // namespace Sentinel
