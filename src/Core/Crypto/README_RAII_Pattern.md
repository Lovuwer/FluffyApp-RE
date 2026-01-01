# RAII Pattern for OpenSSL Resource Management

## Overview

This directory implements RAII (Resource Acquisition Is Initialization) wrappers for OpenSSL contexts to prevent resource leaks that can accumulate during long game sessions and cause eventual crashes.

## Problem

OpenSSL context management traditionally uses manual cleanup:

```cpp
EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
// ... operations ...
EVP_CIPHER_CTX_free(ctx);  // Can be missed on error paths!
```

**Issues with manual cleanup:**
- Exception paths can leak contexts
- Early returns on error can skip cleanup
- Long sessions may accumulate leaks until memory exhaustion
- Crashes during competitive matches are unacceptable
- Anti-cheat components often get blamed for stability issues

## Solution: RAII Wrappers

The `OpenSSLRAII.hpp` header provides RAII wrappers that automatically clean up resources on scope exit:

```cpp
#include "OpenSSLRAII.hpp"

// Automatic cleanup on scope exit, even if exception thrown
EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
if (!ctx) {
    return ErrorCode::CryptoError;
}
// ... operations ...
// Automatic cleanup when ctx goes out of scope
```

## Available Wrappers

| Wrapper Type | OpenSSL Type | Used For | Cleanup Function |
|--------------|--------------|----------|------------------|
| `EVPCipherCtxPtr` | `EVP_CIPHER_CTX*` | Symmetric encryption (AES-GCM) | `EVP_CIPHER_CTX_free()` |
| `EVPMDCtxPtr` | `EVP_MD_CTX*` | Message digests (SHA-256/512) | `EVP_MD_CTX_free()` |
| `EVPMACCtxPtr` | `EVP_MAC_CTX*` | MAC contexts (HMAC) | `EVP_MAC_CTX_free()` |
| `EVPMACPtr` | `EVP_MAC*` | MAC algorithm objects | `EVP_MAC_free()` |

## Usage Examples

### AES Encryption

```cpp
#include "OpenSSLRAII.hpp"

Result<ByteBuffer> encryptData(ByteSpan plaintext) {
    EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return ErrorCode::CryptoError;
    }
    
    if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), key, iv, NULL) != 1) {
        return ErrorCode::EncryptionFailed;  // ctx cleaned up automatically
    }
    
    // ... more operations ...
    // No manual cleanup needed!
}
```

### Hashing

```cpp
#include "OpenSSLRAII.hpp"

Result<ByteBuffer> computeHash(ByteSpan data) {
    EVPMDCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        return ErrorCode::CryptoError;
    }
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    
    ByteBuffer hash(32);
    unsigned int len;
    EVP_DigestFinal_ex(ctx, hash.data(), &len);
    
    return hash;  // ctx cleaned up automatically
}
```

### HMAC

```cpp
#include "OpenSSLRAII.hpp"

Result<ByteBuffer> computeHMAC(ByteSpan key, ByteSpan data) {
    EVPMACPtr mac(EVP_MAC_fetch(NULL, "HMAC", NULL));
    if (!mac) {
        return ErrorCode::CryptoError;
    }
    
    EVPMACCtxPtr ctx(EVP_MAC_CTX_new(mac));
    if (!ctx) {
        return ErrorCode::CryptoError;
    }
    
    // ... HMAC operations ...
    // Both mac and ctx cleaned up automatically
}
```

## Benefits

✅ **Exception Safety**: Resources are freed even if exceptions are thrown  
✅ **No Memory Leaks**: Automatic cleanup on all code paths  
✅ **Easier Code Review**: Visual guarantee of cleanup  
✅ **Less Boilerplate**: No need for manual cleanup code  
✅ **Long Session Stability**: No accumulation of leaked contexts  

## Pattern for Future Resources

When adding new OpenSSL resource types, follow this pattern:

1. **Identify the resource type and its cleanup function**
   - e.g., `EVP_PKEY*` → `EVP_PKEY_free()`

2. **Add a type alias in `OpenSSLRAII.hpp`**
   ```cpp
   using EVPPKeyPtr = OpenSSLRAII<EVP_PKEY, EVP_PKEY_free>;
   ```

3. **Use the wrapper in your code**
   ```cpp
   EVPPKeyPtr pkey(EVP_PKEY_new());
   ```

4. **Update this documentation** with the new wrapper type

## Testing

RAII patterns are verified through:
- Unit tests with exception injection
- Valgrind leak detection
- Long-running stress tests
- Code review verification

## Files Converted

- ✅ `AESCipher.cpp` - AES-256-GCM encryption
- ✅ `HashEngine.cpp` - SHA-256/512 hashing  
- ✅ `HMAC.cpp` - HMAC computation
- ✅ `RSASigner.cpp` - RSA-PSS signing
- ✅ `PacketEncryption.cpp` (SDK) - Packet encryption

## References

- OpenSSL 3.0 EVP API Documentation
- C++ RAII Pattern (Effective C++ Item 13)
- Sentinel Security Task 18: Resource Safety
