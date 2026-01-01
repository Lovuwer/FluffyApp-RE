# String Obfuscation Framework

## Overview

The String Obfuscation Framework provides compile-time string encryption to prevent static analysis via string search. This is critical for anti-cheat systems where revealing string literals can expose detection logic to attackers.

## Problem Statement

Detection code contains string literals that reveal what is being detected. Attackers can search the binary for strings like "speedhack", "aimbot", or specific cheat names and immediately locate detection code. Tools like `strings`, FLOSS, and IDA's string view can enumerate every readable string in seconds.

## Solution

The framework encrypts strings at compile time using XOR encryption with per-build random keys. Strings are only decrypted at runtime immediately before use, and the plaintext is cleared from memory immediately after use.

## Features

- **Compile-Time Encryption**: Strings are encrypted during compilation using template metaprogramming
- **Per-Build Variation**: Encryption keys vary per build using `__TIME__`, `__DATE__`, and `__COUNTER__`, preventing universal decryptors
- **Automatic Memory Cleanup**: RAII wrapper ensures decrypted strings are securely zeroed when no longer needed
- **High Performance**: Decryption adds less than 1 microsecond per string access
- **Easy to Use**: Simple macro-based API

## Usage

### Basic Usage

```cpp
#include <Sentinel/Core/ObfuscatedString.hpp>

// Obfuscate a string literal
auto obfuscated = OBFUSCATE("sensitive string");

// Decrypt when needed
std::string plaintext = obfuscated.decrypt();
```

### RAII Secure String (Recommended)

```cpp
#include <Sentinel/Core/ObfuscatedString.hpp>

// Create obfuscated string with automatic cleanup
auto secure = OBFUSCATE_STR("sensitive data");

// Use directly
std::cout << secure.c_str() << std::endl;

// Or get as std::string
std::string str = secure.str();

// Memory is automatically zeroed when secure goes out of scope
```

### Detection Code Example

```cpp
#include <Sentinel/Core/ObfuscatedString.hpp>

void detectSpeedhack() {
    // Obfuscate detection-related strings
    auto detection_name = OBFUSCATE_STR("speedhack");
    auto signature = OBFUSCATE_STR("SpeedHack.dll");
    
    // Use in detection logic
    if (checkForModule(signature.c_str())) {
        logDetection(detection_name.c_str());
    }
    
    // Plaintext is automatically cleared when function exits
}
```

### Multiple Strings

```cpp
void performDetection() {
    auto cheat1 = OBFUSCATE_STR("CheatEngine");
    auto cheat2 = OBFUSCATE_STR("ArtMoney");
    auto cheat3 = OBFUSCATE_STR("GameGuardian");
    
    // Each string has a unique encryption key
    // due to __COUNTER__ in the macro
}
```

## API Reference

### Macros

#### `OBFUSCATE(str)`

Obfuscates a string literal at compile time.

**Parameters:**
- `str`: String literal to obfuscate

**Returns:** `ObfuscatedString<N, Seed>` object

**Example:**
```cpp
auto obf = OBFUSCATE("secret");
std::string plain = obf.decrypt();
```

#### `OBFUSCATE_STR(str)`

Obfuscates a string with automatic RAII cleanup.

**Parameters:**
- `str`: String literal to obfuscate

**Returns:** `SecureString` object that automatically zeros memory on destruction

**Example:**
```cpp
auto secure = OBFUSCATE_STR("secret");
std::cout << secure.c_str() << std::endl;
// Memory zeroed when secure goes out of scope
```

### Classes

#### `ObfuscatedString<N, Seed>`

Template class that holds an encrypted string.

**Methods:**
- `std::string decrypt() const`: Decrypt and return the string
- `const char* data() const`: Get encrypted data pointer (for testing)
- `size_t length() const`: Get string length (excluding null terminator)

#### `SecureString`

RAII wrapper for automatic memory cleanup.

**Methods:**
- `const std::string& str() const`: Get decrypted string
- `const char* c_str() const`: Get C-string pointer
- `size_t length() const`: Get string length
- `bool empty() const`: Check if string is empty

**Features:**
- Automatically zeros memory on destruction
- Move-only (no copy to prevent plaintext duplication)
- Implicit conversion to `std::string`

## Performance

- **Decryption Time**: < 1 microsecond per string access
- **Compile-Time Overhead**: Minimal, encryption happens during compilation
- **Runtime Memory**: Only plaintext during active use
- **Binary Size Impact**: Negligible

## Security Guarantees

### Build-to-Build Variation

Encryption keys vary between builds using:
- Compilation time (`__TIME__`)
- Compilation date (`__DATE__`)
- Per-instance counter (`__COUNTER__`)

This prevents attackers from creating universal decryption tools.

### Memory Safety

- Plaintext exists only when actively being used
- Automatic zeroing prevents memory dumps from revealing sensitive strings
- Move-only semantics prevent accidental plaintext duplication

### Static Analysis Protection

- No plaintext strings in binary
- Each string has unique encryption key
- XOR encryption with pseudo-random keystream

## Best Practices

### DO

✓ Use `OBFUSCATE_STR` for automatic memory cleanup  
✓ Apply to detection-related strings (cheat names, signatures, API names)  
✓ Limit plaintext scope - decrypt only when needed  
✓ Use immediately after decryption  

### DON'T

✗ Store decrypted strings long-term  
✗ Copy `SecureString` objects (use move instead)  
✗ Use for non-sensitive strings (adds unnecessary overhead)  
✗ Rely on this alone - use as part of defense-in-depth strategy  

## Examples

### Error Messages

```cpp
void reportError(ErrorCode code) {
    auto msg = OBFUSCATE_STR("Detection violation detected");
    logError(code, msg.c_str());
}
```

### Cheat Detection Signatures

```cpp
bool detectCheatEngine() {
    auto process_name = OBFUSCATE_STR("cheatengine");
    auto window_name = OBFUSCATE_STR("Cheat Engine");
    
    return findProcess(process_name.c_str()) ||
           findWindow(window_name.c_str());
}
```

### Module Names

```cpp
bool isBlacklistedModule(const char* module) {
    auto blacklist = {
        OBFUSCATE_STR("speedhack.dll"),
        OBFUSCATE_STR("aimbot.dll"),
        OBFUSCATE_STR("wallhack.dll")
    };
    
    for (const auto& entry : blacklist) {
        if (strcmp(module, entry.c_str()) == 0) {
            return true;
        }
    }
    return false;
}
```

## Limitations

1. **Not True Encryption**: Uses XOR cipher which is vulnerable to known-plaintext attacks
2. **Runtime Exposure**: Plaintext exists in memory during use
3. **Not Anti-Debug**: Memory can be inspected during execution
4. **Build-Time Dependency**: Keys change with each build

## Future Enhancements

- Add stronger encryption algorithms (AES)
- Implement code virtualization for decryption routine
- Add anti-debugging checks during decryption
- Polymorphic decryption code per instance

## Testing

Run the test suite to verify functionality:

```bash
cd build
ctest -R test_obfuscated_string -V
```

Or run all Core tests:

```bash
./bin/CoreTests --gtest_filter=ObfuscatedString*
```

## References

- [Task 11: String and Constant Obfuscation Framework](https://github.com/Lovuwer/Sentinel-RE)
- Compile-time string encryption techniques
- C++20 template metaprogramming
- RAII memory safety patterns
