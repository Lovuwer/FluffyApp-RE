# Sentinel Test Harness

## Overview

The Sentinel Test Harness provides specialized utilities for security testing including mock objects, timing utilities, and adversarial test helpers. This library is designed specifically for testing cryptographic operations, memory safety, and tamper resistance.

## Features

### Timing Utilities
- **`measureTime()`** - Measure execution time of functions with high precision
- **`isConstantTime()`** - Verify constant-time execution to prevent timing side-channels
- **`ASSERT_CONSTANT_TIME()`** - Assertion macro for constant-time verification

### Memory Utilities
- **`isZeroed()`** - Check if memory region contains only zeros
- **`fillPattern()`** - Fill memory with test patterns
- **`GuardedBuffer`** - Allocate memory with guard pages to detect buffer overflows
- **`ASSERT_ZEROED()`** - Assertion macro for zero-memory verification

### Random Data Generation
- **`randomBytes()`** - Generate random byte buffers for testing
- **`randomString()`** - Generate random alphanumeric strings

### Test Fixtures
- **`CryptoTestFixture`** - Base fixture for cryptographic tests with key/data generation
- **`TimingTestFixture`** - Base fixture for timing-sensitive tests with CPU warm-up

### Adversarial Test Helpers
- **`BitFlipper`** - Flip bits in data to test tampering detection
  - `flipBit()` - Flip a specific bit
  - `flipRandomBit()` - Flip a random bit
  - `forEachBitFlip()` - Test all single-bit corruptions
- **`SimpleFuzzer`** - Generate edge-case inputs for validation testing
  - `generate()` - Generate random data within size range
  - `generateEdgeCases()` - Generate boundary-case inputs

### Assertion Macros
- **`ASSERT_CRYPTO_SUCCESS(result)`** - Assert cryptographic operation succeeded
- **`ASSERT_ZEROED(data, size)`** - Assert memory is properly zeroed
- **`ASSERT_CONSTANT_TIME(times, max_var)`** - Assert timing variance is acceptable

## Usage Examples

### Basic Memory Testing

```cpp
#include "TestHarness.hpp"

TEST(MyTest, SecureZeroingWorks) {
    ByteBuffer buffer(256);
    
    // Fill with pattern
    fillPattern(buffer.data(), buffer.size(), 0xAA);
    
    // Zero the buffer
    secureZero(buffer.data(), buffer.size());
    
    // Verify it's zeroed
    ASSERT_ZEROED(buffer.data(), buffer.size());
}
```

### Tampering Detection Testing

```cpp
#include "TestHarness.hpp"

TEST(HMAC, DetectsAllSingleBitCorruptions) {
    ByteBuffer key = randomBytes(32);
    ByteBuffer data = randomBytes(128);
    
    HMAC hmac(key, HashAlgorithm::SHA256);
    auto mac = hmac.compute(data);
    ASSERT_CRYPTO_SUCCESS(mac);
    
    // Test all 256 single-bit corruptions
    int detectedCount = 0;
    BitFlipper::forEachBitFlip(mac.value(), [&](const ByteBuffer& tampered, size_t bit) {
        auto result = hmac.verify(data, tampered);
        if (result.isSuccess() && !result.value()) {
            detectedCount++;
        }
    });
    
    EXPECT_EQ(detectedCount, 256) << "All bit flips should be detected";
}
```

### Constant-Time Verification

```cpp
#include "TestHarness.hpp"

TEST(Crypto, ConstantTimeComparison) {
    std::vector<double> times;
    
    // Measure timing for various inputs
    for (int i = 0; i < 100; i++) {
        auto time = measureTime([&]() {
            constantTimeCompare(buffer1, buffer2);
        }, 1000);
        times.push_back(time);
    }
    
    // Verify timing variance is acceptable (< 10%)
    ASSERT_CONSTANT_TIME(times, 10.0);
}
```

### Using Test Fixtures

```cpp
#include "TestHarness.hpp"

class MyCryptoTest : public CryptoTestFixture {
protected:
    void TestEncryption() {
        auto key = generateKey(32);
        auto plaintext = generateData(1024);
        
        // Use key and plaintext for testing...
    }
};

TEST_F(MyCryptoTest, EncryptionWorks) {
    TestEncryption();
}
```

### Performance Benchmarking

```cpp
#include "TestHarness.hpp"

TEST(Performance, HashingSpeed) {
    ByteBuffer data(1024 * 1024);  // 1MB
    fillPattern(data.data(), data.size(), 0xAA);
    
    HashEngine hasher(HashAlgorithm::SHA256);
    
    auto avg_time_ns = measureTime([&]() {
        hasher.hash(data);
    }, 100);  // 100 iterations
    
    double mb_per_sec = (1.0 / (avg_time_ns / 1e9));
    std::cout << "Hashing speed: " << mb_per_sec << " MB/s" << std::endl;
}
```

### Fuzzing with Edge Cases

```cpp
#include "TestHarness.hpp"

TEST(Parser, HandlesEdgeCases) {
    SimpleFuzzer fuzzer(12345);  // Fixed seed for reproducibility
    
    auto edgeCases = fuzzer.generateEdgeCases();
    
    for (const auto& testCase : edgeCases) {
        auto result = parseInput(testCase);
        // Verify parser handles edge cases gracefully
        EXPECT_TRUE(result.isSuccess() || result.error() == ErrorCode::InvalidArgument);
    }
}
```

## Integration

The test harness is automatically linked to all test executables via CMake:

```cmake
target_link_libraries(MyTests
    PRIVATE
        SentinelCore
        SentinelTestHarness
        gtest
        gtest_main
)
```

Simply include the header in your test files:

```cpp
#include "TestHarness.hpp"

using namespace Sentinel::Testing;
```

## Cross-Platform Support

The test harness supports:
- **Windows**: Uses `VirtualAlloc` for GuardedBuffer
- **Linux/POSIX**: Uses `mmap` for GuardedBuffer
- **macOS**: Uses `mmap` for GuardedBuffer

Platform-specific features are automatically selected at compile time.

## Security Testing Best Practices

### 1. Test Tampering Detection
Always verify that security mechanisms detect tampering:

```cpp
// Test that HMAC detects all single-bit corruptions
BitFlipper::forEachBitFlip(mac, [&](const ByteBuffer& tampered, size_t bit) {
    EXPECT_FALSE(hmac.verify(data, tampered).value());
});
```

### 2. Verify Constant-Time Operations
Prevent timing side-channels:

```cpp
// Verify comparison is constant-time
ASSERT_CONSTANT_TIME(timings, 10.0);  // < 10% variance
```

### 3. Ensure Proper Memory Zeroing
Verify sensitive data is cleared:

```cpp
secureZero(sensitiveData.data(), sensitiveData.size());
ASSERT_ZEROED(sensitiveData.data(), sensitiveData.size());
```

### 4. Use Random Test Data
Use cryptographically random test data:

```cpp
ByteBuffer testData = randomBytes(1024);
// More realistic than deterministic patterns
```

## Files

- **`tests/TestHarness.hpp`** - Public interface
- **`tests/TestHarness.cpp`** - Implementation
- **`tests/Core/test_harness.cpp`** - Meta-tests and examples

## License

Copyright (c) 2024 Sentinel Security. All rights reserved.
