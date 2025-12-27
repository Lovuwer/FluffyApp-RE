// tests/TestHarness.hpp
#pragma once

#include <Sentinel/Core/Types.hpp>
#include <gtest/gtest.h>
#include <chrono>
#include <functional>
#include <vector>
#include <random>

namespace Sentinel::Testing {

// ============================================================================
// Timing Utilities
// ============================================================================

/**
 * Measure execution time of a function
 * @param func Function to measure
 * @param iterations Number of iterations
 * @return Average duration in nanoseconds
 */
template<typename Func>
double measureTime(Func&& func, int iterations = 1000) {
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        func();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
        end - start);
    
    return static_cast<double>(duration.count()) / iterations;
}

/**
 * Check if timing variance is within acceptable range (constant-time test)
 * @param times Vector of timing measurements
 * @param max_variance_percent Maximum acceptable variance (e.g., 10.0 for 10%)
 * @return True if variance is acceptable
 */
bool isConstantTime(const std::vector<double>& times, 
                    double max_variance_percent = 10.0);

// ============================================================================
// Memory Utilities
// ============================================================================

/**
 * Check if memory region contains only zeros
 */
bool isZeroed(const void* data, size_t size);

/**
 * Fill memory with pattern for testing
 */
void fillPattern(void* data, size_t size, uint8_t pattern = 0xAA);

/**
 * Allocate memory that will fault on access after free
 * (Uses guard pages where supported)
 */
class GuardedBuffer {
public: 
    explicit GuardedBuffer(size_t size);
    ~GuardedBuffer();
    
    void* data() { return m_data; }
    const void* data() const { return m_data; }
    size_t size() const { return m_size; }
    
    // Disable copy
    GuardedBuffer(const GuardedBuffer&) = delete;
    GuardedBuffer& operator=(const GuardedBuffer&) = delete;
    
private: 
    void* m_data;
    size_t m_size;
    void* m_allocation;
};

// ============================================================================
// Random Data Generation
// ============================================================================

/**
 * Generate random bytes for testing
 */
ByteBuffer randomBytes(size_t size);

/**
 * Generate random string
 */
std::string randomString(size_t length);

// ============================================================================
// Test Fixtures
// ============================================================================

/**
 * Base fixture for crypto tests
 */
class CryptoTestFixture : public ::testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;
    
    ByteBuffer generateKey(size_t size = 32);
    ByteBuffer generateData(size_t size = 1024);
};

/**
 * Base fixture for timing-sensitive tests
 */
class TimingTestFixture : public ::testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;
    
    // Warm up CPU to stabilize timing
    void warmUp();
    
    // Set CPU affinity to reduce jitter
    void pinToCore(int core = 0);
};

// ============================================================================
// Adversarial Test Helpers
// ============================================================================

/**
 * Bit flipper for tampering tests
 */
class BitFlipper {
public:
    /**
     * Flip single bit at position
     */
    static void flipBit(ByteBuffer& data, size_t bit_position);
    
    /**
     * Flip random bit
     */
    static size_t flipRandomBit(ByteBuffer& data);
    
    /**
     * Iterate all single-bit flips
     */
    static void forEachBitFlip(
        const ByteBuffer& original,
        std::function<void(const ByteBuffer& modified, size_t bit)> callback);
};

/**
 * Fuzzer for input validation tests
 */
class SimpleFuzzer {
public:
    explicit SimpleFuzzer(uint64_t seed = 0);
    
    ByteBuffer generate(size_t min_size, size_t max_size);
    
    // Generate edge-case inputs
    std::vector<ByteBuffer> generateEdgeCases();
    
private:
    std::mt19937_64 m_rng;
};

// ============================================================================
// Assertion Helpers
// ============================================================================

#define ASSERT_CONSTANT_TIME(times, max_var) \
    ASSERT_TRUE(::Sentinel::Testing::isConstantTime(times, max_var)) \
        << "Timing variance exceeds " << max_var << "%"

#define ASSERT_ZEROED(data, size) \
    ASSERT_TRUE(::Sentinel::Testing::isZeroed(data, size)) \
        << "Memory not properly zeroed"

#define ASSERT_CRYPTO_SUCCESS(result) \
    ASSERT_TRUE((result).isSuccess()) \
        << "Crypto operation failed: " << static_cast<int>((result).error())

} // namespace Sentinel::Testing
