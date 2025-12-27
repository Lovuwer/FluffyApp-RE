// tests/TestHarness.cpp

#include "TestHarness.hpp"
#include <Sentinel/Core/Crypto.hpp>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <pthread.h>
#endif

namespace Sentinel::Testing {

bool isConstantTime(const std::vector<double>& times, double max_variance_percent) {
    if (times.empty()) return true;
    
    double min_time = *std::min_element(times.begin(), times.end());
    double max_time = *std::max_element(times.begin(), times.end());
    
    if (max_time == 0) return true;
    
    double variance = ((max_time - min_time) / max_time) * 100.0;
    return variance <= max_variance_percent;
}

bool isZeroed(const void* data, size_t size) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; i++) {
        if (bytes[i] != 0) return false;
    }
    return true;
}

void fillPattern(void* data, size_t size, uint8_t pattern) {
    std::memset(data, pattern, size);
}

// GuardedBuffer implementation
GuardedBuffer::GuardedBuffer(size_t size) : m_size(size) {
    #ifdef _WIN32
    // Allocate with guard page after
    size_t pageSize = 4096;
    size_t totalPages = (size + pageSize - 1) / pageSize + 1;  // +1 for guard
    
    m_allocation = VirtualAlloc(nullptr, totalPages * pageSize,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m_allocation) {
        throw std::bad_alloc();
    }
    
    // Set last page as guard
    DWORD oldProtect;
    VirtualProtect(static_cast<uint8_t*>(m_allocation) + 
                  (totalPages - 1) * pageSize,
                  pageSize, PAGE_NOACCESS, &oldProtect);
    
    // Align data to end of usable region (so overflow hits guard)
    m_data = static_cast<uint8_t*>(m_allocation) + 
            (totalPages - 1) * pageSize - size;
    #else
    // POSIX implementation
    size_t pageSize = 4096;
    size_t totalPages = (size + pageSize - 1) / pageSize + 1;
    
    m_allocation = mmap(nullptr, totalPages * pageSize,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m_allocation == MAP_FAILED) {
        throw std::bad_alloc();
    }
    
    // Protect guard page
    mprotect(static_cast<uint8_t*>(m_allocation) + 
            (totalPages - 1) * pageSize,
            pageSize, PROT_NONE);
    
    m_data = static_cast<uint8_t*>(m_allocation) + 
            (totalPages - 1) * pageSize - size;
    #endif
}

GuardedBuffer::~GuardedBuffer() {
    #ifdef _WIN32
    VirtualFree(m_allocation, 0, MEM_RELEASE);
    #else
    size_t pageSize = 4096;
    size_t totalPages = (m_size + pageSize - 1) / pageSize + 1;
    munmap(m_allocation, totalPages * pageSize);
    #endif
}

ByteBuffer randomBytes(size_t size) {
    Crypto::SecureRandom rng;
    auto result = rng.generate(size);
    if (result.isFailure()) {
        // Fall back to insecure random for testing
        ByteBuffer data(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& b : data) {
            b = static_cast<uint8_t>(dis(gen));
        }
        return data;
    }
    return result.value();
}

std::string randomString(size_t length) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    
    std::string result;
    result.reserve(length);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    
    for (size_t i = 0; i < length; i++) {
        result += charset[dis(gen)];
    }
    
    return result;
}

// CryptoTestFixture
void CryptoTestFixture::SetUp() {
    // Could initialize crypto library here
}

void CryptoTestFixture::TearDown() {
    // Cleanup
}

ByteBuffer CryptoTestFixture::generateKey(size_t size) {
    return randomBytes(size);
}

ByteBuffer CryptoTestFixture::generateData(size_t size) {
    return randomBytes(size);
}

// TimingTestFixture
void TimingTestFixture::SetUp() {
    warmUp();
}

void TimingTestFixture::TearDown() {
    // Nothing special
}

void TimingTestFixture::warmUp() {
    // Perform dummy operations to warm up CPU caches
    volatile uint64_t sum = 0;
    for (int i = 0; i < 1000000; i++) {
        sum += i;
    }
    (void)sum;
}

void TimingTestFixture::pinToCore(int core) {
    #ifdef _WIN32
    SetThreadAffinityMask(GetCurrentThread(), 1ULL << core);
    #else
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    #endif
}

// BitFlipper
void BitFlipper::flipBit(ByteBuffer& data, size_t bit_position) {
    size_t byte_pos = bit_position / 8;
    size_t bit_offset = bit_position % 8;
    
    if (byte_pos < data.size()) {
        data[byte_pos] ^= (1 << bit_offset);
    }
}

size_t BitFlipper::flipRandomBit(ByteBuffer& data) {
    if (data.empty()) return 0;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, data.size() * 8 - 1);
    
    size_t bit = dis(gen);
    flipBit(data, bit);
    return bit;
}

void BitFlipper::forEachBitFlip(
    const ByteBuffer& original,
    std::function<void(const ByteBuffer&, size_t)> callback) {
    
    for (size_t bit = 0; bit < original.size() * 8; bit++) {
        ByteBuffer modified = original;
        flipBit(modified, bit);
        callback(modified, bit);
    }
}

// SimpleFuzzer
SimpleFuzzer::SimpleFuzzer(uint64_t seed) {
    if (seed == 0) {
        std::random_device rd;
        m_rng.seed(rd());
    } else {
        m_rng.seed(seed);
    }
}

ByteBuffer SimpleFuzzer::generate(size_t min_size, size_t max_size) {
    std::uniform_int_distribution<size_t> size_dist(min_size, max_size);
    size_t size = size_dist(m_rng);
    
    ByteBuffer data(size);
    std::uniform_int_distribution<int> byte_dist(0, 255);
    
    for (auto& b : data) {
        b = static_cast<uint8_t>(byte_dist(m_rng));
    }
    
    return data;
}

std::vector<ByteBuffer> SimpleFuzzer::generateEdgeCases() {
    std::vector<ByteBuffer> cases;
    
    // Empty
    cases.push_back({});
    
    // Single byte (all values)
    for (int i = 0; i < 256; i++) {
        cases.push_back({static_cast<uint8_t>(i)});
    }
    
    // Powers of 2 sizes
    for (size_t size = 1; size <= 4096; size *= 2) {
        cases.push_back(ByteBuffer(size, 0x00));  // All zeros
        cases.push_back(ByteBuffer(size, 0xFF));  // All ones
        cases.push_back(generate(size, size));     // Random
    }
    
    // Boundary sizes
    cases.push_back(ByteBuffer(255, 0xAA));
    cases.push_back(ByteBuffer(256, 0xAA));
    cases.push_back(ByteBuffer(65535, 0xBB));
    cases.push_back(ByteBuffer(65536, 0xBB));
    
    return cases;
}

} // namespace Sentinel::Testing
