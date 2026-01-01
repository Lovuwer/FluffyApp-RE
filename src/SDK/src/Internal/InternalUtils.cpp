/**
 * Sentinel SDK - Internal Utilities Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "Internal/Context.hpp"
#include "Internal/Whitelist.hpp"
#include "DiversityEngine.hpp"
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>

#ifdef _WIN32
#include <Windows.h>
#include <intrin.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <net/if.h>
#endif

namespace Sentinel {
namespace SDK {

namespace Internal {

/**
 * Generate a hardware fingerprint based on system characteristics
 */
std::string GenerateHardwareId() {
    // Diversity padding - varies function prologue across builds
    SENTINEL_DIVERSITY_PADDING(__LINE__);
    
    std::stringstream ss;
    
#ifdef _WIN32
    // Get CPU information
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    ss << std::hex << std::setfill('0');
    ss << std::setw(8) << cpuInfo[0];
    ss << std::setw(8) << cpuInfo[3];
    
    // Get volume serial number
    DWORD volumeSerial = 0;
    GetVolumeInformationA("C:\\", nullptr, 0, &volumeSerial, nullptr, nullptr, nullptr, 0);
    ss << std::setw(8) << volumeSerial;
#else
    // Linux: Use machine ID or hostname
    ss << std::hex << std::setfill('0');
    ss << std::setw(16) << gethostid();
#endif
    
    return ss.str();
}

/**
 * Generate a unique session token
 */
std::string GenerateSessionToken() {
    // Diversity padding - varies function prologue across builds
    SENTINEL_DIVERSITY_PADDING(__LINE__);
    
    // Use random device for cryptographically secure randomness
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    
    // Generate token from timestamp + random data
    auto now = std::chrono::high_resolution_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    uint64_t random1 = dis(gen);
    uint64_t random2 = dis(gen);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(16) << timestamp;
    ss << std::setw(16) << random1;
    ss << std::setw(16) << random2;
    
    return ss.str();
}

} // namespace Internal
} // namespace SDK
} // namespace Sentinel
