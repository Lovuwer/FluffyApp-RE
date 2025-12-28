/**
 * Sentinel SDK - Environment Detection Implementation
 * 
 * Detects cloud gaming platforms, VMs, and other environment characteristics
 * to adapt detection thresholds and prevent false positives.
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "Internal/EnvironmentDetection.hpp"

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include <mmdeviceapi.h>
#include <functiondiscoverykeys_devpkey.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <sys/utsname.h>
#endif

#include <cmath>
#include <algorithm>
#include <cstring>

namespace Sentinel {
namespace SDK {

EnvironmentDetector::EnvironmentDetector()
    : env_info_()
    , variance_history_index_(0)
    , variance_history_count_(0)
{
    std::memset(variance_history_, 0, sizeof(variance_history_));
}

EnvironmentDetector::~EnvironmentDetector() {
    Shutdown();
}

void EnvironmentDetector::Initialize() {
    // Reset state
    env_info_ = EnvironmentInfo();
    variance_history_index_ = 0;
    variance_history_count_ = 0;
    std::memset(variance_history_, 0, sizeof(variance_history_));
    
    // Detect environment
    DetectEnvironment();
}

void EnvironmentDetector::Shutdown() {
    // Nothing to clean up
}

void EnvironmentDetector::DetectEnvironment() {
    // Detect hypervisor/VM first
    env_info_.is_hypervisor_present = DetectHypervisor();
    
    // Detect cloud gaming platforms
    bool cloud_detected = false;
    
    // Check process-based detection
    if (DetectCloudGamingProcesses()) {
        cloud_detected = true;
    }
    
    // Check environment variable detection
    if (DetectCloudGamingEnvironment()) {
        cloud_detected = true;
    }
    
    // Check audio driver detection
    if (DetectCloudGamingAudioDrivers()) {
        cloud_detected = true;
    }
    
    // Classify environment type
    if (cloud_detected) {
        env_info_.type = EnvironmentType::CloudGaming;
    } else if (env_info_.is_hypervisor_present) {
        env_info_.type = EnvironmentType::VM;
    } else {
        env_info_.type = EnvironmentType::Local;
    }
}

const EnvironmentInfo& EnvironmentDetector::GetEnvironmentInfo() const {
    return env_info_;
}

EnvironmentType EnvironmentDetector::GetEnvironmentType() const {
    return env_info_.type;
}

float EnvironmentDetector::GetTimingVarianceThreshold() const {
    switch (env_info_.type) {
        case EnvironmentType::CloudGaming:
            return THRESHOLD_CLOUD;  // 50%
        case EnvironmentType::VM:
            return THRESHOLD_VM;     // 35%
        case EnvironmentType::Local:
        default:
            return THRESHOLD_LOCAL;  // 15%
    }
}

void EnvironmentDetector::UpdateTimingInstability(double variance_ratio) {
    // Store variance in circular buffer
    variance_history_[variance_history_index_] = std::abs(variance_ratio);
    variance_history_index_ = (variance_history_index_ + 1) % VARIANCE_HISTORY_SIZE;
    
    if (variance_history_count_ < VARIANCE_HISTORY_SIZE) {
        variance_history_count_++;
    }
    
    // Recalculate instability score
    CalculateTimingInstabilityScore();
}

bool EnvironmentDetector::IsCloudGaming() const {
    return env_info_.type == EnvironmentType::CloudGaming;
}

const char* EnvironmentDetector::GetEnvironmentString() const {
    switch (env_info_.type) {
        case EnvironmentType::CloudGaming:
            return "cloud";
        case EnvironmentType::VM:
            return "vm";
        case EnvironmentType::Local:
        default:
            return "local";
    }
}

bool EnvironmentDetector::DetectCloudGamingProcesses() {
#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    bool cloud_detected = false;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32FirstW(snapshot, &pe)) {
        do {
            std::wstring process_name(pe.szExeFile);
            // Convert to lowercase using a locale-safe approach
            for (auto& c : process_name) {
                if (c >= L'A' && c <= L'Z') {
                    c = c + (L'a' - L'A');
                }
            }
            
            // GeForce NOW detection
            if (process_name.find(L"geforcenow") != std::wstring::npos ||
                process_name.find(L"gfn") != std::wstring::npos) {
                env_info_.is_geforce_now = true;
                cloud_detected = true;
            }
            
            // Xbox Cloud Gaming (xCloud) detection
            if (process_name.find(L"xboxcloudgaming") != std::wstring::npos ||
                process_name.find(L"xcloud") != std::wstring::npos ||
                process_name.find(L"gamestreaming") != std::wstring::npos) {
                env_info_.is_xbox_cloud_gaming = true;
                cloud_detected = true;
            }
            
            // Amazon Luna detection
            if (process_name.find(L"luna") != std::wstring::npos) {
                env_info_.is_amazon_luna = true;
                cloud_detected = true;
            }
            
            // PlayStation Now detection
            if (process_name.find(L"playstationnow") != std::wstring::npos ||
                process_name.find(L"psnow") != std::wstring::npos) {
                env_info_.is_playstation_now = true;
                cloud_detected = true;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    return cloud_detected;
#else
    // Linux: check process list via /proc
    // Simplified for now
    return false;
#endif
}

bool EnvironmentDetector::DetectCloudGamingEnvironment() {
#ifdef _WIN32
    // GeForce NOW environment variable
    char buffer[256];
    if (GetEnvironmentVariableA("GFN_SDK_VERSION", buffer, sizeof(buffer)) > 0) {
        env_info_.is_geforce_now = true;
        return true;
    }
    
    if (GetEnvironmentVariableA("GEFORCE_NOW", buffer, sizeof(buffer)) > 0) {
        env_info_.is_geforce_now = true;
        return true;
    }
    
    // Xbox Cloud Gaming environment variable
    if (GetEnvironmentVariableA("XBOX_CLOUD_GAMING", buffer, sizeof(buffer)) > 0) {
        env_info_.is_xbox_cloud_gaming = true;
        return true;
    }
    
    if (GetEnvironmentVariableA("XCLOUD_ENABLED", buffer, sizeof(buffer)) > 0) {
        env_info_.is_xbox_cloud_gaming = true;
        return true;
    }
    
    // Amazon Luna environment variable
    if (GetEnvironmentVariableA("AMAZON_LUNA", buffer, sizeof(buffer)) > 0) {
        env_info_.is_amazon_luna = true;
        return true;
    }
    
    // PlayStation Now environment variable
    if (GetEnvironmentVariableA("PS_NOW", buffer, sizeof(buffer)) > 0) {
        env_info_.is_playstation_now = true;
        return true;
    }
    
    return false;
#else
    // Linux: check environment variables
    if (getenv("GFN_SDK_VERSION") != nullptr || getenv("GEFORCE_NOW") != nullptr) {
        env_info_.is_geforce_now = true;
        return true;
    }
    
    if (getenv("XBOX_CLOUD_GAMING") != nullptr || getenv("XCLOUD_ENABLED") != nullptr) {
        env_info_.is_xbox_cloud_gaming = true;
        return true;
    }
    
    if (getenv("AMAZON_LUNA") != nullptr) {
        env_info_.is_amazon_luna = true;
        return true;
    }
    
    if (getenv("PS_NOW") != nullptr) {
        env_info_.is_playstation_now = true;
        return true;
    }
    
    return false;
#endif
}

bool EnvironmentDetector::DetectCloudGamingAudioDrivers() {
#ifdef _WIN32
    // Note: Audio device enumeration requires COM initialization
    // For now, we'll skip this to avoid COM complexity
    // This can be implemented if needed by checking for:
    // - "Virtual Audio Cable" type devices
    // - Low-latency streaming audio drivers
    // - Cloud gaming specific audio device names
    return false;
#else
    return false;
#endif
}

bool EnvironmentDetector::DetectHypervisor() {
#ifdef _WIN32
    // Check CPUID leaf 0x1, ECX bit 31 (hypervisor present bit)
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    
    // Hypervisor present bit
    bool hypervisor_present = (cpuInfo[2] & (1 << 31)) != 0;
    
    return hypervisor_present;
#else
    // Linux: check /proc/cpuinfo for hypervisor flag
    // or check /sys/hypervisor/type
    struct utsname buffer;
    if (uname(&buffer) == 0) {
        std::string release(buffer.release);
        // Convert to lowercase using locale-safe approach
        for (auto& c : release) {
            if (c >= 'A' && c <= 'Z') {
                c = c + ('a' - 'A');
            }
        }
        
        if (release.find("vbox") != std::string::npos ||
            release.find("qemu") != std::string::npos ||
            release.find("kvm") != std::string::npos ||
            release.find("xen") != std::string::npos) {
            return true;
        }
    }
    
    // Check for hypervisor CPUID on x86_64
#ifdef __x86_64__
    uint32_t eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid"
                         : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "a"(1));
    return (ecx & (1 << 31)) != 0;
#endif
    
    return false;
#endif
}

void EnvironmentDetector::CalculateTimingInstabilityScore() {
    if (variance_history_count_ == 0) {
        env_info_.timing_instability_score = 0.0;
        return;
    }
    
    // Calculate average variance
    double sum = 0.0;
    for (size_t i = 0; i < variance_history_count_; i++) {
        sum += variance_history_[i];
    }
    double avg_variance = sum / variance_history_count_;
    
    // Normalize to 0.0 - 1.0 scale
    // High instability = average variance > 30%
    env_info_.timing_instability_score = std::min(1.0, avg_variance / HIGH_INSTABILITY_THRESHOLD);
    
    // If we detect high instability with consistent game behavior,
    // this indicates streaming (not cheating)
    // Cloud gaming typically shows 10-30% variance, while speed hacks show 25-1000%
    // High instability (>30% average) without other anomalies suggests cloud gaming
}

} // namespace SDK
} // namespace Sentinel
