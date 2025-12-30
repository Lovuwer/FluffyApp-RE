/**
 * Sentinel SDK - Heartbeat Thread Watchdog Implementation
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * TASK-07: Heartbeat Thread Watchdog
 */

#include "Watchdog.hpp"

namespace Sentinel {
namespace SDK {

Watchdog::Watchdog() {
    // Initialize with current time
    last_heartbeat_tick.store(GetCurrentTimeMs(), std::memory_order_relaxed);
}

void Watchdog::Ping() {
    // Update last heartbeat tick to current time
    last_heartbeat_tick.store(GetCurrentTimeMs(), std::memory_order_relaxed);
}

bool Watchdog::IsAlive(uint64_t max_age_ms) const {
    uint64_t current_time = GetCurrentTimeMs();
    uint64_t last_tick = last_heartbeat_tick.load(std::memory_order_relaxed);
    
    // Check if the time since last ping is within the allowed threshold
    uint64_t elapsed = current_time - last_tick;
    return elapsed <= max_age_ms;
}

uint64_t Watchdog::GetTimeSinceLastPing() const {
    uint64_t current_time = GetCurrentTimeMs();
    uint64_t last_tick = last_heartbeat_tick.load(std::memory_order_relaxed);
    
    return current_time - last_tick;
}

uint64_t Watchdog::GetCurrentTimeMs() {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return static_cast<uint64_t>(duration.count());
}

} // namespace SDK
} // namespace Sentinel
