/**
 * Sentinel SDK - Heartbeat Thread Watchdog
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * TASK-07: Heartbeat Thread Watchdog
 * 
 * Detects when the heartbeat thread has been terminated (e.g., via TerminateThread)
 * by tracking the last heartbeat ping time and checking if it exceeds a threshold.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <chrono>

namespace Sentinel {
namespace SDK {

/**
 * Watchdog for monitoring heartbeat thread liveness
 * 
 * The watchdog tracks the last time the heartbeat thread pinged it.
 * If the time since last ping exceeds a threshold, the thread is considered dead.
 */
class Watchdog {
public:
    /**
     * Constructor - initializes watchdog with current time
     */
    Watchdog();
    
    /**
     * Destructor
     */
    ~Watchdog() = default;
    
    /**
     * Ping the watchdog - called by heartbeat thread each iteration
     * Updates the last heartbeat tick to the current time
     */
    void Ping();
    
    /**
     * Check if the heartbeat thread is alive
     * 
     * @param max_age_ms Maximum allowed age (in milliseconds) since last ping
     * @return true if thread is alive (last ping within max_age_ms), false if dead
     */
    bool IsAlive(uint64_t max_age_ms) const;
    
    /**
     * Get the time (in milliseconds) since the last ping
     * 
     * @return Milliseconds elapsed since last ping
     */
    uint64_t GetTimeSinceLastPing() const;
    
private:
    /// Last heartbeat tick timestamp (milliseconds since epoch)
    std::atomic<uint64_t> last_heartbeat_tick;
    
    /**
     * Get current time in milliseconds since epoch
     */
    static uint64_t GetCurrentTimeMs();
};

} // namespace SDK
} // namespace Sentinel
