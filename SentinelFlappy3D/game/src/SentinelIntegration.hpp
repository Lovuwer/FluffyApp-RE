#pragma once

#include <string>

namespace SentinelFlappy3D {

/**
 * Wrapper class for Sentinel SDK integration
 * 
 * Manages SDK lifecycle (Initialize, Update, Shutdown) and provides
 * a clean interface for the game to interact with the anti-cheat system.
 */
class SentinelIntegration {
public:
    SentinelIntegration();
    ~SentinelIntegration();

    // Initialize SDK with game configuration
    // Returns true on success, false on failure (game continues in degraded mode)
    bool Initialize();

    // Update SDK (call once per frame from game loop)
    // Returns true on success, false if SDK encountered an error
    bool Update();

    // Shutdown SDK cleanly
    void Shutdown();

    // Check if SDK is currently active
    bool IsInitialized() const { return m_initialized; }

    // Get violation count (for debugging/monitoring)
    int GetViolationCount() const { return m_violationCount; }

private:
    bool m_initialized;
    int m_violationCount;

    // Violation callback (static for C API compatibility)
    static bool ViolationHandler(const void* event, void* userData);
};

} // namespace SentinelFlappy3D
