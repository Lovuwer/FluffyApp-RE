#pragma once

#include <string>

// Forward declare Sentinel SDK types when enabled
#ifdef SENTINEL_SDK_ENABLED
namespace Sentinel { namespace SDK { struct ViolationEvent; } }
using ViolationEvent = Sentinel::SDK::ViolationEvent;
#else
// Dummy type when SDK not enabled
struct ViolationEvent {};
#endif

namespace SentinelFlappy3D {

// Forward declare for friend
#ifdef SENTINEL_SDK_ENABLED
bool SentinelViolationHandlerFriend(const ViolationEvent* event, void* userData);
#endif

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
    static bool ViolationHandler(const ViolationEvent* event, void* userData);
    
    // Friend the global handler so it can access private members
#ifdef SENTINEL_SDK_ENABLED
    friend bool SentinelViolationHandlerFriend(const ViolationEvent* event, void* userData);
#endif
};

} // namespace SentinelFlappy3D
