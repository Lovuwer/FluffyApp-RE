#include "SentinelIntegration.hpp"
#include <iostream>

// Include Sentinel SDK if enabled
#ifdef SENTINEL_SDK_ENABLED
#include <SentinelSDK.hpp>
using namespace Sentinel::SDK;

// Forward declare to avoid namespace collision
static bool SentinelViolationHandler(const ViolationEvent* event, void* userData);
#endif

namespace SentinelFlappy3D {

SentinelIntegration::SentinelIntegration()
    : m_initialized(false)
    , m_violationCount(0) {
}

SentinelIntegration::~SentinelIntegration() {
    Shutdown();
}

bool SentinelIntegration::Initialize() {
    std::cout << "[SentinelIntegration] Initialize() called" << std::endl;
    
#ifdef SENTINEL_SDK_ENABLED
    try {
        // Create configuration with defaults
        Configuration config = Configuration::Default();
        
        // Configure basic settings
        config.game_id = "sentinelflappy3d";
        config.license_key = "DEMO-LICENSE-KEY";  // Demo license
        config.features = DetectionFeatures::Standard;
        config.default_action = ResponseAction::Default;
        
        // Set up violation callback
        config.violation_callback = SentinelViolationHandler;
        config.callback_user_data = this;
        
        // Enable debug mode for development
        config.debug_mode = true;
        config.log_path = "/tmp/sentinelflappy3d.log";
        
        // Performance tuning - lightweight for game
        config.heartbeat_interval_ms = 1000;       // Check every second
        config.integrity_scan_interval_ms = 5000;   // Full scan every 5 seconds
        
        std::cout << "[SentinelIntegration] Initializing Sentinel SDK..." << std::endl;
        std::cout << "[SentinelIntegration] Game ID: " << config.game_id << std::endl;
        std::cout << "[SentinelIntegration] Features: Standard" << std::endl;
        
        // Initialize SDK
        ErrorCode result = Sentinel::SDK::Initialize(&config);
        
        if (result == ErrorCode::Success) {
            m_initialized = true;
            std::cout << "[SentinelIntegration] ✓ SDK initialized successfully!" << std::endl;
            return true;
        } else {
            std::cerr << "[SentinelIntegration] ✗ SDK initialization failed: " 
                      << static_cast<int>(result) << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "[SentinelIntegration] Exception during initialization: " 
                  << e.what() << std::endl;
        return false;
    }
#else
    // Stub implementation when SDK is not enabled
    std::cout << "[SentinelIntegration] SDK not compiled in - using stub" << std::endl;
    m_initialized = true;
    return true;
#endif
}

bool SentinelIntegration::Update() {
    if (!m_initialized) {
        return false;
    }
    
#ifdef SENTINEL_SDK_ENABLED
    try {
        // Lightweight per-frame update
        ErrorCode result = Sentinel::SDK::Update();
        return (result == ErrorCode::Success || result == ErrorCode::NotInitialized);
    } catch (const std::exception& e) {
        std::cerr << "[SentinelIntegration] Exception during update: " 
                  << e.what() << std::endl;
        return false;
    }
#else
    // Stub - always success
    return true;
#endif
}

void SentinelIntegration::Shutdown() {
    if (!m_initialized) {
        return;
    }
    
    std::cout << "[SentinelIntegration] Shutdown() called" << std::endl;
    std::cout << "[SentinelIntegration] Total violations detected: " << m_violationCount << std::endl;
    
#ifdef SENTINEL_SDK_ENABLED
    try {
        Sentinel::SDK::Shutdown();
        std::cout << "[SentinelIntegration] ✓ SDK shutdown complete" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[SentinelIntegration] Exception during shutdown: " 
                  << e.what() << std::endl;
    }
#endif
    
    m_initialized = false;
}

bool SentinelIntegration::ViolationHandler(const ViolationEvent* event, void* userData) {
    // This method is never called directly, just for interface compliance
    (void)event;
    (void)userData;
    return true;
}

} // namespace SentinelFlappy3D

// Global handler outside namespace
#ifdef SENTINEL_SDK_ENABLED
static bool SentinelViolationHandler(const ViolationEvent* event, void* userData) {
    return SentinelFlappy3D::SentinelViolationHandlerFriend(event, userData);
}

bool SentinelFlappy3D::SentinelViolationHandlerFriend(const ViolationEvent* event, void* userData) {
    SentinelIntegration* self = static_cast<SentinelIntegration*>(userData);
    
    if (self && event) {
        self->m_violationCount++;
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "VIOLATION DETECTED #" << self->m_violationCount << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Type: " << static_cast<int>(event->type) << std::endl;
        std::cout << "Severity: " << static_cast<int>(event->severity) << std::endl;
        std::cout << "Details: " << event->details << std::endl;
        std::cout << "========================================\n" << std::endl;
    }
    
    // Return true to continue game, false to terminate
    return true;
}
#endif
