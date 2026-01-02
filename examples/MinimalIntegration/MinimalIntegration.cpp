/**
 * @file MinimalIntegration.cpp
 * @brief Minimal Sentinel SDK Integration - Under 10 Lines
 * 
 * This demonstrates the absolute minimum code required to integrate
 * the Sentinel SDK into a game. Perfect for rapid prototyping and
 * quick adoption by studios with limited engineering time.
 * 
 * Task 31: Studio Integration Interface
 * - Single function initialization
 * - Single function update
 * - Simple callback pattern
 * - Sensible defaults requiring no tuning
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <SentinelSDK.hpp>
#include <iostream>

// Optional: Violation callback (can be nullptr for silent monitoring)
bool SENTINEL_CALL OnViolation(const Sentinel::SDK::ViolationEvent* event, void*) {
    std::cout << "Security violation detected: " << event->details << std::endl;
    return true;  // Continue monitoring
}

int main() {
    // ============================================================================
    // MINIMAL INTEGRATION - 8 LINES OF CODE
    // ============================================================================
    
    // Line 1-3: Configure with defaults
    auto config = Sentinel::SDK::Configuration::Default();
    config.license_key = "YOUR-LICENSE-KEY";
    config.game_id = "your-game-id";
    
    // Line 4: Optional callback (can be omitted)
    config.violation_callback = OnViolation;
    
    // Line 5: Initialize
    if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) {
        return 1;  // Initialization failed
    }
    
    // Line 6-7: Game loop
    bool game_running = true;
    while (game_running) {
        Sentinel::SDK::Update();  // Call once per frame
        
        // Your game code here
        // ...
        
        // Exit after some condition
        game_running = false;
    }
    
    // Line 8: Cleanup
    Sentinel::SDK::Shutdown();
    
    return 0;
}
