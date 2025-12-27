/**
 * Sentinel SDK - Thread Whitelist Example
 * 
 * Demonstrates how to use the thread origin whitelist API
 * to prevent false positives from custom game engine threading.
 */

#include <SentinelSDK.hpp>
#include <iostream>

int main() {
    std::cout << "Sentinel SDK Thread Whitelist Example" << std::endl;
    std::cout << "=======================================" << std::endl;
    
    // Initialize SDK with default configuration
    auto config = Sentinel::SDK::Configuration::Default();
    config.license_key = "YOUR_LICENSE_KEY";
    config.game_id = "example_game";
    config.debug_mode = true;
    config.features = Sentinel::SDK::DetectionFeatures::ThreadMonitor;
    
    std::cout << "\nInitializing Sentinel SDK..." << std::endl;
    auto result = Sentinel::SDK::Initialize(&config);
    if (result != Sentinel::SDK::ErrorCode::Success) {
        std::cerr << "Failed to initialize SDK: " 
                  << static_cast<int>(result) << std::endl;
        return 1;
    }
    std::cout << "SDK initialized successfully!" << std::endl;
    
    // Add custom thread origin whitelists for your game engine
    std::cout << "\nAdding custom thread origin whitelists..." << std::endl;
    
    // Example 1: Game engine's job system
    result = Sentinel::SDK::WhitelistThreadOrigin(
        "GameEngine.dll",
        "Main game engine with custom job system"
    );
    if (result == Sentinel::SDK::ErrorCode::Success) {
        std::cout << "✓ Whitelisted GameEngine.dll" << std::endl;
    } else {
        std::cerr << "✗ Failed to whitelist GameEngine.dll" << std::endl;
    }
    
    // Example 2: Physics simulation threads
    result = Sentinel::SDK::WhitelistThreadOrigin(
        "PhysicsEngine.dll",
        "Physics simulation thread pool"
    );
    if (result == Sentinel::SDK::ErrorCode::Success) {
        std::cout << "✓ Whitelisted PhysicsEngine.dll" << std::endl;
    } else {
        std::cerr << "✗ Failed to whitelist PhysicsEngine.dll" << std::endl;
    }
    
    // Example 3: Audio processing threads
    result = Sentinel::SDK::WhitelistThreadOrigin(
        "AudioEngine.dll",
        "Audio processing and mixing threads"
    );
    if (result == Sentinel::SDK::ErrorCode::Success) {
        std::cout << "✓ Whitelisted AudioEngine.dll" << std::endl;
    } else {
        std::cerr << "✗ Failed to whitelist AudioEngine.dll" << std::endl;
    }
    
    std::cout << "\nWhitelist configuration complete!" << std::endl;
    std::cout << "\nBuilt-in whitelists include:" << std::endl;
    std::cout << "  - Windows thread pool (ntdll.dll, kernel32.dll)" << std::endl;
    std::cout << "  - .NET CLR threads (clr.dll, coreclr.dll)" << std::endl;
    std::cout << "  - JIT compilers (V8, Unity IL2CPP, LuaJIT)" << std::endl;
    
    std::cout << "\nRunning thread scan..." << std::endl;
    result = Sentinel::SDK::FullScan();
    if (result == Sentinel::SDK::ErrorCode::Success) {
        std::cout << "Thread scan completed - no suspicious threads detected!" << std::endl;
    } else {
        std::cout << "Thread scan detected potential threats" << std::endl;
    }
    
    // Optionally remove a whitelist entry
    std::cout << "\nRemoving PhysicsEngine.dll from whitelist (example)..." << std::endl;
    Sentinel::SDK::RemoveThreadOriginWhitelist("PhysicsEngine.dll");
    std::cout << "✓ Removed PhysicsEngine.dll" << std::endl;
    
    // Clean up
    std::cout << "\nShutting down SDK..." << std::endl;
    Sentinel::SDK::Shutdown();
    std::cout << "SDK shutdown complete" << std::endl;
    
    return 0;
}
