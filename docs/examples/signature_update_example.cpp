/**
 * Sentinel SDK - Signature Update Example
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * This example demonstrates how to use the Detection Signature Update Mechanism
 * to dynamically update detection signatures without restarting the game.
 */

#include "Internal/SignatureManager.hpp"
#include "Network/UpdateClient.hpp"
#include <iostream>
#include <thread>
#include <chrono>

using namespace Sentinel::SDK;

// Example RSA public key (in production, load from secure storage)
const char* EXAMPLE_PUBLIC_KEY_PEM = R"(
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA...
-----END PUBLIC KEY-----
)";

int main() {
    std::cout << "Sentinel SDK - Signature Update Example\n";
    std::cout << "========================================\n\n";
    
    // ========================================================================
    // Step 1: Initialize Signature Manager
    // ========================================================================
    
    std::cout << "1. Initializing Signature Manager...\n";
    
    auto signature_manager = std::make_shared<SignatureManager>();
    
    // In production, load the public key from embedded resources or secure storage
    // For this example, we'll use a placeholder
    ByteBuffer public_key = {0x30, 0x82, 0x02, 0x22}; // Placeholder
    
    auto init_result = signature_manager->initialize(
        "./signature_cache",  // Cache directory
        public_key
    );
    
    if (init_result.isFailure()) {
        std::cerr << "Failed to initialize SignatureManager: "
                  << static_cast<int>(init_result.error()) << std::endl;
        return 1;
    }
    
    std::cout << "   ✓ Signature Manager initialized\n\n";
    
    // ========================================================================
    // Step 2: Configure and Initialize Update Client
    // ========================================================================
    
    std::cout << "2. Configuring Update Client...\n";
    
    UpdateClientConfig config;
    config.server_url = "https://api.sentinel.com";
    config.api_key = "demo_api_key_12345";
    config.game_id = "demo_game";
    config.check_interval = std::chrono::seconds(60);  // Check every minute for demo
    config.timeout = std::chrono::seconds(30);
    config.max_retries = 3;
    config.retry_delay = std::chrono::seconds(2);
    config.enable_pinning = false;  // Disabled for demo
    
    auto update_client = std::make_unique<UpdateClient>();
    
    auto client_init = update_client->initialize(config, signature_manager);
    if (client_init.isFailure()) {
        std::cerr << "Failed to initialize UpdateClient: "
                  << static_cast<int>(client_init.error()) << std::endl;
        return 1;
    }
    
    std::cout << "   ✓ Update Client configured\n\n";
    
    // ========================================================================
    // Step 3: Set Up Progress Callback
    // ========================================================================
    
    std::cout << "3. Setting up progress callback...\n";
    
    update_client->setProgressCallback([](UpdateStatus status, const std::string& message) {
        std::cout << "   [UPDATE] ";
        
        switch (status) {
            case UpdateStatus::Idle:
                std::cout << "IDLE: ";
                break;
            case UpdateStatus::Checking:
                std::cout << "CHECKING: ";
                break;
            case UpdateStatus::Downloading:
                std::cout << "DOWNLOADING: ";
                break;
            case UpdateStatus::Verifying:
                std::cout << "VERIFYING: ";
                break;
            case UpdateStatus::Applying:
                std::cout << "APPLYING: ";
                break;
            case UpdateStatus::Success:
                std::cout << "SUCCESS: ";
                break;
            case UpdateStatus::Failed:
                std::cout << "FAILED: ";
                break;
        }
        
        std::cout << message << std::endl;
    });
    
    std::cout << "   ✓ Progress callback configured\n\n";
    
    // ========================================================================
    // Step 4: Perform Manual Update Check
    // ========================================================================
    
    std::cout << "4. Checking for updates...\n";
    
    auto check_result = update_client->checkForUpdates(false);
    if (check_result.isSuccess()) {
        if (check_result.value()) {
            std::cout << "   ✓ Updates available!\n";
            
            // Download and apply
            std::cout << "   Downloading and applying updates...\n";
            auto apply_result = update_client->downloadAndApply();
            
            if (apply_result.isSuccess()) {
                std::cout << "   ✓ Updates applied successfully!\n\n";
            } else {
                std::cout << "   ✗ Failed to apply updates\n\n";
            }
        } else {
            std::cout << "   ✓ No updates available (already up-to-date)\n\n";
        }
    } else {
        std::cout << "   ✗ Failed to check for updates (network error)\n\n";
    }
    
    // ========================================================================
    // Step 5: Query Current Signatures
    // ========================================================================
    
    std::cout << "5. Querying current signatures...\n";
    
    auto stats = signature_manager->getStatistics();
    std::cout << "   Current Version: " << stats.current_version << "\n";
    std::cout << "   Total Signatures: " << stats.total_signatures << "\n";
    std::cout << "   Expired Signatures: " << stats.expired_signatures << "\n\n";
    
    // Get all memory pattern signatures
    auto memory_patterns = signature_manager->getSignaturesByType(
        SignatureType::MemoryPattern
    );
    
    std::cout << "   Memory Pattern Signatures: " << memory_patterns.size() << "\n";
    for (const auto& sig : memory_patterns) {
        std::cout << "     - " << sig.id << ": " << sig.name 
                  << " (v" << sig.version << ")\n";
    }
    std::cout << "\n";
    
    // ========================================================================
    // Step 6: Demonstrate Signature Usage
    // ========================================================================
    
    std::cout << "6. Using signatures for detection...\n";
    
    if (!memory_patterns.empty()) {
        const auto& first_sig = memory_patterns[0];
        
        std::cout << "   Example signature:\n";
        std::cout << "     ID: " << first_sig.id << "\n";
        std::cout << "     Name: " << first_sig.name << "\n";
        std::cout << "     Threat Family: " << first_sig.threat_family << "\n";
        std::cout << "     Severity: " << static_cast<int>(first_sig.severity) << "\n";
        std::cout << "     Pattern Size: " << first_sig.pattern_data.size() << " bytes\n";
        
        // In a real game, you would use the pattern for memory scanning:
        // scanner.scanMemory(first_sig.pattern_data, first_sig.pattern_mask);
        
        std::cout << "     (In production: scan memory using this pattern)\n\n";
    }
    
    // ========================================================================
    // Step 7: Start Auto-Update (Optional)
    // ========================================================================
    
    std::cout << "7. Starting automatic update checks...\n";
    
    auto auto_start = update_client->startAutoUpdate();
    if (auto_start.isSuccess()) {
        std::cout << "   ✓ Auto-update started (checking every 60 seconds)\n";
        std::cout << "   Running for 5 minutes...\n\n";
        
        // Let it run for a while
        std::this_thread::sleep_for(std::chrono::minutes(5));
        
        update_client->stopAutoUpdate();
        std::cout << "   ✓ Auto-update stopped\n\n";
    }
    
    // ========================================================================
    // Step 8: Show Final Statistics
    // ========================================================================
    
    std::cout << "8. Final statistics:\n";
    
    auto update_stats = update_client->getStatistics();
    std::cout << "   Total Updates: " << update_stats.total_updates << "\n";
    std::cout << "   Failed Updates: " << update_stats.failed_updates << "\n";
    std::cout << "   Current Version: " << update_stats.current_version << "\n";
    
    auto final_stats = signature_manager->getStatistics();
    std::cout << "   Active Signatures: " << final_stats.total_signatures << "\n\n";
    
    // ========================================================================
    // Done
    // ========================================================================
    
    std::cout << "Example completed successfully!\n";
    std::cout << "\nKey Takeaways:\n";
    std::cout << "  • Signatures update dynamically without game restart\n";
    std::cout << "  • Updates check every 60 seconds automatically\n";
    std::cout << "  • Network failures are handled gracefully\n";
    std::cout << "  • Signatures are cached locally for 24+ hours\n";
    std::cout << "  • All updates are cryptographically verified\n\n";
    
    return 0;
}
