/**
 * @file main.cpp
 * @brief Dummy Game - Realistic SDK Integration Test
 * 
 * This is NOT a cheat testing application.
 * This is a realistic game that exercises Sentinel-RE SDK under real-world conditions
 * to discover false positives, performance issues, and integration problems.
 * 
 * RED-TEAM MINDSET: We're looking for where reality breaks theory.
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <SentinelSDK.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <cstring>
#include <random>
#include <vector>
#include <iomanip>

// Use SDK namespace for main API
using Sentinel::SDK::ErrorCode;
using Sentinel::SDK::Configuration;
using Sentinel::SDK::DetectionFeatures;
using Sentinel::SDK::ResponseAction;
using Sentinel::SDK::ViolationEvent;
using Sentinel::SDK::Severity;
using Sentinel::SDK::Statistics;
using Sentinel::SDK::Initialize;
using Sentinel::SDK::Shutdown;
using Sentinel::SDK::Update;
using Sentinel::SDK::FullScan;
using Sentinel::SDK::Pause;
using Sentinel::SDK::Resume;
using Sentinel::SDK::GetVersion;
using Sentinel::SDK::GetLastError;
using Sentinel::SDK::GetStatistics;
using Sentinel::SDK::CreateProtectedInt;
using Sentinel::SDK::SetProtectedInt;
using Sentinel::SDK::GetProtectedInt;
using Sentinel::SDK::DestroyProtectedValue;
using Sentinel::SDK::ProtectMemory;
using Sentinel::SDK::VerifyMemory;
using Sentinel::SDK::UnprotectMemory;
using Sentinel::SDK::GetSecureTime;
using Sentinel::SDK::GetSecureDeltaTime;
using Sentinel::SDK::ValidateTiming;
using Sentinel::SDK::EncryptPacket;
using Sentinel::SDK::DecryptPacket;
using Sentinel::SDK::GetPacketSequence;
using Sentinel::SDK::ValidatePacketSequence;

// Use Crypto types
using Sentinel::Crypto::SecureRandom;
using Sentinel::Crypto::HashEngine;
using Sentinel::Crypto::HashAlgorithm;
using Sentinel::Crypto::AESCipher;
using Sentinel::Crypto::HMAC;
using Sentinel::Byte;
using Sentinel::ByteSpan;
using Sentinel::ByteBuffer;

// ============================================================================
// Game State
// ============================================================================

struct GameState {
    std::atomic<bool> running{true};
    std::atomic<bool> paused{false};
    std::atomic<int> frame_count{0};
    std::atomic<int> player_health{100};
    std::atomic<int> player_score{0};
    std::atomic<float> position_x{0.0f};
    std::atomic<float> position_y{0.0f};
    
    // Protected values (using SDK)
    uint64_t protected_gold_handle{0};
    uint64_t protected_level_handle{0};
};

static GameState g_game_state;

// ============================================================================
// SDK Callback Handler
// ============================================================================

bool SENTINEL_CALL ViolationHandler(const ViolationEvent* event, void* /*user_data*/) {
    if (!event) return true;
    
    std::cout << "\n[SENTINEL VIOLATION DETECTED]" << std::endl;
    std::cout << "  Type: 0x" << std::hex << static_cast<uint32_t>(event->type) << std::dec << std::endl;
    std::cout << "  Severity: " << static_cast<int>(event->severity) << std::endl;
    std::cout << "  Timestamp: " << event->timestamp << " ms" << std::endl;
    std::cout << "  Module: " << event->module_name << std::endl;
    std::cout << "  Details: " << event->details << std::endl;
    std::cout << "  Address: 0x" << std::hex << event->address << std::dec << std::endl;
    
    // RED-TEAM OBSERVATION: Is this a false positive?
    if (event->severity == Severity::Info || event->severity == Severity::Warning) {
        std::cout << "  [NOTE] Continuing execution - low severity event" << std::endl;
        return true;  // Continue monitoring
    }
    
    // For high severity, log but continue for testing purposes
    std::cout << "  [ALERT] High severity event - in production this might trigger ban" << std::endl;
    return true;  // Continue monitoring for this test
}

// ============================================================================
// Crypto Testing Functions
// ============================================================================

void TestSecureRandom() {
    std::cout << "\n[TEST] SecureRandom..." << std::endl;
    
    try {
        SecureRandom rng;
        
        // Test byte generation
        auto bytes_result = rng.generate(32);
        if (bytes_result.isSuccess()) {
            std::cout << "  ✓ Generated 32 random bytes" << std::endl;
        } else {
            std::cout << "  ✗ Failed to generate random bytes" << std::endl;
        }
        
        // Test value generation
        auto int_result = rng.generateValue<uint64_t>();
        if (int_result.isSuccess()) {
            std::cout << "  ✓ Generated random uint64_t: " << int_result.value() << std::endl;
        }
        
        // Test AES key generation
        auto key_result = rng.generateAESKey();
        if (key_result.isSuccess()) {
            std::cout << "  ✓ Generated AES-256 key" << std::endl;
        }
        
    } catch (const std::exception& ex) {
        std::cout << "  ✗ Exception: " << ex.what() << std::endl;
    }
}

void TestHashEngine() {
    std::cout << "\n[TEST] HashEngine..." << std::endl;
    
    try {
        HashEngine hasher(HashAlgorithm::SHA256);
        
        std::string test_data = "Sentinel SDK Test Data";
        auto hash_result = hasher.hash(test_data);
        
        if (hash_result.isSuccess()) {
            std::cout << "  ✓ SHA-256 hash computed: ";
            for (size_t i = 0; i < std::min<size_t>(16, hash_result.value().size()); ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                         << static_cast<int>(hash_result.value()[i]);
            }
            std::cout << "..." << std::dec << std::endl;
        } else {
            std::cout << "  ✗ Failed to compute hash" << std::endl;
        }
        
    } catch (const std::exception& ex) {
        std::cout << "  ✗ Exception: " << ex.what() << std::endl;
    }
}

void TestAESCipher() {
    std::cout << "\n[TEST] AESCipher..." << std::endl;
    
    try {
        SecureRandom rng;
        
        // Generate key and nonce
        auto key_result = rng.generateAESKey();
        auto nonce_result = rng.generateNonce();
        
        if (key_result.isSuccess() && nonce_result.isSuccess()) {
            AESCipher cipher(key_result.value());
            
            std::string plaintext = "Secret game data";
            std::vector<Byte> plain_bytes(plaintext.begin(), plaintext.end());
            
            // Encrypt
            auto encrypted = cipher.encrypt(plain_bytes, nonce_result.value());
            if (encrypted.isSuccess()) {
                std::cout << "  ✓ Data encrypted (" << encrypted.value().size() << " bytes)" << std::endl;
                
                // Decrypt
                auto decrypted = cipher.decrypt(encrypted.value(), nonce_result.value());
                if (decrypted.isSuccess()) {
                    std::string recovered(decrypted.value().begin(), decrypted.value().end());
                    if (recovered == plaintext) {
                        std::cout << "  ✓ Data decrypted and verified" << std::endl;
                    } else {
                        std::cout << "  ✗ Decrypted data doesn't match original" << std::endl;
                    }
                } else {
                    std::cout << "  ✗ Decryption failed" << std::endl;
                }
            } else {
                std::cout << "  ✗ Encryption failed" << std::endl;
            }
        }
        
    } catch (const std::exception& ex) {
        std::cout << "  ✗ Exception: " << ex.what() << std::endl;
    }
}

void TestHMAC() {
    std::cout << "\n[TEST] HMAC..." << std::endl;
    
    try {
        SecureRandom rng;
        auto key_result = rng.generate(32);
        
        if (key_result.isSuccess()) {
            HMAC hmac(key_result.value());
            
            std::string message = "Game packet data";
            auto mac_result = hmac.compute(ByteSpan(
                reinterpret_cast<const Byte*>(message.data()), 
                message.size()
            ));
            
            if (mac_result.isSuccess()) {
                std::cout << "  ✓ HMAC computed (" << mac_result.value().size() << " bytes)" << std::endl;
                
                // Verify
                auto verify_result = hmac.verify(
                    ByteSpan(reinterpret_cast<const Byte*>(message.data()), message.size()),
                    mac_result.value()
                );
                
                if (verify_result.isSuccess() && verify_result.value()) {
                    std::cout << "  ✓ HMAC verified" << std::endl;
                } else {
                    std::cout << "  ✗ HMAC verification failed" << std::endl;
                }
            } else {
                std::cout << "  ✗ HMAC computation failed" << std::endl;
            }
        }
        
    } catch (const std::exception& ex) {
        std::cout << "  ✗ Exception: " << ex.what() << std::endl;
    }
}

// ============================================================================
// SDK Integration Testing
// ============================================================================

void TestValueProtection() {
    std::cout << "\n[TEST] Protected Values..." << std::endl;
    
    // Create protected values for critical game data
    g_game_state.protected_gold_handle = CreateProtectedInt(1000);
    g_game_state.protected_level_handle = CreateProtectedInt(1);
    
    if (g_game_state.protected_gold_handle && g_game_state.protected_level_handle) {
        std::cout << "  ✓ Protected values created" << std::endl;
        
        // Read values
        int64_t gold = GetProtectedInt(g_game_state.protected_gold_handle);
        int64_t level = GetProtectedInt(g_game_state.protected_level_handle);
        
        std::cout << "  ✓ Initial gold: " << gold << ", level: " << level << std::endl;
        
        // Modify values
        SetProtectedInt(g_game_state.protected_gold_handle, gold + 100);
        SetProtectedInt(g_game_state.protected_level_handle, level + 1);
        
        std::cout << "  ✓ Values modified successfully" << std::endl;
    } else {
        std::cout << "  ✗ Failed to create protected values" << std::endl;
    }
}

void TestMemoryProtection() {
    std::cout << "\n[TEST] Memory Protection..." << std::endl;
    
    // Protect critical game data
    static int critical_game_data[256] = {0};
    for (int i = 0; i < 256; ++i) {
        critical_game_data[i] = i * 7; // Some pattern
    }
    
    uint64_t handle = ProtectMemory(critical_game_data, sizeof(critical_game_data), "CriticalGameData");
    
    if (handle != 0) {
        std::cout << "  ✓ Memory region protected (handle: " << handle << ")" << std::endl;
        
        // Verify integrity
        bool intact = VerifyMemory(handle);
        if (intact) {
            std::cout << "  ✓ Memory integrity verified" << std::endl;
        } else {
            std::cout << "  ✗ Memory integrity check failed" << std::endl;
        }
        
        // Cleanup
        UnprotectMemory(handle);
        std::cout << "  ✓ Memory unprotected" << std::endl;
    } else {
        std::cout << "  ✗ Failed to protect memory" << std::endl;
    }
}

void TestSecureTiming() {
    std::cout << "\n[TEST] Secure Timing..." << std::endl;
    
    uint64_t start_time = GetSecureTime();
    std::cout << "  ✓ Secure time: " << start_time << " ms" << std::endl;
    
    // Simulate some work
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    uint64_t end_time = GetSecureTime();
    uint64_t elapsed = end_time - start_time;
    
    std::cout << "  ✓ Elapsed time: " << elapsed << " ms" << std::endl;
    
    // Validate timing (100ms ± 50ms tolerance)
    bool valid = ValidateTiming(start_time, end_time, 50, 200);
    if (valid) {
        std::cout << "  ✓ Timing validation passed" << std::endl;
    } else {
        std::cout << "  ⚠ Timing validation failed (might be VM/debugger)" << std::endl;
    }
    
    // Test delta time
    float delta = GetSecureDeltaTime();
    std::cout << "  ✓ Secure delta time: " << delta << " seconds" << std::endl;
}

void TestPacketEncryption() {
    std::cout << "\n[TEST] Packet Encryption..." << std::endl;
    
    // Simulate game packet
    struct GamePacket {
        uint32_t sequence;
        uint32_t player_id;
        float position[3];
        uint32_t checksum;
    } packet;
    
    packet.sequence = GetPacketSequence();
    packet.player_id = 12345;
    packet.position[0] = 100.5f;
    packet.position[1] = 200.3f;
    packet.position[2] = 50.8f;
    packet.checksum = 0xDEADBEEF;
    
    std::cout << "  ✓ Packet sequence: " << packet.sequence << std::endl;
    
    // Encrypt packet
    uint8_t encrypted_buffer[512];
    size_t encrypted_size = sizeof(encrypted_buffer);
    
    ErrorCode result = EncryptPacket(&packet, sizeof(packet), encrypted_buffer, &encrypted_size);
    if (result == ErrorCode::Success) {
        std::cout << "  ✓ Packet encrypted (" << encrypted_size << " bytes)" << std::endl;
        
        // Decrypt packet
        GamePacket decrypted_packet;
        size_t decrypted_size = sizeof(decrypted_packet);
        
        result = DecryptPacket(encrypted_buffer, encrypted_size, &decrypted_packet, &decrypted_size);
        if (result == ErrorCode::Success) {
            std::cout << "  ✓ Packet decrypted" << std::endl;
            
            // Validate sequence
            bool seq_valid = ValidatePacketSequence(decrypted_packet.sequence);
            if (seq_valid) {
                std::cout << "  ✓ Packet sequence validated" << std::endl;
            } else {
                std::cout << "  ⚠ Packet sequence invalid (replay attack?)" << std::endl;
            }
        } else {
            std::cout << "  ✗ Packet decryption failed" << std::endl;
        }
    } else {
        std::cout << "  ⚠ Packet encryption not fully implemented (stub?)" << std::endl;
    }
}

// ============================================================================
// Game Simulation Functions
// ============================================================================

void SimulateCPULoad() {
    // Simulate CPU-intensive game logic
    volatile double result = 0.0;
    for (int i = 0; i < 10000; ++i) {
        result += std::sin(i * 0.1) * std::cos(i * 0.2);
    }
}

void SimulateLagSpike(int duration_ms) {
    std::cout << "  [SIMULATE] Lag spike (" << duration_ms << "ms)..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(duration_ms));
}

void UpdateGameLogic(float delta_time) {
    // Simulate player movement
    g_game_state.position_x = g_game_state.position_x.load() + (10.0f * delta_time);
    g_game_state.position_y = g_game_state.position_y.load() + (5.0f * delta_time);
    
    // Update protected values
    if (g_game_state.protected_gold_handle) {
        int64_t gold = GetProtectedInt(g_game_state.protected_gold_handle);
        SetProtectedInt(g_game_state.protected_gold_handle, gold + 1);  // Earn gold
    }
    
    // Simulate game events
    if (g_game_state.frame_count % 60 == 0) {  // Every ~1 second at 60 FPS
        g_game_state.player_score = g_game_state.player_score.load() + 10;
    }
}

void RenderFrame() {
    // Simulate rendering work (no actual rendering in console app)
    SimulateCPULoad();
}

void PrintGameStats() {
    std::cout << "\n[GAME STATS]" << std::endl;
    std::cout << "  Frame: " << g_game_state.frame_count.load() << std::endl;
    std::cout << "  Health: " << g_game_state.player_health.load() << std::endl;
    std::cout << "  Score: " << g_game_state.player_score.load() << std::endl;
    std::cout << "  Position: (" << g_game_state.position_x.load() << ", " 
              << g_game_state.position_y.load() << ")" << std::endl;
    
    if (g_game_state.protected_gold_handle) {
        int64_t gold = GetProtectedInt(g_game_state.protected_gold_handle);
        int64_t level = GetProtectedInt(g_game_state.protected_level_handle);
        std::cout << "  Gold (protected): " << gold << std::endl;
        std::cout << "  Level (protected): " << level << std::endl;
    }
    
    // Get SDK statistics
    Statistics stats;
    GetStatistics(&stats);
    std::cout << "\n[SDK STATS]" << std::endl;
    std::cout << "  Uptime: " << stats.uptime_ms << " ms" << std::endl;
    std::cout << "  Updates: " << stats.updates_performed << std::endl;
    std::cout << "  Scans: " << stats.scans_performed << std::endl;
    std::cout << "  Violations: " << stats.violations_detected << std::endl;
    std::cout << "  Avg Update Time: " << stats.avg_update_time_us << " µs" << std::endl;
    std::cout << "  Avg Scan Time: " << stats.avg_scan_time_ms << " ms" << std::endl;
    std::cout << "  Protected Regions: " << stats.protected_regions << std::endl;
    std::cout << "  Protected Functions: " << stats.protected_functions << std::endl;
}

// ============================================================================
// Main Game Loop
// ============================================================================

int main(int /*argc*/, char** /*argv*/) {
    std::cout << "============================================" << std::endl;
    std::cout << "  Sentinel SDK - Dummy Game Test" << std::endl;
    std::cout << "  Version: " << SENTINEL_SDK_VERSION_STRING << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << "\nRED-TEAM MINDSET: Looking for false positives," << std::endl;
    std::cout << "performance issues, and integration problems." << std::endl;
    std::cout << "\nPress Ctrl+C to exit\n" << std::endl;
    
    // ========================================================================
    // SDK Initialization
    // ========================================================================
    
    std::cout << "[INIT] Initializing Sentinel SDK..." << std::endl;
    
    Configuration config = Configuration::Default();
    config.license_key = "DUMMY-GAME-TEST-KEY-12345";
    config.game_id = "sentinel-dummy-game-v1";
    config.features = DetectionFeatures::Standard;
    config.default_action = ResponseAction::Log | ResponseAction::Notify;
    config.violation_callback = ViolationHandler;
    config.callback_user_data = nullptr;
    config.heartbeat_interval_ms = 1000;
    config.integrity_scan_interval_ms = 5000;
    config.debug_mode = true;
    
    // Use platform-appropriate temp directory for logs
    #ifdef _WIN32
        config.log_path = "C:\\Temp\\sentinel_dummy_game.log";
    #else
        config.log_path = "/tmp/sentinel_dummy_game.log";
    #endif
    
    ErrorCode init_result = Initialize(&config);
    if (init_result != ErrorCode::Success) {
        std::cerr << "ERROR: Failed to initialize SDK: " << static_cast<int>(init_result) << std::endl;
        std::cerr << "Last error: " << GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "✓ SDK initialized successfully" << std::endl;
    std::cout << "✓ SDK version: " << GetVersion() << std::endl;
    
    // ========================================================================
    // Exercise Crypto Components
    // ========================================================================
    
    std::cout << "\n[PHASE 1] Testing Crypto Components..." << std::endl;
    TestSecureRandom();
    TestHashEngine();
    TestAESCipher();
    TestHMAC();
    
    // ========================================================================
    // Exercise SDK Protection Features
    // ========================================================================
    
    std::cout << "\n[PHASE 2] Testing SDK Protection Features..." << std::endl;
    TestValueProtection();
    TestMemoryProtection();
    TestSecureTiming();
    TestPacketEncryption();
    
    // ========================================================================
    // Game Loop with Fixed Timestep
    // ========================================================================
    
    std::cout << "\n[PHASE 3] Starting Game Loop..." << std::endl;
    std::cout << "Target: 60 FPS (16.67ms per frame)" << std::endl;
    
    const double TARGET_FPS = 60.0;
    const auto FRAME_DURATION = std::chrono::microseconds(static_cast<int64_t>(1000000.0 / TARGET_FPS));
    
    auto last_frame_time = std::chrono::steady_clock::now();
    auto last_stats_time = std::chrono::steady_clock::now();
    auto game_start_time = std::chrono::steady_clock::now();
    
    int full_scan_counter = 0;
    const int FULL_SCAN_INTERVAL = 300;  // Every 5 seconds at 60 FPS
    
    std::cout << "\nEntering main loop (will run for 30 seconds)..." << std::endl;
    
    while (g_game_state.running.load()) {
        auto frame_start = std::chrono::steady_clock::now();
        
        // Calculate delta time
        auto delta = std::chrono::duration_cast<std::chrono::microseconds>(
            frame_start - last_frame_time
        );
        float delta_seconds = delta.count() / 1000000.0f;
        last_frame_time = frame_start;
        
        // ====================================================================
        // SDK Update (per-frame lightweight check)
        // ====================================================================
        
        if (!g_game_state.paused.load()) {
            ErrorCode update_result = Update();
            if (update_result != ErrorCode::Success) {
                std::cout << "⚠ SDK Update returned: " << static_cast<int>(update_result) << std::endl;
            }
        }
        
        // ====================================================================
        // SDK Full Scan (periodic comprehensive check)
        // ====================================================================
        
        full_scan_counter++;
        if (full_scan_counter >= FULL_SCAN_INTERVAL) {
            full_scan_counter = 0;
            ErrorCode scan_result = FullScan();
            if (scan_result != ErrorCode::Success) {
                std::cout << "⚠ SDK FullScan returned: " << static_cast<int>(scan_result) << std::endl;
            }
        }
        
        // ====================================================================
        // Game Logic
        // ====================================================================
        
        if (!g_game_state.paused.load()) {
            UpdateGameLogic(delta_seconds);
            RenderFrame();
        }
        
        g_game_state.frame_count++;
        
        // ====================================================================
        // Test Scenarios
        // ====================================================================
        
        // Simulate pause/resume every 10 seconds
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - game_start_time).count();
        
        if (elapsed > 0 && elapsed % 10 == 0 && g_game_state.frame_count % 60 == 0) {
            if (!g_game_state.paused.load()) {
                std::cout << "\n[TEST] Pausing game (simulating menu)..." << std::endl;
                g_game_state.paused = true;
                Pause();
            }
        } else if (elapsed > 0 && elapsed % 10 == 5 && g_game_state.frame_count % 60 == 0) {
            if (g_game_state.paused.load()) {
                std::cout << "[TEST] Resuming game..." << std::endl;
                g_game_state.paused = false;
                Resume();
            }
        }
        
        // Simulate lag spike every 15 seconds
        if (elapsed > 0 && elapsed % 15 == 0 && g_game_state.frame_count % 60 == 30) {
            SimulateLagSpike(150);  // 150ms spike
        }
        
        // Print stats every 5 seconds
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time).count() >= 5) {
            PrintGameStats();
            last_stats_time = now;
        }
        
        // Run for 30 seconds total
        if (elapsed >= 30) {
            std::cout << "\n[TEST] 30-second test completed, exiting..." << std::endl;
            g_game_state.running = false;
            break;
        }
        
        // ====================================================================
        // Frame Rate Limiting
        // ====================================================================
        
        auto frame_end = std::chrono::steady_clock::now();
        auto frame_duration = std::chrono::duration_cast<std::chrono::microseconds>(
            frame_end - frame_start
        );
        
        if (frame_duration < FRAME_DURATION) {
            std::this_thread::sleep_for(FRAME_DURATION - frame_duration);
        }
    }
    
    // ========================================================================
    // Cleanup
    // ========================================================================
    
    std::cout << "\n[CLEANUP] Shutting down..." << std::endl;
    
    // Destroy protected values
    if (g_game_state.protected_gold_handle) {
        DestroyProtectedValue(g_game_state.protected_gold_handle);
    }
    if (g_game_state.protected_level_handle) {
        DestroyProtectedValue(g_game_state.protected_level_handle);
    }
    
    // Final stats
    PrintGameStats();
    
    // Shutdown SDK
    Shutdown();
    
    std::cout << "\n✓ Sentinel SDK shutdown complete" << std::endl;
    std::cout << "============================================" << std::endl;
    
    return 0;
}
