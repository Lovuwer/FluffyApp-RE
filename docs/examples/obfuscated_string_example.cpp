/**
 * @file obfuscated_string_example.cpp
 * @brief Example demonstrating string obfuscation in detection code
 * @author Sentinel Security Team
 * 
 * This example shows how to use the ObfuscatedString framework
 * in anti-cheat detection code to prevent static analysis.
 */

#include <Sentinel/Core/ObfuscatedString.hpp>
#include <iostream>
#include <string>
#include <vector>

// Example 1: Simple detection function
void detectCheatEngine() {
    // Obfuscate cheat-related strings
    auto process_name = OBFUSCATE_STR("cheatengine-x86_64.exe");
    auto window_title = OBFUSCATE_STR("Cheat Engine");
    
    std::cout << "Checking for: " << process_name.c_str() << std::endl;
    std::cout << "Window title: " << window_title.c_str() << std::endl;
    
    // Strings automatically cleared when function exits
}

// Example 2: Detection with multiple signatures
bool detectSpeedhack() {
    // Create obfuscated blacklist
    auto sig1 = OBFUSCATE_STR("speedhack.dll");
    auto sig2 = OBFUSCATE_STR("speed_hack.dll");
    auto sig3 = OBFUSCATE_STR("SpeedHack64.dll");
    
    std::vector<std::string> blacklist = {
        sig1.str(),
        sig2.str(),
        sig3.str()
    };
    
    std::cout << "Checking " << blacklist.size() << " speedhack signatures" << std::endl;
    
    // In real code, you would check loaded modules against blacklist
    for (const auto& sig : blacklist) {
        std::cout << "  Checking: " << sig << std::endl;
    }
    
    return false; // No detection in this example
}

// Example 3: Error/log messages
class DetectionLogger {
public:
    void logViolation(const std::string& violation_type) {
        auto prefix = OBFUSCATE_STR("[VIOLATION]");
        auto detected = OBFUSCATE_STR("detected");
        
        std::cout << prefix.c_str() << " " 
                  << violation_type << " " 
                  << detected.c_str() << std::endl;
    }
};

// Example 4: API function names
void checkForDebugger() {
    // Obfuscate API names that attackers might search for
    auto api1 = OBFUSCATE_STR("IsDebuggerPresent");
    auto api2 = OBFUSCATE_STR("CheckRemoteDebuggerPresent");
    auto api3 = OBFUSCATE_STR("NtQueryInformationProcess");
    
    std::cout << "Using anti-debug APIs:" << std::endl;
    std::cout << "  - " << api1.c_str() << std::endl;
    std::cout << "  - " << api2.c_str() << std::endl;
    std::cout << "  - " << api3.c_str() << std::endl;
}

// Example 5: Memory patterns/signatures
struct SignatureDatabase {
    // Store obfuscated patterns
    static auto getAimbotPattern() {
        // Pattern bytes that would reveal aimbot detection
        return OBFUSCATE_STR("\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0");
    }
    
    static auto getWallhackPattern() {
        return OBFUSCATE_STR("\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9");
    }
};

// Example 6: Configuration strings
class DetectionConfig {
private:
    std::string m_server_url;
    std::string m_api_key;
    
public:
    DetectionConfig() {
        // Obfuscate sensitive configuration
        auto url = OBFUSCATE_STR("https://anticheat-api.example.com");
        auto key = OBFUSCATE_STR("sk_live_abc123def456");
        
        m_server_url = url.str();
        m_api_key = key.str();
    }
    
    const std::string& getServerUrl() const { return m_server_url; }
};

// Example 7: Detection message templates
void reportDetection(const std::string& player_id, const std::string& cheat_type) {
    auto msg_template = OBFUSCATE_STR("Player %s detected using %s");
    auto action = OBFUSCATE_STR("Player will be banned");
    
    std::cout << "Report: Player " << player_id 
              << " using " << cheat_type << std::endl;
    std::cout << action.c_str() << std::endl;
}

int main() {
    std::cout << "=== String Obfuscation Examples ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Example 1: Simple Detection" << std::endl;
    detectCheatEngine();
    std::cout << std::endl;
    
    std::cout << "Example 2: Multiple Signatures" << std::endl;
    detectSpeedhack();
    std::cout << std::endl;
    
    std::cout << "Example 3: Logging" << std::endl;
    DetectionLogger logger;
    logger.logViolation("aimbot");
    std::cout << std::endl;
    
    std::cout << "Example 4: API Names" << std::endl;
    checkForDebugger();
    std::cout << std::endl;
    
    std::cout << "Example 5: Memory Patterns" << std::endl;
    auto pattern1 = SignatureDatabase::getAimbotPattern();
    auto pattern2 = SignatureDatabase::getWallhackPattern();
    std::cout << "Loaded " << 2 << " detection patterns" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Example 6: Configuration" << std::endl;
    DetectionConfig config;
    std::cout << "Server: " << config.getServerUrl() << std::endl;
    std::cout << std::endl;
    
    std::cout << "Example 7: Report Template" << std::endl;
    reportDetection("player_12345", "speedhack");
    std::cout << std::endl;
    
    std::cout << "=== All strings were obfuscated at compile-time ===" << std::endl;
    std::cout << "Binary analysis will not reveal these strings!" << std::endl;
    
    return 0;
}
