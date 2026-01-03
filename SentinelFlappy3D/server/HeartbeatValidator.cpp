#include "HeartbeatValidator.hpp"
#include <iostream>
#include <chrono>
#include <map>
#include <mutex>
#include <cmath>

namespace SentinelFlappy3D {

HeartbeatValidator::HeartbeatValidator() {
}

bool HeartbeatValidator::ValidateHeartbeat(
    const std::string& session_id,
    uint64_t timestamp,
    uint64_t uptime_ms,
    uint32_t frame_count
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    // Check timestamp is within reasonable range (±10 seconds)
    int64_t time_diff = static_cast<int64_t>(now_ms) - static_cast<int64_t>(timestamp);
    if (std::abs(time_diff) > 10000) {
        std::cout << "[HeartbeatValidator] WARNING: Clock desync detected for session " 
                  << session_id.substr(0, 8) << "... (diff: " << time_diff << "ms)" << std::endl;
        // Don't fail, just warn - could be network delay
    }
    
    auto it = m_sessionState.find(session_id);
    if (it == m_sessionState.end()) {
        // First heartbeat for this session
        SessionState state;
        state.last_timestamp = timestamp;
        state.last_uptime = uptime_ms;
        state.last_frame_count = frame_count;
        state.first_seen = now_ms;
        
        m_sessionState[session_id] = state;
        
        std::cout << "[HeartbeatValidator] First heartbeat from session " << session_id.substr(0, 8) << "..." << std::endl;
        return true;
    }
    
    // Validate uptime progression
    uint64_t expected_uptime_increase = timestamp - it->second.last_timestamp;
    uint64_t actual_uptime_increase = uptime_ms - it->second.last_uptime;
    
    if (std::abs(static_cast<int64_t>(expected_uptime_increase) - static_cast<int64_t>(actual_uptime_increase)) > 1000) {
        std::cout << "[HeartbeatValidator] WARNING: Uptime anomaly for session " << session_id.substr(0, 8)
                  << "... (expected: " << expected_uptime_increase << "ms, actual: " << actual_uptime_increase << "ms)" << std::endl;
        // Could indicate speedhack
    }
    
    // Validate frame count progression
    uint32_t frame_increase = frame_count - it->second.last_frame_count;
    double expected_frames = (actual_uptime_increase / 1000.0) * 60.0;  // Assuming 60 FPS
    
    if (std::abs(static_cast<double>(frame_increase) - expected_frames) > 600) {  // ±10 seconds tolerance
        std::cout << "[HeartbeatValidator] WARNING: Frame rate anomaly for session " << session_id.substr(0, 8)
                  << "... (frames: " << frame_increase << ", expected: ~" << expected_frames << ")" << std::endl;
    }
    
    // Update state
    it->second.last_timestamp = timestamp;
    it->second.last_uptime = uptime_ms;
    it->second.last_frame_count = frame_count;
    
    return true;
}

void HeartbeatValidator::LogHeartbeat(const nlohmann::json& data) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::cout << "[HeartbeatValidator] Heartbeat: " << data.dump() << std::endl;
}

} // namespace SentinelFlappy3D
