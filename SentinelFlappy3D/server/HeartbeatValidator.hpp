#pragma once

#include <string>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace SentinelFlappy3D {

class HeartbeatValidator {
public:
    HeartbeatValidator();

    // Validate a heartbeat request
    // Returns true if valid, false if suspicious
    bool ValidateHeartbeat(
        const std::string& session_id,
        uint64_t timestamp,
        uint64_t uptime_ms,
        uint32_t frame_count
    );

    // Log heartbeat for debugging
    void LogHeartbeat(const nlohmann::json& data);

private:
    struct SessionState {
        uint64_t last_timestamp;
        uint64_t last_uptime;
        uint32_t last_frame_count;
        uint64_t first_seen;
    };

    std::map<std::string, SessionState> m_sessionState;
    std::mutex m_mutex;
};

} // namespace SentinelFlappy3D
