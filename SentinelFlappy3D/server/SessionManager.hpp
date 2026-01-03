#pragma once

#include <string>
#include <cstdint>
#include <map>
#include <mutex>

namespace SentinelFlappy3D {

struct SessionInfo {
    std::string session_id;
    uint64_t last_heartbeat_time;
    uint64_t uptime_ms;
    uint32_t frame_count;
    uint32_t violation_count;
    bool active;
};

class SessionManager {
public:
    SessionManager();

    // Register or update a session
    void UpdateSession(const std::string& session_id, uint64_t uptime_ms, uint32_t frame_count);

    // Record a violation for a session
    void RecordViolation(const std::string& session_id);

    // Get session info
    SessionInfo* GetSession(const std::string& session_id);

    // Clean up stale sessions (no heartbeat for > 60 seconds)
    void CleanupStaleSessions();

    // Get active session count
    size_t GetActiveSessionCount() const;

private:
    std::map<std::string, SessionInfo> m_sessions;
    mutable std::mutex m_mutex;
};

} // namespace SentinelFlappy3D
