#include "SessionManager.hpp"
#include <iostream>
#include <chrono>
#include <map>
#include <mutex>

namespace SentinelFlappy3D {

SessionManager::SessionManager() {
}

void SessionManager::UpdateSession(const std::string& session_id, uint64_t uptime_ms, uint32_t frame_count) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) {
        // New session
        SessionInfo info;
        info.session_id = session_id;
        info.last_heartbeat_time = now_ms;
        info.uptime_ms = uptime_ms;
        info.frame_count = frame_count;
        info.violation_count = 0;
        info.active = true;
        
        m_sessions[session_id] = info;
        
        std::cout << "[SessionManager] New session: " << session_id.substr(0, 8) << "..." << std::endl;
    } else {
        // Update existing session
        it->second.last_heartbeat_time = now_ms;
        it->second.uptime_ms = uptime_ms;
        it->second.frame_count = frame_count;
        it->second.active = true;
    }
}

void SessionManager::RecordViolation(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_sessions.find(session_id);
    if (it != m_sessions.end()) {
        it->second.violation_count++;
        std::cout << "[SessionManager] Violation recorded for session " << session_id.substr(0, 8) 
                  << "... (total: " << it->second.violation_count << ")" << std::endl;
    }
}

SessionInfo* SessionManager::GetSession(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_sessions.find(session_id);
    if (it != m_sessions.end()) {
        return &it->second;
    }
    return nullptr;
}

void SessionManager::CleanupStaleSessions() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    for (auto it = m_sessions.begin(); it != m_sessions.end(); ) {
        uint64_t elapsed = now_ms - it->second.last_heartbeat_time;
        if (elapsed > 60000) {  // 60 seconds
            std::cout << "[SessionManager] Cleaning up stale session: " << it->first.substr(0, 8) << "..." << std::endl;
            it = m_sessions.erase(it);
        } else {
            ++it;
        }
    }
}

size_t SessionManager::GetActiveSessionCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_sessions.size();
}

} // namespace SentinelFlappy3D
