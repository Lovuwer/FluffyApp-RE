#include "TelemetryHandler.hpp"
#include <iostream>
#include <fstream>
#include <mutex>

namespace SentinelFlappy3D {

TelemetryHandler::TelemetryHandler()
    : m_eventCount(0) {
}

void TelemetryHandler::HandleEvent(const nlohmann::json& event) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_eventCount++;
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "TELEMETRY EVENT #" << m_eventCount << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << event.dump(2) << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // Log to file
    LogToFile(event);
}

void TelemetryHandler::LogToFile(const nlohmann::json& event) {
    // Log to file in JSON Lines format
    std::ofstream file("/tmp/sentinelflappy3d_server.log", std::ios::app);
    if (file.is_open()) {
        file << event.dump() << std::endl;
        file.close();
    }
}

} // namespace SentinelFlappy3D
