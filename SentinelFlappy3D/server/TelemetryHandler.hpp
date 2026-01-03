#pragma once

#include <string>
#include <mutex>
#include <nlohmann/json.hpp>

namespace SentinelFlappy3D {

class TelemetryHandler {
public:
    TelemetryHandler();

    // Handle telemetry event
    void HandleEvent(const nlohmann::json& event);

    // Log telemetry to file
    void LogToFile(const nlohmann::json& event);

    // Get telemetry count
    size_t GetEventCount() const { return m_eventCount; }

private:
    size_t m_eventCount;
    std::mutex m_mutex;
};

} // namespace SentinelFlappy3D
