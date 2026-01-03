#include <httplib.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>

#include "TelemetryHandler.hpp"
#include "HeartbeatValidator.hpp"
#include "SessionManager.hpp"

using json = nlohmann::json;
using namespace SentinelFlappy3D;

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  SentinelFlappy3D Validation Server" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Create handlers
    TelemetryHandler telemetryHandler;
    HeartbeatValidator heartbeatValidator;
    SessionManager sessionManager;

    // Create HTTP server
    httplib::Server svr;

    // Enable CORS for development
    svr.set_base_dir(".");

    // Health check endpoint
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        json response;
        response["status"] = "ok";
        response["service"] = "SentinelFlappy3D Validation Server";
        res.set_content(response.dump(), "application/json");
    });

    // Telemetry endpoint
    svr.Post("/api/v1/telemetry", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            // Parse JSON body
            json data = json::parse(req.body);
            
            // Validate required fields
            if (!data.contains("session_id")) {
                json error;
                error["status"] = "error";
                error["message"] = "Missing session_id";
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }
            
            std::string session_id = data["session_id"];
            
            // Handle telemetry event
            telemetryHandler.HandleEvent(data);
            
            // Record violation in session
            sessionManager.RecordViolation(session_id);
            
            // Send response
            json response;
            response["status"] = "ok";
            response["action"] = "log";
            res.set_content(response.dump(), "application/json");
            
        } catch (const std::exception& e) {
            std::cerr << "[Server] Error processing telemetry: " << e.what() << std::endl;
            
            json error;
            error["status"] = "error";
            error["message"] = e.what();
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    // Heartbeat endpoint
    svr.Post("/api/v1/heartbeat", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            // Parse JSON body
            json data = json::parse(req.body);
            
            // Validate required fields
            if (!data.contains("session_id") || !data.contains("timestamp") || 
                !data.contains("uptime_ms") || !data.contains("frame_count")) {
                json error;
                error["status"] = "error";
                error["message"] = "Missing required fields";
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }
            
            std::string session_id = data["session_id"];
            uint64_t timestamp = data["timestamp"];
            uint64_t uptime_ms = data["uptime_ms"];
            uint32_t frame_count = data["frame_count"];
            
            // Validate heartbeat
            bool valid = heartbeatValidator.ValidateHeartbeat(
                session_id, timestamp, uptime_ms, frame_count
            );
            
            // Update session
            sessionManager.UpdateSession(session_id, uptime_ms, frame_count);
            
            // Send response
            json response;
            response["status"] = valid ? "ok" : "warning";
            response["next_heartbeat_ms"] = 5000;
            res.set_content(response.dump(), "application/json");
            
        } catch (const std::exception& e) {
            std::cerr << "[Server] Error processing heartbeat: " << e.what() << std::endl;
            
            json error;
            error["status"] = "error";
            error["message"] = e.what();
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    // Status endpoint
    svr.Get("/api/v1/status", [&](const httplib::Request&, httplib::Response& res) {
        json status;
        status["active_sessions"] = sessionManager.GetActiveSessionCount();
        status["telemetry_events"] = telemetryHandler.GetEventCount();
        status["server_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        res.set_content(status.dump(2), "application/json");
    });

    // Start cleanup thread for stale sessions
    std::thread cleanup_thread([&]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            sessionManager.CleanupStaleSessions();
        }
    });
    cleanup_thread.detach();

    // Start server
    std::cout << "Starting HTTP server on http://localhost:8080" << std::endl;
    std::cout << "Endpoints:" << std::endl;
    std::cout << "  GET  /health              - Health check" << std::endl;
    std::cout << "  POST /api/v1/telemetry    - Receive telemetry events" << std::endl;
    std::cout << "  POST /api/v1/heartbeat    - Receive heartbeat pings" << std::endl;
    std::cout << "  GET  /api/v1/status       - Server status" << std::endl;
    std::cout << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    if (!svr.listen("0.0.0.0", 8080)) {
        std::cerr << "Failed to start server on port 8080" << std::endl;
        return 1;
    }

    return 0;
}
