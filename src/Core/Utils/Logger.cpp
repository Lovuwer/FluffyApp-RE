/**
 * @file Logger.cpp
 * @brief Implementation of comprehensive logging infrastructure
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * This implementation uses spdlog for high-performance async logging with
 * structured output support and automatic log rotation.
 */

#include "Sentinel/Core/Logger.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/callback_sink.h>
#include <spdlog/async.h>
#include <iostream>
#include <filesystem>

namespace Sentinel {
namespace Core {

// ============================================================================
// Logger Implementation
// ============================================================================

Logger& Logger::Instance() {
    static Logger instance;
    return instance;
}

Logger::~Logger() {
    Shutdown();
}

bool Logger::Initialize(LogLevel minLevel, LogOutput outputs,
                       const std::string& logFilePath, size_t maxFileSizeMB) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (initialized_) {
        return false; // Already initialized
    }

    minLevel_ = minLevel;
    outputs_ = outputs;
    logFilePath_ = logFilePath;
    maxFileSizeBytes_ = maxFileSizeMB * 1024 * 1024;

    try {
        // Create sinks based on requested outputs
        std::vector<spdlog::sink_ptr> sinks;

        // Console sink
        if (hasFlag(outputs_, LogOutput::Console)) {
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            console_sink->set_level(ToSpdlogLevel(minLevel_));
            sinks.push_back(console_sink);
        }

        // File sink with rotation
        if (hasFlag(outputs_, LogOutput::File) && !logFilePath_.empty()) {
            // Create directory if it doesn't exist
            std::filesystem::path logPath(logFilePath_);
            if (logPath.has_parent_path()) {
                std::filesystem::create_directories(logPath.parent_path());
            }

            auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                logFilePath_, 
                maxFileSizeBytes_, 
                3 // Keep 3 rotated files
            );
            file_sink->set_level(ToSpdlogLevel(minLevel_));
            sinks.push_back(file_sink);
        }

        // Callback sink (for game integration)
        if (hasFlag(outputs_, LogOutput::Callback)) {
            auto callback_sink = std::make_shared<spdlog::sinks::callback_sink_mt>(
                [this](const spdlog::details::log_msg& msg) {
                    if (callback_) {
                        auto level = FromSpdlogLevel(msg.level);
                        std::string message(msg.payload.data(), msg.payload.size());
                        auto timestamp = std::chrono::system_clock::now();
                        callback_(level, message, timestamp);
                    }
                }
            );
            callback_sink->set_level(ToSpdlogLevel(minLevel_));
            sinks.push_back(callback_sink);
        }

        // Create logger with sinks
        if (sinks.empty()) {
            // No sinks specified, use console as default
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            console_sink->set_level(ToSpdlogLevel(minLevel_));
            sinks.push_back(console_sink);
        }

        // Use synchronous logger for reliability (async can be enabled later for production)
        // For now, prioritize correctness over performance
        spdlogger_ = std::make_shared<spdlog::logger>(
            "sentinel", 
            sinks.begin(), 
            sinks.end()
        );

        // Set pattern: [timestamp] [level] [thread] message
        spdlogger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
        spdlogger_->set_level(ToSpdlogLevel(minLevel_));
        spdlogger_->flush_on(spdlog::level::trace); // Always flush for reliability

        initialized_ = true;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize logger: " << e.what() << std::endl;
        return false;
    }
}

void Logger::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!initialized_) {
        return;
    }

    if (spdlogger_) {
        spdlogger_->flush();
        spdlogger_.reset();
    }

    initialized_ = false;
}

void Logger::SetMinLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    minLevel_ = level;
    if (spdlogger_) {
        spdlogger_->set_level(ToSpdlogLevel(level));
    }
}

LogLevel Logger::GetMinLevel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return minLevel_;
}

void Logger::SetOutput(LogOutput output, bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (enabled) {
        outputs_ = outputs_ | output;
    } else {
        outputs_ = static_cast<LogOutput>(
            static_cast<uint8_t>(outputs_) & ~static_cast<uint8_t>(output)
        );
    }
}

void Logger::SetCallback(LogCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(callback);
}

bool Logger::IsLevelEnabled(LogLevel level) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return initialized_ && level >= minLevel_ && level != LogLevel::Off;
}

void Logger::Log(LogLevel level, std::string_view message, 
                const char* file, int line) {
    if (!IsLevelEnabled(level)) {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.dropped++;
        return;
    }

    // Update statistics
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        switch (level) {
            case LogLevel::Trace:    stats_.trace++; break;
            case LogLevel::Debug:    stats_.debug++; break;
            case LogLevel::Info:     stats_.info++; break;
            case LogLevel::Warning:  stats_.warning++; break;
            case LogLevel::Error:    stats_.error++; break;
            case LogLevel::Critical: stats_.critical++; break;
            default: break;
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!spdlogger_) {
        return;
    }

    // Format message with source location if provided
    std::string formattedMsg;
    if (file && line > 0) {
        // Extract just the filename from the full path
        const char* filename = file;
        for (const char* p = file; *p; ++p) {
            if (*p == '/' || *p == '\\') {
                filename = p + 1;
            }
        }
        formattedMsg = std::string("(") + filename + ":" + std::to_string(line) + ") " + std::string(message);
    } else {
        formattedMsg = std::string(message);
    }

    // Log using spdlog
    auto spdlog_level = ToSpdlogLevel(level);
    spdlogger_->log(spdlog_level, formattedMsg);
}

void Logger::Flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (spdlogger_) {
        spdlogger_->flush();
    }
}

Logger::Statistics Logger::GetStatistics() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void Logger::ResetStatistics() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Statistics{};
}

spdlog::level::level_enum Logger::ToSpdlogLevel(LogLevel level) {
    switch (level) {
        case LogLevel::Trace:    return spdlog::level::trace;
        case LogLevel::Debug:    return spdlog::level::debug;
        case LogLevel::Info:     return spdlog::level::info;
        case LogLevel::Warning:  return spdlog::level::warn;
        case LogLevel::Error:    return spdlog::level::err;
        case LogLevel::Critical: return spdlog::level::critical;
        case LogLevel::Off:      return spdlog::level::off;
        default:                 return spdlog::level::info;
    }
}

LogLevel Logger::FromSpdlogLevel(spdlog::level::level_enum level) {
    switch (level) {
        case spdlog::level::trace:    return LogLevel::Trace;
        case spdlog::level::debug:    return LogLevel::Debug;
        case spdlog::level::info:     return LogLevel::Info;
        case spdlog::level::warn:     return LogLevel::Warning;
        case spdlog::level::err:      return LogLevel::Error;
        case spdlog::level::critical: return LogLevel::Critical;
        case spdlog::level::off:      return LogLevel::Off;
        default:                      return LogLevel::Info;
    }
}

std::string Logger::FormatMessage(LogLevel level, std::string_view message,
                                 const char* file, int line) const {
    // This method is kept for compatibility but no longer used
    // spdlog handles formatting internally
    return std::string(message);
}

const char* Logger::LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Trace:    return "TRACE";
        case LogLevel::Debug:    return "DEBUG";
        case LogLevel::Info:     return "INFO ";
        case LogLevel::Warning:  return "WARN ";
        case LogLevel::Error:    return "ERROR";
        case LogLevel::Critical: return "CRIT ";
        default:                 return "UNKN ";
    }
}

} // namespace Core
} // namespace Sentinel
