/**
 * @file Logger.hpp
 * @brief Comprehensive logging infrastructure for Sentinel diagnostics
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Thread-safe logging system with multiple severity levels, file rotation,
 * and structured output for security event tracking and diagnostics.
 */

#pragma once

#ifndef SENTINEL_CORE_LOGGER_HPP
#define SENTINEL_CORE_LOGGER_HPP

#include <string>
#include <string_view>
#include <fstream>
#include <mutex>
#include <memory>
#include <chrono>
#include <thread>
#include <sstream>
#include <iomanip>

namespace Sentinel {
namespace Core {

/**
 * @brief Log severity levels
 */
enum class LogLevel : uint8_t {
    Trace = 0,      ///< Verbose tracing for deep debugging
    Debug = 1,      ///< Debug information for development
    Info = 2,       ///< General informational messages
    Warning = 3,    ///< Warning messages for potential issues
    Error = 4,      ///< Error messages for failures
    Critical = 5,   ///< Critical security events requiring immediate attention
    Off = 255       ///< Disable all logging
};

/**
 * @brief Log output targets
 */
enum class LogOutput : uint8_t {
    None = 0,
    Console = 1 << 0,   ///< Output to console/stdout
    File = 1 << 1,      ///< Output to file
    Callback = 1 << 2,  ///< Call user-provided callback
    All = Console | File | Callback
};

// Bitwise operators for LogOutput
inline LogOutput operator|(LogOutput a, LogOutput b) {
    return static_cast<LogOutput>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}

inline LogOutput operator&(LogOutput a, LogOutput b) {
    return static_cast<LogOutput>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
}

inline bool hasFlag(LogOutput value, LogOutput flag) {
    return (static_cast<uint8_t>(value) & static_cast<uint8_t>(flag)) != 0;
}

/**
 * @brief Log callback function type
 * @param level Severity level of the message
 * @param message Formatted log message
 * @param timestamp Message timestamp
 */
using LogCallback = std::function<void(LogLevel level, std::string_view message, 
                                       std::chrono::system_clock::time_point timestamp)>;

/**
 * @brief Thread-safe logging system for Sentinel
 * 
 * Features:
 * - Multiple severity levels with filtering
 * - Thread-safe file and console output
 * - Automatic log file rotation
 * - Timestamp and thread ID tracking
 * - Color-coded console output (platform-dependent)
 * - User callback integration
 * - Zero-copy message formatting where possible
 */
class Logger {
public:
    /**
     * @brief Get the global logger instance
     */
    static Logger& Instance();

    /**
     * @brief Initialize the logger
     * @param minLevel Minimum log level to record
     * @param outputs Output targets (console, file, callback)
     * @param logFilePath Path to log file (required if File output enabled)
     * @param maxFileSizeMB Maximum log file size in MB before rotation
     * @return true on success
     */
    bool Initialize(LogLevel minLevel = LogLevel::Info,
                   LogOutput outputs = LogOutput::Console,
                   const std::string& logFilePath = "",
                   size_t maxFileSizeMB = 10);

    /**
     * @brief Shutdown the logger and flush all buffers
     */
    void Shutdown();

    /**
     * @brief Set the minimum log level
     */
    void SetMinLevel(LogLevel level);

    /**
     * @brief Get the current minimum log level
     */
    LogLevel GetMinLevel() const;

    /**
     * @brief Enable/disable output target
     */
    void SetOutput(LogOutput output, bool enabled);

    /**
     * @brief Set user callback for log messages
     */
    void SetCallback(LogCallback callback);

    /**
     * @brief Check if a log level is enabled
     */
    bool IsLevelEnabled(LogLevel level) const;

    /**
     * @brief Log a message at the specified level
     * @param level Severity level
     * @param message Message text
     * @param file Source file name (optional)
     * @param line Source line number (optional)
     */
    void Log(LogLevel level, std::string_view message, 
             const char* file = nullptr, int line = 0);

    /**
     * @brief Log a formatted message
     * @param level Severity level
     * @param format Printf-style format string
     * @param args Format arguments
     */
    template<typename... Args>
    void LogFormat(LogLevel level, const char* format, Args&&... args) {
        if (!IsLevelEnabled(level)) return;
        
        // Format the message
        char buffer[1024];
        int result = std::snprintf(buffer, sizeof(buffer), format, std::forward<Args>(args)...);
        
        if (result > 0 && static_cast<size_t>(result) < sizeof(buffer)) {
            Log(level, std::string_view(buffer, result));
        } else if (result > 0) {
            // Buffer too small, allocate larger buffer
            std::string largeBuffer(result + 1, '\0');
            std::snprintf(largeBuffer.data(), largeBuffer.size(), format, std::forward<Args>(args)...);
            Log(level, largeBuffer);
        }
    }

    /**
     * @brief Flush all buffers to disk
     */
    void Flush();

    /**
     * @brief Get total number of messages logged at each level
     */
    struct Statistics {
        size_t trace;
        size_t debug;
        size_t info;
        size_t warning;
        size_t error;
        size_t critical;
        size_t dropped;  ///< Messages dropped due to level filtering
    };

    Statistics GetStatistics() const;

    /**
     * @brief Reset statistics counters
     */
    void ResetStatistics();

private:
    Logger() = default;
    ~Logger();

    // Prevent copying
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    /**
     * @brief Format a log message with metadata
     */
    std::string FormatMessage(LogLevel level, std::string_view message,
                             const char* file, int line) const;

    /**
     * @brief Get string representation of log level
     */
    static const char* LevelToString(LogLevel level);

    /**
     * @brief Get ANSI color code for log level (console output)
     */
    static const char* LevelToColor(LogLevel level);

    /**
     * @brief Write message to console with optional color
     */
    void WriteConsole(LogLevel level, const std::string& message);

    /**
     * @brief Write message to file
     */
    void WriteFile(const std::string& message);

    /**
     * @brief Check and rotate log file if needed
     */
    void CheckRotation();

    /**
     * @brief Rotate the log file
     */
    void RotateLogFile();

    // Configuration
    LogLevel minLevel_ = LogLevel::Info;
    LogOutput outputs_ = LogOutput::Console;
    std::string logFilePath_;
    size_t maxFileSizeBytes_ = 10 * 1024 * 1024; // 10 MB default
    LogCallback callback_;

    // State
    mutable std::mutex mutex_;
    std::ofstream fileStream_;
    bool initialized_ = false;
    size_t currentFileSize_ = 0;

    // Statistics
    mutable std::mutex statsMutex_;
    Statistics stats_{};
};

} // namespace Core
} // namespace Sentinel

// ============================================================================
// Convenience Macros
// ============================================================================

#ifndef SENTINEL_DISABLE_LOGGING

/**
 * @brief Log a trace message
 */
#define SENTINEL_LOG_TRACE(msg) \
    ::Sentinel::Core::Logger::Instance().Log(::Sentinel::Core::LogLevel::Trace, msg, __FILE__, __LINE__)

/**
 * @brief Log a debug message
 */
#define SENTINEL_LOG_DEBUG(msg) \
    ::Sentinel::Core::Logger::Instance().Log(::Sentinel::Core::LogLevel::Debug, msg, __FILE__, __LINE__)

/**
 * @brief Log an info message
 */
#define SENTINEL_LOG_INFO(msg) \
    ::Sentinel::Core::Logger::Instance().Log(::Sentinel::Core::LogLevel::Info, msg, __FILE__, __LINE__)

/**
 * @brief Log a warning message
 */
#define SENTINEL_LOG_WARNING(msg) \
    ::Sentinel::Core::Logger::Instance().Log(::Sentinel::Core::LogLevel::Warning, msg, __FILE__, __LINE__)

/**
 * @brief Log an error message
 */
#define SENTINEL_LOG_ERROR(msg) \
    ::Sentinel::Core::Logger::Instance().Log(::Sentinel::Core::LogLevel::Error, msg, __FILE__, __LINE__)

/**
 * @brief Log a critical message
 */
#define SENTINEL_LOG_CRITICAL(msg) \
    ::Sentinel::Core::Logger::Instance().Log(::Sentinel::Core::LogLevel::Critical, msg, __FILE__, __LINE__)

/**
 * @brief Log a formatted trace message
 */
#define SENTINEL_LOG_TRACE_F(fmt, ...) \
    ::Sentinel::Core::Logger::Instance().LogFormat(::Sentinel::Core::LogLevel::Trace, fmt, __VA_ARGS__)

/**
 * @brief Log a formatted debug message
 */
#define SENTINEL_LOG_DEBUG_F(fmt, ...) \
    ::Sentinel::Core::Logger::Instance().LogFormat(::Sentinel::Core::LogLevel::Debug, fmt, __VA_ARGS__)

/**
 * @brief Log a formatted info message
 */
#define SENTINEL_LOG_INFO_F(fmt, ...) \
    ::Sentinel::Core::Logger::Instance().LogFormat(::Sentinel::Core::LogLevel::Info, fmt, __VA_ARGS__)

/**
 * @brief Log a formatted warning message
 */
#define SENTINEL_LOG_WARNING_F(fmt, ...) \
    ::Sentinel::Core::Logger::Instance().LogFormat(::Sentinel::Core::LogLevel::Warning, fmt, __VA_ARGS__)

/**
 * @brief Log a formatted error message
 */
#define SENTINEL_LOG_ERROR_F(fmt, ...) \
    ::Sentinel::Core::Logger::Instance().LogFormat(::Sentinel::Core::LogLevel::Error, fmt, __VA_ARGS__)

/**
 * @brief Log a formatted critical message
 */
#define SENTINEL_LOG_CRITICAL_F(fmt, ...) \
    ::Sentinel::Core::Logger::Instance().LogFormat(::Sentinel::Core::LogLevel::Critical, fmt, __VA_ARGS__)

#else
// Logging disabled - all macros are no-ops
#define SENTINEL_LOG_TRACE(msg) ((void)0)
#define SENTINEL_LOG_DEBUG(msg) ((void)0)
#define SENTINEL_LOG_INFO(msg) ((void)0)
#define SENTINEL_LOG_WARNING(msg) ((void)0)
#define SENTINEL_LOG_ERROR(msg) ((void)0)
#define SENTINEL_LOG_CRITICAL(msg) ((void)0)
#define SENTINEL_LOG_TRACE_F(fmt, ...) ((void)0)
#define SENTINEL_LOG_DEBUG_F(fmt, ...) ((void)0)
#define SENTINEL_LOG_INFO_F(fmt, ...) ((void)0)
#define SENTINEL_LOG_WARNING_F(fmt, ...) ((void)0)
#define SENTINEL_LOG_ERROR_F(fmt, ...) ((void)0)
#define SENTINEL_LOG_CRITICAL_F(fmt, ...) ((void)0)
#endif // SENTINEL_DISABLE_LOGGING

#endif // SENTINEL_CORE_LOGGER_HPP
