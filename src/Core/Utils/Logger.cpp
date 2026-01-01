/**
 * @file Logger.cpp
 * @brief Implementation of comprehensive logging infrastructure
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include "Sentinel/Core/Logger.hpp"
#include <iostream>
#include <filesystem>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#endif

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

    // Open log file if file output is enabled
    if (hasFlag(outputs_, LogOutput::File) && !logFilePath_.empty()) {
        fileStream_.open(logFilePath_, std::ios::app);
        if (!fileStream_.is_open()) {
            std::cerr << "Failed to open log file: " << logFilePath_ << std::endl;
            return false;
        }

        // Check current file size
        try {
            if (std::filesystem::exists(logFilePath_)) {
                currentFileSize_ = std::filesystem::file_size(logFilePath_);
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to get log file size: " << e.what() << std::endl;
        }
    }

    initialized_ = true;

    return true;
}

void Logger::Shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!initialized_) {
            return;
        }

        // Mark as uninitialized before logging to prevent recursive calls
        initialized_ = false;
    }
    
    // Log shutdown message without holding the lock
    // (Log will check initialized_ and handle appropriately)
    if (fileStream_.is_open()) {
        std::lock_guard<std::mutex> lock(mutex_);
        fileStream_.flush();
        fileStream_.close();
    }
}

void Logger::SetMinLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    minLevel_ = level;
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

    auto now = std::chrono::system_clock::now();
    std::string formattedMessage = FormatMessage(level, message, file, line);

    std::lock_guard<std::mutex> lock(mutex_);

    // Write to console
    if (hasFlag(outputs_, LogOutput::Console)) {
        WriteConsole(level, formattedMessage);
    }

    // Write to file
    if (hasFlag(outputs_, LogOutput::File) && fileStream_.is_open()) {
        WriteFile(formattedMessage);
        CheckRotation();
    }

    // Call user callback
    if (hasFlag(outputs_, LogOutput::Callback) && callback_) {
        callback_(level, message, now);
    }
}

void Logger::Flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (fileStream_.is_open()) {
        fileStream_.flush();
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

std::string Logger::FormatMessage(LogLevel level, std::string_view message,
                                 const char* file, int line) const {
    std::ostringstream oss;

    // Timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

#ifdef _WIN32
    struct tm timeinfo;
    localtime_s(&timeinfo, &time_t_now);
    oss << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S");
#else
    struct tm timeinfo;
    localtime_r(&time_t_now, &timeinfo);
    oss << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S");
#endif

    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

    // Thread ID
    oss << " [" << std::this_thread::get_id() << "]";

    // Log level
    oss << " [" << LevelToString(level) << "]";

    // File and line (if provided)
    if (file && line > 0) {
        // Extract just the filename from the full path
        const char* filename = file;
        for (const char* p = file; *p; ++p) {
            if (*p == '/' || *p == '\\') {
                filename = p + 1;
            }
        }
        oss << " (" << filename << ":" << line << ")";
    }

    // Message
    oss << " " << message;

    return oss.str();
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

const char* Logger::LevelToColor(LogLevel level) {
    switch (level) {
        case LogLevel::Trace:    return "\033[37m";   // White
        case LogLevel::Debug:    return "\033[36m";   // Cyan
        case LogLevel::Info:     return "\033[32m";   // Green
        case LogLevel::Warning:  return "\033[33m";   // Yellow
        case LogLevel::Error:    return "\033[31m";   // Red
        case LogLevel::Critical: return "\033[1;31m"; // Bold Red
        default:                 return "\033[0m";    // Reset
    }
}

void Logger::WriteConsole(LogLevel level, const std::string& message) {
#ifdef _WIN32
    // Enable ANSI color support on Windows 10+
    static bool colorEnabled = []() {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(hOut, &mode)) {
                mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                SetConsoleMode(hOut, mode);
                return true;
            }
        }
        return false;
    }();

    if (colorEnabled) {
        std::cout << LevelToColor(level) << message << "\033[0m" << std::endl;
    } else {
        std::cout << message << std::endl;
    }
#else
    // Unix-like systems support ANSI colors by default
    std::cout << LevelToColor(level) << message << "\033[0m" << std::endl;
#endif
}

void Logger::WriteFile(const std::string& message) {
    fileStream_ << message << std::endl;
    currentFileSize_ += message.size() + 1; // +1 for newline
}

void Logger::CheckRotation() {
    if (currentFileSize_ >= maxFileSizeBytes_) {
        RotateLogFile();
    }
}

void Logger::RotateLogFile() {
    if (!fileStream_.is_open()) {
        return;
    }

    // Close current file
    fileStream_.close();

    try {
        // Generate backup filename with timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        
        std::ostringstream backupName;
        backupName << logFilePath_ << ".";
        
#ifdef _WIN32
        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t_now);
        backupName << std::put_time(&timeinfo, "%Y%m%d_%H%M%S");
#else
        struct tm timeinfo;
        localtime_r(&time_t_now, &timeinfo);
        backupName << std::put_time(&timeinfo, "%Y%m%d_%H%M%S");
#endif

        // Rename current log file
        std::filesystem::rename(logFilePath_, backupName.str());

        // Open new log file
        fileStream_.open(logFilePath_, std::ios::app);
        currentFileSize_ = 0;

        Log(LogLevel::Info, "Log file rotated");

    } catch (const std::exception& e) {
        std::cerr << "Failed to rotate log file: " << e.what() << std::endl;
        
        // Try to reopen the original file
        fileStream_.open(logFilePath_, std::ios::app);
    }
}

} // namespace Core
} // namespace Sentinel
