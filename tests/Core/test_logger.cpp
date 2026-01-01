/**
 * @file test_logger.cpp
 * @brief Unit tests for the Logger infrastructure
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <gtest/gtest.h>
#include "Sentinel/Core/Logger.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>

using namespace Sentinel::Core;

class LoggerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Clean up any existing test log files
        testLogPath_ = "/tmp/sentinel_test_logger.log";
        if (std::filesystem::exists(testLogPath_)) {
            std::filesystem::remove(testLogPath_);
        }
    }

    void TearDown() override {
        // Clean up test log files
        if (std::filesystem::exists(testLogPath_)) {
            std::filesystem::remove(testLogPath_);
        }
        
        // Clean up rotated log files
        for (const auto& entry : std::filesystem::directory_iterator("/tmp")) {
            if (entry.path().filename().string().find("sentinel_test_logger.log.") == 0) {
                std::filesystem::remove(entry.path());
            }
        }
    }

    std::string testLogPath_;
};

TEST_F(LoggerTest, InitializeAndShutdown) {
    auto& logger = Logger::Instance();
    
    EXPECT_TRUE(logger.Initialize(LogLevel::Info, LogOutput::Console));
    EXPECT_TRUE(logger.IsLevelEnabled(LogLevel::Info));
    EXPECT_FALSE(logger.IsLevelEnabled(LogLevel::Debug));
    
    logger.Shutdown();
}

TEST_F(LoggerTest, LogLevelFiltering) {
    auto& logger = Logger::Instance();
    
    logger.Initialize(LogLevel::Warning, LogOutput::Console);
    
    EXPECT_FALSE(logger.IsLevelEnabled(LogLevel::Trace));
    EXPECT_FALSE(logger.IsLevelEnabled(LogLevel::Debug));
    EXPECT_FALSE(logger.IsLevelEnabled(LogLevel::Info));
    EXPECT_TRUE(logger.IsLevelEnabled(LogLevel::Warning));
    EXPECT_TRUE(logger.IsLevelEnabled(LogLevel::Error));
    EXPECT_TRUE(logger.IsLevelEnabled(LogLevel::Critical));
    
    logger.Shutdown();
}

TEST_F(LoggerTest, FileOutput) {
    auto& logger = Logger::Instance();
    
    EXPECT_TRUE(logger.Initialize(LogLevel::Debug, LogOutput::File, testLogPath_));
    
    logger.Log(LogLevel::Info, "Test message 1");
    logger.Log(LogLevel::Error, "Test message 2");
    logger.Flush();
    
    EXPECT_TRUE(std::filesystem::exists(testLogPath_));
    
    // Read the log file
    std::ifstream logFile(testLogPath_);
    std::string content((std::istreambuf_iterator<char>(logFile)),
                        std::istreambuf_iterator<char>());
    
    EXPECT_TRUE(content.find("Test message 1") != std::string::npos);
    EXPECT_TRUE(content.find("Test message 2") != std::string::npos);
    EXPECT_TRUE(content.find("[INFO ]") != std::string::npos);
    EXPECT_TRUE(content.find("[ERROR]") != std::string::npos);
    
    logger.Shutdown();
}

TEST_F(LoggerTest, FormattedLogging) {
    auto& logger = Logger::Instance();
    
    logger.Initialize(LogLevel::Debug, LogOutput::File, testLogPath_);
    
    logger.LogFormat(LogLevel::Info, "Test %s with number %d", "message", 42);
    logger.Flush();
    
    std::ifstream logFile(testLogPath_);
    std::string content((std::istreambuf_iterator<char>(logFile)),
                        std::istreambuf_iterator<char>());
    
    EXPECT_TRUE(content.find("Test message with number 42") != std::string::npos);
    
    logger.Shutdown();
}

TEST_F(LoggerTest, Statistics) {
    auto& logger = Logger::Instance();
    
    logger.Initialize(LogLevel::Trace, LogOutput::Console);
    logger.ResetStatistics();
    
    logger.Log(LogLevel::Trace, "Trace message");
    logger.Log(LogLevel::Debug, "Debug message");
    logger.Log(LogLevel::Info, "Info message");
    logger.Log(LogLevel::Warning, "Warning message");
    logger.Log(LogLevel::Error, "Error message");
    logger.Log(LogLevel::Critical, "Critical message");
    
    auto stats = logger.GetStatistics();
    
    EXPECT_EQ(stats.trace, 1);
    EXPECT_EQ(stats.debug, 1);
    EXPECT_EQ(stats.info, 1);
    EXPECT_EQ(stats.warning, 1);
    EXPECT_EQ(stats.error, 1);
    EXPECT_EQ(stats.critical, 1);
    
    logger.Shutdown();
}

TEST_F(LoggerTest, DroppedMessages) {
    auto& logger = Logger::Instance();
    
    logger.Initialize(LogLevel::Error, LogOutput::Console);
    logger.ResetStatistics();
    
    // These should be dropped
    logger.Log(LogLevel::Trace, "Trace message");
    logger.Log(LogLevel::Debug, "Debug message");
    logger.Log(LogLevel::Info, "Info message");
    logger.Log(LogLevel::Warning, "Warning message");
    
    // These should be logged
    logger.Log(LogLevel::Error, "Error message");
    logger.Log(LogLevel::Critical, "Critical message");
    
    auto stats = logger.GetStatistics();
    
    EXPECT_EQ(stats.dropped, 4);
    EXPECT_EQ(stats.error, 1);
    EXPECT_EQ(stats.critical, 1);
    
    logger.Shutdown();
}

TEST_F(LoggerTest, ThreadSafety) {
    auto& logger = Logger::Instance();
    
    logger.Initialize(LogLevel::Debug, LogOutput::File, testLogPath_);
    logger.ResetStatistics();
    
    const int numThreads = 10;
    const int messagesPerThread = 100;
    
    std::vector<std::thread> threads;
    
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([&logger, i, messagesPerThread]() {
            for (int j = 0; j < messagesPerThread; ++j) {
                logger.LogFormat(LogLevel::Info, "Thread %d message %d", i, j);
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    logger.Flush();
    
    auto stats = logger.GetStatistics();
    EXPECT_EQ(stats.info, numThreads * messagesPerThread);
    
    logger.Shutdown();
}

TEST_F(LoggerTest, Callback) {
    auto& logger = Logger::Instance();
    
    logger.Initialize(LogLevel::Info, LogOutput::Callback);
    
    int callbackCount = 0;
    LogLevel lastLevel = LogLevel::Off;
    std::string lastMessage;
    
    logger.SetCallback([&](LogLevel level, std::string_view message, 
                           std::chrono::system_clock::time_point timestamp) {
        callbackCount++;
        lastLevel = level;
        lastMessage = std::string(message);
    });
    
    logger.Log(LogLevel::Info, "Test callback message");
    
    EXPECT_EQ(callbackCount, 1);
    EXPECT_EQ(lastLevel, LogLevel::Info);
    EXPECT_EQ(lastMessage, "Test callback message");
    
    logger.Shutdown();
}

TEST_F(LoggerTest, Macros) {
    auto& logger = Logger::Instance();
    
    logger.Initialize(LogLevel::Trace, LogOutput::File, testLogPath_);
    logger.ResetStatistics();
    
    SENTINEL_LOG_TRACE("Trace macro test");
    SENTINEL_LOG_DEBUG("Debug macro test");
    SENTINEL_LOG_INFO("Info macro test");
    SENTINEL_LOG_WARNING("Warning macro test");
    SENTINEL_LOG_ERROR("Error macro test");
    SENTINEL_LOG_CRITICAL("Critical macro test");
    
    logger.Flush();
    
    auto stats = logger.GetStatistics();
    EXPECT_EQ(stats.trace, 1);
    EXPECT_EQ(stats.debug, 1);
    EXPECT_EQ(stats.info, 1);
    EXPECT_EQ(stats.warning, 1);
    EXPECT_EQ(stats.error, 1);
    EXPECT_EQ(stats.critical, 1);
    
    // Check file content
    std::ifstream logFile(testLogPath_);
    std::string content((std::istreambuf_iterator<char>(logFile)),
                        std::istreambuf_iterator<char>());
    
    EXPECT_TRUE(content.find("Trace macro test") != std::string::npos);
    EXPECT_TRUE(content.find("test_logger.cpp") != std::string::npos);
    
    logger.Shutdown();
}

TEST_F(LoggerTest, FormattedMacros) {
    auto& logger = Logger::Instance();
    
    logger.Initialize(LogLevel::Debug, LogOutput::File, testLogPath_);
    
    SENTINEL_LOG_INFO_F("Formatted %s with number %d", "message", 123);
    logger.Flush();
    
    std::ifstream logFile(testLogPath_);
    std::string content((std::istreambuf_iterator<char>(logFile)),
                        std::istreambuf_iterator<char>());
    
    EXPECT_TRUE(content.find("Formatted message with number 123") != std::string::npos);
    
    logger.Shutdown();
}
