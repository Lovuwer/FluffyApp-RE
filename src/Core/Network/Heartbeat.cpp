/**
 * @file Heartbeat.cpp
 * @brief Client heartbeat implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/Heartbeat.hpp>
#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/RequestSigner.hpp>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <random>
#include <sstream>
#include <iomanip>

namespace Sentinel::Network {

// ============================================================================
// Heartbeat Implementation
// ============================================================================

class Heartbeat::Impl {
public:
    Impl(
        const HeartbeatConfig& config,
        std::shared_ptr<HttpClient> httpClient,
        std::shared_ptr<RequestSigner> signer
    )
        : m_config(config)
        , m_httpClient(std::move(httpClient))
        , m_signer(std::move(signer))
        , m_running(false)
        , m_sequenceNumber(0)
        , m_successCount(0)
        , m_failureCount(0)
        , m_lastError(ErrorCode::Success)
    {
        // Initialize random number generator for jitter
        std::random_device rd;
        m_rng.seed(rd());
    }
    
    ~Impl() {
        stop();
    }
    
    Result<void> start() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Check if already running
        if (m_running) {
            return ErrorCode::InvalidState;
        }
        
        // Validate configuration
        if (m_config.serverUrl.empty()) {
            return ErrorCode::ConfigInvalid;
        }
        
        if (!m_httpClient) {
            return ErrorCode::NullPointer;
        }
        
        // Reset state
        m_running = true;
        m_sequenceNumber = 0;
        
        // Start heartbeat thread
        m_thread = std::thread(&Impl::heartbeatLoop, this);
        
        return Result<void>::Success();
    }
    
    void stop() noexcept {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_running) {
                return;
            }
            m_running = false;
        }
        
        // Wake up thread if it's waiting
        m_cv.notify_one();
        
        // Wait for thread to finish
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }
    
    bool isRunning() const noexcept {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_running;
    }
    
    HeartbeatStatus getStatus() const noexcept {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        HeartbeatStatus status;
        status.isRunning = m_running;
        status.successCount = m_successCount.load();
        status.failureCount = m_failureCount.load();
        status.sequenceNumber = m_sequenceNumber.load();
        status.lastSuccess = m_lastSuccess;
        status.lastFailure = m_lastFailure;
        status.lastError = m_lastError;
        
        return status;
    }
    
    void updateConfig(const HeartbeatConfig& config) noexcept {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_config = config;
    }
    
    Result<void> sendHeartbeat() {
        return sendHeartbeatInternal();
    }
    
    void setCallbacks(
        std::function<void(uint64_t sequence)> onSuccess,
        std::function<void(ErrorCode error, uint64_t sequence)> onFailure
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_onSuccess = std::move(onSuccess);
        m_onFailure = std::move(onFailure);
    }

private:
    void heartbeatLoop() {
        while (true) {
            // Check if we should stop
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (!m_running) {
                    break;
                }
            }
            
            // Send heartbeat
            (void)sendHeartbeatInternal();
            
            // Calculate next interval with jitter
            auto interval = calculateNextInterval();
            
            // Wait for next interval or stop signal
            std::unique_lock<std::mutex> lock(m_mutex);
            if (m_cv.wait_for(lock, interval, [this] { return !m_running; })) {
                // Stop was signaled
                break;
            }
        }
    }
    
    Result<void> sendHeartbeatInternal() {
        // Get current sequence number (incremented after heartbeat attempt)
        uint64_t sequence = m_sequenceNumber.load();
        
        // Build heartbeat payload
        std::string payload = buildHeartbeatPayload(sequence);
        
        // Send with retries
        Result<void> result = ErrorCode::InternalError;
        int retries = 0;
        int maxRetries = m_config.maxRetries;
        
        while (retries <= maxRetries) {
            try {
                // Send HTTP request
                HttpRequest request;
                request.method = HttpMethod::POST;
                request.url = m_config.serverUrl;
                request.headers["Content-Type"] = "application/json";
                request.body = ByteBuffer(payload.begin(), payload.end());
                request.timeout = m_config.requestTimeout;
                
                auto response = m_httpClient->send(request);
                
                if (response.isSuccess() && response.value().isSuccess()) {
                    // Success - increment sequence number
                    m_sequenceNumber.fetch_add(1);
                    m_successCount.fetch_add(1);
                    m_lastSuccess = Clock::now();
                    m_lastError = ErrorCode::Success;
                    result = Result<void>::Success();
                    
                    // Invoke success callback
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_onSuccess) {
                        m_onSuccess(sequence);
                    }
                    
                    if (m_config.enableLogging) {
                        // TODO: Add proper logging using spdlog or similar
                        // logHeartbeat(sequence, true, ErrorCode::Success);
                    }
                    
                    break;
                } else {
                    // HTTP error
                    ErrorCode errorCode = response.isSuccess() 
                        ? ErrorCode::HttpRequestFailed 
                        : response.error();
                    
                    if (retries < maxRetries) {
                        // Retry on transient errors
                        retries++;
                        std::this_thread::sleep_for(m_config.retryDelay);
                        continue;
                    } else {
                        // Max retries exceeded - increment sequence number
                        m_sequenceNumber.fetch_add(1);
                        m_failureCount.fetch_add(1);
                        m_lastFailure = Clock::now();
                        m_lastError = errorCode;
                        result = errorCode;
                        
                        // Invoke failure callback
                        std::lock_guard<std::mutex> lock(m_mutex);
                        if (m_onFailure) {
                            m_onFailure(errorCode, sequence);
                        }
                        
                        if (m_config.enableLogging) {
                            // TODO: Add proper logging using spdlog or similar
                            // logHeartbeat(sequence, false, errorCode);
                        }
                    }
                }
            } catch (...) {
                // Exception occurred - treat as network error
                if (retries < maxRetries) {
                    retries++;
                    std::this_thread::sleep_for(m_config.retryDelay);
                    continue;
                } else {
                    m_sequenceNumber.fetch_add(1);
                    m_failureCount.fetch_add(1);
                    m_lastFailure = Clock::now();
                    m_lastError = ErrorCode::NetworkError;
                    result = ErrorCode::NetworkError;
                    
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_onFailure) {
                        m_onFailure(ErrorCode::NetworkError, sequence);
                    }
                    
                    if (m_config.enableLogging) {
                        // TODO: Add proper logging using spdlog or similar
                        // logHeartbeat(sequence, false, ErrorCode::NetworkError);
                    }
                }
            }
        }
        
        return result;
    }
    
    std::string buildHeartbeatPayload(uint64_t sequence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Build JSON payload
        std::ostringstream oss;
        oss << "{"
            << "\"client_id\":\"" << escapeJson(m_config.clientId) << "\","
            << "\"session_token\":\"" << escapeJson(m_config.sessionToken) << "\","
            << "\"sequence\":" << sequence << ","
            << "\"timestamp\":" << std::chrono::duration_cast<Milliseconds>(
                Clock::now().time_since_epoch()).count()
            << "}";
        
        return oss.str();
    }
    
    std::string escapeJson(const std::string& input) {
        std::ostringstream oss;
        for (char c : input) {
            switch (c) {
                case '"':  oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b";  break;
                case '\f': oss << "\\f";  break;
                case '\n': oss << "\\n";  break;
                case '\r': oss << "\\r";  break;
                case '\t': oss << "\\t";  break;
                default:
                    if (c < 32) {
                        oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    } else {
                        oss << c;
                    }
            }
        }
        return oss.str();
    }
    
    Milliseconds calculateNextInterval() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Calculate random jitter
        std::uniform_int_distribution<int64_t> dist(0, m_config.jitterMax.count());
        int64_t jitter = dist(m_rng);
        
        // Return base interval + jitter
        return Milliseconds(m_config.interval.count() + jitter);
    }

private:
    HeartbeatConfig m_config;
    std::shared_ptr<HttpClient> m_httpClient;
    std::shared_ptr<RequestSigner> m_signer;
    
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::thread m_thread;
    std::atomic<bool> m_running;
    
    std::atomic<uint64_t> m_sequenceNumber;
    std::atomic<uint64_t> m_successCount;
    std::atomic<uint64_t> m_failureCount;
    
    TimePoint m_lastSuccess;
    TimePoint m_lastFailure;
    ErrorCode m_lastError;
    
    std::mt19937_64 m_rng;
    
    std::function<void(uint64_t sequence)> m_onSuccess;
    std::function<void(ErrorCode error, uint64_t sequence)> m_onFailure;
};

// ============================================================================
// Heartbeat Public API
// ============================================================================

Heartbeat::Heartbeat(
    const HeartbeatConfig& config,
    std::shared_ptr<HttpClient> httpClient,
    std::shared_ptr<RequestSigner> signer
)
    : m_impl(std::make_unique<Impl>(config, std::move(httpClient), std::move(signer)))
{
}

Heartbeat::~Heartbeat() = default;

Heartbeat::Heartbeat(Heartbeat&&) noexcept = default;
Heartbeat& Heartbeat::operator=(Heartbeat&&) noexcept = default;

Result<void> Heartbeat::start() {
    return m_impl->start();
}

void Heartbeat::stop() noexcept {
    m_impl->stop();
}

bool Heartbeat::isRunning() const noexcept {
    return m_impl->isRunning();
}

HeartbeatStatus Heartbeat::getStatus() const noexcept {
    return m_impl->getStatus();
}

void Heartbeat::updateConfig(const HeartbeatConfig& config) noexcept {
    m_impl->updateConfig(config);
}

Result<void> Heartbeat::sendHeartbeat() {
    return m_impl->sendHeartbeat();
}

void Heartbeat::setCallbacks(
    std::function<void(uint64_t sequence)> onSuccess,
    std::function<void(ErrorCode error, uint64_t sequence)> onFailure
) {
    m_impl->setCallbacks(std::move(onSuccess), std::move(onFailure));
}

} // namespace Sentinel::Network
