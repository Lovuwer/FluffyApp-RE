/**
 * Sentinel SDK - Update Client Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 13: Implement Detection Signature Update Mechanism
 */

#include "Network/UpdateClient.hpp"
#include "Internal/SignatureManager.hpp"
#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace Sentinel {
namespace SDK {

UpdateClient::UpdateClient()
    : m_current_status(UpdateStatus::Idle)
    , m_auto_update_running(false)
    , m_initialized(false)
{
    m_statistics.total_updates = 0;
    m_statistics.failed_updates = 0;
    m_statistics.current_version = 0;
}

UpdateClient::~UpdateClient() {
    stopAutoUpdate();
}

Result<void> UpdateClient::initialize(
    const UpdateClientConfig& config,
    std::shared_ptr<SignatureManager> signature_manager)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    if (!signature_manager) {
        return ErrorCode::NullPointer;
    }
    
    m_config = config;
    m_signature_manager = signature_manager;
    
    // Create HTTP client
    m_http_client = std::make_shared<Network::HttpClient>();
    
    // Configure certificate pinning if enabled
    if (m_config.enable_pinning && !m_config.pinned_hashes.empty()) {
        Network::CertificatePin pin;
        
        // Extract hostname from URL
        std::string url = m_config.server_url;
        size_t proto_end = url.find("://");
        if (proto_end != std::string::npos) {
            url = url.substr(proto_end + 3);
        }
        size_t path_start = url.find("/");
        if (path_start != std::string::npos) {
            url = url.substr(0, path_start);
        }
        
        pin.hostname = url;
        pin.pins = m_config.pinned_hashes;
        pin.includeSubdomains = true;
        
        m_http_client->addCertificatePin(pin);
        m_http_client->setPinningEnabled(true);
    }
    
    // Set default timeout
    m_http_client->setDefaultTimeout(
        std::chrono::duration_cast<Milliseconds>(m_config.timeout)
    );
    
    // Set default headers
    m_http_client->addDefaultHeader("User-Agent", "Sentinel-SDK/1.0");
    m_http_client->addDefaultHeader("Accept", "application/json");
    
    m_initialized = true;
    return Result<void>::Success();
}

Result<bool> UpdateClient::checkForUpdates(bool force_update) {
    if (!m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    reportStatus(UpdateStatus::Checking, "Checking for signature updates");
    
    auto version_result = retryWithBackoff([this]() {
        return fetchLatestVersion();
    });
    
    if (version_result.isFailure()) {
        reportStatus(UpdateStatus::Failed, "Failed to check for updates");
        m_statistics.failed_updates++;
        return version_result.error();
    }
    
    m_statistics.last_check = std::chrono::system_clock::now();
    
    uint32_t latest_version = version_result.value();
    auto current_set = m_signature_manager->getCurrentSignatureSet();
    uint32_t current_version = 0;
    
    if (current_set.isSuccess()) {
        current_version = current_set.value().set_version;
    }
    
    m_statistics.current_version = current_version;
    
    bool update_available = (latest_version > current_version) || force_update;
    
    if (update_available) {
        reportStatus(UpdateStatus::Idle, "Update available");
    } else {
        reportStatus(UpdateStatus::Idle, "No updates available");
    }
    
    return update_available;
}

Result<void> UpdateClient::downloadAndApply() {
    if (!m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    reportStatus(UpdateStatus::Downloading, "Downloading signature set");
    
    // Download latest signature set with retry
    auto download_result = retryWithBackoff([this]() {
        return downloadSignatureSet(0);  // 0 = latest
    });
    
    if (download_result.isFailure()) {
        reportStatus(UpdateStatus::Failed, "Failed to download signatures");
        m_statistics.failed_updates++;
        return download_result.error();
    }
    
    std::string json_data = download_result.value();
    
    reportStatus(UpdateStatus::Verifying, "Verifying signature integrity");
    
    // Parse and verify signatures
    auto parse_result = m_signature_manager->loadSignaturesFromJson(json_data, true);
    if (parse_result.isFailure()) {
        reportStatus(UpdateStatus::Failed, "Failed to verify signatures");
        m_statistics.failed_updates++;
        return parse_result.error();
    }
    
    SignatureSet sig_set = parse_result.value();
    
    reportStatus(UpdateStatus::Applying, "Applying signatures");
    
    // Apply signature set
    auto apply_result = m_signature_manager->applySignatureSet(sig_set, false);
    if (apply_result.isFailure()) {
        reportStatus(UpdateStatus::Failed, "Failed to apply signatures");
        m_statistics.failed_updates++;
        return apply_result.error();
    }
    
    // Update statistics
    m_statistics.total_updates++;
    m_statistics.last_success = std::chrono::system_clock::now();
    m_statistics.current_version = sig_set.set_version;
    
    reportStatus(UpdateStatus::Success, "Signatures updated successfully");
    
    return Result<void>::Success();
}

Result<void> UpdateClient::performUpdate(bool force_update) {
    if (!m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    // Check for updates
    auto check_result = checkForUpdates(force_update);
    if (check_result.isFailure()) {
        return check_result.error();
    }
    
    // If no updates available and not forced, return success
    if (!check_result.value() && !force_update) {
        return Result<void>::Success();
    }
    
    // Download and apply
    return downloadAndApply();
}

Result<void> UpdateClient::startAutoUpdate() {
    if (!m_initialized) {
        return ErrorCode::InvalidState;
    }
    
    if (m_auto_update_running.load()) {
        return ErrorCode::InvalidState;  // Already running
    }
    
    m_auto_update_running.store(true);
    m_auto_update_thread = std::make_unique<std::thread>(
        &UpdateClient::autoUpdateLoop, this
    );
    
    return Result<void>::Success();
}

void UpdateClient::stopAutoUpdate() {
    if (m_auto_update_running.load()) {
        m_auto_update_running.store(false);
        
        if (m_auto_update_thread && m_auto_update_thread->joinable()) {
            m_auto_update_thread->join();
        }
    }
}

bool UpdateClient::isAutoUpdateRunning() const noexcept {
    return m_auto_update_running.load();
}

void UpdateClient::setProgressCallback(UpdateProgressCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_progress_callback = callback;
}

UpdateStatistics UpdateClient::getStatistics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_statistics;
}

UpdateStatus UpdateClient::getCurrentStatus() const noexcept {
    return m_current_status;
}

void UpdateClient::setHttpClient(std::shared_ptr<Network::HttpClient> http_client) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_http_client = http_client;
}

// ============================================================================
// Private Methods
// ============================================================================

Result<uint32_t> UpdateClient::fetchLatestVersion() {
    auto request_result = buildAuthenticatedRequest("/api/v1/signatures/version");
    if (request_result.isFailure()) {
        return request_result.error();
    }
    
    auto response = m_http_client->send(request_result.value());
    if (response.isFailure()) {
        return response.error();
    }
    
    if (!response.value().isSuccess()) {
        return ErrorCode::ServerError;
    }
    
    // Verify response authenticity
    auto verify_result = verifyResponse(response.value());
    if (verify_result.isFailure() || !verify_result.value()) {
        return ErrorCode::SignatureInvalid;
    }
    
    // Parse version from JSON response
    std::string body = response.value().bodyAsString();
    
    // Simple JSON parsing - extract "version" field
    size_t pos = body.find("\"version\":");
    if (pos == std::string::npos) {
        return ErrorCode::JsonInvalid;
    }
    
    pos += 10;  // strlen("\"version\":")
    while (pos < body.length() && std::isspace(body[pos])) pos++;
    
    std::string num_str;
    while (pos < body.length() && std::isdigit(body[pos])) {
        num_str += body[pos++];
    }
    
    if (num_str.empty()) {
        return ErrorCode::JsonInvalid;
    }
    
    try {
        return static_cast<uint32_t>(std::stoul(num_str));
    } catch (...) {
        return ErrorCode::JsonInvalid;
    }
}

Result<std::string> UpdateClient::downloadSignatureSet(uint32_t version) {
    std::string endpoint = "/api/v1/signatures/download";
    if (version > 0) {
        endpoint += "?version=" + std::to_string(version);
    }
    
    auto request_result = buildAuthenticatedRequest(endpoint);
    if (request_result.isFailure()) {
        return request_result.error();
    }
    
    auto response = m_http_client->send(request_result.value());
    if (response.isFailure()) {
        return response.error();
    }
    
    if (!response.value().isSuccess()) {
        return ErrorCode::DownloadFailed;
    }
    
    // Verify response authenticity
    auto verify_result = verifyResponse(response.value());
    if (verify_result.isFailure() || !verify_result.value()) {
        return ErrorCode::SignatureInvalid;
    }
    
    return response.value().bodyAsString();
}

Result<Network::HttpRequest> UpdateClient::buildAuthenticatedRequest(
    const std::string& endpoint,
    Network::HttpMethod method)
{
    Network::HttpRequest request;
    request.method = method;
    request.url = m_config.server_url + endpoint;
    request.timeout = std::chrono::duration_cast<Milliseconds>(m_config.timeout);
    request.enablePinning = m_config.enable_pinning;
    
    // Add authentication headers
    request.headers["X-API-Key"] = m_config.api_key;
    request.headers["X-Game-ID"] = m_config.game_id;
    
    // Add timestamp for replay protection
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::system_clock::to_time_t(now);
    request.headers["X-Timestamp"] = std::to_string(timestamp);
    
    return request;
}

Result<bool> UpdateClient::verifyResponse(const Network::HttpResponse& response) {
    // Check for required headers
    std::string content_type = response.getHeader("Content-Type");
    if (content_type.find("application/json") == std::string::npos) {
        return false;
    }
    
    // In production, verify HMAC or signature header
    // For now, basic validation
    if (response.body.empty()) {
        return false;
    }
    
    return true;
}

void UpdateClient::autoUpdateLoop() {
    while (m_auto_update_running.load()) {
        try {
            // Perform update check and apply
            auto result = performUpdate(false);
            
            if (result.isFailure()) {
                // Log error but continue
                reportStatus(UpdateStatus::Failed, "Auto-update cycle failed");
            }
            
        } catch (...) {
            // Catch any exceptions to prevent thread termination
            reportStatus(UpdateStatus::Failed, "Auto-update exception");
        }
        
        // Sleep for configured interval
        auto sleep_duration = m_config.check_interval;
        auto end_time = std::chrono::steady_clock::now() + sleep_duration;
        
        // Sleep in small increments to allow quick shutdown
        while (m_auto_update_running.load() && 
               std::chrono::steady_clock::now() < end_time) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void UpdateClient::reportStatus(UpdateStatus status, const std::string& message) {
    m_current_status = status;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_progress_callback) {
        m_progress_callback(status, message);
    }
}

template<typename Func>
Result<typename std::invoke_result<Func>::type> UpdateClient::retryWithBackoff(Func&& func) {
    using ReturnType = typename std::invoke_result<Func>::type;
    
    int attempts = 0;
    auto delay = m_config.retry_delay;
    
    while (attempts < m_config.max_retries) {
        auto result = func();
        
        if (result.isSuccess()) {
            return result;
        }
        
        attempts++;
        
        if (attempts < m_config.max_retries) {
            // Exponential backoff
            std::this_thread::sleep_for(delay);
            delay *= 2;
        }
    }
    
    // All retries failed
    return ErrorCode::NetworkError;
}

} // namespace SDK
} // namespace Sentinel
