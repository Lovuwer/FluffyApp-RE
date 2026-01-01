/**
 * Sentinel SDK - Update Client
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 13: Implement Detection Signature Update Mechanism
 * Provides secure signature download from server with authentication
 * and integrity verification.
 */

#pragma once

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <Sentinel/Core/HttpClient.hpp>
#include <memory>
#include <string>
#include <functional>
#include <chrono>
#include <thread>
#include <atomic>

namespace Sentinel {
namespace SDK {

// Forward declarations
struct SignatureSet;
class SignatureManager;

/**
 * Update status for monitoring
 */
enum class UpdateStatus : uint8_t {
    Idle,               ///< No update in progress
    Checking,           ///< Checking for updates
    Downloading,        ///< Downloading signature data
    Verifying,          ///< Verifying integrity
    Applying,           ///< Applying signatures
    Success,            ///< Update succeeded
    Failed              ///< Update failed
};

/**
 * Update progress callback
 */
using UpdateProgressCallback = std::function<void(UpdateStatus status, const std::string& message)>;

/**
 * Update client configuration
 */
struct UpdateClientConfig {
    std::string server_url;                 ///< Update server URL
    std::string api_key;                    ///< API key for authentication
    std::string game_id;                    ///< Game identifier
    
    // Timing configuration
    std::chrono::seconds check_interval{900};   ///< Check interval (default 15 min)
    std::chrono::seconds timeout{30};           ///< Request timeout
    
    // Retry configuration
    int max_retries = 3;                    ///< Maximum retry attempts
    std::chrono::seconds retry_delay{5};    ///< Delay between retries
    
    // Certificate pinning
    bool enable_pinning = true;             ///< Enable certificate pinning
    std::vector<SHA256Hash> pinned_hashes;  ///< SHA-256 hashes of server certificates
};

/**
 * Update statistics
 */
struct UpdateStatistics {
    size_t total_updates;                   ///< Total updates performed
    size_t failed_updates;                  ///< Failed update attempts
    std::chrono::system_clock::time_point last_check;     ///< Last check time
    std::chrono::system_clock::time_point last_success;   ///< Last successful update
    uint32_t current_version;               ///< Current signature version
};

/**
 * Update client
 * Downloads and validates signature updates from server
 */
class UpdateClient {
public:
    UpdateClient();
    ~UpdateClient();
    
    // Non-copyable
    UpdateClient(const UpdateClient&) = delete;
    UpdateClient& operator=(const UpdateClient&) = delete;
    
    /**
     * Initialize update client
     * @param config Update client configuration
     * @param signature_manager Signature manager instance
     * @return Success or error
     */
    Result<void> initialize(
        const UpdateClientConfig& config,
        std::shared_ptr<SignatureManager> signature_manager
    );
    
    /**
     * Check for signature updates
     * @param force_update Force update even if version is not newer
     * @return Success with update available flag, or error
     */
    Result<bool> checkForUpdates(bool force_update = false);
    
    /**
     * Download and apply signature updates
     * @return Success or error
     */
    Result<void> downloadAndApply();
    
    /**
     * Perform full update cycle (check + download + apply)
     * @param force_update Force update even if version is not newer
     * @return Success or error
     */
    Result<void> performUpdate(bool force_update = false);
    
    /**
     * Start automatic update loop
     * Checks for updates at configured intervals
     * @return Success or error
     */
    Result<void> startAutoUpdate();
    
    /**
     * Stop automatic update loop
     */
    void stopAutoUpdate();
    
    /**
     * Check if auto-update is running
     */
    [[nodiscard]] bool isAutoUpdateRunning() const noexcept;
    
    /**
     * Set progress callback
     * @param callback Callback function
     */
    void setProgressCallback(UpdateProgressCallback callback);
    
    /**
     * Get update statistics
     */
    [[nodiscard]] UpdateStatistics getStatistics() const;
    
    /**
     * Get current update status
     */
    [[nodiscard]] UpdateStatus getCurrentStatus() const noexcept;
    
    /**
     * Set HTTP client for testing
     * @param http_client Custom HTTP client instance
     */
    void setHttpClient(std::shared_ptr<Network::HttpClient> http_client);

private:
    /**
     * Fetch latest signature version from server
     * @return Latest version number or error
     */
    Result<uint32_t> fetchLatestVersion();
    
    /**
     * Download signature set from server
     * @param version Version to download (0 = latest)
     * @return Signature JSON data or error
     */
    Result<std::string> downloadSignatureSet(uint32_t version = 0);
    
    /**
     * Build authenticated request
     * @param endpoint API endpoint path
     * @param method HTTP method
     * @return HttpRequest or error
     */
    Result<Network::HttpRequest> buildAuthenticatedRequest(
        const std::string& endpoint,
        Network::HttpMethod method = Network::HttpMethod::GET
    );
    
    /**
     * Verify response authenticity
     * @param response HTTP response
     * @return true if authentic, false otherwise
     */
    Result<bool> verifyResponse(const Network::HttpResponse& response);
    
    /**
     * Auto-update thread function
     */
    void autoUpdateLoop();
    
    /**
     * Report update status
     */
    void reportStatus(UpdateStatus status, const std::string& message);
    
    /**
     * Retry logic with exponential backoff
     */
    template<typename Func>
    Result<typename std::invoke_result<Func>::type> retryWithBackoff(Func&& func);

private:
    // Configuration
    UpdateClientConfig m_config;
    
    // Dependencies
    std::shared_ptr<SignatureManager> m_signature_manager;
    std::shared_ptr<Network::HttpClient> m_http_client;
    
    // State
    UpdateStatus m_current_status;
    UpdateStatistics m_statistics;
    
    // Auto-update thread
    std::unique_ptr<std::thread> m_auto_update_thread;
    std::atomic<bool> m_auto_update_running;
    std::mutex m_mutex;
    
    // Progress callback
    UpdateProgressCallback m_progress_callback;
    
    // Initialization flag
    bool m_initialized;
};

} // namespace SDK
} // namespace Sentinel
