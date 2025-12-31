/**
 * Sentinel SDK - CloudReporter Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Violation reporting pipeline with thread-safe queuing, batching, retry logic,
 * and offline buffering to encrypted storage.
 */

#include "Internal/Detection.hpp"
#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/RequestSigner.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <nlohmann/json.hpp>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <deque>
#include <cstring>

#ifdef _WIN32
#include <Windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <pwd.h>
#endif

namespace Sentinel {
namespace SDK {

using json = nlohmann::json;
using namespace Sentinel::Network;
using namespace Sentinel::Crypto;

// ============================================================================
// CloudReporter Implementation
// ============================================================================

class CloudReporter::Impl {
public:
    explicit Impl(const char* endpoint)
        : endpoint_(endpoint ? endpoint : "")
        , batch_size_(10)
        , interval_ms_(30000)
        , max_queue_depth_(1000)
        , running_(false)
        , retry_count_(0)
    {
        // Initialize HTTP client
        http_client_ = std::make_unique<HttpClient>();
        http_client_->setDefaultTimeout(Milliseconds{30000});
        
        // Initialize offline buffer directory
        InitializeOfflineStorage();
    }
    
    ~Impl() {
        Shutdown();
    }
    
    void Start() {
        if (running_) return;
        
        running_ = true;
        reporter_thread_ = std::thread(&Impl::ReportThread, this);
    }
    
    void Shutdown() {
        if (!running_) return;
        
        running_ = false;
        cv_.notify_all();
        
        if (reporter_thread_.joinable()) {
            reporter_thread_.join();
        }
        
        // Flush remaining events to offline storage
        FlushToOfflineStorage();
    }
    
    void SetBatchSize(uint32_t size) {
        if (size >= 1 && size <= 100) {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            batch_size_ = size;
        }
    }
    
    void SetInterval(uint32_t ms) {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        interval_ms_ = ms;
    }
    
    void SetRequestSigner(std::shared_ptr<RequestSigner> signer) {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        http_client_->setRequestSigner(signer);
    }
    
    void QueueEvent(const ViolationEvent& event) {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        
        // Check queue depth limit
        if (event_queue_.size() >= max_queue_depth_) {
            // Evict oldest violation
            event_queue_.pop_front();
        }
        
        event_queue_.push_back(event);
        
        // Check flush triggers
        bool should_flush = false;
        
        // Trigger 1: Queue depth reached batch size
        if (event_queue_.size() >= batch_size_) {
            should_flush = true;
        }
        
        // Trigger 2: Critical severity event
        if (event.severity == Severity::Critical) {
            should_flush = true;
        }
        
        if (should_flush) {
            cv_.notify_one();
        }
    }
    
    ErrorCode ReportCustomEvent(const char* type, const char* data) {
        if (!type || !data) {
            return ErrorCode::InvalidParameter;
        }
        
        // Create a custom violation event
        ViolationEvent event;
        event.type = static_cast<ViolationType>(0x100000); // Custom event type
        event.severity = Severity::Info;
        event.timestamp = GetCurrentTimestamp();
        event.address = 0;
        event.module_name = type;
        event.details = data;
        event.detection_id = 0;
        
        QueueEvent(event);
        return ErrorCode::Success;
    }
    
    void Flush() {
        cv_.notify_one();
    }
    
private:
    void ReportThread() {
        auto last_batch_time = std::chrono::steady_clock::now();
        
        while (running_) {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            // Wait for events or timeout
            auto timeout = std::chrono::milliseconds(interval_ms_);
            cv_.wait_for(lock, timeout, [this, &last_batch_time]() {
                if (!running_) return true;
                
                // Check if we should send a batch
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - last_batch_time).count();
                
                return event_queue_.size() >= batch_size_ || 
                       elapsed >= interval_ms_ ||
                       HasCriticalEvent();
            });
            
            if (!running_) break;
            
            // Check if we have events to send
            if (event_queue_.empty()) continue;
            
            // Extract batch
            size_t batch_count = std::min(event_queue_.size(), 
                                         static_cast<size_t>(batch_size_));
            std::vector<ViolationEvent> batch;
            batch.reserve(batch_count);
            
            for (size_t i = 0; i < batch_count; ++i) {
                batch.push_back(event_queue_.front());
                event_queue_.pop_front();
            }
            
            lock.unlock();
            
            // Send batch with retry logic
            ErrorCode result = SendBatchWithRetry(batch);
            
            if (result != ErrorCode::Success) {
                // Failed to send - store in offline buffer
                lock.lock();
                for (const auto& event : batch) {
                    event_queue_.push_front(event);
                }
                lock.unlock();
                
                SaveToOfflineStorage(batch);
            } else {
                // Successfully sent - reset retry count
                retry_count_ = 0;
            }
            
            last_batch_time = std::chrono::steady_clock::now();
        }
    }
    
    ErrorCode SendBatchWithRetry(const std::vector<ViolationEvent>& batch) {
        const int max_retries = 3;
        const int base_delay_ms = 1000;
        
        for (int attempt = 0; attempt <= max_retries; ++attempt) {
            ErrorCode result = SendBatch(batch);
            
            if (result == ErrorCode::Success) {
                return ErrorCode::Success;
            }
            
            // Check if error is transient
            if (result == ErrorCode::NetworkError || 
                result == ErrorCode::Timeout) {
                
                if (attempt < max_retries) {
                    // Exponential backoff
                    int delay = base_delay_ms * (1 << attempt);
                    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
                    continue;
                }
            }
            
            // Non-transient error or max retries reached
            return result;
        }
        
        return ErrorCode::NetworkError;
    }
    
    ErrorCode SendBatch(const std::vector<ViolationEvent>& batch) {
        if (batch.empty() || endpoint_.empty()) {
            return ErrorCode::InvalidParameter;
        }
        
        try {
            // Serialize batch to JSON
            json j_batch = json::array();
            
            for (const auto& event : batch) {
                json j_event = {
                    {"type", static_cast<uint32_t>(event.type)},
                    {"severity", static_cast<uint8_t>(event.severity)},
                    {"timestamp", event.timestamp},
                    {"address", event.address},
                    {"module", event.module_name},
                    {"details", event.details},
                    {"detection_id", event.detection_id}
                };
                j_batch.push_back(j_event);
            }
            
            json payload = {
                {"version", "1.0"},
                {"events", j_batch},
                {"batch_size", batch.size()},
                {"timestamp", GetCurrentTimestamp()}
            };
            
            std::string json_str = payload.dump();
            
            // Send HTTP POST request
            HttpHeaders headers;
            headers["Content-Type"] = "application/json";
            
            auto response = http_client_->postJson(endpoint_, json_str, headers);
            
            if (!response.isSuccess()) {
                // Network error - treat as transient
                return ErrorCode::NetworkError;
            }
            
            // Check HTTP status code
            if (!response.value().isSuccess()) {
                if (response.value().isServerError()) {
                    return ErrorCode::NetworkError; // Transient
                }
                return ErrorCode::InternalError; // Non-transient
            }
            
            return ErrorCode::Success;
            
        } catch (const std::exception&) {
            return ErrorCode::InternalError;
        }
    }
    
    bool HasCriticalEvent() const {
        for (const auto& event : event_queue_) {
            if (event.severity == Severity::Critical) {
                return true;
            }
        }
        return false;
    }
    
    void InitializeOfflineStorage() {
        try {
            offline_storage_path_ = GetOfflineStoragePath();
            
            // Create directory if it doesn't exist
            std::filesystem::create_directories(
                std::filesystem::path(offline_storage_path_).parent_path()
            );
            
            // Initialize encryption key from hardware
            auto random = SecureRandom();
            auto key_result = random.generateAESKey();
            if (key_result.isSuccess()) {
                encryption_key_ = key_result.value();
            }
            
            // Try to load existing offline events
            LoadFromOfflineStorage();
            
        } catch (const std::exception&) {
            // Offline storage initialization failed - continue without it
            offline_storage_path_.clear();
        }
    }
    
    std::string GetOfflineStoragePath() {
#ifdef _WIN32
        char path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
            return std::string(path) + "\\Sentinel\\violations.dat";
        }
#else
        const char* home = getenv("HOME");
        if (!home) {
            struct passwd* pw = getpwuid(getuid());
            if (pw) home = pw->pw_dir;
        }
        if (home) {
            return std::string(home) + "/.sentinel/violations.dat";
        }
#endif
        return "";
    }
    
    void SaveToOfflineStorage(const std::vector<ViolationEvent>& batch) {
        if (offline_storage_path_.empty() || encryption_key_.empty()) {
            return;
        }
        
        try {
            // Serialize batch to JSON
            json j_batch = json::array();
            for (const auto& event : batch) {
                json j_event = {
                    {"type", static_cast<uint32_t>(event.type)},
                    {"severity", static_cast<uint8_t>(event.severity)},
                    {"timestamp", event.timestamp},
                    {"address", event.address},
                    {"module", event.module_name},
                    {"details", event.details},
                    {"detection_id", event.detection_id}
                };
                j_batch.push_back(j_event);
            }
            
            std::string json_str = j_batch.dump();
            ByteBuffer plaintext(json_str.begin(), json_str.end());
            
            // Encrypt
            AESCipher cipher(encryption_key_);
            auto encrypted_result = cipher.encrypt(
                ByteSpan(plaintext.data(), plaintext.size())
            );
            
            if (!encrypted_result.isSuccess()) {
                return;
            }
            
            // Write to file (append mode)
            std::ofstream file(offline_storage_path_, 
                             std::ios::binary | std::ios::app);
            if (file) {
                const auto& encrypted = encrypted_result.value();
                
                // Write size header
                uint32_t size = static_cast<uint32_t>(encrypted.size());
                file.write(reinterpret_cast<const char*>(&size), sizeof(size));
                
                // Write encrypted data
                file.write(reinterpret_cast<const char*>(encrypted.data()), 
                          encrypted.size());
            }
            
        } catch (const std::exception&) {
            // Offline storage write failed - ignore
        }
    }
    
    void LoadFromOfflineStorage() {
        if (offline_storage_path_.empty() || encryption_key_.empty()) {
            return;
        }
        
        try {
            std::ifstream file(offline_storage_path_, std::ios::binary);
            if (!file) return;
            
            AESCipher cipher(encryption_key_);
            
            while (file) {
                // Read size header
                uint32_t size = 0;
                file.read(reinterpret_cast<char*>(&size), sizeof(size));
                if (!file || size == 0 || size > 1024 * 1024) break;
                
                // Read encrypted data
                ByteBuffer encrypted(size);
                file.read(reinterpret_cast<char*>(encrypted.data()), size);
                if (!file) break;
                
                // Decrypt
                auto decrypted_result = cipher.decrypt(
                    ByteSpan(encrypted.data(), encrypted.size())
                );
                if (!decrypted_result.isSuccess()) continue;
                
                // Parse JSON
                std::string json_str(decrypted_result.value().begin(), 
                                   decrypted_result.value().end());
                auto j_batch = json::parse(json_str);
                
                // Restore events to queue
                std::lock_guard<std::mutex> lock(queue_mutex_);
                for (const auto& j_event : j_batch) {
                    ViolationEvent event;
                    event.type = static_cast<ViolationType>(
                        j_event["type"].get<uint32_t>());
                    event.severity = static_cast<Severity>(
                        j_event["severity"].get<uint8_t>());
                    event.timestamp = j_event["timestamp"].get<uint64_t>();
                    event.address = j_event["address"].get<uint64_t>();
                    event.module_name = j_event["module"].get<std::string>();
                    event.details = j_event["details"].get<std::string>();
                    event.detection_id = j_event["detection_id"].get<uint32_t>();
                    
                    if (event_queue_.size() < max_queue_depth_) {
                        event_queue_.push_back(event);
                    }
                }
            }
            
            // Clear offline storage file after successful load
            file.close();
            std::filesystem::remove(offline_storage_path_);
            
        } catch (const std::exception&) {
            // Offline storage load failed - ignore
        }
    }
    
    void FlushToOfflineStorage() {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        
        if (event_queue_.empty()) return;
        
        // Convert deque to vector for SaveToOfflineStorage
        std::vector<ViolationEvent> batch(event_queue_.begin(), 
                                         event_queue_.end());
        SaveToOfflineStorage(batch);
    }
    
    static uint64_t GetCurrentTimestamp() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }
    
private:
    std::string endpoint_;
    uint32_t batch_size_;
    uint32_t interval_ms_;
    size_t max_queue_depth_;
    
    std::unique_ptr<HttpClient> http_client_;
    std::deque<ViolationEvent> event_queue_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    
    std::thread reporter_thread_;
    bool running_;
    
    // Retry state
    int retry_count_;
    
    // Offline storage
    std::string offline_storage_path_;
    AESKey encryption_key_;
};

// ============================================================================
// CloudReporter Public Interface
// ============================================================================

CloudReporter::CloudReporter(const char* endpoint)
    : endpoint_(endpoint ? endpoint : "")
    , batch_size_(10)
    , interval_ms_(30000)
    , running_(false)
{
    impl_ = std::make_unique<Impl>(endpoint);
    impl_->Start();
}

CloudReporter::~CloudReporter() {
    // Impl destructor will handle shutdown
}

void CloudReporter::SetBatchSize(uint32_t size) {
    batch_size_ = size;
    if (impl_) {
        impl_->SetBatchSize(size);
    }
}

void CloudReporter::SetInterval(uint32_t ms) {
    interval_ms_ = ms;
    if (impl_) {
        impl_->SetInterval(ms);
    }
}

void CloudReporter::SetRequestSigner(std::shared_ptr<Sentinel::Network::RequestSigner> signer) {
    if (impl_) {
        impl_->SetRequestSigner(signer);
    }
}

void CloudReporter::QueueEvent(const ViolationEvent& event) {
    if (impl_) {
        impl_->QueueEvent(event);
    }
}

ErrorCode CloudReporter::ReportCustomEvent(const char* type, const char* data) {
    if (impl_) {
        return impl_->ReportCustomEvent(type, data);
    }
    return ErrorCode::NotInitialized;
}

void CloudReporter::Flush() {
    if (impl_) {
        impl_->Flush();
    }
}

void CloudReporter::ReportThread() {
    // Implementation handled by Impl class
}

ErrorCode CloudReporter::SendBatch() {
    // Implementation handled by Impl class
    return ErrorCode::Success;
}

} // namespace SDK
} // namespace Sentinel
