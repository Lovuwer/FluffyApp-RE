/**
 * @file ServerDirective.cpp
 * @brief Server directive validation implementation
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * Task 24: Server-Authoritative Enforcement Model
 */

#include <Sentinel/Core/ServerDirective.hpp>
#include <Sentinel/Core/RequestSigner.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <Sentinel/Core/HttpClient.hpp>  // Task 24: For HttpMethod enum
#include <nlohmann/json.hpp>
#include <sstream>
#include <cstring>

namespace Sentinel::Network {

using json = nlohmann::json;
using namespace Sentinel::Crypto;

// ============================================================================
// DirectiveValidator Implementation
// ============================================================================

class DirectiveValidator::Impl {
public:
    explicit Impl(
        std::shared_ptr<RequestSigner> signer,
        const std::string& session_id
    )
        : signer_(std::move(signer))
        , session_id_(session_id)
        , last_sequence_(0)
    {
    }
    
    Result<bool> validate(const ServerDirective& directive) {
        // Check 1: Session ID must match
        if (directive.session_id != session_id_) {
            return ErrorCode::AuthenticationFailed;
        }
        
        // Check 2: Timestamp must be within tolerance
        if (!directive.isTimestampValid(60)) {
            return ErrorCode::AuthenticationFailed;
        }
        
        // Check 3: Directive must not be expired
        if (directive.isExpired()) {
            return ErrorCode::AuthenticationFailed;
        }
        
        // Check 4: Sequence must be higher than last seen (prevents replay)
        if (directive.sequence <= last_sequence_) {
            return ErrorCode::AuthenticationFailed;  // Replay attack
        }
        
        // Check 5: Verify HMAC signature
        if (!verifySignature(directive)) {
            return ErrorCode::AuthenticationFailed;  // Signature mismatch
        }
        
        // All checks passed - update sequence tracker
        last_sequence_ = directive.sequence;
        
        return true;
    }
    
    uint64_t getLastSequence() const {
        return last_sequence_;
    }
    
    void resetSequence() {
        last_sequence_ = 0;
    }
    
    void updateSessionId(const std::string& session_id) {
        session_id_ = session_id;
        // Reset sequence on session change
        last_sequence_ = 0;
    }

private:
    bool verifySignature(const ServerDirective& directive) {
        if (!signer_) {
            return false;
        }
        
        // Construct message to sign (same format server uses)
        // Format: type|reason|sequence|timestamp|expires_at|session_id|message
        std::ostringstream oss;
        oss << static_cast<uint32_t>(directive.type) << "|"
            << static_cast<uint32_t>(directive.reason) << "|"
            << directive.sequence << "|"
            << directive.timestamp << "|"
            << directive.expires_at << "|"
            << directive.session_id << "|"
            << directive.message;
        
        std::string message = oss.str();
        
        // Sign using POST method with directive path
        auto sign_result = signer_->sign(
            HttpMethod::POST,
            "/v1/directive",
            ByteSpan(reinterpret_cast<const Byte*>(message.data()), message.size()),
            directive.timestamp
        );
        
        if (!sign_result.isSuccess()) {
            return false;
        }
        
        // Constant-time comparison to prevent timing attacks
        const auto& expected_sig = sign_result.value().signature;
        const auto& actual_sig = directive.signature;
        
        if (expected_sig.size() != actual_sig.size()) {
            return false;
        }
        
        // Constant-time comparison
        volatile unsigned char result = 0;
        for (size_t i = 0; i < expected_sig.size(); ++i) {
            result |= expected_sig[i] ^ actual_sig[i];
        }
        
        return result == 0;
    }
    
    std::shared_ptr<RequestSigner> signer_;
    std::string session_id_;
    uint64_t last_sequence_;
};

DirectiveValidator::DirectiveValidator(
    std::shared_ptr<RequestSigner> signer,
    const std::string& session_id
)
    : m_impl(std::make_unique<Impl>(std::move(signer), session_id))
{
}

DirectiveValidator::~DirectiveValidator() = default;

DirectiveValidator::DirectiveValidator(DirectiveValidator&&) noexcept = default;
DirectiveValidator& DirectiveValidator::operator=(DirectiveValidator&&) noexcept = default;

Result<bool> DirectiveValidator::validate(const ServerDirective& directive) {
    return m_impl->validate(directive);
}

uint64_t DirectiveValidator::getLastSequence() const {
    return m_impl->getLastSequence();
}

void DirectiveValidator::resetSequence() {
    m_impl->resetSequence();
}

void DirectiveValidator::updateSessionId(const std::string& session_id) {
    m_impl->updateSessionId(session_id);
}

// ============================================================================
// JSON Parsing/Serialization
// ============================================================================

Result<ServerDirective> parseDirective(const std::string& json_str) {
    try {
        auto j = json::parse(json_str);
        
        ServerDirective directive;
        directive.type = static_cast<DirectiveType>(
            j.value("type", 0u)
        );
        directive.reason = static_cast<DirectiveReason>(
            j.value("reason", 0u)
        );
        directive.sequence = j.value("sequence", 0ull);
        directive.timestamp = j.value("timestamp", 0ll);
        directive.expires_at = j.value("expires_at", 0ll);
        directive.session_id = j.value("session_id", "");
        directive.message = j.value("message", "");
        directive.signature = j.value("signature", "");
        
        return directive;
        
    } catch (const json::exception&) {
        return ErrorCode::JsonParseFailed;
    }
}

std::string serializeDirective(const ServerDirective& directive) {
    json j = {
        {"type", static_cast<uint32_t>(directive.type)},
        {"reason", static_cast<uint32_t>(directive.reason)},
        {"sequence", directive.sequence},
        {"timestamp", directive.timestamp},
        {"expires_at", directive.expires_at},
        {"session_id", directive.session_id},
        {"message", directive.message},
        {"signature", directive.signature}
    };
    
    return j.dump();
}

} // namespace Sentinel::Network
