/**
 * @file CertPinner.cpp
 * @brief Certificate pinner implementation for HttpClient
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * @copyright Copyright (c) 2025 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/Network.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <vector>
#include <algorithm>

namespace Sentinel::Network {

class CertPinner::Impl {
public:
    std::vector<CertificatePin> pins_;
};

CertPinner::CertPinner() : m_impl(std::make_unique<Impl>()) {}

CertPinner::~CertPinner() = default;

void CertPinner::addPin(const CertificatePin& pin) {
    m_impl->pins_.push_back(pin);
}

void CertPinner::addPins(const std::vector<CertificatePin>& pins) {
    m_impl->pins_.insert(m_impl->pins_.end(), pins.begin(), pins.end());
}

void CertPinner::removePin(const std::string& hostname) {
    auto it = std::remove_if(m_impl->pins_.begin(), m_impl->pins_.end(),
        [&hostname](const CertificatePin& pin) {
            return pin.hostname == hostname;
        });
    m_impl->pins_.erase(it, m_impl->pins_.end());
}

void CertPinner::clearPins() {
    m_impl->pins_.clear();
}

bool CertPinner::verify(
    const std::string& hostname,
    const std::vector<ByteBuffer>& certChain
) const {
    // Find pins for this hostname
    std::vector<const CertificatePin*> matchingPins;
    
    for (const auto& pin : m_impl->pins_) {
        if (pin.hostname == hostname) {
            matchingPins.push_back(&pin);
        } else if (pin.includeSubdomains && hostname.size() > pin.hostname.size()) {
            // Check if hostname is a subdomain
            std::string suffix = hostname.substr(hostname.size() - pin.hostname.size());
            if (suffix == pin.hostname && 
                hostname[hostname.size() - pin.hostname.size() - 1] == '.') {
                matchingPins.push_back(&pin);
            }
        }
    }
    
    // If no pins configured for this hostname, allow by default
    if (matchingPins.empty()) {
        return true;
    }
    
    // Check if any certificate in the chain matches any pin
    for (const auto& cert : certChain) {
        auto hashResult = computeSPKIHash(cert);
        if (hashResult.isFailure()) {
            continue; // Skip invalid certificates
        }
        
        std::string certHashBase64 = hashResult.value();
        
        // Check against all matching pins
        for (const auto* pin : matchingPins) {
            for (const auto& pinHash : pin->pins) {
                // Convert pin hash to base64 for comparison
                std::string pinHashBase64 = Crypto::toBase64(pinHash);
                if (pinHashBase64 == certHashBase64) {
                    return true; // Pin matched
                }
            }
        }
    }
    
    // No pin matched - fail closed
    return false;
}

const std::vector<CertificatePin>& CertPinner::getPins() const {
    return m_impl->pins_;
}

} // namespace Sentinel::Network
