/**
 * @file request_signing_example.cpp
 * @brief Example demonstrating request signing for API authentication
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2025
 * 
 * This example shows how to use RequestSigner to protect API requests
 * against replay attacks, tampering, and forgery.
 */

#include <Sentinel/Core/RequestSigner.hpp>
#include <Sentinel/Core/HttpClient.hpp>
#include <Sentinel/Core/Crypto.hpp>
#include <iostream>
#include <iomanip>
#include <memory>

using namespace Sentinel;
using namespace Sentinel::Network;
using namespace Sentinel::Crypto;

void printSection(const std::string& title) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << title << "\n";
    std::cout << std::string(60, '=') << "\n";
}

int main() {
    printSection("Sentinel Request Signing - Example");
    
    // ========================================================================
    // Step 1: Generate a client-specific secret key
    // ========================================================================
    printSection("1. Generate Client-Specific Secret");
    
    std::cout << "In production, derive the secret from initialization parameters:\n";
    std::cout << "  secret = HMAC-SHA256(masterKey, clientId + deviceId + timestamp)\n\n";
    
    SecureRandom random;
    auto secretResult = random.generate(32);
    if (secretResult.isFailure()) {
        std::cerr << "Failed to generate secret\n";
        return 1;
    }
    
    ByteBuffer clientSecret = secretResult.value();
    std::cout << "Generated 32-byte client secret: " 
              << toHex(ByteSpan(clientSecret.data(), clientSecret.size())).substr(0, 32) 
              << "...\n";
    
    // ========================================================================
    // Step 2: Create a RequestSigner
    // ========================================================================
    printSection("2. Create RequestSigner");
    
    auto signer = std::make_shared<RequestSigner>(
        ByteSpan(clientSecret.data(), clientSecret.size())
    );
    
    std::cout << "RequestSigner created with client-specific secret\n";
    std::cout << "This key should NEVER be hardcoded in the binary!\n";
    
    // ========================================================================
    // Step 3: Sign a request (client-side)
    // ========================================================================
    printSection("3. Sign HTTP Request (Client-Side)");
    
    std::string path = "/v1/heartbeat";
    std::string jsonPayload = R"({
        "player_id": 12345,
        "session_id": "abc123",
        "status": "active"
    })";
    ByteBuffer body(jsonPayload.begin(), jsonPayload.end());
    
    std::cout << "Request details:\n";
    std::cout << "  Method: POST\n";
    std::cout << "  Path: " << path << "\n";
    std::cout << "  Body: " << jsonPayload.substr(0, 50) << "...\n\n";
    
    auto signResult = signer->sign(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size())
    );
    
    if (signResult.isFailure()) {
        std::cerr << "Failed to sign request\n";
        return 1;
    }
    
    const auto& signedData = signResult.value();
    std::cout << "Signature headers:\n";
    std::cout << "  X-Signature: " << signedData.signature << "\n";
    std::cout << "  X-Timestamp: " << signedData.timestamp << "\n";
    
    // ========================================================================
    // Step 4: Verify request (server-side)
    // ========================================================================
    printSection("4. Verify Request (Server-Side)");
    
    std::cout << "Server validates signature using same client secret...\n\n";
    
    auto verifyResult = signer->verify(
        HttpMethod::POST,
        path,
        ByteSpan(body.data(), body.size()),
        signedData.signature,
        signedData.timestamp,
        60  // 60-second time window
    );
    
    if (verifyResult.isSuccess() && verifyResult.value()) {
        std::cout << "✓ Signature VALID - Request authenticated\n";
    } else {
        std::cout << "✗ Signature INVALID - Request rejected\n";
    }
    
    // ========================================================================
    // Step 5: Demonstrate attack prevention
    // ========================================================================
    printSection("5. Attack Prevention Demonstrations");
    
    // Tampered body
    std::cout << "\nAttempting to tamper with body...\n";
    ByteBuffer tamperedBody = {'h', 'a', 'c', 'k', 'e', 'd'};
    auto tamperedResult = signer->verify(
        HttpMethod::POST, path,
        ByteSpan(tamperedBody.data(), tamperedBody.size()),
        signedData.signature,
        signedData.timestamp
    );
    std::cout << (tamperedResult.isSuccess() && tamperedResult.value() 
                  ? "✗ VULNERABILITY: Tampered body accepted!\n"
                  : "✓ Tampered body rejected correctly\n");
    
    // Changed method
    std::cout << "\nAttempting to change HTTP method...\n";
    auto methodResult = signer->verify(
        HttpMethod::GET,  // Changed from POST
        path,
        ByteSpan(body.data(), body.size()),
        signedData.signature,
        signedData.timestamp
    );
    std::cout << (methodResult.isSuccess() && methodResult.value()
                  ? "✗ VULNERABILITY: Method change accepted!\n"
                  : "✓ Method change rejected correctly\n");
    
    // Changed path
    std::cout << "\nAttempting to change request path...\n";
    auto pathResult = signer->verify(
        HttpMethod::POST,
        "/v1/admin/ban_player",  // Different path
        ByteSpan(body.data(), body.size()),
        signedData.signature,
        signedData.timestamp
    );
    std::cout << (pathResult.isSuccess() && pathResult.value()
                  ? "✗ VULNERABILITY: Path change accepted!\n"
                  : "✓ Path change rejected correctly\n");
    
    // Replay attack (old timestamp)
    std::cout << "\nAttempting replay attack with old timestamp...\n";
    int64_t oldTimestamp = RequestSigner::getCurrentTimestamp() - (2 * 60 * 1000);
    auto oldSignResult = signer->sign(HttpMethod::POST, path, 
                                     ByteSpan(body.data(), body.size()), 
                                     oldTimestamp);
    if (oldSignResult.isSuccess()) {
        auto replayResult = signer->verify(
            HttpMethod::POST, path,
            ByteSpan(body.data(), body.size()),
            oldSignResult.value().signature,
            oldSignResult.value().timestamp,
            60  // 60-second window
        );
        std::cout << (replayResult.isSuccess() && replayResult.value()
                      ? "✗ VULNERABILITY: Replay attack succeeded!\n"
                      : "✓ Replay attack rejected correctly (timestamp too old)\n");
    }
    
    // Wrong key (forgery attempt)
    std::cout << "\nAttempting forgery with different secret key...\n";
    auto attackerSecretResult = random.generate(32);
    if (attackerSecretResult.isSuccess()) {
        RequestSigner attackerSigner(
            ByteSpan(attackerSecretResult.value().data(), 
                    attackerSecretResult.value().size())
        );
        auto forgedSignResult = attackerSigner.sign(HttpMethod::POST, path,
                                                    ByteSpan(body.data(), body.size()));
        if (forgedSignResult.isSuccess()) {
            auto forgeryResult = signer->verify(
                HttpMethod::POST, path,
                ByteSpan(body.data(), body.size()),
                forgedSignResult.value().signature,
                forgedSignResult.value().timestamp
            );
            std::cout << (forgeryResult.isSuccess() && forgeryResult.value()
                          ? "✗ VULNERABILITY: Forged signature accepted!\n"
                          : "✓ Forged signature rejected correctly (wrong key)\n");
        }
    }
    
    // ========================================================================
    // Step 6: Integration with HttpClient
    // ========================================================================
    printSection("6. HttpClient Integration");
    
    std::cout << "Setting up HttpClient with automatic request signing...\n\n";
    
    HttpClient client;
    client.setRequestSigner(signer);
    
    std::cout << "All HTTP requests will now automatically include:\n";
    std::cout << "  • X-Signature header (HMAC-SHA256 signature)\n";
    std::cout << "  • X-Timestamp header (current timestamp)\n\n";
    
    std::cout << "Example usage:\n";
    std::cout << "  HttpRequest request;\n";
    std::cout << "  request.url = \"https://api.sentinel.com/v1/heartbeat\";\n";
    std::cout << "  request.method = HttpMethod::POST;\n";
    std::cout << "  request.body = jsonPayload;\n";
    std::cout << "  auto response = client.send(request);\n";
    std::cout << "  // Signature headers automatically added!\n";
    
    // ========================================================================
    // Summary
    // ========================================================================
    printSection("Security Summary");
    
    std::cout << "\nRequest signing provides defense against:\n\n";
    std::cout << "✓ Replay Attacks\n";
    std::cout << "  - Timestamp validation (60-second window)\n";
    std::cout << "  - Old requests are automatically rejected\n\n";
    
    std::cout << "✓ Request Tampering\n";
    std::cout << "  - Body hash included in signature\n";
    std::cout << "  - Any modification invalidates signature\n\n";
    
    std::cout << "✓ Request Forgery\n";
    std::cout << "  - Client-specific secret keys\n";
    std::cout << "  - Attacker cannot forge valid signatures\n\n";
    
    std::cout << "✓ Timing Attacks\n";
    std::cout << "  - Constant-time signature comparison\n";
    std::cout << "  - No timing side-channel leakage\n\n";
    
    std::cout << "✓ Method/Path Manipulation\n";
    std::cout << "  - HTTP method and path included in signature\n";
    std::cout << "  - Cannot be changed without detection\n\n";
    
    std::cout << "Best Practices:\n";
    std::cout << "  • Never hardcode signing keys in binaries\n";
    std::cout << "  • Derive keys from client-specific parameters\n";
    std::cout << "  • Rotate keys periodically\n";
    std::cout << "  • Use HTTPS for transport security\n";
    std::cout << "  • Validate timestamps server-side\n";
    std::cout << "  • Monitor for replay attempt patterns\n\n";
    
    return 0;
}
