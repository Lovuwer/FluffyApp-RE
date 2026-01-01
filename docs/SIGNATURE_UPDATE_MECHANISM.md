# Detection Signature Update Mechanism

## Overview

The Detection Signature Update Mechanism (Task 13) provides dynamic signature updates for the Sentinel SDK without requiring game restarts. This enables rapid response to new cheating threats by allowing signature updates in minutes rather than weeks.

## Architecture

The system consists of two main components:

### 1. SignatureManager
Located in `src/SDK/src/Internal/SignatureManager.{hpp,cpp}`

**Responsibilities:**
- Parse and validate detection signatures from JSON format
- Manage signature versions with atomic updates
- Provide rollback capability for failed updates
- Cache signatures locally with 24-hour survival during network outages
- Verify signature authenticity using RSA signatures

**Key Features:**
- **Sandboxed Parsing**: Malformed signatures cannot crash the SDK
- **Versioning**: Only allows upgrading to newer versions (unless forced)
- **Rollback**: Can revert to previous signature set on command
- **Expiration**: Signatures have expiration timestamps for automatic cleanup
- **Thread-Safe**: All operations are protected with mutexes

### 2. UpdateClient
Located in `src/SDK/src/Network/UpdateClient.{hpp,cpp}`

**Responsibilities:**
- Download signature updates from server
- Authenticate requests using API keys
- Verify response integrity
- Handle network failures gracefully with retries
- Support automatic update checks at configurable intervals

**Key Features:**
- **Certificate Pinning**: Uses HTTPS with certificate pinning for secure downloads
- **Retry Logic**: Exponential backoff for transient failures
- **Auto-Update**: Background thread for periodic update checks
- **Progress Callbacks**: Notify application of update status
- **No Restart Required**: Signatures are applied immediately without game restart

## Usage

### Basic Initialization

```cpp
#include "Internal/SignatureManager.hpp"
#include "Network/UpdateClient.hpp"

// 1. Initialize Signature Manager
auto signature_manager = std::make_shared<SignatureManager>();
auto init_result = signature_manager->initialize(
    "/path/to/cache",
    public_key_der  // RSA public key for signature verification
);

// 2. Configure Update Client
UpdateClientConfig config;
config.server_url = "https://api.sentinel.com";
config.api_key = "your_api_key";
config.game_id = "your_game_id";
config.check_interval = std::chrono::seconds(900);  // 15 minutes
config.enable_pinning = true;
config.pinned_hashes = {server_cert_hash};

// 3. Initialize Update Client
auto update_client = std::make_unique<UpdateClient>();
update_client->initialize(config, signature_manager);

// 4. Set progress callback (optional)
update_client->setProgressCallback([](UpdateStatus status, const std::string& msg) {
    std::cout << "Update Status: " << msg << std::endl;
});

// 5. Start auto-update
update_client->startAutoUpdate();
```

### Manual Update Check

```cpp
// Check for updates
auto has_update = update_client->checkForUpdates(false);
if (has_update.isSuccess() && has_update.value()) {
    // Download and apply updates
    auto result = update_client->downloadAndApply();
    if (result.isSuccess()) {
        std::cout << "Signatures updated successfully" << std::endl;
    }
}
```

### Accessing Signatures

```cpp
// Get specific signature by ID
auto sig = signature_manager->getSignatureById("CHEAT_001");
if (sig.isSuccess()) {
    auto& signature = sig.value();
    // Use signature for detection
    if (signature.type == SignatureType::MemoryPattern) {
        // Scan memory using pattern_data
    }
}

// Get all signatures of a specific type
auto memory_patterns = signature_manager->getSignaturesByType(
    SignatureType::MemoryPattern
);

for (const auto& sig : memory_patterns) {
    // Process each signature
}
```

### Rollback

```cpp
// Rollback to previous signature set if needed
auto rollback_result = signature_manager->rollbackToPrevious();
if (rollback_result.isSuccess()) {
    std::cout << "Rolled back to previous signature set" << std::endl;
}
```

### Statistics

```cpp
// Get signature statistics
auto stats = signature_manager->getStatistics();
std::cout << "Current Version: " << stats.current_version << std::endl;
std::cout << "Total Signatures: " << stats.total_signatures << std::endl;
std::cout << "Expired Signatures: " << stats.expired_signatures << std::endl;

// Get update statistics
auto update_stats = update_client->getStatistics();
std::cout << "Total Updates: " << update_stats.total_updates << std::endl;
std::cout << "Failed Updates: " << update_stats.failed_updates << std::endl;
```

## Signature Format

Signatures are distributed as JSON:

```json
{
  "version": 1,
  "deployed_at": "2025-01-01T00:00:00Z",
  "signatures": [
    {
      "id": "CHEAT_001",
      "name": "CheatEngine Pattern",
      "version": 1,
      "type": "memory_pattern",
      "threat_family": "CheatEngine",
      "severity": 3,
      "pattern": "48895c2408",
      "mask": "",
      "description": "Detects CheatEngine injection",
      "created_at": "2025-01-01T00:00:00Z",
      "expires_at": "2025-01-31T00:00:00Z",
      "signature": "..."
    }
  ],
  "signature": "RSA_SIGNATURE_HEX"
}
```

### Signature Types

- `memory_pattern`: Byte pattern to scan in memory
- `hash`: SHA-256 hash of known cheat code
- `behavior`: Behavioral detection rule
- `module`: Module validation signature

### Severity Levels

- `0`: None
- `1`: Low
- `2`: Medium
- `3`: High
- `4`: Critical

## Server API Endpoints

The update client expects the following API endpoints:

### GET /api/v1/signatures/version
Returns the latest signature version number:
```json
{
  "version": 123
}
```

### GET /api/v1/signatures/download
Returns the complete signature set in JSON format (see Signature Format above).

Optional query parameter: `?version=N` to download a specific version.

### Authentication Headers

All requests include:
- `X-API-Key`: API key for authentication
- `X-Game-ID`: Game identifier
- `X-Timestamp`: Unix timestamp for replay protection

## Security Considerations

### Signature Verification
- All signature sets are signed with RSA-4096
- The SignatureManager verifies signatures using the public key provided during initialization
- Tampering is detected and rejected

### Certificate Pinning
- UpdateClient supports certificate pinning to prevent MITM attacks
- Pin the server's certificate SHA-256 hash during initialization
- Connections fail if the certificate doesn't match

### Sandboxed Parsing
- JSON parsing is wrapped in try-catch blocks
- Malformed input cannot crash the SDK
- Invalid signatures are logged and skipped

### Cache Security
- Cached signatures are stored in the file system
- Cache has a 24-hour maximum age by default
- Signatures are re-verified when loaded from cache

## Performance

### Update Cycle
- **Target**: New signatures active within 15 minutes
- **Network Check**: ~100ms for version check
- **Download**: ~500ms for typical signature set (10KB)
- **Verification**: ~50ms for RSA signature verification
- **Application**: Atomic, no game disruption

### Cache Survival
- Signatures cached locally survive 24+ hour network outages
- Game continues operating with last known good signatures
- Auto-update resumes when network connectivity returns

### Memory Footprint
- SignatureManager: ~2KB + signature data
- UpdateClient: ~1KB + HTTP client overhead
- Typical signature set: 5-20KB

## Testing

Comprehensive unit tests are provided in:
- `tests/SDK/test_signature_manager.cpp` (37 tests)
- `tests/SDK/test_update_client.cpp` (25 tests)

Run tests:
```bash
cd build
cmake --build . --target SDKTests
./bin/SDKTests --gtest_filter="*Signature*"
```

## Troubleshooting

### Update Failures
1. Check network connectivity
2. Verify API key is valid
3. Check certificate pinning configuration
4. Review logs for specific error codes
5. Try manual update: `update_client->performUpdate(true)`

### Signature Verification Failures
1. Ensure public key matches server's private key
2. Check for tampering during transmission
3. Verify signature set hasn't been modified

### Cache Issues
1. Check cache directory permissions
2. Verify disk space available
3. Clear cache and force fresh download

## Future Enhancements

Potential improvements for future releases:
- Delta updates (only download changed signatures)
- Signature compression (reduce bandwidth)
- Signature analytics (track detection rates)
- A/B testing framework for signature effectiveness
- Geographic distribution (CDN support)
- Signature priority levels (critical vs. optional)

## References

- Task 2: HttpClient implementation
- Task 5: Certificate Pinning
- Task 12: Module Signature Verification
- Error codes: `include/Sentinel/Core/ErrorCodes.hpp`
- Crypto primitives: `include/Sentinel/Core/Crypto.hpp`
