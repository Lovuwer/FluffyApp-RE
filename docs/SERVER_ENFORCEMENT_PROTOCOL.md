# Server-Authoritative Enforcement Protocol

**Task 24: Server-Authoritative Enforcement Model**

## Overview

The Sentinel SDK implements a **server-authoritative enforcement model** where:
- **Client SDK**: Detects threats and reports to server (zero enforcement authority)
- **Server**: Receives reports, makes decisions, issues cryptographically-signed directives
- **Game**: Implements server directives as authoritative commands

This prevents attackers from bypassing enforcement by compromising the client.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Server-Authoritative Model                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────┐         ┌──────────────┐         ┌───────────┐ │
│  │   Client   │  Report │    Server    │ Directive│   Game    │ │
│  │    SDK     │────────>│  (Authority) │────────>│  Process  │ │
│  │            │         │              │         │           │ │
│  │ • Detect   │         │ • Receive    │         │ • Execute │ │
│  │ • Report   │         │ • Analyze    │         │ • Enforce │ │
│  │ • NO ENFORCE│        │ • Decide     │         │           │ │
│  └────────────┘         └──────────────┘         └───────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Protocol Details

### 1. Detection and Reporting

SDK detects violations and reports to server:

```cpp
// Violation detected
ViolationEvent event;
event.type = ViolationType::DebuggerAttached;
event.severity = Severity::Critical;

// SDK ONLY reports - does NOT enforce locally
CloudReporter::QueueEvent(event);  // Sent to server
```

### 2. Server Directive Structure

```json
{
  "type": 2,              // SessionTerminate
  "reason": 1,            // CheatDetected
  "sequence": 42,         // Monotonic sequence (replay protection)
  "timestamp": 1704070800000,
  "expires_at": 1704074400000,
  "session_id": "session_abc123",
  "message": "Cheat detected: Debugger attached",
  "signature": "Base64(HMAC-SHA256(...))"
}
```

### 3. Security Features

#### Replay Protection
- **Monotonic sequence numbers**: Server increments sequence for each directive
- **Client validation**: Rejects directives with sequence ≤ last_seen
- **Prevents replay attacks**: Old directives cannot be reused

#### Signature Authentication
- **HMAC-SHA256 signing**: Server signs directives with shared secret
- **Message format**: `type|reason|sequence|timestamp|expires_at|session_id|message`
- **Constant-time comparison**: Prevents timing attacks
- **Prevents forgery**: Client cannot create valid directives

#### Timestamp Validation
- **60-second tolerance**: Allows for clock skew
- **Expiration checking**: Directives expire after specified time
- **Prevents stale directives**: Old directives rejected automatically

## Client Integration

### Basic Setup

```cpp
#include <SentinelSDK.hpp>

// 1. Configure SDK with directive callback
Configuration config = Configuration::Default();
config.license_key = "your-license-key";
config.game_id = "your-game-id";
config.cloud_endpoint = "https://your-server.com/api/v1/violations";

// 2. Set directive callback
config.directive_callback = DirectiveHandler;
config.directive_user_data = &game_state;
config.directive_poll_interval_ms = 5000;  // Poll every 5 seconds

// 3. Initialize SDK
Initialize(&config);
```

### Directive Handler

```cpp
bool DirectiveHandler(const ServerDirective* directive, void* user_data) {
    if (!directive) return false;
    
    GameState* state = static_cast<GameState*>(user_data);
    
    switch (directive->type) {
        case ServerDirectiveType::SessionTerminate:
            // MUST terminate - server authority
            LogInfo("Server terminated session: %s", directive->message);
            state->terminated = true;
            DisconnectFromServer();
            ExitGame();
            return true;
            
        case ServerDirectiveType::RequireReconnect:
            // Reconnect to server
            LogInfo("Server requires reconnect: %s", directive->message);
            ReconnectToServer();
            return true;
            
        case ServerDirectiveType::SessionContinue:
            // Explicit approval to continue
            LogInfo("Server approved session continuation");
            return true;
            
        default:
            LogWarning("Unknown directive type: %d", directive->type);
            return false;
    }
}
```

### Manual Polling (Optional)

Automatic polling runs in heartbeat thread, but you can poll manually:

```cpp
// Manual poll
ErrorCode result = PollServerDirectives();
if (result == ErrorCode::Success) {
    ServerDirective directive;
    if (GetLastServerDirective(&directive)) {
        // Process directive
        HandleDirective(&directive);
    }
}
```

## Server Implementation

### Receiving Violation Reports

```python
@app.post("/api/v1/violations")
async def receive_violations(request: ViolationReport):
    # Validate request signature (Task 4: Request signing)
    if not validate_hmac(request):
        return {"error": "Invalid signature"}, 401
    
    # Store violations for analysis
    for violation in request.events:
        await db.violations.insert({
            "session_id": request.session_id,
            "type": violation.type,
            "severity": violation.severity,
            "timestamp": violation.timestamp,
            "details": violation.details
        })
    
    # Analyze violations (real-time or batch)
    decision = analyze_violations(request.session_id)
    
    # Store decision for directive polling
    if decision.should_terminate:
        await create_directive(
            session_id=request.session_id,
            type="SessionTerminate",
            reason="CheatDetected",
            message=f"Violation detected: {decision.reason}"
        )
    
    return {"status": "received"}
```

### Issuing Directives

```python
async def create_directive(session_id: str, type: str, reason: str, message: str):
    # Get next sequence number (atomic increment)
    sequence = await db.sessions.increment_sequence(session_id)
    
    # Create directive
    directive = {
        "type": DIRECTIVE_TYPES[type],
        "reason": DIRECTIVE_REASONS[reason],
        "sequence": sequence,
        "timestamp": int(time.time() * 1000),
        "expires_at": int((time.time() + 3600) * 1000),  # 1 hour expiry
        "session_id": session_id,
        "message": message
    }
    
    # Sign directive
    message_to_sign = (
        f"{directive['type']}|{directive['reason']}|"
        f"{directive['sequence']}|{directive['timestamp']}|"
        f"{directive['expires_at']}|{directive['session_id']}|"
        f"{directive['message']}"
    )
    directive["signature"] = hmac_sha256(message_to_sign, get_secret(session_id))
    
    # Store for polling
    await db.directives.insert(session_id, directive)
    
    return directive
```

### Directive Polling Endpoint

```python
@app.get("/api/v1/violations/directives")
async def poll_directives(session_id: str):
    # Validate session
    if not await validate_session(session_id):
        return {"error": "Invalid session"}, 401
    
    # Get pending directive (if any)
    directive = await db.directives.get_latest(session_id)
    
    if not directive:
        return {"status": "no_directive"}, 404
    
    # Return directive (client validates signature)
    return directive
```

## Enforcement Latency

### Expected Latency

| Stage | Time | Notes |
|-------|------|-------|
| Detection | < 1s | SDK detects violation |
| Report to server | < 5s | Batched reporting (configurable) |
| Server analysis | < 2s | Real-time decision engine |
| Directive polling | < 5s | Client polls every 5s (configurable) |
| **Total end-to-end** | **< 13s** | Under normal conditions |

### Optimization

- **Immediate flush**: Critical violations trigger immediate report (not batched)
- **Push notifications**: Consider WebSocket for sub-second directive delivery
- **Directive caching**: Server can pre-generate directives for common cases

## Security Considerations

### What This Protects Against

✅ **Local enforcement bypass**: Attacker cannot simply skip ban checks  
✅ **Directive forgery**: Client cannot create fake session_terminate directives  
✅ **Replay attacks**: Old directives cannot be reused  
✅ **Timing attacks**: Constant-time signature comparison  

### What This Does NOT Protect Against

❌ **Server compromise**: If server is compromised, directives can be forged  
❌ **Network interception**: Use TLS to protect directive transmission  
❌ **Coordinated bot attacks**: Requires additional server-side detection  
❌ **Game process termination**: Attacker can kill game process regardless  

### Best Practices

1. **Always validate directives**: Check signature, sequence, timestamp, expiry
2. **Never cache directives**: Always fetch fresh from server
3. **Log all directives**: For audit trail and debugging
4. **Implement rate limiting**: Prevent directive polling DoS
5. **Use TLS**: Encrypt all client-server communication
6. **Rotate secrets**: Periodically rotate HMAC signing keys
7. **Monitor latency**: Alert if enforcement latency exceeds SLA

## Testing

### Unit Tests (TODO)

```cpp
TEST(ServerDirective, ValidateSequence) {
    DirectiveValidator validator(signer, "session_123");
    
    ServerDirective directive1 = CreateTestDirective(sequence: 1);
    ServerDirective directive2 = CreateTestDirective(sequence: 2);
    ServerDirective directive3 = CreateTestDirective(sequence: 1);  // Replay
    
    EXPECT_TRUE(validator.validate(directive1).isSuccess());
    EXPECT_TRUE(validator.validate(directive2).isSuccess());
    EXPECT_FALSE(validator.validate(directive3).isSuccess());  // Replay rejected
}

TEST(ServerDirective, ValidateSignature) {
    DirectiveValidator validator(signer, "session_123");
    
    ServerDirective valid = CreateTestDirective(signature: "valid_hmac");
    ServerDirective invalid = CreateTestDirective(signature: "forged_hmac");
    
    EXPECT_TRUE(validator.validate(valid).isSuccess());
    EXPECT_FALSE(validator.validate(invalid).isSuccess());
}
```

## Migration Guide

### From Client-Side Enforcement

**Before (INSECURE):**
```cpp
void ReportViolation(const ViolationEvent& event) {
    // Report to server
    reporter->QueueEvent(event);
    
    // LOCAL ENFORCEMENT (BYPASSABLE!)
    if (event.severity == Severity::Critical) {
        BanPlayer();  // ❌ Client can bypass this
        TerminateProcess();  // ❌ Client can bypass this
    }
}
```

**After (SECURE):**
```cpp
void ReportViolation(const ViolationEvent& event) {
    // ONLY report to server
    reporter->QueueEvent(event);
    
    // NO local enforcement - server will issue directive
}

// Separate handler for server directives
void OnServerDirective(const ServerDirective* directive) {
    if (directive->type == ServerDirectiveType::SessionTerminate) {
        // Server authority - MUST enforce
        TerminateSession();
    }
}
```

## FAQ

**Q: What if the client doesn't poll for directives?**  
A: Server can implement timeout-based bans. If client stops polling, assume compromise.

**Q: What if network is down when directive is issued?**  
A: Directives expire after a timeout. Client will receive it on next successful poll. Server can re-issue if needed.

**Q: Can an attacker ignore directives?**  
A: Yes, but this requires game process modification. Server can detect missing acknowledgments and escalate enforcement (HWID ban, account suspension).

**Q: What about latency for competitive games?**  
A: Consider WebSocket push for sub-second delivery. Polling is suitable for most games (5-10s latency).

**Q: How do I test this without a server?**  
A: Implement a mock server or use manual directive injection via `SetServerDirectiveCallback()`.

## Conclusion

The server-authoritative enforcement model ensures that:
- **Client has zero enforcement authority** - only detection and reporting
- **Server makes all enforcement decisions** - the single source of truth
- **Directives are cryptographically authenticated** - prevents forgery
- **Replay attacks are prevented** - monotonic sequence numbers
- **Enforcement cannot be bypassed locally** - requires server cooperation

This is a **fundamental security improvement** over client-side enforcement.
