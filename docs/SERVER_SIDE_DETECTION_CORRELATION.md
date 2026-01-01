# Server-Side Detection Correlation Specification

**Document Version:** 1.0  
**Date:** 2026-01-01  
**Classification:** Implementation Specification  
**Priority:** P1  
**Risk Addressed:** Client-side detection bypass through report suppression

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Threat Model](#threat-model)
3. [Client-Side Implementation](#client-side-implementation)
4. [Server-Side Gap Detection](#server-side-gap-detection)
5. [Challenge-Response Protocol](#challenge-response-protocol)
6. [Behavioral Correlation](#behavioral-correlation)
7. [Integration Requirements](#integration-requirements)
8. [Testing and Validation](#testing-and-validation)
9. [Security Considerations](#security-considerations)

---

## Executive Summary

### Problem Statement

Client-side anti-cheat detection can be defeated if attackers can block or modify violation reports before they reach the server. Attackers use local proxies to:
- Filter out violation reports while allowing heartbeats through
- Modify report contents to hide detected cheats
- Suppress specific detection types selectively

Without server-side verification, the server sees a "healthy" client that never detects anything, making the attack completely undetectable.

### Solution Overview

This specification defines a comprehensive server-side correlation system with three defense layers:

1. **Sequential Report Numbering**: Every report batch includes a monotonically increasing sequence number. The server detects gaps indicating suppressed reports.

2. **Challenge-Response Verification**: Server randomly requests specific detection results. Client failure to respond correctly indicates tampering.

3. **Behavioral Correlation**: Server correlates player behavior telemetry with violation reports. Expected violations should occur for observed behavior.

---

## Threat Model

### Attacker Capabilities

**ASSUMPTION 1**: Attacker controls local network traffic
- Can run local proxy (e.g., mitmproxy, Burp Suite)
- Can inspect, modify, drop packets
- Can bypass certificate pinning by patching the binary

**ASSUMPTION 2**: Attacker knows protocol format
- Has reverse-engineered report JSON structure
- Understands message types and routing

**ASSUMPTION 3**: Attacker goal is selective suppression
- Allow heartbeats (maintain "healthy" client appearance)
- Block violation reports (hide detected cheats)
- Maintain low detection profile

### Defense Requirements

**REQUIREMENT 1**: Server must detect missing reports
- Even if heartbeats continue
- Without requiring explicit "I was tampered with" messages from client

**REQUIREMENT 2**: Server must validate report completeness
- Challenge client to prove it performed detections
- Verify client can reproduce detection results on demand

**REQUIREMENT 3**: Server must correlate behavior with detections
- Observed player actions should trigger expected violations
- Absence of expected violations indicates suppression

---

## Client-Side Implementation

### Report Sequence Numbering

The Sentinel SDK CloudReporter implements sequential numbering for all report batches:

```cpp
// CloudReporter.cpp - Impl class members
uint64_t report_sequence_number_;  // Starts at 0, increments per batch
std::mutex sequence_mutex_;        // Thread-safe access

// SendBatch() implementation
uint64_t sequence_num;
{
    std::lock_guard<std::mutex> lock(sequence_mutex_);
    sequence_num = report_sequence_number_++;
}

json payload = {
    {"version", "1.0"},
    {"sequence", sequence_num},        // ← Server uses this for gap detection
    {"events", j_batch},
    {"batch_size", batch.size()},
    {"timestamp", GetCurrentTimestamp()}
};
```

### Sequence Behavior

- **Initialization**: Sequence starts at 0 when CloudReporter is created
- **Increment**: Increments by 1 for each batch sent (not per event)
- **Persistence**: Sequence resets on client restart (session-scoped)
- **Thread Safety**: Mutex-protected increment ensures no duplicates or skips
- **Offline Buffering**: Sequence numbers are preserved when reports are buffered offline

### Session Management

Each client session has a unique `session_id` (typically part of authentication token). The server tracks sequence numbers per session:

```
Session Lifecycle:
1. Client authenticates → Server creates session record
2. First report batch → Server records sequence=0
3. Subsequent batches → Server validates monotonic increase
4. Client disconnects → Server marks session ended
5. Client reconnects → New session, sequence resets to 0
```

---

## Server-Side Gap Detection

### Algorithm Overview

The server maintains per-session sequence tracking and detects gaps in real-time:

```pseudocode
FUNCTION OnReportReceived(session_id, report_data)
    # Parse sequence number
    received_seq := report_data.sequence
    
    # Get session state
    session := GetOrCreateSession(session_id)
    
    # First report for this session
    IF session.expected_sequence IS NULL THEN
        IF received_seq != 0 THEN
            RETURN ReportAnomaly("First sequence not zero", session_id, received_seq)
        END IF
        session.expected_sequence := 1
        session.last_report_time := NOW()
        RETURN SUCCESS
    END IF
    
    # Check for gap
    IF received_seq < session.expected_sequence THEN
        RETURN ReportAnomaly("Sequence regression", session_id, received_seq)
    ELSE IF received_seq > session.expected_sequence THEN
        gap_size := received_seq - session.expected_sequence
        RETURN ReportAnomaly("Sequence gap detected", session_id, 
                            gap_size, session.expected_sequence, received_seq)
    END IF
    
    # Sequence is correct
    session.expected_sequence := received_seq + 1
    session.last_report_time := NOW()
    session.gap_count := 0  # Reset consecutive gap counter
    RETURN SUCCESS
END FUNCTION

FUNCTION ReportAnomaly(anomaly_type, session_id, ...)
    # Log anomaly
    LOG.WARN(anomaly_type, session_id, additional_data...)
    
    # Increment session anomaly score
    session := GetSession(session_id)
    session.anomaly_score += ANOMALY_WEIGHTS[anomaly_type]
    session.gap_count += 1
    
    # Check thresholds
    IF session.anomaly_score >= CRITICAL_THRESHOLD THEN
        TriggerSecurityAction(session_id, "Critical anomaly score")
    ELSE IF session.gap_count >= MAX_CONSECUTIVE_GAPS THEN
        TriggerChallengeResponse(session_id)
    END IF
    
    RETURN SUCCESS  # Don't block legitimate reconnections
END FUNCTION
```

### Session State Schema

```json
{
  "session_id": "uuid-v4",
  "player_id": "player-identifier",
  "start_time": "2026-01-01T00:00:00Z",
  "last_report_time": "2026-01-01T00:15:32Z",
  "expected_sequence": 42,
  "gap_count": 0,
  "anomaly_score": 0.0,
  "challenge_pending": false,
  "challenge_failures": 0
}
```

### Gap Detection Thresholds

```pseudocode
# Configuration constants
MAX_CONSECUTIVE_GAPS := 3           # Trigger challenge after 3 gaps
CRITICAL_THRESHOLD := 100.0         # Anomaly score for immediate action
ANOMALY_WEIGHTS := {
    "sequence_gap": 25.0,           # Each gap adds 25 points
    "sequence_regression": 50.0,    # Backwards sequence (critical)
    "challenge_failure": 50.0,      # Failed challenge
    "timestamp_anomaly": 10.0       # Clock manipulation
}

# Timing validation
MAX_REPORT_INTERVAL := 120_000_MS   # 2 minutes max between reports
MIN_REPORT_INTERVAL := 5_000_MS     # 5 seconds min between reports
```

### Gap Handling Strategy

```pseudocode
FUNCTION HandleSequenceGap(session, gap_size, expected_seq, received_seq)
    # Small gaps may be legitimate (packet loss, reconnection)
    IF gap_size == 1 AND session.gap_count < MAX_CONSECUTIVE_GAPS THEN
        LOG.INFO("Single sequence gap - possible network issue", session.id)
        session.gap_count += 1
        RETURN ALLOW_WITH_MONITORING
    END IF
    
    # Multiple consecutive gaps or large gap - suspicious
    IF gap_size > 5 OR session.gap_count >= MAX_CONSECUTIVE_GAPS THEN
        LOG.WARN("Suspicious gap pattern", session.id, gap_size, session.gap_count)
        TriggerChallengeResponse(session)
        RETURN REQUIRE_CHALLENGE
    END IF
    
    # Medium concern - increment anomaly score
    session.anomaly_score += ANOMALY_WEIGHTS["sequence_gap"]
    session.gap_count += 1
    RETURN ALLOW_WITH_MONITORING
END FUNCTION
```

---

## Challenge-Response Protocol

### Overview

When gaps are detected, the server challenges the client to prove it can still detect cheats. The client must perform specific detection checks and report results within a time window.

### Challenge Message Format

Server → Client:

```json
{
  "type": "challenge",
  "challenge_id": "uuid-v4",
  "timestamp": 1735689600000,
  "checks": [
    {
      "check_type": "anti_debug",
      "check_id": 1,
      "method": "IsDebuggerPresent"
    },
    {
      "check_type": "anti_hook",
      "check_id": 2,
      "function": "NtCreateThread",
      "module": "ntdll.dll"
    },
    {
      "check_type": "integrity",
      "check_id": 3,
      "region": ".text"
    }
  ],
  "deadline_ms": 5000,
  "nonce": "base64-encoded-random-bytes"
}
```

### Response Message Format

Client → Server:

```json
{
  "type": "challenge_response",
  "challenge_id": "uuid-v4",
  "timestamp": 1735689602500,
  "results": [
    {
      "check_id": 1,
      "passed": true,
      "result": "no_debugger",
      "execution_time_us": 125
    },
    {
      "check_id": 2,
      "passed": false,
      "result": "hook_detected",
      "details": "Jump instruction at offset +5",
      "execution_time_us": 342
    },
    {
      "check_id": 3,
      "passed": true,
      "result": "integrity_ok",
      "hash": "sha256-hash-value",
      "execution_time_us": 1823
    }
  ],
  "signature": "hmac-sha256-signature"
}
```

### Challenge Execution Flow

```pseudocode
# Server side
FUNCTION TriggerChallengeResponse(session)
    # Generate random checks
    checks := []
    FOR i := 1 TO RAND(3, 5) DO
        check_type := SELECT_RANDOM(["anti_debug", "anti_hook", "integrity"])
        check := GenerateCheck(check_type)
        checks.APPEND(check)
    END FOR
    
    # Create challenge
    challenge := {
        "challenge_id": GENERATE_UUID(),
        "timestamp": NOW(),
        "checks": checks,
        "deadline_ms": 5000,
        "nonce": GENERATE_NONCE(32)
    }
    
    # Store challenge state
    session.challenge_pending := TRUE
    session.challenge_id := challenge.challenge_id
    session.challenge_deadline := NOW() + 5000
    STORE(challenge.challenge_id, challenge)
    
    # Send to client
    SEND_TO_CLIENT(session.id, challenge)
    
    # Set timeout handler
    SCHEDULE_TIMEOUT(5000, CheckChallengeResponse, session.id, challenge.challenge_id)
END FUNCTION

# Server side - validation
FUNCTION OnChallengeResponse(session_id, response)
    session := GetSession(session_id)
    
    # Validate challenge exists and isn't expired
    IF NOT session.challenge_pending THEN
        RETURN Error("No pending challenge")
    END IF
    
    IF response.challenge_id != session.challenge_id THEN
        RETURN Error("Challenge ID mismatch")
    END IF
    
    IF NOW() > session.challenge_deadline THEN
        session.challenge_failures += 1
        session.anomaly_score += ANOMALY_WEIGHTS["challenge_failure"]
        RETURN Error("Challenge deadline exceeded")
    END IF
    
    # Verify signature
    challenge := LOAD(response.challenge_id)
    IF NOT VerifyHMAC(response, challenge.nonce, session.session_key) THEN
        session.challenge_failures += 1
        session.anomaly_score += 2 * ANOMALY_WEIGHTS["challenge_failure"]
        RETURN Error("Invalid signature")
    END IF
    
    # Validate results
    expected_results := LoadExpectedResults(session, challenge.checks)
    anomalies := CompareResults(response.results, expected_results)
    
    IF anomalies.COUNT > 0 THEN
        LOG.WARN("Challenge response anomalies", session.id, anomalies)
        session.anomaly_score += anomalies.COUNT * 10
    END IF
    
    # Clear challenge state
    session.challenge_pending := FALSE
    session.challenge_id := NULL
    
    # Determine outcome
    IF anomalies.COUNT == 0 THEN
        session.gap_count := 0  # Reset on successful challenge
        RETURN SUCCESS
    ELSE IF anomalies.COUNT <= 1 THEN
        RETURN ALLOW_WITH_MONITORING
    ELSE
        session.challenge_failures += 1
        RETURN SUSPICIOUS
    END IF
END FUNCTION

# Client side - handling (pseudo-implementation)
FUNCTION HandleChallenge(challenge_msg)
    results := []
    
    FOR check IN challenge_msg.checks DO
        start_time := HIGH_PRECISION_TIMER()
        
        CASE check.check_type OF
            "anti_debug":
                result := PerformAntiDebugCheck(check.method)
            "anti_hook":
                result := PerformAntiHookCheck(check.function, check.module)
            "integrity":
                result := PerformIntegrityCheck(check.region)
        END CASE
        
        execution_time := HIGH_PRECISION_TIMER() - start_time
        
        results.APPEND({
            "check_id": check.check_id,
            "passed": result.passed,
            "result": result.status,
            "details": result.details,
            "execution_time_us": execution_time
        })
    END FOR
    
    # Sign response
    response := {
        "type": "challenge_response",
        "challenge_id": challenge_msg.challenge_id,
        "timestamp": NOW(),
        "results": results
    }
    signature := HMAC_SHA256(response, challenge_msg.nonce, session_key)
    response.signature := signature
    
    # Send response
    SEND_TO_SERVER(response)
END FUNCTION
```

### Challenge Check Types

#### Anti-Debug Checks
```json
{
  "check_type": "anti_debug",
  "method": "IsDebuggerPresent" | "RemoteDebugger" | "HardwareBreakpoints" | "TimingAnomaly"
}
```

Expected responses:
- `no_debugger`: No debugger detected
- `debugger_present`: Debugger detected
- `timing_anomaly`: Suspicious timing observed

#### Anti-Hook Checks
```json
{
  "check_type": "anti_hook",
  "function": "function_name",
  "module": "module_name.dll"
}
```

Expected responses:
- `no_hook`: Function is clean
- `hook_detected`: Hook found with details
- `function_not_found`: Function doesn't exist (suspicious)

#### Integrity Checks
```json
{
  "check_type": "integrity",
  "region": ".text" | ".data" | "IAT"
}
```

Expected responses:
- `integrity_ok`: Hash matches baseline
- `integrity_failed`: Tampering detected
- `region_not_found`: Region doesn't exist

---

## Behavioral Correlation

### Overview

The server correlates player behavioral telemetry (Task 12) with violation reports. Certain behaviors should trigger specific violations. Absence of expected violations indicates suppression.

### Correlation Rules

#### Rule 1: Aim Snap Detection

**Behavioral Pattern:**
```json
{
  "aim_snap_count": 15,        // >10 snaps per minute
  "tracking_smoothness": 0.98,  // Unrealistic smoothness (>0.95)
  "headshot_percentage": 85     // Very high HS% (>75%)
}
```

**Expected Violations:**
- `ViolationType::AimbotDetected` OR
- `ViolationType::InlineHook` (if aimbot hooks rendering/input functions)

**Correlation Logic:**
```pseudocode
IF behavioral_data.aim_snap_count > 10 
   AND behavioral_data.tracking_smoothness > 0.95
   AND behavioral_data.headshot_percentage > 75 THEN
    
    # Check if corresponding violations were reported
    violations := GetViolationsInWindow(session_id, 60_000_MS)
    aimbot_violations := violations.FILTER(v => 
        v.type IN ["AimbotDetected", "InlineHook"])
    
    IF aimbot_violations.COUNT == 0 THEN
        # Suspicious - aimbot-like behavior without violations
        session.anomaly_score += 30
        LOG.WARN("Aimbot behavior without violations", session_id)
        TriggerChallengeResponse(session_id)
    END IF
END IF
```

#### Rule 2: Speed Hack Detection

**Behavioral Pattern:**
```json
{
  "avg_velocity": 850,          // Normal max is 600
  "max_velocity": 1200,         // Significantly above normal
  "velocity_variance": 0.05     // Very consistent (bot-like)
}
```

**Expected Violations:**
- `ViolationType::SpeedHack` OR
- `ViolationType::TimeManipulation`

**Correlation Logic:**
```pseudocode
IF behavioral_data.max_velocity > GAME_MAX_VELOCITY * 1.3 THEN
    violations := GetViolationsInWindow(session_id, 60_000_MS)
    speed_violations := violations.FILTER(v =>
        v.type IN ["SpeedHack", "TimeManipulation"])
    
    IF speed_violations.COUNT == 0 THEN
        session.anomaly_score += 25
        LOG.WARN("Speed hack behavior without violations", session_id)
        TriggerChallengeResponse(session_id)
    END IF
END IF
```

#### Rule 3: Wallhack/ESP Detection

**Behavioral Pattern:**
```json
{
  "prefire_rate": 45,           // % of shots fired before target visible
  "tracking_through_walls": 8,  // Times crosshair followed through wall
  "avg_reaction_time_ms": 50    // Unrealistically fast (<100ms)
}
```

**Expected Violations:**
- `ViolationType::MemoryRead` (reading player positions from memory) OR
- `ViolationType::InlineHook` (hooking rendering to show ESP)

**Correlation Logic:**
```pseudocode
IF behavioral_data.prefire_rate > 30
   OR behavioral_data.tracking_through_walls > 5
   OR behavioral_data.avg_reaction_time_ms < 100 THEN
    
    violations := GetViolationsInWindow(session_id, 60_000_MS)
    wallhack_violations := violations.FILTER(v =>
        v.type IN ["MemoryRead", "InlineHook", "ModuleInjection"])
    
    IF wallhack_violations.COUNT == 0 THEN
        session.anomaly_score += 20
        LOG.WARN("Wallhack behavior without violations", session_id)
        # Note: May be skilled player - use lower weight
    END IF
END IF
```

#### Rule 4: Automation Detection

**Behavioral Pattern:**
```json
{
  "actions_per_minute": 450,    // Superhuman APM (>400)
  "input_variance": 0.02,       // Robotic timing (variance <0.05)
  "humanness_score": 0.15       // Very low humanness (<0.3)
}
```

**Expected Violations:**
- `ViolationType::InputInjection` OR
- `ViolationType::ModuleInjection` (macro DLL)

**Correlation Logic:**
```pseudocode
IF behavioral_data.actions_per_minute > 400
   AND behavioral_data.humanness_score < 0.3 THEN
    
    violations := GetViolationsInWindow(session_id, 60_000_MS)
    automation_violations := violations.FILTER(v =>
        v.type IN ["InputInjection", "ModuleInjection"])
    
    IF automation_violations.COUNT == 0 THEN
        session.anomaly_score += 35
        LOG.WARN("Bot-like behavior without violations", session_id)
        TriggerChallengeResponse(session_id)
    END IF
END IF
```

### Correlation Time Windows

```pseudocode
# Constants for correlation
CORRELATION_WINDOW_MS := 60_000        # 1 minute window for behavior-violation correlation
BEHAVIORAL_SAMPLE_RATE := 1_000        # Behavioral data sampled every 1 second
VIOLATION_GRACE_PERIOD := 5_000        # Allow 5 seconds for violation to be reported

# Sliding window for correlation
FUNCTION GetViolationsInWindow(session_id, window_ms)
    now := NOW()
    start_time := now - window_ms
    violations := DATABASE.QUERY(
        "SELECT * FROM violations 
         WHERE session_id = ? AND timestamp >= ?",
        session_id, start_time
    )
    RETURN violations
END FUNCTION
```

### Game-Specific Calibration

Correlation thresholds must be calibrated per game:

```json
{
  "game_id": "example-fps",
  "correlation_config": {
    "aim_snap_threshold": 10,
    "tracking_smoothness_threshold": 0.95,
    "headshot_percentage_threshold": 75,
    "max_velocity_multiplier": 1.3,
    "prefire_rate_threshold": 30,
    "tracking_through_walls_threshold": 5,
    "min_reaction_time_ms": 100,
    "max_apm": 400,
    "min_humanness_score": 0.3
  }
}
```

---

## Integration Requirements

### Game Operator Setup

#### 1. Backend Infrastructure

**Required Components:**
- Event ingestion service (handles report batches and telemetry)
- Sequence tracking database (stores session state)
- Correlation engine (applies behavioral correlation rules)
- Challenge service (generates and validates challenges)
- Action service (bans, kicks, flags for review)

**Database Schema:**

```sql
-- Session tracking table
CREATE TABLE sessions (
    session_id UUID PRIMARY KEY,
    player_id VARCHAR(64) NOT NULL,
    start_time TIMESTAMP NOT NULL,
    last_report_time TIMESTAMP,
    expected_sequence BIGINT DEFAULT 0,
    gap_count INT DEFAULT 0,
    anomaly_score FLOAT DEFAULT 0.0,
    challenge_pending BOOLEAN DEFAULT FALSE,
    challenge_id UUID,
    challenge_deadline TIMESTAMP,
    challenge_failures INT DEFAULT 0,
    status VARCHAR(32) DEFAULT 'active',
    INDEX idx_player_id (player_id),
    INDEX idx_status (status),
    INDEX idx_anomaly_score (anomaly_score)
);

-- Violation reports table
CREATE TABLE violation_reports (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(session_id),
    sequence_number BIGINT NOT NULL,
    batch_timestamp TIMESTAMP NOT NULL,
    violation_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    details JSONB,
    INDEX idx_session_sequence (session_id, sequence_number),
    INDEX idx_timestamp (batch_timestamp),
    INDEX idx_type (violation_type)
);

-- Behavioral telemetry table
CREATE TABLE behavioral_telemetry (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(session_id),
    timestamp TIMESTAMP NOT NULL,
    telemetry_data JSONB NOT NULL,
    INDEX idx_session_timestamp (session_id, timestamp)
);

-- Sequence anomalies table
CREATE TABLE sequence_anomalies (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(session_id),
    timestamp TIMESTAMP NOT NULL,
    anomaly_type VARCHAR(64) NOT NULL,
    expected_sequence BIGINT,
    received_sequence BIGINT,
    gap_size INT,
    details JSONB,
    INDEX idx_session_type (session_id, anomaly_type),
    INDEX idx_timestamp (timestamp)
);

-- Challenges table
CREATE TABLE challenges (
    challenge_id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(session_id),
    created_at TIMESTAMP NOT NULL,
    deadline TIMESTAMP NOT NULL,
    checks JSONB NOT NULL,
    nonce BYTEA NOT NULL,
    response JSONB,
    responded_at TIMESTAMP,
    outcome VARCHAR(32),
    INDEX idx_session_id (session_id),
    INDEX idx_deadline (deadline)
);
```

#### 2. API Endpoints

**Violation Report Ingestion:**
```
POST /api/v1/violations
Content-Type: application/json
Authorization: Bearer <session-token>

Request body: CloudReporter JSON payload with sequence number
Response: 200 OK | 202 Accepted | 409 Sequence Gap | 503 Challenge Required
```

**Challenge Response:**
```
POST /api/v1/challenge/response
Content-Type: application/json
Authorization: Bearer <session-token>

Request body: Challenge response with results and signature
Response: 200 OK | 400 Invalid | 408 Timeout | 403 Failed
```

**Behavioral Telemetry:**
```
POST /api/v1/telemetry
Content-Type: application/json
Authorization: Bearer <session-token>

Request body: BehavioralCollector aggregated data
Response: 202 Accepted
```

#### 3. Server Response Codes

```pseudocode
# Standard flow
200 OK: Report processed successfully
202 Accepted: Report queued for processing

# Gap detected
409 Conflict: Sequence gap detected, report logged but flagged

# Challenge required
503 Service Unavailable (+ Challenge message in response body):
    Server requires challenge-response before accepting more reports

# Authentication/validation
401 Unauthorized: Invalid session token
403 Forbidden: Session banned or suspended
400 Bad Request: Malformed payload
```

#### 4. Configuration

**Server Configuration File (YAML):**

```yaml
detection_correlation:
  enabled: true
  
  # Sequence gap detection
  gap_detection:
    max_consecutive_gaps: 3
    critical_anomaly_threshold: 100.0
    anomaly_weights:
      sequence_gap: 25.0
      sequence_regression: 50.0
      challenge_failure: 50.0
      timestamp_anomaly: 10.0
  
  # Challenge-response
  challenge_response:
    enabled: true
    trigger_gap_count: 3
    deadline_ms: 5000
    min_checks: 3
    max_checks: 5
    max_challenge_failures: 3
  
  # Behavioral correlation
  behavioral_correlation:
    enabled: true
    correlation_window_ms: 60000
    violation_grace_period_ms: 5000
    rules:
      - rule_id: "aim_snap"
        enabled: true
        aim_snap_threshold: 10
        tracking_smoothness_threshold: 0.95
        headshot_percentage_threshold: 75
        anomaly_weight: 30
      
      - rule_id: "speed_hack"
        enabled: true
        velocity_multiplier: 1.3
        anomaly_weight: 25
      
      - rule_id: "wallhack"
        enabled: true
        prefire_rate_threshold: 30
        tracking_through_walls_threshold: 5
        min_reaction_time_ms: 100
        anomaly_weight: 20
      
      - rule_id: "automation"
        enabled: true
        max_apm: 400
        min_humanness_score: 0.3
        anomaly_weight: 35
  
  # Action thresholds
  actions:
    flag_for_review_score: 50.0
    auto_kick_score: 150.0
    auto_ban_score: 200.0
```

#### 5. Monitoring and Alerting

**Metrics to Track:**
- `gap_detection_rate`: Gaps detected per hour
- `challenge_trigger_rate`: Challenges triggered per hour
- `challenge_success_rate`: % of challenges passed
- `correlation_mismatch_rate`: Behavioral mismatches per hour
- `anomaly_score_distribution`: Histogram of anomaly scores
- `false_positive_rate`: % of flagged sessions that are legitimate

**Alerting Rules:**
```yaml
alerts:
  - name: "High Gap Detection Rate"
    condition: gap_detection_rate > 100 per hour
    severity: warning
    action: notify_security_team
  
  - name: "Challenge Failure Spike"
    condition: challenge_success_rate < 70%
    severity: critical
    action: [notify_security_team, trigger_investigation]
  
  - name: "Correlation Mismatch Spike"
    condition: correlation_mismatch_rate > 50 per hour
    severity: warning
    action: review_correlation_rules
```

---

## Testing and Validation

### Integration Test Requirements

#### Test 1: Sequence Numbering

```pseudocode
TEST SequenceNumberingBasic
    # Setup
    reporter := CreateCloudReporter("http://test-server/violations")
    reporter.SetBatchSize(1)  # Send immediately
    
    # Send 10 events
    FOR i := 0 TO 9 DO
        event := CreateTestEvent(i)
        reporter.QueueEvent(event)
        SLEEP(100_MS)
    END FOR
    
    # Wait for all batches to send
    reporter.Flush()
    SLEEP(1000_MS)
    
    # Verify server received all 10 batches with correct sequences
    server_batches := GetServerBatches()
    ASSERT server_batches.COUNT == 10
    FOR i := 0 TO 9 DO
        ASSERT server_batches[i].sequence == i
    END FOR
END TEST
```

#### Test 2: Gap Detection Simulation

**Implementation:** See `tests/SDK/test_cloud_reporter.cpp::GapDetectionWithSimulatedSuppression`

```pseudocode
TEST GapDetectionWithSuppression
    # Setup
    reporter := CreateCloudReporter("http://test-server/violations")
    reporter.SetBatchSize(1)
    
    # Setup proxy to filter specific reports
    proxy := CreateFilteringProxy()
    proxy.SetFilter(batch => 
        batch.events.ANY(e => e.type == "AimbotDetected"))
    
    # Send mixed events
    reporter.QueueEvent(CreateEvent("DebuggerAttached"))      # seq=0, arrives
    reporter.QueueEvent(CreateEvent("AimbotDetected"))        # seq=1, FILTERED
    reporter.QueueEvent(CreateEvent("SpeedHack"))             # seq=2, arrives
    
    SLEEP(2000_MS)
    
    # Verify server detected gap
    anomalies := GetServerAnomalies()
    ASSERT anomalies.COUNT >= 1
    ASSERT anomalies[0].type == "sequence_gap"
    ASSERT anomalies[0].expected_sequence == 1
    ASSERT anomalies[0].received_sequence == 2
END TEST
```

**Note:** The actual implementation in `test_cloud_reporter.cpp` documents the expected behavior since client-side unit tests cannot intercept HTTP traffic. The test demonstrates the sequence numbers that would be generated with and without suppression, and documents the server-side gap detection algorithm that would execute.

#### Test 3: Challenge-Response

**Implementation:** See `tests/SDK/test_cloud_reporter.cpp::ConsecutiveGapsTriggersChallenge`

```pseudocode
TEST ChallengeResponseFlow
    # Setup
    reporter := CreateCloudReporter("http://test-server/violations")
    
    # Simulate gap to trigger challenge
    reporter.QueueEvent(CreateEventWithSequence(0))
    reporter.QueueEvent(CreateEventWithSequence(5))  # Gap of 4
    
    SLEEP(1000_MS)
    
    # Verify server sent challenge
    challenges := GetServerChallenges()
    ASSERT challenges.COUNT == 1
    
    # Simulate client response
    challenge := challenges[0]
    response := ExecuteChallenge(challenge)
    SendChallengeResponse(response)
    
    SLEEP(500_MS)
    
    # Verify server accepted response
    session := GetServerSession()
    ASSERT session.challenge_pending == FALSE
    ASSERT session.gap_count == 0  # Reset on success
END TEST
```

**Note:** The actual implementation documents the challenge-response trigger scenario. Full challenge-response protocol implementation requires server-side support (HTTP 503 response with challenge payload).

#### Test 4: Behavioral Correlation

```pseudocode
TEST BehavioralCorrelationAimbot
    # Setup
    session := CreateTestSession()
    reporter := CreateCloudReporter("http://test-server/violations")
    telemetry := CreateBehavioralCollector()
    
    # Send suspicious behavioral data
    FOR i := 0 TO 60 DO  # 60 seconds of data
        telemetry.RecordAim(
            precision: 0.98,
            flick_speed: 1500,
            is_headshot: TRUE
        )
        SLEEP(1000_MS)
    END FOR
    
    telemetry.Flush()
    
    # DO NOT send corresponding violation reports
    # (simulating suppression)
    
    SLEEP(2000_MS)
    
    # Verify server detected mismatch
    session_state := GetServerSession()
    ASSERT session_state.anomaly_score > 0
    
    anomalies := GetServerAnomalies()
    ASSERT anomalies.ANY(a => a.type == "correlation_mismatch")
END TEST
```

### Load Testing

```pseudocode
TEST LoadTestSequenceTracking
    # Simulate 10,000 concurrent sessions
    sessions := []
    FOR i := 0 TO 9999 DO
        session := CreateSession()
        sessions.APPEND(session)
    END FOR
    
    # Each session sends 100 reports over 10 minutes
    PARALLEL_FOR_EACH session IN sessions DO
        FOR j := 0 TO 99 DO
            SendReport(session, sequence: j)
            SLEEP(RANDOM(5000, 7000))  # 5-7 seconds between reports
        END FOR
    END FOR
    
    # Verify no sequence errors in legitimate sessions
    FOR session IN sessions DO
        session_state := GetServerSession(session.id)
        ASSERT session_state.expected_sequence == 100
        ASSERT session_state.gap_count == 0
    END FOR
END TEST
```

---

## Security Considerations

### Limitations

**LIMITATION 1: Client control**
- Attacker controls client code and can patch sequence numbering
- Defense: Server-side validation and correlation provide independent verification

**LIMITATION 2: Replay attacks**
- Attacker could replay old reports with correct sequences
- Defense: Timestamp validation and session scoping prevent stale replays

**LIMITATION 3: Predictable challenges**
- Attacker could pre-compute challenge responses
- Defense: Randomized checks with nonces make pre-computation infeasible

**LIMITATION 4: Sophisticated proxies**
- Attacker could build proxy that maintains sequence numbers
- Defense: Behavioral correlation detects behavior-violation mismatches

### Defense in Depth

This system is **one layer** of a comprehensive anti-cheat strategy:

```
Layer 1: Client-side detection (Sentinel SDK)
    ↓
Layer 2: Report integrity (sequence numbering, signing)
    ↓
Layer 3: Server correlation (THIS SPECIFICATION)
    ↓
Layer 4: Machine learning anomaly detection
    ↓
Layer 5: Manual review and investigation
```

### False Positive Mitigation

**Source 1: Network issues**
- Legitimate packet loss can cause single gaps
- **Mitigation**: Grace period, allow 1-2 gaps before action

**Source 2: Client crashes**
- Client crash = missing reports until restart
- **Mitigation**: Track crash reports, correlate with sequence resets

**Source 3: Game performance**
- Low FPS may delay reporting
- **Mitigation**: Adjust correlation time windows based on client FPS

**Source 4: Skill-based patterns**
- Pro players may have aimbot-like stats
- **Mitigation**: Higher thresholds, require multiple signals, manual review

### Operational Considerations

**Deployment Strategy:**
1. Deploy with monitoring only (no bans) for 2-4 weeks
2. Calibrate thresholds based on false positive rate
3. Enable flagging for manual review
4. Enable automated kicks for high-confidence cases
5. Enable automated bans only after validation period

**Privacy Compliance:**
- All telemetry is aggregated, no raw input logging
- Session data retained for 90 days max
- Player identifiers hashed in logs
- Behavioral data cannot reconstruct gameplay

---

## Appendix: Message Examples

### Complete Report Flow

**1. Initial Report (sequence=0):**
```json
POST /api/v1/violations
{
  "version": "1.0",
  "sequence": 0,
  "events": [
    {
      "type": 1002,
      "severity": 2,
      "timestamp": 1735689600000,
      "address": 305419896,
      "module": "game.exe",
      "details": "Debugger detected via IsDebuggerPresent",
      "detection_id": 1001
    }
  ],
  "batch_size": 1,
  "timestamp": 1735689600000
}
```

**2. Report with Gap (sequence jumps):**
```json
POST /api/v1/violations
{
  "version": "1.0",
  "sequence": 5,  // Gap detected: expected 1, got 5
  "events": [...],
  "batch_size": 1,
  "timestamp": 1735689650000
}
```

**3. Server Challenge Response:**
```json
HTTP 503 Service Unavailable
{
  "error": "challenge_required",
  "message": "Sequence gap detected. Complete challenge to continue.",
  "challenge": {
    "type": "challenge",
    "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": 1735689651000,
    "checks": [
      {
        "check_type": "anti_debug",
        "check_id": 1,
        "method": "IsDebuggerPresent"
      },
      {
        "check_type": "anti_hook",
        "check_id": 2,
        "function": "NtCreateThread",
        "module": "ntdll.dll"
      }
    ],
    "deadline_ms": 5000,
    "nonce": "cmFuZG9tX25vbmNlXzMyX2J5dGVz"
  }
}
```

**4. Client Challenge Response:**
```json
POST /api/v1/challenge/response
{
  "type": "challenge_response",
  "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1735689652500,
  "results": [
    {
      "check_id": 1,
      "passed": true,
      "result": "no_debugger",
      "execution_time_us": 125
    },
    {
      "check_id": 2,
      "passed": true,
      "result": "no_hook",
      "execution_time_us": 342
    }
  ],
  "signature": "a3f5b8c9d2e1f4a7b6c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9"
}
```

**5. Server Acceptance:**
```json
HTTP 200 OK
{
  "status": "challenge_passed",
  "message": "Verification successful. Resume normal reporting."
}
```

---

**Document End**

*For implementation questions, contact Sentinel Security Engineering.*  
*Last Updated: 2026-01-01*
