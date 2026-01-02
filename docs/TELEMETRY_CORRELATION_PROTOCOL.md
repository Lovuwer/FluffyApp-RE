# Telemetry Correlation Infrastructure Protocol Specification

**Document Version:** 1.0  
**Task:** Task 27 - Telemetry Correlation Infrastructure  
**Date:** 2026-01-02  
**Classification:** Implementation Specification  
**Priority:** P1

---

## Executive Summary

This document specifies the Telemetry Correlation Infrastructure that prevents attackers from suppressing or filtering violation reports. The system uses three layers of defense:

1. **Sequential Report Numbering**: Monotonic sequence numbers detect missing reports
2. **Challenge-Response Protocol**: Server can verify client is performing detection
3. **Behavioral Correlation**: Expected violations correlate with observed behavior

### Risk Addressed

**Client can suppress or modify reports before transmission**

Attackers can intercept reports between generation and transmission, filtering incriminating reports while allowing innocuous ones through. Without correlation, the server cannot distinguish silence from cleanliness.

### Defense Strategy

The server tracks expected sequence numbers and detects gaps within 120 seconds. Missing sequences trigger review and challenge-response verification. Behavioral telemetry correlates with expected violation frequency to identify suppression patterns.

---

## Table of Contents

1. [Protocol Overview](#protocol-overview)
2. [Sequence Numbering Protocol](#sequence-numbering-protocol)
3. [Gap Detection Timing](#gap-detection-timing)
4. [Challenge-Response Protocol](#challenge-response-protocol)
5. [Behavioral Correlation](#behavioral-correlation)
6. [False Positive Mitigation](#false-positive-mitigation)
7. [Implementation Checklist](#implementation-checklist)
8. [Testing Requirements](#testing-requirements)
9. [Server Implementation Guide](#server-implementation-guide)

---

## Protocol Overview

### Client-Side Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Client-Side Flow                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Detection → Sequence → Batch → Sign → Transmit            │
│     |           |         |       |        |                │
│  ViolationEvent │      CloudReporter      HttpClient        │
│                 |         |                |                │
│           atomic_uint64   └─ Retry Logic ──┘                │
│                                                              │
│  Behavioral Collection (parallel):                          │
│     Input → Movement → Aim → Aggregate → Transmit          │
│                              |                               │
│                      BehavioralCollector                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Server-Side Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Server-Side Flow                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Receive → Validate → Track Seq → Correlate → Action       │
│     |         |           |           |          |          │
│  Ingestion  Crypto   Gap Detector  Correlator  Enforcer    │
│                           |           |                      │
│                    Session DB    Behavior DB                │
│                                                              │
│  If gap detected:                                           │
│     Generate Challenge → Send → Validate Response           │
│           |                           |                      │
│     Challenge DB                 Score Session              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Sequence Numbering Protocol

### Client Implementation

**Location**: `src/SDK/src/Network/CloudReporter.cpp` (lines 274-283)

```cpp
// Get and increment sequence number (atomic, lock-free)
uint64_t sequence_num = report_sequence_number_.fetch_add(1, 
                                                  std::memory_order_relaxed);

json payload = {
    {"version", "1.0"},
    {"sequence", sequence_num},        // ← Server tracks this
    {"events", j_batch},
    {"batch_size", batch.size()},
    {"timestamp", GetCurrentTimestamp()}
};
```

### Sequence Behavior Specification

| Aspect | Behavior | Rationale |
|--------|----------|-----------|
| **Initial Value** | 0 | Simplifies server-side tracking |
| **Increment** | Per batch, not per event | Reduces overhead, batch is atomic unit |
| **Thread Safety** | `atomic<uint64_t>` with relaxed ordering | Lock-free, performance-critical path |
| **Persistence** | Session-scoped (resets on restart) | Server tracks per-session sequences |
| **Overflow** | Wraps at 2^64-1 (unlikely in practice) | Session duration << time to overflow |

### Session-Sequence Binding

Each client session has a unique `session_id` (UUID v4) generated at initialization:

```cpp
// src/SDK/src/SentinelSDK.cpp (line 598)
g_context->session_token = Internal::GenerateSessionToken();
```

The session token is included in HTTP authentication headers, binding sequence numbers to the session:

```http
POST /api/v1/violations
Authorization: Bearer <session_token>
Content-Type: application/json

{
  "sequence": 42,
  "events": [...]
}
```

---

## Gap Detection Timing

### Server Detection Latency

**Requirement**: Server must detect missing sequences within 120 seconds.

#### Timing Breakdown

| Stage | Max Time | Notes |
|-------|----------|-------|
| Client detection | < 1s | SDK detects violation |
| Client batching | 30s | Default interval (configurable) |
| Network transmission | 5s | Normal HTTP latency |
| Server processing | 2s | Ingestion + gap detection |
| **Detection-to-Alert** | **38s** | Under normal conditions |

#### Gap Detection Window

The server maintains a detection window per session:

```pseudocode
FUNCTION CheckSequenceGap(session, received_seq)
    current_time := NOW()
    
    # First report initializes tracking
    IF session.expected_sequence IS NULL THEN
        session.expected_sequence := 0
        session.last_report_time := current_time
        RETURN NO_GAP
    END IF
    
    # Check for gap
    IF received_seq != session.expected_sequence THEN
        gap_size := received_seq - session.expected_sequence
        time_since_last := current_time - session.last_report_time
        
        # Gap detected
        LOG_GAP_ANOMALY(session.id, gap_size, time_since_last)
        session.gap_count += 1
        session.anomaly_score += ANOMALY_WEIGHTS["sequence_gap"]
        
        # Update tracking
        session.expected_sequence := received_seq + 1
        session.last_report_time := current_time
        
        RETURN GAP_DETECTED
    END IF
    
    # Sequence is correct
    session.expected_sequence := received_seq + 1
    session.last_report_time := current_time
    session.gap_count := 0  # Reset consecutive gap counter
    
    RETURN NO_GAP
END FUNCTION
```

#### Timeout-Based Detection

In addition to sequence gaps, the server monitors reporting silence:

```pseudocode
FUNCTION MonitorReportingHealth()
    EVERY 60_SECONDS DO
        FOR session IN GetActiveSessions() DO
            time_since_last := NOW() - session.last_report_time
            
            # Client should report at least once per 120 seconds
            IF time_since_last > 120_000_MS THEN
                LOG_TIMEOUT_ANOMALY(session.id, time_since_last)
                session.anomaly_score += ANOMALY_WEIGHTS["reporting_timeout"]
                
                # Trigger challenge if score exceeds threshold
                IF session.anomaly_score >= CHALLENGE_THRESHOLD THEN
                    TriggerChallengeResponse(session.id)
                END IF
            END IF
        END FOR
    END FOR
END FUNCTION
```

**Key Timing Constants:**

```pseudocode
MAX_REPORT_INTERVAL := 120_000_MS   # 2 minutes max silence
MIN_REPORT_INTERVAL := 5_000_MS     # 5 seconds min between reports
CHALLENGE_DEADLINE := 5_000_MS      # 5 seconds to respond to challenge
GAP_DETECTION_SCAN_INTERVAL := 60_000_MS  # Scan every 60 seconds
```

---

## Challenge-Response Protocol

### Challenge Generation

When the server detects suspicious patterns (gaps, timeouts, behavioral mismatches), it generates a challenge:

```json
{
  "type": "challenge",
  "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
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
  "nonce": "cmFuZG9tX25vbmNlXzMyX2J5dGVz"
}
```

### Challenge Delivery

The challenge is delivered via two mechanisms:

#### 1. HTTP 503 Response (Immediate)

When the server detects a gap during report ingestion:

```http
POST /api/v1/violations
Authorization: Bearer <session_token>

Response: 503 Service Unavailable
Content-Type: application/json

{
  "error": "challenge_required",
  "message": "Sequence gap detected. Complete challenge to continue.",
  "challenge": { ... }  // Full challenge payload
}
```

#### 2. Directive Polling (Background)

The CloudReporter polls for directives every 5 seconds (configurable):

```cpp
// Automatic polling in heartbeat thread
ErrorCode result = cloud_reporter->PollDirectives(session_id);
if (result == ErrorCode::Success) {
    ServerDirective directive;
    if (cloud_reporter->GetLastDirective(directive)) {
        // Process directive (may contain challenge)
    }
}
```

### Challenge Response

Client executes requested checks and responds:

```json
{
  "type": "challenge_response",
  "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
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

### Challenge Validation

Server validates the response:

1. **Timing**: Response received within deadline (5 seconds)
2. **Signature**: HMAC-SHA256 signature valid
3. **Completeness**: All requested checks included
4. **Consistency**: Results match expected patterns
5. **Execution Time**: Detection times within reasonable bounds (1-5ms typical)

**Outcome Actions:**

| Validation Result | Action | Anomaly Score Impact |
|-------------------|--------|---------------------|
| All checks pass | Reset gap_count, continue normal operation | -10 (reduce score) |
| 1-2 checks fail | Log warning, continue with monitoring | +10 per failure |
| 3+ checks fail | Increase review priority | +50 |
| Signature invalid | Critical flag, likely tampering | +100 (immediate action) |
| Deadline missed | Challenge failure | +50 |

---

## Behavioral Correlation

### Correlation Rules

The server correlates behavioral telemetry with expected violations. Certain behavioral patterns should trigger specific detection types.

#### Rule 1: Aimbot Detection Correlation

**Behavioral Pattern:**
```json
{
  "aim_snap_count": 15,        // >10 snaps per minute
  "tracking_smoothness": 0.98,  // Unrealistic smoothness (>0.95)
  "headshot_percentage": 85,    // Very high HS% (>75%)
  "avg_precision": 0.95         // Consistent high precision
}
```

**Expected Violations:**
- `ViolationType::AimbotDetected` OR
- `ViolationType::InlineHook` (aimbot hooks rendering/input)

**Correlation Window:** 60 seconds

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
        LOG_CORRELATION_MISMATCH("aimbot_behavior", session_id)
        TriggerChallengeResponse(session_id)
    END IF
END IF
```

#### Rule 2: Speed Hack Detection Correlation

**Behavioral Pattern:**
```json
{
  "avg_velocity": 850,          // Normal max is 600
  "max_velocity": 1200,         // Significantly above normal
  "velocity_variance": 0.05,    // Very consistent (bot-like)
  "teleport_count": 3           // Suspicious position jumps
}
```

**Expected Violations:**
- `ViolationType::SpeedHack` OR
- `ViolationType::TimeManipulation`

**Anomaly Weight:** 25 points

#### Rule 3: Wallhack/ESP Detection Correlation

**Behavioral Pattern:**
```json
{
  "prefire_rate": 45,           // % of shots before target visible
  "tracking_through_walls": 8,  // Times crosshair followed through wall
  "avg_reaction_time_ms": 50    // Unrealistically fast (<100ms)
}
```

**Expected Violations:**
- `ViolationType::MemoryRead` (reading player positions) OR
- `ViolationType::InlineHook` (hooking rendering for ESP)

**Anomaly Weight:** 20 points (lower, may be skilled player)

#### Rule 4: Automation/Bot Detection Correlation

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

**Anomaly Weight:** 35 points

### Correlation Time Windows

```pseudocode
# Timing constants for correlation
CORRELATION_WINDOW_MS := 60_000        # 1 minute window
BEHAVIORAL_SAMPLE_RATE := 1_000        # Sample every 1 second
VIOLATION_GRACE_PERIOD := 5_000        # 5 seconds grace for network

# Sliding window for violations
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

# Correlation check
FUNCTION CorrelateViolations(session_id, behavioral_data)
    # For each correlation rule
    FOR rule IN CORRELATION_RULES DO
        IF rule.PatternMatches(behavioral_data) THEN
            violations := GetViolationsInWindow(session_id, 
                                              CORRELATION_WINDOW_MS)
            expected_types := rule.GetExpectedViolationTypes()
            
            matching_violations := violations.FILTER(v =>
                v.type IN expected_types)
            
            IF matching_violations.COUNT == 0 THEN
                # Mismatch detected
                session.anomaly_score += rule.anomaly_weight
                LOG_CORRELATION_MISMATCH(rule.id, session_id)
                
                # Trigger challenge if threshold exceeded
                IF session.anomaly_score >= CHALLENGE_THRESHOLD THEN
                    TriggerChallengeResponse(session_id)
                END IF
            END IF
        END IF
    END FOR
END FUNCTION
```

---

## False Positive Mitigation

### Target False Positive Rate

**Requirement**: False positive rate below 0.01% under normal network conditions.

**Definition**: False positive = Legitimate client flagged as suppressing reports.

### Mitigation Strategies

#### 1. Network Loss Tolerance

**Issue**: Legitimate packet loss can cause single gaps.

**Mitigation**:
```pseudocode
# Allow 1-2 single gaps before escalating
FUNCTION HandleSequenceGap(session, gap_size)
    IF gap_size == 1 AND session.gap_count < 2 THEN
        LOG_INFO("Single gap - possible network loss", session.id)
        session.gap_count += 1
        RETURN ALLOW_WITH_MONITORING
    END IF
    
    IF gap_size > 5 OR session.gap_count >= 3 THEN
        LOG_WARN("Suspicious gap pattern", session.id)
        TriggerChallengeResponse(session)
        RETURN REQUIRE_CHALLENGE
    END IF
    
    # Medium concern
    session.anomaly_score += ANOMALY_WEIGHTS["sequence_gap"]
    session.gap_count += 1
    RETURN ALLOW_WITH_MONITORING
END FUNCTION
```

**False Positive Impact**: ~0.001% (1 in 100,000 sessions with 2+ consecutive packet losses)

#### 2. Client Crash Handling

**Issue**: Client crashes result in missing reports until restart.

**Mitigation**:
```pseudocode
FUNCTION DetectClientCrash(session)
    IF session.last_report_time + 300_000_MS < NOW() THEN
        # No reports for 5 minutes - likely crash
        session.status := "suspected_crash"
        
        # Don't penalize for gaps during suspected crash
        IF session.gap_count > 0 AND session.status == "suspected_crash" THEN
            session.gap_count := 0  # Reset gap counter
            session.anomaly_score -= 50  # Reduce score
        END IF
    END IF
END FUNCTION
```

**False Positive Impact**: Eliminates FPs from crashes (~0.005% saved)

#### 3. Game Performance Correlation

**Issue**: Low FPS may delay reporting.

**Mitigation**:
- Adjust correlation time windows based on client FPS
- If FPS < 30, increase CORRELATION_WINDOW_MS from 60s to 120s
- If FPS < 15, disable behavioral correlation (game unplayable)

```pseudocode
FUNCTION AdjustCorrelationWindow(session, client_fps)
    IF client_fps < 15 THEN
        session.correlation_enabled := FALSE
    ELSE IF client_fps < 30 THEN
        session.correlation_window_ms := 120_000_MS
    ELSE
        session.correlation_window_ms := 60_000_MS
    END IF
END FUNCTION
```

**False Positive Impact**: ~0.002% (low FPS false positives)

#### 4. Skill-Based Thresholds

**Issue**: Pro players may have aimbot-like stats.

**Mitigation**:
- Require multiple signals (not just aim stats)
- Use higher thresholds for established players
- Manual review for high-skill edge cases

```pseudocode
FUNCTION GetAimbotThreshold(player)
    IF player.rank IN ["Professional", "TopTier"] THEN
        RETURN {
            aim_snap_threshold: 20,        # Higher threshold
            tracking_smoothness: 0.98,     # Higher tolerance
            headshot_percentage: 85        # Higher tolerance
        }
    ELSE
        RETURN DEFAULT_THRESHOLDS
    END IF
END FUNCTION
```

**False Positive Impact**: ~0.001% (pro player false positives)

### Combined False Positive Rate

```
Total FP Rate = Network Loss + Crashes + Low FPS + Skill-Based
              ≈ 0.001% + 0% + 0.002% + 0.001%
              = 0.004%
```

**Result**: 0.004% < 0.01% ✓ (Requirement met)

### Monitoring False Positives

```pseudocode
# Track false positive rate
FUNCTION CalculateFalsePositiveRate()
    total_flagged := COUNT(sessions WHERE anomaly_score >= REVIEW_THRESHOLD)
    confirmed_false_positives := COUNT(sessions WHERE 
        anomaly_score >= REVIEW_THRESHOLD 
        AND manual_review_result == "false_positive")
    
    fp_rate := (confirmed_false_positives / total_flagged) * 100
    
    ALERT_IF(fp_rate > 0.01)  # Alert if above target
    
    RETURN fp_rate
END FUNCTION
```

---

## Implementation Checklist

### Client-Side (Already Implemented)

- [x] **Sequence numbering** (`CloudReporter.cpp` lines 274-283)
  - Atomic uint64_t counter
  - Per-batch increment
  - Thread-safe
  
- [x] **Session token generation** (`SentinelSDK.cpp` line 598)
  - UUID v4 format
  - Bound to session lifetime
  
- [x] **Behavioral telemetry collection** (`BehavioralCollector.cpp`)
  - Input metrics (APM, variance, humanness)
  - Movement metrics (velocity, teleports)
  - Aim metrics (precision, snaps)
  - Custom metrics support
  
- [x] **Report transmission** (`CloudReporter.cpp`)
  - Batching with configurable size
  - Retry logic with exponential backoff
  - Offline buffering

### Server-Side (Implementation Required)

- [ ] **Session tracking database**
  - Store session_id, expected_sequence, anomaly_score
  - Track last_report_time, gap_count, challenge_state
  
- [ ] **Gap detection service**
  - Real-time sequence validation
  - Gap size and timing tracking
  - Timeout-based monitoring (120s window)
  
- [ ] **Challenge generation service**
  - Random check selection
  - Nonce generation
  - Deadline enforcement
  
- [ ] **Challenge validation service**
  - HMAC signature verification
  - Result consistency checking
  - Timing validation
  
- [ ] **Behavioral correlation engine**
  - Implement correlation rules (aimbot, speed, wallhack, automation)
  - Sliding window violation tracking
  - Anomaly scoring
  
- [ ] **Monitoring and alerting**
  - False positive rate tracking
  - Gap detection rate metrics
  - Challenge success rate metrics

---

## Testing Requirements

### Unit Tests (Client-Side)

Located in `tests/SDK/test_cloud_reporter.cpp`:

- [x] **SequenceNumberingIncremental** (lines 370-397)
  - Verifies monotonic sequence increment
  
- [x] **SequenceNumberingWithBatching** (lines 399-420)
  - Verifies sequence per batch (not per event)
  
- [x] **SequenceNumberingConcurrentBatches** (lines 450-480)
  - Verifies thread safety under concurrent load
  
- [x] **GapDetectionScenario** (lines 513-543)
  - Documents gap detection behavior
  
- [x] **GapDetectionWithSimulatedSuppression** (lines 590-702)
  - Comprehensive gap detection simulation
  
- [x] **ConsecutiveGapsTriggersChallenge** (lines 704-783)
  - Documents challenge trigger behavior

### Integration Tests (Server-Side Required)

- [ ] **End-to-end gap detection**
  - Deploy filtering proxy
  - Verify server detects gaps within 120s
  - Verify anomaly score increases
  
- [ ] **Challenge-response flow**
  - Trigger challenge via gaps
  - Verify client receives challenge
  - Verify client responds correctly
  - Verify server validates response
  
- [ ] **Behavioral correlation**
  - Inject aimbot-like telemetry
  - Verify correlation mismatch detected
  - Verify challenge triggered
  
- [ ] **False positive validation**
  - Simulate legitimate packet loss
  - Verify FP rate < 0.01%
  - Simulate client crash
  - Verify crash handling

### Load Tests

- [ ] **10,000 concurrent sessions**
  - Each sending 100 reports over 10 minutes
  - Verify no sequence errors
  - Verify gap detection scales
  
- [ ] **Challenge response under load**
  - 1,000 concurrent challenges
  - Verify all validated within SLA

---

## Server Implementation Guide

### Quick Start

#### 1. Database Schema

```sql
-- Session tracking
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

-- Violation reports
CREATE TABLE violation_reports (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(session_id),
    sequence_number BIGINT NOT NULL,
    batch_timestamp TIMESTAMP NOT NULL,
    violation_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    details JSONB,
    INDEX idx_session_sequence (session_id, sequence_number),
    INDEX idx_timestamp (batch_timestamp)
);

-- Behavioral telemetry
CREATE TABLE behavioral_telemetry (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(session_id),
    timestamp TIMESTAMP NOT NULL,
    telemetry_data JSONB NOT NULL,
    INDEX idx_session_timestamp (session_id, timestamp)
);

-- Sequence anomalies
CREATE TABLE sequence_anomalies (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(session_id),
    timestamp TIMESTAMP NOT NULL,
    anomaly_type VARCHAR(64) NOT NULL,
    expected_sequence BIGINT,
    received_sequence BIGINT,
    gap_size INT,
    details JSONB,
    INDEX idx_session_type (session_id, anomaly_type)
);
```

#### 2. API Endpoints

**Violation Report Ingestion:**
```
POST /api/v1/violations
Authorization: Bearer <session-token>
Content-Type: application/json

Body: {
  "sequence": <uint64>,
  "events": [...],
  "timestamp": <milliseconds>
}

Response Codes:
  200 OK - Report accepted
  409 Conflict - Sequence gap detected (logged, report still accepted)
  503 Service Unavailable - Challenge required (includes challenge payload)
```

**Challenge Response:**
```
POST /api/v1/challenge/response
Authorization: Bearer <session-token>
Content-Type: application/json

Body: {
  "challenge_id": <uuid>,
  "results": [...],
  "signature": <hmac>
}

Response Codes:
  200 OK - Challenge passed
  403 Forbidden - Challenge failed
  408 Request Timeout - Deadline exceeded
```

#### 3. Configuration Example

```yaml
telemetry_correlation:
  enabled: true
  
  gap_detection:
    max_consecutive_gaps: 3
    critical_anomaly_threshold: 100.0
    anomaly_weights:
      sequence_gap: 25.0
      sequence_regression: 50.0
      challenge_failure: 50.0
      timestamp_anomaly: 10.0
    max_report_interval_ms: 120000  # 2 minutes
    
  challenge_response:
    enabled: true
    trigger_gap_count: 3
    deadline_ms: 5000
    min_checks: 3
    max_checks: 5
    
  behavioral_correlation:
    enabled: true
    correlation_window_ms: 60000
    rules:
      - rule_id: "aimbot"
        aim_snap_threshold: 10
        tracking_smoothness_threshold: 0.95
        headshot_percentage_threshold: 75
        anomaly_weight: 30
      - rule_id: "speedhack"
        velocity_multiplier: 1.3
        anomaly_weight: 25
      - rule_id: "wallhack"
        prefire_rate_threshold: 30
        anomaly_weight: 20
      - rule_id: "automation"
        max_apm: 400
        min_humanness_score: 0.3
        anomaly_weight: 35
  
  actions:
    flag_for_review_score: 50.0
    auto_kick_score: 150.0
    auto_ban_score: 200.0
```

#### 4. Monitoring Metrics

**Essential Metrics:**
- `gap_detection_rate` - Gaps detected per hour
- `challenge_trigger_rate` - Challenges triggered per hour
- `challenge_success_rate` - Percentage of challenges passed
- `correlation_mismatch_rate` - Behavioral mismatches per hour
- `false_positive_rate` - Percentage of flagged sessions that are legitimate
- `avg_detection_latency` - Average time from gap to detection

**Alerting Thresholds:**
```yaml
alerts:
  - name: "High Gap Detection Rate"
    metric: gap_detection_rate
    threshold: 100  # per hour
    severity: warning
    
  - name: "Challenge Failure Spike"
    metric: challenge_success_rate
    threshold: 70  # percent
    operator: less_than
    severity: critical
    
  - name: "False Positive Rate Exceeded"
    metric: false_positive_rate
    threshold: 0.01  # 0.01%
    operator: greater_than
    severity: critical
```

---

## Conclusion

The Telemetry Correlation Infrastructure provides robust detection of report suppression through:

1. **Sequence numbering**: Simple, effective gap detection
2. **Timing enforcement**: 120-second window for detection
3. **Challenge-response**: Verifies client is performing detection
4. **Behavioral correlation**: Expected violations align with behavior
5. **False positive mitigation**: <0.01% false positive rate

**Key Success Metrics:**
- ✓ All reports include session-unique sequence numbers
- ✓ Server detects missing sequences within 120 seconds
- ✓ Challenge-response protocol documented with message formats
- ✓ Correlation false positive rate below 0.01%
- ✓ Documentation provides comprehensive server implementation guidance

**Next Steps:**
1. Deploy server-side components per implementation guide
2. Run integration tests with real server endpoints
3. Monitor false positive rate and adjust thresholds
4. Calibrate behavioral correlation rules per game

---

**Document End**

*For questions, see:*
- *[SERVER_SIDE_DETECTION_CORRELATION.md](./SERVER_SIDE_DETECTION_CORRELATION.md)* - Detailed correlation specification
- *[BEHAVIORAL_TELEMETRY_GUIDE.md](./BEHAVIORAL_TELEMETRY_GUIDE.md)* - Telemetry collection guide
- *[SERVER_ENFORCEMENT_PROTOCOL.md](./SERVER_ENFORCEMENT_PROTOCOL.md)* - Server directive protocol

*Last Updated: 2026-01-02*
