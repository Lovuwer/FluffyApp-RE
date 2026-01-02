# Dashboard Telemetry Schema Mapping

**Document Version:** 1.0  
**Task:** Task 32 - Operator Dashboard Telemetry  
**Date:** 2026-01-02  
**Related:** OPERATOR_DASHBOARD_SPECIFICATION.md

---

## Overview

This document maps existing Sentinel telemetry schemas to the dashboard metrics defined in the Operator Dashboard Specification. It demonstrates that the current telemetry infrastructure fully supports dashboard population without requiring schema changes.

---

## Schema Source Documents

1. **PERFORMANCE_TELEMETRY.md** - Performance metrics (Task 17)
2. **behavioral_telemetry_schema.md** - Behavioral patterns (Task 26)
3. **TELEMETRY_CORRELATION_PROTOCOL.md** - Session tracking (Task 27)

---

## Dashboard Metric Mappings

### 1. Detection Events by Category

**Dashboard Requirement:**
- Detection counts by category (Anti-Debug, Anti-Hook, Integrity, Injection, etc.)
- Severity levels (Critical, High, Medium, Low)
- Time-series data for trending

**Telemetry Source:**
CloudReporter violation events already include:
- `violation_type`: Maps directly to detection category
- `severity`: Maps directly to severity level  
- `timestamp`: Provides time-series dimension
- `detection_details`: Additional context for drill-down

**Schema Mapping:**
```json
// Source: CloudReporter violation event
{
  "type": "violation",
  "violation_type": "AntiHook",           // → detection_type
  "severity": "high",                      // → severity
  "timestamp": 1735689600000,              // → time_bucket
  "details": {
    "hook_type": "inline",
    "function": "NtCreateThread",
    "module": "ntdll.dll"
  }
}

// Dashboard aggregation query:
SELECT 
    violation_type as detection_type,
    severity,
    COUNT(*) as detection_count,
    DATE_TRUNC('hour', FROM_UNIXTIME(timestamp/1000)) as time_bucket
FROM violation_events
WHERE studio_id = ? AND timestamp >= ?
GROUP BY violation_type, severity, time_bucket;
```

**Status:** ✅ Fully Supported

---

### 2. Client Health Percentage

**Dashboard Requirement:**
- Health state distribution (Healthy, Suspicious, Flagged, Enforced, Offline)
- Active session count
- Percentage calculations

**Telemetry Source:**
Session tracking from TELEMETRY_CORRELATION_PROTOCOL.md:
- `session_id`: Unique identifier per client session
- `last_heartbeat`: Timestamp of last report
- `detection_count`: Number of violations detected
- `anomaly_score`: Behavioral anomaly score
- `status`: Session status

**Schema Mapping:**
```json
// Source: Session tracking table
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "player_id": "player_12345",
  "last_heartbeat": 1735689600000,         // → active/offline determination
  "detection_count": 2,                     // → health state calculation
  "anomaly_score": 15.5,                    // → health state calculation
  "max_severity": "medium",                 // → health state calculation
  "status": "active"                        // → enforced determination
}

// Health state calculation logic:
CASE
  WHEN last_heartbeat < NOW() - 5min THEN 'offline'
  WHEN status IN ('kicked', 'banned') THEN 'enforced'
  WHEN detection_count >= 3 OR max_severity IN ('high', 'critical') THEN 'flagged'
  WHEN detection_count BETWEEN 1 AND 2 AND max_severity IN ('low', 'medium') THEN 'suspicious'
  WHEN detection_count = 0 AND anomaly_score < 10 THEN 'healthy'
END as health_state
```

**Status:** ✅ Fully Supported

---

### 3. Performance Percentiles by Operation

**Dashboard Requirement:**
- P50, P95, P99 latency by operation type
- Sample counts
- SLA compliance indicators

**Telemetry Source:**
Performance telemetry from PERFORMANCE_TELEMETRY.md:
- Operation types: Initialize, Update, FullScan, ProtectMemory, etc.
- Latency measurements in milliseconds
- Timestamp for time-series

**Schema Mapping:**
```json
// Source: Performance telemetry
{
  "operation_type": "Update",              // → operation_type
  "latency_ms": 2.1,                       // → percentile calculation input
  "timestamp": 1735689600000,              // → time_bucket
  "sample_count": 1
}

// Dashboard aggregation query:
SELECT 
    operation_type,
    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms) as p50_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) as p95_ms,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms) as p99_ms,
    COUNT(*) as sample_count,
    DATE_TRUNC('5 minutes', FROM_UNIXTIME(timestamp/1000)) as time_bucket
FROM performance_samples
WHERE studio_id = ? AND timestamp >= ?
GROUP BY operation_type, time_bucket;
```

**Status:** ✅ Fully Supported

---

### 4. Enforcement Latency

**Dashboard Requirement:**
- End-to-end enforcement latency (detection → action)
- Latency component breakdown
- P50, P95, P99 metrics

**Telemetry Source:**
Enforcement events track full timeline:
- `detection_timestamp`: When SDK detected violation
- `report_timestamp`: When report was sent
- `server_received_timestamp`: When server received report
- `decision_timestamp`: When enforcement decision was made
- `action_timestamp`: When action was executed

**Schema Mapping:**
```json
// Source: Enforcement event
{
  "enforcement_id": "650e8400-e29b-41d4-a716-446655440001",
  "enforcement_type": "kick",              // → enforcement_type
  "detection_timestamp": 1735689600000,    // → latency calculation
  "report_timestamp": 1735689625000,       // → detection_to_report
  "server_received_timestamp": 1735689630000, // → report_to_server
  "decision_timestamp": 1735689632000,     // → server_to_decision
  "action_timestamp": 1735689642000        // → decision_to_action
}

// Latency calculations:
detection_to_report_seconds := (report_timestamp - detection_timestamp) / 1000
report_to_server_seconds := (server_received_timestamp - report_timestamp) / 1000
server_to_decision_seconds := (decision_timestamp - server_received_timestamp) / 1000
decision_to_action_seconds := (action_timestamp - decision_timestamp) / 1000
end_to_end_seconds := (action_timestamp - detection_timestamp) / 1000
```

**Status:** ✅ Fully Supported (requires server-side timestamp tracking)

---

### 5. Behavioral Anomaly Trends

**Dashboard Requirement:**
- Anomaly counts by type (Aimbot, Speed Hack, Automation, Wallhack)
- Average and maximum anomaly scores
- Trend direction over time

**Telemetry Source:**
Behavioral telemetry from behavioral_telemetry_schema.md:
- Input metrics: `actions_per_minute`, `input_variance`, `humanness_score`
- Movement metrics: `avg_velocity`, `max_velocity`, `teleport_count`
- Aim metrics: `avg_precision`, `flick_rate`, `snap_count`, `headshot_percentage`

**Schema Mapping:**
```json
// Source: Behavioral telemetry
{
  "type": "behavioral_telemetry",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "window_start_ms": 1735689600000,
  "window_end_ms": 1735689660000,
  "input": {
    "actions_per_minute": 450,            // → automation indicator
    "input_variance": 0.02,               // → automation indicator
    "humanness_score": 0.15               // → automation indicator
  },
  "movement": {
    "avg_velocity": 850,                  // → speed hack indicator
    "max_velocity": 1200,                 // → speed hack indicator
    "teleport_count": 3                   // → speed hack indicator
  },
  "aim": {
    "snap_count": 15,                     // → aimbot indicator
    "tracking_smoothness": 0.98,          // → aimbot indicator
    "headshot_percentage": 85             // → aimbot indicator
  }
}

// Anomaly detection logic:
IF aim.snap_count > 10 AND aim.tracking_smoothness > 0.95 THEN
    anomaly_type := 'aimbot'
    anomaly_score := 30

IF movement.avg_velocity > 600 AND movement.teleport_count > 0 THEN
    anomaly_type := 'speedhack'
    anomaly_score := 25

IF input.actions_per_minute > 400 AND input.humanness_score < 0.3 THEN
    anomaly_type := 'automation'
    anomaly_score := 35
```

**Status:** ✅ Fully Supported (requires server-side anomaly scoring)

---

## Aggregation Queries

### Detection Events - 5-Minute Aggregation

```sql
CREATE MATERIALIZED VIEW mv_detection_events_5min AS
SELECT 
    studio_id,
    violation_type as detection_type,
    severity,
    COUNT(*) as detection_count,
    DATE_TRUNC('5 minutes', FROM_UNIXTIME(timestamp/1000)) as time_bucket
FROM violation_events
WHERE timestamp >= UNIX_TIMESTAMP(NOW() - INTERVAL 7 DAYS) * 1000
GROUP BY studio_id, violation_type, severity, time_bucket;

-- Refresh every 5 minutes
REFRESH MATERIALIZED VIEW mv_detection_events_5min;
```

### Client Health - 1-Minute Aggregation

```sql
CREATE MATERIALIZED VIEW mv_client_health_1min AS
WITH session_health AS (
    SELECT 
        studio_id,
        session_id,
        CASE
            WHEN last_heartbeat < UNIX_TIMESTAMP(NOW() - INTERVAL 5 MINUTES) * 1000 THEN 'offline'
            WHEN status IN ('kicked', 'banned', 'temp_banned') THEN 'enforced'
            WHEN detection_count >= 3 OR max_severity IN ('high', 'critical') THEN 'flagged'
            WHEN detection_count BETWEEN 1 AND 2 AND max_severity IN ('low', 'medium') THEN 'suspicious'
            ELSE 'healthy'
        END as health_state
    FROM session_metrics
    WHERE last_heartbeat >= UNIX_TIMESTAMP(NOW() - INTERVAL 1 HOUR) * 1000
)
SELECT 
    studio_id,
    health_state,
    COUNT(*) as session_count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (PARTITION BY studio_id), 2) as percentage,
    DATE_TRUNC('1 minute', NOW()) as time_bucket
FROM session_health
GROUP BY studio_id, health_state;

-- Refresh every 1 minute
REFRESH MATERIALIZED VIEW mv_client_health_1min;
```

### Performance Percentiles - 5-Minute Aggregation

```sql
CREATE MATERIALIZED VIEW mv_performance_percentiles_5min AS
SELECT 
    studio_id,
    operation_type,
    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms) as p50_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) as p95_ms,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms) as p99_ms,
    COUNT(*) as sample_count,
    DATE_TRUNC('5 minutes', FROM_UNIXTIME(timestamp/1000)) as time_bucket
FROM performance_samples
WHERE timestamp >= UNIX_TIMESTAMP(NOW() - INTERVAL 24 HOURS) * 1000
GROUP BY studio_id, operation_type, time_bucket;

-- Refresh every 5 minutes
REFRESH MATERIALIZED VIEW mv_performance_percentiles_5min;
```

### Behavioral Anomalies - Hourly Aggregation

```sql
CREATE MATERIALIZED VIEW mv_behavioral_anomalies_hourly AS
SELECT 
    studio_id,
    anomaly_type,
    COUNT(DISTINCT session_id) as flagged_session_count,
    AVG(anomaly_score) as avg_score,
    MAX(anomaly_score) as max_score,
    DATE_TRUNC('hour', FROM_UNIXTIME(timestamp/1000)) as time_bucket
FROM behavioral_anomalies
WHERE timestamp >= UNIX_TIMESTAMP(NOW() - INTERVAL 7 DAYS) * 1000
GROUP BY studio_id, anomaly_type, time_bucket;

-- Refresh every hour
REFRESH MATERIALIZED VIEW mv_behavioral_anomalies_hourly;
```

---

## Data Flow

### Client → Server → Dashboard

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         TELEMETRY DATA FLOW                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. SDK Detection                                                        │
│     └─ Violation detected (AntiHook, AntiDebug, etc.)                   │
│        └─ Timestamp: detection_timestamp                                │
│                                                                          │
│  2. CloudReporter Batching                                              │
│     └─ Batch violations with sequence number                            │
│        └─ Timestamp: report_timestamp                                   │
│                                                                          │
│  3. HTTP Transmission                                                    │
│     └─ POST /api/v1/violations                                          │
│        └─ Timestamp: server_received_timestamp                          │
│                                                                          │
│  4. Server Ingestion                                                     │
│     └─ Validate, parse, enrich with studio_id                           │
│        └─ Write to message queue (Kafka)                                │
│                                                                          │
│  5. Stream Processing                                                    │
│     └─ Real-time aggregation (1-min, 5-min windows)                     │
│        └─ Write to TimescaleDB                                          │
│                                                                          │
│  6. Dashboard Cache                                                      │
│     └─ Update Redis cache for fast queries                              │
│        └─ TTL: 60 seconds                                               │
│                                                                          │
│  7. Dashboard Query                                                      │
│     └─ API: GET /api/v1/dashboard/overview                              │
│        └─ Return cached aggregated metrics                              │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Timestamp Handling

All timestamps in the telemetry system use Unix milliseconds (ms since epoch):

```typescript
// Client-side (SDK)
uint64_t detection_timestamp = GetCurrentTimestamp(); // Milliseconds since epoch

// JSON payload
{
  "timestamp": 1735689600000,  // 2026-01-02 14:00:00 UTC
  "window_start_ms": 1735689600000,
  "window_end_ms": 1735689660000
}

// Server-side processing
// Convert to SQL timestamp
FROM_UNIXTIME(timestamp / 1000)  // Divide by 1000 to convert ms to seconds

// Aggregation time buckets
DATE_TRUNC('5 minutes', FROM_UNIXTIME(timestamp / 1000))
DATE_TRUNC('1 hour', FROM_UNIXTIME(timestamp / 1000))
DATE_TRUNC('1 day', FROM_UNIXTIME(timestamp / 1000))
```

---

## Performance Considerations

### Query Optimization

**Pre-Aggregation:**
- Materialized views refreshed every 1-5 minutes
- 70-90% query time reduction
- Supports < 500ms dashboard query requirement

**Indexing Strategy:**
```sql
-- Time-series index (most selective)
CREATE INDEX idx_violations_studio_time ON violation_events(studio_id, timestamp DESC);

-- Detection type index for filtering
CREATE INDEX idx_violations_type ON violation_events(violation_type);

-- Session health index
CREATE INDEX idx_sessions_studio_heartbeat ON session_metrics(studio_id, last_heartbeat DESC);

-- Performance samples index
CREATE INDEX idx_perf_studio_op_time ON performance_samples(studio_id, operation_type, timestamp DESC);
```

**Partitioning:**
```sql
-- TimescaleDB automatic partitioning by time
SELECT create_hypertable('violation_events', 'timestamp', 
    chunk_time_interval => interval '1 day');

SELECT create_hypertable('performance_samples', 'timestamp',
    chunk_time_interval => interval '1 day');

SELECT create_hypertable('behavioral_telemetry', 'timestamp',
    chunk_time_interval => interval '1 day');
```

### Caching Strategy

**Redis Cache Keys:**
```
dashboard:overview:{studio_id}:{time_range}       TTL: 60s
dashboard:detections:{studio_id}:{time_range}     TTL: 60s
dashboard:performance:{studio_id}:{time_range}    TTL: 60s
dashboard:health:{studio_id}                      TTL: 30s
```

**Cache Invalidation:**
- Time-based expiration (TTL)
- Manual invalidation on materialized view refresh
- Cache warming on scheduled intervals

---

## Schema Completeness Verification

### Required Dashboard Metrics vs Available Telemetry

| Dashboard Metric | Telemetry Source | Status |
|-----------------|------------------|--------|
| Detection events by category | CloudReporter violations | ✅ Available |
| Detection severity levels | CloudReporter violations | ✅ Available |
| Client health distribution | Session tracking | ✅ Available |
| Active session count | Session heartbeats | ✅ Available |
| Performance P50/P95/P99 | Performance telemetry | ✅ Available |
| Performance by operation | Performance telemetry | ✅ Available |
| Enforcement latency | Enforcement events | ⚠️  Requires server timestamps |
| Behavioral anomaly counts | Behavioral telemetry | ✅ Available |
| Behavioral anomaly scores | Behavioral telemetry | ⚠️  Requires server scoring |
| Time-series trending | All sources | ✅ Available |

**Legend:**
- ✅ Available: Data exists in current telemetry schemas
- ⚠️  Requires: Needs server-side processing/enrichment

---

## Server-Side Enrichment Requirements

### 1. Enforcement Timestamp Tracking

**Requirement:** Track full enforcement timeline for latency calculation

**Implementation:**
```sql
CREATE TABLE enforcement_events (
    enforcement_id UUID PRIMARY KEY,
    session_id UUID NOT NULL,
    studio_id UUID NOT NULL,
    enforcement_type VARCHAR(50) NOT NULL,
    detection_timestamp BIGINT NOT NULL,      -- From client
    report_timestamp BIGINT NOT NULL,         -- From client
    server_received_timestamp BIGINT NOT NULL, -- Server adds
    decision_timestamp BIGINT NOT NULL,       -- Server adds
    action_timestamp BIGINT NOT NULL,         -- Server adds
    INDEX idx_enforcement_studio_time (studio_id, detection_timestamp DESC)
);
```

### 2. Behavioral Anomaly Scoring

**Requirement:** Calculate anomaly scores from behavioral telemetry

**Implementation:**
```python
def calculate_anomaly_score(behavioral_data):
    score = 0
    anomalies = []
    
    # Aimbot detection
    if (behavioral_data['aim']['snap_count'] > 10 and
        behavioral_data['aim']['tracking_smoothness'] > 0.95 and
        behavioral_data['aim']['headshot_percentage'] > 75):
        score += 30
        anomalies.append('aimbot')
    
    # Speed hack detection
    if (behavioral_data['movement']['avg_velocity'] > 600 and
        behavioral_data['movement']['teleport_count'] > 0):
        score += 25
        anomalies.append('speedhack')
    
    # Automation detection
    if (behavioral_data['input']['actions_per_minute'] > 400 and
        behavioral_data['input']['humanness_score'] < 0.3):
        score += 35
        anomalies.append('automation')
    
    return score, anomalies
```

---

## Conclusion

The existing Sentinel telemetry infrastructure **fully supports** the operator dashboard requirements:

**✅ Complete Support:**
- Detection events by category
- Client health distribution
- Performance percentiles
- Behavioral anomaly trends
- Time-series data for all metrics

**⚠️  Server-Side Additions Required:**
- Enforcement timeline tracking (add server timestamps)
- Behavioral anomaly scoring (server-side calculation)
- Aggregated view refresh automation (cron jobs)

**No Client-Side Changes Required:** All necessary data is already being collected and transmitted by the SDK.

---

**Document End**

*For implementation details, see OPERATOR_DASHBOARD_SPECIFICATION.md*

*Last Updated: 2026-01-02*
