# Server-Side Behavioral Telemetry Processing Requirements

## Overview

This document specifies the server-side requirements for processing behavioral telemetry data from the Sentinel SDK. The system detects statistical anomalies that may indicate novel or unknown cheating implementations.

**Primary Goal:** Identify anomalous player behavior patterns that deviate significantly from established baselines, indicating potential cheating activity that signature-based detection cannot catch.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        BEHAVIORAL PROCESSING PIPELINE                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│  │ Ingestion│───▶│Validation│───▶│   Storage│───▶│ Analysis │     │
│  │ Endpoint │    │  Layer   │    │  (TSDB)  │    │  Engine  │     │
│  └──────────┘    └──────────┘    └──────────┘    └────┬─────┘     │
│                                                         │           │
│                                                         ▼           │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│  │  Action  │◀───│  Scoring │◀───│Baseline  │    │Anomaly   │     │
│  │  System  │    │  System  │    │ Builder  │◀───│Detection │     │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 1. Ingestion Endpoint Requirements

### HTTP Endpoint Specification

**Endpoint:** `POST /api/v1/telemetry/behavioral`  
**Content-Type:** `application/json`  
**Authentication:** Required (JWT, API Key, or Session Token)

### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | Bearer token or API key |
| `Content-Type` | Yes | Must be `application/json` |
| `X-Session-ID` | Yes | Unique session identifier |
| `X-Player-ID` | Yes | Player/user identifier |
| `X-Client-Version` | Yes | SDK version (e.g., "1.0.0") |
| `X-Game-ID` | Yes | Game identifier |

### Request Body

See [behavioral_telemetry_schema.md](telemetry/behavioral_telemetry_schema.md) for complete schema.

### Response Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 | Success | Data accepted and queued for processing |
| 400 | Bad Request | Invalid JSON or schema validation failed |
| 401 | Unauthorized | Authentication failed |
| 413 | Payload Too Large | Telemetry payload exceeds size limits |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Error | Server error, client should retry with backoff |

### Rate Limiting

- **Per-player limit:** 100 requests per hour
- **Global limit:** 10,000 requests per second
- **Burst limit:** 10 requests per 10 seconds per player

### Performance Requirements

- **Latency:** < 100ms p99 response time
- **Throughput:** Handle 10,000+ requests per second
- **Availability:** 99.9% uptime

## 2. Validation Layer Requirements

### Schema Validation

Validate all incoming telemetry against the schema:

```python
def validate_behavioral_telemetry(payload):
    """Validate behavioral telemetry payload."""
    
    # Required fields
    required_fields = ['type', 'version', 'window_start_ms', 'window_end_ms', 'sample_count']
    for field in required_fields:
        if field not in payload:
            raise ValidationError(f"Missing required field: {field}")
    
    # Type check
    if payload['type'] != 'behavioral_telemetry':
        raise ValidationError(f"Invalid type: {payload['type']}")
    
    # Version check
    if payload['version'] not in SUPPORTED_VERSIONS:
        raise ValidationError(f"Unsupported version: {payload['version']}")
    
    # Timestamp validation
    if payload['window_start_ms'] >= payload['window_end_ms']:
        raise ValidationError("Invalid window: start >= end")
    
    window_duration = payload['window_end_ms'] - payload['window_start_ms']
    if window_duration > 3600000:  # 1 hour
        raise ValidationError(f"Window too large: {window_duration}ms")
    
    # Range validation for metrics
    if 'input' in payload:
        validate_input_metrics(payload['input'])
    
    if 'movement' in payload:
        validate_movement_metrics(payload['movement'])
    
    if 'aim' in payload:
        validate_aim_metrics(payload['aim'])
    
    if 'custom' in payload:
        validate_custom_metrics(payload['custom'])
    
    return True
```

### Data Sanitization

Before storage, sanitize all inputs:

```python
def sanitize_telemetry(payload):
    """Sanitize telemetry data before storage."""
    
    # Sanitize custom metric names (alphanumeric + underscore only)
    if 'custom' in payload:
        for metric in payload['custom']:
            metric['name'] = re.sub(r'[^a-zA-Z0-9_]', '', metric['name'])
            metric['name'] = metric['name'][:64]  # Max 64 chars
            
            if 'unit' in metric:
                metric['unit'] = metric['unit'][:32]  # Max 32 chars
    
    # Clamp numeric values to valid ranges
    if 'input' in payload:
        payload['input']['humanness_score'] = clamp(
            payload['input']['humanness_score'], 0.0, 1.0
        )
    
    if 'aim' in payload:
        payload['aim']['avg_precision'] = clamp(
            payload['aim']['avg_precision'], 0.0, 1.0
        )
        payload['aim']['headshot_percentage'] = clamp(
            payload['aim']['headshot_percentage'], 0.0, 100.0
        )
    
    return payload
```

### Anti-Abuse Detection

Flag suspicious submission patterns:

- Identical payloads submitted repeatedly (possible replay attack)
- Payloads with impossible metric values
- Excessive submission rate from single client
- Metrics that never vary (possible spoofing)

## 3. Storage Requirements

### Time-Series Database

Recommended: **InfluxDB**, **TimescaleDB**, or **Amazon Timestream**

#### Schema Design

**Measurement:** `behavioral_telemetry`

**Tags (indexed):**
- `player_id`: Player identifier
- `session_id`: Session identifier
- `game_id`: Game identifier
- `client_version`: SDK version

**Fields:**
- All metric values from the telemetry payload
- Computed fields (e.g., anomaly scores)

**Timestamp:** `window_end_ms`

#### Retention Policy

| Data Type | Retention | Aggregation |
|-----------|-----------|-------------|
| Raw telemetry | 30 days | None |
| Hourly aggregates | 90 days | Mean, min, max, stddev |
| Daily aggregates | 1 year | Mean, min, max, stddev |
| Player baselines | Indefinite | Rolling statistics |

#### Example InfluxDB Schema

```sql
CREATE DATABASE behavioral_telemetry

-- Raw telemetry retention
CREATE RETENTION POLICY "raw_30d" ON "behavioral_telemetry" 
  DURATION 30d REPLICATION 1 DEFAULT

-- Hourly aggregates
CREATE RETENTION POLICY "hourly_90d" ON "behavioral_telemetry" 
  DURATION 90d REPLICATION 1

-- Continuous query for hourly aggregation
CREATE CONTINUOUS QUERY "cq_hourly_agg" ON "behavioral_telemetry"
BEGIN
  SELECT 
    mean("humanness_score") AS "humanness_score_mean",
    stddev("humanness_score") AS "humanness_score_stddev",
    mean("snap_count") AS "snap_count_mean",
    mean("teleport_count") AS "teleport_count_mean",
    mean("headshot_percentage") AS "headshot_percentage_mean"
  INTO "hourly_90d"."behavioral_aggregates"
  FROM "raw_30d"."behavioral_telemetry"
  GROUP BY time(1h), player_id, game_id
END
```

### Performance Requirements

- **Write throughput:** 100,000+ writes per second
- **Query latency:** < 500ms for baseline queries
- **Storage:** Plan for ~100 bytes per telemetry record

## 4. Baseline Builder Requirements

### Purpose

Establish normal behavioral patterns for each player to enable anomaly detection.

### Baseline Metrics

For each player, maintain rolling statistics over the last 7 days:

#### Input Baseline
```python
{
    "actions_per_minute": {
        "mean": float,
        "stddev": float,
        "min": float,
        "max": float,
        "percentile_25": float,
        "percentile_75": float
    },
    "humanness_score": {
        "mean": float,
        "stddev": float,
        "min": float,
        "max": float
    },
    "sample_count": int
}
```

#### Movement Baseline
```python
{
    "avg_velocity": {"mean": float, "stddev": float, ...},
    "teleport_count": {"mean": float, "stddev": float, ...},
    "sample_count": int
}
```

#### Aim Baseline
```python
{
    "avg_precision": {"mean": float, "stddev": float, ...},
    "snap_count": {"mean": float, "stddev": float, ...},
    "headshot_percentage": {"mean": float, "stddev": float, ...},
    "sample_count": int
}
```

### Baseline Update Algorithm

```python
def update_player_baseline(player_id, new_telemetry):
    """Update player baseline with new telemetry data."""
    
    # Get existing baseline
    baseline = get_player_baseline(player_id)
    
    # If baseline has < 20 samples, we're still in learning phase
    if baseline['sample_count'] < 20:
        # Simply accumulate data
        baseline = accumulate_sample(baseline, new_telemetry)
    else:
        # Use exponential moving average for rolling baseline
        alpha = 0.1  # Weight for new data (tunable: 0.05-0.2)
                     # Lower = more stable, slower adaptation
                     # Higher = faster adaptation, less stable
        
        for metric_category in ['input', 'movement', 'aim']:
            if metric_category in new_telemetry:
                for metric_name, value in new_telemetry[metric_category].items():
                    # Update rolling mean
                    baseline[metric_category][metric_name]['mean'] = \
                        (1 - alpha) * baseline[metric_category][metric_name]['mean'] + \
                        alpha * value
                    
                    # Update rolling stddev (using Welford's algorithm)
                    baseline[metric_category][metric_name]['stddev'] = \
                        update_rolling_stddev(
                            baseline[metric_category][metric_name]['stddev'],
                            baseline[metric_category][metric_name]['mean'],
                            value,
                            alpha
                        )
    
    baseline['sample_count'] += 1
    baseline['last_updated'] = now()
    
    save_player_baseline(player_id, baseline)
    return baseline
```

### Initial Learning Period

- **Duration:** First 20 telemetry samples (typically 20-60 minutes of gameplay)
  - The threshold of 20 samples provides enough data for statistical significance while keeping learning time reasonable
  - Configurable per game based on session lengths and variance in player behavior
- **Behavior:** Build baseline without triggering anomaly alerts
- **Grace period:** No enforcement actions during learning

## 5. Anomaly Detection Requirements

### Detection Algorithm

Use **statistical anomaly detection** with z-scores:

```python
def detect_anomalies(telemetry, baseline):
    """Detect anomalies in telemetry compared to baseline."""
    
    anomalies = []
    
    # Input anomalies
    if 'input' in telemetry and baseline['sample_count'] >= 20:
        humanness = telemetry['input']['humanness_score']
        mean = baseline['input']['humanness_score']['mean']
        stddev = baseline['input']['humanness_score']['stddev']
        
        z_score = abs(humanness - mean) / (stddev + 1e-6)
        
        if z_score > 3.0 and humanness < 0.3:
            anomalies.append({
                'type': 'low_humanness',
                'severity': 'high',
                'value': humanness,
                'z_score': z_score,
                'description': 'Input timing patterns too consistent for human'
            })
    
    # Movement anomalies
    if 'movement' in telemetry:
        teleports = telemetry['movement']['teleport_count']
        
        if teleports > 5:
            anomalies.append({
                'type': 'excessive_teleports',
                'severity': 'critical',
                'value': teleports,
                'description': 'Suspicious position jumps detected'
            })
    
    # Aim anomalies
    if 'aim' in telemetry and baseline['sample_count'] >= 20:
        snap_count = telemetry['aim']['snap_count']
        mean_snaps = baseline['aim']['snap_count']['mean']
        stddev_snaps = baseline['aim']['snap_count']['stddev']
        
        z_score = abs(snap_count - mean_snaps) / (stddev_snaps + 1e-6)
        
        if z_score > 4.0 and snap_count > 10:
            anomalies.append({
                'type': 'excessive_aim_snaps',
                'severity': 'critical',
                'value': snap_count,
                'z_score': z_score,
                'description': 'Possible aimbot detected'
            })
        
        headshot_pct = telemetry['aim']['headshot_percentage']
        
        if headshot_pct > 80.0:
            anomalies.append({
                'type': 'impossible_headshot_rate',
                'severity': 'high',
                'value': headshot_pct,
                'description': 'Headshot percentage too high for legitimate play'
            })
    
    return anomalies
```

### Anomaly Types and Thresholds

| Anomaly Type | Metric | Threshold | Severity |
|--------------|--------|-----------|----------|
| Bot-like input | `humanness_score` | < 0.3 AND z-score > 3 | High |
| Excessive teleports | `teleport_count` | > 5 per minute | Critical |
| Aim snapping | `snap_count` | > 10 per minute AND z-score > 4 | Critical |
| Impossible headshots | `headshot_percentage` | > 80% | High |
| Perfect tracking | `tracking_smoothness` | > 0.98 AND z-score > 3 | Medium |
| Superhuman reaction | `reaction_time_ms` | < 100ms | Medium |

### False Positive Mitigation

1. **Require multiple anomalies** - Single anomalies may be legitimate
2. **Context awareness** - Consider player skill level, game mode
3. **Temporal correlation** - Multiple anomalous windows increase confidence
4. **Cross-validation** - Correlate with other detection signals

## 6. Scoring System Requirements

### Risk Score Calculation

Compute a **behavioral risk score** (0-100) for each player:

```python
def calculate_risk_score(player_id, recent_telemetry_windows=10):
    """Calculate behavioral risk score for player."""
    
    score = 0.0
    weight_sum = 0.0
    
    # Get last N telemetry windows
    windows = get_recent_telemetry(player_id, limit=recent_telemetry_windows)
    
    for i, window in enumerate(windows):
        # More recent windows have higher weight
        weight = 1.0 / (i + 1)
        
        anomalies = detect_anomalies(window['telemetry'], window['baseline'])
        
        # Add points for each anomaly
        for anomaly in anomalies:
            if anomaly['severity'] == 'critical':
                score += 25 * weight
            elif anomaly['severity'] == 'high':
                score += 15 * weight
            elif anomaly['severity'] == 'medium':
                score += 5 * weight
        
        weight_sum += weight
    
    # Normalize to 0-100 range
    if weight_sum > 0:
        score = min(100.0, (score / weight_sum) * 10)
    
    return score
```

### Risk Levels

| Score Range | Risk Level | Recommended Action |
|-------------|------------|-------------------|
| 0-20 | Low | Normal play, no action |
| 21-40 | Moderate | Monitor closely, collect more data |
| 41-60 | High | Flag for manual review |
| 61-80 | Very High | Restrict features, increase monitoring |
| 81-100 | Critical | Temporary ban, manual review required |

## 7. Action System Requirements

### Automated Actions

Based on risk score, trigger automated responses:

```python
def apply_automated_actions(player_id, risk_score):
    """Apply automated actions based on risk score."""
    
    if risk_score >= 80:
        # Critical risk - immediate action
        create_case(
            player_id=player_id,
            priority='critical',
            description='Behavioral anomalies detected',
            auto_actions=['temp_ban_24h', 'manual_review']
        )
        
        apply_temporary_ban(player_id, duration_hours=24)
        send_alert_to_moderators(player_id, risk_score)
        
    elif risk_score >= 60:
        # Very high risk - restrict and monitor
        create_case(
            player_id=player_id,
            priority='high',
            description='Multiple behavioral anomalies',
            auto_actions=['restrict_competitive', 'enhanced_monitoring']
        )
        
        restrict_competitive_modes(player_id)
        increase_telemetry_frequency(player_id)
        
    elif risk_score >= 40:
        # High risk - flag for review
        create_case(
            player_id=player_id,
            priority='medium',
            description='Suspicious behavioral patterns',
            auto_actions=['manual_review']
        )
```

### Manual Review Queue

Provide moderators with:
- Player behavior timeline
- Anomaly visualizations
- Statistical comparison to normal players
- Historical risk scores
- Other detection signals (signature-based, integrity checks)

## 8. Performance Metrics

### System Health Monitoring

Track these metrics:

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Ingestion latency | < 100ms p99 | > 200ms |
| Processing latency | < 1s | > 5s |
| False positive rate | < 5% | > 10% |
| True positive rate | > 70% | < 50% |
| Storage growth | ~10 GB/day per 100k players | > 20 GB/day |

### Detection Effectiveness

Measure and optimize:
- **True Positive Rate:** Correctly identified cheaters
- **False Positive Rate:** Legitimate players flagged
- **Detection Delay:** Time from cheat activation to detection
- **Coverage:** Percentage of cheat types detected

## 9. Privacy and Compliance

### Data Handling Requirements

1. **No PII in telemetry** - Validate that player names, IPs, etc. are not in payload
2. **Data retention limits** - Implement automatic deletion per retention policy
3. **Data access controls** - Only authorized personnel can access raw telemetry
4. **Data export** - Provide player data export for GDPR compliance
5. **Data deletion** - Support right-to-be-forgotten requests

### Audit Logging

Log all access to behavioral telemetry:
- Who accessed the data
- When it was accessed
- What queries were run
- Purpose of access

## 10. Implementation Checklist

### Phase 1: Core Infrastructure (Week 1-2)
- [ ] Set up ingestion endpoint with authentication
- [ ] Implement schema validation
- [ ] Configure time-series database
- [ ] Set up data retention policies
- [ ] Implement rate limiting

### Phase 2: Analytics (Week 3-4)
- [ ] Implement baseline builder
- [ ] Implement anomaly detection algorithms
- [ ] Build risk scoring system
- [ ] Create monitoring dashboards
- [ ] Set up alerting

### Phase 3: Actions (Week 5-6)
- [ ] Implement automated action system
- [ ] Build manual review interface
- [ ] Create case management system
- [ ] Set up moderator tools
- [ ] Implement appeal process

### Phase 4: Optimization (Week 7-8)
- [ ] Tune detection thresholds
- [ ] Optimize false positive rate
- [ ] Performance optimization
- [ ] Load testing
- [ ] Documentation

## References

- [behavioral_telemetry_schema.md](telemetry/behavioral_telemetry_schema.md) - JSON schema specification
- [BEHAVIORAL_TELEMETRY_GUIDE.md](BEHAVIORAL_TELEMETRY_GUIDE.md) - Client integration guide
- [SERVER_SIDE_DETECTION_CORRELATION.md](SERVER_SIDE_DETECTION_CORRELATION.md) - Detection correlation strategies
