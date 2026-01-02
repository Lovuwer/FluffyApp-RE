# Behavioral Telemetry Schema Specification

## Overview

This document defines the JSON schema for behavioral telemetry data transmitted from the Sentinel SDK to the cloud backend. The schema is designed to be privacy-conscious, bandwidth-efficient, and extensible for game-specific metrics.

## Schema Version

**Version:** 1.0  
**Last Updated:** 2025-01-02

## Top-Level Schema

```json
{
  "type": "behavioral_telemetry",
  "version": "1.0",
  "window_start_ms": <uint64>,
  "window_end_ms": <uint64>,
  "sample_count": <uint32>,
  "input": { ... },
  "movement": { ... },
  "aim": { ... },
  "custom": [ ... ]
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Always "behavioral_telemetry" |
| `version` | string | Yes | Schema version (e.g., "1.0") |
| `window_start_ms` | uint64 | Yes | Unix timestamp in milliseconds when aggregation window started |
| `window_end_ms` | uint64 | Yes | Unix timestamp in milliseconds when aggregation window ended |
| `sample_count` | uint32 | Yes | Total number of samples collected in this window |
| `input` | object | No | Input pattern metrics (present if collect_input=true) |
| `movement` | object | No | Movement pattern metrics (present if collect_movement=true) |
| `aim` | object | No | Aim pattern metrics (present if collect_aim=true) |
| `custom` | array | No | Game-specific custom metrics |

## Input Metrics Schema

```json
{
  "actions_per_minute": <uint32>,
  "avg_input_interval_ms": <float>,
  "input_variance": <float>,
  "simultaneous_inputs": <uint32>,
  "humanness_score": <float>
}
```

### Field Descriptions

| Field | Type | Range | Description |
|-------|------|-------|-------------|
| `actions_per_minute` | uint32 | 0-10000 | Number of input actions per minute (APM) |
| `avg_input_interval_ms` | float | 0.0+ | Average time between consecutive inputs in milliseconds |
| `input_variance` | float | 0.0+ | Variance in input timing (higher = more human-like) |
| `simultaneous_inputs` | uint32 | 0-10 | Maximum number of simultaneous inputs observed |
| `humanness_score` | float | 0.0-1.0 | Computed score where higher values indicate more human-like patterns |

### Privacy Notes
- **No raw keystroke data** - Only timing statistics
- **No key codes** - No information about which keys were pressed
- **Aggregated only** - Individual keystrokes cannot be reconstructed

## Movement Metrics Schema

```json
{
  "avg_velocity": <float>,
  "max_velocity": <float>,
  "velocity_variance": <float>,
  "avg_direction_change_rate": <float>,
  "path_smoothness": <float>,
  "teleport_count": <uint32>
}
```

### Field Descriptions

| Field | Type | Range | Description |
|-------|------|-------|-------------|
| `avg_velocity` | float | 0.0+ | Average movement speed in game units per second |
| `max_velocity` | float | 0.0+ | Maximum movement speed observed |
| `velocity_variance` | float | 0.0+ | Variance in velocity values |
| `avg_direction_change_rate` | float | 0.0+ | Average rate of direction changes per second |
| `path_smoothness` | float | 0.0-1.0 | Movement smoothness score (higher = smoother) |
| `teleport_count` | uint32 | 0+ | Number of suspicious position jumps detected (velocity spikes > 5x average) |

### Privacy Notes
- **No absolute positions** - Only velocity and direction change metrics
- **No coordinates** - Player location data is never transmitted

## Aim Metrics Schema

```json
{
  "avg_precision": <float>,
  "flick_rate": <float>,
  "tracking_smoothness": <float>,
  "reaction_time_ms": <float>,
  "headshot_percentage": <float>,
  "snap_count": <uint32>
}
```

### Field Descriptions

| Field | Type | Range | Description |
|-------|------|-------|-------------|
| `avg_precision` | float | 0.0-1.0 | Average aim accuracy (0.0 = miss, 1.0 = perfect) |
| `flick_rate` | float | 0.0+ | Number of rapid aim movements per minute |
| `tracking_smoothness` | float | 0.0-1.0 | Aim tracking consistency (higher = smoother) |
| `reaction_time_ms` | float | 0.0+ | Estimated reaction time in milliseconds |
| `headshot_percentage` | float | 0.0-100.0 | Percentage of shots resulting in headshots |
| `snap_count` | uint32 | 0+ | Number of instant aim snaps detected (potential aimbot indicator) |

### Privacy Notes
- **No target information** - No data about what was aimed at
- **No screen coordinates** - Only aggregated precision metrics

## Custom Metrics Schema

```json
[
  {
    "name": <string>,
    "value": <float>,
    "unit": <string>
  },
  ...
]
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Metric name (alphanumeric, underscores, max 64 chars) |
| `value` | float | Yes | Metric value |
| `unit` | string | No | Unit description (optional, max 32 chars) |

### Constraints
- Maximum 100 custom metrics per window (excess metrics are silently ignored)
- Metric names must be unique within a window
- Total custom metrics size should not exceed 200 bytes

### Example Custom Metrics

```json
[
  {
    "name": "building_speed",
    "value": 15.5,
    "unit": "per_minute"
  },
  {
    "name": "resource_efficiency",
    "value": 0.87,
    "unit": "ratio"
  },
  {
    "name": "combo_length",
    "value": 42.0,
    "unit": "hits"
  }
]
```

## Complete Example Payload

```json
{
  "type": "behavioral_telemetry",
  "version": "1.0",
  "window_start_ms": 1704153600000,
  "window_end_ms": 1704153660000,
  "sample_count": 150,
  "input": {
    "actions_per_minute": 180,
    "avg_input_interval_ms": 333.33,
    "input_variance": 89.5,
    "simultaneous_inputs": 2,
    "humanness_score": 0.75
  },
  "movement": {
    "avg_velocity": 15.3,
    "max_velocity": 32.5,
    "velocity_variance": 45.2,
    "avg_direction_change_rate": 2.1,
    "path_smoothness": 0.82,
    "teleport_count": 0
  },
  "aim": {
    "avg_precision": 0.68,
    "flick_rate": 12.5,
    "tracking_smoothness": 0.71,
    "reaction_time_ms": 245.0,
    "headshot_percentage": 18.3,
    "snap_count": 2
  },
  "custom": [
    {
      "name": "building_speed",
      "value": 15.5,
      "unit": "per_minute"
    },
    {
      "name": "combat_score",
      "value": 1250.0,
      "unit": "points"
    }
  ]
}
```

## Bandwidth Analysis

### Typical Payload Sizes

| Configuration | Approximate Size | Bandwidth (per minute) |
|--------------|------------------|------------------------|
| Input only | 200-250 bytes | 200-250 bytes/min |
| Input + Movement | 350-400 bytes | 350-400 bytes/min |
| All standard metrics | 500-550 bytes | 500-550 bytes/min |
| All + 5 custom metrics | 650-750 bytes | 650-750 bytes/min |

**Target:** < 1KB per minute ✓

### Compression Recommendations

For bandwidth-constrained environments, consider:
- gzip compression (typically 40-60% reduction)
- Longer aggregation windows (2-5 minutes)
- Selective metric collection

## Versioning and Backward Compatibility

### Version Evolution

The schema version follows semantic versioning:
- **Major version** (e.g., 2.0): Breaking changes, incompatible with previous versions
- **Minor version** (e.g., 1.1): New optional fields, backward compatible
- **Patch version** (e.g., 1.0.1): Documentation fixes, no schema changes

### Adding New Fields

New optional fields can be added in minor version updates:
1. New fields must be optional
2. Default values must be documented
3. Old parsers must ignore unknown fields gracefully

### Deprecating Fields

Fields can be deprecated but not removed until the next major version:
1. Mark field as deprecated in documentation
2. Server continues accepting deprecated fields
3. Remove in next major version (e.g., 2.0)

## Server Parsing Guidelines

### Validation Rules

Servers should validate:
1. `type` field equals "behavioral_telemetry"
2. `version` field is supported
3. `window_start_ms` < `window_end_ms`
4. Window duration is reasonable (< 1 hour)
5. Metric values are within documented ranges
6. No SQL injection characters in custom metric names

### Error Handling

For invalid payloads:
- Log validation errors with client identifier
- Reject with HTTP 400 Bad Request
- Do not store invalid data
- Rate limit clients sending invalid data

### Storage Recommendations

- Store in time-series database (InfluxDB, TimescaleDB)
- Index by: player ID, session ID, timestamp
- Retain for 30-90 days for analysis
- Aggregate to hourly/daily summaries for long-term storage

## Security Considerations

### Data Sanitization

Before storage, sanitize:
- Custom metric names (alphanumeric + underscore only)
- String fields (validate length limits)
- Numeric fields (validate ranges)

### Privacy Compliance

This schema is designed for GDPR/CCPA compliance:
- No PII (Personally Identifiable Information)
- No keystroke logging
- No screen capture data
- No absolute position data
- Aggregated metrics only

### Anomaly Detection

Servers should flag:
- `humanness_score` < 0.3 (potential bot)
- `snap_count` > 10 per minute (potential aimbot)
- `teleport_count` > 5 per minute (potential speed hack)
- `headshot_percentage` > 80% (potential aimbot)
- Impossible velocity values (> 5x game's max legitimate velocity)

## References

- [BEHAVIORAL_TELEMETRY_GUIDE.md](../BEHAVIORAL_TELEMETRY_GUIDE.md) - Integration guide
- [SERVER_BEHAVIORAL_PROCESSING.md](../SERVER_BEHAVIORAL_PROCESSING.md) - Server-side processing requirements
- [INTEGRATION_GUIDE.md](../INTEGRATION_GUIDE.md) - General integration guide
