# Behavioral Telemetry Integration Guide

## Overview

The Behavioral Telemetry Collector is a privacy-conscious system for detecting novel cheats through statistical anomaly detection. It collects aggregated behavioral metrics from gameplay without capturing sensitive data like raw keystrokes or screen content.

## Key Features

- **Privacy-Conscious Design**: No keystroke logging, no screen capture, only aggregated statistical metrics
- **Efficient Collection**: Configurable sample rates with minimal performance overhead
- **Local Aggregation**: Data is aggregated locally before transmission to minimize bandwidth
- **Extensible**: Supports game-specific custom metrics
- **Low Bandwidth**: Designed to stay under 1KB per minute at default settings

## Quick Start

### 1. Include the Header

```cpp
#include "Internal/BehavioralCollector.hpp"
```

### 2. Initialize the Collector

```cpp
using namespace Sentinel::SDK;

// Create configuration
BehavioralConfig config;
config.enabled = true;
config.sample_rate_ms = 1000;          // Sample every second
config.aggregation_window_ms = 60000;  // Aggregate over 1 minute
config.collect_input = true;
config.collect_movement = true;
config.collect_aim = true;

// Initialize collector
BehavioralCollector collector;
collector.Initialize(config);

// Set CloudReporter for transmission
CloudReporter* reporter = ...; // Your CloudReporter instance
collector.SetCloudReporter(reporter);
```

### 3. Record Behavioral Data

#### Input Metrics

Record input actions with timing only (no keystroke data):

```cpp
// When player presses a key/button
uint64_t timestamp_ms = GetCurrentTimestamp();
uint32_t concurrent_inputs = 1;  // Number of simultaneous inputs

collector.RecordInput(timestamp_ms, concurrent_inputs);
```

#### Movement Metrics

Record player movement data:

```cpp
// During game tick/frame update
float velocity = CalculatePlayerVelocity();
float direction_change_rate = CalculateDirectionChangeRate();

collector.RecordMovement(velocity, direction_change_rate);
```

#### Aim Metrics

Record aiming and shooting data:

```cpp
// When player shoots/aims
float precision = CalculateAimPrecision();  // 0.0 - 1.0
float flick_speed = CalculateAimSpeed();    // Degrees per second
bool is_headshot = (hit_location == HEAD);

collector.RecordAim(precision, flick_speed, is_headshot);
```

#### Custom Metrics

Add game-specific metrics:

```cpp
// Record any game-specific metric
collector.RecordCustomMetric("building_speed", buildings_per_minute, "per_minute");
collector.RecordCustomMetric("resource_efficiency", efficiency_ratio, "ratio");
collector.RecordCustomMetric("combo_length", max_combo, "hits");
```

### 4. Automatic Transmission

The collector automatically aggregates and transmits data:
- When the aggregation window elapses (default: 1 minute)
- When manually flushed

```cpp
// Manual flush (optional)
collector.Flush();
```

### 5. Shutdown

```cpp
// Clean shutdown (flushes remaining data)
collector.Shutdown();
```

## Configuration Reference

### BehavioralConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Enable/disable collection |
| `sample_rate_ms` | uint32_t | 1000 | Sample interval in milliseconds |
| `aggregation_window_ms` | uint32_t | 60000 | Aggregation window (1 minute) |
| `collect_input` | bool | true | Collect input metrics |
| `collect_movement` | bool | true | Collect movement metrics |
| `collect_aim` | bool | true | Collect aim metrics |

## Collected Metrics

### Input Metrics

- **Actions Per Minute (APM)**: Rate of player inputs
- **Average Input Interval**: Mean time between inputs
- **Input Variance**: Variability in input timing
- **Simultaneous Inputs**: Maximum concurrent inputs
- **Humanness Score**: 0.0-1.0, based on timing variance (bots have lower variance)

### Movement Metrics

- **Average Velocity**: Mean movement speed
- **Max Velocity**: Peak movement speed
- **Velocity Variance**: Variability in speed
- **Direction Change Rate**: Direction changes per second
- **Path Smoothness**: 0.0-1.0, based on movement consistency
- **Teleport Count**: Suspicious position jumps detected

### Aim Metrics

- **Average Precision**: Mean aim accuracy (0.0-1.0)
- **Flick Rate**: Rapid aim changes per minute
- **Tracking Smoothness**: 0.0-1.0, consistency in aim tracking
- **Reaction Time**: Estimated from precision
- **Headshot Percentage**: Percentage of headshots
- **Snap Count**: Instant aim snaps detected (potential aimbot indicator)

## Privacy Compliance

### What is NOT Collected

- ❌ Raw keystroke data (no key codes, no key names)
- ❌ Screen captures or screenshots
- ❌ Mouse coordinates
- ❌ Individual timestamps (only intervals)
- ❌ Player names or identifiers
- ❌ Chat messages or text input

### What IS Collected

- ✅ Aggregated input timing statistics
- ✅ Movement speed and pattern statistics
- ✅ Aim precision and smoothness metrics
- ✅ Game-specific performance metrics

All data is aggregated before transmission, ensuring individual actions cannot be reconstructed from the telemetry.

## Integration Examples

### First-Person Shooter (FPS)

```cpp
void OnPlayerTick() {
    // Record movement
    Vector3 velocity = player->GetVelocity();
    float speed = velocity.Length();
    float direction_change = CalculateDirectionChange();
    
    collector.RecordMovement(speed, direction_change);
}

void OnPlayerShoot(WeaponFire event) {
    // Record aim metrics
    float precision = CalculateHitPrecision(event.target, event.hitPoint);
    float flick_speed = CalculateAimDelta(event.aimDelta, event.timeDelta);
    bool headshot = event.hitLocation == HitLocation::Head;
    
    collector.RecordAim(precision, flick_speed, headshot);
    
    // Record input timing
    collector.RecordInput(event.timestamp, 1);
}

void OnPlayerInput(InputEvent event) {
    // Record input patterns
    uint32_t concurrent = CountActiveInputs();
    collector.RecordInput(event.timestamp, concurrent);
}
```

### Battle Royale

```cpp
void OnPlayerUpdate() {
    // Movement tracking
    collector.RecordMovement(player->velocity, player->turnRate);
    
    // Custom metrics
    collector.RecordCustomMetric("buildings_built", 
        player->GetBuildingsInLastMinute(), "buildings");
    collector.RecordCustomMetric("materials_gathered",
        player->GetMaterialsGatheredRate(), "per_minute");
}

void OnCombatEvent(CombatEvent event) {
    float accuracy = event.shotsHit / (float)event.shotsFired;
    collector.RecordAim(accuracy, event.aimSpeed, event.wasHeadshot);
    
    collector.RecordCustomMetric("combat_score", 
        CalculateCombatScore(), "points");
}
```

### MOBA/Strategy Game

```cpp
void OnGameTick() {
    // APM tracking
    collector.RecordInput(GetCurrentTime(), 
        GetActiveCommandsCount());
    
    // Custom metrics
    collector.RecordCustomMetric("actions_per_minute",
        player->GetAPM(), "apm");
    collector.RecordCustomMetric("camera_movement",
        player->GetCameraSpeed(), "units_per_sec");
    collector.RecordCustomMetric("micro_intensity",
        CalculateMicroIntensity(), "score");
}
```

## Performance Considerations

### Memory Usage

- The collector maintains sample buffers with a maximum size of 10,000 samples per window
- Typical memory usage: ~500KB for a full aggregation window
- Automatic overflow protection prevents memory issues

### CPU Overhead

- Sample recording: < 1 microsecond per call
- Aggregation: ~1-5 milliseconds per window
- Runs on a background thread, no impact on game loop

### Bandwidth Usage

With default settings (1-minute aggregation window):
- Input only: ~200-300 bytes per window
- Input + Movement: ~300-400 bytes per window
- All metrics: ~400-600 bytes per window
- With custom metrics: ~500-800 bytes per window

**Target: < 1KB per minute** ✓

## Best Practices

### 1. Choose Appropriate Sample Rates

```cpp
// High-action games (FPS, Fighting)
config.sample_rate_ms = 500;  // Sample more frequently

// Strategy games (RTS, MOBA)
config.sample_rate_ms = 1000; // Standard rate

// Turn-based games
config.sample_rate_ms = 2000; // Sample less frequently
```

### 2. Adjust Aggregation Windows

```cpp
// For quick feedback
config.aggregation_window_ms = 30000;  // 30 seconds

// For bandwidth-constrained environments
config.aggregation_window_ms = 120000; // 2 minutes
```

### 3. Selective Collection

Disable unnecessary metrics for your game genre:

```cpp
// Racing game - no aim metrics needed
config.collect_aim = false;
config.collect_input = true;
config.collect_movement = true;

// Turn-based strategy - simplified collection
config.collect_movement = false;
config.collect_aim = false;
config.collect_input = true;
```

### 4. Use Custom Metrics Wisely

Add 3-5 game-specific metrics that are most relevant to your game:

```cpp
// Good: Specific, relevant metrics
collector.RecordCustomMetric("headshot_rate", rate, "percentage");
collector.RecordCustomMetric("reaction_time", time_ms, "milliseconds");

// Avoid: Too many metrics (bandwidth overhead)
// Avoid: Metrics that duplicate existing standard metrics
```

## Troubleshooting

### High Bandwidth Usage

1. Increase aggregation window:
   ```cpp
   config.aggregation_window_ms = 120000; // 2 minutes
   ```

2. Disable unnecessary metrics:
   ```cpp
   config.collect_aim = false;
   ```

3. Reduce custom metrics (keep only 3-5 most important)

### Performance Issues

1. Increase sample rate (sample less frequently):
   ```cpp
   config.sample_rate_ms = 2000; // Every 2 seconds
   ```

2. Ensure you're not recording in performance-critical paths

### No Data Being Transmitted

1. Verify CloudReporter is set:
   ```cpp
   collector.SetCloudReporter(reporter);
   ```

2. Check that collection is enabled:
   ```cpp
   config.enabled = true;
   ```

3. Wait for aggregation window to elapse, or manually flush:
   ```cpp
   collector.Flush();
   ```

## Security Considerations

### Server-Side Analysis

The collected metrics should be analyzed server-side to:
- Establish baseline patterns for legitimate players
- Detect statistical anomalies indicating cheating
- Correlate with other anti-cheat signals

### Baseline Establishment

Build player profiles over time:
```
Normal Player:
- Humanness Score: 0.6-0.9
- Aim Snap Count: 0-2 per minute
- Path Smoothness: 0.7-0.95

Potential Aimbot:
- Humanness Score: 0.1-0.3
- Aim Snap Count: 10-50 per minute
- Path Smoothness: 0.95-1.0
```

### Detection Strategy

Behavioral telemetry is most effective when:
1. Combined with other detection methods (signature-based, integrity checks)
2. Used to flag accounts for manual review
3. Analyzed in context of player skill level and game mode

## API Reference

### BehavioralCollector Class

```cpp
class BehavioralCollector {
public:
    // Initialization
    void Initialize(const BehavioralConfig& config);
    void Shutdown();
    void SetCloudReporter(CloudReporter* reporter);
    
    // Data recording
    void RecordInput(uint64_t timestamp_ms, uint32_t concurrent_inputs = 1);
    void RecordMovement(float velocity, float direction_change_rate);
    void RecordAim(float precision, float flick_speed, bool is_headshot = false);
    void RecordCustomMetric(const char* name, float value, const char* unit = nullptr);
    
    // Control
    void Flush();
    
    // Testing/Monitoring
    BehavioralData GetCurrentData() const;
    size_t GetLastTransmitSize() const;
};
```

## Support

For questions or issues:
1. Check the test file: `tests/SDK/test_behavioral_collector.cpp`
2. Review example integrations in this guide
3. Consult the main integration guide: `docs/INTEGRATION_GUIDE.md`
