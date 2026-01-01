# Performance Telemetry - Task 17

## Overview

The Sentinel SDK now includes comprehensive performance telemetry to provide visibility into SDK performance in production environments. This addresses the critical need to verify the 5ms P95 latency target and prevent performance-related rejections from game studios.

## Performance SLA

The SDK maintains the following performance targets:

- **P95 Latency**: < 5ms for all major operations
- **P99 Latency**: < 10ms for all major operations
- **Update() calls**: < 0.01ms average (target for per-frame operations)
- **FullScan() calls**: < 50ms P95 (less frequent, more thorough checks)

## Monitored Operations

The performance telemetry system tracks timing for all major SDK operations:

1. **Initialize** - SDK initialization (one-time)
2. **Update** - Per-frame lightweight checks
3. **FullScan** - Comprehensive integrity scan
4. **ProtectMemory** - Memory region registration
5. **ProtectFunction** - Function protection registration
6. **VerifyMemory** - Memory integrity verification
7. **EncryptPacket** - Network packet encryption
8. **DecryptPacket** - Network packet decryption

## Key Features

### 1. Percentile Tracking

The system calculates and reports:
- **P50 (Median)**: Typical performance
- **P95**: Performance under normal load (SLA target)
- **P99**: Worst-case performance excluding outliers
- **Min/Max**: Range bounds
- **Mean**: Average latency

Statistics are calculated using accurate linear interpolation over sorted samples.

### 2. Self-Throttling

When P95 latency exceeds the 5ms threshold:
- The system automatically enables throttling for that operation
- Operations are probabilistically skipped (configurable, default 50%)
- Throttling remains active until P95 drops below 80% of threshold (hysteresis)
- Cooldown period prevents rapid state changes (default 5 seconds)

This ensures the SDK never causes sustained frame time budget violations.

### 3. Performance Alerts

The system generates alerts when thresholds are breached:
- **P95 Alert**: Warning when P95 > 5ms
- **P99 Alert**: Critical alert when P99 > 10ms

Alerts include:
- Operation type and name
- Measured latency value
- Threshold that was exceeded
- Timestamp of detection

### 4. Aggregation and Windows

Performance data is aggregated in configurable windows:
- **Window Size**: 1000 samples per measurement window (default)
- **Max Samples**: 10,000 samples retained for percentile calculation
- **Report Interval**: 60 seconds between automatic recalculations

Both current window and lifetime statistics are maintained.

## Integration Example

The SDK automatically instruments all major operations. No game developer action is required:

```cpp
// SDK automatically tracks timing
Sentinel::SDK::Initialize(&config);  // Timing recorded

for (;;) {
    Sentinel::SDK::Update();  // Timing recorded, auto-throttled if needed
    // Game frame...
}
```

## Dashboard Mockup

### Operator-Facing Performance View

```
┌─────────────────────────────────────────────────────────────────┐
│ Sentinel SDK Performance Dashboard                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│ Overall Health: ✓ HEALTHY          Last Update: 2026-01-01 08:45│
│                                                                   │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ Operation      │  P50  │  P95  │  P99  │ Calls │ Throttled│   │
│ ├───────────────────────────────────────────────────────────┤   │
│ │ Update         │ 0.8ms │ 2.1ms │ 3.4ms │  145K │    0%    │   │
│ │ FullScan       │ 12ms  │ 24ms  │ 32ms  │   243 │    0%    │   │
│ │ ProtectMemory  │ 0.3ms │ 1.2ms │ 2.1ms │  1.2K │    0%    │   │
│ │ VerifyMemory   │ 0.5ms │ 1.8ms │ 2.9ms │  8.4K │    0%    │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                   │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ Performance Alerts (Last 24h)                            │   │
│ ├───────────────────────────────────────────────────────────┤   │
│ │ ⚠️  2026-01-01 08:23 - Update P95 exceeded: 5.2ms        │   │
│ │     Throttling enabled, recovered after 12 seconds       │   │
│ │                                                            │   │
│ │ No critical P99 breaches in the last 24 hours            │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                   │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ Latency Distribution (Update operation, last hour)       │   │
│ ├───────────────────────────────────────────────────────────┤   │
│ │ 3.5ms+ │ █                                    (1%)        │   │
│ │ 3.0ms  │ ██                                   (2%)        │   │
│ │ 2.5ms  │ ████                                 (5%)        │   │
│ │ 2.0ms  │ ████████                             (12%)       │   │
│ │ 1.5ms  │ ████████████████                     (28%)       │   │
│ │ 1.0ms  │ ████████████████████                 (35%)       │   │
│ │ 0.5ms  │ ████████████                         (17%)       │   │
│ │ <0.5ms │                                      (0%)        │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                   │
│ [Export CSV] [Configure Alerts] [View Detailed Metrics]          │
└─────────────────────────────────────────────────────────────────┘
```

## Monitoring and Alerting

### Recommended Monitoring Setup

1. **Real-Time Metrics Collection**
   - Poll `PerformanceTelemetry::GetAllMetrics()` every 60 seconds
   - Store metrics in time-series database (e.g., Prometheus, InfluxDB)

2. **Alert Configuration**
   - **Warning**: P95 > 5ms for any operation
   - **Critical**: P99 > 10ms for Update/ProtectMemory
   - **Info**: Throttling enabled for any operation

3. **Dashboard Views**
   - Per-operation latency percentiles over time
   - Throttling frequency and duration
   - Alert history and resolution times
   - Distribution histograms for key operations

### Alert Response

When alerts fire:

1. **P95 Warning**
   - Review game load at alert time
   - Check if throttling activated successfully
   - Verify no correlation with other system issues

2. **P99 Critical**
   - Immediate investigation required
   - Check for environmental factors (VM, cloud gaming, overlay)
   - Review SDK version and configuration
   - Consider adjusting thresholds if consistently triggered in specific environments

3. **Sustained Throttling**
   - May indicate performance regression
   - Review recent SDK changes
   - Analyze operation frequency and necessity
   - Consider game-specific optimizations

## API Reference

### Configuration

```cpp
PerfTelemetryConfig config;
config.p95_threshold_ms = 5.0;         // P95 alert threshold
config.p99_threshold_ms = 10.0;        // P99 alert threshold
config.enable_self_throttling = true;  // Auto-throttle on breach
config.throttle_probability = 0.5;     // Skip 50% when throttling
config.window_size = 1000;             // Samples per window
```

### Retrieving Metrics

```cpp
// Get metrics for specific operation
PerformanceMetrics metrics = telemetry->GetMetrics(OperationType::Update);
std::cout << "P95: " << metrics.current_window.p95_ms << "ms\n";

// Get all operation metrics
std::vector<PerformanceMetrics> all = telemetry->GetAllMetrics();

// Get pending alerts
std::vector<PerformanceAlert> alerts = telemetry->GetAlerts();
```

### Telemetry Transmission

Performance metrics are automatically included in the SDK's regular telemetry reporting. The `TelemetryEmitter` class aggregates performance data along with detection events for transmission to the cloud backend.

## Testing

Comprehensive tests verify:
- ✅ Basic timing instrumentation
- ✅ Percentile calculation accuracy
- ✅ Self-throttling mechanism
- ✅ Performance data aggregation
- ✅ Threshold alerts
- ✅ Hysteresis behavior
- ✅ Concurrent recording
- ✅ Artificial delay demonstration

Run tests with:
```bash
cd build
ctest -R test_perf_telemetry -V
```

## Performance Impact

The telemetry system itself has minimal overhead:
- Recording operation: ~100ns (timestamp + array update)
- Percentile calculation: O(n log n) performed asynchronously every 60s
- Memory footprint: ~500KB for 10,000 samples across 8 operation types

## Future Enhancements

Potential improvements for future releases:
1. Histogram-based percentile approximation for lower memory usage
2. Per-game configuration profiles
3. Automatic performance regression detection
4. Integration with game engine profilers
5. Machine learning-based anomaly detection

## References

- Task 17 Implementation: `/src/SDK/src/Internal/PerfTelemetry.{hpp,cpp}`
- Test Suite: `/tests/SDK/test_perf_telemetry.cpp`
- Integration: `/src/SDK/src/SentinelSDK.cpp`
