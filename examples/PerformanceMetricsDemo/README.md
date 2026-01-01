# Performance Metrics Demo

This example demonstrates the Sentinel SDK's comprehensive performance telemetry system, showing real-time collection and visualization of performance metrics.

## What This Demo Shows

- **Real-time Metric Collection**: Automatic tracking of P50/P95/P99 latencies for all SDK operations
- **Performance Alerts**: Detection and reporting of threshold breaches
- **Self-Throttling**: Automatic operation skipping when performance degrades
- **Dashboard Visualization**: Live ASCII-art dashboard showing current performance status

## Building

From the build directory:

```bash
cmake --build . --target PerformanceMetricsDemo
```

## Running

```bash
./bin/PerformanceMetricsDemo
```

The demo will:
1. Initialize the Sentinel SDK
2. Simulate a game loop with 500 iterations
3. Display a live updating dashboard showing performance metrics
4. Inject periodic performance spikes to demonstrate throttling
5. Show real-time alerts when thresholds are exceeded

## Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│                Sentinel SDK Performance Dashboard                        │
├─────────────────────────────────────────────────────────────────────────┤
│ Overall Health: ✓ HEALTHY              Last Update: 14:23:45            │
├─────────────────────────────────────────────────────────────────────────┤
│ Operation         P50      P95      P99     Calls   Throttled           │
├─────────────────────────────────────────────────────────────────────────┤
│ Update          0.8ms    2.1ms    3.4ms      145K       0%              │
│ FullScan        12ms     24ms     32ms        243       0%              │
│ VerifyMemory    0.5ms    1.8ms    2.9ms      8.4K       0%              │
├─────────────────────────────────────────────────────────────────────────┤
│ Performance Alerts (Recent)                                             │
├─────────────────────────────────────────────────────────────────────────┤
│ ✓ No alerts in the current window                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Features Demonstrated

### 1. Percentile Tracking
The dashboard shows P50 (median), P95, and P99 latencies with color coding:
- **Green**: Below threshold (healthy)
- **Yellow**: Approaching threshold (warning)
- **Red**: Exceeds threshold (critical)

### 2. Performance Alerts
When operations exceed configured thresholds, alerts are displayed:
- ⚠️ P95 alerts for sustained performance issues
- 🔴 P99 alerts for critical performance spikes

### 3. Self-Throttling
When P95 latency exceeds 5ms:
- Operations are automatically throttled
- Throttle percentage is shown in the dashboard
- Performance recovers when latency drops below 80% of threshold

### 4. Real-Time Updates
The dashboard refreshes every second, showing:
- Current operation counts
- Latest percentile statistics
- Active throttling status
- Recent performance alerts

## Performance SLA

The SDK maintains these targets (configurable):
- **P95 Latency**: < 5ms (warning threshold)
- **P99 Latency**: < 10ms (critical threshold)
- **Update() Calls**: < 0.01ms average target

## Integration Notes

In a production game, you would:

1. **Query metrics periodically**:
```cpp
auto metrics = GetPerformanceMetrics(OperationType::Update);
LogPerformance(metrics.current_window.p95_ms);
```

2. **Monitor alerts**:
```cpp
auto alerts = GetPerformanceAlerts();
for (const auto& alert : alerts) {
    ReportToMonitoring(alert);
}
```

3. **Adjust configuration**:
```cpp
PerfTelemetryConfig config;
config.p95_threshold_ms = 5.0;
config.enable_self_throttling = true;
```

## See Also

- `/docs/PERFORMANCE_TELEMETRY.md` - Complete performance telemetry documentation
- `/src/SDK/src/Internal/PerfTelemetry.hpp` - Performance telemetry API
- `/tests/SDK/test_perf_telemetry.cpp` - Comprehensive test suite
