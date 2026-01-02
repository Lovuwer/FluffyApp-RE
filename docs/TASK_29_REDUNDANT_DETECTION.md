# Task 29: Redundant Detection Architecture

**Status:** ✅ Implemented  
**Priority:** P2  
**Risk Addressed:** Single detection implementation is single point of failure  
**Attacker Capability Defended:** Targeted bypass of individual detection mechanisms

---

## Overview

The redundant detection architecture enables multiple independent implementations per detection category, providing defense in depth by requiring attackers to bypass multiple different approaches for the same detection category.

### Key Benefits

- **Defense in Depth:** Attackers must bypass multiple implementations using different techniques
- **No Single Point of Failure:** Redundant implementations provide fallback
- **Transparent to Game Integration:** No changes to public API or integration
- **Configurable Per Category:** Enable/disable redundancy per detection type
- **Performance Monitoring:** Track overhead and violations per implementation

---

## Architecture

### DetectionRegistry

The `DetectionRegistry` class manages multiple detection implementations per category:

```
┌──────────────────────────────────────────────────────────┐
│                    DetectionRegistry                      │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  AntiDebug Category:                                     │
│    ┌──────────────────────┐  ┌──────────────────────┐   │
│    │ Primary Implementation│  │Alternative Implementation│   │
│    │ - PEB checks         │  │ - Direct syscalls     │   │
│    │ - Timing anomalies   │  │ - Process environment │   │
│    │ - Hardware BPs       │  │ - Memory patterns     │   │
│    └──────────────────────┘  └──────────────────────┘   │
│           │                           │                   │
│           └───────────┬───────────────┘                   │
│                       ▼                                   │
│              Violation Aggregation                        │
│              & Deduplication                             │
│                       │                                   │
│                       ▼                                   │
│              Single Violation Report                      │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

### IDetectionImplementation Interface

All detection implementations must implement this interface:

```cpp
class IDetectionImplementation {
public:
    virtual DetectionType GetCategory() const = 0;
    virtual const char* GetImplementationId() const = 0;
    virtual const char* GetDescription() const = 0;
    
    virtual std::vector<ViolationEvent> QuickCheck() = 0;
    virtual std::vector<ViolationEvent> FullCheck() = 0;
    
    virtual void Initialize() {}
    virtual void Shutdown() {}
};
```

---

## Usage

### Configuration

Redundancy is **disabled by default** (opt-in) for performance reasons. To enable:

```cpp
// Enable Standard redundancy for AntiDebug (2 implementations)
Sentinel::SDK::SetRedundancy(
    static_cast<uint8_t>(Sentinel::SDK::DetectionType::AntiDebug),
    Sentinel::SDK::RedundancyLevel::Standard
);

// Get current redundancy level
auto level = Sentinel::SDK::GetRedundancy(
    static_cast<uint8_t>(Sentinel::SDK::DetectionType::AntiDebug)
);

// Get performance statistics
Sentinel::SDK::RedundancyStatistics stats;
if (Sentinel::SDK::GetRedundancyStatistics(
        static_cast<uint8_t>(Sentinel::SDK::DetectionType::AntiDebug),
        &stats)) {
    printf("Active implementations: %u\n", stats.active_implementations);
    printf("Duplicate violations filtered: %u\n", stats.duplicate_violations_filtered);
    printf("Average overhead: %.2f microseconds\n", stats.avg_overhead_us);
}
```

### Redundancy Levels

| Level | Implementations | Description |
|-------|----------------|-------------|
| `None` | 1 | Single implementation (default, legacy behavior) |
| `Standard` | 2 | Two implementations with different approaches |
| `High` | 3 | Three or more implementations |
| `Maximum` | All | All available implementations |

---

## Performance Impact

### Overhead Measurements

Redundancy overhead depends on the number of implementations:

| Configuration | Implementations | Overhead (microseconds) |
|--------------|----------------|------------------------|
| None (baseline) | 1 | 0 (baseline) |
| Standard | 2 | ~2-5 µs |
| High | 3 | ~5-10 µs |
| Maximum | All | Varies by category |

**Note:** These are preliminary measurements on Linux VMs. Actual performance may vary based on:
- Hardware specifications
- Operating system
- Detection category complexity
- Whether detections trigger violations

### Recommendations

- **Development/Testing:** Use `RedundancyLevel::None` for fastest iteration
- **Production (Low-Risk):** Use `RedundancyLevel::Standard` for critical detection categories only
- **Production (High-Risk):** Use `RedundancyLevel::High` for all detection categories

---

## Implemented Detection Categories

### AntiDebug (Proof of Concept)

**Primary Implementation:**
- PEB checks (BeingDebugged, NtGlobalFlag, heap flags)
- Debug port and debug object handles
- Hardware breakpoint detection
- Timing anomaly detection
- SEH integrity checks

**Alternative Implementation:**
- Direct syscall verification (bypassing API hooks)
- Process environment inspection
- Thread context analysis
- Memory access pattern detection

Both implementations use different approaches, requiring separate bypasses from attackers.

---

## Violation Aggregation

The registry automatically:

1. **Executes all active implementations** based on redundancy configuration
2. **Collects violations** from each implementation
3. **Deduplicates similar violations** using:
   - Violation type matching
   - Timestamp proximity (within 100ms)
   - Address or module name matching
4. **Returns single aggregated report** to SDK

### Deduplication Rules

Violations are considered duplicates if they have:
- Same `ViolationType`
- Similar timestamp (within 100ms window)
- Same address (if non-zero) OR same module name

---

## Adding New Redundant Implementations

To add redundancy for other detection categories:

### 1. Create Implementation Class

```cpp
class MyDetectorImpl : public IDetectionImplementation {
public:
    DetectionType GetCategory() const override {
        return DetectionType::MyCategory;
    }
    
    const char* GetImplementationId() const override {
        return "my_detector_primary";
    }
    
    const char* GetDescription() const override {
        return "Description of detection approach";
    }
    
    std::vector<ViolationEvent> QuickCheck() override {
        // Implement lightweight check
    }
    
    std::vector<ViolationEvent> FullCheck() override {
        // Implement comprehensive check
    }
};
```

### 2. Register in SDK Initialization

In `SentinelSDK.cpp`, add during initialization:

```cpp
// Register primary implementation
auto primary = std::make_unique<MyDetectorImpl>();
g_context->detection_registry->RegisterImplementation(std::move(primary));

// Register alternative implementation
auto alt = std::make_unique<MyDetectorAltImpl>();
g_context->detection_registry->RegisterImplementation(std::move(alt));

// Configure redundancy (disabled by default)
RedundancyConfig config(DetectionType::MyCategory, RedundancyLevel::Standard, false);
g_context->detection_registry->SetRedundancyConfig(config);
```

---

## Statistics and Monitoring

### Available Metrics

The `RedundancyStatistics` structure provides:

```cpp
struct RedundancyStatistics {
    uint32_t active_implementations;        // Number of implementations currently active
    uint32_t total_checks_performed;        // Total checks executed
    uint32_t unique_violations_detected;    // Unique violations found
    uint32_t duplicate_violations_filtered; // Duplicates removed
    float avg_overhead_us;                  // Average overhead per check
    float max_overhead_us;                  // Maximum overhead observed
};
```

### Use Cases

- **Performance monitoring:** Track overhead per category
- **Effectiveness analysis:** Compare violation detection rates
- **Debugging:** Identify misconfigured or failing implementations

---

## Security Considerations

### Attack Surface Analysis

**Strengths:**
- Multiple bypasses required (increases attacker cost)
- Different implementation approaches prevent single technique bypass
- Transparent to attackers (no external indicator of redundancy)

**Limitations:**
- All implementations run in same process (shared memory space)
- Cannot defend against kernel-mode attacks
- Performance overhead may limit redundancy level in production

### Bypass Cost Increase

With redundant detection:

| Attack Scenario | Single Implementation | Redundant (Standard) | Redundant (High) |
|----------------|----------------------|---------------------|------------------|
| Bypass time | 1x | 2-3x | 3-5x |
| Required knowledge | One approach | Multiple approaches | All approaches |
| Failure impact | Complete bypass | Partial detection | Still detected |

---

## Testing

Comprehensive test suite validates:
- Multiple implementation registration
- Redundancy level configuration
- Violation aggregation and deduplication
- Statistics tracking
- Performance overhead measurement

Run tests:
```bash
cd build
./bin/SDKTests --gtest_filter="RedundantDetectionTest.*"
```

All 8 tests pass successfully.

---

## Future Enhancements

### Phase 6 (Future)

- **Additional Categories:**  Add redundancy for AntiHook, MemoryIntegrity, InjectionDetect
- **Dynamic Selection:** Choose implementations based on environment
- **Machine Learning:** Correlation between implementations for higher confidence
- **Remote Configuration:** Enable/disable redundancy via server directives

---

## Definition of Done

- [x] At least one detection category has redundant implementations (AntiDebug)
- [x] Aggregation produces single violation report from multiple triggers
- [x] Performance overhead documented per redundancy level
- [x] Configuration allows enabling or disabling redundancy per category
- [x] No change to game integration interface
- [x] Comprehensive test coverage (8 tests, all passing)

---

## References

- Source Code: `src/SDK/src/Internal/DetectionRegistry.*`
- Implementations: `src/SDK/src/Internal/RedundantAntiDebug.*`
- Tests: `tests/SDK/test_redundant_detection.cpp`
- API: `src/SDK/include/SentinelSDK.hpp` (SetRedundancy, GetRedundancy, GetRedundancyStatistics)
