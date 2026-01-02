# Operator Dashboard Telemetry Specification

**Document Version:** 1.0  
**Task:** Task 32 - Operator Dashboard Telemetry  
**Date:** 2026-01-02  
**Classification:** Implementation Specification  
**Priority:** P1

---

## Executive Summary

This document specifies the Operator Dashboard system that provides studios with visibility into Sentinel SDK effectiveness. The dashboard converts invisible protection into visible metrics, demonstrating value and justifying continued investment in anti-cheat infrastructure.

### Risk Addressed

**Studios cannot observe SDK effectiveness**

Without dashboards showing detection events, client health, performance impact, and enforcement actions, studios cannot evaluate whether Sentinel is worth its cost. Invisible value is undervalued and eventually removed.

### Solution Strategy

The Operator Dashboard provides real-time visibility into:
- **Detection Events**: What threats are being caught and how frequently
- **Client Health**: Percentage of clients operating normally vs. flagged
- **Performance Impact**: SDK overhead on game performance (P50/P95/P99 latencies)
- **Enforcement Actions**: Server-side actions taken based on detections
- **Behavioral Patterns**: Aggregated player behavior metrics for anomaly detection

Dashboard updates within 5 minutes of telemetry receipt, providing near-real-time operational visibility.

---

## Table of Contents

1. [Dashboard Requirements](#dashboard-requirements)
2. [Key Metrics Specification](#key-metrics-specification)
3. [Dashboard UI Specification](#dashboard-ui-specification)
4. [Data Aggregation Requirements](#data-aggregation-requirements)
5. [Update Latency Requirements](#update-latency-requirements)
6. [Web Interface Requirements](#web-interface-requirements)
7. [Multi-Studio Access Control](#multi-studio-access-control)
8. [Data Retention Policy](#data-retention-policy)
9. [Server-Side Architecture](#server-side-architecture)
10. [Implementation Checklist](#implementation-checklist)

---

## Dashboard Requirements

### Functional Requirements

| Requirement ID | Description | Priority | Status |
|----------------|-------------|----------|--------|
| DR-001 | Display detection events by category with counts | P0 | Specified |
| DR-002 | Show client health percentage (healthy/flagged/banned) | P0 | Specified |
| DR-003 | Display performance percentiles (P50/P95/P99) by operation | P0 | Specified |
| DR-004 | Show enforcement latency (detection → action time) | P0 | Specified |
| DR-005 | Support time range selection (1h, 24h, 7d, 30d, custom) | P1 | Specified |
| DR-006 | Provide drill-down capability for detailed events | P1 | Specified |
| DR-007 | Display behavioral anomaly trends over time | P1 | Specified |
| DR-008 | Show geographic distribution of clients | P2 | Specified |
| DR-009 | Export data to CSV/JSON for external analysis | P2 | Specified |
| DR-010 | Real-time alerting for critical threshold breaches | P1 | Specified |

### Non-Functional Requirements

| Requirement ID | Description | Target | Status |
|----------------|-------------|--------|--------|
| NFR-001 | Dashboard update latency | < 5 minutes | Specified |
| NFR-002 | Page load time (dashboard home) | < 2 seconds | Specified |
| NFR-003 | Query response time (metric retrieval) | < 500ms | Specified |
| NFR-004 | Support concurrent studio users | 100+ simultaneous | Specified |
| NFR-005 | Data freshness indicator | Visible timestamp | Specified |
| NFR-006 | Mobile responsive design | Yes | Specified |
| NFR-007 | Browser compatibility | Chrome/Firefox/Edge/Safari | Specified |

---

## Key Metrics Specification

### 1. Detection Events by Category

**Metric Name:** `detection_count_by_category`  
**Type:** Counter (time-series)  
**Aggregation:** Sum per category per time window  
**Dimensions:** detection_type, severity, time_bucket

**Detection Categories:**
- **Anti-Debug**: Debugger presence detections
- **Anti-Hook**: API hooking detections (inline, IAT, VEH)
- **Integrity**: Code/memory modification detections
- **Injection**: DLL injection and manual mapping detections
- **Speed Hack**: Time manipulation detections
- **Aimbot**: Aim assistance detections (behavioral)
- **Wallhack**: ESP/Wallhack detections (behavioral)
- **Memory Read**: Unauthorized memory read detections
- **Custom**: Game-specific custom detections

**Severity Levels:**
- **Critical**: Confirmed cheat with high confidence
- **High**: Suspicious behavior, likely cheat
- **Medium**: Anomalous behavior, may be legitimate edge case
- **Low**: Informational, baseline behavior

**Example SQL Query:**
```sql
SELECT 
    detection_type,
    severity,
    COUNT(*) as detection_count,
    DATE_TRUNC('hour', timestamp) as time_bucket
FROM detection_events
WHERE 
    studio_id = ? 
    AND timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY detection_type, severity, time_bucket
ORDER BY time_bucket DESC, detection_count DESC;
```

**Dashboard Display:**
- Stacked bar chart showing detection counts by category over time
- Color-coded by severity (Critical=Red, High=Orange, Medium=Yellow, Low=Blue)
- Hoverable tooltips with exact counts and timestamps
- Filter by severity and detection type

---

### 2. Client Health Percentage

**Metric Name:** `client_health_distribution`  
**Type:** Gauge (snapshot)  
**Aggregation:** Percentage distribution per health state  
**Dimensions:** health_state, time_bucket

**Health States:**
- **Healthy**: No detections, passing all integrity checks
- **Suspicious**: 1-2 low-severity detections, under monitoring
- **Flagged**: Multiple detections or high-severity detection, requires review
- **Enforced**: Kicked, temporary ban, or permanent ban applied
- **Offline**: Client not reporting (timeout or legitimate disconnect)

**Calculation Logic:**
```pseudocode
total_active_sessions := COUNT(sessions WHERE last_heartbeat > NOW() - 5 minutes)

healthy_count := COUNT(sessions WHERE 
    detection_count = 0 
    AND anomaly_score < 10 
    AND status = 'active')

suspicious_count := COUNT(sessions WHERE 
    (detection_count BETWEEN 1 AND 2) 
    AND severity IN ('low', 'medium') 
    AND status = 'active')

flagged_count := COUNT(sessions WHERE 
    (detection_count >= 3 OR severity IN ('high', 'critical')) 
    AND status = 'flagged')

enforced_count := COUNT(sessions WHERE 
    status IN ('kicked', 'banned', 'temp_banned'))

healthy_pct := (healthy_count / total_active_sessions) * 100
```

**Dashboard Display:**
- Donut chart showing percentage distribution
- Color-coded segments (Healthy=Green, Suspicious=Yellow, Flagged=Orange, Enforced=Red, Offline=Gray)
- Center displays total active sessions count
- Clickable segments to drill down into session list

---

### 3. Performance Percentiles by Operation

**Metric Name:** `performance_latency_percentiles`  
**Type:** Histogram (time-series)  
**Aggregation:** P50, P95, P99 per operation type per time window  
**Dimensions:** operation_type, percentile, time_bucket

**Operation Types:**
- Initialize
- Update (per-frame)
- FullScan
- ProtectMemory
- ProtectFunction
- VerifyMemory
- EncryptPacket
- DecryptPacket

**Percentiles Tracked:**
- **P50 (Median)**: Typical performance
- **P95**: Performance under normal load (SLA target: < 5ms)
- **P99**: Worst-case performance excluding outliers (SLA target: < 10ms)

**Example SQL Query:**
```sql
SELECT 
    operation_type,
    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms) as p50_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) as p95_ms,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms) as p99_ms,
    COUNT(*) as sample_count,
    DATE_TRUNC('hour', timestamp) as time_bucket
FROM performance_samples
WHERE 
    studio_id = ?
    AND timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY operation_type, time_bucket
ORDER BY time_bucket DESC, operation_type;
```

**Dashboard Display:**
- Line chart with 3 lines per operation (P50, P95, P99)
- Horizontal red line at 5ms (P95 SLA threshold)
- Horizontal orange line at 10ms (P99 SLA threshold)
- Alert badge if any operation exceeds SLA
- Dropdown to select specific operation type
- Table view showing current values with SLA compliance status

---

### 4. Enforcement Latency

**Metric Name:** `enforcement_latency_metrics`  
**Type:** Histogram (time-series)  
**Aggregation:** Average, P50, P95, P99 per enforcement action  
**Dimensions:** enforcement_type, latency_component, time_bucket

**Enforcement Latency Components:**
1. **Detection → Report**: Time from SDK detection to report transmission
2. **Report → Server**: Network transmission time
3. **Server → Decision**: Server processing and decision time
4. **Decision → Action**: Time to execute enforcement action (kick/ban)
5. **End-to-End**: Total time from detection to enforcement

**Enforcement Types:**
- Kick
- Temporary Ban
- Permanent Ban
- Account Flag
- Manual Review

**Target Latencies:**
- Detection → Report: < 30 seconds (batching interval)
- Report → Server: < 5 seconds (network)
- Server → Decision: < 2 seconds (processing)
- Decision → Action: < 10 seconds (execution)
- **End-to-End Target: < 60 seconds**

**Dashboard Display:**
- Waterfall chart showing latency components for each enforcement action
- Color-coded bars for each component
- P95 latency displayed prominently
- Alert if P95 exceeds 60-second target
- Detailed table with breakdown by enforcement type

---

### 5. Behavioral Anomaly Trends

**Metric Name:** `behavioral_anomaly_metrics`  
**Type:** Time-series gauge  
**Aggregation:** Average scores and counts per time window  
**Dimensions:** anomaly_type, severity, time_bucket

**Anomaly Types:**
- **Aimbot Indicators**: High snap count, unrealistic tracking smoothness
- **Speed Hack Indicators**: Excessive velocity, teleport detection
- **Automation Indicators**: Inhuman APM, low input variance
- **Wallhack Indicators**: Prefire rate, tracking through walls

**Metrics per Anomaly Type:**
- Count of sessions flagged
- Average anomaly score
- Maximum anomaly score
- Trend direction (increasing/decreasing)

**Dashboard Display:**
- Multi-line chart showing flagged session counts by anomaly type over time
- Heatmap showing anomaly intensity by time and type
- Top offenders list with session IDs and scores
- Export capability for detailed investigation

---

## Dashboard UI Specification

### Dashboard Home Page Mockup

```
┌────────────────────────────────────────────────────────────────────────────┐
│  Sentinel Operator Dashboard                                [Studio: ACME] │
│  ────────────────────────────────────────────────────────────────────────  │
│                                                                             │
│  ⚡ Overall Health: HEALTHY      Last Update: 2026-01-02 14:45:00 UTC     │
│                                                                             │
│  ┌─────────────────────────────┐  ┌─────────────────────────────────────┐ │
│  │ Client Health Distribution  │  │  Detection Events (Last 24h)        │ │
│  ├─────────────────────────────┤  ├─────────────────────────────────────┤ │
│  │                             │  │                                     │ │
│  │     [DONUT CHART]           │  │  [STACKED BAR CHART]                │ │
│  │                             │  │                                     │ │
│  │  ✓ Healthy:      89.2%      │  │  Anti-Debug:    ███████  245       │ │
│  │  ⚠ Suspicious:    8.1%      │  │  Anti-Hook:     ████  128           │ │
│  │  🚩 Flagged:       2.3%      │  │  Integrity:     ██  67              │ │
│  │  ⛔ Enforced:      0.4%      │  │  Injection:     █████  189          │ │
│  │                             │  │  Aimbot:        ███  98              │ │
│  │  Total Sessions: 12,458     │  │  Speed Hack:    ██  56              │ │
│  └─────────────────────────────┘  │  Custom:        █  23               │ │
│                                   └─────────────────────────────────────┘ │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │ Performance Metrics (P95 Latency)                                   │  │
│  ├─────────────────────────────────────────────────────────────────────┤  │
│  │ Operation       │  P50   │  P95  │  P99  │ Samples │  SLA Status  │  │
│  ├─────────────────────────────────────────────────────────────────────┤  │
│  │ Update          │ 0.8ms  │ 2.1ms │ 3.4ms │  145K   │  ✅ PASS     │  │
│  │ FullScan        │ 15ms   │ 32ms  │ 48ms  │  1.2K   │  ✅ PASS     │  │
│  │ ProtectMemory   │ 0.5ms  │ 1.8ms │ 2.9ms │  8.4K   │  ✅ PASS     │  │
│  │ VerifyMemory    │ 0.9ms  │ 2.7ms │ 4.1ms │  24K    │  ✅ PASS     │  │
│  │ EncryptPacket   │ 0.3ms  │ 1.2ms │ 2.1ms │  56K    │  ✅ PASS     │  │
│  │ DecryptPacket   │ 0.4ms  │ 1.3ms │ 2.2ms │  54K    │  ✅ PASS     │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌─────────────────────────────┐  ┌─────────────────────────────────────┐ │
│  │ Enforcement Latency         │  │  Behavioral Anomalies (7 days)      │ │
│  ├─────────────────────────────┤  ├─────────────────────────────────────┤ │
│  │                             │  │                                     │ │
│  │  [WATERFALL CHART]          │  │  [LINE CHART]                       │ │
│  │                             │  │                                     │ │
│  │  Avg E2E: 42.3 seconds      │  │  Aimbot:     ▄▅▆██▇▅▄  (trending ↑)│ │
│  │  P95 E2E: 58.7 seconds ✅   │  │  Speed:      ▂▃▃▃▂▂▂  (stable)     │ │
│  │  P99 E2E: 72.1 seconds ⚠️    │  │  Automation: ▁▁▂▂▁▁▁  (low)        │ │
│  │                             │  │  Wallhack:   ▃▄▅▅▄▃▃  (stable)     │ │
│  │  Components:                │  │                                     │ │
│  │  - Detection: 25.2s         │  │  [View Details] [Export Data]       │ │
│  │  - Network:    4.1s         │  │                                     │ │
│  │  - Decision:   1.8s         │  │                                     │ │
│  │  - Action:     11.2s        │  │                                     │ │
│  └─────────────────────────────┘  └─────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Recent Alerts                                                         │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │ ⚠️  2026-01-02 14:23 - Aimbot detection spike: 45 events in 5 minutes │ │
│  │ ⚠️  2026-01-02 13:47 - P99 latency breach: FullScan 52ms (SLA: 50ms)  │ │
│  │ ✅  2026-01-02 12:15 - P95 latency recovered: Update 2.1ms            │ │
│  │ 📊  2026-01-02 11:30 - Daily report generated: 806 detections         │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  [⏱️ Last Hour] [📅 Last 24 Hours] [📆 Last 7 Days] [📊 Custom Range]     │
│  [📥 Export Dashboard] [⚙️ Configure Alerts] [📖 Documentation]            │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Dashboard Pages Structure

1. **Home** (Overview dashboard as shown above)
2. **Detections** (Detailed detection event browser)
3. **Performance** (Deep-dive performance analysis)
4. **Enforcement** (Enforcement actions and decisions)
5. **Behavioral** (Behavioral telemetry analysis)
6. **Clients** (Individual client/session viewer)
7. **Alerts** (Alert configuration and history)
8. **Reports** (Scheduled reports and exports)
9. **Settings** (Dashboard configuration)

---

## Data Aggregation Requirements

### Real-Time Aggregation Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    REAL-TIME AGGREGATION PIPELINE                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Raw Telemetry → Ingestion → Stream Processing → Aggregation → Cache   │
│       |              |              |                 |           |      │
│    HTTP POST     Validation    Flink/Spark       Time-Series  Redis     │
│                                 Streaming         Database               │
│                                                                          │
│  Aggregation Windows:                                                   │
│  - 1 minute:  Real-time metrics                                         │
│  - 5 minutes: Dashboard refresh                                         │
│  - 1 hour:    Historical trends                                         │
│  - 1 day:     Long-term analysis                                        │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Aggregation Strategy

**1-Minute Window (Real-Time):**
- Detection event counts by category
- Active session count and health distribution
- Performance percentiles (rolling window)
- Enforcement action counts

**5-Minute Window (Dashboard Refresh):**
- All 1-minute metrics aggregated
- Behavioral anomaly scores computed
- Alert threshold checks
- Dashboard cache update trigger

**1-Hour Window (Historical):**
- All metrics rolled up for storage efficiency
- Trend calculations (moving averages, derivatives)
- Correlation analysis between metrics
- Report generation triggers

**1-Day Window (Long-Term):**
- Daily summary statistics
- Retention policy enforcement
- Historical comparison baselines
- Capacity planning metrics

### Telemetry Schema Support for Dashboard

The existing telemetry schemas already support dashboard population:

**From PERFORMANCE_TELEMETRY.md:**
- Performance samples include operation_type, latency_ms, timestamp
- Already tracked: P50, P95, P99 percentiles
- Self-throttling metrics available
- Performance alerts documented

**From behavioral_telemetry_schema.md:**
- Behavioral metrics include: input patterns, movement patterns, aim patterns
- Anomaly indicators: humanness_score, snap_count, teleport_count
- Custom metrics extensibility
- Privacy-conscious aggregated data

**From TELEMETRY_CORRELATION_PROTOCOL.md:**
- Sequence numbering for tracking report completeness
- Session health tracking
- Gap detection for missing reports
- Challenge-response for verification

---

## Update Latency Requirements

### Latency Budget Breakdown

**Total Budget: 5 minutes from telemetry receipt to dashboard visibility**

| Stage | Target Latency | Description |
|-------|----------------|-------------|
| Client Batching | 30 seconds | SDK batches telemetry before transmission |
| Network Transmission | 5 seconds | HTTP POST from client to server |
| Ingestion Processing | 10 seconds | Validation, parsing, database write |
| Stream Processing | 60 seconds | Real-time aggregation computation |
| Aggregation Storage | 15 seconds | Write aggregated metrics to TSDB |
| Cache Update | 30 seconds | Update Redis cache for dashboard |
| Dashboard Refresh | 60 seconds | Frontend polls for updates |
| **Total** | **210 seconds** | **3.5 minutes (meets < 5 min requirement)** |

### Latency Monitoring Schema

```sql
CREATE TABLE telemetry_latency_tracking (
    id BIGSERIAL PRIMARY KEY,
    studio_id UUID NOT NULL,
    telemetry_id UUID NOT NULL,
    client_timestamp TIMESTAMP NOT NULL,
    server_received_timestamp TIMESTAMP NOT NULL,
    ingestion_complete_timestamp TIMESTAMP,
    stream_processed_timestamp TIMESTAMP,
    aggregation_stored_timestamp TIMESTAMP,
    cache_updated_timestamp TIMESTAMP,
    end_to_end_latency_ms INT,
    INDEX idx_studio_timestamp (studio_id, client_timestamp)
);
```

**Alert Conditions:**
- End-to-end latency > 5 minutes for any metric
- Any stage latency exceeding 2x target
- Sustained high latency (> 3 minutes average over 15 minutes)

---

## Web Interface Requirements

### Technology Stack

**Frontend:**
- **Framework**: React 18+ with TypeScript
- **UI Library**: Material-UI (MUI) or Ant Design
- **Charts**: Recharts or Apache ECharts
- **State Management**: Redux Toolkit or Zustand
- **API Client**: Axios with auto-retry

**Backend API:**
- **Framework**: Node.js (Express) or Python (FastAPI)
- **Authentication**: JWT with refresh tokens
- **API Standard**: RESTful JSON API
- **WebSocket**: For real-time updates (optional enhancement)

### API Endpoints

**Authentication:**
```
POST /api/v1/auth/login
POST /api/v1/auth/logout
POST /api/v1/auth/refresh
```

**Dashboard Metrics:**
```
GET  /api/v1/dashboard/overview?studio_id={id}&time_range={range}
GET  /api/v1/dashboard/detections?studio_id={id}&time_range={range}&category={cat}
GET  /api/v1/dashboard/performance?studio_id={id}&time_range={range}&operation={op}
GET  /api/v1/dashboard/enforcement?studio_id={id}&time_range={range}
GET  /api/v1/dashboard/behavioral?studio_id={id}&time_range={range}
GET  /api/v1/dashboard/health?studio_id={id}
```

**Drill-Down:**
```
GET  /api/v1/sessions/{session_id}
GET  /api/v1/detections/{detection_id}
GET  /api/v1/enforcement/{enforcement_id}
```

**Export:**
```
GET  /api/v1/export/dashboard?studio_id={id}&format={csv|json}&time_range={range}
POST /api/v1/export/custom (with query parameters in body)
```

**Alerts:**
```
GET  /api/v1/alerts?studio_id={id}
POST /api/v1/alerts/configure
PUT  /api/v1/alerts/{alert_id}
DELETE /api/v1/alerts/{alert_id}
```

### Response Format

Standard JSON response format:

```json
{
  "status": "success",
  "data": {
    "metrics": {},
    "metadata": {
      "timestamp": "2026-01-02T14:45:00Z",
      "freshness_seconds": 45,
      "query_time_ms": 125,
      "cached": true
    }
  },
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 1234,
    "has_more": true
  }
}
```

### Frontend Auto-Refresh

Dashboard should auto-refresh metrics every 60 seconds to maintain near-real-time visibility.

---

## Multi-Studio Access Control

### Access Control Model

**Principle: Complete isolation between studios. A studio can only access its own data.**

### Studio Identification

Each studio is assigned a unique `studio_id` (UUID) upon registration.

### User Roles and Permissions

**Role Hierarchy:**

1. **Studio Admin**
   - Full access to studio's dashboard
   - Can invite/remove users
   - Can configure alerts
   - Can export data
   - Can view billing

2. **Studio Operator**
   - Read access to dashboard
   - Can view all metrics
   - Can drill down into details
   - Can export data
   - Cannot manage users or alerts

3. **Studio Viewer** (Read-Only)
   - Read access to dashboard overview only
   - Cannot drill down into individual sessions
   - Cannot export data
   - Cannot configure alerts

4. **Super Admin** (Sentinel Internal)
   - Access to all studios (for support)
   - System health monitoring
   - Cannot modify studio data
   - All actions audited

### Database Schema

```sql
CREATE TABLE studios (
    studio_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    studio_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    subscription_tier VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    contact_email VARCHAR(255),
    UNIQUE(studio_name)
);

CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE user_studio_roles (
    user_id UUID NOT NULL REFERENCES users(user_id),
    studio_id UUID NOT NULL REFERENCES studios(studio_id),
    role VARCHAR(50) NOT NULL,
    granted_at TIMESTAMP DEFAULT NOW(),
    granted_by UUID REFERENCES users(user_id),
    PRIMARY KEY (user_id, studio_id)
);
```

### Row-Level Security

All queries must include `studio_id` filter and validate user access. PostgreSQL Row-Level Security (RLS) policies ensure data isolation at the database level.

### Data Export Controls

- **Free Tier**: No export capability
- **Pro Tier**: CSV export for last 30 days only
- **Enterprise Tier**: Full export capability (CSV, JSON) for all retained data

### Audit Logging

All access to studio data is logged:

```sql
CREATE TABLE audit_log (
    log_id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    user_id UUID NOT NULL REFERENCES users(user_id),
    studio_id UUID NOT NULL REFERENCES studios(studio_id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    INDEX idx_studio_timestamp (studio_id, timestamp),
    INDEX idx_user_timestamp (user_id, timestamp)
);
```

---

## Data Retention Policy

### Retention Tiers

**Tier 1: Raw Telemetry (Hot Storage)**
- **Data Types**: Detection events, performance samples, behavioral telemetry
- **Retention**: 7 days
- **Storage**: PostgreSQL + TimescaleDB
- **Purpose**: Detailed investigation, drill-down analysis
- **Compression**: None (fast queries)

**Tier 2: Aggregated Metrics (Warm Storage)**
- **Data Types**: 5-minute aggregations, hourly summaries
- **Retention**: 90 days
- **Storage**: TimescaleDB with compression
- **Purpose**: Dashboard population, trend analysis
- **Compression**: 70-80% (columnar compression)

**Tier 3: Historical Summaries (Cold Storage)**
- **Data Types**: Daily summaries, weekly reports
- **Retention**: 2 years
- **Storage**: S3/Object Storage + Parquet
- **Purpose**: Long-term trends, compliance, audit
- **Compression**: 90%+ (Parquet columnar format)

**Tier 4: Permanent Archive (Optional)**
- **Data Types**: Critical violations, enforcement decisions
- **Retention**: Indefinite (compliance requirement)
- **Storage**: Glacier/Archive Storage
- **Purpose**: Legal compliance, dispute resolution
- **Compression**: Maximum

### Retention Schedule

```sql
-- Automated retention enforcement (run daily at 02:00 UTC)

-- Delete raw telemetry older than 7 days
DELETE FROM detection_events 
WHERE timestamp < NOW() - INTERVAL '7 days';

DELETE FROM performance_samples 
WHERE timestamp < NOW() - INTERVAL '7 days';

DELETE FROM behavioral_telemetry 
WHERE timestamp < NOW() - INTERVAL '7 days';

-- Delete aggregated metrics older than 90 days
DELETE FROM aggregated_metrics_5min 
WHERE time_bucket < NOW() - INTERVAL '90 days';

DELETE FROM aggregated_metrics_hourly 
WHERE time_bucket < NOW() - INTERVAL '90 days';

-- Delete daily summaries older than 2 years
DELETE FROM daily_summaries 
WHERE date < NOW() - INTERVAL '2 years';
```

### Storage Estimates

**Per Studio (10,000 active players):**
- Raw telemetry: ~500 MB/day × 7 days = 3.5 GB
- Aggregated metrics: ~50 MB/day × 90 days = 4.5 GB
- Historical summaries: ~5 MB/day × 730 days = 3.65 GB
- **Total per studio: ~11.65 GB**

**100 Studios:**
- Total storage: ~1.2 TB
- Monthly growth: ~15 GB per studio = 1.5 TB/month

### Data Retention Configuration

Studios can request extended retention (Enterprise tier only):

```yaml
studio_id: "550e8400-e29b-41d4-a716-446655440000"
retention_override:
  raw_telemetry_days: 30
  aggregated_metrics_days: 180
  historical_summaries_years: 5
  reason: "Regulatory compliance requirement"
  approved_by: "legal@studio.com"
  approved_at: "2026-01-01T00:00:00Z"
```

---

## Server-Side Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      OPERATOR DASHBOARD ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Clients (SDK) → API Gateway → Ingestion Service → Message Queue            │
│                                                                              │
│  Message Queue → [Stream Processor | Aggregation | Correlation | Archive]   │
│                                                                              │
│  Storage Layer: [PostgreSQL | TimescaleDB | Redis | S3]                     │
│                                                                              │
│  Dashboard API Service ← Storage Layer                                       │
│                                                                              │
│  Web Dashboard (React) ← Dashboard API Service                               │
│                                                                              │
│  Studio Operators → Web Dashboard                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Specifications

**1. API Gateway**
- Rate limiting: 1000 requests/minute per studio
- JWT validation
- TLS termination
- Load balancing
- DDoS protection

**2. Ingestion Service**
- Schema validation
- Authentication
- Enrichment (studio_id, timestamps)
- Message queue writes
- Async processing

**3. Message Queue**
- Topics: detection, performance, behavioral, enforcement
- Retention: 24 hours
- Partitioning by studio_id

**4. Stream Processor**
- Real-time windowed aggregations (1-min, 5-min)
- Anomaly detection
- Alert triggers
- Write to TimescaleDB and Redis

**5. Aggregation Service**
- Hourly and daily rollups
- Percentile calculations
- Baseline updates
- Materialized view refresh

**6. Dashboard API Service**
- REST API for queries
- Redis caching (1-minute TTL)
- Row-level security
- Export generation

**7. Storage Layer**
- **PostgreSQL**: Metadata (studios, users, sessions)
- **TimescaleDB**: Time-series metrics
- **Redis**: Cache layer
- **S3**: Archival storage

**8. Web Dashboard**
- React 18 + TypeScript + Material-UI
- Server-side rendering (SSR)
- Progressive Web App (PWA)
- Real-time updates

---

## Implementation Checklist

### Phase 1: Foundation (Weeks 1-2)

- [ ] **Database Schema Design**
  - [ ] Design tables for detection events, sessions, metrics
  - [ ] Set up TimescaleDB for time-series data
  - [ ] Create materialized views for aggregations
  - [ ] Implement row-level security policies

- [ ] **Ingestion Pipeline**
  - [ ] Set up message queue
  - [ ] Implement ingestion service
  - [ ] Set up stream processor
  - [ ] Configure retention policies

- [ ] **API Development**
  - [ ] Implement authentication
  - [ ] Create REST API endpoints
  - [ ] Implement access control
  - [ ] Set up Redis caching

### Phase 2: Dashboard UI (Weeks 3-4)

- [ ] **Frontend Development**
  - [ ] Set up React project
  - [ ] Implement authentication flow
  - [ ] Create dashboard home page
  - [ ] Implement detection events chart
  - [ ] Implement client health chart
  - [ ] Implement performance table
  - [ ] Implement enforcement chart
  - [ ] Implement behavioral chart
  - [ ] Add auto-refresh
  - [ ] Implement time range selector

- [ ] **Drill-Down Pages**
  - [ ] Detection event browser
  - [ ] Session viewer
  - [ ] Performance deep-dive
  - [ ] Enforcement history

### Phase 3: Advanced Features (Weeks 5-6)

- [ ] **Alerting System**
  - [ ] Alert configuration schema
  - [ ] Alert evaluation engine
  - [ ] Notification service
  - [ ] Alert configuration UI

- [ ] **Export Functionality**
  - [ ] CSV export
  - [ ] JSON export
  - [ ] Scheduled reports
  - [ ] Report viewer

- [ ] **Multi-Studio Support**
  - [ ] Studio registration
  - [ ] User invite system
  - [ ] Role management UI
  - [ ] Data isolation testing

### Phase 4: Testing and Optimization (Weeks 7-8)

- [ ] **Performance Testing**
  - [ ] Load test ingestion
  - [ ] Load test dashboard API
  - [ ] Optimize slow queries
  - [ ] Verify < 5 minute latency
  - [ ] Verify < 2 second page load

- [ ] **Security Testing**
  - [ ] Access control testing
  - [ ] Data isolation testing
  - [ ] Input sanitization
  - [ ] Rate limiting testing

- [ ] **User Acceptance Testing**
  - [ ] Pilot studio testing
  - [ ] UI/UX feedback
  - [ ] Metric accuracy
  - [ ] Alert system testing

### Phase 5: Documentation and Launch (Week 9)

- [ ] **Documentation**
  - [ ] Operator user guide
  - [ ] Video tutorials
  - [ ] API documentation
  - [ ] Troubleshooting guide

- [ ] **Launch**
  - [ ] Production deployment
  - [ ] Monitoring setup
  - [ ] Announce to studios
  - [ ] Onboarding support

---

## Success Metrics

### Technical Metrics

- ✅ **Update Latency**: < 5 minutes (P95)
- ✅ **Page Load Time**: < 2 seconds
- ✅ **Query Performance**: < 500ms
- ✅ **Uptime**: 99.9% availability
- ✅ **Data Accuracy**: 100% match
- ✅ **Scalability**: 1000+ studios, 10M+ players

### Business Metrics

- 📊 **Studio Retention**: 90%+ after launch
- 📊 **Dashboard Usage**: 80%+ weekly logins
- 📊 **Value Perception**: 4.5/5 rating
- 📊 **Support Tickets**: 50% reduction
- 📊 **Tier Conversion**: 40%+ free to paid

---

## Conclusion

The Operator Dashboard Telemetry system transforms Sentinel from an invisible protection layer into a visible, measurable asset. By providing studios with real-time visibility into detection events, client health, performance impact, and enforcement actions, the dashboard demonstrates concrete value and justifies continued investment.

**Key Features:**
- ✅ Real-time detection event tracking by category
- ✅ Client health distribution with percentage breakdowns
- ✅ Performance percentiles meeting SLA targets
- ✅ Enforcement latency tracking
- ✅ Behavioral anomaly trend analysis
- ✅ Multi-studio access control with complete data isolation
- ✅ < 5 minute update latency for all metrics
- ✅ Comprehensive data retention policy
- ✅ Web-based dashboard with auto-refresh and export

**Dependencies Satisfied:**
- ✅ Task 7: Heartbeat system provides session health tracking
- ✅ Task 26: Behavioral telemetry enables anomaly detection metrics

**Next Steps:**
1. Begin Phase 1 implementation (database + ingestion)
2. Set up development and staging environments
3. Recruit pilot studios for beta testing
4. Establish monitoring for dashboard infrastructure

---

**Document End**

*For questions or clarifications, contact the Sentinel development team.*

*Last Updated: 2026-01-02*
