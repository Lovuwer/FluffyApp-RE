# Sentinel Data Privacy and Retention Policy

**Version:** 1.0.0  
**Last Updated:** January 2026  
**Document Type:** Privacy Policy & Data Handling  
**Status:** Active  
**Effective Date:** January 1, 2026

---

## Policy Overview

Sentinel is committed to protecting the privacy and security of data collected through our anti-cheat platform. This document defines:

1. What data we collect
2. How we use the data
3. How long we retain the data
4. How we protect the data
5. Your rights and controls

---

## Scope

This policy applies to:
- **Sentinel SaaS Platform**: Cloud-hosted detection and analytics
- **Sentinel SDK**: Client-side detection library embedded in games
- **Sentinel Cortex Dashboard**: Operator dashboard for monitoring

This policy does NOT apply to:
- **Self-Hosted Deployments**: Customers control all data policies
- **Game-Specific Data**: Data collected by your game (outside Sentinel)

---

## Data Collection

### 1. Detection Telemetry

**What We Collect:**
- **Detection Events**: Timestamps, detection types (anti-debug, anti-hook, etc.), severity levels
- **Violation Details**: Which detection triggered, confidence scores, action taken
- **Session Context**: Session ID (anonymous), session duration, game version
- **System Information**: OS version, CPU architecture, memory size (not serial numbers)

**Purpose:**
- Identify cheating patterns
- Improve detection algorithms
- Provide analytics to game operators
- Generate threat intelligence

**Personal Information:** No. All data is anonymized. No player names, emails, or account information collected by Sentinel.

**Example Detection Event:**
```json
{
  "session_id": "a3f9c2e8-1234-5678-90ab-cdef12345678",
  "timestamp": "2026-01-02T16:00:00Z",
  "detection_type": "anti_debug",
  "severity": "high",
  "confidence": 0.95,
  "os": "Windows 11",
  "game_version": "1.2.3"
}
```

---

### 2. System Information

**What We Collect:**
- **Operating System**: Version, build number, architecture (x64, ARM)
- **Hardware Specs**: CPU model, core count, RAM size, GPU model
- **Game Context**: Game version, engine type, launch parameters
- **SDK Version**: Sentinel SDK version and build number

**Purpose:**
- Compatibility analysis
- Performance optimization
- Detection calibration per hardware profile
- Bug investigation

**Personal Information:** No. Hardware specs are NOT unique identifiers. We do NOT collect:
- ❌ Hardware serial numbers
- ❌ MAC addresses
- ❌ Windows product keys
- ❌ Disk serial numbers

---

### 3. Threat Intelligence

**What We Collect:**
- **Binary Hashes**: SHA-256 hashes of detected cheat tools
- **Process Names**: Names of suspicious processes (e.g., "CheatEngine.exe")
- **DLL Paths**: Paths of injected libraries (sanitized to remove username)
- **Signatures**: Byte patterns from detected cheats (for signature database)

**Purpose:**
- Build threat intelligence database
- Share cheat signatures across games
- Improve detection for all customers
- Community protection

**Personal Information:** No. Paths are sanitized to remove usernames.

**Example:**
- ❌ Original: `C:\Users\JohnDoe\Desktop\cheat.dll`
- ✅ Sanitized: `%USERPROFILE%\Desktop\cheat.dll`

---

### 4. Account and Licensing

**What We Collect:**
- **Company Name**: Your studio/company name
- **Contact Email**: Billing and support contact
- **License Key**: Your Sentinel license key
- **Usage Metrics**: Active user counts (for billing)

**Purpose:**
- Account management
- Billing and invoicing
- License validation
- Support ticket routing

**Personal Information:** Yes. Business contact information only (not end-user PII).

---

### 5. Analytics and Usage

**What We Collect:**
- **Dashboard Usage**: Which pages viewed, how often, by which operator
- **API Calls**: Endpoint accessed, timestamp, response time
- **Feature Usage**: Which Sentinel features enabled/disabled

**Purpose:**
- Product analytics
- Feature usage tracking
- Performance monitoring
- UX improvements

**Personal Information:** No. Operator accounts identified by role-based IDs.

---

## What We DO NOT Collect

Sentinel explicitly **does NOT** collect:

- ❌ **Player Personal Information**: No names, emails, addresses, phone numbers
- ❌ **Game Content**: No chat logs, game saves, player creations
- ❌ **Financial Information**: No credit cards, payment methods (handled by payment processor)
- ❌ **Unique Hardware IDs**: No HWID, MAC address, disk serial (unless explicitly enabled by customer)
- ❌ **Biometric Data**: No fingerprints, facial recognition, voice data
- ❌ **Location Data**: No GPS, IP-based geolocation (IP addresses logged for security only)
- ❌ **Browsing History**: No web activity outside the game
- ❌ **Screenshots**: No screen captures or video recording

**If you need HWID banning:**
- You must collect HWID in your game (not Sentinel)
- Sentinel can hash and match HWIDs you provide
- You control HWID collection and storage

---

## Data Usage

### How We Use Collected Data

1. **Detection and Protection**
   - Real-time cheating detection
   - Pattern analysis across player base
   - Correlation of detection signals

2. **Analytics and Reporting**
   - Provide dashboard metrics to game operators
   - Generate threat intelligence reports
   - Track detection effectiveness

3. **Product Improvement**
   - Improve detection algorithms
   - Optimize performance
   - Debug issues reported by customers

4. **Threat Intelligence Sharing**
   - Build community threat database
   - Share anonymized cheat signatures across games
   - Contribute to public cheat mitigation efforts

5. **Compliance and Legal**
   - Respond to legal requests (rare, with customer notification)
   - Enforce terms of service
   - Investigate security incidents

---

### How We DO NOT Use Data

We will **NEVER**:
- ❌ Sell or rent your data to third parties
- ❌ Use data for advertising or marketing profiling
- ❌ Share data with game publishers without your consent
- ❌ Publicly disclose non-anonymized detection data
- ❌ Use data for purposes outside of anti-cheat functionality

---

## Data Retention

### Retention Periods

| Data Type | Default Retention | Configurable Range | Rationale |
|-----------|-------------------|-------------------|-----------|
| **Detection Events** | 30 days | 7-365 days | Short-term pattern analysis |
| **Threat Intelligence** | 1 year | Not configurable | Long-term cheat tracking |
| **Aggregate Analytics** | 2 years | Not configurable | Trend analysis |
| **Account Information** | Duration of subscription | N/A | Business relationship |
| **Audit Logs** (Enterprise) | 90 days | 30-730 days | Compliance requirements |

**After Retention Period:**
- Data is automatically purged (hard delete, not soft delete)
- No backups retained beyond retention period
- Aggregate statistics may be retained (fully anonymized)

---

### Configuring Retention

**Professional & Enterprise Customers:**
- Configure retention per data type in dashboard settings
- Minimum: 7 days (required for detection correlation)
- Maximum: 365 days (regulatory compliance)

**Example Configuration:**
```json
{
  "detection_events": 90,
  "session_data": 30,
  "threat_intelligence": 365
}
```

**Community Tier:**
- Fixed 30-day retention (not configurable)

---

### Data Deletion

**Automatic Deletion:**
- All data purged after retention period
- Scheduled daily purge job at 00:00 UTC
- Deletion is permanent and irreversible

**Manual Deletion:**
- Customers can request immediate deletion via support ticket
- Enterprise customers can delete via API
- Deletion completed within 48 hours

**Account Closure Deletion:**
- Upon account closure, all customer data deleted within 30 days
- Includes: detection events, session data, account info
- Excludes: anonymized threat intelligence (no longer tied to customer)

---

## Data Security

### Encryption

**In Transit:**
- TLS 1.3 for all API communications
- Certificate pinning (Enterprise tier)
- Forward secrecy enabled

**At Rest:**
- AES-256 encryption for all stored data
- Encrypted database volumes
- Encrypted backups

**Key Management:**
- Keys rotated every 90 days
- Hardware security modules (HSM) for key storage (Enterprise)
- Customer-managed encryption keys available (Enterprise)

---

### Access Controls

**Who Can Access Data:**

1. **Game Operators (You)**
   - Access your own detection events via dashboard or API
   - Role-based access control (RBAC)
   - Audit logging of all access (Enterprise)

2. **Sentinel Engineers**
   - Access only for support tickets and debugging
   - Requires customer approval (logged)
   - No access to raw data without consent

3. **Automated Systems**
   - Detection correlation algorithms (real-time)
   - Aggregate analytics generation (batch jobs)
   - Scheduled data purge (deletion jobs)

**Access Logging (Enterprise):**
- All data access logged with timestamp, user, action
- Logs retained for 1 year (configurable)
- Available for audit via dashboard

---

### Infrastructure Security

**Sentinel SaaS Platform:**
- Hosted on AWS (US-East-1 by default, EU/Asia available for Enterprise)
- SOC 2 Type II compliant infrastructure (certification available on request)
- Regular penetration testing (annual)
- Bug bounty program for security researchers

**Self-Hosted Deployments:**
- You control all infrastructure security
- We provide deployment guides and security recommendations
- You are responsible for compliance

---

## Privacy Compliance

### GDPR (General Data Protection Regulation)

**Applicability:** Applies to EU players

**Player Rights:**
1. **Right to Access**: Players can request data collected about them (via your game, not Sentinel directly)
2. **Right to Deletion**: Players can request deletion (you control player identity, we delete on your request)
3. **Right to Portability**: Data export available via API (JSON/CSV)
4. **Right to Object**: Players can opt-out of telemetry (your game must provide option)

**Sentinel Compliance:**
- ✅ Data minimization (only collect what's necessary)
- ✅ Purpose limitation (only use for anti-cheat)
- ✅ Storage limitation (automatic purge after retention period)
- ✅ Security (encryption, access controls)
- ✅ Data processing agreements available (Enterprise)

**EU Data Residency (Enterprise Only):**
- Host Sentinel Cloud in EU regions (Frankfurt, London)
- Data never leaves EU
- EU-based support engineers available

---

### CCPA (California Consumer Privacy Act)

**Applicability:** Applies to California residents

**Consumer Rights:**
1. **Right to Know**: What data is collected and how it's used
2. **Right to Delete**: Request deletion of data
3. **Right to Opt-Out**: Opt-out of data "sale" (we don't sell data)
4. **Non-Discrimination**: Same service regardless of privacy choices

**Sentinel Compliance:**
- ✅ Transparent data collection (this document)
- ✅ Deletion on request
- ✅ No data sales (never)
- ✅ Privacy policy easily accessible

---

### COPPA (Children's Online Privacy Protection Act)

**Applicability:** Games targeting children under 13 in the US

**Requirements:**
- Parental consent required before collecting data from children

**Sentinel Position:**
- Sentinel collects **no personal information** from players (including children)
- Detection telemetry is anonymous and not tied to player identity
- Games targeting children should conduct their own COPPA compliance review

**Recommendation:**
- If your game targets children under 13, consult legal counsel
- Ensure your game's privacy policy covers all data collection (including Sentinel)

---

### Other Regulations

**PIPEDA (Canada):**
- Sentinel complies with PIPEDA principles
- Data processing agreements available

**APPs (Australia):**
- Sentinel complies with Australian Privacy Principles
- Australian data residency available (Enterprise)

**LGPD (Brazil):**
- Sentinel complies with Brazilian data protection law
- Data processing agreements available

---

## Player Privacy Rights

### Data Subject Requests

**How Players Exercise Rights:**

Since Sentinel does **not** collect player personal information, players cannot contact Sentinel directly. Instead:

1. **Player contacts your game/studio** with privacy request
2. **You verify player identity** (your responsibility)
3. **You submit request to Sentinel** via support ticket with:
   - Session IDs to delete/export
   - Date range
   - Player identifier you use (we'll correlate to session IDs)
4. **Sentinel processes request** within 30 days
5. **You deliver result to player**

**Why this flow?**
- Sentinel doesn't know player identity (by design)
- You control player identity and authentication
- Prevents abuse (attackers requesting deletion of detection data)

---

### Data Export (Portability)

**Available To:** Professional and Enterprise customers

**Format:** JSON or CSV

**Contents:**
- All detection events for specified session IDs
- System information
- Timestamps and detection types
- No aggregate analytics (not specific to individual)

**How to Request:**
1. Via API: `GET /api/v1/data/export?session_id=...`
2. Via Dashboard: Settings > Data Export
3. Via Support Ticket: Bulk exports for multiple players

**Delivery:** Download link (expires in 7 days)

---

### Data Deletion

**Available To:** All customers

**Scope:**
- Specific session IDs
- Date range
- Entire account (upon account closure)

**How to Request:**
1. Via API: `DELETE /api/v1/data?session_id=...`
2. Via Dashboard: Settings > Delete Data
3. Via Support Ticket: Bulk deletions

**Timeline:** Completed within 48 hours

**Verification:** Deletion confirmation provided

**Note:** Threat intelligence signatures (anonymized) may be retained for community protection. These are no longer tied to your account or players.

---

## Third-Party Data Sharing

### When We Share Data

**Service Providers:**
- **Cloud Hosting (AWS)**: Infrastructure provider
- **Payment Processor (Stripe)**: Billing (business info only, no player data)
- **Email Service (SendGrid)**: Support communications

**Legal Requirements:**
- Court orders, subpoenas, legal process
- We'll notify you unless legally prohibited
- We'll challenge overbroad requests

**Threat Intelligence Community:**
- Anonymized cheat signatures shared with industry
- No customer or player identification
- Opt-out available (Enterprise)

---

### When We DO NOT Share Data

We will **NEVER** share data:
- ❌ With other game studios/publishers (without your explicit consent)
- ❌ For marketing or advertising purposes
- ❌ With data brokers or aggregators
- ❌ For purposes outside of anti-cheat functionality

---

## Your Control Over Data

### Self-Hosted Deployments

**Complete Control:**
- You host all infrastructure
- You control all data
- You define retention policies
- You handle compliance
- We provide software only

**Sentinel Has No Access:**
- No telemetry sent to Sentinel servers (unless you configure it)
- Signature updates via secure download (no data uploaded)
- Support requires you to provide logs (we don't have automatic access)

---

### Configuration Options

**All Tiers:**
- ✅ Enable/disable specific detection modules
- ✅ Configure detection sensitivity (reduce false positives)

**Professional & Enterprise:**
- ✅ Configure retention periods (7-365 days)
- ✅ Enable/disable telemetry upload (self-hosted)
- ✅ Configure data export schedules

**Enterprise:**
- ✅ Choose data residency region (US, EU, Asia)
- ✅ Enable/disable threat intelligence sharing
- ✅ Customer-managed encryption keys
- ✅ Private VPC deployment (no multi-tenant)

---

## Data Breach Notification

### Our Commitment

In the event of a data breach:

1. **Immediate Investigation**: Within 24 hours of discovery
2. **Customer Notification**: Within 72 hours of confirmation
3. **Remediation**: Immediate steps to contain and mitigate
4. **Post-Mortem**: Detailed incident report within 7 days
5. **Regulatory Notification**: As required by law

**What We'll Tell You:**
- What data was accessed
- How many records affected
- What we're doing about it
- What you should do

---

## Children's Privacy

Sentinel is designed to be **child-safe**:

- ✅ No personal information collected from players (any age)
- ✅ No player names, emails, or account data
- ✅ No location tracking
- ✅ No behavioral profiling

**For Games Targeting Children:**
- Review COPPA requirements with legal counsel
- Ensure your game's privacy policy covers all data collection
- Consider parent consent flows in your game
- Sentinel telemetry is anonymous and COPPA-compatible

---

## Contact Us

### Privacy Questions

**Email:** privacy@sentinel.example.com *(placeholder)*

**Response Time:**
- General questions: 3 business days
- Data subject requests: 30 days (legal requirement)
- Breach notifications: 72 hours

### Data Protection Officer (DPO)

**For GDPR Requests:**
- Email: dpo@sentinel.example.com *(placeholder)*
- Available for EU-based inquiries

---

## Policy Updates

### How We Update This Policy

- Policy reviewed annually (minimum)
- Updated as needed for regulatory changes
- Customers notified 30 days before changes take effect (email + dashboard notification)

### Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | Jan 2026 | Initial privacy policy |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | Jan 2026 | Initial data privacy and retention policy |

---

**Related Documents:**
- [COMMERCIAL_OFFERING.md](COMMERCIAL_OFFERING.md) - Commercial structure overview
- [PRICING_PACKAGING.md](PRICING_PACKAGING.md) - Pricing details
- [SUPPORT_TIERS.md](SUPPORT_TIERS.md) - Support level definitions
- [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) - Security requirements
