# Sentinel Commercial Offering

**Version:** 1.0.0  
**Last Updated:** January 2026  
**Document Type:** Commercial Structure  
**Status:** Active

---

## Executive Summary

Sentinel is a comprehensive game security platform delivered as a **SaaS + SDK** solution with flexible licensing options for studios of all sizes. Our commercial model is designed to align with your business needs while providing world-class anti-cheat protection and telemetry analytics.

### Quick Overview

- **Delivery Model**: SaaS platform + Client SDK
- **Pricing Model**: Per-active-user monthly subscription OR perpetual studio licensing
- **Support Tiers**: Community (Free), Professional, Enterprise
- **Platform Support**: Windows x64, Linux (partial)
- **Deployment Options**: Cloud-hosted or self-hosted infrastructure

---

## Product Offerings

### 1. Sentinel SaaS Platform

**Cloud-hosted detection and analytics platform**

The Sentinel SaaS platform provides:

- **Cloud Telemetry Processing**: Real-time behavioral analysis and detection correlation
- **Analytics Dashboard**: Operator dashboard (Sentinel Cortex GUI) for threat monitoring
- **Signature Updates**: Automated threat intelligence and detection signature updates
- **API Access**: RESTful API for integration with your game infrastructure
- **Data Storage**: Configurable retention periods for telemetry and incident data

**Included Components:**
- ✅ Sentinel Cloud backend infrastructure
- ✅ Operator dashboard (Cortex GUI) access
- ✅ Automated signature updates
- ✅ API access for server integration
- ✅ Basic analytics and reporting

**Pricing:** Per-active-user monthly subscription (see [PRICING_PACKAGING.md](PRICING_PACKAGING.md))

---

### 2. Sentinel SDK

**Client-side detection library for game integration**

The Sentinel SDK is a C++ library that embeds into your game client:

- **Detection Engine**: Anti-debug, anti-hook, integrity checks, injection detection
- **Telemetry Client**: Lightweight client that reports to Sentinel Cloud or your infrastructure
- **Simple Integration**: 8-line integration, minimal overhead (<1ms per frame)
- **Cross-Platform**: Windows x64 (primary), Linux (partial support)

**Included Components:**
- ✅ Compiled SDK libraries (.dll/.so + headers)
- ✅ Integration documentation and examples
- ✅ Basic configuration tools
- ✅ License key management

**Pricing:** Included with SaaS subscription OR perpetual studio licensing

---

### 3. Self-Hosted Options

**For studios requiring on-premises infrastructure**

Sentinel can be deployed entirely on your infrastructure:

- **Private Cloud Deployment**: Deploy Sentinel Cloud on your AWS/Azure/GCP
- **Air-Gapped Installations**: Isolated networks with manual signature updates
- **Full Control**: You own the infrastructure, data never leaves your network
- **Custom Integration**: White-label options available for Enterprise customers

**Requirements:**
- Dedicated infrastructure (specifications provided)
- DevOps team for deployment and maintenance
- Enterprise support contract

**Pricing:** Perpetual studio licensing with annual support subscription (see [PRICING_PACKAGING.md](PRICING_PACKAGING.md))

---

## Licensing Models

### Option 1: SaaS Subscription (Recommended)

**Pay monthly per active user**

- **Active User Definition**: A player who launches your game with Sentinel SDK in a billing period
- **No Upfront Costs**: Zero capital expenditure, operational expense only
- **Automatic Scaling**: Charges scale with your player base
- **Always Updated**: Automatic signature updates and platform improvements
- **Managed Infrastructure**: We handle hosting, scaling, and maintenance

**Ideal For:**
- Indie studios and small teams
- Games with unpredictable player counts
- Studios without dedicated DevOps resources
- Early-stage projects seeking minimal financial commitment

---

### Option 2: Studio Perpetual License

**One-time licensing fee with annual support**

- **Perpetual Usage Rights**: Own the SDK forever, no recurring user fees
- **Predictable Costs**: Fixed annual support cost regardless of player count
- **Self-Hosted Option**: Deploy entirely on your infrastructure
- **Enterprise Features**: Priority support, custom features, white-labeling

**License Terms:**
- One-time license fee (scales with studio size and revenue)
- Annual support and updates subscription (20% of license fee)
- Unlimited active users
- Self-hosted deployment rights
- Source code escrow available (Enterprise tier)

**Ideal For:**
- AAA studios with large player bases
- Studios with strict data sovereignty requirements
- Companies seeking capital expenditure vs. operational expenditure
- Games with predictable, large-scale deployment

---

## Base vs. Premium Features

### Base Offering (All Tiers)

Included in all commercial licenses:

- ✅ **Sentinel SDK**: Client-side detection library
  - Anti-debug detection (user-mode checks)
  - Anti-hook detection (inline + IAT)
  - Integrity checking (code section hashing)
  - Injection detection (DLL + manual mapping)
  - Speed hack detection (client-side)
- ✅ **Cloud Platform**: Basic telemetry processing and storage
  - Real-time detection ingestion
  - 30-day data retention (configurable)
  - Basic analytics dashboard
  - RESTful API access
- ✅ **Signature Updates**: Automated threat intelligence
  - Weekly signature updates
  - Community-sourced threat intelligence
- ✅ **Documentation**: Complete integration guides
- ✅ **Community Support**: GitHub issues, community forums

---

### Premium Add-Ons (Professional & Enterprise)

Additional features available with Professional and Enterprise tiers:

- ⭐ **Advanced Analytics**
  - Custom dashboards and reporting
  - Predictive threat modeling
  - Player behavior correlation
  - Export capabilities (CSV, JSON, API)
- ⭐ **Enhanced Detection**
  - Kernel-mode detection (Windows)
  - Hardware ID tracking and banning
  - Advanced obfuscation resistance
  - Custom detection rules
- ⭐ **Priority Signature Updates**
  - Daily signature updates
  - Zero-day threat intelligence
  - Custom threat research for your game
- ⭐ **Premium Support**
  - Dedicated support engineer
  - 4-hour critical response time
  - On-call escalation
  - Integration assistance
- ⭐ **Self-Hosted Deployment** (Enterprise Only)
  - Private cloud deployment
  - Air-gapped installations
  - White-label options
  - Source code escrow

See [PRICING_PACKAGING.md](PRICING_PACKAGING.md) for detailed tier comparison.

---

## Service Level Agreements (SLA)

### Uptime Commitments

**SaaS Platform Availability:**

| Tier | Uptime SLA | Downtime Budget | Credits |
|------|------------|-----------------|---------|
| Community | Best Effort | N/A | No |
| Professional | 99.5% | 3.65 hours/month | Yes |
| Enterprise | 99.9% | 43.8 minutes/month | Yes |

**Uptime measured:** Monthly, excluding scheduled maintenance windows (announced 7 days in advance)

**Service Credits:** 
- 10% monthly credit for each 0.1% below SLA threshold
- Maximum 100% monthly credit
- Must be claimed within 30 days of incident

---

### Support Response Times

See [SUPPORT_TIERS.md](SUPPORT_TIERS.md) for detailed support commitments.

**Quick Summary:**

| Issue Severity | Community | Professional | Enterprise |
|----------------|-----------|--------------|------------|
| Critical (P0) | Best Effort | 4 hours | 1 hour |
| High (P1) | Best Effort | 8 hours | 4 hours |
| Medium (P2) | Best Effort | 24 hours | 8 hours |
| Low (P3) | Best Effort | 3 days | 1 day |

**Critical Issues (P0):** Service outage, complete detection failure, security breach  
**High Issues (P1):** Major degradation, significant false positives  
**Medium Issues (P2):** Partial degradation, integration problems  
**Low Issues (P3):** Questions, documentation requests, feature requests

---

## Data Privacy and Retention

### Data Collection

Sentinel collects the following telemetry:

- **Detection Events**: Timestamps, detection types, severity levels
- **System Information**: OS version, hardware specs (no PII)
- **Game Session Data**: Session IDs, playtime, anonymous player IDs
- **Threat Intelligence**: Cheat signatures, binary hashes, process names

**We DO NOT collect:**
- Personal identifiable information (PII)
- Player names or email addresses
- Game-specific content or chat logs
- Financial information

---

### Data Retention

| Data Type | Retention Period | Configurable |
|-----------|------------------|--------------|
| Detection Events | 30 days (default) | Yes (7-365 days) |
| Threat Intelligence | 1 year | No |
| Aggregate Analytics | 2 years | No |
| Account Information | Duration of subscription | No |

**Self-Hosted:** You control all retention policies

**Data Deletion:** Automatic purge after retention period, manual deletion available on request

---

### Privacy Commitments

- ✅ **GDPR Compliant**: EU data residency options available (Enterprise)
- ✅ **CCPA Compliant**: California data privacy rights respected
- ✅ **Encryption**: TLS 1.3 in transit, AES-256 at rest
- ✅ **Access Control**: Role-based access control (RBAC) for operator dashboards
- ✅ **Audit Logging**: Complete audit trail of data access (Enterprise)
- ✅ **Data Portability**: Export your data at any time (JSON/CSV)

See [DATA_PRIVACY_POLICY.md](DATA_PRIVACY_POLICY.md) for complete privacy policy.

---

## Commercial Terms

### License Grant

**SaaS Subscription:** Revocable, non-exclusive, non-transferable license to use the Sentinel SDK and platform during the subscription term.

**Perpetual License:** Perpetual, non-exclusive, non-transferable license to use the Sentinel SDK version licensed. Updates and support require active support subscription.

---

### Usage Restrictions

You **MAY**:
- ✅ Embed the SDK in your commercial games
- ✅ Distribute the SDK as part of your game (no separate distribution)
- ✅ Use for internal development and testing

You **MAY NOT**:
- ❌ Reverse engineer, decompile, or disassemble the SDK
- ❌ Distribute the SDK as a standalone product
- ❌ Sublicense, rent, or lease the SDK to third parties
- ❌ Remove or modify licensing/copyright notices
- ❌ Use for competitive intelligence or to build competing products

---

### Warranty and Liability

**Limited Warranty:**
- SDK will substantially conform to documentation
- SaaS platform will meet stated uptime SLAs
- No warranty against all cheating (user-mode limitations documented)

**Liability Limitation:**
- Limited to fees paid in the 12 months preceding the claim
- No liability for indirect, consequential, or punitive damages
- No liability for third-party cheat development

**Disclaimer:**
Sentinel is a **user-mode anti-cheat**. It provides **deterrence** against casual attackers but **cannot prevent** all cheating. See [DEFENSIVE_GAPS.md](DEFENSIVE_GAPS.md) for technical limitations.

---

## Getting Started

### For SaaS Customers

1. **Sign Up**: Create account at [sentinel.example.com](https://sentinel.example.com) *(placeholder)*
2. **Choose Plan**: Select Community, Professional, or Enterprise tier
3. **Download SDK**: Get the SDK package for your platform
4. **Integrate**: Follow [integration/quickstart.md](integration/quickstart.md)
5. **Configure**: Set license key and configure telemetry endpoint
6. **Deploy**: Ship your game with Sentinel protection
7. **Monitor**: Use Cortex dashboard to monitor threats

**Time to Integration:** ~4 hours for first-time integrator

---

### For Studio License Customers

1. **Contact Sales**: Reach out for enterprise pricing and terms
2. **Negotiation**: Discuss studio size, player counts, custom features
3. **Contract**: Sign studio license agreement
4. **Deployment**: Choose SaaS or self-hosted infrastructure
5. **Integration**: Follow [integration/quickstart.md](integration/quickstart.md)
6. **Training**: Optional on-site training and integration support
7. **Go-Live**: Deploy with dedicated enterprise support

**Sales Contact:** sales@sentinel.example.com *(placeholder)*

---

## Comparison with Alternatives

Sentinel vs. competitors (EasyAntiCheat, BattlEye, Riot Vanguard):

See [COMPETITIVE_COMPARISON.md](COMPETITIVE_COMPARISON.md) for detailed comparison.

**Quick Positioning:**
- **vs. Kernel-Mode AC**: User-mode only, transparent limitations, easier integration
- **vs. Easy Anti-Cheat**: More transparent detection logic, self-hostable, indie-friendly pricing
- **vs. BattlEye**: Simpler integration (8 lines of code), open about bypasses, flexible licensing
- **vs. Riot Vanguard**: Less invasive (no kernel driver), no boot-time requirements, cross-platform

**Unique Value Propositions:**
1. **Transparent Security**: We openly document what we can and cannot prevent
2. **Rapid Integration**: 8-line integration, production-ready in 4 hours
3. **Flexible Pricing**: Pay-per-user OR perpetual studio licensing
4. **Self-Hostable**: Full control over infrastructure and data
5. **Open Philosophy**: Detection logic designed for auditability and trust

---

## Frequently Asked Questions

### General

**Q: Is Sentinel open source?**  
A: No. Sentinel is proprietary software. SDK source is not distributed. Public headers and integration examples are provided.

**Q: Can I try Sentinel before committing?**  
A: Yes. Community tier is free for games under 1,000 concurrent players. Perfect for testing and small indie games.

**Q: What happens if I exceed my tier limits?**  
A: You'll receive automated notifications. We'll work with you to upgrade or adjust licensing. No surprise shutdowns.

**Q: Can I switch between SaaS and self-hosted?**  
A: Yes. Enterprise customers can migrate between deployment models. Migration support included.

---

### Technical

**Q: Does Sentinel prevent all cheating?**  
A: No. Sentinel is user-mode only and cannot prevent kernel-mode attacks. See [DEFENSIVE_GAPS.md](DEFENSIVE_GAPS.md) for limitations.

**Q: What's the performance impact?**  
A: <1ms per frame on modern hardware. Detailed benchmarks in [integration/quickstart.md](integration/quickstart.md).

**Q: Does it work on Linux?**  
A: Partial support. Windows x64 is primary platform. Linux support is experimental.

**Q: Do I need source code access?**  
A: No. Integration requires only compiled SDK and public headers. Source escrow available for Enterprise customers.

---

### Commercial

**Q: What counts as an "active user"?**  
A: Any player who launches your game with Sentinel SDK in a calendar month. Counted at most once per player per month.

**Q: Are there volume discounts?**  
A: Yes. Contact sales for custom pricing above 100,000 monthly active users.

**Q: Can I negotiate custom terms?**  
A: Enterprise customers can negotiate custom SLAs, features, and pricing. Contact sales.

**Q: What payment methods are accepted?**  
A: Credit card, wire transfer, purchase orders (Enterprise). Monthly or annual billing available.

---

## Contact Information

**Sales Inquiries:** sales@sentinel.example.com *(placeholder)*  
**Technical Support:** support@sentinel.example.com *(placeholder)*  
**Security Issues:** security@sentinel.example.com *(placeholder)*  
**Documentation:** [docs/](.)  
**GitHub:** https://github.com/Lovuwer/Sentiel-RE

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | Jan 2026 | Initial commercial offering definition |

---

**Related Documents:**
- [PRICING_PACKAGING.md](PRICING_PACKAGING.md) - Detailed pricing tiers
- [SUPPORT_TIERS.md](SUPPORT_TIERS.md) - Support level definitions
- [DATA_PRIVACY_POLICY.md](DATA_PRIVACY_POLICY.md) - Privacy and data handling
- [COMPETITIVE_COMPARISON.md](COMPETITIVE_COMPARISON.md) - Market positioning
- [integration/quickstart.md](integration/quickstart.md) - Integration instructions
- [DEFENSIVE_GAPS.md](DEFENSIVE_GAPS.md) - Security limitations
