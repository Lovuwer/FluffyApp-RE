# Sentinel Pricing and Packaging

**Version:** 1.0.0  
**Last Updated:** January 2026  
**Document Type:** Commercial Pricing  
**Status:** Active

---

## Pricing Philosophy

Sentinel pricing is designed to be **fair, transparent, and scalable**:

- **Aligned with Value**: Pay based on the protection you receive
- **No Hidden Fees**: All costs disclosed upfront
- **Flexible Options**: Choose per-user SaaS or perpetual licensing
- **Growth-Friendly**: Pricing scales as your game grows
- **Indie-Friendly**: Free tier for small games, affordable for studios

---

## SaaS Subscription Pricing

### Per-Active-User Model

**Definition of Active User:**
- A **unique player** who launches your game with Sentinel SDK in a **calendar month**
- Counted **once per player per month** regardless of session count
- Based on unique hardware/account identifiers
- Metered automatically by Sentinel Cloud

**Billing:**
- Monthly billing cycle (calendar month)
- Billed in arrears (pay for previous month's usage)
- Prorated for partial months
- Volume discounts applied automatically

---

## SaaS Pricing Tiers

### Community Tier (Free)

**Price:** $0/month

**Included:**
- ✅ Up to **1,000 monthly active users** (MAU)
- ✅ Sentinel SDK (all detection features)
- ✅ Cloud telemetry processing
- ✅ Basic analytics dashboard
- ✅ 30-day data retention
- ✅ Community support (GitHub issues, forums)
- ✅ Weekly signature updates
- ✅ API access (rate-limited: 100 req/hour)

**Ideal For:**
- Indie developers and solo creators
- Early-stage games in development
- Testing and proof-of-concept
- Small community servers
- Educational projects

**Limitations:**
- Limited to 1,000 MAU (hard cap)
- Best-effort uptime (no SLA)
- Community support only
- Basic analytics (no custom reports)

---

### Professional Tier

**Price:** $0.08 per active user/month

**Minimum:** $80/month (1,000 users)  
**Volume Discounts:**
- 1,000 - 10,000 users: $0.08/user
- 10,001 - 50,000 users: $0.06/user
- 50,001 - 100,000 users: $0.05/user
- 100,001+ users: Contact sales

**Example Pricing:**
- 5,000 users: $400/month
- 25,000 users: $1,300/month (blended rate)
- 75,000 users: $3,800/month (blended rate)

**Included (Everything in Community, plus):**
- ✅ **Unlimited active users** (with tiered pricing)
- ✅ **99.5% uptime SLA**
- ✅ **Professional support** (see [SUPPORT_TIERS.md](SUPPORT_TIERS.md))
  - 4-hour critical response time
  - 8-hour high priority response
  - Email and ticketing system
- ✅ **Advanced analytics**
  - Custom dashboards
  - CSV/JSON export
  - Retention up to 90 days (configurable)
- ✅ **Daily signature updates**
- ✅ **API access** (10,000 req/hour)
- ✅ **Priority queue** for feature requests
- ✅ **Integration support** (up to 8 hours)

**Ideal For:**
- Growing indie studios
- Mid-size multiplayer games
- Early access titles with active communities
- Games with 1K-100K MAU
- Studios seeking predictable scaling

---

### Enterprise Tier

**Price:** Custom (volume-based or studio licensing)

**Typical Range:** $5,000 - $50,000+/month (based on scale and features)

**Included (Everything in Professional, plus):**
- ✅ **Custom pricing** (volume discounts or perpetual licensing)
- ✅ **99.9% uptime SLA**
- ✅ **Enterprise support** (see [SUPPORT_TIERS.md](SUPPORT_TIERS.md))
  - 1-hour critical response time
  - Dedicated support engineer
  - On-call escalation (24/7)
  - Integration assistance (up to 40 hours)
- ✅ **Self-hosted deployment** options
  - Private cloud (AWS/Azure/GCP)
  - Air-gapped installations
  - You own the infrastructure
- ✅ **Advanced features**
  - Custom detection rules
  - White-label options (remove Sentinel branding)
  - Priority threat research
  - Zero-day signature updates
- ✅ **Compliance support**
  - GDPR/CCPA compliance assistance
  - Data residency options (EU, US, Asia)
  - SOC 2 attestation available
- ✅ **Custom SLAs** and contract terms
- ✅ **Source code escrow** (optional)
- ✅ **Unlimited API access**

**Ideal For:**
- AAA studios and publishers
- Games with 100K+ MAU
- Studios with strict compliance requirements
- Self-hosted infrastructure needs
- Custom feature requirements

**Contact Sales:** sales@sentinel.example.com *(placeholder)*

---

## Perpetual Studio Licensing

### Licensing Model

**Alternative to SaaS subscription for predictable costs**

Instead of per-user monthly fees, pay a **one-time license fee** plus **annual support subscription**.

---

### Small Studio License

**One-Time License Fee:** $25,000

**Annual Support:** $5,000/year (20% of license fee)

**Includes:**
- ✅ Perpetual rights to Sentinel SDK
- ✅ Unlimited active users
- ✅ Self-hosted deployment rights
- ✅ Professional-tier features
- ✅ Annual signature updates
- ✅ Professional support (during support term)
- ✅ Major version updates (during support term)

**Studio Definition:**
- Annual revenue <$5M
- <50 employees
- Single game or franchise

**Support Subscription:**
- Required for first year
- Optional thereafter (but no updates/support without it)
- Renews annually at current rate

**ROI Calculation:**
- Breakeven vs. Professional SaaS: ~3,000 MAU sustained over 12 months
- Cost-effective for games with stable, large player bases

---

### Mid-Market Studio License

**One-Time License Fee:** $100,000

**Annual Support:** $20,000/year (20% of license fee)

**Includes:**
- ✅ Everything in Small Studio License
- ✅ Enterprise-tier features
- ✅ Multi-game deployment (up to 5 titles)
- ✅ White-label options available
- ✅ Dedicated support engineer
- ✅ Priority feature development
- ✅ Custom integration assistance (40 hours)

**Studio Definition:**
- Annual revenue $5M - $50M
- 50-200 employees
- Multiple games or large franchise

**ROI Calculation:**
- Breakeven vs. Enterprise SaaS: ~20,000 MAU sustained over 12 months
- Cost-effective for established studios with predictable scale

---

### Enterprise Studio License

**One-Time License Fee:** Custom ($250,000+)

**Annual Support:** 20% of license fee

**Includes:**
- ✅ Everything in Mid-Market License
- ✅ Unlimited game deployments
- ✅ Source code escrow included
- ✅ Custom feature development
- ✅ On-site training and integration
- ✅ 24/7 dedicated support
- ✅ Custom SLAs and contract terms
- ✅ Royalty-free redistribution rights

**Studio Definition:**
- Annual revenue >$50M
- 200+ employees
- AAA publisher or platform

**Contact Sales:** sales@sentinel.example.com *(placeholder)*

---

## Feature Comparison Matrix

| Feature | Community | Professional | Enterprise | Studio License |
|---------|-----------|--------------|------------|----------------|
| **Pricing** | Free | $0.08/user | Custom | $25K+ one-time |
| **MAU Limit** | 1,000 | Unlimited | Unlimited | Unlimited |
| **SDK Access** | ✅ | ✅ | ✅ | ✅ |
| **Cloud Telemetry** | ✅ | ✅ | ✅ | Optional |
| **Basic Dashboard** | ✅ | ✅ | ✅ | ✅ |
| **API Access** | Limited | Standard | Unlimited | Unlimited |
| **Data Retention** | 30 days | 90 days | Custom | Custom |
| **Uptime SLA** | None | 99.5% | 99.9% | 99.9% |
| **Support** | Community | Professional | Enterprise | Professional+ |
| **Response Time (P0)** | None | 4 hours | 1 hour | 2 hours |
| **Signature Updates** | Weekly | Daily | Real-time | Daily+ |
| **Custom Detection** | ❌ | ❌ | ✅ | ✅ |
| **Self-Hosted** | ❌ | ❌ | ✅ | ✅ |
| **White-Label** | ❌ | ❌ | ✅ | Optional |
| **Source Escrow** | ❌ | ❌ | Optional | Optional |
| **Multi-Game** | 1 game | 1 game | Custom | 5+ games |

---

## Add-On Services

### Custom Feature Development

**Price:** $150-$250/hour (depending on complexity)

**Minimum:** 40-hour engagement ($6,000)

**Examples:**
- Custom detection algorithms for game-specific exploits
- Integration with proprietary game engines
- Specialized telemetry processing
- Custom analytics dashboards

**Available To:** Enterprise and Studio License customers

---

### Integration Services

**Price:** $10,000 - $50,000 (project-based)

**Includes:**
- On-site or remote integration assistance
- Code review and optimization
- Performance tuning
- Load testing and optimization
- Documentation and training

**Available To:** Professional, Enterprise, and Studio License customers

---

### Training and Onboarding

**Price:** $2,500/day (on-site) or $1,000/day (remote)

**Topics:**
- Sentinel architecture and detection mechanisms
- Integration best practices
- Dashboard and analytics training
- Security operations center (SOC) training
- Incident response procedures

**Available To:** All paying customers

---

### Dedicated Threat Research

**Price:** Starting at $5,000/month

**Includes:**
- Continuous monitoring of cheat development communities
- Custom signature development for your game
- Zero-day threat intelligence
- Monthly threat intelligence reports
- Direct access to security researchers

**Available To:** Enterprise and Studio License customers

---

## Payment Terms

### SaaS Subscriptions

**Billing Cycle:**
- Monthly (billed in arrears for previous month's usage)
- Annual (20% discount, billed upfront)

**Payment Methods:**
- Credit card (Visa, MasterCard, Amex)
- ACH transfer
- Wire transfer (Enterprise only)
- Purchase orders (Enterprise only, net-30 terms)

**Late Payment:**
- 5-day grace period
- Service suspension after 10 days overdue
- 1.5% monthly late fee (18% APR)

---

### Studio Licenses

**Payment Schedule:**
- 50% upfront upon contract signing
- 50% upon delivery of SDK and documentation
- Annual support billed annually in advance

**Payment Methods:**
- Wire transfer
- Check
- Purchase orders (net-30 terms)

**Renewal:**
- Annual support auto-renews unless cancelled 30 days before renewal
- Price increases capped at 5% per year

---

## Volume Discounts

### SaaS Volume Pricing

Discounts applied automatically based on monthly active users:

| MAU Range | Price per User | Effective Monthly Cost |
|-----------|----------------|------------------------|
| 0 - 1,000 | Free | $0 |
| 1,001 - 10,000 | $0.08 | $80 - $800 |
| 10,001 - 50,000 | $0.06 | $800 - $3,000 |
| 50,001 - 100,000 | $0.05 | $3,000 - $5,000 |
| 100,001 - 500,000 | Custom | Contact sales |
| 500,001+ | Custom | Contact sales |

**Example Calculation (25,000 MAU):**
- First 10,000 users: 10,000 × $0.08 = $800
- Next 15,000 users: 15,000 × $0.06 = $900
- **Total:** $1,700/month

---

### Annual Commitment Discounts

**12-Month Prepay Discount:** 20% off total annual cost  
**24-Month Prepay Discount:** 30% off total annual cost (Enterprise only)

**Example:**
- 25,000 MAU monthly = $1,700/month = $20,400/year
- With 12-month prepay: $16,320/year (saves $4,080)

---

## Pricing FAQs

### General

**Q: What counts as an active user?**  
A: A unique player who launches your game in a calendar month. Counted once per player per month.

**Q: How are active users tracked?**  
A: Hardware fingerprint + account ID (if available). Privacy-preserving, no PII collected.

**Q: What if I go over my tier limit?**  
A: You'll receive automated warnings at 80%, 90%, 100%. Billing automatically adjusts to new tier. No service interruption.

**Q: Can I downgrade my tier?**  
A: Yes, at the end of your current billing cycle. Downgrades take effect next billing period.

**Q: Are there setup fees?**  
A: No setup fees for SaaS. Studio licenses include setup in the license fee.

---

### Billing

**Q: How are overage charges calculated?**  
A: Automatically based on actual active users. Tiered pricing applied retroactively for the month.

**Q: Can I get a refund?**  
A: SaaS: No refunds (pay in arrears, only billed for usage). Studio licenses: 30-day money-back guarantee (minus usage).

**Q: What happens if I cancel?**  
A: SaaS: Immediate cancellation, final bill for usage to date. Studio licenses: Perpetual rights retained, no refund.

**Q: Do you offer academic discounts?**  
A: Yes. 50% discount for accredited educational institutions. Contact sales.

---

### Technical

**Q: Can I test before committing?**  
A: Yes. Community tier is free up to 1,000 MAU. Perfect for testing and development.

**Q: What's the minimum contract term?**  
A: SaaS: Month-to-month (no long-term commitment). Studio licenses: 1-year support subscription required.

**Q: Can I switch from SaaS to studio licensing?**  
A: Yes. Contact sales to apply SaaS fees paid (up to 6 months) toward license fee.

---

## ROI Calculator

### When to Choose SaaS vs. Studio License

**SaaS Makes Sense When:**
- Unpredictable player counts
- Early-stage game or startup
- Want minimal upfront investment
- MAU < 3,000 sustained over 12 months
- Prefer operational expense (OpEx) accounting

**Studio License Makes Sense When:**
- Stable, predictable player base
- MAU > 3,000 sustained over 12+ months
- Want predictable costs
- Need self-hosted deployment
- Prefer capital expenditure (CapEx) accounting

**Breakeven Analysis (Small Studio License at $25K):**
- Professional tier at 3,000 MAU = $240/month
- Breakeven: ~8.7 years
- BUT: Professional tier at 10,000 MAU = $800/month
- Breakeven: ~2.6 years
- AND: Professional tier at 25,000 MAU = $1,700/month
- Breakeven: ~1.2 years

**Recommendation:** Studio license is cost-effective for games with **>10,000 sustained MAU** over multi-year timeline.

---

## Contact Sales

Have questions about pricing or need a custom quote?

**Email:** sales@sentinel.example.com *(placeholder)*  
**Phone:** +1 (555) 123-4567 *(placeholder)*  
**Schedule Demo:** https://sentinel.example.com/demo *(placeholder)*

**Enterprise RFPs:** We respond to formal requests for proposals. Email RFPs to sales@sentinel.example.com.

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | Jan 2026 | Initial pricing structure definition |

---

**Related Documents:**
- [COMMERCIAL_OFFERING.md](COMMERCIAL_OFFERING.md) - Commercial structure overview
- [SUPPORT_TIERS.md](SUPPORT_TIERS.md) - Support level definitions
- [DATA_PRIVACY_POLICY.md](DATA_PRIVACY_POLICY.md) - Privacy and data handling
- [COMPETITIVE_COMPARISON.md](COMPETITIVE_COMPARISON.md) - Market positioning
