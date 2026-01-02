# Sentinel Support Tiers

**Version:** 1.0.0  
**Last Updated:** January 2026  
**Document Type:** Support & SLA Definitions  
**Status:** Active

---

## Support Philosophy

At Sentinel, we believe that **responsive, knowledgeable support** is critical to successfully defending your game against cheaters. Our support structure is designed to provide the right level of assistance based on your needs and scale.

---

## Support Tier Overview

| Tier | Availability | Channels | Response Times | Ideal For |
|------|--------------|----------|----------------|-----------|
| **Community** | Best Effort | GitHub, Forums | None guaranteed | Testing, small indie games |
| **Professional** | Business Hours | Email, Ticketing | 4h - 3 days | Growing studios, mid-size games |
| **Enterprise** | 24/7/365 | All + Phone, Slack | 1h - 1 day | AAA studios, large-scale games |

---

## Community Tier (Free)

**Included With:** Free SaaS tier (up to 1,000 MAU)

### Support Channels

- ✅ **GitHub Issues**: Bug reports, feature requests
- ✅ **Community Forums**: Peer-to-peer support
- ✅ **Documentation**: Self-service guides and API reference
- ✅ **Example Code**: Integration examples and templates

### Response Times

**No guaranteed response times** - Best effort from community and Sentinel team

Typical response times:
- Critical bugs: 1-3 business days
- General questions: 3-7 business days
- Feature requests: No timeline

### What's Included

- ✅ Access to public documentation
- ✅ GitHub issue tracking
- ✅ Community forum participation
- ✅ Example code and integration templates
- ✅ Automated signature updates (weekly)
- ✅ Bug fixes in future releases

### What's NOT Included

- ❌ Direct email/phone support
- ❌ Guaranteed response times
- ❌ Integration assistance
- ❌ Custom feature development
- ❌ Emergency escalation
- ❌ Dedicated support engineer

### Issue Severity Definitions

Since there are no SLA commitments, all issues are treated as:
- **Best Effort**: We'll respond when resources are available
- **Community-Driven**: Peer support encouraged
- **No Escalation**: No priority queue

---

## Professional Tier

**Included With:** Professional SaaS subscription OR Small/Mid-Market Studio License

### Support Channels

- ✅ **Email Support**: support@sentinel.example.com *(placeholder)*
- ✅ **Ticketing System**: Web-based ticket portal with tracking
- ✅ **GitHub Issues**: Priority queue for reported bugs
- ✅ **Documentation**: Complete API reference and guides
- ✅ **Knowledge Base**: Searchable troubleshooting articles

### Availability

**Business Hours:** Monday-Friday, 9 AM - 6 PM PST (excluding holidays)

**After-Hours:** Email/ticket submission available 24/7, responses during business hours

### Response Time SLAs

| Severity | First Response | Resolution Target | Definition |
|----------|----------------|-------------------|------------|
| **P0 - Critical** | 4 hours | 24 hours | Service outage, complete detection failure |
| **P1 - High** | 8 hours | 3 business days | Major degradation, significant false positives |
| **P2 - Medium** | 24 hours | 5 business days | Partial degradation, integration issues |
| **P3 - Low** | 3 business days | Best effort | Questions, documentation, feature requests |

**First Response:** Initial acknowledgment and triage  
**Resolution Target:** Issue resolved or workaround provided

### Issue Severity Criteria

#### P0 - Critical
- **Definition**: Service is completely unavailable or fundamentally broken
- **Examples**:
  - Sentinel Cloud platform is down
  - SDK initialization fails for all users
  - Complete detection failure (no violations reported)
  - Security breach or data leak
  - Authentication/licensing system failure
- **Response**: 4-hour acknowledgment, escalation to engineering team
- **Resolution**: 24-hour target for fix or workaround

#### P1 - High
- **Definition**: Major functionality is impaired or degraded
- **Examples**:
  - Significant performance degradation (>10ms per frame)
  - High false positive rate (>5% of legitimate players flagged)
  - Detection module consistently failing
  - Integration blocking game release
  - Data not appearing in dashboard
- **Response**: 8-hour acknowledgment, engineering investigation
- **Resolution**: 3 business days for fix or mitigation

#### P2 - Medium
- **Definition**: Functionality is partially impaired but workarounds exist
- **Examples**:
  - Intermittent detection failures
  - Dashboard UI issues
  - Documentation gaps
  - Performance concerns (<10ms but higher than expected)
  - API rate limiting issues
  - Configuration questions
- **Response**: 24-hour acknowledgment
- **Resolution**: 5 business days for fix or guidance

#### P3 - Low
- **Definition**: Minor issues, questions, or enhancement requests
- **Examples**:
  - Feature requests
  - Documentation clarifications
  - "How do I...?" questions
  - Cosmetic UI issues
  - Enhancement suggestions
- **Response**: 3 business days
- **Resolution**: Best effort, may be deferred to future release

### What's Included

- ✅ **Email & Ticketing Support**: Direct access to support engineers
- ✅ **SLA-Backed Response Times**: Guaranteed response within SLA
- ✅ **Priority Bug Fixes**: Your issues prioritized in development queue
- ✅ **Integration Assistance**: Up to 8 hours of integration guidance
- ✅ **Configuration Review**: We'll review your Sentinel configuration
- ✅ **Performance Tuning**: Guidance on optimizing Sentinel performance
- ✅ **Daily Signature Updates**: Faster threat intelligence updates
- ✅ **Monthly Status Calls**: Optional check-ins with support team
- ✅ **Knowledge Base Access**: Premium troubleshooting articles

### What's NOT Included

- ❌ 24/7 availability (business hours only)
- ❌ Phone support
- ❌ Dedicated support engineer
- ❌ On-site visits
- ❌ Custom feature development
- ❌ Emergency on-call escalation
- ❌ Code-level debugging of your game

### Support Processes

#### Ticket Submission

1. **Submit Ticket**: Via web portal or email to support@sentinel.example.com
2. **Auto-Acknowledgment**: Immediate automated response with ticket ID
3. **Triage**: Support engineer reviews and assigns severity (within SLA)
4. **Investigation**: Engineer investigates and provides updates
5. **Resolution**: Fix deployed or workaround provided
6. **Closure**: Ticket closed with customer confirmation

#### Escalation

If response SLA is missed:
1. Ticket automatically escalated to senior support engineer
2. Customer receives notification of escalation
3. Escalated ticket receives priority attention
4. Support manager reviews escalated tickets daily

---

## Enterprise Tier

**Included With:** Enterprise SaaS subscription OR Enterprise Studio License

### Support Channels

- ✅ **All Professional Channels** (email, ticketing, GitHub)
- ✅ **Phone Support**: Direct phone line to support team
- ✅ **Slack/Teams Integration**: Dedicated channel for real-time support
- ✅ **Dedicated Support Engineer**: Named engineer familiar with your setup
- ✅ **Video Calls**: Screen-sharing for complex issues
- ✅ **On-Site Support**: Available for critical integrations (additional fee)

### Availability

**24/7/365 Coverage:** Round-the-clock support for critical issues

**Business Hours (Enhanced):** Monday-Friday, 9 AM - 6 PM PST with dedicated engineer  
**After-Hours/Weekends:** On-call rotation for P0/P1 issues

### Response Time SLAs

| Severity | First Response | Resolution Target | Definition |
|----------|----------------|-------------------|------------|
| **P0 - Critical** | 1 hour | 8 hours | Service outage, complete detection failure |
| **P1 - High** | 4 hours | 2 business days | Major degradation, significant false positives |
| **P2 - Medium** | 8 hours | 3 business days | Partial degradation, integration issues |
| **P3 - Low** | 1 business day | Best effort | Questions, documentation, feature requests |

**First Response:** Initial acknowledgment, assigned engineer, action plan  
**Resolution Target:** Issue resolved, hotfix deployed, or comprehensive workaround

### Issue Severity Criteria

*(Same definitions as Professional, with enhanced response commitments)*

**Additional P0 Triggers for Enterprise:**
- Any issue blocking a production release
- Media coverage of exploit/bypass affecting your game
- Regulatory compliance failure
- Major tournament or event disruption

### What's Included (Beyond Professional)

- ✅ **24/7 Critical Support**: On-call engineer for P0/P1 issues
- ✅ **Dedicated Support Engineer**: Named engineer learns your infrastructure
- ✅ **Phone & Video Support**: Real-time troubleshooting
- ✅ **Slack/Teams Channel**: Direct line to support team
- ✅ **Proactive Monitoring**: We monitor your Sentinel deployment
- ✅ **Integration Assistance**: Up to 40 hours of hands-on integration help
- ✅ **Code Review**: We'll review your Sentinel integration code
- ✅ **Performance Analysis**: Deep-dive performance profiling
- ✅ **Custom Signature Development**: We'll create signatures for game-specific cheats
- ✅ **Security Audits**: Annual review of your anti-cheat architecture
- ✅ **Hotfix Priority**: Critical fixes deployed within 8 hours
- ✅ **Release Planning**: We'll coordinate with your release schedule
- ✅ **Training Sessions**: Quarterly training for your team
- ✅ **Executive Escalation**: Direct access to engineering leadership

### What's NOT Included

- ❌ On-site visits (available as add-on)
- ❌ Game code development (we support Sentinel integration only)
- ❌ Unlimited custom development

### Support Processes

#### Ticket Submission

Same as Professional, with enhancements:
1. **Priority Queue**: Enterprise tickets automatically prioritized
2. **Dedicated Engineer**: Routed to your named support engineer
3. **Proactive Updates**: Engineer provides regular updates even before resolution
4. **Root Cause Analysis**: Detailed post-mortem for P0/P1 incidents

#### Emergency Escalation

For critical issues (P0):
1. **Phone Hotline**: Call dedicated emergency number (24/7)
2. **Immediate Response**: On-call engineer responds within 1 hour
3. **War Room**: Video call assembled with engineering team
4. **Executive Notification**: Engineering manager notified of all P0 issues
5. **Hotfix Deployment**: Emergency patches deployed within 8 hours
6. **Post-Mortem**: Written incident report provided within 48 hours

#### Proactive Support

Enterprise customers receive proactive support:
- **Quarterly Business Reviews**: Review metrics, plan ahead
- **Deployment Planning**: We help plan major integrations
- **Performance Reviews**: We analyze your telemetry for optimization
- **Threat Intelligence Briefings**: Monthly updates on cheat landscape
- **Pre-Release Testing**: We'll help test before major game updates

---

## SLA Measurement and Enforcement

### How SLAs Are Measured

**Response Time:**
- Measured from ticket creation to first human response (auto-responses don't count)
- Business hours: Monday-Friday, 9 AM - 6 PM PST
- After-hours responses count but not required except for Enterprise P0/P1

**Resolution Time:**
- Measured from ticket creation to customer confirmation of resolution
- Includes workarounds (fix doesn't have to be in production release)
- Pauses when waiting for customer response

### SLA Credits

If we miss an SLA commitment:

**Professional Tier:**
- Miss response SLA: 10% monthly credit
- Miss resolution SLA: 20% monthly credit
- Maximum credit: 50% of monthly fee

**Enterprise Tier:**
- Miss P0 response SLA: 20% monthly credit
- Miss P0 resolution SLA: 40% monthly credit
- Miss P1 response SLA: 10% monthly credit
- Miss P1 resolution SLA: 20% monthly credit
- Maximum credit: 100% of monthly fee

**How to Claim:**
1. Submit credit request within 30 days of SLA miss
2. Must provide ticket number and timestamps
3. Credits applied to next month's invoice
4. Credits do not apply to Studio Licenses (fixed annual support fee)

### SLA Exclusions

SLAs do not apply when:
- Issue caused by customer's infrastructure (not Sentinel)
- Customer using unsupported SDK version or configuration
- Customer unresponsive to requests for information
- Force majeure (natural disasters, war, etc.)
- Scheduled maintenance (announced 7 days in advance)
- Customer running modified/unofficial SDK builds

---

## Support Best Practices

### For Customers

**To Get the Best Support:**

1. **Choose Right Severity**: Don't mark everything P0 - we'll re-triage anyway
2. **Provide Context**: Logs, SDK version, OS, repro steps
3. **Respond Promptly**: Faster responses = faster resolution
4. **Use Ticket System**: Email is good, tickets are better (trackable)
5. **Read Docs First**: Many questions answered in documentation
6. **Update SDK**: Ensure you're on latest version before reporting bugs
7. **Test in Isolation**: Reproduce issue in minimal example if possible

**Great Bug Reports Include:**
- Sentinel SDK version
- Operating system and version
- Game engine (if applicable)
- Detailed reproduction steps
- Expected vs. actual behavior
- Logs from Sentinel SDK (with debug logging enabled)
- System specifications

---

## Support Add-Ons

### On-Site Integration Support

**Price:** $10,000 - $25,000 per engagement (travel included)

**Includes:**
- 2-5 days on-site at your studio
- Hands-on integration assistance
- Code review and optimization
- Performance profiling
- Team training
- Post-visit follow-up (2 weeks)

**Available To:** Professional and Enterprise customers

---

### Extended Integration Support

**Price:** $5,000/month (20 hours/month of dedicated time)

**Includes:**
- Dedicated integration engineer
- Scheduled video calls
- Code review
- Custom integration patterns
- Performance optimization
- Documentation customization

**Available To:** All paying customers

---

### Custom Training

**Price:** $2,500/day (on-site) or $1,000/day (remote)

**Topics:**
- Sentinel architecture deep-dive
- Detection mechanism internals
- Dashboard and analytics training
- Security operations center (SOC) processes
- Incident response playbooks
- Custom topics by request

**Available To:** All paying customers

---

## Contact Support

### By Tier

**Community:**
- GitHub Issues: https://github.com/Lovuwer/Sentiel-RE/issues
- Community Forums: https://community.sentinel.example.com *(placeholder)*

**Professional & Enterprise:**
- Email: support@sentinel.example.com *(placeholder)*
- Web Portal: https://support.sentinel.example.com *(placeholder)*
- Phone (Enterprise only): +1 (555) 123-4567 *(placeholder)*

### Emergency Contact (Enterprise P0 Only)

**24/7 Hotline:** +1 (555) 911-SENT (911-7368) *(placeholder)*

**Use only for:**
- Complete service outages
- Security breaches
- Production-blocking issues
- Time-sensitive tournament/event issues

---

## Frequently Asked Questions

### General

**Q: Can I upgrade my support tier?**  
A: Yes. Upgrades take effect immediately. Downgrades take effect at next billing cycle.

**Q: What happens if I abuse the support system?**  
A: Repeated false P0 escalations may result in ticket re-prioritization or account review.

**Q: Do I get support for free/community tier?**  
A: Community support only (best effort). No guaranteed response times.

**Q: Can I purchase support without SaaS subscription?**  
A: Yes. Studio License customers can purchase support a la carte.

---

### SLAs

**Q: What if you miss an SLA?**  
A: You're eligible for service credits. See "SLA Credits" section above.

**Q: Do SLAs apply to feature requests?**  
A: No. SLAs apply to bugs and technical issues only.

**Q: Can I get custom SLAs?**  
A: Enterprise customers can negotiate custom SLA terms. Contact sales.

---

### Technical

**Q: Will you debug my game code?**  
A: No. We support Sentinel SDK integration, not general game development.

**Q: Can you write custom features for me?**  
A: Enterprise customers can request custom features. Priced separately.

**Q: Do you support older SDK versions?**  
A: We support the current major version + 1 prior major version. Older versions: best effort.

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | Jan 2026 | Initial support tier definitions |

---

**Related Documents:**
- [COMMERCIAL_OFFERING.md](COMMERCIAL_OFFERING.md) - Commercial structure overview
- [PRICING_PACKAGING.md](PRICING_PACKAGING.md) - Pricing details
- [DATA_PRIVACY_POLICY.md](DATA_PRIVACY_POLICY.md) - Privacy and data handling
