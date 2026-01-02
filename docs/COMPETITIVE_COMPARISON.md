# Sentinel Competitive Comparison

**Version:** 1.0.0  
**Last Updated:** January 2026  
**Document Type:** Market Positioning  
**Status:** Active

---

## Executive Summary

This document provides an **honest, objective comparison** of Sentinel against leading anti-cheat solutions. We believe in transparency—we'll tell you what we do better, what we do differently, and where competitors may have advantages.

**Key Takeaway:** Sentinel is **NOT** trying to replace kernel-mode solutions like Vanguard or BattlEye. We're offering a **user-mode alternative** with transparent limitations, rapid integration, and flexible deployment options.

---

## Competitive Landscape

### Market Categories

**Kernel-Mode Anti-Cheat (Invasive):**
- Riot Vanguard
- BattlEye
- Easy Anti-Cheat (EAC)

**User-Mode Anti-Cheat (Deterrence):**
- Sentinel ← You are here
- Fair Fight
- PunkBuster (deprecated)

**Server-Side Analytics:**
- Overwolf Game Analytics
- Valve Anti-Cheat (VAC)
- Custom ML-based systems

---

## Detailed Comparisons

### Sentinel vs. Easy Anti-Cheat (EAC)

| Feature | Sentinel | Easy Anti-Cheat |
|---------|----------|-----------------|
| **Protection Level** | User-mode only | Kernel-mode driver |
| **Integration Time** | 4 hours (8 lines) | 1-2 weeks |
| **Platform Support** | Windows, Linux (partial) | Windows, macOS, Linux |
| **Self-Hostable** | ✅ Yes | ❌ No (cloud only) |
| **Open About Bypasses** | ✅ Yes | ❌ No |
| **Pricing Model** | Per-user OR perpetual | Per-user only |
| **Source Access** | Headers only | Headers only |
| **Community Tier** | Free up to 1K MAU | No free tier |

**When to Choose Sentinel:**
- ✅ You want **transparent security** (we document what we can't prevent)
- ✅ You need **rapid integration** (production in 4 hours)
- ✅ You want **self-hosted** deployment options
- ✅ You're an **indie studio** (free tier up to 1K MAU)
- ✅ You value **predictable pricing** (perpetual studio license)
- ✅ You're okay with **user-mode limitations** (documented)

**When to Choose EAC:**
- ✅ You need **kernel-mode protection** (more invasive but stronger)
- ✅ You're a **large AAA title** (EAC ecosystem proven at scale)
- ✅ You want **console support** (Xbox, PlayStation)
- ✅ You're willing to invest **weeks in integration**
- ✅ You need **proven market presence** (EAC used by Fortnite, Apex, etc.)

**Sentinel's Advantage:**
- Faster integration (8 lines vs. weeks)
- Transparent limitations (we tell you what we can't do)
- Self-hostable (you own infrastructure)
- Free tier for indies
- Perpetual licensing option

**EAC's Advantage:**
- Kernel-mode protection (prevents more attacks)
- Console support (we're PC only)
- Market proven at massive scale (millions of players)
- More comprehensive platform support

---

### Sentinel vs. BattlEye

| Feature | Sentinel | BattlEye |
|---------|----------|----------|
| **Protection Level** | User-mode only | Kernel-mode driver |
| **Integration Complexity** | Minimal (8 lines) | Moderate (SDK integration) |
| **Boot-Time Driver** | ❌ No | ✅ Yes (stronger but more invasive) |
| **Platform Support** | Windows, Linux (partial) | Windows, Linux, macOS |
| **Pricing Transparency** | ✅ Public pricing | ❌ Enterprise negotiation only |
| **Self-Hostable** | ✅ Yes | ❌ No |
| **Open About Limitations** | ✅ Yes | ❌ No |
| **Community Tier** | Free up to 1K MAU | No free tier |

**When to Choose Sentinel:**
- ✅ You want **simple integration** (no boot-time driver, no UAC prompts)
- ✅ You value **transparent pricing** (public rates, no negotiation)
- ✅ You want **self-hosted** infrastructure
- ✅ You're an **indie studio** (free tier)
- ✅ You're okay with **user-mode limitations** (documented honestly)

**When to Choose BattlEye:**
- ✅ You need **maximum protection** (kernel driver at boot)
- ✅ You're a **competitive PvP game** (BattlEye proven in Rainbow Six, PUBG, etc.)
- ✅ You have **serious cheat problem** requiring nuclear option
- ✅ You're willing to accept **player friction** (boot-time driver, UAC prompts)

**Sentinel's Advantage:**
- Non-invasive (no boot driver, no UAC prompts)
- Transparent pricing (no enterprise sales cycle)
- Simple integration (8 lines of code)
- Self-hostable

**BattlEye's Advantage:**
- Kernel-mode protection (prevents more attacks)
- Market proven in competitive PvP (Rainbow Six, PUBG, Tarkov)
- Boot-time loading (harder to bypass)
- Console support

---

### Sentinel vs. Riot Vanguard

| Feature | Sentinel | Riot Vanguard |
|---------|----------|---------------|
| **Protection Level** | User-mode only | Kernel-mode driver (boot-time) |
| **Invasiveness** | Low (no kernel driver) | High (boots with Windows) |
| **Integration Complexity** | Minimal (8 lines) | Not available (Riot games only) |
| **Platform Support** | Windows, Linux (partial) | Windows only |
| **Player Friction** | Minimal | High (UAC, boot driver, anti-cheat wars) |
| **Self-Hostable** | ✅ Yes | ❌ No (Riot internal) |
| **Licensing** | Commercial | Riot games only |

**When to Choose Sentinel:**
- ✅ Vanguard **isn't available** (Riot-exclusive)
- ✅ You want **less invasive** approach (no boot driver)
- ✅ You care about **player experience** (minimize friction)
- ✅ You're transparent about **limitations** (user-mode tradeoffs documented)
- ✅ You want **community trust** (open about what we can't prevent)

**When to Choose Vanguard:**
- ❌ **You can't.** Vanguard is Riot Games internal technology, not available for licensing.

**Sentinel's Advantage:**
- Actually available to license
- Less invasive (no boot driver reducing player friction)
- Self-hostable
- Transparent about limitations

**Vanguard's Advantage:**
- Kernel-mode protection (prevents more attacks)
- Boot-time loading (maximum security)
- Proven at scale (Valorant has minimal cheating)

**Important Note:** 
Vanguard's **kernel-mode + boot-time** approach is **highly effective** but also **highly controversial**. Sentinel intentionally avoids this approach to respect player privacy and reduce friction. This is a **design tradeoff**, not a capability gap.

---

### Sentinel vs. Valve Anti-Cheat (VAC)

| Feature | Sentinel | VAC |
|---------|----------|-----|
| **Protection Level** | User-mode | User-mode |
| **Detection Approach** | Real-time + telemetry | Delayed ban waves |
| **Licensing** | Commercial SDK | Steam games only |
| **Ban Strategy** | Real-time or delayed | Delayed waves (intentional) |
| **Self-Hostable** | ✅ Yes | ❌ No (Steam ecosystem) |
| **Indie Friendly** | ✅ Yes (free tier) | ✅ Yes (Steam games) |
| **Transparency** | ✅ High (documented bypasses) | ❌ Low (intentionally opaque) |

**When to Choose Sentinel:**
- ✅ You're **not on Steam** (or want multi-platform)
- ✅ You want **real-time detection** (not just delayed bans)
- ✅ You want **telemetry and analytics** (operator dashboard)
- ✅ You want **control** over ban strategy (immediate vs. delayed)
- ✅ You want **transparent security** (documented limitations)

**When to Choose VAC:**
- ✅ You're **shipping on Steam** (VAC is free for Steam games)
- ✅ You prefer **delayed ban waves** (psychologically effective)
- ✅ You want **zero integration effort** (Steamworks automatic)
- ✅ You trust **Valve's opaque approach** (no documentation of capabilities)

**Sentinel's Advantage:**
- Works outside Steam ecosystem
- Real-time detection + analytics
- Operator dashboard for monitoring
- Transparent about limitations
- Self-hostable

**VAC's Advantage:**
- Free for Steam games
- Proven delayed ban wave strategy (psychological deterrent)
- Zero integration effort (automatic via Steamworks)
- Massive cheat signature database (20+ years)

---

### Sentinel vs. Fair Fight

| Feature | Sentinel | Fair Fight |
|---------|----------|-----------|
| **Protection Level** | User-mode | Server-side analytics |
| **Detection Approach** | Client + server telemetry | Server-side only |
| **Client Component** | ✅ Yes (SDK) | ❌ No |
| **False Positive Risk** | Low-Medium | Medium-High (ML-based) |
| **Transparency** | ✅ High | ❌ Low |
| **Self-Hostable** | ✅ Yes | ❌ No |
| **Licensing** | Per-user OR perpetual | Custom negotiation |

**When to Choose Sentinel:**
- ✅ You want **client-side detection** (not just server analytics)
- ✅ You want **lower false positive rate** (deterministic checks)
- ✅ You want **transparent operation** (documented detection logic)
- ✅ You want **self-hosted** infrastructure

**When to Choose Fair Fight:**
- ✅ You want **zero client-side footprint** (server-only)
- ✅ You're willing to accept **ML-based false positives**
- ✅ You want **behavioral analysis** (statistical anomaly detection)
- ✅ You're okay with **opaque operation** (proprietary ML)

**Sentinel's Advantage:**
- Client-side detection (catches more)
- Transparent operation (documented behavior)
- Lower false positive rate (deterministic)
- Self-hostable

**Fair Fight's Advantage:**
- Zero client-side footprint (can't be bypassed at client)
- Server-side only (no SDK integration needed)
- Behavioral ML (catches statistical anomalies)

---

## Feature Matrix

| Feature | Sentinel | EAC | BattlEye | Vanguard | VAC | Fair Fight |
|---------|----------|-----|----------|----------|-----|-----------|
| **Kernel-Mode** | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Boot-Time Driver** | ❌ | ❌ | ✅ | ✅ | ❌ | N/A |
| **Client Detection** | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Server Analytics** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Self-Hostable** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Free Tier** | ✅ | ❌ | ❌ | N/A | ✅* | ❌ |
| **Open About Bypasses** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Transparent Pricing** | ✅ | ❌ | ❌ | N/A | ✅* | ❌ |
| **Perpetual License** | ✅ | ❌ | ❌ | N/A | ✅* | ❌ |
| **Integration Time** | 4 hours | 1-2 weeks | 1 week | N/A | 0** | 1 week |
| **Console Support** | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Mobile Support** | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |

**\* VAC is free for Steam games only**  
**\*\* VAC auto-enables for Steamworks games**

---

## Market Positioning

### Sentinel's Unique Position

Sentinel occupies a **unique niche** in the anti-cheat market:

**What Makes Us Different:**

1. **Honest About Limitations**
   - We openly document what we **cannot** prevent (kernel-mode attacks)
   - We publish our defensive gaps and known bypasses
   - We don't claim to be "unbreakable" or "military-grade"

2. **Rapid Integration**
   - 8 lines of code, 4 hours to production
   - No multi-week integration projects
   - Minimal ongoing maintenance

3. **Self-Hostable**
   - Deploy entirely on your infrastructure
   - You own the data, you control the platform
   - No vendor lock-in

4. **Indie-Friendly Pricing**
   - Free tier up to 1,000 MAU
   - Pay-per-user OR perpetual licensing
   - Transparent, public pricing

5. **Transparent Security**
   - Detection logic designed for auditability
   - No "security through obscurity"
   - Community trust through honesty

---

### Target Customers

**Ideal Sentinel Customers:**

1. **Indie Studios & Solo Developers**
   - Need protection but can't afford $10K/month AAA solutions
   - Want rapid integration (limited development resources)
   - Appreciate free tier up to 1K MAU

2. **Mid-Size Multiplayer Games**
   - Need real protection but not nuclear options (no kernel driver)
   - Want self-hostable infrastructure (data sovereignty)
   - Value transparent pricing (predictable costs)

3. **Non-Competitive PvE Games**
   - Casual cheating is problem, but not existential threat
   - Don't need kernel-mode invasiveness
   - Want deterrence without player friction

4. **Studios Valuing Transparency**
   - Want to understand what protection they're buying
   - Appreciate honest security analysis
   - Prefer "defense-in-depth" philosophy

5. **Data-Sovereign Organizations**
   - Government, education, enterprise games
   - Need self-hosted deployment (data never leaves network)
   - Regulatory compliance requirements

---

### NOT Ideal For:

1. **Ultra-Competitive Esports Games**
   - Need kernel-mode protection (Vanguard, BattlEye level)
   - Cheating is existential threat to competitive integrity
   - **Recommendation:** Use BattlEye or negotiate with EAC

2. **Console-Only Games**
   - Sentinel is PC-focused (Windows, Linux)
   - No Xbox, PlayStation support
   - **Recommendation:** Use EAC or Fair Fight

3. **Mobile Games**
   - Sentinel doesn't support Android/iOS
   - **Recommendation:** Use EAC or mobile-specific solutions

4. **Games Requiring Zero Cheating**
   - Sentinel is user-mode and bypassable with kernel access
   - Cannot guarantee zero cheating
   - **Recommendation:** Use Vanguard-level solution OR accept some cheating

---

## Pricing Comparison

| Solution | Pricing Model | Transparency | Indie Tier | Perpetual License |
|----------|---------------|--------------|------------|-------------------|
| **Sentinel** | $0.08/user OR perpetual | ✅ Public | ✅ Free <1K MAU | ✅ Yes |
| **EAC** | Per-user (undisclosed) | ❌ NDA | ❌ No | ❌ No |
| **BattlEye** | Enterprise negotiation | ❌ NDA | ❌ No | ❌ No |
| **Vanguard** | Not available (Riot only) | N/A | N/A | N/A |
| **VAC** | Free (Steam games) | ✅ Free | ✅ Free | ✅ Free* |
| **Fair Fight** | Enterprise negotiation | ❌ NDA | ❌ No | ❌ No |

**\* VAC is free but Steam-exclusive**

**Sentinel's Pricing Advantage:**
- Only solution with **public, transparent pricing**
- Only solution with **perpetual studio licensing option**
- Only commercial solution with **free indie tier**

---

## Philosophy Comparison

### Sentinel's Philosophy

**"Honest Security Through Defense-in-Depth"**

- ✅ User-mode limitations are **documented, not hidden**
- ✅ Detection is **one layer** in complete security architecture
- ✅ **Transparency builds trust** with players and studios
- ✅ **Rapid integration** enables adoption, deterrence at scale
- ✅ **Self-hosting** respects data sovereignty

**We believe:**
- Better to be **honest** about limitations than promise impossible security
- **Defense-in-depth** (client + server + behavioral + economic) beats any single solution
- **Player experience matters**: invasiveness should be proportional to threat
- **Community trust** is earned through transparency, not secrecy

---

### Competitor Philosophies

**Easy Anti-Cheat / BattlEye:**
- **"Security Through Obscurity"**: Don't publish capabilities or limitations
- **"Kernel-Mode for Maximum Protection"**: More invasive, but more effective
- **"Enterprise Sales Model"**: Custom pricing, no public rates

**Riot Vanguard:**
- **"Nuclear Option"**: Boot-time kernel driver, maximum invasiveness
- **"Zero Tolerance"**: Cheating in competitive games is existential threat
- **"First-Party Only"**: Riot games only, not licensable

**Valve VAC:**
- **"Delayed Ban Waves"**: Psychological deterrent through uncertainty
- **"Intentional Opacity"**: Don't document detection methods
- **"Steam Ecosystem Lock-In"**: Free, but Steam-exclusive

**Fair Fight:**
- **"Server-Side Only"**: No client footprint means no client bypass
- **"ML-Based Detection"**: Statistical anomaly detection
- **"Accept False Positives"**: Some innocent players banned as tradeoff

---

## Hybrid Approaches

### Combining Sentinel with Other Solutions

Sentinel is **designed to complement** other anti-cheat layers:

**Sentinel + Server-Side Validation:**
- Sentinel provides client-side detection telemetry
- Your server validates game state (speed, physics, economy)
- Best of both worlds: deterrence + authoritative validation

**Sentinel + Behavioral Analytics:**
- Sentinel catches obvious cheats (debugger, injectors)
- ML/stats layer catches statistical anomalies (aim assist, wall hacks)
- Reduces false positives (both systems must agree)

**Sentinel + Economic Disincentives:**
- Sentinel detects and reports cheaters
- HWID bans + delayed ban waves increase cheat cost
- Game design (no tradable items, etc.) reduces cheat motivation

**Sentinel + Community Moderation:**
- Sentinel provides cheat reports to moderators
- Human review for edge cases (reduce false positives)
- Community trust through transparent process

---

## Migration Paths

### Migrating TO Sentinel

**From EAC / BattlEye:**
- **Why Migrate:** Reduce costs, self-host, transparent pricing
- **Integration Time:** ~1 week (replace existing AC integration)
- **Considerations:** Loss of kernel-mode protection (document tradeoff)

**From VAC (Steam-only):**
- **Why Migrate:** Multi-platform support, self-hosted, analytics dashboard
- **Integration Time:** ~4 hours (VAC has no integration, Sentinel needs 8 lines)
- **Considerations:** Sentinel is not free (but has free tier up to 1K MAU)

**From Custom/In-House:**
- **Why Migrate:** Reduce development cost, offload maintenance, threat intel sharing
- **Integration Time:** ~1 week (depends on custom solution complexity)
- **Considerations:** Loss of complete control (but self-hosted option available)

---

### Migrating FROM Sentinel

**To EAC / BattlEye:**
- **Why Migrate:** Need kernel-mode protection (competitive PvP escalation)
- **Considerations:** Higher cost, longer integration, less transparency
- **We'll Help:** No lock-in, data export available, we'll assist migration

**To Custom Solution:**
- **Why Migrate:** Need features we don't provide (console, mobile, etc.)
- **Considerations:** Development cost, maintenance burden
- **We'll Help:** Data export, integration guidance, lessons learned

---

## Conclusion

### When to Choose Sentinel

Choose Sentinel if you value:

- ✅ **Transparent security** (we document what we can't prevent)
- ✅ **Rapid integration** (8 lines, 4 hours)
- ✅ **Self-hosted option** (data sovereignty, infrastructure control)
- ✅ **Indie-friendly pricing** (free tier, predictable costs)
- ✅ **User-mode approach** (less invasive, better player experience)
- ✅ **Honest limitations** (documented defensive gaps)

---

### When to Choose Competitors

Choose kernel-mode solutions (EAC, BattlEye, Vanguard) if:

- ✅ You need **maximum protection** (kernel-mode, boot-time)
- ✅ You're a **competitive PvP game** (cheating is existential)
- ✅ You're willing to accept **player friction** (kernel driver, UAC, etc.)
- ✅ You have **budget for enterprise pricing** ($10K+ / month)

Choose VAC if:

- ✅ You're **Steam-exclusive** and want zero cost
- ✅ You prefer **delayed ban waves** over real-time detection
- ✅ You want **zero integration effort** (Steamworks automatic)

Choose Fair Fight if:

- ✅ You want **zero client footprint** (server-side only)
- ✅ You're okay with **ML-based false positives**
- ✅ You have **strong server-side validation** already

---

## Contact Sales

Have questions about how Sentinel compares to your current solution?

**Email:** sales@sentinel.example.com *(placeholder)*  
**Schedule Demo:** https://sentinel.example.com/demo *(placeholder)*

We'll provide **honest answers** about whether Sentinel is right for your game. If we're not the best fit, we'll tell you.

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | Jan 2026 | Initial competitive comparison |

---

**Related Documents:**
- [COMMERCIAL_OFFERING.md](COMMERCIAL_OFFERING.md) - Commercial structure overview
- [PRICING_PACKAGING.md](PRICING_PACKAGING.md) - Pricing details
- [DEFENSIVE_GAPS.md](DEFENSIVE_GAPS.md) - Security limitations
- [STUDIO_INTEGRATION_GUIDE.md](STUDIO_INTEGRATION_GUIDE.md) - Integration instructions
