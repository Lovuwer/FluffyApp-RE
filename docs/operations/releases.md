# Sentinel SDK Release and Versioning Policy

**Document Version:** 1.0  
**Last Updated:** 2026-01-02  
**Status:** Active

---

## Current Version Status

**SDK Version:** 0.1.0-alpha  
**Status:** Pre-release / Alpha  
**Production Ready:** No

---

## Versioning Scheme

Sentinel SDK follows [Semantic Versioning 2.0.0](https://semver.org/) with pre-release labels.

### Version Format

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

**Examples:**
- `0.1.0-alpha` - Current alpha version
- `0.2.0-beta.1` - Beta release, iteration 1
- `1.0.0-rc.1` - Release candidate 1
- `1.0.0` - First stable release
- `1.2.3` - Stable version with minor updates
- `2.0.0` - Major version with breaking changes

### Version Components

#### MAJOR Version (X.0.0)

Increment when making **incompatible API changes**:
- Breaking changes to public API
- Removal of deprecated features
- Architectural redesign
- Changes requiring client code modifications

**Examples:**
- `0.x.x` → `1.0.0`: First stable release
- `1.x.x` → `2.0.0`: Breaking API changes

#### MINOR Version (x.Y.0)

Increment when adding **backward-compatible functionality**:
- New detection features
- New API functions
- Enhanced capabilities
- Performance improvements
- Non-breaking configuration changes

**Examples:**
- `1.0.0` → `1.1.0`: Added new detection method
- `1.1.0` → `1.2.0`: Added telemetry features

#### PATCH Version (x.x.Z)

Increment for **backward-compatible bug fixes**:
- Bug fixes
- Security patches
- Documentation corrections
- Performance optimizations (non-breaking)
- Internal refactoring

**Examples:**
- `1.0.0` → `1.0.1`: Fixed crash bug
- `1.0.1` → `1.0.2`: Security patch

### Pre-Release Labels

#### Alpha (-alpha)

**Status:** Early development, unstable  
**Version Range:** `0.1.0-alpha` to `0.x.x-alpha`  
**Audience:** Internal testing only  
**Stability:** Frequent breaking changes expected  
**Support:** None

**Characteristics:**
- Core functionality incomplete
- Known bugs and limitations
- API may change without notice
- No production use
- No backward compatibility guarantees

**Current Status:** Sentinel SDK is in alpha

#### Beta (-beta.N)

**Status:** Feature-complete, testing phase  
**Version Range:** `0.x.x-beta.1` to `0.x.x-beta.N`  
**Audience:** Selected partners, early adopters  
**Stability:** Feature freeze, API mostly stable  
**Support:** Limited, best-effort

**Characteristics:**
- All planned features implemented
- Known issues being fixed
- API mostly stable
- Performance tuning ongoing
- Not recommended for production

**Entry Criteria for Beta:**
- All P0 features implemented
- All blocking bugs fixed
- API documented
- Integration guide complete

#### Release Candidate (-rc.N)

**Status:** Final testing, production-ready candidate  
**Version Range:** `0.x.x-rc.1` to `0.x.x-rc.N`  
**Audience:** All users (evaluation)  
**Stability:** No new features, bug fixes only  
**Support:** Full support

**Characteristics:**
- Code freeze (bug fixes only)
- API stable and frozen
- Performance acceptable
- Documentation complete
- Ready for production if no critical bugs found

**Entry Criteria for RC:**
- All features complete and tested
- No known critical bugs
- Performance meets targets
- Security review passed
- Integration tested on multiple games

---

## Release Lifecycle

### 0.x.x Versions (Pre-1.0)

**Policy:** Major version 0 indicates pre-release software

- `0.1.0-alpha`: Initial development
- `0.2.0-alpha`: First integration tests
- `0.3.0-beta.1`: Feature-complete beta
- `0.9.0-rc.1`: Release candidate
- `1.0.0`: First stable release

**Breaking Changes Allowed:** Yes, even in minor versions (e.g., 0.1.0 → 0.2.0 may break compatibility)

### 1.x.x Versions (Stable)

**Policy:** Semantic versioning strictly followed

- `1.0.0`: First stable release
- `1.1.0`: New features (backward-compatible)
- `1.0.1`: Bug fixes (backward-compatible)
- `2.0.0`: Breaking changes

**Breaking Changes:** Only in major version increments

---

## Transition to 1.0.0

### Requirements for 1.0.0 Release

The SDK will transition from `0.x.x-alpha` to `1.0.0` when:

#### Technical Requirements ✅ / ❌

- [ ] All P0 features implemented and tested
- [ ] CorrelationEngine test failures fixed (currently 7 failures)
- [ ] Performance targets met (Update() < 0.1ms, FullScan() < 5ms)
- [ ] Security vulnerabilities addressed
- [ ] Certificate pinning implemented
- [ ] SDK Heartbeat integration complete
- [ ] All detection subsystems production-ready
- [ ] False positive rate < 1% for HIGH severity
- [ ] API stable and documented
- [ ] Integration tested on 3+ real games

#### Documentation Requirements

- [ ] Complete API reference
- [ ] Integration guides for major engines (Unreal, Unity)
- [ ] Security documentation reviewed
- [ ] Troubleshooting guide
- [ ] Performance tuning guide
- [ ] Migration guides (for breaking changes)

#### Quality Requirements

- [ ] 95%+ test coverage
- [ ] All tests passing
- [ ] Security audit completed
- [ ] Red team testing completed
- [ ] Performance profiling completed
- [ ] Memory leak testing passed

#### Operational Requirements

- [ ] Build automation stable
- [ ] Release process documented
- [ ] Support infrastructure ready
- [ ] Monitoring and telemetry working
- [ ] Rollback procedures tested

**Current Progress:** ~70% complete (see [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md))

---

## Deprecation Policy

### Marking Features as Deprecated

**Timeline:**
1. Feature marked `@deprecated` in version X.Y.0
2. Warning messages logged when used
3. Feature removed in version (X+2).0.0

**Example:**
- Deprecated in 1.2.0
- Still functional (with warnings) in 1.x.x and 2.x.x
- Removed in 3.0.0

**Minimum Deprecation Period:** 2 major versions or 12 months, whichever is longer

### Communication

Deprecations announced in:
- Changelog (CHANGELOG.md)
- Migration guide
- API documentation
- Release notes
- Blog post (if significant)

---

## Release Schedule

### Current (Alpha Phase)

**Frequency:** As needed, no fixed schedule  
**Versioning:** 0.x.x-alpha with date-based builds  
**Communication:** Internal only

### Beta Phase (Future)

**Frequency:** Every 2-4 weeks  
**Versioning:** 0.x.x-beta.N  
**Communication:** Partner notifications, release notes

### Stable (Post-1.0)

**Frequency:**
- **Patch releases:** As needed (urgent bugs, security)
- **Minor releases:** Every 1-3 months
- **Major releases:** Every 6-12 months

**Support Windows:**
- **Current major version:** Full support
- **Previous major version:** Security updates for 6 months
- **Older versions:** No support

---

## Build Metadata

### Build Version Format

```
0.1.0-alpha+20260102.1234567
```

Components:
- `0.1.0-alpha`: Semantic version with pre-release label
- `+20260102`: Build date (YYYYMMDD)
- `.1234567`: Diversity seed (last 7 digits)

### Accessing Version at Runtime

```cpp
#include <SentinelSDK.hpp>

const char* version = Sentinel::SDK::GetVersion();
// Returns: "0.1.0-alpha+20260102.1234567"
```

---

## Changelog Management

**Location:** [docs/status/changelog.md](../status/changelog.md)

**Format:** [Keep a Changelog](https://keepachangelog.com/)

**Sections:**
- Added
- Changed
- Deprecated
- Removed
- Fixed
- Security

**Update Frequency:** Every release

---

## Communication Channels

### Release Announcements

- **Major/Minor Releases:** Email, blog post, GitHub release
- **Patch Releases:** GitHub release, changelog
- **Pre-releases:** GitHub pre-release tag

### Breaking Changes

**Notice Period:** Minimum 30 days for major versions  
**Advance Warning:** Announced in previous minor version  
**Migration Support:** Migration guide provided

---

## References

- [Semantic Versioning 2.0.0](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [Changelog](../status/changelog.md)
- [Implementation Status](../IMPLEMENTATION_STATUS.md)

---

**Policy Owner:** Engineering Team  
**Review Cycle:** Annually or before major releases
