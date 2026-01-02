# Changelog

All notable changes to the Sentinel SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### In Progress
- None - all initial documentation restructuring tasks complete

---

## [0.1.0-alpha] - 2026-01-02

### Added
- **Documentation restructuring** to improve navigation and organization
  - Created `docs/README.md` as central documentation hub
  - Created `docs/security/` directory with dedicated security documentation index
  - Created `docs/architecture/diversity.md` consolidating diversity documentation
  - Created `docs/internal/task-archive/` for historical task implementation notes
  - Created `docs/operations/releases.md` with versioning policy
  - Created this CHANGELOG.md
- **Integration guides consolidation**
  - Created `docs/integration/` directory with README navigation hub
  - Created `docs/integration/quickstart.md` (8-line integration)
  - Created `docs/integration/engine-specific.md` (Unreal, Unity, Godot)
  - Created `docs/integration/advanced.md` (production-ready integration)
- **Operations documentation structure**
  - Created `docs/operations/` directory with README navigation hub
  - Organized operator dashboard, server correlation, and enforcement docs
- **API stability documentation**
  - Added API stability guarantees section to api-reference.md
  - Documented unstable alpha status and roadmap to stability

### Changed
- **Performance documentation** updated to reflect actual measurements vs. aspirational targets
  - Changed from "Target/Current" format to "Current Measurement/Target Goal"
  - Added "optimization in progress" notes
  - Updated all performance references in README.md
- **Implementation status documentation** significantly enhanced
  - Added CorrelationEngine status with known 7 test failures
  - Distinguished SDK Heartbeat (stub) from Core Heartbeat (fully implemented)
  - Updated HttpClient status to reflect full cURL implementation
  - Updated CloudReporter status to ~80% implementation level
  - Added AESCipher TestAccess security consideration
  - Updated date to 2026-01-02
- **Security documentation** reorganized
  - Moved to `docs/security/` directory
  - Files renamed to lowercase with hyphens (e.g., `defensive-gaps.md`)
  - Added comprehensive security documentation index
- **Diversity documentation** consolidated
  - Merged BUILD_DIVERSITY.md, CLIENT_DIVERSITY.md, and DIVERSITY_IMPLEMENTATION.md
  - Created single comprehensive `docs/architecture/diversity.md`
  - Original files archived to `docs/internal/task-archive/deprecated/`

### Deprecated
- Multiple overlapping documentation files (now archived):
  - `docs/BUILD_DIVERSITY.md` → `docs/architecture/diversity.md`
  - `docs/CLIENT_DIVERSITY.md` → `docs/architecture/diversity.md`
  - `docs/DIVERSITY_IMPLEMENTATION.md` → `docs/architecture/diversity.md`
  - `docs/INTEGRATION_GUIDE.md` → `docs/integration/advanced.md`
  - `docs/integration-guide.md` → `docs/integration/engine-specific.md`
  - `docs/STUDIO_INTEGRATION_GUIDE.md` → `docs/integration/quickstart.md`

### Removed
- Task implementation notes moved from `docs/` root to `docs/internal/task-archive/`
  - 15 TASK_*.md files archived
  - IMPLEMENTATION_SUMMARY_OLD.md archived
  - README.md.old archived
- Uppercase security documentation files removed from docs root (moved to docs/security/)
  - DEFENSIVE_GAPS.md → security/defensive-gaps.md
  - KNOWN_BYPASSES.md → security/known-bypasses.md
  - SECURITY_INVARIANTS.md → security/security-invariants.md
  - REDTEAM_ATTACK_SURFACE.md → security/redteam-attack-surface.md
  - DETECTION_CONFIDENCE_MODEL.md → security/detection-confidence-model.md
  - ANALYSIS_RESISTANCE.md → security/analysis-resistance.md
- Integration guide files consolidated and moved to `docs/integration/`
  - INTEGRATION_GUIDE.md → integration/advanced.md
  - integration-guide.md → integration/engine-specific.md
  - STUDIO_INTEGRATION_GUIDE.md → integration/quickstart.md
- Operations documentation files moved to `docs/operations/`
  - OPERATOR_DASHBOARD_SPECIFICATION.md → operations/
  - DASHBOARD_TELEMETRY_MAPPING.md → operations/
  - SERVER_ENFORCEMENT_PROTOCOL.md → operations/
  - SERVER_BEHAVIORAL_PROCESSING.md → operations/
  - SERVER_SIDE_DETECTION_CORRELATION.md → operations/

### Fixed
- Broken documentation links throughout README.md, docs/README.md, and examples/README.md
- Fixed integration guide references in COMMERCIAL_OFFERING.md, COMPETITIVE_COMPARISON.md, api-reference.md
- Fixed operations document references throughout documentation
- Misleading performance claims in README.md
- Inconsistent file naming (uppercase vs lowercase)
- Documentation namespace pollution (too many files in root)

### Security
- Added note about AESCipher TestAccess class security consideration in production builds
- Documented CorrelationEngine stability issues (7 test failures)
- Clarified that Heartbeat is implemented in Core but SDK integration is pending

---

## Project Status

**Current Version:** 0.1.0-alpha  
**Production Ready:** No  
**API Stability:** Unstable (breaking changes expected)

### Known Issues

1. **CorrelationEngine:** 7 test failures with segmentation faults (not production-ready)
2. **Performance:** Update() at ~0.46ms (target: <0.1ms), FullScan() at ~7-10ms (target: <5ms)
3. **SDK Heartbeat:** Integration pending (Core implementation complete)
4. **Certificate Pinning:** Not implemented (MITM possible)
5. **Memory Protection API:** Not implemented (stub only)
6. **Value Protection API:** Not implemented (stub only)

### Completed Features

- ✅ Anti-debug detection (with known gaps)
- ✅ Anti-hook detection (TOCTOU in periodic scans)
- ✅ Integrity checking (basic code section hashing)
- ✅ Injection detection (needs JIT whitelist tuning)
- ✅ Cryptographic primitives (AES-256-GCM, SHA-256, RSA, HMAC)
- ✅ Build-time diversity infrastructure
- ✅ Core Heartbeat implementation (SDK integration pending)
- ✅ HTTP client with cURL support
- ✅ CloudReporter (~80% implemented)
- ✅ Safe memory operations
- ✅ Thread whitelist configuration

See [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md) for detailed feature status.

---

## Version History

### Version Schema
- `0.x.x-alpha`: Pre-release, unstable, breaking changes expected
- `0.x.x-beta`: Feature-complete, testing phase
- `0.x.x-rc`: Release candidate, production-ready candidate
- `1.0.0`: First stable release

### Roadmap to 1.0.0

**Blocking Issues:**
- Fix CorrelationEngine test failures
- Achieve performance targets
- Complete certificate pinning
- Complete SDK Heartbeat integration
- Implement memory and value protection APIs
- Complete security audit
- Achieve <1% false positive rate

**Current Progress:** ~70% complete

See [releases.md](../operations/releases.md) for detailed versioning policy.

---

## Contributing

Before contributing, please read:
- [CONTRIBUTING.md](../../CONTRIBUTING.md) - Contribution guidelines
- [releases.md](../operations/releases.md) - Versioning and release policy
- [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md) - Current implementation status

---

## Links

- [GitHub Repository](https://github.com/Lovuwer/Sentiel-RE)
- [Documentation Hub](../README.md)
- [Implementation Status](../IMPLEMENTATION_STATUS.md)
- [Versioning Policy](../operations/releases.md)

---

**Changelog Format:** [Keep a Changelog](https://keepachangelog.com/)  
**Versioning:** [Semantic Versioning](https://semver.org/)  
**Last Updated:** 2026-01-02
