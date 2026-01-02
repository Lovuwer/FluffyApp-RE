# Sentinel SDK Documentation

Welcome to the Sentinel SDK documentation. This page serves as the central navigation hub for all documentation.

---

## Start Here

**Choose your path based on your role:**

### 🎮 Game Developers
Start with integration guides to add Sentinel to your game:
- [Studio Integration Guide](STUDIO_INTEGRATION_GUIDE.md) - **Start here**: 8 lines of code integration
- [Integration Guide](INTEGRATION_GUIDE.md) - Complete integration guide with best practices
- [Platform Quickstarts](platform/) - Windows/Linux specific guides
- [Examples](../examples/) - Working code examples

### 🔒 Security Engineers
Understand the security model and limitations:
- [Security Documentation](security/) - **Start here**: Complete security documentation hub
- [Red Team Attack Surface](security/redteam-attack-surface.md) - Attack strategies per subsystem
- [Defensive Gaps](security/defensive-gaps.md) - What cannot be defended
- [Known Bypasses](security/known-bypasses.md) - Catalog of known bypass techniques
- [Security Invariants](security/security-invariants.md) - Non-negotiable security requirements
- [Implementation Status](IMPLEMENTATION_STATUS.md) - What's actually implemented vs documented

### 🏢 Operators & Backend Engineers
Deploy and monitor the backend systems:
- [Operator Dashboard Specification](OPERATOR_DASHBOARD_SPECIFICATION.md)
- [Server-Side Detection Correlation](SERVER_SIDE_DETECTION_CORRELATION.md)
- [Server Enforcement Protocol](SERVER_ENFORCEMENT_PROTOCOL.md)

### 📐 System Architects
Understand the architecture and design decisions:
- [Architecture Documentation](architecture/ARCHITECTURE.md) - System architecture with trust boundaries
- [Build Diversity](BUILD_DIVERSITY.md) - Build-time diversification to break universal bypasses
- [Client Diversity](CLIENT_DIVERSITY.md) - Client diversity infrastructure

---

## Documentation Categories

### Integration & Quickstart
Getting Sentinel SDK integrated into your game:
- [Studio Integration Guide](STUDIO_INTEGRATION_GUIDE.md) - Minimal 8-line integration
- [Integration Guide](INTEGRATION_GUIDE.md) - Complete integration guide
- [Platform Quickstarts](platform/) - Platform-specific guides (Windows, Linux)
- [integration-guide.md](integration-guide.md) - Engine-specific integration (Unreal, Unity, Godot)
- [Examples](../examples/) - Working code examples

### API Reference
Detailed API documentation:
- [API Reference](api-reference.md) - Public API documentation
- [Doxygen Documentation](api/) - Auto-generated API reference

### Architecture & Implementation
Understanding the system design:
- [Architecture](architecture/ARCHITECTURE.md) - System architecture with trust boundaries
- [Diversity](architecture/diversity.md) - Build-time diversification infrastructure
- [Implementation Status](IMPLEMENTATION_STATUS.md) - What's actually implemented
- [Memory Module Implementation](MEMORY_MODULE_IMPLEMENTATION.md) - Reflective loading details

### Security Documentation
Security model, threats, and limitations:
- [Security Documentation Hub](security/README.md) - **Start here**: Complete security documentation index
- [Red Team Attack Surface](security/redteam-attack-surface.md) - Attack strategies per subsystem
- [Defensive Gaps](security/defensive-gaps.md) - What cannot be defended
- [Known Bypasses](security/known-bypasses.md) - High-level bypass classes
- [Security Invariants](security/security-invariants.md) - Non-negotiable security requirements
- [Detection Confidence Model](security/detection-confidence-model.md) - Signal strength and bypass cost
- [Analysis Resistance](security/analysis-resistance.md) - Anti-analysis techniques

### Operations & Backend
Server-side components and operations:
- [Operator Dashboard Specification](OPERATOR_DASHBOARD_SPECIFICATION.md) - Dashboard requirements
- [Dashboard Telemetry Mapping](DASHBOARD_TELEMETRY_MAPPING.md) - Telemetry data mapping
- [Server-Side Detection Correlation](SERVER_SIDE_DETECTION_CORRELATION.md) - Server correlation logic
- [Server Enforcement Protocol](SERVER_ENFORCEMENT_PROTOCOL.md) - Enforcement protocol spec
- [Server Behavioral Processing](SERVER_BEHAVIORAL_PROCESSING.md) - Behavioral analysis server-side
- [Control Plane Separation](CONTROL_PLANE_SEPARATION.md) - Architecture separation

### Telemetry & Monitoring
Understanding telemetry data:
- [Behavioral Telemetry Guide](BEHAVIORAL_TELEMETRY_GUIDE.md) - Behavioral telemetry overview
- [Performance Telemetry](PERFORMANCE_TELEMETRY.md) - Performance metrics
- [Telemetry Correlation Protocol](TELEMETRY_CORRELATION_PROTOCOL.md) - Correlation protocol
- [Telemetry Schema](telemetry/behavioral_telemetry_schema.md) - Telemetry data schema

### Configuration & Features
Configuring SDK features:
- [Thread Whitelist Configuration](THREAD_WHITELIST_CONFIGURATION.md) - Thread whitelisting
- [JIT Signature Database](JIT_SIGNATURE_DATABASE.md) - JIT compiler signatures
- [Signature Update Mechanism](SIGNATURE_UPDATE_MECHANISM.md) - Signature updates
- [HTTP Client Implementation](http_client_implementation.md) - HTTP client details
- [Logging](LOGGING.md) - Logging configuration

### Advanced Topics
Deep dives and specialized topics:
- [ObfuscatedString](ObfuscatedString.md) - String obfuscation implementation
- [ObfuscatedString Summary](ObfuscatedString_Summary.md) - String obfuscation overview
- [Code Examples](examples/) - Advanced code examples
- [Manual Verification Optimizer Resistance](MANUAL_VERIFICATION_OPTIMIZER_RESISTANCE.md)
- [Dummy Game Validation](DUMMY_GAME_VALIDATION.md) - Real-world testing results

### Commercial & Business
Business and commercial information:
- [Commercial Offering](COMMERCIAL_OFFERING.md) - Product offering
- [Competitive Comparison](COMPETITIVE_COMPARISON.md) - Market comparison
- [Pricing & Packaging](PRICING_PACKAGING.md) - Pricing structure
- [Support Tiers](SUPPORT_TIERS.md) - Support options
- [SDK Distribution Guide](SDK_DISTRIBUTION_GUIDE.md) - Distribution guidelines
- [Data Privacy Policy](DATA_PRIVACY_POLICY.md) - Privacy and data handling

### Testing & Validation
Testing and validation documentation:
- [Dummy Game Validation](DUMMY_GAME_VALIDATION.md) - Real-world integration testing
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [Repository Audit](repo_audit/) - Internal code audit results

### Project Status & History
Understanding project status and history:
- [Implementation Status](IMPLEMENTATION_STATUS.md) - Current implementation status
- [Changelog](status/changelog.md) - Version history and changes
- [Release Policy](operations/releases.md) - Versioning and release process
- [Internal Archive](internal/task-archive/) - Historical task documentation

### Roadmap & Future
Future development plans:
- [Phase 3: Cortex GUI](phase3-cortex-gui.md) - Future dashboard plans

---

## Quick Links

### Most Common Tasks
- **Integrate SDK**: Start with [Studio Integration Guide](STUDIO_INTEGRATION_GUIDE.md)
- **Understand Security**: Read [Security Documentation Hub](security/README.md)
- **Check Status**: See [Implementation Status](IMPLEMENTATION_STATUS.md)
- **Review Changes**: See [Changelog](status/changelog.md)
- **Understand Versioning**: See [Release Policy](operations/releases.md)
- **Configure Backend**: Start with [Operator Dashboard](OPERATOR_DASHBOARD_SPECIFICATION.md)
- **API Reference**: See [api-reference.md](api-reference.md)

### External Links
- [GitHub Repository](https://github.com/Lovuwer/Sentiel-RE)
- [Main README](../README.md)
- [Examples](../examples/)
- [Contributing Guide](../CONTRIBUTING.md)

---

## Documentation Organization

Documentation is organized into subdirectories by topic:
- `architecture/` - System architecture and design
- `platform/` - Platform-specific guides
- `security/` - Security documentation hub
- `operations/` - Operations and deployment documentation
- `status/` - Project status and changelog
- `telemetry/` - Telemetry schemas and guides
- `examples/` - Code examples
- `repo_audit/` - Internal audit documentation
- `internal/` - Internal documentation and archives

---

**Last Updated:** 2026-01-02
**Version:** Alpha (pre-1.0)
