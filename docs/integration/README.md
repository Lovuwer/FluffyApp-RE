# Integration Guides

This directory contains guides for integrating the Sentinel SDK into your game.

---

## Start Here

**New to Sentinel?** Start with the [Quickstart Guide](quickstart.md).

---

## Guides Overview

### [Quickstart Guide](quickstart.md) ⭐ **START HERE**

**Audience:** Game developers  
**Time:** 30 minutes for basic integration  
**Focus:** Minimal 8-line integration

The fastest way to get Sentinel running in your game. Perfect for:
- First-time users
- Proof-of-concept integration
- Studios evaluating Sentinel

**What you'll learn:**
- 8-line minimal integration
- Configuration basics
- Platform-specific setup
- Quick troubleshooting

---

### [Engine-Specific Guide](engine-specific.md)

**Audience:** Game developers using specific engines  
**Time:** 2-4 hours  
**Focus:** Engine-specific integration patterns

Detailed integration instructions for popular game engines:
- Unreal Engine
- Unity
- Godot Engine
- Custom C++ engines

**What you'll learn:**
- Engine-specific setup steps
- Build system integration
- Platform considerations
- Engine-specific troubleshooting

---

### [Advanced Integration Guide](advanced.md)

**Audience:** Experienced developers, production deployments  
**Time:** 4+ hours  
**Focus:** Production-ready integration with all features

Comprehensive guide covering all aspects of Sentinel integration:
- Threading requirements
- Memory management
- Performance optimization
- Production vs test builds
- Debugging integration issues
- Red-team security observations

**What you'll learn:**
- Complete API reference
- Advanced configuration
- Performance tuning
- Common mistakes to avoid
- Security best practices
- Production deployment

---

## Quick Reference

### Choose Your Path

| Your Situation | Recommended Guide |
|----------------|-------------------|
| Just evaluating Sentinel | [Quickstart](quickstart.md) |
| Using Unreal/Unity/Godot | [Engine-Specific](engine-specific.md) |
| Production deployment | [Advanced](advanced.md) |
| Need all the details | [Advanced](advanced.md) |

### Integration Steps (All Paths)

1. **Prerequisites**: Install CMake, C++20 compiler, OpenSSL
2. **Link SDK**: Add Sentinel SDK to your build system
3. **Initialize**: Call `Sentinel::SDK::Initialize()` at startup
4. **Update**: Call `Sentinel::SDK::Update()` once per frame
5. **Shutdown**: Call `Sentinel::SDK::Shutdown()` on exit

### Getting Help

- **Troubleshooting**: See quickstart guide troubleshooting section
- **API Reference**: See [api-reference.md](../api-reference.md)
- **Examples**: See [examples/](../../examples/)
- **Platform Guides**: See [platform/](../platform/)

---

## Related Documentation

- [API Reference](../api-reference.md) - Complete API documentation
- [Examples](../../examples/) - Working code examples
- [Platform Quickstarts](../platform/) - Windows/Linux specific setup
- [Performance Telemetry](../PERFORMANCE_TELEMETRY.md) - Performance monitoring
- [Troubleshooting](../troubleshooting.md) - Common issues and solutions

---

**Last Updated:** 2026-01-02  
**Consolidates:** STUDIO_INTEGRATION_GUIDE.md, INTEGRATION_GUIDE.md, integration-guide.md
