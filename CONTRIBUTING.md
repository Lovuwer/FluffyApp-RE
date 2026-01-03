# Contributing to Sentinel Security Ecosystem

Thank you for your interest in contributing to Sentinel! This document provides guidelines for contributing to the project.

## 🎯 Current Development Phase

We are currently in **Phase 1: Foundation Setup**. The focus is on establishing a solid build infrastructure and creating stub implementations for all components.

## 📋 How to Contribute

### Reporting Issues

- Use the GitHub issue tracker to report bugs
- Check if the issue has already been reported
- Provide detailed information:
  - Operating system and version
  - Build configuration (CMake options)
  - Steps to reproduce
  - Expected vs actual behavior
  - Error messages and logs

### Submitting Pull Requests

1. **Fork the repository** and create a new branch from `develop`
2. **Follow the coding standards** (see below)
3. **Write tests** for new functionality
4. **Update documentation** as needed
5. **Ensure builds pass** on all platforms
6. **Submit a pull request** with a clear description

### Coding Standards

#### C++ Style Guide

- **C++ Standard:** C++20
- **Naming Conventions:**
  - Classes: `PascalCase` (e.g., `MemoryScanner`)
  - Functions: `PascalCase` (e.g., `Initialize()`)
  - Variables: `camelCase` (e.g., `configValue`)
  - Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_BUFFER_SIZE`)
  - Private members: `m_camelCase` or `camelCase_`

- **Code Organization:**
  - Header files in `include/Sentinel/`
  - Implementation files in `src/`
  - One class per file when possible
  - Use forward declarations to reduce dependencies

- **Comments:**
  - Use Doxygen-style comments for public APIs
  - Keep comments concise and meaningful
  - Explain "why", not "what" (code should be self-explanatory)

#### Example

```cpp
/**
 * @brief Scans memory for specific patterns
 * @param pattern The byte pattern to search for
 * @param region The memory region to scan
 * @return Vector of matching addresses
 */
std::vector<uintptr_t> ScanMemory(
    const Pattern& pattern,
    const MemoryRegion& region);
```

### CMake Conventions

- Use modern CMake (3.21+)
- Prefer target-based commands over global settings
- Use `target_*` commands instead of global `add_*` commands
- Keep platform-specific code isolated with guards

### Testing

- Write unit tests for all new functionality
- Use Google Test framework
- Aim for 80%+ code coverage
- Tests should be fast, isolated, and deterministic

### Documentation

- Update README.md for user-facing changes
- Update inline comments for API changes
- Use Doxygen for API documentation
- Keep documentation in sync with code

## 🔍 Code Review Process

All submissions require review before merging:

1. Automated checks must pass (build, tests, linting)
2. At least one maintainer approval required
3. All comments must be addressed
4. Squash commits before merge

## 📦 Project Structure

```
Sentinel/
├── include/Sentinel/     # Public API headers
├── src/                  # Implementation files
│   ├── Core/            # Core library
│   ├── SDK/             # In-game SDK
│   ├── Cortex/          # GUI application
│   └── Watchtower/      # Roblox module
├── tests/               # Unit tests
├── docs/                # Documentation
└── cmake/               # CMake modules
```

## 🚀 Development Workflow

### Setting Up Development Environment

```bash
# Clone with submodules
git clone --recursive https://github.com/Lovuwer/Sentiel-RE.git
cd Sentiel-RE

# Create build directory
cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Debug \
  -DSENTINEL_BUILD_TESTS=ON

# Build
cmake --build build

# Run tests
cd build && ctest
```

### Before Submitting

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Code follows style guide
- [ ] Commit messages are clear

## 🛡️ Memory Safety

All PRs must pass AddressSanitizer (ASAN) and ThreadSanitizer (TSAN) checks.  
If your PR introduces a memory error or data race, CI will fail.

### Running Sanitizers Locally

**AddressSanitizer (detects memory errors):**
```bash
cmake -B build -DSENTINEL_ENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=Debug \
  -DSENTINEL_BUILD_TESTS=ON
cmake --build build && cd build && ctest
```

**ThreadSanitizer (detects data races):**
```bash
cmake -B build -DSENTINEL_ENABLE_TSAN=ON -DCMAKE_BUILD_TYPE=Debug \
  -DSENTINEL_BUILD_TESTS=ON
cmake --build build && cd build && ctest
```

### Understanding Sanitizer Failures

- **ASAN errors**: Memory leaks, buffer overflows, use-after-free, etc.
- **TSAN errors**: Data races, deadlocks, thread safety issues

Both sanitizers will print detailed error reports showing:
- The type of error detected
- Stack traces of the problematic code
- Memory addresses and access patterns

Fix all sanitizer errors before submitting your PR. The CI pipeline will automatically run these checks on all pull requests.

## 🐛 Common Issues

### Build Failures

- Ensure CMake 3.21+ is installed
- Clear build directory: `rm -rf build/`
- Check dependencies are installed
- Verify compiler version (GCC 11+, Clang 14+, MSVC 19.30+)

### Platform-Specific Code

- Use `#ifdef _WIN32` for Windows-only code
- Provide Linux alternatives where possible
- Test on both platforms if changes affect both

## 📞 Contact

- GitHub Issues: For bug reports and feature requests
- GitHub Discussions: For questions and general discussion
- Email: [Insert contact email]

## 📄 License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to Sentinel Security Ecosystem! 🛡️
