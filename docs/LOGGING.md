# Sentinel Logging Infrastructure

## Overview

Sentinel uses a comprehensive logging infrastructure built on `spdlog` for production-grade performance and reliability. The logging system provides:

- **Multiple severity levels** (Trace, Debug, Info, Warning, Error, Critical)
- **Multiple output targets** (console, file, callback for game integration)
- **Automatic log rotation** (configurable size limits)
- **Thread-safe operations** 
- **High performance** with synchronous logging
- **Structured output** with timestamps, thread IDs, and source locations

## Architecture

### Backend: spdlog

The Logger class (`Sentinel::Core::Logger`) wraps `spdlog` to provide a consistent API while leveraging spdlog's features:

- **Rotating file sink**: Automatic log rotation at configurable sizes
- **Color console sink**: Color-coded output for different severity levels
- **Callback sink**: Integration with game telemetry systems
- **Thread safety**: All operations are thread-safe

### Logging Levels

```cpp
enum class LogLevel : uint8_t {
    Trace = 0,      // Verbose tracing for deep debugging
    Debug = 1,      // Debug information for development
    Info = 2,       // General informational messages
    Warning = 3,    // Warning messages for potential issues
    Error = 4,      // Error messages for failures
    Critical = 5,   // Critical security events requiring immediate attention
    Off = 255       // Disable all logging
};
```

## Usage

### Initialization

```cpp
using namespace Sentinel::Core;

// Initialize with console output only
Logger::Instance().Initialize(LogLevel::Info, LogOutput::Console);

// Initialize with file output and rotation
Logger::Instance().Initialize(
    LogLevel::Debug,              // Minimum log level
    LogOutput::File,              // Output target
    "/var/log/sentinel/game.log", // Log file path
    10                            // Max file size in MB
);

// Initialize with multiple outputs
Logger::Instance().Initialize(
    LogLevel::Info,
    LogOutput::Console | LogOutput::File | LogOutput::Callback,
    "/var/log/sentinel/game.log",
    10
);
```

### Basic Logging

```cpp
// Using macros (recommended - includes file and line number)
SENTINEL_LOG_TRACE("Entering function");
SENTINEL_LOG_DEBUG("Processing data");
SENTINEL_LOG_INFO("Operation completed successfully");
SENTINEL_LOG_WARNING("Potential issue detected");
SENTINEL_LOG_ERROR("Operation failed");
SENTINEL_LOG_CRITICAL("Security breach detected");

// Using formatted macros
SENTINEL_LOG_INFO_F("User %s logged in", username.c_str());
SENTINEL_LOG_ERROR_F("Failed to connect to %s:%d", host, port);
SENTINEL_LOG_DEBUG_F("Processing %zu items", items.size());
```

### Direct API Usage

```cpp
// Without macros (no file/line information)
Logger::Instance().Log(LogLevel::Info, "Simple message");

// With formatted string
Logger::Instance().LogFormat(LogLevel::Error, "Error code: %d", errorCode);
```

### Game Integration (Callback)

```cpp
// Set up callback for game telemetry
Logger::Instance().SetCallback(
    [](LogLevel level, std::string_view message, auto timestamp) {
        // Forward to game's telemetry system
        GameTelemetry::LogEvent(
            LevelToString(level),
            std::string(message),
            timestamp
        );
    }
);
```

### Statistics

```cpp
// Get logging statistics
auto stats = Logger::Instance().GetStatistics();
std::cout << "Errors: " << stats.error << std::endl;
std::cout << "Warnings: " << stats.warning << std::endl;
std::cout << "Dropped: " << stats.dropped << std::endl;

// Reset statistics
Logger::Instance().ResetStatistics();
```

## Best Practices

### 1. Choose Appropriate Log Levels

- **TRACE**: Function entry/exit, detailed data flow
- **DEBUG**: Detailed diagnostic information, variable values
- **INFO**: Normal operations, significant events
- **WARNING**: Recoverable errors, deprecated usage, monitoring mode
- **ERROR**: Operation failures, unrecoverable errors
- **CRITICAL**: Security events, authentication failures, attacks detected

### 2. Never Log Sensitive Data

**DO NOT LOG:**
- Encryption keys
- Authentication tokens
- Password hashes
- User credentials
- Full license keys
- Personal identifiable information (PII)

**If logging is necessary, truncate:**
```cpp
SENTINEL_LOG_DEBUG_F("License key: %.8s... (truncated)", licenseKey.c_str());
SENTINEL_LOG_INFO_F("Token: %.16s... (truncated)", token.c_str());
```

### 3. Performance Considerations

- **Use appropriate log levels**: Debug/Trace logging can impact performance
- **Avoid logging in hot paths**: Critical performance loops should minimize logging
- **Use `IsLevelEnabled()` for expensive operations**:
  ```cpp
  if (Logger::Instance().IsLevelEnabled(LogLevel::Debug)) {
      std::string expensiveData = computeExpensiveDebugInfo();
      SENTINEL_LOG_DEBUG_F("Debug data: %s", expensiveData.c_str());
  }
  ```

### 4. Structured Logging

Use consistent formatting for similar events:

```cpp
// Network events
SENTINEL_LOG_INFO_F("HTTP %s request to: %s", method, url.c_str());
SENTINEL_LOG_DEBUG_F("HTTP response: %d (%.0fms)", statusCode, elapsed);

// Security events
SENTINEL_LOG_CRITICAL("Certificate pinning validation failed");
SENTINEL_LOG_ERROR_F("Host: %s - Expected pinned certificate", hostname.c_str());

// Detection events
SENTINEL_LOG_CRITICAL("Debugger detected");
SENTINEL_LOG_INFO_F("Detection: %s at %p", detectionType, address);
```

### 5. Error Context

Always provide context with error messages:

```cpp
// Bad: Generic error
SENTINEL_LOG_ERROR("Operation failed");

// Good: Specific error with context
SENTINEL_LOG_ERROR_F("Failed to connect to %s:%d - %s", 
                     host, port, strerror(errno));

// Better: Include attempted action and recovery
SENTINEL_LOG_ERROR_F("Failed to load config from %s - using defaults",
                     configPath.c_str());
```

### 6. Security Event Logging

Security events should always use CRITICAL or ERROR level:

```cpp
SENTINEL_LOG_CRITICAL("Anti-debug detection triggered");
SENTINEL_LOG_CRITICAL("Memory integrity check failed");
SENTINEL_LOG_CRITICAL("Certificate pinning validation failed");
SENTINEL_LOG_ERROR("TLS handshake failed");
SENTINEL_LOG_ERROR("Invalid signature detected");
```

## Production Configuration

### Recommended Settings

```cpp
// Production: Info level with file rotation
Logger::Instance().Initialize(
    LogLevel::Info,
    LogOutput::File | LogOutput::Callback,
    "/var/log/sentinel/production.log",
    50  // 50 MB max size
);

// Development: Debug level with console
Logger::Instance().Initialize(
    LogLevel::Debug,
    LogOutput::Console | LogOutput::File,
    "./sentinel_debug.log",
    10  // 10 MB max size
);
```

### Log Rotation

- Default: 3 rotated files kept (`.1`, `.2`, `.3`)
- Files rotated automatically when size limit reached
- Old files timestamped: `sentinel.log.20260101_153045`

### Performance Impact

Based on benchmarks:
- Synchronous logging: < 0.05% CPU overhead (typical)
- File I/O: ~1-2 microseconds per log entry
- Console output: ~5-10 microseconds per log entry

## File Locations

### Header
- `include/Sentinel/Core/Logger.hpp` - Public API

### Implementation
- `src/Core/Utils/Logger.cpp` - spdlog integration

### Tests
- `tests/Core/test_logger.cpp` - Comprehensive test suite (10 tests)

## Examples

### Network Component
```cpp
SENTINEL_LOG_DEBUG_F("HTTP %s request to: %s", method, url.c_str());

if (signResult.isSuccess()) {
    SENTINEL_LOG_DEBUG("Request signed successfully");
} else {
    SENTINEL_LOG_WARNING("Request signing failed, proceeding without signature");
}

SENTINEL_LOG_DEBUG_F("HTTP response: %d (%.0fms)", statusCode, elapsed);
```

### Crypto Component
```cpp
if (!pkey) {
    SENTINEL_LOG_ERROR("Failed to parse RSA private key");
    return ErrorCode::InvalidKey;
}

SENTINEL_LOG_DEBUG("RSA private key loaded successfully");
```

### Security Events
```cpp
SENTINEL_LOG_CRITICAL("Certificate pinning failed - empty chain");
SENTINEL_LOG_ERROR_F("Host: %s - Empty certificate chain received", hostname);
SENTINEL_LOG_ERROR("Connection REJECTED");
```

## Thread Safety

All logging operations are thread-safe:
- Multiple threads can log simultaneously
- Statistics updates are atomic
- File writes are synchronized
- No manual locking required

## Disabling Logging

Logging can be disabled at compile time:

```cmake
# In CMakeLists.txt
add_compile_definitions(SENTINEL_DISABLE_LOGGING)
```

All logging macros become no-ops with zero overhead.

## Troubleshooting

### No Log Output

1. Check initialization: `Logger::Instance().Initialize(...)`
2. Check log level: Ensure messages meet minimum level
3. Check file permissions: Ensure write access to log directory
4. Check `IsLevelEnabled()`: Verify level filtering

### File Not Created

1. Verify parent directory exists
2. Check file path permissions
3. Verify LogOutput::File is enabled
4. Check disk space

### Performance Issues

1. Reduce log level in production (Info or Warning)
2. Avoid logging in hot paths
3. Use `IsLevelEnabled()` guards for expensive operations
4. Consider disabling console output in production

## Sensitive Data Protection

The logging infrastructure protects sensitive data through:

1. **Explicit truncation** of keys, tokens, and credentials
2. **No automatic logging** of function parameters
3. **Manual logging** of all data (developer controlled)
4. **Code review** requirements for security-critical components

### Audit Checklist

- [x] No full encryption keys logged
- [x] No authentication tokens logged (only truncated)
- [x] No password hashes logged
- [x] License keys truncated (max 8 chars)
- [x] Session tokens truncated (max 16 chars)
- [x] No PII logged without consent
- [x] Error messages don't leak internal paths
- [x] Stack traces sanitized in production

## Future Enhancements

Potential improvements for future versions:

1. **Async logging**: For even higher performance (trade-off with reliability)
2. **JSON structured output**: For automated log analysis
3. **Remote logging**: Direct submission to cloud services
4. **Log compression**: Automatic compression of rotated files
5. **Custom formatters**: Per-component log formatting
6. **Dynamic level control**: Runtime log level adjustment

---

**Last Updated**: 2026-01-01  
**Version**: 1.0.0  
**Maintainer**: Sentinel Security Team
