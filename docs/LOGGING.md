# Sentinel Logging Infrastructure

This document describes the comprehensive logging infrastructure implemented for the Sentinel Security Ecosystem.

## Overview

The Sentinel logging system provides thread-safe, high-performance logging with multiple severity levels, automatic file rotation, and flexible output targets. It's designed to support diagnostics, debugging, and security event tracking.

## Features

- **Multiple Severity Levels**: Trace, Debug, Info, Warning, Error, Critical
- **Thread-Safe**: All operations are protected with mutexes for multi-threaded environments
- **File Logging**: Automatic log file rotation based on size
- **Console Output**: Color-coded severity levels (platform-dependent)
- **Flexible Output**: Console, file, callback, or any combination
- **Performance**: Optimized for minimal overhead with level filtering
- **Statistics**: Track message counts by severity level
- **Macros**: Convenient logging macros with file/line information

## Basic Usage

### Initialization

```cpp
#include "Sentinel/Core/Logger.hpp"

using namespace Sentinel::Core;

int main() {
    auto& logger = Logger::Instance();
    
    // Initialize with Info level, console output
    logger.Initialize(LogLevel::Info, LogOutput::Console);
    
    // Your application code here
    
    logger.Shutdown();
    return 0;
}
```

### File Logging

```cpp
// Initialize with file output
logger.Initialize(
    LogLevel::Debug,                    // Minimum log level
    LogOutput::Console | LogOutput::File, // Output targets
    "/var/log/sentinel.log",            // Log file path
    10                                  // Max file size in MB
);
```

### Logging Messages

```cpp
// Using the Logger directly
logger.Log(LogLevel::Info, "Application started");
logger.Log(LogLevel::Warning, "Memory usage high");
logger.Log(LogLevel::Error, "Failed to connect to server");

// Using formatted logging
logger.LogFormat(LogLevel::Info, "User %s logged in at %d", username, timestamp);
```

### Using Macros (Recommended)

The logging macros automatically include file name and line number:

```cpp
SENTINEL_LOG_TRACE("Detailed trace information");
SENTINEL_LOG_DEBUG("Debug information");
SENTINEL_LOG_INFO("General information");
SENTINEL_LOG_WARNING("Warning message");
SENTINEL_LOG_ERROR("Error occurred");
SENTINEL_LOG_CRITICAL("Critical security event");

// Formatted macros
SENTINEL_LOG_INFO_F("User %s connected from %s", user, ip);
SENTINEL_LOG_ERROR_F("Failed to allocate %d bytes", size);
```

## SDK Integration

The logging system is automatically integrated with the Sentinel SDK configuration:

```cpp
#include <SentinelSDK.hpp>

using namespace Sentinel::SDK;

Configuration config = Configuration::Default();
config.debug_mode = true;                              // Enable debug logging
config.log_path = "/var/log/sentinel_sdk.log";        // Set log file path
config.license_key = "your-license-key";
config.game_id = "your-game-id";

if (Initialize(&config) != ErrorCode::Success) {
    fprintf(stderr, "Failed to initialize Sentinel SDK\n");
    return -1;
}

// SDK operations are automatically logged based on debug_mode
Update();
FullScan();

Shutdown();
```

### SDK Log Levels

- `debug_mode = false`: Log level set to **Info** (production)
- `debug_mode = true`: Log level set to **Debug** (development)

## Log Output Format

Each log entry includes:
- **Timestamp**: `YYYY-MM-DD HH:MM:SS.mmm`
- **Thread ID**: `[thread_id]`
- **Severity**: `[TRACE|DEBUG|INFO |WARN |ERROR|CRIT ]`
- **Location**: `(filename:line)` (when using macros)
- **Message**: The actual log message

Example:
```
2026-01-01 13:09:24.107 [140328354658112] [INFO ] (main.cpp:42) Application started successfully
2026-01-01 13:09:24.108 [140328354658112] [WARN ] (network.cpp:156) Connection timeout, retrying...
2026-01-01 13:09:24.109 [140328354658112] [ERROR] (detection.cpp:89) Hook detected at address 0x7fff12345678
```

## Advanced Features

### Custom Callbacks

You can register a callback to receive log messages:

```cpp
logger.SetCallback([](LogLevel level, std::string_view message, 
                      std::chrono::system_clock::time_point timestamp) {
    // Custom handling, e.g., send to monitoring system
    if (level >= LogLevel::Error) {
        sendToMonitoring(message);
    }
});
```

### Level Filtering

```cpp
// Set minimum level dynamically
logger.SetMinLevel(LogLevel::Warning);  // Only Warning and above

// Check if a level is enabled
if (logger.IsLevelEnabled(LogLevel::Debug)) {
    // Expensive debug operation
}
```

### Statistics

```cpp
auto stats = logger.GetStatistics();
std::cout << "Info messages: " << stats.info << std::endl;
std::cout << "Error messages: " << stats.error << std::endl;
std::cout << "Dropped messages: " << stats.dropped << std::endl;

// Reset statistics
logger.ResetStatistics();
```

### Automatic Log Rotation

Log files are automatically rotated when they reach the configured size:
- Original file: `/var/log/sentinel.log`
- Rotated file: `/var/log/sentinel.log.20260101_130924`

### Disabling Logging

To completely disable logging (for release builds):

```cpp
// Define before including Logger.hpp
#define SENTINEL_DISABLE_LOGGING
#include "Sentinel/Core/Logger.hpp"

// All logging macros become no-ops
SENTINEL_LOG_DEBUG("This does nothing");
```

## Performance Considerations

1. **Level Filtering**: Messages below the minimum level are dropped early with minimal overhead
2. **Lazy Formatting**: Format strings are only evaluated if the level is enabled
3. **Thread Safety**: Minimal lock contention with fine-grained locking
4. **Buffering**: File writes are buffered by the OS for performance

Typical overhead:
- Filtered message: ~10-20 nanoseconds
- Console output: ~50-100 microseconds
- File output: ~20-50 microseconds (buffered)

## Best Practices

1. **Use appropriate levels**:
   - `Trace`: Very detailed, only for deep debugging
   - `Debug`: Development and diagnostic information
   - `Info`: General operational messages
   - `Warning`: Potential issues that don't stop execution
   - `Error`: Errors that affect functionality
   - `Critical`: Security events requiring immediate attention

2. **Use macros for location tracking**:
   ```cpp
   SENTINEL_LOG_ERROR("Failed to allocate memory");  // Good
   logger.Log(LogLevel::Error, "Failed to allocate memory");  // Missing file/line
   ```

3. **Check level before expensive operations**:
   ```cpp
   if (logger.IsLevelEnabled(LogLevel::Debug)) {
       std::string expensive_debug_info = generateDebugInfo();
       SENTINEL_LOG_DEBUG(expensive_debug_info.c_str());
   }
   ```

4. **Flush before critical operations**:
   ```cpp
   logger.Flush();  // Ensure logs are written to disk
   performCriticalOperation();
   ```

5. **Shutdown properly**:
   ```cpp
   logger.Shutdown();  // Flushes buffers and closes files
   ```

## Thread Safety

The Logger is fully thread-safe:
- Multiple threads can log simultaneously
- Singleton instance is thread-safe (guaranteed by C++11 magic statics)
- All public methods use mutex protection
- Log messages maintain order within each thread

## Security Considerations

1. **Sensitive Data**: Never log passwords, keys, or other sensitive information
2. **Log Injection**: Messages are not sanitized - ensure inputs are trusted
3. **File Permissions**: Log files should have appropriate permissions (e.g., 0600)
4. **Disk Space**: Monitor disk usage; rotated logs are not automatically deleted

## Example: Complete Integration

```cpp
#include "Sentinel/Core/Logger.hpp"
#include <SentinelSDK.hpp>

int main() {
    using namespace Sentinel::SDK;
    using namespace Sentinel::Core;
    
    // Configure and initialize SDK
    Configuration config = Configuration::Default();
    config.debug_mode = true;
    config.log_path = "/var/log/my_game.log";
    config.license_key = "your-license-key";
    config.game_id = "my-game-id";
    config.features = DetectionFeatures::Standard;
    
    if (Initialize(&config) != ErrorCode::Success) {
        SENTINEL_LOG_CRITICAL("Failed to initialize Sentinel SDK");
        return -1;
    }
    
    SENTINEL_LOG_INFO("Game started");
    
    // Game loop
    while (game_running) {
        Update();  // SDK updates are logged automatically
        
        // Your game logic
        updateGame();
        renderFrame();
    }
    
    SENTINEL_LOG_INFO("Game shutting down");
    Shutdown();
    
    return 0;
}
```

## Troubleshooting

### Logs not appearing

1. Check the minimum log level: `logger.SetMinLevel(LogLevel::Debug)`
2. Verify output targets: `logger.SetOutput(LogOutput::Console, true)`
3. Ensure logger is initialized: `logger.Initialize(...)`

### File not created

1. Check file path permissions
2. Verify disk space available
3. Check for errors: Failed open is printed to stderr

### Performance issues

1. Increase minimum log level in production
2. Disable trace/debug logging
3. Consider disabling file output for very high-frequency logging

## Future Enhancements

Planned improvements:
- Structured logging (JSON format)
- Remote logging (syslog, network)
- Log compression for rotated files
- Automatic cleanup of old log files
- Asynchronous logging queue

---

For more information, see:
- [API Documentation](api/Logger.html)
- [SDK Integration Guide](INTEGRATION_GUIDE.md)
- [Security Best Practices](SECURITY_INVARIANTS.md)
