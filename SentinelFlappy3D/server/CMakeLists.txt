# ============================================================================
# SentinelFlappy3D - Validation Server
# ============================================================================
# Minimal HTTP server for telemetry and heartbeat validation
# ============================================================================

cmake_minimum_required(VERSION 3.21)

project(SentinelFlappy3DServer
    VERSION 1.0.0
    DESCRIPTION "SentinelFlappy3D Validation Server"
    LANGUAGES CXX
)

# ============================================================================
# C++ Standard
# ============================================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# Dependencies
# ============================================================================

include(FetchContent)

# Fetch cpp-httplib (header-only HTTP server)
message(STATUS "Fetching cpp-httplib...")
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.14.3
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(httplib)

# Fetch nlohmann-json (JSON parsing)
message(STATUS "Fetching nlohmann-json...")
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(json)

# ============================================================================
# Source Files
# ============================================================================

set(SERVER_SOURCES
    main.cpp
    TelemetryHandler.cpp
    HeartbeatValidator.cpp
    SessionManager.cpp
)

set(SERVER_HEADERS
    TelemetryHandler.hpp
    HeartbeatValidator.hpp
    SessionManager.hpp
)

# ============================================================================
# Executable Target
# ============================================================================

add_executable(SentinelFlappy3DServer ${SERVER_SOURCES} ${SERVER_HEADERS})

target_include_directories(SentinelFlappy3DServer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ============================================================================
# Link Libraries
# ============================================================================

target_link_libraries(SentinelFlappy3DServer PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
)

# ============================================================================
# Platform-Specific Configuration
# ============================================================================

if(WIN32)
    target_compile_definitions(SentinelFlappy3DServer PRIVATE
        _WIN32_WINNT=0x0A00
        NOMINMAX
    )
elseif(UNIX AND NOT APPLE)
    target_link_libraries(SentinelFlappy3DServer PRIVATE
        pthread
    )
endif()

# ============================================================================
# Compiler Warnings
# ============================================================================

if(MSVC)
    target_compile_options(SentinelFlappy3DServer PRIVATE /W4)
else()
    target_compile_options(SentinelFlappy3DServer PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ============================================================================
# Post-Build Messages
# ============================================================================

add_custom_command(TARGET SentinelFlappy3DServer POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "  SentinelFlappy3DServer built successfully!"
    COMMAND ${CMAKE_COMMAND} -E echo "  Executable: $<TARGET_FILE:SentinelFlappy3DServer>"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
)
