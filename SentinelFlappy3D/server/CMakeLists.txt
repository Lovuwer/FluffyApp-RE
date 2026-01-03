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

# Note: cpp-httplib will be added via FetchContent in later steps
# For now, just document the requirement

message(STATUS "Server CMakeLists.txt configured")
message(STATUS "  Server implementation will be added in Step 9")
message(STATUS "  Dependencies (cpp-httplib, nlohmann-json) will be configured in Step 9")

# ============================================================================
# Source Files
# ============================================================================

set(SERVER_SOURCES
    # Server sources (to be created in future steps)
    # main.cpp
    # TelemetryHandler.cpp
    # HeartbeatValidator.cpp
    # SessionManager.cpp
)

set(SERVER_HEADERS
    # Server headers (to be created in future steps)
    # TelemetryHandler.hpp
    # HeartbeatValidator.hpp
    # SessionManager.hpp
)

# ============================================================================
# Executable Target
# ============================================================================

# Note: Executable will be created once source files exist
# For now, this is a skeleton that will be populated in later steps

# ============================================================================
# Future Configuration Notes
# ============================================================================

# When implementing Step 9:
# - Add cpp-httplib via FetchContent
# - Add nlohmann-json via FetchContent
# - Create executable: add_executable(SentinelFlappy3DServer ${SERVER_SOURCES})
# - Link dependencies

# Example FetchContent for cpp-httplib:
# include(FetchContent)
# FetchContent_Declare(
#     httplib
#     GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
#     GIT_TAG v0.14.3
# )
# FetchContent_MakeAvailable(httplib)

# Example FetchContent for nlohmann-json:
# FetchContent_Declare(
#     json
#     GIT_REPOSITORY https://github.com/nlohmann/json.git
#     GIT_TAG v3.11.3
# )
# FetchContent_MakeAvailable(json)

# ============================================================================
# Platform-Specific Configuration
# ============================================================================

# Windows-specific settings (for future)
# if(WIN32)
#     target_compile_definitions(SentinelFlappy3DServer PRIVATE
#         _WIN32_WINNT=0x0A00
#         NOMINMAX
#     )
# endif()

# Linux-specific settings (for future)
# if(UNIX AND NOT APPLE)
#     target_link_libraries(SentinelFlappy3DServer PRIVATE
#         pthread
#     )
# endif()

# ============================================================================
# Compiler Warnings
# ============================================================================

# if(MSVC)
#     target_compile_options(SentinelFlappy3DServer PRIVATE /W4)
# else()
#     target_compile_options(SentinelFlappy3DServer PRIVATE -Wall -Wextra -Wpedantic)
# endif()
