# ============================================================================
# SentinelFlappy3D - Reference Implementation
# ============================================================================
# A realistic 3D Flappy Bird game demonstrating Sentinel SDK integration
# ============================================================================

cmake_minimum_required(VERSION 3.21)

project(SentinelFlappy3D
    VERSION 1.0.0
    DESCRIPTION "Reference Implementation of Sentinel SDK Integration"
    LANGUAGES CXX
)

# ============================================================================
# Project Options
# ============================================================================

option(BUILD_GAME "Build the game executable" ON)
option(BUILD_SERVER "Build the validation server" ON)
option(BUILD_TESTS "Build automated tests" OFF)

# ============================================================================
# C++ Standard
# ============================================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# Output Directories
# ============================================================================

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ============================================================================
# Subdirectories
# ============================================================================

if(BUILD_GAME)
    add_subdirectory(game)
endif()

if(BUILD_SERVER)
    add_subdirectory(server)
endif()

if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

# ============================================================================
# Post-Build Messages
# ============================================================================

message(STATUS "")
message(STATUS "========================================")
message(STATUS "  SentinelFlappy3D Configuration")
message(STATUS "========================================")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Game: ${BUILD_GAME}")
message(STATUS "  Server: ${BUILD_SERVER}")
message(STATUS "  Tests: ${BUILD_TESTS}")
message(STATUS "========================================")
message(STATUS "")
