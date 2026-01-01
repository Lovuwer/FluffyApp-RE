# ============================================================================
# Sentinel SDK - Dummy Game Example
# ============================================================================
# Realistic integration test for Sentinel-RE SDK
# Red-team mindset: Find false positives and real-world integration issues
# ============================================================================

cmake_minimum_required(VERSION 3.21)

project(SentinelDummyGame
    VERSION 1.0.0
    DESCRIPTION "Sentinel SDK Integration Test Game"
    LANGUAGES CXX
)

# ============================================================================
# C++ Standard
# ============================================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# Find Dependencies
# ============================================================================

# Find Sentinel SDK
# When built as part of main project, libraries are available
# When built standalone, need to find them
if(NOT TARGET SentinelSDK AND NOT TARGET SentinelSDK_static)
    find_library(SENTINEL_SDK_LIB
        NAMES SentinelSDK SentinelSDK_static
        PATHS ${CMAKE_BINARY_DIR}/lib
              ${CMAKE_SOURCE_DIR}/../../build/lib
        NO_DEFAULT_PATH
    )
    
    if(NOT SENTINEL_SDK_LIB)
        message(FATAL_ERROR "SentinelSDK library not found. Build the main project first.")
    endif()
endif()

# ============================================================================
# Executable
# ============================================================================

add_executable(DummyGame
    main.cpp
)

# ============================================================================
# Include Directories
# ============================================================================

target_include_directories(DummyGame PRIVATE
    ${CMAKE_SOURCE_DIR}/../../include
    ${CMAKE_SOURCE_DIR}/../../src/SDK/include
)

# ============================================================================
# Link Libraries
# ============================================================================

if(TARGET SentinelSDK)
    # Building as part of main project (shared library)
    target_link_libraries(DummyGame PRIVATE
        SentinelSDK
        SentinelCore
    )
elseif(TARGET SentinelSDK_static)
    # Building as part of main project (static library)
    target_link_libraries(DummyGame PRIVATE
        SentinelSDK_static
        SentinelCore
    )
else()
    # Building standalone
    target_link_libraries(DummyGame PRIVATE
        ${SENTINEL_SDK_LIB}
    )
endif()

# ============================================================================
# Platform-Specific Configuration
# ============================================================================

if(WIN32)
    # Windows-specific settings
    target_compile_definitions(DummyGame PRIVATE
        _WIN32_WINNT=0x0A00  # Windows 10+
        NOMINMAX
    )
else()
    # Linux/Unix settings
    target_link_libraries(DummyGame PRIVATE
        pthread
        dl
    )
endif()

# ============================================================================
# Compiler Options
# ============================================================================

if(MSVC)
    target_compile_options(DummyGame PRIVATE
        /W4
        /permissive-
    )
else()
    target_compile_options(DummyGame PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

# ============================================================================
# Build Type Configuration
# ============================================================================

# Debug build
target_compile_definitions(DummyGame PRIVATE
    $<$<CONFIG:Debug>:DEBUG>
    $<$<CONFIG:Debug>:_DEBUG>
)

# Release build
target_compile_definitions(DummyGame PRIVATE
    $<$<CONFIG:Release>:NDEBUG>
)

target_compile_options(DummyGame PRIVATE
    $<$<CONFIG:Release>:-O3>
)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS DummyGame
    RUNTIME DESTINATION bin
)

# ============================================================================
# Post-Build Messages
# ============================================================================

add_custom_command(TARGET DummyGame POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "  DummyGame built successfully!"
    COMMAND ${CMAKE_COMMAND} -E echo "  Executable: $<TARGET_FILE:DummyGame>"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
)
