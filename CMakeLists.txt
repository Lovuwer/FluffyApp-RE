# ============================================================================
# Sentinel Security Ecosystem - Root CMake Configuration
# ============================================================================
# Military-Grade Game Security Platform
# Copyright (c) 2024 Sentinel Security. All rights reserved.
# ============================================================================

cmake_minimum_required(VERSION 3.21)

project(Sentinel
    VERSION 1.0.0
    DESCRIPTION "Military-Grade Game Security Ecosystem"
    LANGUAGES CXX
)

# ============================================================================
# Build Configuration
# ============================================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDE integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ============================================================================
# Options
# ============================================================================

option(SENTINEL_BUILD_CORTEX "Build Sentinel Cortex GUI application" ON)
option(SENTINEL_BUILD_SDK "Build Sentinel SDK library" ON)
option(SENTINEL_BUILD_WATCHTOWER "Build Sentinel Watchtower module" ON)
option(SENTINEL_BUILD_TESTS "Build unit tests" ON)
option(SENTINEL_BUILD_DOCS "Build documentation" ON)
option(SENTINEL_ENABLE_VM_DEOBFUSCATOR "Enable VM Deobfuscation Engine" ON)
option(SENTINEL_ENABLE_ASAN "Enable Address Sanitizer" OFF)
option(SENTINEL_ENABLE_UBSAN "Enable Undefined Behavior Sanitizer" OFF)
option(SENTINEL_ENABLE_TSAN "Enable Thread Sanitizer" OFF)

# ============================================================================
# Compiler Configuration
# ============================================================================

if(MSVC)
    # MSVC-specific flags
    add_compile_options(
        /W4                     # Warning level 4
        # /WX                     # Treat warnings as errors - Disabled for initial build
        /permissive-            # Strict conformance mode
        /MP                     # Multi-processor compilation
        /Zc:__cplusplus         # Correct __cplusplus macro
        /Zc:preprocessor        # Conforming preprocessor
        /utf-8                  # UTF-8 source and execution charset
    )
    
    # Release optimizations
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(
            /O2                 # Maximum optimization
            /Ob3                # Aggressive inlining
            /GL                 # Whole program optimization
            /Gy                 # Enable function-level linking
            /Gw                 # Optimize global data
        )
        add_link_options(
            /LTCG               # Link-time code generation
            /OPT:REF            # Remove unreferenced code
            /OPT:ICF            # COMDAT folding
        )
    endif()
    
    # ========================================================================
    # Security Hardening Flags (MSVC)
    # ========================================================================
    
    # Stack buffer overflow detection
    add_compile_options(/GS)           # Buffer security check (stack canary)
    
    # Control Flow Guard
    add_compile_options(/guard:cf)     # Control flow guard
    add_link_options(/guard:cf)        # CFG in linker
    
    # Safe exception handlers (x86 only)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        add_link_options(/SAFESEH)
    endif()
    
    # ASLR support
    add_link_options(/DYNAMICBASE)     # Enable ASLR
    add_link_options(/HIGHENTROPYVA)   # High-entropy 64-bit ASLR
    
    # DEP (Data Execution Prevention)
    add_link_options(/NXCOMPAT)        # Enable DEP
    
    # Disable incremental linking for security
    add_link_options(/INCREMENTAL:NO)
    
    # Generate full debug info for crash analysis
    add_compile_options(/Zi)
    add_link_options(/DEBUG:FULL)
    
    # Treat warnings as errors in Release
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/WX)
    endif()
    
    # SDL checks (additional security checks)
    add_compile_options(/sdl)
    
    # Spectre mitigation
    add_compile_options(/Qspectre)
    
    # CET Shadow Stack compatible
    add_link_options(/CETCOMPAT)
else()
    # GCC/Clang flags
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        # -Werror  # Disabled for initial build
        -fPIC
    )
    
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O3 -flto)
        add_link_options(-flto)
    endif()
    
    # ========================================================================
    # Security Hardening Flags (GCC/Clang)
    # ========================================================================
    
    # Stack protection
    add_compile_options(-fstack-protector-strong)
    
    # Position Independent Executable (for ASLR)
    # NOTE: -fPIE and -pie are disabled because they conflict with shared library builds.
    # Shared libraries use -fPIC (position independent code) which is already set above.
    # Executables can set CMAKE_POSITION_INDEPENDENT_CODE ON or use -fPIE individually.
    # add_compile_options(-fPIE)
    # add_link_options(-pie)
    
    # Fortify source (buffer overflow detection)
    add_compile_options(-D_FORTIFY_SOURCE=2)
    
    # Format string protection
    add_compile_options(-Wformat -Wformat-security)
    
    # Relocation read-only (RELRO)
    add_link_options(-Wl,-z,relro,-z,now)
    
    # No executable stack
    add_link_options(-Wl,-z,noexecstack)
    
    # Stack clash protection (GCC 8+)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND 
       CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 8)
        add_compile_options(-fstack-clash-protection)
    endif()
    
    # Control flow integrity (Clang)
    # CFI requires LTO to work properly
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # Only enable CFI if not using other sanitizers (they conflict)
        if(NOT SENTINEL_ENABLE_ASAN AND NOT SENTINEL_ENABLE_TSAN AND NOT SENTINEL_ENABLE_UBSAN)
            add_compile_options(-fsanitize=cfi -flto -fvisibility=hidden)
            add_link_options(-fsanitize=cfi -flto)
        endif()
    endif()
endif()

# ============================================================================
# Sanitizers (Debug/Development builds)
# ============================================================================

if(SENTINEL_ENABLE_ASAN)
    if(MSVC)
        add_compile_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

if(SENTINEL_ENABLE_UBSAN)
    # MSVC does not support UBSan. Use /analyze for similar static analysis.
    if(NOT MSVC)
        add_compile_options(-fsanitize=undefined)
        add_link_options(-fsanitize=undefined)
    endif()
endif()

if(SENTINEL_ENABLE_TSAN)
    if(NOT MSVC)
        add_compile_options(-fsanitize=thread)
        add_link_options(-fsanitize=thread)
    endif()
endif()

# ============================================================================
# Dependencies
# ============================================================================

# Find Qt6
find_package(Qt6 COMPONENTS Core Gui Qml Quick Widgets Network QUIET)
if(NOT Qt6_FOUND AND SENTINEL_BUILD_CORTEX)
    message(WARNING "Qt6 not found. Cortex GUI will not be built.")
    set(SENTINEL_BUILD_CORTEX OFF)
endif()

# Find OpenSSL
find_package(OpenSSL QUIET)
if(NOT OpenSSL_FOUND)
    message(WARNING "OpenSSL not found. Using Windows BCrypt instead.")
endif()

# Find CURL
find_package(CURL QUIET)
if(NOT CURL_FOUND)
    message(WARNING "libcurl not found. HTTP client will not be built.")
endif()

# ============================================================================
# Third-Party Libraries (vendored or fetched)
# ============================================================================

include(FetchContent)

# Capstone Disassembly Engine
FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG 5.0.1
)

# MinHook (Windows x64 hooking)
FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG v1.3.3
)

# nlohmann/json for JSON parsing
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)

# spdlog for logging
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.13.0
)

# Google Test for unit testing
if(SENTINEL_BUILD_TESTS)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
endif()

# Set options before fetching
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)

set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "" FORCE)

# Fetch all dependencies
FetchContent_MakeAvailable(capstone minhook nlohmann_json spdlog)

if(SENTINEL_BUILD_TESTS)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
endif()

# ============================================================================
# Include Directories
# ============================================================================

set(SENTINEL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SENTINEL_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

include_directories(
    ${SENTINEL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/lib
)

# ============================================================================
# Subdirectories
# ============================================================================

# Core library (shared utilities)
add_subdirectory(src/Core)

# Sentinel Cortex (GUI Workbench)
if(SENTINEL_BUILD_CORTEX)
    add_subdirectory(src/Cortex)
endif()

# Sentinel SDK (In-Game Shield)
if(SENTINEL_BUILD_SDK)
    add_subdirectory(src/SDK)
    
    # Add SDK examples (including DummyGame) if enabled
    if(SENTINEL_SDK_BUILD_EXAMPLES)
        add_subdirectory(examples/DummyGame)
    endif()
endif()

# Sentinel Watchtower (Roblox Module)
if(SENTINEL_BUILD_WATCHTOWER)
    add_subdirectory(src/Watchtower)
endif()

# Tests
if(SENTINEL_BUILD_TESTS)
    add_subdirectory(tests)
endif()

# ============================================================================
# Documentation
# ============================================================================

if(SENTINEL_BUILD_DOCS)
    find_package(Doxygen QUIET)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
        
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        
        add_custom_target(docs
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
        )
    else()
        message(WARNING "Doxygen not found. Documentation will not be built.")
    endif()
endif()

# ============================================================================
# Installation
# ============================================================================

include(GNUInstallDirs)

install(DIRECTORY ${SENTINEL_INCLUDE_DIR}/Sentinel
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h"
)

# ============================================================================
# Package Configuration
# ============================================================================

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/SentinelConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SentinelConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/SentinelConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Sentinel
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/SentinelConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/SentinelConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Sentinel
)

# ============================================================================
# Binary Hardening Verification
# ============================================================================

# Verification target to check binary hardening
if(WIN32)
    add_custom_target(verify-hardening
        COMMAND powershell -ExecutionPolicy Bypass -File 
                ${CMAKE_SOURCE_DIR}/scripts/verify-hardening.ps1
                $<TARGET_FILE:SentinelCore>
        DEPENDS SentinelCore
        COMMENT "Verifying binary security hardening"
    )
endif()

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "============================================")
message(STATUS "  Sentinel Security Ecosystem v${PROJECT_VERSION}")
message(STATUS "============================================")
message(STATUS "")
message(STATUS "Build Configuration:")
message(STATUS "  Build Type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard:     ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler:         ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "")
message(STATUS "Components:")
message(STATUS "  Cortex GUI:       ${SENTINEL_BUILD_CORTEX}")
message(STATUS "  SDK Library:      ${SENTINEL_BUILD_SDK}")
message(STATUS "  Watchtower:       ${SENTINEL_BUILD_WATCHTOWER}")
message(STATUS "  Unit Tests:       ${SENTINEL_BUILD_TESTS}")
message(STATUS "  Documentation:    ${SENTINEL_BUILD_DOCS}")
message(STATUS "  VM Deobfuscator:  ${SENTINEL_ENABLE_VM_DEOBFUSCATOR}")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  Qt6 Found:        ${Qt6_FOUND}")
message(STATUS "  OpenSSL Found:    ${OpenSSL_FOUND}")
message(STATUS "  CURL Found:       ${CURL_FOUND}")
message(STATUS "  Doxygen Found:    ${DOXYGEN_FOUND}")
message(STATUS "")
message(STATUS "============================================")
