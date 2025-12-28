# ============================================================================
# Sentinel SDK - CMake Build Configuration
# 
# Copyright (c) 2024 Sentinel Security. All rights reserved.
# ============================================================================

cmake_minimum_required(VERSION 3.21)

project(SentinelSDK
    VERSION 1.0.0
    DESCRIPTION "Sentinel In-Game Security Shield"
    LANGUAGES CXX
)

# C++20 minimum (required for std::span and Core library compatibility)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build options
option(SENTINEL_SDK_BUILD_SHARED "Build as shared library" ON)
option(SENTINEL_SDK_BUILD_STATIC "Build as static library" ON)
option(SENTINEL_SDK_BUILD_TESTS "Build unit tests" OFF)
option(SENTINEL_SDK_BUILD_EXAMPLES "Build example projects" ON)
option(SENTINEL_SDK_ENABLE_PROFILING "Enable performance profiling" OFF)

# Source files
set(SDK_SOURCES
    src/SentinelSDK.cpp
    src/Internal/InternalUtils.cpp
    src/Internal/CorrelationEngine.cpp
    src/Internal/SafeMemory.cpp
    src/Internal/SignatureVerify.cpp
    src/Internal/JITSignature.cpp
    src/Core/Heartbeat.cpp
    src/Core/MemoryProtection.cpp
    src/Core/FunctionProtection.cpp
    src/Core/ValueProtection.cpp
    src/Core/Whitelist.cpp
    src/Detection/AntiDebug.cpp
    src/Detection/AntiHook.cpp
    src/Detection/IntegrityCheck.cpp
    src/Detection/SpeedHack.cpp
    src/Detection/InjectionDetect.cpp
    src/Network/PacketEncryption.cpp
    src/Network/CloudReporter.cpp
    src/Util/SecureTime.cpp
    src/Util/HardwareId.cpp
    src/Util/Obfuscation.cpp
)

set(SDK_HEADERS
    include/SentinelSDK.hpp
    src/Internal/Context.hpp
    src/Internal/Detection.hpp
    src/Internal/Protection.hpp
    src/Internal/Whitelist.hpp
    src/Internal/CorrelationEngine.hpp
    src/Internal/SafeMemory.hpp
    src/Internal/SignatureVerify.hpp
    src/Internal/JITSignature.hpp
)

# Header files for IDE organization only (not compiled)
set_source_files_properties(${SDK_HEADERS} PROPERTIES HEADER_FILE_ONLY TRUE)

# Include directories
set(SDK_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Compiler definitions
set(SDK_COMPILE_DEFINITIONS
    SENTINEL_SDK_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    SENTINEL_SDK_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    SENTINEL_SDK_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

# Platform-specific settings
if(WIN32)
    list(APPEND SDK_COMPILE_DEFINITIONS SENTINEL_PLATFORM_WINDOWS)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        list(APPEND SDK_COMPILE_DEFINITIONS SENTINEL_PLATFORM_X64)
    else()
        list(APPEND SDK_COMPILE_DEFINITIONS SENTINEL_PLATFORM_X86)
    endif()
    
    # Windows libraries
    set(SDK_PLATFORM_LIBS
        ntdll
        kernel32
        user32
        advapi32
        crypt32
        ws2_32
        winhttp
        psapi
    )
elseif(UNIX)
    list(APPEND SDK_COMPILE_DEFINITIONS SENTINEL_PLATFORM_LINUX)
    set(SDK_PLATFORM_LIBS
        pthread
        dl
        ssl
        crypto
    )
endif()

# Compiler flags
if(MSVC)
    set(SDK_COMPILE_OPTIONS
        /W4             # High warning level
        /WX             # Warnings as errors
        /GS             # Buffer security check
        /sdl            # Additional security checks
        /guard:cf       # Control flow guard
        /Oi             # Enable intrinsics
        /Ot             # Favor fast code
        /GL             # Whole program optimization (release)
    )
    
    set(SDK_LINK_OPTIONS
        /DYNAMICBASE    # ASLR
        /NXCOMPAT       # DEP
        /HIGHENTROPYVA  # High entropy ASLR
        /GUARD:CF       # Control flow guard
    )
else()
    set(SDK_COMPILE_OPTIONS
        -Wall
        -Wextra
        -Werror
        -fstack-protector-strong
        -fPIC
        -O3
        -fno-rtti
    )
    
    set(SDK_LINK_OPTIONS
        -Wl,-z,relro
        -Wl,-z,now
    )
endif()

# ==================== Shared Library ====================

if(SENTINEL_SDK_BUILD_SHARED)
    add_library(SentinelSDK SHARED ${SDK_SOURCES} ${SDK_HEADERS})
    
    target_include_directories(SentinelSDK
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    
    target_compile_definitions(SentinelSDK
        PRIVATE
            SENTINEL_SDK_EXPORTS
            ${SDK_COMPILE_DEFINITIONS}
    )
    
    target_compile_options(SentinelSDK PRIVATE ${SDK_COMPILE_OPTIONS})
    target_link_options(SentinelSDK PRIVATE ${SDK_LINK_OPTIONS})
    target_link_libraries(SentinelSDK PRIVATE ${SDK_PLATFORM_LIBS})
    
    set_target_properties(SentinelSDK PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        OUTPUT_NAME "SentinelSDK"
        DEBUG_POSTFIX "d"
    )
    
    # Hide internal symbols
    set_target_properties(SentinelSDK PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
endif()

# ==================== Static Library ====================

if(SENTINEL_SDK_BUILD_STATIC)
    add_library(SentinelSDK_static STATIC ${SDK_SOURCES} ${SDK_HEADERS})
    
    target_include_directories(SentinelSDK_static
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    
    target_compile_definitions(SentinelSDK_static
        PUBLIC
            SENTINEL_SDK_STATIC
        PRIVATE
            ${SDK_COMPILE_DEFINITIONS}
    )
    
    target_compile_options(SentinelSDK_static PRIVATE ${SDK_COMPILE_OPTIONS})
    
    set_target_properties(SentinelSDK_static PROPERTIES
        OUTPUT_NAME "SentinelSDK_static"
        DEBUG_POSTFIX "d"
    )
endif()

# ==================== Examples ====================

# if(SENTINEL_SDK_BUILD_EXAMPLES)
#     add_subdirectory(examples)
# endif()

# ==================== Tests ====================

if(SENTINEL_SDK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ==================== Installation ====================

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Install headers
install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

# Install libraries
if(SENTINEL_SDK_BUILD_SHARED)
    install(TARGETS SentinelSDK
        EXPORT SentinelSDKTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

if(SENTINEL_SDK_BUILD_STATIC)
    install(TARGETS SentinelSDK_static
        EXPORT SentinelSDKTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

# Export targets
install(EXPORT SentinelSDKTargets
    FILE SentinelSDKTargets.cmake
    NAMESPACE Sentinel::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SentinelSDK
)

# Package config
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/SentinelSDKConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/SentinelSDKConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SentinelSDK
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/SentinelSDKConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/SentinelSDKConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/SentinelSDKConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SentinelSDK
)
