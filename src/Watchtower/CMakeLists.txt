/**
 * Sentinel Watchtower - CMake Build Configuration
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

cmake_minimum_required(VERSION 3.21)

project(SentinelWatchtower
    VERSION 1.0.0
    DESCRIPTION "Sentinel Roblox Security Module"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(WATCHTOWER_BUILD_SHARED "Build shared library" ON)
option(WATCHTOWER_BUILD_STATIC "Build static library" ON)
option(WATCHTOWER_BUILD_LUA_MODULE "Build Lua module" ON)
option(WATCHTOWER_ENABLE_FUZZER "Enable network fuzzer" ON)

# Source files
set(WATCHTOWER_SOURCES
    src/Watchtower.cpp
    src/Core/PlayerTracker.cpp
    src/Core/RemoteValidator.cpp
    src/Core/MovementValidator.cpp
    src/Detection/SpeedHack.cpp
    src/Detection/Teleport.cpp
    src/Detection/Combat.cpp
    src/Detection/ExecutorDetect.cpp
    src/Detection/ScriptAnalyzer.cpp
    src/Network/PacketValidator.cpp
    src/Network/RateLimiter.cpp
    src/Lua/LuaBridge.cpp
)

if(WATCHTOWER_ENABLE_FUZZER)
    list(APPEND WATCHTOWER_SOURCES
        src/Network/Fuzzer.cpp
    )
endif()

set(WATCHTOWER_HEADERS
    include/Watchtower.hpp
    src/Internal/Config.hpp
    src/Internal/Context.hpp
    src/Internal/PlayerState.hpp
)

# Include directories
set(WATCHTOWER_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Compile definitions
set(WATCHTOWER_DEFINITIONS
    WATCHTOWER_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    WATCHTOWER_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    WATCHTOWER_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

if(WATCHTOWER_ENABLE_FUZZER)
    list(APPEND WATCHTOWER_DEFINITIONS WATCHTOWER_FUZZER_ENABLED)
endif()

# Platform libraries
if(WIN32)
    set(WATCHTOWER_LIBS
        ws2_32
        winhttp
    )
else()
    set(WATCHTOWER_LIBS
        pthread
        ssl
        crypto
    )
endif()

# Compiler options
if(MSVC)
    set(WATCHTOWER_COMPILE_OPTIONS
        /W4 /WX /GS /sdl /guard:cf
    )
else()
    set(WATCHTOWER_COMPILE_OPTIONS
        -Wall -Wextra -Werror -fPIC
    )
endif()

# Shared library
if(WATCHTOWER_BUILD_SHARED)
    add_library(Watchtower SHARED ${WATCHTOWER_SOURCES})
    
    target_include_directories(Watchtower
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    
    target_compile_definitions(Watchtower PRIVATE
        WATCHTOWER_EXPORTS
        ${WATCHTOWER_DEFINITIONS}
    )
    
    target_compile_options(Watchtower PRIVATE ${WATCHTOWER_COMPILE_OPTIONS})
    target_link_libraries(Watchtower PRIVATE ${WATCHTOWER_LIBS})
    
    set_target_properties(Watchtower PROPERTIES
        VERSION ${PROJECT_VERSION}
        OUTPUT_NAME "SentinelWatchtower"
    )
endif()

# Static library
if(WATCHTOWER_BUILD_STATIC)
    add_library(Watchtower_static STATIC ${WATCHTOWER_SOURCES})
    
    target_include_directories(Watchtower_static
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    
    target_compile_definitions(Watchtower_static PRIVATE ${WATCHTOWER_DEFINITIONS})
    target_compile_options(Watchtower_static PRIVATE ${WATCHTOWER_COMPILE_OPTIONS})
    
    set_target_properties(Watchtower_static PROPERTIES
        OUTPUT_NAME "SentinelWatchtower_static"
    )
endif()

# Lua module (for Roblox integration)
if(WATCHTOWER_BUILD_LUA_MODULE)
    # Find Lua (or use bundled Luau headers)
    find_package(Lua QUIET)
    
    if(NOT LUA_FOUND)
        # Use bundled Luau headers
        set(LUA_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/luau/include)
    endif()
    
    add_library(WatchtowerLua MODULE
        src/Lua/LuaModule.cpp
        src/Lua/LuaBridge.cpp
    )
    
    target_include_directories(WatchtowerLua PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${LUA_INCLUDE_DIR}
    )
    
    if(WATCHTOWER_BUILD_STATIC)
        target_link_libraries(WatchtowerLua PRIVATE Watchtower_static)
    else()
        target_link_libraries(WatchtowerLua PRIVATE Watchtower)
    endif()
    
    set_target_properties(WatchtowerLua PROPERTIES
        PREFIX ""
        OUTPUT_NAME "Watchtower"
    )
endif()

# Installation
include(GNUInstallDirs)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

if(WATCHTOWER_BUILD_SHARED)
    install(TARGETS Watchtower
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

if(WATCHTOWER_BUILD_STATIC)
    install(TARGETS Watchtower_static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()
