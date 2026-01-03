# ============================================================================
# SentinelFlappy3D - Game Executable
# ============================================================================
# Core game implementation with OpenGL rendering and Sentinel SDK integration
# ============================================================================

cmake_minimum_required(VERSION 3.21)

project(SentinelFlappy3DGame
    VERSION 1.0.0
    DESCRIPTION "SentinelFlappy3D Game Executable"
    LANGUAGES CXX
)

# ============================================================================
# C++ Standard
# ============================================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# Dependencies - OpenGL, GLFW, GLM
# ============================================================================

include(FetchContent)

# Find OpenGL (required for rendering)
find_package(OpenGL QUIET)

# Check if OpenGL was found
if(OpenGL_FOUND)
    message(STATUS "OpenGL found: ${OPENGL_LIBRARIES}")
else()
    message(STATUS "OpenGL not found (expected in headless/CI environments)")
    message(STATUS "  Game will still build but may not run without OpenGL drivers")
endif()

# Fetch GLFW (window and input handling)
message(STATUS "Fetching GLFW...")
FetchContent_Declare(
    glfw
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG 3.4
    GIT_SHALLOW TRUE
)
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_WAYLAND OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_X11 ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(glfw)

# Fetch GLM (math library for 3D transformations)
message(STATUS "Fetching GLM...")
FetchContent_Declare(
    glm
    GIT_REPOSITORY https://github.com/g-truc/glm.git
    GIT_TAG 1.0.1
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(glm)

# ============================================================================
# Source Files
# ============================================================================

set(GAME_SOURCES
    src/main.cpp
    src/Game.cpp
    src/Renderer.cpp
    src/Player.cpp
    src/Obstacle.cpp
    src/Physics.cpp
    src/Input.cpp
    src/SentinelIntegration.cpp
)

set(GAME_HEADERS
    src/Game.hpp
    src/Renderer.hpp
    src/Player.hpp
    src/Obstacle.hpp
    src/Physics.hpp
    src/Input.hpp
    src/SentinelIntegration.hpp
)

# ============================================================================
# Executable Target
# ============================================================================

add_executable(SentinelFlappy3D ${GAME_SOURCES} ${GAME_HEADERS})

target_include_directories(SentinelFlappy3D PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ============================================================================
# Link Libraries
# ============================================================================

# Link GLFW
target_link_libraries(SentinelFlappy3D PRIVATE glfw)

# Link GLM (header-only)
target_link_libraries(SentinelFlappy3D PRIVATE glm::glm)

# Link OpenGL if found
if(OpenGL_FOUND)
    target_link_libraries(SentinelFlappy3D PRIVATE OpenGL::GL)
endif()

# ============================================================================
# Sentinel SDK Integration (Step 5)
# ============================================================================

# Find Sentinel SDK from parent repository
# The SDK is built as part of the main Sentinel project
set(SENTINEL_SDK_DIR "${CMAKE_SOURCE_DIR}/../src/SDK")

if(EXISTS "${SENTINEL_SDK_DIR}/include/SentinelSDK.hpp")
    message(STATUS "Found Sentinel SDK at: ${SENTINEL_SDK_DIR}")
    
    # Add SDK include directory
    target_include_directories(SentinelFlappy3D PRIVATE
        "${SENTINEL_SDK_DIR}/include"
        "${CMAKE_SOURCE_DIR}/../include"
    )
    
    # Try to find built SDK library
    find_library(SENTINEL_SDK_LIB
        NAMES SentinelSDK SentinelSDK_static
        PATHS "${CMAKE_SOURCE_DIR}/../build/lib"
        NO_DEFAULT_PATH
    )
    
    if(SENTINEL_SDK_LIB)
        message(STATUS "Found Sentinel SDK library: ${SENTINEL_SDK_LIB}")
        target_link_libraries(SentinelFlappy3D PRIVATE ${SENTINEL_SDK_LIB})
        
        # Find SentinelCore library (SDK dependency)
        find_library(SENTINEL_CORE_LIB
            NAMES SentinelCore
            PATHS "${CMAKE_SOURCE_DIR}/../build/lib"
            NO_DEFAULT_PATH
        )
        if(SENTINEL_CORE_LIB)
            message(STATUS "Found Sentinel Core library: ${SENTINEL_CORE_LIB}")
            target_link_libraries(SentinelFlappy3D PRIVATE ${SENTINEL_CORE_LIB})
        endif()
        
        # Define that we're using the SDK
        target_compile_definitions(SentinelFlappy3D PRIVATE SENTINEL_SDK_ENABLED)
    else()
        message(WARNING "Sentinel SDK library not found - using stub implementation")
        message(WARNING "  Build the main Sentinel project first:")
        message(WARNING "    cd ${CMAKE_SOURCE_DIR}/..")
        message(WARNING "    cmake -B build -DSENTINEL_BUILD_SDK=ON")
        message(WARNING "    cmake --build build --target SentinelSDK")
    endif()
else()
    message(WARNING "Sentinel SDK headers not found at: ${SENTINEL_SDK_DIR}")
    message(WARNING "  Using stub implementation only")
endif()

# ============================================================================
# Platform-Specific Configuration
# ============================================================================

if(WIN32)
    target_compile_definitions(SentinelFlappy3D PRIVATE
        _WIN32_WINNT=0x0A00
        NOMINMAX
    )
elseif(UNIX AND NOT APPLE)
    target_link_libraries(SentinelFlappy3D PRIVATE
        pthread
        dl
    )
endif()

# ============================================================================
# Compiler Warnings
# ============================================================================

if(MSVC)
    target_compile_options(SentinelFlappy3D PRIVATE /W4)
else()
    target_compile_options(SentinelFlappy3D PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ============================================================================
# Post-Build Messages
# ============================================================================

add_custom_command(TARGET SentinelFlappy3D POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "  SentinelFlappy3D built successfully!"
    COMMAND ${CMAKE_COMMAND} -E echo "  Executable: $<TARGET_FILE:SentinelFlappy3D>"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
)
