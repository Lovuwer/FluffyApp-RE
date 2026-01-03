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

# Find OpenGL (required for rendering)
# Note: In headless/CI environments, OpenGL may not be available
# This is fine for Step 1 (skeleton only)
find_package(OpenGL QUIET)

# Check if OpenGL was found
if(OpenGL_FOUND)
    message(STATUS "OpenGL found: ${OPENGL_LIBRARIES}")
else()
    message(STATUS "OpenGL not found (expected in headless/CI environments)")
    message(STATUS "  Will be required in Step 2 when game is implemented")
endif()

# Find or fetch GLFW (window and input handling)
find_package(glfw3 QUIET)
if(NOT glfw3_FOUND)
    message(STATUS "GLFW not found, will be fetched if needed in future steps")
    # Note: GLFW will be added via FetchContent in later steps
    # For now, just note that it's required
endif()

# Find or fetch GLM (math library for 3D transformations)
find_package(glm QUIET)
if(NOT glm_FOUND)
    message(STATUS "GLM not found, will be fetched if needed in future steps")
    # Note: GLM will be added via FetchContent in later steps
    # For now, just note that it's required
endif()

# ============================================================================
# Source Files
# ============================================================================

set(GAME_SOURCES
    # Main entry point (to be created in future steps)
    # src/main.cpp
    # src/Game.cpp
    # src/Renderer.cpp
    # src/Player.cpp
    # src/Obstacle.cpp
    # src/Physics.cpp
    # src/Input.cpp
    # src/SentinelIntegration.cpp
)

set(GAME_HEADERS
    # Game headers (to be created in future steps)
    # src/Game.hpp
    # src/Renderer.hpp
    # src/Player.hpp
    # src/Obstacle.hpp
    # src/Physics.hpp
    # src/Input.hpp
    # src/SentinelIntegration.hpp
)

# ============================================================================
# Executable Target
# ============================================================================

# Note: Executable will be created once source files exist
# For now, this is a skeleton that will be populated in later steps

message(STATUS "Game CMakeLists.txt configured")
message(STATUS "  Source files will be added in Step 2")
message(STATUS "  Dependencies (GLFW, GLM) will be configured in Step 2")
message(STATUS "  Sentinel SDK will be integrated in Step 4")

# ============================================================================
# Future Configuration Notes
# ============================================================================

# When implementing Step 2:
# - Uncomment source files above
# - Add executable target: add_executable(SentinelFlappy3D ${GAME_SOURCES})
# - Link OpenGL: target_link_libraries(SentinelFlappy3D PRIVATE OpenGL::GL)
# - Link GLFW: target_link_libraries(SentinelFlappy3D PRIVATE glfw)
# - Link GLM: target_link_libraries(SentinelFlappy3D PRIVATE glm::glm)

# When implementing Step 4 (Sentinel SDK):
# - Find Sentinel SDK: find_package(SentinelSDK)
# - Link SDK: target_link_libraries(SentinelFlappy3D PRIVATE SentinelSDK)
# - Add include paths for SDK headers

# ============================================================================
# Platform-Specific Configuration
# ============================================================================

# Windows-specific settings (for future)
# if(WIN32)
#     target_compile_definitions(SentinelFlappy3D PRIVATE
#         _WIN32_WINNT=0x0A00
#         NOMINMAX
#     )
# endif()

# Linux-specific settings (for future)
# if(UNIX AND NOT APPLE)
#     target_link_libraries(SentinelFlappy3D PRIVATE
#         pthread
#         dl
#     )
# endif()

# ============================================================================
# Compiler Warnings
# ============================================================================

# if(MSVC)
#     target_compile_options(SentinelFlappy3D PRIVATE /W4)
# else()
#     target_compile_options(SentinelFlappy3D PRIVATE -Wall -Wextra -Wpedantic)
# endif()
