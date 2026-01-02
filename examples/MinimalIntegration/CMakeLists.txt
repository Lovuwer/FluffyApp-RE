# Minimal Integration Example
cmake_minimum_required(VERSION 3.21)
project(MinimalIntegration)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find SentinelSDK
# In a real integration, you would link against the distributed SDK
add_executable(MinimalIntegration MinimalIntegration.cpp)

target_link_libraries(MinimalIntegration PRIVATE
    SentinelSDK
    SentinelCore
)

target_include_directories(MinimalIntegration PRIVATE
    ${CMAKE_SOURCE_DIR}/src/SDK/include
    ${CMAKE_SOURCE_DIR}/include
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(MinimalIntegration PRIVATE
        ws2_32
        crypt32
        bcrypt
    )
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(MinimalIntegration PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        pthread
        dl
    )
endif()
