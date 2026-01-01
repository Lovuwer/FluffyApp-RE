# Performance Metrics Demo Example
cmake_minimum_required(VERSION 3.15)

add_executable(PerformanceMetricsDemo
    performance_metrics_demo.cpp
)

target_include_directories(PerformanceMetricsDemo
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../src/SDK/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../src/SDK/src
)

target_link_libraries(PerformanceMetricsDemo
    PRIVATE
        SentinelSDK_static
)

# Set C++ standard
set_target_properties(PerformanceMetricsDemo PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

# Copy to bin directory
set_target_properties(PerformanceMetricsDemo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Add to examples group
set_target_properties(PerformanceMetricsDemo PROPERTIES FOLDER "Examples")
