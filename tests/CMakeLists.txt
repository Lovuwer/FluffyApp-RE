# ============================================================================
# Sentinel Tests - CMake Configuration
# ============================================================================

# Core library tests
add_executable(CoreTests
    Core/test_main.cpp
)

target_link_libraries(CoreTests
    PRIVATE
        SentinelCore
        gtest
        gtest_main
)

# SDK tests
add_executable(SDKTests
    SDK/test_main.cpp
)

target_link_libraries(SDKTests
    PRIVATE
        SentinelSDK_static
        gtest
        gtest_main
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(CoreTests)
gtest_discover_tests(SDKTests)

# Add test target
add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS CoreTests SDKTests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
