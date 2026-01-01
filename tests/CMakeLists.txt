# ============================================================================
# Sentinel Tests - CMake Configuration
# ============================================================================

# Add test harness library
add_library(SentinelTestHarness STATIC
    TestHarness.cpp
    TestHarness.hpp
)

target_link_libraries(SentinelTestHarness
    PUBLIC
        SentinelCore
        gtest
)

target_include_directories(SentinelTestHarness
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Core library tests
add_executable(CoreTests
    Core/test_main.cpp
    Core/test_crypto.cpp
    Core/test_constant_time.cpp
    Core/test_secure_zero.cpp
    Core/test_harness.cpp
    Core/test_aes_cipher.cpp
    Core/test_rsa_signer.cpp
    Core/test_certificate_pinning.cpp
    Core/test_config_loader.cpp
    Core/test_memory.cpp
    Core/test_obfuscated_string.cpp
    Core/test_logger.cpp
)

target_link_libraries(CoreTests
    PRIVATE
        SentinelCore
        SentinelTestHarness
        gtest
        gtest_main
)

# HTTP Client integration tests (separate executable)
if(CURL_FOUND)
    add_executable(HttpClientTests
        Core/test_http_client.cpp
    )
    
    target_link_libraries(HttpClientTests
        PRIVATE
            SentinelCore
            gtest
            gtest_main
    )
    
    # Request Signer tests (depends on crypto)
    add_executable(RequestSignerTests
        Core/test_request_signer.cpp
    )
    
    target_link_libraries(RequestSignerTests
        PRIVATE
            SentinelCore
            gtest
            gtest_main
    )
    
    # Request Signing Integration tests
    add_executable(RequestSigningIntegrationTests
        Core/test_request_signing_integration.cpp
    )
    
    target_link_libraries(RequestSigningIntegrationTests
        PRIVATE
            SentinelCore
            gtest
            gtest_main
    )
    
    # Heartbeat tests (depends on HttpClient and RequestSigner)
    add_executable(HeartbeatTests
        Core/test_heartbeat.cpp
    )
    
    target_link_libraries(HeartbeatTests
        PRIVATE
            SentinelCore
            gtest
            gtest_main
    )
endif()

# SDK tests
add_executable(SDKTests
    SDK/test_main.cpp
    SDK/test_whitelist.cpp
    SDK/test_whitelist_api.cpp
    SDK/test_anti_debug.cpp
    SDK/test_integrity.cpp
    SDK/test_anti_hook.cpp
    SDK/test_injection_detect.cpp
    SDK/test_signature_verify.cpp
    SDK/test_speed_hack.cpp
    SDK/test_packet_encryption.cpp
    SDK/test_correlation_engine.cpp
    SDK/test_correlation_integration.cpp
    SDK/test_correlation_enhancements.cpp
    SDK/test_safe_memory.cpp
    SDK/test_protected_value.cpp
    SDK/test_violation_event_string_safety.cpp
    SDK/test_environment_detection.cpp
    SDK/test_overlay_verifier.cpp
    SDK/test_telemetry_config.cpp
    SDK/test_exception_budget.cpp
    SDK/test_handle_generation.cpp
    SDK/test_watchdog.cpp
    SDK/test_cloud_reporter.cpp
    SDK/test_scan_scheduler.cpp
    SDK/test_integrity_validator.cpp
    SDK/test_diversity_engine.cpp
    SDK/test_signature_manager.cpp
    SDK/test_update_client.cpp
    SDK/test_perf_telemetry.cpp
)

target_include_directories(SDKTests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/SDK/src
)

target_link_libraries(SDKTests
    PRIVATE
        SentinelSDK_static
        SentinelTestHarness
        gtest
        gtest_main
)

# Cortex component tests (built independently of Qt GUI)
# PatchGenerator tests
add_executable(PatchGeneratorTests
    Cortex/test_patchgenerator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/Cortex/PatchGen/PatchGenerator.cpp
)

target_include_directories(PatchGeneratorTests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/Cortex
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(PatchGeneratorTests
    PRIVATE
        SentinelCore
        SentinelTestHarness
        gtest
        gtest_main
)

# VMDeobfuscator tests
add_executable(VMDeobfuscatorTests
    Cortex/test_vmdeobfuscator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/Cortex/VMDeobfuscator/VMDeobfuscator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/Cortex/VMDeobfuscator/DynamicTracer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/Cortex/VMDeobfuscator/SymbolicEngine.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/Cortex/VMDeobfuscator/SSALifter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/Cortex/VMDeobfuscator/PatternMatcher.cpp
)

target_include_directories(VMDeobfuscatorTests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/Cortex
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(VMDeobfuscatorTests
    PRIVATE
        SentinelCore
        SentinelTestHarness
        gtest
        gtest_main
)

# BinaryDiffer tests (existing, only if Cortex is being built)
if(SENTINEL_BUILD_CORTEX)
    add_executable(CortexTests
        Cortex/test_binarydiff.cpp
    )
    
    target_include_directories(CortexTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/Cortex
    )
    
    target_link_libraries(CortexTests
        PRIVATE
            SentinelCore
            SentinelTestHarness
            capstone
            gtest
            gtest_main
    )
endif()

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(CoreTests)
gtest_discover_tests(SDKTests)
gtest_discover_tests(PatchGeneratorTests)
gtest_discover_tests(VMDeobfuscatorTests)

if(CURL_FOUND)
    gtest_discover_tests(HttpClientTests)
    gtest_discover_tests(RequestSignerTests)
    gtest_discover_tests(RequestSigningIntegrationTests)
    gtest_discover_tests(HeartbeatTests)
endif()

if(SENTINEL_BUILD_CORTEX)
    gtest_discover_tests(CortexTests)
endif()

# Add test target
add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS CoreTests SDKTests PatchGeneratorTests VMDeobfuscatorTests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
