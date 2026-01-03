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
    Core/test_analysis_resistance.cpp
)

target_link_libraries(CoreTests
    PRIVATE
        SentinelCore
        SentinelTestHarness
        gtest
        gtest_main
)

target_compile_definitions(CoreTests
    PRIVATE
        SENTINEL_TESTING
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
    
    target_compile_definitions(HttpClientTests
        PRIVATE
            SENTINEL_TESTING
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
    
    target_compile_definitions(RequestSignerTests
        PRIVATE
            SENTINEL_TESTING
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
    
    target_compile_definitions(RequestSigningIntegrationTests
        PRIVATE
            SENTINEL_TESTING
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
    
    target_compile_definitions(HeartbeatTests
        PRIVATE
            SENTINEL_TESTING
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
    SDK/test_client_integrity_attestation.cpp
    SDK/test_diversity_engine.cpp
    SDK/test_signature_manager.cpp
    SDK/test_update_client.cpp
    SDK/test_perf_telemetry.cpp
    SDK/test_behavioral_collector.cpp
    SDK/test_redundant_detection.cpp
    SDK/test_heartbeat_integration.cpp
    SDK/test_vm.cpp
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

target_compile_definitions(SDKTests
    PRIVATE
        SENTINEL_TESTING
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

target_compile_definitions(PatchGeneratorTests
    PRIVATE
        SENTINEL_TESTING
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

target_compile_definitions(VMDeobfuscatorTests
    PRIVATE
        SENTINEL_TESTING
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
    
    target_compile_definitions(CortexTests
        PRIVATE
            SENTINEL_TESTING
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

# ============================================================================
# Fuzzing Targets (Task 5.1)
# ============================================================================
# Fuzzing is opt-in via SENTINEL_ENABLE_FUZZING flag
# Requires Clang compiler with -fsanitize=fuzzer support (Clang 6.0+)
#
# HOW TO BUILD:
#   cmake -DSENTINEL_ENABLE_FUZZING=ON -DCMAKE_CXX_COMPILER=clang++ ..
#   cmake --build . --target fuzz_vm
#
# HOW TO RUN:
#   mkdir -p corpus
#   ./bin/fuzz_vm corpus/ -max_len=65536 -timeout=10
#
# WHAT IT TESTS:
#   - VM robustness against malformed bytecode
#   - Memory safety (with AddressSanitizer)
#   - No crashes or hangs
#
# WHY OPTIONAL:
#   - Requires Clang (not MSVC or GCC)
#   - Adds build time overhead
#   - Primarily for security testing, not regular CI
# ============================================================================

if(SENTINEL_ENABLE_FUZZING)
    # Verify we're using Clang (required for -fsanitize=fuzzer)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(WARNING "Fuzzing requires Clang compiler. Skipping fuzzer targets.")
    else()
        message(STATUS "Fuzzing enabled - building fuzz_vm target")
        
        # ====================================================================
        # fuzz_vm: Fuzzing target for VMInterpreter
        # ====================================================================
        # This executable uses LibFuzzer to test VM against malformed bytecode
        # It links statically to avoid runtime dependencies
        add_executable(fuzz_vm 
            SDK/fuzz_vm.cpp
        )
        
        # Link against SDK library
        # Use SentinelSDK_static to avoid shared library issues with fuzzer
        target_link_libraries(fuzz_vm 
            PRIVATE 
                SentinelSDK_static
        )
        
        # Include SDK internal headers (needed for VMInterpreter.hpp)
        target_include_directories(fuzz_vm
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/../src/SDK/src
        )
        
        # Fuzzer compile options
        # -fsanitize=fuzzer: Enable LibFuzzer instrumentation
        #   - Adds coverage tracking
        #   - Provides LLVMFuzzerTestOneInput entry point
        #   - Links against libFuzzer runtime
        #
        # -fsanitize=address: Enable AddressSanitizer
        #   - Detects buffer overflows
        #   - Detects use-after-free
        #   - Detects memory leaks
        #   - Essential for security fuzzing
        #
        # Note: We don't use -fsanitize=undefined (UBSan) because:
        # - It can cause false positives in optimized code
        # - It significantly slows down fuzzing
        # - ASan catches most critical issues
        target_compile_options(fuzz_vm 
            PRIVATE 
                -fsanitize=fuzzer,address
                -g  # Debug symbols for better crash reports
        )
        
        # Fuzzer link options
        # Must match compile options for sanitizers
        # -fsanitize=fuzzer also links the fuzzer runtime library
        target_link_options(fuzz_vm 
            PRIVATE 
                -fsanitize=fuzzer,address
        )
        
        # Define SENTINEL_TESTING to enable test-specific code paths
        target_compile_definitions(fuzz_vm
            PRIVATE
                SENTINEL_TESTING
        )
        
        # ====================================================================
        # Fuzzer corpus directory
        # ====================================================================
        # Create corpus directory in build tree for convenience
        # This is where fuzzer stores interesting inputs
        # Users should populate with seed inputs (valid bytecode samples)
        add_custom_command(
            TARGET fuzz_vm POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory 
                    ${CMAKE_BINARY_DIR}/corpus/fuzz_vm
            COMMENT "Creating fuzzer corpus directory"
        )
        
        # ====================================================================
        # Usage instructions
        # ====================================================================
        # Print helpful message after building
        add_custom_command(
            TARGET fuzz_vm POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
            COMMAND ${CMAKE_COMMAND} -E echo "Fuzzer built successfully!"
            COMMAND ${CMAKE_COMMAND} -E echo ""
            COMMAND ${CMAKE_COMMAND} -E echo "To run fuzzer:"
            COMMAND ${CMAKE_COMMAND} -E echo "  cd ${CMAKE_BINARY_DIR}"
            COMMAND ${CMAKE_COMMAND} -E echo "  ./bin/fuzz_vm corpus/fuzz_vm/ -max_len=65536 -timeout=10"
            COMMAND ${CMAKE_COMMAND} -E echo ""
            COMMAND ${CMAKE_COMMAND} -E echo "For 1-hour fuzzing session:"
            COMMAND ${CMAKE_COMMAND} -E echo "  ./bin/fuzz_vm corpus/fuzz_vm/ -max_total_time=3600"
            COMMAND ${CMAKE_COMMAND} -E echo ""
            COMMAND ${CMAKE_COMMAND} -E echo "Add seed corpus files to: corpus/fuzz_vm/"
            COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
            VERBATIM
        )
    endif()
endif()

# Add test target
add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS CoreTests SDKTests PatchGeneratorTests VMDeobfuscatorTests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
