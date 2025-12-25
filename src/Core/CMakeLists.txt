# ============================================================================
# Sentinel Core Library - CMake Configuration
# ============================================================================

add_library(SentinelCore STATIC)

target_sources(SentinelCore
    PRIVATE
        # Types and common definitions
        Types/Types.cpp
        Types/ErrorCodes.cpp
        Types/Result.cpp
        
        # Cryptographic utilities
        Crypto/AESCipher.cpp
        Crypto/RSASigner.cpp
        Crypto/HashEngine.cpp
        Crypto/SecureRandom.cpp
        Crypto/HMAC.cpp
        
        # Memory manipulation
        Memory/MemoryScanner.cpp
        Memory/MemoryWriter.cpp
        Memory/RegionEnumerator.cpp
        Memory/PatternScanner.cpp
        Memory/ProtectionManager.cpp
        
        # Network operations
        Network/HttpClient.cpp
        Network/TlsContext.cpp
        Network/CertPinner.cpp
        Network/RequestSigner.cpp
        
        # Utilities
        Utils/Logger.cpp
        Utils/ThreadPool.cpp
        Utils/Config.cpp
        Utils/StringUtils.cpp
        Utils/BinaryUtils.cpp
        Utils/TimeUtils.cpp
)

target_include_directories(SentinelCore
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${SENTINEL_INCLUDE_DIR}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(SentinelCore
    PUBLIC
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        OpenSSL::Crypto
        OpenSSL::SSL
)

target_compile_definitions(SentinelCore
    PRIVATE
        SENTINEL_CORE_EXPORTS
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
)

# Precompiled header (only on Windows)
if(WIN32)
    target_precompile_headers(SentinelCore
        PRIVATE
            <Windows.h>
            <cstdint>
            <string>
            <vector>
            <memory>
            <optional>
            <functional>
    )
else()
    target_precompile_headers(SentinelCore
        PRIVATE
            <cstdint>
            <string>
            <vector>
            <memory>
            <optional>
            <functional>
    )
endif()

# Set output name
set_target_properties(SentinelCore PROPERTIES
    OUTPUT_NAME "SentinelCore"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)
