# ============================================================================
# Sentinel Cortex - Developer Workbench
# ============================================================================

# Require Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick Widgets Network)

qt_standard_project_setup()

# Enable Qt's automatic resource management
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# ============================================================================
# Executable
# ============================================================================

qt_add_executable(SentinelCortex
    # Application entry
    main.cpp
    
    # Core application
    Application/CortexApplication.cpp
    Application/CortexApplication.hpp
    
    # Analysis engine
    Analysis/BinaryAnalyzer.cpp
    Analysis/BinaryAnalyzer.hpp
    Analysis/Disassembler.cpp
    Analysis/Disassembler.hpp
    Analysis/FuzzyHasher.cpp
    Analysis/FuzzyHasher.hpp
    Analysis/DiffEngine.cpp
    Analysis/DiffEngine.hpp
    Analysis/SignatureDatabase.cpp
    Analysis/SignatureDatabase.hpp
    
    # Patch generation
    PatchGen/PatchGenerator.cpp
    PatchGen/PatchGenerator.hpp
    PatchGen/PatchSerializer.cpp
    PatchGen/PatchSerializer.hpp
    
    # VM Deobfuscation Engine
    VMDeobfuscator/VMDeobfuscator.cpp
    VMDeobfuscator/VMDeobfuscator.hpp
    VMDeobfuscator/DynamicTracer.cpp
    VMDeobfuscator/DynamicTracer.hpp
    VMDeobfuscator/SymbolicEngine.cpp
    VMDeobfuscator/SymbolicEngine.hpp
    VMDeobfuscator/SSALifter.cpp
    VMDeobfuscator/SSALifter.hpp
    VMDeobfuscator/PatternMatcher.cpp
    VMDeobfuscator/PatternMatcher.hpp
    
    # Qt/QML Controllers
    Controllers/DashboardController.cpp
    Controllers/DashboardController.hpp
    Controllers/AnalyzerController.cpp
    Controllers/AnalyzerController.hpp
    Controllers/DiffController.cpp
    Controllers/DiffController.hpp
    Controllers/VMTraceController.cpp
    Controllers/VMTraceController.hpp
    Controllers/SettingsController.cpp
    Controllers/SettingsController.hpp
    
    # Cloud integration
    Cloud/CloudClient.cpp
    Cloud/CloudClient.hpp
    Cloud/CloudSync.cpp
    Cloud/CloudSync.hpp
)

# ============================================================================
# QML Module
# ============================================================================

qt_add_qml_module(SentinelCortex
    URI Sentinel.Cortex
    VERSION 1.0
    QML_FILES
        UI/qml/Main.qml
        UI/qml/Theme.qml
        UI/qml/Components/SentinelButton.qml
        UI/qml/Components/SentinelTextField.qml
        UI/qml/Components/SentinelCard.qml
        UI/qml/Components/CodeView.qml
        UI/qml/Components/HexView.qml
        UI/qml/Components/DiffView.qml
        UI/qml/Components/GraphView.qml
        UI/qml/Views/DashboardView.qml
        UI/qml/Views/AnalyzerView.qml
        UI/qml/Views/DiffResultView.qml
        UI/qml/Views/VMTraceView.qml
        UI/qml/Views/PatchEditorView.qml
        UI/qml/Views/SettingsView.qml
    RESOURCES
        UI/resources/icons/sentinel-logo.svg
        UI/resources/icons/dashboard.svg
        UI/resources/icons/analyze.svg
        UI/resources/icons/diff.svg
        UI/resources/icons/patch.svg
        UI/resources/icons/settings.svg
        UI/resources/fonts/JetBrainsMono-Regular.ttf
)

# ============================================================================
# Include Directories
# ============================================================================

target_include_directories(SentinelCortex
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/Analysis
        ${CMAKE_CURRENT_SOURCE_DIR}/PatchGen
        ${CMAKE_CURRENT_SOURCE_DIR}/VMDeobfuscator
        ${CMAKE_CURRENT_SOURCE_DIR}/Controllers
        ${CMAKE_CURRENT_SOURCE_DIR}/Cloud
)

# ============================================================================
# Link Libraries
# ============================================================================

target_link_libraries(SentinelCortex
    PRIVATE
        SentinelCore
        Qt6::Core
        Qt6::Gui
        Qt6::Qml
        Qt6::Quick
        Qt6::Widgets
        Qt6::Network
        capstone
        nlohmann_json::nlohmann_json
        spdlog::spdlog
)

# ============================================================================
# Compile Definitions
# ============================================================================

target_compile_definitions(SentinelCortex
    PRIVATE
        SENTINEL_CORTEX
        QT_QML_DEBUG
        SENTINEL_VERSION_STRING="${PROJECT_VERSION}"
        $<$<CONFIG:Release>:QT_NO_DEBUG_OUTPUT>
)

# ============================================================================
# Windows-specific settings
# ============================================================================

if(WIN32)
    # Set Windows subsystem
    set_target_properties(SentinelCortex PROPERTIES
        WIN32_EXECUTABLE TRUE
    )
    
    # Application icon
    target_sources(SentinelCortex PRIVATE
        UI/resources/cortex.rc
    )
endif()

# ============================================================================
# Output
# ============================================================================

set_target_properties(SentinelCortex PROPERTIES
    OUTPUT_NAME "SentinelCortex"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
