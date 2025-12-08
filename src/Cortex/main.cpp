/**
 * @file main.cpp
 * @brief Sentinel Cortex Application Entry Point
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QIcon>
#include <QFontDatabase>
#include <QDir>

#include "Application/CortexApplication.hpp"
#include "Controllers/DashboardController.hpp"
#include "Controllers/AnalyzerController.hpp"
#include "Controllers/DiffController.hpp"
#include "Controllers/VMTraceController.hpp"
#include "Controllers/SettingsController.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

/**
 * @brief Initialize logging system
 */
void initializeLogging() {
    try {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::debug);
        
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            "logs/cortex.log", 1024 * 1024 * 5, 3
        );
        file_sink->set_level(spdlog::level::trace);
        
        auto logger = std::make_shared<spdlog::logger>(
            "cortex",
            spdlog::sinks_init_list{console_sink, file_sink}
        );
        
        logger->set_level(spdlog::level::debug);
        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%s:%#] %v");
        
        spdlog::set_default_logger(logger);
        spdlog::info("Sentinel Cortex starting...");
    }
    catch (const spdlog::spdlog_ex& ex) {
        // Logging initialization failed, continue without file logging
    }
}

/**
 * @brief Register QML types for C++ integration
 */
void registerQmlTypes() {
    // Register singleton types
    qmlRegisterSingletonType<Sentinel::Cortex::DashboardController>(
        "Sentinel.Cortex", 1, 0, "DashboardController",
        [](QQmlEngine* engine, QJSEngine* scriptEngine) -> QObject* {
            Q_UNUSED(engine)
            Q_UNUSED(scriptEngine)
            return new Sentinel::Cortex::DashboardController();
        }
    );
    
    qmlRegisterSingletonType<Sentinel::Cortex::AnalyzerController>(
        "Sentinel.Cortex", 1, 0, "AnalyzerController",
        [](QQmlEngine* engine, QJSEngine* scriptEngine) -> QObject* {
            Q_UNUSED(engine)
            Q_UNUSED(scriptEngine)
            return new Sentinel::Cortex::AnalyzerController();
        }
    );
    
    qmlRegisterSingletonType<Sentinel::Cortex::DiffController>(
        "Sentinel.Cortex", 1, 0, "DiffController",
        [](QQmlEngine* engine, QJSEngine* scriptEngine) -> QObject* {
            Q_UNUSED(engine)
            Q_UNUSED(scriptEngine)
            return new Sentinel::Cortex::DiffController();
        }
    );
    
    qmlRegisterSingletonType<Sentinel::Cortex::VMTraceController>(
        "Sentinel.Cortex", 1, 0, "VMTraceController",
        [](QQmlEngine* engine, QJSEngine* scriptEngine) -> QObject* {
            Q_UNUSED(engine)
            Q_UNUSED(scriptEngine)
            return new Sentinel::Cortex::VMTraceController();
        }
    );
    
    qmlRegisterSingletonType<Sentinel::Cortex::SettingsController>(
        "Sentinel.Cortex", 1, 0, "SettingsController",
        [](QQmlEngine* engine, QJSEngine* scriptEngine) -> QObject* {
            Q_UNUSED(engine)
            Q_UNUSED(scriptEngine)
            return new Sentinel::Cortex::SettingsController();
        }
    );
}

/**
 * @brief Load custom fonts
 */
void loadFonts() {
    // Load JetBrains Mono for code display
    int fontId = QFontDatabase::addApplicationFont(":/fonts/JetBrainsMono-Regular.ttf");
    if (fontId == -1) {
        spdlog::warn("Failed to load JetBrains Mono font");
    }
}

/**
 * @brief Application entry point
 */
int main(int argc, char* argv[]) {
    // High DPI support
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::PassThrough
    );
    
    // Create application
    QGuiApplication app(argc, argv);
    
    // Set application metadata
    app.setOrganizationName("Sentinel Security");
    app.setOrganizationDomain("sentinel-security.com");
    app.setApplicationName("Sentinel Cortex");
    app.setApplicationVersion(SENTINEL_VERSION_STRING);
    
    // Set application icon
    app.setWindowIcon(QIcon(":/icons/sentinel-logo.svg"));
    
    // Initialize logging
    initializeLogging();
    
    // Create logs directory
    QDir().mkpath("logs");
    
    // Set Quick style
    QQuickStyle::setStyle("Basic");
    
    // Load custom fonts
    loadFonts();
    
    // Register QML types
    registerQmlTypes();
    
    // Create QML engine
    QQmlApplicationEngine engine;
    
    // Set context properties
    engine.rootContext()->setContextProperty("APP_VERSION", SENTINEL_VERSION_STRING);
    engine.rootContext()->setContextProperty("BUILD_DATE", __DATE__);
    
    // Load main QML file
    const QUrl url(QStringLiteral("qrc:/Sentinel/Cortex/UI/qml/Main.qml"));
    
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
        &app, [url](QObject* obj, const QUrl& objUrl) {
            if (!obj && url == objUrl) {
                spdlog::error("Failed to load QML");
                QCoreApplication::exit(-1);
            }
        }, Qt::QueuedConnection);
    
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed,
        &app, []() {
            spdlog::error("QML object creation failed");
            QCoreApplication::exit(-1);
        }, Qt::QueuedConnection);
    
    engine.load(url);
    
    spdlog::info("Sentinel Cortex initialized successfully");
    
    return app.exec();
}
