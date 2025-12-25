#include "SettingsController.hpp"
#include <QSettings>

namespace Sentinel::Cortex {

SettingsController::SettingsController(QObject* parent)
    : QObject(parent)
    , m_expertMode(false)
    , m_darkTheme(true)
    , m_fontSize(12)
{
    loadSettings();
}

void SettingsController::setExpertMode(bool enabled) {
    if (m_expertMode != enabled) {
        m_expertMode = enabled;
        emit expertModeChanged();
    }
}

void SettingsController::setDarkTheme(bool enabled) {
    if (m_darkTheme != enabled) {
        m_darkTheme = enabled;
        emit darkThemeChanged();
    }
}

void SettingsController::setFontSize(int size) {
    if (m_fontSize != size) {
        m_fontSize = size;
        emit fontSizeChanged();
    }
}

void SettingsController::saveSettings() {
    QSettings settings("SentinelSecurity", "SentinelCortex");
    settings.setValue("expertMode", m_expertMode);
    settings.setValue("darkTheme", m_darkTheme);
    settings.setValue("fontSize", m_fontSize);
}

void SettingsController::loadSettings() {
    QSettings settings("SentinelSecurity", "SentinelCortex");
    m_expertMode = settings.value("expertMode", false).toBool();
    m_darkTheme = settings.value("darkTheme", true).toBool();
    m_fontSize = settings.value("fontSize", 12).toInt();
    
    emit expertModeChanged();
    emit darkThemeChanged();
    emit fontSizeChanged();
}

void SettingsController::resetToDefaults() {
    setExpertMode(false);
    setDarkTheme(true);
    setFontSize(12);
}

} // namespace Sentinel::Cortex
