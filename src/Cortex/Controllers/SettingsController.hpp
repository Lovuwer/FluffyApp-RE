#pragma once
#include <QObject>

namespace Sentinel::Cortex {

class SettingsController : public QObject {
    Q_OBJECT
    
    Q_PROPERTY(bool expertMode READ expertMode WRITE setExpertMode NOTIFY expertModeChanged)
    Q_PROPERTY(bool darkTheme READ darkTheme WRITE setDarkTheme NOTIFY darkThemeChanged)
    Q_PROPERTY(int fontSize READ fontSize WRITE setFontSize NOTIFY fontSizeChanged)
    
public:
    explicit SettingsController(QObject* parent = nullptr);
    ~SettingsController() = default;
    
    // Property getters
    bool expertMode() const { return m_expertMode; }
    bool darkTheme() const { return m_darkTheme; }
    int fontSize() const { return m_fontSize; }
    
    // Property setters
    void setExpertMode(bool enabled);
    void setDarkTheme(bool enabled);
    void setFontSize(int size);
    
public slots:
    void saveSettings();
    void loadSettings();
    void resetToDefaults();
    
signals:
    void expertModeChanged();
    void darkThemeChanged();
    void fontSizeChanged();
    
private:
    bool m_expertMode = false;
    bool m_darkTheme = true;
    int m_fontSize = 12;
};

} // namespace Sentinel::Cortex
