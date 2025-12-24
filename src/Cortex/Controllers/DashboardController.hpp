/**
 * DashboardController.hpp
 */

#pragma once

#include <QObject>
#include <QString>

namespace Sentinel::Cortex {

class DashboardController : public QObject {
    Q_OBJECT
    
    Q_PROPERTY(bool isConnected READ isConnected NOTIFY isConnectedChanged)
    Q_PROPERTY(bool isSyncing READ isSyncing NOTIFY isSyncingChanged)
    Q_PROPERTY(int attacksBlocked READ attacksBlocked NOTIFY attacksBlockedChanged)
    Q_PROPERTY(int activePatches READ activePatches NOTIFY activePatchesChanged)
    Q_PROPERTY(int signatureCount READ signatureCount NOTIFY signatureCountChanged)
    Q_PROPERTY(int threatLevel READ threatLevel NOTIFY threatLevelChanged)
    Q_PROPERTY(QString threatLevelText READ threatLevelText NOTIFY threatLevelChanged)
    Q_PROPERTY(QString threatLevelColor READ threatLevelColor NOTIFY threatLevelChanged)
    
public:
    explicit DashboardController(QObject* parent = nullptr);
    ~DashboardController() = default;
    
    // Property getters
    bool isConnected() const { return m_isConnected; }
    bool isSyncing() const { return m_isSyncing; }
    int attacksBlocked() const { return m_attacksBlocked; }
    int activePatches() const { return m_activePatches; }
    int signatureCount() const { return m_signatureCount; }
    int threatLevel() const { return m_threatLevel; }
    QString threatLevelText() const;
    QString threatLevelColor() const;
    
public slots:
    void syncSignatures();
    void updateMetrics();
    
signals:
    void isConnectedChanged();
    void isSyncingChanged();
    void attacksBlockedChanged();
    void activePatchesChanged();
    void signatureCountChanged();
    void threatLevelChanged();
    
private:
    bool m_isConnected = false;
    bool m_isSyncing = false;
    int m_attacksBlocked = 0;
    int m_activePatches = 0;
    int m_signatureCount = 0;
    int m_threatLevel = 0;
};

} // namespace Sentinel::Cortex
