#include "DashboardController.hpp"
#include <QTimer>

namespace Sentinel::Cortex {

DashboardController::DashboardController(QObject* parent)
    : QObject(parent)
    , m_isConnected(false)
    , m_isSyncing(false)
    , m_attacksBlocked(1247)
    , m_activePatches(23)
    , m_signatureCount(45891)
    , m_threatLevel(35)
{
}

QString DashboardController::threatLevelText() const {
    if (m_threatLevel < 20) return "Low";
    if (m_threatLevel < 50) return "Medium";
    if (m_threatLevel < 75) return "High";
    return "Critical";
}

QString DashboardController::threatLevelColor() const {
    if (m_threatLevel < 20) return "#3FB950"; // success
    if (m_threatLevel < 50) return "#58A6FF"; // info
    if (m_threatLevel < 75) return "#D29922"; // warning
    return "#F85149"; // danger
}

void DashboardController::syncSignatures() {
    if (m_isSyncing) return;
    
    m_isSyncing = true;
    emit isSyncingChanged();
    
    // TODO: Implement actual sync with cloud
    // For now, simulate sync completion
    QTimer::singleShot(2000, this, [this]() {
        m_isSyncing = false;
        m_signatureCount += 150;
        emit isSyncingChanged();
        emit signatureCountChanged();
    });
}

void DashboardController::updateMetrics() {
    // TODO: Fetch real metrics from backend
    emit attacksBlockedChanged();
    emit activePatchesChanged();
    emit signatureCountChanged();
    emit threatLevelChanged();
}

} // namespace Sentinel::Cortex
