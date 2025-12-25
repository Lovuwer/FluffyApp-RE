#include "DiffController.hpp"

namespace Sentinel::Cortex {

DiffController::DiffController(QObject* parent)
    : QObject(parent)
    , m_hasDiff(false)
    , m_matchedFunctions(0)
    , m_modifiedFunctions(0)
    , m_similarityScore(0.0)
{
}

void DiffController::compareBinaries(const QString& file1, const QString& file2) {
    // TODO: Connect to DiffEngine backend
    // For now, simulate diff results
    m_hasDiff = true;
    m_matchedFunctions = 156;
    m_modifiedFunctions = 8;
    m_similarityScore = 92.5;
    
    emit hasDiffChanged();
    emit matchedFunctionsChanged();
    emit modifiedFunctionsChanged();
    emit similarityScoreChanged();
}

void DiffController::generatePatch() {
    if (!m_hasDiff) return;
    
    // TODO: Connect to PatchGenerator backend
}

} // namespace Sentinel::Cortex
