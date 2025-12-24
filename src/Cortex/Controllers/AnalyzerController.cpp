#include "AnalyzerController.hpp"
#include <QFileInfo>

namespace Sentinel::Cortex {

AnalyzerController::AnalyzerController(QObject* parent)
    : QObject(parent)
    , m_hasFile(false)
    , m_hasAnalysis(false)
    , m_functionCount(0)
    , m_instructionCount(0)
{
}

void AnalyzerController::loadFile(const QUrl& url) {
    QString path = url.toLocalFile();
    if (path.isEmpty()) {
        path = url.toString();
        // Remove file:/// prefix if present
        if (path.startsWith("file:///")) {
            path = path.mid(8);
        }
    }
    
    QFileInfo fileInfo(path);
    if (!fileInfo.exists()) {
        return;
    }
    
    m_currentFile = fileInfo.fileName();
    m_hasFile = true;
    m_hasAnalysis = false;
    
    emit currentFileChanged();
    emit hasFileChanged();
    emit hasAnalysisChanged();
}

void AnalyzerController::disassemble() {
    if (!m_hasFile) return;
    
    // TODO: Connect to actual Disassembler backend
    // For now, simulate analysis
    m_hasAnalysis = true;
    m_functionCount = 42;
    m_instructionCount = 15234;
    
    emit hasAnalysisChanged();
    emit functionCountChanged();
    emit instructionCountChanged();
}

void AnalyzerController::computeFuzzyHash() {
    if (!m_hasFile) return;
    
    // TODO: Connect to FuzzyHasher backend
}

} // namespace Sentinel::Cortex
