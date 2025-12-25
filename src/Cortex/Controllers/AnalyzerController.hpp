#pragma once
#include <QObject>
#include <QString>
#include <QUrl>

namespace Sentinel::Cortex {

class AnalyzerController : public QObject {
    Q_OBJECT
    
    Q_PROPERTY(bool hasFile READ hasFile NOTIFY hasFileChanged)
    Q_PROPERTY(bool hasAnalysis READ hasAnalysis NOTIFY hasAnalysisChanged)
    Q_PROPERTY(QString currentFile READ currentFile NOTIFY currentFileChanged)
    Q_PROPERTY(int functionCount READ functionCount NOTIFY functionCountChanged)
    Q_PROPERTY(int instructionCount READ instructionCount NOTIFY instructionCountChanged)
    
public:
    explicit AnalyzerController(QObject* parent = nullptr);
    ~AnalyzerController() = default;
    
    // Property getters
    bool hasFile() const { return m_hasFile; }
    bool hasAnalysis() const { return m_hasAnalysis; }
    QString currentFile() const { return m_currentFile; }
    int functionCount() const { return m_functionCount; }
    int instructionCount() const { return m_instructionCount; }
    
public slots:
    void loadFile(const QUrl& url);
    void disassemble();
    void computeFuzzyHash();
    
signals:
    void hasFileChanged();
    void hasAnalysisChanged();
    void currentFileChanged();
    void functionCountChanged();
    void instructionCountChanged();
    
private:
    bool m_hasFile = false;
    bool m_hasAnalysis = false;
    QString m_currentFile;
    int m_functionCount = 0;
    int m_instructionCount = 0;
};

} // namespace Sentinel::Cortex
