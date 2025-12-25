#pragma once
#include <QObject>
#include <QString>

namespace Sentinel::Cortex {

class VMTraceController : public QObject {
    Q_OBJECT
    
    Q_PROPERTY(bool binaryLoaded READ binaryLoaded NOTIFY binaryLoadedChanged)
    Q_PROPERTY(bool isAnalyzing READ isAnalyzing NOTIFY isAnalyzingChanged)
    Q_PROPERTY(int handlerCount READ handlerCount NOTIFY handlerCountChanged)
    Q_PROPERTY(QString liftedCode READ liftedCode NOTIFY liftedCodeChanged)
    
public:
    explicit VMTraceController(QObject* parent = nullptr);
    ~VMTraceController() = default;
    
    // Property getters
    bool binaryLoaded() const { return m_binaryLoaded; }
    bool isAnalyzing() const { return m_isAnalyzing; }
    int handlerCount() const { return m_handlerCount; }
    QString liftedCode() const { return m_liftedCode; }
    
public slots:
    void loadBinary(const QString& path);
    void startAnalysis();
    void stopAnalysis();
    
signals:
    void binaryLoadedChanged();
    void isAnalyzingChanged();
    void handlerCountChanged();
    void liftedCodeChanged();
    void analysisProgressChanged(int phase, double progress);
    void analysisCompleted();
    
private:
    bool m_binaryLoaded = false;
    bool m_isAnalyzing = false;
    int m_handlerCount = 0;
    QString m_liftedCode;
};

} // namespace Sentinel::Cortex
