#pragma once
#include <QObject>
#include <QString>

namespace Sentinel::Cortex {

class DiffController : public QObject {
    Q_OBJECT
    
    Q_PROPERTY(bool hasDiff READ hasDiff NOTIFY hasDiffChanged)
    Q_PROPERTY(int matchedFunctions READ matchedFunctions NOTIFY matchedFunctionsChanged)
    Q_PROPERTY(int modifiedFunctions READ modifiedFunctions NOTIFY modifiedFunctionsChanged)
    Q_PROPERTY(double similarityScore READ similarityScore NOTIFY similarityScoreChanged)
    
public:
    explicit DiffController(QObject* parent = nullptr);
    ~DiffController() = default;
    
    // Property getters
    bool hasDiff() const { return m_hasDiff; }
    int matchedFunctions() const { return m_matchedFunctions; }
    int modifiedFunctions() const { return m_modifiedFunctions; }
    double similarityScore() const { return m_similarityScore; }
    
public slots:
    void compareBinaries(const QString& file1, const QString& file2);
    void generatePatch();
    
signals:
    void hasDiffChanged();
    void matchedFunctionsChanged();
    void modifiedFunctionsChanged();
    void similarityScoreChanged();
    
private:
    bool m_hasDiff = false;
    int m_matchedFunctions = 0;
    int m_modifiedFunctions = 0;
    double m_similarityScore = 0.0;
};

} // namespace Sentinel::Cortex
