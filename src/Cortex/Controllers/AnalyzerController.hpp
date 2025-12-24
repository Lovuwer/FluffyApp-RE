#pragma once
#include <QObject>
namespace Sentinel::Cortex {
class AnalyzerController : public QObject {
    Q_OBJECT
public:
    explicit AnalyzerController(QObject* parent = nullptr) : QObject(parent) {}
    ~AnalyzerController() = default;
};
}
