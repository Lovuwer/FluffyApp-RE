#pragma once
#include <QObject>
namespace Sentinel::Cortex {
class VMTraceController : public QObject {
    Q_OBJECT
public:
    explicit VMTraceController(QObject* parent = nullptr) : QObject(parent) {}
    ~VMTraceController() = default;
};
}
