#pragma once
#include <QObject>
namespace Sentinel::Cortex {
class DiffController : public QObject {
    Q_OBJECT
public:
    explicit DiffController(QObject* parent = nullptr) : QObject(parent) {}
    ~DiffController() = default;
};
}
