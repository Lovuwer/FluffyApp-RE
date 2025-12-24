#pragma once
#include <QObject>
namespace Sentinel::Cortex {
class CloudSync : public QObject {
    Q_OBJECT
public:
    explicit CloudSync(QObject* parent = nullptr) : QObject(parent) {}
    ~CloudSync() = default;
};
}
