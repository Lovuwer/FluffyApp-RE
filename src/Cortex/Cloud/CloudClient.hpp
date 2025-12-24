#pragma once
#include <QObject>
namespace Sentinel::Cortex {
class CloudClient : public QObject {
    Q_OBJECT
public:
    explicit CloudClient(QObject* parent = nullptr) : QObject(parent) {}
    ~CloudClient() = default;
};
}
