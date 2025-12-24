#pragma once
#include <QObject>
namespace Sentinel::Cortex {
class SettingsController : public QObject {
    Q_OBJECT
public:
    explicit SettingsController(QObject* parent = nullptr) : QObject(parent) {}
    ~SettingsController() = default;
};
}
