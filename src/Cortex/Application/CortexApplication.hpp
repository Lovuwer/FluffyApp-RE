/**
 * CortexApplication.hpp
 */

#pragma once

#include <QObject>

namespace Sentinel::Cortex {

class CortexApplication : public QObject {
    Q_OBJECT
    
public:
    explicit CortexApplication(QObject* parent = nullptr) : QObject(parent) {}
    ~CortexApplication() = default;
};

} // namespace Sentinel::Cortex
