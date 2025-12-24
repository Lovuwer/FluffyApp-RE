/**
 * DashboardController.hpp
 */

#pragma once

#include <QObject>

namespace Sentinel::Cortex {

class DashboardController : public QObject {
    Q_OBJECT
    
public:
    explicit DashboardController(QObject* parent = nullptr) : QObject(parent) {}
    ~DashboardController() = default;
};

} // namespace Sentinel::Cortex
