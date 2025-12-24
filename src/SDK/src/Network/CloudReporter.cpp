/**
 * Sentinel SDK - Implementation
 * 
 * Copyright (c) 2025 Sentinel Security. All rights reserved.
 * 
 * This is a stub implementation created as part of Phase 1: Foundation Setup
 * TODO: Implement actual functionality according to production readiness plan
 */

#include "Internal/Detection.hpp"
#include <cstring>

namespace Sentinel {
namespace SDK {

// CloudReporter stub implementation
CloudReporter::CloudReporter(const char* endpoint) : endpoint_(endpoint ? endpoint : "") {}
CloudReporter::~CloudReporter() {}

void CloudReporter::QueueEvent(const ViolationEvent&) {}
ErrorCode CloudReporter::ReportCustomEvent(const char*, const char*) { return ErrorCode::Success; }
void CloudReporter::Flush() {}
void CloudReporter::ReportThread() {}
ErrorCode CloudReporter::SendBatch() { return ErrorCode::Success; }

} // namespace SDK
} // namespace Sentinel
