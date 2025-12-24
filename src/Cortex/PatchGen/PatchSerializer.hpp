/**
 * PatchSerializer.hpp
 * Patch serialization support
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace Sentinel::Cortex {

class PatchSerializer {
public:
    PatchSerializer() = default;
    ~PatchSerializer() = default;
    
    // Stub methods
    bool initialize() { return true; }
    void shutdown() {}
};

} // namespace Sentinel::Cortex
