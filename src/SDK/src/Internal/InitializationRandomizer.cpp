/**
 * Sentinel SDK - Initialization Randomizer Implementation
 * 
 * Task 22: Runtime Behavior Variation
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include "InitializationRandomizer.hpp"
#include <algorithm>
#include <stdexcept>
#include <sstream>

namespace Sentinel {
namespace SDK {

InitializationRandomizer::InitializationRandomizer()
    : initialized_rng_(false)
{
    try {
        secure_random_ = std::make_unique<Sentinel::Crypto::SecureRandom>();
        
        // Test the random generator
        auto test_result = secure_random_->generateValue<uint32_t>();
        if (test_result.isSuccess()) {
            initialized_rng_ = true;
        }
    } catch (...) {
        SENTINEL_LOG_WARNING("Failed to initialize SecureRandom for InitializationRandomizer");
    }
}

void InitializationRandomizer::RegisterComponent(const std::string& name,
                                                 std::function<void()> init_func,
                                                 const std::vector<std::string>& dependencies) {
    components_.emplace_back(name, std::move(init_func), dependencies);
    SENTINEL_LOG_DEBUG_F("[InitOrder] Registered component: %s (deps: %zu)", 
                         name.c_str(), dependencies.size());
}

bool InitializationRandomizer::DependenciesSatisfied(const InitializationComponent& component) const {
    for (const auto& dep_name : component.dependencies) {
        bool found = false;
        for (const auto& comp : components_) {
            if (comp.name == dep_name && comp.initialized) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    return true;
}

std::vector<size_t> InitializationRandomizer::GetReadyComponents() const {
    std::vector<size_t> ready;
    for (size_t i = 0; i < components_.size(); ++i) {
        if (!components_[i].initialized && DependenciesSatisfied(components_[i])) {
            ready.push_back(i);
        }
    }
    return ready;
}

void InitializationRandomizer::SecureShuffle(std::vector<size_t>& indices) {
    if (!initialized_rng_ || !secure_random_) {
        SENTINEL_LOG_WARNING("[InitOrder] RNG not initialized, using deterministic fallback");
        return;  // No shuffle, deterministic order
    }
    
    if (indices.size() <= 1) {
        return;  // Nothing to shuffle
    }
    
    // Fisher-Yates shuffle with cryptographically secure randomness
    for (size_t i = indices.size() - 1; i > 0; --i) {
        // Generate random index in range [0, i]
        auto result = secure_random_->generateValue<uint32_t>();
        if (result.isFailure()) {
            SENTINEL_LOG_WARNING("[InitOrder] Failed to generate random value during shuffle");
            return;  // Stop shuffling on error
        }
        
        uint32_t random_value = result.value();
        
        // Use rejection sampling to avoid modulo bias
        uint32_t range = static_cast<uint32_t>(i + 1);
        uint32_t limit = UINT32_MAX - (UINT32_MAX % range);
        
        int retry_count = 0;
        while (random_value >= limit && retry_count < 10) {
            auto retry_result = secure_random_->generateValue<uint32_t>();
            if (retry_result.isFailure()) {
                break;
            }
            random_value = retry_result.value();
            retry_count++;
        }
        
        size_t j = random_value % range;
        std::swap(indices[i], indices[j]);
    }
}

void InitializationRandomizer::InitializeAll() {
    if (components_.empty()) {
        SENTINEL_LOG_WARNING("[InitOrder] No components registered for initialization");
        return;
    }
    
    SENTINEL_LOG_INFO_F("[InitOrder] Initializing %zu components in randomized order", 
                        components_.size());
    
    actual_order_.clear();
    actual_order_.reserve(components_.size());
    
    size_t initialized_count = 0;
    // Maximum iterations: component_count * 2 to prevent infinite loops
    // Factor of 2 allows for complex dependency graphs with multiple passes
    constexpr size_t MAX_ITERATION_MULTIPLIER = 2;
    size_t max_iterations = components_.size() * MAX_ITERATION_MULTIPLIER;
    size_t iteration = 0;
    
    while (initialized_count < components_.size() && iteration < max_iterations) {
        iteration++;
        
        // Get components ready to initialize
        std::vector<size_t> ready = GetReadyComponents();
        
        if (ready.empty()) {
            // No components ready - check if we have uninitialized components with unsatisfied deps
            bool has_uninitialized = false;
            std::stringstream deps_info;
            for (const auto& comp : components_) {
                if (!comp.initialized) {
                    has_uninitialized = true;
                    deps_info << comp.name << " (waiting for: ";
                    for (const auto& dep : comp.dependencies) {
                        bool dep_satisfied = false;
                        for (const auto& c : components_) {
                            if (c.name == dep && c.initialized) {
                                dep_satisfied = true;
                                break;
                            }
                        }
                        if (!dep_satisfied) {
                            deps_info << dep << " ";
                        }
                    }
                    deps_info << ") ";
                }
            }
            
            if (has_uninitialized) {
                SENTINEL_LOG_ERROR_F("[InitOrder] Dependency deadlock or missing dependencies: %s",
                                     deps_info.str().c_str());
                throw std::runtime_error("Initialization dependency deadlock");
            }
            break;
        }
        
        // Shuffle the ready components for randomization
        SecureShuffle(ready);
        
        // Initialize all ready components in shuffled order
        for (size_t idx : ready) {
            auto& component = components_[idx];
            
            SENTINEL_LOG_DEBUG_F("[InitOrder] Initializing: %s", component.name.c_str());
            
            try {
                component.initialize_func();
                component.initialized = true;
                actual_order_.push_back(component.name);
                initialized_count++;
            } catch (const std::exception& e) {
                SENTINEL_LOG_ERROR_F("[InitOrder] Failed to initialize %s: %s",
                                     component.name.c_str(), e.what());
                throw;
            }
        }
    }
    
    if (initialized_count < components_.size()) {
        SENTINEL_LOG_ERROR_F("[InitOrder] Only initialized %zu/%zu components",
                             initialized_count, components_.size());
        throw std::runtime_error("Failed to initialize all components");
    }
    
    // Log the final initialization order
    std::stringstream order_str;
    for (size_t i = 0; i < actual_order_.size(); ++i) {
        if (i > 0) order_str << " -> ";
        order_str << actual_order_[i];
    }
    SENTINEL_LOG_INFO_F("[InitOrder] Initialization sequence: %s", order_str.str().c_str());
}

void InitializationRandomizer::Clear() {
    components_.clear();
    actual_order_.clear();
}

} // namespace SDK
} // namespace Sentinel
