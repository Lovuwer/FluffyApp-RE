/**
 * Sentinel SDK - Initialization Randomizer
 * 
 * Task 22: Runtime Behavior Variation
 * 
 * Purpose:
 * Randomizes the order of component initialization where dependencies permit.
 * This prevents attackers from predicting the exact initialization sequence,
 * making timing-based attacks more difficult.
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#pragma once

#include <Sentinel/Core/Crypto.hpp>
#include <Sentinel/Core/Logger.hpp>
#include <vector>
#include <string>
#include <functional>
#include <memory>

namespace Sentinel {
namespace SDK {

/**
 * Represents a component that can be initialized
 */
struct InitializationComponent {
    std::string name;                           ///< Component name for logging
    std::function<void()> initialize_func;      ///< Initialization function
    std::vector<std::string> dependencies;      ///< Names of components this depends on
    bool initialized;                           ///< Whether component is initialized
    
    InitializationComponent(const std::string& n, 
                           std::function<void()> func,
                           const std::vector<std::string>& deps = {})
        : name(n)
        , initialize_func(std::move(func))
        , dependencies(deps)
        , initialized(false)
    {}
};

/**
 * Manages randomized initialization of SDK components
 * 
 * Features:
 * - Respects dependency constraints (components wait for dependencies)
 * - Randomizes order where no dependencies exist
 * - Logs the actual initialization order internally
 * - Uses cryptographically secure randomness
 */
class InitializationRandomizer {
public:
    InitializationRandomizer();
    ~InitializationRandomizer() = default;
    
    /**
     * Register a component for initialization
     * @param name Component name
     * @param init_func Function to call to initialize component
     * @param dependencies Names of components that must be initialized first
     */
    void RegisterComponent(const std::string& name,
                           std::function<void()> init_func,
                           const std::vector<std::string>& dependencies = {});
    
    /**
     * Initialize all registered components in randomized order
     * Respects dependency constraints
     */
    void InitializeAll();
    
    /**
     * Get the actual initialization order used (for logging/debugging)
     * @return Vector of component names in order they were initialized
     */
    const std::vector<std::string>& GetActualOrder() const { return actual_order_; }
    
    /**
     * Clear all registered components (for testing)
     */
    void Clear();
    
private:
    /**
     * Check if a component's dependencies are all satisfied
     * @param component Component to check
     * @return true if all dependencies are initialized
     */
    bool DependenciesSatisfied(const InitializationComponent& component) const;
    
    /**
     * Get list of components that can be initialized now
     * (all dependencies satisfied, not yet initialized)
     * @return Indices of ready components
     */
    std::vector<size_t> GetReadyComponents() const;
    
    /**
     * Shuffle a vector using cryptographically secure randomness
     * @param indices Vector to shuffle
     */
    void SecureShuffle(std::vector<size_t>& indices);
    
    std::vector<InitializationComponent> components_;
    std::vector<std::string> actual_order_;
    std::unique_ptr<Sentinel::Crypto::SecureRandom> secure_random_;
    bool initialized_rng_;
};

} // namespace SDK
} // namespace Sentinel
