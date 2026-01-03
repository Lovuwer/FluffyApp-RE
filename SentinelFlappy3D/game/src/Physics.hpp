#pragma once

#include <glm/glm.hpp>

namespace SentinelFlappy3D {

// Simple axis-aligned bounding box for collision detection
struct AABB {
    glm::vec2 min;
    glm::vec2 max;

    AABB() : min(0.0f), max(0.0f) {}
    AABB(const glm::vec2& min, const glm::vec2& max) : min(min), max(max) {}
};

class Physics {
public:
    Physics() = default;

    // Check collision between two AABBs
    static bool CheckCollision(const AABB& a, const AABB& b);

    // Apply gravity to velocity
    static void ApplyGravity(float& velocityY, float deltaTime, float gravity = 980.0f);
};

} // namespace SentinelFlappy3D
