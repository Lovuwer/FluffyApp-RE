#include "Physics.hpp"
#include <algorithm>

namespace SentinelFlappy3D {

bool Physics::CheckCollision(const AABB& a, const AABB& b) {
    return (a.min.x < b.max.x && a.max.x > b.min.x &&
            a.min.y < b.max.y && a.max.y > b.min.y);
}

void Physics::ApplyGravity(float& velocityY, float deltaTime, float gravity) {
    velocityY += gravity * deltaTime;
}

} // namespace SentinelFlappy3D
