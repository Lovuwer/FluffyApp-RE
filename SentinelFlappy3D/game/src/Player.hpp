#pragma once

#include "Physics.hpp"
#include <glm/glm.hpp>

namespace SentinelFlappy3D {

class Player {
public:
    Player();

    // Reset player to initial state
    void Reset();

    // Update player physics
    void Update(float deltaTime);

    // Apply upward velocity (flap)
    void Flap();

    // Get player position
    const glm::vec2& GetPosition() const { return m_position; }

    // Get player bounding box for collision
    AABB GetBoundingBox() const;

    // Check if player is alive
    bool IsAlive() const { return m_alive; }

    // Kill the player
    void Kill() { m_alive = false; }

    // Get player size
    float GetSize() const { return m_size; }

private:
    glm::vec2 m_position;
    float m_velocityY;
    float m_size;
    bool m_alive;

    // Constants
    static constexpr float FLAP_STRENGTH = 400.0f;
    static constexpr float GRAVITY = 980.0f;
    static constexpr float MAX_FALL_SPEED = 600.0f;
};

} // namespace SentinelFlappy3D
