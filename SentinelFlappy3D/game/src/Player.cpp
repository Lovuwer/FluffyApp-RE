#include "Player.hpp"
#include <algorithm>

namespace SentinelFlappy3D {

Player::Player()
    : m_position(100.0f, 300.0f)
    , m_velocityY(0.0f)
    , m_size(30.0f)
    , m_alive(true) {
}

void Player::Reset() {
    m_position = glm::vec2(100.0f, 300.0f);
    m_velocityY = 0.0f;
    m_alive = true;
}

void Player::Update(float deltaTime) {
    if (!m_alive) return;

    // Apply gravity
    Physics::ApplyGravity(m_velocityY, deltaTime, GRAVITY);

    // Clamp fall speed
    m_velocityY = std::min(m_velocityY, MAX_FALL_SPEED);

    // Update position
    m_position.y += m_velocityY * deltaTime;
}

void Player::Flap() {
    if (!m_alive) return;
    m_velocityY = -FLAP_STRENGTH;
}

AABB Player::GetBoundingBox() const {
    float halfSize = m_size * 0.5f;
    return AABB(
        glm::vec2(m_position.x - halfSize, m_position.y - halfSize),
        glm::vec2(m_position.x + halfSize, m_position.y + halfSize)
    );
}

} // namespace SentinelFlappy3D
