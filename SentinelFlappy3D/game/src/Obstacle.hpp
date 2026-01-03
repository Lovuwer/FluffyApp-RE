#pragma once

#include "Physics.hpp"
#include <glm/glm.hpp>
#include <vector>

namespace SentinelFlappy3D {

struct Pipe {
    float x;              // X position
    float gapY;           // Y position of gap center
    float gapSize;        // Size of the gap
    bool scored;          // Whether player has passed this pipe

    Pipe(float x, float gapY, float gapSize)
        : x(x), gapY(gapY), gapSize(gapSize), scored(false) {}

    // Get bounding boxes for top and bottom pipes
    AABB GetTopPipeBounds(float pipeWidth) const;
    AABB GetBottomPipeBounds(float pipeWidth, float groundY) const;
};

class Obstacle {
public:
    Obstacle();

    // Reset obstacles to initial state
    void Reset();

    // Update obstacle positions and spawn new ones
    void Update(float deltaTime);

    // Get all pipes
    const std::vector<Pipe>& GetPipes() const { return m_pipes; }

    // Check collision with player
    bool CheckCollision(const AABB& playerBounds) const;

    // Check if player scored (passed a pipe)
    int CheckAndUpdateScore(float playerX);

    // Get pipe width
    float GetPipeWidth() const { return m_pipeWidth; }

private:
    std::vector<Pipe> m_pipes;
    float m_pipeWidth;
    float m_scrollSpeed;
    float m_spawnTimer;
    float m_spawnInterval;

    // Constants
    static constexpr float PIPE_WIDTH = 80.0f;
    static constexpr float SCROLL_SPEED = 200.0f;
    static constexpr float SPAWN_INTERVAL = 2.0f;
    static constexpr float GAP_SIZE = 200.0f;
};

} // namespace SentinelFlappy3D
