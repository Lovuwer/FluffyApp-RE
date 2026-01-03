#include "Obstacle.hpp"
#include <random>
#include <algorithm>

namespace SentinelFlappy3D {

AABB Pipe::GetTopPipeBounds(float pipeWidth) const {
    return AABB(
        glm::vec2(x - pipeWidth * 0.5f, 0.0f),
        glm::vec2(x + pipeWidth * 0.5f, gapY - gapSize * 0.5f)
    );
}

AABB Pipe::GetBottomPipeBounds(float pipeWidth, float groundY) const {
    return AABB(
        glm::vec2(x - pipeWidth * 0.5f, gapY + gapSize * 0.5f),
        glm::vec2(x + pipeWidth * 0.5f, groundY)
    );
}

Obstacle::Obstacle()
    : m_pipeWidth(PIPE_WIDTH)
    , m_scrollSpeed(SCROLL_SPEED)
    , m_spawnTimer(0.0f)
    , m_spawnInterval(SPAWN_INTERVAL) {
}

void Obstacle::Reset() {
    m_pipes.clear();
    m_spawnTimer = 0.0f;
    
    // Spawn initial pipes
    for (int i = 0; i < 3; ++i) {
        float x = 800.0f + i * 400.0f;
        float gapY = 200.0f + (i * 100.0f);
        m_pipes.emplace_back(x, gapY, GAP_SIZE);
    }
}

void Obstacle::Update(float deltaTime) {
    // Move pipes left
    for (auto& pipe : m_pipes) {
        pipe.x -= m_scrollSpeed * deltaTime;
    }

    // Remove pipes that are off screen
    m_pipes.erase(
        std::remove_if(m_pipes.begin(), m_pipes.end(),
            [](const Pipe& pipe) { return pipe.x < -100.0f; }),
        m_pipes.end()
    );

    // Spawn new pipes
    m_spawnTimer += deltaTime;
    if (m_spawnTimer >= m_spawnInterval) {
        m_spawnTimer -= m_spawnInterval;
        
        // Random gap position
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_real_distribution<float> dis(150.0f, 450.0f);
        
        float gapY = dis(gen);
        m_pipes.emplace_back(900.0f, gapY, GAP_SIZE);
    }
}

bool Obstacle::CheckCollision(const AABB& playerBounds) const {
    for (const auto& pipe : m_pipes) {
        AABB topPipe = pipe.GetTopPipeBounds(m_pipeWidth);
        AABB bottomPipe = pipe.GetBottomPipeBounds(m_pipeWidth, 600.0f);
        
        if (Physics::CheckCollision(playerBounds, topPipe) ||
            Physics::CheckCollision(playerBounds, bottomPipe)) {
            return true;
        }
    }
    return false;
}

int Obstacle::CheckAndUpdateScore(float playerX) {
    int newScore = 0;
    for (auto& pipe : m_pipes) {
        if (!pipe.scored && pipe.x < playerX) {
            pipe.scored = true;
            newScore++;
        }
    }
    return newScore;
}

} // namespace SentinelFlappy3D
