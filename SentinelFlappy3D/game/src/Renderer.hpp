#pragma once

#include <GLFW/glfw3.h>
#include "Player.hpp"
#include "Obstacle.hpp"

namespace SentinelFlappy3D {

class Renderer {
public:
    Renderer();
    ~Renderer();

    // Initialize renderer
    bool Initialize(GLFWwindow* window);

    // Shutdown renderer
    void Shutdown();

    // Clear screen
    void Clear();

    // Present frame
    void Present();

    // Render player
    void RenderPlayer(const Player& player);

    // Render obstacles
    void RenderObstacles(const Obstacle& obstacle);

    // Render score
    void RenderScore(int score);

    // Render game over message
    void RenderGameOver();

    // Get screen dimensions
    float GetScreenWidth() const { return m_screenWidth; }
    float GetScreenHeight() const { return m_screenHeight; }
    float GetGroundY() const { return m_groundY; }

private:
    GLFWwindow* m_window;
    float m_screenWidth;
    float m_screenHeight;
    float m_groundY;

    // Helper to render a rectangle
    void RenderRect(float x, float y, float width, float height, 
                    float r, float g, float b);

    // Helper to render text (simple digit rendering)
    void RenderDigit(int digit, float x, float y, float size);
};

} // namespace SentinelFlappy3D
