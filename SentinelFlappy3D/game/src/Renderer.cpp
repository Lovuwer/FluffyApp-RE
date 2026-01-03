#include "Renderer.hpp"
#include <iostream>

namespace SentinelFlappy3D {

Renderer::Renderer()
    : m_window(nullptr)
    , m_screenWidth(800.0f)
    , m_screenHeight(600.0f)
    , m_groundY(600.0f) {
}

Renderer::~Renderer() {
    Shutdown();
}

bool Renderer::Initialize(GLFWwindow* window) {
    m_window = window;

    // Get framebuffer size
    int width, height;
    glfwGetFramebufferSize(window, &width, &height);
    m_screenWidth = static_cast<float>(width);
    m_screenHeight = static_cast<float>(height);

    // Setup OpenGL viewport
    glViewport(0, 0, width, height);

    // Setup orthographic projection
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glOrtho(0.0, m_screenWidth, m_screenHeight, 0.0, -1.0, 1.0);
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();

    // Enable blending for transparency
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    return true;
}

void Renderer::Shutdown() {
    // Nothing to clean up for now
}

void Renderer::Clear() {
    // Sky blue background
    glClearColor(0.53f, 0.81f, 0.92f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
}

void Renderer::Present() {
    glfwSwapBuffers(m_window);
}

void Renderer::RenderPlayer(const Player& player) {
    const auto& pos = player.GetPosition();
    float size = player.GetSize();

    // Render player as a yellow square (bird)
    if (player.IsAlive()) {
        RenderRect(pos.x, pos.y, size, size, 1.0f, 0.8f, 0.0f);
    } else {
        // Red when dead
        RenderRect(pos.x, pos.y, size, size, 1.0f, 0.0f, 0.0f);
    }
}

void Renderer::RenderObstacles(const Obstacle& obstacle) {
    const auto& pipes = obstacle.GetPipes();
    float pipeWidth = obstacle.GetPipeWidth();

    for (const auto& pipe : pipes) {
        // Top pipe (green)
        float topPipeHeight = pipe.gapY - pipe.gapSize * 0.5f;
        RenderRect(pipe.x, topPipeHeight * 0.5f, pipeWidth, topPipeHeight, 0.0f, 0.8f, 0.2f);

        // Bottom pipe (green)
        float bottomPipeY = pipe.gapY + pipe.gapSize * 0.5f;
        float bottomPipeHeight = m_groundY - bottomPipeY;
        RenderRect(pipe.x, bottomPipeY + bottomPipeHeight * 0.5f, pipeWidth, bottomPipeHeight, 0.0f, 0.8f, 0.2f);
    }
}

void Renderer::RenderScore(int score) {
    // Render score digits at top center
    float digitSize = 40.0f;
    float startX = m_screenWidth * 0.5f - digitSize * 0.5f;
    
    if (score == 0) {
        RenderDigit(0, startX, 30.0f, digitSize);
    } else {
        int tempScore = score;
        int digitCount = 0;
        int temp = score;
        while (temp > 0) {
            digitCount++;
            temp /= 10;
        }
        
        startX = m_screenWidth * 0.5f - (digitCount * digitSize * 0.6f) * 0.5f;
        
        while (tempScore > 0) {
            int digit = tempScore % 10;
            RenderDigit(digit, startX + (digitCount - 1) * digitSize * 0.6f, 30.0f, digitSize);
            tempScore /= 10;
            digitCount--;
        }
    }
}

void Renderer::RenderGameOver() {
    // Render semi-transparent overlay
    glBegin(GL_QUADS);
    glColor4f(0.0f, 0.0f, 0.0f, 0.5f);
    glVertex2f(0.0f, 0.0f);
    glVertex2f(m_screenWidth, 0.0f);
    glVertex2f(m_screenWidth, m_screenHeight);
    glVertex2f(0.0f, m_screenHeight);
    glEnd();

    // Render "GAME OVER" text (simple rectangle for now)
    RenderRect(m_screenWidth * 0.5f, m_screenHeight * 0.5f, 300.0f, 100.0f, 1.0f, 0.0f, 0.0f);
}

void Renderer::RenderRect(float x, float y, float width, float height, float r, float g, float b) {
    float halfW = width * 0.5f;
    float halfH = height * 0.5f;

    glBegin(GL_QUADS);
    glColor3f(r, g, b);
    glVertex2f(x - halfW, y - halfH);
    glVertex2f(x + halfW, y - halfH);
    glVertex2f(x + halfW, y + halfH);
    glVertex2f(x - halfW, y + halfH);
    glEnd();
}

void Renderer::RenderDigit(int digit, float x, float y, float size) {
    // Simple digit rendering using colored rectangles
    // This is a placeholder - in a real game you'd use texture-based fonts
    RenderRect(x, y, size * 0.6f, size, 1.0f, 1.0f, 1.0f);
    
    // Render a small indicator based on digit value
    float indicatorSize = size * 0.2f;
    for (int i = 0; i < digit && i < 9; ++i) {
        float offsetY = (i - 4) * indicatorSize * 0.5f;
        RenderRect(x, y + offsetY, indicatorSize, indicatorSize, 0.0f, 0.0f, 0.0f);
    }
}

} // namespace SentinelFlappy3D
