#include "Game.hpp"
#include <iostream>
#include <chrono>

namespace SentinelFlappy3D {

Game::Game()
    : m_state(GameState::Playing)
    , m_score(0)
    , m_lastFrameTime(0.0)
    , m_window(nullptr) {
}

Game::~Game() {
    Shutdown();
}

bool Game::Initialize() {
    // Set error callback
    glfwSetErrorCallback(ErrorCallback);

    // Initialize GLFW
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return false;
    }

    // Configure GLFW
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 1);
    glfwWindowHint(GLFW_RESIZABLE, GLFW_FALSE);

    // Create window
    m_window = glfwCreateWindow(800, 600, "SentinelFlappy3D", nullptr, nullptr);
    if (!m_window) {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return false;
    }

    // Make context current
    glfwMakeContextCurrent(m_window);

    // Enable VSync
    glfwSwapInterval(1);

    // Initialize renderer
    if (!m_renderer.Initialize(m_window)) {
        std::cerr << "Failed to initialize renderer" << std::endl;
        return false;
    }

    // Initialize input
    m_input.Initialize(m_window);

    // Initialize Sentinel SDK (Step 4 - stub only, actual init in Step 5)
    if (!m_sentinel.Initialize()) {
        std::cout << "Warning: Sentinel SDK initialization failed - continuing in degraded mode" << std::endl;
        // Game continues even if SDK fails (graceful degradation)
    }

    // Initialize game state
    Reset();

    m_lastFrameTime = glfwGetTime();

    std::cout << "SentinelFlappy3D initialized successfully!" << std::endl;
    std::cout << "Press SPACE to flap, ESC to quit" << std::endl;

    return true;
}

void Game::Shutdown() {
    // Shutdown Sentinel SDK
    m_sentinel.Shutdown();
    
    m_renderer.Shutdown();

    if (m_window) {
        glfwDestroyWindow(m_window);
        m_window = nullptr;
    }

    glfwTerminate();
}

void Game::Run() {
    while (!ShouldQuit()) {
        // Calculate delta time
        double currentTime = glfwGetTime();
        float deltaTime = static_cast<float>(currentTime - m_lastFrameTime);
        m_lastFrameTime = currentTime;

        // Cap delta time to prevent large jumps
        if (deltaTime > 0.1f) {
            deltaTime = 0.1f;
        }

        // Poll events
        glfwPollEvents();

        // Update input
        m_input.Update();

        // Update Sentinel SDK (lightweight per-frame check)
        if (m_sentinel.IsInitialized()) {
            m_sentinel.Update();
        }

        // Update game
        Update(deltaTime);

        // Render
        Render();
    }
}

bool Game::ShouldQuit() const {
    return glfwWindowShouldClose(m_window) || m_input.IsEscapeJustPressed();
}

void Game::Update(float deltaTime) {
    if (m_state == GameState::Playing) {
        // Handle flap input
        if (m_input.IsSpaceJustPressed()) {
            m_player.Flap();
        }

        // Update player
        m_player.Update(deltaTime);

        // Update obstacles
        m_obstacle.Update(deltaTime);

        // Check for scoring
        m_score += m_obstacle.CheckAndUpdateScore(m_player.GetPosition().x);

        // Check for collision with pipes
        if (m_obstacle.CheckCollision(m_player.GetBoundingBox())) {
            m_player.Kill();
            m_state = GameState::GameOver;
        }

        // Check for collision with ground or ceiling
        const auto& pos = m_player.GetPosition();
        float halfSize = m_player.GetSize() * 0.5f;
        if (pos.y + halfSize >= m_renderer.GetGroundY() || pos.y - halfSize <= 0.0f) {
            m_player.Kill();
            m_state = GameState::GameOver;
        }
    } else if (m_state == GameState::GameOver) {
        // Press space to restart
        if (m_input.IsSpaceJustPressed()) {
            Reset();
        }
    }
}

void Game::Render() {
    m_renderer.Clear();

    // Render game objects
    m_renderer.RenderObstacles(m_obstacle);
    m_renderer.RenderPlayer(m_player);
    m_renderer.RenderScore(m_score);

    // Render game over overlay
    if (m_state == GameState::GameOver) {
        m_renderer.RenderGameOver();
    }

    m_renderer.Present();
}

void Game::Reset() {
    m_state = GameState::Playing;
    m_score = 0;
    m_player.Reset();
    m_obstacle.Reset();
}

void Game::ErrorCallback(int error, const char* description) {
    std::cerr << "GLFW Error " << error << ": " << description << std::endl;
}

void Game::KeyCallback(GLFWwindow* window, int key, int scancode, int action, int mods) {
    (void)window;
    (void)scancode;
    (void)mods;

    if (key == GLFW_KEY_ESCAPE && action == GLFW_PRESS) {
        glfwSetWindowShouldClose(window, GLFW_TRUE);
    }
}

} // namespace SentinelFlappy3D
