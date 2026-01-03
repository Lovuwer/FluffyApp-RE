#pragma once

#include <GLFW/glfw3.h>
#include "Renderer.hpp"
#include "Player.hpp"
#include "Obstacle.hpp"
#include "Input.hpp"
#include "SentinelIntegration.hpp"

namespace SentinelFlappy3D {

enum class GameState {
    Playing,
    GameOver
};

class Game {
public:
    Game();
    ~Game();

    // Initialize game systems
    bool Initialize();

    // Shutdown game systems
    void Shutdown();

    // Main game loop
    void Run();

    // Check if game should quit
    bool ShouldQuit() const;

private:
    // Game state
    GameState m_state;
    int m_score;
    double m_lastFrameTime;
    
    // Systems
    GLFWwindow* m_window;
    Renderer m_renderer;
    Player m_player;
    Obstacle m_obstacle;
    Input m_input;
    SentinelIntegration m_sentinel;

    // Game logic
    void Update(float deltaTime);
    void Render();
    void Reset();

    // GLFW callbacks
    static void ErrorCallback(int error, const char* description);
    static void KeyCallback(GLFWwindow* window, int key, int scancode, int action, int mods);
};

} // namespace SentinelFlappy3D
