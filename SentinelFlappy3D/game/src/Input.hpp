#pragma once

#include <GLFW/glfw3.h>

namespace SentinelFlappy3D {

class Input {
public:
    Input() = default;

    // Initialize input system with GLFW window
    void Initialize(GLFWwindow* window);

    // Update input state (call once per frame)
    void Update();

    // Check if space key was just pressed (for flapping)
    bool IsSpaceJustPressed() const { return m_spaceJustPressed; }

    // Check if escape key was just pressed (for quitting)
    bool IsEscapeJustPressed() const { return m_escapeJustPressed; }

private:
    GLFWwindow* m_window = nullptr;
    bool m_spacePressed = false;
    bool m_spaceJustPressed = false;
    bool m_escapePressed = false;
    bool m_escapeJustPressed = false;
};

} // namespace SentinelFlappy3D
