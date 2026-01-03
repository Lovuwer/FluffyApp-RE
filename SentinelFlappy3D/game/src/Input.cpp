#include "Input.hpp"

namespace SentinelFlappy3D {

void Input::Initialize(GLFWwindow* window) {
    m_window = window;
    m_spacePressed = false;
    m_spaceJustPressed = false;
    m_escapePressed = false;
    m_escapeJustPressed = false;
}

void Input::Update() {
    // Update space key state
    bool spaceCurrentlyPressed = (glfwGetKey(m_window, GLFW_KEY_SPACE) == GLFW_PRESS);
    m_spaceJustPressed = spaceCurrentlyPressed && !m_spacePressed;
    m_spacePressed = spaceCurrentlyPressed;

    // Update escape key state
    bool escapeCurrentlyPressed = (glfwGetKey(m_window, GLFW_KEY_ESCAPE) == GLFW_PRESS);
    m_escapeJustPressed = escapeCurrentlyPressed && !m_escapePressed;
    m_escapePressed = escapeCurrentlyPressed;
}

} // namespace SentinelFlappy3D
