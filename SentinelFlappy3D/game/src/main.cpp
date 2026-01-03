#include "Game.hpp"
#include <iostream>
#include <cstdlib>

int main() {
    std::cout << "======================================" << std::endl;
    std::cout << "  SentinelFlappy3D - Step 2" << std::endl;
    std::cout << "  Basic Flappy Bird Gameplay" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;

    SentinelFlappy3D::Game game;

    if (!game.Initialize()) {
        std::cerr << "Failed to initialize game!" << std::endl;
        return EXIT_FAILURE;
    }

    game.Run();

    game.Shutdown();

    std::cout << "Game exited successfully." << std::endl;
    return EXIT_SUCCESS;
}
