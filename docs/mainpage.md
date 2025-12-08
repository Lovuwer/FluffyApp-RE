# Sentinel Security Suite {#mainpage}

## Advanced Game Security Ecosystem

Welcome to the Sentinel Security Suite documentation. Sentinel is a comprehensive, enterprise-grade anti-cheat and game security platform designed for modern game developers.

---

## Overview

Sentinel provides three interconnected products:

### 🧠 Sentinel Cortex - Developer Workbench

A powerful desktop application for reverse engineering, analyzing, and neutralizing game cheats.

**Key Features:**
- Advanced disassembly with Capstone Engine
- VM deobfuscation engine for protected code analysis
- Fuzzy hashing (TLSH/ssdeep) for cheat family detection
- Binary diffing for version comparison
- Automated patch generation
- Dark-themed Qt/QML interface

[Learn more about Cortex](@ref Sentinel::Cortex)

---

### 🛡️ Sentinel SDK - In-Game Shield

Lightweight runtime protection library with minimal performance overhead (<0.01ms).

**Key Features:**
- Memory integrity monitoring
- Hook detection (inline, IAT, VTable)
- Anti-debugging and anti-attach
- Speed hack detection
- Protected value storage
- Secure timing functions
- Network packet encryption

[Learn more about the SDK](@ref Sentinel::SDK)

---

### 👁️ Sentinel Watchtower - Roblox Module

Specialized security module for Roblox game developers.

**Key Features:**
- Movement validation (speed, teleport, noclip)
- Combat validation (aimbot, silent aim)
- Remote call validation and rate limiting
- Executor detection
- Luau script analysis
- Network fuzzing tools

[Learn more about Watchtower](@ref Sentinel::Watchtower)

---

## Quick Start

### SDK Integration

```cpp
#include <SentinelSDK.hpp>

int main() {
    // Configure the SDK
    auto config = Sentinel::SDK::Configuration::Default();
    config.license_key = "YOUR_LICENSE_KEY";
    config.game_id = "your-game-id";
    config.features = Sentinel::SDK::DetectionFeatures::Standard;
    
    // Initialize
    if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) {
        // Handle error
        return 1;
    }
    
    // Game loop
    while (gameRunning) {
        // Call once per frame
        Sentinel::SDK::Update();
        
        // Your game logic here
    }
    
    // Cleanup
    Sentinel::SDK::Shutdown();
    return 0;
}
```

### Watchtower Integration (Luau)

```lua
local Watchtower = require(ReplicatedStorage.Watchtower)

-- Initialize on server
Watchtower.Initialize({
    enabled_detections = Watchtower.ExploitType.All,
    default_action = Watchtower.Action.Standard
})

-- Register players
game.Players.PlayerAdded:Connect(function(player)
    Watchtower.RegisterPlayer(player.UserId, player.Name)
end)

-- Validate movement in heartbeat
RunService.Heartbeat:Connect(function()
    for _, player in ipairs(game.Players:GetPlayers()) do
        local character = player.Character
        if character then
            local humanoid = character:FindFirstChild("Humanoid")
            local rootPart = character:FindFirstChild("HumanoidRootPart")
            if humanoid and rootPart then
                Watchtower.ValidateMovement(
                    player.UserId,
                    humanoid.WalkSpeed,
                    humanoid.JumpPower
                )
            end
        end
    end
end)
```

---

## Architecture

```
Sentinel/
├── src/
│   ├── Core/              # Shared core library
│   │   ├── Memory/        # Memory operations
│   │   ├── Crypto/        # Cryptographic utilities
│   │   └── Network/       # HTTP/networking
│   │
│   ├── Cortex/            # Developer workbench
│   │   ├── Analysis/      # Disassembler, differ, hasher
│   │   ├── VMDeobfuscator/# VM deobfuscation engine
│   │   └── UI/            # Qt/QML interface
│   │
│   ├── SDK/               # In-game protection library
│   │   ├── Detection/     # Anti-debug, anti-hook
│   │   └── Protection/    # Memory/value protection
│   │
│   └── Watchtower/        # Roblox module
│       ├── Detection/     # Exploit detection
│       └── Lua/           # Luau bindings
│
└── docs/                  # Documentation
```

---

## Building from Source

### Prerequisites

- CMake 3.21+
- C++17 compatible compiler
- Qt 6.2+ (for Cortex)
- vcpkg (recommended for dependencies)

### Build Commands

```bash
# Configure with vcpkg
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=[vcpkg]/scripts/buildsystems/vcpkg.cmake

# Build all targets
cmake --build build --config Release

# Install
cmake --install build --prefix ./install
```

---

## License

Sentinel Security Suite is proprietary software.
Copyright (c) 2024 Sentinel Security. All rights reserved.

---

## Support

- **Documentation:** https://docs.sentinel.security
- **Issue Tracker:** https://github.com/sentinel-security/sentinel/issues
- **Email:** support@sentinel.security

---

@author Sentinel Security Team
@version 1.0.0
@date 2024
