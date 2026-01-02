# Windows Integration Quick Start

## Visual Studio 2019/2022

### Step 1: Project Setup (2 minutes)

1. **Extract SDK**:
   ```
   YourGame/
   ├── ThirdParty/
   │   └── SentinelSDK/
   │       ├── include/
   │       │   └── SentinelSDK.hpp
   │       └── lib/
   │           ├── x64/
   │           │   ├── SentinelSDK.lib
   │           │   ├── SentinelSDK.dll
   │           │   └── SentinelCore.dll
   ```

2. **Configure Project**:
   - Right-click project → Properties
   - Configuration: **All Configurations**
   - Platform: **x64**

### Step 2: Include Paths

**C/C++ → General → Additional Include Directories**:
```
$(ProjectDir)ThirdParty\SentinelSDK\include
```

### Step 3: Library Paths

**Linker → General → Additional Library Directories**:
```
$(ProjectDir)ThirdParty\SentinelSDK\lib\x64
```

### Step 4: Link Libraries

**Linker → Input → Additional Dependencies**:
```
SentinelSDK.lib
```

### Step 5: Copy DLLs

**Build Events → Post-Build Event → Command Line**:
```batch
xcopy "$(ProjectDir)ThirdParty\SentinelSDK\lib\x64\*.dll" "$(OutDir)" /Y /D
```

### Step 6: Add Code (8 lines)

```cpp
#include <SentinelSDK.hpp>

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Initialize SDK
    auto config = Sentinel::SDK::Configuration::Default();
    config.license_key = "YOUR-LICENSE-KEY";
    config.game_id = "your-game-id";
    
    if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) {
        MessageBoxA(NULL, "Failed to initialize SDK", "Error", MB_OK);
        return 1;
    }
    
    // Game loop
    MSG msg = {};
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        
        Sentinel::SDK::Update();  // Once per frame
        
        // Your game code
        UpdateGame();
        RenderFrame();
    }
    
    // Cleanup
    Sentinel::SDK::Shutdown();
    return 0;
}
```

### Step 7: Build and Run

```batch
# Build
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" YourGame.sln /p:Configuration=Release /p:Platform=x64

# Run
cd x64\Release
YourGame.exe
```

---

## CMake (Windows)

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.21)
project(YourGame)

set(CMAKE_CXX_STANDARD 20)

# Find SDK
set(SENTINEL_SDK_DIR "${CMAKE_SOURCE_DIR}/ThirdParty/SentinelSDK")

add_executable(YourGame main.cpp)

target_include_directories(YourGame PRIVATE
    ${SENTINEL_SDK_DIR}/include
)

target_link_directories(YourGame PRIVATE
    ${SENTINEL_SDK_DIR}/lib/x64
)

target_link_libraries(YourGame PRIVATE
    SentinelSDK
)

# Copy DLLs to output directory
add_custom_command(TARGET YourGame POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${SENTINEL_SDK_DIR}/lib/x64/SentinelSDK.dll"
        "${SENTINEL_SDK_DIR}/lib/x64/SentinelCore.dll"
        $<TARGET_FILE_DIR:YourGame>
)
```

### Build

```batch
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
.\build\Release\YourGame.exe
```

---

## Troubleshooting

### Error: "Cannot open include file 'SentinelSDK.hpp'"

**Solution**: Check include path
```
# Verify file exists
dir "$(ProjectDir)ThirdParty\SentinelSDK\include\SentinelSDK.hpp"
```

### Error: "Cannot open input file 'SentinelSDK.lib'"

**Solution**: Check library path and platform
```
# Must be x64 build
# Verify lib exists
dir "$(ProjectDir)ThirdParty\SentinelSDK\lib\x64\SentinelSDK.lib"
```

### Error: "The program can't start because SentinelSDK.dll is missing"

**Solution**: Copy DLL to output directory
```batch
xcopy "ThirdParty\SentinelSDK\lib\x64\*.dll" "x64\Release\" /Y
```

### Initialization Fails

**Solution**: Check dependencies
```cpp
// Check last error
if (Initialize(&config) != ErrorCode::Success) {
    const char* error = Sentinel::SDK::GetLastError();
    MessageBoxA(NULL, error, "SDK Error", MB_OK);
}
```

Required DLLs:
- `SentinelSDK.dll`
- `SentinelCore.dll`
- `bcrypt.dll` (Windows built-in)
- `crypt32.dll` (Windows built-in)

---

## Distribution

### Include with Game

```
YourGame/
├── YourGame.exe
├── SentinelSDK.dll
├── SentinelCore.dll
└── ... (other game files)
```

### Installer (NSIS)

```nsis
Section "MainSection" SEC01
    SetOutPath "$INSTDIR"
    File "YourGame.exe"
    File "SentinelSDK.dll"
    File "SentinelCore.dll"
SectionEnd
```

---

## Performance

**Measured on Windows 11, Ryzen 9 5900X**:
- `Update()`: 0.3-0.5ms
- `FullScan()`: 5-7ms

**Measured on Linux VM (GitHub Actions)**:
- `Update()`: 0.5-0.8ms (⚠️ VM overhead)
- `FullScan()`: 7-10ms (⚠️ VM overhead)

**Performance Notes**:
- VM environments show higher overhead than bare metal
- Actual hardware typically performs 30-50% better than VM metrics
- Profile on your target platform for accurate measurements

**Recommended**:
- Call `Update()` once per frame
- Call `FullScan()` every 5-10 seconds

---

## Next Steps

1. ✅ SDK integrated
2. Test in Debug mode
3. Build Release version
4. Profile performance
5. Deploy to users

See [STUDIO_INTEGRATION_GUIDE.md](../STUDIO_INTEGRATION_GUIDE.md) for complete guide.
