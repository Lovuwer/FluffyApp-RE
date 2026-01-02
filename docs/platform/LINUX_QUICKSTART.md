# Linux Integration Quick Start

## GCC/Clang

### Step 1: Install SDK (2 minutes)

```bash
# Extract SDK
tar -xzf SentinelSDK-linux-x64.tar.gz
cd SentinelSDK-linux-x64

# Install system-wide (requires sudo)
sudo cp -r include/* /usr/local/include/
sudo cp lib/* /usr/local/lib/
sudo ldconfig

# OR install locally
mkdir -p ~/sdk/sentinel
cp -r include ~/sdk/sentinel/
cp -r lib ~/sdk/sentinel/
export LD_LIBRARY_PATH=~/sdk/sentinel/lib:$LD_LIBRARY_PATH
```

### Step 2: Add Code (8 lines)

**main.cpp:**
```cpp
#include <SentinelSDK.hpp>
#include <iostream>

int main() {
    // Initialize SDK
    auto config = Sentinel::SDK::Configuration::Default();
    config.license_key = "YOUR-LICENSE-KEY";
    config.game_id = "your-game-id";
    
    if (Sentinel::SDK::Initialize(&config) != Sentinel::SDK::ErrorCode::Success) {
        std::cerr << "Failed to initialize SDK\n";
        return 1;
    }
    
    // Game loop
    bool running = true;
    while (running) {
        Sentinel::SDK::Update();  // Once per frame
        
        // Your game code
        UpdateGame();
        RenderFrame();
        
        // Exit condition
        running = CheckIfRunning();
    }
    
    // Cleanup
    Sentinel::SDK::Shutdown();
    return 0;
}
```

### Step 3: Build

**Makefile:**
```makefile
CXX = g++
CXXFLAGS = -std=c++20 -Wall -O2
INCLUDES = -I/usr/local/include
LIBS = -L/usr/local/lib -lSentinelSDK -lSentinelCore -lssl -lcrypto -pthread -ldl

YourGame: main.o
	$(CXX) -o $@ $^ $(LIBS)

main.o: main.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $<

clean:
	rm -f *.o YourGame
```

**Build and run:**
```bash
make
./YourGame
```

---

## CMake

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.21)
project(YourGame)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find SDK
find_library(SENTINEL_SDK SentinelSDK PATHS /usr/local/lib)
find_library(SENTINEL_CORE SentinelCore PATHS /usr/local/lib)

# OpenSSL (required)
find_package(OpenSSL REQUIRED)

add_executable(YourGame main.cpp)

target_include_directories(YourGame PRIVATE
    /usr/local/include
)

target_link_libraries(YourGame PRIVATE
    ${SENTINEL_SDK}
    ${SENTINEL_CORE}
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
    dl
)
```

### Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/YourGame
```

---

## pkg-config (Advanced)

### sentinel.pc

Create `/usr/local/lib/pkgconfig/sentinel.pc`:

```ini
prefix=/usr/local
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: Sentinel SDK
Description: Game security and anti-cheat library
Version: 1.0.0
Requires: openssl >= 1.1.0
Libs: -L${libdir} -lSentinelSDK -lSentinelCore -pthread -ldl
Cflags: -I${includedir}
```

### Usage

```bash
# Compile
g++ -std=c++20 main.cpp $(pkg-config --cflags --libs sentinel) -o YourGame

# Or in Makefile
CXXFLAGS = $(shell pkg-config --cflags sentinel)
LIBS = $(shell pkg-config --libs sentinel)
```

---

## Troubleshooting

### Error: "SentinelSDK.hpp: No such file or directory"

**Solution**: Add include path
```bash
g++ -I/usr/local/include main.cpp ...
```

### Error: "cannot find -lSentinelSDK"

**Solution**: Add library path
```bash
g++ main.cpp -L/usr/local/lib -lSentinelSDK ...
```

### Error: "error while loading shared libraries: libSentinelSDK.so"

**Solution 1**: Update LD_LIBRARY_PATH
```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
./YourGame
```

**Solution 2**: Run ldconfig (requires sudo)
```bash
sudo ldconfig
```

**Solution 3**: Use rpath
```bash
g++ main.cpp -Wl,-rpath,/usr/local/lib -lSentinelSDK ...
```

### Initialization Fails

**Check dependencies:**
```bash
# Check if libraries are found
ldd ./YourGame
# Should show:
#   libSentinelSDK.so => /usr/local/lib/libSentinelSDK.so
#   libSentinelCore.so => /usr/local/lib/libSentinelCore.so
#   libssl.so.1.1 => /lib/x86_64-linux-gnu/libssl.so.1.1
#   libcrypto.so.1.1 => /lib/x86_64-linux-gnu/libcrypto.so.1.1
```

**Missing OpenSSL:**
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# Arch
sudo pacman -S openssl
```

---

## Distribution

### AppImage

```bash
# Create AppDir structure
mkdir -p YourGame.AppDir/usr/{bin,lib}

# Copy files
cp YourGame YourGame.AppDir/usr/bin/
cp /usr/local/lib/libSentinel*.so YourGame.AppDir/usr/lib/

# Create AppImage
appimagetool YourGame.AppDir YourGame-x86_64.AppImage
```

### Flatpak

**Include libraries in manifest:**
```json
{
  "modules": [
    {
      "name": "sentinel-sdk",
      "buildsystem": "simple",
      "build-commands": [
        "install -Dm644 lib/* /app/lib/",
        "install -Dm644 include/* /app/include/"
      ]
    }
  ]
}
```

### Snap

**Include libraries in snapcraft.yaml:**
```yaml
parts:
  sentinel-sdk:
    plugin: dump
    source: SentinelSDK-linux-x64/
    organize:
      lib: usr/lib
      include: usr/include
```

---

## Performance

**Measured on Ubuntu 22.04, Ryzen 9 5900X**:
- `Update()`: 0.4-0.6ms
- `FullScan()`: 6-9ms

**VM Performance (GitHub Actions)**:
- `Update()`: 0.5-0.8ms
- `FullScan()`: 8-12ms

**Recommended**:
- Call `Update()` once per frame
- Call `FullScan()` every 5-10 seconds
- Use `Pause()` during heavy loading

---

## Docker

### Dockerfile

```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy SDK
COPY SentinelSDK-linux-x64/lib/* /usr/local/lib/
RUN ldconfig

# Copy game
COPY YourGame /app/
WORKDIR /app

CMD ["./YourGame"]
```

---

## Next Steps

1. ✅ SDK integrated
2. Test locally
3. Build release version
4. Profile performance
5. Package for distribution

See [STUDIO_INTEGRATION_GUIDE.md](../STUDIO_INTEGRATION_GUIDE.md) for complete guide.
