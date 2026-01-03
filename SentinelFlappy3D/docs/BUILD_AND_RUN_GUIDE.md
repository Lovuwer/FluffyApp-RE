# SentinelFlappy3D - Build and Run Guide for Windows

## 📋 Overview

This guide will help you build and run **SentinelFlappy3D** on Windows from scratch. Even if you've never built a C++ project before, just follow these steps carefully and you'll have the game running in no time!

**What is SentinelFlappy3D?**  
A 3D Flappy Bird game that demonstrates how to integrate the Sentinel anti-cheat SDK into a game project.

**Time Required**: 30-60 minutes (first time)  
**Difficulty**: Beginner-friendly  
**Windows Version**: Windows 10 or Windows 11

---

## 🎯 What You Need to Install

Before building the game, you need to install these free tools:

1. **Visual Studio 2019 or newer** - The compiler that builds C++ programs
2. **CMake** - A tool that configures the build process
3. **Git** - A tool to download the code from GitHub

Don't worry if you don't have these yet - we'll walk through installing each one!

---

## 📥 Step 1: Install Visual Studio (C++ Compiler)

Visual Studio is Microsoft's development environment for building Windows applications.

### Download Visual Studio

1. Go to: https://visualstudio.microsoft.com/downloads/
2. Download **Visual Studio 2022 Community** (it's free!)
3. Run the installer

### Choose the Right Components

When the Visual Studio Installer opens:

1. Select **"Desktop development with C++"** workload
2. On the right side, make sure these are checked:
   - ✅ MSVC v143 (or latest) - C++ build tools
   - ✅ Windows 10 or 11 SDK
   - ✅ C++ CMake tools for Windows
3. Click **"Install"** button

**Note**: The installation is large (several GB) and may take 15-30 minutes.

### Verify Installation

After installation completes:

1. Press `Windows Key + R`
2. Type `cmd` and press Enter
3. In the Command Prompt, type:
   ```cmd
   "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
   cl
   ```
4. You should see something like: "Microsoft (R) C/C++ Optimizing Compiler Version..."

✅ **Success!** Visual Studio is installed.

---

## 📥 Step 2: Install CMake

CMake is a tool that helps configure how the project should be built.

### Download CMake

1. Go to: https://cmake.org/download/
2. Download the **Windows x64 Installer** (file ending in `.msi`)
3. Run the installer

### Installation Steps

1. Click through the wizard
2. **Important**: When you see "Install Options", select:
   - ✅ **"Add CMake to the system PATH for all users"**
3. Complete the installation

### Verify Installation

1. Open a **new** Command Prompt (press `Windows Key + R`, type `cmd`, press Enter)
2. Type:
   ```cmd
   cmake --version
   ```
3. You should see: "cmake version 3.xx.x"

✅ **Success!** CMake is installed.

---

## 📥 Step 3: Install Git (Optional but Recommended)

Git helps you download and manage the source code.

### Download Git

1. Go to: https://git-scm.com/download/win
2. Download the installer
3. Run it

### Installation Steps

1. Use all the default options (just keep clicking "Next")
2. Complete the installation

### Verify Installation

1. Open a new Command Prompt
2. Type:
   ```cmd
   git --version
   ```
3. You should see: "git version 2.xx.x"

✅ **Success!** Git is installed.

---

## 📥 Step 4: Download the Code

Now let's get the SentinelFlappy3D code onto your computer.

### Option A: Using Git (Recommended)

1. Open Command Prompt
2. Navigate to where you want to store the code (e.g., your Documents folder):
   ```cmd
   cd C:\Users\YourUsername\Documents
   ```
3. Clone the repository:
   ```cmd
   git clone https://github.com/Lovuwer/Sentiel-RE.git
   cd Sentiel-RE
   ```

### Option B: Download ZIP

1. Go to: https://github.com/Lovuwer/Sentiel-RE
2. Click the green **"Code"** button
3. Click **"Download ZIP"**
4. Extract the ZIP file to `C:\Users\YourUsername\Documents\Sentiel-RE`

---

## 🔨 Step 5: Build the Sentinel SDK

The Sentinel SDK is the anti-cheat library that the game uses. We need to build it first.

### Open Developer Command Prompt

1. Press the `Windows Key`
2. Type: **"Developer Command Prompt for VS 2022"**
3. Click on it to open

**Why this special command prompt?**  
It has all the C++ build tools ready to use.

### Build the SDK

In the Developer Command Prompt:

```cmd
:: Navigate to the Sentiel-RE folder
cd C:\Users\YourUsername\Documents\Sentiel-RE

:: Configure the build with CMake
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DSENTINEL_BUILD_SDK=ON ^
    -DSENTINEL_BUILD_TESTS=OFF ^
    -DSENTINEL_BUILD_CORTEX=OFF ^
    -DSENTINEL_BUILD_WATCHTOWER=OFF

:: Build the SDK
cmake --build build --config Release --target SentinelSDK
```

**What's happening?**
- First command: CMake reads the project files and prepares to build
- Second command: Compiles the actual Sentinel SDK library

### Expected Output

You should see lots of compilation messages, ending with:
```
Build succeeded.
    0 Warning(s)
    0 Error(s)
```

### Verify the SDK Built Successfully

Check if the library files exist:

```cmd
dir build\lib\Release
```

You should see files like:
- `SentinelSDK.lib` (or `SentinelSDK_static.lib`)
- `SentinelCore.lib`

✅ **Success!** The Sentinel SDK is built.

---

## 🔨 Step 6: Build SentinelFlappy3D

Now we can build the actual game!

### Navigate to the Game Folder

In the same Developer Command Prompt:

```cmd
cd SentinelFlappy3D
```

### Configure and Build the Game

```cmd
:: Configure the game build
cmake -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release

:: Build the game
cmake --build build --config Release
```

**What's happening?**
- CMake will automatically find the Sentinel SDK you just built
- It will download GLFW and GLM (graphics libraries) automatically
- It will compile the game and link everything together

### Expected Output

You should see:
```
Found Sentinel SDK at: ...
Found Sentinel SDK library: ...
==========================================
  SentinelFlappy3D built successfully!
  Executable: ...\build\bin\Release\SentinelFlappy3D.exe
==========================================
```

### Verify the Game Built Successfully

```cmd
dir build\bin\Release
```

You should see: `SentinelFlappy3D.exe`

✅ **Success!** The game is built.

---

## 🎮 Step 7: Run the Game

You're ready to play!

### Launch the Game

```cmd
cd build\bin\Release
SentinelFlappy3D.exe
```

A window should open with the game!

### Expected Console Output

When the game starts, you should see in the console:
```
======================================
  SentinelFlappy3D - Step 2
  Basic Flappy Bird Gameplay
======================================

[SentinelIntegration] Initialize() called
[SentinelIntegration] Initializing Sentinel SDK...
[SentinelIntegration] ✓ SDK initialized successfully!
SentinelFlappy3D initialized successfully!
Press SPACE to flap, ESC to quit
```

### How to Play

- **Press SPACE** to make the bird flap and fly up
- **Avoid the pipes** - if you hit them, it's game over
- **Press ESC** to quit the game
- **Press SPACE after game over** to restart

✅ **Success!** You're playing the game!

---

## 🎯 What the Sentinel SDK Does

While you're playing, the Sentinel SDK is running in the background, monitoring for:

1. **Debuggers** - Checks if someone is trying to debug the game
2. **Code Modification** - Detects if game code is being changed
3. **Memory Tampering** - Watches for memory cheats
4. **Suspicious Activity** - Monitors for unusual program behavior

All of this happens automatically with minimal performance impact!

---

## ❓ Troubleshooting Common Issues

### Problem: "cmake is not recognized"

**Solution:**
- CMake wasn't added to PATH during installation
- Reinstall CMake and make sure to check "Add to PATH"
- Or restart your computer after installing

### Problem: "Cannot open include file: 'windows.h'"

**Solution:**
- Visual Studio C++ components not installed correctly
- Open Visual Studio Installer
- Click "Modify" on your installation
- Make sure "Desktop development with C++" is checked

### Problem: "LINK : fatal error LNK1104: cannot open file"

**Solution:**
- The Sentinel SDK wasn't built first
- Go back to Step 5 and build the SDK
- Make sure you see "Build succeeded" before moving to Step 6

### Problem: Game window opens but is black or crashes

**Solution:**
- Your graphics drivers might be outdated
- Update your graphics drivers:
  - NVIDIA: https://www.nvidia.com/Download/index.aspx
  - AMD: https://www.amd.com/en/support
  - Intel: https://www.intel.com/content/www/us/en/download-center/home.html

### Problem: "OpenGL version too low"

**Solution:**
- The game requires OpenGL 2.1 or higher
- Update your graphics drivers (see above)
- If you have an older computer, your hardware might not support it

### Problem: Build takes forever or seems stuck

**Solution:**
- Building for the first time downloads dependencies
- First build can take 5-15 minutes depending on your internet
- Be patient! Subsequent builds will be much faster

---

## 🔄 Rebuilding After Code Changes

If you modify the code and want to rebuild:

### Quick Rebuild (if you only changed game code)

```cmd
cd C:\Users\YourUsername\Documents\Sentiel-RE\SentinelFlappy3D
cmake --build build --config Release
```

### Full Rebuild (if you changed SDK or had errors)

```cmd
:: Clean the build
cd C:\Users\YourUsername\Documents\Sentiel-RE\SentinelFlappy3D
rmdir /s /q build

:: Rebuild from scratch
cmake -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

---

## 📊 Performance Expectations

The game should run smoothly:

- **Frame Rate**: 60 FPS (frames per second)
- **CPU Usage**: Low (5-10% on modern systems)
- **Memory**: ~15-20 MB
- **SDK Overhead**: Less than 0.5ms per frame

If you're experiencing performance issues, check:
- Close other programs using GPU
- Update graphics drivers
- Make sure you built in Release mode (not Debug)

---

## 🛠️ Advanced: Using Visual Studio IDE (Optional)

If you prefer using Visual Studio's graphical interface:

1. Open Visual Studio 2022
2. Click **"Open a local folder"**
3. Navigate to: `C:\Users\YourUsername\Documents\Sentiel-RE\SentinelFlappy3D`
4. Visual Studio will automatically detect CMake and configure the project
5. Select **"Release"** configuration in the toolbar
6. Click **Build > Build All**
7. Click **Debug > Start Without Debugging** to run

---

## 📝 File Locations Reference

After building, here's where everything is:

```
C:\Users\YourUsername\Documents\Sentiel-RE\
│
├── build\                          # Parent SDK build folder
│   └── lib\Release\
│       ├── SentinelSDK.lib         # Sentinel SDK library
│       └── SentinelCore.lib        # Core anti-cheat engine
│
└── SentinelFlappy3D\               # Game folder
    └── build\                      # Game build folder
        └── bin\Release\
            └── SentinelFlappy3D.exe  # The game executable!
```

---

## 🎓 Learning More

Want to understand more about the project?

- **SDK Integration**: See how the game uses Sentinel in `SentinelFlappy3D\game\src\SentinelIntegration.cpp`
- **Game Code**: Main game logic is in `SentinelFlappy3D\game\src\Game.cpp`
- **CMake Configuration**: Build settings are in `SentinelFlappy3D\CMakeLists.txt`

---

## ✅ Success Checklist

You've completed everything when you can:

- [x] Visual Studio is installed with C++ components
- [x] CMake is installed and in PATH
- [x] Sentiel-RE repository is downloaded
- [x] Sentinel SDK builds without errors
- [x] SentinelFlappy3D game builds without errors
- [x] Game runs and you can play it
- [x] You see the SDK initialization message in console

---

## 🆘 Still Need Help?

If you're stuck:

1. **Read the error message carefully** - it often tells you what's wrong
2. **Check you followed each step exactly** - especially the installation steps
3. **Make sure you're using the Developer Command Prompt** - not regular Command Prompt
4. **Try a clean rebuild** - sometimes old build files cause issues
5. **Check the GitHub Issues** for similar problems: https://github.com/Lovuwer/Sentiel-RE/issues

---

## 🎉 Congratulations!

You've successfully built and run a C++ game project with anti-cheat integration on Windows! This is a real accomplishment, especially if it's your first time building from source.

**What you've learned:**
- How to install C++ development tools on Windows
- How to use CMake to configure and build projects
- How to build multi-part projects (SDK + Application)
- How C++ games integrate anti-cheat systems

Keep experimenting and have fun! 🚀

---

**Document Version**: 2.0 (Windows)  
**Last Updated**: 2026-01-03  
**Target Audience**: Windows beginners  
**Status**: Complete Step-by-Step Windows Guide
