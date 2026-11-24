# Game Client — Native Win32 C++17 Port (`gclient`)

Native Win32 C++17 desktop client built on **Cocos2d-x 2.2.6 (Win32 x86)** + Lua.

## 1. Asset Directory Layout

Place `GCLIENT.exe` (with its companion `.dll` files) alongside your extracted game assets:

```text
C:\GCLIENT\
├── GCLIENT.exe                     # Native Win32 x86 executable (+ .dlls)
├── base_assets\                    # Extracted base "assets/" directory
│   ├── platform\
│   │   ├── config.json             # Plaintext or encrypted platform config
│   │   └── game_config.json        # Plaintext or encrypted game host config
│   ├── res\                        # Base UI (.pb), armatures (.xmlb), sprites (.plistb)
│   └── scripts\                    # Base Lua scripts (main.lua, etc.)
├── Resources\                      # Hot-updated Resources/ directory
│   ├── database\                   # SQLite 3 .db configuration tables
│   ├── res\                        # Updated UI, armatures, and textures
│   └── scripts\                    # Updated Lua scripts
└── profiles\                       # Per-instance isolated writable storage
```

## 2. Connecting to Local `gserver` (`127.0.0.1`)

Write plaintext `C:\GCLIENT\base_assets\platform\game_config.json`:

```json
{
  "host": "http://127.0.0.1:8080",
  "host_debug": "http://127.0.0.1:8080",
  "log_host": "http://127.0.0.1:8080",
  "log_host_debug": "http://127.0.0.1:8080",
  "pushurl": "http://127.0.0.1:8080/push",
  "gn": "vnsg2",
  "language": "vi_VN"
}
```

And launch `GCLIENT.exe`:

```bat
@echo off
set "GCLIENT_AUTH_URL=http://127.0.0.1:8080"
GCLIENT.exe ^
  --resources-dir "C:\GCLIENT\Resources" ^
  --base-assets-dir "C:\GCLIENT\base_assets" ^
  --profile-dir "C:\GCLIENT\profiles\acc1"
```

## 3. Building from Source (MSVC 2022 Win32 x86)

```bat
git clone --branch cocos2d-x-2.2.6 --depth 1 https://github.com/cocos2d/cocos2d-x.git external/cocos2d-x-2.2.6
python tools\patch_cocos2dx.py external\cocos2d-x-2.2.6
vcpkg install sqlite3:x86-windows protobuf:x86-windows curl:x86-windows openssl:x86-windows zlib:x86-windows
cmake -B build -G "Visual Studio 17 2022" -A Win32 ^
  -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" ^
  -DVCPKG_TARGET_TRIPLET=x86-windows ^
  -DGCLIENT_COCOS2DX_ROOT="%CD%\external\cocos2d-x-2.2.6" ^
  -DGCLIENT_COCOS2DX_LIB_DIR="%CD%\external\cocos2d-x-2.2.6\Release.win32"
cmake --build build --config Release
```
