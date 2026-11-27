# Kestrel Canvas — Axmol v2.11.5 LTS Port (`x64` / C++20 / LuaJIT 2.1)

Native **64-bit Windows (`x64`)** port of `kestrel-canvas` built on **[Axmol Engine `v2.11.5` LTS](https://github.com/axmolengine/axmol/releases/tag/v2.11.5)** (`C++20`), **64-bit LuaJIT `2.1`**, **ANGLE (Direct3D 11 / GLES 3.0)**, **Spine `4.2`**, and **OpenAL-Soft**.

> **Branch note:** This `feat/axmol-port` branch targets **Axmol `v2.11.5` (`x64`)** and loads converted plain/modernized resources (`Resources_Axmol_Converted`), while `main` preserves the original 32-bit Cocos2d-x `2.2.6` (`Win32 x86`) baseline untouched.

## Key Engine & Runtime Upgrades

- **64-Bit C++20 Engine Core (`Axmol v2.11.5 LTS`)**: Replaces 32-bit Cocos2d-x `2.2.6` with Axmol's modern `ax::Director`, `ax::RenderViewImpl` (GLFW + ANGLE D3D11), `ax::AudioEngine` (OpenAL-Soft), and `axslcc` precompiled shader pipeline (`axslc/`).
- **64-Bit LuaJIT `2.1` (`AX_USE_LUAJIT=ON`)**: Preserves 100% Lua 5.1 script compatibility (`module(..., package.seeall)`, `loadstring`, `setfenv`, `string.gfind`, `tolua.getpeer`) on 64-bit Windows without 32-bit memory limits.
- **Cocos2d-x `2.2.6` C++ & Lua Runtime Compatibility Layer (`src/compat/`)**:
  - `Axmol226Compat.h/.cpp`: Bridges `CCArray`, `CCDictionary`, `CCString`, `CCInteger`, `TouchGroup`, and `SimpleAudioEngine` onto native `ax::Object`, `ax::ui::Widget`, and `ax::AudioEngine`.
  - `Lua226CompatShim.h/.cpp`: Self-contained runtime bridge for `ccp`/`ccc3`/`ccc4`/`CCSizeMake`/`CCRectMake`, `tolua.cast` (`Button` -> `axui.Button`, `Label` -> `axui.Text`, `ImageView` -> `axui.ImageView`), `CCSequence`/`CCSpawn` array unpacking, `CCLabelBMFont`, `CCNotificationCenter`, and `CCLayer` touch handlers.
- **Converted Asset Pipeline (`Resources_Axmol_Converted`)**:
  - `BtDecryptHook`: Automatic fallback resolver mapping legacy `.pvr.ccz` / `.pvr` / `.pkm` texture requests to converted `.png` files, `.plistb` to `.plist`, `.json` UI layouts to `.pb`, and `.xml` armatures to `.xmlb` (while retaining backwards-compatible decryption if any `BT`-prefixed asset is encountered).
  - `PbGuiLoader` & `XmlbArmatureLoader`: Native `ax::ui::*` (`Button`, `Text`, `TextBMFont`, `TextAtlas`, `ImageView`, `LoadingBar`, `Slider`, `CheckBox`, `TextField`, `ScrollView`, `ListView`, `PageView`, `Layout`) and `ccs::Armature` builders from binary `.pb` and `.xmlb` descriptors.
  - `SpineLuaAnimation` (`LuaHelpers.cpp`): Ported to Axmol's **Spine `4.2`** C++ runtime (`spine::SkeletonAnimation`), supporting Spine `4.1`/`4.2` `.json` + `.atlas` skeletons.

## Running with `Resources_Axmol_Converted`

1. Download the **`gclient-axmol-win64-release`** artifact from GitHub Actions (or build locally using the commands below). Ensure the `axslc/` shader folder and all staged `.dll` files remain beside `GCLIENT.exe`.
2. Place your converted `Resources_Axmol_Converted` folder next to `GCLIENT.exe` renamed as `Resources` (so `Resources/scripts/main.lua` exists), **or** pass `--resources-dir` directly:

```powershell
.\GCLIENT.exe --resources-dir "D:\OMG3Q_Resources\Resources_Axmol_Converted"
```

Optional headless asset sanity check:

```powershell
.\GCLIENT.exe --validate-assets --resources-dir "D:\OMG3Q_Resources\Resources_Axmol_Converted"
```

## Building Locally on Windows x64 (Visual Studio 2022)

### Prerequisites
- Visual Studio 2022 (`MSVC v143` x64 C++ workload)
- CMake `>= 3.25` and PowerShell `7+` (`pwsh`)
- `vcpkg` with `protobuf:x64-windows` and `sqlite3:x64-windows` (Axmol `3rdparty` provides `luajit`, `zlib`, `openssl`, `curl`, `unzip`, `openal`, `glfw`, and `angle`)

### Build Steps

```powershell
# 1. Install Protobuf & SQLite3 via vcpkg (dynamic /MD x64)
vcpkg install protobuf:x64-windows sqlite3:x64-windows

# 2. Clone Axmol v2.11.5 LTS & provision the axslcc shader compiler
git clone --branch v2.11.5 --depth 1 https://github.com/axmolengine/axmol.git external/axmol
$env:AX_ROOT = (Resolve-Path external/axmol).Path
pwsh -NoProfile -ExecutionPolicy Bypass -Command "& { $Global:is_axmol_engine = $true; Set-Location $env:AX_ROOT; . ./1k/1kiss.ps1 -setupOnly -prefix ./tools/external }"

# 3. Configure & build GCLIENT.exe (Release x64)
cmake -B build -G "Visual Studio 17 2022" -A x64 `
  -DGCLIENT_AXMOL_ROOT="$env:AX_ROOT" `
  -DGCLIENT_VCPKG_INSTALLED_DIR="$env:VCPKG_INSTALLATION_ROOT/installed/x64-windows" `
  -DGCLIENT_BUILD_TESTS=ON

cmake --build build --config Release --parallel

# 4. Run CTest regression & LuaJIT 2.1 x64 ABI/shim verification
ctest --test-dir build -C Release --output-on-failure --verbose
```

Compiled output (`GCLIENT.exe`, runtime DLLs, and `axslc/` shaders) is emitted under `build/bin/gclient/Release/`.
