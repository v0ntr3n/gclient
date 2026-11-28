cmake_minimum_required(VERSION 3.25...4.1)

foreach(_pol IN ITEMS CMP0091 CMP0141 CMP0079)
    if(POLICY ${_pol})
        cmake_policy(SET ${_pol} NEW)
    endif()
endforeach()

# Enforce consistent dynamic CRT (/MD in Release, /MDd in Debug) across all CMake targets
# BEFORE project() creates compiler probes or subtargets.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL" CACHE STRING
    "MSVC CRT selection (/MD for Release, /MDd for Debug)" FORCE)

# ==============================================================================
# 1. Pre-Project Axmol Engine & LuaJIT 2.1 x64 Configuration
# ==============================================================================
# APP_NAME MUST match the executable target name expected by ax_setup_app_config()
set(APP_NAME gclient)
set(_AX_LUA_PROJ TRUE)
set(_AX_USE_PREBUILT FALSE)

# Force 64-bit LuaJIT 2.1 instead of plainlua (Lua 5.4) so legacy Lua 5.1 game scripts
# (module(..., package.seeall), loadstring, setfenv, string.gfind) run unmodified on x64.
set(AX_USE_LUAJIT ON CACHE BOOL "Use 64-bit LuaJIT 2.1 instead of Lua 5.4" FORCE)

# Enable required Axmol extensions (axlua requires GUI, CocoStudio, Spine, and FairyGUI)
foreach(_ext_on IN ITEMS AX_EXT_HINT AX_ENABLE_EXT_LUA AX_ENABLE_EXT_GUI AX_ENABLE_EXT_COCOSTUDIO AX_ENABLE_EXT_SPINE AX_ENABLE_EXT_FAIRYGUI)
    set(${_ext_on} ON CACHE BOOL "Enable ${_ext_on}" FORCE)
endforeach()

# Disable optional heavy desktop extras not required by Kestrel Canvas
foreach(_ext_off IN ITEMS AX_ENABLE_EXT_IMGUI AX_ENABLE_EXT_INSPECTOR AX_ENABLE_MSEDGE_WEBVIEW2 AX_ENABLE_MFMEDIA AX_WITH_DOCTEST)
    set(${_ext_off} OFF CACHE BOOL "Disable ${_ext_off}" FORCE)
endforeach()

project(${APP_NAME}
    VERSION 2.0.0
    DESCRIPTION "Kestrel Canvas x64 Port (Visual Studio 2022 + Axmol v2.11.5 LTS + LuaJIT 2.1)"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(GCLIENT_ENFORCE_WIN64 "Require 64-bit x64 target on MSVC" ON)
option(GCLIENT_ENFORCE_MD_CRT "Reject static CRT triplets (-static) on Windows DLL builds" ON)
option(GCLIENT_ENABLE_LUAPROFILER "Register optional luaopen_luaprofiler binding" OFF)
option(GCLIENT_BUILD_TESTS "Build unit, LuaJIT 2.1 ABI, and regression test targets (CTest)" OFF)
option(GCLIENT_ENABLE_ASAN "Enable MSVC AddressSanitizer (/fsanitize=address) diagnostic build" OFF)
option(GCLIENT_SHIPPING_RELEASE "Enforce strict shipping Release hygiene (forbids ASan/Debug CRTs)" OFF)

# Optional compile-time bootstrap defaults (overridden at runtime by CLI / KESTREL_* / COBALT_* env vars)
set(KESTREL_DEFAULT_MAPI_URL "" CACHE STRING "Optional default MAPI endpoint URL baked into AppConfig")
set(KESTREL_DEFAULT_GAME_HOST "" CACHE STRING "Optional default game relay/server host baked into AppConfig")
set(KESTREL_DEFAULT_GAME_PORT "0" CACHE STRING "Optional default game relay/server port baked into AppConfig")

if(WIN32 AND MSVC)
    if(GCLIENT_ENFORCE_WIN64 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR
            "Kestrel Canvas (Axmol v2.11.5 port) targets 64-bit Windows (x64). "
            "Configure with '-G \"Visual Studio 17 2022\" -A x64'."
        )
    endif()
    if(GCLIENT_ENFORCE_MD_CRT AND DEFINED VCPKG_TARGET_TRIPLET AND VCPKG_TARGET_TRIPLET MATCHES "-static")
        message(FATAL_ERROR
            "VCPKG_TARGET_TRIPLET='${VCPKG_TARGET_TRIPLET}' uses static CRT (/MT). "
            "Use dynamic /MD x64-windows packages."
        )
    endif()
    if(GCLIENT_SHIPPING_RELEASE AND GCLIENT_ENABLE_ASAN)
        message(FATAL_ERROR "GCLIENT_ENABLE_ASAN must NOT be enabled when GCLIENT_SHIPPING_RELEASE=ON.")
    endif()
endif()

# ==============================================================================
# 2. Locate & Add Axmol Engine v2.11.5 LTS
# ==============================================================================
if(DEFINED GCLIENT_AXMOL_ROOT AND NOT GCLIENT_AXMOL_ROOT STREQUAL "")
    set(_GCLIENT_AX_CANDIDATE "${GCLIENT_AXMOL_ROOT}")
elseif(DEFINED AX_ROOT AND NOT AX_ROOT STREQUAL "")
    set(_GCLIENT_AX_CANDIDATE "${AX_ROOT}")
elseif(DEFINED ENV{AX_ROOT} AND NOT "$ENV{AX_ROOT}" STREQUAL "")
    set(_GCLIENT_AX_CANDIDATE "$ENV{AX_ROOT}")
else()
    set(_GCLIENT_AX_CANDIDATE "${CMAKE_CURRENT_SOURCE_DIR}/external/axmol")
endif()

file(TO_CMAKE_PATH "${_GCLIENT_AX_CANDIDATE}" _AX_ROOT)
set(GCLIENT_AXMOL_ROOT "${_AX_ROOT}" CACHE PATH "Path to Axmol v2.11.5 source tree" FORCE)

if(NOT EXISTS "${_AX_ROOT}/core/axmol.h")
    message(FATAL_ERROR
        "Axmol v2.11.5 source tree not found at '${_AX_ROOT}'. "
        "Clone https://github.com/axmolengine/axmol.git --branch v2.11.5 into external/axmol "
        "or pass -DGCLIENT_AXMOL_ROOT=<path>."
    )
endif()

# Ensure ENV{AX_ROOT} is populated before AXBuildSet.cmake resolves $ENV{AX_ROOT}/tools/external/axslcc
set(ENV{AX_ROOT} "${_AX_ROOT}")

list(APPEND CMAKE_MODULE_PATH "${_AX_ROOT}/cmake/Modules/")
include(AXBuildSet)

add_subdirectory("${_AX_ROOT}/core" "${ENGINE_BINARY_PATH}/axmol/core")

# ==============================================================================
# 3. External Protobuf & SQLite3 (Resolved AFTER Axmol 3rdparty to avoid zlib clash)
# ==============================================================================
set(GCLIENT_VCPKG_INSTALLED_DIR "" CACHE PATH
    "Optional path to vcpkg installed/<triplet> (e.g. C:/vcpkg/installed/x64-windows) for Protobuf & SQLite3")

if(GCLIENT_VCPKG_INSTALLED_DIR AND EXISTS "${GCLIENT_VCPKG_INSTALLED_DIR}")
    file(TO_CMAKE_PATH "${GCLIENT_VCPKG_INSTALLED_DIR}" _gclient_vcpkg_dir)
    list(APPEND CMAKE_PREFIX_PATH "${_gclient_vcpkg_dir}")
endif()

find_package(Protobuf CONFIG QUIET)
if(NOT Protobuf_FOUND)
    find_package(Protobuf REQUIRED)
endif()

find_package(unofficial-sqlite3 CONFIG QUIET)
if(TARGET unofficial::sqlite3::sqlite3 AND NOT TARGET SQLite::SQLite3)
    add_library(SQLite::SQLite3 ALIAS unofficial::sqlite3::sqlite3)
elseif(NOT TARGET SQLite::SQLite3)
    find_package(SQLite3 REQUIRED)
endif()

# Normalize CURL target alias onto Axmol's 3rdparty `curl` target
if(TARGET curl AND NOT TARGET CURL::libcurl)
    add_library(CURL::libcurl ALIAS curl)
elseif(NOT TARGET CURL::libcurl)
    find_package(CURL REQUIRED)
endif()

# Resolve protoc code generator reliably across vcpkg CONFIG and system packages
if(TARGET protobuf::protoc)
    set(GCLIENT_PROTOC_EXECUTABLE $<TARGET_FILE:protobuf::protoc>)
elseif(DEFINED Protobuf_PROTOC_EXECUTABLE AND EXISTS "${Protobuf_PROTOC_EXECUTABLE}")
    set(GCLIENT_PROTOC_EXECUTABLE "${Protobuf_PROTOC_EXECUTABLE}")
else()
    find_program(GCLIENT_PROTOC_EXECUTABLE
        NAMES protoc
        HINTS "${GCLIENT_VCPKG_INSTALLED_DIR}/tools/protobuf"
        REQUIRED
    )
endif()

# ==============================================================================
# 4. Protobuf Code Generation (CSGUI.proto, CSScene.proto, db.proto)
# ==============================================================================
set(GCLIENT_PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(GCLIENT_PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/proto")
file(MAKE_DIRECTORY "${GCLIENT_PROTO_GEN_DIR}")

set(GCLIENT_PROTO_FILES
    "${GCLIENT_PROTO_DIR}/CSGUI.proto"
    "${GCLIENT_PROTO_DIR}/CSScene.proto"
    "${GCLIENT_PROTO_DIR}/db.proto"
)

set(GCLIENT_PROTO_SRCS "")
set(GCLIENT_PROTO_HDRS "")

foreach(proto_file IN LISTS GCLIENT_PROTO_FILES)
    get_filename_component(proto_name "${proto_file}" NAME_WE)
    set(gen_cc "${GCLIENT_PROTO_GEN_DIR}/${proto_name}.pb.cc")
    set(gen_h  "${GCLIENT_PROTO_GEN_DIR}/${proto_name}.pb.h")

    add_custom_command(
        OUTPUT "${gen_cc}" "${gen_h}"
        COMMAND "${GCLIENT_PROTOC_EXECUTABLE}"
            "--cpp_out=${GCLIENT_PROTO_GEN_DIR}"
            "-I${GCLIENT_PROTO_DIR}"
            "${proto_file}"
        DEPENDS "${proto_file}"
        COMMENT "Generating C++ protobuf sources from proto/${proto_name}.proto"
        VERBATIM
    )

    list(APPEND GCLIENT_PROTO_SRCS "${gen_cc}")
    list(APPEND GCLIENT_PROTO_HDRS "${gen_h}")
endforeach()

add_library(gclient_proto STATIC ${GCLIENT_PROTO_SRCS} ${GCLIENT_PROTO_HDRS})
target_include_directories(gclient_proto SYSTEM PUBLIC "${GCLIENT_PROTO_GEN_DIR}")
target_link_libraries(gclient_proto PUBLIC protobuf::libprotobuf)
if(MSVC)
    target_compile_options(gclient_proto PRIVATE
        /W0 /FS /utf-8 /Zc:char8_t-
        $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:/Zi /O2>
    )
else()
    target_compile_options(gclient_proto PRIVATE -fno-char8_t -w)
endif()

# ==============================================================================
# 5. Common Axmol Interface, Shared `src/common` Headers & Compiler Settings
# ==============================================================================
set(GCLIENT_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/compat/include"
)
file(GLOB GCLIENT_COMMON_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common/*.hpp"
)

add_library(gclient_axmol_interface INTERFACE)
target_include_directories(gclient_axmol_interface INTERFACE ${GCLIENT_INCLUDE_DIRS})
target_include_directories(gclient_axmol_interface SYSTEM INTERFACE
    "${_AX_ROOT}"
    "${_AX_ROOT}/core"
    "${_AX_ROOT}/core/platform"
    "${_AX_ROOT}/extensions"
    "${_AX_ROOT}/extensions/GUI/src"
    "${_AX_ROOT}/extensions/cocostudio/src"
    "${_AX_ROOT}/extensions/spine/src"
    "${_AX_ROOT}/extensions/spine/runtime/include"
    "${_AX_ROOT}/extensions/scripting"
    "${_AX_ROOT}/extensions/scripting/lua-bindings/manual"
    "${_AX_ROOT}/3rdparty"
    "${_AX_ROOT}/3rdparty/glad/include"
    "${_AX_ROOT}/3rdparty/glfw/include"
    "${_AX_ROOT}/3rdparty/glfw/include/GLFW"
    "${_AX_ROOT}/3rdparty/fmt/include"
    "${_AX_ROOT}/3rdparty/robin-map/include"
    "${_AX_ROOT}/3rdparty/lua"
    "${_AX_ROOT}/3rdparty/lua/tolua"
    "${_AX_ROOT}/3rdparty/unzip"
    "${_AX_ROOT}/3rdparty/pugixml"
    "${_AX_ROOT}/3rdparty/simdjson"
    "${_AX_ROOT}/3rdparty/yasio"
)
target_link_libraries(gclient_axmol_interface INTERFACE
    ${_AX_CORE_LIB}
    ${_AX_LUA_LIB}
    ${_AX_EXTENSION_LIBS}
    luajit
    tolua
    lua-cjson
    unzip
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
)

add_library(gclient_build_options INTERFACE)
target_compile_features(gclient_build_options INTERFACE cxx_std_20)
target_compile_definitions(gclient_build_options INTERFACE
    $<$<PLATFORM_ID:Windows>:WIN32 _WINDOWS WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS _WINSOCK_DEPRECATED_NO_WARNINGS CC_TARGET_OS_WIN32>
    HAVE_STRUCT_TIMESPEC=1
    _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS=1
    GCLIENT_USE_COCOS2DX=1
    GCLIENT_ENABLE_COCOS2DX=1
    AX_ENABLE_EXT_SPINE=1
    $<$<BOOL:${GCLIENT_ENABLE_LUAPROFILER}>:GCLIENT_ENABLE_LUAPROFILER=1>
)

if(NOT KESTREL_DEFAULT_MAPI_URL STREQUAL "")
    target_compile_definitions(gclient_build_options INTERFACE
        KESTREL_DEFAULT_MAPI_URL="${KESTREL_DEFAULT_MAPI_URL}"
    )
endif()
if(NOT KESTREL_DEFAULT_GAME_HOST STREQUAL "")
    target_compile_definitions(gclient_build_options INTERFACE
        KESTREL_DEFAULT_GAME_HOST="${KESTREL_DEFAULT_GAME_HOST}"
    )
endif()
if(KESTREL_DEFAULT_GAME_PORT GREATER 0)
    target_compile_definitions(gclient_build_options INTERFACE
        KESTREL_DEFAULT_GAME_PORT=${KESTREL_DEFAULT_GAME_PORT}
    )
endif()

if(MSVC)
    target_compile_options(gclient_build_options INTERFACE
        /W3 /MP /FS /utf-8 /EHsc /permissive- /Zc:__cplusplus /Zc:char8_t- /bigobj
        $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:/Zi /O2 /Oi>
    )
    if(GCLIENT_ENABLE_ASAN)
        target_compile_options(gclient_build_options INTERFACE /fsanitize=address)
        target_compile_definitions(gclient_build_options INTERFACE
            _DISABLE_VECTOR_ANNOTATION=1
            _DISABLE_STRING_ANNOTATION=1
        )
    endif()
else()
    target_compile_options(gclient_build_options INTERFACE -fno-char8_t)
endif()

function(gclient_apply_exe_link_options TARGET_NAME)
    if(MSVC)
        target_link_options(${TARGET_NAME} PRIVATE
            /LARGEADDRESSAWARE
            $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO>
        )
    endif()
endfunction()

# ==============================================================================
# 6. Modular src/ Subsystems
# ==============================================================================
add_library(gclient_diagnostics STATIC
    src/diagnostics/CrashAndTelemetry.h
    src/diagnostics/CrashAndTelemetry.cpp
    ${GCLIENT_COMMON_HEADERS}
)
target_include_directories(gclient_diagnostics PUBLIC ${GCLIENT_INCLUDE_DIRS})
target_link_libraries(gclient_diagnostics
    PUBLIC
        gclient_build_options
        gclient_axmol_interface
    PRIVATE
        $<$<PLATFORM_ID:Windows>:dbghelp psapi>
)

add_library(gclient_compat STATIC
    src/compat/Axmol226Compat.h
    src/compat/Axmol226Compat.cpp
    src/compat/Lua226CompatShim.h
    src/compat/Lua226CompatShim.cpp
    ${GCLIENT_COMMON_HEADERS}
)
target_include_directories(gclient_compat PUBLIC ${GCLIENT_INCLUDE_DIRS})
target_link_libraries(gclient_compat PUBLIC
    gclient_build_options
    gclient_axmol_interface
    gclient_diagnostics
)

function(gclient_add_module MODULE_NAME SUBDIR)
    set(mod_dir "${CMAKE_CURRENT_SOURCE_DIR}/src/${SUBDIR}")
    file(GLOB_RECURSE mod_sources CONFIGURE_DEPENDS
        "${mod_dir}/*.cpp"
        "${mod_dir}/*.cc"
        "${mod_dir}/*.c"
        "${mod_dir}/*.h"
        "${mod_dir}/*.hpp"
    )

    add_library(${MODULE_NAME} STATIC ${mod_sources} ${GCLIENT_COMMON_HEADERS})
    target_include_directories(${MODULE_NAME} PUBLIC ${GCLIENT_INCLUDE_DIRS} "${mod_dir}")
    target_link_libraries(${MODULE_NAME} PUBLIC
        gclient_build_options
        gclient_axmol_interface
        gclient_compat
        gclient_diagnostics
        gclient_proto
        SQLite::SQLite3
        CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
        $<$<PLATFORM_ID:Windows>:ws2_32 bcrypt crypt32 user32 gdi32 advapi32>
    )
endfunction()

gclient_add_module(gclient_assets   assets)
gclient_add_module(gclient_net      net)
gclient_add_module(gclient_platform platform)
gclient_add_module(gclient_update   update)
gclient_add_module(gclient_ui       ui)
gclient_add_module(gclient_bindings bindings)

# Cross-module static library references (bindings <-> net / assets / platform / ui)
target_link_libraries(gclient_bindings PUBLIC
    gclient_assets
    gclient_net
    gclient_platform
    gclient_update
    gclient_ui
)
target_link_libraries(gclient_platform PUBLIC gclient_assets)

# ==============================================================================
# 7. Main Windows x64 Executable Target (GCLIENT.exe + GCLIENT.pdb + axslc)
# ==============================================================================
set(GCLIENT_APP_SOURCES
    src/main.cpp
    src/AppDelegate.h
    src/AppDelegate.cpp
    ${GCLIENT_COMMON_HEADERS}
)
if(WIN32)
    add_executable(${APP_NAME} WIN32 ${GCLIENT_APP_SOURCES})
else()
    add_executable(${APP_NAME} ${GCLIENT_APP_SOURCES})
endif()

target_include_directories(${APP_NAME} PRIVATE ${GCLIENT_INCLUDE_DIRS})

# Plain target_link_libraries signature MUST be retained for ax_setup_app_config() compatibility (CMP0023)
target_link_libraries(${APP_NAME}
    gclient_build_options
    gclient_bindings
    gclient_assets
    gclient_net
    gclient_platform
    gclient_update
    gclient_ui
    gclient_compat
    gclient_diagnostics
    gclient_proto
    gclient_axmol_interface
    SQLite::SQLite3
    protobuf::libprotobuf
    $<$<PLATFORM_ID:Windows>:ws2_32 bcrypt crypt32 user32 gdi32 advapi32 dbghelp psapi shell32 comdlg32 shlwapi ole32 winmm opengl32>
)

# Configure Axmol app layout (bin/gclient/<Config>, /STACK:4194304, /SUBSYSTEM:WINDOWS, axslc shaders)
ax_setup_app_config(${APP_NAME})

set_target_properties(${APP_NAME} PROPERTIES OUTPUT_NAME "GCLIENT")
gclient_apply_exe_link_options(${APP_NAME})

if(WINDOWS AND NOT _AX_USE_PREBUILT)
    ax_sync_target_dlls(${APP_NAME} LUA)
endif()

# ==============================================================================
# 8. Automated Regression, LuaJIT 2.1 x64 ABI & Shim Test Suite (CTest)
# ==============================================================================
if(GCLIENT_BUILD_TESTS)
    set(BUILD_TESTING ON CACHE BOOL "Enable CTest targets for Kestrel Canvas" FORCE)
    enable_testing()
    find_package(Python3 COMPONENTS Interpreter QUIET)

    function(gclient_stage_test_runtime_dlls TEST_TARGET)
        if(WIN32)
            add_custom_command(TARGET ${TEST_TARGET} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    $<TARGET_RUNTIME_DLLS:${TEST_TARGET}>
                    $<TARGET_FILE_DIR:${TEST_TARGET}>
                COMMAND_EXPAND_LISTS
                VERBATIM
            )
        endif()
    endfunction()

    function(gclient_add_cpp_test TARGET_NAME)
        cmake_parse_arguments(TEST "" "MAIN_SOURCE" "SOURCES;DEFINITIONS;LIBS;WIN32_LIBS;TEST_ARGS" ${ARGN})
        if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${TEST_MAIN_SOURCE}")
            return()
        endif()

        add_executable(${TARGET_NAME}
            "${TEST_MAIN_SOURCE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/TestHarness.h"
            ${GCLIENT_COMMON_HEADERS}
            ${TEST_SOURCES}
        )
        target_compile_features(${TARGET_NAME} PRIVATE cxx_std_20)
        target_include_directories(${TARGET_NAME} PRIVATE
            ${GCLIENT_INCLUDE_DIRS}
            "${CMAKE_CURRENT_SOURCE_DIR}/tests"
        )
        target_compile_definitions(${TARGET_NAME} PRIVATE
            ${TEST_DEFINITIONS}
            $<$<PLATFORM_ID:Windows>:WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS>
        )
        target_link_libraries(${TARGET_NAME} PRIVATE
            ${TEST_LIBS}
            $<$<PLATFORM_ID:Windows>:${TEST_WIN32_LIBS}>
            $<$<NOT:$<PLATFORM_ID:Windows>>:pthread dl>
        )
        if(MSVC)
            target_compile_options(${TARGET_NAME} PRIVATE /W3 /utf-8 /EHsc /permissive- /Zc:char8_t- /FS /Zi)
            gclient_apply_exe_link_options(${TARGET_NAME})
        else()
            target_compile_options(${TARGET_NAME} PRIVATE -fno-char8_t)
        endif()
        gclient_stage_test_runtime_dlls(${TARGET_NAME})
        add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME} ${TEST_TEST_ARGS})
    endfunction()

    gclient_add_cpp_test(gclient_win32_regression_tests
        MAIN_SOURCE tests/test_win32_regression.cpp
        SOURCES
            src/assets/BtDecryptHook.cpp
            src/assets/PlistbLoader.cpp
            src/assets/XmlbArmatureLoader.cpp
            src/net/Amf3Module.cpp
            src/net/LCPacket.cpp
            src/net/CConnection.cpp
            src/net/CNetwork.cpp
            src/platform/AccountAuthProvider.cpp
            src/platform/BtPlatformWin32.cpp
            src/platform/tolua_Platform.cpp
            src/update/AtomicHotUpdater.cpp
            src/diagnostics/CrashAndTelemetry.cpp
        DEFINITIONS
            GCLIENT_STANDALONE_BUILD=1
            $<$<PLATFORM_ID:Windows>:_WINSOCK_DEPRECATED_NO_WARNINGS>
        LIBS
            luajit ZLIB::ZLIB SQLite::SQLite3 CURL::libcurl OpenSSL::SSL OpenSSL::Crypto
        WIN32_LIBS
            ws2_32 bcrypt crypt32 dbghelp psapi user32 gdi32 advapi32 shell32
    )

    gclient_add_cpp_test(gclient_luajit_abi_tests
        MAIN_SOURCE tests/test_luajit_abi.cpp
        SOURCES
            src/net/Amf3Module.cpp
            src/compat/Lua226CompatShim.cpp
            src/diagnostics/CrashAndTelemetry.cpp
        LIBS
            luajit
        WIN32_LIBS
            dbghelp psapi kernel32
    )

    gclient_add_cpp_test(gclient_cobalt_relay_e2e_tests
        MAIN_SOURCE tests/test_cobalt_relay_e2e.cpp
        SOURCES
            src/assets/BtDecryptHook.cpp
            src/net/Amf3Module.cpp
            src/net/LCPacket.cpp
            src/net/CConnection.cpp
            src/net/CNetwork.cpp
            src/update/AtomicHotUpdater.cpp
        DEFINITIONS
            GCLIENT_STANDALONE_BUILD=1
            GCLIENT_WITH_LUAJIT_AMF3=1
            $<$<PLATFORM_ID:Windows>:_WINSOCK_DEPRECATED_NO_WARNINGS>
        LIBS
            luajit ZLIB::ZLIB OpenSSL::Crypto
        WIN32_LIBS
            ws2_32 bcrypt crypt32 user32 advapi32 shell32
        TEST_ARGS
            --self-test
    )

    if(Python3_Interpreter_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_patch_and_pe_validator.py")
        add_test(
            NAME gclient_python_patch_and_pe_tests
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_patch_and_pe_validator.py"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        )
    endif()
endif()
