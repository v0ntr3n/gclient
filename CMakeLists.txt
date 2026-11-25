cmake_minimum_required(VERSION 3.20)

if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()

# Enforce consistent dynamic CRT (/MD in Release, /MDd in Debug) across all CMake targets
# BEFORE project() creates compiler probes or subtargets.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL" CACHE STRING
    "MSVC CRT selection (/MD for Release, /MDd for Debug)" FORCE)

project(gclient-win32
    VERSION 1.1.0
    DESCRIPTION "Game Client Native Win32 x86 Port (Visual Studio 2022 v143 + Cocos2d-x 2.2.6 + LuaJIT 2.0.1)"
    LANGUAGES C CXX
)

# ==============================================================================
# 1. Toolchain, CRT & Architecture Enforcement (VS2022 v143 Win32 x86 + /MD)
# ==============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(GCLIENT_ENFORCE_WIN32_X86 "Require 32-bit x86 target on MSVC" ON)
option(GCLIENT_ENFORCE_MD_CRT "Reject static CRT triplets (-static) on Win32 DLL builds" ON)
option(GCLIENT_ENABLE_LUAPROFILER "Register optional luaopen_luaprofiler binding" OFF)
option(GCLIENT_BUILD_TESTS "Build unit and regression test targets (CTest)" OFF)
option(GCLIENT_ENABLE_STATIC_ANALYSIS "Enable MSVC /analyze static analysis on first-party targets" OFF)
option(GCLIENT_ENABLE_ASAN "Enable MSVC AddressSanitizer (/fsanitize=address) diagnostic build (NEVER ship in Release)" OFF)
option(GCLIENT_SHIPPING_RELEASE "Enforce strict shipping Release hygiene (forbids ASan/Debug CRTs)" OFF)
option(GCLIENT_REQUIRE_FRESH_LUAJIT "Require freshly compiled LuaJIT 2.0.1 v143 import library" OFF)
option(GCLIENT_ASSUME_PATCHED_COCOS2DX
    "Define GCLIENT_CCFILEUTILS_HAS_SET_DECRYPT (expects tools/patch_cocos2dx.py applied)" ON)

if(WIN32 AND MSVC)
    if(GCLIENT_ENFORCE_WIN32_X86 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
        message(FATAL_ERROR
            "Game Client targets Win32 x86 (32-bit) for Cocos2d-x 2.2.6 & LuaJIT 2.0.1 ABI compatibility. "
            "Configure with '-G \"Visual Studio 17 2022\" -A Win32 -T v143'."
        )
    endif()
    if(MSVC_VERSION LESS 1930)
        message(WARNING
            "Detected MSVC_VERSION=${MSVC_VERSION} (< 1930). Visual Studio 2022 (MSVC v143, >= 1930) is the supported toolchain."
        )
    endif()
    if(GCLIENT_ENFORCE_MD_CRT AND DEFINED VCPKG_TARGET_TRIPLET AND VCPKG_TARGET_TRIPLET MATCHES "-static")
        message(FATAL_ERROR
            "VCPKG_TARGET_TRIPLET='${VCPKG_TARGET_TRIPLET}' uses static CRT (/MT), which causes cross-DLL heap corruption "
            "with libcocos2d.dll and lua51.dll. Use -DVCPKG_TARGET_TRIPLET=x86-windows."
        )
    endif()
    if(GCLIENT_SHIPPING_RELEASE AND GCLIENT_ENABLE_ASAN)
        message(FATAL_ERROR "GCLIENT_ENABLE_ASAN must NOT be enabled when GCLIENT_SHIPPING_RELEASE=ON.")
    endif()
endif()

# ==============================================================================
# 2. External Cocos2d-x 2.2.6 & Rebuilt LuaJIT 2.0.1 (v143 /MD)
# ==============================================================================
if(DEFINED COCOS2DX_ROOT AND NOT DEFINED GCLIENT_COCOS2DX_ROOT)
    set(GCLIENT_COCOS2DX_ROOT "${COCOS2DX_ROOT}")
endif()
set(GCLIENT_COCOS2DX_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/external/cocos2d-x-2.2.6"
    CACHE PATH "Path to Cocos2d-x 2.2.6 source tree")

set(GCLIENT_COCOS2DX_LIB_DIR "${GCLIENT_COCOS2DX_ROOT}/Release.win32"
    CACHE PATH "Path to compiled Cocos2d-x 2.2.6 Win32 import libraries")

set(GCLIENT_LUAJIT_INCLUDE_DIR "${GCLIENT_COCOS2DX_ROOT}/scripting/lua/luajit/include"
    CACHE PATH "Path to LuaJIT 2.0.1 C API headers")

set(GCLIENT_LUAJIT_LIB_DIR "${GCLIENT_COCOS2DX_ROOT}/scripting/lua/luajit/win32"
    CACHE PATH "Path to freshly compiled LuaJIT 2.0.1 v143 lua51.lib & lua51.dll")

option(GCLIENT_COCOS2DX_BUILD_FROM_SOURCE
    "Add Cocos2d-x 2.2.6 via add_subdirectory instead of linking MSBuild v143 Win32 libs" OFF)

if(GCLIENT_REQUIRE_FRESH_LUAJIT AND NOT EXISTS "${GCLIENT_LUAJIT_LIB_DIR}/lua51.lib")
    message(FATAL_ERROR
        "GCLIENT_REQUIRE_FRESH_LUAJIT=ON, but '${GCLIENT_LUAJIT_LIB_DIR}/lua51.lib' does not exist. "
        "Run tools/build_luajit_vs2022.ps1 first."
    )
endif()

# Fall back to scripting/lua/lua headers ONLY if luajit/include does not exist in a partial local tree.
if(EXISTS "${GCLIENT_LUAJIT_INCLUDE_DIR}/lua.h")
    set(_GCLIENT_ACTIVE_LUA_INCLUDE_DIR "${GCLIENT_LUAJIT_INCLUDE_DIR}")
else()
    set(_GCLIENT_ACTIVE_LUA_INCLUDE_DIR "${GCLIENT_COCOS2DX_ROOT}/scripting/lua/lua")
endif()

if(NOT EXISTS "${GCLIENT_COCOS2DX_ROOT}")
    message(WARNING
        "Cocos2d-x 2.2.6 directory not found at '${GCLIENT_COCOS2DX_ROOT}'. "
        "Place the Cocos2d-x 2.2.6 tree there and run 'python tools/patch_cocos2dx.py external/cocos2d-x-2.2.6' before building."
    )
elseif(EXISTS "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/CCFileUtils.h")
    file(READ "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/CCFileUtils.h" _gclient_ccfileutils_hdr)
    if(NOT _gclient_ccfileutils_hdr MATCHES "GCLIENT_BT_DECRYPT_HOOK")
        message(WARNING
            "CCFileUtils.h at '${GCLIENT_COCOS2DX_ROOT}' does not contain GCLIENT_BT_DECRYPT_HOOK yet. "
            "Run 'python tools/patch_cocos2dx.py \"${GCLIENT_COCOS2DX_ROOT}\"' before compiling."
        )
    endif()
    unset(_gclient_ccfileutils_hdr)
endif()

set(GCLIENT_OVERLAY_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/assets/overlay")
    list(APPEND GCLIENT_OVERLAY_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/src/assets/overlay")
endif()

set(GCLIENT_COCOS2DX_INCLUDE_DIRS
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx"
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/include"
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/kazmath/include"
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/win32"
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/third_party/win32"
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/third_party/win32/OGLES"
    "${GCLIENT_COCOS2DX_ROOT}/CocosDenshion/include"
    "${GCLIENT_COCOS2DX_ROOT}/extensions"
    "${GCLIENT_COCOS2DX_ROOT}/scripting/lua/cocos2dx_support"
    "${_GCLIENT_ACTIVE_LUA_INCLUDE_DIR}"
    "${GCLIENT_COCOS2DX_ROOT}/scripting/lua/tolua"
    "${GCLIENT_COCOS2DX_ROOT}/external"
)

# ==============================================================================
# 3. Third-Party Dependencies (vcpkg x86-windows v143 /MD)
# ==============================================================================
find_package(SQLite3 REQUIRED)
find_package(Protobuf REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(GLEW QUIET)

add_library(gclient_cocos2dx_interface INTERFACE)
target_include_directories(gclient_cocos2dx_interface INTERFACE
    ${GCLIENT_OVERLAY_INCLUDE_DIRS}
)
target_include_directories(gclient_cocos2dx_interface SYSTEM INTERFACE
    ${GCLIENT_COCOS2DX_INCLUDE_DIRS}
)
target_compile_definitions(gclient_cocos2dx_interface INTERFACE
    HAVE_STRUCT_TIMESPEC=1
    _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS=1
    $<$<BOOL:${GCLIENT_ASSUME_PATCHED_COCOS2DX}>:GCLIENT_CCFILEUTILS_HAS_SET_DECRYPT=1>
)

if(GCLIENT_COCOS2DX_BUILD_FROM_SOURCE AND EXISTS "${GCLIENT_COCOS2DX_ROOT}/CMakeLists.txt")
    add_subdirectory("${GCLIENT_COCOS2DX_ROOT}" "${CMAKE_BINARY_DIR}/external/cocos2d-x-2.2.6" EXCLUDE_FROM_ALL)
    target_link_libraries(gclient_cocos2dx_interface INTERFACE
        cocos2d
        CocosDenshion
        extensions
        lua
        $<$<TARGET_EXISTS:GLEW::GLEW>:GLEW::GLEW>
        $<$<NOT:$<TARGET_EXISTS:GLEW::GLEW>>:glew32>
    )
else()
    # Keep legacy third_party/win32/libraries OFF the linker search path whenever vcpkg GLEW::GLEW
    # is present so VS2010/VS2012 .lib archives never shadow vcpkg v143 import libraries!
    target_link_directories(gclient_cocos2dx_interface INTERFACE
        "${GCLIENT_COCOS2DX_LIB_DIR}"
        "${GCLIENT_LUAJIT_LIB_DIR}"
    )
    if(NOT TARGET GLEW::GLEW)
        target_link_directories(gclient_cocos2dx_interface INTERFACE
            "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/third_party/win32/libraries"
        )
    endif()
    target_link_libraries(gclient_cocos2dx_interface INTERFACE
        libcocos2d
        libCocosDenshion
        libExtensions
        liblua
        lua51
        $<$<TARGET_EXISTS:GLEW::GLEW>:GLEW::GLEW>
        $<$<NOT:$<TARGET_EXISTS:GLEW::GLEW>>:glew32>
    )
endif()

# Resolve protoc executable reliably across vcpkg and system installs
if(TARGET protobuf::protoc)
    set(GCLIENT_PROTOC_EXECUTABLE $<TARGET_FILE:protobuf::protoc>)
elseif(DEFINED Protobuf_PROTOC_EXECUTABLE AND EXISTS "${Protobuf_PROTOC_EXECUTABLE}")
    set(GCLIENT_PROTOC_EXECUTABLE "${Protobuf_PROTOC_EXECUTABLE}")
else()
    find_program(GCLIENT_PROTOC_EXECUTABLE NAMES protoc REQUIRED)
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
        /W0
        /FS
        /utf-8
        $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:/Zi /O2>
    )
endif()

# ==============================================================================
# 5. Common Compiler & Platform Settings
# ==============================================================================
add_library(gclient_build_options INTERFACE)
target_compile_features(gclient_build_options INTERFACE cxx_std_17)
target_compile_definitions(gclient_build_options INTERFACE
    WIN32
    _WINDOWS
    WIN32_LEAN_AND_MEAN
    _HAS_AUTO_PTR_ETC=1
    _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS=1
    HAVE_STRUCT_TIMESPEC=1
    NOMINMAX
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
    _WINSOCK_DEPRECATED_NO_WARNINGS
    CC_TARGET_OS_WIN32
    GCLIENT_USE_COCOS2DX=1
    GCLIENT_ENABLE_COCOS2DX=1
    $<$<BOOL:${GCLIENT_ASSUME_PATCHED_COCOS2DX}>:GCLIENT_CCFILEUTILS_HAS_SET_DECRYPT=1>
    $<$<BOOL:${GCLIENT_ENABLE_LUAPROFILER}>:GCLIENT_ENABLE_LUAPROFILER=1>
)

if(MSVC)
    target_compile_options(gclient_build_options INTERFACE
        /W4
        /MP
        /FS
        /utf-8
        /EHsc
        /permissive-
        /Zc:__cplusplus
        $<$<CONFIG:Release>:/Zi /O2 /Oi>
        $<$<AND:$<CONFIG:Release>,$<NOT:$<BOOL:${GCLIENT_ENABLE_ASAN}>>>:/GL>
    )
    if(GCLIENT_ENABLE_STATIC_ANALYSIS)
        target_compile_options(gclient_build_options INTERFACE
            /analyze
            /analyze:external-
            /external:anglebrackets
            /external:W0
        )
    endif()
    if(GCLIENT_ENABLE_ASAN)
        target_compile_options(gclient_build_options INTERFACE /fsanitize=address)
        target_compile_definitions(gclient_build_options INTERFACE
            _DISABLE_VECTOR_ANNOTATION=1
            _DISABLE_STRING_ANNOTATION=1
        )
    endif()
endif()

function(gclient_apply_exe_link_options TARGET_NAME)
    if(MSVC)
        target_link_options(${TARGET_NAME} PRIVATE
            /LARGEADDRESSAWARE
            $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO>
            $<$<AND:$<CONFIG:Release>,$<NOT:$<BOOL:${GCLIENT_ENABLE_ASAN}>>>:/LTCG>
        )
    endif()
endfunction()

# ==============================================================================
# 6. Modular src/ Subsystems
# ==============================================================================
add_library(gclient_diagnostics STATIC
    src/diagnostics/CrashAndTelemetry.h
    src/diagnostics/CrashAndTelemetry.cpp
)
target_include_directories(gclient_diagnostics PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(gclient_diagnostics
    PUBLIC
        gclient_build_options
        gclient_cocos2dx_interface
    PRIVATE
        $<$<PLATFORM_ID:Windows>:dbghelp>
        $<$<PLATFORM_ID:Windows>:psapi>
)

function(gclient_add_module MODULE_NAME SUBDIR)
    set(mod_dir "${CMAKE_CURRENT_SOURCE_DIR}/src/${SUBDIR}")
    if(EXISTS "${mod_dir}/CMakeLists.txt")
        add_subdirectory("${mod_dir}")
        return()
    endif()

    file(GLOB_RECURSE mod_sources CONFIGURE_DEPENDS
        "${mod_dir}/*.cpp"
        "${mod_dir}/*.cc"
        "${mod_dir}/*.c"
        "${mod_dir}/*.h"
        "${mod_dir}/*.hpp"
    )

    set(has_compilable_src FALSE)
    foreach(f IN LISTS mod_sources)
        if(f MATCHES "\\.(cpp|cc|c)$")
            set(has_compilable_src TRUE)
            break()
        endif()
    endforeach()

    if(has_compilable_src)
        add_library(${MODULE_NAME} STATIC ${mod_sources})
        target_include_directories(${MODULE_NAME} PUBLIC
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
            "${mod_dir}"
        )
        target_link_libraries(${MODULE_NAME} PUBLIC
            gclient_build_options
            gclient_cocos2dx_interface
            gclient_diagnostics
            gclient_proto
            SQLite::SQLite3
            CURL::libcurl
            OpenSSL::SSL
            OpenSSL::Crypto
            ZLIB::ZLIB
        )
        if(WIN32)
            target_link_libraries(${MODULE_NAME} PUBLIC
                ws2_32
                bcrypt
                crypt32
                user32
                gdi32
                advapi32
            )
        endif()
    else()
        add_library(${MODULE_NAME} INTERFACE)
        target_include_directories(${MODULE_NAME} INTERFACE
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
            "${mod_dir}"
        )
    endif()
endfunction()

gclient_add_module(gclient_assets   assets)
gclient_add_module(gclient_net      net)
gclient_add_module(gclient_bindings bindings)
gclient_add_module(gclient_platform platform)
gclient_add_module(gclient_update   update)
gclient_add_module(gclient_ui       ui)

# ==============================================================================
# 7. Main Win32 Executable Target (GCLIENT.exe + GCLIENT.pdb)
# ==============================================================================
add_executable(gclient WIN32
    src/main.cpp
    src/AppDelegate.h
    src/AppDelegate.cpp
)

set_target_properties(gclient PROPERTIES
    OUTPUT_NAME "GCLIENT"
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>"
)

target_include_directories(gclient PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(gclient PRIVATE
    gclient_build_options
    gclient_cocos2dx_interface
    gclient_diagnostics
    gclient_assets
    gclient_net
    gclient_bindings
    gclient_platform
    gclient_update
    gclient_ui
    gclient_proto
    SQLite::SQLite3
    protobuf::libprotobuf
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    ws2_32
    bcrypt
    crypt32
    user32
    gdi32
    advapi32
    dbghelp
    psapi
    shell32
    comdlg32
    shlwapi
    ole32
    winmm
    opengl32
)

if(MSVC)
    target_link_options(gclient PRIVATE /SUBSYSTEM:WINDOWS)
    gclient_apply_exe_link_options(gclient)
endif()

# Stage rebuilt LuaJIT 2.0.1 & Cocos2d-x engine DLLs/PDBs beside GCLIENT.exe after build
if(WIN32)
    add_custom_command(TARGET gclient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "[GCLIENT] Staging engine & LuaJIT 2.0.1 DLLs/PDBs into $<TARGET_FILE_DIR:gclient>"
        COMMAND ${CMAKE_COMMAND}
            "-DCOCOS_BIN_DIR=${GCLIENT_COCOS2DX_LIB_DIR}"
            "-DLUAJIT_BIN_DIR=${GCLIENT_LUAJIT_LIB_DIR}"
            "-DDEST_DIR=$<TARGET_FILE_DIR:gclient>"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tools/stage_engine_runtime.cmake"
        VERBATIM
    )
endif()

# ==============================================================================
# 8. Automated Regression & LuaJIT ABI Test Suite (CTest)
# ==============================================================================
if(GCLIENT_BUILD_TESTS)
    enable_testing()
    find_package(Python3 COMPONENTS Interpreter QUIET)

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_win32_regression.cpp")
        add_executable(gclient_win32_regression_tests
            tests/test_win32_regression.cpp
            src/assets/BtDecryptHook.cpp
            src/net/LCPacket.cpp
            src/net/CConnection.cpp
            src/net/CNetwork.cpp
            src/update/AtomicHotUpdater.cpp
            src/diagnostics/CrashAndTelemetry.cpp
        )
        target_include_directories(gclient_win32_regression_tests PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
            "${_GCLIENT_ACTIVE_LUA_INCLUDE_DIR}"
        )
        target_link_directories(gclient_win32_regression_tests PRIVATE
            "${GCLIENT_LUAJIT_LIB_DIR}"
        )
        target_compile_definitions(gclient_win32_regression_tests PRIVATE
            GCLIENT_STANDALONE_BUILD=1
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            UNICODE
            _UNICODE
            _CRT_SECURE_NO_WARNINGS
            _WINSOCK_DEPRECATED_NO_WARNINGS
        )
        target_link_libraries(gclient_win32_regression_tests PRIVATE
            lua51
            ZLIB::ZLIB
            SQLite::SQLite3
            $<$<PLATFORM_ID:Windows>:ws2_32>
            $<$<PLATFORM_ID:Windows>:bcrypt>
            $<$<PLATFORM_ID:Windows>:crypt32>
            $<$<PLATFORM_ID:Windows>:dbghelp>
            $<$<PLATFORM_ID:Windows>:psapi>
            $<$<PLATFORM_ID:Windows>:user32>
            $<$<PLATFORM_ID:Windows>:advapi32>
            $<$<PLATFORM_ID:Windows>:shell32>
        )
        if(MSVC)
            target_compile_options(gclient_win32_regression_tests PRIVATE /W4 /utf-8 /EHsc /permissive- /FS /Zi)
            gclient_apply_exe_link_options(gclient_win32_regression_tests)
        endif()
        if(WIN32)
            add_custom_command(TARGET gclient_win32_regression_tests POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${GCLIENT_LUAJIT_LIB_DIR}/lua51.dll"
                    "$<TARGET_FILE_DIR:gclient_win32_regression_tests>/lua51.dll"
                VERBATIM
            )
        endif()
        add_test(NAME gclient_win32_regression_tests COMMAND gclient_win32_regression_tests)
    endif()

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_luajit_abi.cpp")
        add_executable(gclient_luajit_abi_tests
            tests/test_luajit_abi.cpp
            src/net/Amf3Module.cpp
        )
        target_include_directories(gclient_luajit_abi_tests PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
            "${_GCLIENT_ACTIVE_LUA_INCLUDE_DIR}"
        )
        target_link_directories(gclient_luajit_abi_tests PRIVATE
            "${GCLIENT_LUAJIT_LIB_DIR}"
        )
        target_compile_definitions(gclient_luajit_abi_tests PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            UNICODE
            _UNICODE
            _CRT_SECURE_NO_WARNINGS
        )
        target_link_libraries(gclient_luajit_abi_tests PRIVATE
            lua51
            $<$<PLATFORM_ID:Windows>:psapi>
            $<$<PLATFORM_ID:Windows>:kernel32>
        )
        if(MSVC)
            target_compile_options(gclient_luajit_abi_tests PRIVATE /W4 /utf-8 /EHsc /permissive- /FS /Zi)
            gclient_apply_exe_link_options(gclient_luajit_abi_tests)
        endif()
        if(WIN32)
            add_custom_command(TARGET gclient_luajit_abi_tests POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${GCLIENT_LUAJIT_LIB_DIR}/lua51.dll"
                    "$<TARGET_FILE_DIR:gclient_luajit_abi_tests>/lua51.dll"
                VERBATIM
            )
        endif()
        add_test(NAME gclient_luajit_abi_tests COMMAND gclient_luajit_abi_tests)
    endif()

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cobalt_relay_e2e.cpp")
        add_executable(gclient_cobalt_relay_e2e_tests
            tests/test_cobalt_relay_e2e.cpp
            src/assets/BtDecryptHook.cpp
            src/net/Amf3Module.cpp
            src/net/LCPacket.cpp
            src/net/CConnection.cpp
            src/net/CNetwork.cpp
            src/update/AtomicHotUpdater.cpp
        )
        target_include_directories(gclient_cobalt_relay_e2e_tests PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
            "${_GCLIENT_ACTIVE_LUA_INCLUDE_DIR}"
        )
        target_link_directories(gclient_cobalt_relay_e2e_tests PRIVATE
            "${GCLIENT_LUAJIT_LIB_DIR}"
        )
        target_compile_definitions(gclient_cobalt_relay_e2e_tests PRIVATE
            GCLIENT_STANDALONE_BUILD=1
            GCLIENT_WITH_LUAJIT_AMF3=1
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            UNICODE
            _UNICODE
            _CRT_SECURE_NO_WARNINGS
            _WINSOCK_DEPRECATED_NO_WARNINGS
        )
        target_link_libraries(gclient_cobalt_relay_e2e_tests PRIVATE
            lua51
            ZLIB::ZLIB
            OpenSSL::Crypto
            $<$<PLATFORM_ID:Windows>:ws2_32>
            $<$<PLATFORM_ID:Windows>:bcrypt>
            $<$<PLATFORM_ID:Windows>:crypt32>
            $<$<PLATFORM_ID:Windows>:user32>
            $<$<PLATFORM_ID:Windows>:advapi32>
            $<$<PLATFORM_ID:Windows>:shell32>
        )
        if(MSVC)
            target_compile_options(gclient_cobalt_relay_e2e_tests PRIVATE /W4 /utf-8 /EHsc /permissive- /FS /Zi)
            gclient_apply_exe_link_options(gclient_cobalt_relay_e2e_tests)
        endif()
        if(WIN32)
            add_custom_command(TARGET gclient_cobalt_relay_e2e_tests POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${GCLIENT_LUAJIT_LIB_DIR}/lua51.dll"
                    "$<TARGET_FILE_DIR:gclient_cobalt_relay_e2e_tests>/lua51.dll"
                VERBATIM
            )
        endif()
        if(Python3_Interpreter_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/run_cobalt_relay_e2e.py")
            add_test(
                NAME gclient_cobalt_relay_e2e_tests
                COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/run_cobalt_relay_e2e.py"
                    --client-test-bin "$<TARGET_FILE:gclient_cobalt_relay_e2e_tests>"
                    --auto-clone-relay
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            )
        else()
            add_test(NAME gclient_cobalt_relay_e2e_tests COMMAND gclient_cobalt_relay_e2e_tests --self-test)
        endif()
    endif()

    if(WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cocos2d_dll_init.cpp")
        add_executable(gclient_cocos2d_dll_init_tests
            tests/test_cocos2d_dll_init.cpp
        )
        target_include_directories(gclient_cocos2d_dll_init_tests PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
        )
        target_link_libraries(gclient_cocos2d_dll_init_tests PRIVATE
            gclient_build_options
            gclient_cocos2dx_interface
            gclient_diagnostics
            gclient_assets
            ZLIB::ZLIB
            dbghelp
            psapi
            opengl32
            gdi32
            user32
            advapi32
            shell32
        )
        if(MSVC)
            gclient_apply_exe_link_options(gclient_cocos2d_dll_init_tests)
        endif()
        add_custom_command(TARGET gclient_cocos2d_dll_init_tests POST_BUILD
            COMMAND ${CMAKE_COMMAND}
                "-DCOCOS_BIN_DIR=${GCLIENT_COCOS2DX_LIB_DIR}"
                "-DLUAJIT_BIN_DIR=${GCLIENT_LUAJIT_LIB_DIR}"
                "-DDEST_DIR=$<TARGET_FILE_DIR:gclient_cocos2d_dll_init_tests>"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tools/stage_engine_runtime.cmake"
            VERBATIM
        )
        add_test(
            NAME gclient_cocos2d_dll_init_tests
            COMMAND gclient_cocos2d_dll_init_tests --probe-only
        )
    endif()

    if(Python3_Interpreter_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_patch_and_pe_validator.py")
        add_test(
            NAME gclient_python_patch_and_pe_tests
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_patch_and_pe_validator.py"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        )
    endif()
endif()
