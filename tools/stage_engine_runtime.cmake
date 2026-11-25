# tools/stage_engine_runtime.cmake
# Deterministically copies ONLY freshly built Cocos2d-x engine DLLs/PDBs and rebuilt LuaJIT 2.0.1
# v143 lua51.dll/lua51.pdb into DEST_DIR without ever overwriting vcpkg v143 DLLs with legacy binaries.

if(NOT DEFINED DEST_DIR OR DEST_DIR STREQUAL "")
    message(FATAL_ERROR "DEST_DIR is required")
endif()

file(MAKE_DIRECTORY "${DEST_DIR}")

set(_ENGINE_FILES
    "libcocos2d.dll"
    "libcocos2d.pdb"
    "libCocosDenshion.dll"
    "libCocosDenshion.pdb"
    "libExtensions.dll"
    "libExtensions.pdb"
)

foreach(_fname IN LISTS _ENGINE_FILES)
    if(DEFINED COCOS_BIN_DIR AND EXISTS "${COCOS_BIN_DIR}/${_fname}")
        file(COPY_FILE "${COCOS_BIN_DIR}/${_fname}" "${DEST_DIR}/${_fname}" ONLY_IF_DIFFERENT)
    endif()
endforeach()

set(_LUAJIT_FILES
    "lua51.dll"
    "lua51.pdb"
)

foreach(_fname IN LISTS _LUAJIT_FILES)
    if(DEFINED LUAJIT_BIN_DIR AND EXISTS "${LUAJIT_BIN_DIR}/${_fname}")
        file(COPY_FILE "${LUAJIT_BIN_DIR}/${_fname}" "${DEST_DIR}/${_fname}" ONLY_IF_DIFFERENT)
    endif()
endforeach()
