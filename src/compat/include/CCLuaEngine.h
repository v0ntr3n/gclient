#pragma once
#include "lua-bindings/manual/LuaEngine.h"
#include "compat/Axmol226Compat.h"

namespace ax {
using CCLuaEngine = ax::LuaEngine;
using CCLuaStack  = ax::LuaStack;
using CCLuaValue  = ax::LuaValue;
using CCLuaValueDict = ax::LuaValueDict;
using CCLuaValueArray = ax::LuaValueArray;
using CCScriptEngineManager = ax::ScriptEngineManager;
using CCScriptEngineProtocol = ax::ScriptEngineProtocol;
} // namespace ax
