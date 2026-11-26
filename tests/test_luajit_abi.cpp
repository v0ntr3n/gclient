// ============================================================================
// tests/test_luajit_abi.cpp
// LuaJIT 2.1 x64 C API / ABI Compatibility, JIT Engine Mode, Error Unwinding,
// Bytecode Round-Trip, Lua 2.2.6 Compat Shim, CRT Hygiene, and AMF3 Suite.
// ============================================================================

#include "compat/Lua226CompatShim.h"
#include "net/Amf3Module.h"

extern "C" {
#include "lauxlib.h"
#include "lua.h"
#include "luajit.h"
#include "lualib.h"
}

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace {

int g_passed = 0;
int g_failed = 0;

#define CHECK_ABI(cond)                                                                    \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            std::fprintf(stderr, "[ABI-FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
            std::fflush(stderr);                                                           \
            return false;                                                                  \
        }                                                                                  \
    } while (0)

void runAbiTest(const char* name, const std::function<bool()>& fn) {
    std::printf("[RUN ] %s\n", name);
    std::fflush(stdout);
    const bool ok = fn();
    if (ok) {
        ++g_passed;
        std::printf("[ OK ] %s\n", name);
    } else {
        ++g_failed;
        std::printf("[FAIL] %s\n", name);
    }
    std::fflush(stdout);
}

extern "C" int nativeCallbackRaiseError(lua_State* L) {
    const char* msg = luaL_optstring(L, 1, "default_native_error");
    return luaL_error(L, "native_c_boundary_error:%s", msg);
}

extern "C" int nativeCallbackMultiplyAdd(lua_State* L) {
    const lua_Number a = luaL_checknumber(L, 1);
    const lua_Number b = luaL_checknumber(L, 2);
    const lua_Number c = luaL_checknumber(L, 3);
    lua_pushnumber(L, a * b + c);
    return 1;
}

int dumpWriterToVector(lua_State* /*L*/, const void* p, size_t sz, void* ud) {
    auto* buf = static_cast<std::vector<char>*>(ud);
    const char* bytes = static_cast<const char*>(p);
    buf->insert(buf->end(), bytes, bytes + sz);
    return 0;
}

bool testLuaJitVmBootJitModeAndStackAbi() {
    lua_State* L = luaL_newstate();
    CHECK_ABI(L != nullptr);
    luaL_openlibs(L);

    CHECK_ABI(LUA_VERSION_NUM == 501);

    // Enable JIT engine explicitly via LuaJIT C API extension (luaJIT_setmode)
    const int modeOk = luaJIT_setmode(L, 0, LUAJIT_MODE_ENGINE | LUAJIT_MODE_ON);
    CHECK_ABI(modeOk == 1);

    // Verify jit global table exists and reports LuaJIT 2.1 on 64-bit targets
    lua_getglobal(L, "jit");
    CHECK_ABI(lua_istable(L, -1));
    lua_getfield(L, -1, "version");
    CHECK_ABI(lua_isstring(L, -1));
    const std::string jitVer = lua_tostring(L, -1);
    std::printf("       Active VM: %s (sizeof(void*)=%zu)\n", jitVer.c_str(), sizeof(void*));
    CHECK_ABI(jitVer.find("LuaJIT") != std::string::npos);

    lua_getfield(L, -2, "version_num");
    const lua_Integer jitVerNum = lua_tointeger(L, -1);
    if constexpr (sizeof(void*) == 8) {
        CHECK_ABI(jitVerNum >= 20100);
    } else {
        CHECK_ABI(jitVerNum >= 20001);
    }
    lua_pop(L, 3);

    // Register C++ callback and execute hot JIT loop (10,000 iterations)
    lua_register(L, "c_mul_add", &nativeCallbackMultiplyAdd);
    const char* jitScript =
        "local acc = 0\n"
        "for i = 1, 10000 do\n"
        "    acc = c_mul_add(i, 2.5, acc)\n"
        "end\n"
        "return acc\n";
    CHECK_ABI(luaL_loadstring(L, jitScript) == 0);
    CHECK_ABI(lua_pcall(L, 0, 1, 0) == 0);
    const double result = lua_tonumber(L, -1);
    CHECK_ABI(std::fabs(result - 125012500.0) < 0.5);
    lua_pop(L, 1);
    CHECK_ABI(lua_gettop(L) == 0);

    lua_close(L);
    return true;
}

bool testLuaJitErrorUnwindAndBytecodeRoundTrip() {
    lua_State* L = luaL_newstate();
    CHECK_ABI(L != nullptr);
    luaL_openlibs(L);

    lua_register(L, "c_raise", &nativeCallbackRaiseError);

    const char* protectedScript =
        "local ok, err = xpcall(function() return c_raise('boom_42') end, debug.traceback)\n"
        "assert(not ok)\n"
        "assert(type(err) == 'string' and string.find(err, 'native_c_boundary_error:boom_42', 1, true))\n"
        "return 'unwound_cleanly'\n";
    CHECK_ABI(luaL_loadstring(L, protectedScript) == 0);
    CHECK_ABI(lua_pcall(L, 0, 1, 0) == 0);
    CHECK_ABI(std::string(lua_tostring(L, -1)) == "unwound_cleanly");
    lua_pop(L, 1);

    // Bytecode dump & reload round-trip (verifying bytecode loader compatibility)
    const char* chunkSrc =
        "local t = {10, 20, 30, label = 'kestrel'}\n"
        "return t[1] + t[2] + t[3] .. ':' .. t.label\n";
    CHECK_ABI(luaL_loadstring(L, chunkSrc) == 0);
    std::vector<char> bytecode;
    CHECK_ABI(lua_dump(L, &dumpWriterToVector, &bytecode) == 0);
    lua_pop(L, 1);
    CHECK_ABI(bytecode.size() > 5);
    CHECK_ABI(static_cast<unsigned char>(bytecode[0]) == 0x1Bu);
    CHECK_ABI(bytecode[1] == 'L' && bytecode[2] == 'J');

    CHECK_ABI(luaL_loadbuffer(L, bytecode.data(), bytecode.size(), "=dumped_chunk") == 0);
    CHECK_ABI(lua_pcall(L, 0, 1, 0) == 0);
    CHECK_ABI(std::string(lua_tostring(L, -1)) == "60:kestrel");
    lua_pop(L, 1);

    CHECK_ABI(lua_gettop(L) == 0);
    lua_close(L);
    return true;
}

bool testAmf3NativeModuleRoundTripAndFuzzGuards() {
    lua_State* L = luaL_newstate();
    CHECK_ABI(L != nullptr);
    luaL_openlibs(L);
    luaopen_amf3_extensions(L);
    lua_settop(L, 0);

    const char* amfScript = R"LUA(
        local amf3 = require("amf3")
        local payload = {
            cmd = "battle.enter",
            seq = 123456,
            big_int = 268435455,
            neg_int = -268435456,
            ratio = 3.141592653589793,
            flags = { true, false, "repeat_str", "repeat_str" },
            sparse = {
                [1] = "first",
                [-5] = "negative_key",
                [1.5] = "fractional_key",
                [1e20] = "astronomic_key",
            }
        }
        local blob, encErr = amf3.encode(payload)
        assert(type(blob) == "string" and #blob > 16, tostring(encErr))
        local decoded, nextPos = amf3.decode(blob)
        assert(type(decoded) == "table", tostring(nextPos))
        assert(decoded.cmd == "battle.enter")
        assert(decoded.seq == 123456)
        assert(decoded.big_int == 268435455)
        assert(decoded.neg_int == -268435456)
        assert(math.abs(decoded.ratio - 3.141592653589793) < 1e-12)
        assert(decoded.flags[1] == true and decoded.flags[2] == false)
        assert(decoded.flags[3] == "repeat_str" and decoded.flags[4] == "repeat_str")
        assert(decoded.sparse["-5"] == "negative_key")

        local forgedBomb = string.char(0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0x01)
        local okBomb, bombErr = pcall(amf3.decode, forgedBomb)
        assert(not okBomb and type(bombErr) == "string" and string.find(bombErr, "truncated", 1, true), tostring(bombErr))

        local okTrunc, truncErr = pcall(amf3.decode, string.char(0x05, 0x40, 0x09, 0x21))
        assert(not okTrunc and type(truncErr) == "string", tostring(truncErr))

        return "amf3_verified"
    )LUA";

    CHECK_ABI(luaL_loadstring(L, amfScript) == 0);
    if (lua_pcall(L, 0, 1, 0) != 0) {
        std::fprintf(stderr, "[AMF3 Lua Error] %s\n", lua_tostring(L, -1));
        lua_close(L);
        return false;
    }
    CHECK_ABI(std::string(lua_tostring(L, -1)) == "amf3_verified");
    lua_pop(L, 1);
    CHECK_ABI(lua_gettop(L) == 0);

    lua_close(L);
    return true;
}

bool testLua226CompatShimRuntimeBridges() {
    lua_State* L = luaL_newstate();
    CHECK_ABI(L != nullptr);
    luaL_openlibs(L);

    // Seed mock ax / axui / tolua tables to exercise the 2.2.6 compatibility bridge
    const char* mockAxScript = R"LUA(
        ax = {
            Node = { setLocalZOrder = function(s, z) s._z = z end, getLocalZOrder = function(s) return s._z end },
            Layer = {},
            Sequence = { create = function(cls, ...) return { actions = {...} } end },
            Spawn    = { create = function(cls, ...) return { actions = {...} } end },
            Label    = {
                create = function() return { kind = "empty" } end,
                createWithBMFont = function(cls, fnt, str) return { kind = "bmf", fnt = fnt, str = str } end,
                createWithSystemFont = function(cls, str, fnt, sz) return { kind = "sys", str = str, fnt = fnt, sz = sz } end,
            },
        }
        axui = {
            Widget = {
                addTouchEventListener = function(self, cb) self._cb = cb end,
            },
            Text = {
                setString = function(self, s) self._s = s end,
                getString = function(self) return self._s end,
            },
        }
        tolua = {
            cast = function(obj, typeName)
                return { casted = obj, targetType = typeName }
            end
        }
    )LUA";
    CHECK_ABI(luaL_dostring(L, mockAxScript) == 0);
    CHECK_ABI(gclient::compat::InstallLua226CompatShim(L));

    const char* verifyShimScript = R"LUA(
        -- 1. Lua 5.1 module(..., package.seeall) & string.gfind
        assert(type(module) == "function" and type(package.seeall) == "function")
        assert(type(string.gfind) == "function")

        -- 2. Geometry & color value tables
        local p = ccp(12, 34)
        local q = ccpAdd(p, CCPoint(8, 6))
        assert(q.x == 20 and q.y == 40)
        local sz = CCSizeMake(1136, 640)
        assert(sz.width == 1136 and sz.height == 640)
        local rc = CCRectMake(10, 10, 100, 50)
        assert(CCRectContainsPoint(rc, ccp(50, 30)) == true)
        assert(CCRectContainsPoint(rc, ccp(5, 30)) == false)
        local col = ccc4(255, 128, 64, 200)
        assert(col.r == 255 and col.g == 128 and col.b == 64 and col.a == 200)

        -- 3. Self-contained ax.Handler constants
        assert(ax.Handler.EVENT_TOUCH_BEGAN == 40)
        assert(ax.Handler.EVENT_SPINE_ANIMATION_COMPLETE == 66)

        -- 4. CCLabelBMFont -> ax.Label:createWithBMFont
        local bmf = CCLabelBMFont:create("999", "res/fonts/dmg.fnt")
        assert(bmf.kind == "bmf" and bmf.fnt == "res/fonts/dmg.fnt" and bmf.str == "999")

        -- 5. CCSequence unpacking table / multi-arg actions
        local seq = CCSequence:create({ "act1", "act2", "act3" })
        assert(#seq.actions == 3 and seq.actions[2] == "act2")

        -- 6. CCNotificationCenter post / unregister
        local hit = 0
        local target = {}
        CCNotificationCenter:sharedNotificationCenter():registerScriptObserver(
            target, function(name) if name == "EVT_WIN" then hit = hit + 1 end end, "EVT_WIN")
        CCNotificationCenter:sharedNotificationCenter():postNotification("EVT_WIN")
        CCNotificationCenter:sharedNotificationCenter():unregisterScriptObserver(target, "EVT_WIN")
        CCNotificationCenter:sharedNotificationCenter():postNotification("EVT_WIN")
        assert(hit == 1)

        -- 7. 2-arg legacy Widget:addTouchEventListener(target, selector)
        local w = setmetatable({}, { __index = axui.Widget })
        local gotTarget, gotEvent = nil, nil
        local uiOwner = { id = 77 }
        w:addTouchEventListener(uiOwner, function(self, sender, ev)
            gotTarget = self.id
            gotEvent  = ev
        end)
        w._cb(w, TOUCH_EVENT_ENDED)
        assert(gotTarget == 77 and gotEvent == 2)

        return "shim_verified"
    )LUA";

    CHECK_ABI(luaL_loadstring(L, verifyShimScript) == 0);
    if (lua_pcall(L, 0, 1, 0) != 0) {
        std::fprintf(stderr, "[Shim Lua Error] %s\n", lua_tostring(L, -1));
        lua_close(L);
        return false;
    }
    CHECK_ABI(std::string(lua_tostring(L, -1)) == "shim_verified");
    lua_pop(L, 1);
    CHECK_ABI(lua_gettop(L) == 0);

    lua_close(L);
    return true;
}

bool testWin32InProcessCrtHygiene() {
#ifdef _WIN32
    HMODULE hLua = ::GetModuleHandleW(L"lua51.dll");
    CHECK_ABI(hLua != nullptr);
    CHECK_ABI(::GetProcAddress(hLua, "luaL_newstate") != nullptr);
    CHECK_ABI(::GetProcAddress(hLua, "luaJIT_setmode") != nullptr);

    const wchar_t* forbiddenModules[] = {
        L"MSVCR100.dll",
        L"MSVCP100.dll",
        L"MSVCR110.dll",
        L"MSVCP110.dll",
        L"MSVCR120.dll",
        L"MSVCP120.dll",
        L"pthreadVCE2.dll",
#ifdef NDEBUG
        L"vcruntime140d.dll",
        L"msvcp140d.dll",
        L"ucrtbased.dll",
#endif
    };
    for (const wchar_t* modName : forbiddenModules) {
        if (::GetModuleHandleW(modName) != nullptr) {
            std::fwprintf(stderr, L"[CRT-VIOLATION] Forbidden DLL loaded in process: %ls\n", modName);
            return false;
        }
    }
#endif
    return true;
}

} // namespace

int main() {
    std::printf("======================================================================\n");
    std::printf("Kestrel Canvas LuaJIT 2.1 x64 ABI, Shim & Native AMF3 Test Suite\n");
    std::printf("======================================================================\n");

    runAbiTest("01_LuaJIT_VmBoot_JitModeOn_And_HotLoopStackDiscipline",
               testLuaJitVmBootJitModeAndStackAbi);
    runAbiTest("02_LuaJIT_ErrorUnwindAcrossCBoundary_And_BytecodeRoundTrip",
               testLuaJitErrorUnwindAndBytecodeRoundTrip);
    runAbiTest("03_Amf3NativeModule_SparseFloatKeys_And_MalformedOomGuard",
               testAmf3NativeModuleRoundTripAndFuzzGuards);
    runAbiTest("04_Lua226CompatShim_Geometry_Handler_BMFont_And_WidgetCallbacks",
               testLua226CompatShimRuntimeBridges);
    runAbiTest("05_Win32InProcess_Lua51Exports_And_ZeroLegacyCrtHygiene",
               testWin32InProcessCrtHygiene);

    std::printf("======================================================================\n");
    std::printf("Summary: %d passed, %d failed\n", g_passed, g_failed);
    std::printf("======================================================================\n");
    return (g_failed == 0) ? 0 : 1;
}
