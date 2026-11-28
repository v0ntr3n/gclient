// ============================================================================
// tests/test_luajit_abi.cpp
// LuaJIT 2.1 x64 C API / ABI Compatibility, JIT Engine Mode, Error Unwinding,
// Bytecode Round-Trip, Lua 2.2.6 Compat Shim, CRT Hygiene, and AMF3 Suite.
// ============================================================================

#include "TestHarness.h"
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
#include <string>
#include <vector>

namespace {

struct ScopedLuaVm {
    lua_State* L = nullptr;

    ScopedLuaVm() : L(luaL_newstate()) {
        if (L != nullptr) {
            luaL_openlibs(L);
        }
    }
    ScopedLuaVm(const ScopedLuaVm&) = delete;
    ScopedLuaVm& operator=(const ScopedLuaVm&) = delete;
    ~ScopedLuaVm() {
        if (L != nullptr) {
            lua_close(L);
        }
    }

    bool evalExpectString(const char* script, const char* expected, const char* tag) const {
        if (luaL_loadstring(L, script) != 0 || lua_pcall(L, 0, 1, 0) != 0) {
            std::fprintf(stderr, "[%s] %s\n", tag, lua_tostring(L, -1));
            return false;
        }
        const char* actual = lua_tostring(L, -1);
        const bool match = (actual != nullptr && std::strcmp(actual, expected) == 0);
        lua_pop(L, 1);
        return match && (lua_gettop(L) == 0);
    }
};

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
    const auto* bytes = static_cast<const char*>(p);
    buf->insert(buf->end(), bytes, bytes + sz);
    return 0;
}

bool testLuaJitVmBootJitModeAndStackAbi() {
    ScopedLuaVm vm;
    CHECK_ABI(vm.L != nullptr);
    CHECK_ABI(LUA_VERSION_NUM == 501);
    CHECK_ABI(luaJIT_setmode(vm.L, 0, LUAJIT_MODE_ENGINE | LUAJIT_MODE_ON) == 1);

    lua_getglobal(vm.L, "jit");
    CHECK_ABI(lua_istable(vm.L, -1));
    lua_getfield(vm.L, -1, "version");
    CHECK_ABI(lua_isstring(vm.L, -1));
    const std::string jitVer = lua_tostring(vm.L, -1);
    std::printf("       Active VM: %s (sizeof(void*)=%zu)\n", jitVer.c_str(), sizeof(void*));
    CHECK_ABI(jitVer.find("LuaJIT") != std::string::npos);

    lua_getfield(vm.L, -2, "version_num");
    const lua_Integer jitVerNum = lua_tointeger(vm.L, -1);
    if constexpr (sizeof(void*) == 8) {
        CHECK_ABI(jitVerNum >= 20100);
    } else {
        CHECK_ABI(jitVerNum >= 20001);
    }
    lua_pop(vm.L, 3);

    lua_register(vm.L, "c_mul_add", &nativeCallbackMultiplyAdd);
    const char* jitScript =
        "local acc = 0\n"
        "for i = 1, 10000 do\n"
        "    acc = c_mul_add(i, 2.5, acc)\n"
        "end\n"
        "return acc\n";
    CHECK_ABI(luaL_loadstring(vm.L, jitScript) == 0);
    CHECK_ABI(lua_pcall(vm.L, 0, 1, 0) == 0);
    REQUIRE_NEAR(lua_tonumber(vm.L, -1), 125012500.0, 0.5);
    lua_pop(vm.L, 1);
    CHECK_ABI(lua_gettop(vm.L) == 0);
    return true;
}

bool testLuaJitErrorUnwindAndBytecodeRoundTrip() {
    ScopedLuaVm vm;
    CHECK_ABI(vm.L != nullptr);
    lua_register(vm.L, "c_raise", &nativeCallbackRaiseError);

    const char* protectedScript =
        "local ok, err = xpcall(function() return c_raise('boom_42') end, debug.traceback)\n"
        "assert(not ok)\n"
        "assert(type(err) == 'string' and string.find(err, 'native_c_boundary_error:boom_42', 1, true))\n"
        "return 'unwound_cleanly'\n";
    CHECK_ABI(vm.evalExpectString(protectedScript, "unwound_cleanly", "Unwind"));

    const char* chunkSrc =
        "local t = {10, 20, 30, label = 'kestrel'}\n"
        "return t[1] + t[2] + t[3] .. ':' .. t.label\n";
    CHECK_ABI(luaL_loadstring(vm.L, chunkSrc) == 0);
    std::vector<char> bytecode;
    CHECK_ABI(lua_dump(vm.L, &dumpWriterToVector, &bytecode) == 0);
    lua_pop(vm.L, 1);
    CHECK_ABI(bytecode.size() > 5);
    CHECK_ABI(static_cast<unsigned char>(bytecode[0]) == 0x1Bu);
    CHECK_ABI(bytecode[1] == 'L' && bytecode[2] == 'J');

    CHECK_ABI(luaL_loadbuffer(vm.L, bytecode.data(), bytecode.size(), "=dumped_chunk") == 0);
    CHECK_ABI(lua_pcall(vm.L, 0, 1, 0) == 0);
    REQUIRE_EQ(std::string(lua_tostring(vm.L, -1)), std::string("60:kestrel"));
    lua_pop(vm.L, 1);
    CHECK_ABI(lua_gettop(vm.L) == 0);
    return true;
}

bool testAmf3NativeModuleRoundTripAndFuzzGuards() {
    ScopedLuaVm vm;
    CHECK_ABI(vm.L != nullptr);
    luaopen_amf3_extensions(vm.L);
    lua_settop(vm.L, 0);

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
    return vm.evalExpectString(amfScript, "amf3_verified", "AMF3 Lua Error");
}

bool testLua226CompatShimRuntimeBridges() {
    ScopedLuaVm vm;
    CHECK_ABI(vm.L != nullptr);

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
            Widget = { addTouchEventListener = function(self, cb) self._cb = cb end },
            Text   = { setString = function(self, s) self._s = s end, getString = function(self) return self._s end },
        }
        tolua = {
            cast = function(obj, typeName) return { casted = obj, targetType = typeName } end
        }
    )LUA";
    CHECK_ABI(luaL_dostring(vm.L, mockAxScript) == 0);
    CHECK_ABI(gclient::compat::InstallLua226CompatShim(vm.L));

    const char* verifyShimScript = R"LUA(
        assert(type(module) == "function" and type(package.seeall) == "function")
        assert(type(string.gfind) == "function")

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

        assert(ax.Handler.EVENT_TOUCH_BEGAN == 40)
        assert(ax.Handler.EVENT_SPINE_ANIMATION_COMPLETE == 66)

        local bmf = CCLabelBMFont:create("999", "res/fonts/dmg.fnt")
        assert(bmf.kind == "bmf" and bmf.fnt == "res/fonts/dmg.fnt" and bmf.str == "999")

        local seq = CCSequence:create({ "act1", "act2", "act3" })
        assert(#seq.actions == 3 and seq.actions[2] == "act2")

        local hit = 0
        local target = {}
        CCNotificationCenter:sharedNotificationCenter():registerScriptObserver(
            target, function(name) if name == "EVT_WIN" then hit = hit + 1 end end, "EVT_WIN")
        CCNotificationCenter:sharedNotificationCenter():postNotification("EVT_WIN")
        CCNotificationCenter:sharedNotificationCenter():unregisterScriptObserver(target, "EVT_WIN")
        CCNotificationCenter:sharedNotificationCenter():postNotification("EVT_WIN")
        assert(hit == 1)

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
    return vm.evalExpectString(verifyShimScript, "shim_verified", "Shim Lua Error");
}

bool testLua226CompatShimStrokeAndRichText() {
    ScopedLuaVm vm;
    CHECK_ABI(vm.L != nullptr);

    const char* setupMocks = R"LUA(
        local lastOutline, lastShadow = nil, nil
        local titleRenderer = {
            enableOutline = function(_, col, sz) lastOutline = { col = col, sz = sz } end,
            disableEffect = function() lastOutline = "disabled" end,
        }
        ax = {
            Label = {
                create = function() return {} end,
                enableOutline = function(_, col, sz) lastOutline = { col = col, sz = sz } end,
                disableEffect = function() lastOutline = "disabled" end,
                enableShadow = function(_, col, off, blur) lastShadow = { col = col, off = off, blur = blur } end,
            },
        }
        axui = {
            Text = { enableOutline = ax.Label.enableOutline, disableEffect = ax.Label.disableEffect, enableShadow = ax.Label.enableShadow },
            Button = { getTitleRenderer = function() return titleRenderer end },
            RichText = { create = function() return { kind = "RichText" } end },
            RichElementText = { create = function() return { kind = "RichElementText" } end },
            RichElementCustomNode = { create = function() return { kind = "RichElementCustomNode" } end },
        }
        _G.__getLastOutline = function() return lastOutline end
        _G.__getLastShadow  = function() return lastShadow end
    )LUA";
    CHECK_ABI(luaL_dostring(vm.L, setupMocks) == 0);
    CHECK_ABI(gclient::compat::InstallLua226CompatShim(vm.L));

    const char* verifyScript = R"LUA(
        assert(RichText == axui.RichText, "RichText global alias missing")
        assert(RichElementText == axui.RichElementText, "RichElementText global alias missing")
        assert(RichElementCustomNode == axui.RichElementCustomNode, "RichElementCustomNode global alias missing")

        ax.Label:enableStroke(ccc3(0x82, 0x24, 0x0f), 2, true)
        local o1 = __getLastOutline()
        assert(o1 and o1.col.r == 0x82 and o1.col.g == 0x24 and o1.col.b == 0x0f and o1.col.a == 255 and o1.sz == 2)

        axui.Button:enableTitleStroke(ccc3(0x5c, 0x33, 0x20), 1, true)
        local o2 = __getLastOutline()
        assert(o2 and o2.col.r == 0x5c and o2.col.g == 0x33 and o2.col.b == 0x20 and o2.sz == 1)

        ax.Label:enableShadow(CCSize(2, -2), 0.5, 3, true)
        local sh = __getLastShadow()
        assert(sh and sh.col.a == 128 and sh.off.x == 2 and sh.off.y == -2 and sh.blur == 3)
        return "stroke_and_richtext_verified"
    )LUA";
    return vm.evalExpectString(verifyScript, "stroke_and_richtext_verified", "Stroke/RichText Shim Lua Error");
}

bool testWin32InProcessCrtHygiene() {
#ifdef _WIN32
    HMODULE hLua = ::GetModuleHandleW(L"lua51.dll");
    CHECK_ABI(hLua != nullptr);
    CHECK_ABI(::GetProcAddress(hLua, "luaL_newstate") != nullptr);
    CHECK_ABI(::GetProcAddress(hLua, "luaJIT_setmode") != nullptr);

    const wchar_t* forbiddenModules[] = {
        L"MSVCR100.dll", L"MSVCP100.dll",
        L"MSVCR110.dll", L"MSVCP110.dll",
        L"MSVCR120.dll", L"MSVCP120.dll",
        L"pthreadVCE2.dll",
#ifdef NDEBUG
        L"vcruntime140d.dll", L"msvcp140d.dll", L"ucrtbased.dll",
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
    gclient::test::TestSuite suite("Kestrel Canvas LuaJIT 2.1 x64 ABI, Shim & Native AMF3 Test Suite");
    suite.run("01_LuaJIT_VmBoot_JitModeOn_And_HotLoopStackDiscipline", testLuaJitVmBootJitModeAndStackAbi);
    suite.run("02_LuaJIT_ErrorUnwindAcrossCBoundary_And_BytecodeRoundTrip", testLuaJitErrorUnwindAndBytecodeRoundTrip);
    suite.run("03_Amf3NativeModule_SparseFloatKeys_And_MalformedOomGuard", testAmf3NativeModuleRoundTripAndFuzzGuards);
    suite.run("04_Lua226CompatShim_Geometry_Handler_BMFont_And_WidgetCallbacks", testLua226CompatShimRuntimeBridges);
    suite.run("04b_Lua226CompatShim_Stroke_TitleStroke_Shadow_And_RichTextAliases", testLua226CompatShimStrokeAndRichText);
    suite.run("05_Win32InProcess_Lua51Exports_And_ZeroLegacyCrtHygiene", testWin32InProcessCrtHygiene);
    return suite.finishWithBanner();
}
