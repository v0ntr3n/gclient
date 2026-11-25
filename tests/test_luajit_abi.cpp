// ============================================================================
// tests/test_luajit_abi.cpp
// LuaJIT 2.0.1 C API / ABI Compatibility, JIT Engine Mode, Error Unwinding,
// Bytecode Round-Trip, CRT Hygiene, and Native AMF3 Stress Suite.
// ============================================================================

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

    // Verify jit global table exists and reports LuaJIT
    lua_getglobal(L, "jit");
    CHECK_ABI(lua_istable(L, -1));
    lua_getfield(L, -1, "version");
    CHECK_ABI(lua_isstring(L, -1));
    const std::string jitVer = lua_tostring(L, -1);
    std::printf("       Active VM: %s\n", jitVer.c_str());
    CHECK_ABI(jitVer.find("LuaJIT") != std::string::npos);
#ifdef _WIN32
    // On Win32 x86 shipping builds, strictly enforce LuaJIT 2.0.1 (20001) contract!
    lua_getfield(L, -2, "version_num");
    CHECK_ABI(lua_tointeger(L, -1) == 20001);
    lua_pop(L, 1);
#endif
    lua_pop(L, 2);

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
    // sum_{i=1..10000} (2.5 * i) = 2.5 * (10000 * 10001 / 2) = 125012500
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
    // LuaJIT 2.x bytecode starts with "\x1bLJ"
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

    // 1. Round-trip dense arrays, strings, negative/float/huge numeric keys (AUD-28 UB fix!), and nested objects
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

        -- 2. Malformed / truncated / OOM-bomb AMF3 inputs must raise clean Lua errors via pcall without OOM or C++ UB
        -- Array marker (0x09) + huge U29 denseCount ((0x0FFFFFFF << 1) | 1) with only 6 bytes in buffer!
        local forgedBomb = string.char(0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0x01)
        local okBomb, bombErr = pcall(amf3.decode, forgedBomb)
        assert(not okBomb and type(bombErr) == "string" and string.find(bombErr, "truncated", 1, true), tostring(bombErr))

        -- Truncated double (0x05 + 3 bytes instead of 8)
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

bool testWin32InProcessCrtHygiene() {
#ifdef _WIN32
    // Verify lua51.dll is loaded in-process and ZERO legacy VS2010/VS2012/VS2013 or Debug CRTs exist!
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
    std::printf("Kestrel Canvas LuaJIT 2.0.1 ABI, Bytecode & Native AMF3 Test Suite\n");
    std::printf("======================================================================\n");

    runAbiTest("01_LuaJIT_VmBoot_JitModeOn_And_HotLoopStackDiscipline",
               testLuaJitVmBootJitModeAndStackAbi);
    runAbiTest("02_LuaJIT_ErrorUnwindAcrossCBoundary_And_BytecodeRoundTrip",
               testLuaJitErrorUnwindAndBytecodeRoundTrip);
    runAbiTest("03_Amf3NativeModule_SparseFloatKeys_And_MalformedOomGuard",
               testAmf3NativeModuleRoundTripAndFuzzGuards);
    runAbiTest("04_Win32InProcess_Lua51Exports_And_ZeroLegacyCrtHygiene",
               testWin32InProcessCrtHygiene);

    std::printf("======================================================================\n");
    std::printf("Summary: %d passed, %d failed\n", g_passed, g_failed);
    std::printf("======================================================================\n");
    return (g_failed == 0) ? 0 : 1;
}
