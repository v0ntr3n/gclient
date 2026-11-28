#include "tolua_Platform.h"
#include "BtPlatformWin32.h"

#if defined(GCLIENT_USE_COCOS2DX) && !defined(GCLIENT_STANDALONE_BUILD)
#include "CCLuaEngine.h"
#endif

#include "bindings/LuaBindTemplates.h"
#include "diagnostics/CrashAndTelemetry.h"

#include <array>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>

namespace {

using gclient::lua_bind::bindFlexSingleton;
using gclient::lua_bind::firstArgIndex;
using gclient::lua_bind::optBool;
using gclient::lua_bind::optFloat;
using gclient::lua_bind::optInt;
using gclient::lua_bind::optString;
using gclient::lua_bind::registerMethodTable;

struct LuaCallbackRegistry {
    lua_State* fallbackState = nullptr;
    int primaryHandlerRef = LUA_NOREF;
    int syncHandlerRef = LUA_NOREF;
};

LuaCallbackRegistry& getLuaCallbacks() {
    static LuaCallbackRegistry reg;
    return reg;
}

lua_State* resolveLiveMainLuaState(lua_State* fallbackState) {
#if defined(GCLIENT_USE_COCOS2DX) && !defined(GCLIENT_STANDALONE_BUILD)
    if (auto* engine = ax::LuaEngine::getInstance()) {
        if (auto* stack = engine->getLuaStack()) {
            if (lua_State* mainL = stack->getLuaState()) {
                return mainL;
            }
        }
    }
#endif
    return fallbackState;
}

// Unified traceback-protected pcall: expects [fn, arg1..argN] on top of stack and pops them all.
void pcallWithTraceback(lua_State* L, int nargs, const char* contextTag, int eventId = -1) {
    const int fnSlot = lua_gettop(L) - nargs;
    int errfuncIdx = 0;
    lua_getglobal(L, "debug");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "traceback");
        lua_remove(L, -2);
        if (lua_isfunction(L, -1)) {
            lua_insert(L, fnSlot);
            errfuncIdx = fnSlot;
        } else {
            lua_pop(L, 1);
        }
    } else {
        lua_pop(L, 1);
    }

    if (lua_pcall(L, nargs, 0, errfuncIdx) != 0) {
        const char* err = lua_tostring(L, -1);
        if (eventId >= 0) {
            gclient::diagnostics::CrashAndTelemetry::log(
                gclient::diagnostics::LogLevel::Error,
                "tolua_Platform",
                "%s (event=%d): %s",
                contextTag,
                eventId,
                err ? err : "<unknown>");
        } else {
            gclient::diagnostics::CrashAndTelemetry::log(
                gclient::diagnostics::LogLevel::Error,
                "tolua_Platform",
                "%s: %s",
                contextTag,
                err ? err : "<unknown>");
        }
        gclient::diagnostics::CrashAndTelemetry::flushLogs();
        lua_pop(L, 1);
    }
    if (errfuncIdx != 0) {
        lua_remove(L, errfuncIdx);
    }
}

void invokeLuaHandler(lua_State* L, int funcRef, int eventId, int statusCode, const std::string& payload) {
    (void)statusCode;
    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "tolua_Platform",
        "invokeLuaHandler event=%d funcRef=%d payload=%s",
        eventId,
        funcRef,
        payload.c_str());
    if (!L || funcRef == LUA_NOREF || funcRef == LUA_REFNIL) return;
    lua_rawgeti(L, LUA_REGISTRYINDEX, funcRef);
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        return;
    }
    lua_pushinteger(L, eventId);
    lua_pushlstring(L, payload.data(), payload.size());
    pcallWithTraceback(L, 2, "Lua callback error", eventId);
}

void invokeInlineLuaCallbackJson(lua_State* L, int fnIdx, const char* jsonStr) {
    if (!L || !lua_isfunction(L, fnIdx)) return;
    lua_pushvalue(L, fnIdx);
    lua_pushstring(L, jsonStr ? jsonStr : "{}");
    pcallWithTraceback(L, 1, "Inline Lua callback error");
}

int readTableIntAt(lua_State* L, int tblIdx, int arrayIndex, int fallback = 0) {
    if (tblIdx <= 0 || tblIdx > lua_gettop(L) || !lua_istable(L, tblIdx)) return fallback;
    lua_rawgeti(L, tblIdx, arrayIndex);
    const int val = lua_isnumber(L, -1) ? static_cast<int>(lua_tointeger(L, -1)) : fallback;
    lua_pop(L, 1);
    return val;
}

std::string readTableStringAt(lua_State* L, int tblIdx, int arrayIndex, const char* fieldFallback = nullptr) {
    if (tblIdx <= 0 || tblIdx > lua_gettop(L) || !lua_istable(L, tblIdx)) return {};
    lua_rawgeti(L, tblIdx, arrayIndex);
    if (lua_isstring(L, -1)) {
        std::string out = optString(L, lua_gettop(L), "");
        lua_pop(L, 1);
        return out;
    }
    lua_pop(L, 1);
    if (fieldFallback) {
        lua_getfield(L, tblIdx, fieldFallback);
        std::string out = lua_isstring(L, -1) ? optString(L, lua_gettop(L), "") : std::string{};
        lua_pop(L, 1);
        return out;
    }
    return {};
}

bool isNumericBridgeMethod(std::string_view methodName) noexcept {
    static constexpr std::array<std::string_view, 8> kNumericMethods = {
        "getBatteryLevel", "getAvailMemory", "getTotalMemory", "getFreeDiskSpace",
        "getNetworkType", "getNetworkStatus", "getVersionCode", "getSignalStrength"
    };
    for (auto m : kNumericMethods) {
        if (methodName == m) return true;
    }
    return false;
}

int lua_MobileBridge_callStaticMethod(lua_State* L) {
    const int top = lua_gettop(L);
    const int base = firstArgIndex(L);
    const std::string className = optString(L, base, "");
    const std::string methodName = optString(L, base + 1, "");

    int argsIdx = 0;
    std::string sig;
    if (base + 2 <= top) {
        if (lua_istable(L, base + 2)) {
            argsIdx = base + 2;
            sig = optString(L, base + 3, "");
        } else if (lua_isstring(L, base + 2) && base + 3 > top) {
            sig = optString(L, base + 2, "");
        } else {
            sig = optString(L, base + 3, "");
        }
    }

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "LuaBridge",
        "callStaticMethod class='%s' method='%s' sig='%s'",
        className.c_str(),
        methodName.c_str(),
        sig.c_str());

    if (className.find("ZYWebView") != std::string::npos) {
        auto* plat = bt::Platform::getInstance();
        if (methodName == "displayWebView" || methodName == "showWebView") {
            plat->dispatchWebViewBridge(
                "displayWebView",
                readTableIntAt(L, argsIdx, 1), readTableIntAt(L, argsIdx, 2),
                readTableIntAt(L, argsIdx, 3), readTableIntAt(L, argsIdx, 4), "");
        } else if (methodName == "updateURL" || methodName == "openURL" || methodName == "loadUrl") {
            plat->dispatchWebViewBridge("updateURL", 0, 0, 0, 0, readTableStringAt(L, argsIdx, 1, "url"));
        } else if (methodName == "removeWebView" || methodName == "closeWebView" || methodName == "hideWebView") {
            plat->dispatchWebViewBridge("removeWebView", 0, 0, 0, 0, "");
        }
    }

    lua_pushboolean(L, 1);
    if (const size_t closeParen = sig.find(')'); closeParen != std::string::npos && closeParen + 1 < sig.size()) {
        switch (sig[closeParen + 1]) {
            case 'I': case 'J': case 'S': case 'B': lua_pushinteger(L, 0); return 2;
            case 'F': case 'D':                     lua_pushnumber(L, 0.0); return 2;
            case 'Z':                               lua_pushboolean(L, 0); return 2;
            default:                                lua_pushstring(L, ""); return 2;
        }
    }
    if (isNumericBridgeMethod(methodName)) {
        lua_pushinteger(L, 0);
        return 2;
    }
    lua_pushstring(L, "");
    return 2;
}

int lua_MobileBridge_retainLuaFunction(lua_State* L) {
    const int base = firstArgIndex(L);
    if (base <= lua_gettop(L) && lua_isfunction(L, base)) {
        lua_pushvalue(L, base);
        lua_pushinteger(L, luaL_ref(L, LUA_REGISTRYINDEX));
        return 1;
    }
    lua_pushinteger(L, optInt(L, base, 0));
    return 1;
}

int lua_MobileBridge_releaseLuaFunction(lua_State* L) {
    const int ref = optInt(L, firstArgIndex(L), LUA_NOREF);
    if (ref != LUA_NOREF && ref != LUA_REFNIL && ref > 0) {
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
    }
    return 0;
}

void registerMobileLuaBridges(lua_State* L) {
    if (!L) return;

    static constexpr luaL_Reg kJavaBridgeRegs[] = {
        {"callStaticMethod",      lua_MobileBridge_callStaticMethod},
        {"retainLuaFunction",     lua_MobileBridge_retainLuaFunction},
        {"retainLuaFunctionById", lua_MobileBridge_retainLuaFunction},
        {"releaseLuaFunction",    lua_MobileBridge_releaseLuaFunction},
    };
    static constexpr luaL_Reg kObjcBridgeRegs[] = {
        {"callStaticMethod",       lua_MobileBridge_callStaticMethod},
        {"retainLuaFunctionById",  lua_MobileBridge_retainLuaFunction},
        {"releaseLuaFunctionById", lua_MobileBridge_releaseLuaFunction},
    };
    static constexpr luaL_Reg kShortBridgeRegs[] = {
        {"callStaticMethod", lua_MobileBridge_callStaticMethod},
    };

    lua_newtable(L);
    registerMethodTable(L, -1, kJavaBridgeRegs);
    lua_setglobal(L, "CCLuaJavaBridge");

    lua_newtable(L);
    registerMethodTable(L, -1, kObjcBridgeRegs);
    lua_setglobal(L, "CCLuaObjcBridge");

    for (const char* alias : {"luaj", "luaoc"}) {
        lua_getglobal(L, alias);
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            lua_newtable(L);
            registerMethodTable(L, -1, kShortBridgeRegs);
            lua_setglobal(L, alias);
        } else {
            lua_pop(L, 1);
        }
    }
}

template <const char* GlobalName>
int lua_ReturnNamedGlobal(lua_State* L) {
    lua_getglobal(L, GlobalName);
    return 1;
}

constexpr char kGlobalPlatform[] = "Platform";
constexpr char kGlobalPluginManager[] = "PluginManager";
constexpr char kGlobalNotificationManager[] = "NotificationManager";

template <void (bt::Platform::*MemberFn)(const std::string&)>
int bindPlatformJson(lua_State* L) {
    (bt::Platform::getInstance()->*MemberFn)(optString(L, firstArgIndex(L), "{}"));
    return 0;
}

template <void (bt::Platform::*MemberFn)(const std::string&, const std::string&)>
int bindPlatformStrAndJson(lua_State* L) {
    const int base = firstArgIndex(L);
    (bt::Platform::getInstance()->*MemberFn)(optString(L, base, ""), optString(L, base + 1, "{}"));
    return 0;
}

int lua_Platform_initSDK(lua_State* L) {
    const int base = firstArgIndex(L);
    const std::string jsonParam = optString(L, base, "");
    auto& reg = getLuaCallbacks();
    if (!reg.fallbackState) reg.fallbackState = L;

    int fnIdx = -1;
    if (base + 1 <= lua_gettop(L) && lua_isfunction(L, base + 1)) fnIdx = base + 1;
    else if (base <= lua_gettop(L) && lua_isfunction(L, base)) fnIdx = base;

    if (fnIdx > 0) {
        if (reg.primaryHandlerRef != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, reg.primaryHandlerRef);
        }
        lua_pushvalue(L, fnIdx);
        reg.primaryHandlerRef = luaL_ref(L, LUA_REGISTRYINDEX);
    }

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "tolua_Platform",
        "lua_Platform_initSDK called (fnIdx=%d, json=%s)",
        fnIdx,
        jsonParam.c_str());
    bt::Platform::getInstance()->initSDK(
        jsonParam,
        [](int eventId, int statusCode, const std::string& payload) {
            auto& r = getLuaCallbacks();
            invokeLuaHandler(resolveLiveMainLuaState(r.fallbackState), r.primaryHandlerRef, eventId, statusCode, payload);
        });
    return 0;
}

int lua_Platform_sendInformationToPlatform(lua_State* L) {
    const int base = firstArgIndex(L);
    bt::Platform::getInstance()->sendInformationToPlatform(optInt(L, base, 0), optString(L, base + 1, "{}"));
    return 0;
}

int lua_Platform_callUniversalWebFunction(lua_State* L) {
    const int base = firstArgIndex(L);
    bt::Platform::getInstance()->callUniversalWebFunction(
        optInt(L, base, 0), optString(L, base + 1, ""), optString(L, base + 2, "{}"));
    return 0;
}

int lua_Platform_signUrl_dispatch(lua_State* L) {
    const int base = firstArgIndex(L);
    const std::string url = optString(L, base, "");
    const std::string signedUrl = (base + 1 <= lua_gettop(L) && lua_isstring(L, base + 1))
        ? bt::Platform::getInstance()->signUrl(url, optString(L, base + 1, ""))
        : bt::Platform::getInstance()->signUrl(url);
    lua_pushlstring(L, signedUrl.data(), signedUrl.size());
    return 1;
}

int lua_Platform_setMainScreenBrightness(lua_State* L) {
    bt::Platform::getInstance()->setMainScreenBrightness(optFloat<float>(L, firstArgIndex(L), 1.0f));
    return 0;
}

int lua_Platform_callUniversalFunctionWithBack(lua_State* L) {
    const int top = lua_gettop(L);
    const int base = firstArgIndex(L);
    const std::string funcName = optString(L, base, "");
    const std::string jsonParams = optString(L, base + 1, "{}");

    int callbackIdx = -1;
    for (int i = base; i <= top; ++i) {
        if (lua_isfunction(L, i)) {
            callbackIdx = i;
            break;
        }
    }

    bt::Platform::getInstance()->callUniversalFunctionWithBack(funcName, jsonParams);
    if (callbackIdx > 0) invokeInlineLuaCallbackJson(L, callbackIdx, "{}");
    lua_pushstring(L, "{}");
    return 1;
}

int lua_Platform_registeCallBackBySync(lua_State* L) {
    const int base = firstArgIndex(L);
    auto& reg = getLuaCallbacks();
    if (!reg.fallbackState) reg.fallbackState = L;

    if (base <= lua_gettop(L) && lua_isfunction(L, base)) {
        if (reg.syncHandlerRef != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, reg.syncHandlerRef);
        }
        lua_pushvalue(L, base);
        reg.syncHandlerRef = luaL_ref(L, LUA_REGISTRYINDEX);
        bt::Platform::getInstance()->registeCallBackBySync(
            [](int eventId, int statusCode, const std::string& payload) {
                auto& r = getLuaCallbacks();
                invokeLuaHandler(resolveLiveMainLuaState(r.fallbackState), r.syncHandlerRef, eventId, statusCode, payload);
            });
    }
    return 0;
}

struct LuaConstEntry {
    const char* name;
    lua_Number value;
};

constexpr LuaConstEntry kPlatformConstants[] = {
    {"kCreateNewRole",        0.0},  {"kEnterTheGameHall",     1.0},  {"kLevelUp",              2.0},
    {"kInit",                 1.0},  {"kLogin",                2.0},  {"kGetServerlist",        3.0},
    {"kGetHash",              4.0},  {"kGetVersion",           5.0},  {"kPay",                  6.0},
    {"kQuit",                 7.0},  {"kLogout",               8.0},  {"kCrash",                9.0},
    {"kDiffAccount",          10.0}, {"kShareBack",            11.0}, {"kPlayFinish",           12.0},
    {"kLowMemory",            13.0}, {"kHandleOpenURL",        14.0}, {"kShowLogoFinish",       15.0},
    {"kGetLoginedServerInfo", 16.0}, {"kGetNotice",            17.0}, {"kQuestion",             18.0},
    {"kGetAppleReview",       19.0}, {"kGetSuperNotice",       20.0}, {"kGetUserInformation",   21.0},
    {"kGetBrowseActive",      22.0}, {"kIssueDJOrders",        24.0}, {"kGetForceFix",          25.0},
    {"kHandleUrl",            26.0}, {"kNetworkCapture",       31.0}, {"kPermissionResult",     32.0},
    {"kHttpSuccess",          0.0},  {"kHttpFailed",           1.0},  {"kATTAuthorizedResult",  35.0},
};

const luaL_Reg kPlatformMethods[] = {
    {"getInstance",                   lua_ReturnNamedGlobal<kGlobalPlatform>},
    {"tickLoop",                      bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::tickLoop>},
    {"initSDK",                       lua_Platform_initSDK},
    {"login",                         bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::login>},
    {"logout",                        bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::logout>},
    {"pay",                           bindPlatformJson<&bt::Platform::pay>},
    {"showToolBar",                   bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::showToolBar>},
    {"hideToolBar",                   bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::hideToolBar>},
    {"enterUserCenter",               bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::enterUserCenter>},
    {"accountSwitch",                 bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::accountSwitch>},
    {"sendInformationToPlatform",     lua_Platform_sendInformationToPlatform},
    {"getUserCenterName",             bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getUserCenterName>},
    {"pause",                         bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::pause>},
    {"onPressBack",                   bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::onPressBack>},
    {"getServerList",                 bindPlatformJson<&bt::Platform::getServerList>},
    {"getHash",                       bindPlatformJson<&bt::Platform::getHash>},
    {"getHashWithSimulation",         bindPlatformJson<&bt::Platform::getHashWithSimulation>},
    {"getVersionInfo",                bindPlatformJson<&bt::Platform::getVersionInfo>},
    {"getLoginedServerInfo",          bindPlatformJson<&bt::Platform::getLoginedServerInfo>},
    {"getNotice",                     bindPlatformJson<&bt::Platform::getNotice>},
    {"getAppleReview",                bindPlatformJson<&bt::Platform::getAppleReview>},
    {"question",                      bindPlatformJson<&bt::Platform::question>},
    {"shareWeixin",                   bindPlatformJson<&bt::Platform::shareWeixin>},
    {"playVideo",                     bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::playVideo>},
    {"openCustomWebView",             bindPlatformJson<&bt::Platform::openCustomWebView>},
    {"closeCustomWebView",            bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::closeCustomWebView>},
    {"quit",                          bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::quit>},
    {"doCustomWebViewAction",         bindPlatformJson<&bt::Platform::doCustomWebViewAction>},
    {"openUrl",                       bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::openUrl>},
    {"isDebug",                       bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::isDebug>},
    {"isAd",                          bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::isAd>},
    {"getUUID",                       bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getUUID>},
    {"getPid",                        bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getPid>},
    {"getIdfa",                       bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getIdfa>},
    {"getPL",                         bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getPL>},
    {"getOS",                         bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getOS>},
    {"getGN",                         bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getGN>},
    {"getUrlParam",                   bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getUrlParam>},
    {"getLogHost",                    bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getLogHost>},
    {"getSDKVersion",                 bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getSDKVersion>},
    {"getHost",                       bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getHost>},
    {"getStandAlone",                 bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getStandAlone>},
    {"sendTracking",                  bindPlatformStrAndJson<&bt::Platform::sendTracking>},
    {"retention",                     bindPlatformJson<&bt::Platform::retention>},
    {"sendLog",                       bindPlatformJson<&bt::Platform::sendLog>},
    {"getDeviceInfo",                 bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getDeviceInfo>},
    {"getDeviceFeature",              bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getDeviceFeature>},
    {"getSuperNotice",                bindPlatformJson<&bt::Platform::getSuperNotice>},
    {"setSimulationInfo",             bindPlatformJson<&bt::Platform::setSimulationInfo>},
    {"getUserInformation",            bindPlatformJson<&bt::Platform::getUserInformation>},
    {"getBrowseActive",               bindPlatformJson<&bt::Platform::getBrowseActive>},
    {"sendAdstat",                    bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::sendAdstat>},
    {"callUniversalFunction",         bindPlatformStrAndJson<&bt::Platform::callUniversalFunction>},
    {"showMessage",                   bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::showMessage>},
    {"isLogined",                     bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::isLogined>},
    {"checkMethod",                   bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::checkMethod>},
    {"callUniversalWebFunction",      lua_Platform_callUniversalWebFunction},
    {"setDebugEnv",                   bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::setDebugEnv>},
    {"issueDJOrders",                 bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::issueDJOrders>},
    {"getForceFix",                   bindPlatformJson<&bt::Platform::getForceFix>},
    {"signUrl",                       lua_Platform_signUrl_dispatch},
    {"setMainScreenBrightness",       lua_Platform_setMainScreenBrightness},
    {"getMainScreenBrightness",       bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getMainScreenBrightness>},
    {"searchHandleUrl",               bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::searchHandleUrl>},
    {"callUniversalFunctionWithBack", lua_Platform_callUniversalFunctionWithBack},
    {"getNetworkCapture",             bindPlatformJson<&bt::Platform::getNetworkCapture>},
    {"getLocaleInfo",                 bindFlexSingleton<&bt::Platform::getInstance, &bt::Platform::getLocaleInfo>},
    {"registeCallBackBySync",         lua_Platform_registeCallBackBySync},
};

int lua_StubNoOpClosure(lua_State* L) {
    const char* moduleName = lua_tostring(L, lua_upvalueindex(1));
    const char* methodName = lua_tostring(L, lua_upvalueindex(2));
    std::fprintf(stderr, "[tolua_Stub][%s] Dropped call '%s' safely ignored on Win32 (argc=%d)\n",
                 moduleName ? moduleName : "Unknown",
                 methodName ? methodName : "unknown",
                 lua_gettop(L));
    return 0;
}

int lua_StubFallbackIndex(lua_State* L) {
    const char* moduleName = lua_tostring(L, lua_upvalueindex(1));
    const char* key = lua_tostring(L, 2);
    lua_pushstring(L, moduleName ? moduleName : "Stub");
    lua_pushstring(L, key ? key : "<unknown>");
    lua_pushcclosure(L, lua_StubNoOpClosure, 2);
    return 1;
}

int lua_PluginManager_loadPlugin(lua_State* L) {
    std::fprintf(stderr, "[tolua_PluginManager] loadPlugin('%s') -> Win32 stub\n",
                 optString(L, firstArgIndex(L), "").c_str());
    lua_getglobal(L, "PluginManager");
    return 1;
}

int lua_PluginManager_callString(lua_State* L) {
    std::fprintf(stderr, "[tolua_PluginManager] callStringFuncWithParam('%s') -> \"{}\"\n",
                 optString(L, firstArgIndex(L), "").c_str());
    lua_pushstring(L, "{}");
    return 1;
}

int lua_PluginManager_callInt(lua_State* L) {
    std::fprintf(stderr, "[tolua_PluginManager] callIntFuncWithParam('%s') -> 0\n",
                 optString(L, firstArgIndex(L), "").c_str());
    lua_pushinteger(L, 0);
    return 1;
}

int lua_PluginManager_callBool(lua_State* L) {
    std::fprintf(stderr, "[tolua_PluginManager] callBoolFuncWithParam('%s') -> false\n",
                 optString(L, firstArgIndex(L), "").c_str());
    lua_pushboolean(L, 0);
    return 1;
}

int lua_NotificationManager_getDeviceToken(lua_State* L) {
    std::fprintf(stderr, "[tolua_NotificationManager] getDeviceToken() -> \"\"\n");
    lua_pushstring(L, "");
    return 1;
}

void registerStubModule(lua_State* L, const char* moduleName, std::span<const luaL_Reg> methods) {
    lua_newtable(L);
    registerMethodTable(L, -1, methods);
    lua_newtable(L);
    lua_pushstring(L, moduleName);
    lua_pushcclosure(L, lua_StubFallbackIndex, 1);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);
    lua_setglobal(L, moduleName);
}

} // namespace

int tolua_Platform_open(lua_State* L) {
    if (!L) return 0;

    auto& reg = getLuaCallbacks();
    if (reg.fallbackState != L) {
        reg.fallbackState = L;
        reg.primaryHandlerRef = LUA_NOREF;
        reg.syncHandlerRef = LUA_NOREF;
    }

    for (const auto& c : kPlatformConstants) {
        lua_pushnumber(L, c.value);
        lua_setglobal(L, c.name);
    }

    luaL_newmetatable(L, "CallBack");
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_setglobal(L, "CallBack");

    luaL_newmetatable(L, "Platform");
    registerMethodTable(L, -1, kPlatformMethods);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_setglobal(L, "Platform");

    registerMobileLuaBridges(L);
    return 1;
}

int tolua_PluginManager_open(lua_State* L) {
    if (!L) return 0;
    static constexpr luaL_Reg kMethods[] = {
        {"getInstance",             lua_ReturnNamedGlobal<kGlobalPluginManager>},
        {"loadPlugin",              lua_PluginManager_loadPlugin},
        {"callStringFuncWithParam", lua_PluginManager_callString},
        {"callIntFuncWithParam",    lua_PluginManager_callInt},
        {"callBoolFuncWithParam",   lua_PluginManager_callBool},
    };
    registerStubModule(L, "PluginManager", kMethods);
    return 1;
}

int tolua_NotificationManager_open(lua_State* L) {
    if (!L) return 0;
    static constexpr luaL_Reg kMethods[] = {
        {"getInstance",    lua_ReturnNamedGlobal<kGlobalNotificationManager>},
        {"getDeviceToken", lua_NotificationManager_getDeviceToken},
    };
    registerStubModule(L, "NotificationManager", kMethods);
    return 1;
}

int tolua_GCLIENT_Plugins_open(lua_State* L) {
    tolua_Platform_open(L);
    tolua_PluginManager_open(L);
    tolua_NotificationManager_open(L);
    return 1;
}
