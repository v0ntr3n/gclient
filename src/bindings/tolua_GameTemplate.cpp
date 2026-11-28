#include "tolua_GameTemplate.h"
#include "CConfigManager.h"
#include "GameUtil.h"
#include "LuaHelpers.h"
#include "LuaHttpAndCrypto.h"

#ifndef GCLIENT_USE_COCOS2DX
#define GCLIENT_USE_COCOS2DX 1
#endif

#if defined(__has_include)
#  if __has_include("net/CNetwork.h")
#    include "net/CNetwork.h"
#    define GCLIENT_HAS_CNETWORK 1
#  elif __has_include("../net/CNetwork.h")
#    include "../net/CNetwork.h"
#    define GCLIENT_HAS_CNETWORK 1
#  endif
#endif

#ifdef GCLIENT_HAS_CNETWORK
using gclient::net::CConnection;
using gclient::net::CNetwork;
#endif

#include "CCLuaEngine.h"
#include "cocos2d.h"
#include "tolua_fix.h"
#include "LuaBindTemplates.h"

#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <utility>

USING_NS_CC;

#if !defined(GCLIENT_HAS_CNETWORK)
class CConnection : public cocos2d::CCObject {
public:
    bool send(const std::string& data, bool useLCPacket = true);
    bool connect(const char* host, unsigned int port);
    void registerBodyFunc(int luaFuncRef);
    void registerHeadFunc(int luaFuncRef);
    void registerCloseFunc(int luaFuncRef);
    void setHeaderSize(int size);
    void close();
};

class CNetwork : public cocos2d::CCObject {
public:
    static CNetwork* sharedNetwork();
    CConnection* newConnection();
};
#endif

namespace gclient::lua_bind {

template <> struct ToluaObjTag<CCArray>       { static constexpr const char* name = "CCArray"; };
template <> struct ToluaObjTag<CCString>      { static constexpr const char* name = "CCString"; };
template <> struct ToluaObjTag<CCTexture2D>   { static constexpr const char* name = "CCTexture2D"; };
template <> struct ToluaObjTag<CLuaFuncs>     { static constexpr const char* name = "CLuaFuncs"; };
template <> struct ToluaObjTag<CTimer>        { static constexpr const char* name = "CTimer"; };
template <> struct ToluaObjTag<CCStrokeLabel> { static constexpr const char* name = "CCStrokeLabel"; };
template <> struct ToluaObjTag<SpriteBlur>    { static constexpr const char* name = "SpriteBlur"; };
template <> struct ToluaObjTag<CConnection>   { static constexpr const char* name = "CConnection"; };
template <> struct ToluaObjTag<CNetwork>      { static constexpr const char* name = "CNetwork"; };

} // namespace gclient::lua_bind

namespace {

using gclient::lua_bind::FixedName;
using gclient::lua_bind::ToluaArgTraits;
using gclient::lua_bind::bindTolua;
using gclient::lua_bind::bindToluaObjRet;
using gclient::lua_bind::extractAxObject;
using gclient::lua_bind::getAxObject;
using gclient::lua_bind::pushAxObject;
using gclient::lua_bind::pushToluaReturn;
using gclient::lua_bind::toAbsIndex;

GameTemplateForwardingHooks s_hooks;

template <typename T>
T* getSafeRawUsertype(lua_State* L, int idx, const char* expectedType) {
    if (!L || !expectedType) return nullptr;
    const int absIdx = toAbsIndex(L, idx);
    if (absIdx <= 0 || absIdx > lua_gettop(L)) return nullptr;
    tolua_Error err{};
    if (lua_type(L, absIdx) == LUA_TUSERDATA && tolua_isusertype(L, absIdx, expectedType, 0, &err)) {
        return static_cast<T*>(tolua_tousertype(L, absIdx, nullptr));
    }
    return nullptr;
}

// Binary-safe `std::string` return wrapper using `lua_pushlstring` (preserves embedded NUL bytes).
template <FixedName ClassTag, FixedName FnName, typename... Args, size_t... Is>
int invokeToluaBinStr(lua_State* L, std::string (*fn)(Args...), std::index_sequence<Is...>) {
    tolua_Error err{};
    const bool ok = (tolua_isusertable(L, 1, ClassTag.c_str(), 0, &err) != 0) &&
                    (ToluaArgTraits<std::remove_cvref_t<Args>>::check(L, 2 + static_cast<int>(Is), &err) && ...) &&
                    (tolua_isnoobj(L, 2 + static_cast<int>(sizeof...(Args)), &err) != 0);
    if (!ok) {
        const std::string msg = std::string("#ferror in function '") + FnName.c_str() + "'.";
        tolua_error(L, msg.c_str(), &err);
        return 0;
    }
    const std::string out = fn(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...);
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}

template <FixedName ClassTag, FixedName FnName, auto Fn>
int bindToluaBinStr(lua_State* L) {
    return [&]<typename... Args>(std::string (*f)(Args...)) {
        return invokeToluaBinStr<ClassTag, FnName>(L, f, std::index_sequence_for<Args...>{});
    }(Fn);
}

// Generic wrapper for single `LUA_FUNCTION` callback registration methods (`register*Func`).
template <typename Class, FixedName ClassTag, FixedName FnName, void (Class::*MemberFn)(int)>
int bindLuaFuncMember(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertype(tolua_S, 1, ClassTag.c_str(), 0, &err) ||
        !toluafix_isfunction(tolua_S, 2, "LUA_FUNCTION", 0, &err) ||
        !tolua_isnoobj(tolua_S, 3, &err)) {
        const std::string msg = std::string("#ferror in function '") + FnName.c_str() + "'.";
        tolua_error(tolua_S, msg.c_str(), &err);
        return 0;
    }
    auto* self = getAxObject<Class>(tolua_S, 1, ClassTag.c_str());
    const int handler = toluafix_ref_function(tolua_S, 2, 0);
    if (self) (self->*MemberFn)(handler);
    return 0;
}

// Generic wrapper for non-ax::Object raw tolua++ usertypes (CTable).
template <typename Class, FixedName ClassTag, FixedName FnName, typename R, typename... Args, size_t... Is>
int invokeRawMethod(lua_State* L, R (Class::*fn)(Args...), const char* retTag, std::index_sequence<Is...>) {
    tolua_Error err{};
    const bool ok = (tolua_isusertype(L, 1, ClassTag.c_str(), 0, &err) != 0) &&
                    (ToluaArgTraits<std::remove_cvref_t<Args>>::check(L, 2 + static_cast<int>(Is), &err) && ...) &&
                    (tolua_isnoobj(L, 2 + static_cast<int>(sizeof...(Args)), &err) != 0);
    if (!ok) {
        const std::string msg = std::string("#ferror in function '") + FnName.c_str() + "'.";
        tolua_error(L, msg.c_str(), &err);
        return 0;
    }
    auto* self = getSafeRawUsertype<Class>(L, 1, ClassTag.c_str());
    if constexpr (std::is_void_v<R>) {
        if (self) (self->*fn)(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...);
        return 0;
    } else {
        if (!self) { lua_pushnil(L); return 1; }
        return pushToluaReturn(
            L, (self->*fn)(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...), retTag);
    }
}

template <typename Class, FixedName ClassTag, FixedName FnName, auto MemberFn, FixedName RetTag = "">
int bindRawMethod(lua_State* L) {
    return [&]<typename R, typename... Args>(R (Class::*f)(Args...)) {
        const char* tag = RetTag.c_str()[0] ? RetTag.c_str() : nullptr;
        return invokeRawMethod<Class, ClassTag, FnName>(L, f, tag, std::index_sequence_for<Args...>{});
    }(MemberFn);
}

void tolua_reg_types_GameTemplate(lua_State* tolua_S) {
    static constexpr const char* kTypes[] = {
        "CCHttpClient", "LuaHttpRequest", "CNetwork", "CCCrypto", "CTimer",
        "LuaHttpResponse", "CConnection", "CCHttpResponse", "CCHttpRequest",
        "CCObject", "SpriteBlur", "GameUtil", "CLuaFuncs", "CCArray",
        "CCStrokeLabel", "CTable", "CConfigurationManager"
    };
    for (const char* t : kTypes) {
        tolua_usertype(tolua_S, t);
    }
}

// ============================================================================
// Custom wrappers requiring LUA_FUNCTION refs, optional args, or raw usertypes
// ============================================================================

std::string gameUtilWriteU32(uint32_t val) {
    return GameUtil::writeU32(val);
}

int tolua_CLuaFuncs_addHandler00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertype(tolua_S, 1, "CLuaFuncs", 0, &err) ||
        !tolua_isstring(tolua_S, 2, 0, &err) ||
        !toluafix_isfunction(tolua_S, 3, "LUA_FUNCTION", 0, &err) ||
        !tolua_isnoobj(tolua_S, 4, &err)) {
        tolua_error(tolua_S, "#ferror in function 'addHandler'.", &err);
        return 0;
    }
    auto* self = getAxObject<CLuaFuncs>(tolua_S, 1, "CLuaFuncs");
    const char* name = tolua_tostring(tolua_S, 2, "");
    const int handler = toluafix_ref_function(tolua_S, 3, 0);
    if (self) self->addHandler(name, handler);
    return 0;
}

int tolua_GameUtil_access00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &err) ||
        !tolua_isstring(tolua_S, 2, 0, &err) ||
        !tolua_isnumber(tolua_S, 3, 1, &err) ||
        !tolua_isnoobj(tolua_S, 4, &err)) {
        tolua_error(tolua_S, "#ferror in function 'access'.", &err);
        return 0;
    }
    const char* path = tolua_tostring(tolua_S, 2, "");
    const int mode = static_cast<int>(tolua_tonumber(tolua_S, 3, GameUtil::EFOk));
    tolua_pushnumber(tolua_S, static_cast<lua_Number>(GameUtil::access(path, mode)));
    return 1;
}

int tolua_GameUtil_convertEncoding00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &err) ||
        !tolua_isstring(tolua_S, 2, 0, &err) ||
        !tolua_isstring(tolua_S, 3, 1, &err) ||
        !tolua_isnoobj(tolua_S, 4, &err)) {
        tolua_error(tolua_S, "#ferror in function 'convertEncoding'.", &err);
        return 0;
    }
    tolua_pushcppstring(tolua_S, GameUtil::convertEncoding(
        tolua_tostring(tolua_S, 2, ""), tolua_tostring(tolua_S, 3, "UTF-8")));
    return 1;
}

int tolua_GameUtil_setTimeZone00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertable(tolua_S, 1, "GameUtil", 0, &err) ||
        !(lua_isnumber(tolua_S, 2) || lua_isstring(tolua_S, 2)) ||
        !tolua_isnoobj(tolua_S, 3, &err)) {
        tolua_error(tolua_S, "#ferror in function 'setTimeZone'.", &err);
        return 0;
    }
    if (lua_isnumber(tolua_S, 2)) {
        GameUtil::setTimeZone(static_cast<int>(tolua_tonumber(tolua_S, 2, 0)));
    }
    return 0;
}

int tolua_CTimer_addEvent00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertype(tolua_S, 1, "CTimer", 0, &err) ||
        !tolua_isnumber(tolua_S, 2, 0, &err) ||
        !toluafix_isfunction(tolua_S, 3, "LUA_FUNCTION", 0, &err) ||
        !tolua_isnoobj(tolua_S, 4, &err)) {
        tolua_error(tolua_S, "#ferror in function 'addEvent'.", &err);
        return 0;
    }
    auto* self = getAxObject<CTimer>(tolua_S, 1, "CTimer");
    const int delaySeconds = static_cast<int>(tolua_tonumber(tolua_S, 2, 0));
    const int handler = toluafix_ref_function(tolua_S, 3, 0);
    if (self) self->addEvent(delaySeconds, handler);
    return 0;
}

int tolua_CConnection_send00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertype(tolua_S, 1, "CConnection", 0, &err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &err) ||
        !tolua_isboolean(tolua_S, 3, 1, &err) ||
        !tolua_isnoobj(tolua_S, 4, &err)) {
        tolua_error(tolua_S, "#ferror in function 'send'.", &err);
        return 0;
    }
    auto* self = getAxObject<CConnection>(tolua_S, 1, "CConnection");
    const std::string payload = ToluaArgTraits<std::string>::get(tolua_S, 2);
    const bool useLCPacket = tolua_toboolean(tolua_S, 3, 1) != 0;
    tolua_pushboolean(tolua_S, (self && self->send(payload, useLCPacket)) ? 1 : 0);
    return 1;
}

int tolua_CCStrokeLabel_create00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertable(tolua_S, 1, "CCStrokeLabel", 0, &err)) {
        tolua_error(tolua_S, "#ferror in function 'create'.", &err);
        return 0;
    }
    const char* text = lua_isstring(tolua_S, 2) ? tolua_tostring(tolua_S, 2, "") : "";
    const char* fontName = lua_isstring(tolua_S, 3) ? tolua_tostring(tolua_S, 3, "") : "";
    const int fontSize = lua_isnumber(tolua_S, 4) ? static_cast<int>(tolua_tonumber(tolua_S, 4, 16)) : 16;
    pushAxObject(tolua_S, CCStrokeLabel::create(text, fontName, fontSize), "CCStrokeLabel");
    return 1;
}

int tolua_CCStrokeLabel_setStroke00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertype(tolua_S, 1, "CCStrokeLabel", 0, &err) ||
        !tolua_isnumber(tolua_S, 2, 0, &err)) {
        tolua_error(tolua_S, "#ferror in function 'setStroke'.", &err);
        return 0;
    }
    auto* self = getAxObject<CCStrokeLabel>(tolua_S, 1, "CCStrokeLabel");
    const auto strokeSize = static_cast<unsigned int>(tolua_tonumber(tolua_S, 2, 1));
    ccColor4B color = ccc4(0, 0, 0, 255);
    if (auto* c4 = getSafeRawUsertype<ccColor4B>(tolua_S, 3, "ccColor4B")) {
        color = *c4;
    } else if (auto* c3 = getSafeRawUsertype<ccColor3B>(tolua_S, 3, "ccColor3B")) {
        color = ccc4(c3->r, c3->g, c3->b, 255);
    }
    if (self) self->setStroke(strokeSize, color);
    return 0;
}

int tolua_CConfigurationManager_shared00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertable(tolua_S, 1, "CConfigurationManager", 0, &err) ||
        !tolua_isboolean(tolua_S, 2, 1, &err) ||
        !tolua_isnoobj(tolua_S, 3, &err)) {
        tolua_error(tolua_S, "#ferror in function 'sharedConfigurationManager'.", &err);
        return 0;
    }
    const bool reload = tolua_toboolean(tolua_S, 2, 0) != 0;
    tolua_pushusertype(tolua_S, static_cast<void*>(CConfigurationManager::sharedConfigurationManager(reload)),
                       "CConfigurationManager");
    return 1;
}

int tolua_CConfigurationManager_getTable00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertype(tolua_S, 1, "CConfigurationManager", 0, &err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &err) ||
        !tolua_iscppstring(tolua_S, 3, 0, &err) ||
        !tolua_isnoobj(tolua_S, 4, &err)) {
        tolua_error(tolua_S, "#ferror in function 'getTable'.", &err);
        return 0;
    }
    auto* self = getSafeRawUsertype<CConfigurationManager>(tolua_S, 1, "CConfigurationManager");
    CTable* ret = self
        ? self->getTable(tolua_tocppstring(tolua_S, 2, ""), tolua_tocppstring(tolua_S, 3, ""))
        : nullptr;
    tolua_pushusertype(tolua_S, static_cast<void*>(ret), "CTable");
    return 1;
}

int tolua_SpriteBlur_draw00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertype(tolua_S, 1, "SpriteBlur", 0, &err) ||
        !tolua_isnoobj(tolua_S, 2, &err)) {
        tolua_error(tolua_S, "#ferror in function 'draw'.", &err);
        return 0;
    }
    // Axmol renders via draw(renderer, transform, flags).
    (void)getAxObject<SpriteBlur>(tolua_S, 1, "SpriteBlur");
    return 0;
}

int tolua_SpriteBlur_listenBack2Foreground00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertype(tolua_S, 1, "SpriteBlur", 0, &err) ||
        !(tolua_isusertype(tolua_S, 2, "CCObject", 1, &err) || extractAxObject(tolua_S, 2) != nullptr) ||
        !tolua_isnoobj(tolua_S, 3, &err)) {
        tolua_error(tolua_S, "#ferror in function 'listenBack2Foreground'.", &err);
        return 0;
    }
    if (auto* self = getAxObject<SpriteBlur>(tolua_S, 1, "SpriteBlur")) {
        self->listenBack2Foreground(extractAxObject(tolua_S, 2, "CCObject"));
    }
    return 0;
}

int tolua_SpriteBlur_initWithTexture00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertype(tolua_S, 1, "SpriteBlur", 0, &err) ||
        !tolua_isusertype(tolua_S, 2, "CCTexture2D", 1, &err) ||
        !tolua_isusertype(tolua_S, 3, "CCRect", 0, &err) ||
        !tolua_isnoobj(tolua_S, 4, &err)) {
        tolua_error(tolua_S, "#ferror in function 'initWithTexture'.", &err);
        return 0;
    }
    auto* self = getAxObject<SpriteBlur>(tolua_S, 1, "SpriteBlur");
    auto* tex = getAxObject<CCTexture2D>(tolua_S, 2, "CCTexture2D");
    auto* rect = getSafeRawUsertype<CCRect>(tolua_S, 3, "CCRect");
    tolua_pushboolean(tolua_S, (self && rect && self->initWithTexture(tex, *rect)) ? 1 : 0);
    return 1;
}

int tolua_SpriteBlur_create00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertable(tolua_S, 1, "SpriteBlur", 0, &err)) {
        tolua_error(tolua_S, "#ferror in function 'create'.", &err);
        return 0;
    }
    const char* filename = lua_isstring(tolua_S, 2) ? tolua_tostring(tolua_S, 2, "") : "";
    pushAxObject(tolua_S, SpriteBlur::create(filename), "SpriteBlur");
    return 1;
}

int tolua_SpriteBlur_createWithTexture00(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertable(tolua_S, 1, "SpriteBlur", 0, &err)) {
        tolua_error(tolua_S, "#ferror in function 'createWithTexture'.", &err);
        return 0;
    }
    pushAxObject(tolua_S, SpriteBlur::createWithTexture(getAxObject<CCTexture2D>(tolua_S, 2, "CCTexture2D")),
                 "SpriteBlur");
    return 1;
}

// ============================================================================
// Default logged stubs for external HTTP / Crypto forwarding hooks
// ============================================================================

struct LuaConstDef {
    const char* name;
    lua_Number value;
};

int tolua_unwired_stub(lua_State* tolua_S) {
    lua_Debug ar{};
    const char* fnName = (lua_getstack(tolua_S, 0, &ar) && lua_getinfo(tolua_S, "n", &ar) && ar.name)
        ? ar.name
        : "<unknown>";
    CCLog("tolua_GameTemplate: unwired forwarding hook called for '%s'", fnName);
    lua_pushnil(tolua_S);
    return 1;
}

void registerStubClass(lua_State* tolua_S, const char* cls, const char* base,
                       std::span<const LuaConstDef> consts,
                       std::span<const char* const> methods) {
    tolua_cclass(tolua_S, cls, cls, base, nullptr);
    tolua_beginmodule(tolua_S, cls);
    for (const auto& c : consts) tolua_constant(tolua_S, c.name, c.value);
    for (const char* m : methods) tolua_function(tolua_S, m, tolua_unwired_stub);
    tolua_endmodule(tolua_S);
}

void registerDefaultHttpHooks(lua_State* tolua_S) {
    if (s_hooks.registerCCHttpRequest) {
        s_hooks.registerCCHttpRequest(tolua_S);
    } else {
        static constexpr LuaConstDef kReqConsts[] = {
            {"kHttpGet", 0.0}, {"kHttpPost", 1.0}, {"kHttpPut", 2.0}, {"kHttpDelete", 3.0}, {"kHttpUnkown", 4.0}
        };
        static constexpr const char* kReqMethods[] = {
            "setRequestType", "getRequestType", "setUrl", "getUrl", "setRequestData", "getRequestData",
            "getRequestDataSize", "setTag", "getTag", "getTarget", "setTimeoutForConnect",
            "getTimeoutForConnect", "setTimeoutForRead", "getTimeoutForRead", "setTimeoutForLowSpeed",
            "getTimeoutForLowSpeed", "setLowSpeed", "getLowSpeed"
        };
        registerStubClass(tolua_S, "CCHttpRequest", "CCObject", kReqConsts, kReqMethods);
    }

    if (s_hooks.registerCCHttpResponse) {
        s_hooks.registerCCHttpResponse(tolua_S);
    } else {
        static constexpr const char* kRespMethods[] = {"isSucceed", "getResponseCode", "getErrorBuffer"};
        registerStubClass(tolua_S, "CCHttpResponse", "CCObject", {}, kRespMethods);
    }

    if (s_hooks.registerCCHttpClient) {
        s_hooks.registerCCHttpClient(tolua_S);
    } else {
        static constexpr const char* kClientMethods[] = {"getInstance", "destroyInstance", "send", "enableCookies"};
        registerStubClass(tolua_S, "CCHttpClient", "CCObject", {}, kClientMethods);
    }

    if (s_hooks.registerLuaHttpRequest) {
        s_hooks.registerLuaHttpRequest(tolua_S);
    } else {
        static constexpr const char* kLuaReqMethods[] = {
            "newRequest", "setHeaders", "addHeader", "getHeaders",
            "setResponseScriptFunc", "setBodyDataScriptFunc", "setHeaderDataScriptFunc"
        };
        registerStubClass(tolua_S, "LuaHttpRequest", "CCHttpRequest", {}, kLuaReqMethods);
    }

    if (s_hooks.registerLuaHttpResponse) {
        s_hooks.registerLuaHttpResponse(tolua_S);
    } else {
        static constexpr const char* kLuaRespMethods[] = {
            "getHeaders", "getHeadersSize", "getResponseData", "getResponseDataSize", "getRequest"
        };
        registerStubClass(tolua_S, "LuaHttpResponse", "CCHttpResponse", {}, kLuaRespMethods);
    }
}

void registerDefaultCCCrypto(lua_State* tolua_S) {
    static constexpr LuaConstDef kCryptoConsts[] = {{"EDigestMD5", 1.0}, {"EDigestSha1", 2.0}};
    static constexpr const char* kCryptoMethods[] = {
        "encodeBase64", "decodeBase64", "md5", "sha1", "bin2hex",
        "createDigest", "addBytes", "getDigest", "hex2bin"
    };
    registerStubClass(tolua_S, "CCCrypto", "", kCryptoConsts, kCryptoMethods);
}

// Global Lua bitwise & diagnostics helpers
int lua_andBit(lua_State* L) {
    const auto a = static_cast<uint32_t>(luaL_checknumber(L, 1));
    const auto b = static_cast<uint32_t>(luaL_checknumber(L, 2));
    lua_pushnumber(L, static_cast<lua_Number>(a & b));
    return 1;
}

int lua_xorBit(lua_State* L) {
    const auto a = static_cast<uint32_t>(luaL_checknumber(L, 1));
    const auto b = static_cast<uint32_t>(luaL_checknumber(L, 2));
    lua_pushnumber(L, static_cast<lua_Number>(a ^ b));
    return 1;
}

int lua_dumpMemory(lua_State* L) {
    const int kb = lua_gc(L, LUA_GCCOUNT, 0);
    CCLog("Lua memory usage: %d KB", kb);
    lua_pushnumber(L, static_cast<lua_Number>(kb));
    return 1;
}

} // namespace

TOLUA_API void tolua_GameTemplate_set_hooks(const GameTemplateForwardingHooks& hooks) {
    s_hooks = hooks;
}

TOLUA_API int tolua_GameTemplate_open(lua_State* tolua_S) {
    tolua_open(tolua_S);
    tolua_reg_types_GameTemplate(tolua_S);
    tolua_module(tolua_S, nullptr, 0);
    tolua_beginmodule(tolua_S, nullptr);

    // CLuaFuncs
    tolua_cclass(tolua_S, "CLuaFuncs", "CLuaFuncs", "ax.Object", nullptr);
    tolua_beginmodule(tolua_S, "CLuaFuncs");
    tolua_function(tolua_S, "sharedLuaFuncs", bindToluaObjRet<"CLuaFuncs", "sharedLuaFuncs", "CLuaFuncs", &CLuaFuncs::sharedLuaFuncs>);
    tolua_function(tolua_S, "addHandler", tolua_CLuaFuncs_addHandler00);
    tolua_function(tolua_S, "removeHandler", bindTolua<"CLuaFuncs", "removeHandler", &CLuaFuncs::removeHandler>);
    tolua_endmodule(tolua_S);

    // GameUtil (8 constants + all 23 methods)
    tolua_cclass(tolua_S, "GameUtil", "GameUtil", "", nullptr);
    tolua_beginmodule(tolua_S, "GameUtil");
    tolua_constant(tolua_S, "EFOk", static_cast<lua_Number>(GameUtil::EFOk));
    tolua_constant(tolua_S, "EROk", static_cast<lua_Number>(GameUtil::EROk));
    tolua_constant(tolua_S, "EWOk", static_cast<lua_Number>(GameUtil::EWOk));
    tolua_constant(tolua_S, "EXOk", static_cast<lua_Number>(GameUtil::EXOk));
    tolua_constant(tolua_S, "EUnzipOk", static_cast<lua_Number>(GameUtil::EUnzipOk));
    tolua_constant(tolua_S, "EUnzipFileNotExist", static_cast<lua_Number>(GameUtil::EUnzipFileNotExist));
    tolua_constant(tolua_S, "EUnzipBadFile", static_cast<lua_Number>(GameUtil::EUnzipBadFile));
    tolua_constant(tolua_S, "EUnzipOutOfStorage", static_cast<lua_Number>(GameUtil::EUnzipOutOfStorage));
    tolua_function(tolua_S, "installApk", bindTolua<"GameUtil", "installApk", &GameUtil::installApk>);
    tolua_function(tolua_S, "rename", bindTolua<"GameUtil", "rename", &GameUtil::rename>);
    tolua_function(tolua_S, "mkdir", bindTolua<"GameUtil", "mkdir", &GameUtil::mkdir, false>);
    tolua_function(tolua_S, "rmdir", bindTolua<"GameUtil", "rmdir", &GameUtil::rmdir>);
    tolua_function(tolua_S, "unlink", bindTolua<"GameUtil", "unlink", &GameUtil::unlink>);
    tolua_function(tolua_S, "readdir", bindToluaObjRet<"GameUtil", "readdir", "CCArray", &GameUtil::readdir>);
    tolua_function(tolua_S, "access", tolua_GameUtil_access00);
    tolua_function(tolua_S, "isDir", bindTolua<"GameUtil", "isDir", &GameUtil::isDir>);
    tolua_function(tolua_S, "getDPI", bindTolua<"GameUtil", "getDPI", &GameUtil::getDPI>);
    tolua_function(tolua_S, "getExternalStorageLocation", bindTolua<"GameUtil", "getExternalStorageLocation", &GameUtil::getExternalStorageLocation>);
    tolua_function(tolua_S, "unzip", bindTolua<"GameUtil", "unzip", &GameUtil::unzip>);
    tolua_function(tolua_S, "convertEncoding", tolua_GameUtil_convertEncoding00);
    tolua_function(tolua_S, "getAssetFiles", bindToluaObjRet<"GameUtil", "getAssetFiles", "CCArray", &GameUtil::getAssetFiles>);
    tolua_function(tolua_S, "checkRecordPermission", bindTolua<"GameUtil", "checkRecordPermission", &GameUtil::checkRecordPermission>);
    tolua_function(tolua_S, "setTimeZone", tolua_GameUtil_setTimeZone00);
    tolua_function(tolua_S, "urlEncode", bindToluaBinStr<"GameUtil", "urlEncode", &GameUtil::urlEncode>);
    tolua_function(tolua_S, "urlDecode", bindToluaBinStr<"GameUtil", "urlDecode", &GameUtil::urlDecode>);
    tolua_function(tolua_S, "getMicroSeconds", bindTolua<"GameUtil", "getMicroSeconds", &GameUtil::getMicroSeconds>);
    tolua_function(tolua_S, "makeLCPacket", bindToluaBinStr<"GameUtil", "makeLCPacket", &GameUtil::makeLCPacket>);
    tolua_function(tolua_S, "getU32", bindTolua<"GameUtil", "getU32", &GameUtil::getU32>);
    tolua_function(tolua_S, "writeU32", bindToluaBinStr<"GameUtil", "writeU32", &gameUtilWriteU32>);
    tolua_function(tolua_S, "zipData", bindToluaBinStr<"GameUtil", "zipData", &GameUtil::zipData>);
    tolua_function(tolua_S, "unzipData", bindToluaBinStr<"GameUtil", "unzipData", &GameUtil::unzipData>);
    tolua_endmodule(tolua_S);

    // Forwarding hooks for HTTP classes & CCCrypto
    const bool anyCustomHttpOrCryptoHook =
        s_hooks.registerCCHttpRequest || s_hooks.registerCCHttpResponse ||
        s_hooks.registerCCHttpClient || s_hooks.registerLuaHttpRequest ||
        s_hooks.registerLuaHttpResponse || s_hooks.registerCCCrypto;

    if (!anyCustomHttpOrCryptoHook) {
        gclient::bindings::registerLuaHttpAndCrypto(tolua_S);
    } else {
        registerDefaultHttpHooks(tolua_S);
    }

    // CTimer
    tolua_cclass(tolua_S, "CTimer", "CTimer", "ax.Object", nullptr);
    tolua_beginmodule(tolua_S, "CTimer");
    tolua_function(tolua_S, "sharedTimer", bindToluaObjRet<"CTimer", "sharedTimer", "CTimer", &CTimer::sharedTimer>);
    tolua_function(tolua_S, "addEvent", tolua_CTimer_addEvent00);
    tolua_endmodule(tolua_S);

    if (anyCustomHttpOrCryptoHook) {
        if (s_hooks.registerCCCrypto) {
            s_hooks.registerCCCrypto(tolua_S);
        } else {
            registerDefaultCCCrypto(tolua_S);
        }
    }

    // CConnection (all 7 methods)
    tolua_cclass(tolua_S, "CConnection", "CConnection", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CConnection");
    tolua_function(tolua_S, "send", tolua_CConnection_send00);
    tolua_function(tolua_S, "connect", bindTolua<"CConnection", "connect", &CConnection::connect>);
    tolua_function(tolua_S, "registerBodyFunc", bindLuaFuncMember<CConnection, "CConnection", "registerBodyFunc", &CConnection::registerBodyFunc>);
    tolua_function(tolua_S, "registerHeadFunc", bindLuaFuncMember<CConnection, "CConnection", "registerHeadFunc", &CConnection::registerHeadFunc>);
    tolua_function(tolua_S, "registerCloseFunc", bindLuaFuncMember<CConnection, "CConnection", "registerCloseFunc", &CConnection::registerCloseFunc>);
    tolua_function(tolua_S, "setHeaderSize", bindTolua<"CConnection", "setHeaderSize", &CConnection::setHeaderSize>);
    tolua_function(tolua_S, "close", bindTolua<"CConnection", "close", &CConnection::close>);
    tolua_endmodule(tolua_S);

    // CNetwork (2 methods)
    tolua_cclass(tolua_S, "CNetwork", "CNetwork", "CCObject", nullptr);
    tolua_beginmodule(tolua_S, "CNetwork");
    tolua_function(tolua_S, "sharedNetwork", bindToluaObjRet<"CNetwork", "sharedNetwork", "CNetwork", &CNetwork::sharedNetwork>);
    tolua_function(tolua_S, "newConnection", bindToluaObjRet<"CNetwork", "newConnection", "CConnection", &CNetwork::newConnection>);
    tolua_endmodule(tolua_S);

    // CCStrokeLabel (3 methods)
    tolua_cclass(tolua_S, "CCStrokeLabel", "CCStrokeLabel", "ax.Label", nullptr);
    tolua_beginmodule(tolua_S, "CCStrokeLabel");
    tolua_function(tolua_S, "create", tolua_CCStrokeLabel_create00);
    tolua_function(tolua_S, "setStroke", tolua_CCStrokeLabel_setStroke00);
    tolua_function(tolua_S, "setContrast", bindTolua<"CCStrokeLabel", "setContrast", &CCStrokeLabel::setContrast>);
    tolua_endmodule(tolua_S);

    // CTable (getRowById, getColumnName, getColName, getIdsByConditionStr, release)
    tolua_cclass(tolua_S, "CTable", "CTable", "", nullptr);
    tolua_beginmodule(tolua_S, "CTable");
    tolua_function(tolua_S, "getRowById", bindRawMethod<CTable, "CTable", "getRowById", &CTable::getRowById, "CCArray">);
    tolua_function(tolua_S, "getColumnName", bindRawMethod<CTable, "CTable", "getColumnName", &CTable::getColumnName, "CCArray">);
    tolua_function(tolua_S, "getColName", bindRawMethod<CTable, "CTable", "getColName", &CTable::getColName, "CCArray">);
    tolua_function(tolua_S, "getIdsByConditionStr", bindRawMethod<CTable, "CTable", "getIdsByConditionStr", &CTable::getIdsByConditionStr, "CCArray">);
    tolua_function(tolua_S, "release", bindRawMethod<CTable, "CTable", "release", &CTable::release>);
    tolua_endmodule(tolua_S);

    // CConfigurationManager (2 methods)
    tolua_cclass(tolua_S, "CConfigurationManager", "CConfigurationManager", "", nullptr);
    tolua_beginmodule(tolua_S, "CConfigurationManager");
    tolua_function(tolua_S, "sharedConfigurationManager", tolua_CConfigurationManager_shared00);
    tolua_function(tolua_S, "getTable", tolua_CConfigurationManager_getTable00);
    tolua_endmodule(tolua_S);

    // SpriteBlur (all 7 methods)
    tolua_cclass(tolua_S, "SpriteBlur", "SpriteBlur", "ax.Sprite", nullptr);
    tolua_beginmodule(tolua_S, "SpriteBlur");
    tolua_function(tolua_S, "draw", tolua_SpriteBlur_draw00);
    tolua_function(tolua_S, "initProgram", bindTolua<"SpriteBlur", "initProgram", &SpriteBlur::initProgram>);
    tolua_function(tolua_S, "setBlurSize", bindTolua<"SpriteBlur", "setBlurSize", &SpriteBlur::setBlurSize>);
    tolua_function(tolua_S, "listenBack2Foreground", tolua_SpriteBlur_listenBack2Foreground00);
    tolua_function(tolua_S, "initWithTexture", tolua_SpriteBlur_initWithTexture00);
    tolua_function(tolua_S, "create", tolua_SpriteBlur_create00);
    tolua_function(tolua_S, "createWithTexture", tolua_SpriteBlur_createWithTexture00);
    tolua_endmodule(tolua_S);

    tolua_endmodule(tolua_S);

    lua_register(tolua_S, "andBit", lua_andBit);
    lua_register(tolua_S, "xorBit", lua_xorBit);
    lua_register(tolua_S, "dumpMemory", lua_dumpMemory);

    return 1;
}
