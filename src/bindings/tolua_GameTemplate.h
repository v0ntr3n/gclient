#pragma once

#include <string>

#include "tolua++.h"

struct GameTemplateForwardingHooks {
    int (*registerCCHttpRequest)(lua_State* L) = nullptr;
    int (*registerCCHttpResponse)(lua_State* L) = nullptr;
    int (*registerCCHttpClient)(lua_State* L) = nullptr;
    int (*registerLuaHttpRequest)(lua_State* L) = nullptr;
    int (*registerLuaHttpResponse)(lua_State* L) = nullptr;
    int (*registerCCCrypto)(lua_State* L) = nullptr;
};

TOLUA_API void tolua_GameTemplate_set_hooks(const GameTemplateForwardingHooks& hooks);
TOLUA_API int tolua_GameTemplate_open(lua_State* tolua_S);

#ifdef __cplusplus
void gclient_rescheduleHttpClientCallbacks();
#endif
