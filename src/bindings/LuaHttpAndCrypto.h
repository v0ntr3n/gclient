#pragma once

#include "CCCrypto.h"

struct lua_State;

namespace gclient {
namespace bindings {

// Registers real CCHttpRequest, CCHttpResponse, CCHttpClient, LuaHttpRequest,
// LuaHttpResponse, and CCCrypto bindings in the given Lua state.
void registerLuaHttpAndCrypto(lua_State* L);

// Cleanly tears down WinHttpClient scheduler & pending callback queue prior to Lua VM destruction.
void shutdownLuaHttpClient();

} // namespace bindings
} // namespace gclient
