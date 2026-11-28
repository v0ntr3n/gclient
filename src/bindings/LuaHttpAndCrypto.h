#pragma once

#include "CCCrypto.h"

#include <string>
#include <string_view>

struct lua_State;

namespace gclient {
namespace bindings {

bool isDeadStagingHost(std::string_view host) noexcept;
std::string rewriteLegacyStagingUrl(std::string_view rawUrl, bool* outWasRewritten = nullptr);

// Registers real CCHttpRequest, CCHttpResponse, CCHttpClient, LuaHttpRequest,
// LuaHttpResponse, and CCCrypto bindings in the given Lua state.
void registerLuaHttpAndCrypto(lua_State* L);

// Cancels any in-flight Lua HTTP callbacks owned by the given Lua state (soft restart safety).
void cancelLuaHttpRequestsForState(lua_State* L);

// Cleanly tears down WinHttpClient scheduler & pending callback queue prior to Lua VM destruction.
void shutdownLuaHttpClient();

} // namespace bindings
} // namespace gclient
