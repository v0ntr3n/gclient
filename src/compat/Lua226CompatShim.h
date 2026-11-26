#pragma once

struct lua_State;

namespace gclient::compat {

// Injects the Cocos2d-x 2.2.6 -> Axmol v2.11.5 Lua runtime compatibility layer
// (CC* globals, ccp/ccc3/CCSize/CCRect helpers, CCSequence/CCSpawn CCArray support,
// tolua.cast legacy class mapping, CCLayer touch handler shim, Widget 2.2.6 methods,
// CCNotificationCenter, and UI/CocoStudio enum constants).
bool InstallLua226CompatShim(lua_State* L);

} // namespace gclient::compat
