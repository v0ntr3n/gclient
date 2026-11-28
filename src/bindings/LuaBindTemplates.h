#pragma once
// Header-only C++20 Lua 5.1 / LuaJIT 2.1 & Axmol tolua++ binding templates.
// Layer 1 (Pure Lua C API) compiles in BOTH standalone tests (GCLIENT_STANDALONE_BUILD) and full Axmol builds.
// Layer 2 (Axmol ax::Object + tolua++) activates automatically when cocos2d.h/axmol.h and tolua_fix.h are included.

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

namespace gclient::lua_bind {

template <size_t N>
struct FixedName {
    char data[N]{};
    constexpr FixedName(const char (&str)[N]) noexcept {
        for (size_t i = 0; i < N; ++i) data[i] = str[i];
    }
    constexpr const char* c_str() const noexcept { return data; }
};

inline int toAbsIndex(lua_State* L, int idx) noexcept {
    if (idx < 0 && idx > LUA_REGISTRYINDEX) {
        return lua_gettop(L) + idx + 1;
    }
    return idx;
}

// Supports both colon `Obj:method(a, b)` (self table/userdata at index 1) and dot `Obj.method(a, b)`.
inline int firstArgIndex(lua_State* L) noexcept {
    if (lua_gettop(L) >= 1 && (lua_istable(L, 1) || lua_isuserdata(L, 1))) {
        return 2;
    }
    return 1;
}

inline std::string optString(lua_State* L, int idx, const char* fallback = "") {
    if (idx > 0 && idx <= lua_gettop(L) && lua_isstring(L, idx)) {
        size_t len = 0;
        const char* s = lua_tolstring(L, idx, &len);
        return s ? std::string(s, len) : std::string(fallback ? fallback : "");
    }
    return std::string(fallback ? fallback : "");
}

inline const char* optCString(lua_State* L, int idx, const char* fallback = "") noexcept {
    if (idx > 0 && idx <= lua_gettop(L) && lua_isstring(L, idx)) {
        const char* s = lua_tostring(L, idx);
        return s ? s : fallback;
    }
    return fallback;
}

template <typename T = int>
    requires (std::integral<T> && !std::same_as<T, bool>)
inline T optInt(lua_State* L, int idx, T fallback = T{0}) noexcept {
    if (idx > 0 && idx <= lua_gettop(L) && lua_isnumber(L, idx)) {
        return static_cast<T>(lua_tonumber(L, idx));
    }
    return fallback;
}

inline bool optBool(lua_State* L, int idx, bool fallback = false) noexcept {
    if (idx > 0 && idx <= lua_gettop(L)) {
        if (lua_isboolean(L, idx)) return lua_toboolean(L, idx) != 0;
        if (lua_isnumber(L, idx)) return lua_tonumber(L, idx) != 0.0;
    }
    return fallback;
}

template <std::floating_point T = double>
inline T optFloat(lua_State* L, int idx, T fallback = T{0}) noexcept {
    if (idx > 0 && idx <= lua_gettop(L) && lua_isnumber(L, idx)) {
        return static_cast<T>(lua_tonumber(L, idx));
    }
    return fallback;
}

template <typename T>
struct FlexArgTraits;

template <>
struct FlexArgTraits<bool> {
    static bool get(lua_State* L, int idx) noexcept { return optBool(L, idx, false); }
};

template <typename T>
    requires (std::integral<T> && !std::same_as<T, bool>)
struct FlexArgTraits<T> {
    static T get(lua_State* L, int idx) noexcept { return optInt<T>(L, idx, T{0}); }
};

template <std::floating_point T>
struct FlexArgTraits<T> {
    static T get(lua_State* L, int idx) noexcept { return optFloat<T>(L, idx, T{0}); }
};

template <>
struct FlexArgTraits<const char*> {
    static const char* get(lua_State* L, int idx) noexcept { return optCString(L, idx, ""); }
};

template <>
struct FlexArgTraits<std::string> {
    static std::string get(lua_State* L, int idx) { return optString(L, idx, ""); }
};

template <>
struct FlexArgTraits<std::string_view> {
    static std::string_view get(lua_State* L, int idx) noexcept {
        if (idx > 0 && idx <= lua_gettop(L) && lua_isstring(L, idx)) {
            size_t len = 0;
            const char* s = lua_tolstring(L, idx, &len);
            if (s) return std::string_view(s, len);
        }
        return {};
    }
};

template <typename R>
inline int pushFlexReturn(lua_State* L, R&& val) {
    using CleanR = std::remove_cvref_t<R>;
    if constexpr (std::same_as<CleanR, bool>) {
        lua_pushboolean(L, val ? 1 : 0);
        return 1;
    } else if constexpr (std::integral<CleanR> && sizeof(CleanR) <= sizeof(lua_Integer) && std::is_signed_v<CleanR>) {
        lua_pushinteger(L, static_cast<lua_Integer>(val));
        return 1;
    } else if constexpr (std::integral<CleanR> || std::floating_point<CleanR>) {
        lua_pushnumber(L, static_cast<lua_Number>(val));
        return 1;
    } else if constexpr (std::same_as<CleanR, std::string> || std::same_as<CleanR, std::string_view>) {
        lua_pushlstring(L, val.data(), val.size());
        return 1;
    } else if constexpr (std::same_as<CleanR, const char*>) {
        if (val) lua_pushstring(L, val);
        else lua_pushstring(L, "");
        return 1;
    } else {
        static_assert(sizeof(CleanR) == 0, "Unsupported return type in pushFlexReturn");
        return 0;
    }
}

namespace detail {

template <typename R, typename... Args, size_t... Is>
inline int invokeFlexStaticImpl(lua_State* L, R (*fn)(Args...), int base, std::index_sequence<Is...>) {
    if constexpr (std::is_void_v<R>) {
        fn(FlexArgTraits<std::remove_cvref_t<Args>>::get(L, base + static_cast<int>(Is))...);
        return 0;
    } else {
        return pushFlexReturn(L, fn(FlexArgTraits<std::remove_cvref_t<Args>>::get(L, base + static_cast<int>(Is))...));
    }
}

template <typename Class, typename R, typename... Args, size_t... Is>
inline int invokeFlexMemberImpl(lua_State* L, Class* self, R (Class::*fn)(Args...), int base, std::index_sequence<Is...>) {
    if (!self) return 0;
    if constexpr (std::is_void_v<R>) {
        (self->*fn)(FlexArgTraits<std::remove_cvref_t<Args>>::get(L, base + static_cast<int>(Is))...);
        return 0;
    } else {
        return pushFlexReturn(L, (self->*fn)(FlexArgTraits<std::remove_cvref_t<Args>>::get(L, base + static_cast<int>(Is))...));
    }
}

template <typename Class, typename R, typename... Args, size_t... Is>
inline int invokeFlexConstMemberImpl(lua_State* L, const Class* self, R (Class::*fn)(Args...) const, int base, std::index_sequence<Is...>) {
    if (!self) return 0;
    if constexpr (std::is_void_v<R>) {
        (self->*fn)(FlexArgTraits<std::remove_cvref_t<Args>>::get(L, base + static_cast<int>(Is))...);
        return 0;
    } else {
        return pushFlexReturn(L, (self->*fn)(FlexArgTraits<std::remove_cvref_t<Args>>::get(L, base + static_cast<int>(Is))...));
    }
}

template <typename FnPtr>
struct FunctionTraits;

template <typename R, typename... Args>
struct FunctionTraits<R (*)(Args...)> {
    using ReturnType = R;
    using ArgsTuple = std::tuple<Args...>;
    static constexpr size_t kArity = sizeof...(Args);
    static int callFlex(lua_State* L, R (*fn)(Args...), int base) {
        return invokeFlexStaticImpl(L, fn, base, std::index_sequence_for<Args...>{});
    }
};

template <typename Class, typename R, typename... Args>
struct FunctionTraits<R (Class::*)(Args...)> {
    using ClassType = Class;
    using ReturnType = R;
    using ArgsTuple = std::tuple<Args...>;
    static constexpr size_t kArity = sizeof...(Args);
    static int callFlex(lua_State* L, Class* self, R (Class::*fn)(Args...), int base) {
        return invokeFlexMemberImpl(L, self, fn, base, std::index_sequence_for<Args...>{});
    }
};

template <typename Class, typename R, typename... Args>
struct FunctionTraits<R (Class::*)(Args...) const> {
    using ClassType = Class;
    using ReturnType = R;
    using ArgsTuple = std::tuple<Args...>;
    static constexpr size_t kArity = sizeof...(Args);
    static int callFlex(lua_State* L, const Class* self, R (Class::*fn)(Args...) const, int base) {
        return invokeFlexConstMemberImpl(L, self, fn, base, std::index_sequence_for<Args...>{});
    }
};

} // namespace detail

// Permissive static/free-function Lua wrapper supporting both `Mod:fn(...)` and `Mod.fn(...)`.
template <auto Fn>
int bindFlexStatic(lua_State* L) {
    const int base = firstArgIndex(L);
    return detail::FunctionTraits<decltype(Fn)>::callFlex(L, Fn, base);
}

// Permissive singleton method wrapper supporting both `Platform:method(...)` and `Platform.method(...)`.
template <auto GetInstanceFn, auto MemberFn>
int bindFlexSingleton(lua_State* L) {
    auto* inst = GetInstanceFn();
    const int base = firstArgIndex(L);
    return detail::FunctionTraits<decltype(MemberFn)>::callFlex(L, inst, MemberFn, base);
}

inline void registerMethodTable(lua_State* L, int tableIdx, std::span<const luaL_Reg> regs) {
    const int absIdx = toAbsIndex(L, tableIdx);
    for (const auto& r : regs) {
        if (r.name && r.func) {
            lua_pushcfunction(L, r.func);
            lua_setfield(L, absIdx, r.name);
        }
    }
}

// ============================================================================
// Layer 2: Axmol ax::Object & tolua++ Type-Safe Binding Templates
// ============================================================================
#if !defined(GCLIENT_STANDALONE_BUILD) && (defined(GCLIENT_USE_COCOS2DX) || defined(__AXMOL_H__) || defined(__COCOS2D_H__)) && __has_include("tolua++.h")
#include "tolua++.h"
#if __has_include("lua-bindings/manual/tolua_fix.h")
#include "lua-bindings/manual/tolua_fix.h"
#elif __has_include("tolua_fix.h")
#include "tolua_fix.h"
#endif

inline ax::Object* extractAxObject(lua_State* L, int idx, const char* expectedType = nullptr) {
    if (!L) return nullptr;
    const int absIdx = toAbsIndex(L, idx);
    if (absIdx <= 0 || absIdx > lua_gettop(L)) return nullptr;

    tolua_Error err{};
    const char* checkType = (expectedType && *expectedType) ? expectedType : "CCObject";
    const int t = lua_type(L, absIdx);
    if (t == LUA_TUSERDATA) {
        if (tolua_isusertype(L, absIdx, checkType, 0, &err) ||
            tolua_isusertype(L, absIdx, "ax.Object", 0, &err) ||
            tolua_isusertype(L, absIdx, "CCObject", 0, &err)) {
            return static_cast<ax::Object*>(tolua_tousertype(L, absIdx, nullptr));
        }
        return nullptr;
    }
    if (t == LUA_TTABLE) {
        lua_pushvalue(L, absIdx);
        for (int depth = 0; depth < 4; ++depth) {
            if (!lua_istable(L, -1)) break;
            lua_pushlstring(L, ".c_instance", 11);
            lua_rawget(L, -2);
            if (lua_isnil(L, -1)) {
                lua_pop(L, 1);
                lua_getfield(L, -1, ".c_instance");
            }
            lua_remove(L, -2);
            if (lua_type(L, -1) == LUA_TUSERDATA) {
                ax::Object* obj = nullptr;
                if (tolua_isusertype(L, -1, checkType, 0, &err) ||
                    tolua_isusertype(L, -1, "ax.Object", 0, &err) ||
                    tolua_isusertype(L, -1, "CCObject", 0, &err)) {
                    obj = static_cast<ax::Object*>(tolua_tousertype(L, -1, nullptr));
                }
                lua_pop(L, 1);
                return obj;
            }
        }
        lua_pop(L, 1);
    }
    return nullptr;
}

template <typename T>
    requires std::derived_from<T, ax::Object>
inline T* getAxObject(lua_State* L, int idx, const char* expectedType = nullptr) {
    ax::Object* obj = extractAxObject(L, idx, expectedType);
    return obj ? dynamic_cast<T*>(obj) : nullptr;
}

template <typename T>
    requires std::derived_from<T, ax::Object>
inline void pushAxObject(lua_State* L, T* obj, const char* typeName = "ax.Object") {
    if (!obj) {
        lua_pushnil(L);
        return;
    }
    ax::Object* baseObj = static_cast<ax::Object*>(obj);
    const int nID = static_cast<int>(baseObj->_ID);
    int* pLuaID = &baseObj->_luaID;
    toluafix_pushusertype_object(
        L, nID, pLuaID, static_cast<void*>(baseObj), (typeName && *typeName) ? typeName : "ax.Object");
}

template <typename T>
struct ToluaObjTag {
    static constexpr const char* name = "ax.Object";
};

template <typename T>
struct ToluaArgTraits;

template <>
struct ToluaArgTraits<bool> {
    static bool check(lua_State* L, int idx, tolua_Error* err) { return tolua_isboolean(L, idx, 0, err) != 0; }
    static bool get(lua_State* L, int idx) { return tolua_toboolean(L, idx, 0) != 0; }
};

template <typename T>
    requires (std::integral<T> && !std::same_as<T, bool>)
struct ToluaArgTraits<T> {
    static bool check(lua_State* L, int idx, tolua_Error* err) { return tolua_isnumber(L, idx, 0, err) != 0; }
    static T get(lua_State* L, int idx) { return static_cast<T>(tolua_tonumber(L, idx, 0)); }
};

template <std::floating_point T>
struct ToluaArgTraits<T> {
    static bool check(lua_State* L, int idx, tolua_Error* err) { return tolua_isnumber(L, idx, 0, err) != 0; }
    static T get(lua_State* L, int idx) { return static_cast<T>(tolua_tonumber(L, idx, 0)); }
};

template <>
struct ToluaArgTraits<const char*> {
    static bool check(lua_State* L, int idx, tolua_Error* err) { return tolua_isstring(L, idx, 0, err) != 0; }
    static const char* get(lua_State* L, int idx) {
        const char* s = tolua_tostring(L, idx, "");
        return s ? s : "";
    }
};

template <>
struct ToluaArgTraits<std::string> {
    static bool check(lua_State* L, int idx, tolua_Error* err) { return tolua_iscppstring(L, idx, 0, err) != 0; }
    static std::string get(lua_State* L, int idx) {
        size_t len = 0;
        const char* s = lua_tolstring(L, idx, &len);
        return s ? std::string(s, len) : std::string{};
    }
};

template <typename T>
    requires std::derived_from<std::remove_const_t<T>, ax::Object>
struct ToluaArgTraits<T*> {
    using RawT = std::remove_const_t<T>;
    static bool check(lua_State* L, int idx, tolua_Error* err) {
        return lua_isnil(L, idx) || tolua_isusertype(L, idx, ToluaObjTag<RawT>::name, 0, err) != 0 ||
               extractAxObject(L, idx, ToluaObjTag<RawT>::name) != nullptr;
    }
    static T* get(lua_State* L, int idx) { return getAxObject<RawT>(L, idx, ToluaObjTag<RawT>::name); }
};

template <typename R>
inline int pushToluaReturn(lua_State* L, R&& val, const char* explicitObjTag = nullptr) {
    using CleanR = std::remove_cvref_t<R>;
    if constexpr (std::same_as<CleanR, bool>) {
        tolua_pushboolean(L, val ? 1 : 0);
        return 1;
    } else if constexpr (std::integral<CleanR> || std::floating_point<CleanR>) {
        tolua_pushnumber(L, static_cast<lua_Number>(val));
        return 1;
    } else if constexpr (std::same_as<CleanR, std::string>) {
        tolua_pushcppstring(L, val);
        return 1;
    } else if constexpr (std::same_as<CleanR, const char*>) {
        tolua_pushstring(L, val ? val : "");
        return 1;
    } else if constexpr (std::is_pointer_v<CleanR> &&
                         std::derived_from<std::remove_const_t<std::remove_pointer_t<CleanR>>, ax::Object>) {
        using ObjT = std::remove_const_t<std::remove_pointer_t<CleanR>>;
        const char* tag = explicitObjTag ? explicitObjTag : ToluaObjTag<ObjT>::name;
        pushAxObject(L, const_cast<ObjT*>(val), tag);
        return 1;
    } else {
        static_assert(sizeof(CleanR) == 0, "Unsupported return type in pushToluaReturn");
        return 0;
    }
}

namespace tolua_detail {

template <FixedName ClassTag, FixedName FnName, bool CheckNoObj, typename R, typename... Args, size_t... Is>
int invokeToluaStatic(lua_State* L, R (*fn)(Args...), const char* retTag, std::index_sequence<Is...>) {
    tolua_Error err{};
    const bool ok = (tolua_isusertable(L, 1, ClassTag.c_str(), 0, &err) != 0) &&
                    (ToluaArgTraits<std::remove_cvref_t<Args>>::check(L, 2 + static_cast<int>(Is), &err) && ...) &&
                    (!CheckNoObj || tolua_isnoobj(L, 2 + static_cast<int>(sizeof...(Args)), &err) != 0);
    if (!ok) {
        std::string msg = std::string("#ferror in function '") + FnName.c_str() + "'.";
        tolua_error(L, msg.c_str(), &err);
        return 0;
    }
    if constexpr (std::is_void_v<R>) {
        fn(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...);
        return 0;
    } else {
        return pushToluaReturn(
            L,
            fn(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...),
            retTag);
    }
}

template <typename Class, FixedName ClassTag, FixedName FnName, bool CheckNoObj, typename R, typename... Args, size_t... Is>
int invokeToluaMethod(lua_State* L, R (Class::*fn)(Args...), const char* retTag, std::index_sequence<Is...>) {
    tolua_Error err{};
    const bool selfOk = (tolua_isusertype(L, 1, ClassTag.c_str(), 0, &err) != 0) ||
                        (getAxObject<Class>(L, 1, ClassTag.c_str()) != nullptr);
    const bool ok = selfOk &&
                    (ToluaArgTraits<std::remove_cvref_t<Args>>::check(L, 2 + static_cast<int>(Is), &err) && ...) &&
                    (!CheckNoObj || tolua_isnoobj(L, 2 + static_cast<int>(sizeof...(Args)), &err) != 0);
    if (!ok) {
        std::string msg = std::string("#ferror in function '") + FnName.c_str() + "'.";
        tolua_error(L, msg.c_str(), &err);
        return 0;
    }
    auto* self = getAxObject<Class>(L, 1, ClassTag.c_str());
    if constexpr (std::is_void_v<R>) {
        if (self) (self->*fn)(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...);
        return 0;
    } else {
        if (!self) { lua_pushnil(L); return 1; }
        return pushToluaReturn(
            L,
            (self->*fn)(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...),
            retTag);
    }
}

template <typename Class, FixedName ClassTag, FixedName FnName, bool CheckNoObj, typename R, typename... Args, size_t... Is>
int invokeToluaConstMethod(lua_State* L, R (Class::*fn)(Args...) const, const char* retTag, std::index_sequence<Is...>) {
    tolua_Error err{};
    const bool selfOk = (tolua_isusertype(L, 1, ClassTag.c_str(), 0, &err) != 0) ||
                        (getAxObject<Class>(L, 1, ClassTag.c_str()) != nullptr);
    const bool ok = selfOk &&
                    (ToluaArgTraits<std::remove_cvref_t<Args>>::check(L, 2 + static_cast<int>(Is), &err) && ...) &&
                    (!CheckNoObj || tolua_isnoobj(L, 2 + static_cast<int>(sizeof...(Args)), &err) != 0);
    if (!ok) {
        std::string msg = std::string("#ferror in function '") + FnName.c_str() + "'.";
        tolua_error(L, msg.c_str(), &err);
        return 0;
    }
    const auto* self = getAxObject<Class>(L, 1, ClassTag.c_str());
    if constexpr (std::is_void_v<R>) {
        if (self) (self->*fn)(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...);
        return 0;
    } else {
        if (!self) { lua_pushnil(L); return 1; }
        return pushToluaReturn(
            L,
            (self->*fn)(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...),
            retTag);
    }
}

template <typename FnPtr>
struct ToluaDispatcher;

template <typename R, typename... Args>
struct ToluaDispatcher<R (*)(Args...)> {
    template <FixedName ClassTag, FixedName FnName, bool CheckNoObj>
    static int call(lua_State* L, R (*fn)(Args...), const char* retTag) {
        return invokeToluaStatic<ClassTag, FnName, CheckNoObj>(L, fn, retTag, std::index_sequence_for<Args...>{});
    }
};

template <typename Class, typename R, typename... Args>
struct ToluaDispatcher<R (Class::*)(Args...)> {
    template <FixedName ClassTag, FixedName FnName, bool CheckNoObj>
    static int call(lua_State* L, R (Class::*fn)(Args...), const char* retTag) {
        return invokeToluaMethod<Class, ClassTag, FnName, CheckNoObj>(L, fn, retTag, std::index_sequence_for<Args...>{});
    }
};

template <typename Class, typename R, typename... Args>
struct ToluaDispatcher<R (Class::*)(Args...) const> {
    template <FixedName ClassTag, FixedName FnName, bool CheckNoObj>
    static int call(lua_State* L, R (Class::*fn)(Args...) const, const char* retTag) {
        return invokeToluaConstMethod<Class, ClassTag, FnName, CheckNoObj>(L, fn, retTag, std::index_sequence_for<Args...>{});
    }
};

template <typename Class, typename R, typename... Args, size_t... Is>
int invokeAxPermissive(lua_State* L, R (Class::*fn)(Args...), const char* retTag, std::index_sequence<Is...>) {
    auto* self = getAxObject<Class>(L, 1);
    if (!self) {
        if constexpr (std::is_void_v<R>) return 0;
        else if constexpr (std::same_as<std::remove_cvref_t<R>, bool>) { lua_pushboolean(L, 0); return 1; }
        else if constexpr (std::integral<std::remove_cvref_t<R>> || std::floating_point<std::remove_cvref_t<R>>) { lua_pushnumber(L, 0); return 1; }
        else { lua_pushnil(L); return 1; }
    }
    if constexpr (std::is_void_v<R>) {
        (self->*fn)(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...);
        return 0;
    } else {
        return pushToluaReturn(
            L,
            (self->*fn)(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...),
            retTag);
    }
}

template <typename Class, typename R, typename... Args, size_t... Is>
int invokeAxPermissiveConst(lua_State* L, R (Class::*fn)(Args...) const, const char* retTag, std::index_sequence<Is...>) {
    const auto* self = getAxObject<Class>(L, 1);
    if (!self) {
        if constexpr (std::is_void_v<R>) return 0;
        else if constexpr (std::same_as<std::remove_cvref_t<R>, bool>) { lua_pushboolean(L, 0); return 1; }
        else if constexpr (std::integral<std::remove_cvref_t<R>> || std::floating_point<std::remove_cvref_t<R>>) { lua_pushnumber(L, 0); return 1; }
        else { lua_pushnil(L); return 1; }
    }
    if constexpr (std::is_void_v<R>) {
        (self->*fn)(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...);
        return 0;
    } else {
        return pushToluaReturn(
            L,
            (self->*fn)(ToluaArgTraits<std::remove_cvref_t<Args>>::get(L, 2 + static_cast<int>(Is))...),
            retTag);
    }
}

template <typename FnPtr>
struct AxPermissiveDispatcher;

template <typename Class, typename R, typename... Args>
struct AxPermissiveDispatcher<R (Class::*)(Args...)> {
    static int call(lua_State* L, R (Class::*fn)(Args...), const char* retTag) {
        return invokeAxPermissive<Class>(L, fn, retTag, std::index_sequence_for<Args...>{});
    }
};

template <typename Class, typename R, typename... Args>
struct AxPermissiveDispatcher<R (Class::*)(Args...) const> {
    static int call(lua_State* L, R (Class::*fn)(Args...) const, const char* retTag) {
        return invokeAxPermissiveConst<Class>(L, fn, retTag, std::index_sequence_for<Args...>{});
    }
};

} // namespace tolua_detail

// Strict tolua++ static or member wrapper with `#ferror in function '...'` checking:
// Usage: `bindTolua<"BTUtil", "randomseed", &BTUtil::randomseed>` or `bindTolua<"CLuaFuncs", "removeHandler", &CLuaFuncs::removeHandler>`
template <FixedName ClassTag, FixedName FnName, auto Fn, bool CheckNoObj = true>
int bindTolua(lua_State* L) {
    return tolua_detail::ToluaDispatcher<decltype(Fn)>::template call<ClassTag, FnName, CheckNoObj>(L, Fn, nullptr);
}

template <FixedName ClassTag, FixedName FnName, FixedName RetObjTag, auto Fn, bool CheckNoObj = true>
int bindToluaObjRet(lua_State* L) {
    return tolua_detail::ToluaDispatcher<decltype(Fn)>::template call<ClassTag, FnName, CheckNoObj>(L, Fn, RetObjTag.c_str());
}

// Permissive Axmol method wrapper (no tolua_error on nil/defaulted args, ideal for Axmol226Compat & LuaHelpers):
template <auto MemberFn>
int bindAxMethod(lua_State* L) {
    return tolua_detail::AxPermissiveDispatcher<decltype(MemberFn)>::call(L, MemberFn, nullptr);
}

template <FixedName RetObjTag, auto MemberFn>
int bindAxMethodObjRet(lua_State* L) {
    return tolua_detail::AxPermissiveDispatcher<decltype(MemberFn)>::call(L, MemberFn, RetObjTag.c_str());
}

#endif // Layer 2 Axmol + tolua++

} // namespace gclient::lua_bind
