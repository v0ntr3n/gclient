#include "tolua_BTUtil.h"
#include "BTUtil.h"

#ifndef GCLIENT_USE_COCOS2DX
#define GCLIENT_USE_COCOS2DX 1
#endif

#include "CCLuaEngine.h"
#include "cocos2d.h"
#include "tolua_fix.h"
#include "LuaBindTemplates.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

USING_NS_CC;

namespace gclient::lua_bind {

template <> struct ToluaObjTag<CCString>     { static constexpr const char* name = "CCString"; };
template <> struct ToluaObjTag<CCArray>      { static constexpr const char* name = "CCArray"; };
template <> struct ToluaObjTag<CCDictionary> { static constexpr const char* name = "CCDictionary"; };
template <> struct ToluaObjTag<CCInteger>    { static constexpr const char* name = "CCInteger"; };

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

void tolua_reg_types_BTUtil(lua_State* tolua_S) {
    static constexpr const char* kTypes[] = {
        "CCPoint", "CCString", "cocos2d::CCLuaValue", "ClassInfo", "BTUtil",
        "vector<string>", "CCInteger", "cocos2d::CCArray", "CCObject", "CCDictionary", "CCArray"
    };
    for (const char* t : kTypes) {
        tolua_usertype(tolua_S, t);
    }
}

// Preserves exact tolua++ 2-return-value convention `(ret, str)` for `std::string&` signatures.
template <FixedName FnName, auto Fn>
int bindBTUtilStrRef(lua_State* tolua_S) {
    tolua_Error err{};
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &err) ||
        !tolua_isnoobj(tolua_S, 3, &err)) {
        const std::string msg = std::string("#ferror in function '") + FnName.c_str() + "'.";
        tolua_error(tolua_S, msg.c_str(), &err);
        return 0;
    }
    std::string input = ToluaArgTraits<std::string>::get(tolua_S, 2);
    pushToluaReturn(tolua_S, Fn(input), "CCArray");
    tolua_pushcppstring(tolua_S, input);
    return 2;
}

// BTUtil::split(std::string& str, std::string/char delim, vector<string>& out) -> (bool, str)
int tolua_BTUtil_split00(lua_State* tolua_S) {
    tolua_Error tolua_err{};
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 2, 0, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'split'.", &tolua_err);
        return 0;
    }

    std::string str = ToluaArgTraits<std::string>::get(tolua_S, 2);
    auto* outVec = (lua_type(tolua_S, 4) == LUA_TUSERDATA &&
                    tolua_isusertype(tolua_S, 4, "vector<string>", 0, &tolua_err))
        ? static_cast<std::vector<std::string>*>(tolua_tousertype(tolua_S, 4, nullptr))
        : nullptr;
    std::vector<std::string> localOut;
    std::vector<std::string>& target = outVec ? *outVec : localOut;

    bool ok = false;
    if (tolua_isnumber(tolua_S, 3, 0, &tolua_err)) {
        ok = BTUtil::split(str, static_cast<char>(tolua_tonumber(tolua_S, 3, 0)), target);
    } else if (tolua_iscppstring(tolua_S, 3, 0, &tolua_err)) {
        ok = BTUtil::split(str, ToluaArgTraits<std::string>::get(tolua_S, 3), target);
    } else {
        tolua_error(tolua_S, "#ferror in function 'split'.", &tolua_err);
        return 0;
    }

    tolua_pushboolean(tolua_S, ok ? 1 : 0);
    tolua_pushcppstring(tolua_S, str);
    return 2;
}

// BTUtil::checkType(CCObject* obj, std::string& typeName) -> (bool, typeName)
// Safely accepts nil, non-CCObject values, and tolua.inherit `.c_instance` tables.
int tolua_BTUtil_checkType00(lua_State* tolua_S) {
    tolua_Error tolua_err{};
    if (!tolua_isusertable(tolua_S, 1, "BTUtil", 0, &tolua_err) ||
        !tolua_iscppstring(tolua_S, 3, 0, &tolua_err) ||
        !tolua_isnoobj(tolua_S, 4, &tolua_err)) {
        tolua_error(tolua_S, "#ferror in function 'checkType'.", &tolua_err);
        return 0;
    }
    CCObject* obj = extractAxObject(tolua_S, 2);
    std::string typeName(tolua_tocppstring(tolua_S, 3, ""));
    tolua_pushboolean(tolua_S, (obj && BTUtil::checkType(obj, typeName)) ? 1 : 0);
    tolua_pushcppstring(tolua_S, typeName);
    return 2;
}

// ClassInfo::description (5 overloads: CCPoint, CCInteger, CCString, CCDictionary, CCArray)
int tolua_BTUtil_ClassInfo_description(lua_State* tolua_S) {
    tolua_Error err{};
    if (tolua_isusertable(tolua_S, 1, "ClassInfo", 0, &err) && tolua_isnoobj(tolua_S, 3, &err)) {
        if (tolua_isusertype(tolua_S, 2, "CCPoint", 0, &err)) {
            auto* pt = (lua_type(tolua_S, 2) == LUA_TUSERDATA)
                ? static_cast<CCPoint*>(tolua_tousertype(tolua_S, 2, nullptr))
                : nullptr;
            const std::string desc = pt ? ClassInfo::description(*pt) : "CCPoint(null)";
            lua_pushlstring(tolua_S, desc.data(), desc.size());
            return 1;
        }
        if (tolua_isusertype(tolua_S, 2, "CCInteger", 0, &err)) {
            tolua_pushcppstring(tolua_S, ClassInfo::description(getAxObject<CCInteger>(tolua_S, 2, "CCInteger")));
            return 1;
        }
        if (tolua_isusertype(tolua_S, 2, "CCString", 0, &err)) {
            tolua_pushcppstring(tolua_S, ClassInfo::description(getAxObject<CCString>(tolua_S, 2, "CCString")));
            return 1;
        }
        if (tolua_isusertype(tolua_S, 2, "CCDictionary", 0, &err)) {
            tolua_pushcppstring(tolua_S, ClassInfo::description(getAxObject<CCDictionary>(tolua_S, 2, "CCDictionary")));
            return 1;
        }
        if (tolua_isusertype(tolua_S, 2, "CCArray", 0, &err)) {
            tolua_pushcppstring(tolua_S, ClassInfo::description(getAxObject<CCArray>(tolua_S, 2, "CCArray")));
            return 1;
        }
    }
    // Populate err against primary CCArray signature before emitting #ferror
    (void)(tolua_isusertable(tolua_S, 1, "ClassInfo", 0, &err) &&
           tolua_isusertype(tolua_S, 2, "CCArray", 0, &err) &&
           tolua_isnoobj(tolua_S, 3, &err));
    tolua_error(tolua_S, "#ferror in function 'description'.", &err);
    return 0;
}

} // namespace

TOLUA_API int tolua_BTUtil_open(lua_State* tolua_S) {
    tolua_open(tolua_S);
    tolua_reg_types_BTUtil(tolua_S);
    tolua_module(tolua_S, nullptr, 0);
    tolua_beginmodule(tolua_S, nullptr);

    tolua_constant(tolua_S, "kBT_PLATFORM_IOS", static_cast<lua_Number>(kBT_PLATFORM_IOS));
    tolua_constant(tolua_S, "kBT_PLATFORM_ANDROID", static_cast<lua_Number>(kBT_PLATFORM_ANDROID));

    tolua_cclass(tolua_S, "BTUtil", "BTUtil", "", nullptr);
    tolua_beginmodule(tolua_S, "BTUtil");
    tolua_function(tolua_S, "randomseed", bindTolua<"BTUtil", "randomseed", &BTUtil::randomseed>);
    tolua_function(tolua_S, "random", bindTolua<"BTUtil", "random", &BTUtil::random>);
    tolua_function(tolua_S, "split", tolua_BTUtil_split00);
    tolua_function(tolua_S, "cutString", bindToluaObjRet<"BTUtil", "cutString", "CCArray", &BTUtil::cutString>);
    tolua_function(tolua_S, "splitString", bindBTUtilStrRef<"splitString", &BTUtil::splitString>);
    tolua_function(tolua_S, "checkType", tolua_BTUtil_checkType00);
    tolua_function(tolua_S, "getSvrTimeInterval", bindTolua<"BTUtil", "getSvrTimeInterval", &BTUtil::getSvrTimeInterval>);
    tolua_function(tolua_S, "syncTime", bindTolua<"BTUtil", "syncTime", &BTUtil::syncTime>);
    tolua_function(tolua_S, "getPlatform", bindTolua<"BTUtil", "getPlatform", &BTUtil::getPlatform>);
    tolua_function(tolua_S, "setGuideState", bindTolua<"BTUtil", "setGuideState", &BTUtil::setGuideState>);
    tolua_function(tolua_S, "getGuideState", bindTolua<"BTUtil", "getGuideState", &BTUtil::getGuideState>);
    tolua_function(tolua_S, "isSimulator", bindTolua<"BTUtil", "isSimulator", &BTUtil::isSimulator>);
    tolua_function(tolua_S, "getDebugStatus", bindTolua<"BTUtil", "getDebugStatus", &BTUtil::getDebugStatus>);
    tolua_function(tolua_S, "unscheduleAll", bindTolua<"BTUtil", "unscheduleAll", &BTUtil::unscheduleAll>);
    tolua_function(tolua_S, "isAppStore", bindTolua<"BTUtil", "isAppStore", &BTUtil::isAppStore>);
    tolua_function(tolua_S, "getMd5SumByString", bindBTUtilStrRef<"getMd5SumByString", &BTUtil::getMd5SumByString>);
    tolua_function(tolua_S, "getLuaOrigPackagePath", bindTolua<"BTUtil", "getLuaOrigPackagePath", &BTUtil::getLuaOrigPackagePath>);
    tolua_function(tolua_S, "insertToSearchPathBegin", bindTolua<"BTUtil", "insertToSearchPathBegin", &BTUtil::insertToSearchPathBegin>);
    tolua_function(tolua_S, "getBTOnlineType", bindTolua<"BTUtil", "getBTOnlineType", &BTUtil::getBTOnlineType>);
    tolua_function(tolua_S, "sortUrlString", bindBTUtilStrRef<"sortUrlString", &BTUtil::sortUrlString>);
    tolua_function(tolua_S, "exitNow", bindTolua<"BTUtil", "exitNow", &BTUtil::exitNow>);
    tolua_function(tolua_S, "TimeStart", bindTolua<"BTUtil", "TimeStart", &BTUtil::TimeStart>);
    tolua_function(tolua_S, "TimeEnd", bindTolua<"BTUtil", "TimeEnd", &BTUtil::TimeEnd>);
    tolua_endmodule(tolua_S);

    tolua_cclass(tolua_S, "ClassInfo", "ClassInfo", "", nullptr);
    tolua_beginmodule(tolua_S, "ClassInfo");
    tolua_function(tolua_S, "description", tolua_BTUtil_ClassInfo_description);
    tolua_endmodule(tolua_S);

    tolua_endmodule(tolua_S);
    return 1;
}
