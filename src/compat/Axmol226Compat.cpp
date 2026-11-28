#include "compat/Axmol226Compat.h"
#include "assets/BtDecryptHook.h"
#include "common/KestrelBinaryReader.h"
#include "diagnostics/CrashAndTelemetry.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}
#include "tolua++.h"
#if __has_include("lua-bindings/manual/tolua_fix.h")
#include "lua-bindings/manual/tolua_fix.h"
#elif __has_include("tolua_fix.h")
#include "tolua_fix.h"
#endif
#include "bindings/LuaBindTemplates.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <initializer_list>
#include <span>

namespace ax {

namespace {

std::string formatVaList(const char* fmt, va_list args) {
    char buf[4096];
    std::vsnprintf(buf, sizeof(buf), fmt, args);
    return std::string(buf);
}

ax::Object* valueToCompatObject(const ax::Value& v) {
    switch (v.getType()) {
        case ax::Value::Type::STRING:
        case ax::Value::Type::FLOAT:
        case ax::Value::Type::DOUBLE:   return CCString::create(v.asString());
        case ax::Value::Type::INT_I32:  return CCString::create(std::to_string(v.asInt()));
        case ax::Value::Type::INT_UI32: return CCString::create(std::to_string(v.asUnsignedInt()));
        case ax::Value::Type::INT_I64:  return CCString::create(std::to_string(v.asInt64()));
        case ax::Value::Type::INT_UI64: return CCString::create(std::to_string(v.asUint64()));
        case ax::Value::Type::BOOLEAN:  return CCString::create(v.asBool() ? "true" : "false");
        case ax::Value::Type::VECTOR: {
            auto* arr = CCArray::create();
            for (const auto& elem : v.asValueVector()) {
                if (auto* child = valueToCompatObject(elem)) arr->addObject(child);
            }
            return arr;
        }
        case ax::Value::Type::MAP: {
            auto* dict = CCDictionary::create();
            for (const auto& [k, val] : v.asValueMap()) {
                if (auto* child = valueToCompatObject(val)) dict->setObject(child, k);
            }
            return dict;
        }
        default: return CCString::create("");
    }
}

void resetWidgetHighlightRecursive(ax::Node* node) {
    if (!node) return;
    if (auto* widget = dynamic_cast<ax::ui::Widget*>(node)) widget->setHighlighted(false);
    for (auto* child : node->getChildren()) resetWidgetHighlightRecursive(child);
}

template <typename DirectPred, typename SeekFn>
ax::ui::Widget* seekInContainer(ax::Node* container, DirectPred&& pred, SeekFn&& seekFn) {
    for (auto* child : container->getChildren()) {
        if (auto* w = dynamic_cast<ax::ui::Widget*>(child)) {
            if (pred(w)) return w;
            if (auto* found = seekFn(w)) return found;
        }
    }
    return nullptr;
}

} // namespace

void CCLog(const char* format, ...) {
    if (!format) return;
    va_list args;
    va_start(args, format);
    const std::string msg = formatVaList(format, args);
    va_end(args);
    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info, "CCLog", "%s", msg.c_str());
}

CCString* CCString::createWithFormat(const char* fmt, ...) {
    if (!fmt) return create("");
    va_list args;
    va_start(args, fmt);
    const std::string msg = formatVaList(fmt, args);
    va_end(args);
    return create(msg);
}

CCDictionary* CCDictionary::createWithContentsOfFile(const char* fileName) {
    if (!fileName || !*fileName) return create();
    auto* fu = ax::FileUtils::getInstance();
    if (!fu) return create();
    auto* dict = create();
    for (const auto& [k, v] : fu->getValueMapFromFile(gclient::compat::ResolveConvertedAssetPath(fileName))) {
        if (auto* obj = valueToCompatObject(v)) dict->setObject(obj, k);
    }
    return dict;
}

namespace ui {

bool TouchGroup::init() {
    if (!ax::Layer::init()) return false;
    m_rootWidget = ax::ui::Widget::create();
    if (m_rootWidget) {
        m_rootWidget->setTouchEnabled(false);
        addChild(m_rootWidget);
    }
    return true;
}

void TouchGroup::addWidget(ax::ui::Widget* widget) {
    if (!widget) return;
    if (m_rootWidget) m_rootWidget->addChild(widget);
    else addChild(widget);
}

void TouchGroup::removeWidget(ax::ui::Widget* widget) {
    if (!widget) return;
    if (m_rootWidget && widget->getParent() == m_rootWidget) m_rootWidget->removeChild(widget, true);
    else if (widget->getParent() == this) removeChild(widget, true);
}

ax::ui::Widget* TouchGroup::getWidgetByTag(int tag) {
    ax::Node* root = m_rootWidget ? static_cast<ax::Node*>(m_rootWidget) : static_cast<ax::Node*>(this);
    return seekInContainer(
        root,
        [tag](ax::ui::Widget* w) { return w->getTag() == tag; },
        [tag](ax::ui::Widget* w) { return ax::ui::Helper::seekWidgetByTag(w, tag); });
}

ax::ui::Widget* TouchGroup::getWidgetByName(const char* name) {
    if (!name || !*name) return nullptr;
    ax::Node* root = m_rootWidget ? static_cast<ax::Node*>(m_rootWidget) : static_cast<ax::Node*>(this);
    return seekInContainer(
        root,
        [name](ax::ui::Widget* w) { return w->getName() == name; },
        [name](ax::ui::Widget* w) { return ax::ui::Helper::seekWidgetByName(w, name); });
}

void TouchGroup::clear() {
    if (m_rootWidget) m_rootWidget->removeAllChildrenWithCleanup(true);
    else removeAllChildrenWithCleanup(true);
}

void TouchGroup::clearTouchStat() {
    if (m_rootWidget) resetWidgetHighlightRecursive(m_rootWidget);
    for (auto* child : getChildren()) {
        if (child != m_rootWidget) resetWidgetHighlightRecursive(child);
    }
}

} // namespace ui
} // namespace ax

namespace CocosDenshion {

namespace {
SimpleAudioEngine* g_sharedSimpleAudio = nullptr;
} // namespace

SimpleAudioEngine* SimpleAudioEngine::getInstance() {
    if (!g_sharedSimpleAudio) g_sharedSimpleAudio = new SimpleAudioEngine();
    return g_sharedSimpleAudio;
}

void SimpleAudioEngine::end() {
    if (g_sharedSimpleAudio) {
        g_sharedSimpleAudio->stopAllEffects();
        g_sharedSimpleAudio->stopBackgroundMusic(true);
        delete g_sharedSimpleAudio;
        g_sharedSimpleAudio = nullptr;
    }
    ax::AudioEngine::end();
}

std::string SimpleAudioEngine::resolveAudioPath(const char* rawPath) const {
    if (!rawPath || !*rawPath) return {};
    std::string norm = gclient::assets::NormalizeAssetPath(rawPath);
    auto* fu = ax::FileUtils::getInstance();
    if (!fu || fu->isFileExist(norm)) return norm;

    for (const char* ext : {".mp3", ".ogg", ".wav"}) {
        std::string cand = gclient::assets::ReplaceFileExtension(norm, ext);
        if (fu->isFileExist(cand)) return cand;
    }
    return norm;
}

void SimpleAudioEngine::preloadBackgroundMusic(const char* filePath) {
    if (const std::string p = resolveAudioPath(filePath); !p.empty()) ax::AudioEngine::preload(p);
}

void SimpleAudioEngine::playBackgroundMusic(const char* filePath, bool loop) {
    const std::string p = resolveAudioPath(filePath);
    if (p.empty()) return;
    if (m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID) {
        ax::AudioEngine::stop(m_bgAudioId);
        m_bgAudioId = ax::AudioEngine::INVALID_AUDIO_ID;
    }
    m_bgFilePath = p;
    m_bgLoop     = loop;
    m_bgAudioId  = ax::AudioEngine::play2d(p, loop, m_musicVolume);
}

void SimpleAudioEngine::stopBackgroundMusic(bool releaseData) {
    if (m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID) {
        ax::AudioEngine::stop(m_bgAudioId);
        m_bgAudioId = ax::AudioEngine::INVALID_AUDIO_ID;
    }
    if (releaseData && !m_bgFilePath.empty()) ax::AudioEngine::uncache(m_bgFilePath);
}

void SimpleAudioEngine::pauseBackgroundMusic() {
    if (m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID) ax::AudioEngine::pause(m_bgAudioId);
}

void SimpleAudioEngine::resumeBackgroundMusic() {
    if (m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID) ax::AudioEngine::resume(m_bgAudioId);
}

void SimpleAudioEngine::rewindBackgroundMusic() {
    if (m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID) ax::AudioEngine::setCurrentTime(m_bgAudioId, 0.0f);
    else if (!m_bgFilePath.empty()) playBackgroundMusic(m_bgFilePath.c_str(), m_bgLoop);
}

bool SimpleAudioEngine::isBackgroundMusicPlaying() {
    return m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID &&
           ax::AudioEngine::getState(m_bgAudioId) == ax::AudioEngine::AudioState::PLAYING;
}

void SimpleAudioEngine::setBackgroundMusicVolume(float volume) {
    m_musicVolume = std::clamp(volume, 0.0f, 1.0f);
    if (m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID) ax::AudioEngine::setVolume(m_bgAudioId, m_musicVolume);
}

void SimpleAudioEngine::setEffectsVolume(float volume) {
    m_effectsVolume = std::clamp(volume, 0.0f, 1.0f);
    for (int id : m_activeEffectIds) {
        if (ax::AudioEngine::getState(id) != ax::AudioEngine::AudioState::ERROR) {
            ax::AudioEngine::setVolume(id, m_effectsVolume);
        }
    }
}

unsigned int SimpleAudioEngine::playEffect(const char* filePath, bool loop,
                                           float /*pitch*/, float /*pan*/, float gain) {
    const std::string p = resolveAudioPath(filePath);
    if (p.empty()) return static_cast<unsigned int>(ax::AudioEngine::INVALID_AUDIO_ID);
    const int id = ax::AudioEngine::play2d(p, loop, std::clamp(m_effectsVolume * gain, 0.0f, 1.0f));
    if (id != ax::AudioEngine::INVALID_AUDIO_ID) {
        std::erase_if(m_activeEffectIds, [](int eid) {
            return ax::AudioEngine::getState(eid) == ax::AudioEngine::AudioState::ERROR;
        });
        m_activeEffectIds.push_back(id);
    }
    return static_cast<unsigned int>(id);
}

void SimpleAudioEngine::pauseEffect(unsigned int soundId) { ax::AudioEngine::pause(static_cast<int>(soundId)); }
void SimpleAudioEngine::pauseAllEffects() { for (int id : m_activeEffectIds) ax::AudioEngine::pause(id); }
void SimpleAudioEngine::resumeEffect(unsigned int soundId) { ax::AudioEngine::resume(static_cast<int>(soundId)); }
void SimpleAudioEngine::resumeAllEffects() { for (int id : m_activeEffectIds) ax::AudioEngine::resume(id); }

void SimpleAudioEngine::stopEffect(unsigned int soundId) {
    const int id = static_cast<int>(soundId);
    ax::AudioEngine::stop(id);
    std::erase(m_activeEffectIds, id);
}

void SimpleAudioEngine::stopAllEffects() {
    for (int id : m_activeEffectIds) ax::AudioEngine::stop(id);
    m_activeEffectIds.clear();
}

void SimpleAudioEngine::preloadEffect(const char* filePath) { preloadBackgroundMusic(filePath); }

void SimpleAudioEngine::unloadEffect(const char* filePath) {
    if (const std::string p = resolveAudioPath(filePath); !p.empty()) ax::AudioEngine::uncache(p);
}

} // namespace CocosDenshion

namespace gclient::compat {

namespace {

using gclient::lua_bind::FixedName;
using gclient::lua_bind::bindAxMethod;
using gclient::lua_bind::bindAxMethodObjRet;
using gclient::lua_bind::bindFlexSingleton;
using gclient::lua_bind::firstArgIndex;
using gclient::lua_bind::getAxObject;
using gclient::lua_bind::optBool;
using gclient::lua_bind::optCString;
using gclient::lua_bind::optFloat;
using gclient::lua_bind::optInt;
using gclient::lua_bind::pushAxObject;
using gclient::lua_bind::registerMethodTable;
using SAE = CocosDenshion::SimpleAudioEngine;

const char* inferAxObjectToluaType(ax::Object* obj) {
    if (!obj) return "ax.Object";
#define GCLIENT_TRY_TAG(CppType, TagStr) if (dynamic_cast<CppType*>(obj)) return TagStr
    GCLIENT_TRY_TAG(ax::CCString, "CCString");
    GCLIENT_TRY_TAG(ax::CCInteger, "CCInteger");
    GCLIENT_TRY_TAG(ax::CCArray, "CCArray");
    GCLIENT_TRY_TAG(ax::CCDictionary, "CCDictionary");
    GCLIENT_TRY_TAG(ax::ui::TouchGroup, "TouchGroup");
    GCLIENT_TRY_TAG(ax::ui::Button, "axui.Button");
    GCLIENT_TRY_TAG(ax::ui::ImageView, "axui.ImageView");
    GCLIENT_TRY_TAG(ax::ui::Text, "axui.Text");
    GCLIENT_TRY_TAG(ax::ui::TextAtlas, "axui.TextAtlas");
    GCLIENT_TRY_TAG(ax::ui::TextBMFont, "axui.TextBMFont");
    GCLIENT_TRY_TAG(ax::ui::LoadingBar, "axui.LoadingBar");
    GCLIENT_TRY_TAG(ax::ui::CheckBox, "axui.CheckBox");
    GCLIENT_TRY_TAG(ax::ui::Slider, "axui.Slider");
    GCLIENT_TRY_TAG(ax::ui::TextField, "axui.TextField");
    GCLIENT_TRY_TAG(ax::ui::ListView, "axui.ListView");
    GCLIENT_TRY_TAG(ax::ui::PageView, "axui.PageView");
    GCLIENT_TRY_TAG(ax::ui::ScrollView, "axui.ScrollView");
    GCLIENT_TRY_TAG(ax::ui::Layout, "axui.Layout");
    GCLIENT_TRY_TAG(ax::ui::Widget, "axui.Widget");
    GCLIENT_TRY_TAG(cocostudio::Armature, "ccs.Armature");
    GCLIENT_TRY_TAG(ax::Sprite, "ax.Sprite");
    GCLIENT_TRY_TAG(ax::Layer, "ax.Layer");
    GCLIENT_TRY_TAG(ax::Node, "ax.Node");
    GCLIENT_TRY_TAG(ax::FiniteTimeAction, "ax.FiniteTimeAction");
    GCLIENT_TRY_TAG(ax::Action, "ax.Action");
#undef GCLIENT_TRY_TAG
    return "ax.Object";
}

int pushTypedAxObject(lua_State* L, ax::Object* obj) {
    pushAxObject(L, obj, inferAxObjectToluaType(obj));
    return 1;
}

template <typename T, FixedName Tag>
int lua_createDefault(lua_State* L) {
    pushAxObject(L, T::create(), Tag.c_str());
    return 1;
}

int lua_CCString_create(lua_State* L) {
    pushAxObject(L, ax::CCString::create(optCString(L, 2, "")), "CCString");
    return 1;
}

int lua_CCString_getCString(lua_State* L) {
    auto* self = getAxObject<ax::CCString>(L, 1);
    lua_pushstring(L, self ? self->getCString() : "");
    return 1;
}

int lua_CCInteger_create(lua_State* L) {
    pushAxObject(L, ax::CCInteger::create(optInt<int>(L, 2, 0)), "CCInteger");
    return 1;
}

int lua_CCArray_createWithCapacity(lua_State* L) {
    const auto cap = static_cast<size_t>((std::max)(lua_Integer{0}, optInt<lua_Integer>(L, 2, 0)));
    pushAxObject(L, ax::CCArray::createWithCapacity(cap), "CCArray");
    return 1;
}

int lua_CCArray_objectAtIndex(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    const lua_Integer idx = optInt<lua_Integer>(L, 2, -1);
    if (!self || idx < 0) { lua_pushnil(L); return 1; }
    return pushTypedAxObject(L, self->objectAtIndex(static_cast<size_t>(idx)));
}

int lua_CCArray_lastObject(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    return pushTypedAxObject(L, self ? self->lastObject() : nullptr);
}

int lua_CCArray_addObject(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    if (!self) return 0;
    if (auto* obj = getAxObject<ax::Object>(L, 2)) self->addObject(obj);
    else if (lua_type(L, 2) == LUA_TSTRING) self->addObject(ax::CCString::create(optCString(L, 2, "")));
    return 0;
}

int lua_CCArray_insertObject(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    auto* obj  = getAxObject<ax::Object>(L, 2);
    const auto idx = static_cast<size_t>((std::max)(lua_Integer{0}, optInt<lua_Integer>(L, 3, 0)));
    if (self && obj) self->insertObject(obj, idx);
    return 0;
}

int lua_CCArray_removeObjectAtIndex(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    if (const lua_Integer idx = optInt<lua_Integer>(L, 2, -1); self && idx >= 0) {
        self->removeObjectAtIndex(static_cast<size_t>(idx));
    }
    return 0;
}

int lua_CCDictionary_createWithContentsOfFile(lua_State* L) {
    pushAxObject(L, ax::CCDictionary::createWithContentsOfFile(lua_tostring(L, 2)), "CCDictionary");
    return 1;
}

int lua_CCDictionary_objectForKey(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    if (!self) { lua_pushnil(L); return 1; }
    ax::Object* elem = (lua_type(L, 2) == LUA_TNUMBER)
        ? self->objectForKey(static_cast<intptr_t>(lua_tointeger(L, 2)))
        : (lua_isstring(L, 2) ? self->objectForKey(std::string(optCString(L, 2, ""))) : nullptr);
    return pushTypedAxObject(L, elem);
}

int lua_CCDictionary_valueForKey(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    const char* k = lua_tostring(L, 2);
    const ax::CCString* s = (self && k) ? self->valueForKey(k) : nullptr;
    pushAxObject(L, ax::CCString::create(s ? s->getCString() : ""), "CCString");
    return 1;
}

int lua_CCDictionary_setObject(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    auto* obj  = getAxObject<ax::Object>(L, 2);
    if (!self || !obj) return 0;
    if (lua_type(L, 3) == LUA_TNUMBER) self->setObject(obj, static_cast<intptr_t>(lua_tointeger(L, 3)));
    else if (const char* k = lua_tostring(L, 3)) self->setObject(obj, std::string(k));
    return 0;
}

int lua_CCDictionary_removeObjectForKey(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    if (!self) return 0;
    if (lua_type(L, 2) == LUA_TNUMBER) self->removeObjectForKey(static_cast<intptr_t>(lua_tointeger(L, 2)));
    else if (const char* k = lua_tostring(L, 2)) self->removeObjectForKey(std::string(k));
    return 0;
}

int lua_TouchGroup_getWidgetByTag(lua_State* L) {
    auto* self = getAxObject<ax::ui::TouchGroup>(L, 1);
    return pushTypedAxObject(L, self ? self->getWidgetByTag(optInt<int>(L, 2, 0)) : nullptr);
}

int lua_TouchGroup_getWidgetByName(lua_State* L) {
    auto* self = getAxObject<ax::ui::TouchGroup>(L, 1);
    const char* name = lua_tostring(L, 2);
    return pushTypedAxObject(L, (self && name) ? self->getWidgetByName(name) : nullptr);
}

int lua_TouchGroup_getRootWidget(lua_State* L) {
    auto* self = getAxObject<ax::ui::TouchGroup>(L, 1);
    return pushTypedAxObject(L, self ? self->getRootWidget() : nullptr);
}

int lua_SAE_sharedEngine(lua_State* L) {
    pushAxObject(L, SAE::sharedEngine(), "SimpleAudioEngine");
    return 1;
}

int lua_SAE_playEffect(lua_State* L) {
    const int base = firstArgIndex(L);
    const char* p  = lua_tostring(L, base);
    const bool loop = optBool(L, base + 1, false);
    const float pitch = optFloat<float>(L, base + 2, 1.0f);
    const float pan   = optFloat<float>(L, base + 3, 0.0f);
    const float gain  = optFloat<float>(L, base + 4, 1.0f);
    const unsigned int id = p ? SAE::sharedEngine()->playEffect(p, loop, pitch, pan, gain) : 0u;
    lua_pushinteger(L, static_cast<lua_Integer>(id));
    return 1;
}

void registerCompatClass(lua_State* L,
                         const char* name,
                         const char* base,
                         std::span<const luaL_Reg> methods,
                         std::initializer_list<const char*> aliasTypes = {}) {
    tolua_usertype(L, name);
    for (const char* alias : aliasTypes) tolua_usertype(L, alias);
    tolua_cclass(L, name, name, base, nullptr);
    tolua_beginmodule(L, name);
    for (const auto& m : methods) {
        if (m.name && m.func) tolua_function(L, m.name, m.func);
    }
    tolua_endmodule(L);

    luaL_getmetatable(L, name);
    if (lua_istable(L, -1)) {
        registerMethodTable(L, -1, methods);
        for (const char* alias : aliasTypes) {
            lua_pushvalue(L, -1);
            lua_setfield(L, LUA_REGISTRYINDEX, alias);
        }
    }
    lua_pop(L, 1);
}

} // namespace

std::string ResolveConvertedAssetPath(const std::string& rawPath) {
    if (rawPath.empty()) return {};
    const std::string norm = gclient::assets::NormalizeAssetPath(rawPath);
    auto* fu = ax::FileUtils::getInstance();
    if (!fu || fu->isFileExist(norm)) return norm;

    struct ExtRule { std::string_view suffix; size_t trimLen; const char* replacement; };
    static constexpr ExtRule kRules[] = {
        {".pvr.ccz", 8, ".png"},
        {".pkm",     4, ".png"},
        {".pvr",     4, ".png"},
        {".plistb",  7, ".plist"},
        {".jsonb",   6, ".json"},
    };
    for (const auto& r : kRules) {
        if (gclient::common::endsWithAsciiCI(norm, r.suffix)) {
            std::string cand = norm.substr(0, norm.size() - r.trimLen) + r.replacement;
            if (fu->isFileExist(cand)) return cand;
            break;
        }
    }
    return norm;
}

void RegisterAxmol226CompatLuaBindings(lua_State* L) {
    if (!L) return;

    static const luaL_Reg kCCStringMethods[] = {
        {"create",      lua_CCString_create},
        {"getCString",  lua_CCString_getCString},
        {"length",      bindAxMethod<&ax::CCString::length>},
        {"intValue",    bindAxMethod<&ax::CCString::intValue>},
        {"uintValue",   bindAxMethod<&ax::CCString::uintValue>},
        {"floatValue",  bindAxMethod<&ax::CCString::floatValue>},
        {"doubleValue", bindAxMethod<&ax::CCString::doubleValue>},
        {"boolValue",   bindAxMethod<&ax::CCString::boolValue>},
    };
    static const luaL_Reg kCCIntegerMethods[] = {
        {"create",   lua_CCInteger_create},
        {"getValue", bindAxMethod<&ax::CCInteger::getValue>},
    };
    static const luaL_Reg kCCArrayMethods[] = {
        {"create",                  lua_createDefault<ax::CCArray, "CCArray">},
        {"createWithCapacity",      lua_CCArray_createWithCapacity},
        {"count",                   bindAxMethod<&ax::CCArray::count>},
        {"objectAtIndex",           lua_CCArray_objectAtIndex},
        {"lastObject",              lua_CCArray_lastObject},
        {"addObject",               lua_CCArray_addObject},
        {"insertObject",            lua_CCArray_insertObject},
        {"removeObject",            bindAxMethod<&ax::CCArray::fastRemoveObject>},
        {"removeObjectAtIndex",     lua_CCArray_removeObjectAtIndex},
        {"removeLastObject",        bindAxMethod<&ax::CCArray::removeLastObject>},
        {"removeAllObjects",        bindAxMethod<&ax::CCArray::removeAllObjects>},
        {"fastRemoveObject",        bindAxMethod<&ax::CCArray::fastRemoveObject>},
        {"fastRemoveObjectAtIndex", lua_CCArray_removeObjectAtIndex},
        {"containsObject",          bindAxMethod<&ax::CCArray::containsObject>},
    };
    static const luaL_Reg kCCDictionaryMethods[] = {
        {"create",                   lua_createDefault<ax::CCDictionary, "CCDictionary">},
        {"createWithContentsOfFile", lua_CCDictionary_createWithContentsOfFile},
        {"count",                    bindAxMethod<&ax::CCDictionary::count>},
        {"objectForKey",             lua_CCDictionary_objectForKey},
        {"valueForKey",              lua_CCDictionary_valueForKey},
        {"setObject",                lua_CCDictionary_setObject},
        {"removeObjectForKey",       lua_CCDictionary_removeObjectForKey},
        {"removeAllObjects",         bindAxMethod<&ax::CCDictionary::removeAllObjects>},
        {"allKeys",                  bindAxMethodObjRet<"CCArray", &ax::CCDictionary::allKeys>},
    };
    static const luaL_Reg kTouchGroupMethods[] = {
        {"create",           lua_createDefault<ax::ui::TouchGroup, "TouchGroup">},
        {"addWidget",        bindAxMethod<&ax::ui::TouchGroup::addWidget>},
        {"removeWidget",     bindAxMethod<&ax::ui::TouchGroup::removeWidget>},
        {"getWidgetByTag",   lua_TouchGroup_getWidgetByTag},
        {"getWidgetByName",  lua_TouchGroup_getWidgetByName},
        {"getRootWidget",    lua_TouchGroup_getRootWidget},
        {"clear",            bindAxMethod<&ax::ui::TouchGroup::clear>},
        {"clearTouchStat",   bindAxMethod<&ax::ui::TouchGroup::clearTouchStat>},
        {"setTouchPriority", bindAxMethod<&ax::ui::TouchGroup::setTouchPriority>},
        {"getTouchPriority", bindAxMethod<&ax::ui::TouchGroup::getTouchPriority>},
    };
    static const luaL_Reg kSAEMethods[] = {
        {"sharedEngine",             lua_SAE_sharedEngine},
        {"getInstance",              lua_SAE_sharedEngine},
        {"preloadBackgroundMusic",   bindFlexSingleton<&SAE::sharedEngine, &SAE::preloadBackgroundMusic>},
        {"playBackgroundMusic",      bindFlexSingleton<&SAE::sharedEngine, &SAE::playBackgroundMusic>},
        {"stopBackgroundMusic",      bindFlexSingleton<&SAE::sharedEngine, &SAE::stopBackgroundMusic>},
        {"pauseBackgroundMusic",     bindFlexSingleton<&SAE::sharedEngine, &SAE::pauseBackgroundMusic>},
        {"resumeBackgroundMusic",    bindFlexSingleton<&SAE::sharedEngine, &SAE::resumeBackgroundMusic>},
        {"rewindBackgroundMusic",    bindFlexSingleton<&SAE::sharedEngine, &SAE::rewindBackgroundMusic>},
        {"willPlayBackgroundMusic",  bindFlexSingleton<&SAE::sharedEngine, &SAE::willPlayBackgroundMusic>},
        {"isBackgroundMusicPlaying", bindFlexSingleton<&SAE::sharedEngine, &SAE::isBackgroundMusicPlaying>},
        {"getBackgroundMusicVolume", bindFlexSingleton<&SAE::sharedEngine, &SAE::getBackgroundMusicVolume>},
        {"setBackgroundMusicVolume", bindFlexSingleton<&SAE::sharedEngine, &SAE::setBackgroundMusicVolume>},
        {"getEffectsVolume",         bindFlexSingleton<&SAE::sharedEngine, &SAE::getEffectsVolume>},
        {"setEffectsVolume",         bindFlexSingleton<&SAE::sharedEngine, &SAE::setEffectsVolume>},
        {"playEffect",               lua_SAE_playEffect},
        {"pauseEffect",              bindFlexSingleton<&SAE::sharedEngine, &SAE::pauseEffect>},
        {"pauseAllEffects",          bindFlexSingleton<&SAE::sharedEngine, &SAE::pauseAllEffects>},
        {"resumeEffect",             bindFlexSingleton<&SAE::sharedEngine, &SAE::resumeEffect>},
        {"resumeAllEffects",         bindFlexSingleton<&SAE::sharedEngine, &SAE::resumeAllEffects>},
        {"stopEffect",               bindFlexSingleton<&SAE::sharedEngine, &SAE::stopEffect>},
        {"stopAllEffects",           bindFlexSingleton<&SAE::sharedEngine, &SAE::stopAllEffects>},
        {"preloadEffect",            bindFlexSingleton<&SAE::sharedEngine, &SAE::preloadEffect>},
        {"unloadEffect",             bindFlexSingleton<&SAE::sharedEngine, &SAE::unloadEffect>},
    };

    tolua_open(L);
    tolua_module(L, nullptr, 0);
    tolua_beginmodule(L, nullptr);

    registerCompatClass(L, "CCString", "ax.Object", kCCStringMethods);
    registerCompatClass(L, "CCInteger", "ax.Object", kCCIntegerMethods);
    registerCompatClass(L, "CCArray", "ax.Object", kCCArrayMethods, {"cocos2d::CCArray"});
    registerCompatClass(L, "CCDictionary", "ax.Object", kCCDictionaryMethods);
    registerCompatClass(L, "TouchGroup", "ax.Layer", kTouchGroupMethods,
                        {"UILayer", "axui.TouchGroup", "ccui.TouchGroup"});
    registerCompatClass(L, "SimpleAudioEngine", "ax.Object", kSAEMethods);

    lua_getglobal(L, "TouchGroup");
    if (!lua_isnil(L, -1)) lua_setglobal(L, "UILayer");
    else lua_pop(L, 1);

    tolua_endmodule(L);
}

} // namespace gclient::compat
