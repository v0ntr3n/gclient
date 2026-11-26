#include "compat/Axmol226Compat.h"
#include "assets/BtDecryptHook.h"
#include "diagnostics/CrashAndTelemetry.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}
#include "tolua++.h"
#include "lua-bindings/manual/tolua_fix.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace ax {

void CCLog(const char* format, ...) {
    if (!format) return;
    char buf[4096];
    va_list args;
    va_start(args, format);
    std::vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info, "CCLog", "%s", buf);
}

CCString* CCString::createWithFormat(const char* fmt, ...) {
    if (!fmt) return create("");
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    return create(buf);
}

namespace {

ax::Object* valueToCompatObject(const ax::Value& v) {
    switch (v.getType()) {
        case ax::Value::Type::STRING:
            return CCString::create(v.asString());
        case ax::Value::Type::INT_I32:
            return CCString::create(std::to_string(v.asInt()));
        case ax::Value::Type::INT_UI32:
            return CCString::create(std::to_string(v.asUnsignedInt()));
        case ax::Value::Type::INT_I64:
            return CCString::create(std::to_string(v.asInt64()));
        case ax::Value::Type::INT_UI64:
            return CCString::create(std::to_string(v.asUint64()));
        case ax::Value::Type::FLOAT:
        case ax::Value::Type::DOUBLE:
            return CCString::create(v.asString());
        case ax::Value::Type::BOOLEAN:
            return CCString::create(v.asBool() ? "true" : "false");
        case ax::Value::Type::VECTOR: {
            auto* arr = CCArray::create();
            for (const auto& elem : v.asValueVector()) {
                if (auto* child = valueToCompatObject(elem)) {
                    arr->addObject(child);
                }
            }
            return arr;
        }
        case ax::Value::Type::MAP: {
            auto* dict = CCDictionary::create();
            for (const auto& kv : v.asValueMap()) {
                if (auto* child = valueToCompatObject(kv.second)) {
                    dict->setObject(child, kv.first);
                }
            }
            return dict;
        }
        default:
            return CCString::create("");
    }
}

} // namespace

CCDictionary* CCDictionary::createWithContentsOfFile(const char* fileName) {
    if (!fileName || !*fileName) {
        return create();
    }
    const std::string resolved = gclient::compat::ResolveConvertedAssetPath(fileName);
    auto* fu = ax::FileUtils::getInstance();
    if (!fu) {
        return create();
    }
    ax::ValueMap vm = fu->getValueMapFromFile(resolved);
    auto* dict = create();
    for (const auto& kv : vm) {
        if (auto* obj = valueToCompatObject(kv.second)) {
            dict->setObject(obj, kv.first);
        }
    }
    return dict;
}

namespace ui {

bool TouchGroup::init() {
    if (!ax::Layer::init()) {
        return false;
    }
    m_rootWidget = ax::Node::create();
    if (m_rootWidget) {
        addChild(m_rootWidget);
    }
    return true;
}

void TouchGroup::addWidget(ax::ui::Widget* widget) {
    if (!widget) return;
    if (m_rootWidget) {
        m_rootWidget->addChild(widget);
    } else {
        addChild(widget);
    }
}

void TouchGroup::removeWidget(ax::ui::Widget* widget) {
    if (!widget) return;
    if (m_rootWidget && widget->getParent() == m_rootWidget) {
        m_rootWidget->removeChild(widget, true);
    } else if (widget->getParent() == this) {
        removeChild(widget, true);
    }
}

ax::ui::Widget* TouchGroup::getWidgetByTag(int tag) {
    ax::Node* container = m_rootWidget ? m_rootWidget : static_cast<ax::Node*>(this);
    for (auto* child : container->getChildren()) {
        if (auto* w = dynamic_cast<ax::ui::Widget*>(child)) {
            if (w->getTag() == tag) return w;
            if (auto* found = ax::ui::Helper::seekWidgetByTag(w, tag)) {
                return found;
            }
        }
    }
    return nullptr;
}

ax::ui::Widget* TouchGroup::getWidgetByName(const char* name) {
    if (!name || !*name) return nullptr;
    ax::Node* container = m_rootWidget ? m_rootWidget : static_cast<ax::Node*>(this);
    for (auto* child : container->getChildren()) {
        if (auto* w = dynamic_cast<ax::ui::Widget*>(child)) {
            if (w->getName() == name) return w;
            if (auto* found = ax::ui::Helper::seekWidgetByName(w, name)) {
                return found;
            }
        }
    }
    return nullptr;
}

void TouchGroup::clear() {
    if (m_rootWidget) {
        m_rootWidget->removeAllChildrenWithCleanup(true);
    } else {
        removeAllChildrenWithCleanup(true);
    }
}

} // namespace ui

} // namespace ax

// ============================================================================
// CocosDenshion::SimpleAudioEngine Implementation (wrapping ax::AudioEngine)
// ============================================================================
namespace CocosDenshion {

namespace {
SimpleAudioEngine* g_sharedSimpleAudio = nullptr;
} // namespace

SimpleAudioEngine* SimpleAudioEngine::getInstance() {
    if (!g_sharedSimpleAudio) {
        g_sharedSimpleAudio = new SimpleAudioEngine();
    }
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
    if (!fu) return norm;
    if (fu->isFileExist(norm)) return norm;

    const char* exts[] = {".mp3", ".ogg", ".wav"};
    for (const char* ext : exts) {
        std::string cand = gclient::assets::ReplaceFileExtension(norm, ext);
        if (fu->isFileExist(cand)) return cand;
    }
    return norm;
}

void SimpleAudioEngine::preloadBackgroundMusic(const char* filePath) {
    const std::string p = resolveAudioPath(filePath);
    if (!p.empty()) {
        ax::AudioEngine::preload(p);
    }
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
    if (releaseData && !m_bgFilePath.empty()) {
        ax::AudioEngine::uncache(m_bgFilePath);
    }
}

void SimpleAudioEngine::pauseBackgroundMusic() {
    if (m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID) {
        ax::AudioEngine::pause(m_bgAudioId);
    }
}

void SimpleAudioEngine::resumeBackgroundMusic() {
    if (m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID) {
        ax::AudioEngine::resume(m_bgAudioId);
    }
}

void SimpleAudioEngine::rewindBackgroundMusic() {
    if (m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID) {
        ax::AudioEngine::setCurrentTime(m_bgAudioId, 0.0f);
    } else if (!m_bgFilePath.empty()) {
        playBackgroundMusic(m_bgFilePath.c_str(), m_bgLoop);
    }
}

bool SimpleAudioEngine::isBackgroundMusicPlaying() {
    if (m_bgAudioId == ax::AudioEngine::INVALID_AUDIO_ID) return false;
    return ax::AudioEngine::getState(m_bgAudioId) == ax::AudioEngine::AudioState::PLAYING;
}

void SimpleAudioEngine::setBackgroundMusicVolume(float volume) {
    m_musicVolume = std::clamp(volume, 0.0f, 1.0f);
    if (m_bgAudioId != ax::AudioEngine::INVALID_AUDIO_ID) {
        ax::AudioEngine::setVolume(m_bgAudioId, m_musicVolume);
    }
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
    const float vol = std::clamp(m_effectsVolume * gain, 0.0f, 1.0f);
    const int id = ax::AudioEngine::play2d(p, loop, vol);
    if (id != ax::AudioEngine::INVALID_AUDIO_ID) {
        m_activeEffectIds.erase(
            std::remove_if(m_activeEffectIds.begin(), m_activeEffectIds.end(), [](int eid) {
                return ax::AudioEngine::getState(eid) == ax::AudioEngine::AudioState::ERROR;
            }),
            m_activeEffectIds.end());
        m_activeEffectIds.push_back(id);
    }
    return static_cast<unsigned int>(id);
}

void SimpleAudioEngine::pauseEffect(unsigned int soundId) {
    ax::AudioEngine::pause(static_cast<int>(soundId));
}

void SimpleAudioEngine::pauseAllEffects() {
    for (int id : m_activeEffectIds) {
        ax::AudioEngine::pause(id);
    }
}

void SimpleAudioEngine::resumeEffect(unsigned int soundId) {
    ax::AudioEngine::resume(static_cast<int>(soundId));
}

void SimpleAudioEngine::resumeAllEffects() {
    for (int id : m_activeEffectIds) {
        ax::AudioEngine::resume(id);
    }
}

void SimpleAudioEngine::stopEffect(unsigned int soundId) {
    const int id = static_cast<int>(soundId);
    ax::AudioEngine::stop(id);
    m_activeEffectIds.erase(std::remove(m_activeEffectIds.begin(), m_activeEffectIds.end(), id),
                            m_activeEffectIds.end());
}

void SimpleAudioEngine::stopAllEffects() {
    for (int id : m_activeEffectIds) {
        ax::AudioEngine::stop(id);
    }
    m_activeEffectIds.clear();
}

void SimpleAudioEngine::preloadEffect(const char* filePath) {
    const std::string p = resolveAudioPath(filePath);
    if (!p.empty()) {
        ax::AudioEngine::preload(p);
    }
}

void SimpleAudioEngine::unloadEffect(const char* filePath) {
    const std::string p = resolveAudioPath(filePath);
    if (!p.empty()) {
        ax::AudioEngine::uncache(p);
    }
}

} // namespace CocosDenshion

// ============================================================================
// Asset Path Resolver & tolua++ Bindings for Legacy Container/UI/Audio Types
// ============================================================================
namespace gclient::compat {

namespace {

bool endsWithIgnoreCase(std::string_view s, std::string_view suffix) {
    if (s.size() < suffix.size()) return false;
    const size_t off = s.size() - suffix.size();
    for (size_t i = 0; i < suffix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[off + i])) !=
            std::tolower(static_cast<unsigned char>(suffix[i]))) {
            return false;
        }
    }
    return true;
}

template <typename T>
void pushAxObject(lua_State* L, T* obj, const char* typeName) {
    if (!obj) {
        lua_pushnil(L);
        return;
    }
    auto* base = static_cast<ax::Object*>(obj);
    toluafix_pushusertype_object(L, static_cast<int>(base->_ID), &base->_luaID,
                                 static_cast<void*>(base), typeName);
}

template <typename T>
T* getAxObject(lua_State* L, int idx) {
    if (!L || lua_type(L, idx) != LUA_TUSERDATA) return nullptr;
    auto* raw = static_cast<ax::Object*>(tolua_tousertype(L, idx, nullptr));
    return raw ? dynamic_cast<T*>(raw) : nullptr;
}

// --- CCString Lua methods ---
int lua_CCString_create(lua_State* L) {
    const char* s = lua_tostring(L, 2);
    pushAxObject(L, ax::CCString::create(s ? s : ""), "CCString");
    return 1;
}
int lua_CCString_getCString(lua_State* L) {
    auto* self = getAxObject<ax::CCString>(L, 1);
    lua_pushstring(L, self ? self->getCString() : "");
    return 1;
}
int lua_CCString_length(lua_State* L) {
    auto* self = getAxObject<ax::CCString>(L, 1);
    lua_pushinteger(L, self ? static_cast<lua_Integer>(self->length()) : 0);
    return 1;
}
int lua_CCString_intValue(lua_State* L) {
    auto* self = getAxObject<ax::CCString>(L, 1);
    lua_pushinteger(L, self ? self->intValue() : 0);
    return 1;
}
int lua_CCString_floatValue(lua_State* L) {
    auto* self = getAxObject<ax::CCString>(L, 1);
    lua_pushnumber(L, self ? static_cast<lua_Number>(self->floatValue()) : 0.0);
    return 1;
}
int lua_CCString_boolValue(lua_State* L) {
    auto* self = getAxObject<ax::CCString>(L, 1);
    lua_pushboolean(L, (self && self->boolValue()) ? 1 : 0);
    return 1;
}

// --- CCInteger Lua methods ---
int lua_CCInteger_create(lua_State* L) {
    const int v = static_cast<int>(lua_tointeger(L, 2));
    pushAxObject(L, ax::CCInteger::create(v), "CCInteger");
    return 1;
}
int lua_CCInteger_getValue(lua_State* L) {
    auto* self = getAxObject<ax::CCInteger>(L, 1);
    lua_pushinteger(L, self ? self->getValue() : 0);
    return 1;
}

// Push dynamic runtime type name for elements stored in CCArray/CCDictionary
const char* inferAxObjectToluaType(ax::Object* obj) {
    if (!obj) return "ax.Object";
    if (dynamic_cast<ax::CCString*>(obj)) return "CCString";
    if (dynamic_cast<ax::CCInteger*>(obj)) return "CCInteger";
    if (dynamic_cast<ax::CCArray*>(obj)) return "CCArray";
    if (dynamic_cast<ax::CCDictionary*>(obj)) return "CCDictionary";
    if (dynamic_cast<ax::ui::TouchGroup*>(obj)) return "TouchGroup";
    if (dynamic_cast<ax::ui::Button*>(obj)) return "axui.Button";
    if (dynamic_cast<ax::ui::ImageView*>(obj)) return "axui.ImageView";
    if (dynamic_cast<ax::ui::Text*>(obj)) return "axui.Text";
    if (dynamic_cast<ax::ui::TextAtlas*>(obj)) return "axui.TextAtlas";
    if (dynamic_cast<ax::ui::TextBMFont*>(obj)) return "axui.TextBMFont";
    if (dynamic_cast<ax::ui::LoadingBar*>(obj)) return "axui.LoadingBar";
    if (dynamic_cast<ax::ui::CheckBox*>(obj)) return "axui.CheckBox";
    if (dynamic_cast<ax::ui::Slider*>(obj)) return "axui.Slider";
    if (dynamic_cast<ax::ui::TextField*>(obj)) return "axui.TextField";
    if (dynamic_cast<ax::ui::ListView*>(obj)) return "axui.ListView";
    if (dynamic_cast<ax::ui::PageView*>(obj)) return "axui.PageView";
    if (dynamic_cast<ax::ui::ScrollView*>(obj)) return "axui.ScrollView";
    if (dynamic_cast<ax::ui::Layout*>(obj)) return "axui.Layout";
    if (dynamic_cast<ax::ui::Widget*>(obj)) return "axui.Widget";
    if (dynamic_cast<cocostudio::Armature*>(obj)) return "ccs.Armature";
    if (dynamic_cast<ax::Sprite*>(obj)) return "ax.Sprite";
    if (dynamic_cast<ax::Layer*>(obj)) return "ax.Layer";
    if (dynamic_cast<ax::Node*>(obj)) return "ax.Node";
    if (dynamic_cast<ax::FiniteTimeAction*>(obj)) return "ax.FiniteTimeAction";
    if (dynamic_cast<ax::Action*>(obj)) return "ax.Action";
    return "ax.Object";
}

// --- CCArray Lua methods ---
int lua_CCArray_create(lua_State* L) {
    pushAxObject(L, ax::CCArray::create(), "CCArray");
    return 1;
}
int lua_CCArray_createWithCapacity(lua_State* L) {
    const size_t cap = static_cast<size_t>((std::max)(lua_Integer{0}, lua_tointeger(L, 2)));
    pushAxObject(L, ax::CCArray::createWithCapacity(cap), "CCArray");
    return 1;
}
int lua_CCArray_count(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    lua_pushinteger(L, self ? static_cast<lua_Integer>(self->count()) : 0);
    return 1;
}
int lua_CCArray_objectAtIndex(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    const lua_Integer idx = lua_tointeger(L, 2);
    if (!self || idx < 0) {
        lua_pushnil(L);
        return 1;
    }
    ax::Object* elem = self->objectAtIndex(static_cast<size_t>(idx));
    pushAxObject(L, elem, inferAxObjectToluaType(elem));
    return 1;
}
int lua_CCArray_lastObject(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    ax::Object* elem = self ? self->lastObject() : nullptr;
    pushAxObject(L, elem, inferAxObjectToluaType(elem));
    return 1;
}
int lua_CCArray_addObject(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    auto* obj = getAxObject<ax::Object>(L, 2);
    if (self && obj) {
        self->addObject(obj);
    } else if (self && lua_type(L, 2) == LUA_TSTRING) {
        self->addObject(ax::CCString::create(lua_tostring(L, 2)));
    }
    return 0;
}
int lua_CCArray_insertObject(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    auto* obj = getAxObject<ax::Object>(L, 2);
    const size_t idx = static_cast<size_t>((std::max)(lua_Integer{0}, lua_tointeger(L, 3)));
    if (self && obj) self->insertObject(obj, idx);
    return 0;
}
int lua_CCArray_removeObject(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    auto* obj = getAxObject<ax::Object>(L, 2);
    if (self && obj) self->removeObject(obj);
    return 0;
}
int lua_CCArray_removeObjectAtIndex(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    const lua_Integer idx = lua_tointeger(L, 2);
    if (self && idx >= 0) self->removeObjectAtIndex(static_cast<size_t>(idx));
    return 0;
}
int lua_CCArray_removeLastObject(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    if (self) self->removeLastObject();
    return 0;
}
int lua_CCArray_removeAllObjects(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    if (self) self->removeAllObjects();
    return 0;
}
int lua_CCArray_containsObject(lua_State* L) {
    auto* self = getAxObject<ax::CCArray>(L, 1);
    auto* obj = getAxObject<ax::Object>(L, 2);
    lua_pushboolean(L, (self && obj && self->containsObject(obj)) ? 1 : 0);
    return 1;
}

// --- CCDictionary Lua methods ---
int lua_CCDictionary_create(lua_State* L) {
    pushAxObject(L, ax::CCDictionary::create(), "CCDictionary");
    return 1;
}
int lua_CCDictionary_createWithContentsOfFile(lua_State* L) {
    const char* f = lua_tostring(L, 2);
    pushAxObject(L, ax::CCDictionary::createWithContentsOfFile(f), "CCDictionary");
    return 1;
}
int lua_CCDictionary_count(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    lua_pushinteger(L, self ? static_cast<lua_Integer>(self->count()) : 0);
    return 1;
}
int lua_CCDictionary_objectForKey(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    if (!self) {
        lua_pushnil(L);
        return 1;
    }
    ax::Object* elem = nullptr;
    if (lua_type(L, 2) == LUA_TNUMBER) {
        elem = self->objectForKey(static_cast<intptr_t>(lua_tointeger(L, 2)));
    } else if (const char* k = lua_tostring(L, 2)) {
        elem = self->objectForKey(std::string(k));
    }
    pushAxObject(L, elem, inferAxObjectToluaType(elem));
    return 1;
}
int lua_CCDictionary_valueForKey(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    const char* k = lua_tostring(L, 2);
    if (self && k) {
        const ax::CCString* s = self->valueForKey(k);
        pushAxObject(L, ax::CCString::create(s ? s->getCString() : ""), "CCString");
        return 1;
    }
    pushAxObject(L, ax::CCString::create(""), "CCString");
    return 1;
}
int lua_CCDictionary_setObject(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    auto* obj = getAxObject<ax::Object>(L, 2);
    if (!self || !obj) return 0;
    if (lua_type(L, 3) == LUA_TNUMBER) {
        self->setObject(obj, static_cast<intptr_t>(lua_tointeger(L, 3)));
    } else if (const char* k = lua_tostring(L, 3)) {
        self->setObject(obj, std::string(k));
    }
    return 0;
}
int lua_CCDictionary_removeObjectForKey(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    if (!self) return 0;
    if (lua_type(L, 2) == LUA_TNUMBER) {
        self->removeObjectForKey(static_cast<intptr_t>(lua_tointeger(L, 2)));
    } else if (const char* k = lua_tostring(L, 2)) {
        self->removeObjectForKey(std::string(k));
    }
    return 0;
}
int lua_CCDictionary_removeAllObjects(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    if (self) self->removeAllObjects();
    return 0;
}
int lua_CCDictionary_allKeys(lua_State* L) {
    auto* self = getAxObject<ax::CCDictionary>(L, 1);
    pushAxObject(L, self ? self->allKeys() : ax::CCArray::create(), "CCArray");
    return 1;
}

// --- TouchGroup Lua methods ---
int lua_TouchGroup_create(lua_State* L) {
    pushAxObject(L, ax::ui::TouchGroup::create(), "TouchGroup");
    return 1;
}
int lua_TouchGroup_addWidget(lua_State* L) {
    auto* self = getAxObject<ax::ui::TouchGroup>(L, 1);
    auto* w = getAxObject<ax::ui::Widget>(L, 2);
    if (self && w) self->addWidget(w);
    return 0;
}
int lua_TouchGroup_removeWidget(lua_State* L) {
    auto* self = getAxObject<ax::ui::TouchGroup>(L, 1);
    auto* w = getAxObject<ax::ui::Widget>(L, 2);
    if (self && w) self->removeWidget(w);
    return 0;
}
int lua_TouchGroup_getWidgetByTag(lua_State* L) {
    auto* self = getAxObject<ax::ui::TouchGroup>(L, 1);
    const int tag = static_cast<int>(lua_tointeger(L, 2));
    ax::ui::Widget* w = self ? self->getWidgetByTag(tag) : nullptr;
    pushAxObject(L, w, inferAxObjectToluaType(w));
    return 1;
}
int lua_TouchGroup_getWidgetByName(lua_State* L) {
    auto* self = getAxObject<ax::ui::TouchGroup>(L, 1);
    const char* name = lua_tostring(L, 2);
    ax::ui::Widget* w = (self && name) ? self->getWidgetByName(name) : nullptr;
    pushAxObject(L, w, inferAxObjectToluaType(w));
    return 1;
}
int lua_TouchGroup_clear(lua_State* L) {
    auto* self = getAxObject<ax::ui::TouchGroup>(L, 1);
    if (self) self->clear();
    return 0;
}
int lua_TouchGroup_setTouchPriority(lua_State* L) {
    auto* self = getAxObject<ax::ui::TouchGroup>(L, 1);
    if (self) self->setTouchPriority(static_cast<int>(lua_tointeger(L, 2)));
    return 0;
}
int lua_TouchGroup_getTouchPriority(lua_State* L) {
    auto* self = getAxObject<ax::ui::TouchGroup>(L, 1);
    lua_pushinteger(L, self ? self->getTouchPriority() : 0);
    return 1;
}

// --- SimpleAudioEngine Lua methods ---
int lua_SAE_sharedEngine(lua_State* L) {
    pushAxObject(L, CocosDenshion::SimpleAudioEngine::sharedEngine(), "SimpleAudioEngine");
    return 1;
}
int lua_SAE_preloadBackgroundMusic(lua_State* L) {
    if (const char* p = lua_tostring(L, 2)) {
        CocosDenshion::SimpleAudioEngine::sharedEngine()->preloadBackgroundMusic(p);
    }
    return 0;
}
int lua_SAE_playBackgroundMusic(lua_State* L) {
    const char* p = lua_tostring(L, 2);
    const bool loop = lua_gettop(L) >= 3 ? (lua_toboolean(L, 3) != 0) : false;
    if (p) CocosDenshion::SimpleAudioEngine::sharedEngine()->playBackgroundMusic(p, loop);
    return 0;
}
int lua_SAE_stopBackgroundMusic(lua_State* L) {
    const bool rel = lua_gettop(L) >= 2 ? (lua_toboolean(L, 2) != 0) : false;
    CocosDenshion::SimpleAudioEngine::sharedEngine()->stopBackgroundMusic(rel);
    return 0;
}
int lua_SAE_pauseBackgroundMusic(lua_State* /*L*/) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->pauseBackgroundMusic();
    return 0;
}
int lua_SAE_resumeBackgroundMusic(lua_State* /*L*/) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->resumeBackgroundMusic();
    return 0;
}
int lua_SAE_rewindBackgroundMusic(lua_State* /*L*/) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->rewindBackgroundMusic();
    return 0;
}
int lua_SAE_willPlayBackgroundMusic(lua_State* L) {
    lua_pushboolean(L, 1);
    return 1;
}
int lua_SAE_isBackgroundMusicPlaying(lua_State* L) {
    lua_pushboolean(L, CocosDenshion::SimpleAudioEngine::sharedEngine()->isBackgroundMusicPlaying() ? 1 : 0);
    return 1;
}
int lua_SAE_getBackgroundMusicVolume(lua_State* L) {
    lua_pushnumber(L, CocosDenshion::SimpleAudioEngine::sharedEngine()->getBackgroundMusicVolume());
    return 1;
}
int lua_SAE_setBackgroundMusicVolume(lua_State* L) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->setBackgroundMusicVolume(
        static_cast<float>(lua_tonumber(L, 2)));
    return 0;
}
int lua_SAE_getEffectsVolume(lua_State* L) {
    lua_pushnumber(L, CocosDenshion::SimpleAudioEngine::sharedEngine()->getEffectsVolume());
    return 1;
}
int lua_SAE_setEffectsVolume(lua_State* L) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->setEffectsVolume(
        static_cast<float>(lua_tonumber(L, 2)));
    return 0;
}
int lua_SAE_playEffect(lua_State* L) {
    const char* p = lua_tostring(L, 2);
    const bool loop = lua_gettop(L) >= 3 ? (lua_toboolean(L, 3) != 0) : false;
    const unsigned int id = p ? CocosDenshion::SimpleAudioEngine::sharedEngine()->playEffect(p, loop) : 0u;
    lua_pushinteger(L, static_cast<lua_Integer>(id));
    return 1;
}
int lua_SAE_pauseEffect(lua_State* L) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->pauseEffect(
        static_cast<unsigned int>(lua_tointeger(L, 2)));
    return 0;
}
int lua_SAE_pauseAllEffects(lua_State* /*L*/) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->pauseAllEffects();
    return 0;
}
int lua_SAE_resumeEffect(lua_State* L) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->resumeEffect(
        static_cast<unsigned int>(lua_tointeger(L, 2)));
    return 0;
}
int lua_SAE_resumeAllEffects(lua_State* /*L*/) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->resumeAllEffects();
    return 0;
}
int lua_SAE_stopEffect(lua_State* L) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->stopEffect(
        static_cast<unsigned int>(lua_tointeger(L, 2)));
    return 0;
}
int lua_SAE_stopAllEffects(lua_State* /*L*/) {
    CocosDenshion::SimpleAudioEngine::sharedEngine()->stopAllEffects();
    return 0;
}
int lua_SAE_preloadEffect(lua_State* L) {
    if (const char* p = lua_tostring(L, 2)) {
        CocosDenshion::SimpleAudioEngine::sharedEngine()->preloadEffect(p);
    }
    return 0;
}
int lua_SAE_unloadEffect(lua_State* L) {
    if (const char* p = lua_tostring(L, 2)) {
        CocosDenshion::SimpleAudioEngine::sharedEngine()->unloadEffect(p);
    }
    return 0;
}

} // namespace

std::string ResolveConvertedAssetPath(const std::string& rawPath) {
    if (rawPath.empty()) return {};
    const std::string norm = gclient::assets::NormalizeAssetPath(rawPath);
    auto* fu = ax::FileUtils::getInstance();
    if (!fu) return norm;
    if (fu->isFileExist(norm)) {
        return norm;
    }

    // Converted Resources_Axmol_Converted maps .pvr.ccz and .pkm -> .png
    if (endsWithIgnoreCase(norm, ".pvr.ccz")) {
        const std::string png = norm.substr(0, norm.size() - 8) + ".png";
        if (fu->isFileExist(png)) return png;
    } else if (endsWithIgnoreCase(norm, ".pkm") || endsWithIgnoreCase(norm, ".pvr")) {
        const std::string png = norm.substr(0, norm.size() - 4) + ".png";
        if (fu->isFileExist(png)) return png;
    } else if (endsWithIgnoreCase(norm, ".plistb")) {
        const std::string plist = norm.substr(0, norm.size() - 1);
        if (fu->isFileExist(plist)) return plist;
    } else if (endsWithIgnoreCase(norm, ".jsonb")) {
        const std::string json = norm.substr(0, norm.size() - 1);
        if (fu->isFileExist(json)) return json;
    }
    return norm;
}

void RegisterAxmol226CompatLuaBindings(lua_State* L) {
    if (!L) return;

    tolua_open(L);
    tolua_module(L, nullptr, 0);
    tolua_beginmodule(L, nullptr);

    tolua_usertype(L, "CCString");
    tolua_cclass(L, "CCString", "CCString", "ax.Object", nullptr);
    tolua_beginmodule(L, "CCString");
    tolua_function(L, "create", lua_CCString_create);
    tolua_function(L, "getCString", lua_CCString_getCString);
    tolua_function(L, "length", lua_CCString_length);
    tolua_function(L, "intValue", lua_CCString_intValue);
    tolua_function(L, "uintValue", lua_CCString_intValue);
    tolua_function(L, "floatValue", lua_CCString_floatValue);
    tolua_function(L, "doubleValue", lua_CCString_floatValue);
    tolua_function(L, "boolValue", lua_CCString_boolValue);
    tolua_endmodule(L);

    tolua_usertype(L, "CCInteger");
    tolua_cclass(L, "CCInteger", "CCInteger", "ax.Object", nullptr);
    tolua_beginmodule(L, "CCInteger");
    tolua_function(L, "create", lua_CCInteger_create);
    tolua_function(L, "getValue", lua_CCInteger_getValue);
    tolua_endmodule(L);

    tolua_usertype(L, "CCArray");
    tolua_usertype(L, "cocos2d::CCArray");
    tolua_cclass(L, "CCArray", "CCArray", "ax.Object", nullptr);
    tolua_beginmodule(L, "CCArray");
    tolua_function(L, "create", lua_CCArray_create);
    tolua_function(L, "createWithCapacity", lua_CCArray_createWithCapacity);
    tolua_function(L, "count", lua_CCArray_count);
    tolua_function(L, "objectAtIndex", lua_CCArray_objectAtIndex);
    tolua_function(L, "lastObject", lua_CCArray_lastObject);
    tolua_function(L, "addObject", lua_CCArray_addObject);
    tolua_function(L, "insertObject", lua_CCArray_insertObject);
    tolua_function(L, "removeObject", lua_CCArray_removeObject);
    tolua_function(L, "removeObjectAtIndex", lua_CCArray_removeObjectAtIndex);
    tolua_function(L, "removeLastObject", lua_CCArray_removeLastObject);
    tolua_function(L, "removeAllObjects", lua_CCArray_removeAllObjects);
    tolua_function(L, "fastRemoveObject", lua_CCArray_removeObject);
    tolua_function(L, "fastRemoveObjectAtIndex", lua_CCArray_removeObjectAtIndex);
    tolua_function(L, "containsObject", lua_CCArray_containsObject);
    tolua_endmodule(L);

    // Alias cocos2d::CCArray metatable to CCArray metatable so tolua++ functions registered
    // under either spelling resolve identically.
    luaL_getmetatable(L, "CCArray");
    if (lua_istable(L, -1)) {
        lua_setfield(L, LUA_REGISTRYINDEX, "cocos2d::CCArray");
    } else {
        lua_pop(L, 1);
    }

    tolua_usertype(L, "CCDictionary");
    tolua_cclass(L, "CCDictionary", "CCDictionary", "ax.Object", nullptr);
    tolua_beginmodule(L, "CCDictionary");
    tolua_function(L, "create", lua_CCDictionary_create);
    tolua_function(L, "createWithContentsOfFile", lua_CCDictionary_createWithContentsOfFile);
    tolua_function(L, "count", lua_CCDictionary_count);
    tolua_function(L, "objectForKey", lua_CCDictionary_objectForKey);
    tolua_function(L, "valueForKey", lua_CCDictionary_valueForKey);
    tolua_function(L, "setObject", lua_CCDictionary_setObject);
    tolua_function(L, "removeObjectForKey", lua_CCDictionary_removeObjectForKey);
    tolua_function(L, "removeAllObjects", lua_CCDictionary_removeAllObjects);
    tolua_function(L, "allKeys", lua_CCDictionary_allKeys);
    tolua_endmodule(L);

    tolua_usertype(L, "TouchGroup");
    tolua_cclass(L, "TouchGroup", "TouchGroup", "ax.Layer", nullptr);
    tolua_beginmodule(L, "TouchGroup");
    tolua_function(L, "create", lua_TouchGroup_create);
    tolua_function(L, "addWidget", lua_TouchGroup_addWidget);
    tolua_function(L, "removeWidget", lua_TouchGroup_removeWidget);
    tolua_function(L, "getWidgetByTag", lua_TouchGroup_getWidgetByTag);
    tolua_function(L, "getWidgetByName", lua_TouchGroup_getWidgetByName);
    tolua_function(L, "clear", lua_TouchGroup_clear);
    tolua_function(L, "setTouchPriority", lua_TouchGroup_setTouchPriority);
    tolua_function(L, "getTouchPriority", lua_TouchGroup_getTouchPriority);
    tolua_endmodule(L);

    tolua_usertype(L, "SimpleAudioEngine");
    tolua_cclass(L, "SimpleAudioEngine", "SimpleAudioEngine", "ax.Object", nullptr);
    tolua_beginmodule(L, "SimpleAudioEngine");
    tolua_function(L, "sharedEngine", lua_SAE_sharedEngine);
    tolua_function(L, "getInstance", lua_SAE_sharedEngine);
    tolua_function(L, "preloadBackgroundMusic", lua_SAE_preloadBackgroundMusic);
    tolua_function(L, "playBackgroundMusic", lua_SAE_playBackgroundMusic);
    tolua_function(L, "stopBackgroundMusic", lua_SAE_stopBackgroundMusic);
    tolua_function(L, "pauseBackgroundMusic", lua_SAE_pauseBackgroundMusic);
    tolua_function(L, "resumeBackgroundMusic", lua_SAE_resumeBackgroundMusic);
    tolua_function(L, "rewindBackgroundMusic", lua_SAE_rewindBackgroundMusic);
    tolua_function(L, "willPlayBackgroundMusic", lua_SAE_willPlayBackgroundMusic);
    tolua_function(L, "isBackgroundMusicPlaying", lua_SAE_isBackgroundMusicPlaying);
    tolua_function(L, "getBackgroundMusicVolume", lua_SAE_getBackgroundMusicVolume);
    tolua_function(L, "setBackgroundMusicVolume", lua_SAE_setBackgroundMusicVolume);
    tolua_function(L, "getEffectsVolume", lua_SAE_getEffectsVolume);
    tolua_function(L, "setEffectsVolume", lua_SAE_setEffectsVolume);
    tolua_function(L, "playEffect", lua_SAE_playEffect);
    tolua_function(L, "pauseEffect", lua_SAE_pauseEffect);
    tolua_function(L, "pauseAllEffects", lua_SAE_pauseAllEffects);
    tolua_function(L, "resumeEffect", lua_SAE_resumeEffect);
    tolua_function(L, "resumeAllEffects", lua_SAE_resumeAllEffects);
    tolua_function(L, "stopEffect", lua_SAE_stopEffect);
    tolua_function(L, "stopAllEffects", lua_SAE_stopAllEffects);
    tolua_function(L, "preloadEffect", lua_SAE_preloadEffect);
    tolua_function(L, "unloadEffect", lua_SAE_unloadEffect);
    tolua_endmodule(L);

    tolua_endmodule(L);
}

} // namespace gclient::compat
