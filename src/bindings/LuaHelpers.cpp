// ============================================================================
// LuaHelpers.cpp — Axmol v2.11.5 LTS (x64 C++20) Port
//
// Bridges Kestrel-Canvas Lua helpers, asset loader hooks (PbGuiLoader,
// XmlbArmatureLoader, PlistbLoader), Spine 4.2 SkeletonAnimation (SpineLuaAnimation),
// RichText, UI widget 2.2.6 extensions, and NetworkResilienceHook onto Axmol.
// ============================================================================

#include "bindings/LuaHelpers.h"
#include "bindings/LuaBindingsRegistry.h"
#include "bindings/LuaHttpAndCrypto.h"
#include "bindings/NetworkResilienceHook.h"

#include "assets/BtDecryptHook.h"
#include "assets/PbGuiLoader.h"
#include "assets/PlistbLoader.h"
#include "assets/XmlbArmatureLoader.h"
#include "compat/Axmol226Compat.h"
#include "diagnostics/CrashAndTelemetry.h"

#include "ui/CocosGUI.h"
#include "ui/UIRichText.h"
#include "ui/UIScale9Sprite.h"
#include "cocostudio/CocoStudio.h"
#include "spine/SkeletonAnimation.h"
#include "spine/spine.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}
#include "tolua++.h"
#include "lua-bindings/manual/tolua_fix.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

USING_NS_CC;

namespace {

// ============================================================================
// Safe Object Push & Extraction Helpers for Axmol tolua++
// ============================================================================

int toAbsLuaIndex(lua_State* L, int idx) {
    if (idx < 0 && idx > LUA_REGISTRYINDEX) {
        return lua_gettop(L) + idx + 1;
    }
    return idx;
}

const char* inferRuntimeToluaType(ax::Object* obj) {
    if (!obj) return "ax.Object";
    if (dynamic_cast<spine::SkeletonAnimation*>(obj)) return "SpineLuaAnimation";
    if (dynamic_cast<ax::ui::RichText*>(obj)) return "RichText";
    if (dynamic_cast<ax::ui::RichElementText*>(obj)) return "RichElementText";
    if (dynamic_cast<ax::ui::RichElementImage*>(obj)) return "RichElementImage";
    if (dynamic_cast<ax::ui::RichElementCustomNode*>(obj)) return "RichElementCustomNode";
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
    if (dynamic_cast<ax::ui::Scale9Sprite*>(obj)) return "axui.Scale9Sprite";
    if (dynamic_cast<cocostudio::Armature*>(obj)) return "ccs.Armature";
    if (dynamic_cast<ax::Sprite*>(obj)) return "ax.Sprite";
    if (dynamic_cast<ax::DrawNode*>(obj)) return "ax.DrawNode";
    if (dynamic_cast<ax::Layer*>(obj)) return "ax.Layer";
    if (dynamic_cast<ax::Node*>(obj)) return "ax.Node";
    return "ax.Object";
}

template <typename T>
void pushAxObj(lua_State* L, T* obj, const char* explicitType = nullptr) {
    if (!obj) {
        lua_pushnil(L);
        return;
    }
    auto* base = static_cast<ax::Object*>(obj);
    const char* tname = (explicitType && *explicitType) ? explicitType : inferRuntimeToluaType(base);
    toluafix_pushusertype_object(
        L, static_cast<int>(base->_ID), &base->_luaID, static_cast<void*>(base), tname);
}

ax::Object* extractRawAxObject(lua_State* L, int idx) {
    if (!L) return nullptr;
    const int absIdx = toAbsLuaIndex(L, idx);
    if (absIdx <= 0 || absIdx > lua_gettop(L)) return nullptr;

    if (lua_type(L, absIdx) == LUA_TUSERDATA) {
        return static_cast<ax::Object*>(tolua_tousertype(L, absIdx, nullptr));
    }
    if (lua_type(L, absIdx) == LUA_TTABLE) {
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
                auto* ptr = static_cast<ax::Object*>(tolua_tousertype(L, -1, nullptr));
                lua_pop(L, 1);
                return ptr;
            }
        }
        lua_pop(L, 1);
    }
    return nullptr;
}

template <typename T>
T* getSafeAxObject(lua_State* L, int idx) {
    ax::Object* raw = extractRawAxObject(L, idx);
    return raw ? dynamic_cast<T*>(raw) : nullptr;
}

bool readLuaColor3B(lua_State* L, int idx, ax::Color3B& out) {
    const int absIdx = toAbsLuaIndex(L, idx);
    if (lua_istable(L, absIdx)) {
        lua_getfield(L, absIdx, "r"); const int r = static_cast<int>(lua_tointeger(L, -1)); lua_pop(L, 1);
        lua_getfield(L, absIdx, "g"); const int g = static_cast<int>(lua_tointeger(L, -1)); lua_pop(L, 1);
        lua_getfield(L, absIdx, "b"); const int b = static_cast<int>(lua_tointeger(L, -1)); lua_pop(L, 1);
        out = ax::Color3B(static_cast<uint8_t>(std::clamp(r, 0, 255)),
                          static_cast<uint8_t>(std::clamp(g, 0, 255)),
                          static_cast<uint8_t>(std::clamp(b, 0, 255)));
        return true;
    }
    if (auto* ptr = static_cast<ax::Color3B*>(tolua_tousertype(L, absIdx, nullptr))) {
        out = *ptr;
        return true;
    }
    return false;
}

bool readLuaVec2(lua_State* L, int idx, ax::Vec2& out) {
    const int absIdx = toAbsLuaIndex(L, idx);
    if (lua_istable(L, absIdx)) {
        lua_getfield(L, absIdx, "x");
        if (lua_isnil(L, -1)) { lua_pop(L, 1); lua_getfield(L, absIdx, "width"); }
        if (lua_isnil(L, -1)) { lua_pop(L, 1); lua_rawgeti(L, absIdx, 1); }
        out.x = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);

        lua_getfield(L, absIdx, "y");
        if (lua_isnil(L, -1)) { lua_pop(L, 1); lua_getfield(L, absIdx, "height"); }
        if (lua_isnil(L, -1)) { lua_pop(L, 1); lua_rawgeti(L, absIdx, 2); }
        out.y = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
        return true;
    }
    if (auto* ptr = static_cast<ax::Vec2*>(tolua_tousertype(L, absIdx, nullptr))) {
        out = *ptr;
        return true;
    }
    return false;
}

int callOriginalMethod(lua_State* L) {
    if (!lua_isfunction(L, lua_upvalueindex(1))) {
        return 0;
    }
    const int nargs = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, nargs, LUA_MULTRET);
    return lua_gettop(L);
}

} // namespace

// ============================================================================
// CLuaFuncs & CTimer
// ============================================================================

CLuaFuncs* CLuaFuncs::sharedLuaFuncs() {
    static CLuaFuncs* s_ins = new CLuaFuncs();
    return s_ins;
}

CLuaFuncs::~CLuaFuncs() = default;

void CLuaFuncs::addHandler(const char* name, int luaFuncRef) {
    if (!name) return;
    removeHandler(name);
    if (luaFuncRef != 0) {
        m_handlers[name] = luaFuncRef;
    }
}

void CLuaFuncs::removeHandler(const char* name) {
    if (!name) return;
    auto it = m_handlers.find(name);
    if (it != m_handlers.end()) {
        if (auto* mgr = ax::ScriptEngineManager::getInstance()) {
            if (auto* eng = mgr->getScriptEngine()) {
                eng->removeScriptHandler(it->second);
            }
        }
        m_handlers.erase(it);
    }
}

int CLuaFuncs::call(const char* name, const std::list<ax::LuaValue>& args) {
    if (!name) return 0;
    auto it = m_handlers.find(name);
    if (it == m_handlers.end()) return 0;
    auto* eng = ax::LuaEngine::getInstance();
    if (!eng || !eng->getLuaStack()) return 0;
    auto* stack = eng->getLuaStack();
    for (const auto& v : args) {
        stack->pushLuaValue(v);
    }
    return stack->executeFunctionByHandler(it->second, static_cast<int>(args.size()));
}

CTimer* CTimer::sharedTimer() {
    static CTimer* s_timer = new CTimer();
    return s_timer;
}

CTimer::~CTimer() = default;

void CTimer::addEvent(int delaySeconds, int luaFuncRef) {
    if (luaFuncRef == 0) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.push_back(Event{std::time(nullptr) + (std::max)(0, delaySeconds), luaFuncRef});
}

void CTimer::update(float /*dt*/) {
    std::vector<int> readyRefs;
    const std::time_t now = std::time(nullptr);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_events.begin();
        while (it != m_events.end()) {
            if (now >= it->fireAt) {
                readyRefs.push_back(it->luaFuncRef);
                it = m_events.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (readyRefs.empty()) return;
    auto* eng = ax::LuaEngine::getInstance();
    auto* stack = eng ? eng->getLuaStack() : nullptr;
    for (int ref : readyRefs) {
        if (stack) {
            stack->executeFunctionByHandler(ref, 0);
            stack->removeScriptHandler(ref);
        }
    }
}

// ============================================================================
// CCStrokeLabel & SpriteBlur
// ============================================================================

CCStrokeLabel* CCStrokeLabel::create(const char* text, const char* fontName, int fontSize) {
    auto* ret = new CCStrokeLabel();
    const std::string txt = text ? text : "";
    const std::string fn  = (fontName && *fontName) ? fontName : "Arial";
    const float fs = static_cast<float>(fontSize > 0 ? fontSize : 20);

    bool ok = false;
    if (ax::FileUtils::getInstance()->isFileExist(fn)) {
        ok = ret->initWithTTF(txt, fn, fs);
    } else {
        { ret->setSystemFontName(fn); ret->setSystemFontSize(fs); ret->setString(txt); ok = true; }
    }
    if (ok) {
        ret->autorelease();
        return ret;
    }
    delete ret;
    return nullptr;
}

void CCStrokeLabel::setStroke(unsigned int strokeSize, ax::Color4B color) {
    if (strokeSize > 0) {
        enableOutline(color, static_cast<int>(strokeSize));
    } else {
        disableEffect(ax::LabelEffect::OUTLINE);
    }
}

void CCStrokeLabel::setContrast(float /*contrast*/) {}

SpriteBlur* SpriteBlur::create(const char* filename) {
    auto* ret = new SpriteBlur();
    const std::string resolved = filename ? gclient::compat::ResolveConvertedAssetPath(filename) : std::string();
    if (!resolved.empty() && ret->initWithFile(resolved)) {
        ret->autorelease();
        return ret;
    }
    if (ret->init()) {
        ret->autorelease();
        return ret;
    }
    delete ret;
    return nullptr;
}

SpriteBlur* SpriteBlur::createWithTexture(ax::Texture2D* texture) {
    auto* ret = new SpriteBlur();
    if (texture && ret->initWithTexture(texture, ax::Rect(0.0f, 0.0f,
            texture->getContentSize().width, texture->getContentSize().height))) {
        ret->autorelease();
        return ret;
    }
    if (ret->init()) {
        ret->autorelease();
        return ret;
    }
    delete ret;
    return nullptr;
}

bool SpriteBlur::initWithTexture(ax::Texture2D* texture, const ax::Rect& rect) {
    return ax::Sprite::initWithTexture(texture, rect, false);
}

void SpriteBlur::initProgram() {}
void SpriteBlur::setBlurSize(float size) { m_blurSize = size; }
void SpriteBlur::listenBack2Foreground(ax::Object* /*obj*/) {}
void SpriteBlur::draw(ax::Renderer* renderer, const ax::Mat4& transform, uint32_t flags) {
    ax::Sprite::draw(renderer, transform, flags);
}

// ============================================================================
// Lua Extension Entry Points (CCB & HTTP/Crypto)
// ============================================================================

int tolua_extensions_ccb_open(lua_State* /*tolua_S*/) {
    return 1;
}

extern "C" int luaopen_lua_extensions(lua_State* L) {
    gclient::bindings::registerLuaHttpAndCrypto(L);
    return 1;
}

// ============================================================================
// Scheduler Tracking, Asset Fallback Hooks & Deferred Async Armature Callbacks
// ============================================================================

namespace {

std::mutex              g_luaScriptEntriesMutex;
std::unordered_set<int> g_activeLuaScriptEntries;

int hook_Scheduler_scheduleScriptFunc(lua_State* L) {
    const int nret = callOriginalMethod(L);
    if (nret >= 1 && lua_isnumber(L, -1)) {
        const int entryId = static_cast<int>(lua_tointeger(L, -1));
        if (entryId > 0) {
            std::lock_guard<std::mutex> lock(g_luaScriptEntriesMutex);
            g_activeLuaScriptEntries.insert(entryId);
        }
    }
    return nret;
}

int hook_Scheduler_unscheduleScriptEntry(lua_State* L) {
    if (lua_isnumber(L, 2)) {
        const int entryId = static_cast<int>(lua_tointeger(L, 2));
        std::lock_guard<std::mutex> lock(g_luaScriptEntriesMutex);
        g_activeLuaScriptEntries.erase(entryId);
    }
    return callOriginalMethod(L);
}

bool doesAnyVariantExist(const std::string& rawPath) {
    if (rawPath.empty()) return false;
    auto* fu = ax::FileUtils::getInstance();
    if (!fu) return false;

    const std::string norm = gclient::assets::NormalizeAssetPath(rawPath);
    if (fu->isFileExist(norm)) return true;

    const std::string conv = gclient::compat::ResolveConvertedAssetPath(norm);
    if (conv != norm && fu->isFileExist(conv)) return true;

    const std::string xmlb = gclient::assets::ReplaceFileExtension(norm, ".xmlb");
    if (norm.size() >= 4 && norm.substr(norm.size() - 4) == ".xml" && fu->isFileExist(xmlb)) return true;

    const std::string pb = gclient::assets::ReplaceFileExtension(norm, ".pb");
    if (norm.size() >= 5 && norm.substr(norm.size() - 5) == ".json" && fu->isFileExist(pb)) return true;

    const std::string plistb = gclient::assets::ReplaceFileExtension(norm, ".plistb");
    if (norm.size() >= 6 && norm.substr(norm.size() - 6) == ".plist" && fu->isFileExist(plistb)) return true;

    return false;
}

int hook_FileUtils_isFileExist(lua_State* L) {
    const char* path = lua_tostring(L, 2);
    if (!path || !*path) {
        lua_pushboolean(L, 0);
        return 1;
    }
    lua_pushboolean(L, doesAnyVariantExist(path) ? 1 : 0);
    return 1;
}

int hook_TextureCache_addImage(lua_State* L) {
    const char* path = lua_tostring(L, 2);
    if (!path || !*path) {
        lua_pushnil(L);
        return 1;
    }
    auto* cache = ax::Director::getInstance()->getTextureCache();
    const std::string resolved = gclient::compat::ResolveConvertedAssetPath(path);
    ax::Texture2D* tex = cache ? cache->addImage(resolved) : nullptr;
    pushAxObj(L, tex, "ax.Texture2D");
    return 1;
}

int hook_TextureCache_removeTextureForKey(lua_State* L) {
    const char* key = lua_tostring(L, 2);
    if (key && *key) {
        if (auto* cache = ax::Director::getInstance()->getTextureCache()) {
            cache->removeTextureForKey(key);
            const std::string resolved = gclient::compat::ResolveConvertedAssetPath(key);
            if (resolved != key) {
                cache->removeTextureForKey(resolved);
            }
        }
    }
    return 0;
}

int hook_SpriteFrameCache_addSpriteFrames(lua_State* L) {
    const char* plist = lua_tostring(L, 2);
    if (!plist || !*plist) return 0;

    auto* explicitTex = (lua_gettop(L) >= 3 && lua_type(L, 3) == LUA_TUSERDATA)
        ? getSafeAxObject<ax::Texture2D>(L, 3)
        : nullptr;

    // Try converted XML .plist first; fall back to binary .plistb via PlistbLoader
    const std::string resolvedPlist = gclient::compat::ResolveConvertedAssetPath(plist);
    auto* fu = ax::FileUtils::getInstance();
    if (fu && fu->isFileExist(resolvedPlist) &&
        resolvedPlist.size() >= 6 && resolvedPlist.substr(resolvedPlist.size() - 6) == ".plist") {
        auto* sfc = ax::SpriteFrameCache::getInstance();
        if (explicitTex) {
            sfc->addSpriteFramesWithFile(resolvedPlist, explicitTex);
        } else if (lua_gettop(L) >= 3 && lua_type(L, 3) == LUA_TSTRING) {
            const std::string texPath = gclient::compat::ResolveConvertedAssetPath(lua_tostring(L, 3));
            sfc->addSpriteFramesWithFile(resolvedPlist, texPath);
        } else {
            sfc->addSpriteFramesWithFile(resolvedPlist);
        }
        return 0;
    }

    (void)gclient::assets::PlistbLoader::AddSpriteFramesWithBinary(plist, explicitTex);
    return 0;
}

int hook_SpriteFrameCache_removeSpriteFramesFromFile(lua_State* L) {
    const char* plist = lua_tostring(L, 2);
    if (plist && *plist) {
        (void)gclient::assets::PlistbLoader::RemoveSpriteFramesWithBinary(plist);
        const std::string resolved = gclient::compat::ResolveConvertedAssetPath(plist);
        if (ax::FileUtils::getInstance()->isFileExist(resolved)) {
            ax::SpriteFrameCache::getInstance()->removeSpriteFramesFromFile(resolved);
        }
    }
    return 0;
}

int hook_GUIReader_widgetFromJsonFile(lua_State* L) {
    const char* fileName = lua_tostring(L, 2);
    if (!fileName || !*fileName) {
        lua_pushnil(L);
        return 1;
    }
    if (ax::ui::Widget* w = gclient::assets::PbGuiLoader::WidgetFromPbFile(fileName)) {
        pushAxObj(L, w);
        return 1;
    }
    return callOriginalMethod(L);
}

int hook_SceneReader_createNodeWithSceneFile(lua_State* L) {
    const char* fileName = lua_tostring(L, 2);
    if (fileName && *fileName) {
        if (ax::Node* n = gclient::assets::PbGuiLoader::SceneFromPbFile(fileName)) {
            pushAxObj(L, n, "ax.Node");
            return 1;
        }
    }
    return callOriginalMethod(L);
}

// --- Armature .xmlb hooks & async callback dispatcher ---
class DeferredArmatureAsyncCallback;
std::vector<DeferredArmatureAsyncCallback*> g_pendingArmatureCallbacks;

class DeferredArmatureAsyncCallback final : public ax::Object {
public:
    explicit DeferredArmatureAsyncCallback(int luaHandler) : m_luaHandler(luaHandler) {
        g_pendingArmatureCallbacks.push_back(this);
        ensureOnScheduler();
    }

    ~DeferredArmatureAsyncCallback() override {
        g_pendingArmatureCallbacks.erase(
            std::remove(g_pendingArmatureCallbacks.begin(), g_pendingArmatureCallbacks.end(), this),
            g_pendingArmatureCallbacks.end());
        if (m_luaHandler != 0) {
            if (auto* mgr = ax::ScriptEngineManager::getInstance()) {
                if (auto* eng = mgr->getScriptEngine()) {
                    eng->removeScriptHandler(m_luaHandler);
                }
            }
            m_luaHandler = 0;
        }
    }

    void ensureOnScheduler() {
        if (auto* dir = ax::Director::getInstance()) {
            if (auto* sched = dir->getScheduler()) {
                if (!sched->isScheduled(AX_SCHEDULE_SELECTOR(DeferredArmatureAsyncCallback::onFire), this)) {
                    sched->schedule(AX_SCHEDULE_SELECTOR(DeferredArmatureAsyncCallback::onFire),
                                    this, 0.0f, 0u, 0.0f, false);
                }
            }
        }
    }

    void onFire(float /*dt*/) {
        if (auto* dir = ax::Director::getInstance()) {
            if (auto* sched = dir->getScheduler()) {
                sched->unscheduleAllForTarget(this);
            }
        }
        const int handler = m_luaHandler;
        m_luaHandler = 0;
        if (handler != 0) {
            if (auto* eng = ax::LuaEngine::getInstance()) {
                if (auto* stack = eng->getLuaStack()) {
                    stack->pushFloat(1.0f);
                    stack->executeFunctionByHandler(handler, 1);
                    stack->removeScriptHandler(handler);
                }
            }
        }
        release();
    }

private:
    int m_luaHandler = 0;
};

bool loadArmatureWithXmlbFallback(const char* imagePath, const char* plistPath, const char* configPath) {
    if (!configPath || !*configPath) return false;
    const std::string resolvedImg   = imagePath ? gclient::compat::ResolveConvertedAssetPath(imagePath) : std::string();
    const std::string resolvedPlist = plistPath ? gclient::compat::ResolveConvertedAssetPath(plistPath) : std::string();

    if (gclient::assets::XmlbArmatureLoader::AddDataFromXmlbFile(resolvedImg, resolvedPlist, configPath)) {
        return true;
    }

    auto* fu = ax::FileUtils::getInstance();
    if (fu && fu->isFileExist(configPath)) {
        auto* mgr = cocostudio::ArmatureDataManager::getInstance();
        if (!resolvedImg.empty() && !resolvedPlist.empty()) {
            mgr->addArmatureFileInfo(resolvedImg, resolvedPlist, configPath);
        } else {
            mgr->addArmatureFileInfo(configPath);
        }
        return true;
    }
    return false;
}

int hook_addArmatureFileInfo(lua_State* L) {
    const int argc = lua_gettop(L) - 1;
    if (argc == 1) {
        loadArmatureWithXmlbFallback(nullptr, nullptr, lua_tostring(L, 2));
    } else if (argc >= 3) {
        loadArmatureWithXmlbFallback(lua_tostring(L, 2), lua_tostring(L, 3), lua_tostring(L, 4));
    }
    return 0;
}

int hook_addArmatureFileInfoAsync(lua_State* L) {
    const int argc = lua_gettop(L) - 1;
    int funcIdx = 0;
    if (argc == 2) {
        loadArmatureWithXmlbFallback(nullptr, nullptr, lua_tostring(L, 2));
        funcIdx = 3;
    } else if (argc >= 4) {
        loadArmatureWithXmlbFallback(lua_tostring(L, 2), lua_tostring(L, 3), lua_tostring(L, 4));
        funcIdx = 5;
    }
    if (funcIdx > 0 && lua_isfunction(L, funcIdx)) {
        const int handler = toluafix_ref_function(L, funcIdx, 0);
        if (handler != 0) {
            new DeferredArmatureAsyncCallback(handler);
        }
    }
    return 0;
}

int hook_removeArmatureFileInfo(lua_State* L) {
    const char* configPath = lua_tostring(L, 2);
    if (configPath && *configPath) {
        auto* mgr = cocostudio::ArmatureDataManager::getInstance();
        const std::string norm = gclient::assets::NormalizeAssetPath(configPath);
        const std::string xmlb = gclient::assets::ReplaceFileExtension(norm, ".xmlb");
        mgr->removeArmatureFileInfo(norm);
        if (xmlb != norm) mgr->removeArmatureFileInfo(xmlb);
    }
    return 0;
}

int hook_ArmatureAnimation_setMovementLoopByName(lua_State* L) {
    auto* anim = getSafeAxObject<cocostudio::ArmatureAnimation>(L, 1);
    const char* movName = lua_tostring(L, 2);
    const bool loop = lua_toboolean(L, 3) != 0;
    if (anim && movName && anim->getAnimationData()) {
        if (auto* mov = anim->getAnimationData()->getMovement(movName)) {
            mov->loop = loop;
        }
    }
    return 0;
}

int hook_Director_getCurrentTime(lua_State* L) {
    using namespace std::chrono;
    const double secs = duration<double>(steady_clock::now().time_since_epoch()).count();
    lua_pushnumber(L, static_cast<lua_Number>(secs));
    return 1;
}

// --- Safe Sprite / Scale9Sprite Creation Hooks ---
int hook_Sprite_create(lua_State* L) {
    const int argc = lua_gettop(L) - 1;
    if (argc <= 0 || lua_isnil(L, 2)) {
        pushAxObj(L, ax::Sprite::create(), "ax.Sprite");
        return 1;
    }
    const char* rawPath = lua_tostring(L, 2);
    if (!rawPath || !*rawPath) {
        pushAxObj(L, ax::Sprite::create(), "ax.Sprite");
        return 1;
    }
    const std::string resolved = gclient::compat::ResolveConvertedAssetPath(rawPath);
    if (ax::FileUtils::getInstance()->isFileExist(resolved)) {
        if (auto* sp = ax::Sprite::create(resolved)) {
            pushAxObj(L, sp, "ax.Sprite");
            return 1;
        }
    }
    if (auto* sf = ax::SpriteFrameCache::getInstance()->getSpriteFrameByName(rawPath)) {
        if (auto* sp = ax::Sprite::createWithSpriteFrame(sf)) {
            pushAxObj(L, sp, "ax.Sprite");
            return 1;
        }
    }
    pushAxObj(L, ax::Sprite::create(), "ax.Sprite");
    return 1;
}

int hook_Sprite_createWithSpriteFrameName(lua_State* L) {
    const char* name = lua_tostring(L, 2);
    if (name && *name) {
        if (auto* sf = ax::SpriteFrameCache::getInstance()->getSpriteFrameByName(name)) {
            if (auto* sp = ax::Sprite::createWithSpriteFrame(sf)) {
                pushAxObj(L, sp, "ax.Sprite");
                return 1;
            }
        }
        const std::string resolved = gclient::compat::ResolveConvertedAssetPath(name);
        if (ax::FileUtils::getInstance()->isFileExist(resolved)) {
            if (auto* sp = ax::Sprite::create(resolved)) {
                pushAxObj(L, sp, "ax.Sprite");
                return 1;
            }
        }
    }
    pushAxObj(L, ax::Sprite::create(), "ax.Sprite");
    return 1;
}

int hook_Scale9Sprite_create(lua_State* L) {
    const int argc = lua_gettop(L) - 1;
    if (argc <= 0 || lua_isnil(L, 2)) {
        pushAxObj(L, ax::ui::Scale9Sprite::create(), "axui.Scale9Sprite");
        return 1;
    }
    const char* rawPath = lua_tostring(L, 2);
    if (rawPath && *rawPath) {
        const std::string resolved = gclient::compat::ResolveConvertedAssetPath(rawPath);
        if (ax::FileUtils::getInstance()->isFileExist(resolved)) {
            if (auto* s9 = ax::ui::Scale9Sprite::create(resolved)) {
                pushAxObj(L, s9, "axui.Scale9Sprite");
                return 1;
            }
        }
        if (auto* sf = ax::SpriteFrameCache::getInstance()->getSpriteFrameByName(rawPath)) {
            if (auto* s9 = ax::ui::Scale9Sprite::createWithSpriteFrame(sf)) {
                pushAxObj(L, s9, "axui.Scale9Sprite");
                return 1;
            }
        }
    }
    pushAxObj(L, ax::ui::Scale9Sprite::create(), "axui.Scale9Sprite");
    return 1;
}

int hook_Scale9Sprite_createWithSpriteFrameName(lua_State* L) {
    const char* name = lua_tostring(L, 2);
    if (name && *name) {
        if (auto* sf = ax::SpriteFrameCache::getInstance()->getSpriteFrameByName(name)) {
            if (auto* s9 = ax::ui::Scale9Sprite::createWithSpriteFrame(sf)) {
                pushAxObj(L, s9, "axui.Scale9Sprite");
                return 1;
            }
        }
    }
    pushAxObj(L, ax::ui::Scale9Sprite::create(), "axui.Scale9Sprite");
    return 1;
}

// --- Widget 2.2.6 Node / Texture / Stroke Extensions ---
ax::ui::Widget::TextureResType resolveWidgetTexArg(const char* rawPath,
                                                   int explicitTexType,
                                                   bool hasExplicitType,
                                                   std::string& outPath) {
    if (!rawPath || !*rawPath) {
        outPath.clear();
        return ax::ui::Widget::TextureResType::LOCAL;
    }
    if (hasExplicitType && explicitTexType == 1) {
        if (ax::SpriteFrameCache::getInstance()->getSpriteFrameByName(rawPath) != nullptr) {
            outPath = rawPath;
            return ax::ui::Widget::TextureResType::PLIST;
        }
    }
    const std::string resolved = gclient::compat::ResolveConvertedAssetPath(rawPath);
    if (ax::FileUtils::getInstance()->isFileExist(resolved)) {
        outPath = resolved;
        return ax::ui::Widget::TextureResType::LOCAL;
    }
    if (ax::SpriteFrameCache::getInstance()->getSpriteFrameByName(rawPath) != nullptr) {
        outPath = rawPath;
        return ax::ui::Widget::TextureResType::PLIST;
    }
    outPath = resolved;
    return hasExplicitType
        ? static_cast<ax::ui::Widget::TextureResType>(explicitTexType)
        : ax::ui::Widget::TextureResType::LOCAL;
}

int hook_Widget_addNode(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Widget>(L, 1);
    auto* child = getSafeAxObject<ax::Node>(L, 2);
    if (!self || !child) return 0;
    const int z = lua_isnumber(L, 3) ? static_cast<int>(lua_tointeger(L, 3)) : child->getLocalZOrder();
    if (lua_isnumber(L, 4)) {
        self->addProtectedChild(child, z, static_cast<int>(lua_tointeger(L, 4)));
    } else {
        self->addProtectedChild(child, z, child->getTag());
    }
    return 0;
}

int hook_Widget_removeNode(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Widget>(L, 1);
    auto* child = getSafeAxObject<ax::Node>(L, 2);
    if (self && child) {
        self->removeProtectedChild(child, true);
    }
    return 0;
}

int hook_Widget_removeNodeByTag(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Widget>(L, 1);
    if (self && lua_isnumber(L, 2)) {
        self->removeProtectedChildByTag(static_cast<int>(lua_tointeger(L, 2)), true);
    }
    return 0;
}

int hook_Widget_removeAllNodes(lua_State* L) {
    if (auto* self = getSafeAxObject<ax::ui::Widget>(L, 1)) {
        self->removeAllProtectedChildrenWithCleanup(true);
    }
    return 0;
}

int hook_ImageView_loadTexture(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::ImageView>(L, 1);
    const char* raw = lua_tostring(L, 2);
    if (!self || !raw || !*raw) return 0;
    std::string path;
    const auto rt = resolveWidgetTexArg(raw, static_cast<int>(lua_tointeger(L, 3)), lua_isnumber(L, 3) != 0, path);
    if (!path.empty()) self->loadTexture(path, rt);
    return 0;
}

int hook_LoadingBar_loadTexture(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::LoadingBar>(L, 1);
    const char* raw = lua_tostring(L, 2);
    if (!self || !raw || !*raw) return 0;
    std::string path;
    const auto rt = resolveWidgetTexArg(raw, static_cast<int>(lua_tointeger(L, 3)), lua_isnumber(L, 3) != 0, path);
    if (!path.empty()) self->loadTexture(path, rt);
    return 0;
}

int hook_Layout_setBackGroundImage(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Layout>(L, 1);
    const char* raw = lua_tostring(L, 2);
    if (!self || !raw || !*raw) return 0;
    std::string path;
    const auto rt = resolveWidgetTexArg(raw, static_cast<int>(lua_tointeger(L, 3)), lua_isnumber(L, 3) != 0, path);
    if (!path.empty()) self->setBackGroundImage(path, rt);
    return 0;
}

int hook_Button_loadTextureNormal(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Button>(L, 1);
    const char* raw = lua_tostring(L, 2);
    if (!self || !raw || !*raw) return 0;
    std::string path;
    const auto rt = resolveWidgetTexArg(raw, static_cast<int>(lua_tointeger(L, 3)), lua_isnumber(L, 3) != 0, path);
    if (!path.empty()) self->loadTextureNormal(path, rt);
    return 0;
}

int hook_Button_loadTexturePressed(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Button>(L, 1);
    const char* raw = lua_tostring(L, 2);
    if (!self || !raw || !*raw) return 0;
    std::string path;
    const auto rt = resolveWidgetTexArg(raw, static_cast<int>(lua_tointeger(L, 3)), lua_isnumber(L, 3) != 0, path);
    if (!path.empty()) self->loadTexturePressed(path, rt);
    return 0;
}

int hook_Button_loadTextureDisabled(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Button>(L, 1);
    const char* raw = lua_tostring(L, 2);
    if (!self || !raw || !*raw) return 0;
    std::string path;
    const auto rt = resolveWidgetTexArg(raw, static_cast<int>(lua_tointeger(L, 3)), lua_isnumber(L, 3) != 0, path);
    if (!path.empty()) self->loadTextureDisabled(path, rt);
    return 0;
}

int hook_Button_loadTextures(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Button>(L, 1);
    if (!self) return 0;
    const bool hasType = lua_isnumber(L, 5) != 0;
    const int expType = static_cast<int>(lua_tointeger(L, 5));
    std::string pN, pP, pD;
    if (const char* n = lua_tostring(L, 2); n && *n) {
        const auto rt = resolveWidgetTexArg(n, expType, hasType, pN);
        if (!pN.empty()) self->loadTextureNormal(pN, rt);
    }
    if (const char* p = lua_tostring(L, 3); p && *p) {
        const auto rt = resolveWidgetTexArg(p, expType, hasType, pP);
        if (!pP.empty()) self->loadTexturePressed(pP, rt);
    }
    if (const char* d = lua_tostring(L, 4); d && *d) {
        const auto rt = resolveWidgetTexArg(d, expType, hasType, pD);
        if (!pD.empty()) self->loadTextureDisabled(pD, rt);
    }
    return 0;
}

int hook_Button_enableTitleStroke(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Button>(L, 1);
    if (!self) return 0;
    ax::Color3B c = ax::Color3B::BLACK;
    readLuaColor3B(L, 2, c);
    const int sz = lua_isnumber(L, 3) ? (std::max)(1, static_cast<int>(std::round(lua_tonumber(L, 3)))) : 2;
    if (auto* tr = self->getTitleRenderer()) { tr->enableOutline(ax::Color4B(c.r, c.g, c.b, 255), sz); }
    return 0;
}

int hook_Button_disableTitleStroke(lua_State* L) {
    if (auto* self = getSafeAxObject<ax::ui::Button>(L, 1)) {
        if (auto* tr = self->getTitleRenderer()) {
            tr->disableEffect(ax::LabelEffect::OUTLINE);
        }
    }
    return 0;
}

int hook_Text_enableStroke(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Text>(L, 1);
    if (!self) return 0;
    ax::Color3B c = ax::Color3B::BLACK;
    readLuaColor3B(L, 2, c);
    const int sz = lua_isnumber(L, 3) ? (std::max)(1, static_cast<int>(std::round(lua_tonumber(L, 3)))) : 2;
    self->enableOutline(ax::Color4B(c.r, c.g, c.b, 255), sz);
    return 0;
}

int hook_Text_disableStroke(lua_State* L) {
    if (auto* self = getSafeAxObject<ax::ui::Text>(L, 1)) {
        self->disableEffect(ax::LabelEffect::OUTLINE);
    }
    return 0;
}

int hook_Text_enableShadow(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::Text>(L, 1);
    if (!self) return 0;
    ax::Color3B c = ax::Color3B::BLACK;
    readLuaColor3B(L, 2, c);
    ax::Vec2 offset(2.0f, -2.0f);
    readLuaVec2(L, 3, offset);
    self->enableShadow(ax::Color4B(c.r, c.g, c.b, 255), offset);
    return 0;
}

int hook_Label_enableStroke(lua_State* L) {
    auto* self = getSafeAxObject<ax::Label>(L, 1);
    if (!self) return 0;
    ax::Color3B c = ax::Color3B::BLACK;
    readLuaColor3B(L, 2, c);
    const int sz = lua_isnumber(L, 3) ? (std::max)(1, static_cast<int>(std::round(lua_tonumber(L, 3)))) : 2;
    self->enableOutline(ax::Color4B(c.r, c.g, c.b, 255), sz);
    return 0;
}

int hook_Label_disableStroke(lua_State* L) {
    if (auto* self = getSafeAxObject<ax::Label>(L, 1)) {
        self->disableEffect(ax::LabelEffect::OUTLINE);
    }
    return 0;
}

int hook_Node_getTextHeight(lua_State* L) {
    if (auto* txt = getSafeAxObject<ax::ui::Text>(L, 1)) {
        lua_pushnumber(L, txt->getVirtualRendererSize().height);
        return 1;
    }
    if (auto* rt = getSafeAxObject<ax::ui::RichText>(L, 1)) {
        rt->formatText();
        lua_pushnumber(L, rt->getContentSize().height);
        return 1;
    }
    if (auto* n = getSafeAxObject<ax::Node>(L, 1)) {
        lua_pushnumber(L, n->getContentSize().height);
        return 1;
    }
    lua_pushnumber(L, 0.0);
    return 1;
}

// ============================================================================
// RichText Bindings (Cocos2d-x 2.2.6 Global RichText/RichElement* -> ax::ui::RichText)
// ============================================================================

int lua_RichElementText_create(lua_State* L) {
    const int tag = static_cast<int>(lua_tointeger(L, 2));
    ax::Color3B color = ax::Color3B::WHITE;
    readLuaColor3B(L, 3, color);
    const uint8_t opacity = lua_isnumber(L, 4) ? static_cast<uint8_t>(std::clamp<int>(static_cast<int>(lua_tointeger(L, 4)), 0, 255)) : 255;
    const char* text = lua_tostring(L, 5);
    const char* font = lua_tostring(L, 6);
    const float fsize = lua_isnumber(L, 7) ? static_cast<float>(lua_tonumber(L, 7)) : 20.0f;
    auto* elem = ax::ui::RichElementText::create(
        tag, color, opacity, text ? text : "", (font && *font) ? font : "Arial", fsize);
    pushAxObj(L, elem, "RichElementText");
    return 1;
}

int lua_RichElementImage_create(lua_State* L) {
    const int tag = static_cast<int>(lua_tointeger(L, 2));
    ax::Color3B color = ax::Color3B::WHITE;
    readLuaColor3B(L, 3, color);
    const uint8_t opacity = lua_isnumber(L, 4) ? static_cast<uint8_t>(std::clamp<int>(static_cast<int>(lua_tointeger(L, 4)), 0, 255)) : 255;
    const char* rawPath = lua_tostring(L, 5);
    std::string path;
    const auto rt = resolveWidgetTexArg(rawPath, 0, false, path);
    auto* elem = ax::ui::RichElementImage::create(tag, color, opacity, path, "", rt);
    pushAxObj(L, elem, "RichElementImage");
    return 1;
}

int lua_RichElementCustomNode_create(lua_State* L) {
    const int tag = static_cast<int>(lua_tointeger(L, 2));
    ax::Color3B color = ax::Color3B::WHITE;
    readLuaColor3B(L, 3, color);
    const uint8_t opacity = lua_isnumber(L, 4) ? static_cast<uint8_t>(std::clamp<int>(static_cast<int>(lua_tointeger(L, 4)), 0, 255)) : 255;
    auto* node = getSafeAxObject<ax::Node>(L, 5);
    if (!node) node = ax::Node::create();
    auto* elem = ax::ui::RichElementCustomNode::create(tag, color, opacity, node);
    pushAxObj(L, elem, "RichElementCustomNode");
    return 1;
}

int lua_RichText_create(lua_State* L) {
    pushAxObj(L, ax::ui::RichText::create(), "RichText");
    return 1;
}
int lua_RichText_insertElement(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::RichText>(L, 1);
    auto* elem = getSafeAxObject<ax::ui::RichElement>(L, 2);
    const int idx = static_cast<int>(lua_tointeger(L, 3));
    if (self && elem) self->insertElement(elem, idx);
    return 0;
}
int lua_RichText_pushBackElement(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::RichText>(L, 1);
    auto* elem = getSafeAxObject<ax::ui::RichElement>(L, 2);
    if (self && elem) self->pushBackElement(elem);
    return 0;
}
int lua_RichText_removeElement(lua_State* L) {
    auto* self = getSafeAxObject<ax::ui::RichText>(L, 1);
    if (!self) return 0;
    if (lua_isnumber(L, 2)) {
        self->removeElement(static_cast<int>(lua_tointeger(L, 2)));
    } else if (auto* elem = getSafeAxObject<ax::ui::RichElement>(L, 2)) {
        self->removeElement(elem);
    }
    return 0;
}
int lua_RichText_setVerticalSpace(lua_State* L) {
    if (auto* self = getSafeAxObject<ax::ui::RichText>(L, 1)) {
        self->setVerticalSpace(static_cast<float>(lua_tonumber(L, 2)));
    }
    return 0;
}
int lua_RichText_formatText(lua_State* L) {
    if (auto* self = getSafeAxObject<ax::ui::RichText>(L, 1)) {
        self->formatText();
    }
    return 0;
}

void registerRichTextBindingsInternal(lua_State* L) {
    tolua_open(L);
    tolua_module(L, nullptr, 0);
    tolua_beginmodule(L, nullptr);

    tolua_usertype(L, "RichElement");
    tolua_cclass(L, "RichElement", "RichElement", "ax.Object", nullptr);

    tolua_usertype(L, "RichElementText");
    tolua_cclass(L, "RichElementText", "RichElementText", "RichElement", nullptr);
    tolua_beginmodule(L, "RichElementText");
    tolua_function(L, "create", lua_RichElementText_create);
    tolua_endmodule(L);

    tolua_usertype(L, "RichElementImage");
    tolua_cclass(L, "RichElementImage", "RichElementImage", "RichElement", nullptr);
    tolua_beginmodule(L, "RichElementImage");
    tolua_function(L, "create", lua_RichElementImage_create);
    tolua_endmodule(L);

    tolua_usertype(L, "RichElementCustomNode");
    tolua_cclass(L, "RichElementCustomNode", "RichElementCustomNode", "RichElement", nullptr);
    tolua_beginmodule(L, "RichElementCustomNode");
    tolua_function(L, "create", lua_RichElementCustomNode_create);
    tolua_endmodule(L);

    tolua_usertype(L, "RichText");
    tolua_cclass(L, "RichText", "RichText", "axui.Widget", nullptr);
    tolua_beginmodule(L, "RichText");
    tolua_function(L, "create", lua_RichText_create);
    tolua_function(L, "insertElement", lua_RichText_insertElement);
    tolua_function(L, "pushBackElement", lua_RichText_pushBackElement);
    tolua_function(L, "removeElement", lua_RichText_removeElement);
    tolua_function(L, "setVerticalSpace", lua_RichText_setVerticalSpace);
    tolua_function(L, "formatText", lua_RichText_formatText);
    tolua_function(L, "getTextHeight", hook_Node_getTextHeight);
    tolua_endmodule(L);

    tolua_endmodule(L);
}

// ============================================================================
// SpineLuaAnimation (Powered by Axmol Spine 4.2 Runtime on Converted 4.1 Assets)
// ============================================================================

struct CachedSpineEntry {
    std::string jsonPath;
    std::string atlasPath;
    float       scale = 1.0f;
};

std::unordered_map<std::string, CachedSpineEntry> g_spineCache;

std::string resolveSpinePath(const char* rawPath, const char* preferredExt) {
    if (!rawPath || !*rawPath) return {};
    const std::string norm = gclient::assets::NormalizeAssetPath(rawPath);
    auto* fu = ax::FileUtils::getInstance();
    if (fu && fu->isFileExist(norm)) return norm;

    const std::string conv = gclient::compat::ResolveConvertedAssetPath(norm);
    if (fu && fu->isFileExist(conv)) return conv;

    if (preferredExt && *preferredExt) {
        const std::string alt = gclient::assets::ReplaceFileExtension(norm, preferredExt);
        if (fu && fu->isFileExist(alt)) return alt;
    }
    return conv;
}

void releaseSpineLuaHandler(int& handler) {
    if (handler != 0) {
        if (auto* mgr = ax::ScriptEngineManager::getInstance()) {
            if (auto* eng = mgr->getScriptEngine()) {
                eng->removeScriptHandler(handler);
            }
        }
        handler = 0;
    }
}

void invokeSpineTrackHandler(int handler, int trackIndex, int loopCount, bool passLoopCount) {
    if (handler == 0) return;
    auto* eng = ax::LuaEngine::getInstance();
    auto* stack = eng ? eng->getLuaStack() : nullptr;
    if (!stack) return;
    stack->pushInt(trackIndex);
    if (passLoopCount) {
        stack->pushInt(loopCount);
        stack->executeFunctionByHandler(handler, 2);
    } else {
        stack->executeFunctionByHandler(handler, 1);
    }
}

void invokeSpineEventLuaHandler(int handler,
                                const char* eventName,
                                int trackIndex,
                                const char* animName,
                                int intVal,
                                float floatVal,
                                const char* strVal) {
    if (handler == 0) return;
    auto* eng = ax::LuaEngine::getInstance();
    auto* stack = eng ? eng->getLuaStack() : nullptr;
    if (!stack) return;
    stack->pushString(eventName ? eventName : "");
    stack->pushInt(trackIndex);
    stack->pushString(animName ? animName : "");
    stack->pushInt(intVal);
    stack->pushFloat(floatVal);
    stack->pushString(strVal ? strVal : "");
    stack->executeFunctionByHandler(handler, 6);
}

class GClientSpineAnimation final : public spine::SkeletonAnimation {
public:
    static GClientSpineAnimation* createSafe(const std::string& jsonPath,
                                             const std::string& atlasPath,
                                             float scale) {
        auto* fu = ax::FileUtils::getInstance();
        const std::string rJson  = resolveSpinePath(jsonPath.c_str(), ".json");
        const std::string rAtlas = resolveSpinePath(atlasPath.c_str(), ".atlas");

        if (fu && !rJson.empty() && !rAtlas.empty() &&
            fu->isFileExist(rJson) && fu->isFileExist(rAtlas)) {
            auto* ret = new GClientSpineAnimation();
            ret->initWithJsonFile(rJson, rAtlas, scale > 0.0f ? scale : 1.0f);
            if (ret->getSkeleton() != nullptr) {
                ret->bindInternalListeners();
                ret->autorelease();
                return ret;
            }
            delete ret;
        }

        // Safe empty fallback node so missing Spine assets never crash Lua scripts
        auto* dummy = new GClientSpineAnimation();
        dummy->ax::Node::init();
        dummy->autorelease();
        return dummy;
    }

    ~GClientSpineAnimation() override {
        releaseSpineLuaHandler(m_startHandler);
        releaseSpineLuaHandler(m_endHandler);
        releaseSpineLuaHandler(m_completeHandler);
        releaseSpineLuaHandler(m_eventHandler);
    }

    void setStartLuaHandler(int h) { releaseSpineLuaHandler(m_startHandler); m_startHandler = h; }
    void setEndLuaHandler(int h) { releaseSpineLuaHandler(m_endHandler); m_endHandler = h; }
    void setCompleteLuaHandler(int h) { releaseSpineLuaHandler(m_completeHandler); m_completeHandler = h; }
    void setEventLuaHandler(int h) { releaseSpineLuaHandler(m_eventHandler); m_eventHandler = h; }

    void triggerManualEvent(int trackIdx, const char* eventName, int intVal, float floatVal, const char* strVal) {
        const char* animName = "";
        if (getState()) {
            if (spine::TrackEntry* cur = getState()->getCurrent(static_cast<size_t>((std::max)(0, trackIdx)))) {
                if (cur->getAnimation()) animName = cur->getAnimation()->getName().buffer();
            }
        }
        invokeSpineEventLuaHandler(m_eventHandler, eventName, trackIdx, animName, intVal, floatVal, strVal);
    }

private:
    void bindInternalListeners() {
        setStartListener([this](spine::TrackEntry* entry) {
            if (!entry || m_startHandler == 0) return;
            invokeSpineTrackHandler(m_startHandler, entry->getTrackIndex(), 0, false);
        });
        setEndListener([this](spine::TrackEntry* entry) {
            if (!entry || m_endHandler == 0) return;
            invokeSpineTrackHandler(m_endHandler, entry->getTrackIndex(), 0, false);
        });
        setCompleteListener([this](spine::TrackEntry* entry) {
            if (!entry || m_completeHandler == 0) return;
            const int loops = static_cast<int>(std::floor(entry->getTrackTime() /
                (std::max)(0.0001f, entry->getAnimation() ? entry->getAnimation()->getDuration() : 1.0f))) + 1;
            invokeSpineTrackHandler(m_completeHandler, entry->getTrackIndex(), loops, true);
        });
        setEventListener([this](spine::TrackEntry* entry, spine::Event* event) {
            if (!entry || !event || m_eventHandler == 0) return;
            const char* evName = event->getData().getName().buffer();
            const char* anName = entry->getAnimation() ? entry->getAnimation()->getName().buffer() : "";
            const char* sVal   = event->getStringValue().buffer();
            invokeSpineEventLuaHandler(
                m_eventHandler,
                evName ? evName : "",
                entry->getTrackIndex(),
                anName ? anName : "",
                event->getIntValue(),
                event->getFloatValue(),
                sVal ? sVal : "");
        });
    }

    int m_startHandler    = 0;
    int m_endHandler      = 0;
    int m_completeHandler = 0;
    int m_eventHandler    = 0;
};

int lua_Spine_hasSkeletonData(lua_State* L) {
    const char* modelId = lua_tostring(L, 2);
    lua_pushboolean(L, (modelId && g_spineCache.count(modelId) > 0) ? 1 : 0);
    return 1;
}
int lua_Spine_setSkeletonDataToCache(lua_State* L) {
    const char* modelId   = lua_tostring(L, 2);
    const char* jsonPath  = lua_tostring(L, 3);
    const char* atlasPath = lua_tostring(L, 4);
    const float scale     = lua_isnumber(L, 5) ? static_cast<float>(lua_tonumber(L, 5)) : 1.0f;
    if (modelId && jsonPath && atlasPath) {
        g_spineCache[modelId] = CachedSpineEntry{
            resolveSpinePath(jsonPath, ".json"),
            resolveSpinePath(atlasPath, ".atlas"),
            scale
        };
    }
    return 0;
}
int lua_Spine_createFromCache(lua_State* L) {
    const char* modelId = lua_tostring(L, 2);
    auto it = modelId ? g_spineCache.find(modelId) : g_spineCache.end();
    GClientSpineAnimation* anim = (it != g_spineCache.end())
        ? GClientSpineAnimation::createSafe(it->second.jsonPath, it->second.atlasPath, it->second.scale)
        : GClientSpineAnimation::createSafe("", "", 1.0f);
    pushAxObj(L, anim, "SpineLuaAnimation");
    return 1;
}
int lua_Spine_createWithFile(lua_State* L) {
    const char* jsonPath  = lua_tostring(L, 2);
    const char* atlasPath = lua_tostring(L, 3);
    const float scale     = lua_isnumber(L, 4) ? static_cast<float>(lua_tonumber(L, 4)) : 1.0f;
    auto* anim = GClientSpineAnimation::createSafe(
        jsonPath ? jsonPath : "", atlasPath ? atlasPath : "", scale);
    pushAxObj(L, anim, "SpineLuaAnimation");
    return 1;
}
int lua_Spine_removeSkeletonData(lua_State* L) {
    if (const char* modelId = lua_tostring(L, 2)) {
        g_spineCache.erase(modelId);
    }
    return 0;
}
int lua_Spine_removeAllSkeletonData(lua_State* /*L*/) {
    g_spineCache.clear();
    return 0;
}
int lua_Spine_getAnimationCount(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    int count = 0;
    if (self && self->getSkeleton() && self->getSkeleton()->getData()) {
        count = static_cast<int>(self->getSkeleton()->getData()->getAnimations().size());
    }
    lua_pushinteger(L, count);
    return 1;
}
int lua_Spine_getAnimationName(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    const int idx = static_cast<int>(lua_tointeger(L, 2));
    if (self && self->getSkeleton() && self->getSkeleton()->getData()) {
        auto& anims = self->getSkeleton()->getData()->getAnimations();
        if (idx >= 0 && static_cast<size_t>(idx) < anims.size() && anims[static_cast<size_t>(idx)]) {
            const char* n = anims[static_cast<size_t>(idx)]->getName().buffer();
            lua_pushstring(L, n ? n : "");
            return 1;
        }
    }
    lua_pushstring(L, "");
    return 1;
}
int lua_Spine_setAnimation(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    const int track = (std::max)(0, static_cast<int>(lua_tointeger(L, 2)));
    const char* name = lua_tostring(L, 3);
    const bool loop = lua_toboolean(L, 4) != 0;
    if (self && name && self->getSkeleton() && self->getSkeleton()->getData() &&
        self->getSkeleton()->getData()->findAnimation(spine::String(name))) {
        self->setAnimation(track, name, loop);
        lua_newtable(L);
        lua_pushstring(L, name);
        lua_setfield(L, -2, "animationName");
        lua_pushinteger(L, track);
        lua_setfield(L, -2, "trackIndex");
        lua_pushboolean(L, loop ? 1 : 0);
        lua_setfield(L, -2, "loop");
        return 1;
    }
    lua_pushnil(L);
    return 1;
}
int lua_Spine_addAnimation(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    const int track = (std::max)(0, static_cast<int>(lua_tointeger(L, 2)));
    const char* name = lua_tostring(L, 3);
    const bool loop = lua_toboolean(L, 4) != 0;
    const float delay = lua_isnumber(L, 5) ? static_cast<float>(lua_tonumber(L, 5)) : 0.0f;
    if (self && name && self->getSkeleton() && self->getSkeleton()->getData() &&
        self->getSkeleton()->getData()->findAnimation(spine::String(name))) {
        self->addAnimation(track, name, loop, delay);
        lua_newtable(L);
        lua_pushstring(L, name);
        lua_setfield(L, -2, "animationName");
        lua_pushinteger(L, track);
        lua_setfield(L, -2, "trackIndex");
        lua_pushboolean(L, loop ? 1 : 0);
        lua_setfield(L, -2, "loop");
        return 1;
    }
    lua_pushnil(L);
    return 1;
}
int lua_Spine_setMix(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    const char* from = lua_tostring(L, 2);
    const char* to   = lua_tostring(L, 3);
    const float dur  = static_cast<float>(lua_tonumber(L, 4));
    if (self && self->getSkeleton() && from && to) {
        self->setMix(from, to, dur);
    }
    return 0;
}
int lua_Spine_clearTrack(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    const int track = lua_isnumber(L, 2) ? (std::max)(0, static_cast<int>(lua_tointeger(L, 2))) : 0;
    if (self && self->getSkeleton()) self->clearTrack(track);
    return 0;
}
int lua_Spine_clearTracks(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    if (self && self->getSkeleton()) self->clearTracks();
    return 0;
}
int lua_Spine_setToSetupPose(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    if (self && self->getSkeleton()) self->setToSetupPose();
    return 0;
}
int lua_Spine_setBonesToSetupPose(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    if (self && self->getSkeleton()) self->setBonesToSetupPose();
    return 0;
}
int lua_Spine_setSlotsToSetupPose(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    if (self && self->getSkeleton()) self->setSlotsToSetupPose();
    return 0;
}
int lua_Spine_updateWorldTransform(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    if (self && self->getSkeleton()) self->updateWorldTransform(spine::Physics_Update);
    return 0;
}
int lua_Spine_setTimeScale(lua_State* L) {
    if (auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1)) {
        self->setTimeScale(static_cast<float>(lua_tonumber(L, 2)));
    }
    return 0;
}
int lua_Spine_getCurrent(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    const int track = lua_isnumber(L, 2) ? (std::max)(0, static_cast<int>(lua_tointeger(L, 2))) : 0;
    if (self && self->getState()) {
        if (spine::TrackEntry* cur = self->getState()->getCurrent(static_cast<size_t>(track))) {
            if (cur->getAnimation()) {
                lua_newtable(L);
                const char* n = cur->getAnimation()->getName().buffer();
                lua_pushstring(L, n ? n : "");
                lua_setfield(L, -2, "animationName");
                lua_pushinteger(L, track);
                lua_setfield(L, -2, "trackIndex");
                lua_pushboolean(L, cur->getLoop() ? 1 : 0);
                lua_setfield(L, -2, "loop");
                return 1;
            }
        }
    }
    lua_pushnil(L);
    return 1;
}
int lua_Spine_pause(lua_State* L) {
    if (auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1)) self->pause();
    return 0;
}
int lua_Spine_resume(lua_State* L) {
    if (auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1)) self->resume();
    return 0;
}
int lua_Spine_setSkin(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    const char* skin = lua_tostring(L, 2);
    bool ok = false;
    if (self && self->getSkeleton() && self->getSkeleton()->getData() && skin && *skin) {
        if (self->getSkeleton()->getData()->findSkin(spine::String(skin)) != nullptr) {
            self->setSkin(skin);
            ok = true;
        }
    }
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}
int lua_Spine_findBone(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    const char* boneName = lua_tostring(L, 2);
    if (self && self->getSkeleton() && boneName && *boneName) {
        if (spine::Bone* b = self->findBone(boneName)) {
            lua_newtable(L);
            lua_pushnumber(L, b->getX());        lua_setfield(L, -2, "x");
            lua_pushnumber(L, b->getY());        lua_setfield(L, -2, "y");
            lua_pushnumber(L, b->getWorldX());   lua_setfield(L, -2, "worldX");
            lua_pushnumber(L, b->getWorldY());   lua_setfield(L, -2, "worldY");
            lua_pushnumber(L, b->getRotation()); lua_setfield(L, -2, "rotation");
            lua_pushnumber(L, b->getScaleX());   lua_setfield(L, -2, "scaleX");
            lua_pushnumber(L, b->getScaleY());   lua_setfield(L, -2, "scaleY");
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}
int lua_Spine_setAttachment(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    const char* slot = lua_tostring(L, 2);
    const char* att  = lua_isstring(L, 3) ? lua_tostring(L, 3) : "";
    const bool ok = (self && self->getSkeleton() && slot) ? self->setAttachment(slot, att ? att : "") : false;
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}
int lua_Spine_boundingBox(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    const ax::Rect box = (self && self->getSkeleton()) ? self->getBoundingBox() : ax::Rect::ZERO;
    lua_newtable(L);
    lua_pushnumber(L, box.origin.x);    lua_setfield(L, -2, "x");
    lua_pushnumber(L, box.origin.y);    lua_setfield(L, -2, "y");
    lua_pushnumber(L, box.size.width);  lua_setfield(L, -2, "width");
    lua_pushnumber(L, box.size.height); lua_setfield(L, -2, "height");
    return 1;
}
int lua_Spine_update(lua_State* L) {
    auto* self = getSafeAxObject<spine::SkeletonAnimation>(L, 1);
    if (self && self->getSkeleton()) {
        self->update(static_cast<float>(lua_tonumber(L, 2)));
    }
    return 0;
}
int lua_Spine_triggerEvent(lua_State* L) {
    if (auto* self = getSafeAxObject<GClientSpineAnimation>(L, 1)) {
        const int track = static_cast<int>(lua_tointeger(L, 2));
        const char* ev  = lua_tostring(L, 3);
        const int iVal  = static_cast<int>(lua_tointeger(L, 4));
        const float fVal= static_cast<float>(lua_tonumber(L, 5));
        const char* sVal= lua_tostring(L, 6);
        if (ev && *ev) self->triggerManualEvent(track, ev, iVal, fVal, sVal ? sVal : "");
    }
    return 0;
}
int extractSpineLuaHandler(lua_State* L) {
    const int fnIdx = lua_isfunction(L, 3) ? 3 : (lua_isfunction(L, 2) ? 2 : 0);
    return fnIdx > 0 ? toluafix_ref_function(L, fnIdx, 0) : 0;
}
int lua_Spine_setStartListener(lua_State* L) {
    if (auto* self = getSafeAxObject<GClientSpineAnimation>(L, 1)) self->setStartLuaHandler(extractSpineLuaHandler(L));
    return 0;
}
int lua_Spine_setEndListener(lua_State* L) {
    if (auto* self = getSafeAxObject<GClientSpineAnimation>(L, 1)) self->setEndLuaHandler(extractSpineLuaHandler(L));
    return 0;
}
int lua_Spine_setCompleteListener(lua_State* L) {
    if (auto* self = getSafeAxObject<GClientSpineAnimation>(L, 1)) self->setCompleteLuaHandler(extractSpineLuaHandler(L));
    return 0;
}
int lua_Spine_setEventListener(lua_State* L) {
    if (auto* self = getSafeAxObject<GClientSpineAnimation>(L, 1)) self->setEventLuaHandler(extractSpineLuaHandler(L));
    return 0;
}

void registerSpineBindings(lua_State* L) {
    tolua_open(L);
    tolua_module(L, nullptr, 0);
    tolua_beginmodule(L, nullptr);
    tolua_usertype(L, "SpineLuaAnimation");
    tolua_cclass(L, "SpineLuaAnimation", "SpineLuaAnimation", "ax.Node", nullptr);
    tolua_beginmodule(L, "SpineLuaAnimation");
    tolua_function(L, "hasSkeletonData", lua_Spine_hasSkeletonData);
    tolua_function(L, "setSkeletonDataToCache", lua_Spine_setSkeletonDataToCache);
    tolua_function(L, "createFromCache", lua_Spine_createFromCache);
    tolua_function(L, "createWithFile", lua_Spine_createWithFile);
    tolua_function(L, "removeSkeletonData", lua_Spine_removeSkeletonData);
    tolua_function(L, "removeAllSkeletonData", lua_Spine_removeAllSkeletonData);
    tolua_function(L, "getAnimationCount", lua_Spine_getAnimationCount);
    tolua_function(L, "getAnimationName", lua_Spine_getAnimationName);
    tolua_function(L, "setAnimation", lua_Spine_setAnimation);
    tolua_function(L, "addAnimation", lua_Spine_addAnimation);
    tolua_function(L, "setMix", lua_Spine_setMix);
    tolua_function(L, "clearTrack", lua_Spine_clearTrack);
    tolua_function(L, "clearTracks", lua_Spine_clearTracks);
    tolua_function(L, "setToSetupPose", lua_Spine_setToSetupPose);
    tolua_function(L, "setBonesToSetupPose", lua_Spine_setBonesToSetupPose);
    tolua_function(L, "setSlotsToSetupPose", lua_Spine_setSlotsToSetupPose);
    tolua_function(L, "updateWorldTransform", lua_Spine_updateWorldTransform);
    tolua_function(L, "setTimeScale", lua_Spine_setTimeScale);
    tolua_function(L, "getCurrent", lua_Spine_getCurrent);
    tolua_function(L, "pause", lua_Spine_pause);
    tolua_function(L, "resume", lua_Spine_resume);
    tolua_function(L, "setSkin", lua_Spine_setSkin);
    tolua_function(L, "findBone", lua_Spine_findBone);
    tolua_function(L, "setAttachment", lua_Spine_setAttachment);
    tolua_function(L, "boundingBox", lua_Spine_boundingBox);
    tolua_function(L, "getBoundingBox", lua_Spine_boundingBox);
    tolua_function(L, "update", lua_Spine_update);
    tolua_function(L, "triggerEvent", lua_Spine_triggerEvent);
    tolua_function(L, "setLuaStartListener", lua_Spine_setStartListener);
    tolua_function(L, "setLuaEndListener", lua_Spine_setEndListener);
    tolua_function(L, "setLuaCompleteListener", lua_Spine_setCompleteListener);
    tolua_function(L, "setLuaEventListener", lua_Spine_setEventListener);
    tolua_function(L, "setStartListener", lua_Spine_setStartListener);
    tolua_function(L, "setEndListener", lua_Spine_setEndListener);
    tolua_function(L, "setCompleteListener", lua_Spine_setCompleteListener);
    tolua_function(L, "setEventListener", lua_Spine_setEventListener);
    tolua_endmodule(L);
    tolua_endmodule(L);

    lua_newtable(L);
    lua_getglobal(L, "SpineLuaAnimation");
    lua_pushvalue(L, -1);
    lua_setfield(L, -3, "SpineLuaAnimation");
    lua_setfield(L, -2, "SkeletonAnimation");
    lua_setglobal(L, "spine");
}

void wrapMetatableMethod(lua_State* L, const char* typeName, const char* methodName, lua_CFunction wrapper) {
    luaL_getmetatable(L, typeName);
    if (lua_istable(L, -1)) {
        lua_pushstring(L, methodName);
        lua_rawget(L, -2);
        lua_pushstring(L, methodName);
        lua_pushvalue(L, -2);
        lua_remove(L, -3);
        lua_pushcclosure(L, wrapper, 1);
        lua_rawset(L, -3);
    }
    lua_pop(L, 1);
}

void wrapWidgetCommonHooks(lua_State* L, const char* typeName) {
    wrapMetatableMethod(L, typeName, "addNode", &hook_Widget_addNode);
    wrapMetatableMethod(L, typeName, "removeNode", &hook_Widget_removeNode);
    wrapMetatableMethod(L, typeName, "removeNodeByTag", &hook_Widget_removeNodeByTag);
    wrapMetatableMethod(L, typeName, "removeAllNodes", &hook_Widget_removeAllNodes);
    wrapMetatableMethod(L, typeName, "getTextHeight", &hook_Node_getTextHeight);
}

} // namespace

// ============================================================================
// Public Entry Points
// ============================================================================

void UnscheduleAllLuaScriptEntries() {
    std::vector<int> entries;
    {
        std::lock_guard<std::mutex> lock(g_luaScriptEntriesMutex);
        entries.assign(g_activeLuaScriptEntries.begin(), g_activeLuaScriptEntries.end());
        g_activeLuaScriptEntries.clear();
    }
    if (entries.empty()) return;
    if (auto* dir = ax::Director::getInstance()) {
        if (auto* sched = dir->getScheduler()) {
            for (int id : entries) {
                sched->unscheduleScriptEntry(static_cast<unsigned int>(id));
            }
        }
    }
}

void RescheduleLuaHelpersCallbacks() {
    const std::vector<DeferredArmatureAsyncCallback*> snapshot = g_pendingArmatureCallbacks;
    for (auto* cb : snapshot) {
        if (cb) cb->ensureOnScheduler();
    }
}

void RegisterRichTextBindings(lua_State* L) {
    registerRichTextBindingsInternal(L);
}

void InstallNetworkResilienceHook(lua_State* L) {
    gclient::bindings::InstallNetworkResilienceHookImpl(L);
}

void RegisterAssetLoaderHooks(lua_State* L) {
    if (!L) return;

    InstallNetworkResilienceHook(L);

    wrapMetatableMethod(L, "ax.FileUtils", "isFileExist", &hook_FileUtils_isFileExist);
    wrapMetatableMethod(L, "ax.Scheduler", "scheduleScriptFunc", &hook_Scheduler_scheduleScriptFunc);
    wrapMetatableMethod(L, "ax.Scheduler", "unscheduleScriptEntry", &hook_Scheduler_unscheduleScriptEntry);

    wrapMetatableMethod(L, "ax.TextureCache", "addImage", &hook_TextureCache_addImage);
    wrapMetatableMethod(L, "ax.TextureCache", "removeTextureForKey", &hook_TextureCache_removeTextureForKey);

    wrapMetatableMethod(L, "ax.SpriteFrameCache", "addSpriteFrames", &hook_SpriteFrameCache_addSpriteFrames);
    wrapMetatableMethod(L, "ax.SpriteFrameCache", "addSpriteFramesWithFile", &hook_SpriteFrameCache_addSpriteFrames);
    wrapMetatableMethod(L, "ax.SpriteFrameCache", "addSpriteFramesWithBinary", &hook_SpriteFrameCache_addSpriteFrames);
    wrapMetatableMethod(L, "ax.SpriteFrameCache", "removeSpriteFramesFromFile", &hook_SpriteFrameCache_removeSpriteFramesFromFile);

    wrapMetatableMethod(L, "ccs.GUIReader", "widgetFromJsonFile", &hook_GUIReader_widgetFromJsonFile);
    wrapMetatableMethod(L, "ccs.GUIReader", "widgetFromPbFile", &hook_GUIReader_widgetFromJsonFile);
    wrapMetatableMethod(L, "ccs.SceneReader", "createNodeWithSceneFile", &hook_SceneReader_createNodeWithSceneFile);

    wrapMetatableMethod(L, "ccs.ArmatureDataManager", "addArmatureFileInfo", &hook_addArmatureFileInfo);
    wrapMetatableMethod(L, "ccs.ArmatureDataManager", "addArmatureFileInfoAsync", &hook_addArmatureFileInfoAsync);
    wrapMetatableMethod(L, "ccs.ArmatureDataManager", "removeArmatureFileInfo", &hook_removeArmatureFileInfo);
    wrapMetatableMethod(L, "ccs.ArmatureAnimation", "setMovementLoopByName", &hook_ArmatureAnimation_setMovementLoopByName);

    wrapMetatableMethod(L, "ax.Director", "getCurrentTime", &hook_Director_getCurrentTime);
    wrapMetatableMethod(L, "ax.Node", "getTextHeight", &hook_Node_getTextHeight);

    wrapMetatableMethod(L, "ax.Sprite", "create", &hook_Sprite_create);
    wrapMetatableMethod(L, "ax.Sprite", "createWithSpriteFrameName", &hook_Sprite_createWithSpriteFrameName);
    wrapMetatableMethod(L, "axui.Scale9Sprite", "create", &hook_Scale9Sprite_create);
    wrapMetatableMethod(L, "axui.Scale9Sprite", "createWithSpriteFrameName", &hook_Scale9Sprite_createWithSpriteFrameName);

    wrapMetatableMethod(L, "ax.Label", "enableStroke", &hook_Label_enableStroke);
    wrapMetatableMethod(L, "ax.Label", "disableStroke", &hook_Label_disableStroke);
    wrapMetatableMethod(L, "ax.Label", "getTextHeight", &hook_Node_getTextHeight);

    const char* uiWidgetTypes[] = {
        "axui.Widget", "axui.Layout", "axui.Button", "axui.CheckBox", "axui.ImageView",
        "axui.Text", "axui.TextAtlas", "axui.TextBMFont", "axui.LoadingBar",
        "axui.Slider", "axui.TextField", "axui.ScrollView", "axui.ListView", "axui.PageView"
    };
    for (const char* t : uiWidgetTypes) {
        wrapWidgetCommonHooks(L, t);
    }

    wrapMetatableMethod(L, "axui.ImageView", "loadTexture", &hook_ImageView_loadTexture);
    wrapMetatableMethod(L, "axui.LoadingBar", "loadTexture", &hook_LoadingBar_loadTexture);
    wrapMetatableMethod(L, "axui.Layout", "setBackGroundImage", &hook_Layout_setBackGroundImage);
    wrapMetatableMethod(L, "axui.ScrollView", "setBackGroundImage", &hook_Layout_setBackGroundImage);
    wrapMetatableMethod(L, "axui.ListView", "setBackGroundImage", &hook_Layout_setBackGroundImage);
    wrapMetatableMethod(L, "axui.PageView", "setBackGroundImage", &hook_Layout_setBackGroundImage);

    wrapMetatableMethod(L, "axui.Button", "loadTextures", &hook_Button_loadTextures);
    wrapMetatableMethod(L, "axui.Button", "loadTextureNormal", &hook_Button_loadTextureNormal);
    wrapMetatableMethod(L, "axui.Button", "loadTexturePressed", &hook_Button_loadTexturePressed);
    wrapMetatableMethod(L, "axui.Button", "loadTextureDisabled", &hook_Button_loadTextureDisabled);
    wrapMetatableMethod(L, "axui.Button", "enableTitleStroke", &hook_Button_enableTitleStroke);
    wrapMetatableMethod(L, "axui.Button", "disableTitleStroke", &hook_Button_disableTitleStroke);

    wrapMetatableMethod(L, "axui.Text", "enableStroke", &hook_Text_enableStroke);
    wrapMetatableMethod(L, "axui.Text", "disableStroke", &hook_Text_disableStroke);
    wrapMetatableMethod(L, "axui.Text", "enableShadow", &hook_Text_enableShadow);

    registerRichTextBindingsInternal(L);
    registerSpineBindings(L);
}
