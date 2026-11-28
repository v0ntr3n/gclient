// ============================================================================
// LuaHelpers.cpp — Axmol v2.11.5 LTS (x64 C++20) Port
//
// Bridges Kestrel-Canvas Lua helpers, asset loader hooks (PbGuiLoader,
// XmlbArmatureLoader, PlistbLoader), Spine 4.2 SkeletonAnimation (SpineLuaAnimation),
// RichText, UI widget 2.2.6 extensions, NetworkResilienceHook, and clean
// soft-restart callback/timer reset onto Axmol using LuaBindTemplates.h.
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
#include "bindings/LuaBindTemplates.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

USING_NS_CC;

namespace {

namespace lb = gclient::lua_bind;

template <typename T, lb::FixedName Tag>
struct TypeTagEntry {};

template <typename... Entries>
struct RuntimeTypeTable;

template <>
struct RuntimeTypeTable<> {
    static const char* match(ax::Object*) noexcept { return "ax.Object"; }
};

template <typename T, lb::FixedName Tag, typename... Rest>
struct RuntimeTypeTable<TypeTagEntry<T, Tag>, Rest...> {
    static const char* match(ax::Object* obj) noexcept {
        return dynamic_cast<T*>(obj) ? Tag.c_str() : RuntimeTypeTable<Rest...>::match(obj);
    }
};

const char* inferRuntimeToluaType(ax::Object* obj) {
    if (!obj) return "ax.Object";
    using Table = RuntimeTypeTable<
        TypeTagEntry<spine::SkeletonAnimation, "SpineLuaAnimation">,
        TypeTagEntry<ax::ui::RichText, "RichText">,
        TypeTagEntry<ax::ui::RichElementText, "RichElementText">,
        TypeTagEntry<ax::ui::RichElementImage, "RichElementImage">,
        TypeTagEntry<ax::ui::RichElementCustomNode, "RichElementCustomNode">,
        TypeTagEntry<ax::ui::TouchGroup, "TouchGroup">,
        TypeTagEntry<ax::ui::Button, "axui.Button">,
        TypeTagEntry<ax::ui::ImageView, "axui.ImageView">,
        TypeTagEntry<ax::ui::Text, "axui.Text">,
        TypeTagEntry<ax::ui::TextAtlas, "axui.TextAtlas">,
        TypeTagEntry<ax::ui::TextBMFont, "axui.TextBMFont">,
        TypeTagEntry<ax::ui::LoadingBar, "axui.LoadingBar">,
        TypeTagEntry<ax::ui::CheckBox, "axui.CheckBox">,
        TypeTagEntry<ax::ui::Slider, "axui.Slider">,
        TypeTagEntry<ax::ui::TextField, "axui.TextField">,
        TypeTagEntry<ax::ui::ListView, "axui.ListView">,
        TypeTagEntry<ax::ui::PageView, "axui.PageView">,
        TypeTagEntry<ax::ui::ScrollView, "axui.ScrollView">,
        TypeTagEntry<ax::ui::Layout, "axui.Layout">,
        TypeTagEntry<ax::ui::Widget, "axui.Widget">,
        TypeTagEntry<ax::ui::Scale9Sprite, "axui.Scale9Sprite">,
        TypeTagEntry<cocostudio::Armature, "ccs.Armature">,
        TypeTagEntry<ax::Sprite, "ax.Sprite">,
        TypeTagEntry<ax::DrawNode, "ax.DrawNode">,
        TypeTagEntry<ax::Layer, "ax.Layer">,
        TypeTagEntry<ax::Node, "ax.Node">>;
    return Table::match(obj);
}

template <typename T>
inline void pushAxObj(lua_State* L, T* obj, const char* explicitType = nullptr) {
    if (!obj) {
        lua_pushnil(L);
        return;
    }
    const char* tname = (explicitType && *explicitType)
        ? explicitType
        : inferRuntimeToluaType(static_cast<ax::Object*>(obj));
    lb::pushAxObject(L, obj, tname);
}

inline void releaseEngineScriptHandler(int& handler) {
    if (handler != 0) {
        if (auto* mgr = ax::ScriptEngineManager::getInstance()) {
            if (auto* eng = mgr->getScriptEngine()) {
                eng->removeScriptHandler(handler);
            }
        }
        handler = 0;
    }
}

bool readLuaColor3B(lua_State* L, int idx, ax::Color3B& out) {
    const int absIdx = lb::toAbsIndex(L, idx);
    if (lua_istable(L, absIdx)) {
        auto chan = [&](const char* k) -> uint8_t {
            lua_getfield(L, absIdx, k);
            const int v = static_cast<int>(lua_tointeger(L, -1));
            lua_pop(L, 1);
            return static_cast<uint8_t>(std::clamp(v, 0, 255));
        };
        out = ax::Color3B(chan("r"), chan("g"), chan("b"));
        return true;
    }
    if (auto* ptr = static_cast<ax::Color3B*>(tolua_tousertype(L, absIdx, nullptr))) {
        out = *ptr;
        return true;
    }
    return false;
}

bool readLuaVec2(lua_State* L, int idx, ax::Vec2& out) {
    const int absIdx = lb::toAbsIndex(L, idx);
    if (lua_istable(L, absIdx)) {
        auto comp = [&](const char* k1, const char* k2, int arrIdx) -> float {
            lua_getfield(L, absIdx, k1);
            if (lua_isnil(L, -1)) { lua_pop(L, 1); lua_getfield(L, absIdx, k2); }
            if (lua_isnil(L, -1)) { lua_pop(L, 1); lua_rawgeti(L, absIdx, arrIdx); }
            const float v = static_cast<float>(lua_tonumber(L, -1));
            lua_pop(L, 1);
            return v;
        };
        out.x = comp("x", "width", 1);
        out.y = comp("y", "height", 2);
        return true;
    }
    if (auto* ptr = static_cast<ax::Vec2*>(tolua_tousertype(L, absIdx, nullptr))) {
        out = *ptr;
        return true;
    }
    return false;
}

int callOriginalMethod(lua_State* L) {
    if (!lua_isfunction(L, lua_upvalueindex(1))) return 0;
    const int nargs = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, nargs, LUA_MULTRET);
    return lua_gettop(L);
}

void registerToluaClass(
    lua_State* L,
    const char* className,
    const char* baseName,
    std::span<const luaL_Reg> funcs)
{
    tolua_usertype(L, className);
    tolua_cclass(L, className, className, baseName, nullptr);
    if (!funcs.empty()) {
        tolua_beginmodule(L, className);
        for (const auto& f : funcs) {
            if (f.name && f.func) tolua_function(L, f.name, f.func);
        }
        tolua_endmodule(L);
    }
}

std::mutex                      g_luaFuncsNamesMutex;
std::unordered_set<std::string> g_registeredLuaFuncNames;

std::mutex       g_timerTrackerMutex;
CTimer*          g_sharedTimerInstance = nullptr;
std::vector<int> g_pendingTimerLuaRefs;

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
        std::lock_guard<std::mutex> lock(g_luaFuncsNamesMutex);
        g_registeredLuaFuncNames.insert(name);
    }
}

void CLuaFuncs::removeHandler(const char* name) {
    if (!name) return;
    {
        std::lock_guard<std::mutex> lock(g_luaFuncsNamesMutex);
        g_registeredLuaFuncNames.erase(name);
    }
    auto it = m_handlers.find(name);
    if (it != m_handlers.end()) {
        int ref = it->second;
        releaseEngineScriptHandler(ref);
        m_handlers.erase(it);
    }
}

int CLuaFuncs::call(const char* name, const std::list<ax::LuaValue>& args) {
    if (!name) return 0;
    auto it = m_handlers.find(name);
    if (it == m_handlers.end()) return 0;
    auto* eng = ax::LuaEngine::getInstance();
    auto* stack = eng ? eng->getLuaStack() : nullptr;
    if (!stack) return 0;
    for (const auto& v : args) stack->pushLuaValue(v);
    return stack->executeFunctionByHandler(it->second, static_cast<int>(args.size()));
}

CTimer* CTimer::sharedTimer() {
    std::lock_guard<std::mutex> lock(g_timerTrackerMutex);
    if (!g_sharedTimerInstance) g_sharedTimerInstance = new CTimer();
    return g_sharedTimerInstance;
}

CTimer::~CTimer() = default;

void CTimer::addEvent(int delaySeconds, int luaFuncRef) {
    if (luaFuncRef == 0) return;
    {
        std::lock_guard<std::mutex> trackLock(g_timerTrackerMutex);
        g_pendingTimerLuaRefs.push_back(luaFuncRef);
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.push_back(Event{std::time(nullptr) + (std::max)(0, delaySeconds), luaFuncRef});
}

void CTimer::update(float /*dt*/) {
    std::vector<int> readyRefs;
    const std::time_t now = std::time(nullptr);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_events.begin(); it != m_events.end();) {
            if (now >= it->fireAt) {
                readyRefs.push_back(it->luaFuncRef);
                it = m_events.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (readyRefs.empty()) return;
    {
        std::lock_guard<std::mutex> trackLock(g_timerTrackerMutex);
        for (int ref : readyRefs) {
            auto found = std::find(g_pendingTimerLuaRefs.begin(), g_pendingTimerLuaRefs.end(), ref);
            if (found != g_pendingTimerLuaRefs.end()) g_pendingTimerLuaRefs.erase(found);
        }
    }
    auto* eng = ax::LuaEngine::getInstance();
    if (auto* stack = eng ? eng->getLuaStack() : nullptr) {
        for (int ref : readyRefs) {
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
        ret->setSystemFontName(fn);
        ret->setSystemFontSize(fs);
        ret->setString(txt);
        ok = true;
    }
    if (ok) {
        ret->autorelease();
        return ret;
    }
    delete ret;
    return nullptr;
}

void CCStrokeLabel::setStroke(unsigned int strokeSize, ax::Color4B color) {
    if (strokeSize > 0) enableOutline(color, static_cast<int>(strokeSize));
    else disableEffect(ax::LabelEffect::OUTLINE);
}

void CCStrokeLabel::setContrast(float /*contrast*/) {}

SpriteBlur* SpriteBlur::create(const char* filename) {
    auto* ret = new SpriteBlur();
    const std::string resolved = filename ? gclient::compat::ResolveConvertedAssetPath(filename) : std::string();
    if ((!resolved.empty() && ret->initWithFile(resolved)) || ret->init()) {
        ret->autorelease();
        return ret;
    }
    delete ret;
    return nullptr;
}

SpriteBlur* SpriteBlur::createWithTexture(ax::Texture2D* texture) {
    auto* ret = new SpriteBlur();
    if ((texture && ret->initWithTexture(texture, ax::Rect(0.0f, 0.0f,
            texture->getContentSize().width, texture->getContentSize().height))) ||
        ret->init()) {
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

int tolua_extensions_ccb_open(lua_State* /*tolua_S*/) { return 1; }

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
        std::lock_guard<std::mutex> lock(g_luaScriptEntriesMutex);
        g_activeLuaScriptEntries.erase(static_cast<int>(lua_tointeger(L, 2)));
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

    static constexpr std::pair<std::string_view, const char*> kBinAlts[] = {
        {".xml", ".xmlb"}, {".json", ".pb"}, {".plist", ".plistb"},
    };
    for (const auto& [srcExt, binExt] : kBinAlts) {
        if (norm.ends_with(srcExt) &&
            fu->isFileExist(gclient::assets::ReplaceFileExtension(norm, binExt))) {
            return true;
        }
    }
    return false;
}

int hook_FileUtils_isFileExist(lua_State* L) {
    const char* path = lua_tostring(L, 2);
    lua_pushboolean(L, (path && *path && doesAnyVariantExist(path)) ? 1 : 0);
    return 1;
}

int hook_TextureCache_addImage(lua_State* L) {
    const char* path = lua_tostring(L, 2);
    if (!path || !*path) {
        lua_pushnil(L);
        return 1;
    }
    auto* cache = ax::Director::getInstance()->getTextureCache();
    ax::Texture2D* tex = cache ? cache->addImage(gclient::compat::ResolveConvertedAssetPath(path)) : nullptr;
    pushAxObj(L, tex, "ax.Texture2D");
    return 1;
}

int hook_TextureCache_removeTextureForKey(lua_State* L) {
    if (const char* key = lua_tostring(L, 2); key && *key) {
        if (auto* cache = ax::Director::getInstance()->getTextureCache()) {
            cache->removeTextureForKey(key);
            const std::string resolved = gclient::compat::ResolveConvertedAssetPath(key);
            if (resolved != key) cache->removeTextureForKey(resolved);
        }
    }
    return 0;
}

int hook_SpriteFrameCache_addSpriteFrames(lua_State* L) {
    const char* plist = lua_tostring(L, 2);
    if (!plist || !*plist) return 0;

    auto* explicitTex = (lua_gettop(L) >= 3 && lua_type(L, 3) == LUA_TUSERDATA)
        ? lb::getAxObject<ax::Texture2D>(L, 3)
        : nullptr;

    const std::string resolvedPlist = gclient::compat::ResolveConvertedAssetPath(plist);
    auto* fu = ax::FileUtils::getInstance();
    if (fu && fu->isFileExist(resolvedPlist) && resolvedPlist.ends_with(".plist")) {
        auto* sfc = ax::SpriteFrameCache::getInstance();
        if (explicitTex) {
            sfc->addSpriteFramesWithFile(resolvedPlist, explicitTex);
        } else if (lua_gettop(L) >= 3 && lua_type(L, 3) == LUA_TSTRING) {
            sfc->addSpriteFramesWithFile(
                resolvedPlist, gclient::compat::ResolveConvertedAssetPath(lua_tostring(L, 3)));
        } else {
            sfc->addSpriteFramesWithFile(resolvedPlist);
        }
        return 0;
    }

    (void)gclient::assets::PlistbLoader::AddSpriteFramesWithBinary(plist, explicitTex);
    return 0;
}

int hook_SpriteFrameCache_removeSpriteFramesFromFile(lua_State* L) {
    if (const char* plist = lua_tostring(L, 2); plist && *plist) {
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
    if (const char* fileName = lua_tostring(L, 2); fileName && *fileName) {
        if (ax::Node* n = gclient::assets::PbGuiLoader::SceneFromPbFile(fileName)) {
            pushAxObj(L, n, "ax.Node");
            return 1;
        }
    }
    return callOriginalMethod(L);
}

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
        releaseEngineScriptHandler(m_luaHandler);
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

    void cancelAndRelease() {
        unscheduleSelf();
        releaseEngineScriptHandler(m_luaHandler);
        release();
    }

    void onFire(float /*dt*/) {
        unscheduleSelf();
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
    void unscheduleSelf() {
        if (auto* dir = ax::Director::getInstance()) {
            if (auto* sched = dir->getScheduler()) sched->unscheduleAllForTarget(this);
        }
    }

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
    if (argc == 1) loadArmatureWithXmlbFallback(nullptr, nullptr, lua_tostring(L, 2));
    else if (argc >= 3) loadArmatureWithXmlbFallback(lua_tostring(L, 2), lua_tostring(L, 3), lua_tostring(L, 4));
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
        if (const int handler = toluafix_ref_function(L, funcIdx, 0); handler != 0) {
            new DeferredArmatureAsyncCallback(handler);
        }
    }
    return 0;
}

int hook_removeArmatureFileInfo(lua_State* L) {
    if (const char* configPath = lua_tostring(L, 2); configPath && *configPath) {
        auto* mgr = cocostudio::ArmatureDataManager::getInstance();
        const std::string norm = gclient::assets::NormalizeAssetPath(configPath);
        const std::string xmlb = gclient::assets::ReplaceFileExtension(norm, ".xmlb");
        mgr->removeArmatureFileInfo(norm);
        if (xmlb != norm) mgr->removeArmatureFileInfo(xmlb);
    }
    return 0;
}

int hook_ArmatureAnimation_setMovementLoopByName(lua_State* L) {
    auto* anim = lb::getAxObject<cocostudio::ArmatureAnimation>(L, 1);
    const char* movName = lua_tostring(L, 2);
    if (anim && movName && anim->getAnimationData()) {
        if (auto* mov = anim->getAnimationData()->getMovement(movName)) {
            mov->loop = (lua_toboolean(L, 3) != 0);
        }
    }
    return 0;
}

int hook_Director_getCurrentTime(lua_State* L) {
    using namespace std::chrono;
    lua_pushnumber(L, static_cast<lua_Number>(duration<double>(steady_clock::now().time_since_epoch()).count()));
    return 1;
}

// --- Unified Safe Sprite & Scale9Sprite Creation Templates ---
template <typename NodeT, lb::FixedName Tag>
int hookCreateSpriteLike(lua_State* L) {
    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) {
        if (const char* rawPath = lua_tostring(L, 2); rawPath && *rawPath) {
            const std::string resolved = gclient::compat::ResolveConvertedAssetPath(rawPath);
            if (ax::FileUtils::getInstance()->isFileExist(resolved)) {
                if (auto* obj = NodeT::create(resolved)) {
                    pushAxObj(L, obj, Tag.c_str());
                    return 1;
                }
            }
            if (auto* sf = ax::SpriteFrameCache::getInstance()->getSpriteFrameByName(rawPath)) {
                if (auto* obj = NodeT::createWithSpriteFrame(sf)) {
                    pushAxObj(L, obj, Tag.c_str());
                    return 1;
                }
            }
        }
    }
    pushAxObj(L, NodeT::create(), Tag.c_str());
    return 1;
}

template <typename NodeT, lb::FixedName Tag, bool FallbackToFile>
int hookCreateWithFrameNameLike(lua_State* L) {
    if (const char* name = lua_tostring(L, 2); name && *name) {
        if (auto* sf = ax::SpriteFrameCache::getInstance()->getSpriteFrameByName(name)) {
            if (auto* obj = NodeT::createWithSpriteFrame(sf)) {
                pushAxObj(L, obj, Tag.c_str());
                return 1;
            }
        }
        if constexpr (FallbackToFile) {
            const std::string resolved = gclient::compat::ResolveConvertedAssetPath(name);
            if (ax::FileUtils::getInstance()->isFileExist(resolved)) {
                if (auto* obj = NodeT::create(resolved)) {
                    pushAxObj(L, obj, Tag.c_str());
                    return 1;
                }
            }
        }
    }
    pushAxObj(L, NodeT::create(), Tag.c_str());
    return 1;
}

// --- Widget 2.2.6 Node / Texture / Stroke Extensions ---
ax::ui::Widget::TextureResType resolveWidgetTexArg(
    const char* rawPath,
    int explicitTexType,
    bool hasExplicitType,
    std::string& outPath)
{
    if (!rawPath || !*rawPath) {
        outPath.clear();
        return ax::ui::Widget::TextureResType::LOCAL;
    }
    if (hasExplicitType && explicitTexType == 1 &&
        ax::SpriteFrameCache::getInstance()->getSpriteFrameByName(rawPath) != nullptr) {
        outPath = rawPath;
        return ax::ui::Widget::TextureResType::PLIST;
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
    auto* self = lb::getAxObject<ax::ui::Widget>(L, 1);
    auto* child = lb::getAxObject<ax::Node>(L, 2);
    if (!self || !child) return 0;
    const int z = lua_isnumber(L, 3) ? static_cast<int>(lua_tointeger(L, 3)) : child->getLocalZOrder();
    const int tag = lua_isnumber(L, 4) ? static_cast<int>(lua_tointeger(L, 4)) : child->getTag();
    self->addProtectedChild(child, z, tag);
    return 0;
}

int hook_Widget_removeNode(lua_State* L) {
    auto* self = lb::getAxObject<ax::ui::Widget>(L, 1);
    auto* child = lb::getAxObject<ax::Node>(L, 2);
    if (self && child) self->removeProtectedChild(child, true);
    return 0;
}

int hook_Widget_removeNodeByTag(lua_State* L) {
    auto* self = lb::getAxObject<ax::ui::Widget>(L, 1);
    if (self && lua_isnumber(L, 2)) self->removeProtectedChildByTag(static_cast<int>(lua_tointeger(L, 2)), true);
    return 0;
}

int hook_Widget_removeAllNodes(lua_State* L) {
    if (auto* self = lb::getAxObject<ax::ui::Widget>(L, 1)) self->removeAllProtectedChildrenWithCleanup(true);
    return 0;
}

template <typename WidgetT, typename CallFn>
int hookWidgetLoadTexImpl(lua_State* L, CallFn&& call) {
    auto* self = lb::getAxObject<WidgetT>(L, 1);
    const char* raw = lua_tostring(L, 2);
    if (!self || !raw || !*raw) return 0;
    std::string path;
    const auto rt = resolveWidgetTexArg(raw, static_cast<int>(lua_tointeger(L, 3)), lua_isnumber(L, 3) != 0, path);
    if (!path.empty()) call(self, path, rt);
    return 0;
}

int hook_ImageView_loadTexture(lua_State* L) {
    return hookWidgetLoadTexImpl<ax::ui::ImageView>(L, [](auto* s, const std::string& p, auto rt) { s->loadTexture(p, rt); });
}
int hook_LoadingBar_loadTexture(lua_State* L) {
    return hookWidgetLoadTexImpl<ax::ui::LoadingBar>(L, [](auto* s, const std::string& p, auto rt) { s->loadTexture(p, rt); });
}
int hook_Layout_setBackGroundImage(lua_State* L) {
    return hookWidgetLoadTexImpl<ax::ui::Layout>(L, [](auto* s, const std::string& p, auto rt) { s->setBackGroundImage(p, rt); });
}
int hook_Button_loadTextureNormal(lua_State* L) {
    return hookWidgetLoadTexImpl<ax::ui::Button>(L, [](auto* s, const std::string& p, auto rt) { s->loadTextureNormal(p, rt); });
}
int hook_Button_loadTexturePressed(lua_State* L) {
    return hookWidgetLoadTexImpl<ax::ui::Button>(L, [](auto* s, const std::string& p, auto rt) { s->loadTexturePressed(p, rt); });
}
int hook_Button_loadTextureDisabled(lua_State* L) {
    return hookWidgetLoadTexImpl<ax::ui::Button>(L, [](auto* s, const std::string& p, auto rt) { s->loadTextureDisabled(p, rt); });
}

int hook_Button_loadTextures(lua_State* L) {
    auto* self = lb::getAxObject<ax::ui::Button>(L, 1);
    if (!self) return 0;
    const bool hasType = lua_isnumber(L, 5) != 0;
    const int expType = static_cast<int>(lua_tointeger(L, 5));
    auto applySlot = [&](int argIdx, auto&& call) {
        if (const char* raw = lua_tostring(L, argIdx); raw && *raw) {
            std::string path;
            const auto rt = resolveWidgetTexArg(raw, expType, hasType, path);
            if (!path.empty()) call(path, rt);
        }
    };
    applySlot(2, [&](const std::string& p, auto rt) { self->loadTextureNormal(p, rt); });
    applySlot(3, [&](const std::string& p, auto rt) { self->loadTexturePressed(p, rt); });
    applySlot(4, [&](const std::string& p, auto rt) { self->loadTextureDisabled(p, rt); });
    return 0;
}

void readStrokeColorAndSize(lua_State* L, ax::Color4B& outColor, int& outSize) {
    ax::Color3B c = ax::Color3B::BLACK;
    readLuaColor3B(L, 2, c);
    outColor = ax::Color4B(c.r, c.g, c.b, 255);
    outSize = lua_isnumber(L, 3) ? (std::max)(1, static_cast<int>(std::round(lua_tonumber(L, 3)))) : 2;
}

template <typename NodeT>
int hookEnableOutline(lua_State* L) {
    if (auto* self = lb::getAxObject<NodeT>(L, 1)) {
        ax::Color4B color;
        int sz = 2;
        readStrokeColorAndSize(L, color, sz);
        self->enableOutline(color, sz);
    }
    return 0;
}

template <typename NodeT>
int hookDisableOutline(lua_State* L) {
    if (auto* self = lb::getAxObject<NodeT>(L, 1)) {
        self->disableEffect(ax::LabelEffect::OUTLINE);
    }
    return 0;
}

int hook_Button_enableTitleStroke(lua_State* L) {
    if (auto* self = lb::getAxObject<ax::ui::Button>(L, 1)) {
        if (auto* tr = self->getTitleRenderer()) {
            ax::Color4B color;
            int sz = 2;
            readStrokeColorAndSize(L, color, sz);
            tr->enableOutline(color, sz);
        }
    }
    return 0;
}

int hook_Button_disableTitleStroke(lua_State* L) {
    if (auto* self = lb::getAxObject<ax::ui::Button>(L, 1)) {
        if (auto* tr = self->getTitleRenderer()) tr->disableEffect(ax::LabelEffect::OUTLINE);
    }
    return 0;
}

int hook_Text_enableShadow(lua_State* L) {
    if (auto* self = lb::getAxObject<ax::ui::Text>(L, 1)) {
        ax::Color3B c = ax::Color3B::BLACK;
        readLuaColor3B(L, 2, c);
        ax::Vec2 offset(2.0f, -2.0f);
        readLuaVec2(L, 3, offset);
        self->enableShadow(ax::Color4B(c.r, c.g, c.b, 255), offset);
    }
    return 0;
}

int hook_Node_getTextHeight(lua_State* L) {
    if (auto* txt = lb::getAxObject<ax::ui::Text>(L, 1)) {
        lua_pushnumber(L, txt->getVirtualRendererSize().height);
        return 1;
    }
    if (auto* rt = lb::getAxObject<ax::ui::RichText>(L, 1)) {
        rt->formatText();
        lua_pushnumber(L, rt->getContentSize().height);
        return 1;
    }
    if (auto* n = lb::getAxObject<ax::Node>(L, 1)) {
        lua_pushnumber(L, n->getContentSize().height);
        return 1;
    }
    lua_pushnumber(L, 0.0);
    return 1;
}

// ============================================================================
// RichText Bindings (Cocos2d-x 2.2.6 Global RichText/RichElement* -> ax::ui::RichText)
// ============================================================================

void readRichElemCommonArgs(lua_State* L, int& outTag, ax::Color3B& outColor, uint8_t& outOpacity) {
    outTag = static_cast<int>(lua_tointeger(L, 2));
    outColor = ax::Color3B::WHITE;
    readLuaColor3B(L, 3, outColor);
    outOpacity = lua_isnumber(L, 4)
        ? static_cast<uint8_t>(std::clamp<int>(static_cast<int>(lua_tointeger(L, 4)), 0, 255))
        : 255;
}

int lua_RichElementText_create(lua_State* L) {
    int tag = 0; ax::Color3B color; uint8_t opacity = 255;
    readRichElemCommonArgs(L, tag, color, opacity);
    const char* text = lua_tostring(L, 5);
    const char* font = lua_tostring(L, 6);
    const float fsize = lua_isnumber(L, 7) ? static_cast<float>(lua_tonumber(L, 7)) : 20.0f;
    pushAxObj(L, ax::ui::RichElementText::create(
        tag, color, opacity, text ? text : "", (font && *font) ? font : "Arial", fsize), "RichElementText");
    return 1;
}

int lua_RichElementImage_create(lua_State* L) {
    int tag = 0; ax::Color3B color; uint8_t opacity = 255;
    readRichElemCommonArgs(L, tag, color, opacity);
    std::string path;
    const auto rt = resolveWidgetTexArg(lua_tostring(L, 5), 0, false, path);
    pushAxObj(L, ax::ui::RichElementImage::create(tag, color, opacity, path, "", rt), "RichElementImage");
    return 1;
}

int lua_RichElementCustomNode_create(lua_State* L) {
    int tag = 0; ax::Color3B color; uint8_t opacity = 255;
    readRichElemCommonArgs(L, tag, color, opacity);
    auto* node = lb::getAxObject<ax::Node>(L, 5);
    if (!node) node = ax::Node::create();
    pushAxObj(L, ax::ui::RichElementCustomNode::create(tag, color, opacity, node), "RichElementCustomNode");
    return 1;
}

int lua_RichText_create(lua_State* L) {
    pushAxObj(L, ax::ui::RichText::create(), "RichText");
    return 1;
}

int lua_RichText_insertElement(lua_State* L) {
    auto* self = lb::getAxObject<ax::ui::RichText>(L, 1);
    auto* elem = lb::getAxObject<ax::ui::RichElement>(L, 2);
    if (self && elem) self->insertElement(elem, static_cast<int>(lua_tointeger(L, 3)));
    return 0;
}

int lua_RichText_pushBackElement(lua_State* L) {
    auto* self = lb::getAxObject<ax::ui::RichText>(L, 1);
    auto* elem = lb::getAxObject<ax::ui::RichElement>(L, 2);
    if (self && elem) self->pushBackElement(elem);
    return 0;
}

int lua_RichText_removeElement(lua_State* L) {
    if (auto* self = lb::getAxObject<ax::ui::RichText>(L, 1)) {
        if (lua_isnumber(L, 2)) self->removeElement(static_cast<int>(lua_tointeger(L, 2)));
        else if (auto* elem = lb::getAxObject<ax::ui::RichElement>(L, 2)) self->removeElement(elem);
    }
    return 0;
}

void registerRichTextBindingsInternal(lua_State* L) {
    tolua_open(L);
    tolua_module(L, nullptr, 0);
    tolua_beginmodule(L, nullptr);

    registerToluaClass(L, "RichElement", "ax.Object", {});

    static constexpr luaL_Reg kTextCreate[] = {{"create", lua_RichElementText_create}};
    static constexpr luaL_Reg kImgCreate[]  = {{"create", lua_RichElementImage_create}};
    static constexpr luaL_Reg kCustCreate[] = {{"create", lua_RichElementCustomNode_create}};
    registerToluaClass(L, "RichElementText", "RichElement", kTextCreate);
    registerToluaClass(L, "RichElementImage", "RichElement", kImgCreate);
    registerToluaClass(L, "RichElementCustomNode", "RichElement", kCustCreate);

    static constexpr luaL_Reg kRichTextFuncs[] = {
        {"create", lua_RichText_create},
        {"insertElement", lua_RichText_insertElement},
        {"pushBackElement", lua_RichText_pushBackElement},
        {"removeElement", lua_RichText_removeElement},
        {"setVerticalSpace", lb::bindAxMethod<&ax::ui::RichText::setVerticalSpace>},
        {"formatText", lb::bindAxMethod<&ax::ui::RichText::formatText>},
        {"getTextHeight", hook_Node_getTextHeight},
    };
    registerToluaClass(L, "RichText", "axui.Widget", kRichTextFuncs);

    tolua_endmodule(L);
}

// ============================================================================
// SpineLuaAnimation (Powered by Axmol Spine 4.2 Runtime on Converted 4.1 Assets)
// ============================================================================

class GClientSpineTextureLoader final : public spine::TextureLoader {
public:
    explicit GClientSpineTextureLoader(std::string atlasFilePath)
        : m_atlasFilePath(std::move(atlasFilePath)) {}

    void load(spine::AtlasPage& page, const spine::String& path) override {
        page.texture = nullptr;
        auto* dir = ax::Director::getInstance();
        auto* texCache = dir ? dir->getTextureCache() : nullptr;
        if (!texCache) return;

        const std::string rawTex = path.buffer() ? path.buffer() : "";
        std::vector<std::string> baseList =
            gclient::assets::PlistbLoader::ResolveSpriteSheetCandidates(rawTex, m_atlasFilePath);
        std::vector<std::string> candidates;
        for (const std::string& base : baseList) {
            for (const std::string& cand :
                 gclient::assets::PlistbLoader::BuildTextureCandidatePaths(base)) {
                if (std::find(candidates.begin(), candidates.end(), cand) == candidates.end()) {
                    candidates.push_back(cand);
                }
            }
        }

        ax::Texture2D* texture = nullptr;
        if (auto* fu = ax::FileUtils::getInstance()) {
            for (const std::string& cand : candidates) {
                const std::string conv = gclient::compat::ResolveConvertedAssetPath(cand);
                const std::string full = fu->fullPathForFilename(conv);
                if (!full.empty() && fu->isFileExist(full)) {
                    texture = texCache->addImage(full);
                    if (texture) break;
                }
            }
        }
        if (!texture) return;

        texture->retain();
        auto mapFilter = [](spine::TextureFilter f) -> ax::backend::SamplerFilter {
            switch (f) {
                case spine::TextureFilter_Nearest:
                case spine::TextureFilter_MipMapNearestNearest:
                case spine::TextureFilter_MipMapLinearNearest:
                    return ax::backend::SamplerFilter::NEAREST;
                default:
                    return ax::backend::SamplerFilter::LINEAR;
            }
        };
        auto mapWrap = [](spine::TextureWrap w) -> ax::backend::SamplerAddressMode {
            return w == spine::TextureWrap_ClampToEdge
                       ? ax::backend::SamplerAddressMode::CLAMP_TO_EDGE
                       : ax::backend::SamplerAddressMode::REPEAT;
        };
        ax::Texture2D::TexParams texParams(
            mapFilter(page.minFilter),
            mapFilter(page.magFilter),
            mapWrap(page.uWrap),
            mapWrap(page.vWrap));
        texture->setTexParameters(texParams);

        page.texture = texture;
        if (texture->getPixelsWide() > 0) page.width = texture->getPixelsWide();
        if (texture->getPixelsHigh() > 0) page.height = texture->getPixelsHigh();
    }

    void unload(void* texture) override {
        if (texture) {
            static_cast<ax::Texture2D*>(texture)->release();
        }
    }

private:
    std::string m_atlasFilePath;
};

struct CachedSpineAsset {
    std::string                                        jsonPath;
    std::string                                        atlasPath;
    float                                              scale         = 1.0f;
    bool                                               loadAttempted = false;
    std::unique_ptr<GClientSpineTextureLoader>         textureLoader;
    std::unique_ptr<spine::Atlas>                      atlas;
    std::unique_ptr<spine::AxmolAtlasAttachmentLoader> attachmentLoader;
    std::unique_ptr<spine::SkeletonData>               skeletonData;

    ~CachedSpineAsset() {
        skeletonData.reset();
        attachmentLoader.reset();
        atlas.reset();
        textureLoader.reset();
    }
};

std::unordered_map<std::string, std::shared_ptr<CachedSpineAsset>> g_spineCache;

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
    if (std::string_view(preferredExt ? preferredExt : "") == ".json") {
        const std::string skelAlt = gclient::assets::ReplaceFileExtension(norm, ".skel");
        if (fu && fu->isFileExist(skelAlt)) return skelAlt;
    }
    return conv;
}

bool ensureSpineAssetLoaded(CachedSpineAsset& entry) {
    if (entry.skeletonData != nullptr) return true;
    if (entry.loadAttempted) return false;
    entry.loadAttempted = true;

    if (entry.jsonPath.empty() || entry.atlasPath.empty()) return false;

    unsigned long atlasSize = 0;
    gclient::assets::DecryptResult atlasDiag;
    std::unique_ptr<unsigned char[]> atlasBuf(
        gclient::assets::LoadAndDecryptFileData(entry.atlasPath, &atlasSize, &atlasDiag));
    if (!atlasBuf || atlasSize == 0) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "Spine",
            "Spine atlas missing or unreadable: '%s' (for skeleton '%s')",
            entry.atlasPath.c_str(),
            entry.jsonPath.c_str());
        return false;
    }

    auto texLoader = std::make_unique<GClientSpineTextureLoader>(entry.atlasPath);
    auto atlas = std::make_unique<spine::Atlas>(
        reinterpret_cast<const char*>(atlasBuf.get()),
        static_cast<int>(atlasSize),
        "",
        texLoader.get(),
        true);
    atlasBuf.reset();

    auto& pages = atlas->getPages();
    if (pages.size() == 0) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "Spine",
            "Spine atlas parsed 0 pages: '%s'",
            entry.atlasPath.c_str());
        return false;
    }
    for (size_t i = 0; i < pages.size(); ++i) {
        if (!pages[i] || pages[i]->texture == nullptr) {
            gclient::diagnostics::CrashAndTelemetry::log(
                gclient::diagnostics::LogLevel::Warn,
                "Spine",
                "Spine atlas page texture missing in '%s' (page '%s')",
                entry.atlasPath.c_str(),
                (pages[i] && pages[i]->name.buffer()) ? pages[i]->name.buffer() : "");
            return false;
        }
    }

    unsigned long skelSize = 0;
    gclient::assets::DecryptResult skelDiag;
    std::unique_ptr<unsigned char[]> skelBuf(
        gclient::assets::LoadAndDecryptFileData(entry.jsonPath, &skelSize, &skelDiag));
    if (!skelBuf || skelSize == 0) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "Spine",
            "Spine skeleton missing or unreadable: '%s'",
            entry.jsonPath.c_str());
        return false;
    }

    auto attachmentLoader = std::make_unique<spine::AxmolAtlasAttachmentLoader>(atlas.get());
    const float effScale = entry.scale > 0.0f ? entry.scale : 1.0f;

    size_t bomOff = (skelSize >= 3 && skelBuf[0] == 0xEFu && skelBuf[1] == 0xBBu && skelBuf[2] == 0xBFu)
                        ? 3u
                        : 0u;
    const std::string_view trimmed = gclient::common::trimAscii(std::string_view(
        reinterpret_cast<const char*>(skelBuf.get() + bomOff),
        static_cast<size_t>(skelSize) - bomOff));
    const bool looksLikeJson =
        !gclient::common::endsWithAsciiCI(entry.jsonPath, ".skel") &&
        !trimmed.empty() && trimmed.front() == '{';

    spine::SkeletonData* parsedData = nullptr;
    std::string parseError;
    if (looksLikeJson) {
        std::string jsonText(
            reinterpret_cast<const char*>(skelBuf.get() + bomOff),
            static_cast<size_t>(skelSize) - bomOff);
        spine::SkeletonJson jsonReader(attachmentLoader.get());
        jsonReader.setScale(effScale);
        parsedData = jsonReader.readSkeletonData(jsonText.c_str());
        if (!parsedData && jsonReader.getError().buffer()) {
            parseError = jsonReader.getError().buffer();
        }
    } else {
        spine::SkeletonBinary binReader(attachmentLoader.get());
        binReader.setScale(effScale);
        parsedData = binReader.readSkeletonData(skelBuf.get(), static_cast<int>(skelSize));
        if (!parsedData && binReader.getError().buffer()) {
            parseError = binReader.getError().buffer();
        }
    }
    skelBuf.reset();

    if (!parsedData) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Warn,
            "Spine",
            "Failed to parse Spine skeleton '%s' (atlas '%s'): %s — using safe placeholder node",
            entry.jsonPath.c_str(),
            entry.atlasPath.c_str(),
            parseError.empty() ? "incompatible or malformed skeleton data" : parseError.c_str());
        return false;
    }

    entry.textureLoader    = std::move(texLoader);
    entry.atlas            = std::move(atlas);
    entry.attachmentLoader = std::move(attachmentLoader);
    entry.skeletonData.reset(parsedData);
    return true;
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

void invokeSpineEventLuaHandler(
    int handler,
    const char* eventName,
    int trackIndex,
    const char* animName,
    int intVal,
    float floatVal,
    const char* strVal)
{
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
    explicit GClientSpineAnimation(std::shared_ptr<CachedSpineAsset> asset = nullptr)
        : spine::SkeletonAnimation(), m_cachedAsset(std::move(asset)) {
        // Explicitly zero-initialize all protected SkeletonRenderer & SkeletonAnimation
        // fields left uninitialized by Axmol's default Spine constructors so placeholder
        // instances are completely deterministic across update/draw/destruction.
        _ownsSkeletonData       = false;
        _ownsSkeleton           = false;
        _ownsAtlas              = false;
        _atlas                  = nullptr;
        _attachmentLoader       = nullptr;
        _premultipliedAlpha     = true;
        _skeleton               = nullptr;
        _clipper                = nullptr;
        _twoColorTint           = false;
        _state                  = nullptr;
        _ownsAnimationStateData = false;
        _updateOnlyIfVisible    = false;
        _firstDraw              = false;
    }

    static GClientSpineAnimation* createPlaceholder() {
        auto* dummy = new GClientSpineAnimation();
        dummy->ax::Node::init();
        dummy->autorelease();
        return dummy;
    }

    static GClientSpineAnimation* createFromCachedAsset(
        const std::shared_ptr<CachedSpineAsset>& asset)
    {
        if (asset && ensureSpineAssetLoaded(*asset) && asset->skeletonData != nullptr) {
            auto* ret = new GClientSpineAnimation(asset);
            ret->ax::Node::init();
            ret->initWithData(asset->skeletonData.get(), /*ownsSkeletonData=*/false);
            if (ret->getSkeleton() != nullptr && ret->getState() != nullptr) {
                ret->bindInternalListeners();
                ret->autorelease();
                return ret;
            }
            delete ret;
        }
        return createPlaceholder();
    }

    static GClientSpineAnimation* createSafe(
        const std::string& jsonPath,
        const std::string& atlasPath,
        float scale)
    {
        const std::string rJson  = resolveSpinePath(jsonPath.c_str(), ".json");
        const std::string rAtlas = resolveSpinePath(atlasPath.c_str(), ".atlas");
        if (rJson.empty() || rAtlas.empty()) {
            return createPlaceholder();
        }
        const float effScale = scale > 0.0f ? scale : 1.0f;
        const std::string cacheKey =
            "__file__:" + rJson + "|" + rAtlas + "|" + std::to_string(effScale);
        auto& slot = g_spineCache[cacheKey];
        if (!slot) {
            slot = std::make_shared<CachedSpineAsset>();
            slot->jsonPath  = rJson;
            slot->atlasPath = rAtlas;
            slot->scale     = effScale;
        }
        return createFromCachedAsset(slot);
    }

    ~GClientSpineAnimation() override {
        releaseEngineScriptHandler(m_startHandler);
        releaseEngineScriptHandler(m_endHandler);
        releaseEngineScriptHandler(m_completeHandler);
        releaseEngineScriptHandler(m_eventHandler);
    }

    void update(float deltaTime) override {
        if (!_skeleton || !_state) return;
        spine::SkeletonAnimation::update(deltaTime);
    }

    void draw(ax::Renderer* renderer, const ax::Mat4& transform, uint32_t transformFlags) override {
        if (!_skeleton || !_state) return;
        spine::SkeletonAnimation::draw(renderer, transform, transformFlags);
    }

    ax::Rect getBoundingBox() const override {
        if (!_skeleton) return ax::Rect::ZERO;
        return spine::SkeletonAnimation::getBoundingBox();
    }

    void setStartLuaHandler(int h) { releaseEngineScriptHandler(m_startHandler); m_startHandler = h; }
    void setEndLuaHandler(int h) { releaseEngineScriptHandler(m_endHandler); m_endHandler = h; }
    void setCompleteLuaHandler(int h) { releaseEngineScriptHandler(m_completeHandler); m_completeHandler = h; }
    void setEventLuaHandler(int h) { releaseEngineScriptHandler(m_eventHandler); m_eventHandler = h; }

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
            if (entry && m_startHandler != 0) invokeSpineTrackHandler(m_startHandler, entry->getTrackIndex(), 0, false);
        });
        setEndListener([this](spine::TrackEntry* entry) {
            if (entry && m_endHandler != 0) invokeSpineTrackHandler(m_endHandler, entry->getTrackIndex(), 0, false);
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
                m_eventHandler, evName ? evName : "", entry->getTrackIndex(),
                anName ? anName : "", event->getIntValue(), event->getFloatValue(), sVal ? sVal : "");
        });
    }

    std::shared_ptr<CachedSpineAsset> m_cachedAsset;
    int m_startHandler    = 0;
    int m_endHandler      = 0;
    int m_completeHandler = 0;
    int m_eventHandler    = 0;
};

int pushSpineTrackTable(lua_State* L, const char* animName, int track, bool loop) {
    lua_newtable(L);
    lua_pushstring(L, animName ? animName : "");
    lua_setfield(L, -2, "animationName");
    lua_pushinteger(L, track);
    lua_setfield(L, -2, "trackIndex");
    lua_pushboolean(L, loop ? 1 : 0);
    lua_setfield(L, -2, "loop");
    return 1;
}

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
    if (modelId && *modelId && jsonPath && atlasPath) {
        auto asset       = std::make_shared<CachedSpineAsset>();
        asset->jsonPath  = resolveSpinePath(jsonPath, ".json");
        asset->atlasPath = resolveSpinePath(atlasPath, ".atlas");
        asset->scale     = scale > 0.0f ? scale : 1.0f;
        (void)ensureSpineAssetLoaded(*asset);
        g_spineCache[modelId] = std::move(asset);
    }
    return 0;
}

int lua_Spine_createFromCache(lua_State* L) {
    const char* modelId = lua_tostring(L, 2);
    auto it = (modelId && *modelId) ? g_spineCache.find(modelId) : g_spineCache.end();
    auto* anim = (it != g_spineCache.end())
        ? GClientSpineAnimation::createFromCachedAsset(it->second)
        : GClientSpineAnimation::createPlaceholder();
    pushAxObj(L, anim, "SpineLuaAnimation");
    return 1;
}

int lua_Spine_createWithFile(lua_State* L) {
    const char* jsonPath  = lua_tostring(L, 2);
    const char* atlasPath = lua_tostring(L, 3);
    const float scale     = lua_isnumber(L, 4) ? static_cast<float>(lua_tonumber(L, 4)) : 1.0f;
    pushAxObj(L, GClientSpineAnimation::createSafe(
        jsonPath ? jsonPath : "", atlasPath ? atlasPath : "", scale), "SpineLuaAnimation");
    return 1;
}

int lua_Spine_removeSkeletonData(lua_State* L) {
    if (const char* modelId = lua_tostring(L, 2)) g_spineCache.erase(modelId);
    return 0;
}

int lua_Spine_removeAllSkeletonData(lua_State* /*L*/) {
    g_spineCache.clear();
    return 0;
}

int lua_Spine_getAnimationCount(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    const int count = (self && self->getSkeleton() && self->getSkeleton()->getData())
        ? static_cast<int>(self->getSkeleton()->getData()->getAnimations().size())
        : 0;
    lua_pushinteger(L, count);
    return 1;
}

int lua_Spine_getAnimationName(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
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

template <bool IsAdd>
int luaSpineSetOrAddAnimation(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    const int track = (std::max)(0, static_cast<int>(lua_tointeger(L, 2)));
    const char* name = lua_tostring(L, 3);
    const bool loop = lua_toboolean(L, 4) != 0;
    if (self && name && self->getSkeleton() && self->getSkeleton()->getData() &&
        self->getSkeleton()->getData()->findAnimation(spine::String(name))) {
        if constexpr (IsAdd) {
            const float delay = lua_isnumber(L, 5) ? static_cast<float>(lua_tonumber(L, 5)) : 0.0f;
            self->addAnimation(track, name, loop, delay);
        } else {
            self->setAnimation(track, name, loop);
        }
        return pushSpineTrackTable(L, name, track, loop);
    }
    lua_pushnil(L);
    return 1;
}

int lua_Spine_setMix(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    const char* from = lua_tostring(L, 2);
    const char* to   = lua_tostring(L, 3);
    if (self && self->getSkeleton() && self->getState() && from && to) {
        self->setMix(from, to, static_cast<float>(lua_tonumber(L, 4)));
    }
    return 0;
}

int lua_Spine_clearTrack(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    const int track = lua_isnumber(L, 2) ? (std::max)(0, static_cast<int>(lua_tointeger(L, 2))) : 0;
    if (self && self->getSkeleton() && self->getState()) self->clearTrack(track);
    return 0;
}

template <auto Fn>
int luaSpineSkelVoid(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    if (self && self->getSkeleton() && self->getState()) (self->*Fn)();
    return 0;
}

int lua_Spine_updateWorldTransform(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    if (self && self->getSkeleton()) self->updateWorldTransform(spine::Physics_Update);
    return 0;
}

int lua_Spine_getCurrent(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    const int track = lua_isnumber(L, 2) ? (std::max)(0, static_cast<int>(lua_tointeger(L, 2))) : 0;
    if (self && self->getState()) {
        if (spine::TrackEntry* cur = self->getState()->getCurrent(static_cast<size_t>(track))) {
            if (cur->getAnimation()) {
                return pushSpineTrackTable(L, cur->getAnimation()->getName().buffer(), track, cur->getLoop());
            }
        }
    }
    lua_pushnil(L);
    return 1;
}

int lua_Spine_setSkin(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    const char* skin = lua_tostring(L, 2);
    bool ok = false;
    if (self && self->getSkeleton() && self->getSkeleton()->getData() && skin && *skin &&
        self->getSkeleton()->getData()->findSkin(spine::String(skin)) != nullptr) {
        self->setSkin(skin);
        ok = true;
    }
    lua_pushboolean(L, ok ? 1 : 0);
    return 1;
}

int lua_Spine_findBone(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    const char* boneName = lua_tostring(L, 2);
    if (self && self->getSkeleton() && boneName && *boneName) {
        if (spine::Bone* b = self->findBone(boneName)) {
            lua_newtable(L);
            auto setNum = [&](const char* k, float v) { lua_pushnumber(L, v); lua_setfield(L, -2, k); };
            setNum("x", b->getX());
            setNum("y", b->getY());
            setNum("worldX", b->getWorldX());
            setNum("worldY", b->getWorldY());
            setNum("rotation", b->getRotation());
            setNum("scaleX", b->getScaleX());
            setNum("scaleY", b->getScaleY());
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}

int lua_Spine_setAttachment(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    const char* slot = lua_tostring(L, 2);
    const char* att  = lua_isstring(L, 3) ? lua_tostring(L, 3) : "";
    lua_pushboolean(L, (self && self->getSkeleton() && slot && self->setAttachment(slot, att ? att : "")) ? 1 : 0);
    return 1;
}

int lua_Spine_boundingBox(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    const ax::Rect box = (self && self->getSkeleton()) ? self->getBoundingBox() : ax::Rect::ZERO;
    lua_newtable(L);
    lua_pushnumber(L, box.origin.x);    lua_setfield(L, -2, "x");
    lua_pushnumber(L, box.origin.y);    lua_setfield(L, -2, "y");
    lua_pushnumber(L, box.size.width);  lua_setfield(L, -2, "width");
    lua_pushnumber(L, box.size.height); lua_setfield(L, -2, "height");
    return 1;
}

int lua_Spine_update(lua_State* L) {
    auto* self = lb::getAxObject<spine::SkeletonAnimation>(L, 1);
    if (self && self->getSkeleton() && self->getState()) {
        self->update(static_cast<float>(lua_tonumber(L, 2)));
    }
    return 0;
}

int lua_Spine_triggerEvent(lua_State* L) {
    if (auto* self = lb::getAxObject<GClientSpineAnimation>(L, 1)) {
        const char* ev = lua_tostring(L, 3);
        const char* sVal = lua_tostring(L, 6);
        if (ev && *ev) {
            self->triggerManualEvent(
                static_cast<int>(lua_tointeger(L, 2)), ev,
                static_cast<int>(lua_tointeger(L, 4)),
                static_cast<float>(lua_tonumber(L, 5)),
                sVal ? sVal : "");
        }
    }
    return 0;
}

template <void (GClientSpineAnimation::*SetFn)(int)>
int luaSpineSetListener(lua_State* L) {
    if (auto* self = lb::getAxObject<GClientSpineAnimation>(L, 1)) {
        const int fnIdx = lua_isfunction(L, 3) ? 3 : (lua_isfunction(L, 2) ? 2 : 0);
        (self->*SetFn)(fnIdx > 0 ? toluafix_ref_function(L, fnIdx, 0) : 0);
    }
    return 0;
}

void registerSpineBindings(lua_State* L) {
    tolua_open(L);
    tolua_module(L, nullptr, 0);
    tolua_beginmodule(L, nullptr);

    static constexpr luaL_Reg kSpineFuncs[] = {
        {"hasSkeletonData", lua_Spine_hasSkeletonData},
        {"setSkeletonDataToCache", lua_Spine_setSkeletonDataToCache},
        {"createFromCache", lua_Spine_createFromCache},
        {"createWithFile", lua_Spine_createWithFile},
        {"removeSkeletonData", lua_Spine_removeSkeletonData},
        {"removeAllSkeletonData", lua_Spine_removeAllSkeletonData},
        {"getAnimationCount", lua_Spine_getAnimationCount},
        {"getAnimationName", lua_Spine_getAnimationName},
        {"setAnimation", luaSpineSetOrAddAnimation<false>},
        {"addAnimation", luaSpineSetOrAddAnimation<true>},
        {"setMix", lua_Spine_setMix},
        {"clearTrack", lua_Spine_clearTrack},
        {"clearTracks", luaSpineSkelVoid<&spine::SkeletonAnimation::clearTracks>},
        {"setToSetupPose", luaSpineSkelVoid<&spine::SkeletonAnimation::setToSetupPose>},
        {"setBonesToSetupPose", luaSpineSkelVoid<&spine::SkeletonAnimation::setBonesToSetupPose>},
        {"setSlotsToSetupPose", luaSpineSkelVoid<&spine::SkeletonAnimation::setSlotsToSetupPose>},
        {"updateWorldTransform", lua_Spine_updateWorldTransform},
        {"setTimeScale", lb::bindAxMethod<&spine::SkeletonAnimation::setTimeScale>},
        {"getCurrent", lua_Spine_getCurrent},
        {"pause", lb::bindAxMethod<&spine::SkeletonAnimation::pause>},
        {"resume", lb::bindAxMethod<&spine::SkeletonAnimation::resume>},
        {"setSkin", lua_Spine_setSkin},
        {"findBone", lua_Spine_findBone},
        {"setAttachment", lua_Spine_setAttachment},
        {"boundingBox", lua_Spine_boundingBox},
        {"getBoundingBox", lua_Spine_boundingBox},
        {"update", lua_Spine_update},
        {"triggerEvent", lua_Spine_triggerEvent},
        {"setLuaStartListener", luaSpineSetListener<&GClientSpineAnimation::setStartLuaHandler>},
        {"setLuaEndListener", luaSpineSetListener<&GClientSpineAnimation::setEndLuaHandler>},
        {"setLuaCompleteListener", luaSpineSetListener<&GClientSpineAnimation::setCompleteLuaHandler>},
        {"setLuaEventListener", luaSpineSetListener<&GClientSpineAnimation::setEventLuaHandler>},
        {"setStartListener", luaSpineSetListener<&GClientSpineAnimation::setStartLuaHandler>},
        {"setEndListener", luaSpineSetListener<&GClientSpineAnimation::setEndLuaHandler>},
        {"setCompleteListener", luaSpineSetListener<&GClientSpineAnimation::setCompleteLuaHandler>},
        {"setEventListener", luaSpineSetListener<&GClientSpineAnimation::setEventLuaHandler>},
    };
    registerToluaClass(L, "SpineLuaAnimation", "ax.Node", kSpineFuncs);
    tolua_endmodule(L);

    lua_newtable(L);
    lua_getglobal(L, "SpineLuaAnimation");
    lua_pushvalue(L, -1);
    lua_setfield(L, -3, "SpineLuaAnimation");
    lua_setfield(L, -2, "SkeletonAnimation");
    lua_setglobal(L, "spine");
}

void wrapMetatableMethods(lua_State* L, const char* typeName, std::span<const luaL_Reg> hooks) {
    luaL_getmetatable(L, typeName);
    if (lua_istable(L, -1)) {
        for (const auto& h : hooks) {
            if (!h.name || !h.func) continue;
            lua_pushstring(L, h.name);
            lua_rawget(L, -2);
            lua_pushstring(L, h.name);
            lua_pushvalue(L, -2);
            lua_remove(L, -3);
            lua_pushcclosure(L, h.func, 1);
            lua_rawset(L, -3);
        }
    }
    lua_pop(L, 1);
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
            for (int id : entries) sched->unscheduleScriptEntry(static_cast<unsigned int>(id));
        }
    }
}

void RescheduleLuaHelpersCallbacks() {
    const std::vector<DeferredArmatureAsyncCallback*> snapshot = g_pendingArmatureCallbacks;
    for (auto* cb : snapshot) {
        if (cb) cb->ensureOnScheduler();
    }
}

void ResetLuaHelpersForSoftRestart(bool clearSpineCache) {
    UnscheduleAllLuaScriptEntries();

    const std::vector<DeferredArmatureAsyncCallback*> pendingArmatures = g_pendingArmatureCallbacks;
    g_pendingArmatureCallbacks.clear();
    for (auto* cb : pendingArmatures) {
        if (cb) cb->cancelAndRelease();
    }

    std::vector<int> staleTimerRefs;
    CTimer* oldTimer = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_timerTrackerMutex);
        staleTimerRefs.swap(g_pendingTimerLuaRefs);
        oldTimer = g_sharedTimerInstance;
        g_sharedTimerInstance = new CTimer();
    }
    if (oldTimer) {
        if (auto* dir = ax::Director::getInstance()) {
            if (auto* sched = dir->getScheduler()) sched->unscheduleAllForTarget(oldTimer);
        }
        oldTimer->release();
    }
    for (int ref : staleTimerRefs) {
        releaseEngineScriptHandler(ref);
    }

    std::vector<std::string> handlerNames;
    {
        std::lock_guard<std::mutex> lock(g_luaFuncsNamesMutex);
        handlerNames.assign(g_registeredLuaFuncNames.begin(), g_registeredLuaFuncNames.end());
    }
    if (CLuaFuncs* luaFuncs = CLuaFuncs::sharedLuaFuncs()) {
        for (const std::string& name : handlerNames) luaFuncs->removeHandler(name.c_str());
    }

    if (clearSpineCache) g_spineCache.clear();
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

    static constexpr luaL_Reg kFileUtilsHooks[] = {{"isFileExist", hook_FileUtils_isFileExist}};
    static constexpr luaL_Reg kSchedulerHooks[] = {
        {"scheduleScriptFunc", hook_Scheduler_scheduleScriptFunc},
        {"unscheduleScriptEntry", hook_Scheduler_unscheduleScriptEntry},
    };
    static constexpr luaL_Reg kTexCacheHooks[] = {
        {"addImage", hook_TextureCache_addImage},
        {"removeTextureForKey", hook_TextureCache_removeTextureForKey},
    };
    static constexpr luaL_Reg kSpriteFrameHooks[] = {
        {"addSpriteFrames", hook_SpriteFrameCache_addSpriteFrames},
        {"addSpriteFramesWithFile", hook_SpriteFrameCache_addSpriteFrames},
        {"addSpriteFramesWithBinary", hook_SpriteFrameCache_addSpriteFrames},
        {"removeSpriteFramesFromFile", hook_SpriteFrameCache_removeSpriteFramesFromFile},
    };
    static constexpr luaL_Reg kGuiReaderHooks[] = {
        {"widgetFromJsonFile", hook_GUIReader_widgetFromJsonFile},
        {"widgetFromPbFile", hook_GUIReader_widgetFromJsonFile},
    };
    static constexpr luaL_Reg kSceneReaderHooks[] = {
        {"createNodeWithSceneFile", hook_SceneReader_createNodeWithSceneFile},
    };
    static constexpr luaL_Reg kArmDataHooks[] = {
        {"addArmatureFileInfo", hook_addArmatureFileInfo},
        {"addArmatureFileInfoAsync", hook_addArmatureFileInfoAsync},
        {"removeArmatureFileInfo", hook_removeArmatureFileInfo},
    };
    static constexpr luaL_Reg kArmAnimHooks[] = {
        {"setMovementLoopByName", hook_ArmatureAnimation_setMovementLoopByName},
    };
    static constexpr luaL_Reg kDirectorHooks[] = {{"getCurrentTime", hook_Director_getCurrentTime}};
    static constexpr luaL_Reg kNodeHooks[]     = {{"getTextHeight", hook_Node_getTextHeight}};
    static constexpr luaL_Reg kSpriteHooks[]   = {
        {"create", hookCreateSpriteLike<ax::Sprite, "ax.Sprite">},
        {"createWithSpriteFrameName", hookCreateWithFrameNameLike<ax::Sprite, "ax.Sprite", true>},
    };
    static constexpr luaL_Reg kScale9Hooks[] = {
        {"create", hookCreateSpriteLike<ax::ui::Scale9Sprite, "axui.Scale9Sprite">},
        {"createWithSpriteFrameName", hookCreateWithFrameNameLike<ax::ui::Scale9Sprite, "axui.Scale9Sprite", false>},
    };
    static constexpr luaL_Reg kLabelHooks[] = {
        {"enableStroke", hookEnableOutline<ax::Label>},
        {"disableStroke", hookDisableOutline<ax::Label>},
        {"getTextHeight", hook_Node_getTextHeight},
    };

    wrapMetatableMethods(L, "ax.FileUtils", kFileUtilsHooks);
    wrapMetatableMethods(L, "ax.Scheduler", kSchedulerHooks);
    wrapMetatableMethods(L, "ax.TextureCache", kTexCacheHooks);
    wrapMetatableMethods(L, "ax.SpriteFrameCache", kSpriteFrameHooks);
    wrapMetatableMethods(L, "ccs.GUIReader", kGuiReaderHooks);
    wrapMetatableMethods(L, "ccs.SceneReader", kSceneReaderHooks);
    wrapMetatableMethods(L, "ccs.ArmatureDataManager", kArmDataHooks);
    wrapMetatableMethods(L, "ccs.ArmatureAnimation", kArmAnimHooks);
    wrapMetatableMethods(L, "ax.Director", kDirectorHooks);
    wrapMetatableMethods(L, "ax.Node", kNodeHooks);
    wrapMetatableMethods(L, "ax.Sprite", kSpriteHooks);
    wrapMetatableMethods(L, "axui.Scale9Sprite", kScale9Hooks);
    wrapMetatableMethods(L, "ax.Label", kLabelHooks);

    static constexpr luaL_Reg kWidgetCommonHooks[] = {
        {"addNode", hook_Widget_addNode},
        {"removeNode", hook_Widget_removeNode},
        {"removeNodeByTag", hook_Widget_removeNodeByTag},
        {"removeAllNodes", hook_Widget_removeAllNodes},
        {"getTextHeight", hook_Node_getTextHeight},
    };
    for (const char* t : {
             "axui.Widget", "axui.Layout", "axui.Button", "axui.CheckBox", "axui.ImageView",
             "axui.Text", "axui.TextAtlas", "axui.TextBMFont", "axui.LoadingBar",
             "axui.Slider", "axui.TextField", "axui.ScrollView", "axui.ListView", "axui.PageView"}) {
        wrapMetatableMethods(L, t, kWidgetCommonHooks);
    }

    static constexpr luaL_Reg kImageViewHooks[]  = {{"loadTexture", hook_ImageView_loadTexture}};
    static constexpr luaL_Reg kLoadingBarHooks[] = {{"loadTexture", hook_LoadingBar_loadTexture}};
    static constexpr luaL_Reg kLayoutBgHooks[]   = {{"setBackGroundImage", hook_Layout_setBackGroundImage}};
    static constexpr luaL_Reg kButtonHooks[]     = {
        {"loadTextures", hook_Button_loadTextures},
        {"loadTextureNormal", hook_Button_loadTextureNormal},
        {"loadTexturePressed", hook_Button_loadTexturePressed},
        {"loadTextureDisabled", hook_Button_loadTextureDisabled},
        {"enableTitleStroke", hook_Button_enableTitleStroke},
        {"disableTitleStroke", hook_Button_disableTitleStroke},
    };
    static constexpr luaL_Reg kTextHooks[] = {
        {"enableStroke", hookEnableOutline<ax::ui::Text>},
        {"disableStroke", hookDisableOutline<ax::ui::Text>},
        {"enableShadow", hook_Text_enableShadow},
    };

    wrapMetatableMethods(L, "axui.ImageView", kImageViewHooks);
    wrapMetatableMethods(L, "axui.LoadingBar", kLoadingBarHooks);
    for (const char* t : {"axui.Layout", "axui.ScrollView", "axui.ListView", "axui.PageView"}) {
        wrapMetatableMethods(L, t, kLayoutBgHooks);
    }
    wrapMetatableMethods(L, "axui.Button", kButtonHooks);
    wrapMetatableMethods(L, "axui.Text", kTextHooks);

    registerRichTextBindingsInternal(L);
    registerSpineBindings(L);
}
