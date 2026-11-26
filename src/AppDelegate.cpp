// ============================================================================
// Game Client Axmol v2.11.5 Port — AppDelegate Implementation
// Preserves atomic lifecycle state machine, hotfix health checks, writable path
// isolation, Lua 2.2.6 compatibility shims, and ordered teardown.
// ============================================================================

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#endif

#include "AppDelegate.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <vector>

#include "CCLuaEngine.h"
#include "SimpleAudioEngine.h"
#include "lua-bindings/manual/lua_module_register.h"

#include "compat/Axmol226Compat.h"
#include "compat/Lua226CompatShim.h"
#include "diagnostics/CrashAndTelemetry.h"

#include "assets/BTAssetDecryptor.h"
#include "assets/BtDecryptHook.h"
#include "bindings/BTUtil.h"
#include "bindings/CConfigManager.h"
#include "bindings/LuaBindingsRegistry.h"
#include "bindings/LuaHelpers.h"
#include "bindings/LuaHttpAndCrypto.h"
#include "net/CNetwork.h"
#include "platform/BTPlatform.h"
#include "ui/Win32DesktopBridge.h"
#include "ui/ZYWebViewWin32.h"
#include "update/AtomicHotUpdater.h"

namespace gclient {

namespace {

std::mutex               g_writableDirMutex;
std::string              g_configuredWritableDir;
std::atomic<bool>        g_validateAssetsOnly{false};
std::atomic<AppDelegate*> g_activeAppInstance{nullptr};

constexpr float  kDesignWidth             = 1136.0f;
constexpr float  kDesignHeight            = 640.0f;
constexpr float  kTargetAnimationInterval = 1.0f / 60.0f; // Smooth 60 FPS on Axmol x64

std::string getConfiguredWritableDirSnapshot() {
    std::lock_guard<std::mutex> lock(g_writableDirMutex);
    return g_configuredWritableDir;
}

void setConfiguredWritableDirSnapshot(std::string dir) {
    std::lock_guard<std::mutex> lock(g_writableDirMutex);
    g_configuredWritableDir = std::move(dir);
}

#ifdef _WIN32
std::wstring utf8ToWidePath(const std::string& utf8) {
    if (utf8.empty()) return {};
    int req = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (req <= 0) {
        req = ::MultiByteToWideChar(
            CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    }
    if (req <= 0) return {};
    std::wstring wide(static_cast<std::size_t>(req), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), req);
    return wide;
}

std::string wideToUtf8Path(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int req = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (req <= 0) return {};
    std::string out(static_cast<std::size_t>(req), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), out.data(), req, nullptr, nullptr);
    return out;
}

std::filesystem::path toSafeFsPath(const std::string& utf8) {
    return std::filesystem::path(utf8ToWidePath(utf8));
}
#else
std::filesystem::path toSafeFsPath(const std::string& utf8) {
    return std::filesystem::path(utf8);
}
#endif

template <typename T, typename = void>
struct HasClearLuaStateNoArg : std::false_type {};
template <typename T>
struct HasClearLuaStateNoArg<T, std::void_t<decltype(T::clearLuaState())>> : std::true_type {};

template <typename T = diagnostics::CrashAndTelemetry>
void clearTelemetryLuaStateBeforeTeardown() {
    if constexpr (HasClearLuaStateNoArg<T>::value) {
        T::clearLuaState();
    }
}

bool isRenderViewZeroOrMinimized(ax::RenderViewImpl* rv) {
    if (!rv) return true;
#ifdef _WIN32
    if (HWND hwnd = rv->getWin32Window()) {
        if (!::IsWindow(hwnd) || ::IsIconic(hwnd)) return true;
        RECT rc{};
        if (::GetClientRect(hwnd, &rc)) {
            if ((rc.right - rc.left) < 1 || (rc.bottom - rc.top) < 1) return true;
        }
    }
#endif
    const ax::Vec2 frameSz = rv->getFrameSize();
    return frameSz.width < 1.0f || frameSz.height < 1.0f ||
           !std::isfinite(frameSz.width) || !std::isfinite(frameSz.height);
}

bool isEnvFlagEnabled(const char* name) {
    if (!name || !*name) return false;
    std::string val;
#ifdef _WIN32
    char buf[32] = {};
    const DWORD len = ::GetEnvironmentVariableA(name, buf, static_cast<DWORD>(sizeof(buf)));
    if (len > 0 && len < sizeof(buf)) {
        val.assign(buf, len);
    }
#endif
    if (val.empty()) {
        if (const char* raw = std::getenv(name)) val = raw;
    }
    return val == "1" || val == "true" || val == "TRUE" || val == "yes" || val == "YES";
}

class AlertDialogGate {
public:
    static constexpr std::size_t kMaxPopupsPerProcess = 3;

    bool shouldDisplayPopup(const std::string& messageText,
                            bool validateAssetsOnly,
                            bool suppressMessageBoxEnv,
                            bool headlessEnv) {
        if (validateAssetsOnly || suppressMessageBoxEnv || headlessEnv) return false;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_seenMessages.find(messageText) != m_seenMessages.end()) return false;
        if (m_shownCount >= kMaxPopupsPerProcess) return false;
        m_seenMessages.insert(messageText);
        ++m_shownCount;
        return true;
    }

private:
    std::mutex                      m_mutex;
    std::unordered_set<std::string> m_seenMessages;
    std::size_t                     m_shownCount = 0;
};

AlertDialogGate& sharedAlertDialogGate() {
    static AlertDialogGate* s_gate = new AlertDialogGate();
    return *s_gate;
}

#ifdef _WIN32
void showAsyncWin32Alert(std::string title, std::string message) {
    std::thread([t = std::move(title), m = std::move(message)]() {
        static std::mutex* s_dialogMutex = new std::mutex();
        std::lock_guard<std::mutex> guard(*s_dialogMutex);
        const std::wstring wTitle = utf8ToWidePath(t);
        const std::wstring wMsg   = utf8ToWidePath(m);
        ::MessageBoxW(
            nullptr,
            wMsg.empty() ? L"(error)" : wMsg.c_str(),
            wTitle.empty() ? L"Game Client" : wTitle.c_str(),
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
    }).detach();
}
#endif

void maybeShowWin32AlertPopup(const std::string& titleStr, const std::string& msgStr, bool showAlert) {
#ifdef _WIN32
    if (showAlert) showAsyncWin32Alert(titleStr, msgStr);
#else
    (void)titleStr;
    (void)msgStr;
    (void)showAlert;
#endif
}

void appendSearchLayer(std::vector<std::string>& searchPaths,
                       std::unordered_set<std::string>& seen,
                       std::string layerRoot) {
    std::replace(layerRoot.begin(), layerRoot.end(), '\\', '/');
    while (layerRoot.size() > 1 && layerRoot.back() == '/') {
        if (layerRoot.size() == 3 && layerRoot[1] == ':') break;
        layerRoot.pop_back();
    }
    if (layerRoot.empty()) return;

    const std::string prefix = (layerRoot.back() == '/') ? layerRoot : (layerRoot + "/");
    const std::string subpaths[] = {
        layerRoot,
        prefix + "scripts",
        prefix + "database",
        prefix + "res",
        prefix + "res/database",
        prefix + "res/jsonUI",
    };
    for (const std::string& p : subpaths) {
        if (seen.insert(p).second) {
            searchPaths.push_back(p);
        }
    }
}

} // namespace

// ----------------------------------------------------------------------------
// FrameTicker: ax::Object bridge scheduled on ax::Scheduler
// ----------------------------------------------------------------------------
class AppDelegate::FrameTicker final : public ax::Object {
public:
    void onTick(float dt) {
        if (!AppDelegate::isLifecycleReady()) return;
        if (bt::Platform* platform = bt::Platform::getInstance()) {
            platform->tickLoop();
        }
        if (gclient::net::CNetwork* network = gclient::net::CNetwork::sharedNetwork()) {
            network->update(dt);
        }
        diagnostics::CrashAndTelemetry::recordFrame(dt);

        static int s_frame = 0;
        if (++s_frame == 60) {
            auto* scene = ax::Director::getInstance()->getRunningScene();
            diagnostics::CrashAndTelemetry::log(
                diagnostics::LogLevel::Info,
                "AppDelegate",
                "Frame 60: runningScene=%p children=%zu",
                static_cast<void*>(scene),
                scene ? static_cast<std::size_t>(scene->getChildrenCount()) : 0u);
        } else if (s_frame == 90) {
            if (const char* shotName = std::getenv("GCLIENT_SCREENSHOT_NAME")) {
                auto* director = ax::Director::getInstance();
                auto* rv = director ? dynamic_cast<ax::RenderViewImpl*>(director->getRenderView()) : nullptr;
                if (director && !isRenderViewZeroOrMinimized(rv)) {
                    if (auto* scene = director->getRunningScene()) {
                        const auto winSize = director->getWinSize();
                        if (std::isfinite(winSize.width) && std::isfinite(winSize.height) &&
                            winSize.width >= 1.0f && winSize.height >= 1.0f) {
                            if (auto* rt = ax::RenderTexture::create(
                                    static_cast<int>(winSize.width), static_cast<int>(winSize.height))) {
                                rt->begin();
                                scene->visit();
                                rt->end();
                                rt->saveToFile(shotName, ax::Image::Format::PNG);
                                diagnostics::CrashAndTelemetry::log(
                                    diagnostics::LogLevel::Info, "AppDelegate", "Saved screenshot %s", shotName);
                            }
                        }
                    }
                }
            }
        }
    }
};

static int gclientLuaLoader(lua_State* L) {
    std::string modName = luaL_checkstring(L, 1);
    if (modName.size() >= 4 && modName.substr(modName.size() - 4) == ".lua") {
        modName.resize(modName.size() - 4);
    }
    std::replace(modName.begin(), modName.end(), '.', '/');
    const std::string relFile = modName + ".lua";

    unsigned long sz = 0;
    unsigned char* buf = gclient::assets::LoadAndDecryptFileData(relFile, &sz);
    if (!buf || sz == 0) {
        delete[] buf;
        lua_pushfstring(L, "\n\t[gclientLuaLoader] cannot find '%s'", relFile.c_str());
        return 1;
    }

    const char* code = reinterpret_cast<const char*>(buf);
    size_t codeLen = static_cast<size_t>(sz);
    if (codeLen >= 3 &&
        static_cast<unsigned char>(code[0]) == 0xEF &&
        static_cast<unsigned char>(code[1]) == 0xBB &&
        static_cast<unsigned char>(code[2]) == 0xBF) {
        code += 3;
        codeLen -= 3;
    }

    const std::string chunkName = "@" + relFile;
    const int loadStatus = luaL_loadbuffer(L, code, codeLen, chunkName.c_str());
    delete[] buf;
    if (loadStatus != 0) {
        return lua_error(L);
    }
    return 1;
}

// ----------------------------------------------------------------------------
// AppDelegate Lifecycle
// ----------------------------------------------------------------------------
bool AppDelegate::hasActiveInstance() noexcept {
    return g_activeAppInstance.load(std::memory_order_acquire) != nullptr;
}

bool AppDelegate::isLifecycleReady() noexcept {
    AppDelegate* inst = g_activeAppInstance.load(std::memory_order_acquire);
    return inst != nullptr && inst->isReady();
}

AppDelegate::AppDelegate(const AppConfig& config)
    : m_config(config)
{
    g_validateAssetsOnly.store(m_config.validateAssetsOnly, std::memory_order_release);
    g_activeAppInstance.store(this, std::memory_order_release);
}

AppDelegate::~AppDelegate() {
    shutdown();
    AppDelegate* expected = this;
    g_activeAppInstance.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
}

void AppDelegate::initGfxContextAttrs() {
    GfxContextAttrs gfxContextAttrs = {8, 8, 8, 8, 24, 8, 0};
    ax::RenderView::setGfxContextAttrs(gfxContextAttrs);
}

void AppDelegate::applicationWillQuit() {
    shutdown();
}

bool AppDelegate::executeHeadlessAssetValidation() {
    namespace fs = std::filesystem;

    LifecycleState expectedState = LifecycleState::Uninitialized;
    if (!m_lifecycleState.compare_exchange_strong(
            expectedState, LifecycleState::Initializing, std::memory_order_acq_rel)) {
        return m_assetValidationOk;
    }

    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AssetValidation",
        "Running headless --validate-assets check against '%s'",
        m_config.resourcesDir.c_str());

    std::error_code ec;
    if (!m_config.writableDir.empty()) {
        fs::create_directories(toSafeFsPath(m_config.writableDir), ec);
        ec.clear();
    }

    std::vector<fs::path> searchRoots;
    if (!m_config.writableDir.empty()) {
        searchRoots.push_back(toSafeFsPath(m_config.writableDir) / "Resources");
    }

    if (!m_config.hotfixDir.empty()) {
        update::HotUpdaterConfig hotCfg;
        hotCfg.patchRootDir = toSafeFsPath(m_config.hotfixDir);
        if (!m_config.baseAssetsDir.empty()) {
            hotCfg.baseResourcesDir = toSafeFsPath(m_config.baseAssetsDir);
        } else if (!m_config.resourcesDir.empty()) {
            hotCfg.baseResourcesDir = toSafeFsPath(m_config.resourcesDir);
        }
        update::AtomicHotUpdater updater(hotCfg);
        const auto health = updater.initializeAndCheckStartupHealth();
        if (health.hasActiveOverlay && !health.activeOverlayPath.empty()) {
            searchRoots.push_back(health.activeOverlayPath);
        }
        searchRoots.push_back(toSafeFsPath(m_config.hotfixDir));
    }

    if (!m_config.resourcesDir.empty()) {
        searchRoots.push_back(toSafeFsPath(m_config.resourcesDir));
    }
    if (!m_config.baseAssetsDir.empty()) {
        searchRoots.push_back(toSafeFsPath(m_config.baseAssetsDir));
    }

    fs::path resolvedScriptFs;
    for (const fs::path& root : searchRoots) {
        if (root.empty()) continue;
        const fs::path cand1 = root / "scripts" / "main.lua";
        ec.clear();
        if (fs::is_regular_file(cand1, ec)) {
            resolvedScriptFs = cand1;
            break;
        }
        const fs::path cand2 = root / "main.lua";
        ec.clear();
        if (fs::is_regular_file(cand2, ec)) {
            resolvedScriptFs = cand2;
            break;
        }
    }

    if (resolvedScriptFs.empty()) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AssetValidation",
            "Missing entry script 'scripts/main.lua' under resources dir '%s'",
            m_config.resourcesDir.c_str());
        diagnostics::CrashAndTelemetry::flushLogs();
        m_assetValidationOk = false;
        m_lifecycleState.store(LifecycleState::Failed, std::memory_order_release);
        return false;
    }

#ifdef _WIN32
    const std::string resolvedUtf8 = wideToUtf8Path(resolvedScriptFs.wstring());
#else
    const std::string resolvedUtf8 = resolvedScriptFs.string();
#endif

    unsigned long dataSize = 0;
    unsigned char* data = gclient::assets::LoadAndDecryptFileData(resolvedUtf8, &dataSize);
    if (data == nullptr || dataSize == 0) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AssetValidation",
            "Failed to read or decrypt '%s'",
            resolvedUtf8.c_str());
        delete[] data;
        diagnostics::CrashAndTelemetry::flushLogs();
        m_assetValidationOk = false;
        m_lifecycleState.store(LifecycleState::Failed, std::memory_order_release);
        return false;
    }

    delete[] data;
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AssetValidation",
        "Validated '%s' (%lu bytes loaded successfully)",
        resolvedUtf8.c_str(),
        dataSize);
    diagnostics::CrashAndTelemetry::flushLogs();
    m_assetValidationOk = true;
    m_lifecycleState.store(LifecycleState::Terminated, std::memory_order_release);
    return true;
}

void AppDelegate::shutdown() {
    teardownSubsystems(LifecycleState::Terminated);
}

void AppDelegate::teardownSubsystems(LifecycleState terminalState) {
    LifecycleState cur = m_lifecycleState.load(std::memory_order_acquire);
    if (cur == LifecycleState::Terminated ||
        cur == LifecycleState::ShuttingDown ||
        cur == LifecycleState::Failed ||
        cur == LifecycleState::Uninitialized) {
        if (terminalState == LifecycleState::Terminated || cur == LifecycleState::Uninitialized) {
            m_lifecycleState.store(terminalState, std::memory_order_release);
        }
        return;
    }
    m_lifecycleState.store(LifecycleState::ShuttingDown, std::memory_order_release);

#ifdef _WIN32
    gclient::ui::Win32DesktopBridge::instance().detach();
#endif
    if (auto* webView = gclient::ui::ZYWebViewWin32::getInstance()) {
        webView->shutdown();
    }

    unscheduleNativeLoops();

    if (bt::Platform* platform = bt::Platform::getInstance()) {
        platform->setWebViewBridgeHandler(nullptr);
        platform->setLogHandler(nullptr);
    }

    gclient::bindings::shutdownLuaHttpClient();
    gclient::net::CNetwork::destroySharedNetwork();
    if (auto* cfgMgr = CConfigurationManager::sharedConfigurationManager(false)) {
        cfgMgr->closeAllDbs();
    }

    clearTelemetryLuaStateBeforeTeardown();
    ax::ScriptEngineManager::destroyInstance();
    CocosDenshion::SimpleAudioEngine::end();

    m_lifecycleState.store(terminalState, std::memory_order_release);
}

void AppDelegate::configureFileUtils() {
    ax::FileUtils* fileUtils = ax::FileUtils::getInstance();
    if (m_config.validateAssetsOnly ||
        isEnvFlagEnabled("GCLIENT_HEADLESS") ||
        isEnvFlagEnabled("GCLIENT_SUPPRESS_MESSAGEBOX") ||
        isEnvFlagEnabled("CI") ||
        isEnvFlagEnabled("GITHUB_ACTIONS")) {
        fileUtils->setPopupNotify(false);
    }

    if (!m_config.writableDir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(toSafeFsPath(m_config.writableDir), ec);
    }

    auto normPath = [](std::string p) {
        std::replace(p.begin(), p.end(), '\\', '/');
        return p;
    };

    std::vector<std::string> searchPaths;
    std::unordered_set<std::string> seenPaths;

    if (!m_config.writableDir.empty()) {
        std::string w = normPath(m_config.writableDir);
        if (!w.empty() && w.back() != '/') w.push_back('/');
        setConfiguredWritableDirSnapshot(w);
        fileUtils->setWritablePath(w);
#ifdef _WIN32
        ::SetEnvironmentVariableW(L"GCLIENT_WRITABLE_DIR", utf8ToWidePath(w).c_str());
#endif
        appendSearchLayer(searchPaths, seenPaths, w + "Resources");
    }

    if (!m_config.hotfixDir.empty()) {
        update::HotUpdaterConfig hotCfg;
        hotCfg.patchRootDir = toSafeFsPath(m_config.hotfixDir);
        if (!m_config.baseAssetsDir.empty()) {
            hotCfg.baseResourcesDir = toSafeFsPath(m_config.baseAssetsDir);
        } else if (!m_config.resourcesDir.empty()) {
            hotCfg.baseResourcesDir = toSafeFsPath(m_config.resourcesDir);
        }
        update::AtomicHotUpdater updater(hotCfg);
        const auto health = updater.initializeAndCheckStartupHealth();
        if (health.hasActiveOverlay && !health.activeOverlayPath.empty()) {
#ifdef _WIN32
            appendSearchLayer(searchPaths, seenPaths, wideToUtf8Path(health.activeOverlayPath.wstring()));
#else
            appendSearchLayer(searchPaths, seenPaths, health.activeOverlayPath.string());
#endif
        }
        appendSearchLayer(searchPaths, seenPaths, m_config.hotfixDir);
    }

    if (!m_config.resourcesDir.empty()) {
        const std::string normRes = normPath(m_config.resourcesDir);
#ifdef _WIN32
        ::SetEnvironmentVariableW(L"GCLIENT_RESOURCES_DIR", utf8ToWidePath(normRes).c_str());
#endif
        appendSearchLayer(searchPaths, seenPaths, normRes);
    }
    if (!m_config.baseAssetsDir.empty()) {
        const std::string normBase = normPath(m_config.baseAssetsDir);
#ifdef _WIN32
        ::SetEnvironmentVariableW(L"GCLIENT_BASE_ASSETS_DIR", utf8ToWidePath(normBase).c_str());
#endif
        appendSearchLayer(searchPaths, seenPaths, normBase);
    }

    const std::string appRoot = normPath(fileUtils->getAppRoot());
    if (!appRoot.empty()) {
        const std::string axslcPath = (appRoot.back() == '/') ? (appRoot + "axslc") : (appRoot + "/axslc");
        if (seenPaths.insert(axslcPath).second) {
            searchPaths.push_back(axslcPath);
        }
        if (seenPaths.insert(appRoot).second) {
            searchPaths.push_back(appRoot);
        }
    }

    fileUtils->setSearchPaths(searchPaths);

    if (bt::Platform* platform = bt::Platform::getInstance()) {
        if (!m_config.baseAssetsDir.empty()) {
            platform->setResourceRoot(normPath(m_config.baseAssetsDir));
        } else if (!m_config.resourcesDir.empty()) {
            platform->setResourceRoot(normPath(m_config.resourcesDir));
        }
        platform->setLogHandler([](const std::string& level, const std::string& message) {
            const auto lvl = (level == "error") ? diagnostics::LogLevel::Error : diagnostics::LogLevel::Info;
            diagnostics::CrashAndTelemetry::log(lvl, "bt::Platform", "%s", message.c_str());
        });
        platform->setWebViewBridgeHandler(
            [](const std::string& action, int x, int y, int width, int height, const std::string& url) {
                if (!AppDelegate::isLifecycleReady()) return;
                auto* webView = gclient::ui::ZYWebViewWin32::getInstance();
                if (!webView) return;
                if (action == "displayWebView") {
                    webView->displayWebView(x, y, width, height);
                } else if (action == "updateURL") {
                    webView->updateURL(url);
                } else if (action == "removeWebView") {
                    webView->removeWebView();
                }
            });
    }

    gclient::assets::InstallBtDecryptHook(fileUtils);
}

void AppDelegate::registerLuaBindings(lua_State* L) {
    // 1. Register Axmol's standard C++ -> Lua modules (core, ui, cocostudio, spine, audio, cjson)
    lua_module_register(L);

    // 2. Register Cocos2d-x 2.2.6 container/UI/audio C++ classes & Lua 2.2.6 runtime compatibility shim
    gclient::compat::RegisterAxmol226CompatLuaBindings(L);
    gclient::compat::InstallLua226CompatShim(L);

    // 3. Register Kestrel-Canvas first-party bindings (GameTemplate, BTUtil, AMF3, HTTP/Crypto, Platform)
    tolua_extensions_ccb_open(L);
    tolua_GameTemplate_open(L);
    luaopen_lua_extensions(L);
    luaopen_amf3_extensions(L);
#ifdef GCLIENT_ENABLE_LUAPROFILER
    luaopen_luaprofiler(L);
#endif
    tolua_BTUtil_open(L);

    tolua_Platform_open(L);
    tolua_PluginManager_open(L);
    tolua_NotificationManager_open(L);

    RegisterAssetLoaderHooks(L);

    const lua_CFunction logErrFn = [](lua_State* L) -> int {
        const char* msg = lua_tostring(L, 1);
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error, "LuaErr", "%s", msg ? msg : "(null)");
        diagnostics::CrashAndTelemetry::flushLogs();
        return 0;
    };
    lua_pushcfunction(L, logErrFn);
    lua_setglobal(L, "__GCLIENT_LOG_ERR__");

    const lua_CFunction logInfoFn = [](lua_State* L) -> int {
        const int nargs = lua_gettop(L);
        std::string out;
        lua_getglobal(L, "tostring");
        const bool hasToString = lua_isfunction(L, -1);
        for (int i = 1; i <= nargs; ++i) {
            if (i > 1) out.push_back('\t');
            if (hasToString) {
                lua_pushvalue(L, -1);
                lua_pushvalue(L, i);
                if (lua_pcall(L, 1, 1, 0) == 0) {
                    const char* s = lua_tostring(L, -1);
                    out.append(s ? s : "nil");
                } else {
                    out.append("<tostring-err>");
                }
                lua_pop(L, 1);
            } else {
                const char* s = lua_tostring(L, i);
                out.append(s ? s : "nil");
            }
        }
        lua_pop(L, 1);
        diagnostics::CrashAndTelemetry::log(diagnostics::LogLevel::Info, "Lua", "%s", out.c_str());
        return 0;
    };
    lua_pushcfunction(L, logInfoFn);
    lua_setglobal(L, "__GCLIENT_LOG_INFO__");

    static constexpr const char* kLuaBootstrapShim =
        "do "
        "local _r = require "
        "require = function(n) "
        "  local res = _r(n) "
        "  if (n == 'config.Config' or n == 'config/Config') and type(res) == 'table' and res.currentOS == nil then "
        "    res.currentOS = 'android' "
        "  end "
        "  return res "
        "end "
        "if type(io) == 'table' and type(io.open) == 'function' then "
        "  local _io_open = io.open "
        "  io.open = function(path, mode) "
        "    if mode == nil then mode = 'rb' "
        "    elseif type(mode) == 'string' and not mode:find('b', 1, true) then mode = mode .. 'b' end "
        "    return _io_open(path, mode) "
        "  end "
        "end "
        "end";

    if (luaL_dostring(L, kLuaBootstrapShim) != 0) {
        const char* err = lua_tostring(L, -1);
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error, "AppDelegate", "Bootstrap shim error: %s", err ? err : "(null)");
        lua_pop(L, 1);
    }

    g_validateAssetsOnly.store(m_config.validateAssetsOnly, std::memory_order_release);
    const lua_CFunction ccMessageBoxFn = [](lua_State* L) -> int {
        const char* msg = lua_tostring(L, 1);
        const char* title = lua_tostring(L, 2);
        const std::string msgStr = msg ? msg : "(null)";
        const std::string titleStr = (title && title[0] != '\0') ? title : "Game Client";

        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error, "CCMessageBox", "[%s] %s", titleStr.c_str(), msgStr.c_str());
        diagnostics::CrashAndTelemetry::flushLogs();

        const std::string dedupKey = titleStr + "\n" + msgStr;
        const bool showAlert = sharedAlertDialogGate().shouldDisplayPopup(
            dedupKey,
            g_validateAssetsOnly.load(std::memory_order_acquire),
            isEnvFlagEnabled("GCLIENT_SUPPRESS_MESSAGEBOX"),
            isEnvFlagEnabled("GCLIENT_HEADLESS"));
        maybeShowWin32AlertPopup(titleStr, msgStr, showAlert);
        return 0;
    };
    lua_pushcfunction(L, ccMessageBoxFn);
    lua_setglobal(L, "CCMessageBox");

    // Extend ax.FileUtils metatable with writable path override & removeSearchPath
    luaL_getmetatable(L, "ax.FileUtils");
    if (lua_istable(L, -1)) {
        const lua_CFunction removeSearchPathFn = [](lua_State* L) -> int {
            auto* self = ax::FileUtils::getInstance();
            const char* target = lua_tostring(L, 2);
            if (self && target) {
                std::string targetStr(target);
                std::replace(targetStr.begin(), targetStr.end(), '\\', '/');
                auto paths = self->getSearchPaths();
                paths.erase(
                    std::remove_if(paths.begin(), paths.end(), [&](std::string p) {
                        std::replace(p.begin(), p.end(), '\\', '/');
                        return p == targetStr || (!targetStr.empty() && p == targetStr + "/");
                    }),
                    paths.end());
                self->setSearchPaths(paths);
            }
            return 0;
        };
        lua_pushcfunction(L, removeSearchPathFn);
        lua_setfield(L, -2, "removeSearchPath");

        const lua_CFunction getWritablePathFn = [](lua_State* L) -> int {
            const std::string configured = getConfiguredWritableDirSnapshot();
            if (!configured.empty()) {
                lua_pushlstring(L, configured.data(), configured.size());
                return 1;
            }
            std::string s = ax::FileUtils::getInstance()->getWritablePath();
            std::replace(s.begin(), s.end(), '\\', '/');
            if (!s.empty() && s.back() != '/') s.push_back('/');
            lua_pushlstring(L, s.data(), s.size());
            return 1;
        };
        lua_pushcfunction(L, getWritablePathFn);
        lua_setfield(L, -2, "getWritablePath");
    }
    lua_pop(L, 1);

    // Install custom gclientLuaLoader in package.loaders (Lua 5.1 / LuaJIT) or package.searchers
    lua_getglobal(L, "package");
    if (lua_istable(L, -1)) {
        lua_pushstring(L, "");
        lua_setfield(L, -2, "path");
        lua_getfield(L, -1, "loaders");
        if (!lua_istable(L, -1)) {
            lua_pop(L, 1);
            lua_getfield(L, -1, "searchers");
        }
        if (lua_istable(L, -1)) {
            lua_pushcfunction(L, &gclientLuaLoader);
            lua_rawseti(L, -2, 2);
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

void AppDelegate::scheduleNativeLoops() {
    if (m_ticker == nullptr) {
        m_ticker = new FrameTicker();
    }

    auto bindNativeSchedulers = [this]() {
        if (m_ticker == nullptr) return;
        if (ax::Director* director = ax::Director::getInstance()) {
            if (ax::Scheduler* scheduler = director->getScheduler()) {
                scheduler->unschedule(AX_SCHEDULE_SELECTOR(FrameTicker::onTick), m_ticker);
                scheduler->schedule(
                    AX_SCHEDULE_SELECTOR(FrameTicker::onTick),
                    m_ticker,
                    0.0f,
                    false);
                if (CTimer* timer = CTimer::sharedTimer()) {
                    scheduler->unscheduleAllForTarget(timer);
                    scheduler->scheduleUpdate(timer, 0, false);
                }
            }
        }
        RescheduleLuaHelpersCallbacks();
    };

    bindNativeSchedulers();
    BTUtil::setPostUnscheduleAllHook([bindNativeSchedulers]() {
        UnscheduleAllLuaScriptEntries();
        bindNativeSchedulers();
    });
}

void AppDelegate::unscheduleNativeLoops() {
    BTUtil::setPostUnscheduleAllHook(nullptr);
    if (m_ticker == nullptr) return;
    if (ax::Director* director = ax::Director::getInstance()) {
        if (ax::Scheduler* scheduler = director->getScheduler()) {
            scheduler->unscheduleAllForTarget(m_ticker);
        }
    }
    m_ticker->release();
    m_ticker = nullptr;
}

bool AppDelegate::runAssetValidation() {
    namespace fs = std::filesystem;

    ax::FileUtils* fileUtils = ax::FileUtils::getInstance();
    const std::string mainScriptPath = fileUtils->fullPathForFilename("scripts/main.lua");

    std::error_code ec;
    if (mainScriptPath.empty() || !fs::exists(toSafeFsPath(mainScriptPath), ec)) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AssetValidation",
            "Missing entry script 'scripts/main.lua' under resources dir '%s'",
            m_config.resourcesDir.c_str());
        return false;
    }

    unsigned long dataSize = 0;
    unsigned char* data = gclient::assets::LoadAndDecryptFileData(mainScriptPath, &dataSize);
    if (data == nullptr || dataSize == 0) {
        delete[] data;
        return false;
    }
    delete[] data;
    return true;
}

void AppDelegate::reconcileInitialWindowLifecycleState(ax::Director* director,
                                                       ax::RenderViewImpl* renderView) {
    const bool earlyBg = m_pendingBackground.exchange(false, std::memory_order_acq_rel);
    (void)m_pendingForeground.exchange(false, std::memory_order_acq_rel);

    if (earlyBg || isRenderViewZeroOrMinimized(renderView)) {
        m_isInBackground.store(true, std::memory_order_release);
        if (director) director->stopAnimation();
        if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
            audio->pauseBackgroundMusic();
            audio->pauseAllEffects();
        }
        diagnostics::CrashAndTelemetry::flushLogs();
    } else {
        m_isInBackground.store(false, std::memory_order_release);
        if (director && renderView) {
            const ax::Vec2 winSz = director->getWinSize();
            if (!std::isfinite(winSz.width) || !std::isfinite(winSz.height) ||
                winSz.width < 1.0f || winSz.height < 1.0f) {
                renderView->setDesignResolutionSize(
                    kDesignWidth, kDesignHeight, ResolutionPolicy::FIXED_WIDTH);
            }
        }
    }
}

bool AppDelegate::applicationDidFinishLaunching() {
    LifecycleState expectedState = LifecycleState::Uninitialized;
    if (!m_lifecycleState.compare_exchange_strong(
            expectedState, LifecycleState::Initializing, std::memory_order_acq_rel)) {
        return expectedState == LifecycleState::Ready;
    }

    // 1. Configure FileUtils search paths, hotfix overlay, and writable path isolation FIRST.
    configureFileUtils();

    // 2. Initialize Director and create/bind Axmol GLFW RenderViewImpl if not yet created.
    ax::Director* director = ax::Director::getInstance();
    if (!director) {
        teardownSubsystems(LifecycleState::Failed);
        return false;
    }

    auto* renderView = dynamic_cast<ax::RenderViewImpl*>(director->getRenderView());
    if (!renderView) {
        const float w = static_cast<float>(m_config.windowWidth > 0 ? m_config.windowWidth : 1136);
        const float h = static_cast<float>(m_config.windowHeight > 0 ? m_config.windowHeight : 640);
        renderView = ax::RenderViewImpl::createWithRect(
            "Kestrel Canvas (Axmol x64)", ax::Rect(0.0f, 0.0f, w, h), 1.0f, true);
        if (!renderView) {
            diagnostics::CrashAndTelemetry::log(
                diagnostics::LogLevel::Fatal, "AppDelegate", "Failed to create RenderViewImpl");
            diagnostics::CrashAndTelemetry::flushLogs();
            teardownSubsystems(LifecycleState::Failed);
            return false;
        }
        director->setRenderView(renderView);
    }

#ifdef _WIN32
    if (HWND hwnd = renderView->getWin32Window()) {
        gclient::ui::Win32DesktopBridge::instance().attachToWindow(hwnd);
    }
#endif

    renderView->setDesignResolutionSize(kDesignWidth, kDesignHeight, ResolutionPolicy::FIXED_WIDTH);
    director->setAnimationInterval(kTargetAnimationInterval);
    director->setStatsDisplay(true);

    // 3. Handle --validate-assets if invoked through full application launch.
    if (m_config.validateAssetsOnly) {
        m_assetValidationOk = runAssetValidation();
        director->end();
        teardownSubsystems(m_assetValidationOk ? LifecycleState::Terminated : LifecycleState::Failed);
        return false;
    }

    // 4. Honor --mute CLI flag.
    gclient::ui::Win32DesktopBridge::instance().setInitialMuted(m_config.muteAudio);
    if (m_config.muteAudio) {
        if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
            audio->setBackgroundMusicVolume(0.0f);
            audio->setEffectsVolume(0.0f);
        }
    }

    // 5. Initialize Axmol LuaEngine and register bindings + 2.2.6 compatibility shims.
    ax::LuaEngine* engine = ax::LuaEngine::getInstance();
    if (!engine || !engine->getLuaStack() || !engine->getLuaStack()->getLuaState()) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Fatal, "AppDelegate", "Failed to initialize ax::LuaEngine");
        diagnostics::CrashAndTelemetry::flushLogs();
        director->end();
        teardownSubsystems(LifecycleState::Failed);
        return false;
    }
    ax::ScriptEngineManager::getInstance()->setScriptEngine(engine);

    lua_State* L = engine->getLuaStack()->getLuaState();
    diagnostics::CrashAndTelemetry::installLuaHooks(L);
    registerLuaBindings(L);
    scheduleNativeLoops();

    // 6. Boot Lua game entry point.
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info, "AppDelegate", "Executing Lua entry point: require \"scripts/main\"");

    const int status = engine->executeString("require \"scripts/main\"");
    if (status != 0) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Fatal,
            "AppDelegate",
            "Lua bootstrap failed (status=%d) while executing require \"scripts/main\"",
            status);
        diagnostics::CrashAndTelemetry::flushLogs();
        director->end();
        teardownSubsystems(LifecycleState::Failed);
        return false;
    }

    m_lifecycleState.store(LifecycleState::Ready, std::memory_order_release);
    if (!m_config.hotfixDir.empty()) {
        update::HotUpdaterConfig hotCfg;
        hotCfg.patchRootDir = toSafeFsPath(m_config.hotfixDir);
        if (!m_config.baseAssetsDir.empty()) {
            hotCfg.baseResourcesDir = toSafeFsPath(m_config.baseAssetsDir);
        } else if (!m_config.resourcesDir.empty()) {
            hotCfg.baseResourcesDir = toSafeFsPath(m_config.resourcesDir);
        }
        update::AtomicHotUpdater updater(hotCfg);
        (void)updater.confirmStartupSuccess();
    }
    reconcileInitialWindowLifecycleState(director, renderView);
    return true;
}

void AppDelegate::applicationDidEnterBackground() {
    if (m_lifecycleState.load(std::memory_order_acquire) != LifecycleState::Ready) {
        m_pendingBackground.store(true, std::memory_order_release);
        m_pendingForeground.store(false, std::memory_order_release);
        return;
    }
    if (m_isInBackground.exchange(true, std::memory_order_acq_rel)) return;

    if (auto* director = ax::Director::getInstance()) {
        director->stopAnimation();
    }
    if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
        audio->pauseBackgroundMusic();
        audio->pauseAllEffects();
    }
    diagnostics::CrashAndTelemetry::flushLogs();
}

void AppDelegate::applicationWillEnterForeground() {
    if (m_lifecycleState.load(std::memory_order_acquire) != LifecycleState::Ready) {
        m_pendingForeground.store(true, std::memory_order_release);
        m_pendingBackground.store(false, std::memory_order_release);
        return;
    }

    ax::Director* director = ax::Director::getInstance();
    auto* rv = director ? dynamic_cast<ax::RenderViewImpl*>(director->getRenderView()) : nullptr;
    if (!director || isRenderViewZeroOrMinimized(rv)) {
        m_pendingForeground.store(true, std::memory_order_release);
        return;
    }

    m_pendingForeground.store(false, std::memory_order_release);
    const ax::Vec2 winSz = director->getWinSize();
    if (!std::isfinite(winSz.width) || !std::isfinite(winSz.height) ||
        winSz.width < 1.0f || winSz.height < 1.0f) {
        rv->setDesignResolutionSize(kDesignWidth, kDesignHeight, ResolutionPolicy::FIXED_WIDTH);
    }

    if (!m_isInBackground.exchange(false, std::memory_order_acq_rel)) return;

    director->startAnimation();
    if (!m_config.muteAudio && !gclient::ui::Win32DesktopBridge::instance().isMuted()) {
        if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
            audio->resumeBackgroundMusic();
            audio->resumeAllEffects();
        }
    }
}

} // namespace gclient
