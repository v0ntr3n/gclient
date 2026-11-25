// ============================================================================
// Game Client Win32 Port — AppDelegate Implementation
// Reconstructed from libcocos2dlua.so AppDelegate::applicationDidFinishLaunching
// (0x2a25d8) and hardened with an explicit atomic Win32 lifecycle state machine.
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

std::mutex g_writableDirMutex;
std::string g_configuredWritableDir;
std::atomic<bool> g_validateAssetsOnly{false};
std::atomic<AppDelegate*> g_activeAppInstance{nullptr};

constexpr float kDesignWidth = 1136.0f;
constexpr float kDesignHeight = 640.0f;
constexpr double kTargetAnimationInterval = 0.0333333333; // 30 FPS

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
    if (utf8.empty()) {
        return {};
    }
    int req = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (req <= 0) {
        req = ::MultiByteToWideChar(
            CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    }
    if (req <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(req), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), req);
    return wide;
}

std::string wideToUtf8Path(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }
    const int req = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (req <= 0) {
        return {};
    }
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

template <typename T, typename = void>
struct HasGetFrameSize : std::false_type {};
template <typename T>
struct HasGetFrameSize<T, std::void_t<decltype(std::declval<T*>()->getFrameSize())>> : std::true_type {};

template <typename T, typename = void>
struct HasGetHWnd : std::false_type {};
template <typename T>
struct HasGetHWnd<T, std::void_t<decltype(std::declval<T*>()->getHWnd())>> : std::true_type {};

template <typename T>
bool isEglViewZeroOrMinimized(T* eglView) {
    if (!eglView) {
        return true;
    }
#ifdef _WIN32
    if constexpr (HasGetHWnd<T>::value) {
        HWND hwnd = eglView->getHWnd();
        if (hwnd != nullptr) {
            if (!::IsWindow(hwnd) || ::IsIconic(hwnd)) {
                return true;
            }
            RECT rc{};
            if (::GetClientRect(hwnd, &rc)) {
                if ((rc.right - rc.left) < 1 || (rc.bottom - rc.top) < 1) {
                    return true;
                }
            }
        }
    }
#endif
    if constexpr (HasGetFrameSize<T>::value) {
        const cocos2d::CCSize frameSz = eglView->getFrameSize();
        if (frameSz.width < 1.0f || frameSz.height < 1.0f ||
            !std::isfinite(frameSz.width) || !std::isfinite(frameSz.height)) {
            return true;
        }
    }
    return false;
}

template <typename T>
void ensureNonZeroEglFrameSize(T* eglView, int fallbackW, int fallbackH) {
    if (!eglView) {
        return;
    }
    if constexpr (HasGetFrameSize<T>::value) {
        const cocos2d::CCSize frameSz = eglView->getFrameSize();
        if (frameSz.width < 1.0f || frameSz.height < 1.0f ||
            !std::isfinite(frameSz.width) || !std::isfinite(frameSz.height)) {
            const float safeW = static_cast<float>(fallbackW > 0 ? fallbackW : 1136);
            const float safeH = static_cast<float>(fallbackH > 0 ? fallbackH : 640);
            // Qualify CCEGLViewProtocol::setFrameSize so we never invoke Win32 MoveWindow
            // on an iconic window or trigger recursive synchronous WM_SIZE messages!
            if constexpr (std::is_base_of_v<cocos2d::CCEGLViewProtocol, T>) {
                eglView->cocos2d::CCEGLViewProtocol::setFrameSize(safeW, safeH);
            } else {
                eglView->setFrameSize(safeW, safeH);
            }
        }
    }
}

bool isEnvFlagEnabled(const char* name) {
    if (!name || !*name) {
        return false;
    }
    std::string val;
#ifdef _WIN32
    char buf[32] = {};
    const DWORD len = ::GetEnvironmentVariableA(name, buf, static_cast<DWORD>(sizeof(buf)));
    if (len > 0 && len < sizeof(buf)) {
        val.assign(buf, len);
    }
#endif
    if (val.empty()) {
        if (const char* raw = std::getenv(name)) {
            val = raw;
        }
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
        if (validateAssetsOnly || suppressMessageBoxEnv || headlessEnv) {
            return false;
        }
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_seenMessages.find(messageText) != m_seenMessages.end()) {
            return false;
        }
        if (m_shownCount >= kMaxPopupsPerProcess) {
            return false;
        }
        m_seenMessages.insert(messageText);
        ++m_shownCount;
        return true;
    }

private:
    std::mutex m_mutex;
    std::unordered_set<std::string> m_seenMessages;
    std::size_t m_shownCount = 0;
};

AlertDialogGate& sharedAlertDialogGate() {
    static AlertDialogGate* s_gate = new AlertDialogGate();
    return *s_gate;
}

#ifdef _WIN32
void showAsyncWin32Alert(std::string title, std::string message) {
    std::thread([t = std::move(title), m = std::move(message)]() {
        // Immortal heap mutex avoids static-destruction-order UB if process exits while popup is open.
        static std::mutex* s_dialogMutex = new std::mutex();
        std::lock_guard<std::mutex> lock(*s_dialogMutex);
        const std::wstring wideTitle = utf8ToWidePath(t.empty() ? "Game Client" : t);
        const std::wstring wideMsg = utf8ToWidePath(m);
        ::MessageBoxW(
            nullptr,
            wideMsg.c_str(),
            wideTitle.empty() ? L"Game Client" : wideTitle.c_str(),
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
    }).detach();
}
#endif

void appendSearchLayer(std::vector<std::string>& searchPaths,
                       std::unordered_set<std::string>& seen,
                       std::string layerRoot) {
    std::replace(layerRoot.begin(), layerRoot.end(), '\\', '/');
    while (layerRoot.size() > 1 && layerRoot.back() == '/') {
        if (layerRoot.size() == 3 && layerRoot[1] == ':') {
            break;
        }
        layerRoot.pop_back();
    }
    if (layerRoot.empty()) {
        return;
    }

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

void maybeShowWin32AlertPopup(const std::string& titleStr, const std::string& msgStr, bool showAlert) {
#ifdef _WIN32
    if (showAlert) {
        showAsyncWin32Alert(titleStr, msgStr);
    }
#else
    (void)titleStr;
    (void)msgStr;
    (void)showAlert;
#endif
}

} // namespace

// ----------------------------------------------------------------------------
// FrameTicker: CCObject bridge scheduled on CCScheduler (replaces loom::tick)
// ----------------------------------------------------------------------------
class AppDelegate::FrameTicker final : public cocos2d::CCObject {
public:
    void onTick(float dt) {
        if (!AppDelegate::isLifecycleReady()) {
            return;
        }
        if (bt::Platform* platform = bt::Platform::getInstance()) {
            platform->tickLoop();
        }
        if (gclient::net::CNetwork* network = gclient::net::CNetwork::sharedNetwork()) {
            network->update(dt);
        }
        diagnostics::CrashAndTelemetry::recordFrame(dt);
        static int s_frame = 0;
        if (++s_frame == 60) {
            auto* scene = cocos2d::CCDirector::sharedDirector()->getRunningScene();
            diagnostics::CrashAndTelemetry::log(
                diagnostics::LogLevel::Info,
                "AppDelegate",
                "Frame 60: runningScene=%p children=%u",
                static_cast<void*>(scene),
                scene ? scene->getChildrenCount() : 0u);
        } else if (s_frame == 90) {
            if (const char* shotName = std::getenv("GCLIENT_SCREENSHOT_NAME")) {
                auto* director = cocos2d::CCDirector::sharedDirector();
                auto* eglView = cocos2d::CCEGLView::sharedOpenGLView();
                if (director && !isEglViewZeroOrMinimized(eglView)) {
                    if (auto* scene = director->getRunningScene()) {
                        const auto winSize = director->getWinSize();
                        if (std::isfinite(winSize.width) && std::isfinite(winSize.height) &&
                            winSize.width >= 1.0f && winSize.height >= 1.0f) {
                            if (auto* rt = cocos2d::CCRenderTexture::create(
                                    static_cast<int>(winSize.width), static_cast<int>(winSize.height))) {
                                rt->begin();
                                scene->visit();
                                rt->end();
                                rt->saveToFile(shotName, cocos2d::kCCImageFormatPNG);
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
// AppDelegate lifecycle
// ----------------------------------------------------------------------------
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

bool AppDelegate::executeHeadlessAssetValidation() {
    LifecycleState expectedState = LifecycleState::Uninitialized;
    if (!m_lifecycleState.compare_exchange_strong(
            expectedState, LifecycleState::Initializing, std::memory_order_acq_rel)) {
        return m_assetValidationOk;
    }
    configureFileUtils();
    m_assetValidationOk = runAssetValidation();
    diagnostics::CrashAndTelemetry::flushLogs();
    teardownSubsystems(m_assetValidationOk ? LifecycleState::Terminated : LifecycleState::Failed);
    return m_assetValidationOk;
}

void AppDelegate::shutdown() {
    teardownSubsystems(LifecycleState::Terminated);
}

void AppDelegate::teardownSubsystems(LifecycleState terminalState) {
    LifecycleState cur = m_lifecycleState.load(std::memory_order_acquire);
    if (cur == LifecycleState::Terminated || cur == LifecycleState::ShuttingDown) {
        if (terminalState == LifecycleState::Terminated) {
            m_lifecycleState.store(LifecycleState::Terminated, std::memory_order_release);
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

    // Clear CrashAndTelemetry's cached lua_State* BEFORE Lua engine teardown so
    // background/telemetry collectors never touch a closed lua_State*!
    clearTelemetryLuaStateBeforeTeardown();
    cocos2d::CCScriptEngineManager::purgeSharedManager();
    CocosDenshion::SimpleAudioEngine::end();

    m_lifecycleState.store(terminalState, std::memory_order_release);
}

void AppDelegate::configureFileUtils() {
    cocos2d::CCFileUtils* fileUtils = cocos2d::CCFileUtils::sharedFileUtils();

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
#ifdef _WIN32
        ::SetEnvironmentVariableW(L"GCLIENT_WRITABLE_DIR", utf8ToWidePath(w).c_str());
#endif
        appendSearchLayer(searchPaths, seenPaths, w + "Resources");
    }

    // Check AtomicHotUpdater active overlay health before wiring hotfix search paths.
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
                if (!AppDelegate::isLifecycleReady()) {
                    return;
                }
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

    fileUtils->setDecrypt(&bt_decrypt);
    gclient::assets::InstallBtDecryptHook(fileUtils);
}

void AppDelegate::registerLuaBindings(lua_State* L) {
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
            diagnostics::LogLevel::Error,
            "LuaErr",
            "%s",
            msg ? msg : "(null)");
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
            if (i > 1) {
                out.push_back('\t');
            }
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
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Info,
            "Lua",
            "%s",
            out.c_str());
        return 0;
    };
    lua_pushcfunction(L, logInfoFn);
    lua_setglobal(L, "__GCLIENT_LOG_INFO__");

    static constexpr const char* kLuaBootstrapShim =
        "do "
        "local _gmt = getmetatable(_G) or {} "
        "local _old_ni = _gmt.__newindex "
        "local _old_idx = _gmt.__index "
        "local _hooks = {} "
        "local _already_mirrored = {} "
        "local _in_tb = false "
        "local _in_print = false "
        "local function _get_tb(lvl) "
        "  if type(debug) == 'table' and type(debug.traceback) == 'function' then "
        "    return debug.traceback('', lvl or 2) "
        "  end "
        "  return '' "
        "end "
        "local function _wrap_tb(fn) "
        "  return function(msg) "
        "    local full = tostring(msg) .. '\\n' .. tostring(_get_tb(2)) "
        "    if not _in_tb then "
        "      _in_tb = true "
        "      __GCLIENT_LOG_ERR__(full) "
        "      if type(fn) == 'function' then "
        "        local ok, res = pcall(fn, msg) "
        "        _in_tb = false "
        "        if not ok then "
        "          __GCLIENT_LOG_ERR__('TRACKBACK_HANDLER_ERR:' .. tostring(res)) "
        "        else "
        "          return res "
        "        end "
        "      else "
        "        _in_tb = false "
        "      end "
        "    end "
        "    return full "
        "  end "
        "end "
        "local _native_print = rawget(_G, '__GCLIENT_NATIVE_PRINT__') "
        "if type(_native_print) == 'function' then _already_mirrored[_native_print] = true end "
        "local function _wrap_print(fn) "
        "  if type(fn) == 'function' and _already_mirrored[fn] then return fn end "
        "  local orig = (type(fn) == 'function' and fn ~= __GCLIENT_LOG_INFO__) and fn or nil "
        "  local w "
        "  w = function(...) "
        "    if _in_print then "
        "      if orig then return orig(...) end "
        "      return "
        "    end "
        "    _in_print = true "
        "    __GCLIENT_LOG_INFO__(...) "
        "    if orig then "
        "      local ok, r1, r2 = pcall(orig, ...) "
        "      _in_print = false "
        "      if not ok then error(r1, 0) end "
        "      return r1, r2 "
        "    end "
        "    _in_print = false "
        "  end "
        "  _already_mirrored[w] = true "
        "  return w "
        "end "
        "local function _wrap_existing_mirrored(fn) "
        "  local w "
        "  w = function(...) "
        "    if _in_print then return end "
        "    _in_print = true "
        "    local ok, r1, r2 = pcall(fn, ...) "
        "    _in_print = false "
        "    if not ok then error(r1, 0) end "
        "    return r1, r2 "
        "  end "
        "  _already_mirrored[fn] = true "
        "  _already_mirrored[w] = true "
        "  return w "
        "end "
        "local _init_tb = rawget(_G, '__G__TRACKBACK__') "
        "local _native_tb = rawget(_G, '__GCLIENT_NATIVE_TRACKBACK__') "
        "rawset(_G, '__G__TRACKBACK__', nil) "
        "_hooks.__G__TRACKBACK__ = _wrap_tb((_init_tb ~= _native_tb) and _init_tb or nil) "
        "local _pnames = {'print', 'release_print', 'CCLuaLog'} "
        "for i = 1, #_pnames do "
        "  local pn = _pnames[i] "
        "  local cur = rawget(_G, pn) "
        "  rawset(_G, pn, nil) "
        "  if _native_print ~= nil and type(cur) == 'function' then "
        "    _hooks[pn] = _wrap_existing_mirrored(cur) "
        "  else "
        "    _hooks[pn] = _wrap_print(cur) "
        "  end "
        "end "
        "_gmt.__index = function(t, k) "
        "  local h = _hooks[k] "
        "  if h ~= nil then return h end "
        "  if type(_old_idx) == 'function' then return _old_idx(t, k) "
        "  elseif type(_old_idx) == 'table' then return _old_idx[k] end "
        "  return nil "
        "end "
        "_gmt.__newindex = function(t, k, v) "
        "  if k == '__G__TRACKBACK__' then "
        "    _hooks.__G__TRACKBACK__ = _wrap_tb(v) "
        "    return "
        "  elseif k == 'print' or k == 'release_print' or k == 'CCLuaLog' then "
        "    _hooks[k] = _wrap_print(v) "
        "    return "
        "  elseif k == 'g' and type(v) == 'table' then "
        "    local mt = getmetatable(v) or {} "
        "    mt.__newindex = function(gt, gk, gv) "
        "      if gk == 'isRefresh' then gv = true end "
        "      rawset(gt, gk, gv) "
        "    end "
        "    setmetatable(v, mt) "
        "  end "
        "  if _old_ni then _old_ni(t, k, v) else rawset(t, k, v) end "
        "end "
        "setmetatable(_G, _gmt) "
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
        "local _xp = xpcall "
        "xpcall = function(f, eh, ...) "
        "  local wrapped_eh = function(m) "
        "    if eh ~= _hooks.__G__TRACKBACK__ then "
        "      __GCLIENT_LOG_ERR__('ORIG:' .. tostring(m) .. '\\n' .. tostring(_get_tb(2))) "
        "    end "
        "    if type(eh) == 'function' then "
        "      local ok2, e2 = pcall(eh, m) "
        "      if not ok2 then __GCLIENT_LOG_ERR__('EH_ERR:' .. tostring(e2)) end "
        "      return e2 "
        "    end "
        "    return m "
        "  end "
        "  if select('#', ...) > 0 then return _xp(f, wrapped_eh, ...) end "
        "  return _xp(f, wrapped_eh) "
        "end "
        "end";

    if (luaL_dostring(L, kLuaBootstrapShim) != 0) {
        const char* err = lua_tostring(L, -1);
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AppDelegate",
            "Config shim error: %s",
            err ? err : "(null)");
        lua_pop(L, 1);
    }

    g_validateAssetsOnly.store(m_config.validateAssetsOnly, std::memory_order_release);
    const lua_CFunction ccMessageBoxFn = [](lua_State* L) -> int {
        const char* msg = lua_tostring(L, 1);
        const char* title = lua_tostring(L, 2);
        const std::string msgStr = msg ? msg : "(null)";
        const std::string titleStr = (title && title[0] != '\0') ? title : "Game Client";

        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "CCMessageBox",
            "[%s] %s",
            titleStr.c_str(),
            msgStr.c_str());
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

    luaL_getmetatable(L, "CCFileUtils");
    if (lua_istable(L, -1)) {
        const lua_CFunction removeSearchPathFn = [](lua_State* L) -> int {
            tolua_Error err{};
            auto* self = (lua_type(L, 1) == LUA_TUSERDATA &&
                          tolua_isusertype(L, 1, "CCFileUtils", 0, &err))
                ? static_cast<cocos2d::CCFileUtils*>(tolua_tousertype(L, 1, nullptr))
                : cocos2d::CCFileUtils::sharedFileUtils();
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

        lua_getfield(L, -1, "getWritablePath");
        if (lua_isfunction(L, -1)) {
            const lua_CFunction getWritablePathClosure = [](lua_State* L) -> int {
                const std::string configuredWritable = getConfiguredWritableDirSnapshot();
                if (!configuredWritable.empty()) {
                    lua_pushlstring(L, configuredWritable.data(), configuredWritable.size());
                    return 1;
                }
                lua_pushvalue(L, lua_upvalueindex(1));
                lua_pushvalue(L, 1);
                lua_call(L, 1, 1);
                const char* p = lua_tostring(L, -1);
                if (p && *p) {
                    std::string s(p);
                    std::replace(s.begin(), s.end(), '\\', '/');
                    if (s.back() != '/') s.push_back('/');
                    lua_pop(L, 1);
                    lua_pushlstring(L, s.data(), s.size());
                }
                return 1;
            };
            lua_pushcclosure(L, getWritablePathClosure, 1);
            lua_setfield(L, -2, "getWritablePath");
        } else {
            lua_pop(L, 1);
        }

        std::vector<std::string> initialPaths;
        if (auto* fu = cocos2d::CCFileUtils::sharedFileUtils()) {
            initialPaths = fu->getSearchPaths();
        }
        lua_newtable(L);
        for (size_t i = 0; i < initialPaths.size(); ++i) {
            lua_pushlstring(L, initialPaths[i].data(), initialPaths[i].size());
            lua_rawseti(L, -2, static_cast<int>(i + 1));
        }
        lua_getfield(L, -2, "removeAllPaths");
        const lua_CFunction removeAllPathsClosure = [](lua_State* L) -> int {
            if (lua_isfunction(L, lua_upvalueindex(2))) {
                lua_pushvalue(L, lua_upvalueindex(2));
                lua_pushvalue(L, 1);
                lua_call(L, 1, 0);
            }
            tolua_Error err{};
            auto* self = (lua_type(L, 1) == LUA_TUSERDATA &&
                          tolua_isusertype(L, 1, "CCFileUtils", 0, &err))
                ? static_cast<cocos2d::CCFileUtils*>(tolua_tousertype(L, 1, nullptr))
                : cocos2d::CCFileUtils::sharedFileUtils();
            if (self) {
                int n = static_cast<int>(lua_objlen(L, lua_upvalueindex(1)));
                for (int i = 1; i <= n; ++i) {
                    lua_rawgeti(L, lua_upvalueindex(1), i);
                    if (const char* p = lua_tostring(L, -1)) {
                        self->addSearchPath(p);
                    }
                    lua_pop(L, 1);
                }
            }
            return 0;
        };
        lua_pushcclosure(L, removeAllPathsClosure, 2);
        lua_setfield(L, -2, "removeAllPaths");

        lua_getfield(L, -1, "fullPathForFilename");
        if (lua_isfunction(L, -1)) {
            const lua_CFunction fullPathClosure = [](lua_State* L) -> int {
                tolua_Error err{};
                auto* self = (lua_type(L, 1) == LUA_TUSERDATA &&
                              tolua_isusertype(L, 1, "CCFileUtils", 0, &err))
                    ? static_cast<cocos2d::CCFileUtils*>(tolua_tousertype(L, 1, nullptr))
                    : cocos2d::CCFileUtils::sharedFileUtils();
                const char* rel = lua_tostring(L, 2);
                if (self && rel && rel[0] != '\0') {
                    for (const auto& base : self->getSearchPaths()) {
                        if (base.empty()) continue;
                        std::string cand = base;
                        if (cand.back() != '/' && cand.back() != '\\') cand.push_back('/');
                        cand += rel;
                        std::error_code ec;
                        if (std::filesystem::is_directory(toSafeFsPath(cand), ec)) {
                            std::replace(cand.begin(), cand.end(), '\\', '/');
                            lua_pushlstring(L, cand.data(), cand.size());
                            return 1;
                        }
                    }
                }
                lua_pushvalue(L, lua_upvalueindex(1));
                lua_pushvalue(L, 1);
                lua_pushvalue(L, 2);
                lua_call(L, 2, 1);
                return 1;
            };
            lua_pushcclosure(L, fullPathClosure, 1);
            lua_setfield(L, -2, "fullPathForFilename");
        } else {
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);

    lua_getglobal(L, "package");
    if (lua_istable(L, -1)) {
        lua_pushstring(L, "");
        lua_setfield(L, -2, "path");
        lua_getfield(L, -1, "loaders");
        if (lua_istable(L, -1)) {
            const lua_CFunction loaderFn = &gclientLuaLoader;
            lua_pushcfunction(L, loaderFn);
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
        if (m_ticker == nullptr) {
            return;
        }
        if (cocos2d::CCDirector* director = cocos2d::CCDirector::sharedDirector()) {
            if (cocos2d::CCScheduler* scheduler = director->getScheduler()) {
                using cocos2d::SEL_SCHEDULE;
                scheduler->unscheduleSelector(schedule_selector(FrameTicker::onTick), m_ticker);
                scheduler->scheduleSelector(
                    schedule_selector(FrameTicker::onTick),
                    m_ticker,
                    0.0f,
                    false);
                if (CTimer* timer = CTimer::sharedTimer()) {
                    scheduler->unscheduleAllForTarget(timer);
                    scheduler->scheduleUpdateForTarget(timer, 0, false);
                }
            }
        }
        gclient_rescheduleHttpClientCallbacks();
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
    if (m_ticker == nullptr) {
        return;
    }
    if (cocos2d::CCDirector* director = cocos2d::CCDirector::sharedDirector()) {
        if (cocos2d::CCScheduler* scheduler = director->getScheduler()) {
            scheduler->unscheduleAllForTarget(m_ticker);
        }
    }
    m_ticker->release();
    m_ticker = nullptr;
}

bool AppDelegate::runAssetValidation() {
    namespace fs = std::filesystem;

    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AssetValidation",
        "Running --validate-assets check against '%s'",
        m_config.resourcesDir.c_str());

    cocos2d::CCFileUtils* fileUtils = cocos2d::CCFileUtils::sharedFileUtils();
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
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AssetValidation",
            "Failed to read or decrypt '%s'",
            mainScriptPath.c_str());
        delete[] data;
        return false;
    }

    delete[] data;
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AssetValidation",
        "Validated '%s' (%lu bytes decrypted/loaded successfully)",
        mainScriptPath.c_str(),
        dataSize);
    return true;
}

void AppDelegate::reconcileInitialWindowLifecycleState(cocos2d::CCDirector* director,
                                                       cocos2d::CCEGLView* eglView) {
    const bool earlyBg = m_pendingBackground.exchange(false, std::memory_order_acq_rel);
    (void)m_pendingForeground.exchange(false, std::memory_order_acq_rel);

    if (earlyBg || isEglViewZeroOrMinimized(eglView)) {
        m_isInBackground.store(true, std::memory_order_release);
        if (director) {
            director->stopAnimation();
        }
        if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
            audio->pauseBackgroundMusic();
            audio->pauseAllEffects();
        }
        diagnostics::CrashAndTelemetry::flushLogs();
    } else {
        m_isInBackground.store(false, std::memory_order_release);
        if (director && eglView) {
            const cocos2d::CCSize winSz = director->getWinSize();
            if (!std::isfinite(winSz.width) || !std::isfinite(winSz.height) ||
                winSz.width < 1.0f || winSz.height < 1.0f) {
                eglView->setDesignResolutionSize(kDesignWidth, kDesignHeight, kResolutionFixedWidth);
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

    cocos2d::CCDirector* pDirector = cocos2d::CCDirector::sharedDirector();
    cocos2d::CCEGLView* pEGLView = cocos2d::CCEGLView::sharedOpenGLView();
    if (!pDirector || !pEGLView) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Fatal,
            "AppDelegate",
            "CCDirector or CCEGLView is null during applicationDidFinishLaunching()");
        diagnostics::CrashAndTelemetry::flushLogs();
        teardownSubsystems(LifecycleState::Failed);
        return false;
    }

    // 1. Configure CCFileUtils search paths, hotfix overlay, writable path isolation, and bt_decrypt hook
    //    FIRST before any texture, font, or stats label can be loaded by CCDirector!
    configureFileUtils();

    // 2. Bind OpenGL view to CCDirector and configure 1136x640 design resolution and 30 FPS cap.
    pDirector->setOpenGLView(pEGLView);
    ensureNonZeroEglFrameSize(pEGLView, m_config.windowWidth, m_config.windowHeight);
    pEGLView->setDesignResolutionSize(kDesignWidth, kDesignHeight, kResolutionFixedWidth);
    pDirector->setAnimationInterval(kTargetAnimationInterval);
    pDirector->setDisplayStats(true);

    // 3. Handle headless --validate-assets mode if requested on CLI.
    if (m_config.validateAssetsOnly) {
        m_assetValidationOk = runAssetValidation();
        pDirector->end();
        teardownSubsystems(m_assetValidationOk ? LifecycleState::Terminated : LifecycleState::Failed);
        return false;
    }

    // 4. Honor --mute CLI flag and sync Win32DesktopBridge before Lua scripts initialize audio.
    gclient::ui::Win32DesktopBridge::instance().setInitialMuted(m_config.muteAudio);
    if (m_config.muteAudio) {
        if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
            audio->setBackgroundMusicVolume(0.0f);
            audio->setEffectsVolume(0.0f);
        }
    }

    // 5. Initialize Lua engine and attach global debug.traceback() error hook.
    cocos2d::CCLuaEngine* pEngine = cocos2d::CCLuaEngine::defaultEngine();
    if (!pEngine || !pEngine->getLuaStack() || !pEngine->getLuaStack()->getLuaState()) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Fatal,
            "AppDelegate",
            "Failed to initialize CCLuaEngine / lua_State");
        diagnostics::CrashAndTelemetry::flushLogs();
        pDirector->end();
        teardownSubsystems(LifecycleState::Failed);
        return false;
    }
    cocos2d::CCScriptEngineManager::sharedManager()->setScriptEngine(pEngine);

    lua_State* L = pEngine->getLuaStack()->getLuaState();
    diagnostics::CrashAndTelemetry::installLuaHooks(L);

    // 6. Register all native tolua++ / Lua extension modules.
    registerLuaBindings(L);

    // 7. Schedule native per-frame loops (bt::Platform::tickLoop, CNetwork::update, telemetry) + BTUtil hook.
    scheduleNativeLoops();

    // 8. Boot Lua game entry point.
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AppDelegate",
        "Executing Lua entry point: require \"scripts/main\"");

    const int status = pEngine->executeString("require \"scripts/main\"");
#ifdef _WIN32
    if (status == 0) {
        wchar_t wideAutoScript[4096] = {};
        const DWORD len = ::GetEnvironmentVariableW(
            L"GCLIENT_AUTOTEST_SCRIPT", wideAutoScript, static_cast<DWORD>(_countof(wideAutoScript)));
        if (len > 0 && len < _countof(wideAutoScript)) {
            const std::string autoScriptUtf8 = wideToUtf8Path(std::wstring(wideAutoScript, len));
            diagnostics::CrashAndTelemetry::log(
                diagnostics::LogLevel::Info, "AutoTest", "Loading autotest script: %s", autoScriptUtf8.c_str());
            unsigned long scriptBytes = 0;
            unsigned char* scriptBuf = gclient::assets::LoadAndDecryptFileData(autoScriptUtf8, &scriptBytes);
            if (scriptBuf && scriptBytes > 0) {
                const std::string chunkName = "@" + autoScriptUtf8;
                if (luaL_loadbuffer(L, reinterpret_cast<const char*>(scriptBuf), scriptBytes, chunkName.c_str()) != 0 ||
                    lua_pcall(L, 0, 0, 0) != 0) {
                    const char* err = lua_tostring(L, -1);
                    diagnostics::CrashAndTelemetry::log(
                        diagnostics::LogLevel::Error, "AutoTest", "Script error: %s", err ? err : "(null)");
                    lua_pop(L, 1);
                }
            } else {
                diagnostics::CrashAndTelemetry::log(
                    diagnostics::LogLevel::Error, "AutoTest", "Cannot read autotest script: %s", autoScriptUtf8.c_str());
            }
            delete[] scriptBuf;
        }
    }
#endif
    {
        lua_getglobal(L, "cjson");
        const bool hasCjson = !lua_isnil(L, -1);
        lua_pop(L, 1);
        lua_getglobal(L, "g");
        bool hasLoginProxy = false;
        std::string curOS = "<nil>";
        if (lua_istable(L, -1)) {
            lua_getfield(L, -1, "loginProxy");
            hasLoginProxy = !lua_isnil(L, -1);
            lua_pop(L, 1);
            lua_getfield(L, -1, "config");
            if (lua_istable(L, -1)) {
                lua_getfield(L, -1, "currentOS");
                if (lua_isstring(L, -1)) curOS = lua_tostring(L, -1);
                lua_pop(L, 1);
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Info,
            "AppDelegate",
            "Lua DIAG: hasCjson=%d curOS=%s hasLoginProxy=%d",
            hasCjson ? 1 : 0,
            curOS.c_str(),
            hasLoginProxy ? 1 : 0);
    }
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AppDelegate",
        "After require scripts/main: status=%d runningScene=%p",
        status,
        static_cast<void*>(pDirector->getRunningScene()));
    if (status != 0) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Fatal,
            "AppDelegate",
            "Lua bootstrap failed (status=%d) while executing require \"scripts/main\"",
            status);
        diagnostics::CrashAndTelemetry::flushLogs();
        pDirector->end();
        teardownSubsystems(LifecycleState::Failed);
        return false;
    }

    // 9. Mark application Ready ONLY after all initialization succeeded, then reconcile any
    //    foreground/background transitions captured during native window creation or boot.
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
        const auto confirmRes = updater.confirmStartupSuccess();
        if (!confirmRes.ok()) {
            diagnostics::CrashAndTelemetry::log(
                diagnostics::LogLevel::Warn,
                "AppDelegate",
                "Hotfix startup confirmation warning: %s",
                confirmRes.message.c_str());
        }
    }
    reconcileInitialWindowLifecycleState(pDirector, pEGLView);
    return true;
}

void AppDelegate::applicationDidEnterBackground() {
    if (m_lifecycleState.load(std::memory_order_acquire) != LifecycleState::Ready) {
        // Defer background state until applicationDidFinishLaunching() completes.
        m_pendingBackground.store(true, std::memory_order_release);
        m_pendingForeground.store(false, std::memory_order_release);
        return;
    }

    if (m_isInBackground.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    if (auto* director = cocos2d::CCDirector::sharedDirector()) {
        director->stopAnimation();
    }
    if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
        audio->pauseBackgroundMusic();
        audio->pauseAllEffects();
    }
    diagnostics::CrashAndTelemetry::flushLogs();
}

void AppDelegate::applicationWillEnterForeground() {
    // Guard against synchronous Win32 WM_SIZE(SIZE_RESTORED) fired inside CCEGLView::setFrameSize
    // BEFORE applicationDidFinishLaunching() has bound the GL context, stats texture, or Lua VM
    // (root cause of 0xC0000094 EXCEPTION_INT_DIVIDE_BY_ZERO in CCLabelAtlas::updateAtlasValues).
    if (m_lifecycleState.load(std::memory_order_acquire) != LifecycleState::Ready) {
        m_pendingForeground.store(true, std::memory_order_release);
        m_pendingBackground.store(false, std::memory_order_release);
        return;
    }

    cocos2d::CCDirector* director = cocos2d::CCDirector::sharedDirector();
    cocos2d::CCEGLView* eglView = cocos2d::CCEGLView::sharedOpenGLView();
    if (!director || isEglViewZeroOrMinimized(eglView)) {
        // Window is still minimized/iconic (0x0 client surface); keep m_isInBackground latched
        // until a non-zero restore/maximize arrives.
        m_pendingForeground.store(true, std::memory_order_release);
        return;
    }

    m_pendingForeground.store(false, std::memory_order_release);
    const cocos2d::CCSize winSz = director->getWinSize();
    if (!std::isfinite(winSz.width) || !std::isfinite(winSz.height) ||
        winSz.width < 1.0f || winSz.height < 1.0f) {
        eglView->setDesignResolutionSize(kDesignWidth, kDesignHeight, kResolutionFixedWidth);
    }

    const bool wasInBackground = m_isInBackground.exchange(false, std::memory_order_acq_rel);
    if (!wasInBackground) {
        return;
    }

    director->startAnimation();
    if (!m_config.muteAudio && !gclient::ui::Win32DesktopBridge::instance().isMuted()) {
        if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
            audio->resumeBackgroundMusic();
            audio->resumeAllEffects();
        }
    }
}

} // namespace gclient
