// ============================================================================
// Game Client Axmol v2.11.5 Port — AppDelegate Implementation
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
#else
#include <unistd.h>
extern char** environ;
#endif

#include "AppDelegate.h"

#include "CCLuaEngine.h"
#include "SimpleAudioEngine.h"
#include "lua-bindings/manual/lua_module_register.h"

#include "assets/BTAssetDecryptor.h"
#include "assets/BtDecryptHook.h"
#include "bindings/BTUtil.h"
#include "bindings/CConfigManager.h"
#include "bindings/LuaBindTemplates.h"
#include "bindings/LuaBindingsRegistry.h"
#include "bindings/LuaHelpers.h"
#include "bindings/LuaHttpAndCrypto.h"
#include "common/KestrelBinaryReader.h"
#include "common/KestrelUtf8.h"
#include "compat/Axmol226Compat.h"
#include "compat/Lua226CompatShim.h"
#include "diagnostics/CrashAndTelemetry.h"
#include "net/CNetwork.h"
#include "platform/BTPlatform.h"
#include "ui/Win32DesktopBridge.h"
#include "ui/ZYWebViewWin32.h"
#include "update/AtomicHotUpdater.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <initializer_list>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <vector>

namespace gclient {

namespace {

namespace fs = std::filesystem;
using gclient::utf8::firstNonEmptyEnv;
using gclient::utf8::fsPathToUtf8;
using gclient::utf8::readEnvBool;
using gclient::utf8::utf8ToFsPath;

std::mutex                g_writableDirMutex;
std::string               g_configuredWritableDir;
std::mutex                g_initialPathsMutex;
std::vector<std::string>  g_initialSearchPathsSnapshot;
std::atomic<bool>         g_validateAssetsOnly{false};
std::atomic<bool>         g_headlessServerMode{false};
std::atomic<AppDelegate*> g_activeAppInstance{nullptr};

constexpr float kDesignWidth             = 1136.0f;
constexpr float kDesignHeight            = 640.0f;
constexpr float kTargetAnimationInterval = 1.0f / 60.0f;

std::string getConfiguredWritableDirSnapshot() {
    std::lock_guard<std::mutex> lock(g_writableDirMutex);
    return g_configuredWritableDir;
}

void setConfiguredWritableDirSnapshot(std::string dir) {
    std::lock_guard<std::mutex> lock(g_writableDirMutex);
    g_configuredWritableDir = std::move(dir);
}

std::vector<std::string> getInitialSearchPathsSnapshot() {
    std::lock_guard<std::mutex> lock(g_initialPathsMutex);
    return g_initialSearchPathsSnapshot;
}

void setInitialSearchPathsSnapshot(std::vector<std::string> paths) {
    std::lock_guard<std::mutex> lock(g_initialPathsMutex);
    g_initialSearchPathsSnapshot = std::move(paths);
}

bool hasBootstrapEnvPrefix(std::string_view key) noexcept {
    return key.starts_with("KESTREL_") || key.starts_with("COBALT_") || key.starts_with("GCLIENT_");
}

bool parsePortValue(const std::string& raw, int& outPort) {
    if (raw.empty()) return false;
    char* endPtr = nullptr;
    const long v = std::strtol(raw.c_str(), &endPtr, 10);
    if (endPtr == raw.c_str() || *endPtr != '\0' || v < 1 || v > 65535) return false;
    outPort = static_cast<int>(v);
    return true;
}

#ifdef _WIN32
void collectEnvSnapshotMap(std::map<std::string, std::string>& outMap) {
    LPWCH block = ::GetEnvironmentStringsW();
    if (!block) return;
    for (LPCWSTR cur = block; *cur != L'\0'; cur += std::wcslen(cur) + 1) {
        if (*cur == L'=') continue;
        const std::string entry = gclient::utf8::wideToUtf8(cur);
        const std::size_t eq = entry.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        const std::string key = entry.substr(0, eq);
        if (hasBootstrapEnvPrefix(key) && outMap.find(key) == outMap.end()) {
            outMap[key] = entry.substr(eq + 1);
        }
    }
    ::FreeEnvironmentStringsW(block);
}
#else
void collectEnvSnapshotMap(std::map<std::string, std::string>& outMap) {
    if (!environ) return;
    for (char** cur = environ; *cur != nullptr; ++cur) {
        const std::string_view entry(*cur);
        const std::size_t eq = entry.find('=');
        if (eq == std::string_view::npos || eq == 0) continue;
        const std::string key(entry.substr(0, eq));
        if (hasBootstrapEnvPrefix(key) && outMap.find(key) == outMap.end()) {
            outMap[key] = std::string(entry.substr(eq + 1));
        }
    }
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
        if (::GetClientRect(hwnd, &rc) && ((rc.right - rc.left) < 1 || (rc.bottom - rc.top) < 1)) {
            return true;
        }
    }
#endif
    const ax::Vec2 frameSz = rv->getFrameSize();
    return frameSz.width < 1.0f || frameSz.height < 1.0f ||
           !std::isfinite(frameSz.width) || !std::isfinite(frameSz.height);
}

bool isHeadlessEnvironmentActive() {
    return g_validateAssetsOnly.load(std::memory_order_acquire) ||
           g_headlessServerMode.load(std::memory_order_acquire) ||
           readEnvBool({
               "KESTREL_HEADLESS", "KESTREL_HEADLESS_SERVER",
               "COBALT_HEADLESS", "COBALT_HEADLESS_SERVER",
               "GCLIENT_HEADLESS", "GCLIENT_SUPPRESS_MESSAGEBOX",
               "CI", "GITHUB_ACTIONS"
           }, false);
}

class AlertDialogGate {
public:
    static constexpr std::size_t kMaxPopupsPerProcess = 3;

    bool shouldDisplayPopup(const std::string& messageText, bool nonInteractive) {
        if (nonInteractive) return false;
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

void maybeShowWin32AlertPopup(const std::string& titleStr, const std::string& msgStr, bool showAlert) {
#ifdef _WIN32
    if (!showAlert) return;
    std::thread([t = titleStr, m = msgStr]() {
        static std::mutex* s_dialogMutex = new std::mutex();
        std::lock_guard<std::mutex> guard(*s_dialogMutex);
        const std::wstring wTitle = gclient::utf8::utf8ToWide(t);
        const std::wstring wMsg   = gclient::utf8::utf8ToWide(m);
        ::MessageBoxW(
            nullptr,
            wMsg.empty() ? L"(error)" : wMsg.c_str(),
            wTitle.empty() ? L"Game Client" : wTitle.c_str(),
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
    }).detach();
#else
    (void)titleStr;
    (void)msgStr;
    (void)showAlert;
#endif
}

std::string toForwardSlash(std::string p) {
    std::replace(p.begin(), p.end(), '\\', '/');
    return p;
}

std::string normalizePosixDirPath(std::string p) {
    p = toForwardSlash(std::move(p));
    while (p.size() > 1 && p.back() == '/') {
        if (p.size() == 3 && p[1] == ':') break;
        p.pop_back();
    }
    return p;
}

update::HotUpdaterConfig makeHotUpdaterConfig(const AppConfig& cfg) {
    update::HotUpdaterConfig hotCfg;
    hotCfg.patchRootDir = utf8ToFsPath(cfg.hotfixDir);
    const std::string& baseStr = !cfg.baseAssetsDir.empty() ? cfg.baseAssetsDir : cfg.resourcesDir;
    if (!baseStr.empty()) hotCfg.baseResourcesDir = utf8ToFsPath(baseStr);
    return hotCfg;
}

std::vector<fs::path> collectOrderedAssetRootPaths(const AppConfig& cfg) {
    std::vector<fs::path> roots;
    std::error_code ec;

    if (!cfg.skipHotupdate) {
        if (!cfg.writableDir.empty()) {
            roots.push_back(utf8ToFsPath(cfg.writableDir) / "Resources");
        }
        if (!cfg.hotfixDir.empty()) {
            update::AtomicHotUpdater updater(makeHotUpdaterConfig(cfg));
            const auto health = updater.initializeAndCheckStartupHealth();
            if (health.hasActiveOverlay && !health.activeOverlayPath.empty()) {
                roots.push_back(health.activeOverlayPath);
            }
            roots.push_back(utf8ToFsPath(cfg.hotfixDir));
        }
    }

    if (!cfg.resourcesDir.empty()) {
        const fs::path primaryRes = utf8ToFsPath(cfg.resourcesDir);
        const fs::path parentDir  = primaryRes.parent_path();
        if (!parentDir.empty() && primaryRes.filename() == "Resources") {
            const fs::path siblingConverted = parentDir / "Resources_Axmol_Converted";
            if (fs::is_directory(siblingConverted, ec)) roots.push_back(siblingConverted);
            ec.clear();
        }
        roots.push_back(primaryRes);
        if (!parentDir.empty() && primaryRes.filename() == "Resources_Axmol_Converted") {
            const fs::path siblingLegacy = parentDir / "Resources";
            if (fs::is_directory(siblingLegacy, ec)) roots.push_back(siblingLegacy);
            ec.clear();
        }
    }

    if (!cfg.baseAssetsDir.empty()) {
        roots.push_back(utf8ToFsPath(cfg.baseAssetsDir));
    }
    return roots;
}

void appendSearchLayer(std::vector<std::string>& searchPaths,
                       std::unordered_set<std::string>& seen,
                       std::string layerRoot) {
    layerRoot = normalizePosixDirPath(std::move(layerRoot));
    if (layerRoot.empty()) return;

    const std::string prefix = (layerRoot.back() == '/') ? layerRoot : (layerRoot + "/");
    for (const std::string& p : {
             layerRoot,
             prefix + "scripts",
             prefix + "res",
             prefix + "database",
             prefix + "res/database",
             prefix + "res/jsonUI"}) {
        if (seen.insert(p).second) searchPaths.push_back(p);
    }
}

void stripUtf8Bom(const char*& code, size_t& codeLen) noexcept {
    if (code && codeLen >= 3 &&
        static_cast<unsigned char>(code[0]) == 0xEF &&
        static_cast<unsigned char>(code[1]) == 0xBB &&
        static_cast<unsigned char>(code[2]) == 0xBF) {
        code += 3;
        codeLen -= 3;
    }
}

// Unified decrypted + BOM-stripped Lua chunk loader used by loadfile, package.loaders, and bootstrap fallback.
int loadDecryptedLuaChunk(lua_State* L,
                          const std::string& primaryRel,
                          const std::string& fallbackRel,
                          const std::string& chunkLabel,
                          bool& outFound) {
    unsigned long sz = 0;
    unsigned char* buf = gclient::assets::LoadAndDecryptFileData(primaryRel, &sz);
    if ((!buf || sz == 0) && !fallbackRel.empty()) {
        delete[] buf;
        buf = gclient::assets::LoadAndDecryptFileData(fallbackRel, &sz);
    }
    if (!buf || sz == 0) {
        delete[] buf;
        outFound = false;
        return LUA_ERRFILE;
    }
    outFound = true;
    const char* code = reinterpret_cast<const char*>(buf);
    size_t codeLen = static_cast<size_t>(sz);
    stripUtf8Bom(code, codeLen);

    const std::string chunkName = "@" + chunkLabel;
    const int status = luaL_loadbuffer(L, code, codeLen, chunkName.c_str());
    delete[] buf;
    return status;
}

int luaLoadDecryptedScriptChunk(lua_State* L) {
    const char* rawPath = luaL_checkstring(L, 1);
    if (!rawPath || !*rawPath) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty script path");
        return 2;
    }

    const std::string candidate = toForwardSlash(rawPath);
    const std::string stripped = candidate.starts_with("scripts/") ? candidate.substr(8) : std::string{};
    bool found = false;
    const int status = loadDecryptedLuaChunk(L, candidate, stripped, candidate, found);
    if (!found) {
        lua_pushnil(L);
        lua_pushfstring(L, "cannot open '%s' via Axmol FileUtils", rawPath);
        return 2;
    }
    if (status != 0) {
        const std::string savedErr = gclient::lua_bind::optString(L, -1, "syntax error");
        lua_pop(L, 1);
        lua_pushnil(L);
        lua_pushlstring(L, savedErr.data(), savedErr.size());
        return 2;
    }
    return 1;
}

int gclientLuaLoader(lua_State* L) {
    std::string modName = luaL_checkstring(L, 1);
    if (modName.ends_with(".lua")) modName.resize(modName.size() - 4);
    std::replace(modName.begin(), modName.end(), '.', '/');
    const std::string relFile = modName + ".lua";
    const std::string scriptsFallback = relFile.starts_with("scripts/") ? std::string{} : ("scripts/" + relFile);

    bool found = false;
    const int loadStatus = loadDecryptedLuaChunk(L, relFile, scriptsFallback, relFile, found);
    if (!found) {
        lua_pushfstring(L, "\n\t[gclientLuaLoader] cannot find '%s'", relFile.c_str());
        return 1;
    }
    return (loadStatus != 0) ? lua_error(L) : 1;
}

void pauseAnimationAndAudio(ax::Director* director) {
    if (director) director->stopAnimation();
    if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
        audio->pauseBackgroundMusic();
        audio->pauseAllEffects();
    }
    diagnostics::CrashAndTelemetry::flushLogs();
}

} // namespace

class AppDelegate::FrameTicker final : public ax::Object {
public:
    void onTick(float dt) {
        AppDelegate* app = AppDelegate::activeInstance();
        if (!app || !app->isReady()) return;

        if (app->m_pendingSoftRestart.exchange(false, std::memory_order_acq_rel)) {
            app->performSoftRestart();
            return;
        }

        if (bt::Platform* platform = bt::Platform::getInstance()) platform->tickLoop();
        if (gclient::net::CNetwork* network = gclient::net::CNetwork::sharedNetwork()) network->update(dt);
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
            const std::string shotName = firstNonEmptyEnv({"KESTREL_SCREENSHOT_NAME", "GCLIENT_SCREENSHOT_NAME"});
            if (shotName.empty()) return;
            auto* director = ax::Director::getInstance();
            auto* rv = director ? dynamic_cast<ax::RenderViewImpl*>(director->getRenderView()) : nullptr;
            if (!director || isRenderViewZeroOrMinimized(rv)) return;
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
                            diagnostics::LogLevel::Info, "AppDelegate", "Saved screenshot %s", shotName.c_str());
                    }
                }
            }
        }
    }
};

AppDelegate* AppDelegate::activeInstance() noexcept {
    return g_activeAppInstance.load(std::memory_order_acquire);
}

bool AppDelegate::hasActiveInstance() noexcept {
    return activeInstance() != nullptr;
}

bool AppDelegate::isLifecycleReady() noexcept {
    AppDelegate* inst = activeInstance();
    return inst != nullptr && inst->isReady();
}

AppDelegate::AppDelegate(const AppConfig& config)
    : m_config(config)
{
    resolveBootstrapEnvironment();
    g_validateAssetsOnly.store(m_config.validateAssetsOnly, std::memory_order_release);
    g_headlessServerMode.store(m_config.headlessServer, std::memory_order_release);
    g_activeAppInstance.store(this, std::memory_order_release);
}

AppDelegate::~AppDelegate() {
    shutdown();
    AppDelegate* expected = this;
    g_activeAppInstance.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
}

void AppDelegate::resolveBootstrapEnvironment() {
    if (m_config.mapiUrl.empty()) {
        m_config.mapiUrl = firstNonEmptyEnv({"KESTREL_MAPI_URL", "COBALT_MAPI_URL", "GCLIENT_MAPI_URL"});
    }
    if (m_config.gameHost.empty()) {
        m_config.gameHost = firstNonEmptyEnv({"KESTREL_GAME_HOST", "COBALT_GAME_HOST", "GCLIENT_GAME_HOST"});
    }
    if (m_config.gamePort <= 0) {
        parsePortValue(firstNonEmptyEnv({"KESTREL_GAME_PORT", "COBALT_GAME_PORT", "GCLIENT_GAME_PORT"}),
                       m_config.gamePort);
    }
    if (m_config.pid.empty()) {
        m_config.pid = firstNonEmptyEnv({"KESTREL_PID", "COBALT_PID", "GCLIENT_PID"});
    }
    if (m_config.sessionToken.empty()) {
        m_config.sessionToken = firstNonEmptyEnv({"KESTREL_TOKEN", "COBALT_TOKEN", "GCLIENT_TOKEN"});
    }
    if (m_config.entryScript.empty()) {
        m_config.entryScript = firstNonEmptyEnv({"KESTREL_ENTRY_SCRIPT", "COBALT_ENTRY_SCRIPT", "GCLIENT_ENTRY_SCRIPT"});
    }
    if (!m_config.skipHotupdate) {
        m_config.skipHotupdate = readEnvBool(
            {"KESTREL_SKIP_HOTUPDATE", "COBALT_SKIP_HOTUPDATE", "GCLIENT_SKIP_HOTUPDATE"}, false);
    }
    if (!m_config.headlessServer) {
        m_config.headlessServer = readEnvBool(
            {"KESTREL_HEADLESS_SERVER", "COBALT_HEADLESS_SERVER", "GCLIENT_HEADLESS_SERVER"}, false);
    }
    collectEnvSnapshotMap(m_config.bootstrapEnv);
}

std::string AppDelegate::resolveEntryScriptRelativePath() const {
    if (!m_config.entryScript.empty()) return toForwardSlash(m_config.entryScript);
    return m_config.headlessServer ? "scripts/main_server.lua" : "scripts/main.lua";
}

void AppDelegate::initGfxContextAttrs() {
    GfxContextAttrs gfxContextAttrs = {8, 8, 8, 8, 24, 8, 0};
    ax::RenderView::setGfxContextAttrs(gfxContextAttrs);
}

void AppDelegate::applicationWillQuit() {
    shutdown();
}

void AppDelegate::restartGame() {
    m_pendingSoftRestart.store(true, std::memory_order_release);
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info, "AppDelegate", "Soft restart scheduled via AppDelegate::restartGame()");
}

bool AppDelegate::executeHeadlessAssetValidation() {
    LifecycleState expectedState = LifecycleState::Uninitialized;
    if (!m_lifecycleState.compare_exchange_strong(
            expectedState, LifecycleState::Initializing, std::memory_order_acq_rel)) {
        return m_assetValidationOk;
    }

    const std::string targetEntry = resolveEntryScriptRelativePath();
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AssetValidation",
        "Running headless --validate-assets check for '%s' against '%s' (skipHotupdate=%d)",
        targetEntry.c_str(), m_config.resourcesDir.c_str(), m_config.skipHotupdate ? 1 : 0);

    std::error_code ec;
    if (!m_config.writableDir.empty()) {
        fs::create_directories(utf8ToFsPath(m_config.writableDir), ec);
    }

    const fs::path relTargetFs = utf8ToFsPath(targetEntry);
    const fs::path baseNameFs  = relTargetFs.filename();
    fs::path resolvedScriptFs;
    for (const fs::path& root : collectOrderedAssetRootPaths(m_config)) {
        if (root.empty()) continue;
        ec.clear();
        if (const fs::path cand1 = root / relTargetFs; fs::is_regular_file(cand1, ec)) {
            resolvedScriptFs = cand1;
            break;
        }
        ec.clear();
        if (!baseNameFs.empty()) {
            if (const fs::path cand2 = root / baseNameFs; fs::is_regular_file(cand2, ec)) {
                resolvedScriptFs = cand2;
                break;
            }
        }
    }

    if (resolvedScriptFs.empty()) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AssetValidation",
            "Missing entry script '%s' under resources dir '%s'",
            targetEntry.c_str(), m_config.resourcesDir.c_str());
        diagnostics::CrashAndTelemetry::flushLogs();
        m_assetValidationOk = false;
        m_lifecycleState.store(LifecycleState::Failed, std::memory_order_release);
        return false;
    }

    const std::string resolvedUtf8 = fsPathToUtf8(resolvedScriptFs);
    unsigned long dataSize = 0;
    unsigned char* data = gclient::assets::LoadAndDecryptFileData(resolvedUtf8, &dataSize);
    const bool ok = (data != nullptr && dataSize > 0);
    delete[] data;

    if (!ok) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error, "AssetValidation", "Failed to read or decrypt '%s'", resolvedUtf8.c_str());
        diagnostics::CrashAndTelemetry::flushLogs();
        m_assetValidationOk = false;
        m_lifecycleState.store(LifecycleState::Failed, std::memory_order_release);
        return false;
    }

    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AssetValidation",
        "Validated '%s' (%lu bytes loaded successfully)",
        resolvedUtf8.c_str(), dataSize);
    diagnostics::CrashAndTelemetry::flushLogs();
    m_assetValidationOk = true;
    m_lifecycleState.store(LifecycleState::Terminated, std::memory_order_release);
    return true;
}

bool AppDelegate::executeHeadlessServer() {
    LifecycleState expectedState = LifecycleState::Uninitialized;
    if (!m_lifecycleState.compare_exchange_strong(
            expectedState, LifecycleState::Initializing, std::memory_order_acq_rel)) {
        return expectedState == LifecycleState::Ready;
    }

    g_headlessServerMode.store(true, std::memory_order_release);
    configureFileUtils();

    ax::LuaEngine* engine = ax::LuaEngine::getInstance();
    if (!engine || !engine->getLuaStack() || !engine->getLuaStack()->getLuaState()) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Fatal, "HeadlessServer", "Failed to initialize ax::LuaEngine in --headless-server mode");
        diagnostics::CrashAndTelemetry::flushLogs();
        teardownSubsystems(LifecycleState::Failed);
        return false;
    }
    ax::ScriptEngineManager::getInstance()->setScriptEngine(engine);

    lua_State* L = engine->getLuaStack()->getLuaState();
    diagnostics::CrashAndTelemetry::installLuaHooks(L);
    registerLuaBindings(L);

    const std::string entryScript = resolveEntryScriptRelativePath();
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info, "HeadlessServer", "Booting headless Lua VM entry script '%s'", entryScript.c_str());

    const int status = executeBootstrapScript(engine, entryScript);
    if (status != 0) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Fatal,
            "HeadlessServer",
            "Headless bootstrap script '%s' failed with status=%d",
            entryScript.c_str(), status);
        diagnostics::CrashAndTelemetry::flushLogs();
        teardownSubsystems(LifecycleState::Failed);
        return false;
    }

    m_lifecycleState.store(LifecycleState::Ready, std::memory_order_release);

    constexpr float kHeadlessStepSec = 1.0f / 60.0f;
    while (m_lifecycleState.load(std::memory_order_acquire) == LifecycleState::Ready) {
        if (m_pendingSoftRestart.exchange(false, std::memory_order_acq_rel)) {
            performSoftRestart();
            if (m_lifecycleState.load(std::memory_order_acquire) != LifecycleState::Ready) {
                const bool failed = (m_lifecycleState.load(std::memory_order_acquire) == LifecycleState::Failed);
                teardownSubsystems(failed ? LifecycleState::Failed : LifecycleState::Terminated);
                return !failed;
            }
        }

        lua_getglobal(L, "__KESTREL_SERVER_KEEPALIVE__");
        const bool keepAlive = lua_toboolean(L, -1) != 0;
        lua_pop(L, 1);

        lua_getglobal(L, "__KESTREL_SERVER_TICK__");
        const bool hasTickFn = lua_isfunction(L, -1);
        if (!keepAlive && !hasTickFn) {
            lua_pop(L, 1);
            break;
        }

        if (bt::Platform* platform = bt::Platform::getInstance()) platform->tickLoop();
        if (gclient::net::CNetwork* network = gclient::net::CNetwork::sharedNetwork()) network->update(kHeadlessStepSec);
        if (CTimer* timer = CTimer::sharedTimer()) timer->update(kHeadlessStepSec);

        if (hasTickFn) {
            lua_pushnumber(L, static_cast<lua_Number>(kHeadlessStepSec));
            if (lua_pcall(L, 1, 1, 0) != 0) {
                const char* err = lua_tostring(L, -1);
                diagnostics::CrashAndTelemetry::log(
                    diagnostics::LogLevel::Error, "HeadlessServer", "__KESTREL_SERVER_TICK__ error: %s", err ? err : "(null)");
                lua_pop(L, 1);
                teardownSubsystems(LifecycleState::Failed);
                return false;
            }
            const bool continueTick = lua_isnil(L, -1) ? keepAlive : (lua_toboolean(L, -1) != 0);
            lua_pop(L, 1);
            if (!continueTick) break;
        } else {
            lua_pop(L, 1);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }

    lua_settop(L, 0);
    diagnostics::CrashAndTelemetry::flushLogs();
    teardownSubsystems(LifecycleState::Terminated);
    return true;
}

void AppDelegate::shutdown() {
    teardownSubsystems(LifecycleState::Terminated);
}

void AppDelegate::teardownSubsystems(LifecycleState terminalState) {
    const LifecycleState cur = m_lifecycleState.load(std::memory_order_acquire);
    if (cur == LifecycleState::Terminated || cur == LifecycleState::ShuttingDown ||
        cur == LifecycleState::Failed || cur == LifecycleState::Uninitialized) {
        if (terminalState == LifecycleState::Terminated || cur == LifecycleState::Uninitialized) {
            m_lifecycleState.store(terminalState, std::memory_order_release);
        }
        return;
    }
    m_lifecycleState.store(LifecycleState::ShuttingDown, std::memory_order_release);
    m_pendingSoftRestart.store(false, std::memory_order_release);

#ifdef _WIN32
    gclient::ui::Win32DesktopBridge::instance().detach();
#endif
    if (auto* webView = gclient::ui::ZYWebViewWin32::getInstance()) webView->shutdown();

    unscheduleNativeLoops();
    if (auto* net = gclient::net::CNetwork::peekSharedNetwork()) net->resetForRestart(false);
    ResetLuaHelpersForSoftRestart(true);

    if (bt::Platform* platform = bt::Platform::getInstance()) {
        platform->setWebViewBridgeHandler(nullptr);
        platform->setLogHandler(nullptr);
    }

    gclient::bindings::shutdownLuaHttpClient();
    gclient::net::CNetwork::destroySharedNetwork();
    if (auto* cfgMgr = CConfigurationManager::sharedConfigurationManager(false)) cfgMgr->closeAllDbs();

    clearTelemetryLuaStateBeforeTeardown();
    ax::ScriptEngineManager::destroyInstance();
    CocosDenshion::SimpleAudioEngine::end();

    m_lifecycleState.store(terminalState, std::memory_order_release);
}

void AppDelegate::configureFileUtils() {
    ax::FileUtils* fileUtils = ax::FileUtils::getInstance();
    if (m_config.validateAssetsOnly || m_config.headlessServer || isHeadlessEnvironmentActive()) {
        fileUtils->setPopupNotify(false);
    }

    if (!m_config.writableDir.empty()) {
        std::error_code ec;
        fs::create_directories(utf8ToFsPath(m_config.writableDir), ec);
        std::string writableSlash = toForwardSlash(m_config.writableDir);
        if (!writableSlash.empty() && writableSlash.back() != '/') writableSlash.push_back('/');
        setConfiguredWritableDirSnapshot(writableSlash);
        fileUtils->setWritablePath(writableSlash);
#ifdef _WIN32
        ::SetEnvironmentVariableW(L"GCLIENT_WRITABLE_DIR", gclient::utf8::utf8ToWide(writableSlash).c_str());
#endif
    }

    if (m_config.skipHotupdate) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Info,
            "AppDelegate",
            "skipHotupdate=true: bypassing writable/Resources and hotfix search-path overlays");
    }

#ifdef _WIN32
    if (!m_config.resourcesDir.empty()) {
        ::SetEnvironmentVariableW(
            L"GCLIENT_RESOURCES_DIR", gclient::utf8::utf8ToWide(toForwardSlash(m_config.resourcesDir)).c_str());
    }
    if (!m_config.baseAssetsDir.empty()) {
        ::SetEnvironmentVariableW(
            L"GCLIENT_BASE_ASSETS_DIR", gclient::utf8::utf8ToWide(toForwardSlash(m_config.baseAssetsDir)).c_str());
    }
#endif

    std::vector<std::string> searchPaths;
    std::unordered_set<std::string> seenPaths;
    for (const fs::path& root : collectOrderedAssetRootPaths(m_config)) {
        appendSearchLayer(searchPaths, seenPaths, fsPathToUtf8(root));
    }

    if (const std::string appRoot = toForwardSlash(fileUtils->getAppRoot()); !appRoot.empty()) {
        const std::string axslcPath = (appRoot.back() == '/') ? (appRoot + "axslc") : (appRoot + "/axslc");
        if (seenPaths.insert(axslcPath).second) searchPaths.push_back(axslcPath);
        if (seenPaths.insert(appRoot).second) searchPaths.push_back(appRoot);
    }

    m_initialSearchPaths = searchPaths;
    setInitialSearchPathsSnapshot(searchPaths);
    fileUtils->setSearchPaths(searchPaths);
    fileUtils->purgeCachedEntries();

    if (bt::Platform* platform = bt::Platform::getInstance()) {
        if (!m_config.baseAssetsDir.empty()) platform->setResourceRoot(toForwardSlash(m_config.baseAssetsDir));
        else if (!m_config.resourcesDir.empty()) platform->setResourceRoot(toForwardSlash(m_config.resourcesDir));

        platform->setLogHandler([](const std::string& level, const std::string& message) {
            const auto lvl = (level == "error") ? diagnostics::LogLevel::Error : diagnostics::LogLevel::Info;
            diagnostics::CrashAndTelemetry::log(lvl, "bt::Platform", "%s", message.c_str());
        });
        platform->setWebViewBridgeHandler(
            [](const std::string& action, int x, int y, int width, int height, const std::string& url) {
                if (!AppDelegate::isLifecycleReady()) return;
                auto* webView = gclient::ui::ZYWebViewWin32::getInstance();
                if (!webView) return;
                if (action == "displayWebView") webView->displayWebView(x, y, width, height);
                else if (action == "updateURL") webView->updateURL(url);
                else if (action == "removeWebView") webView->removeWebView();
            });
    }

    gclient::assets::InstallBtDecryptHook(fileUtils);
}

void AppDelegate::installKestrelBootstrapTable(lua_State* L) {
    if (!L) return;
    const int topBefore = lua_gettop(L);

    lua_newtable(L);
    const int backingIdx = lua_gettop(L);

    auto setDual = [&](const char* snakeKey, const char* camelKey, const auto& val) {
        using V = std::remove_cvref_t<decltype(val)>;
        if constexpr (std::same_as<V, std::string>) {
            if (val.empty()) return;
        }
        gclient::lua_bind::pushFlexReturn(L, val);
        lua_setfield(L, backingIdx, snakeKey);
        if (camelKey && std::strcmp(snakeKey, camelKey) != 0) {
            gclient::lua_bind::pushFlexReturn(L, val);
            lua_setfield(L, backingIdx, camelKey);
        }
    };

    lua_pushliteral(L, "2.11.5-axmol-x64"); lua_setfield(L, backingIdx, "version");
    lua_pushliteral(L, "axmol");            lua_setfield(L, backingIdx, "engine");
    lua_pushliteral(L, "x64");              lua_setfield(L, backingIdx, "arch");

    setDual("mapi_url", "mapiUrl", m_config.mapiUrl);
    setDual("game_host", "gameHost", m_config.gameHost);
    if (m_config.gamePort > 0) setDual("game_port", "gamePort", static_cast<lua_Integer>(m_config.gamePort));
    setDual("pid", "pid", m_config.pid);
    setDual("session_token", "sessionToken", m_config.sessionToken);
    if (!m_config.sessionToken.empty()) {
        lua_pushlstring(L, m_config.sessionToken.data(), m_config.sessionToken.size());
        lua_setfield(L, backingIdx, "token");
    }

    setDual("skip_hotupdate", "skipHotupdate", m_config.skipHotupdate);
    setDual("headless_server", "headlessServer", m_config.headlessServer);
    setDual("headless", "headless",
            m_config.headlessServer || m_config.validateAssetsOnly || isHeadlessEnvironmentActive());
    setDual("mute_audio", "muteAudio", m_config.muteAudio);
    setDual("validate_assets", "validateAssetsOnly", m_config.validateAssetsOnly);
    setDual("has_overrides", "hasOverrides",
            !m_config.mapiUrl.empty() || !m_config.gameHost.empty() || m_config.gamePort > 0 ||
            !m_config.pid.empty() || m_config.skipHotupdate || m_config.headlessServer);

    setDual("entry_script", "entryScript", resolveEntryScriptRelativePath());
    setDual("resources_dir", "resourcesDir", normalizePosixDirPath(m_config.resourcesDir));
    setDual("base_assets_dir", "baseAssetsDir", normalizePosixDirPath(m_config.baseAssetsDir));
    setDual("profile_dir", "profileDir", normalizePosixDirPath(m_config.profileDir));
    setDual("writable_dir", "writableDir", normalizePosixDirPath(m_config.writableDir));
    setDual("hotfix_dir", "hotfixDir", normalizePosixDirPath(m_config.hotfixDir));
    setDual("logs_dir", "logsDir", normalizePosixDirPath(m_config.logsDir));

    setDual("window_width", "windowWidth", static_cast<lua_Integer>(m_config.windowWidth));
    setDual("window_height", "windowHeight", static_cast<lua_Integer>(m_config.windowHeight));
    setDual("restart_count", "restartCount",
            static_cast<lua_Integer>(m_restartCount.load(std::memory_order_acquire)));

    lua_newtable(L);
    const int envBackingIdx = lua_gettop(L);
    for (const auto& [k, v] : m_config.bootstrapEnv) {
        if (!k.empty() && hasBootstrapEnvPrefix(k)) {
            lua_pushlstring(L, v.data(), v.size());
            lua_setfield(L, envBackingIdx, k.c_str());
        }
    }
    lua_setfield(L, backingIdx, "env");

    lua_getfield(L, LUA_REGISTRYINDEX, "__kestrel_ro_backing_map");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_newtable(L);
        lua_pushliteral(L, "k");
        lua_setfield(L, -2, "__mode");
        lua_setmetatable(L, -2);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, "__kestrel_ro_backing_map");
    }
    const int roMapIdx = lua_gettop(L);

    static constexpr const char* kFreezeBootstrapLua = R"LUA(
        local rootBacking, _roMap = ...
        if not rawget(_roMap, "__pairs_installed") then
          rawset(_roMap, "__pairs_installed", true)
          local _origPairs = pairs
          pairs = function(t)
            local inner = _roMap[t]
            if inner ~= nil then return next, inner, nil end
            return _origPairs(t)
          end
        end

        local function freezeTable(tbl, label)
          for k, v in next, tbl, nil do
            if type(v) == "table" and _roMap[v] == nil then
              rawset(tbl, k, freezeTable(v, label .. "." .. tostring(k)))
            end
          end
          local proxy = {}
          _roMap[proxy] = tbl
          setmetatable(proxy, {
            __index = tbl,
            __newindex = function(_, k, _)
              error("attempt to modify read-only bootstrap table " .. label .. " (key '" .. tostring(k) .. "')", 2)
            end,
            __pairs = function() return next, tbl, nil end,
            __metatable = "__KESTREL_BOOTSTRAP_READONLY__",
          })
          return proxy
        end

        rawset(_G, "__KESTREL_BOOTSTRAP__", freezeTable(rootBacking, "_G.__KESTREL_BOOTSTRAP__"))
    )LUA";

    if (luaL_loadbuffer(L, kFreezeBootstrapLua, std::strlen(kFreezeBootstrapLua), "@KestrelBootstrapFreeze") == 0) {
        lua_pushvalue(L, backingIdx);
        lua_pushvalue(L, roMapIdx);
        if (lua_pcall(L, 2, 0, 0) != 0) {
            diagnostics::CrashAndTelemetry::log(
                diagnostics::LogLevel::Error,
                "AppDelegate",
                "Failed to freeze _G.__KESTREL_BOOTSTRAP__: %s",
                gclient::lua_bind::optCString(L, -1, "(null)"));
            lua_pop(L, 1);
        }
    } else {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AppDelegate",
            "Failed to compile _G.__KESTREL_BOOTSTRAP__ freeze chunk: %s",
            gclient::lua_bind::optCString(L, -1, "(null)"));
        lua_pop(L, 1);
    }

    lua_settop(L, topBefore);
}

void AppDelegate::registerLuaBindings(lua_State* L) {
    lua_module_register(L);

    gclient::compat::RegisterAxmol226CompatLuaBindings(L);
    gclient::compat::InstallLua226CompatShim(L);

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

    auto setGlobalFn = [&](const char* name, lua_CFunction fn) {
        lua_pushcfunction(L, fn);
        lua_setglobal(L, name);
    };

    setGlobalFn("__GCLIENT_LOG_ERR__", [](lua_State* s) -> int {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error, "LuaErr", "%s", gclient::lua_bind::optCString(s, 1, "(null)"));
        diagnostics::CrashAndTelemetry::flushLogs();
        return 0;
    });

    setGlobalFn("__GCLIENT_LOG_INFO__", [](lua_State* s) -> int {
        const int nargs = lua_gettop(s);
        std::string out;
        lua_getglobal(s, "tostring");
        const bool hasToString = lua_isfunction(s, -1);
        for (int i = 1; i <= nargs; ++i) {
            if (i > 1) out.push_back('\t');
            if (hasToString) {
                lua_pushvalue(s, -1);
                lua_pushvalue(s, i);
                if (lua_pcall(s, 1, 1, 0) == 0) {
                    const char* txt = lua_tostring(s, -1);
                    out.append(txt ? txt : "nil");
                } else {
                    out.append("<tostring-err>");
                }
                lua_pop(s, 1);
            } else {
                const char* txt = lua_tostring(s, i);
                out.append(txt ? txt : "nil");
            }
        }
        lua_pop(s, 1);
        diagnostics::CrashAndTelemetry::log(diagnostics::LogLevel::Info, "Lua", "%s", out.c_str());
        return 0;
    });

    setGlobalFn("__GCLIENT_LOAD_SCRIPT_CHUNK__", &luaLoadDecryptedScriptChunk);
    setGlobalFn("__KESTREL_PREPARE_RESTART__", [](lua_State*) -> int {
        ResetLuaHelpersForSoftRestart(false);
        return 0;
    });

    const lua_CFunction requestRestartFn = [](lua_State*) -> int {
        if (AppDelegate* app = AppDelegate::activeInstance()) app->restartGame();
        return 0;
    };
    setGlobalFn("__KESTREL_RESTART_GAME__", requestRestartFn);
    setGlobalFn("restartGame", requestRestartFn);

    static constexpr const char* kLuaBootstrapShim = R"LUA(
        do
          local _r = require
          require = function(n)
            local res = _r(n)
            if (n == "config.Config" or n == "config/Config") and type(res) == "table" and res.currentOS == nil then
              res.currentOS = "android"
            end
            return res
          end
          if type(io) == "table" and type(io.open) == "function" then
            local _io_open = io.open
            io.open = function(path, mode)
              if mode == nil then mode = "rb"
              elseif type(mode) == "string" and not mode:find("b", 1, true) then mode = mode .. "b" end
              return _io_open(path, mode)
            end
          end
          local _origLoadfile = loadfile
          loadfile = function(filename, ...)
            if type(filename) == "string" and type(_G.__GCLIENT_LOAD_SCRIPT_CHUNK__) == "function" then
              local fn, err = _G.__GCLIENT_LOAD_SCRIPT_CHUNK__(filename)
              if type(fn) == "function" then return fn end
              if _origLoadfile then
                local f2, e2 = _origLoadfile(filename, ...)
                if type(f2) == "function" then return f2 end
              end
              return nil, err
            end
            return _origLoadfile(filename, ...)
          end
          local _origDofile = dofile
          dofile = function(filename)
            if type(filename) == "string" then
              local fn, err = loadfile(filename)
              if not fn then error(err, 2) end
              return fn()
            end
            return _origDofile(filename)
          end
        end
    )LUA";

    if (luaL_dostring(L, kLuaBootstrapShim) != 0) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AppDelegate",
            "Bootstrap shim error: %s",
            gclient::lua_bind::optCString(L, -1, "(null)"));
        lua_pop(L, 1);
    }

    g_validateAssetsOnly.store(m_config.validateAssetsOnly, std::memory_order_release);
    g_headlessServerMode.store(m_config.headlessServer, std::memory_order_release);

    setGlobalFn("CCMessageBox", [](lua_State* s) -> int {
        const char* msg = lua_tostring(s, 1);
        const char* title = lua_tostring(s, 2);
        const std::string msgStr = msg ? msg : "(null)";
        const std::string titleStr = (title && title[0] != '\0') ? title : "Game Client";

        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error, "CCMessageBox", "[%s] %s", titleStr.c_str(), msgStr.c_str());
        diagnostics::CrashAndTelemetry::flushLogs();

        const bool showAlert = sharedAlertDialogGate().shouldDisplayPopup(
            titleStr + "\n" + msgStr, isHeadlessEnvironmentActive());
        maybeShowWin32AlertPopup(titleStr, msgStr, showAlert);
        return 0;
    });

    luaL_getmetatable(L, "ax.FileUtils");
    if (lua_istable(L, -1)) {
        static constexpr luaL_Reg kFileUtilsOverrides[] = {
            {"removeSearchPath", [](lua_State* s) -> int {
                auto* self = ax::FileUtils::getInstance();
                const char* target = lua_tostring(s, 2);
                if (self && target) {
                    const std::string targetStr = toForwardSlash(target);
                    auto paths = self->getSearchPaths();
                    paths.erase(
                        std::remove_if(paths.begin(), paths.end(), [&](const std::string& raw) {
                            const std::string p = toForwardSlash(raw);
                            return p == targetStr || (!targetStr.empty() && p == targetStr + "/");
                        }),
                        paths.end());
                    self->setSearchPaths(paths);
                    self->purgeCachedEntries();
                }
                return 0;
            }},
            {"removeAllPaths", [](lua_State*) -> int {
                if (auto* self = ax::FileUtils::getInstance()) {
                    self->setSearchPaths(getInitialSearchPathsSnapshot());
                    self->purgeCachedEntries();
                }
                return 0;
            }},
            {"purgeCachedEntries", [](lua_State*) -> int {
                if (auto* self = ax::FileUtils::getInstance()) self->purgeCachedEntries();
                return 0;
            }},
            {"getWritablePath", [](lua_State* s) -> int {
                if (const std::string configured = getConfiguredWritableDirSnapshot(); !configured.empty()) {
                    lua_pushlstring(s, configured.data(), configured.size());
                    return 1;
                }
                std::string p = toForwardSlash(ax::FileUtils::getInstance()->getWritablePath());
                if (!p.empty() && p.back() != '/') p.push_back('/');
                lua_pushlstring(s, p.data(), p.size());
                return 1;
            }},
        };
        gclient::lua_bind::registerMethodTable(L, -1, kFileUtilsOverrides);

        lua_getfield(L, -1, "fullPathForFilename");
        if (lua_isfunction(L, -1)) {
            lua_pushcclosure(L, [](lua_State* s) -> int {
                auto* self = ax::FileUtils::getInstance();
                const char* rel = lua_tostring(s, 2);
                if (self && rel && rel[0] != '\0') {
                    for (const auto& base : self->getSearchPaths()) {
                        if (base.empty()) continue;
                        std::string cand = base;
                        if (cand.back() != '/' && cand.back() != '\\') cand.push_back('/');
                        cand += rel;
                        std::error_code ec;
                        if (fs::is_directory(utf8ToFsPath(cand), ec)) {
                            cand = toForwardSlash(std::move(cand));
                            lua_pushlstring(s, cand.data(), cand.size());
                            return 1;
                        }
                    }
                }
                lua_pushvalue(s, lua_upvalueindex(1));
                lua_pushvalue(s, 1);
                lua_pushvalue(s, 2);
                lua_call(s, 2, 1);
                return 1;
            }, 1);
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

    installKestrelBootstrapTable(L);
}

int AppDelegate::executeBootstrapScript(ax::LuaEngine* engine, const std::string& scriptPath) {
    if (!engine || !engine->getLuaStack() || !engine->getLuaStack()->getLuaState()) return -1;

    lua_State* L = engine->getLuaStack()->getLuaState();
    engine->getLuaStack()->clean();
    lua_settop(L, 0);
    installKestrelBootstrapTable(L);

    std::string target = toForwardSlash(scriptPath);
    auto* fu = ax::FileUtils::getInstance();
    std::string resolvedFull = fu ? fu->fullPathForFilename(target) : std::string();
    if (resolvedFull.empty() && target.starts_with("scripts/") && fu) {
        const std::string fallbackShort = target.substr(8);
        resolvedFull = fu->fullPathForFilename(fallbackShort);
        if (!resolvedFull.empty()) target = fallbackShort;
    }

    bool requiresCustomBufferLoad = !(fu && !resolvedFull.empty());
    if (!requiresCustomBufferLoad) {
        const bool prevPopup = fu->isPopupNotify();
        fu->setPopupNotify(false);
        ax::Data rawProbe = fu->getDataFromFile(resolvedFull);
        fu->setPopupNotify(prevPopup);
        if (!rawProbe.isNull() && rawProbe.getSize() >= 3) {
            const uint8_t* b = rawProbe.getBytes();
            if (gclient::assets::IsBtEncryptedBuffer(b, static_cast<size_t>(rawProbe.getSize())) ||
                (b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF)) {
                requiresCustomBufferLoad = true;
            }
        }
    }

    int status = 0;
    if (!requiresCustomBufferLoad) {
        status = engine->executeScriptFile(target.c_str());
    } else {
        lua_getglobal(L, "__G__TRACKBACK__");
        const int errFuncIdx = lua_isfunction(L, -1) ? lua_gettop(L) : 0;
        if (errFuncIdx == 0) lua_pop(L, 1);

        bool found = false;
        status = loadDecryptedLuaChunk(L, target, {}, target, found);
        if (!found) {
            diagnostics::CrashAndTelemetry::log(
                diagnostics::LogLevel::Error, "AppDelegate", "Cannot locate or decrypt entry script '%s'", target.c_str());
            lua_settop(L, 0);
            return 1;
        }
        if (status == 0) status = lua_pcall(L, 0, 0, errFuncIdx);
        if (status != 0) {
            diagnostics::CrashAndTelemetry::log(
                diagnostics::LogLevel::Error,
                "AppDelegate",
                "Lua error in '%s': %s",
                target.c_str(),
                gclient::lua_bind::optCString(L, -1, "(null)"));
        }
    }

    engine->getLuaStack()->clean();
    lua_settop(L, 0);
    return status;
}

void AppDelegate::performSoftRestart() {
    const uint32_t restartNum = m_restartCount.fetch_add(1, std::memory_order_acq_rel) + 1;
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info,
        "AppDelegate",
        "Executing soft restart #%u (skipHotupdate=%d)",
        restartNum, m_config.skipHotupdate ? 1 : 0);

    if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
        audio->stopAllEffects();
        audio->stopBackgroundMusic(true);
    }
    if (auto* webView = gclient::ui::ZYWebViewWin32::getInstance()) webView->removeWebView();

    gclient::net::CNetwork::destroySharedNetwork();
    if (auto* cfgMgr = CConfigurationManager::sharedConfigurationManager(false)) cfgMgr->closeAllDbs();

    ResetLuaHelpersForSoftRestart(true);

    if (!m_config.headlessServer) {
        if (ax::Director* director = ax::Director::getInstance(); director && director->getRunningScene()) {
            director->replaceScene(ax::Scene::create());
        }
    }

    configureFileUtils();
    if (!m_config.headlessServer) scheduleNativeLoops();

    ax::LuaEngine* engine = ax::LuaEngine::getInstance();
    if (!engine || !engine->getLuaStack() || !engine->getLuaStack()->getLuaState()) {
        m_lifecycleState.store(LifecycleState::Failed, std::memory_order_release);
        return;
    }

    lua_State* L = engine->getLuaStack()->getLuaState();
    engine->getLuaStack()->clean();
    lua_settop(L, 0);

    static constexpr const char* kLuaResetSessionChunk = R"LUA(
        do
          if CCNotificationCenter and type(CCNotificationCenter.sharedNotificationCenter) == "function" then
            CCNotificationCenter:sharedNotificationCenter():purgeNotificationCenter()
          end
          local keep = {
            ["_G"] = true, ["package"] = true, ["coroutine"] = true, ["table"] = true,
            ["io"] = true, ["os"] = true, ["string"] = true, ["math"] = true,
            ["debug"] = true, ["bit"] = true, ["jit"] = true, ["ffi"] = true,
            ["jit.opt"] = true, ["jit.util"] = true, ["cjson"] = true, ["cjson.safe"] = true,
            ["amf3"] = true, ["socket.core"] = true, ["mime.core"] = true,
          }
          if type(package) == "table" and type(package.loaded) == "table" then
            local toRemove = {}
            for k, _ in pairs(package.loaded) do
              if type(k) == "string" and not keep[k] then toRemove[#toRemove + 1] = k end
            end
            for i = 1, #toRemove do package.loaded[toRemove[i]] = nil end
          end
          rawset(_G, "g", nil)
          rawset(_G, "__KESTREL_SERVER_KEEPALIVE__", nil)
          rawset(_G, "__KESTREL_SERVER_TICK__", nil)
        end
    )LUA";

    if (luaL_dostring(L, kLuaResetSessionChunk) != 0) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AppDelegate",
            "Lua session reset script error: %s",
            gclient::lua_bind::optCString(L, -1, "(null)"));
        lua_pop(L, 1);
    }

    lua_gc(L, LUA_GCCOLLECT, 0);
    lua_settop(L, 0);

    const std::string entryScript = resolveEntryScriptRelativePath();
    const int status = executeBootstrapScript(engine, entryScript);
    if (status != 0) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AppDelegate",
            "Soft restart #%u failed while executing '%s' (status=%d)",
            restartNum, entryScript.c_str(), status);
        diagnostics::CrashAndTelemetry::flushLogs();
        if (m_config.headlessServer) {
            m_lifecycleState.store(LifecycleState::Failed, std::memory_order_release);
        }
    }
}

void AppDelegate::scheduleNativeLoops() {
    if (m_ticker == nullptr) m_ticker = new FrameTicker();

    auto bindNativeSchedulers = [this]() {
        if (m_ticker == nullptr) return;
        if (ax::Director* director = ax::Director::getInstance()) {
            if (ax::Scheduler* scheduler = director->getScheduler()) {
                scheduler->unschedule(AX_SCHEDULE_SELECTOR(FrameTicker::onTick), m_ticker);
                scheduler->schedule(AX_SCHEDULE_SELECTOR(FrameTicker::onTick), m_ticker, 0.0f, false);
                if (CTimer* timer = CTimer::sharedTimer()) {
                    scheduler->unscheduleAllForTarget(timer);
                    scheduler->scheduleUpdate(timer, 0, false);
                }
            }
        }
        gclient_rescheduleHttpClientCallbacks();
        RescheduleLuaHelpersCallbacks();
    };

    bindNativeSchedulers();
    BTUtil::setPostUnscheduleAllHook([bindNativeSchedulers]() {
        ResetLuaHelpersForSoftRestart(false);
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
    ax::FileUtils* fileUtils = ax::FileUtils::getInstance();
    const std::string entryRel = resolveEntryScriptRelativePath();
    const std::string mainScriptPath = fileUtils->fullPathForFilename(entryRel);

    std::error_code ec;
    if (mainScriptPath.empty() || !fs::exists(utf8ToFsPath(mainScriptPath), ec)) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Error,
            "AssetValidation",
            "Missing entry script '%s' under resources dir '%s'",
            entryRel.c_str(), m_config.resourcesDir.c_str());
        return false;
    }

    unsigned long dataSize = 0;
    unsigned char* data = gclient::assets::LoadAndDecryptFileData(mainScriptPath, &dataSize);
    const bool ok = (data != nullptr && dataSize > 0);
    delete[] data;
    return ok;
}

void AppDelegate::reconcileInitialWindowLifecycleState(ax::Director* director,
                                                       ax::RenderViewImpl* renderView) {
    const bool earlyBg = m_pendingBackground.exchange(false, std::memory_order_acq_rel);
    (void)m_pendingForeground.exchange(false, std::memory_order_acq_rel);

    if (earlyBg || isRenderViewZeroOrMinimized(renderView)) {
        m_isInBackground.store(true, std::memory_order_release);
        pauseAnimationAndAudio(director);
    } else {
        m_isInBackground.store(false, std::memory_order_release);
        if (director && renderView) {
            const ax::Vec2 winSz = director->getWinSize();
            if (!std::isfinite(winSz.width) || !std::isfinite(winSz.height) ||
                winSz.width < 1.0f || winSz.height < 1.0f) {
                renderView->setDesignResolutionSize(kDesignWidth, kDesignHeight, ResolutionPolicy::FIXED_WIDTH);
            }
        }
    }
}

bool AppDelegate::applicationDidFinishLaunching() {
    if (m_config.headlessServer) return executeHeadlessServer();

    LifecycleState expectedState = LifecycleState::Uninitialized;
    if (!m_lifecycleState.compare_exchange_strong(
            expectedState, LifecycleState::Initializing, std::memory_order_acq_rel)) {
        return expectedState == LifecycleState::Ready;
    }

    configureFileUtils();

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

    if (m_config.validateAssetsOnly) {
        m_assetValidationOk = runAssetValidation();
        director->end();
        teardownSubsystems(m_assetValidationOk ? LifecycleState::Terminated : LifecycleState::Failed);
        return false;
    }

    gclient::ui::Win32DesktopBridge::instance().setInitialMuted(m_config.muteAudio);
    if (m_config.muteAudio) {
        if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
            audio->setBackgroundMusicVolume(0.0f);
            audio->setEffectsVolume(0.0f);
        }
    }

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

    const std::string entryScript = resolveEntryScriptRelativePath();
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info, "AppDelegate", "Executing Lua entry point: %s", entryScript.c_str());

    const int status = executeBootstrapScript(engine, entryScript);
    if (status != 0) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Fatal,
            "AppDelegate",
            "Lua bootstrap failed (status=%d) while executing '%s'",
            status, entryScript.c_str());
        diagnostics::CrashAndTelemetry::flushLogs();
        director->end();
        teardownSubsystems(LifecycleState::Failed);
        return false;
    }

    if (const std::string autoScript = firstNonEmptyEnv({"KESTREL_AUTOTEST_SCRIPT", "GCLIENT_AUTOTEST_SCRIPT"});
        !autoScript.empty()) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Info, "AutoTest", "Executing post-boot autotest script: %s", autoScript.c_str());
        (void)executeBootstrapScript(engine, autoScript);
    }

    m_lifecycleState.store(LifecycleState::Ready, std::memory_order_release);
    if (!m_config.skipHotupdate && !m_config.hotfixDir.empty()) {
        update::AtomicHotUpdater updater(makeHotUpdaterConfig(m_config));
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
    pauseAnimationAndAudio(ax::Director::getInstance());
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
