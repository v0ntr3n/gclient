#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "compat/Axmol226Compat.h"

struct lua_State;
namespace ax {
class LuaEngine;
}

namespace gclient {

struct AppConfig {
    std::string resourcesDir;
    std::string baseAssetsDir;
    std::string profileDir;
    std::string writableDir;
    std::string hotfixDir;
    std::string logsDir;
    std::string dumpsDir;

    std::string mapiUrl;
    std::string gameHost;
    int         gamePort = 0;
    std::string pid;
    std::string sessionToken;
    std::string entryScript;

    int windowWidth  = 1136;
    int windowHeight = 640;

    bool muteAudio          = false;
    bool validateAssetsOnly = false;
    bool skipHotupdate      = false;
    bool headlessServer     = false;

    std::map<std::string, std::string> bootstrapEnv;
};

class AppDelegate final : public ax::Application {
public:
    enum class LifecycleState : uint8_t {
        Uninitialized = 0,
        Initializing  = 1,
        Ready         = 2,
        Failed        = 3,
        ShuttingDown  = 4,
        Terminated    = 5
    };

    explicit AppDelegate(const AppConfig& config = AppConfig{});
    ~AppDelegate() override;

    AppDelegate(const AppDelegate&) = delete;
    AppDelegate& operator=(const AppDelegate&) = delete;

    // ax::Application lifecycle overrides
    void initGfxContextAttrs() override;
    bool applicationDidFinishLaunching() override;
    void applicationDidEnterBackground() override;
    void applicationWillEnterForeground() override;
    void applicationWillQuit() override;

    // Headless CLI --validate-assets entrypoint (runs without requiring an OpenGL context)
    bool executeHeadlessAssetValidation();

    // Headless server mode entrypoint
    bool executeHeadlessServer();

    // Schedule a Lua soft restart on the next frame tick
    void restartGame();

    // Explicit ordered teardown (safe & idempotent; called prior to telemetry shutdown)
    void shutdown();

    LifecycleState lifecycleState() const noexcept {
        return m_lifecycleState.load(std::memory_order_acquire);
    }
    bool isReady() const noexcept {
        return lifecycleState() == LifecycleState::Ready;
    }
    bool isInBackground() const noexcept {
        return m_isInBackground.load(std::memory_order_acquire);
    }
    bool hasPendingForeground() const noexcept {
        return m_pendingForeground.load(std::memory_order_acquire);
    }
    bool hasPendingBackground() const noexcept {
        return m_pendingBackground.load(std::memory_order_acquire);
    }

    static AppDelegate* activeInstance() noexcept;
    static bool hasActiveInstance() noexcept;
    static bool isLifecycleReady() noexcept;

    bool assetValidationSucceeded() const noexcept { return m_assetValidationOk; }
    const AppConfig& config() const noexcept { return m_config; }

private:
    class FrameTicker;

    void resolveBootstrapEnvironment();
    std::string resolveEntryScriptRelativePath() const;
    void configureFileUtils();
    void installKestrelBootstrapTable(lua_State* L);
    void registerLuaBindings(lua_State* L);
    int executeBootstrapScript(ax::LuaEngine* engine, const std::string& scriptPath);
    void performSoftRestart();
    void scheduleNativeLoops();
    void unscheduleNativeLoops();
    bool runAssetValidation();
    void reconcileInitialWindowLifecycleState(ax::Director* director,
                                              ax::RenderViewImpl* renderView);
    void teardownSubsystems(LifecycleState terminalState);

    AppConfig                m_config;
    FrameTicker*             m_ticker            = nullptr;
    bool                     m_assetValidationOk = false;
    std::vector<std::string> m_initialSearchPaths;

    std::atomic<LifecycleState> m_lifecycleState{LifecycleState::Uninitialized};
    std::atomic<bool>           m_isInBackground{false};
    std::atomic<bool>           m_pendingForeground{false};
    std::atomic<bool>           m_pendingBackground{false};
    std::atomic<bool>           m_pendingSoftRestart{false};
    std::atomic<uint32_t>       m_restartCount{0};
};

} // namespace gclient
