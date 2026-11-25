#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include "cocos2d.h"

struct lua_State;

namespace gclient {

struct AppConfig {
    std::string resourcesDir;
    std::string baseAssetsDir;
    std::string profileDir;
    std::string writableDir;
    std::string hotfixDir;
    std::string logsDir;
    std::string dumpsDir;

    int windowWidth = 1136;
    int windowHeight = 640;

    bool muteAudio = false;
    bool validateAssetsOnly = false;
};

class AppDelegate final : private cocos2d::CCApplication {
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

    // CCApplication lifecycle overrides
    bool applicationDidFinishLaunching() override;
    void applicationDidEnterBackground() override;
    void applicationWillEnterForeground() override;

    // Headless CLI --validate-assets entrypoint (runs without requiring an OpenGL 2.0 context)
    bool executeHeadlessAssetValidation();

    // Explicit ordered teardown (safe & idempotent; called by wWinMain prior to telemetry shutdown)
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

    static bool isLifecycleReady() noexcept;

    bool assetValidationSucceeded() const noexcept { return m_assetValidationOk; }
    const AppConfig& config() const noexcept { return m_config; }

private:
    class FrameTicker;

    void configureFileUtils();
    void registerLuaBindings(lua_State* L);
    void scheduleNativeLoops();
    void unscheduleNativeLoops();
    bool runAssetValidation();
    void reconcileInitialWindowLifecycleState(cocos2d::CCDirector* director,
                                              cocos2d::CCEGLView* eglView);
    void teardownSubsystems(LifecycleState terminalState);

    AppConfig m_config;
    FrameTicker* m_ticker = nullptr;
    bool m_assetValidationOk = false;

    std::atomic<LifecycleState> m_lifecycleState{LifecycleState::Uninitialized};
    std::atomic<bool> m_isInBackground{false};
    std::atomic<bool> m_pendingForeground{false};
    std::atomic<bool> m_pendingBackground{false};
};

} // namespace gclient
