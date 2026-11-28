#pragma once

#include "platform/IAuthProvider.h"

#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace bt {

/**
 * Platform / Account authentication provider for Win32.
 *
 * Supports native Win32 Account / Guest / PID+Token sign-in and persists valid
 * sessions across launches under %LOCALAPPDATA%/GCLIENT/account_session.json (or an
 * explicit --profile-dir / multi-instance slot override via GCLIENT_SESSION_FILE).
 */
class AccountAuthProvider final : public IAuthProvider {
public:
    struct Config {
        std::string gameId = "vnsg2";
        std::string authorizeUrl = "http://127.0.0.1:8080";
        std::string tokenUrl;
        std::string clientId = "vnsg2";
        std::string ghk = "d345c6c5c29669eae007b682625fbf42";
        std::string gtsdkGameId = "GCLIENT";
        std::string userUrl = "http://127.0.0.1:8080";
        std::string gameVersion = "1.0.38";
        std::string sessionFilePath;
        int timeoutSeconds = 180;
    };

    AccountAuthProvider();
    explicit AccountAuthProvider(Config config);
    ~AccountAuthProvider() override;

    std::string providerName() const override { return "AccountAuthProvider"; }

    bool initialize(const std::map<std::string, std::string>& initParams) override;
    void login(AuthCallback onComplete) override;
    void logout(LogoutCallback onComplete) override;
    bool isAuthenticated() const override;
    AuthSession currentSession() const override;
    void poll() override;

    bool authenticateWithAccount(const std::string& username,
                                const std::string& password,
                                AuthSession& outSession,
                                std::string& outError);
    bool authenticateAsGuest(AuthSession& outSession,
                                std::string& outError);

    static bool isOfflineStubToken(const std::string& tok);
    static bool isLegacyDeadAuthUrl(std::string_view url) noexcept;
    static bool isEphemeralPidInstancePath(const std::string& path);
    static std::string defaultSessionFile();
    static std::string resolvePersistentDeviceId(const std::string& sessionFileHint = "");
    static bool purgePoisonedLocalAppDataSession();

    Config getConfig() const;
    std::string resolveSessionFilePath() const;
    bool tryLoadCachedSession(AuthSession& outSession) const;
    void saveCachedSession(const AuthSession& session) const;
    void clearCachedSession() const;

private:
    void cancelPendingLogin();
    void completeInFlightLogin(AuthCallback primaryCb, const AuthResult& res);
    void enqueueResult(AuthCallback cb, AuthResult res);

    mutable std::mutex mutex_;
    Config config_;
    AuthSession session_;
    bool initialized_ = false;

    std::atomic<bool> loginInProgress_{false};
    std::atomic<bool> cancelRequested_{false};
    std::thread workerThread_;

    std::mutex callbackMutex_;
    std::vector<AuthCallback> coalescedLoginCallbacks_;
    std::deque<std::pair<AuthCallback, AuthResult>> pendingCallbacks_;
};

} // namespace bt
