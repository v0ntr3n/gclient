#pragma once

#include "common/KestrelBinaryReader.h"
#include "common/KestrelUtf8.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

#ifdef poll
#undef poll
#endif

namespace bt {

struct AuthSession {
    std::string pid;             // Platform user ID (mapped to bt::Platform::_pid)
    std::string token;           // Session / access token
    std::string username;        // Display name or account identifier
    std::string extraJson;       // Optional provider-specific JSON payload
    bool authenticated = false;
    int64_t expiresAtEpoch = 0;  // Unix timestamp (seconds), 0 = non-expiring
};

struct AuthResult {
    bool success = false;
    bool fromCache = false;
    int errorCode = 0;
    std::string errorMessage;
    AuthSession session;
};

using AuthCallback = std::function<void(const AuthResult&)>;
using LogoutCallback = std::function<void(bool)>;

class IAuthProvider {
public:
    virtual ~IAuthProvider() = default;

    virtual std::string providerName() const = 0;
    virtual bool initialize(const std::map<std::string, std::string>& initParams) = 0;
    virtual void login(AuthCallback onComplete) = 0;
    virtual void logout(LogoutCallback onComplete) = 0;
    virtual bool isAuthenticated() const = 0;
    virtual AuthSession currentSession() const = 0;
    virtual void poll() {}
};

class LocalStubAuthProvider final : public IAuthProvider {
public:
    struct Config {
        std::string defaultPid = "win32_local_0001";
        std::string defaultToken = "local_stub_session_token";
        std::string defaultUsername = "Win32Tester";
        std::string extraJson = "{}";
        bool failLogin = false;
        std::string failureMessage = "Simulated local login failure";
    };

    LocalStubAuthProvider() = default;
    explicit LocalStubAuthProvider(Config config) : config_(std::move(config)) {}

    std::string providerName() const override { return "LocalStubAuthProvider"; }

    bool initialize(const std::map<std::string, std::string>& initParams) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto assignIfNonEmpty = [&](const char* key, std::string& dst) {
            if (auto it = initParams.find(key); it != initParams.end() && !it->second.empty()) {
                dst = it->second;
            }
        };
        assignIfNonEmpty("stub_pid", config_.defaultPid);
        assignIfNonEmpty("stub_token", config_.defaultToken);
        assignIfNonEmpty("stub_username", config_.defaultUsername);
        initialized_ = true;
        return true;
    }

    void login(AuthCallback onComplete) override {
        AuthResult result;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (config_.failLogin) {
                result.errorCode = -1;
                result.errorMessage = config_.failureMessage;
                session_ = AuthSession{};
            } else {
                session_ = AuthSession{
                    config_.defaultPid, config_.defaultToken, config_.defaultUsername,
                    config_.extraJson, true, 0};
                result.success = true;
                result.session = session_;
            }
        }
        if (onComplete) onComplete(result);
    }

    void logout(LogoutCallback onComplete) override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            session_ = AuthSession{};
        }
        if (onComplete) onComplete(true);
    }

    bool isAuthenticated() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return session_.authenticated;
    }

    AuthSession currentSession() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return session_;
    }

    void setConfig(Config config) {
        std::lock_guard<std::mutex> lock(mutex_);
        config_ = std::move(config);
    }

private:
    mutable std::mutex mutex_;
    Config config_;
    AuthSession session_;
    bool initialized_ = false;
};

class ExternalBrokerAuthProvider final : public IAuthProvider {
public:
    using TokenFetcher = std::function<bool(AuthSession& outSession, std::string& outError)>;

    ExternalBrokerAuthProvider() = default;
    explicit ExternalBrokerAuthProvider(std::string brokerTokenFilePath)
        : brokerTokenFilePath_(std::move(brokerTokenFilePath)) {}
    explicit ExternalBrokerAuthProvider(TokenFetcher fetcher)
        : customFetcher_(std::move(fetcher)) {}

    std::string providerName() const override { return "ExternalBrokerAuthProvider"; }

    void setTokenFetcher(TokenFetcher fetcher) {
        std::lock_guard<std::mutex> lock(mutex_);
        customFetcher_ = std::move(fetcher);
    }

    void setBrokerTokenFilePath(std::string path) {
        std::lock_guard<std::mutex> lock(mutex_);
        brokerTokenFilePath_ = std::move(path);
    }

    void injectSession(AuthSession session) {
        std::lock_guard<std::mutex> lock(mutex_);
        injectedSession_ = std::move(session);
        hasInjectedSession_ = !injectedSession_.pid.empty();
    }

    bool initialize(const std::map<std::string, std::string>& initParams) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (auto it = initParams.find("broker_token_file"); it != initParams.end() && !it->second.empty()) {
            brokerTokenFilePath_ = it->second;
        }
        initialized_ = true;
        return true;
    }

    void login(AuthCallback onComplete) override {
        AuthResult result;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            AuthSession resolved;
            std::string error;
            bool ok = false;

            if (customFetcher_) {
                ok = customFetcher_(resolved, error);
            } else if (hasInjectedSession_) {
                resolved = injectedSession_;
                ok = true;
            } else if (!brokerTokenFilePath_.empty() &&
                       loadFromBrokerFile(brokerTokenFilePath_, resolved, error)) {
                ok = true;
            } else if (loadFromEnvironment(resolved)) {
                ok = true;
            } else if (error.empty()) {
                error = "No broker session available (set TokenFetcher, injectSession, broker file, or GCLIENT_AUTH_PID/GCLIENT_AUTH_TOKEN)";
            }

            if (ok && isSessionExpired(resolved)) {
                ok = false;
                error = "Broker session token has expired";
            }

            if (ok && !resolved.pid.empty()) {
                resolved.authenticated = true;
                session_ = resolved;
                result.success = true;
                result.session = session_;
            } else {
                session_ = AuthSession{};
                result.errorCode = -2;
                result.errorMessage = error.empty() ? "Broker returned empty pid" : error;
            }
        }
        if (onComplete) onComplete(result);
    }

    void logout(LogoutCallback onComplete) override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            session_ = AuthSession{};
            hasInjectedSession_ = false;
            injectedSession_ = AuthSession{};
        }
        if (onComplete) onComplete(true);
    }

    bool isAuthenticated() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return session_.authenticated && !isSessionExpired(session_);
    }

    AuthSession currentSession() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return session_;
    }

private:
    static int64_t currentEpochSeconds() noexcept {
        using namespace std::chrono;
        return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    }

    static bool isSessionExpired(const AuthSession& s) noexcept {
        return s.expiresAtEpoch > 0 && currentEpochSeconds() > s.expiresAtEpoch;
    }

    static int64_t parseInt64OrZero(const std::string& val) noexcept {
        if (val.empty()) return 0;
        char* endp = nullptr;
        const long long parsed = std::strtoll(val.c_str(), &endp, 10);
        return (endp && endp != val.c_str() && *endp == '\0') ? static_cast<int64_t>(parsed) : 0;
    }

    static bool loadFromBrokerFile(const std::string& path,
                                   AuthSession& outSession,
                                   std::string& outError) {
        std::ifstream ifs(gclient::utf8::utf8ToFsPath(path), std::ios::binary);
        if (!ifs.is_open()) {
            outError = "Failed to open broker token file: " + path;
            return false;
        }
        std::string rawLine;
        while (std::getline(ifs, rawLine)) {
            const std::string_view line = gclient::common::trimAscii(rawLine);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
            const size_t eq = line.find('=');
            if (eq == std::string_view::npos) continue;
            const std::string_view key = gclient::common::trimAscii(line.substr(0, eq));
            const std::string val = gclient::common::trimCopy(line.substr(eq + 1));
            if (key == "pid") outSession.pid = val;
            else if (key == "token") outSession.token = val;
            else if (key == "username") outSession.username = val;
            else if (key == "extra_json") outSession.extraJson = val;
            else if (key == "expires_at") outSession.expiresAtEpoch = parseInt64OrZero(val);
        }
        if (outSession.pid.empty()) {
            outError = "Broker token file missing required 'pid' field: " + path;
            return false;
        }
        return true;
    }

    static bool loadFromEnvironment(AuthSession& outSession) {
        const std::string envPid = gclient::utf8::readEnvUtf8("GCLIENT_AUTH_PID");
        if (envPid.empty()) return false;
        outSession.pid = envPid;
        outSession.token = gclient::utf8::readEnvUtf8("GCLIENT_AUTH_TOKEN");
        outSession.username = gclient::utf8::readEnvUtf8("GCLIENT_AUTH_USER");
        outSession.extraJson = gclient::utf8::readEnvUtf8("GCLIENT_AUTH_EXTRA_JSON");
        outSession.expiresAtEpoch = parseInt64OrZero(gclient::utf8::readEnvUtf8("GCLIENT_AUTH_EXPIRES_AT"));
        return true;
    }

    mutable std::mutex mutex_;
    TokenFetcher customFetcher_;
    std::string brokerTokenFilePath_;
    AuthSession injectedSession_;
    bool hasInjectedSession_ = false;
    AuthSession session_;
    bool initialized_ = false;
};

} // namespace bt
