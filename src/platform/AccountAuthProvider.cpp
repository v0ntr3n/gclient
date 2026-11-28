#include "platform/AccountAuthProvider.h"
#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelHttp.h"
#include "common/KestrelJson.h"
#include "common/KestrelUtf8.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string_view>

namespace bt {

namespace {

namespace fs = std::filesystem;
using gclient::common::endsWithAsciiCI;
using gclient::common::trimCopy;
using gclient::crypto::md5Hex;
using gclient::utf8::firstNonEmptyEnv;
using gclient::utf8::fsPathToUtf8;
using gclient::utf8::readEnvBool;
using gclient::utf8::readEnvUtf8;
using gclient::utf8::urlEncode;
using gclient::utf8::utf8ToFsPath;

constexpr const char* kDefaultAuthSecret = "d345c6c5c29669eae007b682625fbf42";
constexpr const char* kDefaultGtsdkGameId = "GCLIENT";
constexpr const char* kDefaultUserUrl = "http://127.0.0.1:8080";
constexpr const char* kDefaultGameVersion = "1.0.38";

std::string stripTrailingSlashes(std::string_view sv) {
    std::string s = trimCopy(sv);
    while (!s.empty() && (s.back() == '/' || s.back() == '\\')) {
        s.pop_back();
    }
    return s;
}

std::string toLowerAsciiNormSlashes(std::string s) {
    for (char& ch : s) {
        ch = (ch == '\\') ? '/' : static_cast<char>(gclient::common::asciiLower(static_cast<unsigned char>(ch)));
    }
    while (!s.empty() && s.back() == '/') {
        s.pop_back();
    }
    return s;
}

bool readFileText(const fs::path& filePath, std::string& outText) {
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs.is_open()) return false;
    std::ostringstream oss;
    oss << ifs.rdbuf();
    outText = oss.str();
    return true;
}

#ifdef _WIN32
std::string getWindowTextUtf8(HWND hwnd) {
    int len = ::GetWindowTextLengthW(hwnd);
    if (len <= 0) return {};
    std::wstring buf(static_cast<size_t>(len) + 1, L'\0');
    int copied = ::GetWindowTextW(hwnd, buf.data(), len + 1);
    if (copied <= 0) return {};
    buf.resize(static_cast<size_t>(copied));
    return trimCopy(gclient::utf8::wideToUtf8(buf));
}
#endif

bool isHeadlessAuthEnvironment() {
    return readEnvBool({"GCLIENT_HEADLESS", "GCLIENT_AUTO_GUEST", "CI", "GITHUB_ACTIONS"}, false);
}

std::string resolveRelayAuthOriginFallback() {
    for (const char* envKey : {
             "GCLIENT_AUTH_URL", "GCLIENT_RELAY_HTTP_URL", "GCLIENT_HTTP_HOST", "GCLIENT_MAPI_URL"}) {
        const std::string v = stripTrailingSlashes(readEnvUtf8(envKey));
        if (!v.empty() && !AccountAuthProvider::isLegacyDeadAuthUrl(v)) {
            return v;
        }
    }
    return kDefaultUserUrl;
}

bool isValidHexTokenId(std::string_view s) noexcept {
    if (s.size() < 16 || s.size() > 64) return false;
    for (unsigned char ch : s) {
        if (!std::isalnum(ch) && ch != '-' && ch != '_') return false;
    }
    return true;
}

AccountAuthProvider::Config resolveEffectiveAuthConfig(const AccountAuthProvider::Config& base) {
    AccountAuthProvider::Config effective = base;
    if (effective.ghk.empty()) effective.ghk = kDefaultAuthSecret;
    if (effective.gtsdkGameId.empty()) effective.gtsdkGameId = kDefaultGtsdkGameId;
    if (effective.userUrl.empty()) effective.userUrl = kDefaultUserUrl;
    if (effective.gameVersion.empty()) effective.gameVersion = kDefaultGameVersion;

    if (const std::string envGhk = readEnvUtf8("GCLIENT_AUTH_SECRET"); !envGhk.empty()) {
        effective.ghk = envGhk;
    }

    const bool disableRewrite = readEnvBool({"GCLIENT_DISABLE_STAGING_REWRITE"}, false);
    if (const std::string envUserUrl = stripTrailingSlashes(readEnvUtf8("GCLIENT_AUTH_URL"));
        !envUserUrl.empty()) {
        effective.userUrl = envUserUrl;
    } else {
        effective.userUrl = stripTrailingSlashes(effective.userUrl);
        if (!disableRewrite &&
            (effective.userUrl.empty() || effective.userUrl == "null" ||
             AccountAuthProvider::isLegacyDeadAuthUrl(effective.userUrl))) {
            effective.userUrl = resolveRelayAuthOriginFallback();
        }
    }

    if (!disableRewrite &&
        (effective.authorizeUrl.empty() || AccountAuthProvider::isLegacyDeadAuthUrl(effective.authorizeUrl))) {
        effective.authorizeUrl = effective.userUrl;
    }

    if (const std::string envGameVer = readEnvUtf8("GCLIENT_GAME_VERSION"); !envGameVer.empty()) {
        effective.gameVersion = envGameVer;
    }
    return effective;
}

std::string postQueryMap(const std::string& baseUrl,
                         const std::map<std::string, std::string>& params,
                         long* outHttpCode = nullptr,
                         std::string* outError = nullptr,
                         const std::atomic<bool>* cancelFlag = nullptr) {
    if (outHttpCode) *outHttpCode = 0;
    if (outError) outError->clear();

#if !GCLIENT_HTTP_HAS_CURL
    (void)baseUrl;
    (void)params;
    (void)cancelFlag;
    if (outError) *outError = "libcurl headers unavailable in standalone test build";
    return {};
#else
    if (cancelFlag && cancelFlag->load(std::memory_order_acquire)) {
        if (outError) *outError = "Login cancelled";
        return {};
    }

    std::string fullUrl = baseUrl;
    bool first = (fullUrl.find('?') == std::string::npos);
    for (const auto& [k, v] : params) {
        fullUrl.push_back(first ? '?' : '&');
        first = false;
        fullUrl += k + "=" + urlEncode(v);
    }

    const bool verifyPeer = !readEnvBool({"GCLIENT_INSECURE_TLS"}, false);
    const std::string caBundle = firstNonEmptyEnv({"GCLIENT_CA_BUNDLE", "CURL_CA_BUNDLE"});

    gclient::http::ensureCurlGlobalInit();
    CURL* curl = curl_easy_init();
    if (!curl) {
        if (outError) *outError = "curl_easy_init failed";
        return {};
    }

    std::string response;
    char errBuf[CURL_ERROR_SIZE] = {};
    gclient::http::configureCurlTlsAndTimeouts(curl, 5000, 12000, verifyPeer, caBundle);
    curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "okhttp/3.10.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &gclient::http::detail::appendWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errBuf);
    if (cancelFlag) {
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(
            curl,
            CURLOPT_XFERINFOFUNCTION,
            +[](void* clientp, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> int {
                const auto* flag = static_cast<const std::atomic<bool>*>(clientp);
                return (flag && flag->load(std::memory_order_acquire)) ? 1 : 0;
            });
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA, const_cast<std::atomic<bool>*>(cancelFlag));
    }

    const CURLcode rc = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    if (outHttpCode) *outHttpCode = httpCode;
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        if (outError) {
            if (rc == CURLE_ABORTED_BY_CALLBACK) {
                *outError = "Login cancelled";
            } else {
                std::string detail = (errBuf[0] != '\0') ? errBuf : curl_easy_strerror(rc);
                detail += " (curl=" + std::to_string(static_cast<int>(rc)) +
                          ", http=" + std::to_string(httpCode) + ")";
                *outError = std::move(detail);
            }
        }
        return {};
    }

    if (httpCode >= 400 && gclient::json::extractStringOr(response, "returnCode").empty()) {
        if (outError) {
            std::string detail = "HTTP " + std::to_string(httpCode);
            if (!response.empty()) detail += ": " + trimCopy(std::string_view(response).substr(0, 160));
            *outError = std::move(detail);
        }
        return {};
    }

    if (response.empty()) {
        if (outError) *outError = "Empty HTTP response (status " + std::to_string(httpCode) + ")";
        return {};
    }
    return response;
#endif
}

std::string nowEpochSecString() {
    return std::to_string(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

bool executeAuthRequest(const AccountAuthProvider::Config& cfg,
                        const char* primaryRoute,
                        const char* fallbackRoute,
                        const std::map<std::string, std::string>& queryParams,
                        const std::string& defaultUsername,
                        bool useResponseAccountName,
                        bool allowOfflineGuestFallback,
                        const char* authLabel,
                        AuthSession& outSession,
                        std::string& outError,
                        const std::atomic<bool>* cancelFlag) {
    long httpCode = 0;
    std::string netErr;
    std::string resp = postQueryMap(cfg.userUrl + primaryRoute, queryParams, &httpCode, &netErr, cancelFlag);
    if (resp.empty() && httpCode == 404 &&
        !(cancelFlag && cancelFlag->load(std::memory_order_acquire))) {
        resp = postQueryMap(cfg.userUrl + fallbackRoute, queryParams, &httpCode, &netErr, cancelFlag);
    }

    if (resp.empty()) {
        if (allowOfflineGuestFallback && readEnvBool({"GCLIENT_OFFLINE_MODE"}, false)) {
            outSession = AuthSession{"win32_guest_0001", "win32_guest_token", "Win32Player", {}, true, 0};
            return true;
        }
        outError = "Network error contacting " + cfg.userUrl + ": " +
                   (netErr.empty() ? "no response" : netErr);
        return false;
    }

    gclient::json::JsonValue root;
    const bool parsedOk = gclient::json::parse(resp, root) && root.isObject();
    auto getField = [&](std::string_view key) -> std::string {
        if (parsedOk) {
            if (const auto* v = root.find(key)) return v->asString();
        }
        return gclient::json::extractStringOr(resp, key);
    };

    const std::string rc = getField("returnCode");
    if (rc == "1" || rc == "2") {
        const std::string uid = getField("userID");
        const std::string sid = getField("sessionID");
        const std::string acc = useResponseAccountName ? getField("accountName") : std::string{};
        if (!uid.empty() && !sid.empty()) {
            outSession.pid = uid;
            outSession.token = sid;
            outSession.username = acc.empty() ? defaultUsername : acc;
            outSession.authenticated = true;
            return true;
        }
    }

    const std::string msg = getField("message");
    outError = msg.empty()
        ? (std::string(authLabel) + " auth failed (returnCode=" + rc + ")")
        : (msg + " (code " + rc + ")");
    return false;
}

bool callAccountAuth(const AccountAuthProvider::Config& rawConfig,
                     const std::string& username,
                     const std::string& password,
                     AuthSession& outSession,
                     std::string& outError,
                     const std::atomic<bool>* cancelFlag = nullptr) {
    if (username.empty() || password.empty()) {
        outError = "Please enter both username and password.";
        return false;
    }
    const AccountAuthProvider::Config cfg = resolveEffectiveAuthConfig(rawConfig);
    const std::string passMd5 = md5Hex(password, false);
    const std::string ts = nowEpochSecString();
    const std::string sig = md5Hex(cfg.ghk + cfg.gtsdkGameId + username + passMd5 + ts, false);

    const std::map<std::string, std::string> queryParams = {
        {"u", username}, {"p", passMd5}, {"timestamp", ts}, {"sig", sig},
        {"gameID", cfg.gtsdkGameId}, {"game_version", cfg.gameVersion},
        {"lang", "vi"}, {"country_login", "VN"}, {"country", "VN"}, {"ver", "v2.0"}
    };
    return executeAuthRequest(
        cfg, "/api/login/login", "/api/login/auth/account", queryParams,
        username, true, false, "Account", outSession, outError, cancelFlag);
}

bool callGuestAuth(const AccountAuthProvider::Config& rawConfig,
                   const std::string& sessionFileHint,
                   AuthSession& outSession,
                   std::string& outError,
                   const std::atomic<bool>* cancelFlag = nullptr) {
    const AccountAuthProvider::Config cfg = resolveEffectiveAuthConfig(rawConfig);
    const std::string ts = nowEpochSecString();
    const std::string deviceId = AccountAuthProvider::resolvePersistentDeviceId(sessionFileHint);
    const std::string sig = md5Hex(cfg.ghk + cfg.gtsdkGameId + deviceId + ts, false);

    const std::map<std::string, std::string> queryParams = {
        {"deviceID", deviceId}, {"timestamp", ts}, {"sig", sig},
        {"gameID", cfg.gtsdkGameId}, {"game_version", cfg.gameVersion},
        {"lang", "vi"}, {"country", "VN"}, {"ver", "v2.0"}
    };
    return executeAuthRequest(
        cfg, "/api/login/createUser/guest", "/phone/guest", queryParams,
        "Guest", false, true, "Guest", outSession, outError, cancelFlag);
}

#ifdef _WIN32
enum ControlIds {
    kIdUserEdit = 1001, kIdPassEdit = 1002, kIdBtnSignIn = 1003, kIdBtnGuest = 1004,
    kIdPidEdit  = 1005, kIdTokEdit  = 1006, kIdBtnPid    = 1007, kIdBtnStub  = 1008,
    kIdStatus   = 1009, kIdBtnClear = 1010,
};

struct LoginDialogState {
    HWND hwnd = nullptr, userEdit = nullptr, passEdit = nullptr, pidEdit = nullptr, tokEdit = nullptr;
    HWND btnSignIn = nullptr, btnGuest = nullptr, btnPid = nullptr, btnStub = nullptr, statusLabel = nullptr;
    HFONT font = nullptr;
    bool busy = false, completed = false, cancelled = false;
    AuthSession session;
    AccountAuthProvider* provider = nullptr;
    AccountAuthProvider::Config authConfig;
    const std::atomic<bool>* cancelFlag = nullptr;

    void setButtonsEnabled(bool enabled) const {
        const BOOL en = enabled ? TRUE : FALSE;
        for (HWND btn : {btnSignIn, btnGuest, btnPid, btnStub}) {
            if (btn) ::EnableWindow(btn, en);
        }
    }
};

LRESULT CALLBACK loginWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* st = reinterpret_cast<LoginDialogState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_CREATE: {
        st = static_cast<LoginDialogState*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
        st->hwnd = hwnd;
        st->font = ::CreateFontW(
            -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        auto makeCtrl = [&](const wchar_t* cls, const wchar_t* text, DWORD style,
                            int x, int y, int w, int h, int id) -> HWND {
            HWND c = ::CreateWindowExW(
                (std::wcscmp(cls, L"EDIT") == 0) ? WS_EX_CLIENTEDGE : 0,
                cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
            if (c && st->font) ::SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(st->font), TRUE);
            return c;
        };

        makeCtrl(L"STATIC", L"Username:", 0, 16, 14, 140, 20, 0);
        st->userEdit = makeCtrl(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, 16, 36, 372, 24, kIdUserEdit);
        makeCtrl(L"STATIC", L"Password:", 0, 16, 68, 140, 20, 0);
        st->passEdit = makeCtrl(L"EDIT", L"", WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, 16, 90, 372, 24, kIdPassEdit);
        st->btnSignIn = makeCtrl(L"BUTTON", L"Sign In", WS_TABSTOP | BS_DEFPUSHBUTTON, 16, 124, 180, 30, kIdBtnSignIn);
        st->btnGuest  = makeCtrl(L"BUTTON", L"Guest Login", WS_TABSTOP, 208, 124, 180, 30, kIdBtnGuest);
        makeCtrl(L"STATIC", L"--- Or enter existing Account UID & Session Token ---", 0, 16, 166, 372, 20, 0);
        makeCtrl(L"STATIC", L"Account UID:", 0, 16, 190, 140, 20, 0);
        st->pidEdit = makeCtrl(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, 16, 212, 372, 24, kIdPidEdit);
        makeCtrl(L"STATIC", L"Session Token:", 0, 16, 244, 140, 20, 0);
        st->tokEdit = makeCtrl(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, 16, 266, 372, 24, kIdTokEdit);
        st->btnPid  = makeCtrl(L"BUTTON", L"Use PID & Token", WS_TABSTOP, 16, 300, 180, 30, kIdBtnPid);
        st->btnStub = makeCtrl(L"BUTTON", L"Quick Offline Guest", WS_TABSTOP, 208, 300, 180, 30, kIdBtnStub);
        makeCtrl(L"BUTTON", L"Clear Saved Session", WS_TABSTOP, 16, 336, 372, 28, kIdBtnClear);
        st->statusLabel = makeCtrl(L"STATIC", L"Ready.", 0, 16, 372, 372, 42, kIdStatus);
        ::SetFocus(st->userEdit);
        return 0;
    }
    case WM_COMMAND: {
        if (!st || st->busy) break;
        const int id = LOWORD(wParam);
        auto runBusyAction = [&](const wchar_t* statusMsg, auto&& actionFn) {
            st->busy = true;
            st->setButtonsEnabled(false);
            ::SetWindowTextW(st->statusLabel, statusMsg);
            ::UpdateWindow(hwnd);
            std::string err;
            if (actionFn(err)) {
                st->completed = true;
                ::DestroyWindow(hwnd);
            } else {
                st->busy = false;
                st->setButtonsEnabled(true);
                ::SetWindowTextW(st->statusLabel, gclient::utf8::utf8ToWide(err).c_str());
            }
        };

        if (id == kIdBtnSignIn) {
            const std::string u = getWindowTextUtf8(st->userEdit);
            const std::string p = getWindowTextUtf8(st->passEdit);
            runBusyAction(L"Signing in...", [&](std::string& err) {
                return callAccountAuth(st->authConfig, u, p, st->session, err, st->cancelFlag);
            });
            return 0;
        }
        if (id == kIdBtnGuest) {
            const std::string sessHint = st->provider ? st->provider->resolveSessionFilePath()
                                                      : AccountAuthProvider::defaultSessionFile();
            runBusyAction(L"Creating guest session...", [&](std::string& err) {
                return callGuestAuth(st->authConfig, sessHint, st->session, err, st->cancelFlag);
            });
            return 0;
        }
        if (id == kIdBtnPid) {
            const std::string pid = getWindowTextUtf8(st->pidEdit);
            const std::string tok = getWindowTextUtf8(st->tokEdit);
            if (pid.empty() || tok.empty()) {
                ::SetWindowTextW(st->statusLabel, L"Please enter both Account UID and Session Token.");
                return 0;
            }
            st->session = AuthSession{pid, tok, pid, {}, true, 0};
            st->completed = true;
            ::DestroyWindow(hwnd);
            return 0;
        }
        if (id == kIdBtnStub) {
            st->session = AuthSession{"win32_guest_0001", "win32_guest_token", "Win32Player", {}, true, 0};
            st->completed = true;
            ::DestroyWindow(hwnd);
            return 0;
        }
        if (id == kIdBtnClear) {
            if (st->provider) st->provider->clearCachedSession();
            AccountAuthProvider::purgePoisonedLocalAppDataSession();
            ::SetWindowTextW(st->statusLabel, L"Cleared cached session files.");
            return 0;
        }
        break;
    }
    case WM_CLOSE:
        if (st) st->cancelled = true;
        ::DestroyWindow(hwnd);
        return 0;
    case WM_TIMER:
        if (st && st->cancelFlag && st->cancelFlag->load(std::memory_order_acquire)) {
            st->cancelled = true;
            ::DestroyWindow(hwnd);
        }
        return 0;
    case WM_DESTROY:
        ::KillTimer(hwnd, 1);
        if (st && st->font) {
            ::DeleteObject(st->font);
            st->font = nullptr;
        }
        ::PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool showNativeWin32LoginDialog(AccountAuthProvider* provider,
                                const AccountAuthProvider::Config& authConfig,
                                AuthSession& outSession,
                                std::string& outError,
                                const std::atomic<bool>& cancelFlag) {
    static const wchar_t* kClassName = L"GCLIENT_AccountLoginDialog";
    HINSTANCE hInst = ::GetModuleHandleW(nullptr);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = loginWndProc;
    wc.hInstance = hInst;
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kClassName;
    ::RegisterClassExW(&wc);

    LoginDialogState state;
    state.provider = provider;
    state.authConfig = authConfig;
    state.cancelFlag = &cancelFlag;

    RECT rc{0, 0, 404, 424};
    constexpr DWORD kStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
    ::AdjustWindowRect(&rc, kStyle, FALSE);
    const int winW = rc.right - rc.left;
    const int winH = rc.bottom - rc.top;

    HWND hwnd = ::CreateWindowExW(
        WS_EX_TOPMOST, kClassName, L"Game Client - Sign In", kStyle | WS_VISIBLE,
        (::GetSystemMetrics(SM_CXSCREEN) - winW) / 2, (::GetSystemMetrics(SM_CYSCREEN) - winH) / 2,
        winW, winH, nullptr, nullptr, hInst, &state);
    if (!hwnd) {
        outError = "Failed to create Win32 login dialog.";
        return false;
    }

    ::SetTimer(hwnd, 1, 100, nullptr);
    ::SetForegroundWindow(hwnd);

    MSG msg{};
    while (!cancelFlag.load(std::memory_order_acquire) && ::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!::IsDialogMessageW(hwnd, &msg)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    }
    if (cancelFlag.load(std::memory_order_acquire) && ::IsWindow(hwnd)) {
        ::DestroyWindow(hwnd);
    }
    while (::PeekMessageW(&msg, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {}

    if (state.completed) {
        outSession = state.session;
        return true;
    }
    outError = cancelFlag.load(std::memory_order_acquire) ? "Login cancelled" : "Login window closed";
    return false;
}
#endif

std::mutex& workerThreadLifecycleMutex() {
    static std::mutex* s_workerMutex = new std::mutex();
    return *s_workerMutex;
}

void reclaimWorkerThread(std::thread& worker) {
    std::thread toJoin;
    {
        std::lock_guard<std::mutex> workerLock(workerThreadLifecycleMutex());
        if (worker.joinable()) {
            if (worker.get_id() == std::this_thread::get_id()) {
                worker.detach();
            } else {
                toJoin = std::move(worker);
            }
        }
    }
    if (toJoin.joinable()) {
        toJoin.join();
    }
}

} // namespace

bool AccountAuthProvider::isOfflineStubToken(const std::string& tok) {
    return tok.empty() || tok == "win32_guest_token" || tok == "local_stub_session_token";
}

bool AccountAuthProvider::isLegacyDeadAuthUrl(std::string_view url) noexcept {
    std::string host = gclient::http::EndpointRewritePolicy::extractUrlHost(url);
    if (const size_t at = host.rfind('@'); at != std::string::npos) {
        host.erase(0, at + 1);
    }
    if (host.empty()) return false;
    return gclient::http::EndpointRewritePolicy::isLegacyDeadHost(host) ||
           endsWithAsciiCI(host, ".zing.vn") ||
           endsWithAsciiCI(host, ".zingplay.com") ||
           endsWithAsciiCI(host, ".vnggames.com") ||
           endsWithAsciiCI(host, ".gtarcade.com") ||
           endsWithAsciiCI(host, ".babeltime.com") ||
           host == "zing.vn" || host == "mto.zing.vn";
}

bool AccountAuthProvider::isEphemeralPidInstancePath(const std::string& path) {
    if (path.empty()) return false;
    const std::string norm = toLowerAsciiNormSlashes(path);
    return norm.find("/instances/pid_") != std::string::npos || norm.rfind("instances/pid_", 0) == 0;
}

std::string AccountAuthProvider::defaultSessionFile() {
    if (const std::string envOverride = readEnvUtf8("GCLIENT_SESSION_FILE"); !envOverride.empty()) {
        return envOverride;
    }

    const std::string localAppData = readEnvUtf8("LOCALAPPDATA");
    const std::string normLegacyRoot = localAppData.empty()
        ? std::string()
        : toLowerAsciiNormSlashes(fsPathToUtf8(utf8ToFsPath(localAppData) / "GCLIENT"));
    const std::string normAxmolRoot = localAppData.empty()
        ? std::string()
        : toLowerAsciiNormSlashes(fsPathToUtf8(utf8ToFsPath(localAppData) / "GCLIENT_AXMOL"));

    auto isDefaultPrimarySlotPath = [&](const std::string& dir) -> bool {
        if (dir.empty()) return false;
        if (isEphemeralPidInstancePath(dir)) return true;
        const std::string normDir = toLowerAsciiNormSlashes(dir);
        for (const std::string& root : {normAxmolRoot, normLegacyRoot}) {
            if (!root.empty() &&
                (normDir == (root + "/profiles/default") ||
                 normDir == (root + "/profiles/default/writable"))) {
                return true;
            }
        }
        return false;
    };

    for (const char* envDirKey : {"GCLIENT_PROFILE_DIR", "GCLIENT_WRITABLE_DIR"}) {
        const std::string dir = readEnvUtf8(envDirKey);
        if (!dir.empty() && !isDefaultPrimarySlotPath(dir)) {
            return fsPathToUtf8(utf8ToFsPath(dir) / "account_session.json");
        }
    }

    if (!localAppData.empty()) {
        const fs::path base = utf8ToFsPath(localAppData);
        const fs::path axmolSess = base / "GCLIENT_AXMOL" / "account_session.json";
        const fs::path legacySess = base / "GCLIENT" / "account_session.json";
        std::error_code ec;
        if (!fs::is_regular_file(axmolSess, ec) && fs::is_regular_file(legacySess, ec)) {
            return fsPathToUtf8(legacySess);
        }
        return fsPathToUtf8(axmolSess);
    }
    return "account_session.json";
}

std::string AccountAuthProvider::resolvePersistentDeviceId(const std::string& sessionFileHint) {
    fs::path uuidPath;
    if (const std::string envUuidFile = readEnvUtf8("GCLIENT_UUID_FILE"); !envUuidFile.empty()) {
        uuidPath = utf8ToFsPath(envUuidFile);
    } else {
        const fs::path sessPath = utf8ToFsPath(sessionFileHint.empty() ? defaultSessionFile() : sessionFileHint);
        uuidPath = sessPath.has_parent_path() ? (sessPath.parent_path() / "device_uuid.txt")
                                              : fs::path("device_uuid.txt");
    }

    std::error_code ec;
    if (fs::is_regular_file(uuidPath, ec)) {
        std::ifstream ifs(uuidPath, std::ios::binary);
        std::string existing;
        if (ifs.is_open() && std::getline(ifs, existing)) {
            existing = trimCopy(existing);
            if (isValidHexTokenId(existing)) return existing;
        }
    }

    const auto nowNs = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    const std::string generated = md5Hex(
        "gclient_win32_device_" + std::to_string(nowNs) + "_" + fsPathToUtf8(uuidPath), false);

    if (uuidPath.has_parent_path()) {
        fs::create_directories(uuidPath.parent_path(), ec);
    }
    std::ofstream ofs(uuidPath, std::ios::binary | std::ios::trunc);
    if (ofs.is_open()) ofs << generated << "\n";
    return generated;
}

bool AccountAuthProvider::purgePoisonedLocalAppDataSession() {
    const std::string localAppData = readEnvUtf8("LOCALAPPDATA");
    if (localAppData.empty()) return false;

    bool purgedAny = false;
    const fs::path base = utf8ToFsPath(localAppData);
    for (const fs::path& cand : {
             base / "GCLIENT_AXMOL" / "account_session.json",
             base / "GCLIENT_AXMOL" / "profiles" / "default" / "account_session.json",
             base / "GCLIENT" / "account_session.json"}) {
        std::error_code ec;
        std::string json;
        if (!fs::is_regular_file(cand, ec) || !readFileText(cand, json)) continue;
        if (isOfflineStubToken(gclient::json::extractStringOr(json, "token"))) {
            fs::remove(cand, ec);
            if (!ec) purgedAny = true;
        }
    }
    return purgedAny;
}

AccountAuthProvider::AccountAuthProvider() {
    purgePoisonedLocalAppDataSession();
}

AccountAuthProvider::AccountAuthProvider(Config config) : config_(std::move(config)) {
    purgePoisonedLocalAppDataSession();
}

AccountAuthProvider::~AccountAuthProvider() {
    cancelPendingLogin();
}

AccountAuthProvider::Config AccountAuthProvider::getConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

std::string AccountAuthProvider::resolveSessionFilePath() const {
    std::string explicitPath;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        explicitPath = config_.sessionFilePath;
    }
    return explicitPath.empty() ? defaultSessionFile() : explicitPath;
}

void AccountAuthProvider::cancelPendingLogin() {
    cancelRequested_.store(true, std::memory_order_release);
    reclaimWorkerThread(workerThread_);
    {
        std::lock_guard<std::mutex> cbLock(callbackMutex_);
        if (!coalescedLoginCallbacks_.empty()) {
            AuthResult cancelledRes{false, false, -3, "Login cancelled", {}};
            for (auto& waiter : coalescedLoginCallbacks_) {
                if (waiter) pendingCallbacks_.emplace_back(std::move(waiter), cancelledRes);
            }
            coalescedLoginCallbacks_.clear();
        }
    }
    loginInProgress_.store(false, std::memory_order_release);
    cancelRequested_.store(false, std::memory_order_release);
}

bool AccountAuthProvider::initialize(const std::map<std::string, std::string>& initParams) {
    purgePoisonedLocalAppDataSession();
    std::lock_guard<std::mutex> lock(mutex_);

    auto pickFirst = [&](std::initializer_list<const char*> keys, std::string& target) {
        for (const char* k : keys) {
            if (auto it = initParams.find(k); it != initParams.end()) {
                if (std::string v = trimCopy(it->second); !v.empty()) {
                    target = std::move(v);
                    return;
                }
            }
        }
    };

    pickFirst({"gn"}, config_.gameId);
    pickFirst({"auth_url"}, config_.authorizeUrl);
    pickFirst({"token_url"}, config_.tokenUrl);
    pickFirst({"ghk", "appKey", "app_key", "auth_secret"}, config_.ghk);
    pickFirst({"gameID", "gtsdk_game_id"}, config_.gtsdkGameId);
    pickFirst({"userUrl", "user_url", "account_url"}, config_.userUrl);
    pickFirst({"game_version", "gameVersion"}, config_.gameVersion);
    pickFirst({"session_file"}, config_.sessionFilePath);

    config_ = resolveEffectiveAuthConfig(config_);
    initialized_ = true;
    return true;
}

bool AccountAuthProvider::authenticateWithAccount(const std::string& username,
                                                  const std::string& password,
                                                  AuthSession& outSession,
                                                  std::string& outError) {
    if (!callAccountAuth(getConfig(), username, password, outSession, outError, &cancelRequested_)) {
        return false;
    }
    if (!isOfflineStubToken(outSession.token)) saveCachedSession(outSession);
    std::lock_guard<std::mutex> lock(mutex_);
    session_ = outSession;
    return true;
}

bool AccountAuthProvider::authenticateAsGuest(AuthSession& outSession, std::string& outError) {
    if (!callGuestAuth(getConfig(), resolveSessionFilePath(), outSession, outError, &cancelRequested_)) {
        return false;
    }
    if (!isOfflineStubToken(outSession.token)) saveCachedSession(outSession);
    std::lock_guard<std::mutex> lock(mutex_);
    session_ = outSession;
    return true;
}

void AccountAuthProvider::completeInFlightLogin(AuthCallback primaryCb, const AuthResult& res) {
    std::vector<AuthCallback> extraWaiters;
    std::lock_guard<std::mutex> lock(callbackMutex_);
    extraWaiters.swap(coalescedLoginCallbacks_);
    loginInProgress_.store(false, std::memory_order_release);
    if (primaryCb) pendingCallbacks_.emplace_back(std::move(primaryCb), res);
    for (auto& w : extraWaiters) {
        if (w) pendingCallbacks_.emplace_back(std::move(w), res);
    }
}

void AccountAuthProvider::login(AuthCallback onComplete) {
    {
        std::lock_guard<std::mutex> cbLock(callbackMutex_);
        bool expected = false;
        if (!loginInProgress_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            if (onComplete) coalescedLoginCallbacks_.push_back(std::move(onComplete));
            return;
        }
    }

    purgePoisonedLocalAppDataSession();

    const std::string envPid = readEnvUtf8("GCLIENT_ACCOUNT_PID");
    const std::string envTok = readEnvUtf8("GCLIENT_ACCOUNT_TOKEN");
    if (!envPid.empty() && !envTok.empty()) {
        AuthResult res{true, false, 0, {}, AuthSession{envPid, envTok, envPid, {}, true, 0}};
        {
            std::lock_guard<std::mutex> lock(mutex_);
            session_ = res.session;
        }
        completeInFlightLogin(std::move(onComplete), res);
        return;
    }

    if (AuthSession cached; tryLoadCachedSession(cached)) {
        AuthResult res{true, true, 0, {}, cached};
        {
            std::lock_guard<std::mutex> lock(mutex_);
            session_ = cached;
        }
        completeInFlightLogin(std::move(onComplete), res);
        return;
    }

    reclaimWorkerThread(workerThread_);
    cancelRequested_.store(false, std::memory_order_release);

    const Config cfgSnapshot = getConfig();
    const std::string sessFileHint = resolveSessionFilePath();
    const bool headlessBootstrap = isHeadlessAuthEnvironment();

    std::thread nextWorker([this, cfgSnapshot, sessFileHint, headlessBootstrap, cb = std::move(onComplete)]() mutable {
        AuthResult result;
        AuthSession sess;
        std::string err;

#ifdef _WIN32
        const bool authenticated = headlessBootstrap
            ? callGuestAuth(cfgSnapshot, sessFileHint, sess, err, &cancelRequested_)
            : showNativeWin32LoginDialog(this, cfgSnapshot, sess, err, cancelRequested_);
#else
        (void)headlessBootstrap;
        const bool authenticated = callGuestAuth(cfgSnapshot, sessFileHint, sess, err, &cancelRequested_);
#endif

        if (authenticated) {
            result.success = true;
            result.session = sess;
            if (!isOfflineStubToken(sess.token)) saveCachedSession(sess);
            std::lock_guard<std::mutex> lock(mutex_);
            session_ = sess;
        } else {
            result.errorCode = cancelRequested_.load(std::memory_order_acquire) ? -3 : -2;
            result.errorMessage = err;
        }
        completeInFlightLogin(std::move(cb), result);
    });

    reclaimWorkerThread(workerThread_);
    std::lock_guard<std::mutex> workerLock(workerThreadLifecycleMutex());
    workerThread_ = std::move(nextWorker);
}

void AccountAuthProvider::logout(LogoutCallback onComplete) {
    cancelPendingLogin();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        session_ = AuthSession{};
    }
    clearCachedSession();
    purgePoisonedLocalAppDataSession();
    if (onComplete) onComplete(true);
}

bool AccountAuthProvider::isAuthenticated() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_.authenticated;
}

AuthSession AccountAuthProvider::currentSession() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_;
}

void AccountAuthProvider::poll() {
    std::deque<std::pair<AuthCallback, AuthResult>> batch;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        batch.swap(pendingCallbacks_);
    }
    for (auto& [cb, res] : batch) {
        if (cb) cb(res);
    }
}

void AccountAuthProvider::enqueueResult(AuthCallback cb, AuthResult res) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    pendingCallbacks_.emplace_back(std::move(cb), std::move(res));
}

bool AccountAuthProvider::tryLoadCachedSession(AuthSession& outSession) const {
    const std::string path = resolveSessionFilePath();
    if (path.empty()) return false;

    const fs::path fsPath = utf8ToFsPath(path);
    std::error_code ec;
    std::string json;
    if (!fs::is_regular_file(fsPath, ec) || !readFileText(fsPath, json)) {
        return false;
    }

    const std::string pid = gclient::json::extractStringOr(json, "pid");
    const std::string token = gclient::json::extractStringOr(json, "token");
    const std::string username = gclient::json::extractStringOr(json, "username");
    if (isOfflineStubToken(token) || pid.empty()) {
        fs::remove(fsPath, ec);
        return false;
    }

    outSession.pid = pid;
    outSession.token = token;
    outSession.username = username.empty() ? pid : username;
    outSession.authenticated = true;
    return true;
}

void AccountAuthProvider::saveCachedSession(const AuthSession& session) const {
    if (session.pid.empty() || isOfflineStubToken(session.token)) return;
    const std::string path = resolveSessionFilePath();
    if (path.empty()) return;

    std::error_code ec;
    const fs::path p = utf8ToFsPath(path);
    if (p.has_parent_path()) fs::create_directories(p.parent_path(), ec);
    const fs::path tmpPath = p.parent_path() / (fsPathToUtf8(p.filename()) + ".tmp");
    {
        std::ofstream ofs(tmpPath, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return;
        ofs << gclient::json::JsonObjectBuilder()
                   .kv("pid", session.pid)
                   .kv("token", session.token)
                   .kv("username", session.username)
                   .finish()
            << "\n";
        ofs.flush();
        if (!ofs.good()) {
            ofs.close();
            fs::remove(tmpPath, ec);
            return;
        }
    }
#ifdef _WIN32
    if (!::MoveFileExW(tmpPath.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        fs::remove(tmpPath, ec);
    }
#else
    fs::rename(tmpPath, p, ec);
    if (ec) fs::remove(tmpPath, ec);
#endif
}

void AccountAuthProvider::clearCachedSession() const {
    if (const std::string path = resolveSessionFilePath(); !path.empty()) {
        std::error_code ec;
        fs::remove(utf8ToFsPath(path), ec);
    }
}

} // namespace bt
