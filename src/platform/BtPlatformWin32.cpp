#include "BtPlatformWin32.h"
#include "platform/AccountAuthProvider.h"
#include "assets/BtDecryptHook.h"
#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelHttp.h"
#include "common/KestrelJson.h"
#include "common/KestrelUtf8.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <thread>

#ifdef _WIN32
#include <shellapi.h>
#endif

#ifdef poll
#undef poll
#endif

namespace bt {

namespace {

using gclient::common::trimAscii;
using gclient::common::trimCopy;
using gclient::json::JsonObjectBuilder;
using gclient::json::JsonValue;
using gclient::utf8::firstNonEmptyEnv;
using gclient::utf8::readEnvBool;
using gclient::utf8::readEnvUtf8;
using gclient::utf8::utf8ToFsPath;

constexpr int kInternalRetryInteractiveLoginEventId = -1001;

gclient::http::MainThreadEventQueue<PendingCallback>& callbackEventQueue() {
    static auto* s_queue = new gclient::http::MainThreadEventQueue<PendingCallback>();
    return *s_queue;
}

std::string jsonValueToConfigScalar(const JsonValue& v) {
    if (v.isNull()) return {};
    if (v.isString()) return v.strVal;
    if (v.isBool()) return v.boolVal ? "true" : "false";
    if (v.type == JsonValue::Type::Int) return std::to_string(v.intVal);
    return v.dump();
}

bool parseJsonToConfigDocument(std::string_view jsonText, ConfigDocument& outDoc) {
    JsonValue root;
    if (!gclient::json::parse(jsonText, root) || !root.isObject()) return false;
    for (const auto& [k, v] : root.objVal) {
        if (v.isObject()) {
            std::map<std::string, std::string> child;
            for (const auto& [ck, cv] : v.objVal) {
                child[ck] = jsonValueToConfigScalar(cv);
            }
            outDoc.objects[k] = std::move(child);
        } else {
            outDoc.values[k] = jsonValueToConfigScalar(v);
        }
    }
    return true;
}

std::string getSdkCookieJarPath() {
    std::string dir = readEnvUtf8("GCLIENT_WRITABLE_DIR");
    if (!dir.empty()) {
        if (dir.back() != '/' && dir.back() != '\\') {
#ifdef _WIN32
            dir.push_back('\\');
#else
            dir.push_back('/');
#endif
        }
        return dir + "sdk_cookies.txt";
    }
    return "sdk_cookies.txt";
}

bool performSharedHttpGet(const std::string& url,
                          std::string& outBody,
                          long& outHttpCode,
                          std::string& outErr) {
    outBody.clear();
    outHttpCode = 0;
    outErr.clear();
#if !GCLIENT_HTTP_HAS_CURL
    (void)url;
    outErr = "libcurl headers unavailable in standalone test build";
    return false;
#else
    static std::mutex* s_cookieIoMutex = new std::mutex();
    std::lock_guard<std::mutex> cookieLock(*s_cookieIoMutex);
    const bool verifyPeer = !readEnvBool({"GCLIENT_INSECURE_TLS"}, false);
    const std::string caBundle = firstNonEmptyEnv({"GCLIENT_CA_BUNDLE", "CURL_CA_BUNDLE"});
    auto res = gclient::http::performCurlRequest(
        url, nullptr, getSdkCookieJarPath(), 10000, 20000, verifyPeer, caBundle);
    outBody = std::move(res.body);
    outHttpCode = res.statusCode;
    outErr = std::move(res.error);
    return res.ok();
#endif
}

bool decryptDesConfigBuffer(const uint8_t* rawBytes, size_t rawSize, std::string& outJson) {
    if (rawSize <= 8 || std::memcmp(rawBytes, "F0F0F0F0", 8) != 0 || ((rawSize - 8) % 8) != 0) {
        return false;
    }
    // Ported from libnew_sdk.so DES_Decrypt2Buffer (LSB-first Char8ToBit64 + exact PC2 table)
    static constexpr int kIp[64] = {
        57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3, 61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7,
        56,48,40,32,24,16,8,0, 58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4, 62,54,46,38,30,22,14,6
    };
    static constexpr int kIp1[64] = {
        39,7,47,15,55,23,63,31, 38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29, 36,4,44,12,52,20,60,28,
        35,3,43,11,51,19,59,27, 34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25, 32,0,40,8,48,16,56,24
    };
    static constexpr int kE[48] = {
        31,0,1,2,3,4, 3,4,5,6,7,8, 7,8,9,10,11,12, 11,12,13,14,15,16,
        15,16,17,18,19,20, 19,20,21,22,23,24, 23,24,25,26,27,28, 27,28,29,30,31,0
    };
    static constexpr int kP[32] = {
        15,6,19,20,28,11,27,16, 0,14,22,25,4,17,30,9, 1,7,23,13,31,26,2,8, 18,12,29,5,21,10,3,24
    };
    static constexpr int kPc1[56] = {
        56,48,40,32,24,16,8, 0,57,49,41,33,25,17, 9,1,58,50,42,34,26, 18,10,2,59,51,43,35,
        62,54,46,38,30,22,14, 6,61,53,45,37,29,21, 13,5,60,52,44,36,28, 20,12,4,27,19,11,3
    };
    static constexpr int kPc2[48] = {
        13,16,10,23,0,4, 2,27,14,5,20,9, 22,18,11,3,25,7, 15,6,26,19,12,1,
        40,51,30,36,46,54, 29,39,50,44,32,46, 43,48,38,55,33,52, 45,41,49,35,28,31
    };
    static constexpr int kShifts[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
    static constexpr uint8_t kS[8][64] = {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    };

    uint8_t keyBits[64]{};
    for (int i = 0; i < 8; ++i) {
        const uint8_t ch = static_cast<uint8_t>(Platform::kDefaultConfigDesKey[i]);
        for (int b = 0; b < 8; ++b) keyBits[i * 8 + b] = (ch >> b) & 1;
    }
    uint8_t cd[56]{};
    for (int i = 0; i < 56; ++i) cd[i] = keyBits[kPc1[i]];
    uint8_t subkeys[16][48]{};
    for (int r = 0; r < 16; ++r) {
        const int sh = kShifts[r];
        uint8_t tmp[56];
        std::memcpy(tmp, cd, 56);
        for (int i = 0; i < 28; ++i) {
            cd[i] = tmp[(i + sh) % 28];
            cd[28 + i] = tmp[28 + (i + sh) % 28];
        }
        for (int i = 0; i < 48; ++i) subkeys[r][i] = cd[kPc2[i]];
    }

    const uint8_t* enc = rawBytes + 8;
    const size_t encLen = rawSize - 8;
    std::vector<uint8_t> dec(encLen);
    for (size_t off = 0; off < encLen; off += 8) {
        uint8_t blkBits[64]{}, ipBits[64]{};
        for (int i = 0; i < 8; ++i) {
            const uint8_t ch = enc[off + i];
            for (int b = 0; b < 8; ++b) blkBits[i * 8 + b] = (ch >> b) & 1;
        }
        for (int i = 0; i < 64; ++i) ipBits[i] = blkBits[kIp[i]];
        uint8_t L[32], R[32];
        std::memcpy(L, ipBits, 32);
        std::memcpy(R, ipBits + 32, 32);
        for (int r = 15; r >= 0; --r) {
            uint8_t ep[48], sb[32], f[32];
            for (int i = 0; i < 48; ++i) ep[i] = R[kE[i]] ^ subkeys[r][i];
            for (int i = 0; i < 8; ++i) {
                const uint8_t* g = ep + i * 6;
                const uint8_t val = kS[i][g[0] * 32 + g[5] * 16 + g[1] * 8 + g[2] * 4 + g[3] * 2 + g[4]];
                sb[i * 4 + 0] = (val >> 3) & 1;
                sb[i * 4 + 1] = (val >> 2) & 1;
                sb[i * 4 + 2] = (val >> 1) & 1;
                sb[i * 4 + 3] = val & 1;
            }
            for (int i = 0; i < 32; ++i) f[i] = sb[kP[i]] ^ L[i];
            std::memcpy(L, R, 32);
            std::memcpy(R, f, 32);
        }
        uint8_t rl[64], outBits[64];
        std::memcpy(rl, R, 32);
        std::memcpy(rl + 32, L, 32);
        for (int i = 0; i < 64; ++i) outBits[i] = rl[kIp1[i]];
        for (int i = 0; i < 8; ++i) {
            uint8_t v = 0;
            for (int b = 0; b < 8; ++b) v |= static_cast<uint8_t>(outBits[i * 8 + b] << b);
            dec[off + i] = v;
        }
    }
    while (!dec.empty() && dec.back() == 0) dec.pop_back();
    outJson.assign(reinterpret_cast<const char*>(dec.data()), dec.size());
    return true;
}

const std::array<CapabilityShimEntry, 26> kCapabilityShimTable = {{
    {"pay",                       "billing",   true,  kPay,             kHttpSuccess, "{\"errornu\":\"0\",\"errordesc\":\"ok\"}"},
    {"issueDJOrders",             "billing",   true,  kIssueDJOrders,   kHttpFailed,  "{\"code\":-1,\"msg\":\"Win32: DJ orders unsupported\"}"},
    {"shareWeixin",               "social",    true,  kShareBack,       kHttpFailed,  "{\"code\":-1,\"msg\":\"Win32: WeChat sharing unsupported\"}"},
    {"playVideo",                 "media",     true,  kPlayFinish,      kHttpSuccess, "{\"code\":0,\"msg\":\"Win32: video playback skipped\"}"},
    {"openCustomWebView",         "webview",   false, 0,                kHttpSuccess, "{}"},
    {"closeCustomWebView",        "webview",   false, 0,                kHttpSuccess, "{}"},
    {"doCustomWebViewAction",     "webview",   false, 0,                kHttpSuccess, "{}"},
    {"showToolBar",               "sdk_ui",    false, 0,                kHttpSuccess, "{}"},
    {"hideToolBar",               "sdk_ui",    false, 0,                kHttpSuccess, "{}"},
    {"enterUserCenter",           "sdk_ui",    false, 0,                kHttpSuccess, "{}"},
    {"accountSwitch",             "sdk_ui",    false, 0,                kHttpSuccess, "{}"},
    {"pause",                     "lifecycle", false, 0,                kHttpSuccess, "{}"},
    {"onPressBack",               "lifecycle", false, 0,                kHttpSuccess, "{}"},
    {"quit",                      "lifecycle", true,  kQuit,            kHttpSuccess, "{\"code\":0,\"msg\":\"Win32: quit acknowledged\"}"},
    {"sendInformationToPlatform", "tracking",  false, 0,                kHttpSuccess, "{}"},
    {"sendTracking",              "tracking",  false, 0,                kHttpSuccess, "{}"},
    {"retention",                 "tracking",  false, 0,                kHttpSuccess, "{}"},
    {"sendLog",                   "tracking",  false, 0,                kHttpSuccess, "{}"},
    {"sendAdstat",                "tracking",  false, 0,                kHttpSuccess, "{}"},
    {"push",                      "push",      false, 0,                kHttpSuccess, "{}"},
    {"registerPush",              "push",      false, 0,                kHttpSuccess, "{}"},
    {"unregisterPush",            "push",      false, 0,                kHttpSuccess, "{}"},
    {"showMessage",               "ui",        false, 0,                kHttpSuccess, "{}"},
    {"searchHandleUrl",           "deeplink",  false, 0,                kHttpSuccess, "{}"},
    {"getNetworkCapture",         "diag",      true,  kNetworkCapture,  kHttpSuccess, "{\"code\":0,\"data\":{}}"},
    {"openUrl",                   "browser",   false, 0,                kHttpSuccess, "{}"},
}};

enum class MapiRouteId : uint8_t {
    ServerList = 0, VersionInfo, LoginedServerInfo, Notice, SuperNotice,
    AppleReview, Question, UserInformation, BrowseActive, ForceFix,
    Hash, HashSimulation
};

struct MapiRouteSpec {
    MapiRouteId id;
    int eventId;
    const char* endpoint;
    bool isHashRoute;
    bool requireLoginPid;
    bool useSimulationHost;
};

constexpr std::array<MapiRouteSpec, 12> kMapiRoutes = {{
    {MapiRouteId::ServerList,        kGetServerlist,        "serverlist",  false, false, false},
    {MapiRouteId::VersionInfo,       kGetVersion,           "getversion",  false, false, false},
    {MapiRouteId::LoginedServerInfo, kGetLoginedServerInfo, "loginrole",   false, false, false},
    {MapiRouteId::Notice,            kGetNotice,            "notice",      false, false, false},
    {MapiRouteId::SuperNotice,       kGetSuperNotice,       "supernotice", false, false, false},
    {MapiRouteId::AppleReview,       kGetAppleReview,       "applereview", false, false, false},
    {MapiRouteId::Question,          kQuestion,             "question",    false, false, false},
    {MapiRouteId::UserInformation,   kGetUserInformation,   "userinfo",    false, false, false},
    {MapiRouteId::BrowseActive,      kGetBrowseActive,      "innerbrowse", false, false, false},
    {MapiRouteId::ForceFix,          kGetForceFix,          "getforcefix", false, false, false},
    {MapiRouteId::Hash,              kGetHash,              "gethash",     true,  true,  false},
    {MapiRouteId::HashSimulation,    kGetHash,              "gethash",     true,  false, true},
}};

std::shared_ptr<IAuthProvider> createDefaultAuthProvider() {
    if (readEnvUtf8("GCLIENT_USE_LOCAL_STUB_AUTH") == "1") {
        return std::make_shared<LocalStubAuthProvider>();
    }
    return std::make_shared<AccountAuthProvider>();
}

std::string buildLoginSuccessJson(std::string_view resolvedPid, const AuthSession& sess) {
    return JsonObjectBuilder()
        .kv("errornu", "0")
        .kv("errordesc", "ok")
        .kv("uid", resolvedPid)
        .kv("pid", resolvedPid)
        .kv("token", sess.token)
        .kv("username", sess.username)
        .kv("newuser", "0")
        .finish();
}

} // namespace

Platform* Platform::getInstance() {
    static Platform* instance = new Platform();
    return instance;
}

Platform::Platform()
    : authProvider_(createDefaultAuthProvider()),
      uuid_(AccountAuthProvider::resolvePersistentDeviceId()) {
#if GCLIENT_HTTP_HAS_CURL
    gclient::http::ensureCurlGlobalInit();
#endif
}

Platform::~Platform() {
    shuttingDown_.store(true);
}

void Platform::setAuthProvider(std::shared_ptr<IAuthProvider> provider) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (provider) authProvider_ = std::move(provider);
}

std::shared_ptr<IAuthProvider> Platform::getAuthProvider() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return authProvider_;
}

void Platform::setDesDecryptor(std::shared_ptr<IDesDecryptor> decryptor) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    desDecryptor_ = std::move(decryptor);
}

void Platform::setLogHandler(LogHandler handler) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    logHandler_ = std::move(handler);
}

void Platform::setCallbackHandler(CallbackHandler handler) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    callbackHandler_ = std::move(handler);
}

void Platform::setSyncCallbackHandler(CallbackHandler handler) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    syncCallbackHandler_ = std::move(handler);
}

void Platform::setWebViewBridgeHandler(WebViewBridgeHandler handler) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    webViewBridgeHandler_ = std::move(handler);
}

void Platform::dispatchWebViewBridge(const std::string& action, int x, int y, int width, int height,
                                     const std::string& url) {
    WebViewBridgeHandler handler;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        handler = webViewBridgeHandler_;
    }
    if (handler) {
        handler(action, x, y, width, height, url);
    } else if (action == "updateURL" && !url.empty()) {
        openUrl(url);
    }
}

void Platform::setResourceRoot(const std::string& rootPath) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    resourceRoot_ = rootPath;
    if (!resourceRoot_.empty() && resourceRoot_.back() != '/' && resourceRoot_.back() != '\\') {
        resourceRoot_.push_back('/');
    }
}

void Platform::log(const std::string& level, const std::string& message) const {
    LogHandler handler;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        handler = logHandler_;
    }
    if (handler) {
        handler(level, message);
    } else {
        std::fprintf(stderr, "[bt::Platform][%s] %s\n", level.c_str(), message.c_str());
    }
}

bool Platform::readBinaryFile(const std::string& path, std::vector<uint8_t>& outBytes) const {
    std::ifstream ifs(utf8ToFsPath(path), std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) return false;
    const std::streamsize size = ifs.tellg();
    if (size <= 0) return false;
    ifs.seekg(0, std::ios::beg);
    outBytes.resize(static_cast<size_t>(size));
    if (!ifs.read(reinterpret_cast<char*>(outBytes.data()), size)) return false;
    size_t len = outBytes.size();
    if (gclient::assets::DecryptBuffer(outBytes.data(), &len, path.c_str(), nullptr)) {
        outBytes.resize(len);
    }
    return true;
}

std::string Platform::resolveConfigPath(const std::string& relativePath) const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return resourceRoot_.empty() ? relativePath : (resourceRoot_ + relativePath);
}

std::vector<std::string> Platform::buildConfigSearchRoots() const {
    std::string rootCopy;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        rootCopy = resourceRoot_;
    }

    auto normalizeRoot = [](std::string_view raw) -> std::string {
        std::string r = trimCopy(raw);
        std::replace(r.begin(), r.end(), '\\', '/');
        if (!r.empty() && r.back() != '/') r.push_back('/');
        return r;
    };

    std::vector<std::string> roots;
    auto addUnique = [&](std::string_view raw, bool allowEmpty) {
        std::string norm = (allowEmpty && raw.empty()) ? std::string() : normalizeRoot(raw);
        if (!allowEmpty && norm.empty()) return;
        if (std::find(roots.begin(), roots.end(), norm) == roots.end()) {
            roots.push_back(std::move(norm));
        }
    };

    addUnique(rootCopy, false);
    for (const char* envKey : {"GCLIENT_BASE_ASSETS_DIR", "GCLIENT_ASSETS_DIR", "GCLIENT_RESOURCES_DIR"}) {
        addUnique(readEnvUtf8(envKey), false);
    }
    for (const char* rel : {"base_assets/", "assets/", "Resources/"}) {
        addUnique(rel, false);
    }
    addUnique("", true);
    return roots;
}

ConfigDocument Platform::loadConfig(const std::string& relativePath) const {
    log("debug", "loadConfig: " + relativePath);

    std::string dirCopy;
    std::shared_ptr<IDesDecryptor> decryptor;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        dirCopy = platformDir_;
        decryptor = desDecryptor_;
    }
    if (!dirCopy.empty() && dirCopy.back() != '/' && dirCopy.back() != '\\') dirCopy.push_back('/');

    std::string relNorm = relativePath;
    while (!relNorm.empty() && (relNorm.front() == '/' || relNorm.front() == '\\')) {
        relNorm.erase(relNorm.begin());
    }

    std::vector<uint8_t> rawBytes;
    bool loaded = false;
    for (const std::string& root : buildConfigSearchRoots()) {
        if (!dirCopy.empty()) {
            const std::string overridePath = root + dirCopy + relNorm;
            log("debug", "filePath candidate = " + overridePath);
            rawBytes.clear();
            if (readBinaryFile(overridePath, rawBytes) && !rawBytes.empty()) {
                log("release", "filePath = " + overridePath);
                loaded = true;
                break;
            }
        }
        const std::string candidatePath = root + relNorm;
        log("debug", "filename candidate = " + candidatePath);
        rawBytes.clear();
        if (readBinaryFile(candidatePath, rawBytes) && !rawBytes.empty()) {
            log("release", "filename = " + candidatePath);
            loaded = true;
            break;
        }
    }

    ConfigDocument doc;
    if (!loaded || rawBytes.empty()) {
        log("debug", "Failed to readFile " + relativePath);
        return doc;
    }

    const std::string_view rawSv(reinterpret_cast<const char*>(rawBytes.data()), rawBytes.size());
    const std::string_view trimmed = trimAscii(rawSv);
    std::string jsonText;
    if (!trimmed.empty() && (trimmed.front() == '{' || trimmed.front() == '[')) {
        jsonText.assign(rawSv);
    } else if (decryptor) {
        if (!decryptor->decrypt(rawBytes.data(), rawBytes.size(), kDefaultConfigDesKey, jsonText)) {
            log("debug", "Failed to DES_Decrypt2Buffer for " + relativePath);
            return doc;
        }
    } else if (!decryptDesConfigBuffer(rawBytes.data(), rawBytes.size(), jsonText)) {
        log("release", "Encrypted config detected (" + relativePath +
                       ") but no IDesDecryptor registered; attempting raw parse fallback");
        jsonText.assign(rawSv);
    }

    if (!parseJsonToConfigDocument(jsonText, doc)) {
        log("debug", "Failed to parse JSON config: " + relativePath);
    }
    log("debug", "loadConfig end");
    return doc;
}

void Platform::initSDK(const std::string& jsonParam, CallbackHandler callback) {
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        initTimestamp_ = static_cast<int64_t>(std::time(nullptr));
        if (callback) callbackHandler_ = std::move(callback);
        if (!jsonParam.empty()) {
            if (std::string dir = gclient::json::extractStringOr(jsonParam, "platformDir"); !dir.empty()) {
                platformDir_ = std::move(dir);
            }
        }
        isLoggingIn_ = false;
    }

    log("release", "platformDir: " + platformDir_);
    log("release", std::string("initSDK version: ") + kSdkVersion);

    ConfigDocument pCfg = loadConfig("platform/config.json");
    ConfigDocument gCfg = loadConfig("platform/game_config.json");

    std::map<std::string, std::string> initMap;
    std::shared_ptr<IAuthProvider> provider;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        platformConfig_ = std::move(pCfg);
        gameConfig_ = std::move(gCfg);

        if (platformConfig_.hasKey("debug")) {
            char* endp = nullptr;
            const std::string dbg = platformConfig_.getString("debug");
            const long v = std::strtol(dbg.c_str(), &endp, 10);
            debugLevel_ = (endp && endp != dbg.c_str() && *endp == '\0') ? static_cast<int>(v) : 0;
        }

        payConfig_ = platformConfig_.getObject("pay");
        localizedConfig_ = gameConfig_.getObject("localized");
        initMap = gameConfig_.values;
        for (const auto& [k, v] : platformConfig_.values) initMap[k] = v;
        for (const auto& [k, v] : platformConfig_.getObject("init")) initMap[k] = v;

        if (platformConfig_.hasKey("isSimulation")) {
            isSimulation_ = (platformConfig_.getString("isSimulation") == "1");
            log("release", "isSimulation=" + std::to_string(isSimulation_ ? 1 : 0));
        }
        if (platformConfig_.hasKey("simulateHashHost")) {
            simulationHashHost_ = platformConfig_.getString("simulateHashHost");
            log("release", "_simulationHashHost=" + simulationHashHost_);
        }
        if (platformConfig_.hasKey("isStandAlone")) {
            isStandAlone_ = (platformConfig_.getString("isStandAlone") == "1");
            log("release", "_isStandAlone=" + std::to_string(isStandAlone_ ? 1 : 0));
        }
        if (gameConfig_.hasKey("pushurl")) pushUrl_ = gameConfig_.getString("pushurl");
        if (gameConfig_.hasKey("gn")) gnOverride_ = gameConfig_.getString("gn");

        combinedPl_ = platformConfig_.getString("pl", "vnsg2");
        if (platformConfig_.hasKey("other_pl")) {
            combinedPl_ = platformConfig_.getString("other_pl") + "|" + combinedPl_;
        }

        uuid_ = AccountAuthProvider::resolvePersistentDeviceId();
        isInitialized_ = true;
        provider = authProvider_;
    }

    if (provider) {
        const bool ok = provider->initialize(initMap);
        log("release", "AuthProvider '" + provider->providerName() + "' initialize=" + (ok ? "ok" : "failed"));
    }

    log("release", "initSDK end");
    receiveCallBack(kInit, kHttpSuccess, "{\"errornu\":\"0\",\"errordesc\":\"ok\"}");
}

void Platform::tickLoop() {
    bool initialized = false;
    std::shared_ptr<IAuthProvider> provider;
    CallbackHandler mainCb;
    CallbackHandler syncCb;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        initialized = isInitialized_;
        provider = authProvider_;
        mainCb = callbackHandler_;
        syncCb = syncCallbackHandler_;
    }
    if (!initialized) return;
    if (provider) provider->poll();

    std::vector<PendingCallback> batch;
    callbackEventQueue().drain(batch);
    for (const auto& item : batch) {
        if (item.eventId == kInternalRetryInteractiveLoginEventId) {
            if (std::shared_ptr<IAuthProvider> retryProv = getAuthProvider()) {
                retryProv->logout(nullptr);
                startLoginAttempt(false);
                retryProv->poll();
            } else {
                startLoginAttempt(false);
            }
            continue;
        }
        if (mainCb) mainCb(item.eventId, item.statusCode, item.payload);
        if (syncCb) syncCb(item.eventId, item.statusCode, item.payload);
    }
}

void Platform::receiveCallBack(int eventId, int statusCode, const std::string& payload) {
    callbackEventQueue().push(PendingCallback{eventId, statusCode, payload});
}

void Platform::registeCallBackBySync(CallbackHandler handler) {
    setSyncCallbackHandler(std::move(handler));
}

void Platform::login() {
    startLoginAttempt(true);
}

void Platform::startLoginAttempt(bool allowInteractiveRetryOnExpiredCache) {
    log("debug", "login");

    std::shared_ptr<IAuthProvider> provider;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        if (isSimulation_) {
            log("release", "is simulation, skip login");
            return;
        }
        if (!isInitialized_ || isLoggingIn_) {
            log("release", "not init or loginning");
            return;
        }
        isLoggingIn_ = true;
        provider = authProvider_;
    }

    if (!provider) {
        {
            std::lock_guard<std::recursive_mutex> lock(stateMutex_);
            isLoggingIn_ = false;
        }
        receiveCallBack(kLogin, kHttpFailed,
                        "{\"errornu\":\"1\",\"code\":-1,\"errordesc\":\"No IAuthProvider configured\",\"msg\":\"No IAuthProvider configured\"}");
        return;
    }

    provider->login([this, allowInteractiveRetryOnExpiredCache](const AuthResult& result) {
        if (shuttingDown_.load()) return;

        auto resetLoginState = [&]() -> std::shared_ptr<IAuthProvider> {
            std::lock_guard<std::recursive_mutex> lock(stateMutex_);
            isLoggingIn_ = false;
            isLogined_ = false;
            pid_.clear();
            sessionToken_.clear();
            return authProvider_;
        };

        if (!result.success) {
            (void)resetLoginState();
            receiveCallBack(
                kLogin,
                kHttpFailed,
                JsonObjectBuilder()
                    .kv("errornu", "1")
                    .kvInt("code", result.errorCode)
                    .kv("errordesc", result.errorMessage)
                    .finish());
            return;
        }

        if (AccountAuthProvider::isOfflineStubToken(result.session.token)) {
            {
                std::lock_guard<std::recursive_mutex> lock(stateMutex_);
                isLoggingIn_ = false;
                isLogined_ = true;
                pid_ = result.session.pid;
                sessionToken_ = result.session.token;
            }
            receiveCallBack(kLogin, kHttpSuccess, buildLoginSuccessJson(result.session.pid, result.session));
            return;
        }

        const std::string uuid = getUUID();
        const std::string rawLoginUrl = getHost() + getStandAlone() +
                                        "/login?userid=" + urlEncode(result.session.pid) +
                                        "&sessionid=" + urlEncode(result.session.token) +
                                        getUrlParam() +
                                        "&bind=" + urlEncode(uuid) +
                                        "&uuid=" + urlEncode(uuid) +
                                        "&country=VN";
        const std::string signedLoginUrl = signUrl(rawLoginUrl);
        log("debug", "login exchange url=" + signedLoginUrl);

        std::thread([this, result, signedLoginUrl, allowInteractiveRetryOnExpiredCache]() {
            if (shuttingDown_.load()) return;
            std::string body, errMsg;
            long httpCode = 0;
            const bool ok = performSharedHttpGet(signedLoginUrl, body, httpCode, errMsg);
            if (shuttingDown_.load()) return;

            auto tryMarshalCachedRetry = [&](const std::shared_ptr<IAuthProvider>& prov,
                                             const std::string& reasonLog) -> bool {
                if (!prov || !result.fromCache || !allowInteractiveRetryOnExpiredCache) return false;
#ifdef _WIN32
                log("release", reasonLog);
                receiveCallBack(kInternalRetryInteractiveLoginEventId, 0, "");
                return true;
#else
                (void)reasonLog;
                if (prov->providerName() != "AccountAuthProvider") {
                    receiveCallBack(kInternalRetryInteractiveLoginEventId, 0, "");
                    return true;
                }
                return false;
#endif
            };

            if (!ok) {
                std::shared_ptr<IAuthProvider> prov;
                {
                    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
                    isLoggingIn_ = false;
                    isLogined_ = false;
                    pid_.clear();
                    sessionToken_.clear();
                    if (httpCode == 401 || httpCode == 403) prov = authProvider_;
                }
                if (tryMarshalCachedRetry(
                        prov,
                        "Cached Platform token rejected with HTTP " + std::to_string(httpCode) +
                            "; marshaling Win32 Sign-In dialog onto main thread")) {
                    return;
                }
                if (prov) prov->logout(nullptr);
                receiveCallBack(
                    kLogin,
                    kHttpFailed,
                    JsonObjectBuilder()
                        .kv("errornu", "1")
                        .kvInt("code", httpCode)
                        .kv("errordesc", errMsg)
                        .finish());
                return;
            }

            log("debug", "login exchange response: " + body);
            const std::string errNo = gclient::json::extractStringOr(body, "errornu");
            const std::string errDesc = gclient::json::extractStringOr(body, "errordesc");
            std::string candPid = gclient::json::extractStringOr(body, "pid");
            if (candPid.empty()) candPid = gclient::json::extractStringOr(body, "uid");

            if ((!errNo.empty() && errNo != "0") || (errNo.empty() && candPid.empty())) {
                std::shared_ptr<IAuthProvider> prov;
                {
                    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
                    isLoggingIn_ = false;
                    isLogined_ = false;
                    pid_.clear();
                    sessionToken_.clear();
                    prov = authProvider_;
                }
                if (tryMarshalCachedRetry(
                        prov,
                        "Cached Platform session expired (" + errDesc +
                            "); marshaling cache clear and Win32 Sign-In dialog onto main thread")) {
                    return;
                }
                if (prov) prov->logout(nullptr);
                receiveCallBack(
                    kLogin,
                    kHttpFailed,
                    JsonObjectBuilder()
                        .kv("errornu", errNo.empty() ? "1" : errNo)
                        .kv("errordesc", errDesc.empty() ? body : errDesc)
                        .finish());
                return;
            }

            const std::string resolvedPid = candPid.empty() ? result.session.pid : candPid;
            {
                std::lock_guard<std::recursive_mutex> lock(stateMutex_);
                isLoggingIn_ = false;
                isLogined_ = true;
                pid_ = resolvedPid;
                sessionToken_ = result.session.token;
            }
            receiveCallBack(kLogin, kHttpSuccess, buildLoginSuccessJson(resolvedPid, result.session));
        }).detach();
    });
}

void Platform::logout() {
    log("debug", "logout");
    std::shared_ptr<IAuthProvider> provider;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        provider = authProvider_;
        isLogined_ = false;
        isLoggingIn_ = false;
        pid_.clear();
        sessionToken_.clear();
    }
    if (const std::string cookieJar = getSdkCookieJarPath(); !cookieJar.empty()) {
        std::error_code ec;
        std::filesystem::remove(utf8ToFsPath(cookieJar), ec);
    }

    if (provider) {
        provider->logout([this](bool ok) {
            if (!shuttingDown_.load()) {
                receiveCallBack(kLogout, ok ? kHttpSuccess : kHttpFailed, "{\"code\":0}");
            }
        });
    } else {
        receiveCallBack(kLogout, kHttpSuccess, "{\"code\":0}");
    }
}

bool Platform::isLogined() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return isLogined_;
}

std::string Platform::getHost() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    const char* key = isDebugEnv_ ? "host_debug" : "host";
    if (!gameConfig_.hasKey(key)) {
        log("release", std::string("error get ") + key + " from game_config");
        return "null";
    }
    return gameConfig_.getString(key);
}

std::string Platform::getLogHost() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (isDebugEnv_ && gameConfig_.hasKey("log_host_debug")) {
        return gameConfig_.getString("log_host_debug");
    }
    return gameConfig_.getString("log_host", "null");
}

std::string Platform::getStandAlone() const { return "/phone"; }

std::string Platform::getKey() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return platformConfig_.hasKey("key") ? platformConfig_.getString("key") : kDefaultSignKey;
}

std::string Platform::getUrlParam() const {
    std::string param = "&pl=" + getPL() + "&os=" + getOS() + "&gn=" + getGN();
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (platformConfig_.hasKey("other_pl")) param += "&other_pl=" + platformConfig_.getString("other_pl");
    if (gameConfig_.hasKey("language")) param += "&language=" + gameConfig_.getString("language");
    return param;
}

std::string Platform::sortUrlParams(const std::string& url) {
    const size_t qPos = url.find('?');
    const std::string_view query = (qPos == std::string::npos)
        ? std::string_view(url)
        : std::string_view(url).substr(qPos + 1);

    std::vector<std::string_view> parts;
    size_t start = 0;
    while (start <= query.size()) {
        size_t amp = query.find('&', start);
        if (amp == std::string_view::npos) amp = query.size();
        if (amp > start) parts.push_back(query.substr(start, amp - start));
        start = amp + 1;
    }
    std::sort(parts.begin(), parts.end());

    // Exact libnew_sdk.so & cobalt-relay sort_url_params concatenation (WITHOUT '&' between pairs).
    std::string sorted;
    for (std::string_view seg : parts) sorted.append(seg);
    return sorted;
}

std::string Platform::md5Hex(const std::string& data) {
    return gclient::crypto::md5Hex(data, false);
}

std::string Platform::signUrl(const std::string& url) const {
    return signUrl(url, getKey());
}

std::string Platform::signUrl(const std::string& url, const std::string& customKey) const {
    const std::string urlWithTime = url + "&time=" + std::to_string(static_cast<int64_t>(std::time(nullptr)));
    const std::string toSign = sortUrlParams(urlWithTime) + customKey;
    log("debug", "key=" + toSign);
    return urlWithTime + "&sign=" + md5Hex(toSign);
}

std::string Platform::compleUrl(const std::string& url) const {
    std::string out = url;
    auto appendIfAbsent = [&](const char* prefix, const std::string& val) {
        if (out.find(prefix) == std::string::npos) {
            out += (out.find('?') == std::string::npos ? "?" : "&");
            out += prefix + val;
        }
    };
    appendIfAbsent("pl=", getPL());
    appendIfAbsent("os=", getOS());
    appendIfAbsent("gn=", getGN());
    appendIfAbsent("uuid=", getUUID());
    return signUrl(out);
}

std::string Platform::urlEncode(const std::string& raw) {
    return gclient::utf8::urlEncode(raw);
}

std::map<std::string, std::string> Platform::parseFlatJsonObject(const std::string& jsonStr) {
    std::map<std::string, std::string> out;
    JsonValue root;
    if (!jsonStr.empty() && gclient::json::parse(jsonStr, root) && root.isObject()) {
        for (const auto& [k, v] : root.objVal) {
            out[k] = jsonValueToConfigScalar(v);
        }
    }
    return out;
}

std::string Platform::buildQueryFromJson(const std::string& jsonParams) const {
    std::string extra;
    for (const auto& [k, v] : parseFlatJsonObject(jsonParams)) {
        const std::string encoded = urlEncode(v);
        extra += "&" + k + "=" + encoded;
        log("debug", "key=" + k + ",value=" + encoded);
    }
    return extra;
}

void Platform::sendHTTPRequest(int eventId, const std::string& url, bool shouldSign) {
    const std::string finalUrl = shouldSign ? signUrl(url) : url;
    log("debug", "sendHTTPRequest event=" + std::to_string(eventId) + " url=" + finalUrl);

    std::thread([this, eventId, finalUrl]() {
        if (shuttingDown_.load()) return;
        std::string responseBody, errMsg;
        long httpCode = 0;
        const bool ok = performSharedHttpGet(finalUrl, responseBody, httpCode, errMsg);
        if (shuttingDown_.load()) return;

        if (ok) {
            const std::string_view trimmed = trimAscii(responseBody);
            const bool looksJson = !trimmed.empty() && (trimmed.front() == '{' || trimmed.front() == '[');
            const std::string payload = looksJson
                ? responseBody
                : JsonObjectBuilder()
                      .kv("errornu", "0")
                      .kv("errordesc", "OK")
                      .kv("data", responseBody)
                      .finish();
            receiveCallBack(eventId, kHttpSuccess, payload);
        } else {
            const std::string safeDesc = errMsg.empty() ? ("HTTP error " + std::to_string(httpCode)) : errMsg;
            receiveCallBack(
                eventId,
                kHttpFailed,
                JsonObjectBuilder()
                    .kv("errornu", "1")
                    .kv("errordesc", safeDesc)
                    .kvInt("code", httpCode)
                    .kvInt("http_code", httpCode)
                    .kv("msg", safeDesc)
                    .finish());
        }
    }).detach();
}

void Platform::callUniversalWebFunction(int eventId,
                                        const std::string& endpoint,
                                        const std::string& jsonParams) {
    log("debug", "callUniversalWebFunction: " + endpoint);
    const auto kv = parseFlatJsonObject(jsonParams);
    std::string extra;
    for (const auto& [k, v] : kv) {
        const std::string encoded = urlEncode(v);
        extra += "&" + k + "=" + encoded;
        log("debug", "key=" + k + ",value=" + encoded);
    }
    if (kv.find("pid") == kv.end() && endpoint.find("pid=") == std::string::npos) {
        std::string currentPid = getPid();
        if (currentPid.empty()) {
            if (std::shared_ptr<IAuthProvider> prov = getAuthProvider(); prov && prov->isAuthenticated()) {
                currentPid = prov->currentSession().pid;
            }
        }
        if (!currentPid.empty()) extra += "&pid=" + urlEncode(currentPid);
    }
    const char* sep = (endpoint.find('?') == std::string::npos) ? "/?uuid=" : "&uuid=";
    const std::string url = getHost() + getStandAlone() + "/" + endpoint + sep + getUUID() + getUrlParam() + extra;
    sendHTTPRequest(eventId, url, true);
}

namespace {
template <MapiRouteId Route>
constexpr const MapiRouteSpec& findMapiRouteSpec() noexcept {
    for (const auto& r : kMapiRoutes) {
        if (r.id == Route) return r;
    }
    return kMapiRoutes[0];
}
} // namespace

void Platform::getHash(const std::string& jsonParams) {
    constexpr const auto& spec = findMapiRouteSpec<MapiRouteId::Hash>();
    log("debug", "getHash");
    std::string pidCopy;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        pidCopy = pid_;
    }
    if (spec.requireLoginPid && pidCopy.empty()) {
        log("release", "not login");
        return;
    }
    const std::string url = getHost() + getStandAlone() + "/" + spec.endpoint + "/?pid=" + pidCopy +
                            "&uuid=" + getUUID() + getUrlParam() + buildQueryFromJson(jsonParams);
    sendHTTPRequest(spec.eventId, url, true);
}

void Platform::getHashWithSimulation(const std::string& jsonParams) {
    constexpr const auto& spec = findMapiRouteSpec<MapiRouteId::HashSimulation>();
    log("debug", "getHashWithSimulation");
    std::string hostOverride, pidCopy;
    {
        std::lock_guard<std::recursive_mutex> lock(stateMutex_);
        hostOverride = simulationHashHost_;
        pidCopy = pid_;
    }
    const std::string baseHost = (spec.useSimulationHost && !hostOverride.empty()) ? hostOverride : getHost();
    const std::string url = baseHost + getStandAlone() + "/" + spec.endpoint + "/?pid=" + pidCopy +
                            "&uuid=" + getUUID() + getUrlParam() + buildQueryFromJson(jsonParams);
    sendHTTPRequest(spec.eventId, url, true);
}

#define DEFINE_MAPI_ROUTE_METHOD(MethodName, RouteEnum)                                         \
    void Platform::MethodName(const std::string& jsonParams) {                                  \
        constexpr const auto& spec = findMapiRouteSpec<MapiRouteId::RouteEnum>();               \
        callUniversalWebFunction(spec.eventId, spec.endpoint, jsonParams);                      \
    }

DEFINE_MAPI_ROUTE_METHOD(getServerList,        ServerList)
DEFINE_MAPI_ROUTE_METHOD(getVersionInfo,       VersionInfo)
DEFINE_MAPI_ROUTE_METHOD(getLoginedServerInfo, LoginedServerInfo)
DEFINE_MAPI_ROUTE_METHOD(getNotice,            Notice)
DEFINE_MAPI_ROUTE_METHOD(getSuperNotice,       SuperNotice)
DEFINE_MAPI_ROUTE_METHOD(getAppleReview,       AppleReview)
DEFINE_MAPI_ROUTE_METHOD(question,             Question)
DEFINE_MAPI_ROUTE_METHOD(getUserInformation,   UserInformation)
DEFINE_MAPI_ROUTE_METHOD(getBrowseActive,      BrowseActive)
DEFINE_MAPI_ROUTE_METHOD(getForceFix,          ForceFix)

#undef DEFINE_MAPI_ROUTE_METHOD

bool Platform::isDebug() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return isDebugEnv_ || debugLevel_ > 0;
}

bool Platform::isAd() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return platformConfig_.getString("isAd", "0") == "1";
}

void Platform::setDebugEnv(bool debugEnv) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    isDebugEnv_ = debugEnv;
}

std::string Platform::getUUID() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return uuid_;
}

std::string Platform::getPid() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return pid_;
}

std::string Platform::getIdfa() const { return ""; }

std::string Platform::getPL() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return platformConfig_.getString("pl", "vnsg2");
}

std::string Platform::getOS() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return platformConfig_.getString("os", "android");
}

std::string Platform::getGN() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return gnOverride_.empty() ? gameConfig_.getString("gn", "vnsg2") : gnOverride_;
}

std::string Platform::getSDKVersion() const { return kSdkVersion; }

std::string Platform::getUserCenterName() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return platformConfig_.getString("userCenterName", "Win32");
}

std::string Platform::getDeviceInfo() const {
    return std::string("{\"os\":\"win32\",\"model\":\"PC\",\"brand\":\"Windows\",\"sdk\":\"") + kSdkVersion + "\"}";
}

std::string Platform::getDeviceFeature() const {
    return "{\"topDangerHeigth\":0,\"bottomDangerHeight\":0,\"leftDangerWidth\":0,\"rightDangerWidth\":0,"
           "\"safeInsetTop\":0,\"safeInsetBottom\":0,\"safeInsetLeft\":0,\"safeInsetRight\":0,"
           "\"statusBarHeight\":0,\"navigationBarHeight\":0}";
}

std::string Platform::getLocaleInfo() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return gameConfig_.getString("language", "en_US");
}

void Platform::setSimulationInfo(const std::string& jsonInfo) {
    const auto kv = parseFlatJsonObject(jsonInfo);
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    if (auto it = kv.find("pid"); it != kv.end() && !it->second.empty()) {
        pid_ = it->second;
        isLogined_ = true;
    }
    if (auto it = kv.find("simulateHashHost"); it != kv.end() && !it->second.empty()) {
        simulationHashHost_ = it->second;
    }
}

void Platform::setMainScreenBrightness(float brightness) {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    screenBrightness_ = std::clamp(brightness, 0.0f, 1.0f);
}

float Platform::getMainScreenBrightness() const {
    std::lock_guard<std::recursive_mutex> lock(stateMutex_);
    return screenBrightness_;
}

bool Platform::checkMethod(const std::string& methodName) const {
    return findCapabilityShim(methodName) != nullptr;
}

const CapabilityShimEntry* Platform::findCapabilityShim(const std::string& methodName) {
    for (const auto& entry : kCapabilityShimTable) {
        if (methodName == entry.methodName) return &entry;
    }
    return nullptr;
}

bool Platform::invokeCapabilityShim(const std::string& methodName, const std::string& detail) {
    const CapabilityShimEntry* entry = findCapabilityShim(methodName);
    if (!entry) {
        log("release", "[CapabilityShim][unknown] Dropped call '" + methodName + "' (detail=" + detail + ")");
        return false;
    }
    log("release", std::string("[CapabilityShim][") + entry->category + "] " + entry->methodName +
                   " ignored on Win32" + (detail.empty() ? "" : (" (" + detail + ")")));
    if (entry->emitCallback) {
        receiveCallBack(entry->callbackEventId, entry->defaultStatusCode,
                        entry->defaultPayloadJson ? entry->defaultPayloadJson : "{}");
    }
    return true;
}

void Platform::pay(const std::string& jsonParams)                  { invokeCapabilityShim("pay", jsonParams); }
void Platform::showToolBar()                                       { invokeCapabilityShim("showToolBar"); }
void Platform::hideToolBar()                                       { invokeCapabilityShim("hideToolBar"); }
void Platform::enterUserCenter()                                   { invokeCapabilityShim("enterUserCenter"); }
void Platform::accountSwitch()                                     { logout(); }
void Platform::sendInformationToPlatform(int t, const std::string& j) { invokeCapabilityShim("sendInformationToPlatform", "type=" + std::to_string(t) + " " + j); }
void Platform::pause()                                             { invokeCapabilityShim("pause"); }
void Platform::onPressBack()                                       { invokeCapabilityShim("onPressBack"); }
void Platform::shareWeixin(const std::string& jsonParams)          { invokeCapabilityShim("shareWeixin", jsonParams); }
void Platform::playVideo(const std::string& videoPath)             { invokeCapabilityShim("playVideo", videoPath); }
void Platform::openCustomWebView(const std::string& jsonParams)    { invokeCapabilityShim("openCustomWebView", jsonParams); }
void Platform::closeCustomWebView()                                { invokeCapabilityShim("closeCustomWebView"); }
void Platform::doCustomWebViewAction(const std::string& jsonParams){ invokeCapabilityShim("doCustomWebViewAction", jsonParams); }
void Platform::quit()                                              { invokeCapabilityShim("quit"); }
void Platform::sendTracking(const std::string& ev, const std::string& j) { invokeCapabilityShim("sendTracking", ev + " " + j); }
void Platform::retention(const std::string& jsonParams)            { invokeCapabilityShim("retention", jsonParams); }
void Platform::sendLog(const std::string& jsonParams)              { invokeCapabilityShim("sendLog", jsonParams); }
void Platform::sendAdstat()                                        { invokeCapabilityShim("sendAdstat"); }
void Platform::showMessage(const std::string& t, const std::string& m) { invokeCapabilityShim("showMessage", t + ": " + m); }
void Platform::issueDJOrders()                                     { invokeCapabilityShim("issueDJOrders"); }
void Platform::searchHandleUrl()                                   { invokeCapabilityShim("searchHandleUrl"); }
void Platform::getNetworkCapture(const std::string& jsonParams)    { invokeCapabilityShim("getNetworkCapture", jsonParams); }

void Platform::openUrl(const std::string& url) {
    invokeCapabilityShim("openUrl", url);
#ifdef _WIN32
    if (gclient::common::startsWithAsciiCI(url, "http://") ||
        gclient::common::startsWithAsciiCI(url, "https://")) {
        const std::wstring wideUrl = gclient::utf8::utf8ToWide(url);
        if (!wideUrl.empty()) {
            ::ShellExecuteW(nullptr, L"open", wideUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }
    }
#endif
}

void Platform::callUniversalFunction(const std::string& funcName, const std::string& jsonParams) {
    invokeCapabilityShim(funcName.empty() ? "callUniversalFunction" : funcName, jsonParams);
}

void Platform::callUniversalFunctionWithBack(const std::string& funcName, const std::string& jsonParams) {
    if (!invokeCapabilityShim(funcName, jsonParams)) {
        log("release", "[CapabilityShim][universal] Resolving unknown universal call '" +
                       funcName + "' cleanly without deadlock");
    }
}

void Platform::callUniversalFunctionWithBack(const std::string& funcName,
                                             const std::string& jsonParams,
                                             std::function<void(const std::string&)> callback) {
    callUniversalFunctionWithBack(funcName, jsonParams);
    if (callback) callback("{}");
}

} // namespace bt
