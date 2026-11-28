#include "bindings/LuaHttpAndCrypto.h"
#include "tolua_GameTemplate.h"
#include "CCCrypto.h"

#include "compat/Axmol226Compat.h"
#include "CCLuaEngine.h"

#if __has_include("net/CNetwork.h")
#include "net/CNetwork.h"
#define GCLIENT_HTTP_HAS_CNETWORK 1
#else
#define GCLIENT_HTTP_HAS_CNETWORK 0
#endif

#if __has_include("platform/BtPlatformWin32.h")
#include "platform/BtPlatformWin32.h"
#define GCLIENT_HTTP_HAS_BTPLATFORM 1
#else
#define GCLIENT_HTTP_HAS_BTPLATFORM 0
#endif

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}
#include "tolua++.h"
#if __has_include("lua-bindings/manual/tolua_fix.h")
#include "lua-bindings/manual/tolua_fix.h"
#else
#include "tolua_fix.h"
#endif

#include "bindings/LuaBindTemplates.h"
#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelHttp.h"
#include "common/KestrelJson.h"
#include "common/KestrelUtf8.h"

#include <curl/curl.h>
#include <openssl/evp.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

USING_NS_CC;

namespace {

namespace lb = gclient::lua_bind;

constexpr const char* kDefaultCobaltRelayOrigin = "http://127.0.0.1:8080";
constexpr const char* kDefaultCobaltRelayTcpHost = "127.0.0.1";
constexpr uint16_t kDefaultCobaltRelayTcpPort = 8160;
constexpr const char* kVnsg2MapiAppKey = "2A0ce68806G8aJ58Mo6_vnsg2@OmZHv";

// ============================================================================
// Base64 & OpenSSL EVP Digest Helpers (Hex & MD5 shared via KestrelCrypto.h)
// ============================================================================

std::string encodeBase64Impl(const unsigned char* data, size_t len) {
    if (!data || len == 0 || len > static_cast<size_t>(INT_MAX / 2)) return {};
    std::string out(4 * ((len + 2) / 3), '\0');
    const int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(out.data()), data, static_cast<int>(len));
    if (written < 0) return {};
    out.resize(static_cast<size_t>(written));
    return out;
}

std::string decodeBase64Impl(const std::string& b64) {
    if (b64.empty()) return {};
    std::string clean;
    clean.reserve(b64.size() + 2);
    for (char c : b64) {
        if (!std::isspace(static_cast<unsigned char>(c))) clean.push_back(c);
    }
    if (clean.empty() || clean.size() > static_cast<size_t>(INT_MAX / 2)) return {};

    const size_t rem = clean.size() % 4;
    if (rem == 1) return {};
    if (rem == 2) clean.append("==");
    else if (rem == 3) clean.push_back('=');

    size_t pad = 0;
    if (!clean.empty() && clean.back() == '=') ++pad;
    if (clean.size() >= 2 && clean[clean.size() - 2] == '=') ++pad;

    std::string out((clean.size() / 4) * 3 + 3, '\0');
    const int decoded = EVP_DecodeBlock(
        reinterpret_cast<unsigned char*>(out.data()),
        reinterpret_cast<const unsigned char*>(clean.data()),
        static_cast<int>(clean.size()));
    if (decoded < 0) return {};
    size_t actual = static_cast<size_t>(decoded);
    if (pad <= actual) actual -= pad;
    out.resize(actual);
    return out;
}

std::string computeDigest(const EVP_MD* md, const void* data, size_t len, bool raw) {
    unsigned char buf[EVP_MAX_MD_SIZE] = {};
    unsigned int outLen = 0;
    static const unsigned char kEmpty = 0;
    const unsigned char* bytes = data ? static_cast<const unsigned char*>(data) : &kEmpty;
    if (EVP_Digest(bytes, data ? len : 0, buf, &outLen, md, nullptr) != 1) return {};
    return raw ? std::string(reinterpret_cast<const char*>(buf), outLen)
               : gclient::crypto::hexEncode(buf, outLen, false);
}

std::string stripTrailingSlash(std::string_view sv) {
    std::string s = gclient::common::trimCopy(sv);
    while (!s.empty() && (s.back() == '/' || s.back() == '\\')) s.pop_back();
    return s;
}

struct ParsedHttpUrl {
    std::string scheme;
    std::string authority;
    std::string hostLower;
    std::string path;
    std::string query;
    bool valid = false;
};

ParsedHttpUrl parseHttpUrl(std::string_view raw) {
    ParsedHttpUrl out;
    const std::string_view trimmed = gclient::common::trimAscii(raw);
    if (trimmed.empty()) return out;

    const size_t schemePos = trimmed.find("://");
    size_t authStart = 0;
    if (schemePos != std::string_view::npos) {
        out.scheme.assign(trimmed.substr(0, schemePos));
        authStart = schemePos + 3;
    } else if (trimmed.front() == '/') {
        out.path.assign(trimmed);
        if (const size_t qPos = out.path.find('?'); qPos != std::string::npos) {
            out.query = out.path.substr(qPos + 1);
            out.path.resize(qPos);
        }
        out.valid = true;
        return out;
    } else {
        return out;
    }

    const size_t pathStart = trimmed.find_first_of("/?#", authStart);
    if (pathStart == std::string_view::npos) {
        out.authority.assign(trimmed.substr(authStart));
        out.path = "/";
    } else {
        out.authority.assign(trimmed.substr(authStart, pathStart - authStart));
        std::string tail(trimmed.substr(pathStart));
        if (const size_t hashPos = tail.find('#'); hashPos != std::string::npos) tail.resize(hashPos);
        if (const size_t qPos = tail.find('?'); qPos != std::string::npos) {
            out.path = tail.substr(0, qPos);
            out.query = tail.substr(qPos + 1);
        } else {
            out.path = std::move(tail);
        }
        if (out.path.empty()) out.path = "/";
    }

    std::string_view hostPart = out.authority;
    if (const size_t atPos = hostPart.rfind('@'); atPos != std::string_view::npos) {
        hostPart.remove_prefix(atPos + 1);
    }
    if (!hostPart.empty() && hostPart.front() == '[') {
        if (const size_t rb = hostPart.find(']'); rb != std::string_view::npos) {
            hostPart = hostPart.substr(1, rb - 1);
        }
    } else if (const size_t colon = hostPart.find(':'); colon != std::string_view::npos) {
        hostPart = hostPart.substr(0, colon);
    }
    out.hostLower = gclient::common::toLowerAscii(hostPart);
    out.valid = !out.hostLower.empty();
    return out;
}

std::string normalizeRoutePath(std::string path) {
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    return path;
}

std::string getQueryParam(std::string_view query, std::string_view key) {
    size_t pos = 0;
    while (pos <= query.size()) {
        size_t amp = query.find('&', pos);
        if (amp == std::string_view::npos) amp = query.size();
        const std::string_view seg = query.substr(pos, amp - pos);
        if (const size_t eq = seg.find('='); eq != std::string_view::npos && seg.substr(0, eq) == key) {
            return std::string(seg.substr(eq + 1));
        }
        pos = amp + 1;
    }
    return {};
}

std::string ensureSignedMapiQuery(std::string query) {
    if (!getQueryParam(query, "sign").empty()) return query;

    std::vector<std::string> parts;
    size_t pos = 0;
    bool hasTime = false;
    while (pos <= query.size()) {
        size_t amp = query.find('&', pos);
        if (amp == std::string::npos) amp = query.size();
        if (amp > pos) {
            std::string item = query.substr(pos, amp - pos);
            if (item.starts_with("time=")) hasTime = true;
            parts.push_back(std::move(item));
        }
        pos = amp + 1;
    }
    if (!hasTime) {
        parts.push_back("time=" + std::to_string(static_cast<int64_t>(std::time(nullptr))));
    }

    std::vector<std::string> sorted = parts;
    std::sort(sorted.begin(), sorted.end());

    // Exact BtPlatformWin32::sortUrlParams concatenation (no '&' between sorted segments).
    std::string canonical;
    for (const auto& seg : sorted) canonical += seg;
    std::string appKey = gclient::utf8::readEnvUtf8("GCLIENT_MAPI_KEY");
    if (appKey.empty()) appKey = kVnsg2MapiAppKey;
    const std::string sign = gclient::crypto::md5Hex(canonical + appKey, false);

    std::string rebuilt;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) rebuilt.push_back('&');
        rebuilt += parts[i];
    }
    rebuilt += "&sign=" + sign;
    return rebuilt;
}

std::string resolveActiveCobaltRelayOrigin() {
    for (const char* envName : {
             "GCLIENT_RELAY_HTTP_URL", "GCLIENT_HTTP_HOST", "GCLIENT_MAPI_URL", "GCLIENT_AUTH_URL"}) {
        const std::string v = stripTrailingSlash(gclient::utf8::readEnvUtf8(envName));
        if (!v.empty()) {
            const auto parsed = parseHttpUrl(v);
            if (parsed.valid && !gclient::bindings::isDeadStagingHost(parsed.hostLower)) return v;
        }
    }

#if GCLIENT_HTTP_HAS_BTPLATFORM
    if (auto* plat = bt::Platform::getInstance()) {
        const std::string host = stripTrailingSlash(plat->getHost());
        if (!host.empty() && host != "null") {
            const auto parsed = parseHttpUrl(host);
            if (parsed.valid && !gclient::bindings::isDeadStagingHost(parsed.hostLower)) return host;
        }
    }
#endif

    return kDefaultCobaltRelayOrigin;
}

std::string resolveSharedSdkCookieJarFallback() {
    const std::string dir = gclient::utf8::readEnvUtf8("GCLIENT_WRITABLE_DIR");
    if (dir.empty()) return {};
    const std::filesystem::path p = gclient::utf8::utf8ToFsPath(dir) / "sdk_cookies.txt";
    std::error_code ec;
    return std::filesystem::is_regular_file(p, ec) ? gclient::utf8::fsPathToUtf8(p) : std::string{};
}

bool isMapiOrRelayRoute(std::string_view normPath) noexcept {
    return normPath.starts_with("/phone/") || normPath == "/phone" ||
           normPath.starts_with("/api/login/") || normPath == "/version.lua" ||
           normPath == "/scripts/version.lua" || normPath.starts_with("/admin/") ||
           normPath == "/health";
}

bool isDeadTelemetryOrPushRoute(std::string_view normPath) noexcept {
    return normPath.starts_with("/push") || normPath.starts_with("/log") ||
           normPath.starts_with("/stat") || normPath.starts_with("/adstat") ||
           normPath.starts_with("/report") || normPath.starts_with("/bi/");
}

bool emitSyntheticResponse(
    long& outStatusCode,
    std::string& outBody,
    std::string& outHeaders,
    std::string body,
    const char* contentType = "application/json",
    const char* synthTag = "offline")
{
    outStatusCode = 200;
    outHeaders = std::string("HTTP/1.1 200 OK\r\nContent-Type: ") + contentType +
                 "\r\nX-GClient-Synthetic: " + synthTag + "\r\n\r\n";
    outBody = std::move(body);
    return true;
}

lua_State* getLiveEngineLuaState() noexcept {
    if (auto* mgr = ax::ScriptEngineManager::getInstance()) {
        if (auto* engine = dynamic_cast<CCLuaEngine*>(mgr->getScriptEngine())) {
            if (auto* stack = engine->getLuaStack()) return stack->getLuaState();
        }
    }
    return nullptr;
}

} // namespace

// ============================================================================
// CCCrypto Static C++ Implementation
// ============================================================================

std::string CCCrypto::md5(const void* data, size_t len, bool raw) {
    static const uint8_t kEmpty = 0;
    const void* ptr = data ? data : &kEmpty;
    const size_t n = data ? len : 0;
    if (raw) {
        const auto digest = gclient::crypto::md5Raw(ptr, n);
        return std::string(reinterpret_cast<const char*>(digest.data()), digest.size());
    }
    return gclient::crypto::md5Hex(ptr, n, false);
}

std::string CCCrypto::sha1(const void* data, size_t len, bool raw) {
    return computeDigest(EVP_sha1(), data, len, raw);
}

std::string CCCrypto::bin2hex(const void* data, size_t len) {
    return (!data || len == 0) ? std::string{} : gclient::crypto::hexEncode(data, len, false);
}

std::string CCCrypto::hex2bin(const std::string& hex) {
    std::vector<uint8_t> decoded;
    if (gclient::crypto::hexDecode(hex, decoded)) {
        return std::string(reinterpret_cast<const char*>(decoded.data()), decoded.size());
    }
    // Preserve permissive prefix decoding if trailing non-hex characters exist.
    auto nibble = [](unsigned char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(static_cast<unsigned char>(hex[i]));
        const int lo = nibble(static_cast<unsigned char>(hex[i + 1]));
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

std::string CCCrypto::encodeBase64(const void* data, size_t len) {
    return encodeBase64Impl(static_cast<const unsigned char*>(data), len);
}

std::string CCCrypto::decodeBase64(const std::string& b64) {
    return decodeBase64Impl(b64);
}

namespace gclient {
namespace bindings {

bool isDeadStagingHost(std::string_view host) noexcept {
    if (host.empty()) return false;
    if (gclient::http::EndpointRewritePolicy::isLegacyDeadHost(host)) return true;
    static constexpr std::string_view kDeadDomains[] = {
        "zing.vn", "zingplay.com", "vnggames.com", "gtarcade.com", "babeltime.com"
    };
    static constexpr std::string_view kDeadSuffixes[] = {
        ".zing.vn", ".zingplay.com", ".vnggames.com", ".gtarcade.com", ".babeltime.com"
    };
    for (size_t i = 0; i < std::size(kDeadDomains); ++i) {
        if (gclient::common::equalsAsciiCI(host, kDeadDomains[i]) ||
            gclient::common::endsWithAsciiCI(host, kDeadSuffixes[i])) {
            return true;
        }
    }
    return false;
}

std::string rewriteLegacyStagingUrl(std::string_view rawUrl, bool* outWasRewritten) {
    if (outWasRewritten) *outWasRewritten = false;
    const std::string trimmed = gclient::common::trimCopy(rawUrl);
    if (trimmed.empty() || gclient::utf8::readEnvBool({"GCLIENT_DISABLE_STAGING_REWRITE"}, false)) {
        return trimmed;
    }

    const ParsedHttpUrl parsed = parseHttpUrl(trimmed);
    if (!parsed.valid || !isDeadStagingHost(parsed.hostLower)) return trimmed;

    const std::string normPath = normalizeRoutePath(parsed.path);
    if (!isMapiOrRelayRoute(normPath)) return trimmed;

    std::string query = parsed.query;
    if (normPath.starts_with("/phone/") || normPath == "/phone") {
        query = ensureSignedMapiQuery(std::move(query));
    }

    std::string rewritten = resolveActiveCobaltRelayOrigin() + parsed.path;
    if (!query.empty()) {
        rewritten.push_back('?');
        rewritten += query;
    }
    if (outWasRewritten) *outWasRewritten = true;
    return rewritten;
}

bool trySynthesizeOfflineMapiResponse(
    std::string_view url,
    long& outStatusCode,
    std::string& outBody,
    std::string& outHeaders,
    bool offlineFallbackAllowed)
{
    using gclient::json::JsonObjectBuilder;

    const ParsedHttpUrl parsed = parseHttpUrl(url);
    if (!parsed.valid) return false;
    const std::string normPath = normalizeRoutePath(parsed.path);

    if (isDeadStagingHost(parsed.hostLower) && isDeadTelemetryOrPushRoute(normPath)) {
        return emitSyntheticResponse(
            outStatusCode, outBody, outHeaders,
            JsonObjectBuilder().kv("errornu", "0").kv("errordesc", "OK").finish(),
            "application/json", "telemetry");
    }

    if (!offlineFallbackAllowed) return false;

    if (normPath == "/version.lua" || normPath == "/scripts/version.lua") {
        return emitSyntheticResponse(
            outStatusCode, outBody, outHeaders,
            "local version = {package = \"1.0.34\", script = \"1.0.1194\", svn = 452448, csvSvn = 449111}\nreturn version\n",
            "text/plain; charset=utf-8");
    }

    if (normPath == "/phone/getversion") {
        std::string pkgVer = getQueryParam(parsed.query, "packageVersion");
        std::string scrVer = getQueryParam(parsed.query, "scriptVersion");
        if (pkgVer.empty()) pkgVer = "1.0.34";
        if (scrVer.empty()) scrVer = "1.0.1194";
        return emitSyntheticResponse(
            outStatusCode, outBody, outHeaders,
            JsonObjectBuilder()
                .kv("errornu", "0").kv("errordesc", "OK")
                .kvInt("error_id", 500).kvInt("ret", 0).kvInt("status", 0).kvInt("isForce", 0)
                .kv("packageVersion", pkgVer).kv("scriptVersion", scrVer)
                .kvInt("svn", 452448).kvInt("csvSvn", 449111)
                .kv("static_url", "").kv("spare_static_url", "")
                .kvRaw("base", "{\"error_id\":500,\"isForce\":0}")
                .kvRaw("script", "[]")
                .finish());
    }

    if (normPath == "/phone/applereview") {
        return emitSyntheticResponse(
            outStatusCode, outBody, outHeaders,
            JsonObjectBuilder()
                .kvInt("ret", 404).kv("msg", "no data").kvInt("applereview", 0)
                .kv("ip", "127.0.0.1").kv("errornu", "0").kv("errordesc", "OK")
                .finish());
    }

    if (normPath == "/phone/notice" || normPath == "/phone/supernotice") {
        return emitSyntheticResponse(
            outStatusCode, outBody, outHeaders,
            JsonObjectBuilder().kv("errornu", "0").kv("errordesc", "OK").kv("data", "").kv("notice", "").finish());
    }

    if (normPath == "/phone/serverlist") {
        std::string tcpHost = gclient::utf8::readEnvUtf8("GCLIENT_TCP_HOST");
        if (tcpHost.empty()) tcpHost = kDefaultCobaltRelayTcpHost;
        uint16_t tcpPort = kDefaultCobaltRelayTcpPort;
        if (const std::string envPort = gclient::utf8::readEnvUtf8("GCLIENT_TCP_PORT"); !envPort.empty()) {
            const long p = std::strtol(envPort.c_str(), nullptr, 10);
            if (p > 0 && p <= 65535) tcpPort = static_cast<uint16_t>(p);
        }
        const std::string itemJson = JsonObjectBuilder()
            .kv("groupid", "2900161").kv("group", "game2900161").kv("name", "S161.Vo Xuong")
            .kv("host", tcpHost).kvInt("port", tcpPort)
            .kvInt("status", 1).kvInt("hot", 1).kvInt("new", 0).kvInt("tj", 1).kvInt("show", 1).kvInt("isRecall", 0)
            .kvInt("serverIndex", 161).kvInt("openDateTime", 1541469600).kvInt("mergeServerTime", 1667530800).kvInt("openPrize", 0)
            .finish();
        const std::string rootJson = JsonObjectBuilder()
            .kvRaw("item", "[" + itemJson + "]")
            .kvRaw("notice", "{\"open\":0,\"desc\":\"\",\"url\":\"\"}")
            .finish();
        return emitSyntheticResponse(
            outStatusCode, outBody, outHeaders,
            JsonObjectBuilder().kv("errornu", "0").kv("errordesc", "OK").kvRaw("root", rootJson).finish());
    }

    if (normPath == "/phone/loginrole") {
        return emitSyntheticResponse(
            outStatusCode, outBody, outHeaders,
            "{\"root\":{\"role\":[],\"recallOk\":0},\"errornu\":\"0\",\"errordesc\":\"OK(1-0)\"}");
    }

    if (normPath == "/phone/platform/getPlatformUserInfo") {
        return emitSyntheticResponse(
            outStatusCode, outBody, outHeaders,
            "{\"errornu\":\"0\",\"errordesc\":\"success\",\"data\":{\"idcardStatus\":1,\"isForceRealName\":0,\"is_fastreg\":0,\"isAdult\":1,\"isBindPhone\":1,\"isConcern\":0,\"isFastUser\":0}}");
    }

    if (normPath == "/phone/helper/getagreeversion") {
        return emitSyntheticResponse(
            outStatusCode, outBody, outHeaders,
            "{\"errornu\":\"0\",\"errordesc\":\"OK\",\"data\":{\"status\":0,\"version\":\"1.0\",\"newUserAgree\":\"\",\"newUserPrivacy\":\"\",\"userChildPrivacy\":\"\"}}");
    }

    if (normPath == "/phone/addiction/getaddiction" || normPath == "/phone/addiction/clear") {
        return emitSyntheticResponse(
            outStatusCode, outBody, outHeaders,
            JsonObjectBuilder().kv("errornu", "0").kv("errordesc", "OK").kvInt("limit_time", 0).finish());
    }

    static constexpr std::string_view kEmptyDataRoutes[] = {
        "/phone/userinfo", "/phone/innerbrowse", "/phone/question", "/phone/getforcefix",
        "/phone/adstat", "/phone/crashlog", "/phone/paparazzi", "/phone/record", "/phone/log"
    };
    for (auto route : kEmptyDataRoutes) {
        if (normPath == route) {
            return emitSyntheticResponse(
                outStatusCode, outBody, outHeaders,
                JsonObjectBuilder().kv("errornu", "0").kv("errordesc", "OK").kvRaw("data", "{}").finish());
        }
    }

    return false;
}

namespace {

constexpr const char* kDigestMetatableName = "GCLIENT.CCCryptoDigest";
constexpr uint32_t kDigestMagic = 0x4F4D4447u; // 'OMDG'

struct LuaDigestUserdata {
    uint32_t magic = 0;
    EVP_MD_CTX* ctx = nullptr;
    const EVP_MD* md = nullptr;
};

struct HttpRetainGuard {
    CCObject* obj = nullptr;
    explicit HttpRetainGuard(CCObject* o) noexcept : obj(o) { if (obj) obj->retain(); }
    ~HttpRetainGuard() { if (obj) obj->release(); }
    HttpRetainGuard(const HttpRetainGuard&) = delete;
    HttpRetainGuard& operator=(const HttpRetainGuard&) = delete;
};

inline size_t clampOptionalLengthArg(lua_State* L, int lenIdx, size_t actualLen) {
    if (lua_type(L, lenIdx) != LUA_TNUMBER) return actualLen;
    const lua_Number reqNum = lua_tonumber(L, lenIdx);
    if (reqNum <= 0) return 0;
    const size_t reqLen = static_cast<size_t>(reqNum);
    return reqLen < actualLen ? reqLen : actualLen;
}

const EVP_MD* resolveDigestAlgorithm(lua_State* L, int idx) {
    const int t = lua_type(L, idx);
    if (t == LUA_TNONE || t == LUA_TNIL) return EVP_md5();
    if (t == LUA_TNUMBER) {
        const int algId = static_cast<int>(lua_tonumber(L, idx));
        if (algId == CCCrypto::EDigestSha1) return EVP_sha1();
        if (algId == CCCrypto::EDigestMD5) return EVP_md5();
        return nullptr;
    }
    if (t == LUA_TSTRING) {
        size_t len = 0;
        const char* s = lua_tolstring(L, idx, &len);
        if (!s || len == 0) return EVP_md5();
        const std::string lower = gclient::common::toLowerAscii(std::string_view(s, len));
        if (lower == "md5") return EVP_md5();
        if (lower == "sha1" || lower == "sha-1") return EVP_sha1();
        if (lower == "sha224" || lower == "sha-224") return EVP_sha224();
        if (lower == "sha256" || lower == "sha-256") return EVP_sha256();
        if (lower == "sha384" || lower == "sha-384") return EVP_sha384();
        if (lower == "sha512" || lower == "sha-512") return EVP_sha512();
        return EVP_get_digestbyname(s);
    }
    return nullptr;
}

LuaDigestUserdata* toDigestUserdata(lua_State* L, int idx, int* outSelfIdx = nullptr) {
    for (int cand : {idx, idx + 1}) {
        if (lua_type(L, cand) == LUA_TUSERDATA) {
            auto* ud = static_cast<LuaDigestUserdata*>(lua_touserdata(L, cand));
            if (ud && ud->magic == kDigestMagic) {
                if (outSelfIdx) *outSelfIdx = cand;
                return ud;
            }
        }
    }
    if (outSelfIdx) *outSelfIdx = idx;
    return nullptr;
}

int lua_Digest_addBytes(lua_State* L) {
    int selfIdx = 1;
    LuaDigestUserdata* ud = toDigestUserdata(L, 1, &selfIdx);
    const int dataIdx = selfIdx + 1;
    if (ud && ud->ctx) {
        size_t len = 0;
        if (const char* data = lua_tolstring(L, dataIdx, &len)) {
            len = clampOptionalLengthArg(L, dataIdx + 1, len);
            if (len > 0) EVP_DigestUpdate(ud->ctx, data, len);
        }
    }
    lua_pushvalue(L, selfIdx);
    return 1;
}

int lua_Digest_getDigest(lua_State* L) {
    int selfIdx = 1;
    LuaDigestUserdata* ud = toDigestUserdata(L, 1, &selfIdx);
    const bool raw = lua_toboolean(L, selfIdx + 1) != 0;
    if (!ud || !ud->ctx) {
        lua_pushstring(L, "");
        return 1;
    }

    unsigned char buf[EVP_MAX_MD_SIZE] = {};
    unsigned int outLen = 0;
    EVP_MD_CTX* copyCtx = EVP_MD_CTX_new();
    if (!copyCtx) {
        lua_pushstring(L, "");
        return 1;
    }
    const bool ok = (EVP_MD_CTX_copy_ex(copyCtx, ud->ctx) == 1) &&
                    (EVP_DigestFinal_ex(copyCtx, buf, &outLen) == 1);
    EVP_MD_CTX_free(copyCtx);

    if (!ok || outLen == 0) {
        lua_pushstring(L, "");
        return 1;
    }
    if (raw) {
        lua_pushlstring(L, reinterpret_cast<const char*>(buf), outLen);
    } else {
        const std::string hex = gclient::crypto::hexEncode(buf, outLen, false);
        lua_pushlstring(L, hex.data(), hex.size());
    }
    return 1;
}

int lua_Digest_reset(lua_State* L) {
    int selfIdx = 1;
    if (LuaDigestUserdata* ud = toDigestUserdata(L, 1, &selfIdx); ud && ud->ctx && ud->md) {
        EVP_DigestInit_ex(ud->ctx, ud->md, nullptr);
    }
    lua_pushvalue(L, selfIdx);
    return 1;
}

int lua_Digest_gc(lua_State* L) {
    if (lua_type(L, 1) == LUA_TUSERDATA) {
        if (auto* ud = static_cast<LuaDigestUserdata*>(lua_touserdata(L, 1)); ud && ud->magic == kDigestMagic) {
            if (ud->ctx) {
                EVP_MD_CTX_free(ud->ctx);
                ud->ctx = nullptr;
            }
            ud->md = nullptr;
            ud->magic = 0;
        }
    }
    return 0;
}

void pushDigestMetatable(lua_State* L) {
    if (luaL_newmetatable(L, kDigestMetatableName) != 0) {
        lua_pushvalue(L, -1);
        lua_setfield(L, -2, "__index");
        static constexpr luaL_Reg kDigestRegs[] = {
            {"__gc", lua_Digest_gc},
            {"addBytes", lua_Digest_addBytes},
            {"getDigest", lua_Digest_getDigest},
            {"reset", lua_Digest_reset},
        };
        lb::registerMethodTable(L, -1, kDigestRegs);
    }
}

// ============================================================================
// CCCrypto Generic Lua Wrappers
// ============================================================================

template <std::string (*Op)(const void*, size_t)>
int luaCryptoBytesOp(lua_State* L) {
    const int base = lb::firstArgIndex(L);
    size_t len = 0;
    const char* data = lua_tolstring(L, base, &len);
    if (data) len = clampOptionalLengthArg(L, base + 1, len);
    const std::string res = data ? Op(data, len) : std::string{};
    lua_pushlstring(L, res.data(), res.size());
    return 1;
}

template <std::string (*Op)(const std::string&)>
int luaCryptoStrOp(lua_State* L) {
    const int base = lb::firstArgIndex(L);
    size_t len = 0;
    const char* data = lua_tolstring(L, base, &len);
    const std::string res = data ? Op(std::string(data, len)) : std::string{};
    lua_pushlstring(L, res.data(), res.size());
    return 1;
}

template <std::string (*HashFn)(const void*, size_t, bool)>
int luaCryptoHash(lua_State* L) {
    const int base = lb::firstArgIndex(L);
    size_t len = 0;
    const char* data = lua_tolstring(L, base, &len);
    bool raw = false;
    if (lua_type(L, base + 1) == LUA_TNUMBER) {
        len = clampOptionalLengthArg(L, base + 1, len);
        raw = lua_toboolean(L, base + 2) != 0;
    } else {
        raw = lua_toboolean(L, base + 1) != 0;
    }
    const std::string res = HashFn(data ? data : "", data ? len : 0, raw);
    lua_pushlstring(L, res.data(), res.size());
    return 1;
}

int lua_CCCrypto_createDigest(lua_State* L) {
    const EVP_MD* md = resolveDigestAlgorithm(L, lb::firstArgIndex(L));
    if (!md) {
        lua_pushnil(L);
        return 1;
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        lua_pushnil(L);
        return 1;
    }
    auto* ud = static_cast<LuaDigestUserdata*>(lua_newuserdata(L, sizeof(LuaDigestUserdata)));
    if (!ud) {
        EVP_MD_CTX_free(ctx);
        lua_pushnil(L);
        return 1;
    }
    ud->magic = kDigestMagic;
    ud->ctx = ctx;
    ud->md = md;
    pushDigestMetatable(L);
    lua_setmetatable(L, -2);
    return 1;
}

// ============================================================================
// HTTP Request / Response / Client Classes (Axmol v2.11.5 Lifetime-Hardened)
// ============================================================================

class WinHttpRequest : public CCObject {
public:
    int requestType = 0;
    std::string url;
    std::string requestData;
    std::string tag;
    std::vector<std::string> headers;
    int timeoutConnect = 30;
    int timeoutRead = 60;
    int timeoutLowSpeed = 0;
    int lowSpeed = 0;
    int responseScriptFunc = 0;
    int bodyDataScriptFunc = 0;
    int headerDataScriptFunc = 0;
    lua_State* ownerLuaState = nullptr;

    void bindScriptState(lua_State* L) noexcept {
        if (L != nullptr) {
            if (ownerLuaState != nullptr && ownerLuaState != L) {
                responseScriptFunc = 0;
                bodyDataScriptFunc = 0;
                headerDataScriptFunc = 0;
            }
            ownerLuaState = L;
        }
    }

    void detachScriptHandlers(bool removeFromLiveVm = true) noexcept {
        if (removeFromLiveVm && ownerLuaState != nullptr && getLiveEngineLuaState() == ownerLuaState) {
            if (CCScriptEngineProtocol* engine = ax::ScriptEngineManager::getInstance()->getScriptEngine()) {
                for (int h : {responseScriptFunc, bodyDataScriptFunc, headerDataScriptFunc}) {
                    if (h != 0) engine->removeScriptHandler(h);
                }
            }
        }
        responseScriptFunc = 0;
        bodyDataScriptFunc = 0;
        headerDataScriptFunc = 0;
        ownerLuaState = nullptr;
    }

    ~WinHttpRequest() override { detachScriptHandlers(true); }
};

class WinHttpResponse : public CCObject {
public:
    WinHttpRequest* request = nullptr;
    bool succeed = false;
    long responseCode = 0;
    std::string errorBuffer;
    std::string responseData;
    std::string headers;

    ~WinHttpResponse() override { CC_SAFE_RELEASE(request); }
};

class WinHttpClient : public CCObject {
public:
    static WinHttpClient* getInstance() {
        if (!instance_) instance_ = new WinHttpClient();
        return instance_;
    }

    static WinHttpClient* peekInstance() noexcept { return instance_; }

    static void destroyInstance() {
        if (instance_) {
            WinHttpClient* inst = instance_;
            instance_ = nullptr;
            if (auto* director = ax::Director::getInstance()) {
                if (auto* scheduler = director->getScheduler()) {
                    scheduler->unscheduleAllForTarget(inst);
                }
            }
            inst->shutdownQueueOnMainThread(true);
            inst->release();
        }
    }

    static void rescheduleIfAlive() {
        if (instance_) instance_->ensureScheduled();
    }

    ~WinHttpClient() override { shutdownQueueOnMainThread(true); }

    void enableCookies(const char* cookieFile) {
        std::lock_guard<std::mutex> lock(sharedState_->workerMutex);
        cookieFile_ = cookieFile ? cookieFile : "";
    }

    void cancelRequestsForLuaState(lua_State* targetState) {
        dispatchEpoch_.fetch_add(1u, std::memory_order_acq_rel);

        std::vector<WinHttpRequest*> toRelease;
        for (auto it = activeRequests_.begin(); it != activeRequests_.end();) {
            WinHttpRequest* req = it->second.req;
            if (targetState == nullptr || (req != nullptr && req->ownerLuaState == targetState)) {
                if (it->second.cancelToken) it->second.cancelToken->store(true, std::memory_order_release);
                if (req != nullptr) {
                    req->detachScriptHandlers(true);
                    toRelease.push_back(req);
                }
                it = activeRequests_.erase(it);
            } else {
                ++it;
            }
        }

        std::vector<PendingEvent> drained;
        sharedState_->events.drain(drained);
        for (auto& ev : drained) {
            if (activeRequests_.find(ev.requestId) != activeRequests_.end()) {
                sharedState_->events.push(std::move(ev));
            }
        }

        for (WinHttpRequest* req : toRelease) req->release();
    }

    void send(WinHttpRequest* req) {
        if (!req) return;
        gclient::http::ensureCurlGlobalInit();

        if (sharedState_->shuttingDown.load(std::memory_order_acquire)) {
            sharedState_ = std::make_shared<SharedQueueState>();
        }

        const uint64_t requestId = ++nextRequestId_;
        auto cancelToken = std::make_shared<std::atomic<bool>>(false);

        req->retain();
        activeRequests_.emplace(requestId, ActiveRequestSlot{req, cancelToken});
        ensureScheduled();

        bool wasStagingRewritten = false;
        std::string effectiveUrl = rewriteLegacyStagingUrl(req->url, &wasStagingRewritten);

        RequestSnapshot snap;
        snap.requestId = requestId;
        snap.requestType = req->requestType;
        snap.originalUrl = req->url;
        snap.effectiveUrl = std::move(effectiveUrl);
        snap.wasStagingRewritten = wasStagingRewritten;
        snap.requestData = req->requestData;
        snap.headers = req->headers;
        snap.timeoutConnect = req->timeoutConnect;
        snap.timeoutRead = req->timeoutRead;
        snap.timeoutLowSpeed = req->timeoutLowSpeed;
        snap.lowSpeed = req->lowSpeed;
        snap.streamBodyChunks = (req->bodyDataScriptFunc != 0);
        snap.streamHeaderChunks = (req->headerDataScriptFunc != 0);
        {
            std::lock_guard<std::mutex> lock(sharedState_->workerMutex);
            snap.cookieFile = cookieFile_;
        }
        if (snap.cookieFile.empty()) snap.cookieFile = resolveSharedSdkCookieJarFallback();

        sharedState_->activeWorkers.fetch_add(1u, std::memory_order_acq_rel);
        std::thread(&WinHttpClient::runWorker, sharedState_, std::move(cancelToken), std::move(snap)).detach();
    }

    void dispatchCallbacks(float /*dt*/) {
        std::vector<PendingEvent> batch;
        sharedState_->events.drain(batch);
        if (batch.empty()) return;

        HttpRetainGuard selfGuard(this);
        const uint64_t startEpoch = dispatchEpoch_.load(std::memory_order_acquire);

        for (PendingEvent& ev : batch) {
            if (sharedState_->shuttingDown.load(std::memory_order_acquire) ||
                instance_ != this ||
                dispatchEpoch_.load(std::memory_order_acquire) != startEpoch) {
                break;
            }

            auto slotIt = activeRequests_.find(ev.requestId);
            if (slotIt == activeRequests_.end()) continue;
            WinHttpRequest* req = slotIt->second.req;
            if (!req) {
                activeRequests_.erase(slotIt);
                continue;
            }

            auto* engine = dynamic_cast<CCLuaEngine*>(ax::ScriptEngineManager::getInstance()->getScriptEngine());
            lua_State* L = (engine && engine->getLuaStack()) ? engine->getLuaStack()->getLuaState() : nullptr;
            const bool vmMatches = (L != nullptr && (req->ownerLuaState == nullptr || L == req->ownerLuaState));

            if (ev.type == PendingEvent::HeaderChunk) {
                if (vmMatches && req->headerDataScriptFunc != 0) {
                    HttpRetainGuard reqGuard(req);
                    lua_pushlstring(L, ev.data.data(), ev.data.size());
                    engine->getLuaStack()->executeFunctionByHandler(req->headerDataScriptFunc, 1);
                }
            } else if (ev.type == PendingEvent::BodyChunk) {
                if (vmMatches && req->bodyDataScriptFunc != 0) {
                    HttpRetainGuard reqGuard(req);
                    lua_pushlstring(L, ev.data.data(), ev.data.size());
                    engine->getLuaStack()->executeFunctionByHandler(req->bodyDataScriptFunc, 1);
                }
            } else if (ev.type == PendingEvent::ResponseDone) {
                activeRequests_.erase(slotIt);

                auto* resp = new WinHttpResponse();
                resp->request = req;
                resp->succeed = ev.succeed;
                resp->responseCode = ev.responseCode;
                resp->errorBuffer = std::move(ev.errorBuffer);
                resp->responseData = std::move(ev.data);
                resp->headers = std::move(ev.headers);

                if (vmMatches && resp->request->responseScriptFunc != 0) {
                    lb::pushAxObject(L, this, "CCHttpClient");
                    lb::pushAxObject(L, resp, "LuaHttpResponse");
                    engine->getLuaStack()->executeFunctionByHandler(resp->request->responseScriptFunc, 2);
                } else if (!vmMatches && resp->request) {
                    resp->request->detachScriptHandlers(false);
                }
                resp->release();
            }
        }
    }

private:
    struct ActiveRequestSlot {
        WinHttpRequest* req = nullptr;
        std::shared_ptr<std::atomic<bool>> cancelToken;
    };

    struct RequestSnapshot {
        uint64_t requestId = 0;
        int requestType = 0;
        std::string originalUrl;
        std::string effectiveUrl;
        bool wasStagingRewritten = false;
        std::string requestData;
        std::vector<std::string> headers;
        std::string cookieFile;
        int timeoutConnect = 30;
        int timeoutRead = 60;
        int timeoutLowSpeed = 0;
        int lowSpeed = 0;
        bool streamBodyChunks = false;
        bool streamHeaderChunks = false;
    };

    struct PendingEvent {
        enum Type { HeaderChunk, BodyChunk, ResponseDone } type = ResponseDone;
        uint64_t requestId = 0;
        bool succeed = false;
        long responseCode = 0;
        std::string errorBuffer;
        std::string data;
        std::string headers;
    };

    struct SharedQueueState {
        gclient::http::MainThreadEventQueue<PendingEvent> events;
        std::mutex workerMutex;
        std::condition_variable workersCv;
        std::atomic<bool> shuttingDown{false};
        std::atomic<size_t> activeWorkers{0};

        void pushIfAlive(PendingEvent&& ev) {
            if (!shuttingDown.load(std::memory_order_acquire)) {
                events.push(std::move(ev));
            }
        }
    };

    static void emitSyntheticChunksIfNeeded(
        SharedQueueState& state,
        uint64_t requestId,
        bool streamHeaders,
        bool streamBody,
        std::string& ioHeaders,
        std::string& ioBody)
    {
        if (state.shuttingDown.load(std::memory_order_acquire)) return;
        if (streamHeaders && !ioHeaders.empty()) {
            state.pushIfAlive(PendingEvent{PendingEvent::HeaderChunk, requestId, false, 0, {}, ioHeaders, {}});
        }
        if (streamBody && !ioBody.empty()) {
            state.pushIfAlive(PendingEvent{PendingEvent::BodyChunk, requestId, false, 0, {}, std::move(ioBody), {}});
            ioBody.clear();
        }
    }

    static void runWorker(
        std::shared_ptr<SharedQueueState> state,
        std::shared_ptr<std::atomic<bool>> cancelToken,
        RequestSnapshot snap)
    {
        struct WorkerScopeGuard {
            SharedQueueState* s;
            ~WorkerScopeGuard() {
                if (s->activeWorkers.fetch_sub(1u, std::memory_order_acq_rel) == 1u) {
                    std::lock_guard<std::mutex> lk(s->workerMutex);
                    s->workersCv.notify_all();
                }
            }
        } workerGuard{state.get()};

        auto isAborted = [&]() noexcept {
            return state->shuttingDown.load(std::memory_order_acquire) ||
                   (cancelToken && cancelToken->load(std::memory_order_acquire));
        };
        if (isAborted()) return;

        const bool forceOfflineMode = gclient::utf8::readEnvBool({"GCLIENT_OFFLINE_MODE"}, false);
        const bool strictOnline = gclient::utf8::readEnvBool({"GCLIENT_STRICT_ONLINE"}, false);
        const bool allowOfflineMapiFallback =
            !strictOnline && gclient::utf8::readEnvBool({"GCLIENT_SYNTHESIZE_OFFLINE_MAPI"}, true);

        bool succeed = false;
        long responseCode = 0;
        std::string errorBuffer;
        std::string finalBody;
        std::string finalHeaders;

        if (trySynthesizeOfflineMapiResponse(
                snap.effectiveUrl, responseCode, finalBody, finalHeaders, forceOfflineMode)) {
            succeed = (responseCode >= 200 && responseCode < 400);
            emitSyntheticChunksIfNeeded(
                *state, snap.requestId, snap.streamHeaderChunks, snap.streamBodyChunks, finalHeaders, finalBody);
        } else {
            struct StreamCtx {
                SharedQueueState* state;
                const std::atomic<bool>* cancelFlag;
                uint64_t requestId;
                bool streamBodyChunks;
                bool streamHeaderChunks;
                std::string responseData;
                std::string responseHeaders;

                bool aborted() const noexcept {
                    return state->shuttingDown.load(std::memory_order_acquire) ||
                           (cancelFlag && cancelFlag->load(std::memory_order_acquire));
                }
            } streamCtx{
                state.get(), cancelToken.get(), snap.requestId,
                snap.streamBodyChunks, snap.streamHeaderChunks, {}, {}
            };

            CURL* curl = curl_easy_init();
            CURLcode rc = CURLE_FAILED_INIT;
            if (!curl) {
                errorBuffer = "curl_easy_init failed";
            } else {
                auto writeCb = +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
                    auto* ctx = static_cast<StreamCtx*>(userdata);
                    if (ctx->aborted()) return 0;
                    const size_t total = size * nmemb;
                    if (ctx->streamBodyChunks) {
                        ctx->state->pushIfAlive(
                            PendingEvent{PendingEvent::BodyChunk, ctx->requestId, false, 0, {}, std::string(ptr, total), {}});
                    } else {
                        ctx->responseData.append(ptr, total);
                    }
                    return total;
                };

                auto headerCb = +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
                    auto* ctx = static_cast<StreamCtx*>(userdata);
                    if (ctx->aborted()) return 0;
                    const size_t total = size * nmemb;
                    ctx->responseHeaders.append(ptr, total);
                    if (ctx->streamHeaderChunks) {
                        ctx->state->pushIfAlive(
                            PendingEvent{PendingEvent::HeaderChunk, ctx->requestId, false, 0, {}, std::string(ptr, total), {}});
                    }
                    return total;
                };

                auto xferAbortCb = +[](void* clientp, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> int {
                    return static_cast<StreamCtx*>(clientp)->aborted() ? 1 : 0;
                };

                const ParsedHttpUrl parsedTarget = parseHttpUrl(snap.effectiveUrl);
                const bool isLoopbackTarget =
                    parsedTarget.hostLower == "127.0.0.1" ||
                    parsedTarget.hostLower == "localhost" ||
                    parsedTarget.hostLower == "::1";

                long effectiveConnectSec = static_cast<long>((std::max)(1, snap.timeoutConnect));
                if ((snap.wasStagingRewritten || isLoopbackTarget) && effectiveConnectSec > 3L) {
                    effectiveConnectSec = 3L;
                }

                const bool verifyPeer = !gclient::utf8::readEnvBool({"GCLIENT_INSECURE_TLS"}, false);
                const std::string caBundle =
                    gclient::utf8::firstNonEmptyEnv({"GCLIENT_CA_BUNDLE", "CURL_CA_BUNDLE"});
                gclient::http::configureCurlTlsAndTimeouts(
                    curl,
                    effectiveConnectSec * 1000L,
                    static_cast<long>((std::max)(1, snap.timeoutRead)) * 1000L,
                    verifyPeer,
                    caBundle);

                curl_easy_setopt(curl, CURLOPT_URL, snap.effectiveUrl.c_str());
                curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
                curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferAbortCb);
                curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &streamCtx);
                if (snap.lowSpeed > 0 && snap.timeoutLowSpeed > 0) {
                    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, static_cast<long>(snap.lowSpeed));
                    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, static_cast<long>(snap.timeoutLowSpeed));
                }
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &streamCtx);
                curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCb);
                curl_easy_setopt(curl, CURLOPT_HEADERDATA, &streamCtx);

                if (!snap.cookieFile.empty()) {
                    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, snap.cookieFile.c_str());
                    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, snap.cookieFile.c_str());
                }

                struct curl_slist* slist = nullptr;
                for (const auto& h : snap.headers) slist = curl_slist_append(slist, h.c_str());
                if (slist) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

                if (snap.requestType == 1) {
                    curl_easy_setopt(curl, CURLOPT_POST, 1L);
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, snap.requestData.data());
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(snap.requestData.size()));
                } else if (snap.requestType == 2) {
                    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, snap.requestData.data());
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(snap.requestData.size()));
                } else if (snap.requestType == 3) {
                    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
                }

                char errBuf[CURL_ERROR_SIZE] = {};
                curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errBuf);

                rc = curl_easy_perform(curl);
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
                if (rc == CURLE_OK && responseCode >= 200 && responseCode < 400) {
                    succeed = true;
                } else {
                    errorBuffer = errBuf[0] ? errBuf : curl_easy_strerror(rc);
                }

                if (slist) curl_slist_free_all(slist);
                curl_easy_cleanup(curl);

                finalBody = std::move(streamCtx.responseData);
                finalHeaders = std::move(streamCtx.responseHeaders);

                const bool connectionUnreachable =
                    (rc == CURLE_COULDNT_CONNECT || rc == CURLE_COULDNT_RESOLVE_HOST || rc == CURLE_OPERATION_TIMEDOUT);
                if (!succeed && !isAborted() && connectionUnreachable && allowOfflineMapiFallback &&
                    (snap.wasStagingRewritten || isLoopbackTarget)) {
                    std::string synthBody, synthHeaders;
                    long synthCode = 0;
                    if (trySynthesizeOfflineMapiResponse(
                            snap.effectiveUrl, synthCode, synthBody, synthHeaders, true)) {
                        succeed = true;
                        responseCode = synthCode;
                        errorBuffer.clear();
                        finalHeaders = std::move(synthHeaders);
                        finalBody = std::move(synthBody);
                        emitSyntheticChunksIfNeeded(
                            *state, snap.requestId, snap.streamHeaderChunks, snap.streamBodyChunks, finalHeaders, finalBody);
                    }
                }
            }
        }

        if (!isAborted()) {
            state->pushIfAlive(PendingEvent{
                PendingEvent::ResponseDone, snap.requestId, succeed, responseCode,
                std::move(errorBuffer), std::move(finalBody), std::move(finalHeaders)
            });
        }
    }

    void shutdownQueueOnMainThread(bool waitForWorkersBriefly) {
        dispatchEpoch_.fetch_add(1u, std::memory_order_acq_rel);
        sharedState_->shuttingDown.store(true, std::memory_order_release);
        sharedState_->events.clear();

        for (auto& kv : activeRequests_) {
            if (kv.second.cancelToken) kv.second.cancelToken->store(true, std::memory_order_release);
        }

        if (waitForWorkersBriefly) {
            std::unique_lock<std::mutex> lock(sharedState_->workerMutex);
            sharedState_->workersCv.wait_for(lock, std::chrono::milliseconds(250), [this]() {
                return sharedState_->activeWorkers.load(std::memory_order_acquire) == 0u;
            });
        }

        std::unordered_map<uint64_t, ActiveRequestSlot> remaining;
        remaining.swap(activeRequests_);
        for (auto& kv : remaining) {
            if (kv.second.req != nullptr) {
                kv.second.req->detachScriptHandlers(true);
                kv.second.req->release();
            }
        }
    }

    void ensureScheduled() {
        if (auto* director = ax::Director::getInstance()) {
            if (auto* scheduler = director->getScheduler()) {
                const auto sel = schedule_selector(WinHttpClient::dispatchCallbacks);
                if (!scheduler->isScheduled(sel, this)) {
                    scheduler->schedule(sel, this, 0.0f, false);
                }
            }
        }
    }

    static WinHttpClient* instance_;
    std::shared_ptr<SharedQueueState> sharedState_ = std::make_shared<SharedQueueState>();
    std::unordered_map<uint64_t, ActiveRequestSlot> activeRequests_;
    uint64_t nextRequestId_ = 0;
    std::atomic<uint64_t> dispatchEpoch_{1};
    std::string cookieFile_;
};

WinHttpClient* WinHttpClient::instance_ = nullptr;

// ============================================================================
// Generic tolua++ / LuaBindTemplates.h Bindings for HTTP Classes
// ============================================================================

inline WinHttpRequest* checkReq(lua_State* L, int idx = 1) {
    return lb::getAxObject<WinHttpRequest>(L, idx, "CCHttpRequest");
}
inline WinHttpResponse* checkResp(lua_State* L, int idx = 1) {
    return lb::getAxObject<WinHttpResponse>(L, idx, "CCHttpResponse");
}
inline WinHttpClient* checkClient(lua_State* L, int idx = 1) {
    return lb::getAxObject<WinHttpClient>(L, idx, "CCHttpClient");
}

template <int WinHttpRequest::*Field, int DefaultVal = 0>
int luaReqSetInt(lua_State* L) {
    if (auto* r = checkReq(L)) r->*Field = static_cast<int>(tolua_tonumber(L, 2, DefaultVal));
    return 0;
}

template <int WinHttpRequest::*Field, int DefaultVal = 0>
int luaReqGetInt(lua_State* L) {
    auto* r = checkReq(L);
    lua_pushnumber(L, r ? r->*Field : DefaultVal);
    return 1;
}

template <typename ObjT, lb::FixedName BaseTag, std::string ObjT::*Field, bool BinarySafe = false>
int luaObjGetStr(lua_State* L) {
    auto* obj = lb::getAxObject<ObjT>(L, 1, BaseTag.c_str());
    if (!obj) {
        lua_pushstring(L, "");
        return 1;
    }
    const std::string& s = obj->*Field;
    if constexpr (BinarySafe) lua_pushlstring(L, s.data(), s.size());
    else lua_pushstring(L, s.c_str());
    return 1;
}

template <typename ObjT, lb::FixedName BaseTag, std::string ObjT::*Field>
int luaObjGetStrSize(lua_State* L) {
    auto* obj = lb::getAxObject<ObjT>(L, 1, BaseTag.c_str());
    lua_pushnumber(L, obj ? static_cast<lua_Number>((obj->*Field).size()) : 0);
    return 1;
}

template <int WinHttpRequest::*HandlerField>
int luaReqSetScriptFunc(lua_State* L) {
    if (auto* r = checkReq(L)) {
        tolua_Error err{};
        if (toluafix_isfunction(L, 2, "LUA_FUNCTION", 0, &err)) {
            r->bindScriptState(L);
            if (r->*HandlerField != 0 && getLiveEngineLuaState() == L) {
                if (auto* eng = ax::ScriptEngineManager::getInstance()->getScriptEngine()) {
                    eng->removeScriptHandler(r->*HandlerField);
                }
            }
            r->*HandlerField = toluafix_ref_function(L, 2, 0);
        }
    }
    return 0;
}

int lua_HttpReq_setUrl(lua_State* L) {
    if (auto* r = checkReq(L)) {
        const char* u = tolua_tostring(L, 2, "");
        r->url = rewriteLegacyStagingUrl(u ? u : "");
    }
    return 0;
}

int lua_HttpReq_setRequestData(lua_State* L) {
    if (auto* r = checkReq(L)) {
        size_t len = 0;
        if (const char* d = lua_tolstring(L, 2, &len)) {
            r->requestData.assign(d, clampOptionalLengthArg(L, 3, len));
        } else {
            r->requestData.clear();
        }
    }
    return 0;
}

int lua_HttpReq_setTag(lua_State* L) {
    if (auto* r = checkReq(L)) {
        const char* t = tolua_tostring(L, 2, "");
        r->tag = t ? t : "";
    }
    return 0;
}

int lua_HttpReq_getTarget(lua_State* L) {
    lua_pushnil(L);
    return 1;
}

int lua_LuaHttpReq_newRequest(lua_State* L) {
    auto* req = new WinHttpRequest();
    req->ownerLuaState = L;
    lb::pushAxObject(L, req, "LuaHttpRequest");
    return 1;
}

int lua_LuaHttpReq_setHeaders(lua_State* L) {
    if (auto* r = checkReq(L)) {
        r->headers.clear();
        if (lua_istable(L, 2)) {
            const int n = static_cast<int>(lua_objlen(L, 2));
            for (int i = 1; i <= n; ++i) {
                lua_rawgeti(L, 2, i);
                if (const char* s = lua_tostring(L, -1)) r->headers.emplace_back(s);
                lua_pop(L, 1);
            }
        }
    }
    return 0;
}

int lua_LuaHttpReq_addHeader(lua_State* L) {
    if (auto* r = checkReq(L)) {
        if (const char* h = tolua_tostring(L, 2, nullptr)) r->headers.emplace_back(h);
    }
    return 0;
}

int lua_LuaHttpReq_getHeaders(lua_State* L) {
    auto* r = checkReq(L);
    lua_newtable(L);
    if (r) {
        for (size_t i = 0; i < r->headers.size(); ++i) {
            lua_pushlstring(L, r->headers[i].data(), r->headers[i].size());
            lua_rawseti(L, -2, static_cast<int>(i + 1));
        }
    }
    return 1;
}

int lua_HttpResp_isSucceed(lua_State* L) {
    auto* r = checkResp(L);
    lua_pushboolean(L, (r && r->succeed) ? 1 : 0);
    return 1;
}

int lua_HttpResp_getResponseCode(lua_State* L) {
    auto* r = checkResp(L);
    lua_pushnumber(L, r ? static_cast<lua_Number>(r->responseCode) : 0);
    return 1;
}

int lua_LuaHttpResp_getRequest(lua_State* L) {
    auto* r = checkResp(L);
    lb::pushAxObject(L, r ? r->request : nullptr, "LuaHttpRequest");
    return 1;
}

int lua_HttpClient_getInstance(lua_State* L) {
    lb::pushAxObject(L, WinHttpClient::getInstance(), "CCHttpClient");
    return 1;
}

int lua_HttpClient_destroyInstance(lua_State* /*L*/) {
    WinHttpClient::destroyInstance();
    return 0;
}

int lua_HttpClient_send(lua_State* L) {
    auto* c = checkClient(L, 1);
    auto* req = checkReq(L, 2);
    if (c && req) {
        req->bindScriptState(L);
        c->send(req);
    }
    return 0;
}

int lua_gclient_rewriteHttpUrl(lua_State* L) {
    size_t len = 0;
    const char* raw = lua_tolstring(L, 1, &len);
    if (!raw || len == 0) {
        lua_pushvalue(L, 1);
        return 1;
    }
    const std::string_view sv(raw, len);
    const ParsedHttpUrl parsed = parseHttpUrl(sv);
    if (parsed.valid && isDeadStagingHost(parsed.hostLower) &&
        (parsed.path == "/" || parsed.path.empty()) && parsed.query.empty()) {
        const std::string origin = resolveActiveCobaltRelayOrigin();
        lua_pushlstring(L, origin.data(), origin.size());
        return 1;
    }
    const std::string rewritten = rewriteLegacyStagingUrl(sv);
    lua_pushlstring(L, rewritten.data(), rewritten.size());
    return 1;
}

int lua_gclient_onLuaSoftRestart(lua_State* L) {
    cancelLuaHttpRequestsForState(L);
#if GCLIENT_HTTP_HAS_CNETWORK
    if (auto* net = gclient::net::CNetwork::peekSharedNetwork()) {
        net->resetForRestart(false);
    }
#endif
    return 0;
}

struct ToluaConstDef {
    const char* name;
    lua_Number value;
};

void registerToluaClass(
    lua_State* L,
    const char* name,
    const char* base,
    std::span<const ToluaConstDef> consts,
    std::span<const luaL_Reg> funcs)
{
    tolua_usertype(L, name);
    tolua_cclass(L, name, name, base, nullptr);
    tolua_beginmodule(L, name);
    for (const auto& c : consts) tolua_constant(L, c.name, c.value);
    for (const auto& f : funcs) {
        if (f.name && f.func) tolua_function(L, f.name, f.func);
    }
    tolua_endmodule(L);
}

} // namespace

void registerLuaHttpAndCrypto(lua_State* tolua_S) {
    static constexpr ToluaConstDef kHttpReqConsts[] = {
        {"kHttpGet", 0.0}, {"kHttpPost", 1.0}, {"kHttpPut", 2.0}, {"kHttpDelete", 3.0}, {"kHttpUnkown", 4.0},
    };
    static constexpr luaL_Reg kHttpReqFuncs[] = {
        {"setRequestType", luaReqSetInt<&WinHttpRequest::requestType, 0>},
        {"getRequestType", luaReqGetInt<&WinHttpRequest::requestType, 0>},
        {"setUrl", lua_HttpReq_setUrl},
        {"getUrl", luaObjGetStr<WinHttpRequest, "CCHttpRequest", &WinHttpRequest::url>},
        {"setRequestData", lua_HttpReq_setRequestData},
        {"getRequestData", luaObjGetStr<WinHttpRequest, "CCHttpRequest", &WinHttpRequest::requestData, true>},
        {"getRequestDataSize", luaObjGetStrSize<WinHttpRequest, "CCHttpRequest", &WinHttpRequest::requestData>},
        {"setTag", lua_HttpReq_setTag},
        {"getTag", luaObjGetStr<WinHttpRequest, "CCHttpRequest", &WinHttpRequest::tag>},
        {"getTarget", lua_HttpReq_getTarget},
        {"setTimeoutForConnect", luaReqSetInt<&WinHttpRequest::timeoutConnect, 30>},
        {"getTimeoutForConnect", luaReqGetInt<&WinHttpRequest::timeoutConnect, 30>},
        {"setTimeoutForRead", luaReqSetInt<&WinHttpRequest::timeoutRead, 60>},
        {"getTimeoutForRead", luaReqGetInt<&WinHttpRequest::timeoutRead, 60>},
        {"setTimeoutForLowSpeed", luaReqSetInt<&WinHttpRequest::timeoutLowSpeed, 0>},
        {"getTimeoutForLowSpeed", luaReqGetInt<&WinHttpRequest::timeoutLowSpeed, 0>},
        {"setLowSpeed", luaReqSetInt<&WinHttpRequest::lowSpeed, 0>},
        {"getLowSpeed", luaReqGetInt<&WinHttpRequest::lowSpeed, 0>},
    };
    registerToluaClass(tolua_S, "CCHttpRequest", "ax.Object", kHttpReqConsts, kHttpReqFuncs);

    static constexpr luaL_Reg kHttpRespFuncs[] = {
        {"isSucceed", lua_HttpResp_isSucceed},
        {"getResponseCode", lua_HttpResp_getResponseCode},
        {"getErrorBuffer", luaObjGetStr<WinHttpResponse, "CCHttpResponse", &WinHttpResponse::errorBuffer>},
    };
    registerToluaClass(tolua_S, "CCHttpResponse", "ax.Object", {}, kHttpRespFuncs);

    static constexpr luaL_Reg kHttpClientFuncs[] = {
        {"getInstance", lua_HttpClient_getInstance},
        {"destroyInstance", lua_HttpClient_destroyInstance},
        {"send", lua_HttpClient_send},
        {"enableCookies", lb::bindAxMethod<&WinHttpClient::enableCookies>},
    };
    registerToluaClass(tolua_S, "CCHttpClient", "ax.Object", {}, kHttpClientFuncs);

    static constexpr luaL_Reg kLuaHttpReqFuncs[] = {
        {"newRequest", lua_LuaHttpReq_newRequest},
        {"setHeaders", lua_LuaHttpReq_setHeaders},
        {"addHeader", lua_LuaHttpReq_addHeader},
        {"getHeaders", lua_LuaHttpReq_getHeaders},
        {"setResponseScriptFunc", luaReqSetScriptFunc<&WinHttpRequest::responseScriptFunc>},
        {"setBodyDataScriptFunc", luaReqSetScriptFunc<&WinHttpRequest::bodyDataScriptFunc>},
        {"setHeaderDataScriptFunc", luaReqSetScriptFunc<&WinHttpRequest::headerDataScriptFunc>},
    };
    registerToluaClass(tolua_S, "LuaHttpRequest", "CCHttpRequest", {}, kLuaHttpReqFuncs);

    static constexpr luaL_Reg kLuaHttpRespFuncs[] = {
        {"getHeaders", luaObjGetStr<WinHttpResponse, "CCHttpResponse", &WinHttpResponse::headers, true>},
        {"getHeadersSize", luaObjGetStrSize<WinHttpResponse, "CCHttpResponse", &WinHttpResponse::headers>},
        {"getResponseData", luaObjGetStr<WinHttpResponse, "CCHttpResponse", &WinHttpResponse::responseData, true>},
        {"getResponseDataSize", luaObjGetStrSize<WinHttpResponse, "CCHttpResponse", &WinHttpResponse::responseData>},
        {"getRequest", lua_LuaHttpResp_getRequest},
    };
    registerToluaClass(tolua_S, "LuaHttpResponse", "CCHttpResponse", {}, kLuaHttpRespFuncs);

    static constexpr ToluaConstDef kCryptoConsts[] = {
        {"EDigestMD5", 1.0}, {"EDigestSha1", 2.0},
    };
    static constexpr luaL_Reg kCryptoFuncs[] = {
        {"encodeBase64", luaCryptoBytesOp<&CCCrypto::encodeBase64>},
        {"decodeBase64", luaCryptoStrOp<&CCCrypto::decodeBase64>},
        {"md5", luaCryptoHash<&CCCrypto::md5>},
        {"sha1", luaCryptoHash<&CCCrypto::sha1>},
        {"bin2hex", luaCryptoBytesOp<&CCCrypto::bin2hex>},
        {"createDigest", lua_CCCrypto_createDigest},
        {"addBytes", lua_Digest_addBytes},
        {"getDigest", lua_Digest_getDigest},
        {"hex2bin", luaCryptoStrOp<&CCCrypto::hex2bin>},
    };
    registerToluaClass(tolua_S, "CCCrypto", "", kCryptoConsts, kCryptoFuncs);

    lua_pushcfunction(tolua_S, lua_gclient_rewriteHttpUrl);
    lua_setglobal(tolua_S, "__gclient_rewrite_http_url");

    lua_pushcfunction(tolua_S, lua_gclient_onLuaSoftRestart);
    lua_setglobal(tolua_S, "__gclient_on_lua_soft_restart");
}

void cancelLuaHttpRequestsForState(lua_State* L) {
    if (auto* client = WinHttpClient::peekInstance()) {
        client->cancelRequestsForLuaState(L);
    }
}

void shutdownLuaHttpClient() {
    WinHttpClient::destroyInstance();
}

} // namespace bindings
} // namespace gclient

void gclient_rescheduleHttpClientCallbacks() {
    gclient::bindings::WinHttpClient::rescheduleIfAlive();
}
