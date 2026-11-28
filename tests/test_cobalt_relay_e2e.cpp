// ============================================================================
// tests/test_cobalt_relay_e2e.cpp
// Strict Cross-Project End-to-End Integration Test Suite
// Wiring kestrel-canvas (C++20 CNetwork + CConnection + LCPacket + BtDecryptHook
// + Amf3WireCodec + KestrelCrypto/Utf8/Json + optional LuaJIT Amf3Module)
// <-> cobalt-relay (gserver --strict-all).
// ============================================================================

#include "TestHarness.h"
#include "assets/BtDecryptHook.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelJson.h"
#include "common/KestrelUtf8.h"
#include "net/Amf3WireCodec.h"
#include "net/CConnection.h"
#include "net/CNetwork.h"
#include "net/LCPacket.h"
#include "update/AtomicHotUpdater.h"

#if defined(GCLIENT_WITH_LUAJIT_AMF3)
#include "net/Amf3Module.h"
extern "C" {
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
}
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

using gclient::amf3::Amf3Decoder;
using gclient::amf3::Amf3Encoder;
using gclient::amf3::Amf3Value;
using gclient::json::JsonValue;

constexpr const char* kVnsg2MapiAppKey = "2A0ce68806G8aJ58Mo6_vnsg2@OmZHv";
constexpr const char* kGtsdkGameId     = "GCLIENT";
constexpr const char* kGtsdkAuthSecret = "d345c6c5c29669eae007b682625fbf42";

inline Amf3Value avInt(int64_t v) { return Amf3Value::makeInt(v); }
inline Amf3Value avBool(bool v) { return Amf3Value::makeBool(v); }
inline Amf3Value avStr(std::string s) { return Amf3Value::makeString(std::move(s)); }
inline Amf3Value avArr(std::initializer_list<Amf3Value> items) {
    return Amf3Value::makeArray(std::vector<Amf3Value>(items));
}
inline Amf3Value decodeAmf3(std::string_view buf) { return Amf3Decoder(buf).decode(); }

Amf3Value decodeZlibAmf3(const std::string& compressed) {
    std::string raw;
    if (!gclient::net::LCPacket::zlibDecompress(
            reinterpret_cast<const uint8_t*>(compressed.data()), compressed.size(), raw)) {
        throw std::runtime_error("LCPacket::zlibDecompress failed on S2C blob");
    }
    return decodeAmf3(raw);
}

void closeRawSocket(SOCKET fd) noexcept {
#ifdef _WIN32
    ::closesocket(fd);
#else
    ::close(fd);
#endif
}

// ============================================================================
// 1. MAPI / GTSDK Signing & HTTP JSON Helper (Delegating to KestrelCrypto/Utf8/Json)
// ============================================================================

std::string signMapiTarget(const std::string& pathAndQuery, int64_t ts) {
    const auto qPos = pathAndQuery.find('?');
    const std::string path = (qPos == std::string::npos) ? pathAndQuery : pathAndQuery.substr(0, qPos);
    const std::string query = (qPos == std::string::npos) ? std::string() : pathAndQuery.substr(qPos + 1);

    std::vector<std::string> segments;
    std::stringstream ss(query);
    std::string item;
    while (std::getline(ss, item, '&')) {
        if (!item.empty() && item.rfind("sign=", 0) != 0 && item.rfind("time=", 0) != 0) {
            segments.push_back(item);
        }
    }
    segments.push_back("time=" + std::to_string(ts));

    std::vector<std::string> sorted = segments;
    std::sort(sorted.begin(), sorted.end());

    // Match BtPlatformWin32::sortUrlParams verbatim: concatenate sorted segments WITHOUT '&'!
    std::string canonical;
    for (const auto& seg : sorted) {
        canonical += seg;
    }
    const std::string sign = gclient::crypto::md5Hex(canonical + kVnsg2MapiAppKey);

    std::string finalQuery;
    for (size_t i = 0; i < segments.size(); ++i) {
        if (i > 0) {
            finalQuery.push_back('&');
        }
        finalQuery += segments[i];
    }
    finalQuery += "&sign=" + sign;
    return path + "?" + finalQuery;
}

std::string computeGuestAuthSig(const std::string& deviceId, const std::string& ts) {
    return gclient::crypto::md5Hex(std::string(kGtsdkAuthSecret) + kGtsdkGameId + deviceId + ts);
}

std::string computeAccountAuthSig(const std::string& username, const std::string& passMd5,
                                  const std::string& ts) {
    return gclient::crypto::md5Hex(std::string(kGtsdkAuthSecret) + kGtsdkGameId + username + passMd5 + ts);
}

struct HttpReply {
    int status = 0;
    std::vector<std::string> cookies;
    JsonValue json;
};

HttpReply httpGetJson(const std::string& host, uint16_t port, const std::string& target,
                      const std::vector<std::string>& cookies = {}) {
    gclient::net::WinsockSession wsa;
    (void)wsa;

    SOCKET fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) {
        throw std::runtime_error("http socket() failed");
    }
    auto guard = gclient::test::makeScopeExit([fd]() noexcept { closeRawSocket(fd); });

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        throw std::runtime_error("http connect() failed");
    }

    std::ostringstream req;
    req << "GET " << target << " HTTP/1.1\r\nHost: " << host << ":" << port
        << "\r\nConnection: close\r\n";
    if (!cookies.empty()) {
        req << "Cookie: ";
        for (size_t i = 0; i < cookies.size(); ++i) {
            if (i > 0) req << "; ";
            req << cookies[i];
        }
        req << "\r\n";
    }
    req << "\r\n";
    const std::string reqStr = req.str();
    size_t sent = 0;
    while (sent < reqStr.size()) {
#ifdef _WIN32
        const auto chunk = static_cast<int>(reqStr.size() - sent);
#else
        const auto chunk = reqStr.size() - sent;
#endif
        const auto n = ::send(fd, reqStr.data() + sent, chunk, 0);
        if (n <= 0) break;
        sent += static_cast<size_t>(n);
    }

    std::string raw;
    char buf[4096];
    while (true) {
        const auto n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        raw.append(buf, static_cast<size_t>(n));
    }

    const auto split = raw.find("\r\n\r\n");
    if (split == std::string::npos) {
        throw std::runtime_error("invalid HTTP response header");
    }
    HttpReply out;
    std::istringstream hs(raw.substr(0, split));
    std::string statusLine;
    std::getline(hs, statusLine);
    {
        std::istringstream sl(statusLine);
        std::string httpVer;
        sl >> httpVer >> out.status;
    }
    std::string line;
    while (std::getline(hs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string k = line.substr(0, colon);
            std::transform(k.begin(), k.end(), k.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (k == "set-cookie") {
                std::string v = line.substr(colon + 1);
                while (!v.empty() && v.front() == ' ') v.erase(v.begin());
                const auto semi = v.find(';');
                out.cookies.push_back(semi == std::string::npos ? v : v.substr(0, semi));
            }
        }
    }
    std::string parseErr;
    if (!gclient::json::parse(raw.substr(split + 4), out.json, &parseErr)) {
        throw std::runtime_error("HTTP JSON parse error: " + parseErr);
    }
    return out;
}

std::string requireJsonStr(const JsonValue& obj, std::string_view key) {
    const JsonValue* v = obj.find(key);
    if (!v) throw std::runtime_error("missing JSON field: " + std::string(key));
    return v->asString();
}

// ============================================================================
// 2. Real kestrel-canvas CNetwork + CConnection + LCPacket Live Wire Client
// ============================================================================

struct AuthTicket {
    std::string pid;
    std::string hash;
    uint16_t tcpPort = 0;
};

struct S2cDecodedMsg {
    std::string err;
    std::string callbackName;
    std::string token;
    Amf3Value ret;
};

class RealKestrelWireClient {
public:
    RealKestrelWireClient() = default;
    ~RealKestrelWireClient() { disconnect(); }

    bool connectToRelay(const std::string& host, uint16_t port) {
        auto* net = gclient::net::CNetwork::sharedNetwork();
        conn_ = net->newConnection();
        if (!conn_) return false;
        conn_->setHeaderSize(8);
        conn_->setHeadCallback([](const char* hdr, size_t hdrSize) -> uint32_t {
            if (!hdr || hdrSize < 8) return 0;
            return gclient::net::LCPacket::readBigEndianU32(reinterpret_cast<const uint8_t*>(hdr));
        });
        conn_->setBodyCallback(
            [this](const char* body, size_t bodyLen, const char* hdr, size_t hdrLen) {
                if (!hdr || hdrLen < 8) return;
                const bool zipped = static_cast<uint8_t>(hdr[5]) != 0;
                const bool multi  = static_cast<uint8_t>(hdr[6]) != 0;

                std::string unpacked;
                if (zipped) {
                    if (!gclient::net::LCPacket::zlibDecompress(
                            reinterpret_cast<const uint8_t*>(body), bodyLen, unpacked)) {
                        return;
                    }
                } else {
                    unpacked.assign(body, bodyLen);
                }

                if (!multi) {
                    ingestSingleAmfEnvelope(unpacked);
                } else {
                    size_t off = 0;
                    while (off + 4 <= unpacked.size()) {
                        const uint32_t subLen = gclient::net::LCPacket::readBigEndianU32(
                            reinterpret_cast<const uint8_t*>(unpacked.data() + off));
                        off += 4;
                        if (off + subLen > unpacked.size()) break;
                        ingestSingleAmfEnvelope(unpacked.substr(off, subLen));
                        off += subLen;
                    }
                }
            });

        if (!conn_->connect(host.c_str(), port)) return false;
        net->addConnection(conn_);

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            net->update(0.016f);
            if (conn_->isConnected()) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return conn_->isConnected();
    }

    void disconnect() {
        if (conn_) {
            conn_->close();
            gclient::net::CNetwork::sharedNetwork()->removeConnection(conn_);
            conn_ = nullptr;
        }
    }

    S2cDecodedMsg callRpcRawArgs(const std::string& method, Amf3Value rawArgs,
                                 bool compressLCPacket = true) {
        ++seq_;
        const bool isTelemetry = (method == "user.stat" || method == "user.guideEvent");
        const std::string cbName = isTelemetry ? method : (method + "_" + std::to_string(seq_));

        Amf3Value reqObj = Amf3Value::makeMap({
            {"method", avStr(method)},
            {"args", std::move(rawArgs)},
            {"token", avStr(token_)},
            {"callback", Amf3Value::makeMap({{"callbackName", avStr(cbName)}})},
        });

        Amf3Encoder enc;
        const std::string rawAmf = enc.encode(reqObj);
        if (compressLCPacket) {
            if (!conn_->send(rawAmf, true)) {
                throw std::runtime_error("CConnection::send(wrapLCPacket=true) failed");
            }
        } else {
            const std::string framed = gclient::net::LCPacket::makeLCPacket(rawAmf, false);
            if (!conn_->send(framed, false)) {
                throw std::runtime_error("CConnection::send(uncompressed LCPacket) failed");
            }
        }

        return waitInbox(std::chrono::seconds(5),
                         [&](const S2cDecodedMsg& m) { return m.callbackName == cbName; },
                         "S2C callback: " + cbName);
    }

    S2cDecodedMsg callRpc(const std::string& method, std::vector<Amf3Value> args,
                          bool compressLCPacket = true) {
        return callRpcRawArgs(method, Amf3Value::makeArray(std::move(args)), compressLCPacket);
    }

    Amf3Value callOk(const std::string& method, std::vector<Amf3Value> args = {},
                     bool compressLCPacket = true) {
        auto resp = callRpc(method, std::move(args), compressLCPacket);
        if (resp.err != "ok") {
            throw std::runtime_error(method + " expected err='ok', got err='" + resp.err + "'");
        }
        return std::move(resp.ret);
    }

    std::string callErr(const std::string& method, std::vector<Amf3Value> args = {},
                        bool compressLCPacket = true) {
        return callRpc(method, std::move(args), compressLCPacket).err;
    }

    void loginTicket(const AuthTicket& tk, std::vector<Amf3Value> extraArgs = {},
                     bool compressLCPacket = true) {
        std::vector<Amf3Value> args;
        args.push_back(Amf3Value::makeMap({
            {"AMF", avInt(3)},
            {"pid", avStr(tk.pid)},
            {"qid", avStr(tk.pid)},
            {"hash", avStr(tk.hash)},
            {"serverID", avStr("game2900161")},
        }));
        for (auto& ex : extraArgs) args.push_back(std::move(ex));
        (void)callOk("user.login", std::move(args), compressLCPacket);
    }

    int64_t connectAndEnterGame(const std::string& host, uint16_t port, const AuthTicket& tk,
                                int64_t createUtid = 0, const std::string& createUname = "") {
        if (!connectToRelay(host, port)) {
            throw std::runtime_error("connectToRelay failed");
        }
        loginTicket(tk);
        if (createUtid > 0 && !createUname.empty()) {
            (void)callOk("user.createUser", {avInt(createUtid), avStr(createUname)});
        }
        const int64_t uid = callOk("user.getUserBeforLogin").get("uid")->asInt();
        if (uid <= 0) throw std::runtime_error("expected positive uid from getUserBeforLogin");
        if (callOk("user.userLogin", {avInt(uid)}).asString() != "ok") {
            throw std::runtime_error("user.userLogin did not return 'ok'");
        }
        return uid;
    }

    S2cDecodedMsg callPing(const std::string& method) {
        Amf3Value reqObj = Amf3Value::makeMap({
            {"method", avStr(method)},
            {"args", Amf3Value::makeEmptyArray()},
            {"token", avStr(token_)},
            {"callback", Amf3Value::makeMap({{"callbackName", avStr(method)}})},
        });
        Amf3Encoder enc;
        conn_->send(enc.encode(reqObj), true);
        return waitInbox(std::chrono::seconds(3),
                         [](const S2cDecodedMsg& m) { return m.err == "ping"; },
                         "S2C ping");
    }

    std::vector<S2cDecodedMsg> drainPushes(int waitMs = 100) {
        const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(waitMs);
        while (std::chrono::steady_clock::now() < until) {
            gclient::net::CNetwork::sharedNetwork()->update(0.016f);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<S2cDecodedMsg> out(inbox_.begin(), inbox_.end());
        inbox_.clear();
        return out;
    }

private:
    template <typename Pred>
    S2cDecodedMsg waitInbox(std::chrono::milliseconds timeout, Pred&& pred,
                            const std::string& waitDesc) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            gclient::net::CNetwork::sharedNetwork()->update(0.016f);
            {
                std::lock_guard<std::mutex> lk(mu_);
                for (auto it = inbox_.begin(); it != inbox_.end(); ++it) {
                    if (pred(*it)) {
                        S2cDecodedMsg found = std::move(*it);
                        inbox_.erase(it);
                        return found;
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(4));
        }
        throw std::runtime_error("Timed out waiting for " + waitDesc);
    }

    void ingestSingleAmfEnvelope(const std::string& amfBytes) {
        Amf3Value env = decodeAmf3(amfBytes);
        S2cDecodedMsg msg;
        if (const auto* e = env.get("err")) msg.err = e->asString();
        if (const auto* cb = env.get("callback")) {
            if (const auto* cbn = cb->get("callbackName")) msg.callbackName = cbn->asString();
        }
        if (const auto* tok = env.get("token")) {
            msg.token = tok->asString();
            if (!msg.token.empty() && msg.token != "0") token_ = msg.token;
        }
        if (const auto* r = env.get("ret")) msg.ret = *r;
        std::lock_guard<std::mutex> lk(mu_);
        inbox_.push_back(std::move(msg));
    }

    gclient::net::CConnection* conn_ = nullptr;
    uint64_t seq_ = 1;
    std::string token_ = "0";
    std::mutex mu_;
    std::deque<S2cDecodedMsg> inbox_;
};

AuthTicket exchangeMapiLoginAndHash(const std::string& httpHost, uint16_t httpPort,
                                    const std::string& userId, const std::string& sessionId,
                                    const std::string& uuidSuffix, int64_t loginTs,
                                    bool checkCookie102) {
    using gclient::utf8::urlEncode;
    const std::string loginTarget = signMapiTarget(
        "/phone/login/?pl=android_vnsg2&gn=vnsg2&os=win32&userid=" + urlEncode(userId) +
            "&sessionid=" + urlEncode(sessionId),
        loginTs);
    auto loginResp = httpGetJson(httpHost, httpPort, loginTarget);
    if (loginResp.cookies.empty() || !loginResp.json.find("pid")) {
        throw std::runtime_error("/phone/login missing cookies or pid");
    }
    const std::string pid = requireJsonStr(loginResp.json, "pid");

    const std::string hashTarget = signMapiTarget(
        "/phone/gethash/?pl=android_vnsg2&gn=vnsg2&pid=" + urlEncode(pid) +
            "&group_id=2900161&uuid=uuid_" + urlEncode(uuidSuffix),
        loginTs + 1);
    if (checkCookie102) {
        auto noCookieResp = httpGetJson(httpHost, httpPort, hashTarget);
        if (requireJsonStr(noCookieResp.json, "errornu") != "102") {
            throw std::runtime_error("expected errornu='102' when cookie omitted");
        }
    }

    auto hashResp = httpGetJson(httpHost, httpPort, hashTarget, loginResp.cookies);
    if (requireJsonStr(hashResp.json, "errornu") != "0") {
        throw std::runtime_error("/phone/gethash failed");
    }
    const JsonValue* portNode = hashResp.json.find("port");
    if (!portNode) throw std::runtime_error("/phone/gethash missing port");
    return AuthTicket{pid, requireJsonStr(hashResp.json, "hash"),
                      static_cast<uint16_t>(portNode->asInt64())};
}

AuthTicket strictGuestHandshake(const std::string& httpHost, uint16_t httpPort,
                                const std::string& deviceId, bool checkCookie102) {
    const std::string ts = "1795502000";
    const std::string sig = computeGuestAuthSig(deviceId, ts);
    auto guestResp = httpGetJson(
        httpHost, httpPort,
        "/api/login/createUser/guest?deviceID=" + gclient::utf8::urlEncode(deviceId) +
            "&gameID=" + kGtsdkGameId + "&timestamp=" + ts + "&sig=" + sig);
    if (requireJsonStr(guestResp.json, "errornu") != "0") {
        throw std::runtime_error("guest GTSDK auth failed");
    }
    return exchangeMapiLoginAndHash(httpHost, httpPort,
                                    requireJsonStr(guestResp.json, "userID"),
                                    requireJsonStr(guestResp.json, "sessionID"),
                                    deviceId, 1795502001, checkCookie102);
}

AuthTicket strictAccountHandshake(const std::string& httpHost, uint16_t httpPort,
                                  const std::string& username, const std::string& password) {
    const std::string ts    = "1795502010";
    const std::string pwMd5 = gclient::crypto::md5Hex(password);
    const std::string sig   = computeAccountAuthSig(username, pwMd5, ts);
    auto acctResp = httpGetJson(
        httpHost, httpPort,
        "/api/login/auth/account?u=" + gclient::utf8::urlEncode(username) + "&p=" + pwMd5 +
            "&gameID=" + kGtsdkGameId + "&timestamp=" + ts + "&sig=" + sig);
    if (requireJsonStr(acctResp.json, "errornu") != "0") {
        throw std::runtime_error("account GTSDK auth failed");
    }
    return exchangeMapiLoginAndHash(httpHost, httpPort,
                                    requireJsonStr(acctResp.json, "userID"),
                                    requireJsonStr(acctResp.json, "sessionID"),
                                    username, 1795502011, false);
}

std::vector<uint8_t> readBinaryFile(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) throw std::runtime_error("unable to open file: " + path);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)),
                                std::istreambuf_iterator<char>());
}

bool hasPush(const std::vector<S2cDecodedMsg>& pushes, const std::string& cbName) {
    return std::any_of(pushes.begin(), pushes.end(),
                       [&](const S2cDecodedMsg& p) { return p.callbackName == cbName; });
}

int64_t sumBagTemplateCount(const Amf3Value& bagRet, const std::string& subBagKey,
                            int64_t targetTid) {
    int64_t total = 0;
    const auto* sub = bagRet.get(subBagKey);
    if (!sub) return 0;
    for (const auto& kv : sub->fields) {
        const auto* tidVal = kv.second.get("item_template_id");
        const auto* numVal = kv.second.get("item_num");
        if (tidVal && numVal && tidVal->asInt() == targetTid) {
            total += numVal->asInt();
        }
    }
    return total;
}

int64_t findFirstBagGidByTemplate(const Amf3Value& bagRet, const std::string& subBagKey,
                                  int64_t targetTid) {
    const auto* sub = bagRet.get(subBagKey);
    if (!sub) return 0;
    for (const auto& kv : sub->fields) {
        const auto* tidVal = kv.second.get("item_template_id");
        if (tidVal && tidVal->asInt() == targetTid) {
            return std::stoll(kv.first);
        }
    }
    return 0;
}

// ============================================================================
// 3. Offline Self-Tests (LCPacket + BtDecryptHook + Amf3WireCodec + LuaJIT AMF3)
// ============================================================================

bool runSelfTests(const std::string& encLuaPath, const std::string& decLuaPath) {
    REQUIRE_TRUE(gclient::assets::HasDecryptKeys());

    if (!encLuaPath.empty() && !decLuaPath.empty()) {
        auto encBuf = readBinaryFile(encLuaPath);
        const auto decExpected = readBinaryFile(decLuaPath);
        REQUIRE_EQ(encBuf.size(), static_cast<size_t>(1729));
        REQUIRE_EQ(decExpected.size(), static_cast<size_t>(1697));
        REQUIRE_TRUE(gclient::assets::IsBtEncryptedBuffer(encBuf.data(), encBuf.size()));

        size_t ioSize = encBuf.size();
        gclient::assets::DecryptResult diag;
        REQUIRE_TRUE(gclient::assets::DecryptBuffer(encBuf.data(), &ioSize,
                                                    "MainTownSceneReader.lua", &diag));
        REQUIRE_EQ(ioSize, decExpected.size());
        REQUIRE_EQ(std::memcmp(encBuf.data(), decExpected.data(), ioSize), 0);
    }

    // Verify shared Amf3WireCodec + LCPacket 24-byte salted MD5 roundtrip
    Amf3Value sample = Amf3Value::makeMap({
        {"method", avStr("user.login")},
        {"args", avArr({avInt(2900161), avStr("TriệuTửLong")})},
        {"token", avStr("0")},
    });
    Amf3Encoder enc;
    const std::string raw = enc.encode(sample);
    const std::string pkt = gclient::net::LCPacket::makeLCPacket(raw, true);
    REQUIRE_TRUE(gclient::net::LCPacket::isFramedLCPacket(pkt.data(), pkt.size()));
    gclient::net::LCPacket::DecodedPacket decPkt;
    REQUIRE_TRUE(gclient::net::LCPacket::parseLCPacket(pkt.data(), pkt.size(), decPkt, true, true));
    REQUIRE_TRUE(decPkt.md5Valid);
    const Amf3Value round = decodeAmf3(decPkt.payload);
    REQUIRE_EQ(round.get("method")->asString(), std::string("user.login"));
    REQUIRE_EQ(round.get("args")->dense[0].asInt(), 2900161LL);

#if defined(GCLIENT_WITH_LUAJIT_AMF3)
    lua_State* L = luaL_newstate();
    REQUIRE_TRUE(L != nullptr);
    auto closeLua = gclient::test::makeScopeExit([L]() noexcept { lua_close(L); });
    luaL_openlibs(L);
    luaopen_amf3_extensions(L);
    const char* script =
        "local amf3 = require('amf3')\n"
        "local bin = amf3.encode({ method = 'city.enter', args = { 1 }, token = 'tok_1' })\n"
        "local t = amf3.decode(bin)\n"
        "assert(t.method == 'city.enter' and t.args[1] == 1 and t.token == 'tok_1')\n";
    REQUIRE_EQ(luaL_dostring(L, script), 0);
#endif

    return true;
}

} // namespace

int main(int argc, char** argv) {
    std::string httpHost = "127.0.0.1";
    uint16_t httpPort = 0;
    std::string tcpHost = "127.0.0.1";
    uint16_t tcpPort = 0;
    std::string encLuaPath;
    std::string decLuaPath;
    bool selfTestOnly  = false;
    bool verifyRestart = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--self-test") {
            selfTestOnly = true;
        } else if (arg == "--verify-restart") {
            verifyRestart = true;
        } else if (arg == "--http-host" && i + 1 < argc) {
            httpHost = argv[++i];
        } else if (arg == "--http-port" && i + 1 < argc) {
            httpPort = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--tcp-host" && i + 1 < argc) {
            tcpHost = argv[++i];
        } else if (arg == "--tcp-port" && i + 1 < argc) {
            tcpPort = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--enc-lua" && i + 1 < argc) {
            encLuaPath = argv[++i];
        } else if (arg == "--dec-lua" && i + 1 < argc) {
            decLuaPath = argv[++i];
        }
    }

    gclient::test::TestSuite suite;
    suite.run("CrossRepo_01_BtDecrypt_LCPacket_And_Amf3_Parity",
              [&]() { return runSelfTests(encLuaPath, decLuaPath); });

    if (selfTestOnly) {
        gclient::net::CNetwork::destroySharedNetwork();
        return suite.finishCompact("self-test mode");
    }

    if (httpPort == 0 || tcpPort == 0) {
        std::fprintf(stderr, "Missing --http-port / --tcp-port for live cobalt-relay mode\n");
        return 2;
    }

    if (verifyRestart) {
        suite.run("CrossRepo_16_VerifyColdRestart_WAL_State_CopyProgress_And_ActStar", [&]() {
            const auto tk = strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_alpha", true);
            REQUIRE_EQ(tk.tcpPort, tcpPort);

            const auto lrTarget = signMapiTarget(
                "/phone/loginrole/?pl=android_vnsg2&gn=vnsg2&pid=" + tk.pid, 1795503000);
            const auto lr = httpGetJson(httpHost, httpPort, lrTarget);
            const auto* root = lr.json.find("root");
            REQUIRE_TRUE(root != nullptr && root->find("role") != nullptr);
            const auto& roles = root->find("role")->arrVal;
            REQUIRE_FALSE(roles.empty());
            REQUIRE_EQ(requireJsonStr(roles[0], "uname"), std::string("LongĐởmThần"));
            REQUIRE_TRUE(roles[0].find("level")->asInt64() >= 35);

            RealKestrelWireClient client;
            (void)client.connectAndEnterGame(tcpHost, tcpPort, tk);

            auto u = client.callOk("user.getUser");
            REQUIRE_EQ(u.get("uname")->asString(), std::string("LongĐởmThần"));
            REQUIRE_TRUE(u.get("level")->asInt() >= 36LL);
            REQUIRE_TRUE(u.get("execution")->asInt() > 300LL);

            REQUIRE_EQ(client.callErr("user.buyVipGift", {avInt(1)}),
                       std::string("vip_gift_already_bought"));
            REQUIRE_EQ(client.callOk("user.getVaConfig").get("kestrel_key")->asString(),
                       std::string("win32_ok"));

            const auto cl = client.callOk("copy.getList", {avInt(1)});
            const auto* cd = cl.get("copyData");
            REQUIRE_TRUE(cd != nullptr);
            const auto* c1001 = cd->get("1001");
            REQUIRE_TRUE(c1001 != nullptr);
            REQUIRE_EQ(c1001->get("star")->asInt(), 15LL);
            REQUIRE_EQ(c1001->get("pass_strongh")->asInt(), 5LL);
            REQUIRE_EQ(c1001->get("prize")->asInt(), 1LL);
            REQUIRE_TRUE(cd->get("1002") != nullptr);

            const auto cc = client.callOk("copy.getCopy", {avInt(1001)});
            const auto* vaCopy = cc.get("va_copy");
            REQUIRE_TRUE(vaCopy != nullptr);
            for (const char* stgKey : {"100102", "100105"}) {
                REQUIRE_TRUE(vaCopy->get(stgKey) != nullptr);
                REQUIRE_EQ(vaCopy->get(stgKey)->get("normal_star")->asInt(), 3LL);
                REQUIRE_EQ(vaCopy->get(stgKey)->get("pass")->asInt(), 1LL);
            }
            REQUIRE_EQ(client.callErr("copy.fetchPrize", {avInt(1001), avInt(0)}),
                       std::string("prize_already_claimed"));

            const auto starInfo = client.callOk("activityStarPlayOpen.getInfo");
            for (const char* claimedId : {"1", "4"}) {
                REQUIRE_TRUE(starInfo.get(claimedId) != nullptr &&
                             starInfo.get(claimedId)->kind == Amf3Value::Kind::Bool &&
                             starInfo.get(claimedId)->boolVal);
            }
            REQUIRE_TRUE(starInfo.get("2") == nullptr && starInfo.get("5") == nullptr);
            REQUIRE_EQ(client.callErr("activityStarPlayOpen.receiveGift", {avInt(1)}),
                       std::string("already_claimed"));
            REQUIRE_EQ(client.callErr("activityStarPlayOpen.receiveGift", {avInt(5)}),
                       std::string("level_not_enough"));
            REQUIRE_EQ(client.callErr("activityStarPlayOpen.receiveGift", {avInt(99)}),
                       std::string("invalid_gift_id"));

            const auto bag = client.callOk("bag.bagInfo");
            REQUIRE_TRUE(sumBagTemplateCount(bag, "item", 17002) >= 5LL);
            REQUIRE_EQ(sumBagTemplateCount(bag, "soul", 50406), 35LL);
            REQUIRE_TRUE(sumBagTemplateCount(bag, "item", 10010) >= 20LL);
            REQUIRE_TRUE(sumBagTemplateCount(bag, "item", 22202) >= 3LL);

            client.disconnect();
            return true;
        });

        gclient::net::CNetwork::destroySharedNetwork();
        return suite.finishCompact("restart-verify mode");
    }

    // Shared cross-case live state for the 12-domain gameplay campaign
    AuthTicket tkA;
    AuthTicket tkB;
    RealKestrelWireClient clientA;
    RealKestrelWireClient clientB;
    int64_t uidA = 0;
    int64_t uidB = 0;
    int64_t composedHid = 0;
    int64_t craftedArmGid = 0;

    suite.run("CrossRepo_02_StrictHttp_MapiSign_AuthSig_Session102_And_DynamicPort", [&]() {
        auto unsignedVer = httpGetJson(httpHost, httpPort, "/phone/getversion?pl=android_vnsg2&gn=vnsg2");
        REQUIRE_TRUE(unsignedVer.json.find("err_code") != nullptr);
        REQUIRE_EQ(unsignedVer.json.find("err_code")->asInt64(), 403LL);

        for (const char* ep : {
                 "/phone/getversion?pl=android_vnsg2&gn=vnsg2&os=win32",
                 "/phone/serverlist/?pl=android_vnsg2&gn=vnsg2",
                 "/phone/applereview/?pl=android_vnsg2&gn=vnsg2",
                 "/phone/notice/?pl=android_vnsg2&gn=vnsg2",
                 "/phone/supernotice/?pl=android_vnsg2&gn=vnsg2",
             }) {
            auto r = httpGetJson(httpHost, httpPort, signMapiTarget(ep, 1795502000));
            REQUIRE_EQ(r.status, 200);
            REQUIRE_TRUE(r.json.find("err_code") == nullptr ||
                         r.json.find("err_code")->asInt64() != 403LL);
        }

        auto unsignedGuest = httpGetJson(
            httpHost, httpPort,
            "/api/login/createUser/guest?deviceID=kestrel_cpp_alpha&gameID=GCLIENT");
        REQUIRE_EQ(requireJsonStr(unsignedGuest.json, "returnCode"), std::string("-3"));

        auto forgedLogin = httpGetJson(
            httpHost, httpPort,
            signMapiTarget("/phone/login/?pl=android_vnsg2&gn=vnsg2&userid=8888&sessionid=SID_bad",
                           1795502005));
        REQUIRE_NE(requireJsonStr(forgedLogin.json, "errornu"), std::string("0"));

        tkA = strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_alpha", true);
        tkB = strictAccountHandshake(httpHost, httpPort, "kestrel_quanvu", "Win32@2026");
        REQUIRE_EQ(tkA.tcpPort, tcpPort);
        REQUIRE_EQ(tkB.tcpPort, tcpPort);
        return true;
    });

    suite.run("CrossRepo_03_RealCNetwork_PreLogin_BadTicket_Ping_And_28StepBootstrap", [&]() {
        REQUIRE_TRUE(clientA.connectToRelay(tcpHost, tcpPort));
        REQUIRE_TRUE(clientB.connectToRelay(tcpHost, tcpPort));

        REQUIRE_EQ(clientA.callErr("user.getUser"), std::string("user_not_logged_in"));
        REQUIRE_EQ(clientA.callErr(
                       "user.login",
                       {Amf3Value::makeMap({
                           {"pid", avStr(tkA.pid)},
                           {"qid", avStr(tkA.pid)},
                           {"hash", avStr("forged_hash_xyz")},
                           {"serverID", avStr("game2900161")},
                       })},
                       false),
                   std::string("invalid_login_hash"));

        REQUIRE_EQ(clientA.callPing("ping").err, std::string("ping"));
        REQUIRE_EQ(clientA.callPing("user.ping").err, std::string("ping"));

        clientA.loginTicket(tkA, {avStr("uuid_kestrel_alpha"), avStr("1.0.1194")}, true);
        (void)clientA.callOk("user.getUserBeforLogin");
        (void)clientA.callOk("user.getRandomName", {avInt(10), avInt(1)});
        (void)clientA.callOk("user.stat", {avInt(1)});

        REQUIRE_EQ(clientA.callErr("user.createUser", {avInt(999), avStr("Bad")}),
                   std::string("invalid_utid"));
        (void)clientA.callOk("user.createUser", {avInt(1), avStr("TriệuTửLong")});

        uidA = clientA.callOk("user.getUserBeforLogin").get("uid")->asInt();
        REQUIRE_TRUE(uidA > 0);
        REQUIRE_EQ(clientA.callOk("user.userLogin", {avInt(uidA)}).asString(), std::string("ok"));

        const std::vector<std::pair<std::string, std::vector<Amf3Value>>> bootSteps = {
            {"user.getUser", {}},
            {"switchfunc.getSwitch", {}},
            {"user.getVaConfig", {}},
            {"formation.get", {}},
            {"formation.getPositionInfo", {}},
            {"bag.bagInfo", {Amf3Value::makeEmptyArray()}},
            {"copy.getList", {avInt(1)}},
            {"copy.getCopy", {avInt(1001)}},
            {"allActivity.getActivityInfo", {}},
            {"activity.getActivityConf", {}},
            {"mail.getMailBoxList", {}},
            {"reward.getRewardList", {avInt(0), avInt(0)}},
            {"sign.getInfo", {}},
            {"online.getInfo", {}},
            {"openOnline.getInfo", {}},
            {"raffle.getInfo", {}},
            {"halidom.getInfo", {}},
            {"opencarnival.getOpenAchieve", {}},
            {"lordwar.getTempleInfo", {}},
            {"crossClanBattle.getTempleInfo", {}},
            {"crossClanBattle.getPromotionInfo", {}},
            {"activityAnswer.getInfo", {}},
            {"smallgame.getInfo", {}},
            {"user.guideEvent", {avInt(240)}},
            {"barrage.get", {}},
            {"barrage.enterRoom", {avInt(1)}},
            {"barrage.getBarrageRecord", {avInt(1)}},
        };
        for (size_t idx = 0; idx < bootSteps.size(); ++idx) {
            (void)clientA.callOk(bootSteps[idx].first, bootSteps[idx].second, (idx % 2) == 0);
        }

        REQUIRE_EQ(clientA.callErr("nonexistent.fakeMethod"), std::string("unsupported_method"));

        clientB.loginTicket(tkB);
        REQUIRE_EQ(clientB.callErr("user.createUser", {avInt(2), avStr("TriệuTửLong")}),
                   std::string("uname_used"));
        (void)clientB.callOk("user.createUser", {avInt(2), avStr("QuanVũVIP")});
        uidB = clientB.callOk("user.getUserBeforLogin").get("uid")->asInt();
        REQUIRE_EQ(clientB.callOk("user.userLogin", {avInt(uidB)}).asString(), std::string("ok"));
        return true;
    });

    suite.run("CrossRepo_04_Progression_Rename_Stamina_Copper_HeroBag_VipGift_VaConfig", [&]() {
        (void)clientA.drainPushes(20);
        REQUIRE_EQ(clientA.callErr("user.changeUname", {avStr("QuanVũVIP")}),
                   std::string("uname_used"));
        (void)clientA.callOk("user.changeUname", {avStr("LongĐởmThần")});
        (void)clientA.callOk("user.buyCopper", {avInt(2)});
        (void)clientA.callOk("user.buyExecution", {avInt(1)});
        (void)clientA.callOk("user.addEnergy", {avInt(1)});
        (void)clientA.callOk("user.openHeroBag", {avInt(2)});

        REQUIRE_EQ(clientA.callErr("user.buyVipGift", {avInt(12)}), std::string("vip_too_low"));
        (void)clientA.callOk("user.buyVipGift", {avInt(1)});
        REQUIRE_EQ(clientA.callErr("user.buyVipGift", {avInt(1)}),
                   std::string("vip_gift_already_bought"));
        (void)clientA.callOk("user.getVipGiftInfo");

        (void)clientA.callOk("user.setVaConfig", {avStr("kestrel_key"), avStr("win32_ok")});
        REQUIRE_EQ(clientA.callOk("user.getVaConfig").get("kestrel_key")->asString(),
                   std::string("win32_ok"));

        REQUIRE_TRUE(hasPush(clientA.drainPushes(60), "user.updateUser"));
        return true;
    });

    suite.run("CrossRepo_05_Inventory_42SubBags_UseItem_Sell_Expand_And_Compose", [&]() {
        REQUIRE_EQ(clientA.callOk("bag.openGridByGold", {avInt(5), avStr("arm")}).asString(),
                   std::string("ok"));

        const auto bag = clientA.callOk("bag.bagInfo");
        const int64_t gid22102 = findFirstBagGidByTemplate(bag, "item", 22102);
        const int64_t gid16012 = findFirstBagGidByTemplate(bag, "item", 16012);
        REQUIRE_TRUE(gid22102 > 0 && gid16012 > 0);

        REQUIRE_EQ(clientA.callErr("exchange.useItemInBag", {avInt(39999), avInt(1)}),
                   std::string("item_not_found"));
        REQUIRE_EQ(clientA.callErr("exchange.useItemInBag", {avInt(gid22102), avInt(9999)}),
                   std::string("insufficient_item_count"));

        (void)clientA.drainPushes(20);
        (void)clientA.callOk("exchange.useItemInBag", {avInt(gid22102), avInt(2)});
        (void)clientA.callOk("exchange.useItemInBagByTpl", {avInt(22202), avInt(3)});
        (void)clientA.callOk("bag.sellItems",
                             {avArr({avArr({avInt(gid16012), avInt(0), avInt(5)})})});

        const auto ch = clientA.callOk("exchange.composeHero", {avInt(50101), avInt(1)});
        if (ch.get("hid") != nullptr) composedHid = ch.get("hid")->asInt();

        const auto heroesAfterComp = clientA.callOk("hero.getAllHeroes");
        for (const auto& kv : heroesAfterComp.fields) {
            const int64_t h = std::stoll(kv.first);
            if (h > composedHid && kv.second.get("htid") != nullptr &&
                kv.second.get("htid")->asInt() == 101) {
                composedHid = h;
            }
        }
        if (composedHid == 0) {
            for (const auto& kv : heroesAfterComp.fields) {
                const int64_t h = std::stoll(kv.first);
                if (h > 10000003LL) composedHid = std::max(composedHid, h);
            }
        }
        REQUIRE_TRUE(composedHid > 10000001LL);

        REQUIRE_EQ(clientA.callOk("exchange.composeArm", {avInt(3113001), avInt(1)}).asString(),
                   std::string("ok"));
        craftedArmGid = findFirstBagGidByTemplate(clientA.callOk("bag.bagInfo"), "arm", 113001);
        REQUIRE_TRUE(craftedArmGid >= 10001LL);
        REQUIRE_EQ(clientA.callErr("exchange.composeArm", {avInt(3113001), avInt(1)}),
                   std::string("insufficient_item_count"));

        const auto pushes = clientA.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushes, "bag.update"));
        REQUIRE_TRUE(hasPush(pushes, "re.hero.new"));
        return true;
    });

    suite.run("CrossRepo_06_HeroRoster_LevelUp_Skill_Surmount_LockGuard_And_Evolve", [&]() {
        REQUIRE_EQ(clientA.callErr("hero.heroLevelUp", {avInt(10000001), avInt(1)}),
                   std::string("protagonist_cannot_level_directly"));

        const auto lv = clientA.callOk("hero.heroLevelUp", {avInt(composedHid), avInt(5)});
        REQUIRE_TRUE(lv.get("newlv") != nullptr);
        REQUIRE_EQ(lv.get("newlv")->asInt(), 6LL);

        (void)clientA.callOk("hero.skillLevelUp", {avInt(composedHid), avInt(2001)});
        (void)clientA.callOk("evolve.surmount", {avInt(composedHid)});
        (void)clientA.callOk("chat.sendWorld", {avInt(1), avStr("/hero 305")});

        int64_t fodderHid = 0;
        for (const auto& kv : clientA.callOk("hero.getAllHeroes").fields) {
            if (kv.second.get("htid")->asInt() == 305) fodderHid = std::stoll(kv.first);
        }
        REQUIRE_TRUE(fodderHid > 0);

        (void)clientA.callOk("hero.lock", {avInt(fodderHid)});
        REQUIRE_EQ(clientA.callErr("evolve.doEvolve",
                                   {avInt(composedHid), avArr({avInt(fodderHid)})}),
                   std::string("locked_hero_cannot_sacrifice"));

        (void)clientA.callOk("hero.unLock", {avInt(fodderHid)});
        REQUIRE_EQ(clientA.callErr("evolve.doEvolve",
                                   {avInt(composedHid), avArr({avInt(fodderHid)})}),
                   std::string("deployed_hero_cannot_sacrifice"));

        (void)clientA.callOk("formation.unsetHeroFromPosition", {avInt(4)});
        (void)clientA.callOk("evolve.doEvolve",
                             {avInt(composedHid), avArr({avInt(fodderHid)})});
        return true;
    });

    suite.run("CrossRepo_07_Squad_9Grid_LittleFriendPartner_9SlotArming_And_Forge", [&]() {
        REQUIRE_EQ(clientA.callErr("formation.unsetHeroFromPosition", {avInt(1)}),
                   std::string("protagonist_cannot_be_removed"));

        (void)clientA.callOk("chat.sendWorld", {avInt(1), avStr("/level 35")});
        (void)clientA.callOk("formation.setHeroToPosition", {avInt(composedHid), avInt(4)});
        (void)clientA.callOk("formation.transHero", {avInt(2), avInt(4)});

        std::vector<int64_t> active;
        for (const auto& v : clientA.callOk("formation.getHeroes").dense) {
            if (v.asInt() > 0) active.push_back(v.asInt());
        }
        REQUIRE_EQ(active.size(), static_cast<size_t>(4));

        REQUIRE_EQ(clientA.callErr("formation.set",
                                   {Amf3Value::makeMap({{"1", avInt(active[0])}})}),
                   std::string("invalid_formation_slot"));

        (void)clientA.callOk("formation.set",
                             {Amf3Value::makeMap({
                                 {"3", avInt(active[0])},
                                 {"6", avInt(active[1])},
                                 {"9", avInt(active[2])},
                                 {"2", avInt(active[3])},
                             })});

        const auto bag = clientA.callOk("bag.bagInfo");
        const int64_t wpnGid = findFirstBagGidByTemplate(bag, "arm", 112001);
        const int64_t trsGid = findFirstBagGidByTemplate(bag, "treasure", 182001);
        REQUIRE_TRUE(wpnGid > 0 && trsGid > 0);

        REQUIRE_EQ(clientA.callErr("formation.addArming", {avInt(1), avInt(1), avInt(trsGid)}),
                   std::string("equip_type_mismatch"));
        (void)clientA.callOk("formation.addArming", {avInt(1), avInt(1), avInt(wpnGid)});
        (void)clientA.callOk("formation.addArming", {avInt(1), avInt(5), avInt(trsGid)});
        (void)clientA.callOk("forge.autoReinforceArm", {avInt(1)});
        (void)clientA.callOk("forge.upgradeArm", {avInt(craftedArmGid), avInt(3)});
        (void)clientA.callOk("formation.transferArming", {avInt(1), avInt(2), avInt(1)});
        (void)clientA.callOk("formation.removeArming", {avInt(1), avInt(5)});

        const auto insp = clientB.callOk("formation.getOtherPositionInfo", {avInt(uidA)});
        REQUIRE_EQ(insp.get("uname")->asString(), std::string("LongĐởmThần"));
        return true;
    });

    suite.run("CrossRepo_08_TwoClient_RealTime_Multiplayer_Town_RoyalCity_And_Castle", [&]() {
        (void)clientA.drainPushes(20);
        (void)clientB.drainPushes(20);
        (void)clientA.callOk("city.enter", {avInt(1)});
        (void)clientB.callOk("city.enter", {avInt(1)});
        REQUIRE_TRUE(hasPush(clientA.drainPushes(100), "town.addPlayer"));

        (void)clientB.callOk("town.move", {avInt(600), avInt(210)});
        REQUIRE_TRUE(hasPush(clientA.drainPushes(100), "town.move"));

        (void)clientA.callOk("castle.getInfo");
        (void)clientA.callOk("castle.levelUp");
        (void)clientB.callOk("imperialcity.enter", {avInt(300), avInt(200)});
        (void)clientB.callOk("imperialcity.leave");
        return true;
    });

    suite.run("CrossRepo_09_WorldChat_PersonalWhisper_ZlibHistory_And_GMCommands", [&]() {
        (void)clientB.drainPushes(20);
        (void)clientA.callOk("chat.sendWorld", {avInt(1), avStr("Kestrel C++ <-> Cobalt Rust Live!")});
        (void)clientA.callOk("chat.sendPersonal",
                             {avStr("QuanVũVIP"), avInt(1), avStr("Mật thư từ Kestrel!")});
        REQUIRE_TRUE(hasPush(clientB.drainPushes(100), "re.chat.getMsg"));

        const auto hist = clientB.callOk("chat.getWorldLastMsgs");
        REQUIRE_FALSE(hist.dense.empty());
        const Amf3Value msgRec = decodeZlibAmf3(hist.dense[0].strVal);
        REQUIRE_EQ(msgRec.get("message")->get("message")->asString(),
                   std::string("Kestrel C++ <-> Cobalt Rust Live!"));
        return true;
    });

    suite.run("CrossRepo_10_MailBox_RewardCenter_And_GiftCode_Idempotency", [&]() {
        (void)clientA.callOk("mail.sendMail",
                             {avInt(uidB), avStr("Thư Chiến Báo"), avStr("Toàn quân tập kết!")});
        (void)clientB.callOk("mail.getMailBoxList");
        (void)clientB.callOk("mail.readAllMail");

        const auto rl = clientA.callOk("reward.getRewardList", {avInt(0), avInt(50)});
        REQUIRE_FALSE(rl.dense.empty());
        const int64_t rid = rl.dense[0].get("rid")->asInt();
        (void)clientA.callOk("reward.receiveByRidArr", {avArr({avInt(rid)})});
        REQUIRE_NE(clientA.callErr("reward.receiveByRidArr", {avArr({avInt(rid)})}),
                   std::string("ok"));

        (void)clientA.callOk("reward.giftByCode", {avStr("GSERVERVIP888")});
        REQUIRE_NE(clientA.callErr("reward.giftByCode", {avStr("GSERVERVIP888")}),
                   std::string("ok"));
        return true;
    });

    suite.run("CrossRepo_11_TavernRaffle_Gacha_And_Shop_PurchaseRefresh", [&]() {
        (void)clientA.callOk("raffle.buyToken", {avInt(5)});
        (void)clientA.callOk("raffle.singleRaffle", {avInt(2)});
        (void)clientA.callOk("raffle.multiRaffle", {avInt(2)});
        (void)clientA.callOk("raffle.raffleHot");
        (void)clientA.callOk("raffle.refreshHotByHand");

        const auto si = clientA.callOk("shop.getInfo", {avInt(1)});
        const std::string gk = si.get("goods_key")->asString();
        (void)clientA.callOk("shop.buy", {avInt(1), avStr(gk), avInt(1), avInt(101), avInt(1)});
        (void)clientA.callOk("shop.refresh", {avInt(1)});
        return true;
    });

    suite.run("CrossRepo_12_PvECopy_Attack_Pass_Sweep_And_ZlibBattleRecord", [&]() {
        const auto atk = clientA.callOk("copy.attack", {avInt(1001), avInt(100101)});
        const int64_t brid = atk.get("brid")->asInt();

        const auto rec = clientA.callOk("battle.getRecord", {avInt(brid)});
        REQUIRE_EQ(decodeZlibAmf3(rec.strVal).get("appraisal")->asInt(), 50LL);
        REQUIRE_EQ(clientA.callErr("battle.getRecord", {avInt(999999)}),
                   std::string("battle_record_not_found"));

        (void)clientA.callOk("copy.pass", {avInt(1001), avInt(100101), Amf3Value::makeEmptyArray()});
        (void)clientA.callOk("copy.sweep", {avInt(1001), avInt(100101), avInt(2)});
        (void)clientA.callOk("copy.fetchFresherReward");
        REQUIRE_EQ(clientA.callErr("copy.fetchFresherReward"), std::string("already_claimed"));
        return true;
    });

    suite.run("CrossRepo_13_PvPArena_RankSwap_DefenderPush_Sign_And_OnlineRewards", [&]() {
        (void)clientB.callOk("arena.enterArena");
        (void)clientA.callOk("arena.enterArena");
        (void)clientB.drainPushes(20);

        const auto ch = clientA.callOk(
            "arena.challenge", {avInt(17), avInt(16), avInt(0), avStr("QuanVũVIP")});
        REQUIRE_EQ(ch.get("position")->asInt(), 16LL);
        REQUIRE_TRUE(hasPush(clientB.drainPushes(100), "re.arena.dataRefresh"));

        (void)clientA.callOk("arena.buyChallengeTimes", {avInt(2)});
        (void)clientA.callOk("arena.fetchChallengeNumReward", {avInt(1)});
        (void)clientA.callOk("sign.signToday");
        REQUIRE_NE(clientA.callErr("sign.signToday"), std::string("ok"));
        (void)clientA.callOk("sign.gainVipSignReward", {avInt(1)});
        (void)clientA.callOk("sign.gainRechargeSignReward", {avInt(1)});
        (void)clientA.callOk("online.fetch", {avInt(1)});
        return true;
    });

    suite.run("CrossRepo_14_FlowA_CopyBattle_SkillIds_Stamina_Rewards_And_ReconnectPersistence",
              [&]() {
                  REQUIRE_EQ(clientA.callErr("copy.attack", {avInt(0), avInt(0)}),
                             std::string("invalid_copy_stage"));
                  REQUIRE_EQ(clientA.callErr("copy.attack", {avInt(1001), avInt(200101)}),
                             std::string("invalid_copy_stage"));

                  const auto preUser = clientA.callOk("user.getUser");
                  const int64_t preExec   = preUser.get("execution")->asInt();
                  const int64_t preExp    = preUser.get("exp")->asInt();
                  const int64_t preCopper = preUser.get("copper")->asInt();
                  const int64_t preSoul   = preUser.get("hero_soul")->asInt();
                  const int64_t preGold   = preUser.get("gold")->asInt();

                  const auto preBag = clientA.callOk("bag.bagInfo");
                  const int64_t pre17002 = sumBagTemplateCount(preBag, "item", 17002);
                  const int64_t pre16012 = sumBagTemplateCount(preBag, "item", 16012);

                  const auto preList = clientA.callOk("copy.getList", {avInt(1)});
                  const auto* preChap = preList.get("copyData")->get("1001");
                  REQUIRE_TRUE(preChap != nullptr);
                  REQUIRE_EQ(preChap->get("star")->asInt(), 3LL);
                  REQUIRE_EQ(preChap->get("pass_strongh")->asInt(), 1LL);

                  const auto atk = clientA.callOk("copy.attack", {avInt(1001), avInt(100102)});
                  REQUIRE_EQ(atk.get("ret")->asString(), std::string("ok"));
                  const int64_t brid = atk.get("brid")->asInt();
                  REQUIRE_TRUE(brid > 0LL);
                  REQUIRE_EQ(atk.get("appraisal")->asInt(), 50LL);

                  const auto* drop = atk.get("drop");
                  REQUIRE_TRUE(drop != nullptr);
                  REQUIRE_EQ(drop->get("copper")->asInt(), 2000LL);
                  REQUIRE_EQ(drop->get("soul")->asInt(), 70LL);
                  REQUIRE_TRUE(drop->get("item") != nullptr);
                  REQUIRE_EQ(drop->get("item")->get("17002")->asInt(), 1LL);

                  const auto* bInfo = atk.get("battleInfo");
                  REQUIRE_TRUE(bInfo != nullptr);
                  REQUIRE_EQ(bInfo->get("isPVP")->asInt(), 0LL);
                  const auto* team1 = bInfo->get("arrTeam1")->get("1")->get("arrHero");
                  const auto* team2 = bInfo->get("arrTeam2")->get("1")->get("arrHero");
                  REQUIRE_TRUE(team1 != nullptr && !team1->fields.empty());
                  REQUIRE_TRUE(team2 != nullptr && !team2->fields.empty());

                  for (const auto* teamHeroMap : {team1, team2}) {
                      for (const auto& kv : teamHeroMap->fields) {
                          const auto* skills = kv.second.get("arrSkill");
                          REQUIRE_TRUE(skills != nullptr && skills->dense.size() == 2);
                          REQUIRE_EQ(skills->dense[0].dense.size(), static_cast<size_t>(2));
                          REQUIRE_EQ(skills->dense[1].dense.size(), static_cast<size_t>(2));
                          const int64_t normalSkillId = skills->dense[0].dense[0].asInt();
                          const int64_t rageSkillId   = skills->dense[1].dense[0].asInt();
                          REQUIRE_TRUE(normalSkillId > 0LL && rageSkillId > 0LL);
                          const int64_t unitHtid =
                              kv.second.get("htid") ? kv.second.get("htid")->asInt() : 0LL;
                          if (teamHeroMap == team1) {
                              REQUIRE_NE(normalSkillId, 1201LL);
                              if (unitHtid == 1LL || unitHtid == 101LL || unitHtid == 401LL ||
                                  unitHtid == 406LL || unitHtid == 426LL) {
                                  const int64_t expectedBase = unitHtid * 100LL;
                                  REQUIRE_TRUE((normalSkillId == expectedBase + 2LL &&
                                                rageSkillId == expectedBase + 1LL) ||
                                               (normalSkillId == 1001LL && rageSkillId == 2001LL));
                              }
                          } else {
                              REQUIRE_TRUE(unitHtid > 20000LL || normalSkillId > 0LL);
                          }
                      }
                  }

                  const auto* arrSeed = atk.get("arrSeed");
                  REQUIRE_TRUE(arrSeed != nullptr && !arrSeed->dense.empty());
                  const auto* uInfo = atk.get("userInfo");
                  REQUIRE_TRUE(uInfo != nullptr && uInfo->get("1") != nullptr &&
                               uInfo->get("2") != nullptr);
                  REQUIRE_EQ(uInfo->get("1")->get("uid")->asInt(), uidA);

                  const auto* fightRetBlob = atk.get("fightRet");
                  REQUIRE_TRUE(fightRetBlob != nullptr && !fightRetBlob->strVal.empty());
                  const Amf3Value fightReport = decodeZlibAmf3(fightRetBlob->strVal);
                  REQUIRE_EQ(fightReport.get("brid")->asInt(), brid);
                  REQUIRE_EQ(fightReport.get("appraisal")->asInt(), 50LL);
                  REQUIRE_TRUE(fightReport.get("round")->asInt() >= 1LL);
                  REQUIRE_TRUE(fightReport.get("heroResoultInfo") != nullptr);
                  REQUIRE_TRUE(fightReport.get("statisticalDataInfo") != nullptr);
                  if (const auto* rq = fightReport.get("rageQueue")) {
                      for (const auto& step : rq->dense) {
                          const int64_t rqSid = step.get("skillId")->asInt();
                          REQUIRE_TRUE(rqSid > 0LL && rqSid != 1201LL);
                      }
                  }

                  const auto rec = clientA.callOk("battle.getRecord", {avInt(brid)});
                  REQUIRE_EQ(decodeZlibAmf3(rec.strVal).get("appraisal")->asInt(), 50LL);

                  (void)clientA.drainPushes(20);
                  const auto pass = clientA.callOk(
                      "copy.pass", {avInt(1001), avInt(100102), Amf3Value::makeEmptyArray()});
                  REQUIRE_EQ(pass.get("ret")->asString(), std::string("ok"));
                  REQUIRE_EQ(pass.get("battle_result")->asInt(), 1LL);
                  REQUIRE_EQ(pass.get("brid")->asInt(), brid);
                  REQUIRE_EQ(pass.get("star")->asInt(), 3LL);
                  REQUIRE_EQ(pass.get("exp")->asInt(), 2100LL);
                  REQUIRE_EQ(pass.get("drop")->get("copper")->asInt(), 2000LL);
                  REQUIRE_EQ(pass.get("drop")->get("soul")->asInt(), 70LL);
                  REQUIRE_EQ(pass.get("drop")->get("item")->get("17002")->asInt(), 1LL);

                  const auto passPushes = clientA.drainPushes(60);
                  REQUIRE_TRUE(hasPush(passPushes, "user.updateUser"));
                  REQUIRE_TRUE(hasPush(passPushes, "bag.update"));

                  const auto midUser = clientA.callOk("user.getUser");
                  REQUIRE_EQ(midUser.get("execution")->asInt(), preExec - 6);
                  REQUIRE_TRUE(midUser.get("level")->asInt() > preUser.get("level")->asInt() ||
                               midUser.get("exp")->asInt() == preExp + 2100);
                  REQUIRE_EQ(midUser.get("copper")->asInt(), preCopper + 2000);
                  REQUIRE_EQ(midUser.get("hero_soul")->asInt(), preSoul + 70);
                  REQUIRE_EQ(sumBagTemplateCount(clientA.callOk("bag.bagInfo"), "item", 17002),
                             pre17002 + 1);

                  for (int64_t stg : {100103LL, 100105LL, 100106LL}) {
                      REQUIRE_EQ(clientA.callOk("copy.attack", {avInt(1001), avInt(stg)})
                                     .get("appraisal")
                                     ->asInt(),
                                 50LL);
                      REQUIRE_EQ(
                          clientA
                              .callOk("copy.pass",
                                      {avInt(1001), avInt(stg), Amf3Value::makeEmptyArray()})
                              .get("star")
                              ->asInt(),
                          3LL);
                  }

                  REQUIRE_EQ(clientA.callOk("copy.fetchPrize", {avInt(1001), avInt(0)})
                                 .get("prize")
                                 ->asInt(),
                             1LL);
                  REQUIRE_EQ(clientA.callErr("copy.fetchPrize", {avInt(1001), avInt(0)}),
                             std::string("prize_already_claimed"));

                  const auto tkReconn =
                      strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_alpha", false);
                  RealKestrelWireClient reconnA;
                  (void)reconnA.connectAndEnterGame(tcpHost, tcpPort, tkReconn);

                  const auto recUser = reconnA.callOk("user.getUser");
                  REQUIRE_EQ(recUser.get("execution")->asInt(), preExec - 24);
                  REQUIRE_TRUE(recUser.get("level")->asInt() >= 36LL);
                  REQUIRE_TRUE(recUser.get("copper")->asInt() >= preCopper + 8000);
                  REQUIRE_TRUE(recUser.get("hero_soul")->asInt() >= preSoul + 280);
                  REQUIRE_EQ(recUser.get("gold")->asInt(), preGold + 100);

                  const auto recBag = reconnA.callOk("bag.bagInfo");
                  REQUIRE_EQ(sumBagTemplateCount(recBag, "item", 17002), pre17002 + 4);
                  REQUIRE_EQ(sumBagTemplateCount(recBag, "item", 16012), pre16012 + 1);

                  const auto recList = reconnA.callOk("copy.getList", {avInt(1)});
                  const auto* recC1001 = recList.get("copyData")->get("1001");
                  REQUIRE_TRUE(recC1001 != nullptr);
                  REQUIRE_EQ(recC1001->get("star")->asInt(), 15LL);
                  REQUIRE_EQ(recC1001->get("pass_strongh")->asInt(), 5LL);
                  REQUIRE_EQ(recC1001->get("prize")->asInt(), 1LL);
                  REQUIRE_TRUE(recList.get("copyData")->get("1002") != nullptr);

                  const auto recCopy = reconnA.callOk("copy.getCopy", {avInt(1001)});
                  REQUIRE_EQ(recCopy.get("va_copy")->get("100102")->get("normal_star")->asInt(), 3LL);
                  REQUIRE_EQ(recCopy.get("va_copy")->get("100105")->get("normal_star")->asInt(), 3LL);

                  reconnA.disconnect();
                  return true;
              });

    suite.run("CrossRepo_15_FlowB_ActStar_ReceiveGift_Eligibility_Bag_Dup_And_Persistence", [&]() {
        const auto initInfo = clientA.callOk("activityStarPlayOpen.getInfo");
        REQUIRE_TRUE(initInfo.dense.empty() && initInfo.fields.empty());

        for (int64_t badId : {0LL, -1LL, 99LL}) {
            REQUIRE_EQ(clientA.callErr("activityStarPlayOpen.receiveGift", {avInt(badId)}),
                       std::string("invalid_gift_id"));
        }
        REQUIRE_EQ(clientB.callErr("activityStarPlayOpen.receiveGift", {avInt(3)}),
                   std::string("level_not_enough"));
        for (int64_t highId : {5LL, 7LL}) {
            REQUIRE_EQ(clientA.callErr("activityStarPlayOpen.receiveGift", {avInt(highId)}),
                       std::string("level_not_enough"));
        }

        const auto preUser = clientA.callOk("user.getUser");
        const int64_t preGold   = preUser.get("gold")->asInt();
        const int64_t preCopper = preUser.get("copper")->asInt();

        const auto preBag   = clientA.callOk("bag.bagInfo");
        const int64_t pre10010 = sumBagTemplateCount(preBag, "item", 10010);
        const int64_t pre22202 = sumBagTemplateCount(preBag, "item", 22202);
        const int64_t pre50406 = sumBagTemplateCount(preBag, "soul", 50406);

        (void)clientA.drainPushes(20);
        const auto claim1 = clientA.callOk("activityStarPlayOpen.receiveGift", {avInt(1)});
        REQUIRE_EQ(claim1.get("ret")->asString(), std::string("ok"));
        REQUIRE_EQ(claim1.get("id")->asInt(), 1LL);

        const auto* rw1 = claim1.get("reward");
        REQUIRE_TRUE(rw1 != nullptr && rw1->dense.size() == 4);
        REQUIRE_EQ(rw1->dense[0].dense[0].asInt(), 2LL);
        REQUIRE_EQ(rw1->dense[0].dense[2].asInt(), 188LL);
        REQUIRE_EQ(rw1->dense[1].dense[0].asInt(), 1LL);
        REQUIRE_EQ(rw1->dense[1].dense[2].asInt(), 50000LL);
        REQUIRE_EQ(rw1->dense[2].dense[0].asInt(), 4LL);
        REQUIRE_EQ(rw1->dense[2].dense[1].asInt(), 10010LL);
        REQUIRE_EQ(rw1->dense[2].dense[2].asInt(), 20LL);
        REQUIRE_EQ(rw1->dense[3].dense[0].asInt(), 4LL);
        REQUIRE_EQ(rw1->dense[3].dense[1].asInt(), 50406LL);
        REQUIRE_EQ(rw1->dense[3].dense[2].asInt(), 10LL);

        const auto pushes1 = clientA.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushes1, "user.updateUser"));
        REQUIRE_TRUE(hasPush(pushes1, "bag.update"));

        const auto claim4 = clientA.callOk("activityStarPlayOpen.receiveGift", {avInt(4)});
        REQUIRE_EQ(claim4.get("id")->asInt(), 4LL);
        const auto* rw4 = claim4.get("reward");
        REQUIRE_TRUE(rw4 != nullptr && rw4->dense.size() == 4);
        REQUIRE_EQ(rw4->dense[2].dense[1].asInt(), 22202LL);
        REQUIRE_EQ(rw4->dense[2].dense[2].asInt(), 3LL);
        REQUIRE_EQ(rw4->dense[3].dense[1].asInt(), 50406LL);
        REQUIRE_EQ(rw4->dense[3].dense[2].asInt(), 25LL);

        const auto postUser = clientA.callOk("user.getUser");
        REQUIRE_EQ(postUser.get("gold")->asInt(), preGold + 188 + 588);
        REQUIRE_EQ(postUser.get("copper")->asInt(), preCopper + 50000 + 200000);

        const auto postBag = clientA.callOk("bag.bagInfo");
        REQUIRE_EQ(sumBagTemplateCount(postBag, "item", 10010), pre10010 + 20);
        REQUIRE_EQ(sumBagTemplateCount(postBag, "item", 22202), pre22202 + 3);
        REQUIRE_EQ(sumBagTemplateCount(postBag, "soul", 50406), pre50406 + 35);

        for (int64_t dupId : {1LL, 4LL}) {
            REQUIRE_EQ(clientA.callErr("activityStarPlayOpen.receiveGift", {avInt(dupId)}),
                       std::string("already_claimed"));
        }
        REQUIRE_EQ(clientA.callOk("user.getUser").get("gold")->asInt(), preGold + 188 + 588);

        const auto postInfo = clientA.callOk("activityStarPlayOpen.getInfo");
        REQUIRE_TRUE(postInfo.get("1") != nullptr && postInfo.get("1")->boolVal);
        REQUIRE_TRUE(postInfo.get("4") != nullptr && postInfo.get("4")->boolVal);
        REQUIRE_TRUE(postInfo.get("2") == nullptr);

        const auto tkReconn =
            strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_alpha", false);
        RealKestrelWireClient reconnStar;
        (void)reconnStar.connectAndEnterGame(tcpHost, tcpPort, tkReconn);

        const auto recInfo = reconnStar.callOk("activityStarPlayOpen.getInfo");
        REQUIRE_TRUE(recInfo.get("1") != nullptr && recInfo.get("1")->boolVal);
        REQUIRE_TRUE(recInfo.get("4") != nullptr && recInfo.get("4")->boolVal);
        REQUIRE_EQ(reconnStar.callErr("activityStarPlayOpen.receiveGift", {avInt(1)}),
                   std::string("already_claimed"));
        REQUIRE_EQ(sumBagTemplateCount(reconnStar.callOk("bag.bagInfo"), "soul", 50406),
                   pre50406 + 35);

        reconnStar.disconnect();
        return true;
    });

    suite.run("CrossRepo_17_AllModes_TavernRaffle_Shops_BagSell_TMNamespace_And_Dungeons", [&]() {
        const auto tkC = strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_modes_c", true);
        RealKestrelWireClient clientC;
        (void)clientC.connectAndEnterGame(tcpHost, tcpPort, tkC, 1, "ChiêuMộQA");
        (void)clientC.callOk("chat.sendWorld", {avInt(1), avStr("/level 60")});
        (void)clientC.callOk("chat.sendWorld", {avInt(1), avStr("/gold 50000")});
        (void)clientC.drainPushes(30);

        const auto rInfo = clientC.callOk("raffle.getInfo");
        REQUIRE_TRUE(rInfo.get("raffle") != nullptr);
        REQUIRE_TRUE(rInfo.get("hot_raffle") != nullptr);
        REQUIRE_TRUE(rInfo.get("red_raffle") != nullptr);

        const auto rOne = clientC.callOk("raffle.singleRaffle", {avInt(1)});
        REQUIRE_TRUE(rOne.get("reward") != nullptr && rOne.get("reward")->dense.size() == 1);
        REQUIRE_FALSE(rOne.get("reward")->dense[0].fields.empty());

        const auto rTen = clientC.callOk("raffle.multiRaffle", {avInt(2)});
        REQUIRE_TRUE(rTen.get("reward") != nullptr && rTen.get("reward")->dense.size() == 10);
        REQUIRE_TRUE(rTen.get("senior_luck_num") != nullptr);

        REQUIRE_FALSE(clientC.callOk("rebel.getRebelInfo").fields.empty());
        (void)clientC.callOk("tmShop.getInfo", {avInt(8)});
        (void)clientC.callOk("tmShop.buy",
                             {avInt(8), avStr("0"), avInt(1), avInt(1), avInt(1)});
        REQUIRE_TRUE(clientC.callOk("tmShop.refresh", {avInt(12)}).get("goods_key") != nullptr);
        REQUIRE_FALSE(clientC.callOk("tmUser.buyCopper", {avInt(2)}).dense.empty());
        REQUIRE_EQ(clientC.callOk("tmUser.buyVipGift", {avInt(0)}).asString(), std::string("ok"));

        (void)clientC.callOk("chat.sendWorld", {avInt(1), avStr("/item 50406 10")});
        const int64_t soulGid =
            findFirstBagGidByTemplate(clientC.callOk("tmBag.bagInfo"), "soul", 50406);
        REQUIRE_TRUE(soulGid >= 50001LL && soulGid <= 60000LL);
        (void)clientC.callOk("tmRefinery.refinerySoul", {avArr({avInt(soulGid)})});

        (void)clientC.callOk("babeltower.getBabeltowerInfo");
        (void)clientC.callOk("copy_daily.getInfo", {avInt(1)});
        (void)clientC.callOk("dota.attack", {avInt(1)});
        (void)clientC.callOk("dota.pass", {avInt(1), avBool(true)});
        (void)clientC.callOk("eatChicken.eat");

        clientC.disconnect();
        return true;
    });

    suite.run("CrossRepo_18_ActiveEventsAndOneClickInstantBuy", [&]() {
        const auto tkD = strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_instant_buy_d", true);
        RealKestrelWireClient clientD;
        (void)clientD.connectAndEnterGame(tcpHost, tcpPort, tkD, 1, "VạnSựNhưÝ");
        (void)clientD.callOk("chat.sendWorld", {avInt(1), avStr("/level 60")});
        (void)clientD.drainPushes(30);

        const auto actConf = clientD.callOk("activity.getActivityConf");
        REQUIRE_TRUE(!actConf.fields.empty() || !actConf.dense.empty());

        const auto ddInit = clientD.callOk("dailyDiscount.getInfo");
        REQUIRE_TRUE(ddInit.get("productBuy") != nullptr);

        const int64_t gold0    = clientD.callOk("user.getUser").get("gold")->asInt();
        const int64_t pre22102 = sumBagTemplateCount(clientD.callOk("bag.bagInfo"), "item", 22102);

        const auto ddFree = clientD.callOk("dailyDiscount.receive", {avInt(1)});
        REQUIRE_TRUE(ddFree.asString() == "ok" ||
                     (ddFree.get("ret") != nullptr && ddFree.get("ret")->asString() == "ok"));
        REQUIRE_TRUE(clientD.callOk("user.getUser").get("gold")->asInt() >= gold0 + 20);
        const auto bagAfterFree = clientD.callOk("bag.bagInfo");
        REQUIRE_TRUE(sumBagTemplateCount(bagAfterFree, "item", 22102) >= pre22102 + 1);

        // Helper matching SDKUtil.pay -> net:sendMsg("pay.instantBuy", cb, payload)
        auto sendInstantBuy = [&](int64_t payId, int64_t payPrice, const std::string& payType,
                                  const std::string& productName, int64_t buyType, int64_t itemId,
                                  Amf3Value payRow = Amf3Value::makeNull()) {
            std::map<std::string, Amf3Value> m{
                {"pay_id", avInt(payId)},
                {"pay_id_str", avStr(std::to_string(payId))},
                {"pay_price", avInt(payPrice)},
                {"pay_type", avStr(payType)},
                {"product_name", avStr(productName)},
                {"buy_type", avInt(buyType)},
                {"item_id", avInt(itemId)},
            };
            if (buyType > 0 || itemId > 0) {
                m["extra_data"] = avArr({avInt(buyType), avInt(itemId), avInt(payId)});
            }
            if (payRow.kind == Amf3Value::Kind::Map) {
                m["pay_row"] = std::move(payRow);
            }
            Amf3Value mapVal;
            mapVal.kind   = Amf3Value::Kind::Map;
            mapVal.fields = std::move(m);
            return clientD.callRpcRawArgs("pay.instantBuy", std::move(mapVal));
        };

        (void)clientD.drainPushes(20);
        const int64_t pre14374 = sumBagTemplateCount(bagAfterFree, "item", 14374);
        REQUIRE_EQ(sendInstantBuy(1603, 5000, "04", "Quà 5000 VND", 4, 2).err, std::string("ok"));
        const auto pushes5k = clientD.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushes5k, "dailyDiscount.normalUpdate") ||
                     hasPush(pushes5k, "user.updateUser"));

        REQUIRE_EQ(sendInstantBuy(1606, 249000, "04", "249000 VND mua 8 ngày", 4, 5).err,
                   std::string("ok"));
        const auto pushesPre8 = clientD.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushesPre8, "dailyDiscount.preBuyUpdate") ||
                     hasPush(pushesPre8, "user.updateUser"));

        if (sumBagTemplateCount(clientD.callOk("bag.bagInfo"), "item", 14374) < pre14374 + 2) {
            if (clientD.callErr("dailyDiscount.receive", {avInt(3)}) != "ok") {
                REQUIRE_EQ(sendInstantBuy(1604, 9000, "04", "Quà 9000 VND", 4, 3).err,
                           std::string("ok"));
            }
            (void)clientD.drainPushes(40);
        }

        REQUIRE_EQ(sendInstantBuy(1620, 25000, "04", "Quà Ngày", 12, 1).err, std::string("ok"));
        const auto pushesQN = clientD.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushesQN, "activityDailyRecharge2.update") ||
                     hasPush(pushesQN, "user.updateUser"));

        REQUIRE_EQ(sendInstantBuy(1619, 249000, "04", "Tam Quốc Chí Tôn Lệnh", 8, 1).err,
                   std::string("ok"));
        const auto pushesQt = clientD.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushesQt, "activityQuarter.update") ||
                     hasPush(pushesQt, "user.updateUser"));

        const int64_t goldBeforeCard = clientD.callOk("user.getUser").get("gold")->asInt();
        REQUIRE_EQ(sendInstantBuy(
                       1001, 109000, "01", "Thẻ Tháng", 0, 0,
                       Amf3Value::makeMap({
                           {"id", avInt(1001)},
                           {"recharge_type", avInt(2)},
                           {"consume_money", avInt(109000)},
                           {"Stall", avInt(30)},
                           {"days", avInt(30)},
                           {"vip_exp", avInt(300)},
                           {"base_reward", avInt(300)},
                           {"daily_reward", avInt(100)},
                       }))
                       .err,
                   std::string("ok"));
        (void)clientD.drainPushes(40);

        REQUIRE_EQ(sendInstantBuy(
                       1004, 25000, "00", "60 Nguyên Bảo", 0, 0,
                       Amf3Value::makeMap({
                           {"id", avInt(1004)},
                           {"recharge_type", avInt(1)},
                           {"consume_money", avInt(25000)},
                           {"Stall", avInt(6)},
                           {"days", avInt(0)},
                           {"vip_exp", avInt(60)},
                           {"base_reward", avInt(60)},
                           {"first_reward", avInt(60)},
                           {"general_reward", avInt(0)},
                       }))
                       .err,
                   std::string("ok"));
        (void)clientD.drainPushes(40);
        REQUIRE_TRUE(clientD.callOk("user.getUser").get("gold")->asInt() > goldBeforeCard);

        const int64_t pre28623 =
            sumBagTemplateCount(clientD.callOk("bag.bagInfo"), "item", 28623);
        (void)clientD.callOk("dailyDiscount.redeem", {avInt(15), avInt(1)});
        (void)clientD.drainPushes(40);
        const auto postRedeemBag = clientD.callOk("bag.bagInfo");
        REQUIRE_TRUE(sumBagTemplateCount(postRedeemBag, "item", 28623) >= pre28623 + 1);

        const int64_t pre21079 = sumBagTemplateCount(postRedeemBag, "item", 21079);
        (void)clientD.callOk("dailyDiscount.recRechargeReward", {avInt(1)});
        (void)clientD.drainPushes(40);
        const auto postPtBag = clientD.callOk("bag.bagInfo");
        REQUIRE_TRUE(sumBagTemplateCount(postPtBag, "item", 21079) >= pre21079 + 1);

        const int64_t pre27501 = sumBagTemplateCount(postPtBag, "item", 27501);
        (void)clientD.callOk("firstGift.receiveReward", {avInt(1)});
        (void)clientD.drainPushes(40);
        REQUIRE_TRUE(sumBagTemplateCount(clientD.callOk("bag.bagInfo"), "item", 27501) >=
                     pre27501 + 1);

        clientD.disconnect();
        return true;
    });

    clientA.disconnect();
    clientB.disconnect();
    gclient::net::CNetwork::destroySharedNetwork();

    return suite.finishCompact();
}
