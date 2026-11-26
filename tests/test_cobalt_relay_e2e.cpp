// ============================================================================
// tests/test_cobalt_relay_e2e.cpp
// Strict Cross-Project End-to-End Integration Test Suite
// Wiring kestrel-canvas (C++17 CNetwork + CConnection + LCPacket + BtDecryptHook
// + optional LuaJIT Amf3Module) <-> cobalt-relay (gserver --strict-all).
// ============================================================================

#include "assets/BtDecryptHook.h"
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

#include <openssl/evp.h>

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
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr const char* kVnsg2MapiAppKey = "2A0ce68806G8aJ58Mo6_vnsg2@OmZHv";
constexpr const char* kGtsdkGameId     = "GCLIENT";
constexpr const char* kGtsdkAuthSecret = "d345c6c5c29669eae007b682625fbf42";

int g_passed = 0;
int g_failed = 0;

#define REQUIRE_TRUE(expr)                                                                 \
    do {                                                                                   \
        if (!(expr)) {                                                                     \
            std::fprintf(stderr, "[FAIL] %s:%d: assertion failed: %s\n", __FILE__,         \
                         __LINE__, #expr);                                                 \
            std::fflush(stderr);                                                           \
            return false;                                                                  \
        }                                                                                  \
    } while (0)

#define REQUIRE_EQ(lhs, rhs)                                                               \
    do {                                                                                   \
        const auto _l = (lhs);                                                             \
        const auto _r = (rhs);                                                             \
        if (!(_l == _r)) {                                                                 \
            std::fprintf(stderr, "[FAIL] %s:%d: expected (%s == %s)\n", __FILE__,          \
                         __LINE__, #lhs, #rhs);                                            \
            std::fflush(stderr);                                                           \
            return false;                                                                  \
        }                                                                                  \
    } while (0)

void runCase(const char* name, const std::function<bool()>& fn) {
    std::printf("[RUN ] %s\n", name);
    std::fflush(stdout);
    bool ok = false;
    try {
        ok = fn();
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "[EXCP] %s: %s\n", name, ex.what());
        ok = false;
    } catch (...) {
        std::fprintf(stderr, "[EXCP] %s: unknown exception\n", name);
        ok = false;
    }
    if (ok) {
        ++g_passed;
        std::printf("[ OK ] %s\n", name);
    } else {
        ++g_failed;
        std::printf("[FAIL] %s\n", name);
    }
    std::fflush(stdout);
}

// ============================================================================
// 1. OpenSSL EVP MD5 + Exact BtPlatformWin32 / AccountAuthProvider Signing
// ============================================================================

std::string md5Hex(const std::string& input) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    unsigned char digest[16]{};
    unsigned int outLen = 0;
    const bool ok = EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, input.data(), input.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest, &outLen) == 1 && outLen == 16;
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        throw std::runtime_error("EVP MD5 digest failed");
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(32, '0');
    for (size_t i = 0; i < 16; ++i) {
        out[i * 2]     = kHex[(digest[i] >> 4) & 0x0Fu];
        out[i * 2 + 1] = kHex[digest[i] & 0x0Fu];
    }
    return out;
}

std::string signMapiTarget(const std::string& pathAndQuery, int64_t ts) {
    const auto qPos = pathAndQuery.find('?');
    const std::string path = (qPos == std::string::npos) ? pathAndQuery : pathAndQuery.substr(0, qPos);
    std::string query = (qPos == std::string::npos) ? std::string() : pathAndQuery.substr(qPos + 1);

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
    const std::string sign = md5Hex(canonical + kVnsg2MapiAppKey);

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
    return md5Hex(std::string(kGtsdkAuthSecret) + kGtsdkGameId + deviceId + ts);
}

std::string computeAccountAuthSig(const std::string& username, const std::string& passMd5,
                                  const std::string& ts) {
    return md5Hex(std::string(kGtsdkAuthSecret) + kGtsdkGameId + username + passMd5 + ts);
}

// ============================================================================
// 2. Self-Contained C++17 AMF3 Codec (Wire-Compatible with Amf3Module.cpp & gserver-protocol)
// ============================================================================

struct Amf3Value {
    enum class Kind {
        Undefined,
        Null,
        Bool,
        Int,
        Double,
        String,
        Array,
        Map
    };

    Kind kind = Kind::Null;
    bool boolVal = false;
    int64_t intVal = 0;
    double doubleVal = 0.0;
    std::string strVal;
    std::vector<Amf3Value> dense;
    std::map<std::string, Amf3Value> fields;

    static Amf3Value makeNull() { return Amf3Value{}; }
    static Amf3Value makeBool(bool b) {
        Amf3Value v;
        v.kind = Kind::Bool;
        v.boolVal = b;
        return v;
    }
    static Amf3Value makeInt(int64_t n) {
        constexpr int64_t kAmfMin = -268435456LL;
        constexpr int64_t kAmfMax = 268435455LL;
        Amf3Value v;
        if (n >= kAmfMin && n <= kAmfMax) {
            v.kind = Kind::Int;
            v.intVal = n;
        } else {
            v.kind = Kind::Double;
            v.doubleVal = static_cast<double>(n);
        }
        return v;
    }
    static Amf3Value makeString(std::string s) {
        Amf3Value v;
        v.kind = Kind::String;
        v.strVal = std::move(s);
        return v;
    }
    static Amf3Value makeArray(std::vector<Amf3Value> items) {
        Amf3Value v;
        v.kind = Kind::Array;
        v.dense = std::move(items);
        return v;
    }
    static Amf3Value makeEmptyArray() { return makeArray({}); }
    static Amf3Value makeMap(std::initializer_list<std::pair<const std::string, Amf3Value>> init) {
        Amf3Value v;
        v.kind = Kind::Map;
        v.fields = std::map<std::string, Amf3Value>(init.begin(), init.end());
        return v;
    }

    const Amf3Value* get(const std::string& key) const {
        if (kind == Kind::Map || kind == Kind::Array) {
            auto it = fields.find(key);
            if (it != fields.end()) {
                return &it->second;
            }
        }
        return nullptr;
    }

    int64_t asInt(int64_t fallback = 0) const {
        if (kind == Kind::Int) {
            return intVal;
        }
        if (kind == Kind::Double) {
            return static_cast<int64_t>(doubleVal);
        }
        if (kind == Kind::String) {
            try {
                return std::stoll(strVal);
            } catch (...) {
                return fallback;
            }
        }
        return fallback;
    }

    std::string asString() const {
        if (kind == Kind::String) {
            return strVal;
        }
        if (kind == Kind::Int) {
            return std::to_string(intVal);
        }
        return {};
    }
};

class Amf3Encoder {
public:
    std::string encode(const Amf3Value& v) {
        out_.clear();
        strRefs_.clear();
        writeValue(v);
        return out_;
    }

private:
    std::string out_;
    std::map<std::string, uint32_t> strRefs_;

    void writeU8(uint8_t b) { out_.push_back(static_cast<char>(b)); }

    void writeU29(uint32_t val) {
        if (val < 0x80u) {
            writeU8(static_cast<uint8_t>(val));
        } else if (val < 0x4000u) {
            writeU8(static_cast<uint8_t>(((val >> 7) & 0x7Fu) | 0x80u));
            writeU8(static_cast<uint8_t>(val & 0x7Fu));
        } else if (val < 0x200000u) {
            writeU8(static_cast<uint8_t>(((val >> 14) & 0x7Fu) | 0x80u));
            writeU8(static_cast<uint8_t>(((val >> 7) & 0x7Fu) | 0x80u));
            writeU8(static_cast<uint8_t>(val & 0x7Fu));
        } else {
            writeU8(static_cast<uint8_t>(((val >> 22) & 0x7Fu) | 0x80u));
            writeU8(static_cast<uint8_t>(((val >> 15) & 0x7Fu) | 0x80u));
            writeU8(static_cast<uint8_t>(((val >> 8) & 0x7Fu) | 0x80u));
            writeU8(static_cast<uint8_t>(val & 0xFFu));
        }
    }

    void writeDoubleBE(double d) {
        uint64_t bits = 0;
        std::memcpy(&bits, &d, sizeof(bits));
        for (int shift = 56; shift >= 0; shift -= 8) {
            writeU8(static_cast<uint8_t>((bits >> shift) & 0xFFu));
        }
    }

    void writeAmfStringBody(const std::string& s) {
        if (s.empty()) {
            writeU29(1u);
            return;
        }
        auto it = strRefs_.find(s);
        if (it != strRefs_.end()) {
            writeU29(it->second << 1);
            return;
        }
        const auto idx = static_cast<uint32_t>(strRefs_.size());
        strRefs_.emplace(s, idx);
        writeU29((static_cast<uint32_t>(s.size()) << 1) | 1u);
        out_.append(s);
    }

    void writeValue(const Amf3Value& v) {
        switch (v.kind) {
            case Amf3Value::Kind::Undefined:
                writeU8(0x00);
                break;
            case Amf3Value::Kind::Null:
                writeU8(0x01);
                break;
            case Amf3Value::Kind::Bool:
                writeU8(v.boolVal ? 0x03 : 0x02);
                break;
            case Amf3Value::Kind::Int: {
                writeU8(0x04);
                const uint32_t u = static_cast<uint32_t>(v.intVal) & 0x1FFFFFFFu;
                writeU29(u);
                break;
            }
            case Amf3Value::Kind::Double:
                writeU8(0x05);
                writeDoubleBE(v.doubleVal);
                break;
            case Amf3Value::Kind::String:
                writeU8(0x06);
                writeAmfStringBody(v.strVal);
                break;
            case Amf3Value::Kind::Array:
                writeU8(0x09);
                writeU29((static_cast<uint32_t>(v.dense.size()) << 1) | 1u);
                for (const auto& kv : v.fields) {
                    writeAmfStringBody(kv.first);
                    writeValue(kv.second);
                }
                writeAmfStringBody("");
                for (const auto& elem : v.dense) {
                    writeValue(elem);
                }
                break;
            case Amf3Value::Kind::Map:
                if (v.fields.empty()) {
                    // Match Amf3Module.cpp empty Lua table `{}` -> `[0x09, 0x01, 0x01]`
                    writeU8(0x09);
                    writeU29(1u);
                    writeU29(1u);
                } else {
                    // Anonymous dynamic object `[0x0A, 0x0B, "", k1, v1, ..., ""]`
                    writeU8(0x0A);
                    writeU29(0x0Bu);
                    writeAmfStringBody("");
                    for (const auto& kv : v.fields) {
                        writeAmfStringBody(kv.first);
                        writeValue(kv.second);
                    }
                    writeAmfStringBody("");
                }
                break;
        }
    }
};

class Amf3Decoder {
public:
    Amf3Decoder(const uint8_t* data, size_t len) : data_(data), len_(len) {}

    Amf3Value decode() { return readValue(0); }

private:
    struct TraitDef {
        bool dynamic = false;
        std::vector<std::string> sealedNames;
    };

    const uint8_t* data_ = nullptr;
    size_t len_ = 0;
    size_t pos_ = 0;
    std::vector<std::string> strRefs_;
    std::vector<Amf3Value> objRefs_;
    std::vector<TraitDef> traitRefs_;

    uint8_t readU8() {
        if (pos_ >= len_) {
            throw std::runtime_error("AMF3 unexpected EOF");
        }
        return data_[pos_++];
    }

    uint32_t readU29() {
        uint32_t acc = 0;
        for (int i = 0; i < 3; ++i) {
            const uint8_t b = readU8();
            acc = (acc << 7) | (b & 0x7Fu);
            if ((b & 0x80u) == 0) {
                return acc;
            }
        }
        const uint8_t b4 = readU8();
        return (acc << 8) | b4;
    }

    double readDoubleBE() {
        if (pos_ + 8 > len_) {
            throw std::runtime_error("AMF3 truncated double");
        }
        uint64_t bits = 0;
        for (int i = 0; i < 8; ++i) {
            bits = (bits << 8) | data_[pos_++];
        }
        double d = 0.0;
        std::memcpy(&d, &bits, sizeof(d));
        return d;
    }

    std::string readAmfStringBody() {
        const uint32_t header = readU29();
        if ((header & 1u) == 0) {
            const uint32_t idx = header >> 1;
            if (idx >= strRefs_.size()) {
                throw std::runtime_error("AMF3 invalid string ref");
            }
            return strRefs_[idx];
        }
        const size_t slen = header >> 1;
        if (pos_ + slen > len_) {
            throw std::runtime_error("AMF3 truncated string");
        }
        std::string s(reinterpret_cast<const char*>(data_ + pos_), slen);
        pos_ += slen;
        if (!s.empty()) {
            strRefs_.push_back(s);
        }
        return s;
    }

    Amf3Value readValue(int depth) {
        if (depth > 64) {
            throw std::runtime_error("AMF3 max depth exceeded");
        }
        const uint8_t marker = readU8();
        switch (marker) {
            case 0x00: {
                Amf3Value v;
                v.kind = Amf3Value::Kind::Undefined;
                return v;
            }
            case 0x01:
                return Amf3Value::makeNull();
            case 0x02:
                return Amf3Value::makeBool(false);
            case 0x03:
                return Amf3Value::makeBool(true);
            case 0x04: {
                uint32_t raw = readU29();
                int32_t signedVal = (raw >= 0x10000000u)
                                        ? static_cast<int32_t>(raw | 0xE0000000u)
                                        : static_cast<int32_t>(raw);
                return Amf3Value::makeInt(signedVal);
            }
            case 0x05: {
                Amf3Value v;
                v.kind = Amf3Value::Kind::Double;
                v.doubleVal = readDoubleBE();
                return v;
            }
            case 0x06:
                return Amf3Value::makeString(readAmfStringBody());
            case 0x08: { // Date
                const uint32_t h = readU29();
                if ((h & 1u) == 0) {
                    const uint32_t idx = h >> 1;
                    if (idx >= objRefs_.size()) {
                        throw std::runtime_error("AMF3 bad date ref");
                    }
                    return objRefs_[idx];
                }
                Amf3Value v;
                v.kind = Amf3Value::Kind::Double;
                v.doubleVal = readDoubleBE();
                objRefs_.push_back(v);
                return v;
            }
            case 0x09: { // Array
                const uint32_t h = readU29();
                if ((h & 1u) == 0) {
                    const uint32_t idx = h >> 1;
                    if (idx >= objRefs_.size()) {
                        throw std::runtime_error("AMF3 bad array ref");
                    }
                    return objRefs_[idx];
                }
                const size_t denseCount = h >> 1;
                const size_t slotIdx = objRefs_.size();
                objRefs_.push_back(Amf3Value::makeEmptyArray());

                Amf3Value arr;
                arr.kind = Amf3Value::Kind::Array;
                while (true) {
                    const std::string k = readAmfStringBody();
                    if (k.empty()) {
                        break;
                    }
                    arr.fields[k] = readValue(depth + 1);
                }
                arr.dense.reserve(denseCount);
                for (size_t i = 0; i < denseCount; ++i) {
                    arr.dense.push_back(readValue(depth + 1));
                }
                if (!arr.fields.empty() && arr.dense.empty()) {
                    arr.kind = Amf3Value::Kind::Map;
                }
                objRefs_[slotIdx] = arr;
                return arr;
            }
            case 0x0A: { // Object
                const uint32_t h = readU29();
                if ((h & 1u) == 0) {
                    const uint32_t idx = h >> 1;
                    if (idx >= objRefs_.size()) {
                        throw std::runtime_error("AMF3 bad object ref");
                    }
                    return objRefs_[idx];
                }
                TraitDef trait;
                if ((h & 2u) == 0) {
                    const uint32_t tidx = h >> 2;
                    if (tidx >= traitRefs_.size()) {
                        throw std::runtime_error("AMF3 bad trait ref");
                    }
                    trait = traitRefs_[tidx];
                } else {
                    if ((h & 4u) != 0) {
                        throw std::runtime_error("AMF3 externalizable unsupported");
                    }
                    trait.dynamic = (h & 8u) != 0;
                    const size_t sealedCount = h >> 4;
                    (void)readAmfStringBody(); // class name
                    trait.sealedNames.reserve(sealedCount);
                    for (size_t i = 0; i < sealedCount; ++i) {
                        trait.sealedNames.push_back(readAmfStringBody());
                    }
                    traitRefs_.push_back(trait);
                }

                const size_t slotIdx = objRefs_.size();
                Amf3Value obj;
                obj.kind = Amf3Value::Kind::Map;
                objRefs_.push_back(obj);

                for (const auto& sk : trait.sealedNames) {
                    obj.fields[sk] = readValue(depth + 1);
                }
                if (trait.dynamic) {
                    while (true) {
                        const std::string dk = readAmfStringBody();
                        if (dk.empty()) {
                            break;
                        }
                        obj.fields[dk] = readValue(depth + 1);
                    }
                }
                objRefs_[slotIdx] = obj;
                return obj;
            }
            case 0x0C: { // ByteArray
                const uint32_t h = readU29();
                if ((h & 1u) == 0) {
                    const uint32_t idx = h >> 1;
                    if (idx >= objRefs_.size()) {
                        throw std::runtime_error("AMF3 bad bytearray ref");
                    }
                    return objRefs_[idx];
                }
                const size_t blen = h >> 1;
                if (pos_ + blen > len_) {
                    throw std::runtime_error("AMF3 truncated bytearray");
                }
                std::string raw(reinterpret_cast<const char*>(data_ + pos_), blen);
                pos_ += blen;
                Amf3Value v = Amf3Value::makeString(std::move(raw));
                objRefs_.push_back(v);
                return v;
            }
            default:
                throw std::runtime_error("AMF3 unsupported marker: " + std::to_string(marker));
        }
    }
};

Amf3Value decodeAmf3(const std::string& bytes) {
    Amf3Decoder dec(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    return dec.decode();
}

// ============================================================================
// 3. Minimal JSON Reader + Loopback HTTP/1.1 Client (Cookie Jar + Strict Signing)
// ============================================================================

struct JsonMini {
    enum class Type { Null, Bool, Number, String, Array, Object };
    Type type = Type::Null;
    bool b = false;
    double num = 0.0;
    std::string s;
    std::vector<JsonMini> arr;
    std::map<std::string, JsonMini> obj;

    const JsonMini* get(const std::string& k) const {
        if (type != Type::Object) {
            return nullptr;
        }
        auto it = obj.find(k);
        return (it != obj.end()) ? &it->second : nullptr;
    }

    std::string scalarStr() const {
        if (type == Type::String) {
            return s;
        }
        if (type == Type::Number) {
            return std::to_string(static_cast<int64_t>(num));
        }
        return {};
    }
};

class JsonParser {
public:
    explicit JsonParser(const std::string& src) : s_(src) {}
    JsonMini parse() {
        skipWs();
        return parseVal();
    }

private:
    const std::string& s_;
    size_t p_ = 0;

    void skipWs() {
        while (p_ < s_.size() &&
               (s_[p_] == ' ' || s_[p_] == '\t' || s_[p_] == '\r' || s_[p_] == '\n')) {
            ++p_;
        }
    }

    char peek() {
        skipWs();
        return (p_ < s_.size()) ? s_[p_] : '\0';
    }

    std::string parseString() {
        if (s_[p_] != '"') {
            throw std::runtime_error("JSON expected '\"'");
        }
        ++p_;
        std::string out;
        while (p_ < s_.size()) {
            char c = s_[p_++];
            if (c == '"') {
                return out;
            }
            if (c == '\\' && p_ < s_.size()) {
                char esc = s_[p_++];
                switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        if (p_ + 4 > s_.size()) {
                            throw std::runtime_error("JSON bad \\u");
                        }
                        uint32_t cp = static_cast<uint32_t>(std::stoul(s_.substr(p_, 4), nullptr, 16));
                        p_ += 4;
                        if (cp < 0x80u) {
                            out.push_back(static_cast<char>(cp));
                        } else if (cp < 0x800u) {
                            out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
                            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
                        } else {
                            out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
                            out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
                            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
                        }
                        break;
                    }
                    default: out.push_back(esc); break;
                }
            } else {
                out.push_back(c);
            }
        }
        throw std::runtime_error("JSON unterminated string");
    }

    JsonMini parseVal() {
        const char c = peek();
        if (c == '"') {
            JsonMini v;
            v.type = JsonMini::Type::String;
            v.s = parseString();
            return v;
        }
        if (c == '{') {
            ++p_;
            JsonMini v;
            v.type = JsonMini::Type::Object;
            if (peek() == '}') {
                ++p_;
                return v;
            }
            while (true) {
                skipWs();
                std::string k = parseString();
                if (peek() != ':') {
                    throw std::runtime_error("JSON expected ':'");
                }
                ++p_;
                v.obj[std::move(k)] = parseVal();
                const char sep = peek();
                if (sep == '}') {
                    ++p_;
                    break;
                }
                if (sep != ',') {
                    throw std::runtime_error("JSON expected ',' or '}'");
                }
                ++p_;
            }
            return v;
        }
        if (c == '[') {
            ++p_;
            JsonMini v;
            v.type = JsonMini::Type::Array;
            if (peek() == ']') {
                ++p_;
                return v;
            }
            while (true) {
                v.arr.push_back(parseVal());
                const char sep = peek();
                if (sep == ']') {
                    ++p_;
                    break;
                }
                if (sep != ',') {
                    throw std::runtime_error("JSON expected ',' or ']'");
                }
                ++p_;
            }
            return v;
        }
        if (s_.compare(p_, 4, "true") == 0) {
            p_ += 4;
            JsonMini v;
            v.type = JsonMini::Type::Bool;
            v.b = true;
            return v;
        }
        if (s_.compare(p_, 5, "false") == 0) {
            p_ += 5;
            JsonMini v;
            v.type = JsonMini::Type::Bool;
            v.b = false;
            return v;
        }
        if (s_.compare(p_, 4, "null") == 0) {
            p_ += 4;
            return JsonMini{};
        }
        size_t start = p_;
        while (p_ < s_.size() &&
               (std::isdigit(static_cast<unsigned char>(s_[p_])) || s_[p_] == '-' ||
                s_[p_] == '+' || s_[p_] == '.' || s_[p_] == 'e' || s_[p_] == 'E')) {
            ++p_;
        }
        if (start == p_) {
            throw std::runtime_error("JSON unexpected token");
        }
        JsonMini v;
        v.type = JsonMini::Type::Number;
        v.num = std::stod(s_.substr(start, p_ - start));
        return v;
    }
};

struct HttpReply {
    int status = 0;
    std::vector<std::string> cookies;
    JsonMini json;
};

HttpReply httpGetJson(const std::string& host, uint16_t port, const std::string& target,
                      const std::vector<std::string>& cookies = {}) {
    gclient::net::WinsockSession wsa;
    (void)wsa;

    SOCKET fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) {
        throw std::runtime_error("http socket() failed");
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
#ifdef _WIN32
        ::closesocket(fd);
#else
        ::close(fd);
#endif
        throw std::runtime_error("http connect() failed");
    }

    std::ostringstream req;
    req << "GET " << target << " HTTP/1.1\r\nHost: " << host << ":" << port
        << "\r\nConnection: close\r\n";
    if (!cookies.empty()) {
        req << "Cookie: ";
        for (size_t i = 0; i < cookies.size(); ++i) {
            if (i > 0) {
                req << "; ";
            }
            req << cookies[i];
        }
        req << "\r\n";
    }
    req << "\r\n";
    const std::string reqStr = req.str();
    size_t sent = 0;
    while (sent < reqStr.size()) {
        const auto n = ::send(fd, reqStr.data() + sent,
#ifdef _WIN32
                              static_cast<int>(reqStr.size() - sent),
#else
                              reqStr.size() - sent,
#endif
                              0);
        if (n <= 0) {
            break;
        }
        sent += static_cast<size_t>(n);
    }

    std::string raw;
    char buf[4096];
    while (true) {
        const auto n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        raw.append(buf, static_cast<size_t>(n));
    }
#ifdef _WIN32
    ::closesocket(fd);
#else
    ::close(fd);
#endif

    const auto split = raw.find("\r\n\r\n");
    if (split == std::string::npos) {
        throw std::runtime_error("invalid HTTP response header");
    }
    const std::string head = raw.substr(0, split);
    const std::string body = raw.substr(split + 4);

    HttpReply out;
    std::istringstream hs(head);
    std::string statusLine;
    std::getline(hs, statusLine);
    {
        std::istringstream sl(statusLine);
        std::string httpVer;
        sl >> httpVer >> out.status;
    }
    std::string line;
    while (std::getline(hs, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string k = line.substr(0, colon);
            std::transform(k.begin(), k.end(), k.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (k == "set-cookie") {
                std::string v = line.substr(colon + 1);
                while (!v.empty() && v.front() == ' ') {
                    v.erase(v.begin());
                }
                const auto semi = v.find(';');
                out.cookies.push_back(semi == std::string::npos ? v : v.substr(0, semi));
            }
        }
    }
    out.json = JsonParser(body).parse();
    return out;
}

// ============================================================================
// 4. Real kestrel-canvas CNetwork + CConnection + LCPacket Live Wire Client!
// ============================================================================

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
        if (!conn_) {
            return false;
        }
        conn_->setHeaderSize(8);
        conn_->setHeadCallback([](const char* hdr, size_t hdrSize) -> uint32_t {
            if (!hdr || hdrSize < 8) {
                return 0;
            }
            return gclient::net::LCPacket::readBigEndianU32(
                reinterpret_cast<const uint8_t*>(hdr));
        });
        conn_->setBodyCallback(
            [this](const char* body, size_t bodyLen, const char* hdr, size_t hdrLen) {
                if (!hdr || hdrLen < 8) {
                    return;
                }
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
                        if (off + subLen > unpacked.size()) {
                            break;
                        }
                        ingestSingleAmfEnvelope(unpacked.substr(off, subLen));
                        off += subLen;
                    }
                }
            });

        if (!conn_->connect(host.c_str(), port)) {
            return false;
        }
        net->addConnection(conn_);

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            net->update(0.016f);
            if (conn_->isConnected()) {
                return true;
            }
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
        const std::string cbName =
            isTelemetry ? method : (method + "_" + std::to_string(seq_));

        Amf3Value reqObj = Amf3Value::makeMap({
            {"method", Amf3Value::makeString(method)},
            {"args", std::move(rawArgs)},
            {"token", Amf3Value::makeString(token_)},
            {"callback", Amf3Value::makeMap({{"callbackName", Amf3Value::makeString(cbName)}})},
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

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            gclient::net::CNetwork::sharedNetwork()->update(0.016f);
            {
                std::lock_guard<std::mutex> lk(mu_);
                for (auto it = inbox_.begin(); it != inbox_.end(); ++it) {
                    if (it->callbackName == cbName) {
                        S2cDecodedMsg found = std::move(*it);
                        inbox_.erase(it);
                        return found;
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(4));
        }
        throw std::runtime_error("Timed out waiting for S2C callback: " + cbName);
    }

    S2cDecodedMsg callRpc(const std::string& method, std::vector<Amf3Value> args,
                          bool compressLCPacket = true) {
        ++seq_;
        const bool isTelemetry = (method == "user.stat" || method == "user.guideEvent");
        const std::string cbName =
            isTelemetry ? method : (method + "_" + std::to_string(seq_));

        Amf3Value reqObj = Amf3Value::makeMap({
            {"method", Amf3Value::makeString(method)},
            {"args", Amf3Value::makeArray(std::move(args))},
            {"token", Amf3Value::makeString(token_)},
            {"callback", Amf3Value::makeMap({{"callbackName", Amf3Value::makeString(cbName)}})},
        });

        Amf3Encoder enc;
        const std::string rawAmf = enc.encode(reqObj);

        if (compressLCPacket) {
            // Exercise CConnection::send(..., wrapLCPacket=true) directly!
            if (!conn_->send(rawAmf, true)) {
                throw std::runtime_error("CConnection::send(wrapLCPacket=true) failed");
            }
        } else {
            const std::string framed = gclient::net::LCPacket::makeLCPacket(rawAmf, false);
            if (!conn_->send(framed, false)) {
                throw std::runtime_error("CConnection::send(uncompressed LCPacket) failed");
            }
        }

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            gclient::net::CNetwork::sharedNetwork()->update(0.016f);
            {
                std::lock_guard<std::mutex> lk(mu_);
                for (auto it = inbox_.begin(); it != inbox_.end(); ++it) {
                    if (it->callbackName == cbName) {
                        S2cDecodedMsg found = std::move(*it);
                        inbox_.erase(it);
                        return found;
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(4));
        }
        throw std::runtime_error("Timed out waiting for S2C callback: " + cbName);
    }

    S2cDecodedMsg callPing(const std::string& method) {
        Amf3Value reqObj = Amf3Value::makeMap({
            {"method", Amf3Value::makeString(method)},
            {"args", Amf3Value::makeEmptyArray()},
            {"token", Amf3Value::makeString(token_)},
            {"callback", Amf3Value::makeMap({{"callbackName", Amf3Value::makeString(method)}})},
        });
        Amf3Encoder enc;
        conn_->send(enc.encode(reqObj), true);

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            gclient::net::CNetwork::sharedNetwork()->update(0.016f);
            {
                std::lock_guard<std::mutex> lk(mu_);
                for (auto it = inbox_.begin(); it != inbox_.end(); ++it) {
                    if (it->err == "ping") {
                        S2cDecodedMsg found = std::move(*it);
                        inbox_.erase(it);
                        return found;
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(4));
        }
        throw std::runtime_error("Timed out waiting for S2C ping");
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
    void ingestSingleAmfEnvelope(const std::string& amfBytes) {
        Amf3Value env = decodeAmf3(amfBytes);
        S2cDecodedMsg msg;
        if (const auto* e = env.get("err")) {
            msg.err = e->asString();
        }
        if (const auto* cb = env.get("callback")) {
            if (const auto* cbn = cb->get("callbackName")) {
                msg.callbackName = cbn->asString();
            }
        }
        if (const auto* tok = env.get("token")) {
            msg.token = tok->asString();
            if (!msg.token.empty() && msg.token != "0") {
                token_ = msg.token;
            }
        }
        if (const auto* r = env.get("ret")) {
            msg.ret = *r;
        }
        std::lock_guard<std::mutex> lk(mu_);
        inbox_.push_back(std::move(msg));
    }

    gclient::net::CConnection* conn_ = nullptr;
    uint64_t seq_ = 1;
    std::string token_ = "0";
    std::mutex mu_;
    std::deque<S2cDecodedMsg> inbox_;
};

struct AuthTicket {
    std::string pid;
    std::string hash;
    uint16_t tcpPort = 0;
};

AuthTicket strictGuestHandshake(const std::string& httpHost, uint16_t httpPort,
                                const std::string& deviceId, bool checkCookie102) {
    const std::string ts = "1795502000";
    const std::string sig = computeGuestAuthSig(deviceId, ts);
    auto guestResp = httpGetJson(
        httpHost, httpPort,
        "/api/login/createUser/guest?deviceID=" + deviceId + "&gameID=" + kGtsdkGameId +
            "&timestamp=" + ts + "&sig=" + sig);
    if (!guestResp.json.get("errornu") || guestResp.json.get("errornu")->scalarStr() != "0") {
        throw std::runtime_error("guest GTSDK auth failed");
    }
    const std::string userId    = guestResp.json.get("userID")->scalarStr();
    const std::string sessionId = guestResp.json.get("sessionID")->scalarStr();

    const std::string loginTarget = signMapiTarget(
        "/phone/login/?pl=android_vnsg2&gn=vnsg2&os=win32&userid=" + userId +
            "&sessionid=" + sessionId,
        1795502001);
    auto loginResp = httpGetJson(httpHost, httpPort, loginTarget);
    if (loginResp.cookies.empty() || !loginResp.json.get("pid")) {
        throw std::runtime_error("/phone/login missing cookies or pid");
    }
    const std::string pid = loginResp.json.get("pid")->scalarStr();

    const std::string hashTarget = signMapiTarget(
        "/phone/gethash/?pl=android_vnsg2&gn=vnsg2&pid=" + pid +
            "&group_id=2900161&uuid=uuid_" + deviceId,
        1795502002);
    if (checkCookie102) {
        auto noCookieResp = httpGetJson(httpHost, httpPort, hashTarget);
        if (!noCookieResp.json.get("errornu") ||
            noCookieResp.json.get("errornu")->scalarStr() != "102") {
            throw std::runtime_error("expected errornu='102' when cookie omitted");
        }
    }

    auto hashResp = httpGetJson(httpHost, httpPort, hashTarget, loginResp.cookies);
    if (!hashResp.json.get("errornu") || hashResp.json.get("errornu")->scalarStr() != "0") {
        throw std::runtime_error("/phone/gethash failed");
    }
    AuthTicket t;
    t.pid     = pid;
    t.hash    = hashResp.json.get("hash")->scalarStr();
    t.tcpPort = static_cast<uint16_t>(hashResp.json.get("port")->num);
    return t;
}

AuthTicket strictAccountHandshake(const std::string& httpHost, uint16_t httpPort,
                                  const std::string& username, const std::string& password) {
    const std::string ts    = "1795502010";
    const std::string pwMd5 = md5Hex(password);
    const std::string sig   = computeAccountAuthSig(username, pwMd5, ts);
    auto acctResp = httpGetJson(
        httpHost, httpPort,
        "/api/login/auth/account?u=" + username + "&p=" + pwMd5 + "&gameID=" + kGtsdkGameId +
            "&timestamp=" + ts + "&sig=" + sig);
    if (!acctResp.json.get("errornu") || acctResp.json.get("errornu")->scalarStr() != "0") {
        throw std::runtime_error("account GTSDK auth failed");
    }
    const std::string userId    = acctResp.json.get("userID")->scalarStr();
    const std::string sessionId = acctResp.json.get("sessionID")->scalarStr();

    const std::string loginTarget = signMapiTarget(
        "/phone/login/?pl=android_vnsg2&gn=vnsg2&os=win32&userid=" + userId +
            "&sessionid=" + sessionId,
        1795502011);
    auto loginResp = httpGetJson(httpHost, httpPort, loginTarget);
    const std::string pid = loginResp.json.get("pid")->scalarStr();

    const std::string hashTarget = signMapiTarget(
        "/phone/gethash/?pl=android_vnsg2&gn=vnsg2&pid=" + pid +
            "&group_id=2900161&uuid=uuid_" + username,
        1795502012);
    auto hashResp = httpGetJson(httpHost, httpPort, hashTarget, loginResp.cookies);
    AuthTicket t;
    t.pid     = pid;
    t.hash    = hashResp.json.get("hash")->scalarStr();
    t.tcpPort = static_cast<uint16_t>(hashResp.json.get("port")->num);
    return t;
}

std::vector<uint8_t> readBinaryFile(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error("unable to open file: " + path);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)),
                                std::istreambuf_iterator<char>());
}

bool hasPush(const std::vector<S2cDecodedMsg>& pushes, const std::string& cbName) {
    for (const auto& p : pushes) {
        if (p.callbackName == cbName) {
            return true;
        }
    }
    return false;
}

int64_t sumBagTemplateCount(const Amf3Value& bagRet, const std::string& subBagKey,
                            int64_t targetTid) {
    int64_t total = 0;
    const auto* sub = bagRet.get(subBagKey);
    if (!sub) {
        return 0;
    }
    for (const auto& kv : sub->fields) {
        const auto* tidVal = kv.second.get("item_template_id");
        const auto* numVal = kv.second.get("item_num");
        if (tidVal && numVal && tidVal->asInt() == targetTid) {
            total += numVal->asInt();
        }
    }
    return total;
}

// ============================================================================
// 5. Offline Self-Tests (LCPacket + BtDecryptHook + Optional LuaJIT Amf3Module)
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

    // Verify C++17 AMF3 + LCPacket 24-byte salted MD5 roundtrip
    Amf3Value sample = Amf3Value::makeMap({
        {"method", Amf3Value::makeString("user.login")},
        {"args", Amf3Value::makeArray({Amf3Value::makeInt(2900161),
                                       Amf3Value::makeString("TriệuTửLong")})},
        {"token", Amf3Value::makeString("0")},
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
    luaL_openlibs(L);
    luaopen_amf3_extensions(L);
    const char* script =
        "local amf3 = require('amf3')\n"
        "local bin = amf3.encode({ method = 'city.enter', args = { 1 }, token = 'tok_1' })\n"
        "local t = amf3.decode(bin)\n"
        "assert(t.method == 'city.enter' and t.args[1] == 1 and t.token == 'tok_1')\n";
    REQUIRE_EQ(luaL_dostring(L, script), 0);
    lua_close(L);
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

    runCase("CrossRepo_01_BtDecrypt_LCPacket_And_Amf3_Parity",
            [&]() { return runSelfTests(encLuaPath, decLuaPath); });

    if (selfTestOnly) {
        gclient::net::CNetwork::destroySharedNetwork();
        std::printf("\n=== Summary: %d passed, %d failed (self-test mode) ===\n",
                    g_passed, g_failed);
        return (g_failed == 0) ? 0 : 1;
    }

    if (httpPort == 0 || tcpPort == 0) {
        std::fprintf(stderr, "Missing --http-port / --tcp-port for live cobalt-relay mode\n");
        return 2;
    }

    if (verifyRestart) {
        runCase("CrossRepo_16_VerifyColdRestart_WAL_State_CopyProgress_And_ActStar", [&]() {
            const auto tk = strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_alpha", true);
            REQUIRE_EQ(tk.tcpPort, tcpPort);

            // Verify /phone/loginrole/ exposes Lv.35 LongĐởmThần after cold restart!
            const auto lrTarget = signMapiTarget(
                "/phone/loginrole/?pl=android_vnsg2&gn=vnsg2&pid=" + tk.pid, 1795503000);
            const auto lr = httpGetJson(httpHost, httpPort, lrTarget);
            const auto* root = lr.json.get("root");
            REQUIRE_TRUE(root != nullptr && root->get("role") != nullptr);
            REQUIRE_TRUE(!root->get("role")->arr.empty());
            REQUIRE_EQ(root->get("role")->arr[0].get("uname")->scalarStr(),
                       std::string("LongĐởmThần"));
            REQUIRE_TRUE(static_cast<int>(root->get("role")->arr[0].get("level")->num) >= 35);

            RealKestrelWireClient client;
            REQUIRE_TRUE(client.connectToRelay(tcpHost, tcpPort));

            auto loginEnv = client.callRpc(
                "user.login",
                {Amf3Value::makeMap({
                    {"AMF", Amf3Value::makeInt(3)},
                    {"pid", Amf3Value::makeString(tk.pid)},
                    {"qid", Amf3Value::makeString(tk.pid)},
                    {"hash", Amf3Value::makeString(tk.hash)},
                    {"serverID", Amf3Value::makeString("game2900161")},
                })});
            REQUIRE_EQ(loginEnv.err, std::string("ok"));

            auto b4 = client.callRpc("user.getUserBeforLogin", {});
            const int64_t uid = b4.ret.get("uid")->asInt();
            REQUIRE_TRUE(uid > 0);

            auto ul = client.callRpc("user.userLogin", {Amf3Value::makeInt(uid)});
            REQUIRE_EQ(ul.ret.asString(), std::string("ok"));

            auto u = client.callRpc("user.getUser", {});
            REQUIRE_EQ(u.ret.get("uname")->asString(), std::string("LongĐởmThần"));
            REQUIRE_TRUE(u.ret.get("level")->asInt() >= 36LL);
            REQUIRE_TRUE(u.ret.get("execution")->asInt() > 300LL);

            // VIP 1 gift must still be marked bought after cold restart!
            auto vipDup = client.callRpc("user.buyVipGift", {Amf3Value::makeInt(1)});
            REQUIRE_EQ(vipDup.err, std::string("vip_gift_already_bought"));

            auto va = client.callRpc("user.getVaConfig", {});
            REQUIRE_EQ(va.ret.get("kestrel_key")->asString(), std::string("win32_ok"));

            // Flow A cold-restart verification: copy stars, passed count, chapter 1002 unlock & prize mask!
            auto cl = client.callRpc("copy.getList", {Amf3Value::makeInt(1)});
            REQUIRE_EQ(cl.err, std::string("ok"));
            const auto* cd = cl.ret.get("copyData");
            REQUIRE_TRUE(cd != nullptr);
            const auto* c1001 = cd->get("1001");
            REQUIRE_TRUE(c1001 != nullptr);
            REQUIRE_EQ(c1001->get("star")->asInt(), 15LL);
            REQUIRE_EQ(c1001->get("pass_strongh")->asInt(), 5LL);
            REQUIRE_EQ(c1001->get("prize")->asInt(), 1LL);
            REQUIRE_TRUE(cd->get("1002") != nullptr);

            auto cc = client.callRpc("copy.getCopy", {Amf3Value::makeInt(1001)});
            REQUIRE_EQ(cc.err, std::string("ok"));
            const auto* vaCopy = cc.ret.get("va_copy");
            REQUIRE_TRUE(vaCopy != nullptr);
            REQUIRE_TRUE(vaCopy->get("100102") != nullptr);
            REQUIRE_EQ(vaCopy->get("100102")->get("normal_star")->asInt(), 3LL);
            REQUIRE_EQ(vaCopy->get("100102")->get("pass")->asInt(), 1LL);
            REQUIRE_TRUE(vaCopy->get("100105") != nullptr);
            REQUIRE_EQ(vaCopy->get("100105")->get("normal_star")->asInt(), 3LL);
            REQUIRE_EQ(vaCopy->get("100105")->get("pass")->asInt(), 1LL);
            REQUIRE_EQ(
                client.callRpc("copy.fetchPrize", {Amf3Value::makeInt(1001), Amf3Value::makeInt(0)})
                    .err,
                std::string("prize_already_claimed"));

            // Flow B cold-restart verification: ActStar claimed gift IDs, duplicate/locked guards & bag rewards!
            auto starInfo = client.callRpc("activityStarPlayOpen.getInfo", {});
            REQUIRE_EQ(starInfo.err, std::string("ok"));
            REQUIRE_TRUE(starInfo.ret.get("1") != nullptr);
            REQUIRE_TRUE(starInfo.ret.get("1")->kind == Amf3Value::Kind::Bool &&
                         starInfo.ret.get("1")->boolVal);
            REQUIRE_TRUE(starInfo.ret.get("4") != nullptr);
            REQUIRE_TRUE(starInfo.ret.get("4")->kind == Amf3Value::Kind::Bool &&
                         starInfo.ret.get("4")->boolVal);
            REQUIRE_TRUE(starInfo.ret.get("2") == nullptr);
            REQUIRE_TRUE(starInfo.ret.get("5") == nullptr);

            REQUIRE_EQ(
                client.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(1)}).err,
                std::string("already_claimed"));
            REQUIRE_EQ(
                client.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(5)}).err,
                std::string("level_not_enough"));
            REQUIRE_EQ(
                client.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(99)}).err,
                std::string("invalid_gift_id"));

            auto bag = client.callRpc("bag.bagInfo", {}).ret;
            REQUIRE_TRUE(sumBagTemplateCount(bag, "item", 17002) >= 5LL);
            REQUIRE_EQ(sumBagTemplateCount(bag, "soul", 50406), 35LL);
            REQUIRE_TRUE(sumBagTemplateCount(bag, "item", 10010) >= 20LL);
            REQUIRE_TRUE(sumBagTemplateCount(bag, "item", 22202) >= 3LL);

            client.disconnect();
            return true;
        });

        gclient::net::CNetwork::destroySharedNetwork();
        std::printf("\n=== Summary: %d passed, %d failed (restart-verify mode) ===\n",
                    g_passed, g_failed);
        return (g_failed == 0) ? 0 : 1;
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

    runCase("CrossRepo_02_StrictHttp_MapiSign_AuthSig_Session102_And_DynamicPort", [&]() {
        // Unsigned MAPI call MUST be rejected with err_code = 403
        auto unsignedVer = httpGetJson(httpHost, httpPort,
                                       "/phone/getversion?pl=android_vnsg2&gn=vnsg2");
        REQUIRE_TRUE(unsignedVer.json.get("err_code") != nullptr);
        REQUIRE_EQ(static_cast<int>(unsignedVer.json.get("err_code")->num), 403);

        // Signed MAPI calls MUST succeed
        for (const char* ep : {
                 "/phone/getversion?pl=android_vnsg2&gn=vnsg2&os=win32",
                 "/phone/serverlist/?pl=android_vnsg2&gn=vnsg2",
                 "/phone/applereview/?pl=android_vnsg2&gn=vnsg2",
                 "/phone/notice/?pl=android_vnsg2&gn=vnsg2",
                 "/phone/supernotice/?pl=android_vnsg2&gn=vnsg2",
             }) {
            auto r = httpGetJson(httpHost, httpPort, signMapiTarget(ep, 1795502000));
            REQUIRE_EQ(r.status, 200);
            REQUIRE_TRUE(r.json.get("err_code") == nullptr ||
                         static_cast<int>(r.json.get("err_code")->num) != 403);
        }

        // Unsigned GTSDK guest call MUST fail with returnCode == "-3"
        auto unsignedGuest = httpGetJson(
            httpHost, httpPort,
            "/api/login/createUser/guest?deviceID=kestrel_cpp_alpha&gameID=GCLIENT");
        REQUIRE_TRUE(unsignedGuest.json.get("returnCode") != nullptr);
        REQUIRE_EQ(unsignedGuest.json.get("returnCode")->scalarStr(), std::string("-3"));

        // Forged sessionid on /phone/login MUST fail under strict_auth_token
        auto forgedLogin = httpGetJson(
            httpHost, httpPort,
            signMapiTarget("/phone/login/?pl=android_vnsg2&gn=vnsg2&userid=8888&sessionid=SID_bad",
                           1795502005));
        REQUIRE_TRUE(forgedLogin.json.get("errornu") != nullptr);
        REQUIRE_TRUE(forgedLogin.json.get("errornu")->scalarStr() != "0");

        tkA = strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_alpha", true);
        tkB = strictAccountHandshake(httpHost, httpPort, "kestrel_quanvu", "Win32@2026");
        REQUIRE_EQ(tkA.tcpPort, tcpPort);
        REQUIRE_EQ(tkB.tcpPort, tcpPort);
        return true;
    });

    runCase("CrossRepo_03_RealCNetwork_PreLogin_BadTicket_Ping_And_28StepBootstrap", [&]() {
        REQUIRE_TRUE(clientA.connectToRelay(tcpHost, tcpPort));
        REQUIRE_TRUE(clientB.connectToRelay(tcpHost, tcpPort));

        // Pre-login negative check
        REQUIRE_EQ(clientA.callRpc("user.getUser", {}).err, std::string("user_not_logged_in"));

        // Forged hash ticket negative check
        auto badLogin = clientA.callRpc(
            "user.login",
            {Amf3Value::makeMap({
                {"pid", Amf3Value::makeString(tkA.pid)},
                {"qid", Amf3Value::makeString(tkA.pid)},
                {"hash", Amf3Value::makeString("forged_hash_xyz")},
                {"serverID", Amf3Value::makeString("game2900161")},
            })},
            false);
        REQUIRE_EQ(badLogin.err, std::string("invalid_login_hash"));

        // Heartbeat ping & user.ping
        REQUIRE_EQ(clientA.callPing("ping").err, std::string("ping"));
        REQUIRE_EQ(clientA.callPing("user.ping").err, std::string("ping"));

        // Authentic compressed 24B LCPacket user.login
        auto okLogin = clientA.callRpc(
            "user.login",
            {
                Amf3Value::makeMap({
                    {"AMF", Amf3Value::makeInt(3)},
                    {"pid", Amf3Value::makeString(tkA.pid)},
                    {"qid", Amf3Value::makeString(tkA.pid)},
                    {"hash", Amf3Value::makeString(tkA.hash)},
                    {"serverID", Amf3Value::makeString("game2900161")},
                }),
                Amf3Value::makeString("uuid_kestrel_alpha"),
                Amf3Value::makeString("1.0.1194"),
            },
            true);
        REQUIRE_EQ(okLogin.err, std::string("ok"));

        REQUIRE_EQ(clientA.callRpc("user.getUserBeforLogin", {}).err, std::string("ok"));
        REQUIRE_EQ(
            clientA.callRpc("user.getRandomName", {Amf3Value::makeInt(10), Amf3Value::makeInt(1)})
                .err,
            std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("user.stat", {Amf3Value::makeInt(1)}).err, std::string("ok"));

        // Negative invalid utid
        REQUIRE_EQ(
            clientA
                .callRpc("user.createUser",
                         {Amf3Value::makeInt(999), Amf3Value::makeString("Bad")})
                .err,
            std::string("invalid_utid"));

        REQUIRE_EQ(
            clientA
                .callRpc("user.createUser",
                         {Amf3Value::makeInt(1), Amf3Value::makeString("TriệuTửLong")})
                .err,
            std::string("ok"));

        auto b4 = clientA.callRpc("user.getUserBeforLogin", {});
        uidA = b4.ret.get("uid")->asInt();
        REQUIRE_TRUE(uidA > 0);
        REQUIRE_EQ(clientA.callRpc("user.userLogin", {Amf3Value::makeInt(uidA)}).ret.asString(),
                   std::string("ok"));

        // Execute all remaining 22 Stage B/C/D/E MainTown bootstrap RPCs!
        const std::vector<std::pair<std::string, std::vector<Amf3Value>>> bootSteps = {
            {"user.getUser", {}},
            {"switchfunc.getSwitch", {}},
            {"user.getVaConfig", {}},
            {"formation.get", {}},
            {"formation.getPositionInfo", {}},
            {"bag.bagInfo", {Amf3Value::makeEmptyArray()}},
            {"copy.getList", {Amf3Value::makeInt(1)}},
            {"copy.getCopy", {Amf3Value::makeInt(1001)}},
            {"allActivity.getActivityInfo", {}},
            {"activity.getActivityConf", {}},
            {"mail.getMailBoxList", {}},
            {"reward.getRewardList", {Amf3Value::makeInt(0), Amf3Value::makeInt(0)}},
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
            {"user.guideEvent", {Amf3Value::makeInt(240)}},
            {"barrage.get", {}},
            {"barrage.enterRoom", {Amf3Value::makeInt(1)}},
            {"barrage.getBarrageRecord", {Amf3Value::makeInt(1)}},
        };
        for (size_t idx = 0; idx < bootSteps.size(); ++idx) {
            auto r = clientA.callRpc(bootSteps[idx].first, bootSteps[idx].second, (idx % 2) == 0);
            REQUIRE_EQ(r.err, std::string("ok"));
        }

        // Strict RPC gate: unknown method MUST fail with err == "unsupported_method"!
        REQUIRE_EQ(clientA.callRpc("nonexistent.fakeMethod", {}).err,
                   std::string("unsupported_method"));

        // Bring Client B online & verify duplicate character name guard
        REQUIRE_EQ(
            clientB
                .callRpc("user.login",
                         {Amf3Value::makeMap({
                             {"pid", Amf3Value::makeString(tkB.pid)},
                             {"qid", Amf3Value::makeString(tkB.pid)},
                             {"hash", Amf3Value::makeString(tkB.hash)},
                             {"serverID", Amf3Value::makeString("game2900161")},
                         })})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientB
                .callRpc("user.createUser",
                         {Amf3Value::makeInt(2), Amf3Value::makeString("TriệuTửLong")})
                .err,
            std::string("uname_used"));
        REQUIRE_EQ(
            clientB
                .callRpc("user.createUser",
                         {Amf3Value::makeInt(2), Amf3Value::makeString("QuanVũVIP")})
                .err,
            std::string("ok"));
        uidB = clientB.callRpc("user.getUserBeforLogin", {}).ret.get("uid")->asInt();
        REQUIRE_EQ(clientB.callRpc("user.userLogin", {Amf3Value::makeInt(uidB)}).ret.asString(),
                   std::string("ok"));
        return true;
    });

    runCase("CrossRepo_04_Progression_Rename_Stamina_Copper_HeroBag_VipGift_VaConfig", [&]() {
        (void)clientA.drainPushes(20);
        REQUIRE_EQ(clientA.callRpc("user.changeUname", {Amf3Value::makeString("QuanVũVIP")}).err,
                   std::string("uname_used"));
        REQUIRE_EQ(clientA.callRpc("user.changeUname", {Amf3Value::makeString("LongĐởmThần")}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("user.buyCopper", {Amf3Value::makeInt(2)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("user.buyExecution", {Amf3Value::makeInt(1)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("user.addEnergy", {Amf3Value::makeInt(1)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("user.openHeroBag", {Amf3Value::makeInt(2)}).err,
                   std::string("ok"));

        REQUIRE_EQ(clientA.callRpc("user.buyVipGift", {Amf3Value::makeInt(12)}).err,
                   std::string("vip_too_low"));
        REQUIRE_EQ(clientA.callRpc("user.buyVipGift", {Amf3Value::makeInt(1)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("user.buyVipGift", {Amf3Value::makeInt(1)}).err,
                   std::string("vip_gift_already_bought"));
        REQUIRE_EQ(clientA.callRpc("user.getVipGiftInfo", {}).err, std::string("ok"));

        REQUIRE_EQ(
            clientA
                .callRpc("user.setVaConfig",
                         {Amf3Value::makeString("kestrel_key"), Amf3Value::makeString("win32_ok")})
                .err,
            std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("user.getVaConfig", {}).ret.get("kestrel_key")->asString(),
                   std::string("win32_ok"));

        auto pushes = clientA.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushes, "user.updateUser"));
        return true;
    });

    runCase("CrossRepo_05_Inventory_42SubBags_UseItem_Sell_Expand_And_Compose", [&]() {
        auto exp = clientA.callRpc(
            "bag.openGridByGold", {Amf3Value::makeInt(5), Amf3Value::makeString("arm")});
        REQUIRE_EQ(exp.err, std::string("ok"));
        REQUIRE_EQ(exp.ret.asString(), std::string("ok"));

        auto bag = clientA.callRpc("bag.bagInfo", {}).ret;
        int64_t gid22102 = 0;
        int64_t gid16012 = 0;
        if (const auto* itemSub = bag.get("item")) {
            for (const auto& kv : itemSub->fields) {
                const int64_t tid = kv.second.get("item_template_id")->asInt();
                if (tid == 22102) {
                    gid22102 = std::stoll(kv.first);
                } else if (tid == 16012) {
                    gid16012 = std::stoll(kv.first);
                }
            }
        }
        REQUIRE_TRUE(gid22102 > 0 && gid16012 > 0);

        REQUIRE_EQ(
            clientA
                .callRpc("exchange.useItemInBag",
                         {Amf3Value::makeInt(39999), Amf3Value::makeInt(1)})
                .err,
            std::string("item_not_found"));
        REQUIRE_EQ(
            clientA
                .callRpc("exchange.useItemInBag",
                         {Amf3Value::makeInt(gid22102), Amf3Value::makeInt(9999)})
                .err,
            std::string("insufficient_item_count"));

        (void)clientA.drainPushes(20);
        REQUIRE_EQ(
            clientA
                .callRpc("exchange.useItemInBag",
                         {Amf3Value::makeInt(gid22102), Amf3Value::makeInt(2)})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("exchange.useItemInBagByTpl",
                         {Amf3Value::makeInt(22202), Amf3Value::makeInt(3)})
                .err,
            std::string("ok"));

        REQUIRE_EQ(
            clientA
                .callRpc("bag.sellItems",
                         {Amf3Value::makeArray({Amf3Value::makeArray(
                             {Amf3Value::makeInt(gid16012), Amf3Value::makeInt(0),
                              Amf3Value::makeInt(5)})})})
                .err,
            std::string("ok"));

        auto ch = clientA.callRpc("exchange.composeHero",
                                  {Amf3Value::makeInt(50101), Amf3Value::makeInt(1)});
        REQUIRE_EQ(ch.err, std::string("ok"));
        if (ch.ret.get("hid") != nullptr) {
            composedHid = ch.ret.get("hid")->asInt();
        }
        auto heroesAfterComp = clientA.callRpc("hero.getAllHeroes", {}).ret;
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
                if (h > 10000003LL) {
                    composedHid = std::max(composedHid, h);
                }
            }
        }
        REQUIRE_TRUE(composedHid > 10000001LL);

        // Starter equipment fragment aligned in cobalt-relay 8ac9658 to vnsg2 `3113001` (x20)
        auto ca = clientA.callRpc("exchange.composeArm",
                                  {Amf3Value::makeInt(3113001), Amf3Value::makeInt(1)});
        REQUIRE_EQ(ca.err, std::string("ok"));
        REQUIRE_EQ(ca.ret.asString(), std::string("ok"));
        auto bagAfterComp = clientA.callRpc("bag.bagInfo", {}).ret;
        if (const auto* armSub = bagAfterComp.get("arm")) {
            for (const auto& kv : armSub->fields) {
                const int64_t g = std::stoll(kv.first);
                if (kv.second.get("item_template_id") != nullptr &&
                    kv.second.get("item_template_id")->asInt() == 113001) {
                    craftedArmGid = g;
                }
            }
        }
        REQUIRE_TRUE(craftedArmGid >= 10001LL);
        REQUIRE_EQ(clientA
                       .callRpc("exchange.composeArm",
                                {Amf3Value::makeInt(3113001), Amf3Value::makeInt(1)})
                       .err,
                   std::string("insufficient_item_count"));

        auto pushes = clientA.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushes, "bag.update"));
        REQUIRE_TRUE(hasPush(pushes, "re.hero.new"));
        return true;
    });

    runCase("CrossRepo_06_HeroRoster_LevelUp_Skill_Surmount_LockGuard_And_Evolve", [&]() {
        REQUIRE_EQ(
            clientA
                .callRpc("hero.heroLevelUp",
                         {Amf3Value::makeInt(10000001), Amf3Value::makeInt(1)})
                .err,
            std::string("protagonist_cannot_level_directly"));

        auto lv = clientA.callRpc("hero.heroLevelUp",
                                  {Amf3Value::makeInt(composedHid), Amf3Value::makeInt(5)});
        REQUIRE_EQ(lv.err, std::string("ok"));
        REQUIRE_TRUE(lv.ret.get("newlv") != nullptr);
        REQUIRE_EQ(lv.ret.get("newlv")->asInt(), 6LL);

        REQUIRE_EQ(
            clientA
                .callRpc("hero.skillLevelUp",
                         {Amf3Value::makeInt(composedHid), Amf3Value::makeInt(2001)})
                .err,
            std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("evolve.surmount", {Amf3Value::makeInt(composedHid)}).err,
                   std::string("ok"));

        REQUIRE_EQ(
            clientA
                .callRpc("chat.sendWorld",
                         {Amf3Value::makeInt(1), Amf3Value::makeString("/hero 305")})
                .err,
            std::string("ok"));
        auto heroes = clientA.callRpc("hero.getAllHeroes", {}).ret;
        int64_t fodderHid = 0;
        for (const auto& kv : heroes.fields) {
            if (kv.second.get("htid")->asInt() == 305) {
                fodderHid = std::stoll(kv.first);
            }
        }
        REQUIRE_TRUE(fodderHid > 0);

        REQUIRE_EQ(clientA.callRpc("hero.lock", {Amf3Value::makeInt(fodderHid)}).err,
                   std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("evolve.doEvolve",
                         {Amf3Value::makeInt(composedHid),
                          Amf3Value::makeArray({Amf3Value::makeInt(fodderHid)})})
                .err,
            std::string("locked_hero_cannot_sacrifice"));

        REQUIRE_EQ(clientA.callRpc("hero.unLock", {Amf3Value::makeInt(fodderHid)}).err,
                   std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("evolve.doEvolve",
                         {Amf3Value::makeInt(composedHid),
                          Amf3Value::makeArray({Amf3Value::makeInt(fodderHid)})})
                .err,
            std::string("deployed_hero_cannot_sacrifice"));

        REQUIRE_EQ(clientA.callRpc("formation.unsetHeroFromPosition", {Amf3Value::makeInt(4)}).err,
                   std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("evolve.doEvolve",
                         {Amf3Value::makeInt(composedHid),
                          Amf3Value::makeArray({Amf3Value::makeInt(fodderHid)})})
                .err,
            std::string("ok"));
        return true;
    });

    runCase("CrossRepo_07_Squad_9Grid_LittleFriendPartner_9SlotArming_And_Forge", [&]() {
        REQUIRE_EQ(clientA.callRpc("formation.unsetHeroFromPosition", {Amf3Value::makeInt(1)}).err,
                   std::string("protagonist_cannot_be_removed"));

        REQUIRE_EQ(
            clientA
                .callRpc("chat.sendWorld",
                         {Amf3Value::makeInt(1), Amf3Value::makeString("/level 35")})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("formation.setHeroToPosition",
                         {Amf3Value::makeInt(composedHid), Amf3Value::makeInt(4)})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("formation.transHero",
                         {Amf3Value::makeInt(2), Amf3Value::makeInt(4)})
                .err,
            std::string("ok"));

        auto sq = clientA.callRpc("formation.getHeroes", {}).ret.dense;
        std::vector<int64_t> active;
        for (const auto& v : sq) {
            if (v.asInt() > 0) {
                active.push_back(v.asInt());
            }
        }
        REQUIRE_EQ(active.size(), static_cast<size_t>(4));

        // Negative: incomplete 3x3 grid rejected
        REQUIRE_EQ(
            clientA
                .callRpc("formation.set",
                         {Amf3Value::makeMap({{"1", Amf3Value::makeInt(active[0])}})})
                .err,
            std::string("invalid_formation_slot"));

        REQUIRE_EQ(
            clientA
                .callRpc("formation.set",
                         {Amf3Value::makeMap({
                             {"3", Amf3Value::makeInt(active[0])},
                             {"6", Amf3Value::makeInt(active[1])},
                             {"9", Amf3Value::makeInt(active[2])},
                             {"2", Amf3Value::makeInt(active[3])},
                         })})
                .err,
            std::string("ok"));

        auto bag = clientA.callRpc("bag.bagInfo", {}).ret;
        int64_t wpnGid = 0;
        int64_t trsGid = 0;
        if (const auto* armSub = bag.get("arm")) {
            for (const auto& kv : armSub->fields) {
                if (kv.second.get("item_template_id")->asInt() == 112001) {
                    wpnGid = std::stoll(kv.first);
                }
            }
        }
        if (const auto* trsSub = bag.get("treasure")) {
            for (const auto& kv : trsSub->fields) {
                if (kv.second.get("item_template_id")->asInt() == 182001) {
                    trsGid = std::stoll(kv.first);
                }
            }
        }
        REQUIRE_TRUE(wpnGid > 0 && trsGid > 0);

        // Negative: equip slot mismatch
        REQUIRE_EQ(
            clientA
                .callRpc("formation.addArming",
                         {Amf3Value::makeInt(1), Amf3Value::makeInt(1), Amf3Value::makeInt(trsGid)})
                .err,
            std::string("equip_type_mismatch"));

        REQUIRE_EQ(
            clientA
                .callRpc("formation.addArming",
                         {Amf3Value::makeInt(1), Amf3Value::makeInt(1), Amf3Value::makeInt(wpnGid)})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("formation.addArming",
                         {Amf3Value::makeInt(1), Amf3Value::makeInt(5), Amf3Value::makeInt(trsGid)})
                .err,
            std::string("ok"));

        REQUIRE_EQ(clientA.callRpc("forge.autoReinforceArm", {Amf3Value::makeInt(1)}).err,
                   std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("forge.upgradeArm",
                         {Amf3Value::makeInt(craftedArmGid), Amf3Value::makeInt(3)})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("formation.transferArming",
                         {Amf3Value::makeInt(1), Amf3Value::makeInt(2), Amf3Value::makeInt(1)})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("formation.removeArming",
                         {Amf3Value::makeInt(1), Amf3Value::makeInt(5)})
                .err,
            std::string("ok"));

        auto insp = clientB.callRpc("formation.getOtherPositionInfo", {Amf3Value::makeInt(uidA)});
        REQUIRE_EQ(insp.err, std::string("ok"));
        REQUIRE_EQ(insp.ret.get("uname")->asString(), std::string("LongĐởmThần"));
        return true;
    });

    runCase("CrossRepo_08_TwoClient_RealTime_Multiplayer_Town_RoyalCity_And_Castle", [&]() {
        (void)clientA.drainPushes(20);
        (void)clientB.drainPushes(20);
        REQUIRE_EQ(clientA.callRpc("city.enter", {Amf3Value::makeInt(1)}).err, std::string("ok"));
        REQUIRE_EQ(clientB.callRpc("city.enter", {Amf3Value::makeInt(1)}).err, std::string("ok"));
        REQUIRE_TRUE(hasPush(clientA.drainPushes(100), "town.addPlayer"));

        REQUIRE_EQ(
            clientB.callRpc("town.move", {Amf3Value::makeInt(600), Amf3Value::makeInt(210)}).err,
            std::string("ok"));
        REQUIRE_TRUE(hasPush(clientA.drainPushes(100), "town.move"));

        REQUIRE_EQ(clientA.callRpc("castle.getInfo", {}).err, std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("castle.levelUp", {}).err, std::string("ok"));
        REQUIRE_EQ(
            clientB
                .callRpc("imperialcity.enter",
                         {Amf3Value::makeInt(300), Amf3Value::makeInt(200)})
                .err,
            std::string("ok"));
        REQUIRE_EQ(clientB.callRpc("imperialcity.leave", {}).err, std::string("ok"));
        return true;
    });

    runCase("CrossRepo_09_WorldChat_PersonalWhisper_ZlibHistory_And_GMCommands", [&]() {
        (void)clientB.drainPushes(20);
        REQUIRE_EQ(
            clientA
                .callRpc("chat.sendWorld",
                         {Amf3Value::makeInt(1),
                          Amf3Value::makeString("Kestrel C++ <-> Cobalt Rust Live!")})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("chat.sendPersonal",
                         {Amf3Value::makeString("QuanVũVIP"), Amf3Value::makeInt(1),
                          Amf3Value::makeString("Mật thư từ Kestrel!")})
                .err,
            std::string("ok"));
        REQUIRE_TRUE(hasPush(clientB.drainPushes(100), "re.chat.getMsg"));

        // Decompress Zlib-encoded chat history using kestrel-canvas LCPacket::zlibDecompress!
        auto hist = clientB.callRpc("chat.getWorldLastMsgs", {});
        REQUIRE_EQ(hist.err, std::string("ok"));
        REQUIRE_TRUE(!hist.ret.dense.empty());
        const std::string& zippedBlob = hist.ret.dense[0].strVal;
        std::string unzipped;
        REQUIRE_TRUE(gclient::net::LCPacket::zlibDecompress(
            reinterpret_cast<const uint8_t*>(zippedBlob.data()), zippedBlob.size(), unzipped));
        const Amf3Value msgRec = decodeAmf3(unzipped);
        REQUIRE_EQ(msgRec.get("message")->get("message")->asString(),
                   std::string("Kestrel C++ <-> Cobalt Rust Live!"));
        return true;
    });

    runCase("CrossRepo_10_MailBox_RewardCenter_And_GiftCode_Idempotency", [&]() {
        REQUIRE_EQ(
            clientA
                .callRpc("mail.sendMail",
                         {Amf3Value::makeInt(uidB), Amf3Value::makeString("Thư Chiến Báo"),
                          Amf3Value::makeString("Toàn quân tập kết!")})
                .err,
            std::string("ok"));
        REQUIRE_EQ(clientB.callRpc("mail.getMailBoxList", {}).err, std::string("ok"));
        REQUIRE_EQ(clientB.callRpc("mail.readAllMail", {}).err, std::string("ok"));

        auto rl = clientA.callRpc("reward.getRewardList",
                                  {Amf3Value::makeInt(0), Amf3Value::makeInt(50)});
        REQUIRE_TRUE(!rl.ret.dense.empty());
        const int64_t rid = rl.ret.dense[0].get("rid")->asInt();
        REQUIRE_EQ(
            clientA
                .callRpc("reward.receiveByRidArr",
                         {Amf3Value::makeArray({Amf3Value::makeInt(rid)})})
                .err,
            std::string("ok"));
        REQUIRE_TRUE(
            clientA
                .callRpc("reward.receiveByRidArr",
                         {Amf3Value::makeArray({Amf3Value::makeInt(rid)})})
                .err != "ok");

        REQUIRE_EQ(
            clientA.callRpc("reward.giftByCode", {Amf3Value::makeString("GSERVERVIP888")}).err,
            std::string("ok"));
        REQUIRE_TRUE(
            clientA.callRpc("reward.giftByCode", {Amf3Value::makeString("GSERVERVIP888")}).err !=
            "ok");
        return true;
    });

    runCase("CrossRepo_11_TavernRaffle_Gacha_And_Shop_PurchaseRefresh", [&]() {
        REQUIRE_EQ(clientA.callRpc("raffle.buyToken", {Amf3Value::makeInt(5)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("raffle.singleRaffle", {Amf3Value::makeInt(2)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("raffle.multiRaffle", {Amf3Value::makeInt(2)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("raffle.raffleHot", {}).err, std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("raffle.refreshHotByHand", {}).err, std::string("ok"));

        auto si = clientA.callRpc("shop.getInfo", {Amf3Value::makeInt(1)});
        REQUIRE_EQ(si.err, std::string("ok"));
        const std::string gk = si.ret.get("goods_key")->asString();
        REQUIRE_EQ(
            clientA
                .callRpc("shop.buy",
                         {Amf3Value::makeInt(1), Amf3Value::makeString(gk), Amf3Value::makeInt(1),
                          Amf3Value::makeInt(101), Amf3Value::makeInt(1)})
                .err,
            std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("shop.refresh", {Amf3Value::makeInt(1)}).err, std::string("ok"));
        return true;
    });

    runCase("CrossRepo_12_PvECopy_Attack_Pass_Sweep_And_ZlibBattleRecord", [&]() {
        auto atk = clientA.callRpc("copy.attack",
                                   {Amf3Value::makeInt(1001), Amf3Value::makeInt(100101)});
        REQUIRE_EQ(atk.err, std::string("ok"));
        const int64_t brid = atk.ret.get("brid")->asInt();

        auto rec = clientA.callRpc("battle.getRecord", {Amf3Value::makeInt(brid)});
        REQUIRE_EQ(rec.err, std::string("ok"));
        std::string rawBattle;
        REQUIRE_TRUE(gclient::net::LCPacket::zlibDecompress(
            reinterpret_cast<const uint8_t*>(rec.ret.strVal.data()), rec.ret.strVal.size(),
            rawBattle));
        const Amf3Value battleObj = decodeAmf3(rawBattle);
        REQUIRE_EQ(battleObj.get("appraisal")->asInt(), 50LL);

        REQUIRE_EQ(clientA.callRpc("battle.getRecord", {Amf3Value::makeInt(999999)}).err,
                   std::string("battle_record_not_found"));

        REQUIRE_EQ(
            clientA
                .callRpc("copy.pass",
                         {Amf3Value::makeInt(1001), Amf3Value::makeInt(100101),
                          Amf3Value::makeEmptyArray()})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientA
                .callRpc("copy.sweep",
                         {Amf3Value::makeInt(1001), Amf3Value::makeInt(100101),
                          Amf3Value::makeInt(2)})
                .err,
            std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("copy.fetchFresherReward", {}).err, std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("copy.fetchFresherReward", {}).err,
                   std::string("already_claimed"));
        return true;
    });

    runCase("CrossRepo_13_PvPArena_RankSwap_DefenderPush_Sign_And_OnlineRewards", [&]() {
        REQUIRE_EQ(clientB.callRpc("arena.enterArena", {}).err, std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("arena.enterArena", {}).err, std::string("ok"));
        (void)clientB.drainPushes(20);

        auto ch = clientA.callRpc(
            "arena.challenge",
            {Amf3Value::makeInt(17), Amf3Value::makeInt(16), Amf3Value::makeInt(0),
             Amf3Value::makeString("QuanVũVIP")});
        REQUIRE_EQ(ch.err, std::string("ok"));
        REQUIRE_EQ(ch.ret.get("position")->asInt(), 16LL);
        REQUIRE_TRUE(hasPush(clientB.drainPushes(100), "re.arena.dataRefresh"));

        REQUIRE_EQ(clientA.callRpc("arena.buyChallengeTimes", {Amf3Value::makeInt(2)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("arena.fetchChallengeNumReward", {Amf3Value::makeInt(1)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("sign.signToday", {}).err, std::string("ok"));
        REQUIRE_TRUE(clientA.callRpc("sign.signToday", {}).err != "ok");
        REQUIRE_EQ(clientA.callRpc("sign.gainVipSignReward", {Amf3Value::makeInt(1)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("sign.gainRechargeSignReward", {Amf3Value::makeInt(1)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientA.callRpc("online.fetch", {Amf3Value::makeInt(1)}).err,
                   std::string("ok"));
        return true;
    });

    runCase("CrossRepo_14_FlowA_CopyBattle_SkillIds_Stamina_Rewards_And_ReconnectPersistence",
            [&]() {
                // 1. Negative: invalid / mismatched copy stage must be strictly rejected
                REQUIRE_EQ(
                    clientA.callRpc("copy.attack", {Amf3Value::makeInt(0), Amf3Value::makeInt(0)})
                        .err,
                    std::string("invalid_copy_stage"));
                REQUIRE_EQ(
                    clientA
                        .callRpc("copy.attack",
                                 {Amf3Value::makeInt(1001), Amf3Value::makeInt(200101)})
                        .err,
                    std::string("invalid_copy_stage"));

                // 2. Snapshot pre-battle UserData, BagData, and CopyData
                auto preUser = clientA.callRpc("user.getUser", {}).ret;
                const int64_t preExec = preUser.get("execution")->asInt();
                const int64_t preExp = preUser.get("exp")->asInt();
                const int64_t preCopper = preUser.get("copper")->asInt();
                const int64_t preSoul = preUser.get("hero_soul")->asInt();
                const int64_t preGold = preUser.get("gold")->asInt();

                auto preBag = clientA.callRpc("bag.bagInfo", {}).ret;
                const int64_t pre17002 = sumBagTemplateCount(preBag, "item", 17002);
                const int64_t pre16012 = sumBagTemplateCount(preBag, "item", 16012);

                auto preList = clientA.callRpc("copy.getList", {Amf3Value::makeInt(1)});
                REQUIRE_EQ(preList.err, std::string("ok"));
                const auto* preChap = preList.ret.get("copyData")->get("1001");
                REQUIRE_TRUE(preChap != nullptr);
                REQUIRE_EQ(preChap->get("star")->asInt(), 3LL);
                REQUIRE_EQ(preChap->get("pass_strongh")->asInt(), 1LL);

                // 3. Execute copy.attack against Chapter 1001 Stronghold 100102 (`Vu Cát`)
                auto atk = clientA.callRpc("copy.attack",
                                           {Amf3Value::makeInt(1001), Amf3Value::makeInt(100102)});
                REQUIRE_EQ(atk.err, std::string("ok"));
                REQUIRE_EQ(atk.ret.get("ret")->asString(), std::string("ok"));
                const int64_t brid = atk.ret.get("brid")->asInt();
                REQUIRE_TRUE(brid > 0LL);
                REQUIRE_EQ(atk.ret.get("appraisal")->asInt(), 50LL);

                // Verify CopyProxy:groupDrops drop schema `{ copper, soul, item = { ["17002"] = 1 } }`
                const auto* drop = atk.ret.get("drop");
                REQUIRE_TRUE(drop != nullptr);
                REQUIRE_EQ(drop->get("copper")->asInt(), 2000LL);
                REQUIRE_EQ(drop->get("soul")->asInt(), 70LL);
                REQUIRE_TRUE(drop->get("item") != nullptr);
                REQUIRE_EQ(drop->get("item")->get("17002")->asInt(), 1LL);

                // Verify hero battle units carry valid configured skill IDs (`1001` normal, `2001` rage)
                const auto* bInfo = atk.ret.get("battleInfo");
                REQUIRE_TRUE(bInfo != nullptr);
                REQUIRE_EQ(bInfo->get("isPVP")->asInt(), 0LL);
                const auto* team1 = bInfo->get("arrTeam1")->get("1")->get("arrHero");
                const auto* team2 = bInfo->get("arrTeam2")->get("1")->get("arrHero");
                REQUIRE_TRUE(team1 != nullptr && !team1->fields.empty());
                REQUIRE_TRUE(team2 != nullptr && !team2->fields.empty());

                for (const auto* teamHeroMap : {team1, team2}) {
                    for (const auto& kv : teamHeroMap->fields) {
                        const auto* skills = kv.second.get("arrSkill");
                        REQUIRE_TRUE(skills != nullptr);
                        REQUIRE_EQ(skills->dense.size(), static_cast<size_t>(2));
                        REQUIRE_EQ(skills->dense[0].dense.size(), static_cast<size_t>(2));
                        REQUIRE_EQ(skills->dense[1].dense.size(), static_cast<size_t>(2));
                        const int64_t normalSkillId = skills->dense[0].dense[0].asInt();
                        const int64_t rageSkillId = skills->dense[1].dense[0].asInt();
                        REQUIRE_TRUE(normalSkillId > 0LL);
                        REQUIRE_TRUE(rageSkillId > 0LL);
                        const int64_t unitHtid = kv.second.get("htid") ? kv.second.get("htid")->asInt() : 0LL;
                        if (teamHeroMap == team1) {
                            // Verify authentic per-hero skill mapping (never broken 1201, and exact com_atk/angry_atk when A4 is active)
                            REQUIRE_TRUE(normalSkillId != 1201LL);
                            if (unitHtid == 1LL) {
                                REQUIRE_TRUE((normalSkillId == 102LL && rageSkillId == 101LL) ||
                                             (normalSkillId == 1001LL && rageSkillId == 2001LL));
                            } else if (unitHtid == 101LL) {
                                REQUIRE_TRUE((normalSkillId == 10102LL && rageSkillId == 10101LL) ||
                                             (normalSkillId == 1001LL && rageSkillId == 2001LL));
                            } else if (unitHtid == 401LL) {
                                REQUIRE_TRUE((normalSkillId == 40102LL && rageSkillId == 40101LL) ||
                                             (normalSkillId == 1001LL && rageSkillId == 2001LL));
                            } else if (unitHtid == 406LL) {
                                REQUIRE_TRUE((normalSkillId == 40602LL && rageSkillId == 40601LL) ||
                                             (normalSkillId == 1001LL && rageSkillId == 2001LL));
                            } else if (unitHtid == 426LL) {
                                REQUIRE_TRUE((normalSkillId == 42602LL && rageSkillId == 42601LL) ||
                                             (normalSkillId == 1001LL && rageSkillId == 2001LL));
                            }
                        } else {
                            REQUIRE_TRUE(unitHtid > 20000LL || normalSkillId > 0LL);
                        }
                    }
                }

                // Verify arrSeed & string-keyed userInfo Map `{"1": u1, "2": u2}` (`FightOperateLogic` & `FightProxy`)
                const auto* arrSeed = atk.ret.get("arrSeed");
                REQUIRE_TRUE(arrSeed != nullptr && !arrSeed->dense.empty());
                const auto* uInfo = atk.ret.get("userInfo");
                REQUIRE_TRUE(uInfo != nullptr && uInfo->get("1") != nullptr && uInfo->get("2") != nullptr);
                REQUIRE_EQ(uInfo->get("1")->get("uid")->asInt(), uidA);

                // Verify Zlib-compressed `fightRet` inside `copy.attack` + `battle.getRecord` parity
                const auto* fightRetBlob = atk.ret.get("fightRet");
                REQUIRE_TRUE(fightRetBlob != nullptr && !fightRetBlob->strVal.empty());
                std::string rawFightRet;
                REQUIRE_TRUE(gclient::net::LCPacket::zlibDecompress(
                    reinterpret_cast<const uint8_t*>(fightRetBlob->strVal.data()),
                    fightRetBlob->strVal.size(), rawFightRet));
                const Amf3Value fightReport = decodeAmf3(rawFightRet);
                REQUIRE_EQ(fightReport.get("brid")->asInt(), brid);
                REQUIRE_EQ(fightReport.get("appraisal")->asInt(), 50LL);
                REQUIRE_TRUE(fightReport.get("round")->asInt() >= 1LL);
                REQUIRE_TRUE(fightReport.get("heroResoultInfo") != nullptr);
                REQUIRE_TRUE(fightReport.get("statisticalDataInfo") != nullptr);
                if (const auto* rq = fightReport.get("rageQueue")) {
                    for (const auto& step : rq->dense) {
                        const int64_t rqSid = step.get("skillId")->asInt();
                        REQUIRE_TRUE(rqSid > 0LL);
                        REQUIRE_TRUE(rqSid != 1201LL);
                    }
                }

                auto rec = clientA.callRpc("battle.getRecord", {Amf3Value::makeInt(brid)});
                REQUIRE_EQ(rec.err, std::string("ok"));
                std::string rawRec;
                REQUIRE_TRUE(gclient::net::LCPacket::zlibDecompress(
                    reinterpret_cast<const uint8_t*>(rec.ret.strVal.data()),
                    rec.ret.strVal.size(), rawRec));
                REQUIRE_EQ(decodeAmf3(rawRec).get("appraisal")->asInt(), 50LL);

                // 4. Settle battle via `copy.pass` (`CopyProxy:fightEnd`) & verify pushes + state
                (void)clientA.drainPushes(20);
                auto pass = clientA.callRpc(
                    "copy.pass",
                    {Amf3Value::makeInt(1001), Amf3Value::makeInt(100102),
                     Amf3Value::makeEmptyArray()});
                REQUIRE_EQ(pass.err, std::string("ok"));
                REQUIRE_EQ(pass.ret.get("ret")->asString(), std::string("ok"));
                REQUIRE_EQ(pass.ret.get("battle_result")->asInt(), 1LL);
                REQUIRE_EQ(pass.ret.get("brid")->asInt(), brid);
                REQUIRE_EQ(pass.ret.get("star")->asInt(), 3LL);
                REQUIRE_EQ(pass.ret.get("exp")->asInt(), 2100LL);
                REQUIRE_EQ(pass.ret.get("drop")->get("copper")->asInt(), 2000LL);
                REQUIRE_EQ(pass.ret.get("drop")->get("soul")->asInt(), 70LL);
                REQUIRE_EQ(pass.ret.get("drop")->get("item")->get("17002")->asInt(), 1LL);

                auto passPushes = clientA.drainPushes(60);
                REQUIRE_TRUE(hasPush(passPushes, "user.updateUser"));
                REQUIRE_TRUE(hasPush(passPushes, "bag.update"));

                auto midUser = clientA.callRpc("user.getUser", {}).ret;
                REQUIRE_EQ(midUser.get("execution")->asInt(), preExec - 6);
                REQUIRE_TRUE(midUser.get("level")->asInt() > preUser.get("level")->asInt() ||
                             midUser.get("exp")->asInt() == preExp + 2100);
                REQUIRE_EQ(midUser.get("copper")->asInt(), preCopper + 2000);
                REQUIRE_EQ(midUser.get("hero_soul")->asInt(), preSoul + 70);

                auto midBag = clientA.callRpc("bag.bagInfo", {}).ret;
                REQUIRE_EQ(sumBagTemplateCount(midBag, "item", 17002), pre17002 + 1);

                // 5. Clear remaining Chapter 1001 strongholds (`100103`, `100105`, `100106`) per `copy.db` to unlock `1002`
                for (int64_t stg : {100103LL, 100105LL, 100106LL}) {
                    auto atkBoss = clientA.callRpc(
                        "copy.attack", {Amf3Value::makeInt(1001), Amf3Value::makeInt(stg)});
                    REQUIRE_EQ(atkBoss.err, std::string("ok"));
                    REQUIRE_EQ(atkBoss.ret.get("appraisal")->asInt(), 50LL);

                    auto passBoss = clientA.callRpc(
                        "copy.pass",
                        {Amf3Value::makeInt(1001), Amf3Value::makeInt(stg),
                         Amf3Value::makeEmptyArray()});
                    REQUIRE_EQ(passBoss.err, std::string("ok"));
                    REQUIRE_EQ(passBoss.ret.get("star")->asInt(), 3LL);
                }

                // Claim 3-star chapter chest (`copy.fetchPrize`) and verify duplicate guard
                auto prize = clientA.callRpc(
                    "copy.fetchPrize", {Amf3Value::makeInt(1001), Amf3Value::makeInt(0)});
                REQUIRE_EQ(prize.err, std::string("ok"));
                REQUIRE_EQ(prize.ret.get("prize")->asInt(), 1LL);
                REQUIRE_EQ(
                    clientA
                        .callRpc("copy.fetchPrize",
                                 {Amf3Value::makeInt(1001), Amf3Value::makeInt(0)})
                        .err,
                    std::string("prize_already_claimed"));

                // 6. Reconnect on a fresh TCP session and verify all Flow A mutations persisted!
                const auto tkReconn =
                    strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_alpha", false);
                RealKestrelWireClient reconnA;
                REQUIRE_TRUE(reconnA.connectToRelay(tcpHost, tcpPort));
                REQUIRE_EQ(
                    reconnA
                        .callRpc("user.login",
                                 {Amf3Value::makeMap({
                                     {"AMF", Amf3Value::makeInt(3)},
                                     {"pid", Amf3Value::makeString(tkReconn.pid)},
                                     {"qid", Amf3Value::makeString(tkReconn.pid)},
                                     {"hash", Amf3Value::makeString(tkReconn.hash)},
                                     {"serverID", Amf3Value::makeString("game2900161")},
                                 })})
                        .err,
                    std::string("ok"));
                REQUIRE_EQ(
                    reconnA.callRpc("user.userLogin", {Amf3Value::makeInt(uidA)}).ret.asString(),
                    std::string("ok"));

                auto recUser = reconnA.callRpc("user.getUser", {}).ret;
                REQUIRE_EQ(recUser.get("execution")->asInt(), preExec - 24);
                REQUIRE_TRUE(recUser.get("level")->asInt() >= 36LL);
                REQUIRE_TRUE(recUser.get("copper")->asInt() >= preCopper + 8000);
                REQUIRE_TRUE(recUser.get("hero_soul")->asInt() >= preSoul + 280);
                REQUIRE_EQ(recUser.get("gold")->asInt(), preGold + 100);

                auto recBag = reconnA.callRpc("bag.bagInfo", {}).ret;
                REQUIRE_EQ(sumBagTemplateCount(recBag, "item", 17002), pre17002 + 4);
                REQUIRE_EQ(sumBagTemplateCount(recBag, "item", 16012), pre16012 + 1);

                auto recList = reconnA.callRpc("copy.getList", {Amf3Value::makeInt(1)});
                REQUIRE_EQ(recList.err, std::string("ok"));
                const auto* recC1001 = recList.ret.get("copyData")->get("1001");
                REQUIRE_TRUE(recC1001 != nullptr);
                REQUIRE_EQ(recC1001->get("star")->asInt(), 15LL);
                REQUIRE_EQ(recC1001->get("pass_strongh")->asInt(), 5LL);
                REQUIRE_EQ(recC1001->get("prize")->asInt(), 1LL);
                REQUIRE_TRUE(recList.ret.get("copyData")->get("1002") != nullptr);

                auto recCopy = reconnA.callRpc("copy.getCopy", {Amf3Value::makeInt(1001)});
                REQUIRE_EQ(recCopy.err, std::string("ok"));
                REQUIRE_EQ(recCopy.ret.get("va_copy")->get("100102")->get("normal_star")->asInt(),
                           3LL);
                REQUIRE_EQ(recCopy.ret.get("va_copy")->get("100105")->get("normal_star")->asInt(),
                           3LL);

                reconnA.disconnect();
                return true;
            });

    runCase("CrossRepo_15_FlowB_ActStar_ReceiveGift_Eligibility_Bag_Dup_And_Persistence", [&]() {
        // 1. Initial `activityStarPlayOpen.getInfo` returns `{}` (`ActStarCodeData:parseData`)
        auto initInfo = clientA.callRpc("activityStarPlayOpen.getInfo", {});
        REQUIRE_EQ(initInfo.err, std::string("ok"));
        REQUIRE_TRUE(initInfo.ret.dense.empty() && initInfo.ret.fields.empty());

        // 2. (e) Reject non-existent gift IDs (`0`, `-1`, `99`) and level-locked gift tiers
        REQUIRE_EQ(
            clientA.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(0)}).err,
            std::string("invalid_gift_id"));
        REQUIRE_EQ(
            clientA.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(-1)}).err,
            std::string("invalid_gift_id"));
        REQUIRE_EQ(
            clientA.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(99)}).err,
            std::string("invalid_gift_id"));

        // Client B is Lv.10 -> Tier 3 (`req_level = 20`) must be rejected with `level_not_enough`
        REQUIRE_EQ(
            clientB.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(3)}).err,
            std::string("level_not_enough"));

        // Client A is Lv.35 -> Tier 5 (`req_level = 40`) & Tier 7 (`req_level = 60`) must fail
        REQUIRE_EQ(
            clientA.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(5)}).err,
            std::string("level_not_enough"));
        REQUIRE_EQ(
            clientA.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(7)}).err,
            std::string("level_not_enough"));

        // 3. Snapshot Client A currencies & inventory before claiming `Quà Điêu Thuyền`
        auto preUser = clientA.callRpc("user.getUser", {}).ret;
        const int64_t preGold = preUser.get("gold")->asInt();
        const int64_t preCopper = preUser.get("copper")->asInt();

        auto preBag = clientA.callRpc("bag.bagInfo", {}).ret;
        const int64_t pre10010 = sumBagTemplateCount(preBag, "item", 10010);
        const int64_t pre22202 = sumBagTemplateCount(preBag, "item", 22202);
        const int64_t pre50406 = sumBagTemplateCount(preBag, "soul", 50406);

        // 4. (a)+(b) Claim Tier 1 (`req_level = 1`) & Tier 4 (`req_level = 30`) on Lv.35 Client A
        (void)clientA.drainPushes(20);
        auto claim1 =
            clientA.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(1)});
        REQUIRE_EQ(claim1.err, std::string("ok"));
        REQUIRE_EQ(claim1.ret.get("ret")->asString(), std::string("ok"));
        REQUIRE_EQ(claim1.ret.get("id")->asInt(), 1LL);

        // Verify `GainItemListInfoPanel` / `RewardManager:addRewardsByFixTb` `[type, id, num]` schema!
        const auto* rw1 = claim1.ret.get("reward");
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

        auto pushes1 = clientA.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushes1, "user.updateUser"));
        REQUIRE_TRUE(hasPush(pushes1, "bag.update"));

        auto claim4 =
            clientA.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(4)});
        REQUIRE_EQ(claim4.err, std::string("ok"));
        REQUIRE_EQ(claim4.ret.get("id")->asInt(), 4LL);
        const auto* rw4 = claim4.ret.get("reward");
        REQUIRE_TRUE(rw4 != nullptr && rw4->dense.size() == 4);
        REQUIRE_EQ(rw4->dense[2].dense[1].asInt(), 22202LL);
        REQUIRE_EQ(rw4->dense[2].dense[2].asInt(), 3LL);
        REQUIRE_EQ(rw4->dense[3].dense[1].asInt(), 50406LL);
        REQUIRE_EQ(rw4->dense[3].dense[2].asInt(), 25LL);

        auto postUser = clientA.callRpc("user.getUser", {}).ret;
        REQUIRE_EQ(postUser.get("gold")->asInt(), preGold + 188 + 588);
        REQUIRE_EQ(postUser.get("copper")->asInt(), preCopper + 50000 + 200000);

        auto postBag = clientA.callRpc("bag.bagInfo", {}).ret;
        REQUIRE_EQ(sumBagTemplateCount(postBag, "item", 10010), pre10010 + 20);
        REQUIRE_EQ(sumBagTemplateCount(postBag, "item", 22202), pre22202 + 3);
        REQUIRE_EQ(sumBagTemplateCount(postBag, "soul", 50406), pre50406 + 35);

        // 5. (d) Reject duplicate claims of already-claimed gift IDs without double-granting!
        REQUIRE_EQ(
            clientA.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(1)}).err,
            std::string("already_claimed"));
        REQUIRE_EQ(
            clientA.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(4)}).err,
            std::string("already_claimed"));
        REQUIRE_EQ(clientA.callRpc("user.getUser", {}).ret.get("gold")->asInt(),
                   preGold + 188 + 588);

        // 6. (c) Verify claimed gift IDs persist on `getInfo` and across a fresh TCP reconnect!
        auto postInfo = clientA.callRpc("activityStarPlayOpen.getInfo", {});
        REQUIRE_EQ(postInfo.err, std::string("ok"));
        REQUIRE_TRUE(postInfo.ret.get("1") != nullptr && postInfo.ret.get("1")->boolVal);
        REQUIRE_TRUE(postInfo.ret.get("4") != nullptr && postInfo.ret.get("4")->boolVal);
        REQUIRE_TRUE(postInfo.ret.get("2") == nullptr);

        const auto tkReconn =
            strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_alpha", false);
        RealKestrelWireClient reconnStar;
        REQUIRE_TRUE(reconnStar.connectToRelay(tcpHost, tcpPort));
        REQUIRE_EQ(
            reconnStar
                .callRpc("user.login",
                         {Amf3Value::makeMap({
                             {"AMF", Amf3Value::makeInt(3)},
                             {"pid", Amf3Value::makeString(tkReconn.pid)},
                             {"qid", Amf3Value::makeString(tkReconn.pid)},
                             {"hash", Amf3Value::makeString(tkReconn.hash)},
                             {"serverID", Amf3Value::makeString("game2900161")},
                         })})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            reconnStar.callRpc("user.userLogin", {Amf3Value::makeInt(uidA)}).ret.asString(),
            std::string("ok"));

        auto recInfo = reconnStar.callRpc("activityStarPlayOpen.getInfo", {});
        REQUIRE_EQ(recInfo.err, std::string("ok"));
        REQUIRE_TRUE(recInfo.ret.get("1") != nullptr && recInfo.ret.get("1")->boolVal);
        REQUIRE_TRUE(recInfo.ret.get("4") != nullptr && recInfo.ret.get("4")->boolVal);
        REQUIRE_EQ(
            reconnStar.callRpc("activityStarPlayOpen.receiveGift", {Amf3Value::makeInt(1)}).err,
            std::string("already_claimed"));
        auto recBag = reconnStar.callRpc("bag.bagInfo", {}).ret;
        REQUIRE_EQ(sumBagTemplateCount(recBag, "soul", 50406), pre50406 + 35);

        reconnStar.disconnect();
        return true;
    });

    runCase("CrossRepo_17_AllModes_TavernRaffle_Shops_BagSell_TMNamespace_And_Dungeons", [&]() {
        const auto tkC = strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_modes_c", true);
        RealKestrelWireClient clientC;
        REQUIRE_TRUE(clientC.connectToRelay(tcpHost, tcpPort));
        REQUIRE_EQ(
            clientC
                .callRpc("user.login",
                         {Amf3Value::makeMap({
                             {"AMF", Amf3Value::makeInt(3)},
                             {"pid", Amf3Value::makeString(tkC.pid)},
                             {"qid", Amf3Value::makeString(tkC.pid)},
                             {"hash", Amf3Value::makeString(tkC.hash)},
                             {"serverID", Amf3Value::makeString("game2900161")},
                         })})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientC
                .callRpc("user.createUser",
                         {Amf3Value::makeInt(1), Amf3Value::makeString("ChiêuMộQA")})
                .err,
            std::string("ok"));
        const int64_t uidC =
            clientC.callRpc("user.getUserBeforLogin", {}).ret.get("uid")->asInt();
        REQUIRE_EQ(clientC.callRpc("user.userLogin", {Amf3Value::makeInt(uidC)}).ret.asString(),
                   std::string("ok"));
        REQUIRE_EQ(
            clientC
                .callRpc("chat.sendWorld",
                         {Amf3Value::makeInt(1), Amf3Value::makeString("/level 60")})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientC
                .callRpc("chat.sendWorld",
                         {Amf3Value::makeInt(1), Amf3Value::makeString("/gold 50000")})
                .err,
            std::string("ok"));
        (void)clientC.drainPushes(30);

        // 1. Chiêu Mộ (Tavern Raffle): verify getInfo + free Warrior singleRaffle `ret.reward` + pre-response `re.hero.new`!
        auto rInfo = clientC.callRpc("raffle.getInfo", {});
        REQUIRE_EQ(rInfo.err, std::string("ok"));
        REQUIRE_TRUE(rInfo.ret.get("raffle") != nullptr);
        REQUIRE_TRUE(rInfo.ret.get("hot_raffle") != nullptr);
        REQUIRE_TRUE(rInfo.ret.get("red_raffle") != nullptr);

        auto rOne = clientC.callRpc("raffle.singleRaffle", {Amf3Value::makeInt(1)});
        REQUIRE_EQ(rOne.err, std::string("ok"));
        const auto* rw = rOne.ret.get("reward");
        REQUIRE_TRUE(rw != nullptr && rw->dense.size() == 1);
        REQUIRE_TRUE(!rw->dense[0].fields.empty());

        auto rTen = clientC.callRpc("raffle.multiRaffle", {Amf3Value::makeInt(2)});
        REQUIRE_EQ(rTen.err, std::string("ok"));
        REQUIRE_TRUE(rTen.ret.get("reward") != nullptr &&
                     rTen.ret.get("reward")->dense.size() == 10);
        REQUIRE_TRUE(rTen.ret.get("senior_luck_num") != nullptr);

        // 2. Rebel gate + GoldShop (8) + MysteryShop (12) + VIP 0 Gift + dense-array buyCopper!
        auto reb = clientC.callRpc("rebel.getRebelInfo", {});
        REQUIRE_EQ(reb.err, std::string("ok"));
        REQUIRE_TRUE(!reb.ret.fields.empty());

        auto gs = clientC.callRpc("tmShop.getInfo", {Amf3Value::makeInt(8)});
        REQUIRE_EQ(gs.err, std::string("ok"));
        REQUIRE_EQ(
            clientC
                .callRpc("tmShop.buy",
                         {Amf3Value::makeInt(8), Amf3Value::makeString("0"), Amf3Value::makeInt(1),
                          Amf3Value::makeInt(1), Amf3Value::makeInt(1)})
                .err,
            std::string("ok"));
        auto msRef = clientC.callRpc("tmShop.refresh", {Amf3Value::makeInt(12)});
        REQUIRE_EQ(msRef.err, std::string("ok"));
        REQUIRE_TRUE(msRef.ret.get("goods_key") != nullptr);

        auto bc = clientC.callRpc("tmUser.buyCopper", {Amf3Value::makeInt(2)});
        REQUIRE_EQ(bc.err, std::string("ok"));
        REQUIRE_TRUE(!bc.ret.dense.empty());
        REQUIRE_EQ(clientC.callRpc("tmUser.buyVipGift", {Amf3Value::makeInt(0)}).ret.asString(),
                   std::string("ok"));

        // 3. Bag Sell (`tmRefinery.refinerySoul`) & Play Modes (`babeltower`, `copy_daily`, `dota`, `eatChicken`)!
        REQUIRE_EQ(
            clientC
                .callRpc("chat.sendWorld",
                         {Amf3Value::makeInt(1), Amf3Value::makeString("/item 50406 10")})
                .err,
            std::string("ok"));
        auto cBag = clientC.callRpc("tmBag.bagInfo", {}).ret;
        int64_t soulGid = 0;
        if (const auto* sSub = cBag.get("soul")) {
            for (const auto& kv : sSub->fields) {
                if (kv.second.get("item_template_id")->asInt() == 50406) {
                    soulGid = std::stoll(kv.first);
                }
            }
        }
        REQUIRE_TRUE(soulGid >= 50001LL && soulGid <= 60000LL);
        REQUIRE_EQ(
            clientC
                .callRpc("tmRefinery.refinerySoul",
                         {Amf3Value::makeArray({Amf3Value::makeInt(soulGid)})})
                .err,
            std::string("ok"));

        REQUIRE_EQ(clientC.callRpc("babeltower.getBabeltowerInfo", {}).err, std::string("ok"));
        REQUIRE_EQ(clientC.callRpc("copy_daily.getInfo", {Amf3Value::makeInt(1)}).err,
                   std::string("ok"));
        REQUIRE_EQ(clientC.callRpc("dota.attack", {Amf3Value::makeInt(1)}).err, std::string("ok"));
        REQUIRE_EQ(
            clientC.callRpc("dota.pass", {Amf3Value::makeInt(1), Amf3Value::makeBool(true)}).err,
            std::string("ok"));
        REQUIRE_EQ(clientC.callRpc("eatChicken.eat", {}).err, std::string("ok"));

        clientC.disconnect();
        return true;
    });

    runCase("CrossRepo_18_ActiveEventsAndOneClickInstantBuy", [&]() {
        const auto tkD = strictGuestHandshake(httpHost, httpPort, "kestrel_cpp_instant_buy_d", true);
        RealKestrelWireClient clientD;
        REQUIRE_TRUE(clientD.connectToRelay(tcpHost, tcpPort));
        REQUIRE_EQ(
            clientD
                .callRpc("user.login",
                         {Amf3Value::makeMap({
                             {"AMF", Amf3Value::makeInt(3)},
                             {"pid", Amf3Value::makeString(tkD.pid)},
                             {"qid", Amf3Value::makeString(tkD.pid)},
                             {"hash", Amf3Value::makeString(tkD.hash)},
                             {"serverID", Amf3Value::makeString("game2900161")},
                         })})
                .err,
            std::string("ok"));
        REQUIRE_EQ(
            clientD
                .callRpc("user.createUser",
                         {Amf3Value::makeInt(1), Amf3Value::makeString("VạnSựNhưÝ")})
                .err,
            std::string("ok"));
        const int64_t uidD =
            clientD.callRpc("user.getUserBeforLogin", {}).ret.get("uid")->asInt();
        REQUIRE_EQ(clientD.callRpc("user.userLogin", {Amf3Value::makeInt(uidD)}).ret.asString(),
                   std::string("ok"));
        REQUIRE_EQ(
            clientD
                .callRpc("chat.sendWorld",
                         {Amf3Value::makeInt(1), Amf3Value::makeString("/level 60")})
                .err,
            std::string("ok"));
        (void)clientD.drainPushes(30);

        // 1. activity.getActivityConf
        auto actConf = clientD.callRpc("activity.getActivityConf", {});
        REQUIRE_EQ(actConf.err, std::string("ok"));
        REQUIRE_TRUE(!actConf.ret.fields.empty() || !actConf.ret.dense.empty());

        // 2. dailyDiscount.getInfo & dailyDiscount.receive (0 VND free, id=1)
        auto ddInit = clientD.callRpc("dailyDiscount.getInfo", {});
        REQUIRE_EQ(ddInit.err, std::string("ok"));
        REQUIRE_TRUE(ddInit.ret.get("productBuy") != nullptr);

        auto preUser0 = clientD.callRpc("user.getUser", {}).ret;
        const int64_t gold0 = preUser0.get("gold")->asInt();
        auto preBag0 = clientD.callRpc("bag.bagInfo", {}).ret;
        const int64_t pre22102 = sumBagTemplateCount(preBag0, "item", 22102);

        auto ddFree = clientD.callRpc("dailyDiscount.receive", {Amf3Value::makeInt(1)});
        REQUIRE_EQ(ddFree.err, std::string("ok"));
        REQUIRE_TRUE(ddFree.ret.asString() == "ok" ||
                     (ddFree.ret.get("ret") != nullptr &&
                      ddFree.ret.get("ret")->asString() == "ok"));

        auto userAfterFree = clientD.callRpc("user.getUser", {}).ret;
        REQUIRE_TRUE(userAfterFree.get("gold")->asInt() >= gold0 + 20);
        auto bagAfterFree = clientD.callRpc("bag.bagInfo", {}).ret;
        REQUIRE_TRUE(sumBagTemplateCount(bagAfterFree, "item", 22102) >= pre22102 + 1);

        // Helper matching SDKUtil.pay -> net:sendMsg("pay.instantBuy", cb, payload)
        auto sendInstantBuy = [&](int64_t payId, int64_t payPrice, const std::string& payType,
                                  const std::string& productName, int64_t buyType, int64_t itemId,
                                  Amf3Value payRow = Amf3Value::makeNull()) {
            std::map<std::string, Amf3Value> m{
                {"pay_id", Amf3Value::makeInt(payId)},
                {"pay_id_str", Amf3Value::makeString(std::to_string(payId))},
                {"pay_price", Amf3Value::makeInt(payPrice)},
                {"pay_type", Amf3Value::makeString(payType)},
                {"product_name", Amf3Value::makeString(productName)},
                {"buy_type", Amf3Value::makeInt(buyType)},
                {"item_id", Amf3Value::makeInt(itemId)},
            };
            if (buyType > 0 || itemId > 0) {
                m["extra_data"] = Amf3Value::makeArray({
                    Amf3Value::makeInt(buyType),
                    Amf3Value::makeInt(itemId),
                    Amf3Value::makeInt(payId),
                });
            }
            if (payRow.kind == Amf3Value::Kind::Map) {
                m["pay_row"] = std::move(payRow);
            }
            Amf3Value mapVal;
            mapVal.kind = Amf3Value::Kind::Map;
            mapVal.fields = std::move(m);
            return clientD.callRpcRawArgs("pay.instantBuy", std::move(mapVal));
        };

        // 3a. pay.instantBuy: 5000 VND daily discount (buy_type=4, item_id=2, pay_id=1603)
        (void)clientD.drainPushes(20);
        const int64_t pre14374 = sumBagTemplateCount(bagAfterFree, "item", 14374);
        auto buy5k = sendInstantBuy(1603, 5000, "04", "Quà 5000 VND", 4, 2);
        REQUIRE_EQ(buy5k.err, std::string("ok"));
        auto pushes5k = clientD.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushes5k, "dailyDiscount.normalUpdate") ||
                     hasPush(pushes5k, "user.updateUser"));

        // 3b. pay.instantBuy: 249000 VND 8-day pre-buy (buy_type=4, item_id=5, pay_id=1606)
        auto buyPre8 = sendInstantBuy(1606, 249000, "04", "249000 VND mua 8 ngày", 4, 5);
        REQUIRE_EQ(buyPre8.err, std::string("ok"));
        auto pushesPre8 = clientD.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushesPre8, "dailyDiscount.preBuyUpdate") ||
                     hasPush(pushesPre8, "user.updateUser"));

        // Ensure >= 2 tokens of 14374 for dailyDiscount.redeem (claim pre-buy tier 3 or buy 9000 VND tier 3)
        auto bagMid = clientD.callRpc("bag.bagInfo", {}).ret;
        if (sumBagTemplateCount(bagMid, "item", 14374) < pre14374 + 2) {
            auto rec3 = clientD.callRpc("dailyDiscount.receive", {Amf3Value::makeInt(3)});
            if (rec3.err != "ok") {
                REQUIRE_EQ(sendInstantBuy(1604, 9000, "04", "Quà 9000 VND", 4, 3).err,
                           std::string("ok"));
            }
            (void)clientD.drainPushes(40);
        }

        // 3c. pay.instantBuy: Quà Ngày (buy_type=12, item_id=1, pay_id=1620)
        auto buyQuaNgay = sendInstantBuy(1620, 25000, "04", "Quà Ngày", 12, 1);
        REQUIRE_EQ(buyQuaNgay.err, std::string("ok"));
        auto pushesQN = clientD.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushesQN, "activityDailyRecharge2.update") ||
                     hasPush(pushesQN, "user.updateUser"));

        // 3d. pay.instantBuy: Tam Quốc Chí Tôn Lệnh (buy_type=8, item_id=1, pay_id=1619)
        auto buyQuarter = sendInstantBuy(1619, 249000, "04", "Tam Quốc Chí Tôn Lệnh", 8, 1);
        REQUIRE_EQ(buyQuarter.err, std::string("ok"));
        auto pushesQt = clientD.drainPushes(60);
        REQUIRE_TRUE(hasPush(pushesQt, "activityQuarter.update") ||
                     hasPush(pushesQt, "user.updateUser"));

        // 3e. pay.instantBuy: MonthCard (PayType="01", pay_id=1001)
        auto preCardUser = clientD.callRpc("user.getUser", {}).ret;
        const int64_t goldBeforeCard = preCardUser.get("gold")->asInt();
        auto buyMonthCard = sendInstantBuy(
            1001, 109000, "01", "Thẻ Tháng", 0, 0,
            Amf3Value::makeMap({
                {"id", Amf3Value::makeInt(1001)},
                {"recharge_type", Amf3Value::makeInt(2)},
                {"consume_money", Amf3Value::makeInt(109000)},
                {"Stall", Amf3Value::makeInt(30)},
                {"days", Amf3Value::makeInt(30)},
                {"vip_exp", Amf3Value::makeInt(300)},
                {"base_reward", Amf3Value::makeInt(300)},
                {"daily_reward", Amf3Value::makeInt(100)},
            }));
        REQUIRE_EQ(buyMonthCard.err, std::string("ok"));
        (void)clientD.drainPushes(40);

        // 3f. pay.instantBuy: Gold (PayType="00", pay_id=1004)
        auto buyGold = sendInstantBuy(
            1004, 25000, "00", "60 Nguyên Bảo", 0, 0,
            Amf3Value::makeMap({
                {"id", Amf3Value::makeInt(1004)},
                {"recharge_type", Amf3Value::makeInt(1)},
                {"consume_money", Amf3Value::makeInt(25000)},
                {"Stall", Amf3Value::makeInt(6)},
                {"days", Amf3Value::makeInt(0)},
                {"vip_exp", Amf3Value::makeInt(60)},
                {"base_reward", Amf3Value::makeInt(60)},
                {"first_reward", Amf3Value::makeInt(60)},
                {"general_reward", Amf3Value::makeInt(0)},
            }));
        REQUIRE_EQ(buyGold.err, std::string("ok"));
        (void)clientD.drainPushes(40);
        auto postGoldUser = clientD.callRpc("user.getUser", {}).ret;
        REQUIRE_TRUE(postGoldUser.get("gold")->asInt() > goldBeforeCard);

        // 4. dailyDiscount.redeem (shop id=15: 2x 14374 -> 1x 28623)
        auto preRedeemBag = clientD.callRpc("bag.bagInfo", {}).ret;
        const int64_t pre28623 = sumBagTemplateCount(preRedeemBag, "item", 28623);
        auto redeemRes =
            clientD.callRpc("dailyDiscount.redeem", {Amf3Value::makeInt(15), Amf3Value::makeInt(1)});
        REQUIRE_EQ(redeemRes.err, std::string("ok"));
        (void)clientD.drainPushes(40);
        auto postRedeemBag = clientD.callRpc("bag.bagInfo", {}).ret;
        REQUIRE_TRUE(sumBagTemplateCount(postRedeemBag, "item", 28623) >= pre28623 + 1);

        // 5. dailyDiscount.recRechargeReward (point id=1: 300 points -> 1x 21079)
        const int64_t pre21079 = sumBagTemplateCount(postRedeemBag, "item", 21079);
        auto recPtRes =
            clientD.callRpc("dailyDiscount.recRechargeReward", {Amf3Value::makeInt(1)});
        REQUIRE_EQ(recPtRes.err, std::string("ok"));
        (void)clientD.drainPushes(40);
        auto postPtBag = clientD.callRpc("bag.bagInfo", {}).ret;
        REQUIRE_TRUE(sumBagTemplateCount(postPtBag, "item", 21079) >= pre21079 + 1);

        // 6. firstGift.receiveReward (tier 1: 60 gold -> 1x 27501)
        const int64_t pre27501 = sumBagTemplateCount(postPtBag, "item", 27501);
        auto firstGiftRes =
            clientD.callRpc("firstGift.receiveReward", {Amf3Value::makeInt(1)});
        REQUIRE_EQ(firstGiftRes.err, std::string("ok"));
        (void)clientD.drainPushes(40);
        auto postFirstBag = clientD.callRpc("bag.bagInfo", {}).ret;
        REQUIRE_TRUE(sumBagTemplateCount(postFirstBag, "item", 27501) >= pre27501 + 1);

        clientD.disconnect();
        return true;
    });

    clientA.disconnect();
    clientB.disconnect();
    gclient::net::CNetwork::destroySharedNetwork();

    std::printf("\n=== Summary: %d passed, %d failed (live strict cross-repo mode) ===\n",
                g_passed, g_failed);
    return (g_failed == 0) ? 0 : 1;
}
