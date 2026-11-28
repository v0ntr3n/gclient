#pragma once
// Header-only C++20 wire-compatible AMF3 AST & binary encoder/decoder shared across C++ wire suites and Amf3Module.cpp.

#include "common/KestrelBinaryReader.h"

#include <algorithm>
#include <bit>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gclient::amf3 {

constexpr uint8_t kMarkerUndefined = 0x00;
constexpr uint8_t kMarkerNull      = 0x01;
constexpr uint8_t kMarkerFalse     = 0x02;
constexpr uint8_t kMarkerTrue      = 0x03;
constexpr uint8_t kMarkerInteger   = 0x04;
constexpr uint8_t kMarkerDouble    = 0x05;
constexpr uint8_t kMarkerString    = 0x06;
constexpr uint8_t kMarkerXmlDoc    = 0x07;
constexpr uint8_t kMarkerDate      = 0x08;
constexpr uint8_t kMarkerArray     = 0x09;
constexpr uint8_t kMarkerObject    = 0x0A;
constexpr uint8_t kMarkerXml       = 0x0B;
constexpr uint8_t kMarkerByteArray = 0x0C;

constexpr int32_t kIntMin = -268435456;
constexpr int32_t kIntMax =  268435455;
constexpr int kMaxRecursionDepth = 64;

inline void appendU29(std::string& out, uint32_t v) {
    v &= 0x1FFFFFFFu;
    if (v < 0x80u) {
        out.push_back(static_cast<char>(v));
    } else if (v < 0x4000u) {
        out.push_back(static_cast<char>(((v >> 7) & 0x7Fu) | 0x80u));
        out.push_back(static_cast<char>(v & 0x7Fu));
    } else if (v < 0x200000u) {
        out.push_back(static_cast<char>(((v >> 14) & 0x7Fu) | 0x80u));
        out.push_back(static_cast<char>(((v >> 7) & 0x7Fu) | 0x80u));
        out.push_back(static_cast<char>(v & 0x7Fu));
    } else {
        out.push_back(static_cast<char>(((v >> 22) & 0x7Fu) | 0x80u));
        out.push_back(static_cast<char>(((v >> 15) & 0x7Fu) | 0x80u));
        out.push_back(static_cast<char>(((v >> 8) & 0x7Fu) | 0x80u));
        out.push_back(static_cast<char>(v & 0xFFu));
    }
}

inline void appendDoubleBE(std::string& out, double d) {
    uint8_t buf[8];
    gclient::common::writeBE<uint64_t>(buf, std::bit_cast<uint64_t>(d));
    out.append(reinterpret_cast<const char*>(buf), 8);
}

inline bool readU29Checked(const uint8_t* data, size_t size, size_t& pos, uint32_t& out) noexcept {
    uint32_t acc = 0;
    for (int i = 0; i < 4; ++i) {
        if (pos >= size) return false;
        const uint8_t b = data[pos++];
        if (i < 3) {
            acc = (acc << 7) | static_cast<uint32_t>(b & 0x7Fu);
            if ((b & 0x80u) == 0) {
                out = acc;
                return true;
            }
        } else {
            acc = (acc << 8) | static_cast<uint32_t>(b);
            out = acc;
            return true;
        }
    }
    return false;
}

inline bool readDoubleBEChecked(const uint8_t* data, size_t size, size_t& pos, double& out) noexcept {
    if (pos + 8 > size) return false;
    const uint64_t bits = gclient::common::readBE<uint64_t>(data + pos);
    pos += 8;
    out = std::bit_cast<double>(bits);
    return true;
}

struct Amf3Value {
    enum class Kind { Undefined, Null, Bool, Int, Double, String, Array, Map };

    Kind kind = Kind::Null;
    bool boolVal = false;
    int64_t intVal = 0;
    double doubleVal = 0.0;
    std::string strVal;
    std::vector<Amf3Value> dense;
    std::map<std::string, Amf3Value> fields;

    static Amf3Value makeNull() { return Amf3Value{}; }
    static Amf3Value makeBool(bool b) { Amf3Value v; v.kind = Kind::Bool; v.boolVal = b; return v; }
    static Amf3Value makeInt(int64_t n) {
        Amf3Value v;
        if (n >= kIntMin && n <= kIntMax) { v.kind = Kind::Int; v.intVal = n; }
        else { v.kind = Kind::Double; v.doubleVal = static_cast<double>(n); }
        return v;
    }
    static Amf3Value makeDouble(double d) { Amf3Value v; v.kind = Kind::Double; v.doubleVal = d; return v; }
    static Amf3Value makeString(std::string s) { Amf3Value v; v.kind = Kind::String; v.strVal = std::move(s); return v; }
    static Amf3Value makeArray(std::vector<Amf3Value> items) { Amf3Value v; v.kind = Kind::Array; v.dense = std::move(items); return v; }
    static Amf3Value makeEmptyArray() { return makeArray({}); }
    static Amf3Value makeMap(std::initializer_list<std::pair<const std::string, Amf3Value>> init) {
        Amf3Value v; v.kind = Kind::Map; v.fields = std::map<std::string, Amf3Value>(init.begin(), init.end()); return v;
    }

    const Amf3Value* get(const std::string& key) const {
        if (kind == Kind::Map || kind == Kind::Array) {
            auto it = fields.find(key);
            if (it != fields.end()) return &it->second;
            if (kind == Kind::Array && !key.empty() &&
                std::all_of(key.begin(), key.end(), [](unsigned char c) { return std::isdigit(c); })) {
                const size_t luaIdx = static_cast<size_t>(std::stoull(key));
                if (luaIdx >= 1 && luaIdx <= dense.size()) return &dense[luaIdx - 1];
            }
        }
        return nullptr;
    }

    int64_t asInt(int64_t fallback = 0) const {
        if (kind == Kind::Int) return intVal;
        if (kind == Kind::Double) return static_cast<int64_t>(doubleVal);
        if (kind == Kind::String) {
            try { return std::stoll(strVal); } catch (...) { return fallback; }
        }
        return fallback;
    }

    std::string asString() const {
        if (kind == Kind::String) return strVal;
        if (kind == Kind::Int) return std::to_string(intVal);
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

    void writeStringBody(const std::string& s) {
        if (s.empty()) {
            appendU29(out_, 1u);
            return;
        }
        auto it = strRefs_.find(s);
        if (it != strRefs_.end()) {
            appendU29(out_, it->second << 1);
            return;
        }
        const uint32_t idx = static_cast<uint32_t>(strRefs_.size());
        strRefs_.emplace(s, idx);
        appendU29(out_, (static_cast<uint32_t>(s.size()) << 1) | 1u);
        out_.append(s);
    }

    void writeValue(const Amf3Value& v) {
        switch (v.kind) {
            case Amf3Value::Kind::Undefined: out_.push_back(static_cast<char>(kMarkerUndefined)); break;
            case Amf3Value::Kind::Null:      out_.push_back(static_cast<char>(kMarkerNull)); break;
            case Amf3Value::Kind::Bool:      out_.push_back(static_cast<char>(v.boolVal ? kMarkerTrue : kMarkerFalse)); break;
            case Amf3Value::Kind::Int:
                if (v.intVal >= kIntMin && v.intVal <= kIntMax) {
                    out_.push_back(static_cast<char>(kMarkerInteger));
                    appendU29(out_, static_cast<uint32_t>(v.intVal) & 0x1FFFFFFFu);
                } else {
                    out_.push_back(static_cast<char>(kMarkerDouble));
                    appendDoubleBE(out_, static_cast<double>(v.intVal));
                }
                break;
            case Amf3Value::Kind::Double:
                out_.push_back(static_cast<char>(kMarkerDouble));
                appendDoubleBE(out_, v.doubleVal);
                break;
            case Amf3Value::Kind::String:
                out_.push_back(static_cast<char>(kMarkerString));
                writeStringBody(v.strVal);
                break;
            case Amf3Value::Kind::Array:
                out_.push_back(static_cast<char>(kMarkerArray));
                appendU29(out_, (static_cast<uint32_t>(v.dense.size()) << 1) | 1u);
                for (const auto& [k, fv] : v.fields) {
                    writeStringBody(k);
                    writeValue(fv);
                }
                writeStringBody("");
                for (const auto& item : v.dense) writeValue(item);
                break;
            case Amf3Value::Kind::Map:
                out_.push_back(static_cast<char>(kMarkerObject));
                appendU29(out_, 0x0Bu);
                writeStringBody("");
                for (const auto& [k, fv] : v.fields) {
                    writeStringBody(k);
                    writeValue(fv);
                }
                writeStringBody("");
                break;
        }
    }
};

class Amf3Decoder {
public:
    explicit Amf3Decoder(std::string_view buf)
        : data_(reinterpret_cast<const uint8_t*>(buf.data())), size_(buf.size()) {}

    Amf3Value decode() { return readValue(0); }
    size_t offset() const noexcept { return pos_; }
    bool eof() const noexcept { return pos_ >= size_; }

private:
    struct TraitDef {
        bool dynamic = false;
        std::vector<std::string> sealedNames;
    };

    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    size_t pos_ = 0;
    std::vector<std::string> strRefs_;
    std::vector<Amf3Value> objRefs_;
    std::vector<TraitDef> traitRefs_;

    uint8_t readU8() {
        if (pos_ >= size_) throw std::runtime_error("AMF3 unexpected EOF");
        return data_[pos_++];
    }

    uint32_t readU29() {
        uint32_t v = 0;
        if (!readU29Checked(data_, size_, pos_, v)) throw std::runtime_error("AMF3 truncated U29");
        return v;
    }

    double readDouble() {
        double d = 0.0;
        if (!readDoubleBEChecked(data_, size_, pos_, d)) throw std::runtime_error("AMF3 truncated double");
        return d;
    }

    std::string readBytes(size_t n) {
        if (pos_ + n > size_) throw std::runtime_error("AMF3 truncated bytes");
        std::string s(reinterpret_cast<const char*>(data_ + pos_), n);
        pos_ += n;
        return s;
    }

    std::string readAmfString() {
        const uint32_t header = readU29();
        if ((header & 1u) == 0) {
            const size_t idx = header >> 1;
            if (idx >= strRefs_.size()) throw std::runtime_error("AMF3 invalid string ref");
            return strRefs_[idx];
        }
        const size_t len = header >> 1;
        if (len == 0) return {};
        std::string s = readBytes(len);
        strRefs_.push_back(s);
        return s;
    }

    Amf3Value readValue(int depth) {
        if (depth > kMaxRecursionDepth) throw std::runtime_error("AMF3 max recursion depth exceeded");
        const uint8_t marker = readU8();
        switch (marker) {
            case kMarkerUndefined: { Amf3Value v; v.kind = Amf3Value::Kind::Undefined; return v; }
            case kMarkerNull:      return Amf3Value::makeNull();
            case kMarkerFalse:     return Amf3Value::makeBool(false);
            case kMarkerTrue:      return Amf3Value::makeBool(true);
            case kMarkerInteger: {
                uint32_t u = readU29();
                int32_t signedVal = (u & 0x10000000u) ? static_cast<int32_t>(u | 0xE0000000u) : static_cast<int32_t>(u);
                return Amf3Value::makeInt(signedVal);
            }
            case kMarkerDouble: return Amf3Value::makeDouble(readDouble());
            case kMarkerString: return Amf3Value::makeString(readAmfString());
            case kMarkerDate: {
                const uint32_t h = readU29();
                if ((h & 1u) == 0) {
                    const size_t idx = h >> 1;
                    if (idx >= objRefs_.size()) throw std::runtime_error("AMF3 invalid date ref");
                    return objRefs_[idx];
                }
                Amf3Value v = Amf3Value::makeDouble(readDouble());
                objRefs_.push_back(v);
                return v;
            }
            case kMarkerByteArray:
            case kMarkerXmlDoc:
            case kMarkerXml: {
                const uint32_t h = readU29();
                if ((h & 1u) == 0) {
                    const size_t idx = h >> 1;
                    if (idx >= objRefs_.size()) throw std::runtime_error("AMF3 invalid byte ref");
                    return objRefs_[idx];
                }
                Amf3Value v = Amf3Value::makeString(readBytes(h >> 1));
                objRefs_.push_back(v);
                return v;
            }
            case kMarkerArray: {
                const uint32_t h = readU29();
                if ((h & 1u) == 0) {
                    const size_t idx = h >> 1;
                    if (idx >= objRefs_.size()) throw std::runtime_error("AMF3 invalid array ref");
                    return objRefs_[idx];
                }
                const size_t denseCount = h >> 1;
                const size_t slot = objRefs_.size();
                objRefs_.push_back(Amf3Value::makeEmptyArray());
                Amf3Value arr;
                arr.kind = Amf3Value::Kind::Array;
                while (true) {
                    std::string k = readAmfString();
                    if (k.empty()) break;
                    arr.fields[k] = readValue(depth + 1);
                }
                arr.dense.reserve(std::min<size_t>(denseCount, 65536));
                for (size_t i = 0; i < denseCount; ++i) {
                    arr.dense.push_back(readValue(depth + 1));
                }
                if (denseCount == 0 && !arr.fields.empty()) arr.kind = Amf3Value::Kind::Map;
                objRefs_[slot] = arr;
                return arr;
            }
            case kMarkerObject: {
                const uint32_t h = readU29();
                if ((h & 1u) == 0) {
                    const size_t idx = h >> 1;
                    if (idx >= objRefs_.size()) throw std::runtime_error("AMF3 invalid object ref");
                    return objRefs_[idx];
                }
                TraitDef trait{};
                if ((h & 2u) == 0) {
                    const size_t tidx = h >> 2;
                    if (tidx >= traitRefs_.size()) throw std::runtime_error("AMF3 invalid trait ref");
                    trait = traitRefs_[tidx];
                } else {
                    if ((h & 4u) != 0) throw std::runtime_error("AMF3 externalizable unsupported");
                    trait.dynamic = ((h & 8u) != 0);
                    const size_t count = h >> 4;
                    (void)readAmfString();
                    trait.sealedNames.reserve(std::min<size_t>(count, 4096));
                    for (size_t i = 0; i < count; ++i) trait.sealedNames.push_back(readAmfString());
                    traitRefs_.push_back(trait);
                }
                const size_t slot = objRefs_.size();
                objRefs_.push_back(Amf3Value::makeNull());
                Amf3Value obj;
                obj.kind = Amf3Value::Kind::Map;
                for (const auto& name : trait.sealedNames) {
                    obj.fields[name] = readValue(depth + 1);
                }
                if (trait.dynamic) {
                    while (true) {
                        std::string k = readAmfString();
                        if (k.empty()) break;
                        obj.fields[k] = readValue(depth + 1);
                    }
                }
                objRefs_[slot] = obj;
                return obj;
            }
            default:
                throw std::runtime_error("AMF3 unknown marker");
        }
    }
};

} // namespace gclient::amf3
