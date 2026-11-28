#pragma once
// Header-only C++20 zero-dependency RFC 8259 JSON parser, string escaper, typed extractors, and object builder.

#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace gclient::json {

inline std::string escapeString(std::string_view s) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20u) {
                    out += "\\u00";
                    out.push_back(kHex[(c >> 4) & 0x0Fu]);
                    out.push_back(kHex[c & 0x0Fu]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

struct JsonValue {
    enum class Type { Null, Bool, Int, Double, String, Array, Object };

    Type type = Type::Null;
    bool boolVal = false;
    int64_t intVal = 0;
    double doubleVal = 0.0;
    std::string strVal;
    std::vector<JsonValue> arrVal;
    std::map<std::string, JsonValue> objVal;

    bool isNull() const noexcept { return type == Type::Null; }
    bool isBool() const noexcept { return type == Type::Bool; }
    bool isNumber() const noexcept { return type == Type::Int || type == Type::Double; }
    bool isString() const noexcept { return type == Type::String; }
    bool isArray() const noexcept { return type == Type::Array; }
    bool isObject() const noexcept { return type == Type::Object; }

    const JsonValue* find(std::string_view key) const {
        if (type != Type::Object) return nullptr;
        auto it = objVal.find(std::string(key));
        return (it != objVal.end()) ? &it->second : nullptr;
    }

    std::string asString(std::string_view fallback = {}) const {
        if (type == Type::String) return strVal;
        if (type == Type::Int) return std::to_string(intVal);
        if (type == Type::Bool) return boolVal ? "true" : "false";
        return std::string(fallback);
    }

    int64_t asInt64(int64_t fallback = 0) const {
        if (type == Type::Int) return intVal;
        if (type == Type::Double) return static_cast<int64_t>(doubleVal);
        if (type == Type::String) {
            char* endp = nullptr;
            long long v = std::strtoll(strVal.c_str(), &endp, 10);
            if (endp && endp != strVal.c_str() && *endp == '\0') return static_cast<int64_t>(v);
        }
        return fallback;
    }

    bool asBool(bool fallback = false) const {
        if (type == Type::Bool) return boolVal;
        if (type == Type::Int) return intVal != 0;
        if (type == Type::String) return strVal == "true" || strVal == "1";
        return fallback;
    }

    std::string dump() const {
        switch (type) {
            case Type::Null: return "null";
            case Type::Bool: return boolVal ? "true" : "false";
            case Type::Int:  return std::to_string(intVal);
            case Type::Double: {
                if (!std::isfinite(doubleVal)) return "null";
                char buf[64];
                std::snprintf(buf, sizeof(buf), "%.15g", doubleVal);
                return buf;
            }
            case Type::String: return "\"" + escapeString(strVal) + "\"";
            case Type::Array: {
                std::string s = "[";
                for (size_t i = 0; i < arrVal.size(); ++i) {
                    if (i > 0) s.push_back(',');
                    s += arrVal[i].dump();
                }
                s.push_back(']');
                return s;
            }
            case Type::Object: {
                std::string s = "{";
                bool first = true;
                for (const auto& [k, v] : objVal) {
                    if (!first) s.push_back(',');
                    first = false;
                    s.push_back('"');
                    s += escapeString(k);
                    s += "\":";
                    s += v.dump();
                }
                s.push_back('}');
                return s;
            }
        }
        return "null";
    }
};

namespace detail {

inline void appendUtf8Codepoint(std::string& out, uint32_t cp) {
    if (cp <= 0x7Fu) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FFu) {
        out.push_back(static_cast<char>(0xC0u | ((cp >> 6) & 0x1Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else if (cp <= 0xFFFFu) {
        out.push_back(static_cast<char>(0xE0u | ((cp >> 12) & 0x0Fu)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else if (cp <= 0x10FFFFu) {
        out.push_back(static_cast<char>(0xF0u | ((cp >> 18) & 0x07u)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    }
}

class Parser {
public:
    explicit Parser(std::string_view src) : s_(src) {}

    bool parseRoot(JsonValue& out, std::string* err) {
        skipWs();
        if (!parseValue(out, 0)) {
            if (err) *err = err_.empty() ? "invalid JSON" : err_;
            return false;
        }
        skipWs();
        if (pos_ != s_.size()) {
            if (err) *err = "trailing characters after JSON value";
            return false;
        }
        return true;
    }

private:
    std::string_view s_;
    size_t pos_ = 0;
    std::string err_;

    void skipWs() {
        while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\r' || s_[pos_] == '\n')) {
            ++pos_;
        }
    }

    bool parseHex4(uint32_t& out) {
        if (pos_ + 4 > s_.size()) return false;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned char c = static_cast<unsigned char>(s_[pos_++]);
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (c - '0');
            else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
            else return false;
        }
        out = v;
        return true;
    }

    bool parseStringRaw(std::string& out) {
        if (pos_ >= s_.size() || s_[pos_] != '"') return false;
        ++pos_;
        out.clear();
        while (pos_ < s_.size()) {
            char c = s_[pos_++];
            if (c == '"') return true;
            if (static_cast<unsigned char>(c) < 0x20u) return false;
            if (c == '\\') {
                if (pos_ >= s_.size()) return false;
                char esc = s_[pos_++];
                switch (esc) {
                    case '"':  out.push_back('"');  break;
                    case '\\': out.push_back('\\'); break;
                    case '/':  out.push_back('/');  break;
                    case 'b':  out.push_back('\b'); break;
                    case 'f':  out.push_back('\f'); break;
                    case 'n':  out.push_back('\n'); break;
                    case 'r':  out.push_back('\r'); break;
                    case 't':  out.push_back('\t'); break;
                    case 'u': {
                        uint32_t cp = 0;
                        if (!parseHex4(cp)) return false;
                        if (cp >= 0xD800u && cp <= 0xDBFFu && pos_ + 6 <= s_.size() &&
                            s_[pos_] == '\\' && s_[pos_ + 1] == 'u') {
                            pos_ += 2;
                            uint32_t lo = 0;
                            if (!parseHex4(lo) || lo < 0xDC00u || lo > 0xDFFFu) return false;
                            cp = 0x10000u + (((cp - 0xD800u) << 10) | (lo - 0xDC00u));
                        }
                        appendUtf8Codepoint(out, cp);
                        break;
                    }
                    default: return false;
                }
            } else {
                out.push_back(c);
            }
        }
        return false;
    }

    bool parseNumber(JsonValue& out) {
        const size_t start = pos_;
        if (pos_ < s_.size() && s_[pos_] == '-') ++pos_;
        if (pos_ >= s_.size() || !std::isdigit(static_cast<unsigned char>(s_[pos_]))) return false;
        if (s_[pos_] == '0') {
            ++pos_;
        } else {
            while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
        }
        bool isFloat = false;
        if (pos_ < s_.size() && s_[pos_] == '.') {
            isFloat = true;
            ++pos_;
            if (pos_ >= s_.size() || !std::isdigit(static_cast<unsigned char>(s_[pos_]))) return false;
            while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
        }
        if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            isFloat = true;
            ++pos_;
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
            if (pos_ >= s_.size() || !std::isdigit(static_cast<unsigned char>(s_[pos_]))) return false;
            while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
        }
        const std::string token(s_.substr(start, pos_ - start));
        if (!isFloat) {
            char* endp = nullptr;
            errno = 0;
            long long iv = std::strtoll(token.c_str(), &endp, 10);
            if (errno == 0 && endp && *endp == '\0') {
                out = JsonValue{};
                out.type = JsonValue::Type::Int;
                out.intVal = static_cast<int64_t>(iv);
                return true;
            }
        }
        char* endp = nullptr;
        double dv = std::strtod(token.c_str(), &endp);
        if (!endp || *endp != '\0' || !std::isfinite(dv)) return false;
        out = JsonValue{};
        out.type = JsonValue::Type::Double;
        out.doubleVal = dv;
        return true;
    }

    bool parseValue(JsonValue& out, int depth) {
        if (depth > 64) { err_ = "JSON max depth exceeded"; return false; }
        skipWs();
        if (pos_ >= s_.size()) return false;
        const char c = s_[pos_];
        if (c == '"') {
            out = JsonValue{};
            out.type = JsonValue::Type::String;
            return parseStringRaw(out.strVal);
        }
        if (c == '{') {
            ++pos_;
            out = JsonValue{};
            out.type = JsonValue::Type::Object;
            skipWs();
            if (pos_ < s_.size() && s_[pos_] == '}') { ++pos_; return true; }
            while (pos_ < s_.size()) {
                skipWs();
                std::string key;
                if (!parseStringRaw(key)) return false;
                skipWs();
                if (pos_ >= s_.size() || s_[pos_] != ':') return false;
                ++pos_;
                JsonValue val;
                if (!parseValue(val, depth + 1)) return false;
                out.objVal[std::move(key)] = std::move(val);
                skipWs();
                if (pos_ < s_.size() && s_[pos_] == ',') { ++pos_; continue; }
                if (pos_ < s_.size() && s_[pos_] == '}') { ++pos_; return true; }
                return false;
            }
            return false;
        }
        if (c == '[') {
            ++pos_;
            out = JsonValue{};
            out.type = JsonValue::Type::Array;
            skipWs();
            if (pos_ < s_.size() && s_[pos_] == ']') { ++pos_; return true; }
            while (pos_ < s_.size()) {
                JsonValue elem;
                if (!parseValue(elem, depth + 1)) return false;
                out.arrVal.push_back(std::move(elem));
                skipWs();
                if (pos_ < s_.size() && s_[pos_] == ',') { ++pos_; continue; }
                if (pos_ < s_.size() && s_[pos_] == ']') { ++pos_; return true; }
                return false;
            }
            return false;
        }
        if (s_.substr(pos_, 4) == "true") {
            pos_ += 4; out = JsonValue{}; out.type = JsonValue::Type::Bool; out.boolVal = true; return true;
        }
        if (s_.substr(pos_, 5) == "false") {
            pos_ += 5; out = JsonValue{}; out.type = JsonValue::Type::Bool; out.boolVal = false; return true;
        }
        if (s_.substr(pos_, 4) == "null") {
            pos_ += 4; out = JsonValue{}; return true;
        }
        return parseNumber(out);
    }
};

} // namespace detail

inline bool parse(std::string_view jsonText, JsonValue& out, std::string* err = nullptr) {
    detail::Parser p(jsonText);
    return p.parseRoot(out, err);
}

inline bool extractString(std::string_view jsonText, std::string_view key, std::string& out) {
    JsonValue root;
    if (parse(jsonText, root) && root.isObject()) {
        if (const auto* v = root.find(key)) {
            if (v->isString() || v->isNumber() || v->isBool()) {
                out = v->asString();
                return true;
            }
        }
    }
    return false;
}

inline std::string extractStringOr(std::string_view jsonText, std::string_view key, std::string_view fallback = {}) {
    std::string out;
    return extractString(jsonText, key, out) ? out : std::string(fallback);
}

inline bool extractUint32(std::string_view jsonText, std::string_view key, uint32_t& out) {
    JsonValue root;
    if (parse(jsonText, root) && root.isObject()) {
        if (const auto* v = root.find(key)) {
            const int64_t n = v->asInt64(-1);
            if (n >= 0 && n <= static_cast<int64_t>(UINT32_MAX)) {
                out = static_cast<uint32_t>(n);
                return true;
            }
        }
    }
    return false;
}

class JsonObjectBuilder {
public:
    JsonObjectBuilder() : buf_("{") {}

    JsonObjectBuilder& kv(std::string_view k, std::string_view v) {
        sep();
        buf_.push_back('"'); buf_ += escapeString(k); buf_ += "\":\""; buf_ += escapeString(v); buf_.push_back('"');
        return *this;
    }

    JsonObjectBuilder& kvInt(std::string_view k, int64_t v) {
        sep();
        buf_.push_back('"'); buf_ += escapeString(k); buf_ += "\":"; buf_ += std::to_string(v);
        return *this;
    }

    JsonObjectBuilder& kvBool(std::string_view k, bool v) {
        sep();
        buf_.push_back('"'); buf_ += escapeString(k); buf_ += "\":"; buf_ += (v ? "true" : "false");
        return *this;
    }

    JsonObjectBuilder& kvRaw(std::string_view k, std::string_view rawJson) {
        sep();
        buf_.push_back('"'); buf_ += escapeString(k); buf_ += "\":"; buf_ += rawJson;
        return *this;
    }

    std::string finish() const {
        return buf_ + "}";
    }

private:
    std::string buf_;
    bool hasField_ = false;
    void sep() {
        if (hasField_) buf_.push_back(',');
        hasField_ = true;
    }
};

} // namespace gclient::json
