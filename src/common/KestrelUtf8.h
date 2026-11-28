#pragma once
// Header-only C++20 Win32/POSIX UTF-8 <-> UTF-16 path conversion, environment readers, URL codecs, and MAPI signing.

#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"

#include <cstdlib>
#include <filesystem>
#include <initializer_list>
#include <map>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace gclient::utf8 {

#ifdef _WIN32
inline std::wstring utf8ToWide(std::string_view utf8) {
    if (utf8.empty()) return {};
    int req = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (req <= 0) {
        flags = 0;
        req = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    }
    if (req <= 0) return {};
    std::wstring wide(static_cast<size_t>(req), L'\0');
    ::MultiByteToWideChar(CP_UTF8, flags, utf8.data(), static_cast<int>(utf8.size()), wide.data(), req);
    return wide;
}

inline std::string wideToUtf8(std::wstring_view wide) {
    if (wide.empty()) return {};
    int req = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (req <= 0) return {};
    std::string utf8(static_cast<size_t>(req), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(), req, nullptr, nullptr);
    return utf8;
}

inline std::filesystem::path utf8ToFsPath(std::string_view utf8) {
    return std::filesystem::path(utf8ToWide(utf8));
}

inline std::string fsPathToUtf8(const std::filesystem::path& p) {
    return wideToUtf8(p.wstring());
}

inline std::string readEnvUtf8(const char* name) {
    if (!name || !*name) return {};
    const std::wstring wName = utf8ToWide(name);
    DWORD needed = ::GetEnvironmentVariableW(wName.c_str(), nullptr, 0);
    if (needed == 0) return {};
    std::wstring buf(static_cast<size_t>(needed), L'\0');
    DWORD written = ::GetEnvironmentVariableW(wName.c_str(), buf.data(), needed);
    if (written == 0 || written >= needed) return {};
    buf.resize(static_cast<size_t>(written));
    return gclient::common::trimCopy(wideToUtf8(buf));
}
#else
inline std::filesystem::path utf8ToFsPath(std::string_view utf8) {
    return std::filesystem::path(utf8);
}

inline std::string fsPathToUtf8(const std::filesystem::path& p) {
    return p.string();
}

inline std::string readEnvUtf8(const char* name) {
    if (!name || !*name) return {};
    const char* v = std::getenv(name);
    return v ? gclient::common::trimCopy(v) : std::string{};
}
#endif

inline std::string firstNonEmptyEnv(std::initializer_list<const char*> names) {
    for (const char* n : names) {
        std::string v = readEnvUtf8(n);
        if (!v.empty()) return v;
    }
    return {};
}

constexpr bool parseEnvBool(std::string_view raw, bool defaultVal = false) noexcept {
    const auto s = gclient::common::trimAscii(raw);
    if (s.empty()) return defaultVal;
    if (s == "1" || gclient::common::equalsAsciiCI(s, "true") ||
        gclient::common::equalsAsciiCI(s, "yes") || gclient::common::equalsAsciiCI(s, "on")) {
        return true;
    }
    if (s == "0" || gclient::common::equalsAsciiCI(s, "false") ||
        gclient::common::equalsAsciiCI(s, "no") || gclient::common::equalsAsciiCI(s, "off")) {
        return false;
    }
    return defaultVal;
}

inline bool readEnvBool(std::initializer_list<const char*> names, bool defaultVal = false) {
    const std::string raw = firstNonEmptyEnv(names);
    return raw.empty() ? defaultVal : parseEnvBool(raw, defaultVal);
}

inline std::string urlEncode(std::string_view input) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(input.size() + 16);
    for (unsigned char c : input) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[(c >> 4) & 0x0Fu]);
            out.push_back(kHex[c & 0x0Fu]);
        }
    }
    return out;
}

inline std::string urlDecode(std::string_view input) {
    auto hexVal = [](unsigned char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '+') {
            out.push_back(' ');
        } else if (input[i] == '%' && i + 2 < input.size()) {
            int hi = hexVal(static_cast<unsigned char>(input[i + 1]));
            int lo = hexVal(static_cast<unsigned char>(input[i + 2]));
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
            } else {
                out.push_back(input[i]);
            }
        } else {
            out.push_back(input[i]);
        }
    }
    return out;
}

inline std::string signMapiSortedParams(const std::map<std::string, std::string>& params, std::string_view appKey) {
    std::string canonical;
    bool first = true;
    for (const auto& [k, v] : params) {
        if (k == "sign") continue;
        if (!first) canonical.push_back('&');
        first = false;
        canonical.append(k);
        canonical.push_back('=');
        canonical.append(v);
    }
    canonical.append(appKey);
    return gclient::crypto::md5Hex(canonical, false);
}

inline std::string buildSignedMapiQuery(const std::map<std::string, std::string>& params, std::string_view appKey) {
    std::string query;
    bool first = true;
    for (const auto& [k, v] : params) {
        if (k == "sign") continue;
        if (!first) query.push_back('&');
        first = false;
        query.append(urlEncode(k));
        query.push_back('=');
        query.append(urlEncode(v));
    }
    const std::string sign = signMapiSortedParams(params, appKey);
    if (!query.empty()) query.push_back('&');
    query.append("sign=");
    query.append(sign);
    return query;
}

} // namespace gclient::utf8
