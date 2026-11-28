#pragma once
// Header-only C++20 endian-safe binary span readers, ASCII case-insensitive matchers, and FNV-1a hashing.

#include <algorithm>
#include <bit>
#include <cctype>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

namespace gclient::common {

template <std::integral T>
constexpr T byteSwap(T val) noexcept {
    using U = std::make_unsigned_t<T>;
    U u = static_cast<U>(val);
    if constexpr (sizeof(T) == 1) {
        return val;
    } else if constexpr (sizeof(T) == 2) {
        u = static_cast<U>((u >> 8) | (u << 8));
        return static_cast<T>(u);
    } else if constexpr (sizeof(T) == 4) {
        u = ((u & 0x000000FFu) << 24) |
            ((u & 0x0000FF00u) << 8) |
            ((u & 0x00FF0000u) >> 8) |
            ((u & 0xFF000000u) >> 24);
        return static_cast<T>(u);
    } else if constexpr (sizeof(T) == 8) {
        u = ((u & 0x00000000000000FFull) << 56) |
            ((u & 0x000000000000FF00ull) << 40) |
            ((u & 0x0000000000FF0000ull) << 24) |
            ((u & 0x00000000FF000000ull) << 8) |
            ((u & 0x000000FF00000000ull) >> 8) |
            ((u & 0x0000FF0000000000ull) >> 24) |
            ((u & 0x00FF000000000000ull) >> 40) |
            ((u & 0xFF00000000000000ull) >> 56);
        return static_cast<T>(u);
    }
    return val;
}

template <std::integral T>
inline T readLE(const uint8_t* p) noexcept {
    using U = std::make_unsigned_t<T>;
    U v = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        v |= static_cast<U>(p[i]) << (i * 8);
    }
    return static_cast<T>(v);
}

template <std::integral T>
inline T readLE(std::span<const uint8_t> buf, size_t offset = 0) noexcept {
    if (offset + sizeof(T) > buf.size()) {
        return T{0};
    }
    return readLE<T>(buf.data() + offset);
}

template <std::integral T>
inline T readBE(const uint8_t* p) noexcept {
    using U = std::make_unsigned_t<T>;
    U v = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        v = static_cast<U>((v << 8) | static_cast<U>(p[i]));
    }
    return static_cast<T>(v);
}

template <std::integral T>
inline T readBE(std::span<const uint8_t> buf, size_t offset = 0) noexcept {
    if (offset + sizeof(T) > buf.size()) {
        return T{0};
    }
    return readBE<T>(buf.data() + offset);
}

template <std::integral T>
constexpr void writeLE(uint8_t* p, T val) noexcept {
    using U = std::make_unsigned_t<T>;
    U u = static_cast<U>(val);
    for (size_t i = 0; i < sizeof(T); ++i) {
        p[i] = static_cast<uint8_t>((u >> (i * 8)) & 0xFFu);
    }
}

template <std::integral T>
constexpr void writeBE(uint8_t* p, T val) noexcept {
    using U = std::make_unsigned_t<T>;
    U u = static_cast<U>(val);
    for (size_t i = 0; i < sizeof(T); ++i) {
        p[sizeof(T) - 1 - i] = static_cast<uint8_t>((u >> (i * 8)) & 0xFFu);
    }
}

constexpr unsigned char asciiLower(unsigned char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c + ('a' - 'A')) : c;
}

constexpr bool equalsAsciiCI(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (asciiLower(static_cast<unsigned char>(a[i])) != asciiLower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

constexpr bool startsWithAsciiCI(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size() && equalsAsciiCI(s.substr(0, prefix.size()), prefix);
}

constexpr bool endsWithAsciiCI(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size() && equalsAsciiCI(s.substr(s.size() - suffix.size()), suffix);
}

inline std::string toLowerAscii(std::string_view s) {
    std::string out(s);
    for (char& ch : out) {
        ch = static_cast<char>(asciiLower(static_cast<unsigned char>(ch)));
    }
    return out;
}

constexpr std::string_view trimAscii(std::string_view s) noexcept {
    size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    size_t e = s.size();
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

inline std::string trimCopy(std::string_view s) {
    return std::string(trimAscii(s));
}

inline std::string readFixedCString(std::span<const uint8_t> buf, size_t offset, size_t maxLen) {
    if (offset >= buf.size()) return {};
    const size_t avail = std::min(maxLen, buf.size() - offset);
    size_t len = 0;
    while (len < avail && buf[offset + len] != 0) ++len;
    return std::string(reinterpret_cast<const char*>(buf.data() + offset), len);
}

constexpr uint64_t fnv1a64(std::string_view s) noexcept {
    uint64_t h = 14695981039346656037ull;
    for (unsigned char c : s) {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

} // namespace gclient::common
