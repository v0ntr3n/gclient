#pragma once
// Header-only C++20 unified MD5, BabelTime salted XOR-MD5, SHA-1, SHA-256, Hex, and Zlib helpers.
// Self-contained RFC 1321 MD5 & FIPS 180-4 SHA-256 + optional OpenSSL EVP SHA-1..SHA-512 & Zlib wrappers,
// so every target compiles identically whether or not -lcrypto is linked.

#include "common/KestrelBinaryReader.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if __has_include(<zlib.h>)
#include <zlib.h>
#define GCLIENT_CRYPTO_HAS_ZLIB 1
#else
#define GCLIENT_CRYPTO_HAS_ZLIB 0
#endif

namespace gclient::crypto {

inline std::string hexEncode(const void* data, size_t len, bool upper = false) {
    static constexpr char kLower[] = "0123456789abcdef";
    static constexpr char kUpper[] = "0123456789ABCDEF";
    const char* lut = upper ? kUpper : kLower;
    const auto* bytes = static_cast<const uint8_t*>(data);
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = lut[(bytes[i] >> 4) & 0x0Fu];
        out[i * 2 + 1] = lut[bytes[i] & 0x0Fu];
    }
    return out;
}

inline std::string hexEncode(std::span<const uint8_t> bytes, bool upper = false) {
    return hexEncode(bytes.data(), bytes.size(), upper);
}

inline bool hexDecode(std::string_view hex, std::vector<uint8_t>& out) {
    if ((hex.size() & 1u) != 0) return false;
    auto nibble = [](unsigned char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(static_cast<unsigned char>(hex[i]));
        int lo = nibble(static_cast<unsigned char>(hex[i + 1]));
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

class Md5Stream {
public:
    constexpr Md5Stream() noexcept { reset(); }

    constexpr void reset() noexcept {
        state_[0] = 0x67452301u;
        state_[1] = 0xefcdab89u;
        state_[2] = 0x98badcfeu;
        state_[3] = 0x10325476u;
        bitCount_ = 0;
    }

    inline void update(const void* input, size_t len) noexcept {
        if (!input || len == 0) return;
        const auto* data = static_cast<const uint8_t*>(input);
        size_t idx = static_cast<size_t>((bitCount_ >> 3) & 0x3Fu);
        bitCount_ += static_cast<uint64_t>(len) * 8ull;
        size_t i = 0;
        if (idx > 0) {
            const size_t fill = 64 - idx;
            if (len < fill) {
                std::memcpy(buffer_ + idx, data, len);
                return;
            }
            std::memcpy(buffer_ + idx, data, fill);
            transform(buffer_);
            i = fill;
        }
        for (; i + 64 <= len; i += 64) {
            transform(data + i);
        }
        if (i < len) {
            std::memcpy(buffer_, data + i, len - i);
        }
    }

    inline std::array<uint8_t, 16> finish() noexcept {
        const uint64_t totalBits = bitCount_;
        const uint8_t padStart = 0x80u;
        update(&padStart, 1);
        static constexpr uint8_t kZero[64] = {};
        const size_t rem = static_cast<size_t>((bitCount_ >> 3) & 0x3Fu);
        const size_t padZeros = (rem <= 56) ? (56 - rem) : (120 - rem);
        if (padZeros > 0) update(kZero, padZeros);
        uint8_t lenBytes[8];
        gclient::common::writeLE<uint64_t>(lenBytes, totalBits);
        update(lenBytes, 8);
        std::array<uint8_t, 16> digest{};
        for (int i = 0; i < 4; ++i) {
            gclient::common::writeLE<uint32_t>(digest.data() + i * 4, state_[i]);
        }
        return digest;
    }

private:
    uint32_t state_[4]{};
    uint64_t bitCount_ = 0;
    uint8_t buffer_[64]{};

    inline void transform(const uint8_t block[64]) noexcept {
        static constexpr uint32_t kShift[64] = {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
        };
        static constexpr uint32_t kTab[64] = {
            0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
            0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
            0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
            0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
            0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
            0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
            0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
            0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
        };
        uint32_t m[16];
        for (int i = 0; i < 16; ++i) m[i] = gclient::common::readLE<uint32_t>(block + i * 4);
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        for (uint32_t i = 0; i < 64; ++i) {
            uint32_t f = 0, g = 0;
            if (i < 16)      { f = (b & c) | ((~b) & d); g = i; }
            else if (i < 32) { f = (d & b) | ((~d) & c); g = (5u * i + 1u) & 15u; }
            else if (i < 48) { f = b ^ c ^ d;            g = (3u * i + 5u) & 15u; }
            else             { f = c ^ (b | (~d));       g = (7u * i) & 15u; }
            uint32_t tmp = d;
            d = c;
            c = b;
            uint32_t sum = a + f + kTab[i] + m[g];
            b = b + std::rotl(sum, static_cast<int>(kShift[i]));
            a = tmp;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    }
};

inline std::array<uint8_t, 16> md5Raw(const void* data, size_t len) noexcept {
    Md5Stream s;
    s.update(data, len);
    return s.finish();
}

inline std::array<uint8_t, 16> md5Raw(std::string_view sv) noexcept {
    return md5Raw(sv.data(), sv.size());
}

inline std::string md5Hex(const void* data, size_t len, bool upper = false) {
    const auto d = md5Raw(data, len);
    return hexEncode(d.data(), d.size(), upper);
}

inline std::string md5Hex(std::string_view sv, bool upper = false) {
    return md5Hex(sv.data(), sv.size(), upper);
}

inline std::array<uint8_t, 16> babeltimeSaltedMd5(const uint8_t* body, size_t len) {
    static constexpr uint8_t kSalt[9] = {'B','a','b','e','l','T','i','m','e'};
    std::vector<uint8_t> buf(len + sizeof(kSalt));
    if (len > 0 && body) std::memcpy(buf.data(), body, len);
    std::memcpy(buf.data() + len, kSalt, sizeof(kSalt));
    for (size_t i = 1; i + 1 < buf.size(); ++i) {
        buf[i] ^= buf[i - 1];
    }
    return md5Raw(buf.data(), buf.size());
}

class Sha256Stream {
public:
    constexpr Sha256Stream() noexcept { reset(); }

    constexpr void reset() noexcept {
        state_[0] = 0x6a09e667u; state_[1] = 0xbb67ae85u; state_[2] = 0x3c6ef372u; state_[3] = 0xa54ff53au;
        state_[4] = 0x510e527fu; state_[5] = 0x9b05688cu; state_[6] = 0x1f83d9abu; state_[7] = 0x5be0cd19u;
        bitLen_ = 0;
        bufLen_ = 0;
    }

    inline void update(const void* input, size_t len) noexcept {
        if (!input || len == 0) return;
        const auto* data = static_cast<const uint8_t*>(input);
        for (size_t i = 0; i < len; ++i) {
            buffer_[bufLen_++] = data[i];
            if (bufLen_ == 64) {
                transform(buffer_);
                bitLen_ += 512;
                bufLen_ = 0;
            }
        }
    }

    inline std::array<uint8_t, 32> finish() noexcept {
        const uint64_t totalBits = bitLen_ + static_cast<uint64_t>(bufLen_) * 8ull;
        buffer_[bufLen_++] = 0x80u;
        if (bufLen_ > 56) {
            while (bufLen_ < 64) buffer_[bufLen_++] = 0;
            transform(buffer_);
            bufLen_ = 0;
        }
        while (bufLen_ < 56) buffer_[bufLen_++] = 0;
        gclient::common::writeBE<uint64_t>(buffer_ + 56, totalBits);
        transform(buffer_);
        bufLen_ = 0;
        std::array<uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i) {
            gclient::common::writeBE<uint32_t>(out.data() + i * 4, state_[i]);
        }
        return out;
    }

private:
    uint32_t state_[8]{};
    uint64_t bitLen_ = 0;
    size_t bufLen_ = 0;
    uint8_t buffer_[64]{};

    inline void transform(const uint8_t block[64]) noexcept {
        static constexpr uint32_t k[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
        };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) w[i] = gclient::common::readBE<uint32_t>(block + i * 4);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }
};

inline std::array<uint8_t, 32> sha256Raw(const void* data, size_t len) noexcept {
    Sha256Stream s;
    s.update(data, len);
    return s.finish();
}

inline std::string sha256Hex(const void* data, size_t len, bool upper = false) {
    const auto d = sha256Raw(data, len);
    return hexEncode(d.data(), d.size(), upper);
}

inline std::string sha256Hex(std::string_view sv, bool upper = false) {
    return sha256Hex(sv.data(), sv.size(), upper);
}

inline bool sha256FileHex(const std::filesystem::path& filePath, std::string& outHex) {
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs.is_open()) return false;
    Sha256Stream s;
    char buf[16384];
    while (ifs.good()) {
        ifs.read(buf, sizeof(buf));
        const auto got = ifs.gcount();
        if (got > 0) s.update(buf, static_cast<size_t>(got));
    }
    if (ifs.bad()) return false;
    const auto d = s.finish();
    outHex = hexEncode(d.data(), d.size(), false);
    return true;
}

#if GCLIENT_CRYPTO_HAS_ZLIB
inline bool zlibCompress(const void* data, size_t len, std::string& out, int level = Z_DEFAULT_COMPRESSION) {
    uLongf bound = compressBound(static_cast<uLong>(len));
    out.resize(bound);
    int rc = compress2(
        reinterpret_cast<Bytef*>(out.data()),
        &bound,
        static_cast<const Bytef*>(data),
        static_cast<uLong>(len),
        level);
    if (rc != Z_OK) {
        out.clear();
        return false;
    }
    out.resize(bound);
    return true;
}

inline bool zlibDecompress(const void* data, size_t len, std::string& out, size_t maxOutBytes = 64 * 1024 * 1024) {
    out.clear();
    if (!data || len == 0) return false;
    z_stream zs{};
    zs.next_in = const_cast<Bytef*>(static_cast<const Bytef*>(data));
    zs.avail_in = static_cast<uInt>(len);
    if (inflateInit(&zs) != Z_OK) return false;
    char chunk[16384];
    int ret = Z_OK;
    while (ret == Z_OK) {
        zs.next_out = reinterpret_cast<Bytef*>(chunk);
        zs.avail_out = sizeof(chunk);
        ret = inflate(&zs, Z_NO_FLUSH);
        const size_t produced = sizeof(chunk) - zs.avail_out;
        if (produced > 0) {
            if (out.size() + produced > maxOutBytes) {
                inflateEnd(&zs);
                out.clear();
                return false;
            }
            out.append(chunk, produced);
        }
    }
    inflateEnd(&zs);
    if (ret != Z_STREAM_END) {
        out.clear();
        return false;
    }
    return true;
}
#endif

} // namespace gclient::crypto
