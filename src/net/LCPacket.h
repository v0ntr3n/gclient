#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace gclient::net {

class LCPacket {
public:
    static constexpr size_t kHeaderLengthSize = 4;
    static constexpr size_t kHeaderFlagsSize  = 4;
    static constexpr size_t kHeaderMd5Size    = 16;
    static constexpr size_t kTotalHeaderSize  = kHeaderLengthSize + kHeaderFlagsSize + kHeaderMd5Size; // 24 bytes
    static constexpr size_t kDefaultMaxDecompressedBytes = 64u * 1024u * 1024u; // 64 MiB cap on Win32 x86
    static constexpr size_t kMaxCompressInputBytes = kDefaultMaxDecompressedBytes;

    struct DecodedPacket {
        uint32_t bodyLength = 0;
        std::array<uint8_t, kHeaderFlagsSize> flags{0, 0, 0, 0};
        std::array<uint8_t, kHeaderMd5Size> md5{};
        std::string payload;
        bool md5Valid = false;
    };

    static std::string makeLCPacket(const std::string& rawPayload, bool compressPayload = true);
    // Explicit C-string overload prevents C++17 implicit conversion of (const char*, bool) -> (const void*, size_t(0|1))!
    static std::string makeLCPacket(const char* rawCString, bool compressPayload = true);
    static std::string makeLCPacket(std::span<const uint8_t> payload, bool compressPayload = true);
    static std::string makeLCPacket(const void* data, size_t size, bool compressPayload = true);

    static bool isFramedLCPacket(const void* data, size_t size) noexcept;

    static bool parseLCPacket(const void* packetData, size_t packetSize,
                              DecodedPacket& outPacket, bool decompress = true,
                              bool requireValidMd5 = true,
                              size_t maxDecompressedBytes = kDefaultMaxDecompressedBytes);

    static std::array<uint8_t, kHeaderMd5Size> computeBabelTimeMd5(const uint8_t* body, size_t bodySize) noexcept;

    static bool zlibCompress(const uint8_t* input, size_t inputSize, std::string& output);

    static bool zlibDecompress(const uint8_t* input, size_t inputSize, std::string& output,
                               size_t maxOutputSize = kDefaultMaxDecompressedBytes);

    static uint32_t readBigEndianU32(const uint8_t* data);
    static void writeBigEndianU32(uint8_t* out, uint32_t value);
};

} // namespace gclient::net
