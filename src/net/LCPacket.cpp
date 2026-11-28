#include "LCPacket.h"

#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace gclient::net {

namespace {

constexpr bool constantTimeEq16(const uint8_t* a, const uint8_t* b) noexcept {
    uint8_t diff = 0;
    for (size_t i = 0; i < 16u; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0u;
}

constexpr bool isValidFrameFlags(const uint8_t* f) noexcept {
    return (f[0] == 0u || f[0] == 1u) && f[1] == 1u && f[2] == 1u && f[3] == 1u;
}

} // namespace

bool LCPacket::zlibCompress(const uint8_t* input, size_t inputSize, std::string& output) {
    if ((input == nullptr && inputSize > 0) || inputSize > kMaxCompressInputBytes) {
        output.clear();
        return false;
    }
    static constexpr uint8_t kEmptyByte = 0;
    return gclient::crypto::zlibCompress(input != nullptr ? input : &kEmptyByte, inputSize, output);
}

bool LCPacket::zlibDecompress(const uint8_t* input, size_t inputSize, std::string& output,
                              size_t maxOutputSize) {
    output.clear();
    if (input == nullptr || inputSize < 2u ||
        inputSize > static_cast<size_t>((std::numeric_limits<uint32_t>::max)())) {
        return false;
    }
    const size_t safeCap = (std::min)(maxOutputSize, (std::numeric_limits<size_t>::max)() - 65536u);
    return gclient::crypto::zlibDecompress(input, inputSize, output, safeCap);
}

std::array<uint8_t, LCPacket::kHeaderMd5Size> LCPacket::computeBabelTimeMd5(
    const uint8_t* body, size_t bodySize) noexcept {
    static constexpr uint8_t kSalt[9] = {'B', 'a', 'b', 'e', 'l', 'T', 'i', 'm', 'e'};
    gclient::crypto::Md5Stream md5;
    md5.update(kSalt, sizeof(kSalt));

    if (body != nullptr && bodySize > 0) {
        uint8_t chunk[4096];
        for (size_t i = 0; i + 1 < bodySize;) {
            const size_t batch = (std::min)(sizeof(chunk), (bodySize - 1u) - i);
            for (size_t k = 0; k < batch; ++k) {
                chunk[k] = static_cast<uint8_t>(body[i + k + 1] ^ body[i + k]);
            }
            md5.update(chunk, batch);
            i += batch;
        }
        const uint8_t tail = static_cast<uint8_t>(body[bodySize - 1] ^ static_cast<uint8_t>(bodySize & 0xFFu));
        md5.update(&tail, 1u);
    }
    return md5.finish();
}

std::string LCPacket::makeLCPacket(const std::string& rawPayload, bool compressPayload) {
    return makeLCPacket(rawPayload.data(), rawPayload.size(), compressPayload);
}

std::string LCPacket::makeLCPacket(const char* rawCString, bool compressPayload) {
    if (rawCString == nullptr) {
        return makeLCPacket(static_cast<const void*>(nullptr), 0u, compressPayload);
    }
    return makeLCPacket(static_cast<const void*>(rawCString), std::strlen(rawCString), compressPayload);
}

std::string LCPacket::makeLCPacket(std::span<const uint8_t> payload, bool compressPayload) {
    return makeLCPacket(payload.data(), payload.size(), compressPayload);
}

std::string LCPacket::makeLCPacket(const void* data, size_t size, bool compressPayload) {
    if (data == nullptr && size > 0) {
        return {};
    }
    const auto* rawBytes = static_cast<const uint8_t*>(data);

    std::string body;
    if (compressPayload) {
        if (!zlibCompress(rawBytes, size, body)) {
            return {};
        }
    } else if (rawBytes != nullptr && size > 0) {
        body.assign(reinterpret_cast<const char*>(rawBytes), size);
    }

    if (body.size() > static_cast<size_t>((std::numeric_limits<uint32_t>::max)() - kTotalHeaderSize)) {
        return {};
    }

    const uint32_t bodyLen = static_cast<uint32_t>(body.size());
    const auto md5Digest = computeBabelTimeMd5(
        reinterpret_cast<const uint8_t*>(body.data()), body.size());

    std::string packet(kTotalHeaderSize + body.size(), '\0');
    auto* out = reinterpret_cast<uint8_t*>(packet.data());

    gclient::common::writeBE<uint32_t>(out, bodyLen);
    out[4] = compressPayload ? 1u : 0u;
    out[5] = 1u;
    out[6] = 1u;
    out[7] = 1u;
    std::memcpy(out + 8, md5Digest.data(), kHeaderMd5Size);

    if (!body.empty()) {
        std::memcpy(out + kTotalHeaderSize, body.data(), body.size());
    }
    return packet;
}

bool LCPacket::isFramedLCPacket(const void* data, size_t size) noexcept {
    if (data == nullptr || size < kTotalHeaderSize) {
        return false;
    }
    const auto* bytes = static_cast<const uint8_t*>(data);
    const size_t actualBodySize = size - kTotalHeaderSize;
    if (static_cast<size_t>(gclient::common::readBE<uint32_t>(bytes)) != actualBodySize ||
        !isValidFrameFlags(bytes + 4)) {
        return false;
    }
    const auto expectedMd5 = computeBabelTimeMd5(bytes + kTotalHeaderSize, actualBodySize);
    return constantTimeEq16(bytes + 8, expectedMd5.data());
}

bool LCPacket::parseLCPacket(const void* packetData, size_t packetSize,
                             DecodedPacket& outPacket, bool decompress,
                             bool requireValidMd5,
                             size_t maxDecompressedBytes) {
    outPacket = DecodedPacket{};
    if (packetData == nullptr || packetSize < kTotalHeaderSize) {
        return false;
    }

    const auto* bytes = static_cast<const uint8_t*>(packetData);
    const uint32_t bodyLen = gclient::common::readBE<uint32_t>(bytes);
    if (static_cast<size_t>(bodyLen) > packetSize - kTotalHeaderSize ||
        !isValidFrameFlags(bytes + 4)) {
        return false;
    }

    outPacket.bodyLength = bodyLen;
    std::memcpy(outPacket.flags.data(), bytes + 4, kHeaderFlagsSize);
    std::memcpy(outPacket.md5.data(), bytes + 8, kHeaderMd5Size);

    const uint8_t* bodyPtr = bytes + kTotalHeaderSize;
    const auto expectedMd5 = computeBabelTimeMd5(bodyPtr, bodyLen);
    outPacket.md5Valid = constantTimeEq16(expectedMd5.data(), outPacket.md5.data());
    if (requireValidMd5 && !outPacket.md5Valid) {
        return false;
    }

    if (decompress && outPacket.flags[0] != 0u) {
        return zlibDecompress(bodyPtr, bodyLen, outPacket.payload, maxDecompressedBytes);
    }
    outPacket.payload.assign(reinterpret_cast<const char*>(bodyPtr), bodyLen);
    return true;
}

} // namespace gclient::net
