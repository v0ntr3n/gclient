#include "BtDecryptHook.h"

#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelUtf8.h"

#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
#include "compat/Axmol226Compat.h"
#endif

#if !defined(GCLIENT_STANDALONE_BUILD)
#include "diagnostics/CrashAndTelemetry.h"
#endif

namespace gclient {
namespace assets {

namespace {

using gclient::common::readLE;

#if defined(__has_include)
#if __has_include("07_bt_decrypt_keys.inc")
#include "07_bt_decrypt_keys.inc"
#endif
#elif defined(GCLIENT_USE_BT_DECRYPT_KEYS_INC)
#include "07_bt_decrypt_keys.inc"
#endif

#if !defined(GCLIENT_BT_DECRYPT_KEYS_DEFINED)
#define GCLIENT_BT_DECRYPT_KEYS_DEFINED 0
static const BtKeyEntry kBtDefaultKeyTables[kBtKeyTableCount] = {};
#endif

std::mutex           g_runtimeKeyTablesMutex;
std::vector<uint8_t> g_runtimeKeyStorage[kBtKeyTableCount];
BtKeyEntry           g_runtimeKeyTables[kBtKeyTableCount] = {};
std::atomic<bool>    g_warnedMissingKeys{false};

#if !defined(GCLIENT_STANDALONE_BUILD)
gclient::diagnostics::LogLevel ParseLogLevel(const char* level) {
    if (!level) return gclient::diagnostics::LogLevel::Info;
    if (std::strcmp(level, "ERROR") == 0) return gclient::diagnostics::LogLevel::Error;
    if (std::strcmp(level, "WARN") == 0)  return gclient::diagnostics::LogLevel::Warn;
    if (std::strcmp(level, "DEBUG") == 0) return gclient::diagnostics::LogLevel::Debug;
    if (std::strcmp(level, "TRACE") == 0) return gclient::diagnostics::LogLevel::Trace;
    if (std::strcmp(level, "FATAL") == 0) return gclient::diagnostics::LogLevel::Fatal;
    return gclient::diagnostics::LogLevel::Info;
}
#endif

void LogMessage(const char* level, const char* text) {
    const char* safeLevel = level ? level : "INFO";
    const char* safeText  = text ? text : "";
#if !defined(GCLIENT_STANDALONE_BUILD)
    gclient::diagnostics::CrashAndTelemetry::log(
        ParseLogLevel(safeLevel), "BtDecryptHook", "%s", safeText);
    cocos2d::CCLog("[BtDecryptHook][%s] %s", safeLevel, safeText);
#elif defined(GCLIENT_ENABLE_COCOS2DX)
    cocos2d::CCLog("[BtDecryptHook][%s] %s", safeLevel, safeText);
#else
    std::fprintf(stderr, "[BtDecryptHook][%s] %s\n", safeLevel, safeText);
#endif
#if defined(_WIN32) && defined(GCLIENT_STANDALONE_BUILD)
    const std::string dbg = std::string("[BtDecryptHook][") + safeLevel + "] " + safeText + "\n";
    OutputDebugStringA(dbg.c_str());
#endif
}

void WarnIfKeysMissingOnce() {
    if (g_warnedMissingKeys.load(std::memory_order_relaxed) || HasDecryptKeys()) {
        return;
    }
    bool expected = false;
    if (g_warnedMissingKeys.compare_exchange_strong(expected, true)) {
        LogMessage(
            "WARN",
            "07_bt_decrypt_keys.inc is not present and no runtime key tables are registered. "
            "Encrypted assets with 0xFEFEFEFE headers will fail decryption until key tables are supplied.");
    }
}

BtKeyEntry ResolveKeyTable(uint8_t keyIndex) {
    if (keyIndex > kBtMaxKeyIndex) return {};
    {
        std::lock_guard<std::mutex> lock(g_runtimeKeyTablesMutex);
        if (g_runtimeKeyTables[keyIndex].data != nullptr &&
            g_runtimeKeyTables[keyIndex].length > 0) {
            return g_runtimeKeyTables[keyIndex];
        }
    }
    return kBtDefaultKeyTables[keyIndex];
}

const char* StatusToString(DecryptStatus status) {
    switch (status) {
        case DecryptStatus::Ok:                    return "OK";
        case DecryptStatus::NotEncrypted:          return "NOT_ENCRYPTED";
        case DecryptStatus::InvalidBuffer:         return "INVALID_BUFFER";
        case DecryptStatus::TruncatedHeader:       return "TRUNCATED_HEADER";
        case DecryptStatus::PayloadLengthMismatch: return "PAYLOAD_LENGTH_MISMATCH";
        case DecryptStatus::UnsupportedAlgoIndex:  return "UNSUPPORTED_ALGO_INDEX";
        case DecryptStatus::InvalidKeyIndex:       return "INVALID_KEY_INDEX";
        case DecryptStatus::MissingKeyTable:       return "MISSING_KEY_TABLE";
        default:                                   return "UNKNOWN";
    }
}

} // namespace

bool HasDecryptKeys() {
    std::lock_guard<std::mutex> lock(g_runtimeKeyTablesMutex);
    for (size_t i = 0; i < kBtKeyTableCount; ++i) {
        if ((g_runtimeKeyTables[i].data != nullptr && g_runtimeKeyTables[i].length > 0) ||
            (kBtDefaultKeyTables[i].data != nullptr && kBtDefaultKeyTables[i].length > 0)) {
            return true;
        }
    }
    return false;
}

bool RegisterKeyTable(uint8_t keyIndex, const uint8_t* keyData, uint32_t keyLength) {
    if (keyIndex > kBtMaxKeyIndex || keyData == nullptr || keyLength == 0 ||
        keyLength > kBtMaxKeyLength) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_runtimeKeyTablesMutex);
    g_runtimeKeyStorage[keyIndex].assign(keyData, keyData + keyLength);
    g_runtimeKeyTables[keyIndex].data   = g_runtimeKeyStorage[keyIndex].data();
    g_runtimeKeyTables[keyIndex].length = keyLength;
    return true;
}

bool IsBtEncryptedBuffer(const uint8_t* data, size_t size) {
    return data != nullptr && size >= kBtDecryptHeaderSize &&
           readLE<uint32_t>(data) == kBtDecryptMagic;
}

void LogDecryptFailure(const DecryptResult& diag, const char* contextPath) {
    char buf[512];
    std::snprintf(
        buf,
        sizeof(buf),
        "status=%s path=\"%s\" magic=0x%08X algo=%u keyIndex=%u headerPayload=%u actualPayload=%zu detail=\"%s\"",
        StatusToString(diag.status),
        contextPath ? contextPath : "<memory>",
        diag.magic,
        static_cast<unsigned>(diag.algoIndex),
        static_cast<unsigned>(diag.keyIndex),
        diag.headerPayloadSize,
        diag.actualPayloadSize,
        diag.message.c_str());
    LogMessage("ERROR", buf);
}

uint32_t DecryptBasic(uint8_t* data, uint32_t totalSize, DecryptResult* outDiag) {
    DecryptResult diag;
    auto finish = [&](DecryptStatus st, const char* msg, uint32_t rc) -> uint32_t {
        diag.status  = st;
        diag.message = msg;
        if (outDiag) *outDiag = diag;
        return rc;
    };

    if (data == nullptr) {
        return finish(DecryptStatus::InvalidBuffer, "Null buffer passed to DecryptBasic", 3u);
    }
    if (totalSize < kBtDecryptHeaderSize) {
        diag.actualPayloadSize = 0;
        return finish(DecryptStatus::TruncatedHeader,
                      "Buffer smaller than 32-byte Game Client header",
                      3u);
    }

    diag.magic             = readLE<uint32_t>(data);
    diag.headerPayloadSize = readLE<uint32_t>(data + 4);
    diag.algoIndex         = data[8];
    diag.keyIndex          = data[9];

    if (diag.magic != kBtDecryptMagic) {
        return finish(DecryptStatus::NotEncrypted, "Missing 0xFEFEFEFE magic in DecryptBasic", 3u);
    }
    if (diag.algoIndex != 0 && diag.algoIndex != 1) {
        return finish(DecryptStatus::UnsupportedAlgoIndex,
                      "Unsupported encryption algorithm index in DecryptBasic",
                      3u);
    }

    const uint32_t payloadLen = totalSize - static_cast<uint32_t>(kBtDecryptHeaderSize);
    diag.actualPayloadSize    = payloadLen;

    if (payloadLen != diag.headerPayloadSize) {
        return finish(DecryptStatus::PayloadLengthMismatch,
                      "Header payload size does not match (totalSize - 32)",
                      3u);
    }
    if (diag.keyIndex > kBtMaxKeyIndex) {
        return finish(DecryptStatus::InvalidKeyIndex, "Key index out of range (expected 0..15)", 3u);
    }

    const BtKeyEntry key = ResolveKeyTable(diag.keyIndex);
    if (key.data == nullptr || key.length == 0) {
        WarnIfKeysMissingOnce();
        return finish(DecryptStatus::MissingKeyTable,
                      "Key table slot is empty (drop 07_bt_decrypt_keys.inc or register key)",
                      3u);
    }

    if (payloadLen > 0) {
        uint8_t*       payload = data + kBtDecryptHeaderSize;
        const uint32_t keyLen  = key.length;
        const uint32_t offset  = payloadLen % keyLen;
        for (uint32_t i = 0; i < payloadLen; i += 2) {
            payload[i] ^= key.data[(i + offset) % keyLen];
        }
    }

    return finish(DecryptStatus::Ok, "Decrypted successfully", 0u);
}

bool DecryptBuffer(uint8_t* data,
                   size_t* size,
                   const char* contextPath,
                   DecryptResult* outDiag) {
    DecryptResult diag;
    auto fail = [&](DecryptStatus st, const char* msg, bool logErr) -> bool {
        diag.status  = st;
        diag.message = msg;
        if (logErr) LogDecryptFailure(diag, contextPath);
        if (outDiag) *outDiag = diag;
        return false;
    };

    if (data == nullptr || size == nullptr) {
        return fail(DecryptStatus::InvalidBuffer, "Null data or size pointer", true);
    }
    if (*size < kBtDecryptHeaderSize) {
        diag.actualPayloadSize = *size;
        return fail(DecryptStatus::NotEncrypted,
                    "Buffer shorter than 32-byte header; treating as plaintext",
                    false);
    }

    diag.magic             = readLE<uint32_t>(data);
    diag.headerPayloadSize = readLE<uint32_t>(data + 4);
    diag.algoIndex         = data[8];
    diag.keyIndex          = data[9];
    diag.actualPayloadSize = *size - kBtDecryptHeaderSize;

    if (diag.magic != kBtDecryptMagic) {
        return fail(DecryptStatus::NotEncrypted, "No 0xFEFEFEFE header; plaintext asset", false);
    }
    if (diag.algoIndex != 0 && diag.algoIndex != 1) {
        return fail(DecryptStatus::UnsupportedAlgoIndex,
                    "Unsupported encryption algorithm index in header[8]",
                    true);
    }

    if (DecryptBasic(data, static_cast<uint32_t>(*size), &diag) != 0u) {
        LogDecryptFailure(diag, contextPath);
        if (outDiag) *outDiag = diag;
        return false;
    }

    const size_t payloadLen = *size - kBtDecryptHeaderSize;
    if (payloadLen > 0) {
        std::memmove(data, data + kBtDecryptHeaderSize, payloadLen);
    }
    data[payloadLen] = '\0';
    if constexpr (kBtDecryptHeaderSize > 1) {
        std::memset(data + payloadLen + 1, 0, kBtDecryptHeaderSize - 1);
    }
    *size = payloadLen;

    if (outDiag) *outDiag = diag;
    return true;
}

std::string NormalizeAssetPath(const std::string& rawPath) {
    if (rawPath.empty()) return {};

    std::string unified;
    unified.reserve(rawPath.size());
    for (char c : rawPath) {
        unified.push_back(c == '\\' ? '/' : c);
    }

    std::string prefix;
    size_t      pos                  = 0;
    bool        isAbsolute           = false;
    size_t      minProtectedSegments = 0;

    if (unified.size() >= 2 && unified[0] == '/' && unified[1] == '/' &&
        (unified.size() == 2 || unified[2] != '/')) {
        prefix               = "//";
        pos                  = 2;
        isAbsolute           = true;
        minProtectedSegments = 2;
    } else if (unified[0] == '/') {
        prefix     = "/";
        isAbsolute = true;
        while (pos < unified.size() && unified[pos] == '/') ++pos;
    } else if (unified.size() >= 2 &&
               std::isalpha(static_cast<unsigned char>(unified[0])) &&
               unified[1] == ':') {
        if (unified.size() >= 3 && unified[2] == '/') {
            prefix     = unified.substr(0, 3);
            pos        = 3;
            isAbsolute = true;
            while (pos < unified.size() && unified[pos] == '/') ++pos;
        } else {
            prefix     = unified.substr(0, 2);
            pos        = 2;
            isAbsolute = false;
        }
    }

    const bool hadTrailingSlash = (pos < unified.size() && unified.back() == '/');

    std::vector<std::string> segments;
    while (pos < unified.size()) {
        while (pos < unified.size() && unified[pos] == '/') ++pos;
        if (pos >= unified.size()) break;

        const size_t nextSlash = unified.find('/', pos);
        const size_t segEnd    = (nextSlash == std::string::npos) ? unified.size() : nextSlash;
        std::string  seg       = unified.substr(pos, segEnd - pos);
        pos                    = segEnd;

        if (seg.empty() || seg == ".") continue;
        if (seg == "..") {
            if (segments.size() > minProtectedSegments && segments.back() != "..") {
                segments.pop_back();
            } else if (!isAbsolute) {
                segments.push_back(std::move(seg));
            }
        } else {
            segments.push_back(std::move(seg));
        }
    }

    if (segments.empty()) {
        if (!prefix.empty()) return prefix;
        return (unified == ".") ? std::string(".") : std::string();
    }

    std::string out = prefix;
    for (size_t i = 0; i < segments.size(); ++i) {
        if (i > 0) out.push_back('/');
        out.append(segments[i]);
    }
    if (hadTrailingSlash && !out.empty() && out.back() != '/') {
        out.push_back('/');
    }
    return out;
}

std::string ResolveRelativeAssetPath(const std::string& relativePath,
                                     const std::string& baseFilePath) {
    const std::string normRel  = NormalizeAssetPath(relativePath);
    const std::string normBase = NormalizeAssetPath(baseFilePath);
    if (normRel.empty()) return normBase;
    if (normRel[0] == '/' || (normRel.size() >= 2 && normRel[1] == ':')) return normRel;

    const size_t slashPos = normBase.find_last_of('/');
    if (slashPos == std::string::npos) return normRel;
    return NormalizeAssetPath(normBase.substr(0, slashPos + 1) + normRel);
}

std::string ReplaceFileExtension(const std::string& path, const std::string& newExt) {
    const std::string norm     = NormalizeAssetPath(path);
    const size_t      slashPos = norm.find_last_of('/');
    const size_t      dotPos   = norm.find_last_of('.');
    if (dotPos == std::string::npos || (slashPos != std::string::npos && dotPos < slashPos)) {
        return norm + newExt;
    }
    return norm.substr(0, dotPos) + newExt;
}

#if defined(_WIN32) && (defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD))
namespace {
FILE* OpenWin32ReadBinary(const std::string& utf8OrLocalPath) {
    auto openNormalizedWide = [](std::wstring wide) -> FILE* {
        if (wide.empty()) return nullptr;
        for (wchar_t& ch : wide) {
            if (ch == L'/') ch = L'\\';
        }
        return ::_wfopen(wide.c_str(), L"rb");
    };

    if (FILE* fp = openNormalizedWide(gclient::utf8::utf8ToWide(utf8OrLocalPath))) {
        return fp;
    }
    const int req = ::MultiByteToWideChar(
        CP_ACP, 0, utf8OrLocalPath.data(), static_cast<int>(utf8OrLocalPath.size()), nullptr, 0);
    if (req <= 0) return nullptr;
    std::wstring acpWide(static_cast<size_t>(req), L'\0');
    if (::MultiByteToWideChar(CP_ACP, 0, utf8OrLocalPath.data(),
                              static_cast<int>(utf8OrLocalPath.size()), acpWide.data(), req) <= 0) {
        return nullptr;
    }
    return openNormalizedWide(std::move(acpWide));
}

unsigned char* ReadRawBinaryWin32(const std::string& utf8OrLocalPath, unsigned long* outSize) {
    if (outSize) *outSize = 0;
    if (utf8OrLocalPath.empty()) return nullptr;

    FILE* fp = OpenWin32ReadBinary(utf8OrLocalPath);
    if (!fp) return nullptr;

    if (::_fseeki64(fp, 0, SEEK_END) != 0) {
        std::fclose(fp);
        return nullptr;
    }
    const long long fileLen = ::_ftelli64(fp);
    if (fileLen <= 0 || fileLen > 0x7FFFFFFFLL || ::_fseeki64(fp, 0, SEEK_SET) != 0) {
        std::fclose(fp);
        return nullptr;
    }

    const size_t   rawLen = static_cast<size_t>(fileLen);
    unsigned char* buf    = new unsigned char[rawLen + kBtDecryptHeaderSize + 1u];
    const size_t   nRead  = std::fread(buf, 1u, rawLen, fp);
    std::fclose(fp);
    if (nRead != rawLen) {
        delete[] buf;
        return nullptr;
    }
    buf[rawLen] = '\0';
    if (outSize) *outSize = static_cast<unsigned long>(rawLen);
    return buf;
}
} // namespace
#endif

unsigned char* LoadAndDecryptFileData(const std::string& filePath,
                                      unsigned long* outSize,
                                      DecryptResult* outDiag) {
    if (outSize) *outSize = 0;
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normPath = NormalizeAssetPath(filePath);
    if (normPath.empty()) return nullptr;

    unsigned long  rawSize  = 0;
    unsigned char* buffer   = nullptr;
    std::string    fullPath = normPath;

#if defined(_WIN32)
    if (normPath[0] == '/' || (normPath.size() >= 2 && normPath[1] == ':')) {
        buffer = ReadRawBinaryWin32(normPath, &rawSize);
    }
#endif

    if (!buffer) {
        auto* fu = ax::FileUtils::getInstance();
        if (!fu) return nullptr;

        const std::string compatNorm = gclient::compat::ResolveConvertedAssetPath(normPath);
        const std::string resolved   = fu->fullPathForFilename(compatNorm);
        fullPath                     = resolved.empty() ? compatNorm : resolved;
#if defined(_WIN32)
        buffer = ReadRawBinaryWin32(fullPath, &rawSize);
        if (!buffer && fullPath != compatNorm) {
            buffer = ReadRawBinaryWin32(compatNorm, &rawSize);
        }
#endif
        if (!buffer) {
            const bool prevPopup = fu->isPopupNotify();
            fu->setPopupNotify(false);
            ax::Data fileData = fu->getDataFromFile(fullPath);
            fu->setPopupNotify(prevPopup);
            if (!fileData.isNull() && fileData.getSize() > 0) {
                rawSize = static_cast<unsigned long>(fileData.getSize());
                buffer  = new unsigned char[fileData.getSize() + kBtDecryptHeaderSize + 1u];
                std::memcpy(buffer, fileData.getBytes(), fileData.getSize());
                buffer[fileData.getSize()] = '\0';
            }
        }
    }

    if (!buffer || rawSize == 0) {
        delete[] buffer;
        return nullptr;
    }

    if (rawSize >= 4 && rawSize < kBtDecryptHeaderSize &&
        readLE<uint32_t>(buffer) == kBtDecryptMagic) {
        DecryptResult diag;
        diag.status            = DecryptStatus::TruncatedHeader;
        diag.magic             = kBtDecryptMagic;
        diag.actualPayloadSize = 0;
        diag.message           = "Truncated 0xFEFEFEFE header (< 32 bytes)";
        LogDecryptFailure(diag, fullPath.c_str());
        if (outDiag) *outDiag = diag;
        delete[] buffer;
        return nullptr;
    }

    if (IsBtEncryptedBuffer(buffer, static_cast<size_t>(rawSize))) {
        size_t sz = static_cast<size_t>(rawSize);
        if (!DecryptBuffer(buffer, &sz, fullPath.c_str(), outDiag) || sz == 0) {
            delete[] buffer;
            return nullptr;
        }
        rawSize = static_cast<unsigned long>(sz);
    } else if (outDiag) {
        outDiag->status            = DecryptStatus::NotEncrypted;
        outDiag->actualPayloadSize = static_cast<size_t>(rawSize);
        outDiag->message           = "Plaintext or already decrypted by CCFileUtils";
    }

    buffer[rawSize] = '\0';
    if (outSize) *outSize = rawSize;
    return buffer;
#else
    (void)filePath;
    (void)outDiag;
    return nullptr;
#endif
}

void InstallBtDecryptHook(cocos2d::CCFileUtils* fileUtils) {
    WarnIfKeysMissingOnce();
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    cocos2d::CCFileUtils* fu = fileUtils ? fileUtils : ax::FileUtils::getInstance();
    if (!fu) {
        LogMessage("ERROR",
                   "InstallBtDecryptHook called before CCFileUtils::sharedFileUtils() is ready");
    }
#else
    (void)fileUtils;
#endif
}

} // namespace assets
} // namespace gclient

bool bt_decrypt(unsigned char* data, unsigned long* size) {
    if (data == nullptr || size == nullptr) return false;
    size_t     sz = static_cast<size_t>(*size);
    const bool ok = gclient::assets::DecryptBuffer(data, &sz, nullptr, nullptr);
    if (ok) *size = static_cast<unsigned long>(sz);
    return ok;
}

bool bt_decrypt_u64(uint8_t* data, uint64_t* size) {
    if (data == nullptr || size == nullptr || *size > 0xFFFFFFFFull) return false;
    size_t     sz = static_cast<size_t>(*size);
    const bool ok = gclient::assets::DecryptBuffer(data, &sz, nullptr, nullptr);
    if (ok) *size = static_cast<uint64_t>(sz);
    return ok;
}

uint32_t decrypt_basic(uint8_t* data, int totalSize) {
    return (totalSize < 0)
               ? 3u
               : gclient::assets::DecryptBasic(data, static_cast<uint32_t>(totalSize), nullptr);
}
