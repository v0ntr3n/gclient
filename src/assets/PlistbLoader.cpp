#include "PlistbLoader.h"

#include "BtDecryptHook.h"
#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelUtf8.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
#include "compat/Axmol226Compat.h"
#endif

namespace gclient {
namespace assets {

namespace {

using gclient::common::endsWithAsciiCI;
using gclient::common::readFixedCString;
using gclient::common::readLE;
using gclient::common::startsWithAsciiCI;
using gclient::common::trimAscii;

std::mutex                                                g_loadedPlistbMutex;
std::unordered_set<std::string>                           g_loadedPlistbFiles;
std::unordered_map<std::string, std::vector<std::string>> g_plistFrameNamesMap;

bool ReadValidatedFixedCString(const uint8_t* ptr,
                               size_t maxLen,
                               bool requireNonEmpty,
                               std::string* outStr) {
    if (std::memchr(ptr, '\0', maxLen) == nullptr) {
        return false;
    }
    std::string s = readFixedCString(std::span<const uint8_t>(ptr, maxLen), 0, maxLen);
    if (requireNonEmpty && s.empty()) {
        return false;
    }
    for (unsigned char ch : s) {
        if (ch < 0x20u || ch == 0x7Fu) {
            return false;
        }
    }
    if (outStr) *outStr = std::move(s);
    return true;
}

bool LooksLikePlaintextXmlPlist(const uint8_t* data, size_t size) {
    if (!data || size == 0) return false;
    size_t off = (size >= 3 && data[0] == 0xEFu && data[1] == 0xBBu && data[2] == 0xBFu) ? 3u : 0u;
    const std::string_view sv = trimAscii(
        std::string_view(reinterpret_cast<const char*>(data + off), size - off));
    return startsWithAsciiCI(sv, "<?xml") || startsWithAsciiCI(sv, "<plist") ||
           startsWithAsciiCI(sv, "<!doctype") || startsWithAsciiCI(sv, "<!--");
}

std::string StripTextureExtension(const std::string& normalizedPath) {
    if (endsWithAsciiCI(normalizedPath, ".pvr.ccz")) {
        return normalizedPath.substr(0, normalizedPath.size() - 8);
    }
    if (endsWithAsciiCI(normalizedPath, ".pvr.gz")) {
        return normalizedPath.substr(0, normalizedPath.size() - 7);
    }
    const size_t slashPos = normalizedPath.find_last_of('/');
    const size_t dotPos   = normalizedPath.find_last_of('.');
    if (dotPos == std::string::npos || (slashPos != std::string::npos && dotPos < slashPos)) {
        return normalizedPath;
    }
    return normalizedPath.substr(0, dotPos);
}

void AppendUniqueCandidate(std::vector<std::string>& out, const std::string& candidate) {
    if (!candidate.empty() && std::find(out.begin(), out.end(), candidate) == out.end()) {
        out.push_back(candidate);
    }
}

std::string BuildPlistbPath(const std::string& plistPath) {
    const std::string norm = NormalizeAssetPath(plistPath);
    if (norm.empty() || endsWithAsciiCI(norm, ".plistb")) return norm;
    if (endsWithAsciiCI(norm, ".plist")) return norm + "b";
    return ReplaceFileExtension(norm, ".plistb");
}

[[maybe_unused]] std::string BuildXmlPlistPath(const std::string& plistPath) {
    const std::string norm = NormalizeAssetPath(plistPath);
    if (norm.empty() || endsWithAsciiCI(norm, ".plist")) return norm;
    if (endsWithAsciiCI(norm, ".plistb")) return norm.substr(0, norm.size() - 1);
    return ReplaceFileExtension(norm, ".plist");
}

std::string UnescapeXmlText(const char* s, size_t len) {
    struct EntitySpec {
        std::string_view token;
        char             ch;
    };
    static constexpr EntitySpec kEntities[] = {
        {"&amp;", '&'}, {"&lt;", '<'}, {"&gt;", '>'}, {"&quot;", '"'}, {"&apos;", '\''}};

    std::string out;
    out.reserve(len);
    const std::string_view sv(s, len);
    for (size_t i = 0; i < len; ++i) {
        if (s[i] == '&') {
            bool matched = false;
            for (const auto& ent : kEntities) {
                if (sv.substr(i).starts_with(ent.token)) {
                    out.push_back(ent.ch);
                    i += ent.token.size() - 1;
                    matched = true;
                    break;
                }
            }
            if (matched) continue;
        }
        out.push_back(s[i]);
    }
    return out;
}

struct XmlCursor {
    const char* p   = nullptr;
    const char* end = nullptr;

    void skipWsAndComments() {
        while (p < end) {
            if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
                ++p;
                continue;
            }
            if (end - p >= 4 && std::memcmp(p, "<!--", 4) == 0) {
                p += 4;
                while (end - p >= 3 && std::memcmp(p, "-->", 3) != 0) ++p;
                p = (end - p >= 3) ? (p + 3) : end;
                continue;
            }
            if (end - p >= 2 && (std::memcmp(p, "<?", 2) == 0 || std::memcmp(p, "<!", 2) == 0)) {
                while (p < end && *p != '>') ++p;
                if (p < end) ++p;
                continue;
            }
            break;
        }
    }

    bool readNextTag(std::string* outName, bool* outIsClosing, bool* outSelfClosing) {
        skipWsAndComments();
        if (p >= end || *p != '<') return false;
        ++p;
        *outIsClosing   = false;
        *outSelfClosing = false;
        if (p < end && *p == '/') {
            *outIsClosing = true;
            ++p;
        }
        const char* nameStart = p;
        while (p < end && *p != '>' && *p != '/' && *p != ' ' && *p != '\t' && *p != '\r' &&
               *p != '\n') {
            ++p;
        }
        outName->assign(nameStart, static_cast<size_t>(p - nameStart));
        while (p < end && *p != '>') {
            if (*p == '/' && (p + 1 < end && p[1] == '>')) *outSelfClosing = true;
            ++p;
        }
        if (p >= end || *p != '>') return false;
        ++p;
        return !outName->empty();
    }

    bool readElementTextUntilClose(const std::string& tagName, std::string* outText) {
        const char*       textStart = p;
        const std::string closeSeq  = "</" + tagName + ">";
        while (p < end) {
            if (*p == '<' && static_cast<size_t>(end - p) >= closeSeq.size() &&
                std::memcmp(p, closeSeq.data(), closeSeq.size()) == 0) {
                if (outText) {
                    *outText = UnescapeXmlText(textStart, static_cast<size_t>(p - textStart));
                }
                p += closeSeq.size();
                return true;
            }
            ++p;
        }
        return false;
    }
};

bool SkipXmlPlistValue(XmlCursor& cur, const std::string& openTag, bool selfClosing, int depth) {
    if (depth > 32) return false;
    if (selfClosing) return true;
    if (openTag == "dict") {
        while (true) {
            std::string tag;
            bool        isClosing = false, sc = false;
            if (!cur.readNextTag(&tag, &isClosing, &sc)) return false;
            if (isClosing) return tag == "dict";
            if (tag != "key") return false;
            if (!sc && !cur.readElementTextUntilClose("key", nullptr)) return false;
            std::string valTag;
            bool        valClosing = false, valSc = false;
            if (!cur.readNextTag(&valTag, &valClosing, &valSc) || valClosing) return false;
            if (!SkipXmlPlistValue(cur, valTag, valSc, depth + 1)) return false;
        }
    }
    if (openTag == "array") {
        while (true) {
            std::string tag;
            bool        isClosing = false, sc = false;
            if (!cur.readNextTag(&tag, &isClosing, &sc)) return false;
            if (isClosing) return tag == "array";
            if (!SkipXmlPlistValue(cur, tag, sc, depth + 1)) return false;
        }
    }
    return cur.readElementTextUntilClose(openTag, nullptr);
}

bool ReadXmlPlistScalarMap(XmlCursor& cur,
                           std::unordered_map<std::string, std::string>* outStrings,
                           std::unordered_map<std::string, bool>* outBools,
                           int depth = 1) {
    if (depth > 32) return false;
    while (true) {
        std::string tag;
        bool        isClosing = false, selfClosing = false;
        if (!cur.readNextTag(&tag, &isClosing, &selfClosing)) return false;
        if (isClosing) return tag == "dict";
        if (tag != "key") return false;

        std::string keyName;
        if (!selfClosing && !cur.readElementTextUntilClose("key", &keyName)) return false;

        std::string valTag;
        bool        valClosing = false, valSelfClosing = false;
        if (!cur.readNextTag(&valTag, &valClosing, &valSelfClosing) || valClosing) return false;

        if (valTag == "true" || valTag == "false") {
            if (!valSelfClosing && !cur.readElementTextUntilClose(valTag, nullptr)) return false;
            const bool b = (valTag == "true");
            if (outBools) (*outBools)[keyName] = b;
            if (outStrings) (*outStrings)[keyName] = b ? "true" : "false";
        } else if (valTag == "string" || valTag == "integer" || valTag == "real") {
            std::string text;
            if (!valSelfClosing && !cur.readElementTextUntilClose(valTag, &text)) return false;
            if (outStrings) (*outStrings)[keyName] = std::move(text);
        } else {
            if (!SkipXmlPlistValue(cur, valTag, valSelfClosing, depth + 1)) return false;
        }
    }
}

size_t ExtractBraceFloats(std::string_view sv, float* outVals, size_t maxCount) {
    size_t      count = 0;
    const char* p     = sv.data();
    const char* end   = p + sv.size();
    while (p < end && count < maxCount) {
        while (p < end && !((*p >= '0' && *p <= '9') || *p == '-' || *p == '+' || *p == '.')) {
            ++p;
        }
        if (p >= end) break;
        std::string tmp(p, static_cast<size_t>(end - p));
        char*       parseEnd = nullptr;
        const float v        = std::strtof(tmp.c_str(), &parseEnd);
        if (parseEnd == tmp.c_str()) {
            ++p;
            continue;
        }
        outVals[count++] = v;
        p += static_cast<size_t>(parseEnd - tmp.c_str());
    }
    return count;
}

float ParseScalarFloat(const std::unordered_map<std::string, std::string>& m,
                       const char* key,
                       float fallback = 0.0f) {
    auto it = m.find(key);
    if (it == m.end() || it->second.empty()) return fallback;
    char* endPtr = nullptr;
    const float v = std::strtof(it->second.c_str(), &endPtr);
    return (endPtr == it->second.c_str()) ? fallback : v;
}

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)

void SetDictString(cocos2d::CCDictionary* dict, const std::string& key, const std::string& val) {
    auto* strObj = new cocos2d::CCString(val);
    dict->setObject(strObj, key);
    strObj->release();
}

void SetDictFmt(cocos2d::CCDictionary* dict, const std::string& key, const char* fmt, ...) {
    char    buf[128];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    SetDictString(dict, key, buf);
}

cocos2d::CCObject* ParseXmlPlistValue(XmlCursor& cur,
                                      const std::string& openTag,
                                      bool selfClosing,
                                      int depth);

cocos2d::CCDictionary* ParseXmlDictBody(XmlCursor& cur, int depth) {
    if (depth > 32) return nullptr;
    auto* dict = new cocos2d::CCDictionary();
    while (true) {
        std::string tag;
        bool        isClosing = false, selfClosing = false;
        if (!cur.readNextTag(&tag, &isClosing, &selfClosing)) break;
        if (isClosing) {
            if (tag == "dict") return dict;
            break;
        }
        if (tag != "key") break;

        std::string keyName;
        if (!selfClosing && !cur.readElementTextUntilClose("key", &keyName)) break;

        std::string valTag;
        bool        valClosing = false, valSelfClosing = false;
        if (!cur.readNextTag(&valTag, &valClosing, &valSelfClosing) || valClosing) break;

        cocos2d::CCObject* valObj = ParseXmlPlistValue(cur, valTag, valSelfClosing, depth + 1);
        if (!valObj) break;
        dict->setObject(valObj, keyName);
        valObj->release();
    }
    dict->release();
    return nullptr;
}

cocos2d::CCArray* ParseXmlArrayBody(XmlCursor& cur, int depth) {
    if (depth > 32) return nullptr;
    auto* arr = new cocos2d::CCArray();
    while (true) {
        std::string tag;
        bool        isClosing = false, selfClosing = false;
        if (!cur.readNextTag(&tag, &isClosing, &selfClosing)) break;
        if (isClosing) {
            if (tag == "array") return arr;
            break;
        }
        cocos2d::CCObject* item = ParseXmlPlistValue(cur, tag, selfClosing, depth + 1);
        if (!item) break;
        arr->addObject(item);
        item->release();
    }
    arr->release();
    return nullptr;
}

cocos2d::CCObject* ParseXmlPlistValue(XmlCursor& cur,
                                      const std::string& openTag,
                                      bool selfClosing,
                                      int depth) {
    if (openTag == "dict") {
        return selfClosing ? new cocos2d::CCDictionary() : ParseXmlDictBody(cur, depth);
    }
    if (openTag == "array") {
        return selfClosing ? new cocos2d::CCArray() : ParseXmlArrayBody(cur, depth);
    }
    if (openTag == "true" || openTag == "false") {
        if (!selfClosing) (void)cur.readElementTextUntilClose(openTag, nullptr);
        return new cocos2d::CCString(openTag == "true" ? "1" : "0");
    }
    if (openTag == "string" || openTag == "integer" || openTag == "real" || openTag == "data") {
        if (selfClosing) return new cocos2d::CCString("");
        std::string text;
        return cur.readElementTextUntilClose(openTag, &text) ? new cocos2d::CCString(text)
                                                             : nullptr;
    }
    return nullptr;
}

cocos2d::CCDictionary* ParseXmlPlistToDictionary(const uint8_t* data, size_t size) {
    const size_t off =
        (size >= 3 && data[0] == 0xEFu && data[1] == 0xBBu && data[2] == 0xBFu) ? 3u : 0u;
    XmlCursor cur{reinterpret_cast<const char*>(data + off),
                  reinterpret_cast<const char*>(data + size)};

    std::string tag;
    bool        isClosing = false, selfClosing = false;
    if (!cur.readNextTag(&tag, &isClosing, &selfClosing) || isClosing) return nullptr;
    if (tag == "plist") {
        if (selfClosing || !cur.readNextTag(&tag, &isClosing, &selfClosing) || isClosing) {
            return nullptr;
        }
    }
    if (tag != "dict") return nullptr;

    cocos2d::CCDictionary* dict =
        selfClosing ? new cocos2d::CCDictionary() : ParseXmlDictBody(cur, 0);
    if (dict) dict->autorelease();
    return dict;
}

cocos2d::CCDictionary* BuildSpriteSheetDictionary(const PlistbFileData& parsed) {
    auto* root = cocos2d::CCDictionary::create();
    if (!root) return nullptr;

    auto* metadata = new cocos2d::CCDictionary();
    SetDictString(metadata, "format", "2");
    SetDictString(metadata, "textureFileName", parsed.textureFileName);
    SetDictString(metadata, "realTextureFileName", parsed.textureFileName);
    root->setObject(metadata, "metadata");
    metadata->release();

    auto* frames = new cocos2d::CCDictionary();
    for (const auto& rec : parsed.frames) {
        if (rec.frameName.empty()) continue;
        auto* entry = new cocos2d::CCDictionary();
        SetDictFmt(entry,
                   "frame",
                   "{{%d,%d},{%d,%d}}",
                   static_cast<int>(rec.rectX),
                   static_cast<int>(rec.rectY),
                   static_cast<int>(rec.rectWidth),
                   static_cast<int>(rec.rectHeight));
        SetDictFmt(entry,
                   "offset",
                   "{%d,%d}",
                   static_cast<int>(rec.offsetX),
                   static_cast<int>(rec.offsetY));
        SetDictString(entry, "rotated", rec.rotated ? "true" : "false");
        SetDictFmt(entry,
                   "sourceSize",
                   "{%d,%d}",
                   static_cast<int>(rec.originalWidth),
                   static_cast<int>(rec.originalHeight));
        frames->setObject(entry, rec.frameName);
        entry->release();
    }
    root->setObject(frames, "frames");
    frames->release();
    return root;
}

cocos2d::CCTexture2D* LoadFirstMatchingTexture(const std::vector<std::string>& candidateList) {
    auto* texCache = ax::Director::getInstance()->getTextureCache();
    if (!texCache) return nullptr;
    if (auto* fu = ax::FileUtils::getInstance()) {
        for (const std::string& cand : candidateList) {
            const std::string full = fu->fullPathForFilename(cand.c_str());
            if (!full.empty() && fu->isFileExist(full)) {
                if (auto* tex = texCache->addImage(full.c_str())) return tex;
            }
        }
    }
    for (const std::string& cand : candidateList) {
        if (auto* tex = texCache->addImage(cand.c_str())) return tex;
    }
    return nullptr;
}

#endif // GCLIENT_ENABLE_COCOS2DX

} // namespace

bool PlistbLoader::ParseBuffer(const uint8_t* data,
                               size_t size,
                               PlistbFileData* outData,
                               std::string* outError) {
    auto fail = [&](std::string msg) -> bool {
        if (outError) *outError = std::move(msg);
        return false;
    };

    if (data == nullptr || outData == nullptr) {
        return fail("Null buffer or output pointer");
    }
    if (size >= 4 && readLE<uint32_t>(data) == kBtDecryptMagic) {
        return fail("Undecrypted 0xFEFEFEFE buffer passed to PlistbLoader::ParseBuffer");
    }
    if (LooksLikePlaintextXmlPlist(data, size)) {
        return fail("Plaintext XML plist passed to binary PlistbLoader::ParseBuffer");
    }
    if (size < kPlistbHeaderSize) {
        return fail("Buffer smaller than 66-byte .plistb header");
    }

    std::string texName;
    if (!ReadValidatedFixedCString(data, kPlistbNameMaxLen, /*requireNonEmpty=*/true, &texName)) {
        return fail("Invalid or non-NUL-terminated textureFileName in .plistb header");
    }

    const int16_t frameCount = readLE<int16_t>(data + 64);
    if (frameCount < 0) {
        return fail("Negative frame count in .plistb header");
    }

    const size_t requiredBytes =
        kPlistbHeaderSize + static_cast<size_t>(frameCount) * kPlistbRecordSize;
    if (size < requiredBytes) {
        char msg[160];
        std::snprintf(msg,
                      sizeof(msg),
                      "Truncated .plistb buffer: need %zu bytes for %d frames, got %zu",
                      requiredBytes,
                      static_cast<int>(frameCount),
                      size);
        return fail(msg);
    }

    std::vector<PlistbFrameRecord> parsedFrames;
    parsedFrames.reserve(static_cast<size_t>(frameCount));

    const uint8_t* cursor = data + kPlistbHeaderSize;
    for (int16_t i = 0; i < frameCount; ++i, cursor += kPlistbRecordSize) {
        PlistbFrameRecord rec;
        if (!ReadValidatedFixedCString(
                cursor, kPlistbNameMaxLen, /*requireNonEmpty=*/false, &rec.frameName)) {
            return fail("Invalid or non-NUL-terminated frameName in .plistb record");
        }
        rec.rectX          = static_cast<float>(readLE<uint16_t>(cursor + 64));
        rec.rectY          = static_cast<float>(readLE<uint16_t>(cursor + 66));
        rec.rectWidth      = static_cast<float>(readLE<uint16_t>(cursor + 68));
        rec.rectHeight     = static_cast<float>(readLE<uint16_t>(cursor + 70));
        rec.rotated        = (cursor[72] != 0);
        rec.offsetX        = static_cast<float>(readLE<int16_t>(cursor + 74));
        rec.offsetY        = static_cast<float>(readLE<int16_t>(cursor + 76));
        rec.originalWidth  = static_cast<float>(readLE<uint16_t>(cursor + 78));
        rec.originalHeight = static_cast<float>(readLE<uint16_t>(cursor + 80));
        parsedFrames.push_back(std::move(rec));
    }

    outData->textureFileName = std::move(texName);
    outData->frames          = std::move(parsedFrames);
    return true;
}

bool PlistbLoader::ParseXmlSpriteSheetBuffer(const uint8_t* data,
                                             size_t size,
                                             PlistbFileData* outData,
                                             std::string* outError) {
    auto fail = [&](std::string msg) -> bool {
        if (outError) *outError = std::move(msg);
        return false;
    };

    if (data == nullptr || size == 0 || outData == nullptr) {
        return fail("Null or empty XML plist buffer");
    }
    if (size >= 4 && readLE<uint32_t>(data) == kBtDecryptMagic) {
        return fail("Undecrypted 0xFEFEFEFE buffer passed to PlistbLoader::ParseXmlSpriteSheetBuffer");
    }
    if (!LooksLikePlaintextXmlPlist(data, size)) {
        return fail("Non-XML buffer passed to PlistbLoader::ParseXmlSpriteSheetBuffer");
    }

    const size_t off =
        (size >= 3 && data[0] == 0xEFu && data[1] == 0xBBu && data[2] == 0xBFu) ? 3u : 0u;
    XmlCursor cur{reinterpret_cast<const char*>(data + off),
                  reinterpret_cast<const char*>(data + size)};

    std::string tag;
    bool        isClosing = false, selfClosing = false;
    if (!cur.readNextTag(&tag, &isClosing, &selfClosing) || isClosing) {
        return fail("Malformed XML plist header");
    }
    if (tag == "plist") {
        if (selfClosing || !cur.readNextTag(&tag, &isClosing, &selfClosing) || isClosing) {
            return fail("Empty or malformed <plist> root element");
        }
    }
    if (tag != "dict") {
        return fail("Expected root <dict> in XML sprite-sheet plist");
    }
    if (selfClosing) {
        return fail("Empty root <dict/> in XML sprite-sheet plist");
    }

    bool                           hasFramesDict = false;
    bool                           rootClosed    = false;
    std::string                    realTexName;
    std::string                    texName;
    std::string                    fmt0TexName;
    std::vector<PlistbFrameRecord> parsedFrames;

    while (true) {
        std::string keyTag;
        bool        kClose = false, kSelf = false;
        if (!cur.readNextTag(&keyTag, &kClose, &kSelf)) break;
        if (kClose) {
            rootClosed = (keyTag == "dict");
            break;
        }
        if (keyTag != "key") break;

        std::string topKey;
        if (!kSelf && !cur.readElementTextUntilClose("key", &topKey)) break;

        std::string valTag;
        bool        vClose = false, vSelf = false;
        if (!cur.readNextTag(&valTag, &vClose, &vSelf) || vClose) break;

        if (topKey == "metadata" && valTag == "dict") {
            if (!vSelf) {
                std::unordered_map<std::string, std::string> metaStrs;
                if (!ReadXmlPlistScalarMap(cur, &metaStrs, nullptr, 1)) break;
                if (auto it = metaStrs.find("realTextureFileName");
                    it != metaStrs.end() && !it->second.empty()) {
                    realTexName = it->second;
                }
                if (auto it = metaStrs.find("textureFileName");
                    it != metaStrs.end() && !it->second.empty()) {
                    texName = it->second;
                }
            }
        } else if (topKey == "texture" && valTag == "dict") {
            if (!vSelf) {
                std::unordered_map<std::string, std::string> texStrs;
                if (!ReadXmlPlistScalarMap(cur, &texStrs, nullptr, 1)) break;
                if (auto it = texStrs.find("filename");
                    it != texStrs.end() && !it->second.empty()) {
                    fmt0TexName = it->second;
                }
            }
        } else if (topKey == "frames" && valTag == "dict") {
            hasFramesDict = true;
            if (!vSelf) {
                bool framesClosed = false;
                while (true) {
                    std::string fTag;
                    bool        fClose = false, fSelf = false;
                    if (!cur.readNextTag(&fTag, &fClose, &fSelf)) break;
                    if (fClose) {
                        framesClosed = (fTag == "dict");
                        break;
                    }
                    if (fTag != "key") break;

                    std::string frameName;
                    if (!fSelf && !cur.readElementTextUntilClose("key", &frameName)) break;

                    std::string entryTag;
                    bool        eClose = false, eSelf = false;
                    if (!cur.readNextTag(&entryTag, &eClose, &eSelf) || eClose) break;
                    if (entryTag != "dict") {
                        if (!SkipXmlPlistValue(cur, entryTag, eSelf, 2)) break;
                        continue;
                    }

                    std::unordered_map<std::string, std::string> fStrs;
                    std::unordered_map<std::string, bool>        fBools;
                    if (!eSelf && !ReadXmlPlistScalarMap(cur, &fStrs, &fBools, 2)) break;
                    if (frameName.empty()) continue;

                    PlistbFrameRecord rec;
                    rec.frameName = std::move(frameName);

                    if (auto itFrame = fStrs.find("frame");
                        itFrame != fStrs.end() && !itFrame->second.empty()) {
                        float r[4]{};
                        ExtractBraceFloats(itFrame->second, r, 4);
                        rec.rectX      = r[0];
                        rec.rectY      = r[1];
                        rec.rectWidth  = r[2];
                        rec.rectHeight = r[3];

                        if (auto itOff = fStrs.find("offset"); itOff != fStrs.end()) {
                            float o[2]{};
                            if (ExtractBraceFloats(itOff->second, o, 2) >= 2) {
                                rec.offsetX = o[0];
                                rec.offsetY = o[1];
                            }
                        }
                        float s[2]{rec.rectWidth, rec.rectHeight};
                        if (auto itSrc = fStrs.find("sourceSize"); itSrc != fStrs.end()) {
                            ExtractBraceFloats(itSrc->second, s, 2);
                        }
                        rec.originalWidth  = s[0];
                        rec.originalHeight = s[1];
                        if (auto itRot = fBools.find("rotated"); itRot != fBools.end()) {
                            rec.rotated = itRot->second;
                        }
                    } else if (auto itTexRect = fStrs.find("textureRect");
                               itTexRect != fStrs.end() && !itTexRect->second.empty()) {
                        float tr[4]{};
                        ExtractBraceFloats(itTexRect->second, tr, 4);
                        rec.rectX      = tr[0];
                        rec.rectY      = tr[1];
                        rec.rectWidth  = tr[2];
                        rec.rectHeight = tr[3];

                        if (auto itSprSz = fStrs.find("spriteSize");
                            itSprSz != fStrs.end() && !itSprSz->second.empty()) {
                            float ss[2]{};
                            if (ExtractBraceFloats(itSprSz->second, ss, 2) >= 2) {
                                rec.rectWidth  = ss[0];
                                rec.rectHeight = ss[1];
                            }
                        }
                        if (auto itOff = fStrs.find("spriteOffset"); itOff != fStrs.end()) {
                            float so[2]{};
                            if (ExtractBraceFloats(itOff->second, so, 2) >= 2) {
                                rec.offsetX = so[0];
                                rec.offsetY = so[1];
                            }
                        }
                        float sss[2]{rec.rectWidth, rec.rectHeight};
                        if (auto itSrc = fStrs.find("spriteSourceSize"); itSrc != fStrs.end()) {
                            ExtractBraceFloats(itSrc->second, sss, 2);
                        }
                        rec.originalWidth  = sss[0];
                        rec.originalHeight = sss[1];
                        if (auto itRot = fBools.find("textureRotated"); itRot != fBools.end()) {
                            rec.rotated = itRot->second;
                        } else if (auto itRot2 = fBools.find("rotated"); itRot2 != fBools.end()) {
                            rec.rotated = itRot2->second;
                        }
                    } else {
                        rec.rectX          = ParseScalarFloat(fStrs, "x");
                        rec.rectY          = ParseScalarFloat(fStrs, "y");
                        rec.rectWidth      = ParseScalarFloat(fStrs, "width");
                        rec.rectHeight     = ParseScalarFloat(fStrs, "height");
                        rec.offsetX        = ParseScalarFloat(fStrs, "offsetX");
                        rec.offsetY        = ParseScalarFloat(fStrs, "offsetY");
                        rec.originalWidth  = ParseScalarFloat(fStrs, "originalWidth", rec.rectWidth);
                        rec.originalHeight = ParseScalarFloat(fStrs, "originalHeight", rec.rectHeight);
                        rec.rotated        = false;
                    }

                    parsedFrames.push_back(std::move(rec));
                }
                if (!framesClosed) break;
            }
        } else {
            if (!SkipXmlPlistValue(cur, valTag, vSelf, 1)) break;
        }
    }

    if (!rootClosed || !hasFramesDict) {
        return fail("Invalid or truncated XML sprite-sheet plist (missing <frames> dictionary)");
    }

    outData->textureFileName = !realTexName.empty()
                                   ? std::move(realTexName)
                                   : (!texName.empty() ? std::move(texName) : std::move(fmt0TexName));
    outData->frames          = std::move(parsedFrames);
    return true;
}

std::vector<std::string> PlistbLoader::ResolveSpriteSheetCandidates(
    const std::string& rawSheetPath,
    const std::string& baseFilePath) {
    std::vector<std::string> candidates;
    const std::string        normSheet = NormalizeAssetPath(rawSheetPath);
    if (normSheet.empty()) return candidates;

    const std::string normBase = NormalizeAssetPath(baseFilePath);
    if (normBase.empty()) {
        candidates.push_back(normSheet);
        return candidates;
    }

    const size_t      slashPos = normBase.find_last_of('/');
    const std::string baseDir =
        (slashPos != std::string::npos) ? normBase.substr(0, slashPos + 1) : std::string{};

    if (baseDir.empty() || startsWithAsciiCI(normSheet, baseDir)) {
        candidates.push_back(normSheet);
        return candidates;
    }

    const std::string relCand = ResolveRelativeAssetPath(normSheet, normBase);
    if (normSheet.find('/') == std::string::npos) {
        AppendUniqueCandidate(candidates, relCand);
        AppendUniqueCandidate(candidates, normSheet);
    } else {
        AppendUniqueCandidate(candidates, normSheet);
        AppendUniqueCandidate(candidates, relCand);
    }
    return candidates;
}

std::vector<std::string> PlistbLoader::BuildTextureCandidatePaths(const std::string& texturePath) {
    std::vector<std::string> candidates;
    const std::string        norm = NormalizeAssetPath(texturePath);
    if (norm.empty()) return candidates;

    const std::string stem = StripTextureExtension(norm);
    for (const std::string& cand : {stem + ".png",
                                    norm,
                                    stem + ".pvr.ccz",
                                    stem + ".pkm",
                                    stem + ".webp",
                                    stem + ".jpg"}) {
        AppendUniqueCandidate(candidates, cand);
    }
    return candidates;
}

bool PlistbLoader::AddSpriteFramesFromPlistbFile(const std::string& plistPath,
                                                 cocos2d::CCTexture2D* texture,
                                                 cocos2d::CCSpriteFrameCache* cache) {
    return AddSpriteFramesWithBinary(plistPath, texture, cache);
}

bool PlistbLoader::AddSpriteFramesWithBinary(const std::string& plistPath,
                                             cocos2d::CCTexture2D* texture,
                                             cocos2d::CCSpriteFrameCache* cache) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normBasePath = NormalizeAssetPath(plistPath);
    const std::string plistbPath   = BuildPlistbPath(normBasePath);
    const std::string xmlPlistPath = BuildXmlPlistPath(normBasePath);
    if (plistbPath.empty()) return false;

    std::string    loadedPath = plistbPath;
    unsigned long  fileSize   = 0;
    DecryptResult  diag;
    unsigned char* rawData = LoadAndDecryptFileData(plistbPath, &fileSize, &diag);
    if ((!rawData || fileSize == 0) && !xmlPlistPath.empty() && xmlPlistPath != plistbPath) {
        delete[] rawData;
        rawData    = LoadAndDecryptFileData(xmlPlistPath, &fileSize, &diag);
        loadedPath = xmlPlistPath;
    }
    if (!rawData || fileSize == 0) {
        cocos2d::CCLog("[PlistbLoader] Failed to load binary plist: %s", plistbPath.c_str());
        delete[] rawData;
        return false;
    }

    PlistbFileData parsed;
    std::string    parseErr;
    const size_t   byteLen = static_cast<size_t>(fileSize);
    const bool     ok      = LooksLikePlaintextXmlPlist(rawData, byteLen)
                                 ? ParseXmlSpriteSheetBuffer(rawData, byteLen, &parsed, &parseErr)
                                 : ParseBuffer(rawData, byteLen, &parsed, &parseErr);
    delete[] rawData;
    if (!ok) {
        cocos2d::CCLog("[PlistbLoader] Parse failed for %s: %s",
                       loadedPath.c_str(),
                       parseErr.c_str());
        return false;
    }

    if (parsed.textureFileName.empty()) {
        parsed.textureFileName = StripTextureExtension(loadedPath) + ".png";
    }

    cocos2d::CCTexture2D* targetTexture = texture;
    if (!targetTexture) {
        const std::string        texRelPath    = NormalizeAssetPath(parsed.textureFileName);
        const std::string        relBaseTex    = startsWithAsciiCI(texRelPath, loadedPath.substr(0, loadedPath.find_last_of('/') + 1))
                                                     ? texRelPath
                                                     : ResolveRelativeAssetPath(texRelPath, loadedPath);
        std::vector<std::string> candidateList = BuildTextureCandidatePaths(relBaseTex);
        for (const std::string& c : BuildTextureCandidatePaths(texRelPath)) {
            AppendUniqueCandidate(candidateList, c);
        }
        if (auto* fu = ax::FileUtils::getInstance()) {
            const std::string fromFu = NormalizeAssetPath(
                fu->fullPathFromRelativeFile(texRelPath.c_str(), loadedPath.c_str()));
            if (!fromFu.empty() && fromFu != relBaseTex) {
                for (const std::string& c : BuildTextureCandidatePaths(fromFu)) {
                    AppendUniqueCandidate(candidateList, c);
                }
            }
        }
        targetTexture = LoadFirstMatchingTexture(candidateList);
        if (!targetTexture) {
            cocos2d::CCLog("cocos2d: CCSpriteFrameCache: Couldn't load texture: %s (from %s)",
                           relBaseTex.c_str(),
                           loadedPath.c_str());
            return false;
        }
    }

    cocos2d::CCSpriteFrameCache* targetCache =
        cache ? cache : ax::SpriteFrameCache::getInstance();
    if (!targetCache) return false;

    std::vector<std::string> registeredNames;
    registeredNames.reserve(parsed.frames.size());

    for (const auto& rec : parsed.frames) {
        if (rec.frameName.empty()) continue;
        auto* frame = new cocos2d::CCSpriteFrame();
        frame->initWithTexture(
            targetTexture,
            cocos2d::CCRect(rec.rectX, rec.rectY, rec.rectWidth, rec.rectHeight),
            rec.rotated,
            cocos2d::CCPoint(rec.offsetX, rec.offsetY),
            cocos2d::CCSize(rec.originalWidth, rec.originalHeight));
        targetCache->addSpriteFrame(frame, rec.frameName.c_str());
        frame->release();
        registeredNames.push_back(rec.frameName);
    }

    {
        std::lock_guard<std::mutex> lock(g_loadedPlistbMutex);
        g_loadedPlistbFiles.insert(normBasePath);
        g_loadedPlistbFiles.insert(plistbPath);
        if (!xmlPlistPath.empty()) g_loadedPlistbFiles.insert(xmlPlistPath);
        g_plistFrameNamesMap[plistbPath] = std::move(registeredNames);
    }
    return true;
#else
    (void)plistPath;
    (void)texture;
    (void)cache;
    return false;
#endif
}

bool PlistbLoader::RemoveSpriteFramesWithBinary(const std::string& plistPath,
                                                cocos2d::CCSpriteFrameCache* cache) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normBasePath = NormalizeAssetPath(plistPath);
    const std::string plistbPath   = BuildPlistbPath(normBasePath);
    const std::string xmlPlistPath = BuildXmlPlistPath(normBasePath);
    if (plistbPath.empty()) return false;

    std::vector<std::string> namesToRemove;
    {
        std::lock_guard<std::mutex> lock(g_loadedPlistbMutex);
        if (auto it = g_plistFrameNamesMap.find(plistbPath); it != g_plistFrameNamesMap.end()) {
            namesToRemove = std::move(it->second);
            g_plistFrameNamesMap.erase(it);
        }
        g_loadedPlistbFiles.erase(normBasePath);
        g_loadedPlistbFiles.erase(plistbPath);
        if (!xmlPlistPath.empty()) g_loadedPlistbFiles.erase(xmlPlistPath);
    }
    if (namesToRemove.empty()) return false;

    cocos2d::CCSpriteFrameCache* targetCache =
        cache ? cache : ax::SpriteFrameCache::getInstance();
    if (!targetCache) return false;

    for (const std::string& frameName : namesToRemove) {
        if (!frameName.empty()) targetCache->removeSpriteFrameByName(frameName.c_str());
    }
    return true;
#else
    (void)plistPath;
    (void)cache;
    return false;
#endif
}

cocos2d::CCDictionary* PlistbLoader::LoadDictionaryFromBinaryBuffer(const uint8_t* data,
                                                                    size_t size,
                                                                    std::string* outError) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    if (!data || size == 0) {
        if (outError) *outError = "Null or empty plist buffer";
        return nullptr;
    }
    if (size >= 4 && readLE<uint32_t>(data) == kBtDecryptMagic) {
        if (outError) *outError = "Undecrypted 0xFEFEFEFE buffer in LoadDictionaryFromBinaryBuffer";
        return nullptr;
    }
    if (LooksLikePlaintextXmlPlist(data, size)) {
        cocos2d::CCDictionary* xmlDict = ParseXmlPlistToDictionary(data, size);
        if (!xmlDict && outError) *outError = "Failed to parse XML plist dictionary";
        return xmlDict;
    }
    PlistbFileData parsed;
    return ParseBuffer(data, size, &parsed, outError) ? BuildSpriteSheetDictionary(parsed)
                                                      : nullptr;
#else
    (void)data;
    (void)size;
    if (outError) *outError = "Cocos2d-x disabled in standalone build";
    return nullptr;
#endif
}

cocos2d::CCDictionary* PlistbLoader::LoadDictionaryFromBinaryFile(const std::string& plistPath,
                                                                  std::string* outError) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string norm = NormalizeAssetPath(plistPath);
    if (norm.empty()) {
        if (outError) *outError = "Empty plist path";
        return nullptr;
    }

    std::vector<std::string> candidates;
    AppendUniqueCandidate(candidates, BuildPlistbPath(norm));
    AppendUniqueCandidate(candidates, BuildXmlPlistPath(norm));
    AppendUniqueCandidate(candidates, norm);

    for (const std::string& cand : candidates) {
        unsigned long  fileSize = 0;
        DecryptResult  diag;
        unsigned char* rawData = LoadAndDecryptFileData(cand, &fileSize, &diag);
        if (!rawData || fileSize == 0) {
            delete[] rawData;
            continue;
        }
        cocos2d::CCDictionary* dict =
            LoadDictionaryFromBinaryBuffer(rawData, static_cast<size_t>(fileSize), outError);
        delete[] rawData;
        if (dict) return dict;
    }

    if (outError && outError->empty()) {
        *outError = "Unable to load plist/plistb dictionary: " + norm;
    }
    return nullptr;
#else
    (void)plistPath;
    if (outError) *outError = "Cocos2d-x disabled in standalone build";
    return nullptr;
#endif
}

bool PlistbLoader::IsPlistbLoaded(const std::string& plistPath) {
    const std::string norm   = NormalizeAssetPath(plistPath);
    const std::string plistb = BuildPlistbPath(norm);
    std::lock_guard<std::mutex> lock(g_loadedPlistbMutex);
    return g_loadedPlistbFiles.contains(norm) || g_loadedPlistbFiles.contains(plistb);
}

void PlistbLoader::ClearLoadedTracking() {
    std::lock_guard<std::mutex> lock(g_loadedPlistbMutex);
    g_loadedPlistbFiles.clear();
    g_plistFrameNamesMap.clear();
}

} // namespace assets
} // namespace gclient
