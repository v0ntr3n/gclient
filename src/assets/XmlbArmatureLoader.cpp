#include "XmlbArmatureLoader.h"

#include "BtDecryptHook.h"
#include "PlistbLoader.h"
#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelUtf8.h"

#if !defined(GCLIENT_STANDALONE_BUILD) || defined(GCLIENT_XMLB_WITH_PROTOBUF)
#include "db.pb.h"
#define GCLIENT_XMLB_HAS_PROTOBUF 1
#endif

#include <algorithm>
#include <cmath>
#include <concepts>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <span>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
#include "compat/Axmol226Compat.h"
#include "cocos-ext.h"
#endif

#if !defined(GCLIENT_STANDALONE_BUILD)
#include "diagnostics/CrashAndTelemetry.h"
#endif

namespace gclient {
namespace assets {

namespace {

using gclient::common::endsWithAsciiCI;
using gclient::common::readFixedCString;
using gclient::common::readLE;
using gclient::common::startsWithAsciiCI;
using gclient::common::trimAscii;

void LogArmatureWarn(const char* msg) {
#if !defined(GCLIENT_STANDALONE_BUILD)
    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Warn, "XmlbArmatureLoader", "%s", msg ? msg : "");
#endif
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    cocos2d::CCLog("[XmlbArmatureLoader][WARN] %s", msg ? msg : "");
#else
    std::fprintf(stderr, "[XmlbArmatureLoader][WARN] %s\n", msg ? msg : "");
#endif
}

void LogArmatureWarnFmt(const char* fmt, ...) {
    char    msg[320];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    LogArmatureWarn(msg);
}

inline std::string ReadBoundedCString(const uint8_t* ptr, size_t maxLen) {
    return readFixedCString(std::span<const uint8_t>(ptr, maxLen), 0, maxLen);
}

bool ValidateFixedCStringField(const uint8_t* ptr, size_t maxLen, bool requireNonEmpty) {
    const void* nulPos = std::memchr(ptr, '\0', maxLen);
    if (nulPos == nullptr) return false;
    const size_t len = static_cast<size_t>(static_cast<const uint8_t*>(nulPos) - ptr);
    if (requireNonEmpty && len == 0) return false;
    for (size_t i = 0; i < len; ++i) {
        if (ptr[i] < 0x20u || ptr[i] == 0x7Fu) return false;
    }
    return true;
}

bool LooksLikePlaintextXml(const uint8_t* data, size_t size) {
    if (!data || size == 0) return false;
    const size_t off =
        (size >= 3 && data[0] == 0xEFu && data[1] == 0xBBu && data[2] == 0xBFu) ? 3u : 0u;
    const std::string_view sv =
        trimAscii(std::string_view(reinterpret_cast<const char*>(data + off), size - off));
    return startsWithAsciiCI(sv, "<?xml") || startsWithAsciiCI(sv, "<plist") ||
           startsWithAsciiCI(sv, "<skeleton") || startsWithAsciiCI(sv, "<armature") ||
           startsWithAsciiCI(sv, "<!doctype") || startsWithAsciiCI(sv, "<!--");
}

bool ReadProtoVarint(const uint8_t* data, size_t size, size_t* ioOff, uint64_t* outVal) {
    uint64_t result = 0;
    int      shift  = 0;
    size_t   off    = *ioOff;
    while (off < size && shift < 64) {
        const uint8_t byte = data[off++];
        result |= static_cast<uint64_t>(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0) {
            *ioOff  = off;
            *outVal = result;
            return true;
        }
        shift += 7;
    }
    return false;
}

constexpr bool IsValidArmatureRootTopTag(uint64_t tag) noexcept {
    return tag == 0x0Du || tag == 0x12u || tag == 0x1Au || tag == 0x22u || tag == 0x2Au;
}

constexpr bool IsValidSubmessageFirstTag(uint64_t outerTag, uint64_t innerTag) noexcept {
    if (outerTag == 0x12u) return innerTag == 0x0Du || innerTag == 0x12u || innerTag == 0x1Au;
    if (outerTag == 0x1Au) return innerTag == 0x0Au || innerTag == 0x12u;
    if (outerTag == 0x22u) {
        return innerTag == 0x0Au || innerTag == 0x15u || innerTag == 0x1Du ||
               innerTag == 0x25u || innerTag == 0x2Du || innerTag == 0x32u || innerTag == 0x3Au;
    }
    return true;
}

bool LooksLikeArmatureProtobufWire(const uint8_t* data, size_t size) {
    if (!data || size < 2) return false;
    size_t   off      = 0;
    uint64_t firstTag = 0;
    if (!ReadProtoVarint(data, size, &off, &firstTag) || !IsValidArmatureRootTopTag(firstTag)) {
        return false;
    }

    if (firstTag == 0x0Du) {
        if (off + 4 > size) return true;
        float scaleVal = 0.0f;
        std::memcpy(&scaleVal, data + off, sizeof(float));
        off += 4;
        if (!std::isfinite(scaleVal) || scaleVal <= 0.0f || scaleVal > 64.0f) return false;
        if (off == size) return true;
        uint64_t secondTag = 0;
        return ReadProtoVarint(data, size, &off, &secondTag) &&
               IsValidArmatureRootTopTag(secondTag);
    }

    uint64_t subLen = 0;
    if (!ReadProtoVarint(data, size, &off, &subLen)) return false;
    if (firstTag == 0x2Au) {
        return subLen > 0 && subLen <= 260 && off < size && data[off] >= 0x20u &&
               data[off] < 0x7Fu;
    }
    if (subLen == 0) return off == size || IsValidArmatureRootTopTag(data[off]);
    if (off >= size) return true;

    uint64_t innerTag = 0;
    size_t   innerOff = off;
    return ReadProtoVarint(data, size, &innerOff, &innerTag) &&
           IsValidSubmessageFirstTag(firstTag, innerTag);
}

// Shared sticky-blend state machine used across BitCache and Protobuf frame decoders.
void ApplyStickyBlendPair(bool hasNonDefaultBlend,
                          uint32_t candidateSrc,
                          uint32_t candidateDst,
                          bool* ioHasStickyBlend,
                          uint32_t* ioStickyBlendSrc,
                          uint32_t* ioStickyBlendDst,
                          uint32_t* outSrc,
                          uint32_t* outDst) {
    if (hasNonDefaultBlend) {
        *outSrc = candidateSrc;
        *outDst = candidateDst;
        if (ioHasStickyBlend) *ioHasStickyBlend = true;
        if (ioStickyBlendSrc) *ioStickyBlendSrc = candidateSrc;
        if (ioStickyBlendDst) *ioStickyBlendDst = candidateDst;
    } else if (ioHasStickyBlend && *ioHasStickyBlend && ioStickyBlendSrc && ioStickyBlendDst) {
        *outSrc = *ioStickyBlendSrc;
        *outDst = *ioStickyBlendDst;
    } else {
        XmlbArmatureLoader::MapBlendTypeToGL(0, outSrc, outDst);
    }
}

struct BitCacheCursor {
    const uint8_t* ptr = nullptr;
    const uint8_t* end = nullptr;

    size_t remaining() const noexcept { return static_cast<size_t>(end - ptr); }

    const uint8_t* take(size_t n) noexcept {
        if (remaining() < n) return nullptr;
        const uint8_t* cur = ptr;
        ptr += n;
        return cur;
    }
};

struct NoopBitCacheVisitor {
    void onCounts(uint16_t, uint16_t, uint16_t) {}
    void beginArmature(const uint8_t*, uint16_t) {}
    void beginBone(const uint8_t*, uint16_t) {}
    void onDisplay(const uint8_t*) {}
    void endBone() {}
    void endArmature() {}
    void beginAnimation(const uint8_t*, uint16_t) {}
    bool beginMovement(const uint8_t*, size_t, uint16_t) { return true; }
    void beginMovBone(const uint8_t*, uint16_t) {}
    bool onFrame(const uint8_t*, size_t) { return true; }
    void endMovBone() {}
    void endMovement() {}
    void endAnimation() {}
    void onTexture(const uint8_t*) {}
};

template <typename VisitorT>
bool WalkBitCacheStream(const uint8_t* bitCacheData,
                        size_t bitCacheSize,
                        const XmlbBitCacheLayout& layout,
                        VisitorT&& visitor) {
    if (!bitCacheData || layout.skeletonStructSize < 6 || bitCacheSize < layout.skeletonStructSize) {
        return false;
    }
    if (bitCacheSize >= 4 && readLE<uint32_t>(bitCacheData) == kBtDecryptMagic) return false;
    if (LooksLikePlaintextXml(bitCacheData, bitCacheSize)) return false;
    if (layout.armatureDataStructSize < 66 || layout.boneDataStructSize < 68 ||
        layout.displayDataStructSize < 65 || layout.animationDataStructSize < 66 ||
        layout.movementDataStructSize < 74 || layout.movementBoneDataStructSize < 66 ||
        layout.frameDataStructSize < 168 || layout.textureDataStructSize < 68) {
        return false;
    }

    BitCacheCursor cur{bitCacheData, bitCacheData + bitCacheSize};
    const uint8_t* skelHdr = cur.take(layout.skeletonStructSize);
    if (!skelHdr) return false;

    const uint16_t armatureCount  = readLE<uint16_t>(skelHdr + 0);
    const uint16_t animationCount = readLE<uint16_t>(skelHdr + 2);
    const uint16_t textureCount   = readLE<uint16_t>(skelHdr + 4);
    if (armatureCount == 0 && animationCount == 0 && textureCount == 0) return false;
    visitor.onCounts(armatureCount, animationCount, textureCount);

    for (uint16_t a = 0; a < armatureCount; ++a) {
        const uint8_t* armHdr = cur.take(layout.armatureDataStructSize);
        if (!armHdr || !ValidateFixedCStringField(armHdr, 64, true)) return false;
        const uint16_t boneCount = readLE<uint16_t>(armHdr + 64);
        visitor.beginArmature(armHdr, boneCount);

        for (uint16_t b = 0; b < boneCount; ++b) {
            const uint8_t* boneHdr = cur.take(layout.boneDataStructSize);
            if (!boneHdr || !ValidateFixedCStringField(boneHdr, 64, true)) return false;
            const uint16_t displayCount = readLE<uint16_t>(boneHdr + 66);
            visitor.beginBone(boneHdr, displayCount);

            for (uint16_t d = 0; d < displayCount; ++d) {
                const uint8_t* dispHdr = cur.take(layout.displayDataStructSize);
                if (!dispHdr || dispHdr[0] > 2u ||
                    !ValidateFixedCStringField(dispHdr + 1, 64, false)) {
                    return false;
                }
                visitor.onDisplay(dispHdr);
            }
            visitor.endBone();
        }
        visitor.endArmature();
    }

    for (uint16_t a = 0; a < animationCount; ++a) {
        const uint8_t* animHdr = cur.take(layout.animationDataStructSize);
        if (!animHdr || !ValidateFixedCStringField(animHdr, 64, true)) return false;
        const uint16_t movCount = readLE<uint16_t>(animHdr + 64);
        visitor.beginAnimation(animHdr, movCount);

        for (uint16_t m = 0; m < movCount; ++m) {
            const uint8_t* movHdr = cur.take(layout.movementDataStructSize);
            if (!movHdr || !ValidateFixedCStringField(movHdr, 64, true)) return false;
            const uint16_t movBoneCount = readLE<uint16_t>(movHdr + 72);
            if (!visitor.beginMovement(movHdr, layout.movementDataStructSize, movBoneCount)) {
                return false;
            }

            for (uint16_t mb = 0; mb < movBoneCount; ++mb) {
                const uint8_t* mbHdr = cur.take(layout.movementBoneDataStructSize);
                if (!mbHdr || !ValidateFixedCStringField(mbHdr, 64, true)) return false;
                const uint16_t frameCount = readLE<uint16_t>(mbHdr + 64);
                visitor.beginMovBone(mbHdr, frameCount);

                for (uint16_t f = 0; f < frameCount; ++f) {
                    const uint8_t* fr = cur.take(layout.frameDataStructSize);
                    if (!fr || !ValidateFixedCStringField(fr + 40, 64, false) ||
                        !ValidateFixedCStringField(fr + 104, 64, false) ||
                        !visitor.onFrame(fr, layout.frameDataStructSize)) {
                        return false;
                    }
                }
                visitor.endMovBone();
            }
            visitor.endMovement();
        }
        visitor.endAnimation();
    }

    for (uint16_t t = 0; t < textureCount; ++t) {
        const uint8_t* texHdr = cur.take(layout.textureDataStructSize);
        if (!texHdr || !ValidateFixedCStringField(texHdr, 64, true)) return false;
        visitor.onTexture(texHdr);
    }

    if (cur.remaining() > 3) return false;
    for (size_t i = 0; i < cur.remaining(); ++i) {
        if (cur.ptr[i] != 0) return false;
    }
    return true;
}

// ============================================================================
// Unified Intermediate Armature Specs & C++20 Source Concept
// ============================================================================
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)

constexpr float kPi    = 3.14159265358979323846f;
constexpr float kTwoPi = 6.28318530717958647692f;

std::mutex g_armatureDataManagerMutex;

template <typename Fn>
void WithArmatureMgrLock(bool asyncLock, Fn&& fn) {
    if (asyncLock) {
        std::lock_guard<std::mutex> lock(g_armatureDataManagerMutex);
        fn();
    } else {
        fn();
    }
}

ax::backend::BlendFactor GlBlendToAxFactor(uint32_t glEnum) {
    switch (glEnum) {
        case 0u:      return ax::backend::BlendFactor::ZERO;
        case 1u:      return ax::backend::BlendFactor::ONE;
        case 0x0300u: return ax::backend::BlendFactor::SRC_COLOR;
        case 0x0301u: return ax::backend::BlendFactor::ONE_MINUS_SRC_COLOR;
        case 0x0302u: return ax::backend::BlendFactor::SRC_ALPHA;
        case 0x0303u: return ax::backend::BlendFactor::ONE_MINUS_SRC_ALPHA;
        case 0x0304u: return ax::backend::BlendFactor::DST_ALPHA;
        case 0x0305u: return ax::backend::BlendFactor::ONE_MINUS_DST_ALPHA;
        case 0x0306u: return ax::backend::BlendFactor::DST_COLOR;
        case 0x0307u: return ax::backend::BlendFactor::ONE_MINUS_DST_COLOR;
        default:      return ax::backend::BlendFactor::ONE;
    }
}

ax::BlendFunc MakeAxBlendFunc(uint32_t srcGl, uint32_t dstGl) {
    return ax::BlendFunc{GlBlendToAxFactor(srcGl), GlBlendToAxFactor(dstGl)};
}

std::string StripAssetExtension(const std::string& normalizedPath) {
    const size_t slashPos = normalizedPath.find_last_of('/');
    const size_t dotPos   = normalizedPath.find_last_of('.');
    if (dotPos == std::string::npos || (slashPos != std::string::npos && dotPos < slashPos)) {
        return normalizedPath;
    }
    return normalizedPath.substr(0, dotPos);
}

bool DoesAnyFileExist(const std::string& candidatePath) {
    if (candidatePath.empty()) return false;
    auto* fu = ax::FileUtils::getInstance();
    if (!fu) return false;
    const std::string full = fu->fullPathForFilename(candidatePath.c_str());
    return !full.empty() && fu->isFileExist(full);
}

bool IsValidNonEmptyXmlPlist(const std::string& candidatePath) {
    if (candidatePath.empty() || endsWithAsciiCI(candidatePath, ".plistb") ||
        !DoesAnyFileExist(candidatePath)) {
        return false;
    }
    unsigned long  sz  = 0;
    unsigned char* buf = LoadAndDecryptFileData(candidatePath, &sz, nullptr);
    if (!buf || sz == 0) {
        delete[] buf;
        return false;
    }
    const bool isXml = LooksLikePlaintextXml(buf, static_cast<size_t>(sz));
    delete[] buf;
    return isXml;
}

std::string ResolveParticlePlistPath(const std::string& rawPlist,
                                     const std::string& effectiveBase) {
    const std::string normRaw = NormalizeAssetPath(rawPlist);
    if (normRaw.empty() || effectiveBase.empty()) return normRaw;

    const std::string relCand = ResolveRelativeAssetPath(normRaw, effectiveBase);
    if (DoesAnyFileExist(relCand)) return relCand;
    if (DoesAnyFileExist(normRaw)) return normRaw;
    return relCand;
}

cocos2d::CCTexture2D* LoadExplicitTextureWithFallback(const std::string& imagePath,
                                                      const std::string& effectiveBase) {
    if (imagePath.empty()) return nullptr;
    auto* texCache = ax::Director::getInstance()->getTextureCache();
    if (!texCache) return nullptr;

    const std::string        normImg = NormalizeAssetPath(imagePath);
    std::vector<std::string> basePaths{normImg};
    if (!effectiveBase.empty()) {
        const std::string relImg = ResolveRelativeAssetPath(normImg, effectiveBase);
        if (relImg != normImg) basePaths.push_back(relImg);
    }

    if (auto* fu = ax::FileUtils::getInstance()) {
        for (const std::string& base : basePaths) {
            for (const std::string& cand : PlistbLoader::BuildTextureCandidatePaths(base)) {
                const std::string full = fu->fullPathForFilename(cand.c_str());
                if (!full.empty() && fu->isFileExist(full)) {
                    if (auto* tex = texCache->addImage(full.c_str())) return tex;
                }
            }
        }
    }
    for (const std::string& base : basePaths) {
        for (const std::string& cand : PlistbLoader::BuildTextureCandidatePaths(base)) {
            if (auto* tex = texCache->addImage(cand.c_str())) return tex;
        }
    }
    return nullptr;
}

bool TryLoadSpriteSheetCandidate(const std::string& sheetPath,
                                 cocos2d::CCTexture2D* explicitTex,
                                 std::unordered_set<std::string>& loadedSet) {
    const std::string normSheet = NormalizeAssetPath(sheetPath);
    if (normSheet.empty()) return false;
    if (loadedSet.contains(normSheet)) return true;

    if (PlistbLoader::AddSpriteFramesWithBinary(normSheet, explicitTex)) {
        loadedSet.insert(normSheet);
        loadedSet.insert(ReplaceFileExtension(normSheet, ".plistb"));
        loadedSet.insert(ReplaceFileExtension(normSheet, ".plist"));
        return true;
    }

    const std::string xmlPlistPath = endsWithAsciiCI(normSheet, ".plistb")
                                         ? normSheet.substr(0, normSheet.size() - 1)
                                         : normSheet;
    if (IsValidNonEmptyXmlPlist(xmlPlistPath)) {
        if (auto* sfc = ax::SpriteFrameCache::getInstance()) {
            if (explicitTex) {
                sfc->addSpriteFramesWithFile(xmlPlistPath.c_str(), explicitTex);
            } else {
                sfc->addSpriteFramesWithFile(xmlPlistPath.c_str());
            }
            loadedSet.insert(normSheet);
            loadedSet.insert(xmlPlistPath);
            return true;
        }
    }
    return false;
}

bool LoadResolvedSpriteSheet(const std::string& rawSheetPath,
                             const std::string& effectiveBase,
                             cocos2d::CCTexture2D* explicitTex,
                             std::unordered_set<std::string>& loadedSet) {
    const std::string normSheet = NormalizeAssetPath(rawSheetPath);
    if (normSheet.empty()) return false;
    if (!effectiveBase.empty()) {
        const std::string relResolved = ResolveRelativeAssetPath(normSheet, effectiveBase);
        if (!relResolved.empty() &&
            TryLoadSpriteSheetCandidate(relResolved, explicitTex, loadedSet)) {
            return true;
        }
    }
    return TryLoadSpriteSheetCandidate(normSheet, explicitTex, loadedSet);
}

void PreloadArmatureSpriteSheets(const std::string& normConfigPath,
                                 const std::string& effectiveBase,
                                 const std::string& plistPath,
                                 const std::string& imagePath,
                                 std::unordered_set<std::string>& loadedSet) {
    cocos2d::CCTexture2D* explicitTex = LoadExplicitTextureWithFallback(imagePath, effectiveBase);
    if (!plistPath.empty()) {
        LoadResolvedSpriteSheet(plistPath, effectiveBase, explicitTex, loadedSet);
    }

    const std::string dirAndStem =
        StripAssetExtension(effectiveBase.empty() ? normConfigPath : effectiveBase);
    if (dirAndStem.empty()) return;

    cocos2d::CCTexture2D* stemTex = plistPath.empty() ? explicitTex : nullptr;
    if (!TryLoadSpriteSheetCandidate(dirAndStem + ".plistb", stemTex, loadedSet)) {
        TryLoadSpriteSheetCandidate(dirAndStem + ".plist", stemTex, loadedSet);
    }

    for (int idx = 0; idx <= 9; ++idx) {
        const std::string numberedStem = dirAndStem + std::to_string(idx);
        if (!TryLoadSpriteSheetCandidate(numberedStem + ".plistb", nullptr, loadedSet) &&
            !TryLoadSpriteSheetCandidate(numberedStem + ".plist", nullptr, loadedSet)) {
            break;
        }
    }
}

void SanitizeArmatureBoneParents(cocos2d::extension::CCArmatureData* armData,
                                 const std::vector<cocos2d::extension::CCBoneData*>& bones,
                                 const std::string& configPath) {
    if (!armData) return;
    for (cocos2d::extension::CCBoneData* bone : bones) {
        if (!bone || bone->parentName.empty()) continue;

        if (bone->parentName == bone->name) {
            LogArmatureWarnFmt("Clearing self-parent on bone '%s' in armature '%s' (%s)",
                               bone->name.c_str(),
                               armData->name.c_str(),
                               configPath.c_str());
            bone->parentName.clear();
            continue;
        }
        if (armData->boneDataDic.find(bone->parentName) == armData->boneDataDic.end()) {
            LogArmatureWarnFmt("Clearing missing parent '%s' on bone '%s' in armature '%s' (%s)",
                               bone->parentName.c_str(),
                               bone->name.c_str(),
                               armData->name.c_str(),
                               configPath.c_str());
            bone->parentName.clear();
            continue;
        }

        std::unordered_set<std::string> visited{bone->name};
        std::string                     currParent = bone->parentName;
        while (!currParent.empty()) {
            if (!visited.insert(currParent).second) {
                LogArmatureWarnFmt(
                    "Breaking parent cycle at bone '%s' (parent '%s') in armature '%s' (%s)",
                    bone->name.c_str(),
                    bone->parentName.c_str(),
                    armData->name.c_str(),
                    configPath.c_str());
                bone->parentName.clear();
                break;
            }
            auto ancIt = armData->boneDataDic.find(currParent);
            auto* ancestor = (ancIt != armData->boneDataDic.end()) ? ancIt->second : nullptr;
            if (!ancestor) break;
            currParent = ancestor->parentName;
        }
    }
}

void EnsureDummyAnimationDataForArmatures(cocos2d::extension::CCArmatureDataManager* manager,
                                          const std::vector<std::string>& armatureNames,
                                          const std::string& normConfigPath,
                                          bool asyncLock) {
    if (!manager) return;
    std::unordered_set<std::string> seen;
    for (const std::string& name : armatureNames) {
        if (name.empty() || !seen.insert(name).second) continue;
        WithArmatureMgrLock(asyncLock, [&] {
            if (manager->getAnimationData(name.c_str()) == nullptr) {
                auto* dummyAnim = new cocos2d::extension::CCAnimationData();
                dummyAnim->name = name;
                manager->addAnimationData(name.c_str(), dummyAnim, normConfigPath.c_str());
                dummyAnim->release();
            }
        });
    }
}

void NormalizeMovementBoneSkew(cocos2d::extension::CCMovementBoneData* movBoneData) {
    if (!movBoneData || movBoneData->frameList.size() < 2) return;
    for (int i = static_cast<int>(movBoneData->frameList.size()) - 1; i > 0; --i) {
        auto* curr = static_cast<cocos2d::extension::CCFrameData*>(movBoneData->frameList.at(i));
        auto* prev =
            static_cast<cocos2d::extension::CCFrameData*>(movBoneData->frameList.at(i - 1));
        if (!curr || !prev) continue;

        const float diffX = curr->skewX - prev->skewX;
        if (diffX < -kPi || diffX > kPi) prev->skewX += (diffX < 0.0f) ? -kTwoPi : kTwoPi;

        const float diffY = curr->skewY - prev->skewY;
        if (diffY < -kPi || diffY > kPi) prev->skewY += (diffY < 0.0f) ? -kTwoPi : kTwoPi;
    }
}

void AppendClosingFrame(cocos2d::extension::CCMovementBoneData* movBoneData) {
    if (!movBoneData || movBoneData->frameList.empty()) return;
    auto* lastFrame = static_cast<cocos2d::extension::CCFrameData*>(movBoneData->frameList.back());
    if (!lastFrame) return;

    auto* closingFrame = new cocos2d::extension::CCFrameData();
    closingFrame->copy(lastFrame);
    closingFrame->frameID = static_cast<int>(movBoneData->duration);
    movBoneData->addFrameData(closingFrame);
    closingFrame->release();
}

struct ArmatureDisplaySpec {
    int32_t     displayType = 0;
    std::string name;
    bool        hasSkin     = false;
    float       skinX       = 0.0f;
    float       skinY       = 0.0f;
    float       skinScaleX  = 1.0f;
    float       skinScaleY  = 1.0f;
    float       skinSkewX   = 0.0f;
    float       skinSkewY   = 0.0f;
};

struct ArmatureBoneSpec {
    std::string                      name;
    std::string                      parentName;
    float                            x      = 0.0f;
    float                            y      = 0.0f;
    int                              zOrder = 0;
    float                            scaleX = 1.0f;
    float                            scaleY = 1.0f;
    float                            skewX  = 0.0f;
    float                            skewY  = 0.0f;
    bool                             hasColor = false;
    uint8_t                          r = 255, g = 255, b = 255, a = 255;
    std::vector<ArmatureDisplaySpec> displays;
};

struct ArmatureDefSpec {
    std::string                   name;
    bool                          hasVersion = false;
    float                         version    = 0.0f;
    std::vector<ArmatureBoneSpec> bones;
};

struct ResolvedFrameSpec {
    XmlbDecodedFrameRecord rec;
    int                    frameId = 0;
};

struct ArmatureMovBoneSpec {
    std::string                    name;
    float                          delay              = 0.0f;
    float                          computedDuration   = 0.0f;
    bool                           appendClosingFrame = false;
    std::vector<ResolvedFrameSpec> frames;
};

struct ArmatureMovSpec {
    std::string                      name;
    int32_t                          duration      = 0;
    int32_t                          durationTo    = 0;
    int32_t                          durationTween = 0;
    bool                             loop          = false;
    int32_t                          tweenEasing   = 0;
    float                            scale         = 1.0f;
    std::vector<ArmatureMovBoneSpec> movBones;
};

struct ArmatureAnimSpec {
    std::string                  name;
    std::vector<ArmatureMovSpec> movements;
};

struct ArmatureTexSpec {
    std::string                                    name;
    std::string                                    plistFile;
    bool                                           hasDimensions = false;
    float                                          width         = 0.0f;
    float                                          height        = 0.0f;
    float                                          pivotX        = 0.0f;
    float                                          pivotY        = 0.0f;
    std::vector<std::vector<std::pair<float, float>>> contours;
};

template <typename S>
concept ArmatureSkeletonSource = requires(S& src,
                                          std::vector<std::string>& extraSheets,
                                          std::vector<ArmatureDefSpec>& armatures,
                                          std::vector<ArmatureAnimSpec>& animations,
                                          std::vector<ArmatureTexSpec>& textures) {
    { src.alwaysPreloadSheets() } -> std::same_as<bool>;
    { src.useEffectiveBaseForParticles() } -> std::same_as<bool>;
    { src.extract(extraSheets, armatures, animations, textures) } -> std::same_as<bool>;
};

template <ArmatureSkeletonSource SourceT>
bool PopulateArmatureManagerFromSource(SourceT& src,
                                       const std::string& configFilePath,
                                       const std::string& baseFilePath,
                                       bool asyncLock,
                                       const std::string& plistPath,
                                       const std::string& imagePath) {
    auto* manager = cocostudio::ArmatureDataManager::getInstance();
    if (!manager) return false;

    std::vector<std::string>      extraSheets;
    std::vector<ArmatureDefSpec>  armatures;
    std::vector<ArmatureAnimSpec> animations;
    std::vector<ArmatureTexSpec>  textures;
    if (!src.extract(extraSheets, armatures, animations, textures)) {
        return false;
    }

    const std::string normConfigPath = NormalizeAssetPath(configFilePath);
    const std::string effectiveBase =
        baseFilePath.empty() ? normConfigPath : NormalizeAssetPath(baseFilePath);
    const std::string& particleBase =
        src.useEffectiveBaseForParticles() ? effectiveBase : normConfigPath;

    std::unordered_set<std::string> loadedSheets;
    if (src.alwaysPreloadSheets() || !normConfigPath.empty() || !effectiveBase.empty() ||
        !plistPath.empty() || !imagePath.empty()) {
        PreloadArmatureSpriteSheets(
            normConfigPath, effectiveBase, plistPath, imagePath, loadedSheets);
    }
    for (const std::string& extra : extraSheets) {
        LoadResolvedSpriteSheet(extra, effectiveBase, nullptr, loadedSheets);
    }

    std::vector<std::string> armatureNamesForAnimGuard;

    for (const ArmatureDefSpec& armSpec : armatures) {
        if (armSpec.name.empty()) continue;

        auto* armData = new cocos2d::extension::CCArmatureData();
        armData->init();
        armData->name = armSpec.name;
        if (armSpec.hasVersion) armData->dataVersion = armSpec.version;
        armatureNamesForAnimGuard.push_back(armData->name);

        std::vector<cocos2d::extension::CCBoneData*> addedBones;
        addedBones.reserve(armSpec.bones.size());

        for (const ArmatureBoneSpec& boneSpec : armSpec.bones) {
            if (boneSpec.name.empty()) continue;

            auto* boneData       = new cocos2d::extension::CCBoneData();
            boneData->init();
            boneData->name       = boneSpec.name;
            boneData->parentName = boneSpec.parentName;
            boneData->x          = boneSpec.x;
            boneData->y          = boneSpec.y;
            boneData->zOrder     = boneSpec.zOrder;
            boneData->scaleX     = boneSpec.scaleX;
            boneData->scaleY     = boneSpec.scaleY;
            boneData->skewX      = boneSpec.skewX;
            boneData->skewY      = boneSpec.skewY;
            if (boneSpec.hasColor) {
                boneData->isUseColorInfo = true;
                boneData->r              = boneSpec.r;
                boneData->g              = boneSpec.g;
                boneData->b              = boneSpec.b;
                boneData->a              = boneSpec.a;
            }

            for (const ArmatureDisplaySpec& dispSpec : boneSpec.displays) {
                cocos2d::extension::CCDisplayData* dispData = nullptr;
                if (dispSpec.displayType == cocos2d::extension::CS_DISPLAY_SPRITE) {
                    auto* sprDisp        = new cocos2d::extension::CCSpriteDisplayData();
                    sprDisp->displayType = cocos2d::extension::CS_DISPLAY_SPRITE;
                    sprDisp->displayName = dispSpec.name;
                    if (dispSpec.hasSkin) {
                        sprDisp->skinData.x      = dispSpec.skinX;
                        sprDisp->skinData.y      = dispSpec.skinY;
                        sprDisp->skinData.scaleX = dispSpec.skinScaleX;
                        sprDisp->skinData.scaleY = dispSpec.skinScaleY;
                        sprDisp->skinData.skewX  = dispSpec.skinSkewX;
                        sprDisp->skinData.skewY  = dispSpec.skinSkewY;
                    }
                    dispData = sprDisp;
                } else if (dispSpec.displayType == cocos2d::extension::CS_DISPLAY_ARMATURE) {
                    auto* armDisp        = new cocos2d::extension::CCArmatureDisplayData();
                    armDisp->displayType = cocos2d::extension::CS_DISPLAY_ARMATURE;
                    armDisp->displayName = dispSpec.name;
                    if (!armDisp->displayName.empty()) {
                        armatureNamesForAnimGuard.push_back(armDisp->displayName);
                    }
                    dispData = armDisp;
                } else if (dispSpec.displayType == cocos2d::extension::CS_DISPLAY_PARTICLE) {
                    auto* partDisp        = new cocos2d::extension::CCParticleDisplayData();
                    partDisp->displayType = cocos2d::extension::CS_DISPLAY_PARTICLE;
                    if (!dispSpec.name.empty()) {
                        partDisp->displayName =
                            ResolveParticlePlistPath(dispSpec.name, particleBase);
                    }
                    dispData = partDisp;
                }
                if (dispData) {
                    boneData->addDisplayData(dispData);
                    dispData->release();
                }
            }

            armData->addBoneData(boneData);
            addedBones.push_back(boneData);
            boneData->release();
        }

        SanitizeArmatureBoneParents(armData, addedBones, normConfigPath);
        WithArmatureMgrLock(asyncLock, [&] {
            manager->addArmatureData(armData->name.c_str(), armData, normConfigPath.c_str());
        });
        armData->release();
    }

    for (const ArmatureAnimSpec& animSpec : animations) {
        if (animSpec.name.empty()) continue;

        auto* animData = new cocos2d::extension::CCAnimationData();
        animData->name = animSpec.name;

        for (const ArmatureMovSpec& movSpec : animSpec.movements) {
            if (movSpec.name.empty()) continue;

            auto* movData          = new cocos2d::extension::CCMovementData();
            movData->name          = movSpec.name;
            movData->duration      = movSpec.duration;
            movData->loop          = movSpec.loop;
            movData->durationTo    = movSpec.durationTo;
            movData->durationTween = movSpec.durationTween;
            movData->tweenEasing =
                static_cast<cocos2d::extension::CCTweenType>(movSpec.tweenEasing);
            movData->scale =
                (std::isfinite(movSpec.scale) && movSpec.scale > 0.0f) ? movSpec.scale : 1.0f;

            int maxBoneDuration = 0;

            for (const ArmatureMovBoneSpec& mbSpec : movSpec.movBones) {
                if (mbSpec.name.empty() || mbSpec.frames.empty()) continue;

                auto* movBoneData     = new cocos2d::extension::CCMovementBoneData();
                movBoneData->init();
                movBoneData->name     = mbSpec.name;
                movBoneData->delay    = mbSpec.delay;
                movBoneData->duration = mbSpec.computedDuration;

                for (const ResolvedFrameSpec& rf : mbSpec.frames) {
                    const XmlbDecodedFrameRecord& d = rf.rec;
                    auto* frameData                 = new cocos2d::extension::CCFrameData();
                    frameData->x                    = d.x;
                    frameData->y                    = d.y;
                    frameData->scaleX               = d.scaleX;
                    frameData->scaleY               = d.scaleY;
                    frameData->skewX                = d.skewX;
                    frameData->skewY                = d.skewY;
                    frameData->tweenRotate          = d.tweenRotate;
                    frameData->duration             = d.duration;
                    frameData->a                    = d.a;
                    frameData->r                    = d.r;
                    frameData->g                    = d.g;
                    frameData->b                    = d.b;
                    frameData->zOrder               = d.zOrder;
                    frameData->isUseColorInfo       = d.isUseColorInfo;
                    frameData->tweenEasing =
                        static_cast<cocos2d::extension::CCTweenType>(d.tweenEasing);
                    frameData->isTween      = d.isTween;
                    frameData->displayIndex = d.displayIndex;
                    frameData->blendFunc    = MakeAxBlendFunc(d.blendSrc, d.blendDst);
                    frameData->strEvent     = d.strEvent;
                    frameData->strMovement  = d.strMovement;
                    frameData->frameID      = rf.frameId;

                    movBoneData->addFrameData(frameData);
                    frameData->release();
                }

                if (movBoneData->frameList.empty()) {
                    movBoneData->release();
                    continue;
                }

                NormalizeMovementBoneSkew(movBoneData);
                if (mbSpec.appendClosingFrame) AppendClosingFrame(movBoneData);
                maxBoneDuration =
                    std::max(maxBoneDuration, static_cast<int>(movBoneData->duration));

                movData->addMovementBoneData(movBoneData);
                movBoneData->release();
            }

            if (movData->duration < 1) movData->duration = std::max(1, maxBoneDuration);
            animData->addMovement(movData);
            movData->release();
        }

        WithArmatureMgrLock(asyncLock, [&] {
            manager->addAnimationData(animData->name.c_str(), animData, normConfigPath.c_str());
        });
        animData->release();
    }

    EnsureDummyAnimationDataForArmatures(
        manager, armatureNamesForAnimGuard, normConfigPath, asyncLock);

    for (const ArmatureTexSpec& texSpec : textures) {
        if (texSpec.name.empty()) continue;
        if (!texSpec.plistFile.empty()) {
            LoadResolvedSpriteSheet(texSpec.plistFile, effectiveBase, nullptr, loadedSheets);
        }

        auto* texData = new cocos2d::extension::CCTextureData();
        texData->init();
        texData->name = texSpec.name;
        if (texSpec.hasDimensions) {
            texData->width  = texSpec.width;
            texData->height = texSpec.height;
        }
        texData->pivotX = texSpec.pivotX;
        texData->pivotY = texSpec.pivotY;

        for (const auto& verts : texSpec.contours) {
            if (verts.size() < 3) continue;
            auto* contour = new cocos2d::extension::CCContourData();
            contour->init();
            for (const auto& [vx, vy] : verts) {
                contour->vertexList.emplace_back(vx, vy);
            }
            texData->addContourData(contour);
            contour->release();
        }

        WithArmatureMgrLock(asyncLock, [&] {
            manager->addTextureData(texData->name.c_str(), texData, normConfigPath.c_str());
        });
        texData->release();
    }
    return true;
}

#if defined(GCLIENT_XMLB_HAS_PROTOBUF)
template <typename PbT>
void CopyPbTransform2D(const PbT& pb,
                       float contentScale,
                       float& x,
                       float& y,
                       float& scaleX,
                       float& scaleY,
                       float& skewX,
                       float& skewY) {
    x      = pb.x() * contentScale;
    y      = pb.y() * contentScale;
    scaleX = pb.has_cx() ? pb.cx() : 1.0f;
    scaleY = pb.has_cy() ? pb.cy() : 1.0f;
    skewX  = pb.kx();
    skewY  = pb.ky();
}

void ApplyPbArmatureColor(const ArmatureColor& c,
                          bool& hasColor,
                          uint8_t& r,
                          uint8_t& g,
                          uint8_t& b,
                          uint8_t& a) {
    hasColor = true;
    r        = XmlbArmatureLoader::ClampColorChannel(c.has_r() ? c.r() : 255);
    g        = XmlbArmatureLoader::ClampColorChannel(c.has_g() ? c.g() : 255);
    b        = XmlbArmatureLoader::ClampColorChannel(c.has_b() ? c.b() : 255);
    a        = XmlbArmatureLoader::ClampColorChannel(c.has_a() ? c.a() : 255);
}

struct ProtoArmatureSource {
    const ArmatureRoot& root;

    constexpr bool alwaysPreloadSheets() const noexcept { return true; }
    constexpr bool useEffectiveBaseForParticles() const noexcept { return true; }

    bool extract(std::vector<std::string>& extraSheets,
                 std::vector<ArmatureDefSpec>& armatures,
                 std::vector<ArmatureAnimSpec>& animations,
                 std::vector<ArmatureTexSpec>& textures) {
        const float rawScale = root.has_content_scale() ? root.content_scale() : 1.0f;
        const float contentScale =
            (std::isfinite(rawScale) && rawScale > 0.0f) ? rawScale : 1.0f;

        extraSheets.reserve(static_cast<size_t>(root.config_file_path_size()));
        for (int i = 0; i < root.config_file_path_size(); ++i) {
            extraSheets.push_back(root.config_file_path(i));
        }

        armatures.reserve(static_cast<size_t>(root.armature_data_size()));
        for (int i = 0; i < root.armature_data_size(); ++i) {
            const ArmatureData& pbArm = root.armature_data(i);
            if (pbArm.name().empty()) continue;

            ArmatureDefSpec armSpec;
            armSpec.name       = pbArm.name();
            armSpec.hasVersion = true;
            armSpec.version    = pbArm.version();
            armSpec.bones.reserve(static_cast<size_t>(pbArm.bone_data_size()));

            for (int b = 0; b < pbArm.bone_data_size(); ++b) {
                const ArmatureBoneData& pbBone = pbArm.bone_data(b);
                if (pbBone.name().empty()) continue;

                ArmatureBoneSpec boneSpec;
                boneSpec.name       = pbBone.name();
                boneSpec.parentName = pbBone.parent();
                boneSpec.zOrder = static_cast<int>(pbBone.z());
                CopyPbTransform2D(pbBone, contentScale, boneSpec.x, boneSpec.y, boneSpec.scaleX, boneSpec.scaleY, boneSpec.skewX, boneSpec.skewY);
                if (pbBone.has_color()) {
                    ApplyPbArmatureColor(pbBone.color(), boneSpec.hasColor, boneSpec.r, boneSpec.g, boneSpec.b, boneSpec.a);
                }

                boneSpec.displays.reserve(static_cast<size_t>(pbBone.display_data_size()));
                for (int d = 0; d < pbBone.display_data_size(); ++d) {
                    const ArmatureDisplayData& pbDisp = pbBone.display_data(d);
                    ArmatureDisplaySpec        dispSpec;
                    dispSpec.displayType =
                        pbDisp.has_displaytype()
                            ? pbDisp.displaytype()
                            : static_cast<int32_t>(cocos2d::extension::CS_DISPLAY_SPRITE);
                    if (dispSpec.displayType == cocos2d::extension::CS_DISPLAY_PARTICLE) {
                        dispSpec.name =
                            (pbDisp.has_plist() && !pbDisp.plist().empty())
                                ? pbDisp.plist()
                                : (pbDisp.has_name() ? pbDisp.name() : std::string());
                    } else if (pbDisp.has_name()) {
                        dispSpec.name = pbDisp.name();
                    }
                    if (dispSpec.displayType == cocos2d::extension::CS_DISPLAY_SPRITE &&
                        pbDisp.skin_data_size() > 0) {
                        dispSpec.hasSkin = true;
                        CopyPbTransform2D(pbDisp.skin_data(0), contentScale, dispSpec.skinX, dispSpec.skinY, dispSpec.skinScaleX, dispSpec.skinScaleY, dispSpec.skinSkewX, dispSpec.skinSkewY);
                    }
                    boneSpec.displays.push_back(std::move(dispSpec));
                }
                armSpec.bones.push_back(std::move(boneSpec));
            }
            armatures.push_back(std::move(armSpec));
        }

        animations.reserve(static_cast<size_t>(root.animation_data_size()));
        for (int i = 0; i < root.animation_data_size(); ++i) {
            const ArmatureAnimationData& pbAnim = root.animation_data(i);
            if (pbAnim.name().empty()) continue;

            ArmatureAnimSpec animSpec;
            animSpec.name = pbAnim.name();
            animSpec.movements.reserve(static_cast<size_t>(pbAnim.mov_data_size()));

            for (int m = 0; m < pbAnim.mov_data_size(); ++m) {
                const ArmatureMovData& pbMov = pbAnim.mov_data(m);
                if (pbMov.name().empty()) continue;

                ArmatureMovSpec movSpec;
                movSpec.name          = pbMov.name();
                movSpec.duration      = pbMov.dr();
                movSpec.loop          = pbMov.lp();
                movSpec.durationTo    = std::max(0, pbMov.to());
                movSpec.durationTween = std::max(0, pbMov.drtw());
                movSpec.tweenEasing   = (pbMov.twe() == 2) ? 3 : pbMov.twe();
                movSpec.scale         = pbMov.has_sc() ? pbMov.sc() : 1.0f;
                movSpec.movBones.reserve(static_cast<size_t>(pbMov.mov_bone_data_size()));

                for (int mb = 0; mb < pbMov.mov_bone_data_size(); ++mb) {
                    const ArmatureMovBoneData& pbMovBone = pbMov.mov_bone_data(mb);
                    if (pbMovBone.name().empty() || pbMovBone.frame_data_size() == 0) continue;

                    ArmatureMovBoneSpec mbSpec;
                    mbSpec.name  = pbMovBone.name();
                    mbSpec.delay = pbMovBone.dl();
                    mbSpec.frames.reserve(static_cast<size_t>(pbMovBone.frame_data_size()));

                    int      cumulativeDuration    = 0;
                    int      nextSequentialFrameId = 0;
                    bool     hasStickyBlend        = false;
                    uint32_t stickySrc = 1u, stickyDst = 0x0303u;

                    for (int f = 0; f < pbMovBone.frame_data_size(); ++f) {
                        const ArmatureFrameData& pbFrame = pbMovBone.frame_data(f);
                        ResolvedFrameSpec        rf;
                        XmlbDecodedFrameRecord&  rec = rf.rec;

                        rec.displayIndex = pbFrame.di();
                        rec.zOrder       = pbFrame.z();
                        CopyPbTransform2D(pbFrame, contentScale, rec.x, rec.y, rec.scaleX, rec.scaleY, rec.skewX, rec.skewY);
                        rec.tweenEasing  = (pbFrame.twe() == 2) ? 3 : pbFrame.twe();
                        rec.isTween      = pbFrame.has_tweenframe() ? pbFrame.tweenframe() : true;
                        rec.duration     = pbFrame.has_dr()
                                               ? ((pbFrame.dr() >= 0) ? pbFrame.dr() : 1)
                                               : 1;

                        rf.frameId = (pbFrame.has_fi() && pbFrame.fi() >= 0)
                                         ? pbFrame.fi()
                                         : nextSequentialFrameId;
                        const int64_t nextSeq64 =
                            static_cast<int64_t>(rf.frameId) +
                            static_cast<int64_t>((rec.duration > 0) ? rec.duration : 1);
                        nextSequentialFrameId =
                            static_cast<int>(std::min<int64_t>(nextSeq64, 0x7FFFFFFFLL));

                        if (pbFrame.has_evt()) rec.strEvent = pbFrame.evt();

                        if (pbFrame.has_bd()) {
                            uint32_t s = 1u, d = 0x0303u;
                            switch (static_cast<cocos2d::extension::CCBlendType>(pbFrame.bd())) {
                                case cocos2d::extension::BLEND_LAYER:
                                case cocos2d::extension::BLEND_ADD:
                                    s = 1u; d = 1u;
                                    break;
                                case cocos2d::extension::BLEND_MULTIPLY:
                                    s = 0x0306u; d = 0x0303u;
                                    break;
                                case cocos2d::extension::BLEND_SCREEN:
                                    s = 1u; d = 0x0301u;
                                    break;
                                default:
                                    break;
                            }
                            rec.blendSrc = s;
                            rec.blendDst = d;
                            if (pbFrame.bd() != 0) {
                                hasStickyBlend = true;
                                stickySrc      = s;
                                stickyDst      = d;
                            }
                        } else {
                            ApplyStickyBlendPair(rec.strEvent == "1",
                                                 1u,
                                                 1u,
                                                 &hasStickyBlend,
                                                 &stickySrc,
                                                 &stickyDst,
                                                 &rec.blendSrc,
                                                 &rec.blendDst);
                        }

                        if (pbFrame.has_color()) {
                            ApplyPbArmatureColor(pbFrame.color(), rec.isUseColorInfo, rec.r, rec.g, rec.b, rec.a);
                        }

                        const int64_t cum64 =
                            static_cast<int64_t>(cumulativeDuration) +
                            static_cast<int64_t>(rec.duration);
                        cumulativeDuration =
                            static_cast<int>(std::min<int64_t>(cum64, 0x7FFFFFFFLL));
                        const int64_t span64 =
                            static_cast<int64_t>(rf.frameId) + static_cast<int64_t>(rec.duration);
                        const int clampedSpan =
                            static_cast<int>(std::min<int64_t>(span64, 0x7FFFFFFFLL));
                        mbSpec.computedDuration =
                            static_cast<float>(std::max(cumulativeDuration, clampedSpan));

                        mbSpec.frames.push_back(std::move(rf));
                    }
                    movSpec.movBones.push_back(std::move(mbSpec));
                }
                animSpec.movements.push_back(std::move(movSpec));
            }
            animations.push_back(std::move(animSpec));
        }

        textures.reserve(static_cast<size_t>(root.texture_data_size()));
        for (int i = 0; i < root.texture_data_size(); ++i) {
            const ArmatureTextureData& pbTex = root.texture_data(i);
            if (pbTex.name().empty()) continue;

            ArmatureTexSpec texSpec;
            texSpec.name          = pbTex.name();
            texSpec.plistFile     = pbTex.has_plistfile() ? pbTex.plistfile() : std::string();
            texSpec.hasDimensions = true;
            texSpec.width         = pbTex.width();
            texSpec.height        = pbTex.height();
            texSpec.pivotX        = pbTex.px();
            texSpec.pivotY        = pbTex.py();

            for (int c = 0; c < pbTex.contour_data_size(); ++c) {
                const ArmatureContourData& pbContour = pbTex.contour_data(c);
                if (pbContour.vertex_size() < 3) continue;
                std::vector<std::pair<float, float>> verts;
                verts.reserve(static_cast<size_t>(pbContour.vertex_size()));
                for (int v = 0; v < pbContour.vertex_size(); ++v) {
                    const ArmatureVertex& pbV = pbContour.vertex(v);
                    verts.emplace_back(pbV.x() * contentScale, pbV.y() * contentScale);
                }
                texSpec.contours.push_back(std::move(verts));
            }
            textures.push_back(std::move(texSpec));
        }
        return true;
    }
};
#endif // GCLIENT_XMLB_HAS_PROTOBUF

struct BitCacheArmatureSource {
    const uint8_t*            data = nullptr;
    size_t                    size = 0;
    const XmlbBitCacheLayout& layout;

    constexpr bool alwaysPreloadSheets() const noexcept { return false; }
    constexpr bool useEffectiveBaseForParticles() const noexcept { return false; }

    bool extract(std::vector<std::string>& /*extraSheets*/,
                 std::vector<ArmatureDefSpec>& armatures,
                 std::vector<ArmatureAnimSpec>& animations,
                 std::vector<ArmatureTexSpec>& textures) {
        struct Collector : NoopBitCacheVisitor {
            const XmlbBitCacheLayout&      layout;
            std::vector<ArmatureDefSpec>&  armatures;
            std::vector<ArmatureAnimSpec>& animations;
            std::vector<ArmatureTexSpec>&  textures;

            ArmatureDefSpec     curArm;
            ArmatureBoneSpec    curBone;
            ArmatureAnimSpec    curAnim;
            ArmatureMovSpec     curMov;
            ArmatureMovBoneSpec curMb;
            int                 cumulativeFrameId = 0;
            bool                hasStickyBlend    = false;
            uint32_t            stickySrc = 1u, stickyDst = 0x0303u;

            Collector(const XmlbBitCacheLayout& l,
                      std::vector<ArmatureDefSpec>& a,
                      std::vector<ArmatureAnimSpec>& an,
                      std::vector<ArmatureTexSpec>& t)
                : layout(l), armatures(a), animations(an), textures(t) {}

            void onCounts(uint16_t ac, uint16_t anc, uint16_t tc) {
                armatures.reserve(ac);
                animations.reserve(anc);
                textures.reserve(tc);
            }
            void beginArmature(const uint8_t* hdr, uint16_t boneCount) {
                curArm      = {};
                curArm.name = ReadBoundedCString(hdr, 64);
                curArm.bones.reserve(boneCount);
            }
            void beginBone(const uint8_t* hdr, uint16_t dispCount) {
                curBone        = {};
                curBone.name   = ReadBoundedCString(hdr, 64);
                curBone.zOrder = static_cast<int>(static_cast<int8_t>(hdr[64]));
                curBone.displays.reserve(dispCount);
            }
            void onDisplay(const uint8_t* hdr) {
                curBone.displays.push_back(
                    ArmatureDisplaySpec{static_cast<int32_t>(hdr[0]), ReadBoundedCString(hdr + 1, 64)});
            }
            void endBone() { curArm.bones.push_back(std::move(curBone)); }
            void endArmature() { armatures.push_back(std::move(curArm)); }

            void beginAnimation(const uint8_t* hdr, uint16_t movCount) {
                curAnim      = {};
                curAnim.name = ReadBoundedCString(hdr, 64);
                curAnim.movements.reserve(movCount);
            }
            bool beginMovement(const uint8_t* hdr, size_t avail, uint16_t mbCount) {
                XmlbDecodedMovementHeader dec;
                if (!XmlbArmatureLoader::DecodeBitCacheMovementHeader(hdr, avail, &dec, layout)) {
                    return false;
                }
                curMov               = {};
                curMov.name          = std::move(dec.name);
                curMov.duration      = dec.duration;
                curMov.durationTo    = dec.durationTo;
                curMov.durationTween = dec.durationTween;
                curMov.loop          = dec.loop;
                curMov.tweenEasing   = dec.tweenEasing;
                curMov.scale         = 1.0f;
                curMov.movBones.reserve(mbCount);
                return true;
            }
            void beginMovBone(const uint8_t* hdr, uint16_t frameCount) {
                curMb                    = {};
                curMb.name               = ReadBoundedCString(hdr, 64);
                curMb.appendClosingFrame = true;
                curMb.frames.reserve(frameCount);
                cumulativeFrameId = 0;
                hasStickyBlend    = false;
                stickySrc         = 1u;
                stickyDst         = 0x0303u;
            }
            bool onFrame(const uint8_t* fr, size_t avail) {
                ResolvedFrameSpec rf;
                if (!XmlbArmatureLoader::DecodeBitCacheFrameRecord(
                        fr, avail, &hasStickyBlend, &stickySrc, &stickyDst, &rf.rec, layout)) {
                    return false;
                }
                rf.frameId = cumulativeFrameId;
                cumulativeFrameId += rf.rec.duration;
                curMb.computedDuration = static_cast<float>(cumulativeFrameId);
                curMb.frames.push_back(std::move(rf));
                return true;
            }
            void endMovBone() { curMov.movBones.push_back(std::move(curMb)); }
            void endMovement() { curAnim.movements.push_back(std::move(curMov)); }
            void endAnimation() { animations.push_back(std::move(curAnim)); }

            void onTexture(const uint8_t* hdr) {
                ArmatureTexSpec tex;
                tex.name   = ReadBoundedCString(hdr, 64);
                tex.pivotX = static_cast<float>(readLE<int16_t>(hdr + 64)) * 0.001f;
                tex.pivotY = static_cast<float>(readLE<int16_t>(hdr + 66)) * 0.001f;
                textures.push_back(std::move(tex));
            }
        };

        return WalkBitCacheStream(data, size, layout, Collector(layout, armatures, animations, textures));
    }
};

#endif // GCLIENT_ENABLE_COCOS2DX

} // namespace

uint8_t XmlbArmatureLoader::ClampColorChannel(int32_t value) {
    return static_cast<uint8_t>(std::clamp(value, 0, 255));
}

int32_t XmlbArmatureLoader::DecodeBitCacheTweenEasing(int8_t rawEasing) {
    return (rawEasing == 2) ? 3 : static_cast<int32_t>(rawEasing);
}

void XmlbArmatureLoader::MapBlendTypeToGL(uint8_t rawBlend, uint32_t* outSrc, uint32_t* outDst) {
    uint32_t src = 0x0001u, dst = 0x0303u; // GL_ONE, GL_ONE_MINUS_SRC_ALPHA
    switch (rawBlend) {
        case 1:
        case 8: src = 0x0001u; dst = 0x0001u; break; // Premultiplied ADD
        case 2: src = 0x0306u; dst = 0x0303u; break; // MULTIPLY
        case 3:
        case 5: src = 0x0001u; dst = 0x0301u; break; // SCREEN
        default: break;
    }
    if (outSrc) *outSrc = src;
    if (outDst) *outDst = dst;
}

bool XmlbArmatureLoader::DecodeBitCacheMovementHeader(const uint8_t* movHdr,
                                                      size_t availBytes,
                                                      XmlbDecodedMovementHeader* outMov,
                                                      const XmlbBitCacheLayout& layout) {
    if (!movHdr || !outMov || layout.movementDataStructSize < 74 ||
        availBytes < layout.movementDataStructSize) {
        return false;
    }
    outMov->name          = ReadBoundedCString(movHdr, 64);
    outMov->duration      = static_cast<int32_t>(readLE<int16_t>(movHdr + 64));
    outMov->durationTo    = std::max(0, static_cast<int32_t>(readLE<int16_t>(movHdr + 66)));
    outMov->durationTween = std::max(0, static_cast<int32_t>(readLE<int16_t>(movHdr + 68)));
    outMov->loop          = (movHdr[70] != 0);
    outMov->tweenEasing   = DecodeBitCacheTweenEasing(static_cast<int8_t>(movHdr[71]));
    outMov->movBoneCount  = readLE<uint16_t>(movHdr + 72);
    return true;
}

bool XmlbArmatureLoader::DecodeBitCacheFrameRecord(const uint8_t* fr,
                                                   size_t availBytes,
                                                   bool* ioHasStickyBlend,
                                                   uint32_t* ioStickyBlendSrc,
                                                   uint32_t* ioStickyBlendDst,
                                                   XmlbDecodedFrameRecord* outFrame,
                                                   const XmlbBitCacheLayout& layout) {
    if (!fr || !outFrame || layout.frameDataStructSize < 168 ||
        availBytes < layout.frameDataStructSize) {
        return false;
    }
    auto fixedFrac = [&](size_t intOff, size_t milliOff) -> float {
        return static_cast<float>(readLE<int16_t>(fr + intOff) +
                                  readLE<int16_t>(fr + milliOff) * 0.001);
    };
    outFrame->x              = fixedFrac(0, 4);
    outFrame->y              = fixedFrac(2, 6);
    outFrame->scaleX         = fixedFrac(8, 12);
    outFrame->scaleY         = fixedFrac(10, 14);
    outFrame->skewX          = static_cast<float>(readLE<int16_t>(fr + 16)) * 0.001f;
    outFrame->skewY          = static_cast<float>(readLE<int16_t>(fr + 18)) * 0.001f;
    outFrame->tweenRotate    = fixedFrac(20, 22);
    outFrame->duration       = std::max(0, static_cast<int32_t>(readLE<int16_t>(fr + 24)));
    outFrame->a              = ClampColorChannel(readLE<int16_t>(fr + 26));
    outFrame->r              = ClampColorChannel(readLE<int16_t>(fr + 28));
    outFrame->g              = ClampColorChannel(readLE<int16_t>(fr + 30));
    outFrame->b              = ClampColorChannel(readLE<int16_t>(fr + 32));
    outFrame->zOrder         = static_cast<int32_t>(static_cast<int8_t>(fr[34]));
    outFrame->isUseColorInfo = (fr[35] != 0);
    outFrame->tweenEasing    = DecodeBitCacheTweenEasing(static_cast<int8_t>(fr[36]));
    outFrame->isTween        = (fr[37] != 0);
    outFrame->rawBlendType   = fr[38];
    outFrame->displayIndex   = static_cast<int32_t>(static_cast<int8_t>(fr[39]));
    outFrame->strEvent       = ReadBoundedCString(fr + 40, 64);
    outFrame->strMovement    = ReadBoundedCString(fr + 104, 64);

    const uint8_t effBlend =
        (outFrame->rawBlendType == 0 && outFrame->strEvent == "1") ? 1u : outFrame->rawBlendType;
    uint32_t candSrc = 1u, candDst = 0x0303u;
    if (effBlend != 0) MapBlendTypeToGL(effBlend, &candSrc, &candDst);
    ApplyStickyBlendPair(effBlend != 0,
                         candSrc,
                         candDst,
                         ioHasStickyBlend,
                         ioStickyBlendSrc,
                         ioStickyBlendDst,
                         &outFrame->blendSrc,
                         &outFrame->blendDst);
    return true;
}

bool XmlbArmatureLoader::ValidateBitCacheBuffer(const uint8_t* bitCacheData,
                                                size_t bitCacheSize,
                                                const XmlbBitCacheLayout& layout) {
    return WalkBitCacheStream(bitCacheData, bitCacheSize, layout, NoopBitCacheVisitor{});
}

bool XmlbArmatureLoader::AddDataFromXmlbFile(const std::string& filePath,
                                             const std::string& baseFilePath) {
    return AddDataFromXmlbFileImpl(std::string(), std::string(), filePath, baseFilePath, false);
}

bool XmlbArmatureLoader::AddDataFromXmlbFile(const std::string& imagePath,
                                             const std::string& plistPath,
                                             const std::string& xmlbPath,
                                             bool asyncLock) {
    return AddDataFromXmlbFileImpl(imagePath, plistPath, xmlbPath, std::string(), asyncLock);
}

bool XmlbArmatureLoader::AddDataFromXmlbFile(const char* imagePath,
                                             const char* plistPath,
                                             const char* xmlbPath,
                                             bool asyncLock) {
    if (!xmlbPath || xmlbPath[0] == '\0') return false;
    return AddDataFromXmlbFileImpl(imagePath ? std::string(imagePath) : std::string(),
                                   plistPath ? std::string(plistPath) : std::string(),
                                   std::string(xmlbPath),
                                   std::string(),
                                   asyncLock);
}

bool XmlbArmatureLoader::AddDataFromXmlbFileImpl(const std::string& imagePath,
                                                 const std::string& plistPath,
                                                 const std::string& filePath,
                                                 const std::string& baseFilePath,
                                                 bool asyncLock) {
    std::string normPath = NormalizeAssetPath(filePath);
    if (normPath.empty()) return false;

    const std::string        xmlbPath = ReplaceFileExtension(normPath, ".xmlb");
    std::vector<std::string> candidates;
    if (xmlbPath != normPath) candidates.push_back(xmlbPath);
    candidates.push_back(normPath);
    if (!baseFilePath.empty()) {
        for (const std::string& rel : {ResolveRelativeAssetPath(xmlbPath, baseFilePath),
                                       ResolveRelativeAssetPath(normPath, baseFilePath)}) {
            if (!rel.empty() &&
                std::find(candidates.begin(), candidates.end(), rel) == candidates.end()) {
                candidates.push_back(rel);
            }
        }
    }

    unsigned long  fileSize = 0;
    DecryptResult  diag;
    unsigned char* rawData = nullptr;
    for (const std::string& cand : candidates) {
        rawData = LoadAndDecryptFileData(cand, &fileSize, &diag);
        if (rawData && fileSize > 0) {
            normPath = cand;
            break;
        }
        delete[] rawData;
        rawData  = nullptr;
        fileSize = 0;
    }

    if (!rawData || fileSize == 0) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
        cocos2d::CCLog("[XmlbArmatureLoader] Failed to load armature file: %s", normPath.c_str());
#endif
        delete[] rawData;
        return false;
    }

    const std::string requestedConfigPath = NormalizeAssetPath(filePath);
    const std::string effectiveBase       = baseFilePath.empty() ? normPath : baseFilePath;
    const bool        ok                  = AddDataFromXmlbBuffer(rawData,
                                                  static_cast<size_t>(fileSize),
                                                  requestedConfigPath,
                                                  effectiveBase,
                                                  asyncLock,
                                                  plistPath,
                                                  imagePath);
    delete[] rawData;
    return ok;
}

bool XmlbArmatureLoader::AddDataFromXmlbBuffer(const uint8_t* data,
                                               size_t size,
                                               const std::string& configFilePath,
                                               const std::string& baseFilePath,
                                               bool asyncLock,
                                               const std::string& plistPath,
                                               const std::string& imagePath) {
    if (data == nullptr || size == 0) return false;
    if (size >= 4 && readLE<uint32_t>(data) == kBtDecryptMagic) {
        LogArmatureWarnFmt("Rejected undecrypted 0xFEFEFEFE buffer for %s", configFilePath.c_str());
        return false;
    }
    if (LooksLikePlaintextXml(data, size)) {
        LogArmatureWarnFmt("Rejected plaintext XML buffer in AddDataFromXmlbBuffer for %s",
                           configFilePath.c_str());
        return false;
    }

#if defined(GCLIENT_XMLB_HAS_PROTOBUF)
    ArmatureRoot root;
    if (root.ParseFromArray(data, static_cast<int>(size)) &&
        (root.armature_data_size() > 0 || root.animation_data_size() > 0 ||
         root.texture_data_size() > 0 || root.config_file_path_size() > 0 ||
         root.has_content_scale())) {
        return AddDataFromArmatureRoot(
            root, configFilePath, baseFilePath, asyncLock, plistPath, imagePath);
    }
#endif

    const XmlbBitCacheLayout defaultLayout;
    if (!ValidateBitCacheBuffer(data, size, defaultLayout)) {
        if (LooksLikeArmatureProtobufWire(data, size)) {
            LogArmatureWarnFmt("Malformed Protobuf ArmatureRoot stream rejected (skipping BitCache): %s",
                               configFilePath.c_str());
        }
        return false;
    }

    return AddDataFromBitCache(
        data, size, configFilePath, asyncLock, defaultLayout, plistPath, imagePath, baseFilePath);
}

bool XmlbArmatureLoader::AddDataFromXmlbBuffer(const uint8_t* data,
                                               size_t size,
                                               const char* imagePath,
                                               const char* plistPath,
                                               const char* configFilePath,
                                               bool asyncLock) {
    if (!configFilePath || configFilePath[0] == '\0') return false;
    return AddDataFromXmlbBuffer(data,
                                 size,
                                 std::string(configFilePath),
                                 std::string(),
                                 asyncLock,
                                 plistPath ? std::string(plistPath) : std::string(),
                                 imagePath ? std::string(imagePath) : std::string());
}

bool XmlbArmatureLoader::AddDataFromProtobufBuffer(const uint8_t* data,
                                                   size_t size,
                                                   const std::string& configFilePath,
                                                   const std::string& baseFilePath,
                                                   bool asyncLock,
                                                   const std::string& plistPath,
                                                   const std::string& imagePath) {
    if (data == nullptr || size == 0) return false;
    if (size >= 4 && readLE<uint32_t>(data) == kBtDecryptMagic) return false;

#if defined(GCLIENT_XMLB_HAS_PROTOBUF)
    ArmatureRoot root;
    if (!root.ParseFromArray(data, static_cast<int>(size))) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
        cocos2d::CCLog("[XmlbArmatureLoader] ArmatureRoot::ParseFromArray failed for %s",
                       configFilePath.c_str());
#endif
        return false;
    }
    return AddDataFromArmatureRoot(
        root, configFilePath, baseFilePath, asyncLock, plistPath, imagePath);
#else
    (void)configFilePath;
    (void)baseFilePath;
    (void)asyncLock;
    (void)plistPath;
    (void)imagePath;
    return false;
#endif
}

bool XmlbArmatureLoader::AddDataFromArmatureRoot(const ArmatureRoot& root,
                                                 const std::string& configFilePath,
                                                 const std::string& baseFilePath,
                                                 bool asyncLock,
                                                 const std::string& plistPath,
                                                 const std::string& imagePath) {
#if (defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)) && \
    defined(GCLIENT_XMLB_HAS_PROTOBUF)
    ProtoArmatureSource source{root};
    return PopulateArmatureManagerFromSource(
        source, configFilePath, baseFilePath, asyncLock, plistPath, imagePath);
#else
    (void)root;
    (void)configFilePath;
    (void)baseFilePath;
    (void)asyncLock;
    (void)plistPath;
    (void)imagePath;
    return false;
#endif
}

bool XmlbArmatureLoader::AddDataFromBitCache(const uint8_t* bitCacheData,
                                             size_t bitCacheSize,
                                             const std::string& configFilePath,
                                             bool asyncLock,
                                             const XmlbBitCacheLayout& layout,
                                             const std::string& plistPath,
                                             const std::string& imagePath,
                                             const std::string& baseFilePath) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    BitCacheArmatureSource source{bitCacheData, bitCacheSize, layout};
    return PopulateArmatureManagerFromSource(
        source, configFilePath, baseFilePath, asyncLock, plistPath, imagePath);
#else
    (void)bitCacheData;
    (void)bitCacheSize;
    (void)configFilePath;
    (void)asyncLock;
    (void)layout;
    (void)plistPath;
    (void)imagePath;
    (void)baseFilePath;
    return false;
#endif
}

} // namespace assets
} // namespace gclient
