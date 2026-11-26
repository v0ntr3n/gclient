#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>

class ArmatureRoot;

namespace gclient {
namespace assets {

// ============================================================================
// XmlbArmatureLoader - .xmlb / Protobuf Armature Loader (Win32 Port)
//
// Ported from libcocos2dlua.so (arm64-v8a):
//   - cocos2d::extension::CCDataReaderHelper::addDataFromBitCache @ 0x4e7ec8
//   - Wired to db.pb.h (ArmatureRoot / ArmatureData / ArmatureAnimationData /
//     ArmatureTextureData)
//
// Supports both:
//   1. Protobuf-encoded .xmlb assets deserialized via db.pb.h `ArmatureRoot`.
//   2. Raw packed binary BitCache buffers matching `addDataFromBitCache`.
// ============================================================================

struct XmlbBitCacheLayout {
    size_t skeletonStructSize         = 6;
    size_t armatureDataStructSize     = 66;
    size_t boneDataStructSize         = 68;
    size_t displayDataStructSize      = 65;
    size_t animationDataStructSize    = 66;
    size_t movementDataStructSize     = 74;
    size_t movementBoneDataStructSize = 66;
    size_t frameDataStructSize        = 168;
    size_t textureDataStructSize      = 68;
};

struct XmlbDecodedMovementHeader {
    std::string name;
    int32_t     duration      = 0;
    int32_t     durationTo    = 0;
    int32_t     durationTween = 0;
    bool        loop          = false;
    int32_t     tweenEasing   = 0;
    uint16_t    movBoneCount  = 0;
};

struct XmlbDecodedFrameRecord {
    float       x = 0.0f, y = 0.0f, scaleX = 1.0f, scaleY = 1.0f;
    float       skewX = 0.0f, skewY = 0.0f, tweenRotate = 0.0f;
    int32_t     duration = 0, zOrder = 0, tweenEasing = 0, displayIndex = 0;
    uint8_t     a = 255, r = 255, g = 255, b = 255, rawBlendType = 0;
    bool        isUseColorInfo = false, isTween = true;
    uint32_t    blendSrc = 0x0001u, blendDst = 0x0303u;
    std::string strEvent, strMovement;
};

class XmlbArmatureLoader {
public:
    static uint8_t ClampColorChannel(int32_t value);
    static int32_t DecodeBitCacheTweenEasing(int8_t rawEasing);
    static void MapBlendTypeToGL(uint8_t rawBlend, uint32_t* outSrc, uint32_t* outDst);
    static bool DecodeBitCacheMovementHeader(const uint8_t* movHdr, size_t availBytes,
                                             XmlbDecodedMovementHeader* outMov,
                                             const XmlbBitCacheLayout& layout = XmlbBitCacheLayout());
    static bool DecodeBitCacheFrameRecord(const uint8_t* fr, size_t availBytes,
                                          bool* ioHasStickyBlend, uint32_t* ioStickyBlendSrc,
                                          uint32_t* ioStickyBlendDst, XmlbDecodedFrameRecord* outFrame,
                                          const XmlbBitCacheLayout& layout = XmlbBitCacheLayout());
    // Loads and decrypts an .xmlb file, auto-discovers sibling .plistb/.plist
    // sheets (including numbered <stem>0.plistb .. <stem>9.plistb), parses
    // ArmatureRoot protobuf (falling back to validated BitCache binary layout if
    // needed), and registers all armature, animation, and texture data into
    // CCArmatureDataManager.
    static bool AddDataFromXmlbFile(const std::string& filePath,
                                    const std::string& baseFilePath = "");

    // Preserves 3-argument (filePath, baseFilePath, asyncLock) callers without
    // allowing string literals (const char*) to implicitly convert to bool.
    template <typename Bool,
              typename = std::enable_if_t<std::is_same_v<Bool, bool>>>
    static bool AddDataFromXmlbFile(const std::string& filePath,
                                    const std::string& baseFilePath,
                                    Bool asyncLock) {
        return AddDataFromXmlbFileImpl(std::string(), std::string(), filePath, baseFilePath, asyncLock);
    }

    // Explicit 3-path overload matching CCArmatureDataManager::addArmatureFileInfo(
    // imagePath, plistPath, configFilePath) while also probing sibling sheets.
    static bool AddDataFromXmlbFile(const std::string& imagePath,
                                    const std::string& plistPath,
                                    const std::string& xmlbPath,
                                    bool asyncLock = false);

    // Null-safe C-string overload for (imagePath, plistPath, xmlbPath).
    static bool AddDataFromXmlbFile(const char* imagePath,
                                    const char* plistPath,
                                    const char* xmlbPath,
                                    bool asyncLock = false);

    // Parses an in-memory decrypted .xmlb buffer (trying ArmatureRoot protobuf
    // first, rejecting malformed Protobuf wire streams, and falling back only to
    // strictly validated packed binary BitCache) and preloads sibling sheets.
    static bool AddDataFromXmlbBuffer(const uint8_t* data,
                                      size_t size,
                                      const std::string& configFilePath,
                                      const std::string& baseFilePath = "",
                                      bool asyncLock = false,
                                      const std::string& plistPath = "",
                                      const std::string& imagePath = "");

    static bool AddDataFromXmlbBuffer(const uint8_t* data,
                                      size_t size,
                                      const char* imagePath,
                                      const char* plistPath,
                                      const char* configFilePath,
                                      bool asyncLock = false);

    // Parses an in-memory decrypted protobuf ArmatureRoot buffer and registers it.
    static bool AddDataFromProtobufBuffer(const uint8_t* data,
                                          size_t size,
                                          const std::string& configFilePath,
                                          const std::string& baseFilePath = "",
                                          bool asyncLock = false,
                                          const std::string& plistPath = "",
                                          const std::string& imagePath = "");

    // Registers an already-parsed db.pb.h ArmatureRoot into CCArmatureDataManager.
    static bool AddDataFromArmatureRoot(const ArmatureRoot& root,
                                        const std::string& configFilePath,
                                        const std::string& baseFilePath = "",
                                        bool asyncLock = false,
                                        const std::string& plistPath = "",
                                        const std::string& imagePath = "");

    // Strictly validates a packed binary BitCache buffer's magic, fixed C-strings,
    // display types, and record bounds before any CCArmatureData is registered.
    static bool ValidateBitCacheBuffer(const uint8_t* bitCacheData,
                                       size_t bitCacheSize,
                                       const XmlbBitCacheLayout& layout = XmlbBitCacheLayout());

    // Direct port of CCDataReaderHelper::addDataFromBitCache @ 0x4e7ec8 for
    // packed binary skeleton/armature/animation/texture bit-cache buffers.
    static bool AddDataFromBitCache(const uint8_t* bitCacheData,
                                    size_t bitCacheSize,
                                    const std::string& configFilePath,
                                    bool asyncLock = false,
                                    const XmlbBitCacheLayout& layout = XmlbBitCacheLayout(),
                                    const std::string& plistPath = "",
                                    const std::string& imagePath = "",
                                    const std::string& baseFilePath = "");

private:
    static bool AddDataFromXmlbFileImpl(const std::string& imagePath,
                                        const std::string& plistPath,
                                        const std::string& filePath,
                                        const std::string& baseFilePath,
                                        bool asyncLock);
};

} // namespace assets
} // namespace gclient
