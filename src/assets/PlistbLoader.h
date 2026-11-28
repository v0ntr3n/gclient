#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
#include "compat/Axmol226Compat.h"
#else
namespace ax {
class CCDictionary;
class SpriteFrameCache;
class Texture2D;
using CCSpriteFrameCache = SpriteFrameCache;
using CCTexture2D = Texture2D;
}
namespace cocos2d = ax;
#endif

namespace gclient {
namespace assets {

// ============================================================================
// PlistbLoader - Binary Sprite Sheet (.plistb) & XML Fallback Parser / Loader
//
// Ported from libcocos2dlua.so (arm64-v8a):
//   - cocos2d::CCSpriteFrameCache::addSpriteFramesWithBinary @ 0x66f100
//
// Binary Layout (little-endian):
//   Header (66 bytes):
//     [0..63]   char[64]  textureFileName (null-terminated)
//     [64..65]  int16_t   frameCount
//
//   Frame Record (82 bytes x frameCount, starting at offset 66):
//     [0..63]   char[64]  frameName (null-terminated)
//     [64..65]  uint16_t  rectX
//     [66..67]  uint16_t  rectY
//     [68..69]  uint16_t  rectW
//     [70..71]  uint16_t  rectH
//     [72]      uint8_t   rotated (0 or 1)
//     [73]      uint8_t   padding
//     [74..75]  int16_t   offsetX
//     [76..77]  int16_t   offsetY
//     [78..79]  uint16_t  originalWidth
//     [80..81]  uint16_t  originalHeight
// ============================================================================

constexpr size_t kPlistbHeaderSize = 66;
constexpr size_t kPlistbRecordSize = 82;
constexpr size_t kPlistbNameMaxLen = 64;

struct PlistbFrameRecord {
    std::string frameName;
    float       rectX          = 0.0f;
    float       rectY          = 0.0f;
    float       rectWidth      = 0.0f;
    float       rectHeight     = 0.0f;
    bool        rotated        = false;
    float       offsetX        = 0.0f;
    float       offsetY        = 0.0f;
    float       originalWidth  = 0.0f;
    float       originalHeight = 0.0f;
};

struct PlistbFileData {
    std::string                    textureFileName;
    std::vector<PlistbFrameRecord> frames;
};

class PlistbLoader {
public:
    // Parses an in-memory decrypted binary .plistb buffer into PlistbFileData.
    // Rejects undecrypted 0xFEFEFEFE buffers, plaintext XML plists, and
    // unterminated fixed-length strings immediately.
    static bool ParseBuffer(const uint8_t* data,
                            size_t size,
                            PlistbFileData* outData,
                            std::string* outError = nullptr);

    // Parses an in-memory decrypted plaintext XML sprite-sheet plist buffer
    // (Cocos2d / TexturePacker formats 0, 1, 2, and 3) into PlistbFileData.
    // Used when converted .plistb files contain plaintext XML sprite-sheet data.
    static bool ParseXmlSpriteSheetBuffer(const uint8_t* data,
                                          size_t size,
                                          PlistbFileData* outData,
                                          std::string* outError = nullptr);

    // Resolves candidate sprite-sheet paths for `rawSheetPath` against `baseFilePath`
    // without duplicating already-present directory prefixes (e.g. prevents
    // "ArmatureRes/common/ArmatureRes/common/shuaxindaiji.plistb").
    static std::vector<std::string> ResolveSpriteSheetCandidates(
        const std::string& rawSheetPath,
        const std::string& baseFilePath);

    // Builds deduplicated texture candidate paths in priority order:
    //   1. .png
    //   2. original normalized path
    //   3. .pvr.ccz
    //   4. .pkm   (Android ETC1 + _alpha)
    //   5. .webp
    //   6. .jpg
    static std::vector<std::string> BuildTextureCandidatePaths(const std::string& texturePath);

    // Port of CCSpriteFrameCache::addSpriteFramesWithBinary(plistPath, texture).
    // Automatically resolves ".plist" -> ".plistb", transparently parses either
    // binary .plistb or converted plaintext XML .plistb/.plist buffers, and probes
    // texture fallbacks (.png, .pvr.ccz, .pkm, .webp, .jpg) via CCTextureCache.
    static bool AddSpriteFramesWithBinary(const std::string& plistPath,
                                          cocos2d::CCTexture2D* texture = nullptr,
                                          cocos2d::CCSpriteFrameCache* cache = nullptr);

    // Alias matching AddSpriteFramesFromPlistbFile naming convention.
    static bool AddSpriteFramesFromPlistbFile(const std::string& plistPath,
                                              cocos2d::CCTexture2D* texture = nullptr,
                                              cocos2d::CCSpriteFrameCache* cache = nullptr);

    // Removes sprite frames previously registered from a .plistb / .plist path
    // so AssetManager:removeSpriteFrame / removeArmatureFileInfo cleans up stale frames.
    static bool RemoveSpriteFramesWithBinary(const std::string& plistPath,
                                             cocos2d::CCSpriteFrameCache* cache = nullptr);

    // Parses an in-memory decrypted .plistb or XML .plist buffer into a
    // Cocos2d-x CCDictionary (for particle / dictionary / sprite-sheet callers).
    static cocos2d::CCDictionary* LoadDictionaryFromBinaryBuffer(const uint8_t* data,
                                                                 size_t size,
                                                                 std::string* outError = nullptr);

    // Loads and decrypts a .plistb or .plist file into a Cocos2d-x CCDictionary.
    static cocos2d::CCDictionary* LoadDictionaryFromBinaryFile(const std::string& plistPath,
                                                               std::string* outError = nullptr);

    // Helper: returns true if this .plistb path was already loaded through PlistbLoader.
    static bool IsPlistbLoaded(const std::string& plistPath);

    // Clears the internal loaded-path tracking set (e.g., on cache purge).
    static void ClearLoadedTracking();
};

} // namespace assets
} // namespace gclient
