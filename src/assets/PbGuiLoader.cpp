#include "PbGuiLoader.h"

#include "BtDecryptHook.h"
#include "PlistbLoader.h"
#include "XmlbArmatureLoader.h"
#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelUtf8.h"
#include "CSGUI.pb.h"
#include "CSScene.pb.h"

#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
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

#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
namespace {

using gclient::common::endsWithAsciiCI;
using gclient::common::readLE;
using gclient::common::startsWithAsciiCI;
using gclient::common::toLowerAscii;
using gclient::common::trimAscii;

enum class GuiWidgetKind {
    GenericWidget,
    Button,
    CheckBox,
    ImageView,
    Label,
    LabelAtlas,
    LabelBMFont,
    LoadingBar,
    Slider,
    TextField,
    Layout,
    ScrollView,
    ListView,
    PageView,
};

GuiWidgetKind ClassifyWidgetClass(std::string_view cls) noexcept {
    if (cls == "Button" || cls == "TextButton") return GuiWidgetKind::Button;
    if (cls == "CheckBox") return GuiWidgetKind::CheckBox;
    if (cls == "ImageView") return GuiWidgetKind::ImageView;
    if (cls == "Label" || cls == "TextArea" || cls == "Text") return GuiWidgetKind::Label;
    if (cls == "LabelAtlas" || cls == "TextAtlas") return GuiWidgetKind::LabelAtlas;
    if (cls == "LabelBMFont" || cls == "TextBMFont") return GuiWidgetKind::LabelBMFont;
    if (cls == "LoadingBar") return GuiWidgetKind::LoadingBar;
    if (cls == "Slider") return GuiWidgetKind::Slider;
    if (cls == "TextField") return GuiWidgetKind::TextField;
    if (cls == "Panel" || cls == "Layout") return GuiWidgetKind::Layout;
    if (cls == "ScrollView" || cls == "DragPanel") return GuiWidgetKind::ScrollView;
    if (cls == "ListView") return GuiWidgetKind::ListView;
    if (cls == "PageView") return GuiWidgetKind::PageView;
    return GuiWidgetKind::GenericWidget;
}

void LogGuiWarn(const char* msg) {
#if !defined(GCLIENT_STANDALONE_BUILD)
    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Warn, "PbGuiLoader", "%s", msg ? msg : "");
#endif
    cocos2d::CCLog("[PbGuiLoader][WARN] %s", msg ? msg : "");
}

void LogGuiWarnFmt(const char* fmt, ...) {
    char    msg[320];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    LogGuiWarn(msg);
}

std::string ExtractDirectoryPrefix(const std::string& normalizedPath) {
    const size_t slashPos = normalizedPath.find_last_of('/');
    return (slashPos == std::string::npos) ? std::string() : normalizedPath.substr(0, slashPos + 1);
}

std::string JoinBaseAndRelativePath(const std::string& baseDir, const std::string& relPath) {
    const std::string normRel = NormalizeAssetPath(relPath);
    if (normRel.empty()) return {};
    if (normRel[0] == '/' || (normRel.size() >= 2 && normRel[1] == ':')) return normRel;

    const std::string normBase = NormalizeAssetPath(baseDir);
    if (normBase.empty() || normBase == ".") return normRel;
    return NormalizeAssetPath(normBase.back() == '/' ? (normBase + normRel)
                                                     : (normBase + "/" + normRel));
}

std::string StripLeadingDotDotSegments(const std::string& normalizedPath) {
    size_t pos = 0;
    while (pos + 3 <= normalizedPath.size() && normalizedPath.compare(pos, 3, "../") == 0) {
        pos += 3;
    }
    if (normalizedPath.compare(pos, std::string::npos, "..") == 0) return {};
    return normalizedPath.substr(pos);
}

void AppendUniquePath(std::vector<std::string>& out, const std::string& candidate) {
    if (!candidate.empty() && std::find(out.begin(), out.end(), candidate) == out.end()) {
        out.push_back(candidate);
    }
}

std::vector<std::string> BuildRelativeCandidatePaths(const std::string& rawRelPath,
                                                     const std::string& baseDir) {
    std::vector<std::string> out;
    const std::string        normRel = NormalizeAssetPath(rawRelPath);
    if (normRel.empty()) return out;

    AppendUniquePath(out, JoinBaseAndRelativePath(baseDir, normRel));
    AppendUniquePath(out, normRel);
    AppendUniquePath(out, StripLeadingDotDotSegments(normRel));
    return out;
}

bool DoesExactAssetFileExist(const std::string& candidatePath, std::string* outFullPath = nullptr) {
    if (candidatePath.empty()) return false;
    auto* fu = ax::FileUtils::getInstance();
    if (!fu) return false;
    const std::string full = fu->fullPathForFilename(candidatePath.c_str());
    if (!full.empty() && fu->isFileExist(full)) {
        if (outFullPath) *outFullPath = full;
        return true;
    }
    return false;
}

bool DoesAssetOrTextureVariantExist(const std::string& candidatePath) {
    if (DoesExactAssetFileExist(candidatePath)) return true;
    if (endsWithAsciiCI(candidatePath, ".plist")) {
        return DoesExactAssetFileExist(candidatePath + "b");
    }
    const std::string extLower = toLowerAscii(candidatePath);
    if (extLower.ends_with(".fnt") || extLower.ends_with(".pb") || extLower.ends_with(".xmlb") ||
        extLower.ends_with(".tmx")) {
        return false;
    }
    for (const std::string& texCand : PlistbLoader::BuildTextureCandidatePaths(candidatePath)) {
        if (DoesExactAssetFileExist(texCand)) return true;
    }
    return false;
}

std::string ResolveLocalAssetPath(const std::string& rawRelPath, const std::string& baseDir) {
    const std::vector<std::string> candidates = BuildRelativeCandidatePaths(rawRelPath, baseDir);
    if (candidates.empty()) return {};
    for (const std::string& cand : candidates) {
        if (DoesAssetOrTextureVariantExist(cand)) return cand;
    }
    return candidates.front();
}

void TriggerLayoutPass(ax::ui::Layout* layout) {
    if (!layout) return;
    layout->requestDoLayout();
    layout->forceDoLayout();
}

struct TextureCacheAccessor : public ax::TextureCache {
    static void AliasTextureKey(ax::TextureCache* cache, const std::string& key, ax::Texture2D* tex) {
        if (!cache || key.empty() || !tex) return;
        auto& mapRef = cache->*(&TextureCacheAccessor::_textures);
        if (mapRef.find(key) == mapRef.end()) {
            tex->retain();
            mapRef.emplace(key, tex);
        }
    }
};

cocos2d::CCTexture2D* ProbeAndLoadTextureAcrossRoots(const std::string& rawTexPath,
                                                     const std::string& baseDir,
                                                     std::string* outResolvedCand = nullptr) {
    auto* texCache = ax::Director::getInstance()->getTextureCache();
    auto* fu       = ax::FileUtils::getInstance();
    if (!texCache) return nullptr;

    std::vector<std::string> allCandidates;
    for (const std::string& b : BuildRelativeCandidatePaths(rawTexPath, baseDir)) {
        for (const std::string& tc : PlistbLoader::BuildTextureCandidatePaths(b)) {
            AppendUniquePath(allCandidates, tc);
        }
    }

    if (fu) {
        for (const std::string& cand : allCandidates) {
            const std::string full = fu->fullPathForFilename(cand.c_str());
            if (!full.empty() && fu->isFileExist(full)) {
                if (cocos2d::CCTexture2D* tex = texCache->addImage(full.c_str())) {
                    if (outResolvedCand) *outResolvedCand = cand;
                    return tex;
                }
            }
        }
    }
    for (const std::string& cand : allCandidates) {
        if (cocos2d::CCTexture2D* tex = texCache->addImage(cand.c_str())) {
            if (outResolvedCand) *outResolvedCand = cand;
            return tex;
        }
    }
    return nullptr;
}

bool BufferLooksLikeXmlPlistDict(const uint8_t* data, size_t size) {
    if (!data || size < 16 || IsBtEncryptedBuffer(data, size)) return false;
    const size_t off =
        (size >= 3 && data[0] == 0xEFu && data[1] == 0xBBu && data[2] == 0xBFu) ? 3u : 0u;
    const std::string_view sv =
        trimAscii(std::string_view(reinterpret_cast<const char*>(data + off), size - off));
    if (!startsWithAsciiCI(sv, "<?xml") && !startsWithAsciiCI(sv, "<plist") &&
        !startsWithAsciiCI(sv, "<!doctype") && !startsWithAsciiCI(sv, "<!--")) {
        return false;
    }
    return sv.find("<plist") != std::string_view::npos &&
           sv.find("<dict") != std::string_view::npos;
}

std::string ExtractXmlKeyStringValue(const std::string& xml, const char* keyName) {
    const std::string needle = std::string("<key>") + keyName + "</key>";
    const size_t      kPos   = xml.find(needle);
    if (kPos == std::string::npos) return {};
    const size_t sOpen = xml.find("<string>", kPos + needle.size());
    if (sOpen == std::string::npos) return {};
    const size_t valStart = sOpen + 8;
    const size_t sClose   = xml.find("</string>", valStart);
    return (sClose == std::string::npos) ? std::string() : xml.substr(valStart, sClose - valStart);
}

bool VerifyValidXmlPlistOnDisk(const std::string& xmlCandidate,
                               std::string* outXmlContent = nullptr) {
    if (xmlCandidate.empty() || endsWithAsciiCI(xmlCandidate, ".plistb") ||
        !DoesExactAssetFileExist(xmlCandidate)) {
        return false;
    }
    unsigned long  sz  = 0;
    unsigned char* buf = LoadAndDecryptFileData(xmlCandidate, &sz, nullptr);
    if (!buf || sz == 0) {
        delete[] buf;
        return false;
    }
    const bool ok = BufferLooksLikeXmlPlistDict(buf, static_cast<size_t>(sz));
    if (ok && outXmlContent) {
        outXmlContent->assign(reinterpret_cast<const char*>(buf), static_cast<size_t>(sz));
    }
    delete[] buf;
    return ok;
}

std::vector<std::string> ExtractFntPageFiles(const uint8_t* data, size_t size) {
    std::vector<std::string> pages;
    if (!data || size < 4) return pages;

    // Binary AngelCode BMFont v3 ("BMF\x03")
    if (data[0] == 'B' && data[1] == 'M' && data[2] == 'F' && data[3] == 3) {
        size_t off = 4;
        while (size - off >= 5u) {
            const uint8_t  blockType = data[off];
            const uint32_t blockSize = readLE<uint32_t>(data + off + 1);
            off += 5u;
            if (static_cast<size_t>(blockSize) > size - off) break;
            if (blockType == 3 && blockSize > 0) {
                size_t pOff = 0;
                while (pOff < static_cast<size_t>(blockSize)) {
                    const uint8_t* start  = data + off + pOff;
                    const size_t   rem    = static_cast<size_t>(blockSize) - pOff;
                    const void*    nulPtr = std::memchr(start, '\0', rem);
                    const size_t   sLen =
                        nulPtr ? static_cast<size_t>(static_cast<const uint8_t*>(nulPtr) - start)
                               : rem;
                    if (sLen > 0) {
                        AppendUniquePath(pages,
                                         std::string(reinterpret_cast<const char*>(start), sLen));
                    }
                    if (!nulPtr) break;
                    pOff += sLen + 1u;
                }
            }
            off += static_cast<size_t>(blockSize);
        }
        return pages;
    }

    const std::string_view content(reinterpret_cast<const char*>(data), size);
    size_t                 lineStart = 0;
    while (lineStart < content.size()) {
        size_t lineEnd = content.find('\n', lineStart);
        if (lineEnd == std::string_view::npos) lineEnd = content.size();
        const std::string_view line = content.substr(lineStart, lineEnd - lineStart);
        lineStart                   = lineEnd + 1;

        const size_t pagePos = line.find("page");
        if (pagePos == std::string_view::npos) continue;
        const size_t fileKeyPos = line.find("file=", pagePos);
        if (fileKeyPos == std::string_view::npos) continue;

        size_t valPos = fileKeyPos + 5;
        while (valPos < line.size() && (line[valPos] == ' ' || line[valPos] == '\t')) ++valPos;
        if (valPos >= line.size()) continue;

        if (line[valPos] == '"' || line[valPos] == '\'') {
            const char   quote  = line[valPos++];
            const size_t endPos = line.find(quote, valPos);
            if (endPos != std::string_view::npos && endPos > valPos) {
                AppendUniquePath(pages, std::string(line.substr(valPos, endPos - valPos)));
            }
        } else {
            size_t endPos = valPos;
            while (endPos < line.size() && line[endPos] != ' ' && line[endPos] != '\t' &&
                   line[endPos] != '\r' && line[endPos] != '\n' && line[endPos] != '>') {
                ++endPos;
            }
            if (endPos > valPos) {
                AppendUniquePath(pages, std::string(line.substr(valPos, endPos - valPos)));
            }
        }
    }
    return pages;
}

std::string ResolveCsDataPath(const CSData& data,
                              const std::string& baseDir,
                              cocos2d::ui::TextureResType* outType) {
    const auto texType = static_cast<cocos2d::ui::TextureResType>(data.resourcetype());
    if (outType) *outType = texType;
    if (!data.has_path() || data.path().empty()) return {};
    return (texType == cocos2d::ui::UI_TEX_TYPE_PLIST) ? NormalizeAssetPath(data.path())
                                                       : ResolveLocalAssetPath(data.path(), baseDir);
}

bool CanLoadWidgetTexture(const std::string& path, cocos2d::ui::TextureResType rt) {
    if (path.empty()) return false;
    if (rt == cocos2d::ui::UI_TEX_TYPE_PLIST) {
        auto* sfc = ax::SpriteFrameCache::getInstance();
        return sfc && sfc->getSpriteFrameByName(path.c_str()) != nullptr;
    }
    return DoesAssetOrTextureVariantExist(path) ||
           ProbeAndLoadTextureAcrossRoots(path, std::string()) != nullptr;
}

template <typename Fn>
void WithResolvedCsData(bool hasData,
                        const CSData& data,
                        const std::string& baseDir,
                        Fn&& apply,
                        bool requireLoadable = false) {
    if (!hasData) return;
    cocos2d::ui::TextureResType rt = cocos2d::ui::UI_TEX_TYPE_LOCAL;
    const std::string           p  = ResolveCsDataPath(data, baseDir, &rt);
    if (!p.empty() && (!requireLoadable || CanLoadWidgetTexture(p, rt))) {
        apply(p.c_str(), rt);
    }
}

cocos2d::ccColor3B MakeOptColor3B(bool hasR, int32_t r,
                                  bool hasG, int32_t g,
                                  bool hasB, int32_t b) {
    return cocos2d::ccc3(static_cast<GLubyte>(hasR ? r : 255),
                         static_cast<GLubyte>(hasG ? g : 255),
                         static_cast<GLubyte>(hasB ? b : 255));
}

cocos2d::CCRect MakeOptCapInsets(const CSOptions& opt) {
    return cocos2d::CCRect(opt.has_capinsetsx() ? opt.capinsetsx() : 0.0f,
                           opt.has_capinsetsy() ? opt.capinsetsy() : 0.0f,
                           opt.has_capinsetswidth() ? opt.capinsetswidth() : 0.0f,
                           opt.has_capinsetsheight() ? opt.capinsetsheight() : 0.0f);
}

cocos2d::ui::Margin MakeOptMargin(const CSLayoutParameter& lp) {
    return cocos2d::ui::Margin(lp.has_marginleft() ? lp.marginleft() : 0.0f,
                               lp.has_margintop() ? lp.margintop() : 0.0f,
                               lp.has_marginright() ? lp.marginright() : 0.0f,
                               lp.has_margindown() ? lp.margindown() : 0.0f);
}

template <typename Scale9WidgetT>
void ApplyScale9CapAndSize(Scale9WidgetT* widget, const CSOptions& opt) {
    if (!widget || !opt.has_scale9enable() || !opt.scale9enable()) return;
    widget->setCapInsets(MakeOptCapInsets(opt));
    if (opt.has_scale9width() && opt.has_scale9height()) {
        widget->setContentSize(cocos2d::CCSize(opt.scale9width(), opt.scale9height()));
    }
}

void SyncPercentSizeAndPosition(cocos2d::ui::Widget* widget,
                                const CSOptions& opt,
                                bool onlyWhenPercentMode) {
    if (!widget) return;
    const bool applySize = onlyWhenPercentMode
                               ? (opt.has_sizetype() && opt.sizetype() == 1)
                               : (opt.has_sizepercentx() || opt.has_sizepercenty());
    if (applySize) {
        widget->setSizePercent(cocos2d::CCPoint(
            opt.has_sizepercentx() ? opt.sizepercentx() : 0.0f,
            opt.has_sizepercenty() ? opt.sizepercenty() : 0.0f));
        if (onlyWhenPercentMode) {
            if (auto* childLayout = dynamic_cast<cocos2d::ui::Layout*>(widget)) {
                TriggerLayoutPass(childLayout);
            }
        }
    }

    const bool applyPos = onlyWhenPercentMode
                              ? (opt.has_positiontype() && opt.positiontype() == 1)
                              : (opt.has_positionpercentx() || opt.has_positionpercenty());
    if (applyPos) {
        widget->setPositionPercent(cocos2d::CCPoint(
            opt.has_positionpercentx() ? opt.positionpercentx() : 0.0f,
            opt.has_positionpercenty() ? opt.positionpercenty() : 0.0f));
    }
}

void ApplyBaseWidgetOptions(cocos2d::ui::Widget* widget, const CSOptions& opt) {
    if (!widget) return;

    if (opt.has_ignoresize()) widget->ignoreContentAdaptWithSize(opt.ignoresize());
    if (opt.has_sizetype()) widget->setSizeType(static_cast<cocos2d::ui::SizeType>(opt.sizetype()));
    if (opt.has_positiontype()) {
        widget->setPositionType(static_cast<cocos2d::ui::PositionType>(opt.positiontype()));
    }

    if (opt.has_width() || opt.has_height()) {
        const auto cur = widget->getContentSize();
        widget->setContentSize(cocos2d::CCSize(opt.has_width() ? opt.width() : cur.width,
                                               opt.has_height() ? opt.height() : cur.height));
    }
    SyncPercentSizeAndPosition(widget, opt, /*onlyWhenPercentMode=*/false);

    if (opt.has_tag()) widget->setTag(opt.tag());
    if (opt.has_actiontag()) widget->setActionTag(opt.actiontag());
    if (opt.has_touchable()) widget->setTouchEnabled(opt.touchable());
    if (opt.has_name()) widget->setName(opt.name().c_str());

    widget->setPosition(cocos2d::CCPoint(opt.has_x() ? static_cast<float>(opt.x()) : 0.0f,
                                         opt.has_y() ? static_cast<float>(opt.y()) : 0.0f));

    if (opt.has_scalex()) widget->setScaleX(opt.scalex());
    if (opt.has_scaley()) widget->setScaleY(opt.scaley());
    if (opt.has_rotation()) widget->setRotation(opt.rotation());
    if (opt.has_visible()) widget->setVisible(opt.visible());
    if (opt.has_zorder()) widget->setLocalZOrder(opt.zorder());
    if (opt.has_flipx()) widget->setFlippedX(opt.flipx());
    if (opt.has_flipy()) widget->setFlippedY(opt.flipy());

    if (opt.has_anchorpointx() || opt.has_anchorpointy()) {
        widget->setAnchorPoint(cocos2d::CCPoint(
            opt.has_anchorpointx() ? opt.anchorpointx() : 0.5f,
            opt.has_anchorpointy() ? opt.anchorpointy() : 0.5f));
    }

    if (opt.has_opacity()) widget->setOpacity(static_cast<GLubyte>(opt.opacity()));
    if (opt.has_colorr() || opt.has_colorg() || opt.has_colorb()) {
        widget->setColor(MakeOptColor3B(opt.has_colorr(), opt.colorr(),
                                        opt.has_colorg(), opt.colorg(),
                                        opt.has_colorb(), opt.colorb()));
    }

    if (opt.has_layoutparameter()) {
        const CSLayoutParameter& lp = opt.layoutparameter();
        if (lp.type() == 1) {
            auto* linear = cocos2d::ui::LinearLayoutParameter::create();
            if (lp.has_gravity()) {
                linear->setGravity(static_cast<cocos2d::ui::LinearGravity>(lp.gravity()));
            }
            linear->setMargin(MakeOptMargin(lp));
            widget->setLayoutParameter(linear);
        } else if (lp.type() == 2) {
            auto* rel = cocos2d::ui::RelativeLayoutParameter::create();
            if (lp.has_relativename()) rel->setRelativeName(lp.relativename().c_str());
            if (lp.has_relativetoname()) rel->setRelativeToWidgetName(lp.relativetoname().c_str());
            if (lp.has_align()) rel->setAlign(static_cast<cocos2d::ui::RelativeAlign>(lp.align()));
            rel->setMargin(MakeOptMargin(lp));
            widget->setLayoutParameter(rel);
        }
    }
}

void ApplyLayoutOptions(cocos2d::ui::Layout* layout,
                        const CSOptions& opt,
                        const std::string& baseDir) {
    if (!layout) return;

    if (opt.has_clipable()) layout->setClippingEnabled(opt.clipable());
    if (opt.has_colortype()) {
        layout->setBackGroundColorType(
            static_cast<cocos2d::ui::LayoutBackGroundColorType>(opt.colortype()));
    }
    if (opt.has_bgcolorr() || opt.has_bgcolorg() || opt.has_bgcolorb()) {
        layout->setBackGroundColor(MakeOptColor3B(opt.has_bgcolorr(), opt.bgcolorr(),
                                                  opt.has_bgcolorg(), opt.bgcolorg(),
                                                  opt.has_bgcolorb(), opt.bgcolorb()));
    }
    if (opt.has_bgstartcolorr() || opt.has_bgendcolorr()) {
        layout->setBackGroundColor(
            MakeOptColor3B(opt.has_bgstartcolorr(), opt.bgstartcolorr(),
                           opt.has_bgstartcolorg(), opt.bgstartcolorg(),
                           opt.has_bgstartcolorb(), opt.bgstartcolorb()),
            MakeOptColor3B(opt.has_bgendcolorr(), opt.bgendcolorr(),
                           opt.has_bgendcolorg(), opt.bgendcolorg(),
                           opt.has_bgendcolorb(), opt.bgendcolorb()));
    }
    if (opt.has_vectorx() || opt.has_vectory()) {
        layout->setBackGroundColorVector(cocos2d::CCPoint(
            opt.has_vectorx() ? opt.vectorx() : 0.0f,
            opt.has_vectory() ? opt.vectory() : -1.0f));
    }
    if (opt.has_bgcoloropacity()) {
        layout->setBackGroundColorOpacity(static_cast<GLubyte>(opt.bgcoloropacity()));
    }
    if (opt.has_backgroundscale9enable()) {
        layout->setBackGroundImageScale9Enabled(opt.backgroundscale9enable());
    }
    WithResolvedCsData(opt.has_backgroundimagedata(), opt.backgroundimagedata(), baseDir,
                       [&](const char* p, auto rt) { layout->setBackGroundImage(p, rt); });
    if (opt.has_backgroundscale9enable() && opt.backgroundscale9enable()) {
        layout->setBackGroundImageCapInsets(MakeOptCapInsets(opt));
    }
    if (opt.has_layouttype()) {
        layout->setLayoutType(static_cast<cocos2d::ui::LayoutType>(opt.layouttype()));
    }
    if (opt.has_adaptscreen() && opt.adaptscreen()) {
        layout->setContentSize(ax::Director::getInstance()->getWinSize());
    }
}

void ApplyButtonOptions(cocos2d::ui::Button* button,
                        const CSOptions& opt,
                        const std::string& baseDir) {
    if (!button) return;
    if (opt.has_scale9enable()) button->setScale9Enabled(opt.scale9enable());

    WithResolvedCsData(opt.has_normaldata(), opt.normaldata(), baseDir,
                       [&](const char* p, auto rt) { button->loadTextureNormal(p, rt); });
    WithResolvedCsData(opt.has_presseddata(), opt.presseddata(), baseDir,
                       [&](const char* p, auto rt) { button->loadTexturePressed(p, rt); });
    // Note: CSGUI.proto field 31 is spelled `disbledData`.
    WithResolvedCsData(opt.has_disbleddata(), opt.disbleddata(), baseDir,
                       [&](const char* p, auto rt) { button->loadTextureDisabled(p, rt); });

    ApplyScale9CapAndSize(button, opt);

    if (opt.has_text()) button->setTitleText(opt.text());
    if (opt.has_fontname()) button->setTitleFontName(opt.fontname().c_str());
    if (opt.has_fontsize()) button->setTitleFontSize(static_cast<float>(opt.fontsize()));
    if (opt.has_textcolorr() || opt.has_textcolorg() || opt.has_textcolorb()) {
        button->setTitleColor(MakeOptColor3B(opt.has_textcolorr(), opt.textcolorr(),
                                             opt.has_textcolorg(), opt.textcolorg(),
                                             opt.has_textcolorb(), opt.textcolorb()));
    }
}

void ApplyCheckBoxOptions(cocos2d::ui::CheckBox* cb,
                          const CSOptions& opt,
                          const std::string& baseDir) {
    if (!cb) return;
    WithResolvedCsData(opt.has_backgroundboxdata(), opt.backgroundboxdata(), baseDir,
                       [&](const char* p, auto rt) { cb->loadTextureBackGround(p, rt); });
    WithResolvedCsData(opt.has_backgroundboxselecteddata(), opt.backgroundboxselecteddata(), baseDir,
                       [&](const char* p, auto rt) { cb->loadTextureBackGroundSelected(p, rt); });
    WithResolvedCsData(opt.has_frontcrossdata(), opt.frontcrossdata(), baseDir,
                       [&](const char* p, auto rt) { cb->loadTextureFrontCross(p, rt); });
    WithResolvedCsData(opt.has_backgroundboxdisableddata(), opt.backgroundboxdisableddata(), baseDir,
                       [&](const char* p, auto rt) { cb->loadTextureBackGroundDisabled(p, rt); });
    WithResolvedCsData(opt.has_frontcrossdisableddata(), opt.frontcrossdisableddata(), baseDir,
                       [&](const char* p, auto rt) { cb->loadTextureFrontCrossDisabled(p, rt); });
}

void ApplyImageViewOptions(cocos2d::ui::ImageView* img,
                           const CSOptions& opt,
                           const std::string& baseDir) {
    if (!img) return;
    WithResolvedCsData(opt.has_filenamedata(), opt.filenamedata(), baseDir,
                       [&](const char* p, auto rt) { img->loadTexture(p, rt); });
    if (opt.has_scale9enable()) {
        img->setScale9Enabled(opt.scale9enable());
        ApplyScale9CapAndSize(img, opt);
    }
}

void ApplyLabelOptions(cocos2d::ui::Label* label, const CSOptions& opt) {
    if (!label) return;

    if (opt.has_touchscaleenable()) label->setTouchScaleChangeEnabled(opt.touchscaleenable());
    const int fontSize = (opt.has_fontsize() && opt.fontsize() > 0) ? opt.fontsize() : 20;
    if (opt.has_fontsize()) label->setFontSize(opt.fontsize());
    if (opt.has_fontname()) label->setFontName(opt.fontname());
    if (opt.has_halignment()) {
        label->setTextHorizontalAlignment(static_cast<cocos2d::CCTextAlignment>(opt.halignment()));
    }
    if (opt.has_valignment()) {
        label->setTextVerticalAlignment(
            static_cast<cocos2d::CCVerticalTextAlignment>(opt.valignment()));
    }
    if (opt.has_text()) label->setString(opt.text());

    const bool  optIgnoreSize = opt.has_ignoresize() ? opt.ignoresize() : true;
    float       areaW         = opt.has_areawidth() ? opt.areawidth() : 0.0f;
    float       areaH         = opt.has_areaheight() ? opt.areaheight() : 0.0f;
    const float optW          = opt.has_width() ? opt.width() : 0.0f;
    const float optH          = opt.has_height() ? opt.height() : 0.0f;

    if (!optIgnoreSize && areaW <= 0.0f && optW > 0.0f) areaW = optW;
    if (!optIgnoreSize && areaH <= 0.0f && optH > 0.0f) areaH = optH;

    const float refHeight           = (areaH > 0.0f) ? areaH : optH;
    const float singleLineThreshold = static_cast<float>(fontSize) * 1.6f;

    if (areaW > 0.0f && areaH > 0.0f && refHeight > singleLineThreshold) {
        label->ignoreContentAdaptWithSize(false);
        label->setTextAreaSize(cocos2d::CCSize(areaW, 0.0f));
        if (auto* ttf = dynamic_cast<ax::Label*>(label->getVirtualRenderer())) {
            ttf->setDimensions(areaW, 0.0f);
            const float targetH = std::max(areaH, ttf->getContentSize().height);
            label->setContentSize(cocos2d::CCSize(areaW, targetH));
            label->setTextAreaSize(cocos2d::CCSize(areaW, 0.0f));
            ttf->setDimensions(areaW, 0.0f);
            ttf->setScaleX(1.0f);
            ttf->setScaleY(1.0f);
        }
    } else {
        label->ignoreContentAdaptWithSize(true);
        label->setTextAreaSize(cocos2d::CCSizeZero);
        if (auto* ttf = dynamic_cast<ax::Label*>(label->getVirtualRenderer())) {
            ttf->setDimensions(0.0f, 0.0f);
            ttf->setScaleX(1.0f);
            ttf->setScaleY(1.0f);
        }
    }
}

void ApplyLabelAtlasOptions(cocos2d::ui::LabelAtlas* atlas,
                            const CSOptions& opt,
                            const std::string& baseDir) {
    if (!atlas) return;

    const int itemW = opt.has_itemwidth() ? opt.itemwidth() : 0;
    const int itemH = opt.has_itemheight() ? opt.itemheight() : 0;
    if (itemW <= 0 || itemH <= 0) {
        if (opt.has_charmapfiledata() || opt.has_charmapfile()) {
            LogGuiWarn("Skipping LabelAtlas::setProperty because itemWidth/itemHeight <= 0");
        }
        return;
    }

    const std::string rawCharMap =
        (opt.has_charmapfiledata() && opt.charmapfiledata().has_path())
            ? opt.charmapfiledata().path()
            : (opt.has_charmapfile() ? opt.charmapfile() : std::string());
    if (rawCharMap.empty()) return;

    std::string           resolvedTexPath;
    cocos2d::CCTexture2D* tex =
        ProbeAndLoadTextureAcrossRoots(rawCharMap, baseDir, &resolvedTexPath);
    if (!tex) {
        LogGuiWarnFmt("Skipping LabelAtlas::setProperty: missing charMap texture '%s' (base '%s')",
                      rawCharMap.c_str(),
                      baseDir.c_str());
        return;
    }

    const cocos2d::CCSize texSize = tex->getContentSize();
    if (!std::isfinite(texSize.width) || !std::isfinite(texSize.height) ||
        static_cast<int>(texSize.width) < itemW || static_cast<int>(texSize.height) < itemH) {
        LogGuiWarnFmt(
            "Skipping LabelAtlas::setProperty: charMap '%s' (%0.1fx%0.1f) smaller than cell (%dx%d)",
            rawCharMap.c_str(),
            texSize.width,
            texSize.height,
            itemW,
            itemH);
        return;
    }

    if (resolvedTexPath.empty()) {
        resolvedTexPath = ResolveLocalAssetPath(rawCharMap, baseDir);
    }

    auto* fu       = ax::FileUtils::getInstance();
    auto* texCache = ax::Director::getInstance()->getTextureCache();
    if (fu && texCache) {
        const std::string expectedKey = fu->fullPathForFilename(resolvedTexPath);
        if (!expectedKey.empty()) {
            TextureCacheAccessor::AliasTextureKey(texCache, expectedKey, tex);
        }
    }

    const std::string startChar =
        (opt.has_startcharmap() && !opt.startcharmap().empty()) ? opt.startcharmap() : "0";
    atlas->setProperty(
        opt.has_stringvalue() ? opt.stringvalue() : "", resolvedTexPath, itemW, itemH, startChar);
}

void ApplyLabelBMFontOptions(cocos2d::ui::LabelBMFont* bmfont,
                             const CSOptions& opt,
                             const std::string& baseDir) {
    if (!bmfont) return;

    bool fntReady = false;
    if (opt.has_filenamedata() && opt.filenamedata().has_path() &&
        !opt.filenamedata().path().empty()) {
        const std::string              rawFnt     = opt.filenamedata().path();
        const std::vector<std::string> candidates = BuildRelativeCandidatePaths(rawFnt, baseDir);

        std::string    chosenFnt;
        unsigned long  fntSize = 0;
        unsigned char* fntData = nullptr;
        for (const std::string& cand : candidates) {
            if (!DoesExactAssetFileExist(cand)) continue;
            fntData = LoadAndDecryptFileData(cand, &fntSize, nullptr);
            if (fntData && fntSize > 0) {
                chosenFnt = cand;
                break;
            }
            delete[] fntData;
            fntData = nullptr;
            fntSize = 0;
        }

        if (!fntData || fntSize == 0) {
            delete[] fntData;
            LogGuiWarnFmt("Skipping LabelBMFont::setFntFile: missing or empty .fnt '%s' (base '%s')",
                          rawFnt.c_str(),
                          baseDir.c_str());
            return;
        }

        const std::vector<std::string> pageFiles =
            ExtractFntPageFiles(fntData, static_cast<size_t>(fntSize));
        delete[] fntData;

        if (pageFiles.empty()) {
            LogGuiWarnFmt("Skipping LabelBMFont::setFntFile: no bitmap page entries in '%s'",
                          chosenFnt.c_str());
            return;
        }

        const std::string fntDir   = ExtractDirectoryPrefix(chosenFnt);
        auto*             fu       = ax::FileUtils::getInstance();
        auto*             texCache = ax::Director::getInstance()->getTextureCache();

        for (const std::string& pageFile : pageFiles) {
            cocos2d::CCTexture2D* pageTex = ProbeAndLoadTextureAcrossRoots(pageFile, fntDir);
            if (!pageTex) {
                LogGuiWarnFmt("Skipping LabelBMFont::setFntFile: missing page texture '%s' for '%s'",
                              pageFile.c_str(),
                              chosenFnt.c_str());
                return;
            }
            if (fu && texCache) {
                const std::string expectedAtlasKey =
                    fu->fullPathFromRelativeFile(pageFile, chosenFnt);
                if (!expectedAtlasKey.empty()) {
                    TextureCacheAccessor::AliasTextureKey(texCache, expectedAtlasKey, pageTex);
                }
            }
        }

        bmfont->setFntFile(chosenFnt.c_str());
        fntReady = true;
    }

    if (fntReady && opt.has_text()) {
        bmfont->setString(opt.text().c_str());
    }
}

void ApplyLoadingBarOptions(cocos2d::ui::LoadingBar* bar,
                            const CSOptions& opt,
                            const std::string& baseDir) {
    if (!bar) return;

    const cocos2d::CCSize preLoadSize  = bar->getContentSize();
    const bool            scale9Enable = opt.has_scale9enable() && opt.scale9enable();

    float targetW = preLoadSize.width;
    float targetH = preLoadSize.height;
    if (scale9Enable && opt.has_scale9width() && opt.scale9width() > 0.0f) {
        targetW = opt.scale9width();
    } else if (opt.has_width() && opt.width() > 0.0f) {
        targetW = opt.width();
    } else if (opt.has_length() && opt.length() > 0.0f) {
        targetW = opt.length();
    }
    if (scale9Enable && opt.has_scale9height() && opt.scale9height() > 0.0f) {
        targetH = opt.scale9height();
    } else if (opt.has_height() && opt.height() > 0.0f) {
        targetH = opt.height();
    }

    if (opt.has_scale9enable()) bar->setScale9Enabled(scale9Enable);

    WithResolvedCsData(opt.has_texturedata(),
                       opt.texturedata(),
                       baseDir,
                       [&](const char* p, auto rt) { bar->loadTexture(p, rt); },
                       /*requireLoadable=*/true);

    if (scale9Enable) {
        bar->setScale9Enabled(true);
        bar->setCapInsets(MakeOptCapInsets(opt));
        const auto cur = bar->getContentSize();
        if (targetW <= 0.0f && cur.width > 0.0f) targetW = cur.width;
        if (targetH <= 0.0f && cur.height > 0.0f) targetH = cur.height;
        bar->setContentSize(cocos2d::CCSize(targetW, targetH));
    } else {
        const bool ignoreSize = opt.has_ignoresize() ? opt.ignoresize() : true;
        if (!ignoreSize && (targetW > 0.0f || targetH > 0.0f)) {
            const auto cur = bar->getContentSize();
            bar->ignoreContentAdaptWithSize(false);
            bar->setContentSize(cocos2d::CCSize((targetW > 0.0f) ? targetW : cur.width,
                                                (targetH > 0.0f) ? targetH : cur.height));
        }
    }

    if (opt.has_direction()) {
        bar->setDirection(
            static_cast<cocos2d::ui::LoadingBarType>(static_cast<int>(opt.direction())));
    }
    if (opt.has_percent()) bar->setPercent(opt.percent());
}

void ApplySliderOptions(cocos2d::ui::Slider* slider,
                        const CSOptions& opt,
                        const std::string& baseDir) {
    if (!slider) return;
    if (opt.has_bartexturescale9enable()) slider->setScale9Enabled(opt.bartexturescale9enable());

    if (opt.has_barfilenamedata()) {
        WithResolvedCsData(true, opt.barfilenamedata(), baseDir,
                           [&](const char* p, auto rt) { slider->loadBarTexture(p, rt); });
    } else if (opt.has_barfilename() && !opt.barfilename().empty()) {
        slider->loadBarTexture(ResolveLocalAssetPath(opt.barfilename(), baseDir).c_str());
    }

    WithResolvedCsData(opt.has_ballnormaldata(), opt.ballnormaldata(), baseDir,
                       [&](const char* p, auto rt) { slider->loadSlidBallTextureNormal(p, rt); });
    WithResolvedCsData(opt.has_ballpresseddata(), opt.ballpresseddata(), baseDir,
                       [&](const char* p, auto rt) { slider->loadSlidBallTexturePressed(p, rt); });
    WithResolvedCsData(opt.has_balldisableddata(), opt.balldisableddata(), baseDir,
                       [&](const char* p, auto rt) { slider->loadSlidBallTextureDisabled(p, rt); });
    WithResolvedCsData(opt.has_progressbardata(), opt.progressbardata(), baseDir,
                       [&](const char* p, auto rt) { slider->loadProgressBarTexture(p, rt); });

    if (opt.has_bartexturescale9enable() && opt.bartexturescale9enable() && opt.has_length()) {
        slider->setContentSize(cocos2d::CCSize(opt.length(), slider->getContentSize().height));
    }
    if (opt.has_percent()) slider->setPercent(opt.percent());
}

void ApplyTextFieldOptions(cocos2d::ui::TextField* tf, const CSOptions& opt) {
    if (!tf) return;
    if (opt.has_touchsizewidth() && opt.has_touchsizeheight()) {
        tf->setTouchSize(cocos2d::CCSize(opt.touchsizewidth(), opt.touchsizeheight()));
    }
    if (opt.has_placeholder()) tf->setPlaceHolder(opt.placeholder());
    if (opt.has_text()) tf->setString(opt.text());
    if (opt.has_fontsize()) tf->setFontSize(opt.fontsize());
    if (opt.has_fontname()) tf->setFontName(opt.fontname());
    if (opt.has_maxlengthenable()) {
        tf->setMaxLengthEnabled(opt.maxlengthenable());
        if (opt.maxlengthenable() && opt.has_maxlength()) tf->setMaxLength(opt.maxlength());
    }
    if (opt.has_passwordenable()) {
        tf->setPasswordEnabled(opt.passwordenable());
        if (opt.passwordenable() && opt.has_passwordstyletext()) {
            tf->setPasswordStyleText(opt.passwordstyletext().c_str());
        }
    }
}

void ApplyScrollViewOptions(cocos2d::ui::ScrollView* sv,
                            const CSOptions& opt,
                            const std::string& baseDir) {
    if (!sv) return;
    ApplyLayoutOptions(sv, opt, baseDir);
    if (opt.has_innerwidth() && opt.has_innerheight()) {
        sv->setInnerContainerSize(cocos2d::CCSize(opt.innerwidth(), opt.innerheight()));
    }
    if (opt.has_direction()) {
        sv->setDirection(
            static_cast<cocos2d::ui::SCROLLVIEW_DIR>(static_cast<int>(opt.direction())));
    }
    if (opt.has_bounceenable()) sv->setBounceEnabled(opt.bounceenable());
}

void ApplyListViewOptions(cocos2d::ui::ListView* lv,
                          const CSOptions& opt,
                          const std::string& baseDir) {
    if (!lv) return;
    ApplyScrollViewOptions(lv, opt, baseDir);
    if (opt.has_gravity()) {
        lv->setGravity(static_cast<cocos2d::ui::ListViewGravity>(static_cast<int>(opt.gravity())));
    }
    if (opt.has_itemmargin()) lv->setItemsMargin(opt.itemmargin());
}

struct ActionManagerExAccessor : public cocostudio::ActionManagerEx {
    static std::unordered_map<std::string, ax::Vector<cocostudio::ActionObject*>>*
    GetActionMap(cocostudio::ActionManagerEx* mgr) {
        return mgr ? &(mgr->*(&ActionManagerExAccessor::_actionDic)) : nullptr;
    }
};

struct TrackedActionNodeEntry {
    cocostudio::ActionObject* actionObj    = nullptr;
    cocostudio::ActionNode*   actionNode   = nullptr;
    ax::ui::Widget*           targetWidget = nullptr;
};

struct WidgetActionGroup {
    std::vector<std::string>            registeredKeys;
    std::vector<TrackedActionNodeEntry> entries;

    ~WidgetActionGroup() {
        for (auto& e : entries) {
            if (e.actionObj) {
                if (e.actionObj->isPlaying()) e.actionObj->stop();
                e.actionObj->release();
                e.actionObj = nullptr;
            }
            if (e.actionNode) {
                e.actionNode->setObject(nullptr);
                e.actionNode->release();
                e.actionNode = nullptr;
            }
        }
    }

    void stopPlayingForWidget(ax::ui::Widget* widget, bool allIfRoot) {
        for (auto& e : entries) {
            if ((allIfRoot || e.targetWidget == widget) && e.actionObj && e.actionObj->isPlaying()) {
                e.actionObj->stop();
            }
        }
    }

    void detachDestroyedWidget(ax::ui::Widget* widget) {
        if (!widget) return;
        for (auto& e : entries) {
            if (e.targetWidget == widget) {
                if (e.actionObj && e.actionObj->isPlaying()) e.actionObj->stop();
                if (e.actionNode && e.actionNode->getObject() == widget) {
                    e.actionNode->setObject(nullptr);
                }
                e.targetWidget = nullptr;
            }
        }
    }

    void detachAllAndEvictFromActionManager() {
        for (auto& e : entries) {
            if (e.actionObj && e.actionObj->isPlaying()) e.actionObj->stop();
            if (e.actionNode) e.actionNode->setObject(nullptr);
            e.targetWidget = nullptr;
        }
        if (registeredKeys.empty()) return;
        auto* actionMap =
            ActionManagerExAccessor::GetActionMap(cocostudio::ActionManagerEx::getInstance());
        if (!actionMap) return;
        for (const std::string& key : registeredKeys) {
            actionMap->erase(key);
        }
        registeredKeys.clear();
    }
};

class WidgetActionGuardComponent final : public ax::Component {
public:
    WidgetActionGuardComponent(ax::ui::Widget* ownerWidget, bool isRootGuard, const char* compName)
        : m_ownerWidget(ownerWidget), m_isRootGuard(isRootGuard) {
        init();
        setName(compName);
    }

    ~WidgetActionGuardComponent() override {
        for (const auto& group : m_groups) {
            if (!group) continue;
            if (m_isRootGuard) {
                group->detachAllAndEvictFromActionManager();
            } else {
                group->detachDestroyedWidget(m_ownerWidget);
            }
        }
    }

    void onExit() override {
        ax::Component::onExit();
        for (const auto& group : m_groups) {
            if (group) group->stopPlayingForWidget(m_ownerWidget, m_isRootGuard);
        }
    }

    void addGroup(const std::shared_ptr<WidgetActionGroup>& group) {
        if (group && std::find(m_groups.begin(), m_groups.end(), group) == m_groups.end()) {
            m_groups.push_back(group);
        }
    }

private:
    ax::ui::Widget*                                 m_ownerWidget = nullptr;
    bool                                            m_isRootGuard = false;
    std::vector<std::shared_ptr<WidgetActionGroup>> m_groups;
};

void AttachActionGuardToWidget(ax::ui::Widget* widget,
                               bool isRootGuard,
                               const std::shared_ptr<WidgetActionGroup>& group) {
    if (!widget || !group) return;
    const char* compName =
        isRootGuard ? "__gclient_action_root_guard__" : "__gclient_action_target_guard__";
    if (auto* existing =
            dynamic_cast<WidgetActionGuardComponent*>(widget->getComponent(compName))) {
        existing->addGroup(group);
        return;
    }
    auto* guard = new WidgetActionGuardComponent(widget, isRootGuard, compName);
    guard->addGroup(group);
    if (widget->addComponent(guard)) {
        guard->release();
    } else {
        delete guard;
    }
}

ax::ui::Widget* SeekActionWidgetByActionTag(ax::ui::Widget* root, int actionTag) {
    if (!root) return nullptr;
    if (root->getActionTag() == actionTag) return root;
    for (ax::Node* child : root->getChildren()) {
        if (auto* childWidget = dynamic_cast<ax::ui::Widget*>(child)) {
            if (ax::ui::Widget* found = SeekActionWidgetByActionTag(childWidget, actionTag)) {
                return found;
            }
        }
    }
    return nullptr;
}

std::vector<std::string> BuildActionDictionaryKeys(const std::string& sourceFileName) {
    std::vector<std::string> keys;
    const std::string        normPath = NormalizeAssetPath(sourceFileName);
    if (normPath.empty()) return keys;

    const size_t      slashPos = normPath.find_last_of('/');
    const std::string baseName =
        (slashPos == std::string::npos) ? normPath : normPath.substr(slashPos + 1);
    for (const std::string& scope : {baseName, normPath}) {
        if (scope.empty()) continue;
        AppendUniquePath(keys, scope);
        AppendUniquePath(keys, ReplaceFileExtension(scope, ".json"));
        AppendUniquePath(keys, ReplaceFileExtension(scope, ".pb"));
    }
    return keys;
}

template <typename FrameT, typename InitFn>
void EmitActionFrame(cocostudio::ActionNode* actionNode, int frameId, int& ioSlot, InitFn&& init) {
    auto* frame = new FrameT();
    frame->setFrameIndex(frameId);
    init(frame);
    actionNode->insertFrame(ioSlot++, frame);
    frame->release();
}

void RegisterGuiAnimations(const CSAnimation& anim,
                           const std::string& sourceFileName,
                           ax::ui::Widget* rootWidget) {
    if (!rootWidget || anim.actionlist_size() == 0) return;

    auto* actionMap =
        ActionManagerExAccessor::GetActionMap(cocostudio::ActionManagerEx::getInstance());
    if (!actionMap) return;

    ax::Vector<cocostudio::ActionObject*> actionVec;
    auto                                  group = std::make_shared<WidgetActionGroup>();
    std::vector<ax::ui::Widget*>          boundTargets;

    for (int i = 0; i < anim.actionlist_size(); ++i) {
        const CSAction& pbAction = anim.actionlist(i);
        const float     unitTime = (pbAction.has_unittime() && pbAction.unittime() > 0.0f)
                                       ? pbAction.unittime()
                                       : (1.0f / 60.0f);
        auto* actionObj = new cocostudio::ActionObject();
        actionObj->setName(pbAction.name().c_str());
        actionObj->setLoop(pbAction.loop());
        actionObj->setUnitTime(unitTime);

        for (int n = 0; n < pbAction.actionnodelist_size(); ++n) {
            const CSActionNode& pbNode     = pbAction.actionnodelist(n);
            auto*               actionNode = new cocostudio::ActionNode();
            actionNode->setActionTag(pbNode.actiontag());
            actionNode->setUnitTime(unitTime);

            ax::ui::Widget* targetWidget =
                SeekActionWidgetByActionTag(rootWidget, pbNode.actiontag());
            if (targetWidget) {
                actionNode->setObject(targetWidget);
                boundTargets.push_back(targetWidget);
            }

            actionObj->retain();
            actionNode->retain();
            group->entries.push_back({actionObj, actionNode, targetWidget});

            int moveSlot = 0, scaleSlot = 0, rotSlot = 0, fadeSlot = 0, tintSlot = 0;
            for (int f = 0; f < pbNode.actionframelist_size(); ++f) {
                const CSActionFrame& pbFrame = pbNode.actionframelist(f);
                const int            frameId = pbFrame.frameid();

                if (pbFrame.has_positionx() || pbFrame.has_positiony()) {
                    EmitActionFrame<cocostudio::ActionMoveFrame>(
                        actionNode, frameId, moveSlot, [&](auto* fr) {
                            fr->setPosition(ax::Vec2(
                                pbFrame.has_positionx() ? pbFrame.positionx() : 0.0f,
                                pbFrame.has_positiony() ? pbFrame.positiony() : 0.0f));
                        });
                }
                if (pbFrame.has_scalex() || pbFrame.has_scaley()) {
                    EmitActionFrame<cocostudio::ActionScaleFrame>(
                        actionNode, frameId, scaleSlot, [&](auto* fr) {
                            fr->setScaleX(pbFrame.has_scalex() ? pbFrame.scalex() : 1.0f);
                            fr->setScaleY(pbFrame.has_scaley() ? pbFrame.scaley() : 1.0f);
                        });
                }
                if (pbFrame.has_rotation()) {
                    EmitActionFrame<cocostudio::ActionRotationFrame>(
                        actionNode, frameId, rotSlot, [&](auto* fr) {
                            fr->setRotation(pbFrame.rotation());
                        });
                }
                if (pbFrame.has_opacity()) {
                    EmitActionFrame<cocostudio::ActionFadeFrame>(
                        actionNode, frameId, fadeSlot, [&](auto* fr) {
                            fr->setOpacity(pbFrame.opacity());
                        });
                }
                if (pbFrame.has_colorr() || pbFrame.has_colorg() || pbFrame.has_colorb()) {
                    EmitActionFrame<cocostudio::ActionTintFrame>(
                        actionNode, frameId, tintSlot, [&](auto* fr) {
                            fr->setColor(MakeOptColor3B(pbFrame.has_colorr(), pbFrame.colorr(),
                                                        pbFrame.has_colorg(), pbFrame.colorg(),
                                                        pbFrame.has_colorb(), pbFrame.colorb()));
                        });
                }
            }

            actionObj->addActionNode(actionNode);
            actionNode->release();
        }

        actionVec.pushBack(actionObj);
        actionObj->release();
    }

    const std::vector<std::string> keys = BuildActionDictionaryKeys(sourceFileName);
    group->registeredKeys               = keys;

    AttachActionGuardToWidget(rootWidget, true, group);
    for (ax::ui::Widget* targetWidget : boundTargets) {
        AttachActionGuardToWidget(targetWidget, false, group);
    }

    for (const std::string& key : keys) {
        if (auto it = actionMap->find(key); it != actionMap->end()) {
            for (auto* prevObj : it->second) {
                if (prevObj && prevObj->isPlaying()) prevObj->stop();
            }
        }
        (*actionMap)[key] = actionVec;
    }
}

bool ValidateSceneParticlePlist(const std::string& rawPlistPath,
                                const std::string& baseDir,
                                std::string* outResolvedPlist) {
    for (const std::string& cand : BuildRelativeCandidatePaths(rawPlistPath, baseDir)) {
        std::string xmlContent;
        if (!VerifyValidXmlPlistOnDisk(cand, &xmlContent)) continue;

        const std::string embeddedData = ExtractXmlKeyStringValue(xmlContent, "textureImageData");
        const std::string texFile      = ExtractXmlKeyStringValue(xmlContent, "textureFileName");
        if (embeddedData.empty() && !texFile.empty()) {
            const std::string plistDir = ExtractDirectoryPrefix(cand);
            if (!ProbeAndLoadTextureAcrossRoots(texFile, plistDir) &&
                !DoesAssetOrTextureVariantExist(JoinBaseAndRelativePath(plistDir, texFile)) &&
                !DoesAssetOrTextureVariantExist(NormalizeAssetPath(texFile))) {
                LogGuiWarnFmt("Skipping CCParticleSystemQuad '%s': missing particle texture '%s'",
                              cand.c_str(),
                              texFile.c_str());
                return false;
            }
        }
        if (outResolvedPlist) *outResolvedPlist = cand;
        return true;
    }
    return false;
}

void AddRenderComponent(cocos2d::CCNode* owner, cocos2d::CCNode* child, const std::string& name) {
    if (owner && child) {
        owner->addComponent(cocos2d::extension::CCComRender::create(child, name.c_str()));
    }
}

void AttachSceneComponent(cocos2d::CCNode* node,
                          const CSComponent& comp,
                          const std::string& baseDir) {
    if (!node) return;

    const std::string& cls      = comp.classname();
    const std::string& compName = comp.name();

    std::string rawPath;
    std::string rawPlist;
    int32_t     resType = 0;
    if (comp.has_filedata()) {
        resType = comp.filedata().resourcetype();
        if (comp.filedata().has_path()) rawPath = comp.filedata().path();
        if (comp.filedata().has_plist()) rawPlist = comp.filedata().plist();
    }

    const std::string resPath =
        (resType == 1) ? NormalizeAssetPath(rawPath) : ResolveLocalAssetPath(rawPath, baseDir);
    const std::string plistPath = ResolveLocalAssetPath(rawPlist, baseDir);

    if (cls == "CCSprite") {
        cocos2d::CCSprite* sprite = nullptr;
        if (resType == 1) {
            if (!rawPlist.empty()) PbGuiLoader::LoadPlistSpriteFramesSafe(rawPlist, baseDir);
            if (!resPath.empty()) {
                auto* sfc = ax::SpriteFrameCache::getInstance();
                if (sfc && sfc->getSpriteFrameByName(resPath.c_str()) != nullptr) {
                    sprite = cocos2d::CCSprite::createWithSpriteFrameName(resPath.c_str());
                }
            }
        } else if (!resPath.empty() &&
                   CanLoadWidgetTexture(resPath, cocos2d::ui::UI_TEX_TYPE_LOCAL)) {
            sprite = cocos2d::CCSprite::create(resPath.c_str());
        }
        AddRenderComponent(node, sprite, compName);
    } else if (cls == "CCTMXTiledMap") {
        if (!resPath.empty() && DoesExactAssetFileExist(resPath)) {
            AddRenderComponent(node, cocos2d::CCTMXTiledMap::create(resPath.c_str()), compName);
        }
    } else if (cls == "CCParticleSystemQuad") {
        if (!rawPath.empty()) {
            std::string verifiedPlist;
            if (ValidateSceneParticlePlist(rawPath, baseDir, &verifiedPlist)) {
                if (auto* ps = cocos2d::CCParticleSystemQuad::create(verifiedPlist.c_str())) {
                    ps->setPosition(cocos2d::CCPointZero);
                    AddRenderComponent(node, ps, compName);
                }
            } else {
                LogGuiWarnFmt(
                    "Skipping CCParticleSystemQuad::create: missing or invalid plist '%s' (base '%s')",
                    rawPath.c_str(),
                    baseDir.c_str());
            }
        }
    } else if (cls == "CCArmature") {
        if (!resPath.empty()) {
            if (!plistPath.empty()) {
                XmlbArmatureLoader::AddDataFromXmlbFile(std::string(), plistPath, resPath);
            } else {
                XmlbArmatureLoader::AddDataFromXmlbFile(resPath, baseDir);
            }
            const size_t slashPos = resPath.find_last_of('/');
            const size_t dotPos   = resPath.find_last_of('.');
            const size_t start    = (slashPos == std::string::npos) ? 0 : slashPos + 1;
            const size_t len      = (dotPos == std::string::npos || dotPos < start)
                                        ? std::string::npos
                                        : (dotPos - start);
            const std::string armName = resPath.substr(start, len);

            auto* armMgr = cocostudio::ArmatureDataManager::getInstance();
            if (armMgr && !armName.empty() && armMgr->getArmatureData(armName.c_str()) != nullptr) {
                if (auto* arm = cocos2d::extension::CCArmature::create(armName.c_str())) {
                    if (comp.has_selectedactionname() && !comp.selectedactionname().empty()) {
                        const std::string& actionName = comp.selectedactionname();
                        auto*              anim       = arm->getAnimation();
                        auto*              animData   = anim ? anim->getAnimationData() : nullptr;
                        if (anim && animData &&
                            animData->getMovement(actionName.c_str()) != nullptr) {
                            anim->play(actionName.c_str());
                        } else {
                            LogGuiWarnFmt("Skipping missing armature movement '%s' on '%s'",
                                          actionName.c_str(),
                                          armName.c_str());
                        }
                    }
                    AddRenderComponent(node, arm, compName);
                }
            } else {
                LogGuiWarnFmt("Skipping CCArmature::create: armature '%s' not registered from '%s'",
                              armName.c_str(),
                              resPath.c_str());
            }
        }
    } else if (cls == "GUIComponent") {
        if (!resPath.empty()) {
            if (auto* uiWidget = PbGuiLoader::WidgetFromPbFile(resPath)) {
                auto* uiLayer = cocos2d::ui::TouchGroup::create();
                uiLayer->addWidget(uiWidget);
                AddRenderComponent(node, uiLayer, compName);
            }
        }
    } else if (cls == "CCComAudio") {
        auto* audioComp = cocos2d::extension::CCComAudio::create();
        audioComp->setName(compName.c_str());
        if (!resPath.empty()) audioComp->setFile(resPath.c_str());
        node->addComponent(audioComp);
    } else if (cls == "CCComAttribute") {
        auto* attrComp = cocos2d::extension::CCComAttribute::create();
        attrComp->setName(compName.c_str());
        if (!resPath.empty() && DoesExactAssetFileExist(resPath)) {
            attrComp->parse(resPath.c_str());
        }
        node->addComponent(attrComp);
    }
}

} // namespace
#endif // GCLIENT_ENABLE_COCOS2DX

cocos2d::ui::Widget* PbGuiLoader::CreateWidgetByClassName(const std::string& className) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    switch (ClassifyWidgetClass(className)) {
        case GuiWidgetKind::Button:      return cocos2d::ui::Button::create();
        case GuiWidgetKind::CheckBox:    return cocos2d::ui::CheckBox::create();
        case GuiWidgetKind::ImageView:   return cocos2d::ui::ImageView::create();
        case GuiWidgetKind::Label:       return cocos2d::ui::Label::create();
        case GuiWidgetKind::LabelAtlas:  return cocos2d::ui::LabelAtlas::create();
        case GuiWidgetKind::LabelBMFont: return cocos2d::ui::LabelBMFont::create();
        case GuiWidgetKind::LoadingBar:  return cocos2d::ui::LoadingBar::create();
        case GuiWidgetKind::Slider:      return cocos2d::ui::Slider::create();
        case GuiWidgetKind::TextField:   return cocos2d::ui::TextField::create();
        case GuiWidgetKind::Layout:      return cocos2d::ui::Layout::create();
        case GuiWidgetKind::ScrollView:  return cocos2d::ui::ScrollView::create();
        case GuiWidgetKind::ListView:    return cocos2d::ui::ListView::create();
        case GuiWidgetKind::PageView:    return cocos2d::ui::PageView::create();
        case GuiWidgetKind::GenericWidget:
        default:                         return cocos2d::ui::Widget::create();
    }
#else
    (void)className;
    return nullptr;
#endif
}

bool PbGuiLoader::LoadPlistSpriteFramesSafe(const std::string& plistPath,
                                            const std::string& baseDir) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    if (plistPath.empty()) return false;

    CSData csData;
    csData.set_resourcetype(0);
    csData.set_path(plistPath);

    std::vector<std::string> candidates;
    AppendUniquePath(candidates, ResolveCsDataPath(csData, baseDir, nullptr));
    for (const std::string& c : BuildRelativeCandidatePaths(plistPath, baseDir)) {
        AppendUniquePath(candidates, c);
    }

    for (const std::string& cand : candidates) {
        if (PlistbLoader::AddSpriteFramesWithBinary(cand)) return true;
    }

    auto* sfc = ax::SpriteFrameCache::getInstance();
    if (!sfc) return false;

    for (const std::string& cand : candidates) {
        const std::string xmlCand =
            endsWithAsciiCI(cand, ".plistb") ? cand.substr(0, cand.size() - 1) : cand;
        if (!endsWithAsciiCI(xmlCand, ".plist")) continue;

        std::string xmlContent;
        if (!VerifyValidXmlPlistOnDisk(xmlCand, &xmlContent)) continue;

        std::string texName = ExtractXmlKeyStringValue(xmlContent, "realTextureFileName");
        if (texName.empty()) texName = ExtractXmlKeyStringValue(xmlContent, "textureFileName");

        cocos2d::CCTexture2D* explicitTex = nullptr;
        if (!texName.empty()) {
            explicitTex =
                ProbeAndLoadTextureAcrossRoots(texName, ExtractDirectoryPrefix(xmlCand));
            if (!explicitTex) {
                LogGuiWarnFmt("Skipping XML sprite sheet '%s': missing atlas texture '%s'",
                              xmlCand.c_str(),
                              texName.c_str());
                continue;
            }
        }

        if (explicitTex) {
            sfc->addSpriteFramesWithFile(xmlCand.c_str(), explicitTex);
        } else {
            sfc->addSpriteFramesWithFile(xmlCand.c_str());
        }
        return true;
    }
    return false;
#else
    (void)plistPath;
    (void)baseDir;
    return false;
#endif
}

cocos2d::ui::Widget* PbGuiLoader::WidgetFromPbFile(const std::string& fileName) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normInput = NormalizeAssetPath(fileName);
    const std::string baseDir   = ExtractDirectoryPrefix(normInput);
    const std::string pbPath    = ReplaceFileExtension(normInput, ".pb");

    unsigned long  fileSize = 0;
    DecryptResult  diag;
    unsigned char* rawData = LoadAndDecryptFileData(pbPath, &fileSize, &diag);
    if (!rawData || fileSize == 0) {
        cocos2d::CCLog("PbGuiLoader::WidgetFromPbFile: file[%s] not exist!", pbPath.c_str());
        delete[] rawData;
        return nullptr;
    }

    cocos2d::ui::Widget* widget =
        WidgetFromPbBuffer(rawData, static_cast<size_t>(fileSize), baseDir, normInput);
    delete[] rawData;
    cocos2d::CCLog("widgetFromPbFile load %s end", pbPath.c_str());
    return widget;
#else
    (void)fileName;
    return nullptr;
#endif
}

cocos2d::ui::Widget* PbGuiLoader::WidgetFromPbBuffer(const uint8_t* data,
                                                     size_t size,
                                                     const std::string& baseDir,
                                                     const std::string& sourceFileName) {
    if (!data || size == 0 || IsBtEncryptedBuffer(data, size)) return nullptr;

    CSGUIRoot root;
    if (!root.ParseFromArray(data, static_cast<int>(size))) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
        cocos2d::CCLog("parse gui file:%s failed", sourceFileName.c_str());
#endif
        return nullptr;
    }
    return CreateWidgetFromPbRoot(root, baseDir, sourceFileName);
}

cocos2d::ui::Widget* PbGuiLoader::CreateWidgetFromPbRoot(const CSGUIRoot& root,
                                                         const std::string& baseDir,
                                                         const std::string& sourceFileName) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normBaseDir = NormalizeAssetPath(baseDir);
    for (int i = 0; i < root.textures_size(); ++i) {
        LoadPlistSpriteFramesSafe(root.textures(i), normBaseDir);
    }
    if (!root.has_widgettree()) return nullptr;

    cocos2d::ui::Widget* rootWidget = CreateWidgetFromPb(root.widgettree(), normBaseDir);
    if (root.has_animation()) {
        RegisterGuiAnimations(root.animation(), sourceFileName, rootWidget);
    }
    return rootWidget;
#else
    (void)root;
    (void)baseDir;
    (void)sourceFileName;
    return nullptr;
#endif
}

cocos2d::ui::Widget* PbGuiLoader::CreateWidgetFromPb(const CSWidget& pbWidget,
                                                     const std::string& baseDir) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string   cls    = pbWidget.has_classname() ? pbWidget.classname() : "Widget";
    const GuiWidgetKind kind   = ClassifyWidgetClass(cls);
    const CSOptions&    opt    = pbWidget.options();
    cocos2d::ui::Widget* widget = CreateWidgetByClassName(cls);
    if (!widget) return nullptr;

    ApplyBaseWidgetOptions(widget, opt);

    switch (kind) {
        case GuiWidgetKind::Button:
            ApplyButtonOptions(static_cast<cocos2d::ui::Button*>(widget), opt, baseDir);
            break;
        case GuiWidgetKind::CheckBox:
            ApplyCheckBoxOptions(static_cast<cocos2d::ui::CheckBox*>(widget), opt, baseDir);
            break;
        case GuiWidgetKind::ImageView:
            ApplyImageViewOptions(static_cast<cocos2d::ui::ImageView*>(widget), opt, baseDir);
            break;
        case GuiWidgetKind::Label:
            ApplyLabelOptions(static_cast<cocos2d::ui::Label*>(widget), opt);
            break;
        case GuiWidgetKind::LabelAtlas:
            ApplyLabelAtlasOptions(static_cast<cocos2d::ui::LabelAtlas*>(widget), opt, baseDir);
            break;
        case GuiWidgetKind::LabelBMFont:
            ApplyLabelBMFontOptions(static_cast<cocos2d::ui::LabelBMFont*>(widget), opt, baseDir);
            break;
        case GuiWidgetKind::LoadingBar:
            ApplyLoadingBarOptions(static_cast<cocos2d::ui::LoadingBar*>(widget), opt, baseDir);
            break;
        case GuiWidgetKind::Slider:
            ApplySliderOptions(static_cast<cocos2d::ui::Slider*>(widget), opt, baseDir);
            break;
        case GuiWidgetKind::TextField:
            ApplyTextFieldOptions(static_cast<cocos2d::ui::TextField*>(widget), opt);
            break;
        case GuiWidgetKind::Layout:
        case GuiWidgetKind::PageView:
            ApplyLayoutOptions(static_cast<cocos2d::ui::Layout*>(widget), opt, baseDir);
            break;
        case GuiWidgetKind::ScrollView:
            ApplyScrollViewOptions(static_cast<cocos2d::ui::ScrollView*>(widget), opt, baseDir);
            break;
        case GuiWidgetKind::ListView:
            ApplyListViewOptions(static_cast<cocos2d::ui::ListView*>(widget), opt, baseDir);
            break;
        case GuiWidgetKind::GenericWidget:
            break;
    }

    for (int i = 0; i < pbWidget.children_size(); ++i) {
        const CSWidget&      childPb = pbWidget.children(i);
        cocos2d::ui::Widget* child   = CreateWidgetFromPb(childPb, baseDir);
        if (!child) continue;

        if (kind == GuiWidgetKind::PageView) {
            if (auto* pageLayout = dynamic_cast<cocos2d::ui::Layout*>(child)) {
                static_cast<cocos2d::ui::PageView*>(widget)->addPage(pageLayout);
            } else {
                widget->addChild(child);
            }
        } else if (kind == GuiWidgetKind::ListView) {
            static_cast<cocos2d::ui::ListView*>(widget)->pushBackCustomItem(child);
        } else {
            widget->addChild(child);
        }
        SyncPercentSizeAndPosition(child, childPb.options(), /*onlyWhenPercentMode=*/true);
    }

    if (auto* layoutWidget = dynamic_cast<cocos2d::ui::Layout*>(widget)) {
        TriggerLayoutPass(layoutWidget);
    }
    return widget;
#else
    (void)pbWidget;
    (void)baseDir;
    return nullptr;
#endif
}

cocos2d::CCNode* PbGuiLoader::SceneFromPbFile(const std::string& fileName) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    const std::string normInput = NormalizeAssetPath(fileName);
    const std::string baseDir   = ExtractDirectoryPrefix(normInput);
    const std::string pbPath    = ReplaceFileExtension(normInput, ".pb");

    unsigned long  fileSize = 0;
    DecryptResult  diag;
    unsigned char* rawData = LoadAndDecryptFileData(pbPath, &fileSize, &diag);
    if (!rawData || fileSize == 0) {
        cocos2d::CCLog("PbGuiLoader::SceneFromPbFile: file[%s] not exist!", pbPath.c_str());
        delete[] rawData;
        return nullptr;
    }

    CSSceneRoot root;
    const bool  parsed = root.ParseFromArray(rawData, static_cast<int>(fileSize));
    delete[] rawData;
    if (!parsed) {
        cocos2d::CCLog("PbGuiLoader::SceneFromPbFile: parse scene file:%s failed", pbPath.c_str());
        return nullptr;
    }
    return CreateSceneFromPbRoot(root, baseDir);
#else
    (void)fileName;
    return nullptr;
#endif
}

cocos2d::CCNode* PbGuiLoader::CreateSceneFromPbRoot(const CSSceneRoot& root,
                                                    const std::string& baseDir) {
#if defined(GCLIENT_ENABLE_COCOS2DX) || !defined(GCLIENT_STANDALONE_BUILD)
    auto* node = cocos2d::CCNode::create();
    if (!node) return nullptr;

    node->setPosition(
        cocos2d::CCPoint(static_cast<float>(root.x()), static_cast<float>(root.y())));
    node->setVisible(root.has_visible() ? root.visible() : true);
    if (root.has_objecttag()) node->setTag(root.objecttag());
    node->setLocalZOrder(root.zorder());
    node->setScaleX(root.has_scalex() ? root.scalex() : 1.0f);
    node->setScaleY(root.has_scaley() ? root.scaley() : 1.0f);
    node->setRotation(static_cast<float>(root.rotation()));

    for (int i = 0; i < root.components_size(); ++i) {
        AttachSceneComponent(node, root.components(i), baseDir);
    }
    for (int i = 0; i < root.gameobjects_size(); ++i) {
        if (auto* child = CreateSceneFromPbRoot(root.gameobjects(i), baseDir)) {
            node->addChild(child);
        }
    }
    return node;
#else
    (void)root;
    (void)baseDir;
    return nullptr;
#endif
}

} // namespace assets
} // namespace gclient
