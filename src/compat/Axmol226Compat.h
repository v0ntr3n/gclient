#pragma once

// ============================================================================
// Axmol226Compat.h — Cocos2d-x 2.2.6 -> Axmol v2.11.5 LTS (x64 C++20) Bridge
// ============================================================================

#include "cocos2d.h"
#include "audio/AudioEngine.h"
#include "ui/CocosGUI.h"
#include "cocostudio/CocoStudio.h"
#include "common/KestrelBinaryReader.h"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

struct lua_State;

#ifndef USING_NS_CC
#define USING_NS_CC using namespace ax
#endif
#ifndef USING_NS_CC_EXT
#define USING_NS_CC_EXT using namespace ax::extension
#endif
#ifndef schedule_selector
#define schedule_selector(_SELECTOR) AX_SCHEDULE_SELECTOR(_SELECTOR)
#endif
#ifndef callfunc_selector
#define callfunc_selector(_SELECTOR) AX_CALLFUNC_SELECTOR(_SELECTOR)
#endif
#ifndef callfuncN_selector
#define callfuncN_selector(_SELECTOR) AX_CALLFUNCN_SELECTOR(_SELECTOR)
#endif
#ifndef callfuncO_selector
#define callfuncO_selector(_SELECTOR) AX_CALLFUNCO_SELECTOR(_SELECTOR)
#endif

namespace ax {

using CCObject             = ax::Object;
using CCNode               = ax::Node;
using CCNodeRGBA           = ax::Node;
using CCSprite             = ax::Sprite;
using CCSpriteBatchNode    = ax::SpriteBatchNode;
using CCSpriteFrame        = ax::SpriteFrame;
using CCSpriteFrameCache   = ax::SpriteFrameCache;
using CCTexture2D          = ax::Texture2D;
using CCTextureCache       = ax::TextureCache;
using CCDirector           = ax::Director;
using CCScheduler          = ax::Scheduler;
using CCApplication        = ax::Application;
using CCEGLView            = ax::RenderViewImpl;
using CCEGLViewProtocol    = ax::RenderView;
using CCFileUtils          = ax::FileUtils;
using CCScene              = ax::Scene;
using CCLayer              = ax::Layer;
using CCLayerColor         = ax::LayerColor;
using CCLayerGradient      = ax::LayerGradient;
using CCDrawNode           = ax::DrawNode;
using CCLabelTTF           = ax::Label;
using CCLabelBMFont        = ax::Label;
using CCLabelAtlas         = ax::LabelAtlas;
using CCRenderTexture      = ax::RenderTexture;
using CCParticleSystemQuad = ax::ParticleSystemQuad;
using CCTMXTiledMap        = ax::TMXTiledMap;
using CCComponent          = ax::Component;
using CCAction             = ax::Action;
using CCFiniteTimeAction   = ax::FiniteTimeAction;
using CCActionInterval     = ax::ActionInterval;
using CCGLProgram          = ax::backend::ProgramState;

using CCPoint                 = ax::Vec2;
using CCSize                  = ax::Vec2;
using CCRect                  = ax::Rect;
using ccColor3B               = ax::Color3B;
using ccColor4B               = ax::Color4B;
using ccColor4F               = ax::Color4F;
using ccBlendFunc             = ax::BlendFunc;
using CCTextAlignment         = ax::TextHAlignment;
using CCVerticalTextAlignment = ax::TextVAlignment;

inline constexpr ax::Vec2 CCPointZero{0.0f, 0.0f};
inline constexpr ax::Vec2 CCSizeZero{0.0f, 0.0f};
inline constexpr ax::Rect CCRectZero{0.0f, 0.0f, 0.0f, 0.0f};

inline constexpr int  kCCNodeTagInvalid                  = ax::Node::INVALID_TAG;
inline constexpr auto kCCImageFormatPNG                  = ax::Image::Format::PNG;
inline constexpr auto kCCImageFormatJPEG                 = ax::Image::Format::JPG;
inline constexpr auto kCCTexture2DPixelFormat_RGBA8888   = ax::backend::PixelFormat::RGBA8;
inline constexpr auto kCCTexture2DPixelFormat_RGBA4444   = ax::backend::PixelFormat::RGBA4;
inline constexpr auto kCCTexture2DPixelFormat_RGB565     = ax::backend::PixelFormat::RGB565;

inline constexpr ResolutionPolicy kResolutionExactFit    = ResolutionPolicy::EXACT_FIT;
inline constexpr ResolutionPolicy kResolutionNoBorder    = ResolutionPolicy::NO_BORDER;
inline constexpr ResolutionPolicy kResolutionShowAll     = ResolutionPolicy::SHOW_ALL;
inline constexpr ResolutionPolicy kResolutionFixedHeight = ResolutionPolicy::FIXED_HEIGHT;
inline constexpr ResolutionPolicy kResolutionFixedWidth  = ResolutionPolicy::FIXED_WIDTH;
inline constexpr ResolutionPolicy kResolutionUnKnown     = ResolutionPolicy::UNKNOWN;

inline ax::Color3B ccc3(uint8_t r, uint8_t g, uint8_t b) { return ax::Color3B(r, g, b); }
inline ax::Color4B ccc4(uint8_t r, uint8_t g, uint8_t b, uint8_t a) { return ax::Color4B(r, g, b, a); }
inline ax::Color4F ccc4f(float r, float g, float b, float a) { return ax::Color4F(r, g, b, a); }

void CCLog(const char* format, ...);

namespace compat_detail {
template <typename T, typename... Args>
inline T* makeAutoreleased(Args&&... args) {
    auto* ret = new T(std::forward<Args>(args)...);
    ret->autorelease();
    return ret;
}
} // namespace compat_detail

class CCString : public ax::Object {
public:
    CCString() = default;
    explicit CCString(std::string s) : m_sString(s), m_str(std::move(s)) {}
    explicit CCString(const char* s) : m_sString(s ? s : ""), m_str(m_sString) {}
    ~CCString() override = default;

    static CCString* create(const std::string& s) { return compat_detail::makeAutoreleased<CCString>(s); }
    static CCString* createWithData(const unsigned char* data, size_t len) {
        return compat_detail::makeAutoreleased<CCString>(
            (data && len > 0) ? std::string(reinterpret_cast<const char*>(data), len) : std::string());
    }
    static CCString* createWithFormat(const char* fmt, ...);

    const char* getCString() const { return m_str.c_str(); }
    const std::string& getString() const { return m_str; }
    unsigned int length() const { return static_cast<unsigned int>(m_str.size()); }
    int intValue() const { return std::atoi(m_str.c_str()); }
    unsigned int uintValue() const { return static_cast<unsigned int>(std::strtoul(m_str.c_str(), nullptr, 10)); }
    float floatValue() const { return std::strtof(m_str.c_str(), nullptr); }
    double doubleValue() const { return std::strtod(m_str.c_str(), nullptr); }
    bool boolValue() const {
        return m_str == "1" || gclient::common::equalsAsciiCI(m_str, "true") || m_str == "yes";
    }

    std::string m_sString;
    void setString(std::string s) { m_str = std::move(s); m_sString = m_str; }

private:
    std::string m_str;
};

class CCInteger : public ax::Object {
public:
    explicit CCInteger(int v = 0) : m_nValue(v) {}
    ~CCInteger() override = default;

    static CCInteger* create(int v) { return compat_detail::makeAutoreleased<CCInteger>(v); }
    int getValue() const { return m_nValue; }

private:
    int m_nValue = 0;
};

class CCArray : public ax::Object {
public:
    CCArray() = default;
    explicit CCArray(size_t capacity) { m_data.reserve(static_cast<ssize_t>(capacity)); }
    ~CCArray() override { removeAllObjects(); }

    static CCArray* create() { return compat_detail::makeAutoreleased<CCArray>(); }
    static CCArray* createWithCapacity(size_t capacity) { return compat_detail::makeAutoreleased<CCArray>(capacity); }
    static CCArray* createWithObject(ax::Object* obj) {
        auto* ret = create();
        ret->addObject(obj);
        return ret;
    }

    bool init() { return true; }
    bool initWithCapacity(size_t capacity) { m_data.reserve(static_cast<ssize_t>(capacity)); return true; }
    unsigned int count() const { return static_cast<unsigned int>(m_data.size()); }

    ax::Object* objectAtIndex(size_t index) const {
        return (index < static_cast<size_t>(m_data.size())) ? m_data.at(static_cast<ssize_t>(index)) : nullptr;
    }
    ax::Object* lastObject() const { return m_data.empty() ? nullptr : m_data.back(); }
    ax::Object* randomObject() const {
        return m_data.empty() ? nullptr
                              : m_data.at(static_cast<ssize_t>(static_cast<size_t>(std::rand()) % static_cast<size_t>(m_data.size())));
    }

    bool containsObject(ax::Object* obj) const { return obj != nullptr && m_data.contains(obj); }
    ssize_t indexOfObject(ax::Object* obj) const { return obj ? m_data.getIndex(obj) : -1; }

    void addObject(ax::Object* obj) { if (obj) m_data.pushBack(obj); }
    void addObjectsFromArray(CCArray* other) {
        if (!other) return;
        for (ssize_t i = 0; i < other->m_data.size(); ++i) addObject(other->m_data.at(i));
    }
    void insertObject(ax::Object* obj, size_t index) {
        if (!obj) return;
        if (index >= static_cast<size_t>(m_data.size())) m_data.pushBack(obj);
        else m_data.insert(static_cast<ssize_t>(index), obj);
    }

    void removeLastObject(bool /*releaseObj*/ = true) { if (!m_data.empty()) m_data.popBack(); }
    void removeObject(ax::Object* obj, bool /*releaseObj*/ = true) { if (obj) m_data.eraseObject(obj, true); }
    void removeObjectAtIndex(size_t index, bool /*releaseObj*/ = true) {
        if (index < static_cast<size_t>(m_data.size())) m_data.erase(static_cast<ssize_t>(index));
    }
    void removeAllObjects() { m_data.clear(); }
    void fastRemoveObject(ax::Object* obj) { removeObject(obj); }
    void fastRemoveObjectAtIndex(size_t index) { removeObjectAtIndex(index); }

    const ax::Vector<ax::Object*>& innerVector() const { return m_data; }

private:
    ax::Vector<ax::Object*> m_data;
};

class CCDictionary : public ax::Object {
public:
    CCDictionary() = default;
    ~CCDictionary() override { removeAllObjects(); }

    static CCDictionary* create() { return compat_detail::makeAutoreleased<CCDictionary>(); }
    static CCDictionary* createWithContentsOfFile(const char* fileName);

    unsigned int count() const { return static_cast<unsigned int>(m_strMap.size() + m_intMap.size()); }

    ax::Object* objectForKey(const std::string& key) const { return findIn(m_strMap, key); }
    ax::Object* objectForKey(intptr_t key) const { return findIn(m_intMap, key); }

    const CCString* valueForKey(const std::string& key) const {
        if (auto* s = dynamic_cast<CCString*>(objectForKey(key))) return s;
        static const CCString kEmpty("");
        return &kEmpty;
    }

    void setObject(ax::Object* obj, const std::string& key) { putIn(m_strMap, key, obj); }
    void setObject(ax::Object* obj, intptr_t key) { putIn(m_intMap, key, obj); }

    void removeObjectForKey(const std::string& key) { eraseFrom(m_strMap, key); }
    void removeObjectForKey(intptr_t key) { eraseFrom(m_intMap, key); }

    void removeAllObjects() { clearMap(m_strMap); clearMap(m_intMap); }

    CCArray* allKeys() const {
        auto* arr = CCArray::createWithCapacity(m_strMap.size() + m_intMap.size());
        for (const auto& [k, _] : m_strMap) arr->addObject(CCString::create(k));
        for (const auto& [k, _] : m_intMap) arr->addObject(CCInteger::create(static_cast<int>(k)));
        return arr;
    }

    const std::unordered_map<std::string, ax::Object*>& stringEntries() const { return m_strMap; }

private:
    template <typename Map, typename K>
    static ax::Object* findIn(const Map& m, const K& key) {
        auto it = m.find(key);
        return (it != m.end()) ? it->second : nullptr;
    }
    template <typename Map, typename K>
    static void putIn(Map& m, const K& key, ax::Object* obj) {
        if (!obj) return;
        obj->retain();
        if (auto it = m.find(key); it != m.end() && it->second) it->second->release();
        m[key] = obj;
    }
    template <typename Map, typename K>
    static void eraseFrom(Map& m, const K& key) {
        if (auto it = m.find(key); it != m.end()) {
            if (it->second) it->second->release();
            m.erase(it);
        }
    }
    template <typename Map>
    static void clearMap(Map& m) {
        for (auto& [_, v] : m) {
            if (v) v->release();
        }
        m.clear();
    }

    std::unordered_map<std::string, ax::Object*> m_strMap;
    std::unordered_map<intptr_t, ax::Object*>    m_intMap;
};

namespace ui {

using Label                     = ax::ui::Text;
using LabelAtlas                = ax::ui::TextAtlas;
using LabelBMFont               = ax::ui::TextBMFont;
using LayoutBackGroundColorType = ax::ui::Layout::BackGroundColorType;
using LayoutType                = ax::ui::Layout::Type;
using TextureResType            = ax::ui::Widget::TextureResType;
using TouchEventType            = ax::ui::Widget::TouchEventType;
using SizeType                  = ax::ui::Widget::SizeType;
using PositionType              = ax::ui::Widget::PositionType;
using LoadingBarType            = ax::ui::LoadingBar::Direction;
using SCROLLVIEW_DIR            = ax::ui::ScrollView::Direction;
using ListViewGravity           = ax::ui::ListView::Gravity;
using LinearGravity             = ax::ui::LinearLayoutParameter::LinearGravity;
using RelativeAlign             = ax::ui::RelativeLayoutParameter::RelativeAlign;
using RichElementType           = ax::ui::RichElement::Type;

inline constexpr auto UI_TEX_TYPE_LOCAL         = ax::ui::Widget::TextureResType::LOCAL;
inline constexpr auto UI_TEX_TYPE_PLIST         = ax::ui::Widget::TextureResType::PLIST;
inline constexpr auto LoadingBarTypeLeft        = ax::ui::LoadingBar::Direction::LEFT;
inline constexpr auto LoadingBarTypeRight       = ax::ui::LoadingBar::Direction::RIGHT;
inline constexpr auto SCROLLVIEW_DIR_NONE       = ax::ui::ScrollView::Direction::NONE;
inline constexpr auto SCROLLVIEW_DIR_VERTICAL   = ax::ui::ScrollView::Direction::VERTICAL;
inline constexpr auto SCROLLVIEW_DIR_HORIZONTAL = ax::ui::ScrollView::Direction::HORIZONTAL;
inline constexpr auto SCROLLVIEW_DIR_BOTH       = ax::ui::ScrollView::Direction::BOTH;
inline constexpr auto RICH_TEXT                 = ax::ui::RichElement::Type::TEXT;
inline constexpr auto RICH_IMAGE                = ax::ui::RichElement::Type::IMAGE;
inline constexpr auto RICH_CUSTOM               = ax::ui::RichElement::Type::CUSTOM;

class TouchGroup : public ax::Layer {
public:
    TouchGroup() = default;
    ~TouchGroup() override = default;

    static TouchGroup* create() {
        auto* ret = new TouchGroup();
        if (ret->init()) {
            ret->autorelease();
            return ret;
        }
        delete ret;
        return nullptr;
    }

    bool init() override;
    void addWidget(ax::ui::Widget* widget);
    void removeWidget(ax::ui::Widget* widget);
    ax::ui::Widget* getWidgetByTag(int tag);
    ax::ui::Widget* getWidgetByName(const char* name);
    ax::ui::Widget* getRootWidget() const { return m_rootWidget; }
    void clear();
    void clearTouchStat();

    void setTouchPriority(int priority) { m_touchPriority = priority; }
    int getTouchPriority() const { return m_touchPriority; }
    ax::Node* getRootWidgetNode() const { return m_rootWidget; }

private:
    ax::ui::Widget* m_rootWidget    = nullptr;
    int             m_touchPriority = 0;
};

using UILayer = TouchGroup;

} // namespace ui

using TouchGroup = ax::ui::TouchGroup;
using UILayer    = ax::ui::TouchGroup;

namespace extension {

using CCScale9Sprite        = ax::ui::Scale9Sprite;
using CCArmature            = cocostudio::Armature;
using CCArmatureAnimation   = cocostudio::ArmatureAnimation;
using CCArmatureDataManager = cocostudio::ArmatureDataManager;
using CCArmatureData        = cocostudio::ArmatureData;
using CCBoneData            = cocostudio::BoneData;
using CCBaseData            = cocostudio::BaseData;
using CCDisplayData         = cocostudio::DisplayData;
using CCSpriteDisplayData   = cocostudio::SpriteDisplayData;
using CCArmatureDisplayData = cocostudio::ArmatureDisplayData;
using CCParticleDisplayData = cocostudio::ParticleDisplayData;
using CCAnimationData       = cocostudio::AnimationData;
using CCMovementData        = cocostudio::MovementData;
using CCMovementBoneData    = cocostudio::MovementBoneData;
using CCFrameData           = cocostudio::FrameData;
using CCTextureData         = cocostudio::TextureData;
using CCContourData         = cocostudio::ContourData;
using CCContourVertex2      = ax::Vec2;
using CCBlendType           = cocostudio::BlendType;
using CCTweenType           = ax::tweenfunc::TweenType;

using ActionManager         = cocostudio::ActionManagerEx;
using ActionObject          = cocostudio::ActionObject;
using ActionNode            = cocostudio::ActionNode;
using ActionFrame           = cocostudio::ActionFrame;
using ActionMoveFrame       = cocostudio::ActionMoveFrame;
using ActionScaleFrame      = cocostudio::ActionScaleFrame;
using ActionRotationFrame   = cocostudio::ActionRotationFrame;
using ActionFadeFrame       = cocostudio::ActionFadeFrame;
using ActionTintFrame       = cocostudio::ActionTintFrame;

using CCComRender           = cocostudio::ComRender;
using CCComAudio            = cocostudio::ComAudio;
using CCComAttribute        = cocostudio::ComAttribute;
using GUIReader             = cocostudio::GUIReader;
using SceneReader           = cocostudio::SceneReader;

inline constexpr auto CS_DISPLAY_SPRITE   = cocostudio::CS_DISPLAY_SPRITE;
inline constexpr auto CS_DISPLAY_ARMATURE = cocostudio::CS_DISPLAY_ARMATURE;
inline constexpr auto CS_DISPLAY_PARTICLE = cocostudio::CS_DISPLAY_PARTICLE;

inline constexpr auto BLEND_NORMAL   = cocostudio::BLEND_NORMAL;
inline constexpr auto BLEND_LAYER    = cocostudio::BLEND_LAYER;
inline constexpr auto BLEND_MULTIPLY = cocostudio::BLEND_MULTIPLY;
inline constexpr auto BLEND_SCREEN   = cocostudio::BLEND_SCREEN;
inline constexpr auto BLEND_ADD      = cocostudio::BLEND_ADD;

} // namespace extension

} // namespace ax

namespace CocosDenshion {

class SimpleAudioEngine : public ax::Object {
public:
    static SimpleAudioEngine* getInstance();
    static SimpleAudioEngine* sharedEngine() { return getInstance(); }
    static void end();

    void preloadBackgroundMusic(const char* filePath);
    void playBackgroundMusic(const char* filePath, bool loop = false);
    void stopBackgroundMusic(bool releaseData = false);
    void pauseBackgroundMusic();
    void resumeBackgroundMusic();
    void rewindBackgroundMusic();
    bool willPlayBackgroundMusic() { return true; }
    bool isBackgroundMusicPlaying();

    float getBackgroundMusicVolume() const { return m_musicVolume; }
    void setBackgroundMusicVolume(float volume);

    float getEffectsVolume() const { return m_effectsVolume; }
    void setEffectsVolume(float volume);

    unsigned int playEffect(const char* filePath, bool loop = false,
                            float pitch = 1.0f, float pan = 0.0f, float gain = 1.0f);
    void pauseEffect(unsigned int soundId);
    void pauseAllEffects();
    void resumeEffect(unsigned int soundId);
    void resumeAllEffects();
    void stopEffect(unsigned int soundId);
    void stopAllEffects();
    void preloadEffect(const char* filePath);
    void unloadEffect(const char* filePath);

private:
    SimpleAudioEngine() = default;
    ~SimpleAudioEngine() override = default;

    std::string resolveAudioPath(const char* rawPath) const;

    int         m_bgAudioId     = ax::AudioEngine::INVALID_AUDIO_ID;
    std::string m_bgFilePath;
    bool        m_bgLoop        = false;
    float       m_musicVolume   = 1.0f;
    float       m_effectsVolume = 1.0f;
    std::vector<int> m_activeEffectIds;
};

} // namespace CocosDenshion

namespace gclient::compat {

std::string ResolveConvertedAssetPath(const std::string& rawPath);
void RegisterAxmol226CompatLuaBindings(lua_State* L);

} // namespace gclient::compat
