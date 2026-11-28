#include "BTUtil.h"
#include "common/KestrelCrypto.h"

#include "compat/Axmol226Compat.h"
#include "cocos-ext.h"
#include "ui/UIRichText.h"
#include "spine/SkeletonRenderer.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <initializer_list>
#include <random>
#include <string_view>
#include <typeinfo>
#include <utility>

USING_NS_CC;

namespace {
// 31-bit PRNG keeps BTUtil::random() in [0.0, 1.0) matching Android libc's / 2147483650.0.
std::mt19937 s_rng(static_cast<uint32_t>(std::time(nullptr)));
bool s_guideState = false;
int64_t s_svrTimeOffset = 0;
std::chrono::steady_clock::time_point s_timerStart = std::chrono::steady_clock::now();
BTUtil::PostUnscheduleAllHook s_postUnscheduleAllHook;

template <typename Target>
bool matchesDynamicType(CCObject* obj, std::string_view typeName,
                        std::initializer_list<std::string_view> names) {
    for (std::string_view n : names) {
        if (typeName == n) {
            return dynamic_cast<Target*>(obj) != nullptr;
        }
    }
    return false;
}

bool containsAnySubstring(std::string_view haystack, std::initializer_list<std::string_view> needles) {
    for (std::string_view needle : needles) {
        if (haystack.find(needle) != std::string_view::npos) return true;
    }
    return false;
}

} // namespace

void BTUtil::randomseed(unsigned int seed) {
    s_rng.seed(seed);
}

double BTUtil::random() {
    const uint32_t v = s_rng() & 0x7FFFFFFFu;
    return static_cast<double>(v) / 2147483650.0;
}

bool BTUtil::split(const std::string& str, char delim, std::vector<std::string>& out) {
    return split(str, std::string(1, delim), out);
}

bool BTUtil::split(const std::string& str, const std::string& delim, std::vector<std::string>& out) {
    if (str.empty()) return false;
    if (delim.empty()) {
        out.push_back(str);
        return true;
    }
    size_t start = 0;
    while (true) {
        const size_t pos = str.find(delim, start);
        if (pos == std::string::npos) break;
        out.emplace_back(str.substr(start, pos - start));
        start = pos + delim.size();
    }
    if (start < str.size()) {
        out.emplace_back(str.substr(start));
    }
    return true;
}

CCArray* BTUtil::cutString(CCString* str, CCString* delim) {
    CCArray* arr = CCArray::create();
    if (!str || !delim) return arr;
    std::vector<std::string> parts;
    split(str->getCString(), delim->getCString(), parts);
    for (const auto& s : parts) {
        arr->addObject(CCString::create(s));
    }
    return arr;
}

CCArray* BTUtil::splitString(const std::string& utf8Str) {
    CCArray* arr = CCArray::create();
    size_t i = 0;
    const size_t n = utf8Str.size();
    while (i < n) {
        const auto c = static_cast<unsigned char>(utf8Str[i]);
        size_t step = 1;
        if ((c & 0x80u) == 0)       step = 1;
        else if ((c >> 4) == 0x0Fu) step = 4;
        else if ((c >> 5) == 0x07u) step = 3;
        else if ((c >> 6) == 0x03u) step = 2;
        if (i + step > n) step = n - i;
        arr->addObject(CCString::create(utf8Str.substr(i, step)));
        i += step;
    }
    return arr;
}

bool BTUtil::checkType(CCObject* obj, const std::string& typeName) {
    if (!obj || typeName.empty()) return false;
    if (typeName == "CCObject") return true;

    if (matchesDynamicType<CCNode>(obj, typeName, {"CCNode"}) ||
        matchesDynamicType<CCScene>(obj, typeName, {"CCScene"}) ||
        matchesDynamicType<CCSprite>(obj, typeName, {"CCSprite"}) ||
        matchesDynamicType<CCLabelTTF>(obj, typeName, {"CCLabelTTF"}) ||
        matchesDynamicType<CCArray>(obj, typeName, {"CCArray"}) ||
        matchesDynamicType<CCDictionary>(obj, typeName, {"CCDictionary"}) ||
        matchesDynamicType<CCString>(obj, typeName, {"CCString"}) ||
        matchesDynamicType<CCInteger>(obj, typeName, {"CCInteger"}) ||
        matchesDynamicType<cocos2d::ui::Layout>(obj, typeName, {"Layout", "Panel", "UIPanel", "UILayout"}) ||
        matchesDynamicType<cocos2d::ui::Widget>(obj, typeName, {"Widget", "UIWidget"}) ||
        matchesDynamicType<cocos2d::ui::ScrollView>(obj, typeName, {"ScrollView", "UIScrollView"}) ||
        matchesDynamicType<cocos2d::ui::ListView>(obj, typeName, {"ListView", "UIListView"}) ||
        matchesDynamicType<cocos2d::ui::PageView>(obj, typeName, {"PageView", "UIPageView"}) ||
        matchesDynamicType<cocos2d::ui::Button>(obj, typeName, {"Button", "UIButton"}) ||
        matchesDynamicType<cocos2d::ui::ImageView>(obj, typeName, {"UIImageView", "ImageView"}) ||
        matchesDynamicType<cocos2d::ui::Label>(obj, typeName, {"Label", "UILabel"}) ||
        matchesDynamicType<cocos2d::ui::LabelAtlas>(obj, typeName, {"LabelAtlas", "UILabelAtlas"}) ||
        matchesDynamicType<cocos2d::ui::LoadingBar>(obj, typeName, {"LoadingBar", "UILoadingBar"}) ||
        matchesDynamicType<cocos2d::ui::Slider>(obj, typeName, {"Slider", "UISlider"}) ||
        matchesDynamicType<cocos2d::ui::CheckBox>(obj, typeName, {"CheckBox", "UICheckBox"}) ||
        matchesDynamicType<cocos2d::ui::TextField>(obj, typeName, {"TextField", "UITextField"}) ||
        matchesDynamicType<spine::SkeletonRenderer>(obj, typeName,
            {"SpineLuaAnimation", "SkeletonAnimation", "CCSkeletonAnimation", "CCSkeleton"}) ||
        matchesDynamicType<cocos2d::extension::CCScale9Sprite>(obj, typeName, {"CCScale9Sprite", "Scale9Sprite"}) ||
        matchesDynamicType<cocos2d::extension::CCArmature>(obj, typeName, {"CCArmature", "Armature"}) ||
        matchesDynamicType<cocos2d::ui::RichText>(obj, typeName, {"RichText", "UIRichText"})) {
        return true;
    }

    if (auto* w = dynamic_cast<cocos2d::ui::Widget*>(obj)) {
        const std::string desc = w->getDescription();
        if (desc == typeName ||
            (desc == "Panel" && typeName == "Layout") ||
            (desc == "Layout" && typeName == "Panel")) {
            return true;
        }
    }

    const std::string rttiName(typeid(*obj).name());
    if (rttiName.find(typeName) != std::string::npos) return true;
    if ((typeName == "Layout" || typeName == "Panel") &&
        containsAnySubstring(rttiName, {"Layout", "Panel", "ScrollView", "ListView", "PageView"})) {
        return true;
    }
    if ((typeName == "SpineLuaAnimation" || typeName == "SkeletonAnimation") &&
        containsAnySubstring(rttiName, {"GClientSkeletonAnimation", "CCSkeletonAnimation", "CCSkeleton", "SpineLuaAnimation"})) {
        return true;
    }
    if (typeName == "RichText" && containsAnySubstring(rttiName, {"GClientRichText", "RichText"})) {
        return true;
    }
    return false;
}

int64_t BTUtil::getSvrTimeInterval() {
    return static_cast<int64_t>(std::time(nullptr)) + s_svrTimeOffset;
}

void BTUtil::syncTime(int64_t svrTime) {
    s_svrTimeOffset = svrTime - static_cast<int64_t>(std::time(nullptr));
}

int BTUtil::getPlatform() { return kBT_PLATFORM_ANDROID; }
bool BTUtil::isAppStore() { return false; }
bool BTUtil::isSimulator() { return false; }
bool BTUtil::getDebugStatus() { return false; }
int BTUtil::getBTOnlineType() { return 0; }

void BTUtil::setGuideState(bool state) { s_guideState = state; }
bool BTUtil::getGuideState() { return s_guideState; }

void BTUtil::setPostUnscheduleAllHook(PostUnscheduleAllHook hook) {
    s_postUnscheduleAllHook = std::move(hook);
}

void BTUtil::unscheduleAll() {
    if (s_postUnscheduleAllHook) {
        PostUnscheduleAllHook hookCopy = s_postUnscheduleAllHook;
        hookCopy();
    }
}

std::string BTUtil::getMd5SumByString(const std::string& input) {
    return gclient::crypto::md5Hex(input, false);
}

std::string BTUtil::getLuaOrigPackagePath() {
    return "scripts/?.lua;?.lua";
}

std::string BTUtil::insertToSearchPathBegin(const std::string& path) {
    std::string norm = path;
    std::replace(norm.begin(), norm.end(), '\\', '/');
    if (auto* fu = ax::FileUtils::getInstance()) {
        std::vector<std::string> paths = fu->getSearchPaths();
        paths.insert(paths.begin(), norm);
        fu->setSearchPaths(paths);
    }
    return norm;
}

std::string BTUtil::sortUrlString(const std::string& url) {
    if (url.empty()) return "";
    std::vector<std::string> halves;
    split(url, "?", halves);
    if (halves.size() < 2 || halves[0].empty() || halves[1].empty()) {
        return url;
    }
    std::vector<std::string> params;
    split(halves[1], "&", params);
    std::sort(params.begin(), params.end());
    std::string out;
    for (const auto& p : params) out += p;
    return out;
}

void BTUtil::exitNow() {
    if (auto* director = ax::Director::getInstance()) {
        director->end();
    }
#ifdef _WIN32
    if (auto* director = ax::Director::getInstance()) {
        if (auto* rv = dynamic_cast<ax::RenderViewImpl*>(director->getRenderView())) {
            if (HWND hwnd = rv->getWin32Window(); hwnd != nullptr && ::IsWindow(hwnd)) {
                ::PostMessageW(hwnd, WM_CLOSE, 0, 0);
            }
        }
    }
#endif
}

void BTUtil::TimeStart() {
    s_timerStart = std::chrono::steady_clock::now();
}

uint64_t BTUtil::TimeEnd() {
    const auto now = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now - s_timerStart).count());
}

// ============================================================================
// ClassInfo
// ============================================================================

std::string ClassInfo::description(CCArray* arr) {
    return arr ? ("CCArray(count=" + std::to_string(arr->count()) + ")") : "CCArray(null)";
}

std::string ClassInfo::description(CCDictionary* dict) {
    return dict ? ("CCDictionary(count=" + std::to_string(dict->count()) + ")") : "CCDictionary(null)";
}

std::string ClassInfo::description(CCString* str) {
    return str ? (std::string("CCString(\"") + str->getCString() + "\")") : "CCString(null)";
}

std::string ClassInfo::description(CCInteger* val) {
    return val ? ("CCInteger(" + std::to_string(val->getValue()) + ")") : "CCInteger(null)";
}

std::string ClassInfo::description(const CCPoint& pt) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "CCPoint(%.2f, %.2f)", pt.x, pt.y);
    return buf;
}
