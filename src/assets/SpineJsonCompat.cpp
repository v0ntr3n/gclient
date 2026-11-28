// ============================================================================
// SpineJsonCompat.cpp — In-memory Spine 4.1 / legacy JSON -> Spine 4.2 adapter
// ============================================================================

#include "assets/SpineJsonCompat.h"
#include "common/KestrelJson.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <unordered_set>

namespace gclient::assets {

namespace {

using gclient::json::JsonValue;

JsonValue makeStr(std::string_view v) {
    JsonValue j;
    j.type = JsonValue::Type::String;
    j.strVal.assign(v.data(), v.size());
    return j;
}

JsonValue makeDouble(double v) {
    JsonValue j;
    j.type = JsonValue::Type::Double;
    j.doubleVal = std::isfinite(v) ? v : 0.0;
    return j;
}

double asNum(const JsonValue& v, double fallback = 0.0) noexcept {
    if (v.type == JsonValue::Type::Double) return std::isfinite(v.doubleVal) ? v.doubleVal : fallback;
    if (v.type == JsonValue::Type::Int) return static_cast<double>(v.intVal);
    return fallback;
}

double getObjNum(const JsonValue& obj, std::string_view key, double fallback = 0.0) {
    const JsonValue* p = obj.find(key);
    return p ? asNum(*p, fallback) : fallback;
}

std::string_view getObjStrView(const JsonValue& obj, std::string_view key, std::string_view fallback = {}) {
    const JsonValue* p = obj.find(key);
    return (p && p->isString()) ? std::string_view(p->strVal) : fallback;
}

bool renameFieldIfAbsent(
    JsonValue& obj,
    std::string_view oldKey,
    std::string_view newKey,
    size_t& counter,
    bool& modified)
{
    if (!obj.isObject()) return false;
    auto oldIt = obj.objVal.find(std::string(oldKey));
    if (oldIt == obj.objVal.end()) return false;
    if (obj.objVal.find(std::string(newKey)) == obj.objVal.end()) {
        obj.objVal.emplace(std::string(newKey), std::move(oldIt->second));
    }
    obj.objVal.erase(oldIt);
    ++counter;
    modified = true;
    return true;
}

int hexNibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

std::array<double, 4> parseHexColor(std::string_view hex, bool hasAlpha) noexcept {
    std::array<double, 4> out{1.0, 1.0, 1.0, 1.0};
    if (hex.size() >= 6) {
        out[0] = static_cast<double>((hexNibble(hex[0]) << 4) | hexNibble(hex[1])) / 255.0;
        out[1] = static_cast<double>((hexNibble(hex[2]) << 4) | hexNibble(hex[3])) / 255.0;
        out[2] = static_cast<double>((hexNibble(hex[4]) << 4) | hexNibble(hex[5])) / 255.0;
        if (hasAlpha && hex.size() >= 8) {
            out[3] = static_cast<double>((hexNibble(hex[6]) << 4) | hexNibble(hex[7])) / 255.0;
        }
    }
    return out;
}

bool isPreSpine40Version(std::string_view ver) noexcept {
    size_t i = 0;
    while (i < ver.size() && std::isspace(static_cast<unsigned char>(ver[i]))) ++i;
    if (i >= ver.size() || !std::isdigit(static_cast<unsigned char>(ver[i]))) return false;
    int major = 0;
    while (i < ver.size() && std::isdigit(static_cast<unsigned char>(ver[i]))) {
        major = major * 10 + (ver[i] - '0');
        if (major >= 4) return false;
        ++i;
    }
    return major > 0 && major < 4;
}

template <size_t MaxChannels, typename EvalFn>
void normalizeCurveKeyframes(
    JsonValue& framesArr,
    size_t channels,
    bool isPre40,
    EvalFn&& evalChannels,
    SpineJsonCompatReport& report)
{
    if (!framesArr.isArray() || framesArr.arrVal.empty()) return;
    auto& frames = framesArr.arrVal;
    const size_t expectedLen = channels * 4u;

    for (size_t i = 0; i < frames.size(); ++i) {
        JsonValue& kf = frames[i];
        if (!kf.isObject()) continue;

        const bool isLast = (i + 1u >= frames.size()) || !frames[i + 1u].isObject();
        auto eraseLegacyTangents = [&]() {
            kf.objVal.erase("c2");
            kf.objVal.erase("c3");
            kf.objVal.erase("c4");
        };

        auto curveIt = kf.objVal.find("curve");
        if (curveIt == kf.objVal.end()) {
            eraseLegacyTangents();
            continue;
        }

        if (isLast) {
            // SkeletonJson ignores curve on the final keyframe; drop non-stepped clutter cleanly.
            if (!(curveIt->second.isString() && curveIt->second.strVal == "stepped")) {
                kf.objVal.erase(curveIt);
                ++report.curvesNormalized;
                report.modified = true;
            }
            eraseLegacyTangents();
            continue;
        }

        const JsonValue& nextKf = frames[i + 1u];
        auto expandNormalizedBezier = [&](double cx1, double cy1, double cx2, double cy2) {
            const double t1 = getObjNum(kf, "time", 0.0);
            const double t2 = getObjNum(nextKf, "time", 0.0);
            const double dt = t2 - t1;
            const std::array<double, MaxChannels> v1 = evalChannels(kf, i);
            const std::array<double, MaxChannels> v2 = evalChannels(nextKf, i + 1u);

            JsonValue arr;
            arr.type = JsonValue::Type::Array;
            arr.arrVal.reserve(expectedLen);
            for (size_t ch = 0; ch < channels; ++ch) {
                const double dv = v2[ch] - v1[ch];
                arr.arrVal.push_back(makeDouble(t1 + dt * cx1));
                arr.arrVal.push_back(makeDouble(v1[ch] + dv * cy1));
                arr.arrVal.push_back(makeDouble(t1 + dt * cx2));
                arr.arrVal.push_back(makeDouble(v1[ch] + dv * cy2));
            }
            curveIt->second = std::move(arr);
            eraseLegacyTangents();
            ++report.curvesNormalized;
            report.modified = true;
        };

        if (curveIt->second.isString()) {
            if (curveIt->second.strVal == "stepped") {
                eraseLegacyTangents();
                continue;
            }
            // "linear" (or any unknown curve string) crashes Spine 4.2 SkeletonJson::readCurve
            // because readCurve only checks for "stepped" before indexing curve as an array.
            kf.objVal.erase(curveIt);
            eraseLegacyTangents();
            ++report.curvesNormalized;
            report.modified = true;
            continue;
        }

        if (curveIt->second.isNumber()) {
            const double cx1 = asNum(curveIt->second, 0.0);
            const double cy1 = getObjNum(kf, "c2", 0.0);
            const double cx2 = getObjNum(kf, "c3", 1.0);
            const double cy2 = getObjNum(kf, "c4", 1.0);
            expandNormalizedBezier(cx1, cy1, cx2, cy2);
            continue;
        }

        if (curveIt->second.isArray()) {
            const auto& cArr = curveIt->second.arrVal;
            const bool allNumbers = std::all_of(
                cArr.begin(), cArr.end(), [](const JsonValue& x) { return x.isNumber(); });
            if (!allNumbers) {
                kf.objVal.erase(curveIt);
                eraseLegacyTangents();
                ++report.curvesNormalized;
                report.modified = true;
                continue;
            }

            if (cArr.size() == expectedLen && !isPre40) {
                eraseLegacyTangents();
                continue;
            }

            if (cArr.size() == 4u && (isPre40 || channels > 1u)) {
                expandNormalizedBezier(
                    asNum(cArr[0], 0.0),
                    asNum(cArr[1], 0.0),
                    asNum(cArr[2], 1.0),
                    asNum(cArr[3], 1.0));
                continue;
            }

            if (cArr.size() != expectedLen) {
                // Prevent SkeletonJson::readCurve out-of-bounds NULL dereference on short arrays.
                kf.objVal.erase(curveIt);
                eraseLegacyTangents();
                ++report.curvesNormalized;
                report.modified = true;
                continue;
            }

            eraseLegacyTangents();
            continue;
        }

        kf.objVal.erase(curveIt);
        eraseLegacyTangents();
        ++report.curvesNormalized;
        report.modified = true;
    }
}

void normalize1Channel(JsonValue& framesArr, double defaultVal, bool isPre40, SpineJsonCompatReport& report) {
    normalizeCurveKeyframes<1>(
        framesArr, 1u, isPre40,
        [defaultVal](const JsonValue& kf, size_t) -> std::array<double, 1> {
            return {getObjNum(kf, "value", defaultVal)};
        },
        report);
}

void normalize2Channel(
    JsonValue& framesArr,
    std::string_view k1,
    std::string_view k2,
    double def1,
    double def2,
    bool isPre40,
    SpineJsonCompatReport& report)
{
    normalizeCurveKeyframes<2>(
        framesArr, 2u, isPre40,
        [k1, k2, def1, def2](const JsonValue& kf, size_t) -> std::array<double, 2> {
            return {getObjNum(kf, k1, def1), getObjNum(kf, k2, def2)};
        },
        report);
}

void appendEscapedJsonString(std::string_view s, std::string& out) {
    static constexpr char kHex[] = "0123456789abcdef";
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20u) {
                    out += "\\u00";
                    out.push_back(kHex[(c >> 4) & 0x0Fu]);
                    out.push_back(kHex[c & 0x0Fu]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
}

void dumpJsonTo(const JsonValue& val, std::string& out) {
    switch (val.type) {
        case JsonValue::Type::Null:
            out += "null";
            return;
        case JsonValue::Type::Bool:
            out += (val.boolVal ? "true" : "false");
            return;
        case JsonValue::Type::Int: {
            char buf[32];
            const int n = std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(val.intVal));
            if (n > 0) out.append(buf, static_cast<size_t>(n));
            return;
        }
        case JsonValue::Type::Double: {
            if (!std::isfinite(val.doubleVal)) {
                out += "null";
                return;
            }
            char buf[64];
            const int n = std::snprintf(buf, sizeof(buf), "%.15g", val.doubleVal);
            if (n > 0) out.append(buf, static_cast<size_t>(n));
            return;
        }
        case JsonValue::Type::String:
            appendEscapedJsonString(val.strVal, out);
            return;
        case JsonValue::Type::Array:
            out.push_back('[');
            for (size_t i = 0; i < val.arrVal.size(); ++i) {
                if (i > 0) out.push_back(',');
                dumpJsonTo(val.arrVal[i], out);
            }
            out.push_back(']');
            return;
        case JsonValue::Type::Object: {
            out.push_back('{');
            bool first = true;
            for (const auto& [k, v] : val.objVal) {
                if (!first) out.push_back(',');
                first = false;
                appendEscapedJsonString(k, out);
                out.push_back(':');
                dumpJsonTo(v, out);
            }
            out.push_back('}');
            return;
        }
    }
}

void ensureConstraintBonesArray(JsonValue& constraintObj, SpineJsonCompatReport& report) {
    if (!constraintObj.isObject()) return;
    if (constraintObj.objVal.find("bones") != constraintObj.objVal.end()) return;
    JsonValue arr;
    arr.type = JsonValue::Type::Array;
    auto singleIt = constraintObj.objVal.find("bone");
    if (singleIt != constraintObj.objVal.end() && singleIt->second.isString()) {
        arr.arrVal.push_back(std::move(singleIt->second));
        constraintObj.objVal.erase(singleIt);
    }
    constraintObj.objVal.emplace("bones", std::move(arr));
    ++report.legacyUpgrades;
    report.modified = true;
}

void mergeLegacyDeformObject(
    JsonValue& animObj,
    const char* legacyKey,
    bool isPre40,
    SpineJsonCompatReport& report)
{
    auto defIt = animObj.objVal.find(legacyKey);
    if (defIt == animObj.objVal.end()) return;
    if (defIt->second.isObject()) {
        JsonValue& attRoot = animObj.objVal["attachments"];
        if (!attRoot.isObject()) {
            attRoot = JsonValue{};
            attRoot.type = JsonValue::Type::Object;
        }
        for (auto& [skinName, skinVal] : defIt->second.objVal) {
            if (!skinVal.isObject()) continue;
            JsonValue& dstSkin = attRoot.objVal[skinName];
            if (!dstSkin.isObject()) dstSkin.type = JsonValue::Type::Object;
            for (auto& [slotName, slotVal] : skinVal.objVal) {
                if (!slotVal.isObject()) continue;
                JsonValue& dstSlot = dstSkin.objVal[slotName];
                if (!dstSlot.isObject()) dstSlot.type = JsonValue::Type::Object;
                for (auto& [attName, framesVal] : slotVal.objVal) {
                    if (!framesVal.isArray()) continue;
                    JsonValue& dstAtt = dstSlot.objVal[attName];
                    if (!dstAtt.isObject()) dstAtt.type = JsonValue::Type::Object;
                    if (dstAtt.objVal.find("deform") == dstAtt.objVal.end()) {
                        dstAtt.objVal.emplace("deform", std::move(framesVal));
                    }
                }
            }
        }
    }
    animObj.objVal.erase(defIt);
    ++report.legacyUpgrades;
    report.modified = true;
    (void)isPre40;
}

} // namespace

bool NormalizeSpineJsonFor42(
    std::string_view rawJson,
    std::string& outJson,
    SpineJsonCompatReport* outReport)
{
    SpineJsonCompatReport report;
    if (rawJson.size() >= 3u &&
        static_cast<unsigned char>(rawJson[0]) == 0xEFu &&
        static_cast<unsigned char>(rawJson[1]) == 0xBBu &&
        static_cast<unsigned char>(rawJson[2]) == 0xBFu)
    {
        rawJson.remove_prefix(3u);
    }

    JsonValue root;
    if (!gclient::json::parse(rawJson, root, nullptr) || !root.isObject()) {
        if (outReport) *outReport = std::move(report);
        return false;
    }

    // 1. Skeleton header & version gate ("4.2" prefix required by Spine 4.2 SkeletonJson).
    JsonValue& skelObj = root.objVal["skeleton"];
    if (!skelObj.isObject()) {
        skelObj = JsonValue{};
        skelObj.type = JsonValue::Type::Object;
        report.modified = true;
    }
    if (const JsonValue* sp = skelObj.find("spine"); sp && sp->isString()) {
        report.sourceVersion = sp->strVal;
    }
    const bool isPre40 = isPreSpine40Version(report.sourceVersion);
    if (report.sourceVersion.rfind("4.2", 0) != 0) {
        skelObj.objVal["spine"] = makeStr("4.2.00");
        report.targetVersion    = "4.2.00";
        report.versionRewritten = true;
        report.modified         = true;
    } else {
        report.targetVersion = report.sourceVersion;
    }

    // 2. Bones setup pose: Spine 4.0/4.1 "transform" -> Spine 4.2 "inherit" (plus 2.1 booleans).
    auto bonesIt = root.objVal.find("bones");
    if (bonesIt == root.objVal.end() || !bonesIt->second.isArray() || bonesIt->second.arrVal.empty()) {
        JsonValue rootBone;
        rootBone.type = JsonValue::Type::Object;
        rootBone.objVal.emplace("name", makeStr("root"));
        JsonValue bonesArr;
        bonesArr.type = JsonValue::Type::Array;
        bonesArr.arrVal.push_back(std::move(rootBone));
        root.objVal["bones"] = std::move(bonesArr);
        ++report.legacyUpgrades;
        report.modified = true;
    } else {
        for (JsonValue& bone : bonesIt->second.arrVal) {
            if (!bone.isObject()) continue;
            if (bone.objVal.find("inherit") == bone.objVal.end()) {
                auto tfIt = bone.objVal.find("transform");
                if (tfIt != bone.objVal.end() && tfIt->second.isString()) {
                    bone.objVal.emplace("inherit", std::move(tfIt->second));
                    bone.objVal.erase(tfIt);
                    ++report.bonesInheritFixed;
                    report.modified = true;
                } else if (bone.objVal.find("inheritRotation") != bone.objVal.end() ||
                           bone.objVal.find("inheritScale") != bone.objVal.end())
                {
                    const JsonValue* ir = bone.find("inheritRotation");
                    const JsonValue* is = bone.find("inheritScale");
                    const bool rot = ir ? ir->asBool(true) : true;
                    const bool scl = is ? is->asBool(true) : true;
                    const char* mode = "normal";
                    if (!rot && !scl) mode = "onlyTranslation";
                    else if (!rot && scl) mode = "noRotationOrReflection";
                    else if (rot && !scl) mode = "noScaleOrReflection";
                    bone.objVal.emplace("inherit", makeStr(mode));
                    bone.objVal.erase("inheritRotation");
                    bone.objVal.erase("inheritScale");
                    ++report.bonesInheritFixed;
                    report.modified = true;
                }
            } else {
                if (bone.objVal.erase("transform") > 0) {
                    ++report.bonesInheritFixed;
                    report.modified = true;
                }
            }

            auto fxIt = bone.objVal.find("flipX");
            if (fxIt != bone.objVal.end()) {
                if (fxIt->second.asBool(false)) {
                    bone.objVal["scaleX"] = makeDouble(-getObjNum(bone, "scaleX", 1.0));
                }
                bone.objVal.erase(fxIt);
                ++report.legacyUpgrades;
                report.modified = true;
            }
            auto fyIt = bone.objVal.find("flipY");
            if (fyIt != bone.objVal.end()) {
                if (fyIt->second.asBool(false)) {
                    bone.objVal["scaleY"] = makeDouble(-getObjNum(bone, "scaleY", 1.0));
                }
                bone.objVal.erase(fyIt);
                ++report.legacyUpgrades;
                report.modified = true;
            }
        }
    }

    // 3. Slots setup pose & slot name index (guards against orphan skin slots).
    std::unordered_set<std::string> validSlots;
    if (auto slotsIt = root.objVal.find("slots"); slotsIt != root.objVal.end() && slotsIt->second.isArray()) {
        for (JsonValue& slot : slotsIt->second.arrVal) {
            if (!slot.isObject()) continue;
            if (const JsonValue* n = slot.find("name"); n && n->isString()) {
                validSlots.insert(n->strVal);
            }
            if (auto attIt = slot.objVal.find("attachment"); attIt != slot.objVal.end() && attIt->second.isNull()) {
                slot.objVal.erase(attIt);
                report.modified = true;
            }
        }
    }

    // 4. IK / Transform / Path constraints setup pose.
    if (auto ikIt = root.objVal.find("ik"); ikIt != root.objVal.end() && ikIt->second.isArray()) {
        for (JsonValue& ikObj : ikIt->second.arrVal) {
            ensureConstraintBonesArray(ikObj, report);
        }
    }
    if (auto tcIt = root.objVal.find("transform"); tcIt != root.objVal.end() && tcIt->second.isArray()) {
        for (JsonValue& tcObj : tcIt->second.arrVal) {
            ensureConstraintBonesArray(tcObj, report);
            renameFieldIfAbsent(tcObj, "rotateMix", "mixRotate", report.legacyUpgrades, report.modified);
            renameFieldIfAbsent(tcObj, "translateMix", "mixX", report.legacyUpgrades, report.modified);
            renameFieldIfAbsent(tcObj, "scaleMix", "mixScaleX", report.legacyUpgrades, report.modified);
            renameFieldIfAbsent(tcObj, "shearMix", "mixShearY", report.legacyUpgrades, report.modified);
        }
    }
    if (auto pcIt = root.objVal.find("path"); pcIt != root.objVal.end() && pcIt->second.isArray()) {
        for (JsonValue& pcObj : pcIt->second.arrVal) {
            ensureConstraintBonesArray(pcObj, report);
            renameFieldIfAbsent(pcObj, "rotateMix", "mixRotate", report.legacyUpgrades, report.modified);
            renameFieldIfAbsent(pcObj, "translateMix", "mixX", report.legacyUpgrades, report.modified);
        }
    }

    // 5. Skins: convert <=3.7 map format to 4.x array format & upgrade attachment fields.
    if (auto skinsIt = root.objVal.find("skins"); skinsIt != root.objVal.end()) {
        if (skinsIt->second.isObject()) {
            JsonValue skinsArr;
            skinsArr.type = JsonValue::Type::Array;
            auto pushSkinEntry = [&](const std::string& name, JsonValue&& attachmentsObj) {
                JsonValue entry;
                entry.type = JsonValue::Type::Object;
                entry.objVal.emplace("name", makeStr(name));
                entry.objVal.emplace("attachments", std::move(attachmentsObj));
                skinsArr.arrVal.push_back(std::move(entry));
            };
            if (auto defSkin = skinsIt->second.objVal.find("default"); defSkin != skinsIt->second.objVal.end()) {
                pushSkinEntry("default", std::move(defSkin->second));
            }
            for (auto& [skinName, skinAtts] : skinsIt->second.objVal) {
                if (skinName == "default") continue;
                pushSkinEntry(skinName, std::move(skinAtts));
            }
            skinsIt->second = std::move(skinsArr);
            ++report.legacyUpgrades;
            report.modified = true;
        }

        if (skinsIt->second.isArray()) {
            for (JsonValue& skinObj : skinsIt->second.arrVal) {
                if (!skinObj.isObject()) continue;
                auto attsIt = skinObj.objVal.find("attachments");
                if (attsIt == skinObj.objVal.end() || !attsIt->second.isObject()) continue;

                for (auto slotIt = attsIt->second.objVal.begin(); slotIt != attsIt->second.objVal.end();) {
                    if (!validSlots.empty() && validSlots.find(slotIt->first) == validSlots.end()) {
                        slotIt = attsIt->second.objVal.erase(slotIt);
                        ++report.legacyUpgrades;
                        report.modified = true;
                        continue;
                    }
                    if (slotIt->second.isObject()) {
                        for (auto& [attKey, attVal] : slotIt->second.objVal) {
                            (void)attKey;
                            if (!attVal.isObject()) continue;
                            const std::string_view t = getObjStrView(attVal, "type", "region");
                            if (t == "skinnedmesh" || t == "weightedmesh") {
                                attVal.objVal["type"] = makeStr("mesh");
                                ++report.legacyUpgrades;
                                report.modified = true;
                            }
                            if (t == "linkedmesh" || attVal.objVal.find("parent") != attVal.objVal.end()) {
                                renameFieldIfAbsent(
                                    attVal, "deform", "timelines", report.legacyUpgrades, report.modified);
                            }
                        }
                    }
                    ++slotIt;
                }
            }
        }
    }

    // 6. Animations: slot/bone/constraint/attachment timelines & curve channel safety.
    if (auto animsIt = root.objVal.find("animations");
        animsIt != root.objVal.end() && animsIt->second.isObject())
    {
        for (auto& [animName, animObj] : animsIt->second.objVal) {
            (void)animName;
            if (!animObj.isObject()) continue;

            renameFieldIfAbsent(animObj, "draworder", "drawOrder", report.legacyUpgrades, report.modified);
            mergeLegacyDeformObject(animObj, "deform", isPre40, report);
            mergeLegacyDeformObject(animObj, "ffd", isPre40, report);

            // 6a. Slot timelines.
            if (auto sTlIt = animObj.objVal.find("slots");
                sTlIt != animObj.objVal.end() && sTlIt->second.isObject())
            {
                for (auto& [slotName, slotTl] : sTlIt->second.objVal) {
                    (void)slotName;
                    if (!slotTl.isObject()) continue;
                    renameFieldIfAbsent(slotTl, "color", "rgba", report.legacyUpgrades, report.modified);
                    renameFieldIfAbsent(slotTl, "twoColor", "rgba2", report.legacyUpgrades, report.modified);

                    for (auto tlIt = slotTl.objVal.begin(); tlIt != slotTl.objVal.end();) {
                        const std::string& tlName = tlIt->first;
                        JsonValue& frames = tlIt->second;
                        if (tlName == "attachment") {
                            if (frames.isArray()) {
                                for (JsonValue& kf : frames.arrVal) {
                                    if (!kf.isObject()) continue;
                                    if (auto nIt = kf.objVal.find("name");
                                        nIt != kf.objVal.end() && nIt->second.isNull())
                                    {
                                        kf.objVal.erase(nIt);
                                        report.modified = true;
                                    }
                                }
                            }
                            ++tlIt;
                        } else if (tlName == "rgba") {
                            normalizeCurveKeyframes<4>(
                                frames, 4u, isPre40,
                                [](const JsonValue& kf, size_t) -> std::array<double, 4> {
                                    return parseHexColor(getObjStrView(kf, "color", "ffffffff"), true);
                                },
                                report);
                            ++tlIt;
                        } else if (tlName == "rgb") {
                            normalizeCurveKeyframes<3>(
                                frames, 3u, isPre40,
                                [](const JsonValue& kf, size_t) -> std::array<double, 3> {
                                    const auto c = parseHexColor(getObjStrView(kf, "color", "ffffff"), false);
                                    return {c[0], c[1], c[2]};
                                },
                                report);
                            ++tlIt;
                        } else if (tlName == "alpha") {
                            normalize1Channel(frames, 0.0, isPre40, report);
                            ++tlIt;
                        } else if (tlName == "rgba2") {
                            normalizeCurveKeyframes<7>(
                                frames, 7u, isPre40,
                                [](const JsonValue& kf, size_t) -> std::array<double, 7> {
                                    const auto l = parseHexColor(getObjStrView(kf, "light", "ffffffff"), true);
                                    const auto d = parseHexColor(getObjStrView(kf, "dark", "000000"), false);
                                    return {l[0], l[1], l[2], l[3], d[0], d[1], d[2]};
                                },
                                report);
                            ++tlIt;
                        } else if (tlName == "rgb2") {
                            normalizeCurveKeyframes<6>(
                                frames, 6u, isPre40,
                                [](const JsonValue& kf, size_t) -> std::array<double, 6> {
                                    const auto l = parseHexColor(getObjStrView(kf, "light", "ffffff"), false);
                                    const auto d = parseHexColor(getObjStrView(kf, "dark", "000000"), false);
                                    return {l[0], l[1], l[2], d[0], d[1], d[2]};
                                },
                                report);
                            ++tlIt;
                        } else {
                            tlIt = slotTl.objVal.erase(tlIt);
                            ++report.legacyUpgrades;
                            report.modified = true;
                        }
                    }
                }
            }

            // 6b. Bone timelines.
            if (auto bTlIt = animObj.objVal.find("bones");
                bTlIt != animObj.objVal.end() && bTlIt->second.isObject())
            {
                for (auto& [boneName, boneTl] : bTlIt->second.objVal) {
                    (void)boneName;
                    if (!boneTl.isObject()) continue;
                    renameFieldIfAbsent(boneTl, "transform", "inherit", report.bonesInheritFixed, report.modified);

                    for (auto tlIt = boneTl.objVal.begin(); tlIt != boneTl.objVal.end();) {
                        const std::string& tlName = tlIt->first;
                        JsonValue& frames = tlIt->second;
                        if (tlName == "rotate") {
                            if (frames.isArray()) {
                                for (JsonValue& kf : frames.arrVal) {
                                    renameFieldIfAbsent(
                                        kf, "angle", "value", report.legacyUpgrades, report.modified);
                                }
                            }
                            normalize1Channel(frames, 0.0, isPre40, report);
                            ++tlIt;
                        } else if (tlName == "translate" || tlName == "shear") {
                            normalize2Channel(frames, "x", "y", 0.0, 0.0, isPre40, report);
                            ++tlIt;
                        } else if (tlName == "scale") {
                            normalize2Channel(frames, "x", "y", 1.0, 1.0, isPre40, report);
                            ++tlIt;
                        } else if (tlName == "translatex" || tlName == "translatey" ||
                                   tlName == "shearx" || tlName == "sheary")
                        {
                            normalize1Channel(frames, 0.0, isPre40, report);
                            ++tlIt;
                        } else if (tlName == "scalex" || tlName == "scaley") {
                            normalize1Channel(frames, 1.0, isPre40, report);
                            ++tlIt;
                        } else if (tlName == "inherit") {
                            if (frames.isArray()) {
                                for (JsonValue& kf : frames.arrVal) {
                                    renameFieldIfAbsent(
                                        kf, "transform", "inherit", report.bonesInheritFixed, report.modified);
                                }
                            }
                            ++tlIt;
                        } else {
                            // Strip removed legacy timelines (e.g. 2.1 flipX/flipY) that abort SkeletonJson.
                            tlIt = boneTl.objVal.erase(tlIt);
                            ++report.legacyUpgrades;
                            report.modified = true;
                        }
                    }
                }
            }

            // 6c. IK constraint timelines.
            if (auto ikTlIt = animObj.objVal.find("ik");
                ikTlIt != animObj.objVal.end() && ikTlIt->second.isObject())
            {
                for (auto& [ikName, frames] : ikTlIt->second.objVal) {
                    (void)ikName;
                    normalize2Channel(frames, "mix", "softness", 1.0, 0.0, isPre40, report);
                }
            }

            // 6d. Transform constraint timelines.
            if (auto tcTlIt = animObj.objVal.find("transform");
                tcTlIt != animObj.objVal.end() && tcTlIt->second.isObject())
            {
                for (auto& [tcName, frames] : tcTlIt->second.objVal) {
                    (void)tcName;
                    if (frames.isArray()) {
                        for (JsonValue& kf : frames.arrVal) {
                            renameFieldIfAbsent(kf, "rotateMix", "mixRotate", report.legacyUpgrades, report.modified);
                            renameFieldIfAbsent(kf, "translateMix", "mixX", report.legacyUpgrades, report.modified);
                            renameFieldIfAbsent(kf, "scaleMix", "mixScaleX", report.legacyUpgrades, report.modified);
                            renameFieldIfAbsent(kf, "shearMix", "mixShearY", report.legacyUpgrades, report.modified);
                        }
                    }
                    normalizeCurveKeyframes<6>(
                        frames, 6u, isPre40,
                        [](const JsonValue& kf, size_t) -> std::array<double, 6> {
                            const double mixRotate = getObjNum(kf, "mixRotate", 1.0);
                            const double mixX      = getObjNum(kf, "mixX", 1.0);
                            const double mixY      = getObjNum(kf, "mixY", mixX);
                            const double mixScaleX = getObjNum(kf, "mixScaleX", 1.0);
                            const double mixScaleY = getObjNum(kf, "mixScaleY", mixScaleX);
                            const double mixShearY = getObjNum(kf, "mixShearY", 1.0);
                            return {mixRotate, mixX, mixY, mixScaleX, mixScaleY, mixShearY};
                        },
                        report);
                }
            }

            // 6e. Path constraint timelines.
            if (auto pcTlIt = animObj.objVal.find("path");
                pcTlIt != animObj.objVal.end() && pcTlIt->second.isObject())
            {
                for (auto& [pcName, pcMap] : pcTlIt->second.objVal) {
                    (void)pcName;
                    if (!pcMap.isObject()) continue;
                    for (auto& [tlName, frames] : pcMap.objVal) {
                        if (tlName == "position") {
                            if (frames.isArray()) {
                                for (JsonValue& kf : frames.arrVal) {
                                    renameFieldIfAbsent(
                                        kf, "position", "value", report.legacyUpgrades, report.modified);
                                }
                            }
                            normalize1Channel(frames, 0.0, isPre40, report);
                        } else if (tlName == "spacing") {
                            if (frames.isArray()) {
                                for (JsonValue& kf : frames.arrVal) {
                                    renameFieldIfAbsent(
                                        kf, "spacing", "value", report.legacyUpgrades, report.modified);
                                }
                            }
                            normalize1Channel(frames, 0.0, isPre40, report);
                        } else if (tlName == "mix") {
                            if (frames.isArray()) {
                                for (JsonValue& kf : frames.arrVal) {
                                    renameFieldIfAbsent(
                                        kf, "rotateMix", "mixRotate", report.legacyUpgrades, report.modified);
                                    renameFieldIfAbsent(
                                        kf, "translateMix", "mixX", report.legacyUpgrades, report.modified);
                                }
                            }
                            normalizeCurveKeyframes<3>(
                                frames, 3u, isPre40,
                                [](const JsonValue& kf, size_t) -> std::array<double, 3> {
                                    const double mixRotate = getObjNum(kf, "mixRotate", 1.0);
                                    const double mixX      = getObjNum(kf, "mixX", 1.0);
                                    const double mixY      = getObjNum(kf, "mixY", mixX);
                                    return {mixRotate, mixX, mixY};
                                },
                                report);
                        }
                    }
                }
            }

            // 6f. Physics constraint timelines.
            if (auto phTlIt = animObj.objVal.find("physics");
                phTlIt != animObj.objVal.end() && phTlIt->second.isObject())
            {
                for (auto& [phName, phMap] : phTlIt->second.objVal) {
                    (void)phName;
                    if (!phMap.isObject()) continue;
                    for (auto& [tlName, frames] : phMap.objVal) {
                        if (tlName != "reset") {
                            normalize1Channel(frames, 0.0, isPre40, report);
                        }
                    }
                }
            }

            // 6g. Attachment deform timelines.
            if (auto attTlIt = animObj.objVal.find("attachments");
                attTlIt != animObj.objVal.end() && attTlIt->second.isObject())
            {
                for (auto& [skinName, skinVal] : attTlIt->second.objVal) {
                    (void)skinName;
                    if (!skinVal.isObject()) continue;
                    for (auto& [slotName, slotVal] : skinVal.objVal) {
                        (void)slotName;
                        if (!slotVal.isObject()) continue;
                        for (auto& [attName, attMap] : slotVal.objVal) {
                            (void)attName;
                            if (!attMap.isObject()) continue;
                            if (auto defIt = attMap.objVal.find("deform"); defIt != attMap.objVal.end()) {
                                normalizeCurveKeyframes<1>(
                                    defIt->second, 1u, isPre40,
                                    [](const JsonValue&, size_t idx) -> std::array<double, 1> {
                                        // SkeletonJson::readAnimation passes value1=0, value2=1 on deform curves.
                                        return {idx == 0 ? 0.0 : 1.0};
                                    },
                                    report);
                            }
                        }
                    }
                }
            }
        }
    }

    if (!report.modified) {
        outJson.assign(rawJson.data(), rawJson.size());
    } else {
        outJson.clear();
        outJson.reserve(rawJson.size() + 64u);
        dumpJsonTo(root, outJson);
    }

    if (outReport) *outReport = std::move(report);
    return true;
}

} // namespace gclient::assets
