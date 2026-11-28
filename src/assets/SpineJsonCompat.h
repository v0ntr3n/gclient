#pragma once
// ============================================================================
// SpineJsonCompat.h — In-memory Spine 4.1 / legacy JSON -> Spine 4.2 adapter
//
// Normalizes Spine 4.1.x (as well as 4.0.x / 3.8.x / 2.1.x) JSON skeletons in
// memory so Axmol v2.11.5's bundled Spine 4.2 SkeletonJson runtime can parse
// converted Spine JSON assets (such as spineRes/effect/Loading11.json) without
// version rejection, lost bone inheritance modes, or curve timeline crashes.
// ============================================================================

#include <cstddef>
#include <string>
#include <string_view>

namespace gclient::assets {

struct SpineJsonCompatReport {
    std::string sourceVersion;
    std::string targetVersion;
    bool modified            = false;
    bool versionRewritten    = false;
    size_t bonesInheritFixed = 0;
    size_t curvesNormalized  = 0;
    size_t legacyUpgrades    = 0;
};

// Normalizes rawJson into Spine 4.2-compatible JSON stored in outJson.
// Returns true if rawJson parsed as a JSON skeleton object; returns false on
// malformed JSON input.
bool NormalizeSpineJsonFor42(
    std::string_view rawJson,
    std::string& outJson,
    SpineJsonCompatReport* outReport = nullptr);

} // namespace gclient::assets
