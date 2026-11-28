#include "AtomicHotUpdater.h"

#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelHttp.h"
#include "common/KestrelJson.h"
#include "common/KestrelUtf8.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <string_view>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace gclient {
namespace update {

namespace fs = std::filesystem;

namespace {

using gclient::common::endsWithAsciiCI;
using gclient::common::equalsAsciiCI;
using gclient::common::fnv1a64;
using gclient::common::startsWithAsciiCI;
using gclient::utf8::fsPathToUtf8;
using gclient::utf8::utf8ToFsPath;

std::string_view bootStateToString(BootState state) noexcept {
    switch (state) {
        case BootState::Confirmed:           return "confirmed";
        case BootState::PendingVerification: return "pending_verification";
        case BootState::RolledBack:          return "rolled_back";
    }
    return "confirmed";
}

BootState stringToBootState(std::string_view s) noexcept {
    if (s == "pending_verification") return BootState::PendingVerification;
    if (s == "rolled_back") return BootState::RolledBack;
    return BootState::Confirmed;
}

std::string normalizeComparePath(const fs::path& rawPath) {
    if (rawPath.empty()) return {};
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(rawPath, ec);
    if (ec || canon.empty()) {
        ec.clear();
        canon = fs::absolute(rawPath, ec).lexically_normal();
    }
    std::string s = fsPathToUtf8(canon.empty() ? rawPath.lexically_normal() : canon);
    for (char& ch : s) {
        if (ch == '\\') ch = '/';
#ifdef _WIN32
        else ch = static_cast<char>(gclient::common::asciiLower(static_cast<unsigned char>(ch)));
#endif
    }
    while (s.size() > 1 && s.back() == '/') {
        if (s.size() == 3 && s[1] == ':') break;
        s.pop_back();
    }
    return s;
}

bool isSameOrSubpathNormalized(std::string_view childNorm, std::string_view parentNorm) noexcept {
    if (childNorm.empty() || parentNorm.empty()) return false;
    if (childNorm == parentNorm) return true;
    if (childNorm.size() <= parentNorm.size() || !childNorm.starts_with(parentNorm)) return false;
    return parentNorm.back() == '/' || childNorm[parentNorm.size()] == '/';
}

bool isStrictSubpathNormalized(std::string_view childNorm, std::string_view parentNorm) noexcept {
    return childNorm != parentNorm && isSameOrSubpathNormalized(childNorm, parentNorm);
}

bool containsProtectedConvertedDirComponent(const fs::path& p) {
    for (const fs::path& part : p) {
        if (equalsAsciiCI(fsPathToUtf8(part), "resources_axmol_converted")) {
            return true;
        }
    }
    return false;
}

bool isReservedWindowsDeviceStem(std::string_view filename) noexcept {
    const size_t dot = filename.find('.');
    const std::string_view stem = (dot == std::string_view::npos) ? filename : filename.substr(0, dot);
    if (stem.size() < 3 || stem.size() > 4) return false;
    if (equalsAsciiCI(stem, "con") || equalsAsciiCI(stem, "prn") ||
        equalsAsciiCI(stem, "aux") || equalsAsciiCI(stem, "nul")) {
        return true;
    }
    return stem.size() == 4 &&
           (startsWithAsciiCI(stem, "com") || startsWithAsciiCI(stem, "lpt")) &&
           stem[3] >= '1' && stem[3] <= '9';
}

bool readBinaryTextFile(const fs::path& p, std::string& out) {
    std::ifstream ifs(p, std::ios::in | std::ios::binary);
    if (!ifs.is_open()) return false;
    std::ostringstream oss;
    oss << ifs.rdbuf();
    out = oss.str();
    return !ifs.bad();
}

#if GCLIENT_HTTP_HAS_CURL && !defined(GCLIENT_STANDALONE_BUILD)
bool defaultCurlOrFileTransport(const std::string& rawUrl, const fs::path& destinationPath, std::string& errorOut) {
    if (startsWithAsciiCI(rawUrl, "http://") || startsWithAsciiCI(rawUrl, "https://")) {
        const std::string overrideBase = gclient::utf8::firstNonEmptyEnv(
            {"KESTREL_UPDATE_URL", "GCLIENT_UPDATE_URL", "KESTREL_MAPI_URL"});
        const std::string effectiveUrl = gclient::http::EndpointRewritePolicy::rewriteToBase(rawUrl, overrideBase);
        const bool insecureTls = gclient::utf8::readEnvBool({"GCLIENT_INSECURE_TLS", "KESTREL_INSECURE_TLS"}, false);
        const std::string caBundle = gclient::utf8::readEnvUtf8("CURL_CA_BUNDLE");
        const auto resp = gclient::http::performCurlRequest(
            effectiveUrl, nullptr, {}, 8000, 60000, !insecureTls, caBundle);
        if (!resp.ok()) {
            errorOut = !resp.error.empty()
                ? resp.error
                : ("HTTP status " + std::to_string(resp.statusCode));
            return false;
        }
        std::ofstream ofs(destinationPath, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            errorOut = "Failed to open staged destination file for write.";
            return false;
        }
        ofs.write(resp.body.data(), static_cast<std::streamsize>(resp.body.size()));
        if (!ofs.good()) {
            errorOut = "Failed writing HTTP response body to staged file.";
            return false;
        }
        return true;
    }
    return false;
}
#endif

} // namespace

AtomicHotUpdater::CrossProcessLock::CrossProcessLock(const fs::path& patchRoot)
    : m_lockFilePath(patchRoot / "update.lock") {
    std::ostringstream oss;
    oss << "Local\\GCLIENT_HotUpdate_" << std::hex << fnv1a64(fsPathToUtf8(patchRoot));
    m_mutexName = oss.str();
}

AtomicHotUpdater::CrossProcessLock::~CrossProcessLock() {
    release();
}

bool AtomicHotUpdater::CrossProcessLock::acquire(uint32_t timeoutMs, std::string& errorOut) {
    if (m_acquired) return true;
#ifdef _WIN32
    const std::wstring wideName = gclient::utf8::utf8ToWide(m_mutexName);
    HANDLE h = CreateMutexW(nullptr, FALSE, wideName.c_str());
    if (!h) {
        errorOut = "CreateMutexW failed with Win32 error " + std::to_string(GetLastError());
        return false;
    }
    const DWORD waitRes = WaitForSingleObject(h, timeoutMs);
    if (waitRes == WAIT_OBJECT_0 || waitRes == WAIT_ABANDONED) {
        m_mutexHandle = h;
        m_acquired = true;
        return true;
    }
    CloseHandle(h);
    errorOut = (waitRes == WAIT_TIMEOUT)
        ? "Timed out waiting for another Game Client instance to finish hot-updating"
        : "WaitForSingleObject failed with code " + std::to_string(waitRes);
    return false;
#else
    std::error_code ec;
    fs::create_directories(m_lockFilePath.parent_path(), ec);
    m_lockFd = ::open(m_lockFilePath.c_str(), O_CREAT | O_RDWR, 0644);
    if (m_lockFd < 0) {
        errorOut = "Failed to open lock file: " + m_lockFilePath.string();
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        if (::flock(m_lockFd, LOCK_EX | LOCK_NB) == 0) {
            m_acquired = true;
            return true;
        }
        if (std::chrono::steady_clock::now() >= deadline) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
    ::close(m_lockFd);
    m_lockFd = -1;
    errorOut = "Another Game Client instance holds the hot-update lock";
    return false;
#endif
}

void AtomicHotUpdater::CrossProcessLock::release() {
    if (!m_acquired) return;
#ifdef _WIN32
    if (m_mutexHandle) {
        ReleaseMutex(static_cast<HANDLE>(m_mutexHandle));
        CloseHandle(static_cast<HANDLE>(m_mutexHandle));
        m_mutexHandle = nullptr;
    }
#else
    if (m_lockFd >= 0) {
        ::flock(m_lockFd, LOCK_UN);
        ::close(m_lockFd);
        m_lockFd = -1;
    }
#endif
    m_acquired = false;
}

AtomicHotUpdater::AtomicHotUpdater(HotUpdaterConfig config)
    : m_config(std::move(config)) {
#if GCLIENT_HTTP_HAS_CURL && !defined(GCLIENT_STANDALONE_BUILD)
    m_transport = &defaultCurlOrFileTransport;
#endif
}

AtomicHotUpdater::~AtomicHotUpdater() = default;

void AtomicHotUpdater::setResourceHandleHooks(ResourceHandleHooks hooks) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_hooks = std::move(hooks);
}

void AtomicHotUpdater::setDownloadTransport(DownloadTransport transport) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_transport = std::move(transport);
}

fs::path AtomicHotUpdater::stagingRoot() const { return m_config.patchRootDir / "staging"; }
fs::path AtomicHotUpdater::releasesRoot() const { return m_config.patchRootDir / "releases"; }
fs::path AtomicHotUpdater::activeManifestPath() const { return m_config.patchRootDir / "active_manifest.json"; }
fs::path AtomicHotUpdater::previousManifestPath() const { return m_config.patchRootDir / "previous_manifest.json"; }
fs::path AtomicHotUpdater::releaseDirForVersion(const std::string& version) const {
    return releasesRoot() / utf8ToFsPath(version);
}

bool AtomicHotUpdater::validatePatchRootIsolation(std::string& errorOut) const {
    if (m_config.patchRootDir.empty()) {
        errorOut = "HotUpdaterConfig::patchRootDir is empty.";
        return false;
    }
    if (containsProtectedConvertedDirComponent(m_config.patchRootDir)) {
        errorOut = "Refusing to point AtomicHotUpdater::patchRootDir inside protected Resources_Axmol_Converted tree.";
        return false;
    }
    const std::string patchNorm = normalizeComparePath(m_config.patchRootDir);
    if (patchNorm.empty() || patchNorm == "/" || (patchNorm.size() == 3 && patchNorm[1] == ':' && patchNorm[2] == '/')) {
        errorOut = "Refusing to use filesystem root as AtomicHotUpdater::patchRootDir.";
        return false;
    }
    if (!m_config.baseResourcesDir.empty()) {
        const std::string baseNorm = normalizeComparePath(m_config.baseResourcesDir);
        if (!baseNorm.empty()) {
            if (isSameOrSubpathNormalized(patchNorm, baseNorm)) {
                errorOut = "AtomicHotUpdater::patchRootDir overlaps or resides inside read-only baseResourcesDir.";
                return false;
            }
            if (isSameOrSubpathNormalized(baseNorm, patchNorm)) {
                errorOut = "AtomicHotUpdater::patchRootDir encloses read-only baseResourcesDir.";
                return false;
            }
        }
    }
    return true;
}

bool AtomicHotUpdater::isOverlayDirContainedInReleases(const fs::path& candidateDir) const {
    if (candidateDir.empty() || containsProtectedConvertedDirComponent(candidateDir)) {
        return false;
    }
    const std::string candNorm = normalizeComparePath(candidateDir);
    if (!isStrictSubpathNormalized(candNorm, normalizeComparePath(releasesRoot()))) {
        return false;
    }
    if (!m_config.baseResourcesDir.empty()) {
        const std::string baseNorm = normalizeComparePath(m_config.baseResourcesDir);
        if (!baseNorm.empty() &&
            (isSameOrSubpathNormalized(candNorm, baseNorm) || isSameOrSubpathNormalized(baseNorm, candNorm))) {
            return false;
        }
    }
    return true;
}

bool AtomicHotUpdater::isDirectoryTreeUnlocked(const fs::path& dirPath) const {
#ifdef _WIN32
    std::error_code ec;
    if (!fs::exists(dirPath, ec)) return true;
    for (const auto& entry : fs::recursive_directory_iterator(dirPath, ec)) {
        if (ec) return false;
        if (!entry.is_regular_file(ec)) continue;
        HANDLE h = ::CreateFileW(
            entry.path().c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            if (::GetLastError() != ERROR_FILE_NOT_FOUND) return false;
        } else {
            ::CloseHandle(h);
        }
    }
    return true;
#else
    (void)dirPath;
    return true;
#endif
}

bool AtomicHotUpdater::validateDownloadedPayloadCompatibility(
    const std::string& relativePath,
    const fs::path& stagedFile,
    std::string& errorOut) const {
    if (!m_config.enforceAxmolConvertedAssetCompat) return true;
    if (!isAxmolCompatibleRelativeAssetPath(relativePath)) {
        errorOut = "Patch contains legacy un-converted texture format incompatible with Resources_Axmol_Converted: " + relativePath;
        return false;
    }
    if (endsWithAsciiCI(relativePath, ".lua")) {
        std::ifstream ifs(stagedFile, std::ios::in | std::ios::binary);
        if (ifs.is_open()) {
            std::array<uint8_t, 5> hdr{};
            ifs.read(reinterpret_cast<char*>(hdr.data()), static_cast<std::streamsize>(hdr.size()));
            if (ifs.gcount() >= 5 && hdr[0] == 0x1Bu && hdr[1] == 'L' && hdr[2] == 'J') {
                if (hdr[3] < 0x02u || (hdr[4] & 0x08u) == 0u) {
                    errorOut = "Rejected 32-bit (non-GC64) LuaJIT bytecode in x64 Axmol overlay: " + relativePath;
                    return false;
                }
            }
        }
    }
    return true;
}

bool AtomicHotUpdater::ensureDirectoryLayout(std::string& errorOut) const {
    if (!validatePatchRootIsolation(errorOut)) return false;
    std::error_code ec;
    for (const auto& [dir, label] : std::array<std::pair<fs::path, const char*>, 3>{
             {{m_config.patchRootDir, "patch root"}, {stagingRoot(), "staging"}, {releasesRoot(), "releases"}}}) {
        fs::create_directories(dir, ec);
        if (ec) {
            errorOut = std::string("Failed to create ") + label + " dir: " + ec.message();
            return false;
        }
    }
    return true;
}

StartupHealthResult AtomicHotUpdater::initializeAndCheckStartupHealth() {
    std::lock_guard<std::mutex> lock(m_mutex);
    StartupHealthResult result;

    if (!ensureDirectoryLayout(result.diagnosticMessage)) {
        return result;
    }

    CrossProcessLock procLock(m_config.patchRootDir);
    std::string lockErr;
    const bool haveLock = procLock.acquire(2000, lockErr);

    ActiveOverlayState state;
    if (!loadActiveStateLocked(state)) {
        result.diagnosticMessage = "No active hot-update overlay; booting from base Resources_Axmol_Converted/.";
        return result;
    }

    std::error_code ec;
    const fs::path activeFsPath = utf8ToFsPath(state.activeOverlayDir);
    const bool activeOutsideReleases = !state.activeOverlayDir.empty() &&
                                       !isOverlayDirContainedInReleases(activeFsPath);
    const bool activeDirMissing = !state.activeOverlayDir.empty() && !fs::exists(activeFsPath, ec);
    const bool exceededBootFailures =
        state.bootState == BootState::PendingVerification &&
        state.consecutiveBootFailures >= state.maxBootFailuresBeforeRollback;

    if (activeOutsideReleases || activeDirMissing || exceededBootFailures) {
        result.rolledBack = true;
        result.rolledBackFromVersion = state.activeVersion;

        ActiveOverlayState reverted = state;
        const fs::path prevFsPath = utf8ToFsPath(state.previousOverlayDir);
        const bool prevValid = !state.previousOverlayDir.empty() &&
                               isOverlayDirContainedInReleases(prevFsPath) &&
                               fs::exists(prevFsPath, ec);
        reverted.activeVersion = prevValid ? state.previousVersion : "";
        reverted.activeOverlayDir = prevValid ? state.previousOverlayDir : "";
        reverted.previousVersion.clear();
        reverted.previousOverlayDir.clear();
        reverted.bootState = BootState::RolledBack;
        reverted.consecutiveBootFailures = 0;
        reverted.activatedUtc = currentUtcIso8601();

        std::string writeErr;
        if (haveLock && !writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(reverted), writeErr)) {
            result.diagnosticMessage = "Auto-rollback write failed: " + writeErr;
        } else {
            result.hasActiveOverlay = !reverted.activeOverlayDir.empty();
            result.activeVersion = reverted.activeVersion;
            result.activeOverlayPath = utf8ToFsPath(reverted.activeOverlayDir);
            result.diagnosticMessage = activeOutsideReleases
                ? "Quarantined unsafe activeOverlayDir outside releases/; reverted to clean base Resources_Axmol_Converted/."
                : (activeDirMissing
                    ? "Active overlay directory missing; rolled back from " + state.activeVersion
                    : "Startup verification failed " + std::to_string(state.consecutiveBootFailures) +
                      " time(s); rolled back from " + state.activeVersion +
                      " to " + (reverted.activeVersion.empty() ? "base Resources_Axmol_Converted/" : reverted.activeVersion));
        }
        return result;
    }

    if (haveLock && state.bootState == BootState::PendingVerification) {
        state.consecutiveBootFailures += 1;
        std::string writeErr;
        writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(state), writeErr);
    }

    result.hasActiveOverlay = !state.activeOverlayDir.empty();
    result.activeVersion = state.activeVersion;
    result.activeOverlayPath = activeFsPath;
    result.diagnosticMessage = "Overlay " + state.activeVersion + " active (" +
                               std::string(bootStateToString(state.bootState)) + ").";
    return result;
}

UpdateResult AtomicHotUpdater::confirmStartupSuccess() {
    std::lock_guard<std::mutex> lock(m_mutex);
    UpdateResult res;

    if (!validatePatchRootIsolation(res.message)) {
        res.status = UpdateStatus::InvalidPathTraversal;
        return res;
    }

    ActiveOverlayState state;
    if (!loadActiveStateLocked(state)) {
        res.status = UpdateStatus::Ok;
        res.message = "No active overlay manifest to confirm.";
        return res;
    }

    if (state.bootState == BootState::Confirmed && state.consecutiveBootFailures == 0) {
        res.status = UpdateStatus::Ok;
        res.activeVersion = state.activeVersion;
        res.activeOverlayPath = utf8ToFsPath(state.activeOverlayDir);
        res.message = "Active overlay already confirmed.";
        return res;
    }

    CrossProcessLock procLock(m_config.patchRootDir);
    if (!procLock.acquire(3000, res.message)) {
        res.status = UpdateStatus::LockAcquisitionFailed;
        return res;
    }

    state.bootState = BootState::Confirmed;
    state.consecutiveBootFailures = 0;

    std::string err;
    if (!writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(state), err)) {
        res.status = UpdateStatus::IoError;
        res.message = "Failed to confirm startup state: " + err;
        return res;
    }

    res.status = UpdateStatus::Ok;
    res.activeVersion = state.activeVersion;
    res.activeOverlayPath = utf8ToFsPath(state.activeOverlayDir);
    res.message = "Confirmed startup health for overlay " + state.activeVersion + ".";
    return res;
}

UpdateStatus AtomicHotUpdater::checkCompatibility(
    const PatchManifest& manifest,
    std::string& reasonOut) const {
    if (manifest.patchVersion.empty() || !isValidVersionToken(manifest.patchVersion)) {
        reasonOut = "Invalid or empty patchVersion in manifest.";
        return UpdateStatus::InvalidManifest;
    }

    const auto& caps = m_config.capabilities;
    const auto& req = manifest.contract;

    if (caps.nativeBindingApiVersion < req.minNativeBindingApiVersion ||
        caps.nativeBindingApiVersion > req.maxNativeBindingApiVersion) {
        reasonOut = "Native binding API version mismatch: client=" +
                    std::to_string(caps.nativeBindingApiVersion) +
                    ", patch requires [" + std::to_string(req.minNativeBindingApiVersion) +
                    ", " + std::to_string(req.maxNativeBindingApiVersion) + "].";
        return UpdateStatus::IncompatibleNativeBinding;
    }
    if (caps.protoSchemaVersion != req.requiredProtoSchemaVersion) {
        reasonOut = "Proto2 schema version mismatch: client=" +
                    std::to_string(caps.protoSchemaVersion) +
                    ", patch requires " + std::to_string(req.requiredProtoSchemaVersion) + ".";
        return UpdateStatus::IncompatibleProtoSchema;
    }
    if (caps.dbSchemaVersion != req.requiredDbSchemaVersion) {
        reasonOut = "SQLite DB schema version mismatch: client=" +
                    std::to_string(caps.dbSchemaVersion) +
                    ", patch requires " + std::to_string(req.requiredDbSchemaVersion) + ".";
        return UpdateStatus::IncompatibleDbSchema;
    }
    if (!req.minClientVersion.empty() && compareSemver(caps.clientVersion, req.minClientVersion) < 0) {
        reasonOut = "Client version " + caps.clientVersion +
                    " is older than patch minimum " + req.minClientVersion + ".";
        return UpdateStatus::IncompatibleClientVersion;
    }
    for (const auto& symbol : req.requiredNativeBindings) {
        if (caps.exportedBindings.find(symbol) == caps.exportedBindings.end()) {
            reasonOut = "Patch requires missing native C++ binding: " + symbol;
            return UpdateStatus::MissingRequiredBinding;
        }
    }
    if (m_config.enforceAxmolConvertedAssetCompat) {
        for (const auto& entry : manifest.files) {
            if (!entry.relativePath.empty() && !isAxmolCompatibleRelativeAssetPath(entry.relativePath)) {
                reasonOut = "Rejected legacy un-converted texture format in manifest: " + entry.relativePath;
                return UpdateStatus::InvalidManifest;
            }
        }
    }

    reasonOut.clear();
    return UpdateStatus::Ok;
}

UpdateResult AtomicHotUpdater::stagePatch(
    const PatchManifest& manifest,
    const StageProgressCallback& progressCb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    UpdateResult res;

    res.status = checkCompatibility(manifest, res.message);
    if (res.status != UpdateStatus::Ok) return res;

    if (!m_transport) {
        res.status = UpdateStatus::DownloadFailed;
        res.message = "No DownloadTransport registered on AtomicHotUpdater.";
        return res;
    }
    if (!ensureDirectoryLayout(res.message)) {
        res.status = UpdateStatus::InvalidPathTraversal;
        return res;
    }

    const fs::path targetReleaseDir = releaseDirForVersion(manifest.patchVersion);
    if (!isOverlayDirContainedInReleases(targetReleaseDir)) {
        res.status = UpdateStatus::InvalidPathTraversal;
        res.message = "Target release path escapes releases/ boundary.";
        return res;
    }

    std::error_code ec;
    if (fs::exists(targetReleaseDir, ec) && fs::is_directory(targetReleaseDir, ec)) {
        ActiveOverlayState cur;
        if (loadActiveStateLocked(cur) && cur.activeVersion == manifest.patchVersion) {
            res.status = UpdateStatus::AlreadyUpToDate;
            res.activeVersion = cur.activeVersion;
            res.activeOverlayPath = utf8ToFsPath(cur.activeOverlayDir);
            res.message = "Patch " + manifest.patchVersion + " is already active.";
            return res;
        }
    }

    for (const auto& entry : manifest.files) {
        if (!isSafeRelativePath(entry.relativePath)) {
            res.status = UpdateStatus::InvalidPathTraversal;
            res.message = "Rejected unsafe relative path in manifest: " + entry.relativePath;
            return res;
        }
        if (m_config.enforceAxmolConvertedAssetCompat && !isAxmolCompatibleRelativeAssetPath(entry.relativePath)) {
            res.status = UpdateStatus::InvalidManifest;
            res.message = "Rejected legacy un-converted texture format in manifest: " + entry.relativePath;
            return res;
        }
        if (entry.sha256.empty() && entry.md5.empty()) {
            res.status = UpdateStatus::InvalidManifest;
            res.message = "Manifest entry missing both SHA-256 and MD5 checksum: " + entry.relativePath;
            return res;
        }
    }

    const fs::path stagingDir = stagingRoot() / (manifest.patchVersion + "_" + generateStagingNonce());
    const std::string stageNorm = normalizeComparePath(stagingDir);
    const std::string stageRootNorm = normalizeComparePath(stagingRoot());
    if (!isStrictSubpathNormalized(stageNorm, stageRootNorm)) {
        res.status = UpdateStatus::InvalidPathTraversal;
        res.message = "Staging path escaped staging/ root.";
        return res;
    }

    fs::create_directories(stagingDir, ec);
    if (ec) {
        res.status = UpdateStatus::IoError;
        res.message = "Failed to create staging directory: " + ec.message();
        return res;
    }

    auto cleanupStaging = [&]() {
        if (isStrictSubpathNormalized(normalizeComparePath(stagingDir), normalizeComparePath(stagingRoot())) &&
            !containsProtectedConvertedDirComponent(stagingDir)) {
            std::error_code rmEc;
            fs::remove_all(stagingDir, rmEc);
        }
    };

    const size_t totalFiles = manifest.files.size();
    for (size_t i = 0; i < totalFiles; ++i) {
        const auto& entry = manifest.files[i];
        const fs::path destFile = stagingDir / utf8ToFsPath(entry.relativePath);
        if (!isStrictSubpathNormalized(normalizeComparePath(destFile), stageNorm)) {
            cleanupStaging();
            res.status = UpdateStatus::InvalidPathTraversal;
            res.message = "Resolved file escaped staging directory: " + entry.relativePath;
            return res;
        }

        fs::create_directories(destFile.parent_path(), ec);
        if (ec) {
            cleanupStaging();
            res.status = UpdateStatus::IoError;
            res.message = "Failed to create parent dir for " + entry.relativePath + ": " + ec.message();
            return res;
        }

        std::string dlErr;
        if (!m_transport(entry.downloadUrl, destFile, dlErr)) {
            cleanupStaging();
            res.status = UpdateStatus::DownloadFailed;
            res.message = "Download failed for " + entry.relativePath + ": " + dlErr;
            return res;
        }

        if (entry.expectedSize > 0) {
            const uint64_t actualSize = fs::file_size(destFile, ec);
            if (ec || actualSize != entry.expectedSize) {
                cleanupStaging();
                res.status = UpdateStatus::SizeMismatch;
                res.message = "Size mismatch for " + entry.relativePath +
                              " (expected " + std::to_string(entry.expectedSize) +
                              ", got " + std::to_string(actualSize) + ").";
                return res;
            }
        }

        auto verifyDigest = [&](HashAlgorithm algo, const std::string& expected, const char* label) -> bool {
            if (expected.empty()) return true;
            std::string actual, hashErr;
            if (!computeFileHash(destFile, algo, actual, hashErr) || !equalsAsciiCI(actual, expected)) {
                cleanupStaging();
                res.status = UpdateStatus::ChecksumMismatch;
                res.message = std::string(label) + " mismatch for " + entry.relativePath +
                              (hashErr.empty() ? "" : (" (" + hashErr + ")"));
                return false;
            }
            return true;
        };
        if (!verifyDigest(HashAlgorithm::SHA256, entry.sha256, "SHA-256") ||
            !verifyDigest(HashAlgorithm::MD5, entry.md5, "MD5")) {
            return res;
        }

        if (!validateDownloadedPayloadCompatibility(entry.relativePath, destFile, res.message)) {
            cleanupStaging();
            res.status = UpdateStatus::IncompatibleNativeBinding;
            return res;
        }

        if (progressCb) {
            progressCb(i + 1, totalFiles, entry.relativePath);
        }
    }

    CrossProcessLock procLock(m_config.patchRootDir);
    if (!procLock.acquire(5000, res.message)) {
        cleanupStaging();
        res.status = UpdateStatus::LockAcquisitionFailed;
        return res;
    }

    std::string moveErr;
    if (!moveDirectoryAtomically(stagingDir, targetReleaseDir, moveErr)) {
        cleanupStaging();
        res.status = UpdateStatus::IoError;
        res.message = "Failed to promote staged release: " + moveErr;
        return res;
    }

    res.status = UpdateStatus::Ok;
    res.activeVersion = manifest.patchVersion;
    res.activeOverlayPath = targetReleaseDir;
    res.message = "Staged and verified patch " + manifest.patchVersion +
                  " (" + std::to_string(totalFiles) + " files).";
    return res;
}

UpdateResult AtomicHotUpdater::commitStagedPatch(const std::string& patchVersion) {
    std::lock_guard<std::mutex> lock(m_mutex);
    UpdateResult res;

    if (!validatePatchRootIsolation(res.message)) {
        res.status = UpdateStatus::InvalidPathTraversal;
        return res;
    }
    if (!isValidVersionToken(patchVersion)) {
        res.status = UpdateStatus::InvalidManifest;
        res.message = "Invalid patchVersion token: " + patchVersion;
        return res;
    }

    const fs::path releaseDir = releaseDirForVersion(patchVersion);
    if (!isOverlayDirContainedInReleases(releaseDir)) {
        res.status = UpdateStatus::InvalidPathTraversal;
        res.message = "Release directory escapes releases/ boundary: " + patchVersion;
        return res;
    }

    std::error_code ec;
    if (!fs::exists(releaseDir, ec) || !fs::is_directory(releaseDir, ec)) {
        res.status = UpdateStatus::InvalidManifest;
        res.message = "Staged release directory not found for version " + patchVersion;
        return res;
    }

    CrossProcessLock procLock(m_config.patchRootDir);
    if (!procLock.acquire(5000, res.message)) {
        res.status = UpdateStatus::LockAcquisitionFailed;
        return res;
    }

    ActiveOverlayState prevState;
    const bool hadPrevState = loadActiveStateLocked(prevState);
    const fs::path oldOverlayDir =
        (hadPrevState && isOverlayDirContainedInReleases(utf8ToFsPath(prevState.activeOverlayDir)))
            ? utf8ToFsPath(prevState.activeOverlayDir)
            : fs::path{};

    auto failAbort = [&](UpdateStatus st, std::string msg) -> UpdateResult {
        if (m_hooks.abortSwap) m_hooks.abortSwap(oldOverlayDir);
        res.status = st;
        res.message = std::move(msg);
        return res;
    };

    if (m_hooks.prepareForSwap) {
        std::string hookErr;
        if (!m_hooks.prepareForSwap(hookErr)) {
            return failAbort(UpdateStatus::HandleReleaseFailed, "Subsystem refused handle release: " + hookErr);
        }
    }
    if (m_hooks.verifyHandlesReleased) {
        std::string verifyErr;
        if (!m_hooks.verifyHandlesReleased(verifyErr)) {
            return failAbort(UpdateStatus::HandleReleaseFailed,
                             "Open handles still detected after prepareForSwap: " + verifyErr);
        }
    }
    if (fs::exists(activeManifestPath(), ec)) {
        std::string probeErr;
        if (!probePathUnlockedWithRetry(activeManifestPath(), probeErr)) {
            return failAbort(UpdateStatus::NtfsLockTimeout, "NTFS lock timeout on active_manifest.json: " + probeErr);
        }
    }

    if (hadPrevState && (prevState.activeOverlayDir.empty() || !oldOverlayDir.empty())) {
        std::string backupErr;
        writeFileAtomically(previousManifestPath(), serializeOverlayStateJson(prevState), backupErr);
    }

    ActiveOverlayState nextState;
    nextState.activeVersion = patchVersion;
    nextState.activeOverlayDir = fsPathToUtf8(releaseDir);
    nextState.previousVersion = !oldOverlayDir.empty() ? prevState.activeVersion : "";
    nextState.previousOverlayDir = !oldOverlayDir.empty() ? prevState.activeOverlayDir : "";
    nextState.bootState = BootState::PendingVerification;
    nextState.consecutiveBootFailures = 0;
    nextState.maxBootFailuresBeforeRollback = m_config.maxBootFailuresBeforeRollback;
    nextState.nativeBindingApiVersion = m_config.capabilities.nativeBindingApiVersion;
    nextState.protoSchemaVersion = m_config.capabilities.protoSchemaVersion;
    nextState.dbSchemaVersion = m_config.capabilities.dbSchemaVersion;
    nextState.activatedUtc = currentUtcIso8601();

    std::string swapErr;
    if (!writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(nextState), swapErr)) {
        return failAbort(UpdateStatus::SwapFailed, "Atomic manifest swap failed: " + swapErr);
    }

    if (m_hooks.reloadAfterSwap) {
        std::string reloadErr;
        if (!m_hooks.reloadAfterSwap(releaseDir, reloadErr)) {
            ActiveOverlayState rollbackState = (!oldOverlayDir.empty()) ? prevState : ActiveOverlayState{};
            rollbackState.bootState = BootState::RolledBack;
            rollbackState.consecutiveBootFailures = 0;
            std::string rbErr;
            writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(rollbackState), rbErr);
            if (m_hooks.abortSwap) m_hooks.abortSwap(oldOverlayDir);
            res.status = UpdateStatus::ReloadFailedRolledBack;
            res.activeVersion = rollbackState.activeVersion;
            res.activeOverlayPath = utf8ToFsPath(rollbackState.activeOverlayDir);
            res.message = "Subsystem reload failed (" + reloadErr + "); rolled back to " +
                          (rollbackState.activeVersion.empty() ? "base Resources_Axmol_Converted/" : rollbackState.activeVersion);
            return res;
        }
    }

    res.status = UpdateStatus::Ok;
    res.activeVersion = nextState.activeVersion;
    res.activeOverlayPath = releaseDir;
    res.message = "Atomically activated overlay " + patchVersion + " (pending startup verification).";
    return res;
}

UpdateResult AtomicHotUpdater::applyPatch(
    const PatchManifest& manifest,
    const StageProgressCallback& progressCb) {
    UpdateResult stageRes = stagePatch(manifest, progressCb);
    if (!stageRes.ok() || stageRes.status == UpdateStatus::AlreadyUpToDate) {
        return stageRes;
    }
    return commitStagedPatch(manifest.patchVersion);
}

UpdateResult AtomicHotUpdater::rollbackToPrevious() {
    std::lock_guard<std::mutex> lock(m_mutex);
    UpdateResult res;

    if (!validatePatchRootIsolation(res.message)) {
        res.status = UpdateStatus::InvalidPathTraversal;
        return res;
    }

    ActiveOverlayState curState;
    if (!loadActiveStateLocked(curState)) {
        res.status = UpdateStatus::RollbackUnavailable;
        res.message = "No active overlay manifest found to roll back.";
        return res;
    }

    CrossProcessLock procLock(m_config.patchRootDir);
    if (!procLock.acquire(5000, res.message)) {
        res.status = UpdateStatus::LockAcquisitionFailed;
        return res;
    }

    if (m_hooks.prepareForSwap) {
        std::string hookErr;
        if (!m_hooks.prepareForSwap(hookErr)) {
            res.status = UpdateStatus::HandleReleaseFailed;
            res.message = "Could not release handles for rollback: " + hookErr;
            return res;
        }
    }

    std::error_code ec;
    const fs::path prevFsPath = utf8ToFsPath(curState.previousOverlayDir);
    const bool prevValid = !curState.previousOverlayDir.empty() &&
                           isOverlayDirContainedInReleases(prevFsPath) &&
                           fs::exists(prevFsPath, ec);

    ActiveOverlayState reverted = curState;
    reverted.activeVersion = prevValid ? curState.previousVersion : "";
    reverted.activeOverlayDir = prevValid ? curState.previousOverlayDir : "";
    reverted.previousVersion.clear();
    reverted.previousOverlayDir.clear();
    reverted.bootState = BootState::RolledBack;
    reverted.consecutiveBootFailures = 0;
    reverted.activatedUtc = currentUtcIso8601();

    std::string writeErr;
    if (!writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(reverted), writeErr)) {
        res.status = UpdateStatus::RollbackFailed;
        res.message = "Failed to persist rollback manifest: " + writeErr;
        return res;
    }

    if (m_hooks.reloadAfterSwap) {
        std::string reloadErr;
        m_hooks.reloadAfterSwap(utf8ToFsPath(reverted.activeOverlayDir), reloadErr);
    }

    res.status = UpdateStatus::Ok;
    res.activeVersion = reverted.activeVersion;
    res.activeOverlayPath = utf8ToFsPath(reverted.activeOverlayDir);
    res.message = "Rolled back from " + curState.activeVersion + " to " +
                  (reverted.activeVersion.empty() ? "base Resources_Axmol_Converted/" : reverted.activeVersion) + ".";
    return res;
}

size_t AtomicHotUpdater::pruneOldReleases(size_t keepCount) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string err;
    if (!validatePatchRootIsolation(err)) return 0;

    CrossProcessLock procLock(m_config.patchRootDir);
    if (!procLock.acquire(2000, err)) return 0;

    size_t removed = 0;
    std::error_code ec;
    const std::string stageRootNorm = normalizeComparePath(stagingRoot());

    if (fs::exists(stagingRoot(), ec)) {
        for (const auto& entry : fs::directory_iterator(stagingRoot(), ec)) {
            if (!isStrictSubpathNormalized(normalizeComparePath(entry.path()), stageRootNorm) ||
                containsProtectedConvertedDirComponent(entry.path()) ||
                !isDirectoryTreeUnlocked(entry.path())) {
                continue;
            }
            std::error_code rmEc;
            fs::remove_all(entry.path(), rmEc);
            if (!rmEc) ++removed;
        }
    }

    ActiveOverlayState curState;
    const bool hasState = loadActiveStateLocked(curState);

    std::vector<std::pair<fs::file_time_type, fs::path>> candidates;
    if (fs::exists(releasesRoot(), ec)) {
        for (const auto& entry : fs::directory_iterator(releasesRoot(), ec)) {
            if (!entry.is_directory(ec) || !isOverlayDirContainedInReleases(entry.path())) continue;
            const std::string ver = fsPathToUtf8(entry.path().filename());
            if (hasState && (ver == curState.activeVersion || ver == curState.previousVersion)) continue;
            candidates.emplace_back(entry.last_write_time(ec), entry.path());
        }
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    for (size_t i = keepCount; i < candidates.size(); ++i) {
        if (!isDirectoryTreeUnlocked(candidates[i].second)) continue;
        std::error_code rmEc;
        fs::remove_all(candidates[i].second, rmEc);
        if (!rmEc) ++removed;
    }
    return removed;
}

std::optional<ActiveOverlayState> AtomicHotUpdater::getActiveState() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string isoErr;
    if (!validatePatchRootIsolation(isoErr)) return std::nullopt;
    ActiveOverlayState state;
    if (!loadActiveStateLocked(state)) return std::nullopt;
    return state;
}

std::optional<fs::path> AtomicHotUpdater::getActiveOverlayPath() const {
    auto state = getActiveState();
    if (!state || state->activeOverlayDir.empty()) return std::nullopt;
    const fs::path p = utf8ToFsPath(state->activeOverlayDir);
    return isOverlayDirContainedInReleases(p) ? std::optional<fs::path>(p) : std::nullopt;
}

bool AtomicHotUpdater::loadActiveStateLocked(ActiveOverlayState& outState) const {
    std::string raw;
    if (readBinaryTextFile(activeManifestPath(), raw) && parseOverlayStateJson(raw, outState)) {
        return true;
    }
    if (!readBinaryTextFile(previousManifestPath(), raw) || !parseOverlayStateJson(raw, outState)) {
        return false;
    }
    std::string healErr;
    writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(outState), healErr);
    return true;
}

bool AtomicHotUpdater::writeFileAtomically(
    const fs::path& targetPath,
    const std::string& contents,
    std::string& errorOut) const {
    if (!validatePatchRootIsolation(errorOut)) return false;
    if (!isStrictSubpathNormalized(normalizeComparePath(targetPath), normalizeComparePath(m_config.patchRootDir)) ||
        containsProtectedConvertedDirComponent(targetPath)) {
        errorOut = "Refusing atomic write outside patchRootDir.";
        return false;
    }

    std::error_code ec;
    fs::create_directories(targetPath.parent_path(), ec);
    const fs::path tmpPath = targetPath.parent_path() /
                             (fsPathToUtf8(targetPath.filename()) + "." + generateStagingNonce() + ".tmp");

#ifdef _WIN32
    HANDLE hFile = CreateFileW(
        tmpPath.wstring().c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        errorOut = "CreateFileW failed for temp manifest: Win32 error " + std::to_string(GetLastError());
        return false;
    }
    DWORD written = 0;
    const BOOL writeOk = WriteFile(hFile, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr);
    const BOOL flushOk = writeOk ? FlushFileBuffers(hFile) : FALSE;
    const DWORD lastErr = GetLastError();
    CloseHandle(hFile);

    if (!writeOk || written != contents.size() || !flushOk) {
        DeleteFileW(tmpPath.wstring().c_str());
        errorOut = "WriteFile/FlushFileBuffers failed: Win32 error " + std::to_string(lastErr);
        return false;
    }

    for (uint32_t attempt = 0; attempt <= m_config.lockProbeMaxRetries; ++attempt) {
        if (MoveFileExW(tmpPath.wstring().c_str(), targetPath.wstring().c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            return true;
        }
        const DWORD moveErr = GetLastError();
        if (moveErr != ERROR_SHARING_VIOLATION && moveErr != ERROR_ACCESS_DENIED &&
            moveErr != ERROR_LOCK_VIOLATION) {
            DeleteFileW(tmpPath.wstring().c_str());
            errorOut = "MoveFileExW failed: Win32 error " + std::to_string(moveErr);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(m_config.lockProbeBackoffMs * (attempt + 1)));
    }
    DeleteFileW(tmpPath.wstring().c_str());
    errorOut = "MoveFileExW timed out due to NTFS sharing/lock violation.";
    return false;
#else
    const int fd = ::open(tmpPath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        errorOut = "Failed to open temp file: " + tmpPath.string();
        return false;
    }
    size_t totalWritten = 0;
    while (totalWritten < contents.size()) {
        const ssize_t n = ::write(fd, contents.data() + totalWritten, contents.size() - totalWritten);
        if (n <= 0) {
            ::close(fd);
            ::unlink(tmpPath.c_str());
            errorOut = "Failed to write temp file: " + tmpPath.string();
            return false;
        }
        totalWritten += static_cast<size_t>(n);
    }
    ::fsync(fd);
    ::close(fd);

    if (::rename(tmpPath.c_str(), targetPath.c_str()) != 0) {
        ::unlink(tmpPath.c_str());
        errorOut = "Atomic rename failed for: " + targetPath.string();
        return false;
    }
    return true;
#endif
}

bool AtomicHotUpdater::probePathUnlockedWithRetry(
    const fs::path& path,
    std::string& errorOut) const {
#ifdef _WIN32
    for (uint32_t attempt = 0; attempt <= m_config.lockProbeMaxRetries; ++attempt) {
        HANDLE h = CreateFileW(
            path.wstring().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return true;
        }
        const DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) return true;
        if (err != ERROR_SHARING_VIOLATION && err != ERROR_LOCK_VIOLATION && err != ERROR_ACCESS_DENIED) {
            errorOut = "Unexpected Win32 error probing lock: " + std::to_string(err);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(m_config.lockProbeBackoffMs * (attempt + 1)));
    }
    errorOut = "File remains locked after " + std::to_string(m_config.lockProbeMaxRetries) + " retries.";
    return false;
#else
    (void)path;
    (void)errorOut;
    return true;
#endif
}

bool AtomicHotUpdater::moveDirectoryAtomically(
    const fs::path& srcDir,
    const fs::path& dstDir,
    std::string& errorOut) const {
    if (!validatePatchRootIsolation(errorOut)) return false;
    if (!isOverlayDirContainedInReleases(dstDir)) {
        errorOut = "Destination directory is outside releases/.";
        return false;
    }

    std::error_code ec;
    if (fs::exists(dstDir, ec)) {
        if (!isDirectoryTreeUnlocked(dstDir)) {
            errorOut = "Existing release directory has open handles in a running client.";
            return false;
        }
        const fs::path trashDir = stagingRoot() / ("replaced_" + generateStagingNonce());
        fs::rename(dstDir, trashDir, ec);
        if (ec) {
            errorOut = "Existing release directory is locked or busy: " + ec.message();
            return false;
        }
        std::error_code rmEc;
        fs::remove_all(trashDir, rmEc);
    }

    fs::rename(srcDir, dstDir, ec);
    if (ec) {
        errorOut = "Failed to promote staging dir to releases/: " + ec.message();
        return false;
    }
    return true;
}

std::string AtomicHotUpdater::serializeOverlayStateJson(const ActiveOverlayState& state) {
    return gclient::json::JsonObjectBuilder()
        .kv("activeVersion", state.activeVersion)
        .kv("activeOverlayDir", state.activeOverlayDir)
        .kv("previousVersion", state.previousVersion)
        .kv("previousOverlayDir", state.previousOverlayDir)
        .kv("bootState", bootStateToString(state.bootState))
        .kvInt("consecutiveBootFailures", state.consecutiveBootFailures)
        .kvInt("maxBootFailuresBeforeRollback", state.maxBootFailuresBeforeRollback)
        .kvInt("nativeBindingApiVersion", state.nativeBindingApiVersion)
        .kvInt("protoSchemaVersion", state.protoSchemaVersion)
        .kvInt("dbSchemaVersion", state.dbSchemaVersion)
        .kv("activatedUtc", state.activatedUtc)
        .finish() + "\n";
}

bool AtomicHotUpdater::parseOverlayStateJson(const std::string& json, ActiveOverlayState& outState) {
    gclient::json::JsonValue root;
    if (!gclient::json::parse(json, root) || !root.isObject()) return false;
    const auto* activeVer = root.find("activeVersion");
    if (!activeVer || !activeVer->isString()) return false;

    ActiveOverlayState parsed;
    parsed.activeVersion = activeVer->strVal;
    if (const auto* v = root.find("activeOverlayDir"); v && v->isString()) parsed.activeOverlayDir = v->strVal;
    if (const auto* v = root.find("previousVersion"); v && v->isString()) parsed.previousVersion = v->strVal;
    if (const auto* v = root.find("previousOverlayDir"); v && v->isString()) parsed.previousOverlayDir = v->strVal;
    if (const auto* v = root.find("bootState"); v && v->isString()) parsed.bootState = stringToBootState(v->strVal);

    auto readU32 = [&](std::string_view key, uint32_t& dst) {
        if (const auto* v = root.find(key)) {
            const int64_t n = v->asInt64(-1);
            if (n >= 0 && n <= static_cast<int64_t>(UINT32_MAX)) dst = static_cast<uint32_t>(n);
        }
    };
    readU32("consecutiveBootFailures", parsed.consecutiveBootFailures);
    readU32("maxBootFailuresBeforeRollback", parsed.maxBootFailuresBeforeRollback);
    readU32("nativeBindingApiVersion", parsed.nativeBindingApiVersion);
    readU32("protoSchemaVersion", parsed.protoSchemaVersion);
    readU32("dbSchemaVersion", parsed.dbSchemaVersion);
    if (const auto* v = root.find("activatedUtc"); v && v->isString()) parsed.activatedUtc = v->strVal;

    outState = std::move(parsed);
    return true;
}

bool AtomicHotUpdater::computeFileHash(
    const fs::path& filePath,
    HashAlgorithm algo,
    std::string& hexDigestOut,
    std::string& errorOut) {
    std::ifstream ifs(filePath, std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        errorOut = "Cannot open file for hashing: " + fsPathToUtf8(filePath);
        return false;
    }

    char buf[32768];
    if (algo == HashAlgorithm::SHA256) {
        gclient::crypto::Sha256Stream sha;
        while (ifs.good()) {
            ifs.read(buf, sizeof(buf));
            const auto n = ifs.gcount();
            if (n > 0) sha.update(buf, static_cast<size_t>(n));
        }
        if (ifs.bad()) {
            errorOut = "I/O error while hashing file: " + fsPathToUtf8(filePath);
            return false;
        }
        hexDigestOut = gclient::crypto::hexEncode(sha.finish(), false);
    } else {
        gclient::crypto::Md5Stream md5;
        while (ifs.good()) {
            ifs.read(buf, sizeof(buf));
            const auto n = ifs.gcount();
            if (n > 0) md5.update(buf, static_cast<size_t>(n));
        }
        if (ifs.bad()) {
            errorOut = "I/O error while hashing file: " + fsPathToUtf8(filePath);
            return false;
        }
        hexDigestOut = gclient::crypto::hexEncode(md5.finish(), false);
    }
    return true;
}

bool AtomicHotUpdater::isSafeRelativePath(const std::string& relativePath) {
    if (relativePath.empty() || relativePath.find('\0') != std::string::npos ||
        relativePath[0] == '/' || relativePath[0] == '\\' ||
        relativePath.find(':') != std::string::npos) {
        return false;
    }
    if (equalsAsciiCI(relativePath, "active_manifest.json") ||
        equalsAsciiCI(relativePath, "previous_manifest.json") ||
        equalsAsciiCI(relativePath, "update.lock")) {
        return false;
    }

    const fs::path p = utf8ToFsPath(relativePath);
    if (p.is_absolute() || p.has_root_name() || p.has_root_directory() ||
        containsProtectedConvertedDirComponent(p)) {
        return false;
    }

    bool sawAnyPart = false;
    for (const auto& part : p) {
        const std::string seg = fsPathToUtf8(part);
        if (seg.empty() || seg == "." || seg == ".." ||
            seg.back() == '.' || seg.back() == ' ' ||
            isReservedWindowsDeviceStem(seg)) {
            return false;
        }
        sawAnyPart = true;
    }
    return sawAnyPart;
}

bool AtomicHotUpdater::isAxmolCompatibleRelativeAssetPath(const std::string& relativePath) {
    return !endsWithAsciiCI(relativePath, ".pvr.ccz") &&
           !endsWithAsciiCI(relativePath, ".pvr") &&
           !endsWithAsciiCI(relativePath, ".pkm");
}

int AtomicHotUpdater::compareSemver(const std::string& lhs, const std::string& rhs) {
    auto parseParts = [](const std::string& v) {
        std::array<uint32_t, 3> parts = {0, 0, 0};
        size_t idx = 0, start = 0;
        while (idx < 3 && start < v.size()) {
            const size_t dot = v.find('.', start);
            const std::string_view tok = (dot == std::string::npos)
                ? std::string_view(v).substr(start)
                : std::string_view(v).substr(start, dot - start);
            uint32_t num = 0;
            for (unsigned char c : tok) {
                if (!std::isdigit(c)) break;
                num = num * 10u + static_cast<uint32_t>(c - '0');
            }
            parts[idx++] = num;
            if (dot == std::string::npos) break;
            start = dot + 1;
        }
        return parts;
    };
    const auto a = parseParts(lhs);
    const auto b = parseParts(rhs);
    for (size_t i = 0; i < 3; ++i) {
        if (a[i] != b[i]) return (a[i] < b[i]) ? -1 : 1;
    }
    return 0;
}

std::string AtomicHotUpdater::currentUtcIso8601() {
    const std::time_t tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm utcTm{};
#ifdef _WIN32
    gmtime_s(&utcTm, &tt);
#else
    gmtime_r(&tt, &utcTm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utcTm);
    return std::string(buf);
}

std::string AtomicHotUpdater::generateStagingNonce() {
    static thread_local std::mt19937_64 rng(
        static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::ostringstream oss;
    oss << std::hex << std::setw(12) << std::setfill('0') << (rng() & 0xFFFFFFFFFFFFull);
    return oss.str();
}

std::string AtomicHotUpdater::toLowerHex(const uint8_t* data, size_t len) {
    return gclient::crypto::hexEncode(data, len, false);
}

std::string AtomicHotUpdater::toLowerAscii(std::string value) {
    return gclient::common::toLowerAscii(value);
}

bool AtomicHotUpdater::isValidVersionToken(const std::string& version) {
    if (version.empty() || version.size() > 64 || version == "." || version == "..") return false;
    return std::all_of(version.begin(), version.end(), [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '.' || c == '-' || c == '_';
    });
}

} // namespace update
} // namespace gclient
