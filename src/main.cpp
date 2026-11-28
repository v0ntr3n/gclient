// ============================================================================
// Game Client Axmol v2.11.5 Port (x64) — Application Entry Point
// ============================================================================

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <fcntl.h>
#include <stdlib.h>
#else
#include <unistd.h>
extern char** environ;
#endif

#include "AppDelegate.h"
#include "common/KestrelBinaryReader.h"
#include "common/KestrelUtf8.h"
#include "diagnostics/CrashAndTelemetry.h"
#include "ui/Win32DesktopBridge.h"

#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <initializer_list>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace fs = std::filesystem;
using gclient::common::equalsAsciiCI;
using gclient::common::trimAscii;
using gclient::utf8::firstNonEmptyEnv;
using gclient::utf8::fsPathToUtf8;
using gclient::utf8::readEnvBool;
using gclient::utf8::utf8ToFsPath;

bool parsePositiveInt(const std::string& text, int minVal, int maxVal, int& outValue) {
    if (text.empty()) return false;
    char* endPtr = nullptr;
    const long parsed = std::strtol(text.c_str(), &endPtr, 10);
    if (endPtr == text.c_str() || *endPtr != '\0' || parsed < minVal || parsed > maxVal) return false;
    outValue = static_cast<int>(parsed);
    return true;
}

bool parseBoolText(std::string_view raw, bool& outValue) {
    const std::string_view s = trimAscii(raw);
    if (s.empty()) return false;
    if (s == "1" || equalsAsciiCI(s, "true") || equalsAsciiCI(s, "yes") || equalsAsciiCI(s, "on")) {
        outValue = true;
        return true;
    }
    if (s == "0" || equalsAsciiCI(s, "false") || equalsAsciiCI(s, "no") || equalsAsciiCI(s, "off")) {
        outValue = false;
        return true;
    }
    return false;
}

bool hasBootstrapEnvPrefix(std::string_view key) noexcept {
    return key.starts_with("KESTREL_") || key.starts_with("COBALT_") || key.starts_with("GCLIENT_");
}

#ifdef _WIN32
HANDLE g_profileLockHandle = INVALID_HANDLE_VALUE;

void releaseProfileSlotLock() {
    if (g_profileLockHandle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(g_profileLockHandle);
        g_profileLockHandle = INVALID_HANDLE_VALUE;
    }
}

void writeEnvUtf8Single(const char* name, const std::string& value) {
    if (!name || !*name) return;
    const std::wstring wName = gclient::utf8::utf8ToWide(name);
    const std::wstring wVal  = gclient::utf8::utf8ToWide(value);
    if (!wName.empty()) ::SetEnvironmentVariableW(wName.c_str(), wVal.c_str());
}

void collectBootstrapEnvSnapshot(std::map<std::string, std::string>& outEnv) {
    LPWCH block = ::GetEnvironmentStringsW();
    if (!block) return;
    for (LPCWSTR cur = block; *cur != L'\0'; cur += std::wcslen(cur) + 1) {
        if (*cur == L'=') continue;
        const std::string entry = gclient::utf8::wideToUtf8(cur);
        const std::size_t eqPos = entry.find('=');
        if (eqPos == std::string::npos || eqPos == 0) continue;
        const std::string key = entry.substr(0, eqPos);
        if (hasBootstrapEnvPrefix(key)) outEnv[key] = entry.substr(eqPos + 1);
    }
    ::FreeEnvironmentStringsW(block);
}

void enableDpiAwareness() {
    if (HMODULE user32 = ::GetModuleHandleW(L"user32.dll")) {
        using SetDpiCtxFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
        auto setDpiCtx = reinterpret_cast<SetDpiCtxFn>(
            ::GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (setDpiCtx && setDpiCtx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) return;
    }
    ::SetProcessDPIAware();
}

fs::path getExecutableDirectory() {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD len = ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) return fs::current_path();
        if (len < buffer.size()) {
            buffer.resize(len);
            return fs::path(buffer).parent_path();
        }
        buffer.resize(buffer.size() * 2);
    }
}

fs::path getDefaultBaseProfileRoot() {
    PWSTR localAppData = nullptr;
    if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &localAppData)) && localAppData) {
        fs::path root = fs::path(localAppData) / L"GCLIENT_AXMOL";
        ::CoTaskMemFree(localAppData);
        return root;
    }
    if (localAppData) ::CoTaskMemFree(localAppData);
    return getExecutableDirectory() / L"userdata";
}

bool tryLockSlotDirectory(const fs::path& slotDir, HANDLE& outLockHandle) {
    std::error_code ec;
    fs::create_directories(slotDir, ec);
    if (ec) return false;
    HANDLE h = ::CreateFileW(
        (slotDir / L".instance.lock").c_str(),
        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    outLockHandle = h;
    return true;
}
#else
void releaseProfileSlotLock() {}

void writeEnvUtf8Single(const char* name, const std::string& value) {
    if (name && *name) ::setenv(name, value.c_str(), 1);
}

void collectBootstrapEnvSnapshot(std::map<std::string, std::string>& outEnv) {
    if (!environ) return;
    for (char** cur = environ; *cur != nullptr; ++cur) {
        const std::string_view entry(*cur);
        const std::size_t eqPos = entry.find('=');
        if (eqPos == std::string_view::npos || eqPos == 0) continue;
        const std::string_view key = entry.substr(0, eqPos);
        if (hasBootstrapEnvPrefix(key)) outEnv[std::string(key)] = std::string(entry.substr(eqPos + 1));
    }
}

fs::path getExecutableDirectory() {
    std::error_code ec;
    const fs::path exe = fs::read_symlink("/proc/self/exe", ec);
    return (!ec && !exe.empty()) ? exe.parent_path() : fs::current_path();
}

fs::path getDefaultBaseProfileRoot() {
    if (const char* home = std::getenv("HOME"); home && *home) {
        return fs::path(home) / ".local" / "share" / "GCLIENT_AXMOL";
    }
    return getExecutableDirectory() / "userdata";
}
#endif

bool isHeadlessOrNonInteractive(const gclient::AppConfig& cfg) {
    if (cfg.validateAssetsOnly || cfg.headlessServer) return true;
    return readEnvBool({
        "KESTREL_HEADLESS", "KESTREL_HEADLESS_SERVER",
        "COBALT_HEADLESS", "COBALT_HEADLESS_SERVER",
        "GCLIENT_HEADLESS", "GCLIENT_SUPPRESS_MESSAGEBOX",
        "CI", "GITHUB_ACTIONS"
    }, false);
}

std::string normalizeDiscoveredPath(const fs::path& dir) {
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(dir, ec);
    if (ec || canon.empty()) {
        ec.clear();
        canon = fs::absolute(dir, ec);
    }
    return fsPathToUtf8(canon.empty() ? dir : canon);
}

bool hasValidResourcesDir(const fs::path& dir) {
    std::error_code ec;
    return fs::is_regular_file(dir / "scripts" / "main.lua", ec) ||
           fs::is_regular_file(dir / "main.lua", ec) ||
           fs::is_regular_file(dir / "scripts" / "main_server.lua", ec) ||
           fs::is_regular_file(dir / "main_server.lua", ec);
}

bool hasPlatformConfigAssets(const fs::path& dir) {
    std::error_code ec;
    return fs::is_regular_file(dir / "platform" / "config.json", ec) ||
           fs::is_regular_file(dir / "platform" / "game_config.json", ec);
}

template <typename ValidatorFn>
std::string walkParentsForDir(std::span<const fs::path> startRoots,
                              std::span<const char* const> relSubpaths,
                              ValidatorFn&& validator,
                              std::string_view excludeNormalized = {}) {
    std::error_code ec;
    for (const fs::path& startRoot : startRoots) {
        fs::path cur = startRoot;
        for (int depth = 0; depth <= 6 && !cur.empty(); ++depth) {
            for (const char* rel : relSubpaths) {
                const fs::path cand = cur / rel;
                ec.clear();
                if (fs::is_directory(cand, ec) && validator(cand)) {
                    std::string norm = normalizeDiscoveredPath(cand);
                    if (excludeNormalized.empty() || norm != excludeNormalized) {
                        return norm;
                    }
                }
            }
            fs::path parent = cur.parent_path();
            if (parent.empty() || parent == cur) break;
            cur = std::move(parent);
        }
    }
    return {};
}

std::string autoDiscoverResourcesDir(const fs::path& exeDir) {
    if (const std::string envResStr = firstNonEmptyEnv(
            {"KESTREL_RESOURCES_DIR", "COBALT_RESOURCES_DIR", "GCLIENT_RESOURCES_DIR"});
        !envResStr.empty()) {
        std::error_code ec;
        const fs::path envRes = utf8ToFsPath(envResStr);
        if (fs::is_directory(envRes, ec)) return normalizeDiscoveredPath(envRes);
    }

    std::error_code ec;
    for (const char* nearRel : {"Resources_Axmol_Converted", "Resources", "Content"}) {
        const fs::path cand = exeDir / nearRel;
        ec.clear();
        if (fs::is_directory(cand, ec) && hasValidResourcesDir(cand)) {
            return normalizeDiscoveredPath(cand);
        }
    }

    std::vector<fs::path> searchRoots = {exeDir};
    ec.clear();
    if (const fs::path cwd = fs::current_path(ec); !ec && !cwd.empty() && cwd != exeDir) {
        searchRoots.push_back(cwd);
    }
    static constexpr const char* kUpRel[] = {
        "Resources_Axmol_Converted",
        "OMG3Q_Resources/Resources_Axmol_Converted",
        "Resources",
        "OMG3Q_Resources/Resources",
    };
    if (std::string found = walkParentsForDir(searchRoots, kUpRel, hasValidResourcesDir); !found.empty()) {
        return found;
    }
    return fsPathToUtf8(exeDir / "Resources");
}

std::string autoDiscoverBaseAssetsDir(const fs::path& exeDir, const std::string& resourcesDirUtf8) {
    if (const std::string envBaseStr = firstNonEmptyEnv({
            "KESTREL_BASE_ASSETS_DIR", "COBALT_BASE_ASSETS_DIR",
            "GCLIENT_BASE_ASSETS_DIR", "GCLIENT_ASSETS_DIR"});
        !envBaseStr.empty()) {
        std::error_code ec;
        const fs::path envBase = utf8ToFsPath(envBaseStr);
        if (fs::is_directory(envBase, ec)) return normalizeDiscoveredPath(envBase);
    }

    std::vector<fs::path> roots;
    if (!resourcesDirUtf8.empty()) {
        if (const fs::path resParent = utf8ToFsPath(resourcesDirUtf8).parent_path(); !resParent.empty()) {
            roots.push_back(resParent);
        }
    }
    roots.push_back(exeDir);

    static constexpr const char* kAssetRel[] = {"base_assets", "assets", "Resources"};
    return walkParentsForDir(roots, kAssetRel, hasPlatformConfigAssets, resourcesDirUtf8);
}

gclient::AppConfig parseArgs(const std::vector<std::string>& args) {
    gclient::AppConfig cfg;
    const fs::path exeDir = getExecutableDirectory();
    cfg.resourcesDir  = autoDiscoverResourcesDir(exeDir);
    cfg.baseAssetsDir = autoDiscoverBaseAssetsDir(exeDir, cfg.resourcesDir);

    if (const std::string envProfile = firstNonEmptyEnv(
            {"KESTREL_PROFILE_DIR", "COBALT_PROFILE_DIR", "GCLIENT_PROFILE_DIR"});
        !envProfile.empty()) {
        cfg.profileDir = normalizeDiscoveredPath(utf8ToFsPath(envProfile));
    }

    cfg.mapiUrl      = firstNonEmptyEnv({"KESTREL_MAPI_URL", "COBALT_MAPI_URL", "GCLIENT_MAPI_URL"});
    cfg.gameHost     = firstNonEmptyEnv({"KESTREL_GAME_HOST", "COBALT_GAME_HOST", "GCLIENT_GAME_HOST"});
    cfg.pid          = firstNonEmptyEnv({"KESTREL_PID", "COBALT_PID", "GCLIENT_PID"});
    cfg.sessionToken = firstNonEmptyEnv({"KESTREL_TOKEN", "COBALT_TOKEN", "GCLIENT_TOKEN"});
    cfg.entryScript  = firstNonEmptyEnv({"KESTREL_ENTRY_SCRIPT", "COBALT_ENTRY_SCRIPT", "GCLIENT_ENTRY_SCRIPT"});

#ifdef KESTREL_DEFAULT_MAPI_URL
    if (cfg.mapiUrl.empty()) cfg.mapiUrl = KESTREL_DEFAULT_MAPI_URL;
#endif
#ifdef KESTREL_DEFAULT_GAME_HOST
    if (cfg.gameHost.empty()) cfg.gameHost = KESTREL_DEFAULT_GAME_HOST;
#endif
#ifdef KESTREL_DEFAULT_GAME_PORT
    if (cfg.gamePort <= 0) parsePositiveInt(std::to_string(KESTREL_DEFAULT_GAME_PORT), 1, 65535, cfg.gamePort);
#endif

    if (const std::string v = firstNonEmptyEnv({"KESTREL_GAME_PORT", "COBALT_GAME_PORT", "GCLIENT_GAME_PORT"}); !v.empty()) {
        parsePositiveInt(v, 1, 65535, cfg.gamePort);
    }
    if (const std::string v = firstNonEmptyEnv({"KESTREL_WIDTH", "GCLIENT_WIDTH"}); !v.empty()) {
        parsePositiveInt(v, 320, 7680, cfg.windowWidth);
    }
    if (const std::string v = firstNonEmptyEnv({"KESTREL_HEIGHT", "GCLIENT_HEIGHT"}); !v.empty()) {
        parsePositiveInt(v, 240, 4320, cfg.windowHeight);
    }

    cfg.muteAudio          = readEnvBool({"KESTREL_MUTE", "COBALT_MUTE", "GCLIENT_MUTE"}, false);
    cfg.validateAssetsOnly = readEnvBool({"KESTREL_VALIDATE_ASSETS", "GCLIENT_VALIDATE_ASSETS"}, false);
    cfg.skipHotupdate      = readEnvBool({"KESTREL_SKIP_HOTUPDATE", "COBALT_SKIP_HOTUPDATE", "GCLIENT_SKIP_HOTUPDATE"}, false);
    cfg.headlessServer     = readEnvBool({"KESTREL_HEADLESS_SERVER", "COBALT_HEADLESS_SERVER", "GCLIENT_HEADLESS_SERVER"}, false);

    auto takeValue = [&](size_t& idx, const std::string& arg, std::string_view prefix, std::string& out) -> bool {
        if (arg == prefix) {
            if (idx + 1 >= args.size()) return false;
            out = args[++idx];
            return true;
        }
        if (arg.starts_with(prefix) && arg.size() > prefix.size() && arg[prefix.size()] == '=') {
            out = arg.substr(prefix.size() + 1);
            return true;
        }
        return false;
    };

    auto takeBoolFlag = [](const std::string& arg, std::string_view flagName, bool& outBool) -> bool {
        if (arg == flagName) {
            outBool = true;
            return true;
        }
        if (arg.starts_with("--no-") && std::string_view(arg).substr(5) == flagName.substr(2)) {
            outBool = false;
            return true;
        }
        if (arg.starts_with(flagName) && arg.size() > flagName.size() && arg[flagName.size()] == '=') {
            bool parsed = true;
            if (parseBoolText(std::string_view(arg).substr(flagName.size() + 1), parsed)) outBool = parsed;
            return true;
        }
        return false;
    };

    bool explicitBaseAssets = false;
    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& arg = args[i];
        std::string val;
        if (takeValue(i, arg, "--resources-dir", val))        cfg.resourcesDir = normalizeDiscoveredPath(utf8ToFsPath(val));
        else if (takeValue(i, arg, "--base-assets-dir", val)) { cfg.baseAssetsDir = normalizeDiscoveredPath(utf8ToFsPath(val)); explicitBaseAssets = true; }
        else if (takeValue(i, arg, "--profile-dir", val))     cfg.profileDir = normalizeDiscoveredPath(utf8ToFsPath(val));
        else if (takeValue(i, arg, "--mapi-url", val))        cfg.mapiUrl = val;
        else if (takeValue(i, arg, "--game-host", val))       cfg.gameHost = val;
        else if (takeValue(i, arg, "--game-port", val))       parsePositiveInt(val, 1, 65535, cfg.gamePort);
        else if (takeValue(i, arg, "--pid", val))             cfg.pid = val;
        else if (takeValue(i, arg, "--token", val))           cfg.sessionToken = val;
        else if (takeValue(i, arg, "--entry-script", val))    cfg.entryScript = val;
        else if (takeValue(i, arg, "--width", val))           parsePositiveInt(val, 320, 7680, cfg.windowWidth);
        else if (takeValue(i, arg, "--height", val))          parsePositiveInt(val, 240, 4320, cfg.windowHeight);
        else if (takeBoolFlag(arg, "--mute", cfg.muteAudio)) {}
        else if (takeBoolFlag(arg, "--validate-assets", cfg.validateAssetsOnly)) {}
        else if (takeBoolFlag(arg, "--skip-hotupdate", cfg.skipHotupdate)) {}
        else if (takeBoolFlag(arg, "--headless-server", cfg.headlessServer)) {}
    }

    if (!explicitBaseAssets && cfg.baseAssetsDir.empty() && !cfg.resourcesDir.empty()) {
        cfg.baseAssetsDir = autoDiscoverBaseAssetsDir(exeDir, cfg.resourcesDir);
    }

    for (const auto& [envKey, strVal] : std::initializer_list<std::pair<const char*, const std::string*>>{
             {"KESTREL_MAPI_URL", &cfg.mapiUrl},
             {"KESTREL_GAME_HOST", &cfg.gameHost},
             {"KESTREL_PID", &cfg.pid},
             {"KESTREL_TOKEN", &cfg.sessionToken},
             {"KESTREL_ENTRY_SCRIPT", &cfg.entryScript}}) {
        if (!strVal->empty()) writeEnvUtf8Single(envKey, *strVal);
    }
    if (cfg.gamePort > 0) writeEnvUtf8Single("KESTREL_GAME_PORT", std::to_string(cfg.gamePort));
    if (cfg.skipHotupdate) writeEnvUtf8Single("KESTREL_SKIP_HOTUPDATE", "1");
    if (cfg.headlessServer) {
        writeEnvUtf8Single("KESTREL_HEADLESS_SERVER", "1");
        writeEnvUtf8Single("GCLIENT_HEADLESS", "1");
    }

    collectBootstrapEnvSnapshot(cfg.bootstrapEnv);
    return cfg;
}

bool prepareIsolatedStorage(gclient::AppConfig& cfg) {
    const fs::path baseRoot = getDefaultBaseProfileRoot();
    fs::path profileRoot;

    if (!cfg.profileDir.empty()) {
        profileRoot = utf8ToFsPath(cfg.profileDir);
    } else if (const std::string envProfile = firstNonEmptyEnv(
                   {"KESTREL_PROFILE_DIR", "COBALT_PROFILE_DIR", "GCLIENT_PROFILE_DIR"});
               !envProfile.empty()) {
        profileRoot = utf8ToFsPath(envProfile);
    } else {
#ifdef _WIN32
        const DWORD pid = ::GetCurrentProcessId();
        if (cfg.validateAssetsOnly || cfg.headlessServer) {
            profileRoot = baseRoot / L"instances" / (L"pid_" + std::to_wstring(pid));
        } else if (const fs::path primarySlot = baseRoot / L"profiles" / L"default";
                   tryLockSlotDirectory(primarySlot, g_profileLockHandle)) {
            profileRoot = primarySlot;
        } else {
            for (int slot = 2; slot <= 64; ++slot) {
                const fs::path slotDir = baseRoot / L"profiles" / (L"instance_" + std::to_wstring(slot));
                if (tryLockSlotDirectory(slotDir, g_profileLockHandle)) {
                    profileRoot = slotDir;
                    break;
                }
            }
            if (profileRoot.empty()) {
                profileRoot = baseRoot / L"instances" / (L"pid_" + std::to_wstring(pid));
            }
        }
#else
        profileRoot = (cfg.validateAssetsOnly || cfg.headlessServer)
            ? (baseRoot / "instances" / ("pid_" + std::to_string(static_cast<long>(::getpid()))))
            : (baseRoot / "profiles" / "default");
#endif
    }

    const fs::path writableDir = profileRoot / "writable";
    const fs::path hotfixDir   = writableDir / "hotfix";
    const fs::path cacheDir    = writableDir / "cache";
    const fs::path logsDir     = profileRoot / "logs";
    const fs::path dumpsDir    = profileRoot / "dumps";

    std::error_code ec;
    for (const auto& dir : {profileRoot, writableDir, hotfixDir, cacheDir, logsDir, dumpsDir}) {
        fs::create_directories(dir, ec);
        if (ec) return false;
    }

    cfg.profileDir  = normalizeDiscoveredPath(profileRoot);
    cfg.writableDir = normalizeDiscoveredPath(writableDir);
    cfg.hotfixDir   = normalizeDiscoveredPath(hotfixDir);
    cfg.logsDir     = normalizeDiscoveredPath(logsDir);
    cfg.dumpsDir    = normalizeDiscoveredPath(dumpsDir);

#ifdef _WIN32
    ::SetEnvironmentVariableW(L"GCLIENT_PROFILE_DIR", profileRoot.c_str());
    ::SetEnvironmentVariableW(L"GCLIENT_WRITABLE_DIR", writableDir.c_str());
    if (::GetEnvironmentVariableW(L"GCLIENT_SESSION_FILE", nullptr, 0) <= 1) {
        ::SetEnvironmentVariableW(L"GCLIENT_SESSION_FILE", (profileRoot / L"account_session.json").c_str());
    }
    if (::GetEnvironmentVariableW(L"GCLIENT_UUID_FILE", nullptr, 0) <= 1) {
        ::SetEnvironmentVariableW(L"GCLIENT_UUID_FILE", (profileRoot / L"device_uuid.txt").c_str());
    }
#else
    writeEnvUtf8Single("GCLIENT_PROFILE_DIR", cfg.profileDir);
    writeEnvUtf8Single("GCLIENT_WRITABLE_DIR", cfg.writableDir);
#endif
    cfg.bootstrapEnv["GCLIENT_PROFILE_DIR"]  = cfg.profileDir;
    cfg.bootstrapEnv["GCLIENT_WRITABLE_DIR"] = cfg.writableDir;
    return true;
}

int runKestrelClient(gclient::AppConfig config) {
    if (!prepareIsolatedStorage(config)) {
        releaseProfileSlotLock();
        return EXIT_FAILURE;
    }

    gclient::diagnostics::DiagnosticsConfig diagConfig;
    diagConfig.logDirectory  = config.logsDir;
    diagConfig.dumpDirectory = config.dumpsDir;
    diagConfig.appName       = config.headlessServer ? "gclient-headless-server" : "gclient-axmol";
    gclient::diagnostics::CrashAndTelemetry::install(diagConfig);

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "Main",
        "Starting Kestrel Canvas Axmol v2.11.5 x64 (res=%dx%d, mute=%d, validateAssets=%d, headlessServer=%d, skipHotupdate=%d, mapi='%s', host='%s', port=%d, pid='%s', resources='%s', profile='%s')",
        config.windowWidth, config.windowHeight,
        config.muteAudio ? 1 : 0, config.validateAssetsOnly ? 1 : 0,
        config.headlessServer ? 1 : 0, config.skipHotupdate ? 1 : 0,
        config.mapiUrl.c_str(), config.gameHost.c_str(), config.gamePort,
        config.pid.c_str(), config.resourcesDir.c_str(), config.profileDir.c_str());

    gclient::AppDelegate app(config);
    gclient::ui::Win32DesktopBridge::instance().setInitialMuted(config.muteAudio);

    int exitCode = EXIT_FAILURE;
    if (config.validateAssetsOnly) {
        exitCode = app.executeHeadlessAssetValidation() ? EXIT_SUCCESS : EXIT_FAILURE;
    } else if (config.headlessServer) {
        exitCode = app.executeHeadlessServer() ? EXIT_SUCCESS : EXIT_FAILURE;
    } else {
        exitCode = ax::Application::getInstance()->run();
        if (app.lifecycleState() == gclient::AppDelegate::LifecycleState::Failed) {
            exitCode = EXIT_FAILURE;
        }
    }

    app.shutdown();
    gclient::diagnostics::CrashAndTelemetry::shutdown();
    releaseProfileSlotLock();
    return exitCode;
}

} // namespace

#if defined(_WIN32) && !defined(_CONSOLE)
int WINAPI wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    _set_fmode(_O_BINARY);
    enableDpiAwareness();

    std::vector<std::string> args;
    int argc = 0;
    if (LPWSTR* argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc)) {
        args.reserve(static_cast<size_t>(argc));
        for (int i = 0; i < argc; ++i) {
            args.push_back(gclient::utf8::wideToUtf8(argv[i]));
        }
        ::LocalFree(argv);
    }

    gclient::AppConfig cfg = parseArgs(args);
    if (isHeadlessOrNonInteractive(cfg)) {
        ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }
    return runKestrelClient(std::move(cfg));
}
#else
int main(int argc, char** argv) {
    std::vector<std::string> args;
    args.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i] ? argv[i] : "");
    }
    return runKestrelClient(parseArgs(args));
}
#endif
