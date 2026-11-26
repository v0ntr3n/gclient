// ============================================================================
// Game Client Axmol v2.11.5 Port (x64) — Application Entry Point
// Preserves DPI awareness, CLI parsing, lock-based persistent profile slots,
// crash/telemetry installation, headless --validate-assets, and Axmol run loop.
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
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "AppDelegate.h"
#include "diagnostics/CrashAndTelemetry.h"
#include "ui/Win32DesktopBridge.h"

namespace {

namespace fs = std::filesystem;

bool parsePositiveInt(const std::string& text, int minVal, int maxVal, int& outValue) {
    if (text.empty()) return false;
    char* endPtr = nullptr;
    long parsed = std::strtol(text.c_str(), &endPtr, 10);
    if (endPtr == text.c_str() || *endPtr != '\0') return false;
    if (parsed < minVal || parsed > maxVal) return false;
    outValue = static_cast<int>(parsed);
    return true;
}

#ifdef _WIN32
HANDLE g_profileLockHandle = INVALID_HANDLE_VALUE;

void releaseProfileSlotLock() {
    if (g_profileLockHandle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(g_profileLockHandle);
        g_profileLockHandle = INVALID_HANDLE_VALUE;
    }
}

std::string wideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int required = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string utf8(static_cast<std::size_t>(required), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(), required, nullptr, nullptr);
    return utf8;
}

std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    int required = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (required <= 0) {
        required = ::MultiByteToWideChar(
            CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    }
    if (required <= 0) return {};
    std::wstring wide(static_cast<std::size_t>(required), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), required);
    return wide;
}

bool isHeadlessOrNonInteractive(const gclient::AppConfig& cfg) {
    if (cfg.validateAssetsOnly) return true;
    const wchar_t* flags[] = {
        L"GCLIENT_HEADLESS",
        L"GCLIENT_SUPPRESS_MESSAGEBOX",
        L"CI",
        L"GITHUB_ACTIONS"
    };
    for (const wchar_t* name : flags) {
        wchar_t buf[16] = {};
        const DWORD len = ::GetEnvironmentVariableW(name, buf, _countof(buf));
        if (len > 0 && len < _countof(buf)) {
            if (_wcsicmp(buf, L"1") == 0 || _wcsicmp(buf, L"true") == 0 || _wcsicmp(buf, L"yes") == 0) {
                return true;
            }
        }
    }
    return false;
}

void enableDpiAwareness() {
    HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
    if (user32 != nullptr) {
        using SetDpiCtxFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
        auto setDpiCtx = reinterpret_cast<SetDpiCtxFn>(
            ::GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (setDpiCtx != nullptr && setDpiCtx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
            return;
        }
    }
    ::SetProcessDPIAware();
}

fs::path getExecutableDirectory() {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        DWORD len = ::GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) return fs::current_path();
        if (len < buffer.size()) {
            buffer.resize(len);
            break;
        }
        buffer.resize(buffer.size() * 2);
    }
    return fs::path(buffer).parent_path();
}

fs::path getDefaultBaseProfileRoot() {
    PWSTR localAppData = nullptr;
    if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &localAppData)) &&
        localAppData != nullptr) {
        fs::path root = fs::path(localAppData) / L"GCLIENT_AXMOL";
        ::CoTaskMemFree(localAppData);
        return root;
    }
    if (localAppData != nullptr) ::CoTaskMemFree(localAppData);
    return getExecutableDirectory() / L"userdata";
}

fs::path readEnvDir(const wchar_t* wideName, const char* narrowName) {
    const DWORD required = ::GetEnvironmentVariableW(wideName, nullptr, 0);
    if (required > 1) {
        std::wstring buffer(static_cast<std::size_t>(required), L'\0');
        const DWORD copied = ::GetEnvironmentVariableW(wideName, buffer.data(), required);
        if (copied > 0 && copied < required) {
            buffer.resize(copied);
            return fs::path(buffer);
        }
    }
    if (const char* raw = std::getenv(narrowName)) {
        if (raw[0] != '\0') return fs::path(utf8ToWide(raw));
    }
    return {};
}

std::string pathToUtf8(const fs::path& p) { return wideToUtf8(p.wstring()); }
fs::path utf8ToFsPath(const std::string& s) { return fs::path(utf8ToWide(s)); }

bool tryLockSlotDirectory(const fs::path& slotDir, HANDLE& outLockHandle) {
    std::error_code ec;
    fs::create_directories(slotDir, ec);
    if (ec) return false;
    const fs::path lockFile = slotDir / L".instance.lock";
    HANDLE h = ::CreateFileW(
        lockFile.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    outLockHandle = h;
    return true;
}
#else
void releaseProfileSlotLock() {}

fs::path getExecutableDirectory() {
    std::error_code ec;
    fs::path exe = fs::read_symlink("/proc/self/exe", ec);
    if (!ec && !exe.empty()) return exe.parent_path();
    return fs::current_path();
}

fs::path getDefaultBaseProfileRoot() {
    if (const char* home = std::getenv("HOME")) {
        if (*home) return fs::path(home) / ".local" / "share" / "GCLIENT_AXMOL";
    }
    return getExecutableDirectory() / "userdata";
}

fs::path readEnvDir(const wchar_t* /*wideName*/, const char* narrowName) {
    if (const char* raw = std::getenv(narrowName)) {
        if (raw[0] != '\0') return fs::path(raw);
    }
    return {};
}

std::string pathToUtf8(const fs::path& p) { return p.string(); }
fs::path utf8ToFsPath(const std::string& s) { return fs::path(s); }
#endif

std::string normalizeDiscoveredPath(const fs::path& dir) {
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(dir, ec);
    if (ec || canon.empty()) {
        ec.clear();
        canon = fs::absolute(dir, ec);
    }
    return pathToUtf8(canon.empty() ? dir : canon);
}

bool hasValidResourcesDir(const fs::path& dir) {
    std::error_code ec;
    return fs::is_regular_file(dir / "scripts" / "main.lua", ec) ||
           fs::is_regular_file(dir / "main.lua", ec);
}

std::string autoDiscoverResourcesDir(const fs::path& exeDir) {
    const fs::path envRes = readEnvDir(L"GCLIENT_RESOURCES_DIR", "GCLIENT_RESOURCES_DIR");
    std::error_code ec;
    if (!envRes.empty() && fs::is_directory(envRes, ec)) {
        return normalizeDiscoveredPath(envRes);
    }

    const fs::path candidatesNearExe[] = {
        exeDir / "Resources_Axmol_Converted",
        exeDir / "Resources",
        exeDir / "Content",
    };
    for (const auto& cand : candidatesNearExe) {
        ec.clear();
        if (fs::is_directory(cand, ec) && hasValidResourcesDir(cand)) {
            return normalizeDiscoveredPath(cand);
        }
    }

    fs::path cur = exeDir;
    for (int depth = 0; depth <= 6 && !cur.empty(); ++depth) {
        const fs::path upCandidates[] = {
            cur / "Resources_Axmol_Converted",
            cur / "Resources",
            cur / "OMG3Q_Resources" / "Resources_Axmol_Converted",
        };
        for (const auto& cand : upCandidates) {
            ec.clear();
            if (fs::is_directory(cand, ec) && hasValidResourcesDir(cand)) {
                return normalizeDiscoveredPath(cand);
            }
        }
        fs::path parent = cur.parent_path();
        if (parent.empty() || parent == cur) break;
        cur = std::move(parent);
    }

    return pathToUtf8(exeDir / "Resources");
}

gclient::AppConfig parseArgs(const std::vector<std::string>& args) {
    gclient::AppConfig cfg;
    const fs::path exeDir = getExecutableDirectory();
    cfg.resourcesDir = autoDiscoverResourcesDir(exeDir);
    const fs::path envBase = readEnvDir(L"GCLIENT_BASE_ASSETS_DIR", "GCLIENT_BASE_ASSETS_DIR");
    if (!envBase.empty()) {
        cfg.baseAssetsDir = normalizeDiscoveredPath(envBase);
    }

    auto takeValue = [&](size_t& idx, const std::string& arg, const std::string& prefix, std::string& out) -> bool {
        if (arg == prefix) {
            if (idx + 1 < args.size()) {
                out = args[++idx];
                return true;
            }
            return false;
        }
        const std::string eqPrefix = prefix + "=";
        if (arg.rfind(eqPrefix, 0) == 0) {
            out = arg.substr(eqPrefix.size());
            return true;
        }
        return false;
    };

    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& arg = args[i];
        std::string val;
        if (takeValue(i, arg, "--resources-dir", val)) {
            cfg.resourcesDir = normalizeDiscoveredPath(utf8ToFsPath(val));
        } else if (takeValue(i, arg, "--base-assets-dir", val)) {
            cfg.baseAssetsDir = normalizeDiscoveredPath(utf8ToFsPath(val));
        } else if (takeValue(i, arg, "--profile-dir", val)) {
            cfg.profileDir = normalizeDiscoveredPath(utf8ToFsPath(val));
        } else if (takeValue(i, arg, "--width", val)) {
            parsePositiveInt(val, 320, 7680, cfg.windowWidth);
        } else if (takeValue(i, arg, "--height", val)) {
            parsePositiveInt(val, 240, 4320, cfg.windowHeight);
        } else if (arg == "--mute") {
            cfg.muteAudio = true;
        } else if (arg == "--validate-assets") {
            cfg.validateAssetsOnly = true;
        }
    }
    return cfg;
}

bool prepareIsolatedStorage(gclient::AppConfig& cfg) {
    const fs::path baseRoot = getDefaultBaseProfileRoot();
    fs::path profileRoot;

    if (!cfg.profileDir.empty()) {
        profileRoot = utf8ToFsPath(cfg.profileDir);
    } else if (const fs::path envProfile = readEnvDir(L"GCLIENT_PROFILE_DIR", "GCLIENT_PROFILE_DIR");
               !envProfile.empty()) {
        profileRoot = envProfile;
    } else {
#ifdef _WIN32
        const DWORD pid = ::GetCurrentProcessId();
        if (cfg.validateAssetsOnly) {
            profileRoot = baseRoot / L"instances" / (L"pid_" + std::to_wstring(pid));
        } else {
            const fs::path primarySlot = baseRoot / L"profiles" / L"default";
            if (tryLockSlotDirectory(primarySlot, g_profileLockHandle)) {
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
        }
#else
        profileRoot = baseRoot / "profiles" / "default";
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
    const fs::path sessionFile = profileRoot / L"account_session.json";
    const fs::path uuidFile    = profileRoot / L"device_uuid.txt";
    ::SetEnvironmentVariableW(L"GCLIENT_PROFILE_DIR", profileRoot.c_str());
    ::SetEnvironmentVariableW(L"GCLIENT_WRITABLE_DIR", writableDir.c_str());
    if (::GetEnvironmentVariableW(L"GCLIENT_SESSION_FILE", nullptr, 0) <= 1) {
        ::SetEnvironmentVariableW(L"GCLIENT_SESSION_FILE", sessionFile.c_str());
    }
    if (::GetEnvironmentVariableW(L"GCLIENT_UUID_FILE", nullptr, 0) <= 1) {
        ::SetEnvironmentVariableW(L"GCLIENT_UUID_FILE", uuidFile.c_str());
    }
#endif
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
    diagConfig.appName       = "gclient-axmol";
    gclient::diagnostics::CrashAndTelemetry::install(diagConfig);

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "Main",
        "Starting Kestrel Canvas Axmol v2.11.5 x64 (res=%dx%d, mute=%d, validateAssets=%d, resources='%s', profile='%s')",
        config.windowWidth,
        config.windowHeight,
        config.muteAudio ? 1 : 0,
        config.validateAssetsOnly ? 1 : 0,
        config.resourcesDir.c_str(),
        config.profileDir.c_str());

    gclient::AppDelegate app(config);
    gclient::ui::Win32DesktopBridge::instance().setInitialMuted(config.muteAudio);

    if (config.validateAssetsOnly) {
        const bool ok = app.executeHeadlessAssetValidation();
        const int valExit = ok ? EXIT_SUCCESS : EXIT_FAILURE;
        app.shutdown();
        gclient::diagnostics::CrashAndTelemetry::shutdown();
        releaseProfileSlotLock();
        return valExit;
    }

    int exitCode = ax::Application::getInstance()->run();
    if (app.lifecycleState() == gclient::AppDelegate::LifecycleState::Failed) {
        exitCode = EXIT_FAILURE;
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
            args.push_back(wideToUtf8(argv[i]));
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
