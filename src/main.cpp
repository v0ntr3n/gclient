// ============================================================================
// Game Client Win32 Port — Application Entry Point
// Handles DPI awareness, CLI parsing, lock-based persistent profile slots,
// crash/telemetry installation, and Cocos2d-x Win32 message loop bootstrap.
// ============================================================================

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

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "cocos2d.h"
#include "CCEGLView.h"

#include "AppDelegate.h"
#include "diagnostics/CrashAndTelemetry.h"
#include "ui/Win32DesktopBridge.h"

namespace {

namespace fs = std::filesystem;

HANDLE g_profileLockHandle = INVALID_HANDLE_VALUE;

void releaseProfileSlotLock() {
    if (g_profileLockHandle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(g_profileLockHandle);
        g_profileLockHandle = INVALID_HANDLE_VALUE;
    }
}

std::string wideToUtf8(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }
    const int required = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }
    std::string utf8(static_cast<std::size_t>(required), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        utf8.data(), required, nullptr, nullptr);
    return utf8;
}

std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) {
        return {};
    }
    int required = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()),
        nullptr, 0);
    if (required <= 0) {
        required = ::MultiByteToWideChar(
            CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()),
            nullptr, 0);
    }
    if (required <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(required), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()),
        wide.data(), required);
    return wide;
}

bool isHeadlessOrNonInteractive(const gclient::AppConfig& cfg) {
    if (cfg.validateAssetsOnly) {
        return true;
    }
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

HHOOK g_headlessCbtHook = nullptr;
HHOOK g_headlessWndRetHook = nullptr;
HWND  g_lastDismissedDialog = nullptr;

void dismissHeadlessModalDialog(HWND hwnd) noexcept {
    if (hwnd == nullptr) {
        return;
    }
    wchar_t className[32] = {};
    if (::GetClassNameW(hwnd, className, _countof(className)) <= 0 ||
        std::wcscmp(className, L"#32770") != 0) {
        return;
    }
    if (g_lastDismissedDialog != hwnd) {
        g_lastDismissedDialog = hwnd;
        wchar_t titleBuf[256] = {};
        ::GetWindowTextW(hwnd, titleBuf, _countof(titleBuf));
        std::fwprintf(stderr, L"[GCLIENT][HeadlessDialogSuppressed] Auto-dismissed modal dialog '%ls'\n", titleBuf);
        std::fflush(stderr);
    }
    ::PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), 0);
    ::PostMessageW(hwnd, WM_CLOSE, 0, 0);
}

LRESULT CALLBACK headlessDialogSuppressorCbtProc(int nCode, WPARAM wParam, LPARAM lParam) noexcept {
    if (nCode == HCBT_ACTIVATE) {
        dismissHeadlessModalDialog(reinterpret_cast<HWND>(wParam));
    }
    return ::CallNextHookEx(g_headlessCbtHook, nCode, wParam, lParam);
}

LRESULT CALLBACK headlessDialogSuppressorWndRetProc(int nCode, WPARAM wParam, LPARAM lParam) noexcept {
    if (nCode >= 0 && lParam != 0) {
        const auto* cwp = reinterpret_cast<const CWPRETSTRUCT*>(lParam);
        if (cwp->message == WM_INITDIALOG) {
            dismissHeadlessModalDialog(cwp->hwnd);
        }
    }
    return ::CallNextHookEx(g_headlessWndRetHook, nCode, wParam, lParam);
}

class ScopedHeadlessDialogSuppressor {
public:
    explicit ScopedHeadlessDialogSuppressor(bool enabled) noexcept {
        if (enabled) {
            ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
            const DWORD tid = ::GetCurrentThreadId();
            g_headlessCbtHook = ::SetWindowsHookExW(
                WH_CBT, &headlessDialogSuppressorCbtProc, nullptr, tid);
            g_headlessWndRetHook = ::SetWindowsHookExW(
                WH_CALLWNDPROCRET, &headlessDialogSuppressorWndRetProc, nullptr, tid);
        }
    }
    ~ScopedHeadlessDialogSuppressor() noexcept {
        if (g_headlessWndRetHook != nullptr) {
            ::UnhookWindowsHookEx(g_headlessWndRetHook);
            g_headlessWndRetHook = nullptr;
        }
        if (g_headlessCbtHook != nullptr) {
            ::UnhookWindowsHookEx(g_headlessCbtHook);
            g_headlessCbtHook = nullptr;
        }
    }
    ScopedHeadlessDialogSuppressor(const ScopedHeadlessDialogSuppressor&) = delete;
    ScopedHeadlessDialogSuppressor& operator=(const ScopedHeadlessDialogSuppressor&) = delete;
};

void reportFatalStartupMessage(const gclient::AppConfig& cfg, const wchar_t* message) {
    ::OutputDebugStringW(message);
    ::OutputDebugStringW(L"\n");
    if (!isHeadlessOrNonInteractive(cfg)) {
        ::MessageBoxW(nullptr, message, L"Game Client Startup Error", MB_OK | MB_ICONERROR);
    } else {
        std::fwprintf(stderr, L"[GCLIENT][FATAL] %ls\n", message);
    }
}

void enableDpiAwareness() {
    HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
    if (user32 != nullptr) {
        using SetDpiCtxFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
        auto setDpiCtx = reinterpret_cast<SetDpiCtxFn>(
            ::GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (setDpiCtx != nullptr &&
            setDpiCtx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
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
        if (len == 0) {
            return fs::current_path();
        }
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
        fs::path root = fs::path(localAppData) / L"GCLIENT";
        ::CoTaskMemFree(localAppData);
        return root;
    }
    if (localAppData != nullptr) {
        ::CoTaskMemFree(localAppData);
    }
    return getExecutableDirectory() / L"userdata";
}

bool parsePositiveInt(const std::string& text, int minVal, int maxVal, int& outValue) {
    if (text.empty()) {
        return false;
    }
    char* endPtr = nullptr;
    long parsed = std::strtol(text.c_str(), &endPtr, 10);
    if (endPtr == text.c_str() || *endPtr != '\0') {
        return false;
    }
    if (parsed < minVal || parsed > maxVal) {
        return false;
    }
    outValue = static_cast<int>(parsed);
    return true;
}

fs::path readEnvDir(const wchar_t* wideName, const char* narrowName) {
#ifdef _WIN32
    const DWORD required = ::GetEnvironmentVariableW(wideName, nullptr, 0);
    if (required > 1) {
        std::wstring buffer(static_cast<std::size_t>(required), L'\0');
        const DWORD copied = ::GetEnvironmentVariableW(wideName, buffer.data(), required);
        if (copied > 0 && copied < required) {
            buffer.resize(copied);
            return fs::path(buffer);
        }
    }
#else
    (void)wideName;
#endif
    if (const char* raw = std::getenv(narrowName)) {
        if (raw[0] != '\0') {
            return fs::path(utf8ToWide(raw));
        }
    }
    return {};
}

bool hasNonEmptyEnvVarW(const wchar_t* wideName) {
    return ::GetEnvironmentVariableW(wideName, nullptr, 0) > 1;
}

std::string normalizeDiscoveredPath(const fs::path& dir) {
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(dir, ec);
    if (ec || canon.empty()) {
        ec.clear();
        canon = fs::absolute(dir, ec);
    }
    return wideToUtf8((canon.empty() ? dir : canon).wstring());
}

bool hasPlatformConfigAssets(const fs::path& dir) {
    std::error_code ec;
    if (dir.empty() || !fs::is_directory(dir, ec)) {
        return false;
    }
    return fs::is_regular_file(dir / L"platform" / L"config.json", ec) ||
           fs::is_regular_file(dir / L"platform" / L"game_config.json", ec);
}

bool hasValidGameAssets(const fs::path& dir) {
    std::error_code ec;
    if (dir.empty() || !fs::is_directory(dir, ec)) {
        return false;
    }
    return hasPlatformConfigAssets(dir) ||
           fs::is_regular_file(dir / L"scripts" / L"main.lua", ec);
}

bool hasValidResourcesDir(const fs::path& dir) {
    std::error_code ec;
    if (dir.empty() || !fs::is_directory(dir, ec)) {
        return false;
    }
    return fs::is_regular_file(dir / L"scripts" / L"main.lua", ec) ||
           fs::is_directory(dir / L"database", ec);
}

std::vector<fs::path> collectSearchRoots(const fs::path& exeDir) {
    std::vector<fs::path> roots;
    if (!exeDir.empty()) {
        roots.push_back(exeDir);
    }
    std::error_code ec;
    const fs::path cwd = fs::current_path(ec);
    if (!ec && !cwd.empty() && (roots.empty() || cwd != roots.front())) {
        roots.push_back(cwd);
    }
    return roots;
}

std::string autoDiscoverBaseAssetsDir(const fs::path& exeDir) {
    const std::pair<const wchar_t*, const char*> envVars[] = {
        { L"GCLIENT_BASE_ASSETS_DIR", "GCLIENT_BASE_ASSETS_DIR" },
        { L"GCLIENT_ASSETS_DIR",      "GCLIENT_ASSETS_DIR" },
    };
    for (const auto& [wideName, narrowName] : envVars) {
        const fs::path envDir = readEnvDir(wideName, narrowName);
        if (!envDir.empty() && hasValidGameAssets(envDir)) {
            return normalizeDiscoveredPath(envDir);
        }
    }

    const std::vector<fs::path> roots = collectSearchRoots(exeDir);

    for (const fs::path& root : roots) {
        fs::path cur = root;
        for (int depth = 0; depth <= 7 && !cur.empty(); ++depth) {
            const fs::path candidates[] = {
                cur / L"base_assets",
                cur / L"assets",
                cur / L"win64-client" / L"assets",
                cur / L"GClient" / L"win64-client" / L"assets",
            };
            for (const auto& cand : candidates) {
                if (hasPlatformConfigAssets(cand)) {
                    return normalizeDiscoveredPath(cand);
                }
            }
            fs::path parent = cur.parent_path();
            if (parent.empty() || parent == cur) {
                break;
            }
            cur = std::move(parent);
        }
    }

    for (const fs::path& root : roots) {
        fs::path cur = root;
        for (int depth = 0; depth <= 7 && !cur.empty(); ++depth) {
            const fs::path mergedRes = cur / L"Resources";
            if (hasPlatformConfigAssets(mergedRes)) {
                return normalizeDiscoveredPath(mergedRes);
            }
            fs::path parent = cur.parent_path();
            if (parent.empty() || parent == cur) {
                break;
            }
            cur = std::move(parent);
        }
    }

    for (const fs::path& root : roots) {
        fs::path cur = root;
        for (int depth = 0; depth <= 7 && !cur.empty(); ++depth) {
            const fs::path candidates[] = {
                cur / L"base_assets",
                cur / L"assets",
                cur / L"win64-client" / L"assets",
                cur / L"GClient" / L"win64-client" / L"assets",
            };
            for (const auto& cand : candidates) {
                if (hasValidGameAssets(cand)) {
                    return normalizeDiscoveredPath(cand);
                }
            }
            fs::path parent = cur.parent_path();
            if (parent.empty() || parent == cur) {
                break;
            }
            cur = std::move(parent);
        }
    }

    return {};
}

std::string autoDiscoverResourcesDir(const fs::path& exeDir) {
    const fs::path envRes = readEnvDir(L"GCLIENT_RESOURCES_DIR", "GCLIENT_RESOURCES_DIR");
    std::error_code ec;
    if (!envRes.empty() && fs::is_directory(envRes, ec)) {
        return normalizeDiscoveredPath(envRes);
    }

    const fs::path defaultRes = exeDir / L"Resources";
    ec.clear();
    if (!exeDir.empty() && fs::is_directory(defaultRes, ec)) {
        return normalizeDiscoveredPath(defaultRes);
    }

    const std::vector<fs::path> roots = collectSearchRoots(exeDir);
    for (const fs::path& root : roots) {
        fs::path cur = root;
        for (int depth = 0; depth <= 7 && !cur.empty(); ++depth) {
            const fs::path candidates[] = {
                cur / L"Resources",
                cur / L"win64-client" / L"Resources",
                cur / L"GClient" / L"win64-client" / L"Resources",
            };
            for (const auto& cand : candidates) {
                if (hasValidResourcesDir(cand)) {
                    return normalizeDiscoveredPath(cand);
                }
            }
            fs::path parent = cur.parent_path();
            if (parent.empty() || parent == cur) {
                break;
            }
            cur = std::move(parent);
        }
    }

    return wideToUtf8(defaultRes.wstring());
}

gclient::AppConfig parseCommandLine() {
    gclient::AppConfig cfg;
    const fs::path exeDir = getExecutableDirectory();
    cfg.resourcesDir = autoDiscoverResourcesDir(exeDir);
    cfg.baseAssetsDir = autoDiscoverBaseAssetsDir(exeDir);

    int argc = 0;
    LPWSTR* argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    if (argv == nullptr) {
        return cfg;
    }

    bool explicitResourcesDir = false;
    bool explicitBaseAssetsDir = false;

    auto takeValue = [&](int& idx, const std::string& arg, const std::string& prefix, std::string& out) -> bool {
        if (arg == prefix) {
            if (idx + 1 < argc) {
                out = wideToUtf8(argv[++idx]);
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

    for (int i = 1; i < argc; ++i) {
        const std::string arg = wideToUtf8(argv[i]);
        std::string val;

        if (takeValue(i, arg, "--resources-dir", val)) {
            cfg.resourcesDir = normalizeDiscoveredPath(fs::path(utf8ToWide(val)));
            explicitResourcesDir = true;
        } else if (takeValue(i, arg, "--base-assets-dir", val)) {
            cfg.baseAssetsDir = normalizeDiscoveredPath(fs::path(utf8ToWide(val)));
            explicitBaseAssetsDir = true;
        } else if (takeValue(i, arg, "--profile-dir", val)) {
            cfg.profileDir = normalizeDiscoveredPath(fs::path(utf8ToWide(val)));
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

    ::LocalFree(argv);

    if (!explicitBaseAssetsDir && cfg.baseAssetsDir.empty() && !cfg.resourcesDir.empty()) {
        const fs::path resParent = fs::path(utf8ToWide(cfg.resourcesDir)).parent_path();
        if (!resParent.empty()) {
            cfg.baseAssetsDir = autoDiscoverBaseAssetsDir(resParent);
        }
    }
    if (!explicitResourcesDir && !cfg.baseAssetsDir.empty()) {
        std::error_code ec;
        if (!fs::is_directory(fs::path(utf8ToWide(cfg.resourcesDir)), ec)) {
            const fs::path baseParent = fs::path(utf8ToWide(cfg.baseAssetsDir)).parent_path();
            if (!baseParent.empty()) {
                cfg.resourcesDir = autoDiscoverResourcesDir(baseParent);
            }
        }
    }

    return cfg;
}

bool isValidSavedSessionJson(const fs::path& candidate) {
    std::error_code ec;
    if (!fs::is_regular_file(candidate, ec)) {
        return false;
    }
    std::ifstream ifs(candidate, std::ios::binary);
    if (!ifs.is_open()) {
        return false;
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    const std::string json = oss.str();
    if (json.find("\"pid\"") == std::string::npos ||
        json.find("\"token\"") == std::string::npos) {
        return false;
    }
    if (json.find("win32_guest_token") != std::string::npos ||
        json.find("local_stub_session_token") != std::string::npos) {
        return false;
    }
    return true;
}

void migrateLegacyPidInstanceSessionIfNeeded(const fs::path& baseRoot, const fs::path& destSessionFile) {
    std::error_code ec;
    if (fs::is_regular_file(destSessionFile, ec)) {
        return;
    }
    const fs::path instancesDir = baseRoot / L"instances";
    if (!fs::is_directory(instancesDir, ec)) {
        return;
    }

    fs::path newestPath;
    fs::file_time_type newestTime{};
    bool found = false;

    for (const auto& entry : fs::directory_iterator(instancesDir, ec)) {
        if (!entry.is_directory(ec)) {
            continue;
        }
        const fs::path candidates[] = {
            entry.path() / L"writable" / L"account_session.json",
            entry.path() / L"account_session.json",
        };
        for (const auto& cand : candidates) {
            if (!isValidSavedSessionJson(cand)) {
                continue;
            }
            const auto mtime = fs::last_write_time(cand, ec);
            if (!ec && (!found || mtime > newestTime)) {
                newestTime = mtime;
                newestPath = cand;
                found = true;
            }
        }
    }

    if (found && !newestPath.empty()) {
        if (destSessionFile.has_parent_path()) {
            fs::create_directories(destSessionFile.parent_path(), ec);
        }
        fs::copy_file(newestPath, destSessionFile, fs::copy_options::overwrite_existing, ec);
    }
}

bool tryLockSlotDirectory(const fs::path& slotDir, HANDLE& outLockHandle) {
    std::error_code ec;
    fs::create_directories(slotDir, ec);
    if (ec) {
        return false;
    }
    const fs::path lockFile = slotDir / L".instance.lock";
    HANDLE h = ::CreateFileW(
        lockFile.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }
    outLockHandle = h;
    return true;
}

bool prepareIsolatedStorage(gclient::AppConfig& cfg) {
    const DWORD pid = ::GetCurrentProcessId();
    const fs::path baseRoot = getDefaultBaseProfileRoot();

    fs::path profileRoot;
    fs::path sessionFile;
    fs::path uuidFile;

    if (!cfg.profileDir.empty()) {
        profileRoot = fs::path(utf8ToWide(cfg.profileDir));
        sessionFile = profileRoot / L"account_session.json";
        uuidFile    = profileRoot / L"device_uuid.txt";
    } else if (const fs::path envProfile = readEnvDir(L"GCLIENT_PROFILE_DIR", "GCLIENT_PROFILE_DIR");
               !envProfile.empty()) {
        profileRoot = envProfile;
        sessionFile = profileRoot / L"account_session.json";
        uuidFile    = profileRoot / L"device_uuid.txt";
    } else if (cfg.validateAssetsOnly) {
        profileRoot = baseRoot / L"instances" / (L"pid_" + std::to_wstring(pid));
        sessionFile = baseRoot / L"account_session.json";
        uuidFile    = baseRoot / L"device_uuid.txt";
    } else {
        const fs::path primarySlot = baseRoot / L"profiles" / L"default";
        if (tryLockSlotDirectory(primarySlot, g_profileLockHandle)) {
            profileRoot = primarySlot;
            sessionFile = baseRoot / L"account_session.json";
            uuidFile    = baseRoot / L"device_uuid.txt";
            migrateLegacyPidInstanceSessionIfNeeded(baseRoot, sessionFile);
        } else {
            bool acquiredSecondary = false;
            for (int slot = 2; slot <= 64; ++slot) {
                const fs::path slotDir = baseRoot / L"profiles" / (L"instance_" + std::to_wstring(slot));
                if (tryLockSlotDirectory(slotDir, g_profileLockHandle)) {
                    profileRoot = slotDir;
                    sessionFile = slotDir / L"account_session.json";
                    uuidFile    = slotDir / L"device_uuid.txt";
                    acquiredSecondary = true;
                    break;
                }
            }
            if (!acquiredSecondary) {
                profileRoot = baseRoot / L"instances" / (L"pid_" + std::to_wstring(pid));
                sessionFile = profileRoot / L"account_session.json";
                uuidFile    = profileRoot / L"device_uuid.txt";
            }
        }
    }

    std::error_code ec;
    profileRoot = fs::weakly_canonical(profileRoot, ec);
    if (ec) {
        ec.clear();
        profileRoot = fs::absolute(profileRoot, ec);
    }
    sessionFile = fs::weakly_canonical(sessionFile, ec);
    if (ec) {
        ec.clear();
        sessionFile = fs::absolute(sessionFile, ec);
    }
    uuidFile = fs::weakly_canonical(uuidFile, ec);
    if (ec) {
        ec.clear();
        uuidFile = fs::absolute(uuidFile, ec);
    }

    const fs::path writableDir = profileRoot / L"writable";
    const fs::path hotfixDir   = writableDir / L"hotfix";
    const fs::path cacheDir    = writableDir / L"cache";
    const fs::path logsDir     = profileRoot / L"logs";
    const fs::path dumpsDir    = profileRoot / L"dumps";

    const fs::path dirs[] = { profileRoot, writableDir, hotfixDir, cacheDir, logsDir, dumpsDir };
    for (const auto& dir : dirs) {
        fs::create_directories(dir, ec);
        if (ec) {
            return false;
        }
    }

    cfg.profileDir  = wideToUtf8(profileRoot.wstring());
    cfg.writableDir = wideToUtf8(writableDir.wstring());
    cfg.hotfixDir   = wideToUtf8(hotfixDir.wstring());
    cfg.logsDir     = wideToUtf8(logsDir.wstring());
    cfg.dumpsDir    = wideToUtf8(dumpsDir.wstring());

    ::SetEnvironmentVariableW(L"GCLIENT_PROFILE_DIR", profileRoot.c_str());
    ::SetEnvironmentVariableW(L"GCLIENT_WRITABLE_DIR", writableDir.c_str());
    if (!sessionFile.empty() && !hasNonEmptyEnvVarW(L"GCLIENT_SESSION_FILE")) {
        ::SetEnvironmentVariableW(L"GCLIENT_SESSION_FILE", sessionFile.c_str());
    }
    if (!uuidFile.empty() && !hasNonEmptyEnvVarW(L"GCLIENT_UUID_FILE")) {
        ::SetEnvironmentVariableW(L"GCLIENT_UUID_FILE", uuidFile.c_str());
    }

    return true;
}

} // namespace

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

    // Ensure CRT file I/O defaults to binary mode (prevents 0x1A / CRLF corruption in Lua io.open).
    _set_fmode(_O_BINARY);

    // 1. Enable DPI awareness prior to any window or OpenGL surface creation.
    enableDpiAwareness();

    // 2. Parse CLI flags (--resources-dir, --base-assets-dir, --profile-dir, --width, --height, --mute, --validate-assets).
    gclient::AppConfig config = parseCommandLine();

    // 3. Provision lock-isolated persistent profile & writable storage directories.
    if (!prepareIsolatedStorage(config)) {
        releaseProfileSlotLock();
        reportFatalStartupMessage(
            config,
            L"Failed to create isolated profile/writable directories for Game Client.");
        return EXIT_FAILURE;
    }

    // 4. Install Win32 unhandled exception minidump writer and PID-isolated rotating logger.
    gclient::diagnostics::DiagnosticsConfig diagConfig;
    diagConfig.logDirectory = config.logsDir;
    diagConfig.dumpDirectory = config.dumpsDir;
    diagConfig.appName = "gclient";
    gclient::diagnostics::CrashAndTelemetry::install(diagConfig);

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "Main",
        "Starting Game Client Win32 (PID=%lu, res=%dx%d, mute=%d, validateAssets=%d, resources='%s', baseAssets='%s', profile='%s')",
        static_cast<unsigned long>(::GetCurrentProcessId()),
        config.windowWidth,
        config.windowHeight,
        config.muteAudio ? 1 : 0,
        config.validateAssetsOnly ? 1 : 0,
        config.resourcesDir.c_str(),
        config.baseAssetsDir.c_str(),
        config.profileDir.c_str());

    // Suppress any third-party modal MessageBox (such as Cocos2d-x's OpenGL < 1.5 dialog on headless VMs)
    // whenever running in headless / non-interactive CI mode.
    ScopedHeadlessDialogSuppressor headlessDialogGuard(isHeadlessOrNonInteractive(config));

    // 5. Instantiate AppDelegate BEFORE CCEGLView::setFrameSize so WM_SIZE during window creation
    // finds a valid CCApplication::sharedApplication() instance guarded by LifecycleState::Uninitialized.
    gclient::AppDelegate app(config);
    gclient::ui::Win32DesktopBridge::instance().setInitialMuted(config.muteAudio);

    // 5b. Execute --validate-assets headlessly without requiring a GPU / OpenGL 2.0 WGL context.
    if (config.validateAssetsOnly) {
        const bool ok = app.executeHeadlessAssetValidation();
        const int valExit = ok ? EXIT_SUCCESS : EXIT_FAILURE;
        app.shutdown();
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Info,
            "Main",
            "Headless --validate-assets completed with exit code %d",
            valExit);
        gclient::diagnostics::CrashAndTelemetry::shutdown();
        releaseProfileSlotLock();
        return valExit;
    }

    // 6. Create Cocos2d-x Win32 EGL view, verify WGL/HWND readiness, attach Win32DesktopBridge, and run.
    cocos2d::CCEGLView* eglView = cocos2d::CCEGLView::sharedOpenGLView();
    if (eglView == nullptr || eglView->getHWnd() == nullptr || !eglView->isOpenGLReady()) {
        gclient::diagnostics::CrashAndTelemetry::log(
            gclient::diagnostics::LogLevel::Fatal,
            "Main",
            "Failed to create Win32 OpenGL 2.0 view (eglView=%p, hwnd=%p, glReady=%d)",
            static_cast<void*>(eglView),
            eglView ? static_cast<void*>(eglView->getHWnd()) : nullptr,
            (eglView && eglView->isOpenGLReady()) ? 1 : 0);
        app.shutdown();
        gclient::diagnostics::CrashAndTelemetry::shutdown();
        releaseProfileSlotLock();
        reportFatalStartupMessage(
            config,
            L"Failed to initialize Win32 OpenGL context. Ensure a supported display adapter/driver is active.");
        return EXIT_FAILURE;
    }

    eglView->setViewName("Game Client");
    eglView->setFrameSize(
        static_cast<float>(config.windowWidth),
        static_cast<float>(config.windowHeight));
#ifdef _WIN32
    gclient::ui::Win32DesktopBridge::instance().attachToWindow(eglView->getHWnd());
#endif

    int exitCode = cocos2d::CCApplication::sharedApplication()->run();

    if (config.validateAssetsOnly) {
        exitCode = app.assetValidationSucceeded() ? EXIT_SUCCESS : EXIT_FAILURE;
    } else if (app.lifecycleState() == gclient::AppDelegate::LifecycleState::Failed) {
        exitCode = EXIT_FAILURE;
    }

    // 7. Run ordered AppDelegate subsystem teardown BEFORE shutting down telemetry or releasing slot lock!
    app.shutdown();

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "Main",
        "Game Client shutting down with exit code %d",
        exitCode);
    gclient::diagnostics::CrashAndTelemetry::shutdown();
    releaseProfileSlotLock();

    return exitCode;
}
