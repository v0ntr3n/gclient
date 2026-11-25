#include "ui/ZYWebViewWin32.h"
#include "diagnostics/CrashAndTelemetry.h"

#include <algorithm>

#ifdef _WIN32
#include <shellapi.h>
#ifdef GCLIENT_ENABLE_WEBVIEW2
#include <wrl.h>
#include "WebView2.h"
#endif
#endif

namespace gclient::ui {

ZYWebViewWin32* ZYWebViewWin32::getInstance() {
    static ZYWebViewWin32 instance;
    return &instance;
}

ZYWebViewWin32::~ZYWebViewWin32() {
    shutdown();
}

#ifdef _WIN32
void ZYWebViewWin32::setParentWindow(HWND hwnd) {
    m_parentHwnd = (hwnd && ::IsWindow(hwnd)) ? hwnd : nullptr;
}
#endif

void ZYWebViewWin32::displayWebView(int x, int y, int width, int height) {
    m_x = x;
    m_y = y;
    m_width = std::max(0, width);
    m_height = std::max(0, height);

#if defined(_WIN32) && defined(GCLIENT_ENABLE_WEBVIEW2)
    if (m_width <= 0 || m_height <= 0) {
        m_visible = false;
        return;
    }
    m_visible = true;
    if (!m_parentHwnd || !::IsWindow(m_parentHwnd)) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Warn, "ZYWebViewWin32",
            "displayWebView called before valid parent HWND was bound.");
        return;
    }
    if (!m_hostHwnd || !::IsWindow(m_hostHwnd)) {
        m_hostHwnd = ::CreateWindowExW(
            0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
            m_x, m_y, m_width, m_height,
            m_parentHwnd, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    } else {
        ::MoveWindow(m_hostHwnd, m_x, m_y, m_width, m_height, TRUE);
        ::ShowWindow(m_hostHwnd, SW_SHOW);
    }
#else
    m_visible = false;
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info, "ZYWebViewWin32",
        "displayWebView(%d,%d,%d,%d): skipping child HWND creation (GCLIENT_ENABLE_WEBVIEW2 disabled).",
        m_x, m_y, m_width, m_height);
#endif
}

void ZYWebViewWin32::updateURL(const std::string& url) {
    m_currentUrl = url;
    if (url.empty()) return;

#ifdef _WIN32
#ifdef GCLIENT_ENABLE_WEBVIEW2
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info, "ZYWebViewWin32",
        "WebView2 navigating to: %s", url.c_str());
#else
    if (url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0) {
        const int req = ::MultiByteToWideChar(
            CP_UTF8, 0, url.data(), static_cast<int>(url.size()), nullptr, 0);
        if (req > 0) {
            std::wstring wideUrl(static_cast<std::size_t>(req), L'\0');
            ::MultiByteToWideChar(
                CP_UTF8, 0, url.data(), static_cast<int>(url.size()), wideUrl.data(), req);
            HWND owner = (m_parentHwnd && ::IsWindow(m_parentHwnd)) ? m_parentHwnd : nullptr;
            ::ShellExecuteW(owner, L"open", wideUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }
    }
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info, "ZYWebViewWin32",
        "Opened URL in external browser (WebView2 disabled): %s", url.c_str());
#endif
#endif
}

void ZYWebViewWin32::removeWebView() {
    m_visible = false;
#ifdef _WIN32
    if (m_hostHwnd) {
        if (::IsWindow(m_hostHwnd)) {
            ::DestroyWindow(m_hostHwnd);
        }
        m_hostHwnd = nullptr;
    }
#endif
}

void ZYWebViewWin32::onParentResized(int clientWidth, int clientHeight) {
#if defined(_WIN32) && defined(GCLIENT_ENABLE_WEBVIEW2)
    if (clientWidth <= 0 || clientHeight <= 0) {
        return;
    }
    if (m_visible && m_hostHwnd && ::IsWindow(m_hostHwnd)) {
        ::MoveWindow(m_hostHwnd, m_x, m_y, m_width, m_height, TRUE);
    }
#else
    (void)clientWidth;
    (void)clientHeight;
#endif
}

void ZYWebViewWin32::onParentDestroyed() {
    m_visible = false;
#ifdef _WIN32
    // Child HWNDs are automatically destroyed by Win32 when the parent HWND is destroyed.
    m_hostHwnd = nullptr;
    m_parentHwnd = nullptr;
#endif
}

void ZYWebViewWin32::shutdown() {
    removeWebView();
#ifdef _WIN32
    m_parentHwnd = nullptr;
#endif
}

} // namespace gclient::ui
