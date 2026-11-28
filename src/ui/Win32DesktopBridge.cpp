#include "ui/Win32DesktopBridge.h"
#include "ui/ZYWebViewWin32.h"
#include "AppDelegate.h"
#include "common/KestrelUtf8.h"
#include "diagnostics/CrashAndTelemetry.h"
#include "platform/BtPlatformWin32.h"
#include "SimpleAudioEngine.h"

#include <cmath>

#ifdef _WIN32
#include <commdlg.h>
#endif

namespace gclient::ui {

namespace {

#ifdef _WIN32
void syncViewportOnClientResize(cocos2d::CCEGLView* eglView, int clientW, int clientH) {
    if (!eglView || clientW <= 0 || clientH <= 0) return;

    const float rawZoom = eglView->getFrameZoomFactor();
    const float zoom = (std::isfinite(rawZoom) && rawZoom > 0.0f) ? rawZoom : 1.0f;
    const float unzoomedW = static_cast<float>(clientW) / zoom;
    const float unzoomedH = static_cast<float>(clientH) / zoom;
    if (unzoomedW < 1.0f || unzoomedH < 1.0f) return;

    const cocos2d::CCSize prevFrame = eglView->getFrameSize();
    const cocos2d::CCSize prevDesign = eglView->getDesignResolutionSize();
    const ResolutionPolicy prevPolicy = eglView->getResolutionPolicy();

    eglView->ax::RenderView::setFrameSize(unzoomedW, unzoomedH);

    const bool hasValidPrevDesign =
        std::isfinite(prevDesign.width) && std::isfinite(prevDesign.height) &&
        prevDesign.width >= 1.0f && prevDesign.height >= 1.0f &&
        prevPolicy != ResolutionPolicy::UNKNOWN;

    if (hasValidPrevDesign) {
        const bool sameAspect =
            (prevFrame.width > 0.0f && prevFrame.height > 0.0f) &&
            (std::fabs((unzoomedW / unzoomedH) - (prevFrame.width / prevFrame.height)) < 1e-3f);
        eglView->setDesignResolutionSize(
            prevDesign.width, prevDesign.height, sameAspect ? prevPolicy : ResolutionPolicy::SHOW_ALL);
    } else {
        eglView->setDesignResolutionSize(1136.0f, 640.0f, ResolutionPolicy::FIXED_WIDTH);
    }
}

void logMouseRoutingTrace(HWND hwnd, const char* eventName, WPARAM wParam, LPARAM lParam) {
    const int clientX = static_cast<int>(static_cast<short>(LOWORD(lParam)));
    const int clientY = static_cast<int>(static_cast<short>(HIWORD(lParam)));
    RECT rc{};
    ::GetClientRect(hwnd, &rc);

    auto* eglView = dynamic_cast<ax::RenderViewImpl*>(ax::Director::getInstance()->getRenderView());
    if (!eglView) return;

    const float rawZoom = eglView->getFrameZoomFactor();
    const float zoom = (std::isfinite(rawZoom) && rawZoom > 0.0f) ? rawZoom : 1.0f;
    const cocos2d::CCSize frameSz = eglView->getFrameSize();
    const cocos2d::CCSize designSz = eglView->getDesignResolutionSize();
    const cocos2d::CCRect vp = eglView->getViewPortRect();
    const float sx = eglView->getScaleX() != 0.0f ? eglView->getScaleX() : 1.0f;
    const float sy = eglView->getScaleY() != 0.0f ? eglView->getScaleY() : 1.0f;
    const float glX = (static_cast<float>(clientX) / zoom - vp.origin.x) / sx;
    const float glY = designSz.height - (static_cast<float>(clientY) / zoom - vp.origin.y) / sy;

    gclient::diagnostics::CrashAndTelemetry::log(
        gclient::diagnostics::LogLevel::Info,
        "InputRoute",
        "%s wParam=0x%llX client=(%d,%d) clientRect=%ldx%ld frame=%.1fx%.1f zoom=%.2f design=%.1fx%.1f vp=(%.1f,%.1f,%.1f,%.1f) gl=(%.2f,%.2f)",
        eventName, static_cast<unsigned long long>(wParam),
        clientX, clientY, rc.right - rc.left, rc.bottom - rc.top,
        frameSz.width, frameSz.height, zoom, designSz.width, designSz.height,
        vp.origin.x, vp.origin.y, vp.size.width, vp.size.height, glX, glY);
}
#endif

} // namespace

Win32DesktopBridge::Win32DesktopBridge() {
    m_traceInput.store(gclient::utf8::readEnvBool({"GCLIENT_TRACE_INPUT"}, false), std::memory_order_relaxed);
}

Win32DesktopBridge& Win32DesktopBridge::instance() {
    static Win32DesktopBridge s;
    return s;
}

#ifdef _WIN32
void Win32DesktopBridge::attachToWindow(HWND hwnd) {
    if (!hwnd || !::IsWindow(hwnd) || m_hwnd == hwnd) return;
    if (m_hwnd != nullptr) detach();

    m_hwnd = hwnd;
    m_savedPlacement = {};
    m_savedPlacement.length = sizeof(WINDOWPLACEMENT);
    m_savedStyle = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
    m_savedExStyle = ::GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    ZYWebViewWin32::getInstance()->setParentWindow(hwnd);
    m_origProc = reinterpret_cast<WNDPROC>(
        ::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&Win32DesktopBridge::subclassProc)));
}

void Win32DesktopBridge::detach() {
    if (m_hwnd && m_origProc && ::IsWindow(m_hwnd)) {
        const auto curProc = reinterpret_cast<WNDPROC>(::GetWindowLongPtrW(m_hwnd, GWLP_WNDPROC));
        if (curProc == &Win32DesktopBridge::subclassProc) {
            ::SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(m_origProc));
        }
    }
    m_hwnd = nullptr;
    m_origProc = nullptr;
    m_fullscreen = false;
}

LRESULT CALLBACK Win32DesktopBridge::subclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto& self = Win32DesktopBridge::instance();
    WNDPROC orig = self.m_origProc;
    const bool readyForInput =
        !gclient::AppDelegate::hasActiveInstance() || gclient::AppDelegate::isLifecycleReady();
    auto traceMouseIfEnabled = [&](const char* eventName) {
        if (self.isInputTraceEnabled()) logMouseRoutingTrace(hwnd, eventName, wParam, lParam);
    };

    switch (msg) {
        case WM_DESTROY:
        case WM_NCDESTROY: {
            if (auto* wv = ZYWebViewWin32::getInstance()) wv->onParentDestroyed();
            if (msg == WM_NCDESTROY) self.detach();
            break;
        }
        case WM_KEYDOWN: {
            if (!readyForInput) return 0;
            if ((lParam & (1LL << 30)) == 0) {
                if (wParam == VK_ESCAPE) {
                    if (auto* p = bt::Platform::getInstance()) p->onPressBack();
                    return 0;
                }
                if (wParam == VK_F11) {
                    self.toggleFullscreen();
                    return 0;
                }
                if (wParam == 'M' && (::GetKeyState(VK_CONTROL) & 0x8000)) {
                    self.toggleMute();
                    return 0;
                }
            }
            break;
        }
        case WM_KEYUP:
        case WM_CHAR:
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP:
            if (!readyForInput) return 0;
            break;
        case WM_LBUTTONDOWN:
            if (!readyForInput) return 0;
            traceMouseIfEnabled("WM_LBUTTONDOWN");
            wParam = MK_LBUTTON;
            break;
        case WM_MOUSEMOVE:
            if (!readyForInput) return 0;
            if ((wParam & MK_LBUTTON) != 0) {
                traceMouseIfEnabled("WM_MOUSEMOVE");
                wParam = MK_LBUTTON;
            }
            break;
        case WM_LBUTTONUP:
            if (!readyForInput) return 0;
            traceMouseIfEnabled("WM_LBUTTONUP");
            break;
        case WM_SIZE: {
            const int clientW = static_cast<int>(LOWORD(lParam));
            const int clientH = static_cast<int>(HIWORD(lParam));
            if (auto* wv = ZYWebViewWin32::getInstance()) wv->onParentResized(clientW, clientH);
            if (readyForInput && (wParam == SIZE_RESTORED || wParam == SIZE_MAXIMIZED) &&
                clientW > 0 && clientH > 0) {
                if (auto* eglView = dynamic_cast<ax::RenderViewImpl*>(ax::Director::getInstance()->getRenderView())) {
                    syncViewportOnClientResize(eglView, clientW, clientH);
                }
                if (wParam == SIZE_MAXIMIZED && gclient::AppDelegate::hasActiveInstance()) {
                    if (auto* app = ax::Application::getInstance()) app->applicationWillEnterForeground();
                }
            }
            break;
        }
        default:
            break;
    }
    return orig ? ::CallWindowProcW(orig, hwnd, msg, wParam, lParam)
                : ::DefWindowProcW(hwnd, msg, wParam, lParam);
}
#endif

void Win32DesktopBridge::toggleFullscreen() {
#ifdef _WIN32
    if (!m_hwnd || !::IsWindow(m_hwnd)) return;
    if (!m_fullscreen) {
        MONITORINFO mi = { sizeof(mi) };
        m_savedPlacement.length = sizeof(WINDOWPLACEMENT);
        m_savedStyle = ::GetWindowLongPtrW(m_hwnd, GWL_STYLE);
        m_savedExStyle = ::GetWindowLongPtrW(m_hwnd, GWL_EXSTYLE);
        if (::GetWindowPlacement(m_hwnd, &m_savedPlacement) &&
            ::GetMonitorInfoW(::MonitorFromWindow(m_hwnd, MONITOR_DEFAULTTOPRIMARY), &mi)) {
            const LONG_PTR borderlessStyle =
                (m_savedStyle & ~static_cast<LONG_PTR>(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU)) |
                static_cast<LONG_PTR>(WS_POPUP | WS_VISIBLE);
            const LONG_PTR borderlessExStyle =
                m_savedExStyle & ~static_cast<LONG_PTR>(WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE | WS_EX_STATICEDGE);
            ::SetWindowLongPtrW(m_hwnd, GWL_STYLE, borderlessStyle);
            ::SetWindowLongPtrW(m_hwnd, GWL_EXSTYLE, borderlessExStyle);
            ::SetWindowPos(m_hwnd, HWND_TOP,
                mi.rcMonitor.left, mi.rcMonitor.top,
                mi.rcMonitor.right - mi.rcMonitor.left, mi.rcMonitor.bottom - mi.rcMonitor.top,
                SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
            m_fullscreen = true;
        }
    } else {
        ::SetWindowLongPtrW(m_hwnd, GWL_STYLE, m_savedStyle);
        ::SetWindowLongPtrW(m_hwnd, GWL_EXSTYLE, m_savedExStyle);
        ::SetWindowPlacement(m_hwnd, &m_savedPlacement);
        ::SetWindowPos(m_hwnd, nullptr, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
        m_fullscreen = false;
    }
#endif
}

void Win32DesktopBridge::toggleMute() {
    const bool nextMuted = !m_muted.load(std::memory_order_acquire);
    m_muted.store(nextMuted, std::memory_order_release);
    if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
        const float vol = nextMuted ? 0.0f : 1.0f;
        audio->setBackgroundMusicVolume(vol);
        audio->setEffectsVolume(vol);
    }
}

std::string Win32DesktopBridge::pickImageFileDialog() {
#ifdef _WIN32
    wchar_t fileBuf[4096] = {0};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = (m_hwnd && ::IsWindow(m_hwnd)) ? m_hwnd : nullptr;
    ofn.lpstrFilter = L"Images (*.png;*.jpg;*.jpeg)\0*.png;*.jpg;*.jpeg\0All Files\0*.*\0";
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = static_cast<DWORD>(_countof(fileBuf));
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (::GetOpenFileNameW(&ofn)) {
        return gclient::utf8::wideToUtf8(fileBuf);
    }
#endif
    return "";
}

} // namespace gclient::ui
