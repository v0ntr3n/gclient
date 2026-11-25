#include "ui/Win32DesktopBridge.h"
#include "ui/ZYWebViewWin32.h"
#include "AppDelegate.h"
#include "platform/BtPlatformWin32.h"
#include "SimpleAudioEngine.h"

#ifdef _WIN32
#include <commdlg.h>
#endif

namespace gclient::ui {

Win32DesktopBridge& Win32DesktopBridge::instance() {
    static Win32DesktopBridge s;
    return s;
}

#ifdef _WIN32
void Win32DesktopBridge::attachToWindow(HWND hwnd) {
    if (!hwnd || !::IsWindow(hwnd) || m_hwnd == hwnd) return;
    if (m_hwnd != nullptr) {
        detach();
    }
    m_hwnd = hwnd;
    m_savedPlacement.length = sizeof(WINDOWPLACEMENT);
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
}

LRESULT CALLBACK Win32DesktopBridge::subclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto& self = Win32DesktopBridge::instance();
    WNDPROC orig = self.m_origProc;

    switch (msg) {
        case WM_DESTROY:
        case WM_NCDESTROY: {
            if (auto* wv = ZYWebViewWin32::getInstance()) {
                wv->onParentDestroyed();
            }
            if (msg == WM_NCDESTROY) {
                self.detach();
            }
            break;
        }
        case WM_KEYDOWN: {
            // Ignore premature/teardown input and Win32 key auto-repeat (bit 30).
            if (!gclient::AppDelegate::isLifecycleReady()) {
                return 0;
            }
            const bool isAutoRepeat = (lParam & (1LL << 30)) != 0;
            if (!isAutoRepeat) {
                if (wParam == VK_ESCAPE) {
                    if (auto* p = bt::Platform::getInstance()) {
                        p->onPressBack();
                    }
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
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_MOUSEMOVE:
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP: {
            if (!gclient::AppDelegate::isLifecycleReady()) {
                return 0;
            }
            break;
        }
        case WM_SIZE: {
            const int clientW = static_cast<int>(LOWORD(lParam));
            const int clientH = static_cast<int>(HIWORD(lParam));
            if (auto* wv = ZYWebViewWin32::getInstance()) {
                wv->onParentResized(clientW, clientH);
            }
            if (gclient::AppDelegate::isLifecycleReady() &&
                (wParam == SIZE_RESTORED || wParam == SIZE_MAXIMIZED) &&
                clientW > 0 && clientH > 0) {
                if (auto* eglView = cocos2d::CCEGLView::sharedOpenGLView()) {
                    eglView->cocos2d::CCEGLViewProtocol::setFrameSize(
                        static_cast<float>(clientW), static_cast<float>(clientH));
                    eglView->setDesignResolutionSize(1136.0f, 640.0f, kResolutionFixedWidth);
                }
                if (wParam == SIZE_MAXIMIZED) {
                    if (auto* app = cocos2d::CCApplication::sharedApplication()) {
                        app->applicationWillEnterForeground();
                    }
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
    LONG_PTR style = ::GetWindowLongPtrW(m_hwnd, GWL_STYLE);
    if (!m_fullscreen) {
        MONITORINFO mi = { sizeof(mi) };
        if (::GetWindowPlacement(m_hwnd, &m_savedPlacement) &&
            ::GetMonitorInfoW(::MonitorFromWindow(m_hwnd, MONITOR_DEFAULTTOPRIMARY), &mi)) {
            ::SetWindowLongPtrW(m_hwnd, GWL_STYLE, style & ~static_cast<LONG_PTR>(WS_OVERLAPPEDWINDOW));
            ::SetWindowPos(m_hwnd, HWND_TOP,
                mi.rcMonitor.left, mi.rcMonitor.top,
                mi.rcMonitor.right - mi.rcMonitor.left,
                mi.rcMonitor.bottom - mi.rcMonitor.top,
                SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
            m_fullscreen = true;
        }
    } else {
        ::SetWindowLongPtrW(m_hwnd, GWL_STYLE, style | static_cast<LONG_PTR>(WS_OVERLAPPEDWINDOW));
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
        audio->setBackgroundMusicVolume(nextMuted ? 0.0f : 1.0f);
        audio->setEffectsVolume(nextMuted ? 0.0f : 1.0f);
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
        const int req = ::WideCharToMultiByte(
            CP_UTF8, 0, fileBuf, -1, nullptr, 0, nullptr, nullptr);
        if (req > 1) {
            std::string utf8(static_cast<std::size_t>(req - 1), '\0');
            ::WideCharToMultiByte(
                CP_UTF8, 0, fileBuf, -1, utf8.data(), req - 1, nullptr, nullptr);
            return utf8;
        }
    }
#endif
    return "";
}

} // namespace gclient::ui
