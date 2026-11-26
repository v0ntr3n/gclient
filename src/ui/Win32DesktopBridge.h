#pragma once
#include <atomic>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace gclient::ui {

class Win32DesktopBridge {
public:
    static Win32DesktopBridge& instance();

#ifdef _WIN32
    void attachToWindow(HWND hwnd);
    void detach();
#endif

    void toggleFullscreen();
    void toggleMute();
    void setInitialMuted(bool muted) noexcept { m_muted.store(muted, std::memory_order_release); }
    bool isMuted() const noexcept { return m_muted.load(std::memory_order_acquire); }

    void setInputTraceEnabled(bool enabled) noexcept {
        m_traceInput.store(enabled, std::memory_order_release);
    }
    bool isInputTraceEnabled() const noexcept {
        return m_traceInput.load(std::memory_order_acquire);
    }

    // Native Win32 Unicode file picker replacement for GameTemplate.GetImageFromGallery
    std::string pickImageFileDialog();

private:
    Win32DesktopBridge();

#ifdef _WIN32
    static LRESULT CALLBACK subclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    HWND    m_hwnd = nullptr;
    WNDPROC m_origProc = nullptr;
    WINDOWPLACEMENT m_savedPlacement{};
    LONG_PTR m_savedStyle = 0;
    LONG_PTR m_savedExStyle = 0;
#endif
    bool m_fullscreen = false;
    std::atomic<bool> m_muted{false};
    std::atomic<bool> m_traceInput{false};
};

} // namespace gclient::ui
