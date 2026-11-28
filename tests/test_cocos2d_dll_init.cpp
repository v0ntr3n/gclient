// ============================================================================
// tests/test_cocos2d_dll_init.cpp
// In-process Win32 Watchdog, DbgHelp PDB & PE Export Symbol Resolver for
// libcocos2d.dll + libExtensions.dll + libCocosDenshion.dll + lua51.dll.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <wingdi.h>

#include "cocos2d.h"
#include "cocos-ext.h"
#include "CCLuaEngine.h"
#include "SimpleAudioEngine.h"
#include "textures/CCTextureETC.h"

#include "TestHarness.h"
#include "assets/BtDecryptHook.h"
#include "assets/PlistbLoader.h"
#include "assets/XmlbArmatureLoader.h"
#include "common/KestrelJson.h"
#include "common/KestrelUtf8.h"
#include "diagnostics/CrashAndTelemetry.h"

#include "zlib.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

using gclient::json::escapeString;
using gclient::test::PhaseRecord;
using gclient::test::makeScopeExit;

inline DWORD64 uptrToAddr64(uintptr_t v) noexcept {
    return static_cast<DWORD64>(v);
}

std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    const int needed = ::MultiByteToWideChar(
        CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring w(static_cast<size_t>(needed), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), needed);
    return w;
}

std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int needed = ::WideCharToMultiByte(
        CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

struct RvaSymbolInfo {
    uint32_t rva = 0;
    std::string symbolName;
    uint64_t symbolDisplacement = 0;
    std::string nearestExportName;
    uint32_t nearestExportRva = 0;
    std::string sourceFile;
    uint32_t sourceLine = 0;
    std::string bytesHex;
};

struct ExportEntry {
    uint32_t rva = 0;
    std::string name;
};

std::mutex g_symMutex;
bool g_symReady = false;
uintptr_t g_cocosBase = 0;
uint32_t g_cocosSize = 0;
std::string g_cocosPath;
std::vector<ExportEntry> g_cocosExports;

void parsePeExportsInMemory(uintptr_t moduleBase, uint32_t moduleSize, std::vector<ExportEntry>& out) {
    out.clear();
    if (moduleBase == 0 || moduleSize < sizeof(IMAGE_DOS_HEADER)) return;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        static_cast<uint32_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > moduleSize) {
        return;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
        moduleBase + static_cast<uintptr_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
        dir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) > moduleSize) {
        return;
    }
    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(moduleBase + dir.VirtualAddress);
    if (exp->AddressOfNames == 0 || exp->AddressOfNameOrdinals == 0 || exp->AddressOfFunctions == 0) {
        return;
    }
    const auto* names = reinterpret_cast<const uint32_t*>(moduleBase + exp->AddressOfNames);
    const auto* ords  = reinterpret_cast<const uint16_t*>(moduleBase + exp->AddressOfNameOrdinals);
    const auto* funcs = reinterpret_cast<const uint32_t*>(moduleBase + exp->AddressOfFunctions);

    out.reserve(exp->NumberOfNames);
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const uint32_t nameRva = names[i];
        const uint16_t ord = ords[i];
        if (nameRva == 0 || nameRva >= moduleSize || ord >= exp->NumberOfFunctions) continue;
        const uint32_t fnRva = funcs[ord];
        if (fnRva >= dir.VirtualAddress && fnRva < dir.VirtualAddress + dir.Size) continue;
        const char* rawName = reinterpret_cast<const char*>(moduleBase + nameRva);
        char undec[512] = {};
        std::string pretty = rawName;
        if (::UnDecorateSymbolName(rawName, undec, sizeof(undec) - 1, UNDNAME_COMPLETE) > 0) {
            pretty = undec;
        }
        out.push_back(ExportEntry{fnRva, std::move(pretty)});
    }
    std::sort(out.begin(), out.end(),
              [](const ExportEntry& a, const ExportEntry& b) { return a.rva < b.rva; });
}

void initDbgHelpForProcess(const std::string& extraSearchDir) {
    std::lock_guard<std::mutex> lk(g_symMutex);
    if (g_symReady) return;

    wchar_t exePathW[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, exePathW, MAX_PATH);
    std::string searchPath = gclient::utf8::fsPathToUtf8(fs::path(exePathW).parent_path());
    if (!extraSearchDir.empty()) {
        searchPath += ";" + extraSearchDir;
    }

    ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS);
    if (::SymInitialize(::GetCurrentProcess(), searchPath.c_str(), TRUE)) {
        g_symReady = true;
    }

    HMODULE hCocos = ::GetModuleHandleW(L"libcocos2d.dll");
    if (hCocos) {
        g_cocosBase = reinterpret_cast<uintptr_t>(hCocos);
        MODULEINFO mi{};
        if (::GetModuleInformation(::GetCurrentProcess(), hCocos, &mi, sizeof(mi))) {
            g_cocosSize = static_cast<uint32_t>(mi.SizeOfImage);
        }
        wchar_t modPathW[MAX_PATH] = {};
        ::GetModuleFileNameW(hCocos, modPathW, MAX_PATH);
        g_cocosPath = wideToUtf8(modPathW);
        parsePeExportsInMemory(g_cocosBase, g_cocosSize, g_cocosExports);

        if (g_symReady) {
            ::SymLoadModuleEx(::GetCurrentProcess(), nullptr, g_cocosPath.c_str(),
                              "libcocos2d.dll", uptrToAddr64(g_cocosBase), g_cocosSize, nullptr, 0);
        }
    }
}

RvaSymbolInfo resolveCocosRva(uint32_t rva, size_t dumpByteCount = 64) {
    std::lock_guard<std::mutex> lk(g_symMutex);
    RvaSymbolInfo info;
    info.rva = rva;
    if (g_cocosBase == 0 || (g_cocosSize != 0 && rva >= g_cocosSize)) {
        info.symbolName = "<out-of-range-or-unloaded>";
        return info;
    }

    if (!g_cocosExports.empty()) {
        auto it = std::upper_bound(
            g_cocosExports.begin(), g_cocosExports.end(), rva,
            [](uint32_t target, const ExportEntry& e) { return target < e.rva; });
        if (it != g_cocosExports.begin()) {
            --it;
            info.nearestExportName = it->name;
            info.nearestExportRva = it->rva;
        }
    }

    const uintptr_t va = g_cocosBase + static_cast<uintptr_t>(rva);
    const DWORD64 addr64 = uptrToAddr64(va);

    alignas(SYMBOL_INFO) char symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
    auto* sym = reinterpret_cast<SYMBOL_INFO*>(symBuf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen = MAX_SYM_NAME;

    DWORD64 disp64 = 0;
    if (g_symReady && ::SymFromAddr(::GetCurrentProcess(), addr64, &disp64, sym)) {
        info.symbolName = sym->Name ? sym->Name : "<unnamed>";
        info.symbolDisplacement = static_cast<uint64_t>(disp64);
    } else if (!info.nearestExportName.empty()) {
        info.symbolName = info.nearestExportName;
        info.symbolDisplacement = rva - info.nearestExportRva;
    } else {
        char errBuf[64];
        std::snprintf(errBuf, sizeof(errBuf), "<SymFromAddr-err-%lu>",
                      static_cast<unsigned long>(::GetLastError()));
        info.symbolName = errBuf;
    }

    IMAGEHLP_LINE64 lineInfo{};
    lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    DWORD lineDisp = 0;
    if (g_symReady && ::SymGetLineFromAddr64(::GetCurrentProcess(), addr64, &lineDisp, &lineInfo)) {
        info.sourceFile = lineInfo.FileName ? lineInfo.FileName : "";
        info.sourceLine = static_cast<uint32_t>(lineInfo.LineNumber);
    }

    if (dumpByteCount > 0 && (g_cocosSize == 0 || rva + dumpByteCount <= g_cocosSize)) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQuery(reinterpret_cast<LPCVOID>(va), &mbi, sizeof(mbi)) == sizeof(mbi) &&
            mbi.State == MEM_COMMIT) {
            const auto* p = reinterpret_cast<const unsigned char*>(va);
            std::ostringstream oss;
            for (size_t i = 0; i < dumpByteCount; ++i) {
                if (i > 0) oss << ' ';
                char hex[4];
                std::snprintf(hex, sizeof(hex), "%02X", static_cast<unsigned int>(p[i]));
                oss << hex;
            }
            info.bytesHex = oss.str();
        }
    }
    return info;
}

std::string formatAddrWithModuleAndSym(uintptr_t addr) {
    HMODULE hMod = nullptr;
    char modName[128] = "<unmapped>";
    uintptr_t modBase = 0;
    if (::GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(addr), &hMod) &&
        hMod != nullptr) {
        modBase = reinterpret_cast<uintptr_t>(hMod);
        char fullMod[MAX_PATH] = {};
        if (::GetModuleFileNameA(hMod, fullMod, MAX_PATH) > 0) {
            const char* slash = std::strrchr(fullMod, '\\');
            std::snprintf(modName, sizeof(modName), "%s", slash ? (slash + 1) : fullMod);
        }
    }

    std::lock_guard<std::mutex> lk(g_symMutex);
    const DWORD64 addr64 = uptrToAddr64(addr);
    alignas(SYMBOL_INFO) char symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
    auto* sym = reinterpret_cast<SYMBOL_INFO*>(symBuf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen = MAX_SYM_NAME;
    DWORD64 disp64 = 0;

    std::ostringstream oss;
    if (modBase != 0) {
        oss << modName << "+0x" << std::hex << (addr - modBase) << std::dec;
    } else {
        oss << "0x" << std::hex << addr << std::dec;
    }
    if (g_symReady && ::SymFromAddr(::GetCurrentProcess(), addr64, &disp64, sym)) {
        oss << " (" << sym->Name << "+0x" << std::hex << disp64 << std::dec << ")";
    }
    IMAGEHLP_LINE64 lineInfo{};
    lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    DWORD lineDisp = 0;
    if (g_symReady && ::SymGetLineFromAddr64(::GetCurrentProcess(), addr64, &lineDisp, &lineInfo) &&
        lineInfo.FileName != nullptr) {
        oss << " [" << lineInfo.FileName << ":" << lineInfo.LineNumber << "]";
    }
    return oss.str();
}

std::atomic<bool> g_watchdogStop{false};
std::atomic<uint64_t> g_phaseStartTick{0};
std::mutex g_phaseMutex;
std::string g_activePhaseName = "startup";
std::vector<PhaseRecord> g_phaseResults;

void writeJsonReport(const std::string& jsonPath,
                     const std::string& verdict,
                     const RvaSymbolInfo& primaryRva,
                     const std::vector<RvaSymbolInfo>& nearbySyms,
                     const std::string& hangDiagnostic) {
    if (jsonPath.empty()) return;
    std::ofstream ofs(gclient::utf8::utf8ToFsPath(jsonPath), std::ios::binary | std::ios::trunc);
    if (!ofs) return;

    ofs << "{\n"
        << "  \"verdict\": \"" << escapeString(verdict) << "\",\n"
        << "  \"libcocos2d_base_hex\": \"0x" << std::hex << g_cocosBase << std::dec << "\",\n"
        << "  \"libcocos2d_size_hex\": \"0x" << std::hex << g_cocosSize << std::dec << "\",\n"
        << "  \"libcocos2d_exports_parsed\": " << g_cocosExports.size() << ",\n"
        << "  \"target_rva_hex\": \"0x" << std::hex << primaryRva.rva << std::dec << "\",\n"
        << "  \"target_symbol\": \"" << escapeString(primaryRva.symbolName) << "\",\n"
        << "  \"target_symbol_disp_hex\": \"0x" << std::hex << primaryRva.symbolDisplacement << std::dec << "\",\n"
        << "  \"nearest_export\": \"" << escapeString(primaryRva.nearestExportName) << "\",\n"
        << "  \"nearest_export_rva_hex\": \"0x" << std::hex << primaryRva.nearestExportRva << std::dec << "\",\n"
        << "  \"target_source_file\": \"" << escapeString(primaryRva.sourceFile) << "\",\n"
        << "  \"target_source_line\": " << primaryRva.sourceLine << ",\n"
        << "  \"target_bytes_hex\": \"" << escapeString(primaryRva.bytesHex) << "\",\n"
        << "  \"hang_diagnostic\": \"" << escapeString(hangDiagnostic) << "\",\n"
        << "  \"nearby_rvas\": [\n";
    for (size_t i = 0; i < nearbySyms.size(); ++i) {
        const auto& ns = nearbySyms[i];
        ofs << "    {\"rva\": \"0x" << std::hex << ns.rva << std::dec
            << "\", \"symbol\": \"" << escapeString(ns.symbolName)
            << "+0x" << std::hex << ns.symbolDisplacement << std::dec
            << "\", \"file\": \"" << escapeString(ns.sourceFile)
            << "\", \"line\": " << ns.sourceLine << "}"
            << (i + 1 < nearbySyms.size() ? "," : "") << "\n";
    }
    ofs << "  ],\n  \"phases\": [\n";
    for (size_t i = 0; i < g_phaseResults.size(); ++i) {
        const auto& pr = g_phaseResults[i];
        ofs << "    {\"name\": \"" << escapeString(pr.name)
            << "\", \"passed\": " << (pr.passed ? "true" : "false")
            << ", \"duration_ms\": " << pr.durationMs
            << ", \"detail\": \"" << escapeString(pr.detail) << "\"}"
            << (i + 1 < g_phaseResults.size() ? "," : "") << "\n";
    }
    ofs << "  ]\n}\n";
    ofs.flush();
}

std::vector<uint8_t> buildValidRgbaPng(uint32_t width, uint32_t height) {
    auto appendBE32 = [](std::vector<uint8_t>& buf, uint32_t v) {
        buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
        buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
        buf.push_back(static_cast<uint8_t>(v & 0xFFu));
    };
    auto appendChunk = [&](std::vector<uint8_t>& out, const char type[4], const uint8_t* data, uint32_t len) {
        appendBE32(out, len);
        const size_t typeOffset = out.size();
        out.insert(out.end(), reinterpret_cast<const uint8_t*>(type), reinterpret_cast<const uint8_t*>(type) + 4);
        if (len > 0 && data != nullptr) out.insert(out.end(), data, data + len);
        uLong crc = ::crc32(0L, Z_NULL, 0);
        crc = ::crc32(crc, out.data() + typeOffset, 4u + len);
        appendBE32(out, static_cast<uint32_t>(crc));
    };

    std::vector<uint8_t> png = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    std::vector<uint8_t> ihdr;
    appendBE32(ihdr, width);
    appendBE32(ihdr, height);
    ihdr.insert(ihdr.end(), {8, 6, 0, 0, 0});
    appendChunk(png, "IHDR", ihdr.data(), static_cast<uint32_t>(ihdr.size()));

    const size_t rowStride = 1u + static_cast<size_t>(width) * 4u;
    std::vector<uint8_t> rawScanlines(rowStride * static_cast<size_t>(height), 0u);
    for (uint32_t y = 0; y < height; ++y) {
        uint8_t* row = rawScanlines.data() + static_cast<size_t>(y) * rowStride;
        for (uint32_t x = 0; x < width; ++x) {
            row[1 + x * 4 + 0] = static_cast<uint8_t>((x * 7u + y) & 0xFFu);
            row[1 + x * 4 + 1] = static_cast<uint8_t>((y * 13u) & 0xFFu);
            row[1 + x * 4 + 2] = 0xCCu;
            row[1 + x * 4 + 3] = 0xFFu;
        }
    }

    uLongf compCap = ::compressBound(static_cast<uLong>(rawScanlines.size()));
    std::vector<uint8_t> idat(static_cast<size_t>(compCap));
    if (::compress2(idat.data(), &compCap, rawScanlines.data(),
                    static_cast<uLong>(rawScanlines.size()), Z_BEST_SPEED) == Z_OK) {
        idat.resize(static_cast<size_t>(compCap));
        appendChunk(png, "IDAT", idat.data(), static_cast<uint32_t>(idat.size()));
    }
    appendChunk(png, "IEND", nullptr, 0);
    return png;
}

class DummyTickTarget : public cocos2d::CCObject {
public:
    int ticks = 0;
    void onTick(float) { ++ticks; }
    virtual void update(float) { ++ticks; }
};

class ScopedDummyApplication final : public cocos2d::CCApplication {
public:
    bool applicationDidFinishLaunching() override { return true; }
    void applicationDidEnterBackground() override {}
    void applicationWillEnterForeground() override {}
};

struct ScopedDummyWglContext {
    HWND hwnd = nullptr;
    HDC hdc = nullptr;
    HGLRC hglrc = nullptr;
    bool gl11Ready = false;
    bool ready = false;
    std::string glVersion;

    ScopedDummyWglContext() {
        hwnd = ::CreateWindowExW(
            0, L"STATIC", L"GClientCocosInitTest", WS_POPUP,
            0, 0, 64, 64, nullptr, nullptr, ::GetModuleHandleW(nullptr), nullptr);
        if (!hwnd) return;
        hdc = ::GetDC(hwnd);
        if (!hdc) return;

        PIXELFORMATDESCRIPTOR pfd{};
        pfd.nSize = sizeof(pfd);
        pfd.nVersion = 1;
        pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
        pfd.iPixelType = PFD_TYPE_RGBA;
        pfd.cColorBits = 32;
        pfd.cDepthBits = 24;
        pfd.cStencilBits = 8;
        pfd.iLayerType = PFD_MAIN_PLANE;

        const int pf = ::ChoosePixelFormat(hdc, &pfd);
        if (pf == 0 || !::SetPixelFormat(hdc, pf, &pfd)) return;

        hglrc = ::wglCreateContext(hdc);
        if (!hglrc || !::wglMakeCurrent(hdc, hglrc)) return;
        gl11Ready = true;

        glewExperimental = GL_TRUE;
        const GLenum glewRc = ::glewInit();
        if (const GLubyte* ver = ::glGetString(GL_VERSION)) {
            glVersion = reinterpret_cast<const char*>(ver);
        }
        ready = (glewRc == GLEW_OK) && GLEW_VERSION_2_0 &&
                (glCreateProgram != nullptr) && (glGenBuffers != nullptr);
    }

    ~ScopedDummyWglContext() {
        if (hglrc) {
            ::wglMakeCurrent(nullptr, nullptr);
            ::wglDeleteContext(hglrc);
        }
        if (hwnd && hdc) ::ReleaseDC(hwnd, hdc);
        if (hwnd) ::DestroyWindow(hwnd);
    }
};

struct DirectorViewTestAccessor : public cocos2d::CCDirector {
    static cocos2d::CCEGLView* currentView(cocos2d::CCDirector* dir) {
        return dir ? dir->*(&DirectorViewTestAccessor::m_pobOpenGLView) : nullptr;
    }
    static void bindHeadlessView(cocos2d::CCDirector* dir, cocos2d::CCEGLView* view) {
        if (!dir) return;
        dir->*(&DirectorViewTestAccessor::m_pobOpenGLView) = view;
        if (view) {
            const cocos2d::CCSize ds = view->getDesignResolutionSize();
            dir->*(&DirectorViewTestAccessor::m_obWinSizeInPoints) =
                (ds.width > 0.0f && ds.height > 0.0f) ? ds : cocos2d::CCSizeMake(1136.0f, 640.0f);
            view->setTouchDelegate(dir->getTouchDispatcher());
            if (dir->getTouchDispatcher()) dir->getTouchDispatcher()->setDispatchEvents(true);
        }
    }
    static void syncWinSizeAndOrtho(cocos2d::CCDirector* dir, const cocos2d::CCSize& ds) {
        if (!dir) return;
        dir->*(&DirectorViewTestAccessor::m_obWinSizeInPoints) = ds;
        kmGLMatrixMode(KM_GL_PROJECTION);
        kmGLLoadIdentity();
        kmMat4 ortho;
        kmMat4OrthographicProjection(&ortho, 0.0f, ds.width, 0.0f, ds.height, -1024.0f, 1024.0f);
        kmGLMultMatrix(&ortho);
        kmGLMatrixMode(KM_GL_MODELVIEW);
        kmGLLoadIdentity();
    }
};

class TestableWin32EGLView final : public cocos2d::CCEGLView {
public:
    explicit TestableWin32EGLView(bool hasGl20) : m_hasGl20(hasGl20) {}
    bool isOpenGLReady() override { return m_hasGl20 ? cocos2d::CCEGLView::isOpenGLReady() : true; }
    void swapBuffers() override { if (m_hasGl20) cocos2d::CCEGLView::swapBuffers(); }
    void centerWindow() override {}
    void setViewPortInPoints(float x, float y, float w, float h) override {
        if (m_hasGl20) cocos2d::CCEGLView::setViewPortInPoints(x, y, w, h);
    }
    void setDesignResolutionSize(float width, float height, ResolutionPolicy policy) override {
        if (width <= 0.0f || height <= 0.0f || m_obScreenSize.width <= 0.0f || m_obScreenSize.height <= 0.0f) return;
        if (m_hasGl20) {
            cocos2d::CCEGLView::setDesignResolutionSize(width, height, policy);
            DirectorViewTestAccessor::syncWinSizeAndOrtho(cocos2d::CCDirector::sharedDirector(), m_obDesignResolutionSize);
            return;
        }
        m_obDesignResolutionSize.setSize(width, height);
        m_fScaleX = m_obScreenSize.width / m_obDesignResolutionSize.width;
        m_fScaleY = m_obScreenSize.height / m_obDesignResolutionSize.height;
        if (policy == kResolutionNoBorder) m_fScaleX = m_fScaleY = (std::max)(m_fScaleX, m_fScaleY);
        else if (policy == kResolutionShowAll) m_fScaleX = m_fScaleY = (std::min)(m_fScaleX, m_fScaleY);
        else if (policy == kResolutionFixedHeight) {
            m_fScaleX = m_fScaleY;
            m_obDesignResolutionSize.width = std::ceil(m_obScreenSize.width / m_fScaleX);
        } else if (policy == kResolutionFixedWidth) {
            m_fScaleY = m_fScaleX;
            m_obDesignResolutionSize.height = std::ceil(m_obScreenSize.height / m_fScaleY);
        }
        const float vpW = m_obDesignResolutionSize.width * m_fScaleX;
        const float vpH = m_obDesignResolutionSize.height * m_fScaleY;
        m_obViewPortRect.setRect((m_obScreenSize.width - vpW) * 0.5f,
                                 (m_obScreenSize.height - vpH) * 0.5f, vpW, vpH);
        m_eResolutionPolicy = policy;
        DirectorViewTestAccessor::syncWinSizeAndOrtho(cocos2d::CCDirector::sharedDirector(), m_obDesignResolutionSize);
    }
    static LRESULT CALLBACK hostWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        if (msg == WM_NCCREATE) {
            const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        } else if (msg == WM_GETMINMAXINFO) {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
            mmi->ptMaxTrackSize.x = mmi->ptMaxTrackSize.y = mmi->ptMaxSize.x = mmi->ptMaxSize.y = 8192;
            return 0;
        }
        auto* self = reinterpret_cast<TestableWin32EGLView*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (self && self->getHWnd() == hwnd && msg != WM_DESTROY) {
            return self->WindowProc(msg, wParam, lParam);
        }
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    }
private:
    bool m_hasGl20 = false;
};

class NonSwallowingProbeLayer final : public cocos2d::CCLayer {
public:
    explicit NonSwallowingProbeLayer(int prio) : m_prio(prio) {}
    void onEnter() override {
        cocos2d::CCLayer::onEnter();
        if (auto* td = cocos2d::CCDirector::sharedDirector()->getTouchDispatcher()) {
            td->addTargetedDelegate(this, m_prio, false);
        }
    }
    void onExit() override {
        if (auto* td = cocos2d::CCDirector::sharedDirector()->getTouchDispatcher()) {
            td->removeDelegate(this);
        }
        cocos2d::CCLayer::onExit();
    }
    bool ccTouchBegan(cocos2d::CCTouch*, cocos2d::CCEvent*) override { ++beganCount; return true; }
    int beganCount = 0;
private:
    int m_prio = 0;
};

class WidgetCallbackTarget final : public cocos2d::CCObject {
public:
    std::function<void(cocos2d::CCObject*, cocos2d::ui::TouchEventType)> onEvent;
    void handleTouch(cocos2d::CCObject* s, cocos2d::ui::TouchEventType t) {
        if (onEvent) onEvent(s, t);
    }
};

cocos2d::ui::Widget* createConfiguredTouchWidget(bool hasGl20, float w, float h, float scale,
                                                 cocos2d::CCPoint anchor) {
    cocos2d::ui::Widget* btn = hasGl20
        ? static_cast<cocos2d::ui::Widget*>(cocos2d::ui::Button::create())
        : static_cast<cocos2d::ui::Widget*>(cocos2d::ui::Layout::create());
    btn->ignoreContentAdaptWithSize(false);
    btn->setSize(cocos2d::CCSizeMake(w, h));
    btn->setScale(scale);
    btn->setAnchorPoint(anchor);
    btn->setTouchEnabled(true);
    return btn;
}

cocos2d::ui::Layout* createTouchMaskLayout(float w, float h, float x, float y) {
    auto* mask = cocos2d::ui::Layout::create();
    mask->setSize(cocos2d::CCSizeMake(w, h));
    mask->setPosition(cocos2d::CCPointMake(x, y));
    mask->setTouchEnabled(true);
    return mask;
}

cocos2d::ui::ImageView* createSizedLocalImage(cocos2d::ui::Widget* parent, const char* texPath, float sz) {
    auto* img = cocos2d::ui::ImageView::create();
    img->ignoreContentAdaptWithSize(false);
    parent->addChild(img);
    img->loadTexture(texPath, cocos2d::ui::UI_TEX_TYPE_LOCAL);
    img->setSize(cocos2d::CCSize(sz, sz));
    return img;
}

cocos2d::CCTexture2D* decodePngIntoTextureCache(const std::vector<uint8_t>& pngBytes,
                                                int expectedW, int expectedH,
                                                const char* cacheKey,
                                                std::string& errOut) {
    auto* img = new cocos2d::CCImage();
    auto rel = makeScopeExit([img]() noexcept { img->release(); });
    if (!img->initWithImageData(const_cast<uint8_t*>(pngBytes.data()),
                                static_cast<int>(pngBytes.size()),
                                cocos2d::CCImage::kFmtPng)) {
        errOut = std::string("CCImage::initWithImageData failed for ") + cacheKey;
        return nullptr;
    }
    if (img->getWidth() != expectedW || img->getHeight() != expectedH || img->getData() == nullptr) {
        errOut = std::string("Unexpected decoded PNG dimensions for ") + cacheKey;
        return nullptr;
    }
    if (cacheKey == nullptr) return nullptr;
    cocos2d::CCTextureCache* cache = cocos2d::CCTextureCache::sharedTextureCache();
    cocos2d::CCTexture2D* tex = cache ? cache->addUIImage(img, cacheKey) : nullptr;
    if (!tex) errOut = std::string("CCTextureCache::addUIImage failed for ") + cacheKey;
    return tex;
}

struct SendInputProbeStatus { bool available = false; std::string reason; };

SendInputProbeStatus probeInteractiveSendInput(HWND targetHwnd) {
    DWORD sessionId = 0;
    if (!::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionId) || sessionId == 0) {
        return {false, "Session-0 non-interactive service session"};
    }
    if (HWINSTA hWinSta = ::GetProcessWindowStation()) {
        USEROBJECTFLAGS uof{};
        DWORD len = 0;
        if (::GetUserObjectInformationW(hWinSta, UOI_FLAGS, &uof, sizeof(uof), &len) &&
            (uof.dwFlags & WSF_VISIBLE) == 0) {
            return {false, "WindowStation lacks WSF_VISIBLE (headless/non-interactive)"};
        }
    }
    HDESK hDesk = ::OpenInputDesktop(0, FALSE, DESKTOP_WRITEOBJECTS | DESKTOP_JOURNALPLAYBACK);
    if (!hDesk) return {false, "OpenInputDesktop denied/locked (err=" + std::to_string(::GetLastError()) + ")"};
    ::CloseDesktop(hDesk);
    if (gclient::utf8::readEnvUtf8("GITHUB_ACTIONS") == "true") {
        return {false, "GITHUB_ACTIONS headless runner desktop"};
    }
    ::ShowWindow(targetHwnd, SW_SHOWNOACTIVATE);
    ::SetForegroundWindow(targetHwnd);
    if (::GetForegroundWindow() != targetHwnd) {
        return {false, "Target HWND could not acquire foreground focus (UIPI/locked desktop)"};
    }
    return {true, "Interactive unlocked desktop verified"};
}

bool dispatchWin32ClickViaWindowProc(HWND hwnd, int clientX, int clientY, WPARAM downWParam = MK_LBUTTON) {
    if (!hwnd || !::IsWindow(hwnd)) return false;
    const LPARAM lp = MAKELPARAM(static_cast<short>(clientX), static_cast<short>(clientY));
    ::SendMessageW(hwnd, WM_MOUSEMOVE, 0, lp);
    ::SendMessageW(hwnd, WM_LBUTTONDOWN, downWParam, lp);
    ::SendMessageW(hwnd, WM_MOUSEMOVE, downWParam, lp);
    ::SendMessageW(hwnd, WM_LBUTTONUP, 0, lp);
    return true;
}

bool dispatchWin32ClickViaSendInput(HWND hwnd, int clientX, int clientY, std::string& errOut) {
    POINT screenPt{clientX, clientY};
    if (!::ClientToScreen(hwnd, &screenPt)) { errOut = "ClientToScreen failed"; return false; }
    const int vL = ::GetSystemMetrics(SM_XVIRTUALSCREEN), vT = ::GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int vW = (std::max)(1, ::GetSystemMetrics(SM_CXVIRTUALSCREEN));
    const int vH = (std::max)(1, ::GetSystemMetrics(SM_CYVIRTUALSCREEN));
    INPUT inputs[3] = {};
    inputs[0].type = INPUT_MOUSE;
    inputs[0].mi.dx = static_cast<LONG>(((static_cast<int64_t>(screenPt.x - vL) * 65535) + vW / 2) / vW);
    inputs[0].mi.dy = static_cast<LONG>(((static_cast<int64_t>(screenPt.y - vT) * 65535) + vH / 2) / vH);
    inputs[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
    inputs[1] = inputs[0]; inputs[1].mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
    inputs[2] = inputs[0]; inputs[2].mi.dwFlags |= MOUSEEVENTF_LEFTUP;
    ::SetLastError(0);
    const UINT sent = ::SendInput(3, inputs, sizeof(INPUT));
    if (sent != 3) {
        errOut = "SendInput returned " + std::to_string(sent) + " (err=" + std::to_string(::GetLastError()) + ")";
        return false;
    }
    MSG msg{};
    const ULONGLONG deadline = ::GetTickCount64() + 250;
    while (::GetTickCount64() < deadline) {
        while (::PeekMessageW(&msg, hwnd, 0, 0, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
        ::Sleep(5);
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    uint32_t targetRva = 0xB6524u;
    uint32_t timeoutMs = 6000u;
    bool probeOnly = false;
    std::string jsonOutPath;
    std::string pdbDir;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--probe-only") {
            probeOnly = true;
        } else if (arg == "--json-out" && i + 1 < argc) {
            jsonOutPath = argv[++i];
        } else if (arg == "--pdb-dir" && i + 1 < argc) {
            pdbDir = argv[++i];
        } else if (arg == "--resolve-rva" && i + 1 < argc) {
            targetRva = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
        } else if (arg == "--timeout-ms" && i + 1 < argc) {
            timeoutMs = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
        }
    }

    ::SetEnvironmentVariableW(L"GCLIENT_HEADLESS", L"1");
    ::SetEnvironmentVariableW(L"GCLIENT_SUPPRESS_MESSAGEBOX", L"1");

    initDbgHelpForProcess(pdbDir);

    const RvaSymbolInfo primaryRva = resolveCocosRva(targetRva, 64);
    std::printf("[CocosInitTest] libcocos2d.dll base=0x%08zX size=0x%08X exports=%zu\n",
                static_cast<size_t>(g_cocosBase), g_cocosSize, g_cocosExports.size());
    std::printf("[CocosInitTest] RVA +0x%X -> %s + 0x%llX [%s:%u] (nearestExport=%s @ +0x%X)\n",
                primaryRva.rva, primaryRva.symbolName.c_str(),
                static_cast<unsigned long long>(primaryRva.symbolDisplacement),
                primaryRva.sourceFile.c_str(), primaryRva.sourceLine,
                primaryRva.nearestExportName.c_str(), primaryRva.nearestExportRva);
    std::printf("[CocosInitTest] Bytes @ +0x%X: %s\n", primaryRva.rva, primaryRva.bytesHex.c_str());
    std::fflush(stdout);

    std::vector<RvaSymbolInfo> nearbySyms;
    for (int32_t off : {-0x200, -0x100, -0x80, -0x40, -0x20, -0x10, 0, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200}) {
        if (off < 0 && static_cast<uint32_t>(-off) > targetRva) continue;
        nearbySyms.push_back(resolveCocosRva(static_cast<uint32_t>(static_cast<int64_t>(targetRva) + off), 0));
    }

    HANDLE hMainThread = nullptr;
    ::DuplicateHandle(::GetCurrentProcess(), ::GetCurrentThread(), ::GetCurrentProcess(), &hMainThread,
                      THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, 0);

    g_phaseStartTick.store(::GetTickCount64(), std::memory_order_release);

    std::thread watchdog([hMainThread, timeoutMs, probeOnly, jsonOutPath, primaryRva, nearbySyms]() {
        while (!g_watchdogStop.load(std::memory_order_acquire)) {
            ::Sleep(50);
            if (g_watchdogStop.load(std::memory_order_acquire)) break;
            const uint64_t start = g_phaseStartTick.load(std::memory_order_acquire);
            const uint64_t now = ::GetTickCount64();
            if (now > start && (now - start) >= timeoutMs) {
                std::string phaseCopy;
                {
                    std::lock_guard<std::mutex> lk(g_phaseMutex);
                    phaseCopy = g_activePhaseName;
                }
                std::ostringstream diag;
                diag << "WATCHDOG TIMEOUT (" << (now - start) << " ms) in phase '" << phaseCopy << "'. ";

                if (hMainThread != nullptr) {
                    ::SuspendThread(hMainThread);
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_FULL;
                    if (::GetThreadContext(hMainThread, &ctx)) {
#if defined(_M_IX86)
                        diag << "EIP=" << formatAddrWithModuleAndSym(static_cast<uintptr_t>(ctx.Eip))
                             << " ECX=0x" << std::hex << ctx.Ecx
                             << " ESP=0x" << ctx.Esp
                             << " EBP=0x" << ctx.Ebp << std::dec << " | Stack: ";

                        STACKFRAME64 sf{};
                        sf.AddrPC.Offset = uptrToAddr64(static_cast<uintptr_t>(ctx.Eip));
                        sf.AddrPC.Mode = AddrModeFlat;
                        sf.AddrFrame.Offset = uptrToAddr64(static_cast<uintptr_t>(ctx.Ebp));
                        sf.AddrFrame.Mode = AddrModeFlat;
                        sf.AddrStack.Offset = uptrToAddr64(static_cast<uintptr_t>(ctx.Esp));
                        sf.AddrStack.Mode = AddrModeFlat;

                        CONTEXT walkCtx = ctx;
                        for (int frame = 0; frame < 14; ++frame) {
                            if (!::StackWalk64(IMAGE_FILE_MACHINE_I386, ::GetCurrentProcess(), hMainThread,
                                               &sf, &walkCtx, nullptr, ::SymFunctionTableAccess64,
                                               ::SymGetModuleBase64, nullptr) ||
                                sf.AddrPC.Offset == 0) {
                                break;
                            }
                            if (frame > 0) diag << " <- ";
                            diag << "#" << frame << " "
                                 << formatAddrWithModuleAndSym(static_cast<uintptr_t>(sf.AddrPC.Offset));
                        }
#endif
                    }
                }

                const std::string diagStr = diag.str();
                std::fprintf(stderr, "[WATCHDOG-HANG] %s\n", diagStr.c_str());
                std::fflush(stderr);
                writeJsonReport(jsonOutPath, "HANG_DETECTED", primaryRva, nearbySyms, diagStr);
                ::TerminateProcess(::GetCurrentProcess(), probeOnly ? 0u : 124u);
            }
        }
    });

    bool anyFailed = false;
    auto runPhase = [&](const char* phaseName, const std::function<bool(std::string&)>& fn) {
        const bool ok = gclient::test::runTimedPhase(
            phaseName, g_phaseResults, fn,
            [&](const char* active) {
                {
                    std::lock_guard<std::mutex> lk(g_phaseMutex);
                    g_activePhaseName = active;
                }
                g_phaseStartTick.store(::GetTickCount64(), std::memory_order_release);
            });
        if (!ok) anyFailed = true;
    };

    gclient::test::ScopedTempDir tempDir(
        fs::temp_directory_path() /
        gclient::utf8::utf8ToFsPath("kestrel_cocos_init_Tiếng_Việt_" + std::to_string(::GetCurrentProcessId())));
    const fs::path& tempFixture = tempDir.path;
    fs::create_directories(tempFixture / L"scripts");
    {
        std::ofstream luaOut(tempFixture / L"scripts" / L"boot_probe.lua", std::ios::binary);
        luaOut << "return 1337\n";
    }

    ScopedDummyApplication dummyApp;
    ScopedDummyWglContext wglCtx;

    // Phase 1: CCFileUtils + setSearchPaths + bt_decrypt + UTF-8 path resolution
    runPhase("phase1_fileutils_and_bt_decrypt", [&](std::string& detail) -> bool {
        cocos2d::CCFileUtils* fu = cocos2d::CCFileUtils::sharedFileUtils();
        PHASE_REQUIRE(fu != nullptr, detail, "CCFileUtils::sharedFileUtils() returned null");
        fu->setPopupNotify(false);

        std::string rootUtf8 = gclient::utf8::fsPathToUtf8(tempFixture);
        std::replace(rootUtf8.begin(), rootUtf8.end(), '\\', '/');
        fu->setSearchPaths({rootUtf8, "Resources"});
        fu->setDecrypt(&bt_decrypt);
        gclient::assets::InstallBtDecryptHook(fu);

        const auto searchCopy = fu->getSearchPaths();
        PHASE_REQUIRE(!fu->isFileExist("cc_fps_images") &&
                          !fu->isFileExist("nonexistent_Tửu_Quán_probe.png"),
                      detail, "isFileExist unexpectedly returned true for non-existent probe path");

        const std::string resolved = fu->fullPathForFilename("scripts/boot_probe.lua");
        PHASE_REQUIRE(!resolved.empty() && fu->isFileExist(resolved),
                      detail, "Failed to resolve UTF-8 path scripts/boot_probe.lua -> " + resolved);

        unsigned long sz = 0;
        unsigned char* buf = fu->getFileData(resolved.c_str(), "rb", &sz);
        const bool ok = (buf != nullptr && sz > 0 && !searchCopy.empty());
        delete[] buf;
        detail = "resolved=" + resolved + " bytes=" + std::to_string(sz) +
                 " searchPaths=" + std::to_string(searchCopy.size());
        return ok;
    });

    // Phase 2: CCImage PNG decode (libpng.lib + vcpkg libz.dll) + CCTextureCache + CCLabelAtlas
    runPhase("phase2_ccimage_png_and_label_atlas", [&](std::string& detail) -> bool {
        const std::vector<uint8_t> pngData = buildValidRgbaPng(256, 32);
        std::string texErr;
        if (wglCtx.ready) {
            cocos2d::CCTexture2D* tex =
                decodePngIntoTextureCache(pngData, 256, 32, "cc_fps_images_probe", texErr);
            PHASE_REQUIRE(tex != nullptr, detail, texErr + " (" + wglCtx.glVersion + ")");
            auto* label = new cocos2d::CCLabelAtlas();
            auto relLbl = makeScopeExit([label]() noexcept { label->release(); });
            PHASE_REQUIRE(label->initWithString("00.0", tex, 12, 32, '.'),
                          detail, "CCLabelAtlas::initWithString('00.0', tex, 12, 32, '.') returned false");
            label->setString("59.9");
            label->setTexture(tex);
            label->updateAtlasValues();
        } else {
            (void)decodePngIntoTextureCache(pngData, 256, 32, nullptr, texErr);
            PHASE_REQUIRE(texErr.empty(), detail, texErr);
        }
        detail = "PNG 256x32 decoded cleanly; WGL20=" +
                 (wglCtx.ready ? wglCtx.glVersion : ("unavailable(gl=" + wglCtx.glVersion + ")"));
        return true;
    });

    // Phase 3: CCConfiguration + gatherGPUInfo + dumpInfo + CCDirector + CCScheduler + SimpleAudioEngine
    runPhase("phase3_configuration_director_scheduler", [&](std::string& detail) -> bool {
        cocos2d::CCDirector* dir = cocos2d::CCDirector::sharedDirector();
        PHASE_REQUIRE(dir != nullptr, detail, "CCDirector::sharedDirector() returned null");
        cocos2d::CCConfiguration* conf = cocos2d::CCConfiguration::sharedConfiguration();
        PHASE_REQUIRE(conf != nullptr, detail, "CCConfiguration::sharedConfiguration() returned null");

        if (wglCtx.ready) conf->gatherGPUInfo();
        conf->dumpInfo();
        dir->setAnimationInterval(1.0 / 30.0);
        dir->setDisplayStats(true);

        if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
            audio->setBackgroundMusicVolume(0.0f);
            audio->setEffectsVolume(0.0f);
        }

        cocos2d::CCScheduler* sched = dir->getScheduler();
        PHASE_REQUIRE(sched != nullptr, detail, "CCDirector::getScheduler() returned null");

        using cocos2d::SEL_SCHEDULE;
        auto* dummy = new DummyTickTarget();
        auto relDummy = makeScopeExit([dummy]() noexcept { dummy->release(); });
        sched->unscheduleSelector(schedule_selector(DummyTickTarget::onTick), dummy);
        sched->scheduleSelector(schedule_selector(DummyTickTarget::onTick), dummy, 0.0f, false);
        sched->unscheduleAllForTarget(dummy);
        sched->scheduleUpdateForTarget(dummy, 0, false);
        sched->update(0.016f);
        sched->unscheduleAllForTarget(dummy);

        detail = "ticks=" + std::to_string(dummy->ticks) +
                 " maxTex=" + std::to_string(conf->getMaxTextureSize());
        return dummy->ticks >= 1;
    });

    // Phase 4: CCLuaEngine::defaultEngine + tolua++ bindings + Lua CCFileUtils call
    runPhase("phase4_ccluaengine_and_bindings", [&](std::string& detail) -> bool {
        cocos2d::CCLuaEngine* engine = cocos2d::CCLuaEngine::defaultEngine();
        PHASE_REQUIRE(engine && engine->getLuaStack() && engine->getLuaStack()->getLuaState(),
                      detail, "CCLuaEngine::defaultEngine() failed");
        cocos2d::CCScriptEngineManager::sharedManager()->setScriptEngine(engine);
        lua_State* L = engine->getLuaStack()->getLuaState();
        const int rc = engine->executeString(
            "local fu = CCFileUtils:sharedFileUtils()\n"
            "assert(fu ~= nil)\n"
            "local p = fu:fullPathForFilename('scripts/boot_probe.lua')\n"
            "assert(type(p) == 'string' and #p > 0)\n"
            "__GCLIENT_INIT_PROBE_OK = 42\n");
        lua_getglobal(L, "__GCLIENT_INIT_PROBE_OK");
        const int probeVal = static_cast<int>(lua_tointeger(L, -1));
        lua_pop(L, 1);
        detail = "rc=" + std::to_string(rc) + " probeVal=" + std::to_string(probeVal);
        return rc == 0 && probeVal == 42;
    });

    // Phase 5: Real Win32 HWND + CCEGLView + TouchGroup + FuncMenu (Tửu Quán) Mouse Routing (>= 24 cycles)
    runPhase("phase5_win32_funcmenu_mouse_routing", [&](std::string& detail) -> bool {
        using cocos2d::ui::SEL_TouchEvent;
        cocos2d::CCDirector* dir = cocos2d::CCDirector::sharedDirector();
        PHASE_REQUIRE(dir && dir->getTouchDispatcher(), detail, "CCDirector/CCTouchDispatcher null");

        static const wchar_t* kTestWndClass = L"KestrelFuncMenuMouseProbeWnd";
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
        wc.lpfnWndProc = &TestableWin32EGLView::hostWndProc;
        wc.hInstance = ::GetModuleHandleW(nullptr);
        wc.lpszClassName = kTestWndClass;
        ::RegisterClassExW(&wc);

        auto* testView = new TestableWin32EGLView(false);
        HWND testHwnd = ::CreateWindowExW(0, kTestWndClass, L"Kestrel Issue #8 FuncMenu Mouse Probe",
                                          WS_POPUP, 0, 0, 1136, 640, nullptr, nullptr, wc.hInstance, testView);
        if (!testHwnd) {
            delete testView;
            detail = "CreateWindowExW failed";
            return false;
        }
        testView->setHWnd(testHwnd);

        cocos2d::CCEGLView* prevView = DirectorViewTestAccessor::currentView(dir);
        DirectorViewTestAccessor::bindHeadlessView(dir, testView);
        auto cleanupView = makeScopeExit([&]() noexcept {
            DirectorViewTestAccessor::bindHeadlessView(dir, prevView);
            testView->setHWnd(nullptr);
            ::DestroyWindow(testHwnd);
            delete testView;
        });

        struct ResCase { int baseW, baseH, dpiPct; };
        const ResCase kCases[12] = {
            {960, 640, 100},   {960, 640, 125},   {960, 640, 150},
            {1136, 640, 100},  {1136, 640, 125},  {1136, 640, 150},
            {1280, 720, 100},  {1280, 720, 125},  {1280, 720, 150},
            {1920, 1080, 100}, {1920, 1080, 125}, {1920, 1080, 150},
        };

        int completedCycles = 0, directOpens = 0, secOpens = 0, jgOpens = 0, panelCloses = 0;
        std::string failReason;

        auto runCycle = [&](int cycleIdx, const ResCase& rc, bool secMode) -> bool {
            const float zoom = static_cast<float>(rc.dpiPct) / 100.0f;
            testView->setFrameZoomFactor(zoom);
            testView->setFrameSize(static_cast<float>(rc.baseW), static_cast<float>(rc.baseH));
            RECT clientRc{};
            ::GetClientRect(testHwnd, &clientRc);

            testView->setDesignResolutionSize(1136.0f, 640.0f, kResolutionFixedWidth);
            cocos2d::CCSize cppDesign = testView->getDesignResolutionSize();
            if (cppDesign.height > 768.0f) {
                testView->setDesignResolutionSize(1136.0f, 768.0f, kResolutionShowAll);
                cppDesign = testView->getDesignResolutionSize();
            }
            const float luaW = cppDesign.width, luaH = (std::max)(cppDesign.height, 640.0f);
            const float yShift = (luaH - 640.0f) * 0.5f;
            const float stScale = (cppDesign.height < 640.0f) ? (cppDesign.height / 640.0f) : 1.0f;
            const float stX = (cppDesign.height < 640.0f)
                ? ((cppDesign.width - 1136.0f * stScale) * 0.5f)
                : ((cppDesign.width - 1136.0f) * 0.5f);
            const float stY = (cppDesign.height < 640.0f) ? 0.0f : ((cppDesign.height - 640.0f) * 0.5f);

            auto* stage = cocos2d::CCScene::create();
            stage->retain();
            auto* stageLayer = cocos2d::CCNode::create();
            stageLayer->setPosition(cocos2d::CCPointMake(stX, stY));
            stageLayer->setScale(stScale);
            stage->addChild(stageLayer);

            auto* sceneHost = cocos2d::CCNode::create();
            auto* panelHost = cocos2d::CCNode::create();
            stageLayer->addChild(sceneHost, 0);
            stageLayer->addChild(panelHost, 10);

            auto* touchFxProbe = new NonSwallowingProbeLayer(-123);
            touchFxProbe->autorelease();
            stage->addChild(touchFxProbe, 100);
            auto* rotateProbe = new NonSwallowingProbeLayer(-3);
            rotateProbe->autorelease();
            sceneHost->addChild(rotateProbe, 0);

            auto* mainScene = cocos2d::ui::TouchGroup::create();
            mainScene->setTouchPriority(-2);
            sceneHost->addChild(mainScene, 999);

            auto* funcMenu = cocos2d::ui::Layout::create();
            funcMenu->setPosition(cocos2d::CCPointMake(0.0f, yShift));
            mainScene->addWidget(funcMenu);

            auto* choukaWrap = cocos2d::ui::Layout::create();
            choukaWrap->setPosition(cocos2d::CCPointMake(50.0f, 400.0f));
            funcMenu->addChild(choukaWrap);

            auto* choukaBtn = createConfiguredTouchWidget(
                wglCtx.ready, 119.0f, 112.0f, 0.8f, cocos2d::CCPointMake(0.5f, 0.0f));
            choukaWrap->addChild(choukaBtn);

            auto* tipsMore = cocos2d::ui::Layout::create();
            tipsMore->setPosition(cocos2d::CCPointMake(0.0f, -yShift));
            tipsMore->addChild(createTouchMaskLayout(1.0f, 1.0f, 0.0f, 20.0f));
            mainScene->addWidget(tipsMore);

            bool raffleOpen = false, secondaryOpen = false;
            cocos2d::ui::TouchGroup* activeRaffle = nullptr;
            cocos2d::ui::Layout* secMask = nullptr;
            cocos2d::ui::Widget* secBg = nullptr;

            auto* choukaCb = new WidgetCallbackTarget();
            auto* closeCb  = new WidgetCallbackTarget();
            auto* maskCb   = new WidgetCallbackTarget();
            auto* jgCb     = new WidgetCallbackTarget();
            auto cleanupCycle = makeScopeExit([&]() noexcept {
                stage->onExit();
                stage->cleanup();
                stage->release();
                choukaCb->release();
                closeCb->release();
                maskCb->release();
                jgCb->release();
            });

            auto spawnRaffle = [&]() {
                if (raffleOpen) return;
                raffleOpen = true;
                activeRaffle = cocos2d::ui::TouchGroup::create();
                activeRaffle->setTouchPriority(-26);
                auto* modalBg = createTouchMaskLayout(luaW, luaH, 0.0f, -yShift);
                activeRaffle->addWidget(modalBg);
                modalBg->setZOrder(-2);

                auto* closeBtn = createConfiguredTouchWidget(
                    wglCtx.ready, 80.0f, 80.0f, 1.0f, cocos2d::CCPointMake(0.5f, 0.5f));
                closeBtn->setPosition(cocos2d::CCPointMake(1060.0f, 580.0f + yShift));
                closeBtn->addTouchEventListener(closeCb, toucheventselector(WidgetCallbackTarget::handleTouch));
                activeRaffle->addWidget(closeBtn);
                panelHost->addChild(activeRaffle);
            };
            closeCb->onEvent = [&](cocos2d::CCObject*, cocos2d::ui::TouchEventType t) {
                if (t == cocos2d::ui::TOUCH_EVENT_ENDED && activeRaffle) {
                    activeRaffle->removeFromParentAndCleanup(true);
                    activeRaffle = nullptr;
                    raffleOpen = false;
                    ++panelCloses;
                }
            };
            auto closeSec = [&]() {
                if (!secondaryOpen) return;
                secondaryOpen = false;
                if (secBg) { secBg->removeFromParentAndCleanup(true); secBg = nullptr; }
                if (secMask) { secMask->removeFromParentAndCleanup(true); secMask = nullptr; }
            };
            maskCb->onEvent = [&](cocos2d::CCObject*, cocos2d::ui::TouchEventType t) {
                if (t == cocos2d::ui::TOUCH_EVENT_ENDED) closeSec();
            };
            jgCb->onEvent = [&](cocos2d::CCObject*, cocos2d::ui::TouchEventType t) {
                if (t == cocos2d::ui::TOUCH_EVENT_ENDED) { ++jgOpens; closeSec(); spawnRaffle(); }
            };
            choukaCb->onEvent = [&](cocos2d::CCObject*, cocos2d::ui::TouchEventType t) {
                if (t != cocos2d::ui::TOUCH_EVENT_ENDED) return;
                if (!secMode) {
                    ++directOpens;
                    spawnRaffle();
                } else {
                    if (secondaryOpen) { closeSec(); return; }
                    secondaryOpen = true;
                    ++secOpens;
                    secMask = createTouchMaskLayout(luaW, luaH, 0.0f, -yShift);
                    secMask->addTouchEventListener(maskCb, toucheventselector(WidgetCallbackTarget::handleTouch));
                    funcMenu->addChild(secMask);

                    secBg = wglCtx.ready
                        ? static_cast<cocos2d::ui::Widget*>(cocos2d::ui::ImageView::create())
                        : static_cast<cocos2d::ui::Widget*>(cocos2d::ui::Layout::create());
                    secBg->ignoreContentAdaptWithSize(false);
                    secBg->setAnchorPoint(cocos2d::CCPointMake(0.0f, 0.0f));
                    secBg->setPosition(cocos2d::CCPointMake(100.0f, 370.0f));
                    secBg->setSize(cocos2d::CCSizeMake(245.0f, 110.0f));
                    funcMenu->addChild(secBg);

                    auto* jgWrap = cocos2d::ui::Layout::create();
                    jgWrap->setPosition(cocos2d::CCPointMake(68.0f, 10.0f));
                    secBg->addChild(jgWrap);
                    auto* jgBtn = createConfiguredTouchWidget(
                        wglCtx.ready, 119.0f, 112.0f, 0.8f, cocos2d::CCPointMake(0.5f, 0.0f));
                    jgBtn->addTouchEventListener(jgCb, toucheventselector(WidgetCallbackTarget::handleTouch));
                    jgWrap->addChild(jgBtn);
                }
            };
            choukaBtn->addTouchEventListener(choukaCb, toucheventselector(WidgetCallbackTarget::handleTouch));
            stage->onEnter();
            stage->onEnterTransitionDidFinish();

            auto sceneToClient = [&](float sx, float sy) -> POINT {
                const float glX = stX + sx * stScale, glY = stY + sy * stScale;
                const cocos2d::CCRect vp = testView->getViewPortRect();
                return POINT{
                    static_cast<LONG>(std::lround((glX * testView->getScaleX() + vp.origin.x) * zoom)),
                    static_cast<LONG>(std::lround(((cppDesign.height - glY) * testView->getScaleY() + vp.origin.y) * zoom))
                };
            };

            const POINT choukaPt = sceneToClient(50.0f, yShift + ((cycleIdx % 2 == 0) ? 444.8f : 435.0f));
            const WPARAM clickWParam = (cycleIdx % 3 == 1) ? (MK_LBUTTON | MK_CONTROL)
                                     : (cycleIdx % 3 == 2) ? static_cast<WPARAM>(0)
                                                           : static_cast<WPARAM>(MK_LBUTTON);

            if (cycleIdx == 0) {
                const POINT missPt = sceneToClient(50.0f, yShift + 392.0f);
                dispatchWin32ClickViaWindowProc(testHwnd, missPt.x, missPt.y, MK_LBUTTON);
                PHASE_REQUIRE(!raffleOpen && !secondaryOpen, failReason, "Hit below bottom-center anchor y=400");
                ::SendMessageW(testHwnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(choukaPt.x, choukaPt.y));
                ::SendMessageW(testHwnd, WM_CAPTURECHANGED, 0, reinterpret_cast<LPARAM>(wglCtx.hwnd));
                PHASE_REQUIRE(!raffleOpen && !secondaryOpen, failReason, "WM_CAPTURECHANGED did not cancel touch");
            }

            std::printf("[InputRoute] cycle=%02d mode=%s res=%dx%d@%d%% client=%ldx%ld cppDesign=%.0fx%.0f clickClient=(%ld,%ld) wParam=0x%llX\n",
                        cycleIdx + 1, secMode ? "Lv50_Secondary" : "Direct_Raffle",
                        rc.baseW, rc.baseH, rc.dpiPct,
                        clientRc.right - clientRc.left, clientRc.bottom - clientRc.top,
                        cppDesign.width, cppDesign.height, choukaPt.x, choukaPt.y,
                        static_cast<unsigned long long>(clickWParam));
            dispatchWin32ClickViaWindowProc(testHwnd, choukaPt.x, choukaPt.y, clickWParam);
            const POINT closePt = sceneToClient(1060.0f, 580.0f + yShift);
            if (!secMode) {
                const int prevOpens = directOpens;
                PHASE_REQUIRE(raffleOpen, failReason, "Direct Tửu Quán open failed");
                dispatchWin32ClickViaWindowProc(testHwnd, choukaPt.x, choukaPt.y, MK_LBUTTON);
                PHASE_REQUIRE(directOpens == prevOpens, failReason, "Modal RaffleMainPanel did not swallow click");
                dispatchWin32ClickViaWindowProc(testHwnd, closePt.x, closePt.y, MK_LBUTTON);
                PHASE_REQUIRE(!raffleOpen, failReason, "RaffleMainPanel close failed");
            } else {
                PHASE_REQUIRE(secondaryOpen, failReason, "Secondary simg_bg open failed");
                const POINT jgPt = sceneToClient(168.0f, yShift + 424.8f);
                dispatchWin32ClickViaWindowProc(testHwnd, jgPt.x, jgPt.y, MK_LBUTTON);
                PHASE_REQUIRE(!secondaryOpen && raffleOpen, failReason, "Secondary jiuguan open failed");
                dispatchWin32ClickViaWindowProc(testHwnd, closePt.x, closePt.y, MK_LBUTTON);
                PHASE_REQUIRE(!raffleOpen, failReason, "RaffleMainPanel close failed after jiuguan");
            }
            PHASE_REQUIRE(touchFxProbe->beganCount >= 2, failReason, "TouchEffectManager (-123) missed touches");
            return true;
        };

        for (int i = 0; i < 12 && failReason.empty(); ++i) { if (!runCycle(i, kCases[i], false)) break; ++completedCycles; }
        for (int i = 0; i < 12 && failReason.empty(); ++i) { if (!runCycle(12 + i, kCases[i], true)) break; ++completedCycles; }

        std::string sendInputVerdict;
        if (failReason.empty()) {
            const SendInputProbeStatus siProbe = probeInteractiveSendInput(testHwnd);
            if (!siProbe.available) {
                sendInputVerdict = "BLOCKED (" + siProbe.reason + ")";
            } else {
                testView->setFrameZoomFactor(1.0f);
                testView->setFrameSize(1136.0f, 640.0f);
                testView->setDesignResolutionSize(1136.0f, 640.0f, kResolutionFixedWidth);
                auto* siScene = cocos2d::CCScene::create(); siScene->retain();
                auto* siGroup = cocos2d::ui::TouchGroup::create(); siGroup->setTouchPriority(-2);
                auto* siBtn = createConfiguredTouchWidget(
                    wglCtx.ready, 119.0f, 112.0f, 0.8f, cocos2d::CCPointMake(0.5f, 0.0f));
                siBtn->setPosition(cocos2d::CCPointMake(50.0f, 400.0f));
                bool siHit = false;
                auto* siCb = new WidgetCallbackTarget();
                siCb->onEvent = [&](cocos2d::CCObject*, cocos2d::ui::TouchEventType t) {
                    if (t == cocos2d::ui::TOUCH_EVENT_ENDED) siHit = true;
                };
                siBtn->addTouchEventListener(siCb, toucheventselector(WidgetCallbackTarget::handleTouch));
                siGroup->addWidget(siBtn);
                siScene->addChild(siGroup);
                siScene->onEnter();

                std::string siErr;
                const bool sentOk = dispatchWin32ClickViaSendInput(testHwnd, 50, 195, siErr);
                siScene->onExit(); siScene->cleanup(); siScene->release(); siCb->release();
                sendInputVerdict = (!sentOk || !siHit)
                    ? ("BLOCKED (" + (siErr.empty() ? std::string("UIPI/desktop filter swallowed SendInput") : siErr) + ")")
                    : std::string("OK (hardware queue delivered)");
            }
            std::printf("[InputRoute] SendInput=%s\n", sendInputVerdict.c_str());
        }

        std::fflush(stdout);
        PHASE_REQUIRE(failReason.empty(), detail, failReason);
        detail = "cycles=" + std::to_string(completedCycles) + " direct=" + std::to_string(directOpens) +
                 " sec=" + std::to_string(secOpens) + " jiuguan=" + std::to_string(jgOpens) +
                 " closes=" + std::to_string(panelCloses) + " sendInput=" + sendInputVerdict;
        return completedCycles == 24 && directOpens == 12 && secOpens == 12 &&
               jgOpens == 12 && panelCloses == 24;
    });

    // Phase 6 (Issue #8): >= 50 iterations of GainItemListInfoPanel / GainItemCell widget lifecycle
    runPhase("phase5_issue8_widget_lifecycle_and_imageview_icons", [&](std::string& detail) -> bool {
        cocos2d::CCSpriteFrame* frame5 = nullptr;
        if (wglCtx.ready) {
            fs::create_directories(tempFixture / L"gameImage" / L"item");
            const std::vector<uint8_t> iconPng = buildValidRgbaPng(98, 98);
            {
                std::ofstream iconOut(tempFixture / L"gameImage" / L"item" / L"jinjiedan.png", std::ios::binary);
                iconOut.write(reinterpret_cast<const char*>(iconPng.data()),
                              static_cast<std::streamsize>(iconPng.size()));
            }
            std::string texErr;
            cocos2d::CCTexture2D* frameTex = decodePngIntoTextureCache(
                buildValidRgbaPng(100, 100), 100, 100, "issue8_frame_5_atlas", texErr);
            PHASE_REQUIRE(frameTex != nullptr, detail, texErr);
            frame5 = cocos2d::CCSpriteFrame::createWithTexture(
                frameTex, cocos2d::CCRect(0.0f, 0.0f, 100.0f, 100.0f));
            cocos2d::CCSpriteFrameCache::sharedSpriteFrameCache()->addSpriteFrame(frame5, "frame_5.png");
        }

        auto makeFrameOrNode = [&]() -> cocos2d::CCNode* {
            return frame5 ? static_cast<cocos2d::CCNode*>(cocos2d::CCSprite::createWithSpriteFrame(frame5))
                          : cocos2d::CCNode::create();
        };

        constexpr int kLoops = 60;
        for (int iter = 0; iter < kLoops; ++iter) {
            auto* itemContainer = cocos2d::ui::Layout::create();
            itemContainer->retain();
            auto relContainer = makeScopeExit([itemContainer]() noexcept { itemContainer->release(); });

            for (int c = 0; c < 5; ++c) {
                auto* cell = cocos2d::ui::Layout::create();
                itemContainer->addChild(cell);

                cocos2d::CCNode* glow = makeFrameOrNode();
                glow->setPosition(cocos2d::CCPoint(87.0f, 69.0f));
                glow->setScale(1.2f);
                cell->addNode(glow, -1, 101);

                auto* iconItem = cocos2d::ui::Layout::create();
                iconItem->setPosition(cocos2d::CCPoint(40.0f, 0.0f));
                cell->addChild(iconItem);

                if (wglCtx.ready) {
                    auto* iconQuality = createSizedLocalImage(iconItem, "gameImage/frame/frame_5.png", 100.0f);
                    auto* icon = createSizedLocalImage(iconItem, "gameImage/item/jinjiedan.png", 98.0f);
                    auto* lbName = cocos2d::ui::Label::create();
                    lbName->setText("Tiến Cấp Đơn");
                    iconItem->addChild(lbName);

                    auto* qVr = dynamic_cast<cocos2d::CCSprite*>(iconQuality->getVirtualRenderer());
                    auto* iVr = dynamic_cast<cocos2d::CCSprite*>(icon->getVirtualRenderer());
                    PHASE_REQUIRE(qVr && qVr->getTexture() && qVr->getContentSize().width > 0.0f && qVr->getScaleX() > 0.0f &&
                                      iVr && iVr->getTexture() && iVr->getContentSize().width > 0.0f && iVr->getScaleX() > 0.0f,
                                  detail, "ImageView virtualRenderer missing texture or zero scale on iter=" + std::to_string(iter));
                }

                auto* fade = cocos2d::CCFadeIn::create(14.0f / 60.0f);
                fade->startWithTarget(cell);
                fade->update(0.0f);
                fade->update(1.0f);
                PHASE_REQUIRE(cell->getOpacity() == 255 && cell->getDisplayedOpacity() == 255,
                              detail, "CCFadeIn failed to restore Widget/CCNodeRGBA opacity=255");

                cocos2d::CCNode* fxNode = makeFrameOrNode();
                const unsigned int baseRef = fxNode->retainCount();
                cell->addNode(fxNode, 0, 202);
                PHASE_REQUIRE(cell->getNodes() && cell->getNodes()->count() == 2u,
                              detail, "Expected 2 nodes after addNode(fxNode)");
                fxNode->removeFromParentAndCleanup(true);
                PHASE_REQUIRE(cell->getNodes()->count() == 1u &&
                                  !cell->getNodes()->containsObject(fxNode) &&
                                  fxNode->retainCount() == baseRef,
                              detail, "Stale pointer or leaked retainCount in Widget::getNodes() after removeFromParentAndCleanup");

                if (c % 2 == 0) {
                    cell->removeAllChildrenWithCleanup(true);
                    PHASE_REQUIRE(cell->getNodes()->count() == 0u && cell->getChildren()->count() == 0u,
                                  detail, "Widget::removeAllChildrenWithCleanup failed to clear _nodes");
                }
            }

            itemContainer->removeAllChildrenWithCleanup(true);
            PHASE_REQUIRE(itemContainer->getNodes()->count() == 0u && itemContainer->getChildren()->count() == 0u,
                          detail, "itemContainer->removeAllChildrenWithCleanup left stale children/nodes");
            relContainer.release();
            itemContainer->release();
            cocos2d::CCPoolManager::sharedPoolManager()->pop();
        }

        detail = "60 GainItemListInfoPanel/GainItemCell lifecycle + ImageView/CCFadeIn iterations passed cleanly";
        return true;
    });

    // Phase 7: Issue #8 Armature BitCache/Plistb + WGL Offscreen Starburst Seam & Glow Ring glReadPixels
    runPhase("phase5_armature_seam_and_glow_wgl_pixels", [&](std::string& detail) -> bool {
        PHASE_REQUIRE(gclient::assets::XmlbArmatureLoader::ClampColorChannel(260) == 255u &&
                          gclient::assets::XmlbArmatureLoader::ClampColorChannel(-5) == 0u,
                      detail, "XmlbArmatureLoader::ClampColorChannel failed [0,255] bounds");
        if (!wglCtx.gl11Ready) {
            detail = "WGL 1.1 unavailable in headless session; skipped glReadPixels";
            return true;
        }

        constexpr int kAtlasDim = 64;
        std::vector<uint8_t> atlas(kAtlasDim * kAtlasDim * 4, 0u);
        for (int y = 2; y < 18; ++y) {
            for (int x = 2; x < 18; ++x) {
                const size_t idx = static_cast<size_t>((y * kAtlasDim + x) * 4);
                atlas[idx + 0] = 220u;
                atlas[idx + 1] = 200u;
                atlas[idx + 2] = 140u;
                atlas[idx + 3] = 220u;
            }
        }

        GLuint texId = 0;
        glGenTextures(1, &texId);
        glBindTexture(GL_TEXTURE_2D, texId);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        const GLint wrapMode = GLEW_VERSION_1_2 ? GL_CLAMP_TO_EDGE : GL_CLAMP;
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, wrapMode);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, wrapMode);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, kAtlasDim, kAtlasDim, 0, GL_RGBA, GL_UNSIGNED_BYTE, atlas.data());

        glViewport(0, 0, 64, 64);
        glMatrixMode(GL_PROJECTION); glLoadIdentity(); glOrtho(0.0, 64.0, 0.0, 64.0, -1.0, 1.0);
        glMatrixMode(GL_MODELVIEW); glLoadIdentity();
        glEnable(GL_TEXTURE_2D);
        glEnable(GL_BLEND);
        glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
        glClearColor(18.0f / 255.0f, 18.0f / 255.0f, 24.0f / 255.0f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        glColor4ub(255, 255, 255, 255);

        const float uCut = 2.5f / 64.0f, uOuter = 18.0f / 64.0f;
        const float vOuter = 2.0f / 64.0f, vCut = 17.5f / 64.0f;
        const float signs[4][2] = {{1.0f, 1.0f}, {-1.0f, 1.0f}, {1.0f, -1.0f}, {-1.0f, -1.0f}};
        for (const auto& s : signs) {
            const float x0 = 32.0f, x1 = 32.0f + s[0] * 32.0f;
            const float y0 = 32.0f, y1 = 32.0f + s[1] * 32.0f;
            glBegin(GL_QUADS);
            glTexCoord2f(uCut, vCut);     glVertex2f(x0, y0);
            glTexCoord2f(uOuter, vCut);   glVertex2f(x1, y0);
            glTexCoord2f(uOuter, vOuter); glVertex2f(x1, y1);
            glTexCoord2f(uCut, vOuter);   glVertex2f(x0, y1);
            glEnd();
        }
        glFinish();

        std::vector<uint8_t> fb(64 * 64 * 4, 0u);
        glReadPixels(0, 0, 64, 64, GL_RGBA, GL_UNSIGNED_BYTE, fb.data());
        glDeleteTextures(1, &texId);

        const int centerR = fb[(32 * 64 + 32) * 4 + 0];
        const int seamXR  = fb[(40 * 64 + 32) * 4 + 0];
        const int seamYR  = fb[(32 * 64 + 40) * 4 + 0];
        const int innerR  = fb[(40 * 64 + 40) * 4 + 0];
        detail = "centerR=" + std::to_string(centerR) +
                 " seamXR=" + std::to_string(seamXR) +
                 " seamYR=" + std::to_string(seamYR) +
                 " innerR=" + std::to_string(innerR);
        return innerR >= 200 && std::abs(centerR - innerR) <= 2 &&
               std::abs(seamXR - innerR) <= 2 && std::abs(seamYR - innerR) <= 2;
    });

    g_watchdogStop.store(true, std::memory_order_release);
    if (watchdog.joinable()) watchdog.join();
    if (hMainThread != nullptr) ::CloseHandle(hMainThread);

    writeJsonReport(jsonOutPath, anyFailed ? "FAILED" : "PASSED", primaryRva, nearbySyms, "");
    return (anyFailed && !probeOnly) ? 1 : 0;
}
