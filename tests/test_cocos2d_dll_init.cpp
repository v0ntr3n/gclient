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

#include "assets/BtDecryptHook.h"
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

inline DWORD64 uptrToAddr64(uintptr_t v) noexcept {
    return static_cast<DWORD64>(v);
}

std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int needed = ::MultiByteToWideChar(
        CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring w(static_cast<size_t>(needed), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), needed);
    return w;
}

std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int needed = ::WideCharToMultiByte(
        CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(c));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
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

struct PhaseResult {
    std::string name;
    bool passed = false;
    uint64_t durationMs = 0;
    std::string detail;
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
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(moduleBase + static_cast<uintptr_t>(dos->e_lfanew));
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
    const auto* ords = reinterpret_cast<const uint16_t*>(moduleBase + exp->AddressOfNameOrdinals);
    const auto* funcs = reinterpret_cast<const uint32_t*>(moduleBase + exp->AddressOfFunctions);

    out.reserve(exp->NumberOfNames);
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const uint32_t nameRva = names[i];
        const uint16_t ord = ords[i];
        if (nameRva == 0 || nameRva >= moduleSize || ord >= exp->NumberOfFunctions) continue;
        const uint32_t fnRva = funcs[ord];
        // Skip export forwarders pointing inside export directory
        if (fnRva >= dir.VirtualAddress && fnRva < dir.VirtualAddress + dir.Size) continue;
        const char* rawName = reinterpret_cast<const char*>(moduleBase + nameRva);
        char undec[512] = {};
        std::string pretty = rawName;
        if (::UnDecorateSymbolName(rawName, undec, sizeof(undec) - 1, UNDNAME_COMPLETE) > 0) {
            pretty = undec;
        }
        out.push_back(ExportEntry{fnRva, std::move(pretty)});
    }
    std::sort(out.begin(), out.end(), [](const ExportEntry& a, const ExportEntry& b) {
        return a.rva < b.rva;
    });
}

void initDbgHelpForProcess(const std::string& extraSearchDir) {
    std::lock_guard<std::mutex> lk(g_symMutex);
    if (g_symReady) return;

    wchar_t exePathW[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, exePathW, MAX_PATH);
    fs::path exeDir = fs::path(exePathW).parent_path();

    std::string searchPath = wideToUtf8(exeDir.wstring());
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
            ::SymLoadModuleEx(
                ::GetCurrentProcess(),
                nullptr,
                g_cocosPath.c_str(),
                "libcocos2d.dll",
                uptrToAddr64(g_cocosBase),
                g_cocosSize,
                nullptr,
                0);
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
            g_cocosExports.begin(),
            g_cocosExports.end(),
            rva,
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
        std::snprintf(errBuf, sizeof(errBuf), "<SymFromAddr-err-%lu>", static_cast<unsigned long>(::GetLastError()));
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
            reinterpret_cast<LPCSTR>(addr),
            &hMod) &&
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
std::vector<PhaseResult> g_phaseResults;

void writeJsonReport(const std::string& jsonPath,
                     const std::string& verdict,
                     const RvaSymbolInfo& primaryRva,
                     const std::vector<RvaSymbolInfo>& nearbySyms,
                     const std::string& hangDiagnostic) {
    if (jsonPath.empty()) return;
    std::ofstream ofs(fs::path(utf8ToWide(jsonPath)), std::ios::binary | std::ios::trunc);
    if (!ofs) return;

    ofs << "{\n";
    ofs << "  \"verdict\": \"" << jsonEscape(verdict) << "\",\n";
    ofs << "  \"libcocos2d_base_hex\": \"0x" << std::hex << g_cocosBase << std::dec << "\",\n";
    ofs << "  \"libcocos2d_size_hex\": \"0x" << std::hex << g_cocosSize << std::dec << "\",\n";
    ofs << "  \"libcocos2d_exports_parsed\": " << g_cocosExports.size() << ",\n";
    ofs << "  \"target_rva_hex\": \"0x" << std::hex << primaryRva.rva << std::dec << "\",\n";
    ofs << "  \"target_symbol\": \"" << jsonEscape(primaryRva.symbolName) << "\",\n";
    ofs << "  \"target_symbol_disp_hex\": \"0x" << std::hex << primaryRva.symbolDisplacement << std::dec << "\",\n";
    ofs << "  \"nearest_export\": \"" << jsonEscape(primaryRva.nearestExportName) << "\",\n";
    ofs << "  \"nearest_export_rva_hex\": \"0x" << std::hex << primaryRva.nearestExportRva << std::dec << "\",\n";
    ofs << "  \"target_source_file\": \"" << jsonEscape(primaryRva.sourceFile) << "\",\n";
    ofs << "  \"target_source_line\": " << primaryRva.sourceLine << ",\n";
    ofs << "  \"target_bytes_hex\": \"" << jsonEscape(primaryRva.bytesHex) << "\",\n";
    ofs << "  \"hang_diagnostic\": \"" << jsonEscape(hangDiagnostic) << "\",\n";
    ofs << "  \"nearby_rvas\": [\n";
    for (size_t i = 0; i < nearbySyms.size(); ++i) {
        const auto& ns = nearbySyms[i];
        ofs << "    {\"rva\": \"0x" << std::hex << ns.rva << std::dec
            << "\", \"symbol\": \"" << jsonEscape(ns.symbolName)
            << "+0x" << std::hex << ns.symbolDisplacement << std::dec
            << "\", \"file\": \"" << jsonEscape(ns.sourceFile)
            << "\", \"line\": " << ns.sourceLine << "}"
            << (i + 1 < nearbySyms.size() ? "," : "") << "\n";
    }
    ofs << "  ],\n";
    ofs << "  \"phases\": [\n";
    for (size_t i = 0; i < g_phaseResults.size(); ++i) {
        const auto& pr = g_phaseResults[i];
        ofs << "    {\"name\": \"" << jsonEscape(pr.name)
            << "\", \"passed\": " << (pr.passed ? "true" : "false")
            << ", \"duration_ms\": " << pr.durationMs
            << ", \"detail\": \"" << jsonEscape(pr.detail) << "\"}"
            << (i + 1 < g_phaseResults.size() ? "," : "") << "\n";
    }
    ofs << "  ]\n";
    ofs << "}\n";
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
        if (len > 0 && data != nullptr) {
            out.insert(out.end(), data, data + len);
        }
        uLong crc = ::crc32(0L, Z_NULL, 0);
        crc = ::crc32(crc, out.data() + typeOffset, 4u + len);
        appendBE32(out, static_cast<uint32_t>(crc));
    };

    std::vector<uint8_t> png = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};

    std::vector<uint8_t> ihdr;
    appendBE32(ihdr, width);
    appendBE32(ihdr, height);
    ihdr.push_back(8);
    ihdr.push_back(6);
    ihdr.push_back(0);
    ihdr.push_back(0);
    ihdr.push_back(0);
    appendChunk(png, "IHDR", ihdr.data(), static_cast<uint32_t>(ihdr.size()));

    const size_t rowStride = 1u + static_cast<size_t>(width) * 4u;
    std::vector<uint8_t> rawScanlines(rowStride * static_cast<size_t>(height), 0u);
    for (uint32_t y = 0; y < height; ++y) {
        uint8_t* row = rawScanlines.data() + static_cast<size_t>(y) * rowStride;
        row[0] = 0;
        for (uint32_t x = 0; x < width; ++x) {
            row[1 + x * 4 + 0] = static_cast<uint8_t>((x * 7u + y) & 0xFFu);
            row[1 + x * 4 + 1] = static_cast<uint8_t>((y * 13u) & 0xFFu);
            row[1 + x * 4 + 2] = 0xCCu;
            row[1 + x * 4 + 3] = 0xFFu;
        }
    }

    uLongf compCap = ::compressBound(static_cast<uLong>(rawScanlines.size()));
    std::vector<uint8_t> idat(static_cast<size_t>(compCap));
    if (::compress2(idat.data(), &compCap, rawScanlines.data(), static_cast<uLong>(rawScanlines.size()), Z_BEST_SPEED) == Z_OK) {
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

        int pf = ::ChoosePixelFormat(hdc, &pfd);
        if (pf == 0 || !::SetPixelFormat(hdc, pf, &pfd)) return;

        hglrc = ::wglCreateContext(hdc);
        if (!hglrc || !::wglMakeCurrent(hdc, hglrc)) return;
        gl11Ready = true;

        glewExperimental = GL_TRUE;
        const GLenum glewRc = ::glewInit();
        const GLubyte* ver = ::glGetString(GL_VERSION);
        if (ver) {
            glVersion = reinterpret_cast<const char*>(ver);
        }
        // Headless Windows Hyper-V GDI Generic only exposes OpenGL 1.1.0 (`glCreateProgram == nullptr`);
        // Cocos2d-x 2.2.6 CCShaderCache / CCSprite / VBOs strictly require OpenGL 2.0 entry points.
        ready = (glewRc == GLEW_OK) && GLEW_VERSION_2_0 &&
                (glCreateProgram != nullptr) && (glGenBuffers != nullptr);
    }

    ~ScopedDummyWglContext() {
        if (hglrc) {
            ::wglMakeCurrent(nullptr, nullptr);
            ::wglDeleteContext(hglrc);
        }
        if (hwnd && hdc) {
            ::ReleaseDC(hwnd, hdc);
        }
        if (hwnd) {
            ::DestroyWindow(hwnd);
        }
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
        const float vpW = m_obDesignResolutionSize.width * m_fScaleX, vpH = m_obDesignResolutionSize.height * m_fScaleY;
        m_obViewPortRect.setRect((m_obScreenSize.width - vpW) * 0.5f, (m_obScreenSize.height - vpH) * 0.5f, vpW, vpH);
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
        if (auto* td = cocos2d::CCDirector::sharedDirector()->getTouchDispatcher()) td->addTargetedDelegate(this, m_prio, false);
    }
    void onExit() override {
        if (auto* td = cocos2d::CCDirector::sharedDirector()->getTouchDispatcher()) td->removeDelegate(this);
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
    void handleTouch(cocos2d::CCObject* s, cocos2d::ui::TouchEventType t) { if (onEvent) onEvent(s, t); }
};

struct SendInputProbeStatus { bool available = false; std::string reason; };

SendInputProbeStatus probeInteractiveSendInput(HWND targetHwnd) {
    DWORD sessionId = 0;
    if (!::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionId) || sessionId == 0) {
        return {false, "Session-0 non-interactive service session"};
    }
    if (HWINSTA hWinSta = ::GetProcessWindowStation()) {
        USEROBJECTFLAGS uof{};
        DWORD len = 0;
        if (::GetUserObjectInformationW(hWinSta, UOI_FLAGS, &uof, sizeof(uof), &len) && (uof.dwFlags & WSF_VISIBLE) == 0) {
            return {false, "WindowStation lacks WSF_VISIBLE (headless/non-interactive)"};
        }
    }
    HDESK hDesk = ::OpenInputDesktop(0, FALSE, DESKTOP_WRITEOBJECTS | DESKTOP_JOURNALPLAYBACK);
    if (!hDesk) return {false, "OpenInputDesktop denied/locked (err=" + std::to_string(::GetLastError()) + ")"};
    ::CloseDesktop(hDesk);
    wchar_t ciBuf[16] = {};
    if (::GetEnvironmentVariableW(L"GITHUB_ACTIONS", ciBuf, 16) > 0 && std::wcscmp(ciBuf, L"true") == 0) {
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
        while (::PeekMessageW(&msg, hwnd, 0, 0, PM_REMOVE)) { ::TranslateMessage(&msg); ::DispatchMessageW(&msg); }
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
    std::printf(
        "[CocosInitTest] libcocos2d.dll base=0x%08zX size=0x%08X exports=%zu\n",
        static_cast<size_t>(g_cocosBase),
        g_cocosSize,
        g_cocosExports.size());
    std::printf(
        "[CocosInitTest] RVA +0x%X -> %s + 0x%llX [%s:%u] (nearestExport=%s @ +0x%X)\n",
        primaryRva.rva,
        primaryRva.symbolName.c_str(),
        static_cast<unsigned long long>(primaryRva.symbolDisplacement),
        primaryRva.sourceFile.c_str(),
        primaryRva.sourceLine,
        primaryRva.nearestExportName.c_str(),
        primaryRva.nearestExportRva);
    std::printf("[CocosInitTest] Bytes @ +0x%X: %s\n", primaryRva.rva, primaryRva.bytesHex.c_str());
    std::fflush(stdout);

    std::vector<RvaSymbolInfo> nearbySyms;
    const int32_t offsets[] = {-0x200, -0x100, -0x80, -0x40, -0x20, -0x10, 0, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200};
    for (int32_t off : offsets) {
        if (off < 0 && static_cast<uint32_t>(-off) > targetRva) continue;
        const uint32_t probe = static_cast<uint32_t>(static_cast<int64_t>(targetRva) + off);
        nearbySyms.push_back(resolveCocosRva(probe, 0));
    }

    HANDLE hMainThread = nullptr;
    ::DuplicateHandle(
        ::GetCurrentProcess(),
        ::GetCurrentThread(),
        ::GetCurrentProcess(),
        &hMainThread,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE,
        0);

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
                            if (!::StackWalk64(
                                    IMAGE_FILE_MACHINE_I386,
                                    ::GetCurrentProcess(),
                                    hMainThread,
                                    &sf,
                                    &walkCtx,
                                    nullptr,
                                    ::SymFunctionTableAccess64,
                                    ::SymGetModuleBase64,
                                    nullptr)) {
                                break;
                            }
                            if (sf.AddrPC.Offset == 0) break;
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
        {
            std::lock_guard<std::mutex> lk(g_phaseMutex);
            g_activePhaseName = phaseName;
        }
        const uint64_t t0 = ::GetTickCount64();
        g_phaseStartTick.store(t0, std::memory_order_release);
        std::printf("[PHASE] %s ...\n", phaseName);
        std::fflush(stdout);

        std::string detail;
        bool ok = false;
        try {
            ok = fn(detail);
        } catch (const std::exception& ex) {
            detail = std::string("std::exception: ") + ex.what();
            ok = false;
        } catch (...) {
            detail = "unknown C++ exception";
            ok = false;
        }
        const uint64_t dt = ::GetTickCount64() - t0;
        g_phaseResults.push_back(PhaseResult{phaseName, ok, dt, detail});
        std::printf("[%s] %s (%llu ms) %s\n",
                    ok ? " OK  " : "FAIL ",
                    phaseName,
                    static_cast<unsigned long long>(dt),
                    detail.c_str());
        std::fflush(stdout);
        if (!ok) {
            anyFailed = true;
        }
    };

    const fs::path tempFixture = fs::temp_directory_path() /
        fs::path(utf8ToWide("kestrel_cocos_init_Tiếng_Việt_" + std::to_string(::GetCurrentProcessId())));
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
        if (!fu) {
            detail = "CCFileUtils::sharedFileUtils() returned null";
            return false;
        }
        fu->setPopupNotify(false);

        std::vector<std::string> paths;
        std::string rootUtf8 = wideToUtf8(tempFixture.wstring());
        for (char& ch : rootUtf8) {
            if (ch == '\\') ch = '/';
        }
        paths.push_back(rootUtf8);
        paths.push_back("Resources");
        fu->setSearchPaths(paths);
        fu->setDecrypt(&bt_decrypt);
        gclient::assets::InstallBtDecryptHook(fu);

        const auto searchCopy = fu->getSearchPaths();
        // Regression guard for Issue #8: verify non-existent ASCII & UTF-8 paths do not tail-recurse.
        if (fu->isFileExist("cc_fps_images") || fu->isFileExist("nonexistent_Tửu_Quán_probe.png")) {
            detail = "isFileExist unexpectedly returned true for non-existent probe path";
            return false;
        }
        const std::string resolved = fu->fullPathForFilename("scripts/boot_probe.lua");
        if (resolved.empty() || !fu->isFileExist(resolved)) {
            detail = "Failed to resolve UTF-8 path scripts/boot_probe.lua -> " + resolved;
            return false;
        }
        unsigned long sz = 0;
        unsigned char* buf = fu->getFileData(resolved.c_str(), "rb", &sz);
        const bool ok = (buf != nullptr && sz > 0 && !searchCopy.empty());
        delete[] buf;
        detail = "resolved=" + resolved + " bytes=" + std::to_string(sz) + " searchPaths=" + std::to_string(searchCopy.size());
        return ok;
    });

    // Phase 2: CCImage PNG decode (libpng.lib + vcpkg libz.dll) + CCTextureCache + CCLabelAtlas
    runPhase("phase2_ccimage_png_and_label_atlas", [&](std::string& detail) -> bool {
        const std::vector<uint8_t> pngData = buildValidRgbaPng(256, 32);
        auto* img = new cocos2d::CCImage();
        if (!img->initWithImageData(
                const_cast<uint8_t*>(pngData.data()),
                static_cast<int>(pngData.size()),
                cocos2d::CCImage::kFmtPng)) {
            img->release();
            detail = "CCImage::initWithImageData(kFmtPng, 256x32) returned false";
            return false;
        }
        if (img->getWidth() != 256 || img->getHeight() != 32 || img->getData() == nullptr) {
            img->release();
            detail = "Unexpected decoded PNG dimensions";
            return false;
        }

        if (wglCtx.ready) {
            cocos2d::CCTextureCache* cache = cocos2d::CCTextureCache::sharedTextureCache();
            cocos2d::CCTexture2D* tex = cache ? cache->addUIImage(img, "cc_fps_images_probe") : nullptr;
            img->release();
            if (!tex) {
                detail = "CCTextureCache::addUIImage failed under WGL (" + wglCtx.glVersion + ")";
                return false;
            }
            auto* label = new cocos2d::CCLabelAtlas();
            const bool lblOk = label->initWithString("00.0", tex, 12, 32, '.');
            if (lblOk) {
                label->setString("59.9");
                label->setTexture(tex);
                label->updateAtlasValues();
            }
            label->release();
            if (!lblOk) {
                detail = "CCLabelAtlas::initWithString('00.0', tex, 12, 32, '.') returned false";
                return false;
            }
        } else {
            img->release();
        }
        detail = "PNG 256x32 decoded cleanly; WGL20=" + (wglCtx.ready ? wglCtx.glVersion : ("unavailable(gl=" + wglCtx.glVersion + ")"));
        return true;
    });

    // Phase 3: CCConfiguration + gatherGPUInfo + dumpInfo + CCDirector + CCScheduler + SimpleAudioEngine
    runPhase("phase3_configuration_director_scheduler", [&](std::string& detail) -> bool {
        cocos2d::CCDirector* dir = cocos2d::CCDirector::sharedDirector();
        if (!dir) {
            detail = "CCDirector::sharedDirector() returned null";
            return false;
        }
        cocos2d::CCConfiguration* conf = cocos2d::CCConfiguration::sharedConfiguration();
        if (!conf) {
            detail = "CCConfiguration::sharedConfiguration() returned null";
            return false;
        }
        if (wglCtx.ready) {
            conf->gatherGPUInfo();
        }
        conf->dumpInfo();

        dir->setAnimationInterval(1.0 / 30.0);
        dir->setDisplayStats(true);

        if (auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine()) {
            audio->setBackgroundMusicVolume(0.0f);
            audio->setEffectsVolume(0.0f);
        }

        cocos2d::CCScheduler* sched = dir->getScheduler();
        if (!sched) {
            detail = "CCDirector::getScheduler() returned null";
            return false;
        }
        using cocos2d::SEL_SCHEDULE;
        auto* dummy = new DummyTickTarget();
        sched->unscheduleSelector(schedule_selector(DummyTickTarget::onTick), dummy);
        sched->scheduleSelector(schedule_selector(DummyTickTarget::onTick), dummy, 0.0f, false);
        sched->unscheduleAllForTarget(dummy);
        sched->scheduleUpdateForTarget(dummy, 0, false);
        sched->update(0.016f);
        sched->unscheduleAllForTarget(dummy);
        const int ticks = dummy->ticks;
        dummy->release();

        detail = "ticks=" + std::to_string(ticks) + " maxTex=" + std::to_string(conf->getMaxTextureSize());
        return ticks >= 1;
    });

    // Phase 4: CCLuaEngine::defaultEngine + tolua++ bindings + Lua CCFileUtils call
    runPhase("phase4_ccluaengine_and_bindings", [&](std::string& detail) -> bool {
        cocos2d::CCLuaEngine* engine = cocos2d::CCLuaEngine::defaultEngine();
        if (!engine || !engine->getLuaStack() || !engine->getLuaStack()->getLuaState()) {
            detail = "CCLuaEngine::defaultEngine() failed";
            return false;
        }
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
        auto makeTouchBtn = [&]() -> cocos2d::ui::Widget* {
            if (wglCtx.ready) return cocos2d::ui::Button::create();
            return cocos2d::ui::Layout::create();
        };
        using cocos2d::ui::SEL_TouchEvent;
        cocos2d::CCDirector* dir = cocos2d::CCDirector::sharedDirector();
        if (!dir || !dir->getTouchDispatcher()) { detail = "CCDirector/CCTouchDispatcher null"; return false; }

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
        if (!testHwnd) { delete testView; detail = "CreateWindowExW failed"; return false; }
        testView->setHWnd(testHwnd);

        cocos2d::CCEGLView* prevView = DirectorViewTestAccessor::currentView(dir);
        DirectorViewTestAccessor::bindHeadlessView(dir, testView);

        struct ResCase { int baseW, baseH, dpiPct; };
        const ResCase kCases[12] = {
            {960, 640, 100},  {960, 640, 125},  {960, 640, 150},
            {1136, 640, 100}, {1136, 640, 125}, {1136, 640, 150},
            {1280, 720, 100}, {1280, 720, 125}, {1280, 720, 150},
            {1920, 1080, 100},{1920, 1080, 125},{1920, 1080, 150},
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
            const float stX = (cppDesign.height < 640.0f) ? ((cppDesign.width - 1136.0f * stScale) * 0.5f) : ((cppDesign.width - 1136.0f) * 0.5f);
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

            auto* choukaBtn = makeTouchBtn();
            choukaBtn->ignoreContentAdaptWithSize(false);
            choukaBtn->setSize(cocos2d::CCSizeMake(119.0f, 112.0f));
            choukaBtn->setScale(0.8f);
            choukaBtn->setAnchorPoint(cocos2d::CCPointMake(0.5f, 0.0f));
            choukaBtn->setTouchEnabled(true);
            choukaWrap->addChild(choukaBtn);

            auto* tipsMore = cocos2d::ui::Layout::create();
            tipsMore->setPosition(cocos2d::CCPointMake(0.0f, -yShift));
            auto* panelMask = cocos2d::ui::Layout::create();
            panelMask->setSize(cocos2d::CCSizeMake(1.0f, 1.0f));
            panelMask->setPosition(cocos2d::CCPointMake(0.0f, 20.0f));
            panelMask->setTouchEnabled(true);
            tipsMore->addChild(panelMask);
            mainScene->addWidget(tipsMore);

            bool raffleOpen = false, secondaryOpen = false;
            cocos2d::ui::TouchGroup* activeRaffle = nullptr;
            cocos2d::ui::Layout* secMask = nullptr;
            cocos2d::ui::Widget* secBg = nullptr;

            auto* choukaCb = new WidgetCallbackTarget();
            auto* closeCb = new WidgetCallbackTarget();
            auto* maskCb = new WidgetCallbackTarget();
            auto* jgCb = new WidgetCallbackTarget();

            auto spawnRaffle = [&]() {
                if (raffleOpen) return;
                raffleOpen = true;
                activeRaffle = cocos2d::ui::TouchGroup::create();
                activeRaffle->setTouchPriority(-26);
                auto* modalBg = cocos2d::ui::Layout::create();
                modalBg->setSize(cocos2d::CCSizeMake(luaW, luaH));
                modalBg->setPosition(cocos2d::CCPointMake(0.0f, -yShift));
                modalBg->setTouchEnabled(true);
                activeRaffle->addWidget(modalBg);
                modalBg->setZOrder(-2);

                auto* closeBtn = makeTouchBtn();
                closeBtn->ignoreContentAdaptWithSize(false);
                closeBtn->setSize(cocos2d::CCSizeMake(80.0f, 80.0f));
                closeBtn->setPosition(cocos2d::CCPointMake(1060.0f, 580.0f + yShift));
                closeBtn->setTouchEnabled(true);
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
                    secMask = cocos2d::ui::Layout::create();
                    secMask->setSize(cocos2d::CCSizeMake(luaW, luaH));
                    secMask->setPosition(cocos2d::CCPointMake(0.0f, -yShift));
                    secMask->setTouchEnabled(true);
                    secMask->addTouchEventListener(maskCb, toucheventselector(WidgetCallbackTarget::handleTouch));
                    funcMenu->addChild(secMask);

                    secBg = wglCtx.ready ? static_cast<cocos2d::ui::Widget*>(cocos2d::ui::ImageView::create()) : static_cast<cocos2d::ui::Widget*>(cocos2d::ui::Layout::create());
                    secBg->ignoreContentAdaptWithSize(false);
                    secBg->setAnchorPoint(cocos2d::CCPointMake(0.0f, 0.0f));
                    secBg->setPosition(cocos2d::CCPointMake(100.0f, 370.0f));
                    secBg->setSize(cocos2d::CCSizeMake(245.0f, 110.0f));
                    funcMenu->addChild(secBg);

                    auto* jgWrap = cocos2d::ui::Layout::create();
                    jgWrap->setPosition(cocos2d::CCPointMake(68.0f, 10.0f));
                    secBg->addChild(jgWrap);
                    auto* jgBtn = makeTouchBtn();
                    jgBtn->ignoreContentAdaptWithSize(false);
                    jgBtn->setSize(cocos2d::CCSizeMake(119.0f, 112.0f));
                    jgBtn->setScale(0.8f);
                    jgBtn->setAnchorPoint(cocos2d::CCPointMake(0.5f, 0.0f));
                    jgBtn->setTouchEnabled(true);
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

            bool ok = true;
            const POINT choukaPt = sceneToClient(50.0f, yShift + ((cycleIdx % 2 == 0) ? 444.8f : 435.0f));
            const WPARAM clickWParam = (cycleIdx % 3 == 1) ? (MK_LBUTTON | MK_CONTROL)
                                     : (cycleIdx % 3 == 2) ? static_cast<WPARAM>(0) : static_cast<WPARAM>(MK_LBUTTON);

            if (cycleIdx == 0) {
                const POINT missPt = sceneToClient(50.0f, yShift + 392.0f);
                dispatchWin32ClickViaWindowProc(testHwnd, missPt.x, missPt.y, MK_LBUTTON);
                if (raffleOpen || secondaryOpen) { failReason = "Hit below bottom-center anchor y=400"; ok = false; }
                ::SendMessageW(testHwnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(choukaPt.x, choukaPt.y));
                ::SendMessageW(testHwnd, WM_CAPTURECHANGED, 0, reinterpret_cast<LPARAM>(wglCtx.hwnd));
                if (raffleOpen || secondaryOpen) { failReason = "WM_CAPTURECHANGED did not cancel touch"; ok = false; }
            }

            if (ok) {
                std::printf("[InputRoute] cycle=%02d mode=%s res=%dx%d@%d%% client=%ldx%ld cppDesign=%.0fx%.0f clickClient=(%ld,%ld) wParam=0x%llX\n",
                            cycleIdx + 1, secMode ? "Lv50_Secondary" : "Direct_Raffle",
                            rc.baseW, rc.baseH, rc.dpiPct, clientRc.right - clientRc.left, clientRc.bottom - clientRc.top,
                            cppDesign.width, cppDesign.height, choukaPt.x, choukaPt.y, static_cast<unsigned long long>(clickWParam));
                dispatchWin32ClickViaWindowProc(testHwnd, choukaPt.x, choukaPt.y, clickWParam);
                const POINT closePt = sceneToClient(1060.0f, 580.0f + yShift);
                if (!secMode) {
                    const int prevOpens = directOpens;
                    if (!raffleOpen) { failReason = "Direct Tửu Quán open failed"; ok = false; }
                    else {
                        dispatchWin32ClickViaWindowProc(testHwnd, choukaPt.x, choukaPt.y, MK_LBUTTON);
                        if (directOpens != prevOpens) { failReason = "Modal RaffleMainPanel did not swallow click"; ok = false; }
                        dispatchWin32ClickViaWindowProc(testHwnd, closePt.x, closePt.y, MK_LBUTTON);
                        if (raffleOpen) { failReason = "RaffleMainPanel close failed"; ok = false; }
                    }
                } else {
                    if (!secondaryOpen) { failReason = "Secondary simg_bg open failed"; ok = false; }
                    else {
                        const POINT jgPt = sceneToClient(168.0f, yShift + 424.8f);
                        dispatchWin32ClickViaWindowProc(testHwnd, jgPt.x, jgPt.y, MK_LBUTTON);
                        if (secondaryOpen || !raffleOpen) { failReason = "Secondary jiuguan open failed"; ok = false; }
                        else {
                            dispatchWin32ClickViaWindowProc(testHwnd, closePt.x, closePt.y, MK_LBUTTON);
                            if (raffleOpen) { failReason = "RaffleMainPanel close failed after jiuguan"; ok = false; }
                        }
                    }
                }
            }
            if (ok && touchFxProbe->beganCount < 2) { failReason = "TouchEffectManager (-123) missed touches"; ok = false; }

            stage->onExit();
            stage->cleanup();
            stage->release();
            choukaCb->release(); closeCb->release(); maskCb->release(); jgCb->release();
            return ok;
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
                auto* siBtn = makeTouchBtn();
                siBtn->ignoreContentAdaptWithSize(false);
                siBtn->setSize(cocos2d::CCSizeMake(119.0f, 112.0f));
                siBtn->setScale(0.8f);
                siBtn->setAnchorPoint(cocos2d::CCPointMake(0.5f, 0.0f));
                siBtn->setPosition(cocos2d::CCPointMake(50.0f, 400.0f));
                siBtn->setTouchEnabled(true);
                bool siHit = false;
                auto* siCb = new WidgetCallbackTarget();
                siCb->onEvent = [&](cocos2d::CCObject*, cocos2d::ui::TouchEventType t) { if (t == cocos2d::ui::TOUCH_EVENT_ENDED) siHit = true; };
                siBtn->addTouchEventListener(siCb, toucheventselector(WidgetCallbackTarget::handleTouch));
                siGroup->addWidget(siBtn); siScene->addChild(siGroup); siScene->onEnter();

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
        DirectorViewTestAccessor::bindHeadlessView(dir, prevView);
        testView->setHWnd(nullptr);
        ::DestroyWindow(testHwnd);
        delete testView;

        if (!failReason.empty()) { detail = failReason; return false; }
        detail = "cycles=" + std::to_string(completedCycles) + " direct=" + std::to_string(directOpens) +
                 " sec=" + std::to_string(secOpens) + " jiuguan=" + std::to_string(jgOpens) +
                 " closes=" + std::to_string(panelCloses) + " sendInput=" + sendInputVerdict;
        return completedCycles == 24 && directOpens == 12 && secOpens == 12 && jgOpens == 12 && panelCloses == 24;
    });

    g_watchdogStop.store(true, std::memory_order_release);
    if (watchdog.joinable()) {
        watchdog.join();
    }
    if (hMainThread != nullptr) {
        ::CloseHandle(hMainThread);
    }

    std::error_code ec;
    fs::remove_all(tempFixture, ec);

    const std::string verdict = anyFailed ? "FAILED" : "PASSED";
    writeJsonReport(jsonOutPath, verdict, primaryRva, nearbySyms, "");

    if (anyFailed && !probeOnly) {
        return 1;
    }
    return 0;
}
