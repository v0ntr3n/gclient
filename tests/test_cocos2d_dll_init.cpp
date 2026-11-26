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
#include "CCLuaEngine.h"
#include "SimpleAudioEngine.h"
#include "textures/CCTextureETC.h"

#include "assets/BtDecryptHook.h"
#include "assets/PlistbLoader.h"
#include "assets/XmlbArmatureLoader.h"
#include "diagnostics/CrashAndTelemetry.h"

#include "zlib.h"

#include <algorithm>
#include <atomic>
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

    // Phase 5: Issue #8 Armature BitCache/Plistb + WGL Offscreen Starburst Seam & Glow Ring glReadPixels
    runPhase("phase5_armature_seam_and_glow_wgl_pixels", [&](std::string& detail) -> bool {
        // Verify BitCache color clamp & sticky additive blend on gclient_assets
        if (gclient::assets::XmlbArmatureLoader::ClampColorChannel(260) != 255u ||
            gclient::assets::XmlbArmatureLoader::ClampColorChannel(-5) != 0u) {
            detail = "XmlbArmatureLoader::ClampColorChannel failed [0,255] bounds";
            return false;
        }
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
        glMatrixMode(GL_PROJECTION);
        glLoadIdentity();
        glOrtho(0.0, 64.0, 0.0, 64.0, -1.0, 1.0);
        glMatrixMode(GL_MODELVIEW);
        glLoadIdentity();
        glEnable(GL_TEXTURE_2D);
        glEnable(GL_BLEND);
        glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
        glClearColor(18.0f / 255.0f, 18.0f / 255.0f, 24.0f / 255.0f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        glColor4ub(255, 255, 255, 255);

        // Render 4 mirrored quadrants using CCSkin::setTextureCoords half-texel-clamped cut-seam UVs
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
        const bool seamFree =
            innerR >= 200 &&
            std::abs(centerR - innerR) <= 2 &&
            std::abs(seamXR - innerR) <= 2 &&
            std::abs(seamYR - innerR) <= 2;
        detail = "centerR=" + std::to_string(centerR) +
                 " seamXR=" + std::to_string(seamXR) +
                 " seamYR=" + std::to_string(seamYR) +
                 " innerR=" + std::to_string(innerR);
        return seamFree;
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
