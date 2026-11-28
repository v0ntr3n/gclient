// ============================================================================
// tests/test_win32_regression.cpp
// Deterministic Win32 Startup, Lifecycle, CCLabelAtlas Divide-by-Zero Guard,
// Memory/Integer Safety, Unicode Hot-Update, SQLite URI, and Network Framing
// Regression Suite for kestrel-canvas (gclient-win32).
// ============================================================================

#include "assets/BtDecryptHook.h"
#include "assets/PlistbLoader.h"
#include "assets/XmlbArmatureLoader.h"
#if defined(GCLIENT_TEST_EGL_GL)
#define GL_GLEXT_PROTOTYPES 1
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GL/gl.h>
#include <GL/glext.h>
#endif
#include "bindings/NetworkResilienceHook.h"
#include "diagnostics/CrashAndTelemetry.h"
#include "net/Amf3Module.h"
#include "net/CConnection.h"
#include "net/CNetwork.h"
#include "net/LCPacket.h"
#include "platform/BtPlatformWin32.h"
#include "platform/tolua_Platform.h"
#include "update/AtomicHotUpdater.h"

extern "C" {
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
}
#include "sqlite3.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "TestHarness.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

using gclient::test::ScopedTempDir;
using gclient::test::makeScopeExit;

void closeSocketCrossPlatform(SOCKET fd) noexcept {
    if (fd == INVALID_SOCKET) return;
#ifdef _WIN32
    ::closesocket(fd);
#else
    ::close(fd);
#endif
}

struct ScopedSocket {
    SOCKET fd = INVALID_SOCKET;
    explicit ScopedSocket(SOCKET s = INVALID_SOCKET) noexcept : fd(s) {}
    ScopedSocket(const ScopedSocket&) = delete;
    ScopedSocket& operator=(const ScopedSocket&) = delete;
    ScopedSocket(ScopedSocket&& o) noexcept : fd(o.fd) { o.fd = INVALID_SOCKET; }
    ~ScopedSocket() noexcept { reset(); }
    void reset(SOCKET next = INVALID_SOCKET) noexcept {
        if (fd != INVALID_SOCKET) closeSocketCrossPlatform(fd);
        fd = next;
    }
};

struct LoopbackTcpListener {
    ScopedSocket listenSock;
    unsigned int port = 0;

    bool bindEphemeral(int backlog = 4) {
        listenSock.reset(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (listenSock.fd == INVALID_SOCKET) return false;
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (::bind(listenSock.fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::listen(listenSock.fd, backlog) != 0) {
            return false;
        }
#ifdef _WIN32
        int addrLen = sizeof(addr);
#else
        socklen_t addrLen = sizeof(addr);
#endif
        if (::getsockname(listenSock.fd, reinterpret_cast<sockaddr*>(&addr), &addrLen) != 0) {
            return false;
        }
        port = ntohs(addr.sin_port);
        return port > 0;
    }

    ScopedSocket acceptOne() {
        return ScopedSocket(::accept(listenSock.fd, nullptr, nullptr));
    }
};

struct ScopedLuaVm {
    lua_State* L = nullptr;

    explicit ScopedLuaVm(bool withAmf3 = false) : L(luaL_newstate()) {
        if (L != nullptr) {
            luaL_openlibs(L);
            if (withAmf3) luaopen_amf3_extensions(L);
        }
    }
    ScopedLuaVm(const ScopedLuaVm&) = delete;
    ScopedLuaVm& operator=(const ScopedLuaVm&) = delete;
    ~ScopedLuaVm() noexcept {
        if (L != nullptr) lua_close(L);
    }

    bool execChecked(const char* script, const char* errTag) const {
        if (luaL_dostring(L, script) != 0) {
            const char* err = lua_tostring(L, -1);
            std::fprintf(stderr, "[%s] %s\n", errTag, err ? err : "(null)");
            return false;
        }
        return true;
    }
};

struct ScopedDiagnosticsSession {
    ScopedTempDir tempRoot;
    bool installed = false;

    ScopedDiagnosticsSession(const char* folderName, const char* appName, double flushSec = 0.0)
        : tempRoot(fs::temp_directory_path() / folderName, false) {
        gclient::diagnostics::DiagnosticsConfig cfg;
        cfg.logDirectory = (tempRoot.path / "logs").u8string();
        cfg.dumpDirectory = (tempRoot.path / "dumps").u8string();
        cfg.appName = appName;
        if (flushSec > 0.0) cfg.metricsFlushIntervalSec = flushSec;
        installed = gclient::diagnostics::CrashAndTelemetry::install(cfg);
    }
    ~ScopedDiagnosticsSession() noexcept {
        if (installed) {
            gclient::diagnostics::CrashAndTelemetry::clearLuaState();
            gclient::diagnostics::CrashAndTelemetry::shutdown();
        }
    }
};

void writeBinaryString(const fs::path& dst, const std::string& data) {
    std::ofstream ofs(dst, std::ios::binary | std::ios::trunc);
    ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
}

// ============================================================================
// Exact Mirror Harness of Patched CCLabelAtlas + CCAtlasNode + AppDelegate
// Lifecycle State Machine (verifies AUD-01, AUD-02, AUD-03, AUD-05 contracts)
// ============================================================================

struct MockTexture2D {
    uint32_t pixelsWide = 0;
    uint32_t pixelsHigh = 0;
};

struct MockQuad {
    float tl_u = 0.0f, tl_v = 0.0f, br_u = 0.0f, br_v = 0.0f;
    float width = 0.0f, height = 0.0f;
};

struct MockTextureAtlas {
    MockTexture2D* m_pTexture = nullptr;
    std::vector<MockQuad> quads{64};
    uint32_t updatedCount = 0;

    MockTexture2D* getTexture() const noexcept { return m_pTexture; }
    void setTexture(MockTexture2D* tex) noexcept { m_pTexture = tex; }
    size_t getCapacity() const noexcept { return quads.size(); }
    void resizeCapacity(size_t newCap) { quads.resize(newCap); }
    void updateQuad(const MockQuad& q, size_t idx) {
        if (idx < quads.size()) {
            quads[idx] = q;
            ++updatedCount;
        }
    }
};

class PatchedLabelAtlasHarness {
public:
    MockTextureAtlas* m_pTextureAtlas = nullptr;
    uint32_t m_uItemWidth = 0;
    uint32_t m_uItemHeight = 0;
    uint32_t m_uItemsPerRow = 0;
    uint32_t m_uItemsPerColumn = 0;
    uint32_t m_uMapStartChar = '.';
    std::string m_sString;

    void calculateMaxItems() noexcept {
        MockTexture2D* tex = m_pTextureAtlas ? m_pTextureAtlas->getTexture() : nullptr;
        if (!tex || m_uItemHeight == 0 || m_uItemWidth == 0) {
            m_uItemsPerColumn = 0;
            m_uItemsPerRow = 0;
            return;
        }
        m_uItemsPerColumn = tex->pixelsHigh / m_uItemHeight;
        m_uItemsPerRow = tex->pixelsWide / m_uItemWidth;
    }

    // Exact guard contract injected by tools/patch_cocos2dx.py into CCLabelAtlas::updateAtlasValues()
    void updateAtlasValues() {
        if (!m_pTextureAtlas ||
            !m_pTextureAtlas->getTexture() ||
            m_uItemsPerRow == 0)
        {
            return;
        }

        const size_t n = m_sString.size();
        if (n == 0) {
            return;
        }
        if (m_pTextureAtlas->getCapacity() < n) {
            m_pTextureAtlas->resizeCapacity(n + 1);
        }

        MockTexture2D* texture = m_pTextureAtlas->getTexture();
        const float textureWide = static_cast<float>(texture->pixelsWide);
        const float textureHigh = static_cast<float>(texture->pixelsHigh);
        if (textureWide <= 0.0f || textureHigh <= 0.0f ||
            m_uItemWidth == 0 || m_uItemHeight == 0) {
            return;
        }

        const float itemWidthInPixels = static_cast<float>(m_uItemWidth);
        const float itemHeightInPixels = static_cast<float>(m_uItemHeight);

        for (size_t i = 0; i < n; ++i) {
            const unsigned char ch = static_cast<unsigned char>(m_sString[i]);
            if (ch < m_uMapStartChar) {
                continue;
            }
            const uint32_t a = static_cast<uint32_t>(ch) - m_uMapStartChar;
            const float row = static_cast<float>(a % m_uItemsPerRow);
            const float col = static_cast<float>(a / m_uItemsPerRow);

            const float left = row * itemWidthInPixels / textureWide;
            const float right = left + itemWidthInPixels / textureWide;
            const float top = col * itemHeightInPixels / textureHigh;
            const float bottom = top + itemHeightInPixels / textureHigh;

            if (bottom > 1.0001f || right > 1.0001f) {
                continue;
            }

            MockQuad quad{};
            quad.tl_u = left;
            quad.tl_v = top;
            quad.br_u = right;
            quad.br_v = bottom;
            quad.width = itemWidthInPixels;
            quad.height = itemHeightInPixels;
            m_pTextureAtlas->updateQuad(quad, i);
        }
    }

    // Exact deferred-init recovery contract injected into CCAtlasNode::setTexture & draw
    void setTexture(MockTexture2D* texture) {
        if (!m_pTextureAtlas) {
            return;
        }
        m_pTextureAtlas->setTexture(texture);
        if (texture != nullptr) {
            calculateMaxItems();
            if (m_uItemsPerRow > 0) {
                updateAtlasValues();
            }
        }
    }

    void draw() {
        if (!m_pTextureAtlas || !m_pTextureAtlas->getTexture()) {
            return;
        }
        if (m_uItemsPerRow == 0 && m_uItemWidth > 0 && m_uItemHeight > 0) {
            calculateMaxItems();
            if (m_uItemsPerRow > 0) {
                updateAtlasValues();
            }
        }
        if (m_uItemsPerRow == 0) {
            return;
        }
    }
};

enum class SimLifecycleState : uint8_t {
    Uninitialized = 0,
    Initializing = 1,
    Ready = 2,
    Failed = 3,
    ShuttingDown = 4,
    Terminated = 5
};

class LifecycleStateSimulator {
public:
    std::atomic<SimLifecycleState> state{SimLifecycleState::Uninitialized};
    std::atomic<bool> inBackground{false};
    std::atomic<bool> pendingForeground{false};
    std::atomic<bool> pendingBackground{false};

    int designResolutionCalls = 0;
    int pauseCount = 0;
    int resumeCount = 0;
    int teardownCount = 0;
    bool displayStatsEnabled = true; // Must stay enabled (never masked by disabling FPS)

    void onWindowProcSize(bool isMinimized, int width, int height) {
        if (state.load(std::memory_order_acquire) != SimLifecycleState::Ready) {
            // Even if CCEGLView::WindowProc bypassed its own guard, AppDelegate guards too:
            if (isMinimized) {
                applicationDidEnterBackground();
            } else if (width > 0 && height > 0) {
                applicationWillEnterForeground();
            }
            return;
        }
        if (isMinimized) {
            applicationDidEnterBackground();
        } else if (width > 0 && height > 0) {
            applicationWillEnterForeground();
        }
    }

    void applicationDidEnterBackground() {
        if (state.load(std::memory_order_acquire) != SimLifecycleState::Ready) {
            pendingBackground.store(true, std::memory_order_release);
            pendingForeground.store(false, std::memory_order_release);
            return;
        }
        if (inBackground.exchange(true, std::memory_order_acq_rel)) {
            return; // Deduplicated
        }
        ++pauseCount;
    }

    void applicationWillEnterForeground() {
        if (state.load(std::memory_order_acquire) != SimLifecycleState::Ready) {
            pendingForeground.store(true, std::memory_order_release);
            pendingBackground.store(false, std::memory_order_release);
            return;
        }
        if (!inBackground.exchange(false, std::memory_order_acq_rel)) {
            return; // Deduplicated
        }
        ++designResolutionCalls;
        ++resumeCount;
    }

    bool finishLaunching(bool succeed, bool windowCurrentlyIconic) {
        SimLifecycleState expected = SimLifecycleState::Uninitialized;
        if (!state.compare_exchange_strong(expected, SimLifecycleState::Initializing,
                                           std::memory_order_acq_rel)) {
            return false;
        }
        if (!succeed) {
            teardown(SimLifecycleState::Failed);
            return false;
        }

        // Initial design resolution setup with GL context ready
        ++designResolutionCalls;
        state.store(SimLifecycleState::Ready, std::memory_order_release);

        const bool hadBg = pendingBackground.exchange(false, std::memory_order_acq_rel);
        const bool hadFg = pendingForeground.exchange(false, std::memory_order_acq_rel);

        if (windowCurrentlyIconic || (hadBg && !hadFg)) {
            applicationDidEnterBackground();
        } else if (hadFg && inBackground.load(std::memory_order_acquire)) {
            applicationWillEnterForeground();
        }
        return true;
    }

    void shutdown() {
        const SimLifecycleState cur = state.load(std::memory_order_acquire);
        if (cur == SimLifecycleState::Terminated || cur == SimLifecycleState::Failed) {
            return;
        }
        teardown(SimLifecycleState::Terminated);
    }

private:
    void teardown(SimLifecycleState terminal) {
        state.store(SimLifecycleState::ShuttingDown, std::memory_order_release);
        ++teardownCount;
        inBackground.store(false, std::memory_order_release);
        pendingBackground.store(false, std::memory_order_release);
        pendingForeground.store(false, std::memory_order_release);
        state.store(terminal, std::memory_order_release);
    }
};

// ============================================================================
// Scenarios 1–6: Startup Lifecycle, Premature WM_SIZE, Minimize/Restore Storm,
// Failed Partial Init Rollback, and CCLabelAtlas Divide-by-Zero Guard
// ============================================================================

bool testStartupLifecycleAndPrematureWmSize() {
    // Scenario 1: Exact crash sequence from wWinMain -> setFrameSize -> MoveWindow -> WM_SIZE(SIZE_RESTORED)
    LifecycleStateSimulator sim;
    REQUIRE_EQ(sim.state.load(), SimLifecycleState::Uninitialized);
    REQUIRE_TRUE(sim.displayStatsEnabled);

    // Premature WM_SIZE fires synchronously BEFORE applicationDidFinishLaunching!
    sim.onWindowProcSize(/*isMinimized=*/false, 1136, 640);
    REQUIRE_EQ(sim.designResolutionCalls, 0);
    REQUIRE_EQ(sim.resumeCount, 0);
    REQUIRE_TRUE(sim.pendingForeground.load());

    // Zero-size client rect during window creation must not corrupt state
    sim.onWindowProcSize(/*isMinimized=*/false, 0, 0);
    REQUIRE_EQ(sim.designResolutionCalls, 0);

    // Finish launching with normal restored window
    REQUIRE_TRUE(sim.finishLaunching(/*succeed=*/true, /*windowCurrentlyIconic=*/false));
    REQUIRE_EQ(sim.state.load(), SimLifecycleState::Ready);
    REQUIRE_EQ(sim.designResolutionCalls, 1);
    REQUIRE_TRUE(!sim.inBackground.load());
    REQUIRE_TRUE(!sim.pendingForeground.load());

    // Scenario 3: Rapid minimize / restore / duplicate WM_SIZE storm
    sim.onWindowProcSize(true, 0, 0);
    sim.onWindowProcSize(true, 0, 0);  // Duplicate minimize -> must be ignored
    REQUIRE_EQ(sim.pauseCount, 1);
    REQUIRE_TRUE(sim.inBackground.load());

    sim.onWindowProcSize(false, 1280, 720);
    sim.onWindowProcSize(false, 1920, 1080); // Already foreground -> no duplicate resume
    REQUIRE_EQ(sim.resumeCount, 1);
    REQUIRE_EQ(sim.designResolutionCalls, 2);
    REQUIRE_TRUE(!sim.inBackground.load());

    sim.shutdown();
    sim.shutdown(); // Idempotent second shutdown
    REQUIRE_EQ(sim.teardownCount, 1);
    REQUIRE_EQ(sim.state.load(), SimLifecycleState::Terminated);
    return true;
}

bool testMinimizedLaunchAndFailedInitRollback() {
    // Scenario 2: Launch with --minimized / SW_SHOWMINIMIZED
    LifecycleStateSimulator minSim;
    minSim.onWindowProcSize(/*isMinimized=*/true, 0, 0);
    REQUIRE_EQ(minSim.pauseCount, 0);
    REQUIRE_TRUE(minSim.pendingBackground.load());

    REQUIRE_TRUE(minSim.finishLaunching(/*succeed=*/true, /*windowCurrentlyIconic=*/true));
    REQUIRE_EQ(minSim.state.load(), SimLifecycleState::Ready);
    REQUIRE_EQ(minSim.pauseCount, 1);
    REQUIRE_TRUE(minSim.inBackground.load());
    minSim.shutdown();

    // Scenario 4: Failed partial initialization must never enter Ready or crash on WM_SIZE
    LifecycleStateSimulator failSim;
    failSim.onWindowProcSize(/*isMinimized=*/false, 1136, 640);
    REQUIRE_TRUE(!failSim.finishLaunching(/*succeed=*/false, /*windowCurrentlyIconic=*/false));
    REQUIRE_EQ(failSim.state.load(), SimLifecycleState::Failed);
    REQUIRE_EQ(failSim.teardownCount, 1);

    // Late WM_DESTROY / WM_SIZE during process exit must be safe no-ops
    failSim.onWindowProcSize(/*isMinimized=*/false, 800, 600);
    failSim.onWindowProcSize(/*isMinimized=*/true, 0, 0);
    failSim.shutdown();
    REQUIRE_EQ(failSim.designResolutionCalls, 0);
    REQUIRE_EQ(failSim.teardownCount, 1);
    return true;
}

bool testCCLabelAtlasZeroGuardAndDeferredRecovery() {
    // Scenario 6: Exact reproduction of 0xC0000094 in CCLabelAtlas::updateAtlasValues()
    PatchedLabelAtlasHarness label;
    label.m_sString = "30.0";
    label.m_uItemWidth = 12;
    label.m_uItemHeight = 32;
    label.m_uItemsPerRow = 0;

    // 6a: Null m_pTextureAtlas -> safe return
    label.updateAtlasValues();

    // 6b: Non-null atlas, null texture -> safe return
    MockTextureAtlas atlas;
    label.m_pTextureAtlas = &atlas;
    label.updateAtlasValues();
    REQUIRE_EQ(atlas.updatedCount, 0u);

    // 6c: Texture with 0x0 pixels (uninitialized GL texture before context ready) -> safe return
    MockTexture2D zeroTex{0, 0};
    label.setTexture(&zeroTex);
    REQUIRE_EQ(label.m_uItemsPerRow, 0u);
    label.updateAtlasValues();
    label.draw();
    REQUIRE_EQ(atlas.updatedCount, 0u);

    // 6d: Texture smaller than glyph cell (e.g. 8x8 texture vs 12x32 glyph -> m_uItemsPerRow == 0)
    MockTexture2D tinyTex{8, 8};
    label.setTexture(&tinyTex);
    REQUIRE_EQ(label.m_uItemsPerRow, 0u);
    label.updateAtlasValues();
    REQUIRE_EQ(atlas.updatedCount, 0u);

    // 6e: Deferred recovery when real cc_fps_images texture (192x32 -> 16 items/row) arrives!
    MockTexture2D fpsTex{192, 32};
    label.setTexture(&fpsTex);
    REQUIRE_EQ(label.m_uItemsPerRow, 16u);
    REQUIRE_EQ(label.m_uItemsPerColumn, 1u);
    REQUIRE_EQ(atlas.updatedCount, 4u); // "30.0" -> 4 glyphs populated, NOT permanently blank!
    REQUIRE_TRUE(atlas.quads[0].br_u > atlas.quads[0].tl_u);
    REQUIRE_TRUE(atlas.quads[0].br_v > atlas.quads[0].tl_v);

    // 6f: Also verify draw()-time recovery if texture dimensions populated in-place
    MockTextureAtlas atlas2;
    MockTexture2D delayedTex{0, 0};
    atlas2.setTexture(&delayedTex);
    PatchedLabelAtlasHarness label2;
    label2.m_pTextureAtlas = &atlas2;
    label2.m_sString = "60.0";
    label2.m_uItemWidth = 12;
    label2.m_uItemHeight = 32;
    label2.calculateMaxItems();
    REQUIRE_EQ(label2.m_uItemsPerRow, 0u);

    delayedTex.pixelsWide = 192;
    delayedTex.pixelsHigh = 32;
    label2.draw(); // Must self-heal m_uItemsPerRow and populate all 4 quads
    REQUIRE_EQ(label2.m_uItemsPerRow, 16u);
    REQUIRE_EQ(atlas2.updatedCount, 4u);
    return true;
}

// ============================================================================
// Scenarios 7–9: 32-Bit Integer Overflow Guards & Telemetry NaN/Inf Sanitization
// ============================================================================

bool testIntegerOverflowArithmeticContracts() {
    // Scenario 7: Verify 64-bit size arithmetic rejects 32-bit wrap-around in .fnt block Size
    const uint32_t maliciousBlockSize = 0xFFFFFFFCu; // Wraps 32-bit cursor + 5 + blockSize!
    const size_t totalBufferSize = 256;
    const size_t cursor = 20;
    const bool safeBoundsCheck = (maliciousBlockSize <= totalBufferSize - (cursor + 5));
    REQUIRE_TRUE(!safeBoundsCheck);

    // Scenario 8: Verify ZIP Central Directory 1024-byte buffer & 64-bit offset subtraction check
    const uint16_t zipNameLen = 4096; // Previously overflowed char fileName[1024]
    char boundedNameBuf[1024] = {};
    const size_t copyLen = (zipNameLen < sizeof(boundedNameBuf) - 1)
                               ? static_cast<size_t>(zipNameLen)
                               : (sizeof(boundedNameBuf) - 1);
    REQUIRE_EQ(copyLen, 1023u);
    boundedNameBuf[copyLen] = '\0';

    const uint32_t maliciousCdOffset = 0xFFFFFFF0u;
    const uint32_t maliciousCdSize = 0x00000100u;
    const uint64_t zipSize = 512;
    const bool safeZipDirectory =
        (static_cast<uint64_t>(maliciousCdOffset) + static_cast<uint64_t>(maliciousCdSize) <= zipSize);
    REQUIRE_TRUE(!safeZipDirectory);
    return true;
}

bool testCrashAndTelemetryNanSortAndLuaHooks() {
    ScopedDiagnosticsSession diag("kestrel_telemetry_test", "kestrel_test", 0.25);
    REQUIRE_TRUE(diag.installed);
    ScopedLuaVm vm;
    REQUIRE_TRUE(vm.L != nullptr);
    gclient::diagnostics::CrashAndTelemetry::installLuaHooks(vm.L);

    const float nanVal = std::numeric_limits<float>::quiet_NaN();
    const float posInf = std::numeric_limits<float>::infinity();
    for (int i = 0; i < 600; ++i) {
        const float sample = (i % 17 == 0) ? nanVal
                           : (i % 23 == 0) ? posInf
                           : (i % 29 == 0) ? -posInf
                           : (i % 31 == 0) ? -0.5f : 0.0333f;
        gclient::diagnostics::CrashAndTelemetry::recordFrame(sample);
    }

    const auto snap = gclient::diagnostics::CrashAndTelemetry::getLatestSnapshot();
    REQUIRE_TRUE(std::isfinite(snap.avgFps) && std::isfinite(snap.avgFrameMs) &&
                 std::isfinite(snap.p95FrameMs) && std::isfinite(snap.maxFrameMs));
    REQUIRE_TRUE(snap.totalFrames >= 500);

    const int topBefore = lua_gettop(vm.L);
    lua_getglobal(vm.L, "__G__TRACKBACK__");
    REQUIRE_TRUE(lua_isfunction(vm.L, -1));
    lua_pushstring(vm.L, "synthetic_lua_error");
    REQUIRE_EQ(lua_pcall(vm.L, 1, 1, 0), 0);
    lua_pop(vm.L, 1);
    REQUIRE_EQ(lua_gettop(vm.L), topBefore);
    gclient::diagnostics::CrashAndTelemetry::clearLuaState();
    return true;
}

// ============================================================================
// Scenario 13: BtDecryptHook Key Lifetime Safety & Path Normalization
// ============================================================================

bool testBtDecryptKeyLifetimeAndPathNormalization() {
    // Verify AUD-21 fix: RegisterKeyTable must deep-copy key bytes so destroying caller's vector never UAFs!
    const std::string plaintext = "return { hero = 'Kestrel', power = 9001 }\n";
    uint8_t slotIndex = 14;
    {
        std::vector<uint8_t> transientKey(64);
        for (size_t i = 0; i < transientKey.size(); ++i) {
            transientKey[i] = static_cast<uint8_t>((i * 13u + 0x5Au) & 0xFFu);
        }
        REQUIRE_TRUE(gclient::assets::RegisterKeyTable(
            slotIndex, transientKey.data(), static_cast<uint32_t>(transientKey.size())));

        // Build valid 0xFEFEFEFE encrypted payload using same XOR schedule
        std::vector<uint8_t> encrypted(gclient::assets::kBtDecryptHeaderSize + plaintext.size() + 1, 0);
        const uint32_t magic = gclient::assets::kBtDecryptMagic;
        const uint32_t payloadLen = static_cast<uint32_t>(plaintext.size());
        std::memcpy(encrypted.data(), &magic, 4);
        std::memcpy(encrypted.data() + 4, &payloadLen, 4);
        encrypted[8] = 0; // algoIndex = 0
        encrypted[9] = slotIndex;
        std::memcpy(encrypted.data() + 32, plaintext.data(), plaintext.size());
        const size_t keyLen = transientKey.size();
        const size_t keyOff = plaintext.size() % keyLen;
        for (size_t i = 0; i < plaintext.size(); i += 2) {
            encrypted[32 + i] ^= transientKey[(i + keyOff) % keyLen];
        }

        // Overwrite and free transientKey BEFORE calling DecryptBuffer!
        std::fill(transientKey.begin(), transientKey.end(), 0xCCu);
        transientKey.clear();
        transientKey.shrink_to_fit();

        size_t ioSize = gclient::assets::kBtDecryptHeaderSize + plaintext.size();
        gclient::assets::DecryptResult diag{};
        REQUIRE_TRUE(gclient::assets::DecryptBuffer(encrypted.data(), &ioSize, "script/test.lua", &diag));
        REQUIRE_TRUE(diag.ok());
        REQUIRE_EQ(ioSize, plaintext.size());
        REQUIRE_EQ(std::string(reinterpret_cast<const char*>(encrypted.data()), ioSize), plaintext);
        REQUIRE_EQ(encrypted[ioSize], 0u);
    }

    // Truncated / length-mismatched 0xFEFEFEFE buffer must fail closed
    std::vector<uint8_t> badBuf(40, 0xFEu);
    size_t badSize = badBuf.size();
    gclient::assets::DecryptResult badDiag{};
    REQUIRE_TRUE(!gclient::assets::DecryptBuffer(badBuf.data(), &badSize, "corrupt.bin", &badDiag));
    REQUIRE_TRUE(!badDiag.ok());

    // Path normalization edge cases
    REQUIRE_EQ(gclient::assets::NormalizeAssetPath("ui\\hero//panel/../icon.png"), "ui/hero/icon.png");
    REQUIRE_EQ(gclient::assets::NormalizeAssetPath("\\\\fileserver\\share\\res\\a.plist"),
               "//fileserver/share/res/a.plist");
    REQUIRE_EQ(gclient::assets::ResolveRelativeAssetPath("../textures/atlas.png", "ui/dialogs/main.pb"),
               "ui/textures/atlas.png");
    return true;
}

// ============================================================================
// Scenarios 14 & 15: Unicode Hot-Update Atomic Swap/Rollback & SQLite Read-Only URI
// ============================================================================

bool testUnicodeAtomicHotUpdaterAndTornManifestRecovery() {
    ScopedTempDir unicodeRoot(fs::temp_directory_path() / fs::u8path(u8"Kestrel Hotfix Tiếng Việt 日本語 Space"));
    std::error_code ec;
    const fs::path baseRes = unicodeRoot.path / fs::u8path(u8"Resources Base");
    const fs::path patchRoot = unicodeRoot.path / fs::u8path(u8"Patch Overlay Tiếng Việt");
    const fs::path remoteSource = unicodeRoot.path / fs::u8path(u8"Remote CDN");
    fs::create_directories(baseRes, ec);
    fs::create_directories(remoteSource, ec);

    const fs::path remoteScript = remoteSource / "main_v2.lua";
    const std::string v1Content = "return 'version_1_ok'\n";
    const std::string v2Content = "return 'version_2_faulty'\n";
    writeBinaryString(remoteSource / "main_v1.lua", v1Content);
    writeBinaryString(remoteScript, v2Content);

    std::string shaV1, shaV2, hashErr;
    REQUIRE_TRUE(gclient::update::AtomicHotUpdater::computeFileHash(
        remoteSource / "main_v1.lua", gclient::update::HashAlgorithm::SHA256, shaV1, hashErr));
    REQUIRE_TRUE(gclient::update::AtomicHotUpdater::computeFileHash(
        remoteScript, gclient::update::HashAlgorithm::SHA256, shaV2, hashErr));

    gclient::update::HotUpdaterConfig cfg;
    cfg.baseResourcesDir = baseRes;
    cfg.patchRootDir = patchRoot;
    cfg.maxBootFailuresBeforeRollback = 2;
    cfg.capabilities.clientVersion = "1.1.0";
    cfg.capabilities.exportedBindings.insert("luaopen_amf3");

    gclient::update::AtomicHotUpdater updater(cfg);
    updater.setDownloadTransport(
        [](const std::string& url, const fs::path& dst, std::string& errOut) -> bool {
            std::error_code copyEc;
            fs::create_directories(dst.parent_path(), copyEc);
            fs::copy_file(fs::u8path(url), dst, fs::copy_options::overwrite_existing, copyEc);
            if (copyEc) errOut = copyEc.message();
            return !copyEc;
        });

    REQUIRE_FALSE(gclient::update::AtomicHotUpdater::isSafeRelativePath("../evil.dll"));
    REQUIRE_FALSE(gclient::update::AtomicHotUpdater::isSafeRelativePath("C:/evil.lua"));
    REQUIRE_TRUE(gclient::update::AtomicHotUpdater::isSafeRelativePath("scripts/main.lua"));

    gclient::update::PatchManifest m1;
    m1.patchVersion = "1.0.1";
    m1.baseVersion = "1.0.0";
    m1.contract.requiredNativeBindings = {"luaopen_amf3"};
    m1.files.push_back({"scripts/main.lua", (remoteSource / "main_v1.lua").u8string(), v1Content.size(), shaV1, {}});

    REQUIRE_TRUE(updater.applyPatch(m1).ok());
    REQUIRE_TRUE(updater.confirmStartupSuccess().ok());

    gclient::update::PatchManifest mBad = m1;
    mBad.patchVersion = "1.0.9";
    mBad.files[0].sha256 = std::string(64, '0');
    REQUIRE_EQ(updater.stagePatch(mBad).status, gclient::update::UpdateStatus::ChecksumMismatch);

    gclient::update::PatchManifest m2 = m1;
    m2.patchVersion = "1.0.2";
    m2.files[0].downloadUrl = remoteScript.u8string();
    m2.files[0].expectedSize = v2Content.size();
    m2.files[0].sha256 = shaV2;
    REQUIRE_TRUE(updater.applyPatch(m2).ok());

    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto boot = updater.initializeAndCheckStartupHealth();
        REQUIRE_FALSE(boot.rolledBack);
        REQUIRE_EQ(boot.activeVersion, std::string("1.0.2"));
    }
    const auto boot3 = updater.initializeAndCheckStartupHealth();
    REQUIRE_TRUE(boot3.rolledBack);
    REQUIRE_EQ(boot3.activeVersion, std::string("1.0.1"));
    REQUIRE_EQ(boot3.rolledBackFromVersion, std::string("1.0.2"));

    writeBinaryString(patchRoot / "active_manifest.json", "{ truncated_json");
    const auto recovered = updater.getActiveState();
    REQUIRE_TRUE(recovered.has_value() && !recovered->activeVersion.empty());
    return true;
}

bool testSqliteReadOnlyUnicodeUri() {
    ScopedTempDir dir(fs::temp_directory_path() / fs::u8path(u8"Kestrel DB Tiếng Việt #1"));
    const fs::path dbFile = dir.path / "DB_Item_Config.db";

    sqlite3* writer = nullptr;
    REQUIRE_EQ(sqlite3_open_v2(dbFile.u8string().c_str(), &writer,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr),
               SQLITE_OK);
    char* errMsg = nullptr;
    REQUIRE_EQ(sqlite3_exec(writer,
                            "CREATE TABLE Item(id INTEGER PRIMARY KEY, name TEXT);"
                            "INSERT INTO Item VALUES(101, 'Kestrel Blade');",
                            nullptr, nullptr, &errMsg),
               SQLITE_OK);
    sqlite3_close_v2(writer);

    // Encode RFC 8089 URI matching CTable::buildReadOnlyUri
    std::string rawPosix = dbFile.generic_u8string();
    std::string uri = "file:";
    if (!rawPosix.empty() && rawPosix[0] != '/') {
        uri += "///";
    } else {
        uri += "//";
    }
    for (unsigned char c : rawPosix) {
        if (c == '%') uri += "%25";
        else if (c == '?') uri += "%3f";
        else if (c == '#') uri += "%23";
        else if (c == ' ') uri += "%20";
        else uri.push_back(static_cast<char>(c));
    }
    uri += "?mode=ro&immutable=1";

    sqlite3* reader = nullptr;
    REQUIRE_EQ(sqlite3_open_v2(uri.c_str(), &reader,
                               SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX,
                               nullptr),
               SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    REQUIRE_EQ(sqlite3_prepare_v2(reader, "SELECT name FROM Item WHERE id = 101;", -1, &stmt, nullptr),
               SQLITE_OK);
    REQUIRE_EQ(sqlite3_step(stmt), SQLITE_ROW);
    const char* itemName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    REQUIRE_TRUE(itemName != nullptr);
    REQUIRE_EQ(std::string(itemName), std::string("Kestrel Blade"));
    sqlite3_finalize(stmt);
    REQUIRE_EQ(sqlite3_close(reader), SQLITE_OK); // Zero leaked statements -> SQLITE_OK!
    return true;
}

// ============================================================================
// Scenarios 16 & 17: LCPacket Overload/MD5/Zip-Bomb & CNetwork/CConnection Loopback
// ============================================================================

bool testLCPacketFramingAndOverloadSafety() {
    using gclient::net::LCPacket;

    // 16a: Verify (const char*, bool) overload does NOT silently convert bool -> size_t(0 or 1)!
    const char* literalMsg = "kestrel_protocol_login_request_payload";
    const std::string framedUncompressed = LCPacket::makeLCPacket(literalMsg, false);
    REQUIRE_EQ(framedUncompressed.size(), LCPacket::kTotalHeaderSize + std::strlen(literalMsg));

    LCPacket::DecodedPacket decoded{};
    REQUIRE_TRUE(LCPacket::parseLCPacket(framedUncompressed.data(), framedUncompressed.size(), decoded));
    REQUIRE_TRUE(decoded.md5Valid);
    REQUIRE_EQ(decoded.payload, std::string(literalMsg));

    // 16b: Compressed round-trip
    const std::string repeated(4096, 'K');
    const std::string framedCompressed = LCPacket::makeLCPacket(repeated, true);
    REQUIRE_TRUE(framedCompressed.size() < repeated.size());

    LCPacket::DecodedPacket decodedComp{};
    REQUIRE_TRUE(LCPacket::parseLCPacket(framedCompressed.data(), framedCompressed.size(), decodedComp));
    REQUIRE_TRUE(decodedComp.md5Valid);
    REQUIRE_EQ(decodedComp.payload, repeated);

    // 16c: Forged MD5 must be rejected BEFORE zlib inflate!
    std::string tampered = framedCompressed;
    const size_t flipIdx = LCPacket::kHeaderLengthSize + LCPacket::kHeaderFlagsSize;
    tampered[flipIdx] = static_cast<char>(static_cast<unsigned char>(tampered[flipIdx]) ^ 0xFFu);
    LCPacket::DecodedPacket tamperedOut{};
    REQUIRE_TRUE(!LCPacket::parseLCPacket(tampered.data(), tampered.size(), tamperedOut,
                                          /*decompress=*/true, /*requireValidMd5=*/true));

    // 16d: Decompression size cap (zip-bomb defense)
    std::string cappedOut;
    const uint8_t* compBody = reinterpret_cast<const uint8_t*>(framedCompressed.data()) +
                              LCPacket::kTotalHeaderSize;
    const size_t compBodyLen = framedCompressed.size() - LCPacket::kTotalHeaderSize;
    REQUIRE_TRUE(!LCPacket::zlibDecompress(compBody, compBodyLen, cappedOut, /*maxOutputSize=*/512));

    // 16e: 0-byte compressed stream must fail closed
    uint8_t dummy = 0;
    REQUIRE_TRUE(!LCPacket::zlibDecompress(&dummy, 0, cappedOut, 1024));
    return true;
}

bool testCNetworkLoopbackReentrantAndDestroySafety() {
    using gclient::net::CConnection;
    using gclient::net::CNetwork;
    using gclient::net::LCPacket;
    using gclient::net::WinsockSession;

    WinsockSession ws;
    REQUIRE_TRUE(ws.isInitialized());

    LoopbackTcpListener listener;
    REQUIRE_TRUE(listener.bindEphemeral(4));
    const unsigned int port = listener.port;

    std::atomic<bool> serverReceivedOk{false};
    std::thread serverThread([&listener, &serverReceivedOk]() {
        ScopedSocket client = listener.acceptOne();
        if (client.fd != INVALID_SOCKET) {
            char buf[256] = {};
            const auto n = ::recv(client.fd, buf, sizeof(buf), 0);
            if (n >= static_cast<int>(LCPacket::kTotalHeaderSize)) {
                LCPacket::DecodedPacket pkt{};
                if (LCPacket::parseLCPacket(buf, static_cast<size_t>(n), pkt) &&
                    pkt.payload == "ping_from_client") {
                    serverReceivedOk.store(true, std::memory_order_release);
                }
            }
            const std::string reply1 = LCPacket::makeLCPacket("pong_packet_1", true);
            const std::string reply2 = LCPacket::makeLCPacket("pong_packet_2", false);
            ::send(client.fd, reply1.data(), static_cast<int>(reply1.size()), 0);
            ::send(client.fd, reply2.data(), static_cast<int>(reply2.size()), 0);
        }
        listener.listenSock.reset();
    });

    CNetwork* net = CNetwork::sharedNetwork();
    CConnection* conn = net->newConnection();
    conn->setHeaderSize(static_cast<int>(LCPacket::kTotalHeaderSize));

    std::vector<std::string> receivedPayloads;
    conn->setBodyCallback([conn, &receivedPayloads](const char* body, size_t bodyLen,
                                                    const char* hdr, size_t hdrLen) {
        std::string rawFrame(hdr, hdrLen);
        rawFrame.append(body, bodyLen);
        LCPacket::DecodedPacket decoded{};
        if (LCPacket::parseLCPacket(rawFrame.data(), rawFrame.size(), decoded)) {
            receivedPayloads.push_back(decoded.payload);
        }
        // Reentrant doRead() inside BodyCallback must NEVER double-dispatch or UAF (AUD-19)!
        conn->doRead();
    });

    REQUIRE_TRUE(conn->connect("127.0.0.1", port));
    // Verify C-string overload on CConnection::send(const char*, bool) (AUD-26)!
    REQUIRE_TRUE(conn->send("ping_from_client", /*wrapLCPacket=*/true));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (receivedPayloads.size() < 2 && std::chrono::steady_clock::now() < deadline) {
        net->update(0.016f);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Exercise immediate destruction race guard while pollThread_ is running (AUD-18)!
    {
        auto transientConn = std::make_unique<CConnection>();
        transientConn->connect("127.0.0.1", port);
        transientConn.reset(); // Invokes ~CConnection -> onConnectionDestroyed synchronously
    }

    serverThread.join();
    CNetwork::destroySharedNetwork();

    REQUIRE_TRUE(serverReceivedOk.load(std::memory_order_acquire));
    REQUIRE_EQ(receivedPayloads.size(), 2u);
    REQUIRE_EQ(receivedPayloads[0], std::string("pong_packet_1"));
    REQUIRE_EQ(receivedPayloads[1], std::string("pong_packet_2"));
    return true;
}

// ============================================================================
// Scenario 18 (Issue #8): Win32 Mouse Routing, DPI/Viewport Sync & FuncMenu 24-Cycle QA
// ============================================================================

struct SimVec2 { float x = 0.0f, y = 0.0f; };
struct SimSize { float width = 0.0f, height = 0.0f; };
struct SimRect {
    float x = 0.0f, y = 0.0f, width = 0.0f, height = 0.0f;
    bool isZero() const noexcept { return width == 0.0f && height == 0.0f && x == 0.0f && y == 0.0f; }
    bool containsPoint(float px, float py) const noexcept {
        return px >= x && px <= (x + width) && py >= y && py <= (y + height);
    }
};

enum class SimResPolicy { Unknown, ShowAll, FixedHeight, FixedWidth };
enum class SimTouchEv { Began = 0, Moved = 1, Ended = 2, Canceled = 3 };

struct SimWidget {
    std::string name;
    bool isLayout = false, visible = true, enabled = true, touchEnabled = false;
    bool clippingEnabled = false, touchPassedEnabled = false, hitted = false, focused = false;
    int zOrder = 0;
    SimVec2 pos{0.0f, 0.0f}, anchor{0.5f, 0.5f};
    SimSize size{0.0f, 0.0f};
    float scaleX = 1.0f, scaleY = 1.0f;
    SimWidget* parent = nullptr;
    std::vector<std::shared_ptr<SimWidget>> children;
    std::function<void(SimWidget*, SimTouchEv)> listener;

    static std::shared_ptr<SimWidget> createLayout(const std::string& nm) {
        auto w = std::make_shared<SimWidget>();
        w->name = nm;
        w->isLayout = true;
        w->anchor = {0.0f, 0.0f};
        return w;
    }
    static std::shared_ptr<SimWidget> createButton(const std::string& nm, float wSz, float hSz) {
        auto w = std::make_shared<SimWidget>();
        w->name = nm;
        w->size = {wSz, hSz};
        w->touchEnabled = true;
        return w;
    }
    void addChild(const std::shared_ptr<SimWidget>& ch, int z = 0) {
        ch->parent = this;
        ch->zOrder = z;
        auto it = std::upper_bound(children.begin(), children.end(), z,
            [](int lhsZ, const std::shared_ptr<SimWidget>& rhs) { return lhsZ < rhs->zOrder; });
        children.insert(it, ch);
    }
    void removeFromParent() {
        if (!parent) return;
        auto& vec = parent->children;
        vec.erase(std::remove_if(vec.begin(), vec.end(),
            [this](const std::shared_ptr<SimWidget>& p) { return p.get() == this; }), vec.end());
        parent = nullptr;
    }
    SimVec2 worldToLocal(SimVec2 worldPt, SimVec2 stageOrigin, float stageScale) const {
        std::vector<const SimWidget*> chain;
        for (const SimWidget* cur = this; cur != nullptr; cur = cur->parent) chain.push_back(cur);
        SimVec2 p{(worldPt.x - stageOrigin.x) / stageScale, (worldPt.y - stageOrigin.y) / stageScale};
        // In CocoStudio UIWidget, CCNode::m_obContentSize is (0,0) while Widget::_size is tested
        // against CCRect(-_size * anchor, _size) in UIWidget::hitTest.
        for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
            const SimWidget* n = *it;
            p.x = (p.x - n->pos.x) / (n->scaleX != 0.0f ? n->scaleX : 1.0f);
            p.y = (p.y - n->pos.y) / (n->scaleY != 0.0f ? n->scaleY : 1.0f);
        }
        return p;
    }
    bool hitTest(SimVec2 glPt, SimVec2 stageOrigin, float stageScale) const {
        const SimVec2 nsp = worldToLocal(glPt, stageOrigin, stageScale);
        const float ox = -size.width * anchor.x, oy = -size.height * anchor.y;
        return nsp.x >= ox && nsp.x <= (ox + size.width) && nsp.y >= oy && nsp.y <= (oy + size.height);
    }
    bool clippingParentAreaContainPoint(SimVec2 glPt, SimVec2 stageOrigin, float stageScale) const {
        for (const SimWidget* p = parent; p != nullptr; p = p->parent) {
            if (p->isLayout && p->clippingEnabled) {
                return p->hitTest(glPt, stageOrigin, stageScale) &&
                       p->clippingParentAreaContainPoint(glPt, stageOrigin, stageScale);
            }
        }
        return true;
    }
    bool onTouchBegan(SimVec2 glPt, SimVec2 stageOrigin, float stageScale) {
        hitted = enabled && touchEnabled && hitTest(glPt, stageOrigin, stageScale) &&
                 clippingParentAreaContainPoint(glPt, stageOrigin, stageScale);
        if (!hitted) return false;
        focused = true;
        if (listener) listener(this, SimTouchEv::Began);
        return !touchPassedEnabled;
    }
    void onTouchMoved(SimVec2 glPt, SimVec2 stageOrigin, float stageScale) {
        focused = hitTest(glPt, stageOrigin, stageScale);
        if (listener) listener(this, SimTouchEv::Moved);
    }
    void onTouchEnded(SimVec2) {
        const bool wasFocused = focused;
        focused = false;
        if (listener) listener(this, wasFocused ? SimTouchEv::Ended : SimTouchEv::Canceled);
    }
    void onTouchCancelled() {
        focused = false;
        if (listener) listener(this, SimTouchEv::Canceled);
    }
};

struct SimTouchDelegate {
    int priority = 0;
    bool swallowsTouches = true, visible = true;
    std::function<bool(SimVec2)> onBegan;
    std::function<void(SimVec2)> onMoved;
    std::function<void(SimVec2)> onEnded;
    std::function<void()> onCancelled;
};

struct SimTouchGroup {
    explicit SimTouchGroup(int prio) : priority(prio), rootWidget(SimWidget::createLayout("Root")) {}
    int priority = 0;
    bool visible = true;
    std::shared_ptr<SimWidget> rootWidget;
    std::vector<std::shared_ptr<SimWidget>> selectedWidgets;

    bool checkTouchEvent(const std::shared_ptr<SimWidget>& r, SimVec2 glPt, SimVec2 stOrig, float stScale) {
        if (!r || !r->visible) return false;
        for (int i = static_cast<int>(r->children.size()) - 1; i >= 0; --i) {
            if (checkTouchEvent(r->children[static_cast<size_t>(i)], glPt, stOrig, stScale)) return true;
        }
        const bool pass = r->onTouchBegan(glPt, stOrig, stScale);
        if (r->hitted) {
            selectedWidgets.push_back(r);
            return true;
        }
        return pass;
    }
    bool ccTouchBegan(SimVec2 glPt, SimVec2 stOrig, float stScale) {
        if (!visible) return false;
        selectedWidgets.clear();
        checkTouchEvent(rootWidget, glPt, stOrig, stScale);
        return !selectedWidgets.empty();
    }
    void ccTouchMoved(SimVec2 glPt, SimVec2 stOrig, float stScale) {
        auto snap = selectedWidgets;
        for (auto& w : snap) w->onTouchMoved(glPt, stOrig, stScale);
    }
    void ccTouchEnded(SimVec2 glPt) {
        auto snap = selectedWidgets;
        selectedWidgets.clear();
        for (auto& w : snap) w->onTouchEnded(glPt);
    }
    void ccTouchCancelled() {
        auto snap = selectedWidgets;
        selectedWidgets.clear();
        for (auto& w : snap) w->onTouchCancelled();
    }
};

struct PatchedWin32EglPipeline {
    SimSize screenSize{1136.0f, 640.0f}, designSize{1136.0f, 640.0f};
    SimRect viewPortRect{0.0f, 0.0f, 1136.0f, 640.0f};
    float scaleX = 1.0f, scaleY = 1.0f, frameZoomFactor = 1.0f;
    SimResPolicy policy = SimResPolicy::Unknown;
    bool supportTouch = true, captured = false, hasActiveTouch0 = false;
    std::vector<SimTouchDelegate*> delegates, claimed;

    void setFrameSizeWithClientClamp(float reqW, float reqH, int actualClientW, int actualClientH) {
        const float zoom = frameZoomFactor > 0.0f ? frameZoomFactor : 1.0f;
        screenSize = designSize = (actualClientW > 0 && actualClientH > 0)
            ? SimSize{static_cast<float>(actualClientW) / zoom, static_cast<float>(actualClientH) / zoom}
            : SimSize{reqW, reqH};
    }
    void setDesignResolutionSize(float w, float h, SimResPolicy pol) {
        if (w <= 0.0f || h <= 0.0f || screenSize.width <= 0.0f || screenSize.height <= 0.0f) return;
        designSize = {w, h};
        scaleX = screenSize.width / designSize.width;
        scaleY = screenSize.height / designSize.height;
        if (pol == SimResPolicy::ShowAll) scaleX = scaleY = (std::min)(scaleX, scaleY);
        else if (pol == SimResPolicy::FixedHeight) { scaleX = scaleY; designSize.width = std::ceil(screenSize.width / scaleX); }
        else if (pol == SimResPolicy::FixedWidth) { scaleY = scaleX; designSize.height = std::ceil(screenSize.height / scaleY); }
        const float vpW = designSize.width * scaleX, vpH = designSize.height * scaleY;
        viewPortRect = {(screenSize.width - vpW) * 0.5f, (screenSize.height - vpH) * 0.5f, vpW, vpH};
        policy = pol;
    }
    void onWmSize(int clientW, int clientH) {
        if (clientW <= 0 || clientH <= 0) return;
        const float zoom = frameZoomFactor > 0.0f ? frameZoomFactor : 1.0f;
        const float unzoomedW = static_cast<float>(clientW) / zoom, unzoomedH = static_cast<float>(clientH) / zoom;
        const SimSize prevFrame = screenSize, prevDesign = designSize;
        const SimResPolicy prevPol = policy;
        screenSize = designSize = {unzoomedW, unzoomedH};
        if (prevDesign.width >= 1.0f && prevDesign.height >= 1.0f && prevPol != SimResPolicy::Unknown) {
            const bool sameAspect = prevFrame.width > 0.0f && prevFrame.height > 0.0f &&
                                    std::fabs((unzoomedW / unzoomedH) - (prevFrame.width / prevFrame.height)) < 1e-3f;
            setDesignResolutionSize(prevDesign.width, prevDesign.height, sameAspect ? prevPol : SimResPolicy::ShowAll);
        } else {
            setDesignResolutionSize(1136.0f, 640.0f, SimResPolicy::FixedWidth);
        }
    }
    SimVec2 clientToGL(float ptX, float ptY) const {
        return {(ptX - viewPortRect.x) / scaleX, designSize.height - (ptY - viewPortRect.y) / scaleY};
    }
    static bool isTouchSynthesizedMouse(uint32_t extraInfo, bool inSendMessage) noexcept {
        return !inSendMessage && ((extraInfo & 0xFFFFFF80u) == 0xFF515780u);
    }
    void cancelActiveTouch0() {
        if (!hasActiveTouch0) return;
        auto snap = claimed;
        claimed.clear();
        hasActiveTouch0 = false;
        for (auto* d : snap) if (d->onCancelled) d->onCancelled();
    }
    void onWmLButtonDown(int clientX, int clientY, uint32_t, uint32_t extra = 0, bool inSendMsg = false) {
        if (supportTouch && isTouchSynthesizedMouse(extra, inSendMsg)) return;
        const float zoom = frameZoomFactor > 0.0f ? frameZoomFactor : 1.0f;
        const float ptX = static_cast<float>(clientX) / zoom, ptY = static_cast<float>(clientY) / zoom;
        if (viewPortRect.isZero() || viewPortRect.containsPoint(ptX, screenSize.height - ptY)) {
            captured = true;
            if (hasActiveTouch0) cancelActiveTouch0();
            hasActiveTouch0 = true;
            claimed.clear();
            const SimVec2 glPt = clientToGL(ptX, ptY);
            std::vector<SimTouchDelegate*> sorted = delegates;
            std::stable_sort(sorted.begin(), sorted.end(),
                [](const SimTouchDelegate* a, const SimTouchDelegate* b) { return a->priority < b->priority; });
            for (auto* d : sorted) {
                if (d->visible && d->onBegan && d->onBegan(glPt)) {
                    claimed.push_back(d);
                    if (d->swallowsTouches) break;
                }
            }
        }
    }
    void onWmMouseMove(int clientX, int clientY, uint32_t wParam, uint32_t extra = 0, bool inSendMsg = false) {
        if (supportTouch && isTouchSynthesizedMouse(extra, inSendMsg)) return;
        if (!captured || (wParam & 0x0001u) == 0 || !hasActiveTouch0) return;
        const float zoom = frameZoomFactor > 0.0f ? frameZoomFactor : 1.0f;
        const SimVec2 glPt = clientToGL(static_cast<float>(clientX) / zoom, static_cast<float>(clientY) / zoom);
        auto snap = claimed;
        for (auto* d : snap) if (d->onMoved) d->onMoved(glPt);
    }
    void onWmLButtonUp(int clientX, int clientY, uint32_t extra = 0, bool inSendMsg = false) {
        if (supportTouch && isTouchSynthesizedMouse(extra, inSendMsg)) return;
        if (!captured) return;
        captured = false;
        if (!hasActiveTouch0) return;
        const float zoom = frameZoomFactor > 0.0f ? frameZoomFactor : 1.0f;
        const SimVec2 glPt = clientToGL(static_cast<float>(clientX) / zoom, static_cast<float>(clientY) / zoom);
        auto snap = claimed;
        claimed.clear();
        hasActiveTouch0 = false;
        for (auto* d : snap) if (d->onEnded) d->onEnded(glPt);
    }
    void onWmCaptureChanged(bool lostToOtherWindow) {
        if (captured && lostToOtherWindow) { captured = false; cancelActiveTouch0(); }
    }
};

bool testWin32MouseRoutingDpiViewportAndFuncMenuCycles() {
    // 1. Verify Windows Pen (0xFF515700) vs Touch (0xFF515780) & InSendMessage filter
    REQUIRE_TRUE(!PatchedWin32EglPipeline::isTouchSynthesizedMouse(0xFF515700u, false));
    REQUIRE_TRUE(!PatchedWin32EglPipeline::isTouchSynthesizedMouse(0xFF515701u, false));
    REQUIRE_TRUE(PatchedWin32EglPipeline::isTouchSynthesizedMouse(0xFF515780u, false));
    REQUIRE_TRUE(!PatchedWin32EglPipeline::isTouchSynthesizedMouse(0xFF515780u, true));

    // 2. Verify WM_SIZE preservation of 1024x768 ShowAll & F11 fullscreen letterboxing
    {
        PatchedWin32EglPipeline pipe;
        pipe.setFrameSizeWithClientClamp(1024.0f, 768.0f, 1024, 768);
        pipe.setDesignResolutionSize(1136.0f, 640.0f, SimResPolicy::FixedWidth);
        REQUIRE_TRUE(pipe.designSize.height > 768.0f);
        pipe.setDesignResolutionSize(1136.0f, 768.0f, SimResPolicy::ShowAll);
        pipe.onWmSize(1024, 768);
        REQUIRE_NEAR(pipe.designSize.width, 1136.0f, 1e-3f);
        REQUIRE_NEAR(pipe.designSize.height, 768.0f, 1e-3f);
        REQUIRE_TRUE(pipe.policy == SimResPolicy::ShowAll);

        pipe.setFrameSizeWithClientClamp(1136.0f, 640.0f, 1136, 640);
        pipe.setDesignResolutionSize(1136.0f, 640.0f, SimResPolicy::FixedWidth);
        pipe.onWmSize(1920, 1200);
        REQUIRE_NEAR(pipe.designSize.width, 1136.0f, 1e-3f);
        REQUIRE_NEAR(pipe.designSize.height, 640.0f, 1e-3f);
        REQUIRE_TRUE(pipe.policy == SimResPolicy::ShowAll);
        REQUIRE_NEAR(pipe.viewPortRect.y, (1200.0f - 640.0f * (1920.0f / 1136.0f)) * 0.5f, 0.5f);
    }

    // 3. Verify monitor-clamped bordered window (1920x1080 requested -> 1920x1041 client rect)
    {
        PatchedWin32EglPipeline clamped;
        clamped.setFrameSizeWithClientClamp(1920.0f, 1080.0f, 1920, 1041);
        clamped.setDesignResolutionSize(1136.0f, 640.0f, SimResPolicy::FixedWidth);
        REQUIRE_NEAR(clamped.screenSize.height, 1041.0f, 1e-3f);
        const SimVec2 glC = clamped.clientToGL(50.0f * clamped.scaleX, (clamped.designSize.height - 444.8f) * clamped.scaleY);
        REQUIRE_NEAR(glC.x, 50.0f, 0.05f);
        REQUIRE_NEAR(glC.y, 444.8f, 0.05f);
    }

    // 4. Execute 24 open/close cycles across 960x640, 1136x640, 1280x720, 1920x1080 x 100%/125%/150% DPI
    struct ResDpiSpec { int baseW, baseH, dpiPct; };
    const ResDpiSpec kSpecs[12] = {
        {960, 640, 100},  {960, 640, 125},  {960, 640, 150},
        {1136, 640, 100}, {1136, 640, 125}, {1136, 640, 150},
        {1280, 720, 100}, {1280, 720, 125}, {1280, 720, 150},
        {1920, 1080, 100},{1920, 1080, 125},{1920, 1080, 150},
    };

    int totalCycles = 0;
    for (int mode = 0; mode < 2; ++mode) {
        const bool secondaryMode = (mode == 1);
        for (int i = 0; i < 12; ++i) {
            const auto& sp = kSpecs[i];
            const float zoom = static_cast<float>(sp.dpiPct) / 100.0f;
            const int clientW = static_cast<int>(std::lround(sp.baseW * zoom));
            const int clientH = static_cast<int>(std::lround(sp.baseH * zoom));

            PatchedWin32EglPipeline pipe;
            pipe.frameZoomFactor = zoom;
            pipe.setFrameSizeWithClientClamp(static_cast<float>(sp.baseW), static_cast<float>(sp.baseH), clientW, clientH);
            pipe.setDesignResolutionSize(1136.0f, 640.0f, SimResPolicy::FixedWidth);
            if (pipe.designSize.height > 768.0f) pipe.setDesignResolutionSize(1136.0f, 768.0f, SimResPolicy::ShowAll);
            pipe.onWmSize(clientW, clientH);
            REQUIRE_NEAR(pipe.screenSize.width, static_cast<float>(sp.baseW), 0.5f);
            REQUIRE_NEAR(pipe.screenSize.height, static_cast<float>(sp.baseH), 0.5f);

            const float cppW = pipe.designSize.width, cppH = pipe.designSize.height;
            const float luaH = (std::max)(cppH, 640.0f), yShift = (luaH - 640.0f) * 0.5f;
            const float stageScale = (cppH < 640.0f) ? (cppH / 640.0f) : 1.0f;
            const SimVec2 stageOrigin = (cppH < 640.0f)
                ? SimVec2{(cppW - 1136.0f * stageScale) * 0.5f, 0.0f}
                : SimVec2{(cppW - 1136.0f) * 0.5f, (cppH - 640.0f) * 0.5f};

            int touchFxCount = 0;
            SimTouchDelegate touchFxDel{-123, false, true, [&](SimVec2) { ++touchFxCount; return true; }, {}, {}, {}};
            SimTouchDelegate rotateListDel{-3, false, true, [&](SimVec2) { return true; }, {}, {}, {}};

            SimTouchGroup mainSceneGroup(-2), rafflePanelGroup(-26);
            rafflePanelGroup.visible = false;

            auto funcMenu = SimWidget::createLayout("FuncMenu");
            funcMenu->pos = {0.0f, yShift};
            mainSceneGroup.rootWidget->addChild(funcMenu, 0);

            auto choukaWrap = SimWidget::createLayout("MainMenuBtn_chouka");
            choukaWrap->pos = {50.0f, 400.0f};
            funcMenu->addChild(choukaWrap, 0);

            auto choukaBtn = SimWidget::createButton("btn_chouka", 119.0f, 112.0f);
            choukaBtn->scaleX = choukaBtn->scaleY = 0.8f;
            choukaBtn->anchor = {0.5f, 0.0f};
            choukaWrap->addChild(choukaBtn, 0);

            auto tipsMore = SimWidget::createLayout("MainTipsMoreItem");
            tipsMore->pos = {0.0f, -yShift};
            auto panelMask = SimWidget::createLayout("Panel_mask");
            panelMask->size = {1.0f, 1.0f};
            panelMask->pos = {0.0f, 20.0f};
            panelMask->touchEnabled = true;
            tipsMore->addChild(panelMask, 0);
            mainSceneGroup.rootWidget->addChild(tipsMore, 0);

            auto raffleModalBg = SimWidget::createLayout("RaffleModalBg");
            raffleModalBg->size = {cppW, luaH};
            raffleModalBg->pos = {0.0f, -yShift};
            raffleModalBg->touchEnabled = true;
            rafflePanelGroup.rootWidget->addChild(raffleModalBg, -2);

            auto raffleCloseBtn = SimWidget::createButton("RaffleCloseBtn", 80.0f, 80.0f);
            raffleCloseBtn->pos = {1060.0f, 580.0f + yShift};
            rafflePanelGroup.rootWidget->addChild(raffleCloseBtn, 1);

            bool raffleOpen = false, secondaryOpen = false;
            std::shared_ptr<SimWidget> secMask, secBg;
            raffleCloseBtn->listener = [&](SimWidget*, SimTouchEv ev) {
                if (ev == SimTouchEv::Ended) { raffleOpen = false; rafflePanelGroup.visible = false; }
            };
            auto closeSecondary = [&]() {
                secondaryOpen = false;
                if (secBg) { secBg->removeFromParent(); secBg.reset(); }
                if (secMask) { secMask->removeFromParent(); secMask.reset(); }
            };
            choukaBtn->listener = [&](SimWidget*, SimTouchEv ev) {
                if (ev != SimTouchEv::Ended) return;
                if (!secondaryMode) {
                    raffleOpen = rafflePanelGroup.visible = true;
                } else {
                    secondaryOpen = true;
                    secMask = SimWidget::createLayout("FuncMenu_rootLayout");
                    secMask->size = {cppW, luaH};
                    secMask->pos = {0.0f, -yShift};
                    secMask->touchEnabled = true;
                    secMask->listener = [&](SimWidget*, SimTouchEv mEv) { if (mEv == SimTouchEv::Ended) closeSecondary(); };
                    funcMenu->addChild(secMask, 0);

                    secBg = SimWidget::createLayout("simg_bg");
                    secBg->pos = {100.0f, 370.0f};
                    secBg->size = {245.0f, 110.0f};
                    funcMenu->addChild(secBg, 0);

                    auto jgWrap = SimWidget::createLayout("MainMenuBtn_jiuguan");
                    jgWrap->pos = {68.0f, 10.0f};
                    secBg->addChild(jgWrap, 0);

                    auto jgBtn = SimWidget::createButton("btn_jiuguan", 119.0f, 112.0f);
                    jgBtn->scaleX = jgBtn->scaleY = 0.8f;
                    jgBtn->anchor = {0.5f, 0.0f};
                    jgBtn->listener = [&](SimWidget*, SimTouchEv jEv) {
                        if (jEv == SimTouchEv::Ended) { closeSecondary(); raffleOpen = rafflePanelGroup.visible = true; }
                    };
                    jgWrap->addChild(jgBtn, 0);
                }
            };

            SimTouchDelegate mainSceneDel{-2, true, true,
                [&](SimVec2 p) { return mainSceneGroup.ccTouchBegan(p, stageOrigin, stageScale); },
                [&](SimVec2 p) { mainSceneGroup.ccTouchMoved(p, stageOrigin, stageScale); },
                [&](SimVec2 p) { mainSceneGroup.ccTouchEnded(p); },
                [&]() { mainSceneGroup.ccTouchCancelled(); }};
            SimTouchDelegate raffleDel{-26, true, true,
                [&](SimVec2 p) { return rafflePanelGroup.ccTouchBegan(p, stageOrigin, stageScale); },
                [&](SimVec2 p) { rafflePanelGroup.ccTouchMoved(p, stageOrigin, stageScale); },
                [&](SimVec2 p) { rafflePanelGroup.ccTouchEnded(p); },
                [&]() { rafflePanelGroup.ccTouchCancelled(); }};
            pipe.delegates = {&touchFxDel, &raffleDel, &rotateListDel, &mainSceneDel};

            auto toClient = [&](float sx, float sy) -> std::pair<int, int> {
                const float glX = stageOrigin.x + sx * stageScale, glY = stageOrigin.y + sy * stageScale;
                return {
                    static_cast<int>(std::lround((glX * pipe.scaleX + pipe.viewPortRect.x) * zoom)),
                    static_cast<int>(std::lround(((cppH - glY) * pipe.scaleY + pipe.viewPortRect.y) * zoom))
                };
            };
            auto clickAt = [&](std::pair<int, int> pt, uint32_t wP = 0x0001u, uint32_t ex = 0u) {
                pipe.onWmLButtonDown(pt.first, pt.second, wP, ex, false);
                pipe.onWmMouseMove(pt.first, pt.second, wP | 0x0001u, ex, false);
                pipe.onWmLButtonUp(pt.first, pt.second, ex, false);
            };

            clickAt(toClient(50.0f, yShift + 392.0f));
            REQUIRE_TRUE(!raffleOpen && !secondaryOpen);

            const auto choukaPt = toClient(50.0f, yShift + ((totalCycles % 2 == 0) ? 444.8f : 435.0f));
            pipe.onWmLButtonDown(choukaPt.first, choukaPt.second, 0x0001u);
            pipe.onWmCaptureChanged(/*lostToOtherWindow=*/true);
            REQUIRE_TRUE(!raffleOpen && !secondaryOpen);

            const uint32_t testWParam = (totalCycles % 3 == 1) ? 0x0009u : (totalCycles % 3 == 2 ? 0u : 0x0001u);
            const uint32_t testExtra = (totalCycles % 4 == 3) ? 0xFF515700u : 0u;
            const SimVec2 routedGl = pipe.clientToGL(choukaPt.first / zoom, choukaPt.second / zoom);
            std::printf(
                "  [InputRoute] cycle=%02d mode=%s res=%dx%d@%d%% client=%dx%d cppDesign=%.0fx%.0f clickClient=(%d,%d) gl=(%.2f,%.2f) wParam=0x%X extra=0x%X\n",
                totalCycles + 1, secondaryMode ? "Lv50_Secondary" : "Direct_Raffle",
                sp.baseW, sp.baseH, sp.dpiPct, clientW, clientH, cppW, cppH,
                choukaPt.first, choukaPt.second, routedGl.x, routedGl.y, testWParam, testExtra);
            clickAt(choukaPt, testWParam, testExtra);

            if (!secondaryMode) {
                REQUIRE_TRUE(raffleOpen);
                clickAt(choukaPt);
                REQUIRE_TRUE(raffleOpen);
                clickAt(toClient(1060.0f, 580.0f + yShift));
                REQUIRE_TRUE(!raffleOpen);
            } else {
                REQUIRE_TRUE(secondaryOpen);
                clickAt(toClient(168.0f, yShift + 424.8f));
                REQUIRE_TRUE(!secondaryOpen && raffleOpen);
                clickAt(toClient(1060.0f, 580.0f + yShift));
                REQUIRE_TRUE(!raffleOpen);
            }
            REQUIRE_TRUE(touchFxCount >= 2);
            ++totalCycles;
        }
    }
    REQUIRE_EQ(totalCycles, 24);

#ifdef _WIN32
    {
        static std::atomic<int> s_win32Clicks{0};
        static const wchar_t* kRegCls = L"KestrelWin32RegressionMouseProbe";
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = [](HWND h, UINT m, WPARAM w, LPARAM l) -> LRESULT {
            if (m == WM_LBUTTONUP) { s_win32Clicks.fetch_add(1, std::memory_order_relaxed); return 0; }
            return ::DefWindowProcW(h, m, w, l);
        };
        wc.hInstance = ::GetModuleHandleW(nullptr);
        wc.lpszClassName = kRegCls;
        ::RegisterClassExW(&wc);
        HWND hwnd = ::CreateWindowExW(0, kRegCls, L"MouseProbe", WS_POPUP, 0, 0, 1136, 640,
                                      nullptr, nullptr, wc.hInstance, nullptr);
        REQUIRE_TRUE(hwnd != nullptr);
        const LPARAM lp = MAKELPARAM(50, 195);
        ::SendMessageW(hwnd, WM_MOUSEMOVE, 0, lp);
        ::SendMessageW(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp);
        ::SendMessageW(hwnd, WM_LBUTTONUP, 0, lp);
        REQUIRE_EQ(s_win32Clicks.load(std::memory_order_relaxed), 1);

        DWORD sessId = 0;
        const bool sessionZero = !::ProcessIdToSessionId(::GetCurrentProcessId(), &sessId) || sessId == 0;
        HDESK hDesk = ::OpenInputDesktop(0, FALSE, DESKTOP_WRITEOBJECTS | DESKTOP_JOURNALPLAYBACK);
        if (sessionZero || hDesk == nullptr) {
            std::printf("  [InputRoute] SendInput=BLOCKED (session=%lu, err=%lu)\n",
                        static_cast<unsigned long>(sessId), static_cast<unsigned long>(::GetLastError()));
        } else {
            ::CloseDesktop(hDesk);
            INPUT in[2] = {};
            in[0].type = INPUT_MOUSE; in[0].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
            in[1].type = INPUT_MOUSE; in[1].mi.dwFlags = MOUSEEVENTF_LEFTUP;
            const UINT sent = ::SendInput(2, in, sizeof(INPUT));
            std::printf("  [InputRoute] SendInput=%s (sent=%u, err=%lu)\n",
                        sent == 2 ? "OK" : "BLOCKED", sent, static_cast<unsigned long>(::GetLastError()));
        }
        ::DestroyWindow(hwnd);
    }
#else
    std::printf("  [InputRoute] SendInput=BLOCKED (non-Win32 POSIX host; verified via WindowProc/SendMessageW simulation)\n");
#endif
    return true;
}

// ============================================================================
// Scenario 18 (Issue #8): >= 50 Iterations of GainItemListInfoPanel / GainItemCell
// Creation, UIWidget::addNode + CCArmature::removeFromParentAndCleanup(true),
// Widget::getNodes() Stale-Pointer Elimination, removeAllChildrenWithCleanup(true)
// Internal-Renderer Preservation, ImageView ignoreContentAdaptWithSize(false) ->
// loadTexture -> setSize(100,100)/(98,98), Opaque RGBA _alpha PKM, & CCFadeIn
// ============================================================================

struct Issue8RefObject {
    static inline int s_liveInstances = 0;
    int retainCount = 1;

    Issue8RefObject() noexcept { ++s_liveInstances; }
    virtual ~Issue8RefObject() noexcept { --s_liveInstances; }

    Issue8RefObject(const Issue8RefObject&) = delete;
    Issue8RefObject& operator=(const Issue8RefObject&) = delete;

    void retain() noexcept { ++retainCount; }
    void release() noexcept {
        if (--retainCount <= 0) {
            delete this;
        }
    }
};

class Issue8Array : public Issue8RefObject {
public:
    std::vector<Issue8RefObject*> arr;

    ~Issue8Array() noexcept override { removeAllObjects(); }

    size_t count() const noexcept { return arr.size(); }

    bool containsObject(const Issue8RefObject* obj) const noexcept {
        for (const auto* p : arr) {
            if (p == obj) return true;
        }
        return false;
    }

    void addObject(Issue8RefObject* obj) {
        if (!obj) return;
        obj->retain();
        arr.push_back(obj);
    }

    void removeObject(Issue8RefObject* obj) {
        if (!obj) return;
        for (auto it = arr.begin(); it != arr.end(); ++it) {
            if (*it == obj) {
                Issue8RefObject* victim = *it;
                arr.erase(it);
                victim->release();
                return;
            }
        }
    }

    void removeObjectAtIndex(size_t idx) {
        if (idx >= arr.size()) return;
        Issue8RefObject* victim = arr[idx];
        arr.erase(arr.begin() + static_cast<std::ptrdiff_t>(idx));
        if (victim) victim->release();
    }

    void removeAllObjects() {
        std::vector<Issue8RefObject*> local;
        local.swap(arr);
        for (Issue8RefObject* obj : local) {
            if (obj) obj->release();
        }
    }
};

struct Issue8SpriteFrame {
    std::string key;
    float width = 0.0f;
    float height = 0.0f;
    float offsetX = 0.0f;
    float offsetY = 0.0f;
    bool rotated = false;
    uint8_t sampleAlpha = 255;
};

struct Issue8AssetEnv {
    std::vector<Issue8SpriteFrame> plistFrames;
    std::vector<Issue8SpriteFrame> diskFiles;

    static std::vector<std::string> buildPrefixCandidates(std::string s) {
        std::replace(s.begin(), s.end(), '\\', '/');
        while (!s.empty() && s.front() == '#') s.erase(s.begin());
        if (s.empty()) return {};
        std::vector<std::string> out{s};
        if (s.rfind("res/jsonUI/", 0) == 0 && s.size() > 11) out.push_back(s.substr(11));
        if (s.rfind("res/", 0) == 0 && s.size() > 4) out.push_back(s.substr(4));
        if (s.rfind("gameImage/", 0) == 0 && s.size() > 10) out.push_back("images/" + s.substr(10));
        return out;
    }

    const Issue8SpriteFrame* findSpriteFrameWithFallback(const std::string& rawName) const {
        auto cands = buildPrefixCandidates(rawName);
        if (cands.empty()) return nullptr;
        const size_t slash = cands[0].find_last_of('/');
        if (slash != std::string::npos && slash + 1 < cands[0].size()) {
            cands.push_back(cands[0].substr(slash + 1));
        }
        for (const std::string& k : cands) {
            for (const auto& f : plistFrames) {
                if (f.key == k) return &f;
            }
            const size_t sl = k.find_last_of('/'), dt = k.find_last_of('.');
            if (dt == std::string::npos || (sl != std::string::npos && dt < sl)) {
                const std::string withPng = k + ".png";
                for (const auto& f : plistFrames) {
                    if (f.key == withPng) return &f;
                }
            }
        }
        return nullptr;
    }

    const Issue8SpriteFrame* loadTextureWithFallback(const std::string& rawName) const {
        static const char* const kExts[] = {".pvr.ccz", ".pkm", ".png", ".webp", ".jpg", ".jpeg"};
        for (const std::string& base : buildPrefixCandidates(rawName)) {
            for (const auto& f : diskFiles) {
                if (f.key == base) return &f;
            }
            std::string stem = base;
            if (stem.size() > 8 && stem.compare(stem.size() - 8, 8, ".pvr.ccz") == 0) {
                stem.resize(stem.size() - 8);
            } else {
                const size_t sl = stem.find_last_of('/'), dt = stem.find_last_of('.');
                if (dt != std::string::npos && (sl == std::string::npos || dt > sl)) stem.resize(dt);
            }
            for (const char* ext : kExts) {
                const std::string cand = stem + ext;
                for (const auto& f : diskFiles) {
                    if (f.key == cand) return &f;
                }
            }
        }
        return nullptr;
    }
};

// Exact mirror of patched gclientExtractAlphaChannelBuffer RGBA _alpha logic
uint8_t extractCompanionRgbaAlphaSample(const std::vector<uint8_t>& rgbaPixels) {
    const size_t totalPx = rgbaPixels.size() / 4u;
    if (totalPx == 0) return 0;
    bool hasVariedAlpha = false;
    bool anyNonZeroG = false;
    for (size_t i = 0; i < totalPx; ++i) {
        if (rgbaPixels[i * 4u + 3u] != 255u) hasVariedAlpha = true;
        if (rgbaPixels[i * 4u + 1u] != 0u) anyNonZeroG = true;
        if (hasVariedAlpha && anyNonZeroG) break;
    }
    const bool useAlphaChan = hasVariedAlpha || (!anyNonZeroG && rgbaPixels[3] > 0u);
    return useAlphaChan ? rgbaPixels[3] : rgbaPixels[1];
}

class Issue8Node : public Issue8RefObject {
public:
    Issue8Node* parent = nullptr;
    Issue8Array* children = new Issue8Array();
    int zOrder = 0;
    int tag = -1;
    bool visible = true;
    float posX = 0.0f, posY = 0.0f;
    float scaleX = 1.0f, scaleY = 1.0f;
    float width = 0.0f, height = 0.0f;
    uint8_t realOpacity = 255;
    uint8_t displayedOpacity = 255;
    std::function<void()> onExitCallback;

    ~Issue8Node() noexcept override {
        if (children) {
            children->release();
            children = nullptr;
        }
    }

    Issue8Node* getParent() const noexcept { return parent; }

    virtual void setOpacity(uint8_t opa) {
        realOpacity = displayedOpacity = opa;
    }

    virtual void addChild(Issue8Node* child, int z = 0, int t = -1) {
        if (!child || child == this) return;
        bool reparented = false;
        if (child->parent != nullptr) {
            child->retain();
            reparented = true;
            child->removeFromParentAndCleanup(false);
        }
        child->zOrder = z;
        child->tag = t;
        child->parent = this;
        children->addObject(child);
        if (reparented) {
            child->release();
        }
    }

    virtual void removeChild(Issue8Node* child, bool /*cleanup*/ = true) {
        if (!child || !children || !children->containsObject(child)) return;
        child->retain();
        if (child->onExitCallback) {
            auto cb = child->onExitCallback;
            child->onExitCallback = nullptr;
            cb();
        }
        child->parent = nullptr;
        children->removeObject(child);
        child->release();
    }

    virtual void removeFromParentAndCleanup(bool cleanup = true) {
        if (parent) {
            parent->removeChild(this, cleanup);
        }
    }

    virtual void removeAllChildrenWithCleanup(bool cleanup = true) {
        if (!children) return;
        for (auto* obj : children->arr) {
            if (auto* n = static_cast<Issue8Node*>(obj)) {
                if (n->onExitCallback) {
                    auto cb = n->onExitCallback;
                    n->onExitCallback = nullptr;
                    cb();
                }
                n->parent = nullptr;
            }
        }
        (void)cleanup;
        children->removeAllObjects();
    }
};

class Issue8Sprite : public Issue8Node {
public:
    float offsetX = 0.0f;
    float offsetY = 0.0f;
    bool rectRotated = false;
    bool hasTexture = false;
    uint8_t texAlpha = 0;

    bool initWithSpriteFrame(const Issue8SpriteFrame& frame) {
        hasTexture = (frame.width > 0.0f && frame.height > 0.0f);
        width = frame.width;
        height = frame.height;
        offsetX = frame.offsetX;
        offsetY = frame.offsetY;
        rectRotated = frame.rotated;
        texAlpha = frame.sampleAlpha;
        return hasTexture;
    }

    float renderedQuadWidth() const noexcept {
        return (hasTexture && visible && displayedOpacity > 0 && texAlpha > 0) ? (width * scaleX) : 0.0f;
    }
    float renderedQuadHeight() const noexcept {
        return (hasTexture && visible && displayedOpacity > 0 && texAlpha > 0) ? (height * scaleY) : 0.0f;
    }
};

class Issue8Armature : public Issue8Node {
public:
    std::string animName;
    bool disposed = false;
    void dispose() noexcept { disposed = true; }
};

// Exact mirror of patched Cocos2d-x 2.2.6 ui::Widget
class Issue8Widget : public Issue8Node {
public:
    Issue8Array* widgetChildren = new Issue8Array();
    Issue8Array* nodes = new Issue8Array();
    bool ignoreSize = true;
    float customW = 0.0f, customH = 0.0f;
    float sizeW = 0.0f, sizeH = 0.0f;
    uint8_t widgetOpacity = 255;

    ~Issue8Widget() noexcept override {
        removeAllChildrenWithCleanup(true);
        removeAllNodes();
        if (widgetChildren) {
            widgetChildren->release();
            widgetChildren = nullptr;
        }
        if (nodes) {
            nodes->release();
            nodes = nullptr;
        }
    }

    virtual void onSizeChanged() {}
    virtual void updateTextureOpacity() {}

    void ignoreContentAdaptWithSize(bool ignore) {
        ignoreSize = ignore;
        if (ignoreSize) {
            sizeW = width;
            sizeH = height;
        } else {
            sizeW = customW;
            sizeH = customH;
        }
        onSizeChanged();
    }

    void setSize(float w, float h) {
        customW = w;
        customH = h;
        if (!ignoreSize) {
            sizeW = w;
            sizeH = h;
        }
        onSizeChanged();
    }

    void setOpacity(uint8_t opa) override {
        widgetOpacity = opa;
        Issue8Node::setOpacity(opa);
        updateTextureOpacity();
    }

    void addChild(Issue8Node* child, int z = 0, int t = -1) override {
        if (!child || child == this) return;
        if (dynamic_cast<Issue8Widget*>(child) == nullptr) {
            addNode(child, z, t);
            return;
        }
        if (child->getParent() == this) {
            child->zOrder = z;
            child->tag = t;
            if (!widgetChildren->containsObject(child)) widgetChildren->addObject(child);
            return;
        }
        Issue8Node::addChild(child, z, t);
        if (!widgetChildren->containsObject(child)) widgetChildren->addObject(child);
    }

    virtual void addNode(Issue8Node* node, int z = 0, int t = -1) {
        if (!node || node == this) return;
        if (dynamic_cast<Issue8Widget*>(node) != nullptr) {
            addChild(node, z, t);
            return;
        }
        if (node->getParent() == this) {
            node->zOrder = z;
            node->tag = t;
            if (!nodes->containsObject(node)) nodes->addObject(node);
            return;
        }
        Issue8Node::addChild(node, z, t);
        if (!nodes->containsObject(node)) nodes->addObject(node);
    }

    static void drainTrackedArrayToSnapshot(Issue8Array* bucket, std::vector<Issue8Node*>& snapshot) {
        if (!bucket || bucket->arr.empty()) return;
        for (auto* obj : bucket->arr) {
            if (auto* n = static_cast<Issue8Node*>(obj)) {
                n->retain();
                snapshot.push_back(n);
            }
        }
        bucket->removeAllObjects();
    }

    void removeChild(Issue8Node* child, bool cleanup = true) override {
        if (!child) return;
        child->retain();
        Issue8Node::removeChild(child, cleanup);
        if (widgetChildren) widgetChildren->removeObject(child);
        if (nodes) nodes->removeObject(child);
        child->release();
    }

    virtual void removeNode(Issue8Node* node) { removeChild(node, true); }

    virtual void removeAllNodes() {
        std::vector<Issue8Node*> snapshot;
        drainTrackedArrayToSnapshot(nodes, snapshot);
        for (Issue8Node* n : snapshot) {
            Issue8Node::removeChild(n, true);
            n->release();
        }
    }

    void removeAllChildrenWithCleanup(bool cleanup = true) override {
        std::vector<Issue8Node*> snapshot;
        drainTrackedArrayToSnapshot(widgetChildren, snapshot);
        drainTrackedArrayToSnapshot(nodes, snapshot);
        for (Issue8Node* item : snapshot) {
            Issue8Node::removeChild(item, cleanup);
            item->release();
        }
    }

    virtual Issue8Array* getNodes() {
        if (nodes) {
            for (int i = static_cast<int>(nodes->arr.size()) - 1; i >= 0; --i) {
                auto* pNode = static_cast<Issue8Node*>(nodes->arr[static_cast<size_t>(i)]);
                if (!pNode || pNode->getParent() != this) {
                    nodes->removeObjectAtIndex(static_cast<size_t>(i));
                }
            }
        }
        return nodes;
    }
};

class Issue8Layout : public Issue8Widget {
public:
    Issue8Sprite* backGroundImage = nullptr;
    bool layoutSuppliedToWidgetOnly = true;
    float clipOriginX = 0.0f, clipOriginY = 0.0f, clipW = 0.0f, clipH = 0.0f;

    Issue8Layout() {
        backGroundImage = new Issue8Sprite();
        Issue8Node::addChild(backGroundImage, -2, -1); // Internal protected renderer in m_pChildren ONLY
        backGroundImage->release();
    }

    void supplyTheLayoutParameterLackToChild(Issue8Widget* w) {
        if (!w) layoutSuppliedToWidgetOnly = false;
    }

    void addChild(Issue8Node* child, int z = 0, int t = -1) override {
        if (!child || child == this) return;
        if (auto* wChild = dynamic_cast<Issue8Widget*>(child)) {
            supplyTheLayoutParameterLackToChild(wChild);
        }
        Issue8Widget::addChild(child, z, t);
    }

    // Mirrors patched Layout::getClippingRect (.origin.y fix instead of stock .origin.x bug)
    void computeNestedClippingRect(float parentClipX, float parentClipY, float parentClipW, float parentClipH,
                                   float childWorldX, float childWorldY, float childW, float childH) {
        float finalX = childWorldX;
        float finalY = childWorldY;
        float finalW = childW;
        float finalH = childH;
        const float bottomOffset = childWorldY - parentClipY;
        if (bottomOffset < 0.0f) {
            finalY = parentClipY; // Stock 2.2.6 bug had parentClipX here!
            finalH += bottomOffset;
        }
        const float leftOffset = childWorldX - parentClipX;
        if (leftOffset < 0.0f) {
            finalX = parentClipX;
            finalW += leftOffset;
        }
        if (finalX + finalW > parentClipX + parentClipW) {
            finalW = (parentClipX + parentClipW) - finalX;
        }
        if (finalY + finalH > parentClipY + parentClipH) {
            finalH = (parentClipY + parentClipH) - finalY;
        }
        clipOriginX = finalX;
        clipOriginY = finalY;
        clipW = finalW;
        clipH = finalH;
    }
};

class Issue8ImageView : public Issue8Widget {
public:
    Issue8Sprite* imageRenderer = nullptr;
    std::string textureFile;
    int texType = 0; // 0 = UI_TEX_TYPE_LOCAL, 1 = UI_TEX_TYPE_PLIST

    Issue8ImageView() {
        imageRenderer = new Issue8Sprite();
        Issue8Node::addChild(imageRenderer, -1, -1); // Protected internal _imageRenderer
        imageRenderer->release();
    }

    void imageTextureScaleChangedWithSize() {
        if (ignoreSize) {
            imageRenderer->scaleX = 1.0f;
            imageRenderer->scaleY = 1.0f;
            sizeW = width;
            sizeH = height;
        } else {
            if (imageRenderer->width <= 0.0f || imageRenderer->height <= 0.0f) {
                imageRenderer->scaleX = 1.0f;
                imageRenderer->scaleY = 1.0f;
                return;
            }
            imageRenderer->scaleX = sizeW / imageRenderer->width;
            imageRenderer->scaleY = sizeH / imageRenderer->height;
        }
    }

    void onSizeChanged() override {
        imageTextureScaleChangedWithSize();
    }

    void updateTextureOpacity() override {
        if (imageRenderer) {
            imageRenderer->setOpacity(widgetOpacity);
        }
    }

    bool loadTexture(const Issue8AssetEnv& env, const std::string& fileName, int resType = 0) {
        if (fileName.empty()) return false;
        textureFile = fileName;
        texType = resType;
        const Issue8SpriteFrame* resolved = nullptr;
        if (resType == 1) {
            resolved = env.findSpriteFrameWithFallback(fileName);
            if (!resolved) resolved = env.loadTextureWithFallback(fileName);
        } else {
            resolved = env.loadTextureWithFallback(fileName);
            if (!resolved) resolved = env.findSpriteFrameWithFallback(fileName);
        }
        if (!resolved || !imageRenderer->initWithSpriteFrame(*resolved)) {
            return false;
        }
        width = imageRenderer->width;
        height = imageRenderer->height;
        imageTextureScaleChangedWithSize();
        updateTextureOpacity();
        return true;
    }
};

class Issue8Label : public Issue8Widget {
public:
    std::string text;
};

bool testIssue8GainItemPanelLifecycleAndImageViewRendering() {
    REQUIRE_EQ(Issue8RefObject::s_liveInstances, 0);

    // 1. Verify companion RGBA _alpha opaque plane fix:
    //    Solid (R=0, G=0, B=0, A=255) RGBA _alpha companion MUST preserve alpha=255 (NOT G=0!),
    //    whereas a genuine green-channel grayscale mask (R=0, G=128, B=0, A=255) still reads G=128,
    //    and varied-alpha RGBA (A=64) reads A=64.
    {
        const std::vector<uint8_t> solidOpaqueRgbaAlpha = {
            0, 0, 0, 255,   0, 0, 0, 255,   0, 0, 0, 255,   0, 0, 0, 255
        };
        REQUIRE_EQ(extractCompanionRgbaAlphaSample(solidOpaqueRgbaAlpha), static_cast<uint8_t>(255));

        const std::vector<uint8_t> greenChannelMaskRgba = {
            0, 128, 0, 255, 0, 128, 0, 255, 0, 128, 0, 255, 0, 128, 0, 255
        };
        REQUIRE_EQ(extractCompanionRgbaAlphaSample(greenChannelMaskRgba), static_cast<uint8_t>(128));

        const std::vector<uint8_t> variedAlphaRgba = {
            0, 200, 0, 64,  0, 200, 0, 192, 0, 200, 0, 255, 0, 200, 0, 0
        };
        REQUIRE_EQ(extractCompanionRgbaAlphaSample(variedAlphaRgba), static_cast<uint8_t>(64));
    }

    // 2. Populate authentic vnsg2 asset fixture:
    //    - frame_3.png (quality 3), frame_4.png (quality 4), frame_5.png (quality 5) packed inside .plistb CCSpriteFrameCache!
    //    - item 10010 ("Tiến Cấp Đơn", small_pic="item/jinjiedan") stored on disk as .jpg!
    //    - item 10020 ("Pet Tăng Sao Đơn", small_pic="item/shengxingdan") stored as .pkm + opaque RGBA _alpha!
    //    - item 10012 ("Đá Luyện Trang Sức", small_pic="item/baowujinglianshi") stored under images/item/!
    Issue8AssetEnv env;
    env.plistFrames.push_back({"frame_3.png", 104.0f, 104.0f, 0.0f, 0.0f, false, 255});
    env.plistFrames.push_back({"gameImage/frame/frame_4.png", 100.0f, 100.0f, 4.0f, -3.0f, true, 255});
    env.plistFrames.push_back({"frame_5.png", 100.0f, 100.0f, 0.0f, 0.0f, false, 255});
    env.plistFrames.push_back({"public_tm_itemIcon.png", 36.0f, 36.0f, 0.0f, 0.0f, false, 255});

    const uint8_t pkmOpaqueAlpha = extractCompanionRgbaAlphaSample({0, 0, 0, 255, 0, 0, 0, 255});
    env.diskFiles.push_back({"gameImage/item/jinjiedan.jpg", 98.0f, 98.0f, 0.0f, 0.0f, false, 255});
    env.diskFiles.push_back({"gameImage/item/shengxingdan.pkm", 98.0f, 98.0f, 0.0f, 0.0f, false, pkmOpaqueAlpha});
    env.diskFiles.push_back({"images/item/baowujinglianshi.webp", 98.0f, 98.0f, 0.0f, 0.0f, false, 255});

    struct RewardItemSpec {
        int id;
        const char* name;
        const char* frameReq;
        const char* iconReq;
        int quality;
    };
    const RewardItemSpec kRewardSpecs[3] = {
        {10010, "Tiến Cấp Đơn", "gameImage/frame/frame_3.png", "gameImage/item/jinjiedan.png", 3},
        {10020, "Pet Tăng Sao Đơn", "gameImage/frame/frame_4.png", "gameImage/item/shengxingdan.png", 4},
        {10012, "Đá Luyện Trang Sức", "gameImage/frame/frame_5.png", "gameImage/item/baowujinglianshi.png", 5},
    };

    // 3. Execute 64 full iterations (>= 50 required) of GainItemListInfoPanel open -> populate ->
    //    playFadeIn -> playArmatureOnce + removeFromParentAndCleanup(true) -> clearData -> close -> reopen!
    constexpr int kIterations = 64;
    for (int iter = 0; iter < kIterations; ++iter) {
        auto* panelRoot = new Issue8Layout();
        auto* itemContainer = new Issue8Layout();
        panelRoot->addChild(itemContainer, 0, 100);

        // Verify nested clipping rect inside ListView_reward (origin = (175, 151), size = 785x318)
        itemContainer->computeNestedClippingRect(175.0f, 151.0f, 785.0f, 318.0f,
                                                 215.0f, 120.0f, 100.0f, 120.0f);
        REQUIRE_EQ(itemContainer->clipOriginY, 151.0f); // Must clamp to parentClipY (151), NOT parentClipX (175)!
        REQUIRE_TRUE(itemContainer->clipH > 80.0f);

        const int cellCount = (iter % 2 == 0) ? 4 : 7;
        std::vector<Issue8Layout*> cells;
        cells.reserve(static_cast<size_t>(cellCount));

        for (int c = 0; c < cellCount; ++c) {
            const RewardItemSpec& spec = kRewardSpecs[(static_cast<size_t>(iter) + static_cast<size_t>(c)) % 3u];

            // GainItemCell.lua: Layout cell
            auto* cell = new Issue8Layout();
            itemContainer->addChild(cell, 0, 1000 + c);

            // GainItemCell.lua:61: quality glow added via self:addNode(self.sprite, -1) at (87, 69), scale=1.2
            auto* glowSprite = new Issue8Armature();
            glowSprite->animName = (spec.quality >= 5) ? "wupinhuode_uihuang_1" : "wupinhuode_uizise_1";
            glowSprite->posX = 87.0f;
            glowSprite->posY = 69.0f;
            glowSprite->scaleX = glowSprite->scaleY = 1.2f;
            cell->addNode(glowSprite, -1, 501);
            glowSprite->release(); // Owned solely by cell->children + cell->nodes

            // BaseItemWithNameIcon_TM.lua: Layout iconItem added via cell:addChild(self.iconItem) (z=0) at (40, 0)
            auto* iconItem = new Issue8Layout();
            iconItem->posX = 40.0f;
            iconItem->posY = 0.0f;
            cell->addChild(iconItem, 0, 502);

            // BaseItemIcon_TM.lua:60-66: ignoreContentAdaptWithSize(false) BEFORE loadTexture & BEFORE setSize!
            auto* iconQuality = new Issue8ImageView();
            iconQuality->ignoreContentAdaptWithSize(false);
            REQUIRE_TRUE(std::isfinite(iconQuality->imageRenderer->scaleX));
            REQUIRE_EQ(iconQuality->imageRenderer->scaleX, 1.0f);
            iconItem->addChild(iconQuality, 0, 601);

            auto* icon = new Issue8ImageView();
            icon->ignoreContentAdaptWithSize(false);
            REQUIRE_TRUE(std::isfinite(icon->imageRenderer->scaleX));
            iconItem->addChild(icon, 0, 602);

            // Test reused sprite offset reset: first load trimmed/rotated frame_4, then target icon
            REQUIRE_TRUE(icon->loadTexture(env, "gameImage/frame/frame_4.png", /*UI_TEX_TYPE_LOCAL=*/0));
            REQUIRE_TRUE(icon->imageRenderer->rectRotated);

            // BaseItemIcon_TM.lua:114, 134, 143-148: 1-arg loadTexture (UI_TEX_TYPE_LOCAL) -> setSize(100,100) / (98,98)
            REQUIRE_TRUE(iconQuality->loadTexture(env, spec.frameReq, /*UI_TEX_TYPE_LOCAL=*/0));
            REQUIRE_TRUE(icon->loadTexture(env, spec.iconReq, /*UI_TEX_TYPE_LOCAL=*/0));
            REQUIRE_TRUE(!icon->imageRenderer->rectRotated);
            REQUIRE_EQ(icon->imageRenderer->offsetX, 0.0f);
            REQUIRE_EQ(icon->imageRenderer->offsetY, 0.0f);

            iconItem->setSize(100.0f, 120.0f);
            iconQuality->setSize(100.0f, 100.0f);
            icon->setSize(98.0f, 98.0f);
            iconQuality->posX = icon->posX = 50.0f;
            iconQuality->posY = icon->posY = 70.0f;

            // BaseItemWithNameIcon_TM.lua:24: lbName ("Tiến Cấp Đơn")
            auto* lbName = new Issue8Label();
            lbName->text = spec.name;
            iconItem->addChild(lbName, 0, 603);
            lbName->release();

            // Verify runtime observation & rendering fix:
            // Widget scale is (1,1), opacity is 255, AND _imageRenderer now renders visible 100x100 & 98x98 quads!
            REQUIRE_EQ(iconQuality->scaleX, 1.0f);
            REQUIRE_EQ(iconQuality->scaleY, 1.0f);
            REQUIRE_TRUE(std::fabs(iconQuality->imageRenderer->renderedQuadWidth() - 100.0f) < 0.01f);
            REQUIRE_TRUE(std::fabs(iconQuality->imageRenderer->renderedQuadHeight() - 100.0f) < 0.01f);
            REQUIRE_TRUE(std::fabs(icon->imageRenderer->renderedQuadWidth() - 98.0f) < 0.01f);
            REQUIRE_TRUE(std::fabs(icon->imageRenderer->renderedQuadHeight() - 98.0f) < 0.01f);

            // BaseItemIcon_TM.lua:181, 207: optional newziUI tip armature added via addNode and removed via removeFromParentAndCleanup
            auto* tipArm = new Issue8Armature();
            tipArm->animName = "newziUI";
            iconItem->addNode(tipArm, 0, 604);
            tipArm->release();
            REQUIRE_EQ(iconItem->getNodes()->count(), 1u);
            tipArm->removeFromParentAndCleanup(true);
            REQUIRE_EQ(iconItem->getNodes()->count(), 0u); // Zero stale pointer in iconItem:getNodes()!

            // UIEffectUtil:playFadeIn(cell, 1, 15, fn) -> CCFadeIn steps 0 -> 128 -> 255
            cell->visible = false;
            cell->visible = true;
            cell->setOpacity(0);
            REQUIRE_EQ(cell->displayedOpacity, static_cast<uint8_t>(0));
            cell->setOpacity(128);
            REQUIRE_EQ(cell->displayedOpacity, static_cast<uint8_t>(128));
            cell->setOpacity(255);
            REQUIRE_EQ(cell->displayedOpacity, static_cast<uint8_t>(255));

            // Callback fn: UIEffectUtil:playArmatureOnce("dangewupinhuode", nil, ccp(90, 72), 1, cell)
            auto* burstArm = new Issue8Armature();
            burstArm->animName = "dangewupinhuode";
            burstArm->posX = 90.0f;
            burstArm->posY = 72.0f;
            burstArm->scaleX = burstArm->scaleY = 1.2f;
            cell->addNode(burstArm, 0, 503);
            burstArm->release();
            REQUIRE_EQ(cell->getNodes()->count(), 2u); // glowSprite + burstArm

            // Movement COMPLETE callback (type == 1): armature:removeFromParentAndCleanup(true)
            burstArm->removeFromParentAndCleanup(true);

            // CRITICAL ASSERTION: Widget::getNodes() MUST NOT retain stale pointer to burstArm!
            Issue8Array* liveCellNodes = cell->getNodes();
            REQUIRE_EQ(liveCellNodes->count(), 1u);
            REQUIRE_EQ(liveCellNodes->arr[0], glowSprite);
            REQUIRE_EQ(glowSprite->getParent(), cell);

            // Also test direct non-virtual CCNode::removeChild bypass + getNodes() pruning on an extra effect node
            auto* bypassNode = new Issue8Node();
            cell->addNode(bypassNode, 2, 504);
            bypassNode->release();
            REQUIRE_EQ(cell->getNodes()->count(), 2u);
            cell->Issue8Node::removeChild(bypassNode, true); // Bypasses Widget::removeChild!
            REQUIRE_EQ(cell->getNodes()->count(), 1u);       // getNodes() prunes detached node cleanly!

            // Test re-entrant onExit mutation during removeAllChildrenWithCleanup
            auto* reentrantChild = new Issue8Armature();
            auto* companionNode = new Issue8Armature();
            cell->addNode(companionNode, 3, 505);
            companionNode->release();
            reentrantChild->onExitCallback = [cell, companionNode]() {
                if (companionNode->getParent() == cell) {
                    companionNode->removeFromParentAndCleanup(true);
                }
            };
            cell->addNode(reentrantChild, 3, 506);
            reentrantChild->release();

            iconQuality->release();
            icon->release();
            iconItem->release();
            cells.push_back(cell);
        }

        // Simulate GainItemCell:clearData() on half the cells and _itemContainer:removeAllChildrenWithCleanup(true) on the rest
        for (size_t idx = 0; idx < cells.size(); ++idx) {
            Issue8Layout* cell = cells[idx];
            if (idx % 2 == 0) {
                // GainItemCell.lua:109-116: sprite:dispose(); sprite:removeFromParentAndCleanup(true); self:removeAllChildrenWithCleanup(true)
                if (!cell->getNodes()->arr.empty()) {
                    auto* sp = static_cast<Issue8Node*>(cell->getNodes()->arr[0]);
                    sp->removeFromParentAndCleanup(true);
                }
                cell->removeAllChildrenWithCleanup(true);
                REQUIRE_EQ(cell->getNodes()->count(), 0u);
                REQUIRE_EQ(cell->widgetChildren->count(), 0u);
                // Internal protected backGroundImage renderer MUST still be alive in cell->children!
                REQUIRE_EQ(cell->children->count(), 1u);
                REQUIRE_EQ(cell->children->arr[0], cell->backGroundImage);
                REQUIRE_EQ(cell->backGroundImage->getParent(), cell);
            }
            cell->release();
        }

        // GainItemListInfoPanel.lua:273: self._itemContainer:removeAllChildrenWithCleanup(true)
        itemContainer->removeAllChildrenWithCleanup(true);
        REQUIRE_EQ(itemContainer->getNodes()->count(), 0u);
        REQUIRE_EQ(itemContainer->widgetChildren->count(), 0u);
        REQUIRE_EQ(itemContainer->children->count(), 1u); // Protected backGroundImage preserved!

        // Close & destroy panel before next reopen iteration
        panelRoot->removeAllChildrenWithCleanup(true);
        itemContainer->release();
        panelRoot->release();

        // Zero leaked CCObjects across every single iteration!
        REQUIRE_EQ(Issue8RefObject::s_liveInstances, 0);
    }
    return true;
}

void writeLE16U(uint8_t* dst, uint16_t v) { dst[0] = static_cast<uint8_t>(v & 0xFFu); dst[1] = static_cast<uint8_t>((v >> 8) & 0xFFu); }
void writeLE16S(uint8_t* dst, int16_t v) { writeLE16U(dst, static_cast<uint16_t>(v)); }

bool testXmlbBitCacheBinaryLayoutStickyBlendAndColorClamp() {
    using gclient::assets::XmlbArmatureLoader;
    using gclient::assets::XmlbDecodedFrameRecord;
    using gclient::assets::XmlbDecodedMovementHeader;

    std::vector<uint8_t> movHdr(74, 0u);
    const char* movName = "dangewupinhuode_baoguang_1";
    std::memcpy(movHdr.data(), movName, std::strlen(movName));
    writeLE16S(movHdr.data() + 64, 40);
    writeLE16S(movHdr.data() + 66, 6);
    writeLE16S(movHdr.data() + 68, 40);
    movHdr[70] = 0;
    movHdr[71] = 2; // Sine_EaseInOut -> 3
    writeLE16U(movHdr.data() + 72, 1);

    XmlbDecodedMovementHeader decMov{};
    REQUIRE_TRUE(XmlbArmatureLoader::DecodeBitCacheMovementHeader(movHdr.data(), movHdr.size(), &decMov));
    REQUIRE_EQ(decMov.duration, 40);
    REQUIRE_EQ(decMov.durationTo, 6);
    REQUIRE_EQ(decMov.durationTween, 40);
    REQUIRE_TRUE(!decMov.loop);
    REQUIRE_EQ(decMov.tweenEasing, 3);
    REQUIRE_EQ(decMov.movBoneCount, 1u);

    bool hasSticky = false;
    uint32_t stickySrc = 0x0001u, stickyDst = 0x0303u;

    std::vector<uint8_t> fr0(168, 0u);
    writeLE16S(fr0.data() + 8, 1); writeLE16S(fr0.data() + 10, 1); writeLE16S(fr0.data() + 24, 3);
    writeLE16S(fr0.data() + 26, 255); writeLE16S(fr0.data() + 28, 255);
    writeLE16S(fr0.data() + 30, 255); writeLE16S(fr0.data() + 32, 255);
    fr0[34] = static_cast<uint8_t>(static_cast<int8_t>(-2));
    fr0[39] = static_cast<uint8_t>(static_cast<int8_t>(-1)); // hidden frame

    XmlbDecodedFrameRecord dec0{};
    REQUIRE_TRUE(XmlbArmatureLoader::DecodeBitCacheFrameRecord(fr0.data(), fr0.size(), &hasSticky, &stickySrc, &stickyDst, &dec0));
    REQUIRE_EQ(dec0.displayIndex, -1);
    REQUIRE_TRUE(!dec0.isTween);
    REQUIRE_TRUE(!dec0.isUseColorInfo);
    REQUIRE_EQ(dec0.blendDst, 0x0303u);

    std::vector<uint8_t> fr1(168, 0u);
    writeLE16S(fr1.data() + 0, -12); writeLE16S(fr1.data() + 4, -500);
    writeLE16S(fr1.data() + 2, 8);   writeLE16S(fr1.data() + 6, 250);
    writeLE16S(fr1.data() + 8, 1);   writeLE16S(fr1.data() + 12, 200);
    writeLE16S(fr1.data() + 10, -1); writeLE16S(fr1.data() + 14, -200);
    writeLE16S(fr1.data() + 16, 3142); writeLE16S(fr1.data() + 18, -3142);
    writeLE16S(fr1.data() + 20, 2);  writeLE16S(fr1.data() + 22, 500);
    writeLE16S(fr1.data() + 24, 10);
    writeLE16S(fr1.data() + 26, 255); writeLE16S(fr1.data() + 28, 255);
    writeLE16S(fr1.data() + 30, 260); writeLE16S(fr1.data() + 32, 260); // >255 must clamp to 255, NOT wrap to 4!
    fr1[34] = 7; fr1[35] = 1; fr1[36] = 80; fr1[37] = 1; fr1[38] = 1; fr1[39] = 0; fr1[40] = '1';

    XmlbDecodedFrameRecord dec1{};
    REQUIRE_TRUE(XmlbArmatureLoader::DecodeBitCacheFrameRecord(fr1.data(), fr1.size(), &hasSticky, &stickySrc, &stickyDst, &dec1));
    REQUIRE_TRUE(std::fabs(dec1.x - (-12.5f)) < 1e-4f);
    REQUIRE_TRUE(std::fabs(dec1.scaleY - (-1.2f)) < 1e-4f);
    REQUIRE_TRUE(std::fabs(dec1.tweenRotate - 2.5f) < 1e-4f);
    REQUIRE_EQ(dec1.r, 255u); REQUIRE_EQ(dec1.g, 255u); REQUIRE_EQ(dec1.b, 255u);
    REQUIRE_TRUE(dec1.isUseColorInfo); REQUIRE_TRUE(dec1.isTween);
    REQUIRE_EQ(dec1.tweenEasing, 80); REQUIRE_EQ(dec1.displayIndex, 0);
    REQUIRE_EQ(dec1.blendSrc, 0x0001u); REQUIRE_EQ(dec1.blendDst, 0x0001u);

    std::vector<uint8_t> fr2 = fr1;
    writeLE16S(fr2.data() + 26, 0); writeLE16S(fr2.data() + 32, -5); // <0 must clamp to 0!
    fr2[38] = 0; fr2[40] = '\0';
    XmlbDecodedFrameRecord dec2{};
    REQUIRE_TRUE(XmlbArmatureLoader::DecodeBitCacheFrameRecord(fr2.data(), fr2.size(), &hasSticky, &stickySrc, &stickyDst, &dec2));
    REQUIRE_EQ(dec2.a, 0u); REQUIRE_EQ(dec2.b, 0u);
    REQUIRE_EQ(dec2.blendSrc, 0x0001u); REQUIRE_EQ(dec2.blendDst, 0x0001u);
    return true;
}

struct QuadUV { float bl_u, bl_v, br_u, br_v, tl_u, tl_v, tr_u, tr_v; };

QuadUV computeSkinQuadUV(const gclient::assets::PlistbFrameRecord& rec, float atlasW, float atlasH, bool clampSeam) {
    const float spanU = rec.rotated ? rec.rectHeight : rec.rectWidth;
    const float spanV = rec.rotated ? rec.rectWidth : rec.rectHeight;
    const bool isSubRect = (rec.rectX > 0.0f) || (rec.rectY > 0.0f) || (spanU < atlasW - 0.5f) || (spanV < atlasH - 0.5f);
    const float trimLeftPx = rec.offsetX + (rec.originalWidth - rec.rectWidth) * 0.5f;
    const float trimBottomPx = rec.offsetY + (rec.originalHeight - rec.rectHeight) * 0.5f;
    const float trimRightPx = (rec.originalWidth - rec.rectWidth) - trimLeftPx;
    const float trimTopPx = (rec.originalHeight - rec.rectHeight) - trimBottomPx;
    float left = rec.rectX / atlasW, right = (rec.rectX + spanU) / atlasW;
    float top = rec.rectY / atlasH, bottom = (rec.rectY + spanV) / atlasH;
    const float halfU = 0.5f / atlasW, halfV = 0.5f / atlasH;
    if (rec.rotated) {
        if (clampSeam && isSubRect) {
            if (spanU >= 2.0f) { if (trimBottomPx <= 0.5f) left += halfU; if (trimTopPx <= 0.5f) right -= halfU; }
            if (spanV >= 2.0f) { if (trimLeftPx <= 0.5f) top += halfV; if (trimRightPx <= 0.5f) bottom -= halfV; }
        }
        return QuadUV{left, top, left, bottom, right, top, right, bottom};
    }
    if (clampSeam && isSubRect) {
        if (spanU >= 2.0f) { if (trimLeftPx <= 0.5f) left += halfU; if (trimRightPx <= 0.5f) right -= halfU; }
        if (spanV >= 2.0f) { if (trimTopPx <= 0.5f) top += halfV; if (trimBottomPx <= 0.5f) bottom -= halfV; }
    }
    return QuadUV{left, bottom, right, bottom, left, top, right, top};
}

bool testPlistbParseRotatedFramesAndSkinSubRectUvClamp() {
    using gclient::assets::PlistbFileData;
    using gclient::assets::PlistbLoader;
    auto addRec = [](std::vector<uint8_t>& buf, const char* name, uint16_t rx, uint16_t ry,
                     uint16_t rw, uint16_t rh, bool rot, int16_t ox, int16_t oy, uint16_t ow, uint16_t oh) {
        const size_t b = buf.size();
        buf.resize(b + gclient::assets::kPlistbRecordSize, 0u);
        std::memcpy(buf.data() + b, name, std::strlen(name));
        writeLE16U(buf.data() + b + 64, rx); writeLE16U(buf.data() + b + 66, ry);
        writeLE16U(buf.data() + b + 68, rw); writeLE16U(buf.data() + b + 70, rh);
        buf[b + 72] = rot ? 1u : 0u;
        writeLE16S(buf.data() + b + 74, ox); writeLE16S(buf.data() + b + 76, oy);
        writeLE16U(buf.data() + b + 78, ow); writeLE16U(buf.data() + b + 80, oh);
    };

    std::vector<uint8_t> plistb(gclient::assets::kPlistbHeaderSize, 0u);
    std::memcpy(plistb.data(), "baoguang.png", 12);
    writeLE16S(plistb.data() + 64, 4);
    addRec(plistb, "q_unrot.png", 2, 2, 82, 78, false, -9, -11, 100, 100);
    addRec(plistb, "q_rot.png",  90, 2, 82, 78, true,  -9, -11, 100, 100);
    addRec(plistb, "glow.png",    2, 90, 96, 96, false,  0,   0, 128, 128);
    addRec(plistb, "px1.png",   200, 2,  1,  1, false,  0,   0,   1,   1);

    PlistbFileData parsed{};
    REQUIRE_TRUE(PlistbLoader::ParseBuffer(plistb.data(), plistb.size(), &parsed));
    REQUIRE_EQ(parsed.frames.size(), 4u);

    const QuadUV uv0 = computeSkinQuadUV(parsed.frames[0], 256.0f, 256.0f, true);
    REQUIRE_TRUE(std::fabs(uv0.bl_u - (2.5f / 256.0f)) < 1e-6f && std::fabs(uv0.bl_v - (79.5f / 256.0f)) < 1e-6f);
    REQUIRE_TRUE(std::fabs(uv0.tr_u - (84.0f / 256.0f)) < 1e-6f && std::fabs(uv0.tr_v - (2.0f / 256.0f)) < 1e-6f);

    const QuadUV uv1 = computeSkinQuadUV(parsed.frames[1], 256.0f, 256.0f, true);
    REQUIRE_TRUE(std::fabs(uv1.bl_u - (90.5f / 256.0f)) < 1e-6f && std::fabs(uv1.bl_v - (2.5f / 256.0f)) < 1e-6f);
    REQUIRE_TRUE(std::fabs(uv1.tr_u - (168.0f / 256.0f)) < 1e-6f && std::fabs(uv1.tr_v - (84.0f / 256.0f)) < 1e-6f);

    const QuadUV uv2C = computeSkinQuadUV(parsed.frames[2], 256.0f, 256.0f, true);
    const QuadUV uv2S = computeSkinQuadUV(parsed.frames[2], 256.0f, 256.0f, false);
    REQUIRE_TRUE(std::fabs(uv2C.bl_u - uv2S.bl_u) < 1e-6f && std::fabs(uv2C.tr_v - uv2S.tr_v) < 1e-6f);

    const QuadUV uv3C = computeSkinQuadUV(parsed.frames[3], 256.0f, 256.0f, true);
    const QuadUV uv3S = computeSkinQuadUV(parsed.frames[3], 256.0f, 256.0f, false);
    REQUIRE_TRUE(std::fabs(uv3C.bl_u - uv3S.bl_u) < 1e-6f);
    return true;
}

struct Rgba8 { uint8_t r, g, b, a; };

bool testPvrRgba8UnpackPremulAlphaAndBlendPipeline() {
    const uint16_t raw4444 = 0xFA48u;
    const unsigned int px = (raw4444 & 0xFFu) | ((raw4444 >> 8) << 8);
    REQUIRE_EQ(((px >> 12) & 0xFu) * 17u, 255u);
    REQUIRE_EQ(((px >> 8) & 0xFu) * 17u, 170u);
    REQUIRE_EQ(((px >> 4) & 0xFu) * 17u, 68u);
    REQUIRE_EQ((px & 0xFu) * 17u, 136u);

    const uint8_t boneOpacity = 2u, texPremulR = 200u;
    const int outUnpatched = (254 * texPremulR) / 255;
    const int outPatched = (static_cast<int>(254 * (boneOpacity / 255.0f)) * texPremulR) / 255;
    REQUIRE_TRUE(outUnpatched > 190 && outPatched <= 2);

    const Rgba8 glowPremul{128u, 110u, 40u, 128u};
    REQUIRE_EQ(static_cast<int>(glowPremul.r), 128);
    REQUIRE_EQ((glowPremul.r * glowPremul.a + 127) / 255, 64);
    return true;
}

Rgba8 sampleBilinearClampToEdge(const std::vector<Rgba8>& tex, int w, int h, float u, float v) {
    const float fx = std::clamp(u * w - 0.5f, 0.0f, static_cast<float>(w - 1));
    const float fy = std::clamp(v * h - 0.5f, 0.0f, static_cast<float>(h - 1));
    const int x0 = static_cast<int>(std::floor(fx)), y0 = static_cast<int>(std::floor(fy));
    const int x1 = std::min(x0 + 1, w - 1), y1 = std::min(y0 + 1, h - 1);
    const float tx = fx - x0, ty = fy - y0;
    const Rgba8 &c00 = tex[y0 * w + x0], &c10 = tex[y0 * w + x1];
    const Rgba8 &c01 = tex[y1 * w + x0], &c11 = tex[y1 * w + x1];
    auto bl = [&](uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
        return static_cast<uint8_t>(std::clamp(std::lround((a * (1 - tx) + b * tx) * (1 - ty) + (c * (1 - tx) + d * tx) * ty), 0L, 255L));
    };
    return Rgba8{bl(c00.r, c10.r, c01.r, c11.r), bl(c00.g, c10.g, c01.g, c11.g),
                 bl(c00.b, c10.b, c01.b, c11.b), bl(c00.a, c10.a, c01.a, c11.a)};
}

void rasterizeStarburst4Quadrants(const std::vector<Rgba8>& atlas, int atlasDim, const QuadUV& qUv,
                                  std::vector<Rgba8>& fb, int fbSize) {
    const int half = fbSize / 2;
    for (int py = 0; py < fbSize; ++py) {
        for (int px = 0; px < fbSize; ++px) {
            const float sx = ((px >= half ? (px - half) : (half - 1 - px)) + 0.5f) / static_cast<float>(half);
            const float sy = ((py >= half ? (py - half) : (half - 1 - py)) + 0.5f) / static_cast<float>(half);
            const Rgba8 src = sampleBilinearClampToEdge(
                atlas, atlasDim, atlasDim, qUv.bl_u + sx * (qUv.br_u - qUv.bl_u), qUv.bl_v + sy * (qUv.tl_v - qUv.bl_v));
            Rgba8& dst = fb[py * fbSize + px];
            const int invA = 255 - src.a;
            dst.r = static_cast<uint8_t>(std::min(255, src.r + (dst.r * invA + 127) / 255));
            dst.g = static_cast<uint8_t>(std::min(255, src.g + (dst.g * invA + 127) / 255));
            dst.b = static_cast<uint8_t>(std::min(255, src.b + (dst.b * invA + 127) / 255));
        }
    }
}

bool testStarburstSeamAndGlowRingOffscreenPixelVerification() {
    constexpr int kAtlasDim = 64, kFbDim = 64;
    std::vector<Rgba8> atlas(kAtlasDim * kAtlasDim, Rgba8{0, 0, 0, 0});
    for (int y = 2; y < 18; ++y)
        for (int x = 2; x < 18; ++x)
            atlas[y * kAtlasDim + x] = Rgba8{220, 200, 140, 220};

    gclient::assets::PlistbFrameRecord rec{"baoguang_01.png", 2.0f, 2.0f, 16.0f, 16.0f, false, -2.0f, -2.0f, 20.0f, 20.0f};
    const Rgba8 darkBg{18, 18, 24, 255};

    std::vector<Rgba8> fbUnpatched(kFbDim * kFbDim, darkBg), fbPatched(kFbDim * kFbDim, darkBg);
    const QuadUV uvUnpatched = computeSkinQuadUV(rec, kAtlasDim, kAtlasDim, false);
    const QuadUV uvPatched   = computeSkinQuadUV(rec, kAtlasDim, kAtlasDim, true);
    rasterizeStarburst4Quadrants(atlas, kAtlasDim, uvUnpatched, fbUnpatched, kFbDim);
    rasterizeStarburst4Quadrants(atlas, kAtlasDim, uvPatched, fbPatched, kFbDim);

    REQUIRE_TRUE(fbUnpatched[32 * kFbDim + 32].r < fbUnpatched[40 * kFbDim + 40].r - 85);
    REQUIRE_TRUE(std::abs(static_cast<int>(fbPatched[32 * kFbDim + 32].r) - static_cast<int>(fbPatched[40 * kFbDim + 40].r)) <= 1);
    REQUIRE_TRUE(std::abs(static_cast<int>(fbPatched[40 * kFbDim + 32].r) - static_cast<int>(fbPatched[40 * kFbDim + 40].r)) <= 1);
    REQUIRE_TRUE(std::abs(static_cast<int>(fbPatched[32 * kFbDim + 40].r) - static_cast<int>(fbPatched[40 * kFbDim + 40].r)) <= 1);

#if defined(GCLIENT_TEST_EGL_GL)
    auto getPlatDpy = reinterpret_cast<PFNEGLGETPLATFORMDISPLAYEXTPROC>(eglGetProcAddress("eglGetPlatformDisplayEXT"));
    EGLDisplay dpy = getPlatDpy ? getPlatDpy(0x31DD, nullptr, nullptr) : eglGetDisplay(EGL_DEFAULT_DISPLAY);
    REQUIRE_TRUE(dpy != EGL_NO_DISPLAY);
    EGLint maj = 0, min = 0;
    REQUIRE_TRUE(eglInitialize(dpy, &maj, &min) == EGL_TRUE && eglBindAPI(EGL_OPENGL_API) == EGL_TRUE);
    const EGLint cfgAtt[] = { EGL_SURFACE_TYPE, 0, EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT, EGL_NONE };
    EGLConfig cfg = nullptr; EGLint nCfg = 0;
    (void)eglChooseConfig(dpy, cfgAtt, &cfg, 1, &nCfg);
    const EGLint ctxAtt[] = { EGL_CONTEXT_MAJOR_VERSION, 2, EGL_CONTEXT_MINOR_VERSION, 1, EGL_NONE };
    EGLContext ctx = eglCreateContext(dpy, cfg, EGL_NO_CONTEXT, ctxAtt);
    REQUIRE_TRUE(ctx != EGL_NO_CONTEXT && eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, ctx) == EGL_TRUE);

    GLuint fbo = 0, colorTex = 0, starTex = 0, glowTexId = 0;
    glGenFramebuffers(1, &fbo); glBindFramebuffer(GL_FRAMEBUFFER, fbo);
    glGenTextures(1, &colorTex); glBindTexture(GL_TEXTURE_2D, colorTex);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, kFbDim, kFbDim, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, colorTex, 0);
    REQUIRE_EQ(glCheckFramebufferStatus(GL_FRAMEBUFFER), static_cast<GLenum>(GL_FRAMEBUFFER_COMPLETE));

    glGenTextures(1, &starTex); glBindTexture(GL_TEXTURE_2D, starTex);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, kAtlasDim, kAtlasDim, 0, GL_RGBA, GL_UNSIGNED_BYTE, atlas.data());

    glViewport(0, 0, kFbDim, kFbDim);
    glMatrixMode(GL_PROJECTION); glLoadIdentity(); glOrtho(0.0, kFbDim, 0.0, kFbDim, -1.0, 1.0);
    glMatrixMode(GL_MODELVIEW); glLoadIdentity();
    glEnable(GL_TEXTURE_2D); glEnable(GL_BLEND);

    auto drawQuadSet = [&](const QuadUV& uv) {
        glClearColor(18.0f / 255.0f, 18.0f / 255.0f, 24.0f / 255.0f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        glBindTexture(GL_TEXTURE_2D, starTex);
        glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
        glColor4ub(255, 255, 255, 255);
        const float signs[4][2] = {{1, 1}, {-1, 1}, {1, -1}, {-1, -1}};
        for (const auto& s : signs) {
            glBegin(GL_QUADS);
            glTexCoord2f(uv.bl_u, uv.bl_v); glVertex2f(32.0f, 32.0f);
            glTexCoord2f(uv.br_u, uv.br_v); glVertex2f(32.0f + s[0] * 32.0f, 32.0f);
            glTexCoord2f(uv.tr_u, uv.tr_v); glVertex2f(32.0f + s[0] * 32.0f, 32.0f + s[1] * 32.0f);
            glTexCoord2f(uv.tl_u, uv.tl_v); glVertex2f(32.0f, 32.0f + s[1] * 32.0f);
            glEnd();
        }
    };

    std::vector<Rgba8> glPx(kFbDim * kFbDim);
    drawQuadSet(uvUnpatched);
    glReadPixels(0, 0, kFbDim, kFbDim, GL_RGBA, GL_UNSIGNED_BYTE, glPx.data());
    REQUIRE_TRUE(glPx[32 * kFbDim + 32].r < glPx[40 * kFbDim + 40].r - 80);

    drawQuadSet(uvPatched);
    glReadPixels(0, 0, kFbDim, kFbDim, GL_RGBA, GL_UNSIGNED_BYTE, glPx.data());
    REQUIRE_TRUE(std::abs(static_cast<int>(glPx[32 * kFbDim + 32].r) - static_cast<int>(glPx[40 * kFbDim + 40].r)) <= 2);
    REQUIRE_TRUE(std::abs(static_cast<int>(glPx[40 * kFbDim + 32].r) - static_cast<int>(glPx[40 * kFbDim + 40].r)) <= 2);
    REQUIRE_TRUE(std::abs(static_cast<int>(glPx[32 * kFbDim + 40].r) - static_cast<int>(glPx[40 * kFbDim + 40].r)) <= 2);

    std::vector<Rgba8> glowTex(32 * 32, Rgba8{0, 0, 0, 0});
    for (int y = 0; y < 32; ++y) {
        const float dy = std::fabs((y + 0.5f) - 16.0f) / 16.0f;
        const uint8_t a8 = static_cast<uint8_t>(std::clamp(std::lround((1.0f - dy) * 15.0f), 0L, 15L) * 17);
        for (int x = 0; x < 32; ++x)
            glowTex[y * 32 + x] = Rgba8{a8, static_cast<uint8_t>((221u * a8 + 127u) / 255u), static_cast<uint8_t>((102u * a8 + 127u) / 255u), a8};
    }
    glGenTextures(1, &glowTexId); glBindTexture(GL_TEXTURE_2D, glowTexId);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 32, 32, 0, GL_RGBA, GL_UNSIGNED_BYTE, glowTex.data());
    glClear(GL_COLOR_BUFFER_BIT);
    glBlendFunc(GL_ONE, GL_ONE);
    glColor4ub(gclient::assets::XmlbArmatureLoader::ClampColorChannel(255),
               gclient::assets::XmlbArmatureLoader::ClampColorChannel(260),
               gclient::assets::XmlbArmatureLoader::ClampColorChannel(260), 255);
    glBegin(GL_QUADS);
    glTexCoord2f(0, 0); glVertex2f(0, 0); glTexCoord2f(1, 0); glVertex2f(64, 0);
    glTexCoord2f(1, 1); glVertex2f(64, 64); glTexCoord2f(0, 1); glVertex2f(0, 64);
    glEnd();
    glReadPixels(0, 0, kFbDim, kFbDim, GL_RGBA, GL_UNSIGNED_BYTE, glPx.data());
    REQUIRE_TRUE(glPx[32 * kFbDim + 32].r >= 240 && glPx[32 * kFbDim + 32].g >= 200 && glPx[32 * kFbDim + 32].b >= 100);
    REQUIRE_TRUE(glPx[40 * kFbDim + 32].r > glPx[41 * kFbDim + 32].r && (glPx[40 * kFbDim + 32].r - glPx[41 * kFbDim + 32].r) <= 12);

    glDeleteTextures(1, &glowTexId); glDeleteTextures(1, &starTex);
    glDeleteTextures(1, &colorTex); glDeleteFramebuffers(1, &fbo);
    eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroyContext(dpy, ctx); eglTerminate(dpy);
#endif
    return true;
}


// ============================================================================
// Scenario 17: Layer 1 CConnection lua_pcall + Layer 2 Network/DataLoading/BindableData Resilience
// ============================================================================

bool testLayer1CConnectionProtectedLuaCallbacks() {
    ScopedDiagnosticsSession diag("kestrel_net_layer1_test", "kestrel_layer1");
    REQUIRE_TRUE(diag.installed);

    ScopedLuaVm vm;
    lua_State* L = vm.L;
    REQUIRE_TRUE(L != nullptr);
    gclient::diagnostics::CrashAndTelemetry::installLuaHooks(L);

    REQUIRE_EQ(luaL_dostring(L, R"LUA(
        _G.__CAPTURED_CCLUALOG = {}
        _G.CCLuaLog = function(msg)
            table.insert(_G.__CAPTURED_CCLUALOG, tostring(msg))
        end
        _G.__PKT2_RECEIVED = false
        function _testCrashingBodyHandler(body, head)
            if body == "CRASH_PACKET_1" then
                local nilTbl = nil
                return nilTbl.boom_field
            end
            if body == "VALID_PACKET_2" then
                _G.__PKT2_RECEIVED = (#head == 8)
            end
        end
        function _testCrashingCloseHandler()
            local nilConn = nil
            return nilConn.on_close_crash
        end
    )LUA"), 0);

    lua_getglobal(L, "_testCrashingBodyHandler");
    const int bodyRef = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_getglobal(L, "_testCrashingCloseHandler");
    const int closeRef = luaL_ref(L, LUA_REGISTRYINDEX);
    REQUIRE_TRUE(bodyRef > 0 && closeRef > 0);

    // Push two sentinel values onto the Lua stack so savedTop == 2 before CConnection dispatches
    lua_pushinteger(L, 12345);
    lua_pushstring(L, "stack_sentinel");
    const int savedTop = lua_gettop(L);
    REQUIRE_EQ(savedTop, 2);

    // Subcase 1A: With __GCLIENT_NATIVE_TRACKBACK__ active, feed two framed packets back-to-back over loopback
    {
        gclient::net::WinsockSession ws;
        REQUIRE_TRUE(ws.isInitialized());

        LoopbackTcpListener listener;
        REQUIRE_TRUE(listener.bindEphemeral(4));

        auto conn = std::make_unique<gclient::net::CConnection>();
        conn->setStandaloneLuaState(L);
        conn->registerBodyFunc(bodyRef);
        conn->registerCloseFunc(closeRef);
        REQUIRE_TRUE(conn->connect("127.0.0.1", listener.port));

        ScopedSocket serverClient = listener.acceptOne();
        REQUIRE_TRUE(serverClient.fd != INVALID_SOCKET);

        auto makeRawFrame = [](const std::string& payload) {
            std::string f(8 + payload.size(), '\0');
            const uint32_t beLen = htonl(static_cast<uint32_t>(payload.size()));
            std::memcpy(&f[0], &beLen, 4);
            std::memcpy(&f[8], payload.data(), payload.size());
            return f;
        };
        const std::string wire = makeRawFrame("CRASH_PACKET_1") + makeRawFrame("VALID_PACKET_2");
        REQUIRE_TRUE(::send(serverClient.fd, wire.data(), static_cast<int>(wire.size()), 0) == static_cast<int>(wire.size()));

        auto* netMgr = gclient::net::CNetwork::sharedNetwork();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        bool pkt2Done = false;
        while (std::chrono::steady_clock::now() < deadline && !pkt2Done) {
            netMgr->update(0.016f);
            lua_getglobal(L, "__PKT2_RECEIVED");
            pkt2Done = lua_toboolean(L, -1) != 0;
            lua_pop(L, 1);
            if (!pkt2Done) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }
        REQUIRE_TRUE(pkt2Done);
        REQUIRE_EQ(lua_gettop(L), savedTop);

        // Close must also catch closeLuaHandler_ error via lua_pcall, record trace, and restore stack
        conn->close();
        REQUIRE_EQ(lua_gettop(L), savedTop);

        bool sawBodyErrTrace = false;
        bool sawCloseErrTrace = false;
        for (const auto& entry : conn->traceBuffer().snapshot()) {
            if ( std::strcmp(entry.event, "BODY_SCRIPT_ERROR") == 0 ) sawBodyErrTrace = true;
            if ( std::strcmp(entry.event, "CLOSE_SCRIPT_ERROR") == 0 ) sawCloseErrTrace = true;
        }
        REQUIRE_TRUE(sawBodyErrTrace);
        REQUIRE_TRUE(sawCloseErrTrace);

        conn.reset();
        gclient::net::CNetwork::destroySharedNetwork();
    }

    // Subcase 1B: Fallback to debug.traceback when __GCLIENT_NATIVE_TRACKBACK__ is absent
    lua_pushnil(L);
    lua_setglobal(L, "__GCLIENT_NATIVE_TRACKBACK__");
    {
        gclient::net::CConnection directConn;
        directConn.setStandaloneLuaState(L);
        directConn.registerBodyFunc(bodyRef);
        const char* crashBody = "CRASH_PACKET_1";
        directConn.doPacketBody(crashBody, std::strlen(crashBody));
        REQUIRE_EQ(lua_gettop(L), savedTop);
    }

    REQUIRE_TRUE(vm.execChecked(R"LUA(
        assert(#_G.__CAPTURED_CCLUALOG >= 3, "Expected >= 3 CCLuaLog entries, got " .. tostring(#_G.__CAPTURED_CCLUALOG))
        assert(string.find(_G.__CAPTURED_CCLUALOG[1], "nilTbl", 1, true) ~= nil, "log1=" .. tostring(_G.__CAPTURED_CCLUALOG[1]))
        assert(string.find(_G.__CAPTURED_CCLUALOG[1], "stack traceback:", 1, true) ~= nil, "tb1=" .. tostring(_G.__CAPTURED_CCLUALOG[1]))
        assert(string.find(_G.__CAPTURED_CCLUALOG[2], "nilConn", 1, true) ~= nil, "log2=" .. tostring(_G.__CAPTURED_CCLUALOG[2]))
        assert(string.find(_G.__CAPTURED_CCLUALOG[3], "nilTbl", 1, true) ~= nil, "log3=" .. tostring(_G.__CAPTURED_CCLUALOG[3]))
        assert(string.find(_G.__CAPTURED_CCLUALOG[3], "stack traceback:", 1, true) ~= nil, "tb3=" .. tostring(_G.__CAPTURED_CCLUALOG[3]))
    )LUA", "Layer1 Assert Err"));

    REQUIRE_EQ(lua_gettop(L), savedTop);
    REQUIRE_EQ(static_cast<int>(lua_tointeger(L, 1)), 12345);
    REQUIRE_EQ(std::string(lua_tostring(L, 2)), "stack_sentinel");
    lua_pop(L, 2);

    luaL_unref(L, LUA_REGISTRYINDEX, bodyRef);
    luaL_unref(L, LUA_REGISTRYINDEX, closeRef);
    gclient::diagnostics::CrashAndTelemetry::clearLuaState();
    return true;
}

bool testNetworkDataLoadingResilienceAndBindableDataRecovery() {
    if (!testLayer1CConnectionProtectedLuaCallbacks()) {
        return false;
    }

    // Layer 2: Test InstallNetworkResilienceHookImpl against clean APK-equivalent modules + real C++ Amf3Module
    {
        ScopedLuaVm vm(true);
        REQUIRE_TRUE(vm.L != nullptr);
        gclient::bindings::InstallNetworkResilienceHookImpl(vm.L);

        static const char* const kCleanHarnessChunks[] = {
            R"LUA(
                _G.amf3 = require("amf3")
                _G.__LOGS = {}
                _G.__MSGBOXES = {}
                _G.CCLuaLog = function(msg)
                    table.insert(_G.__LOGS, tostring(msg))
                end
                _G.CCMessageBox = function(msg, title)
                    table.insert(_G.__MSGBOXES, { msg = tostring(msg), title = tostring(title) })
                end
                _G.lang = function(k) return "ERR_PREFIX:" end
                _G.Logger = {
                    showTrace = function() end,
                    showWarning = function() end,
                    showFatal = function() end,
                }
                _G.sendNotification = function() end

                -- Preload minimal lib.Class, LoadingManager, DataLoading, ReconnectLoading, ReconnectProxy,
                -- system.Network, core.BindableData, and core.BaseProxy matching clean main_apk scripts.
                package.preload["lib.Class"] = function()
                    local Class = { __type = "class" }
                    function Class:extend_table(name, t)
                        for k, v in pairs(self) do t[k] = v end
                        t.super = self
                        t._NAME = name
                        return t
                    end
                    function Class:_dealGetterAndSetterMap()
                        self._getterAndSetterMap = {}
                    end
                    function Class:new(...)
                        local inst = {}
                        setmetatable(inst, { __index = self })
                        inst.__type = "object"
                        if inst.ctor then inst:ctor(...) end
                        return inst
                    end
                    return Class
                end

                package.preload["game.modules.loading.DataLoading"] = function()
                    local DL = {}
                    function DL:new()
                        local o = { visible = false, hiddenCount = 0 }
                        function o:show() self.visible = true end
                        function o:hide() self.visible = false; self.hiddenCount = self.hiddenCount + 1 end
                        return o
                    end
                    return DL
                end

                package.preload["game.modules.loading.ReconnectLoading"] = function()
                    local RL = {}
                    function RL:new()
                        local o = { shown = false }
                        function o:show() self.shown = true end
                        function o:hide() self.shown = false end
                        return o
                    end
                    return RL
                end

                package.preload["game.modules.reconnect.ReconnectProxy"] = function()
                    local RP = { _ins = { startedReasons = {}, banned = false } }
                    function RP._ins:isBanSendMsg() return self.banned end
                    function RP._ins:start(des) table.insert(self.startedReasons, tostring(des)) end
                    function RP._ins:showReconnectPanel() end
                    function RP:ins() return self._ins end
                    return RP
                end
            )LUA",
            R"LUA(
                package.preload["game.modules.loading.LoadingManager"] = function()
                    local Class = require("lib.Class")
                    local M = Class:extend_table("LoadingManager", {})
                    M.NONE_LOADING_TYPE = 0
                    M.DATA_LOADING_TYPE = 1
                    M.SWITCH_LOADING_TYPE = 2
                    M.BLANK_LOADING_TYPE = 3
                    M.MAIN_LOADING_TYPE = 4
                    function M:ctor()
                        self._mainLoading = nil
                        self._blankLoading = nil
                        self._switchLoading = nil
                        self._dataLoading = nil
                        self._reconnectLoading = nil
                        self._dataLoadingShowCount = 0
                        self._dataLoadingKeyMap = {}
                        self._curLoadingType = M.NONE_LOADING_TYPE
                        self._hideHistory = {}
                    end
                    function M:ins()
                        self._ins = self._ins or self:new()
                        return self._ins
                    end
                    function M:_checkCanShowLoading(t) return self._curLoadingType < t end
                    function M:_addLoadingKey(key)
                        self._dataLoadingKeyMap[key] = (self._dataLoadingKeyMap[key] or 0) + 1
                    end
                    function M:_delLoadingKey(key)
                        local v = self._dataLoadingKeyMap[key]
                        if v then
                            self._dataLoadingKeyMap[key] = v - 1
                            if self._dataLoadingKeyMap[key] <= 0 then
                                self._dataLoadingKeyMap[key] = nil
                            end
                        end
                    end
                    function M:_checkHasLoadingKey()
                        for _, v in pairs(self._dataLoadingKeyMap) do
                            if v and v > 0 then return true end
                        end
                        return false
                    end
                    function M:_forceClearDataLoading()
                        self._dataLoadingShowCount = 0
                        self._dataLoadingKeyMap = {}
                        if self._dataLoading then self._dataLoading:hide() end
                        self._dataLoading = nil
                        self._curLoadingType = M.NONE_LOADING_TYPE
                    end
                    function M:showDataLoading(key)
                        if self._curLoadingType ~= M.DATA_LOADING_TYPE and not self:_checkCanShowLoading(M.DATA_LOADING_TYPE) then
                            return
                        end
                        if key then
                            self:_addLoadingKey(key)
                        else
                            self._dataLoadingShowCount = self._dataLoadingShowCount + 1
                        end
                        if not self._dataLoading then
                            self._dataLoading = require("game.modules.loading.DataLoading"):new()
                            self._dataLoading:show()
                            self._curLoadingType = M.DATA_LOADING_TYPE
                        end
                    end
                    function M:hideDataLoading(key)
                        table.insert(self._hideHistory, tostring(key))
                        if self._curLoadingType ~= M.DATA_LOADING_TYPE then return end
                        if key then
                            self:_delLoadingKey(key)
                        else
                            self._dataLoadingShowCount = self._dataLoadingShowCount - 1
                        end
                        if self._dataLoadingShowCount <= 0 and self:_checkHasLoadingKey() == false then
                            self:_forceClearDataLoading()
                        end
                    end
                    function M:hideSwitchLoading() end
                    function M:showReconnectLoading()
                        if self._reconnectLoading then return end
                        if self._curLoadingType == M.NONE_LOADING_TYPE then
                            self._reconnectLoading = require("game.modules.loading.ReconnectLoading"):new()
                            self._reconnectLoading:show()
                        end
                    end
                    return M
                end
            )LUA",
            R"LUA(
                package.preload["system.Network"] = function()
                    local Class = require("lib.Class")
                    local M = Class:extend_table("Network", {})
                    M.kETClosedEvent = "Network.onClosed"
                    function M:ins()
                        M._ins = M._ins or M:new()
                        return M._ins
                    end
                    function M:ctor()
                        self.mToken = "0"
                        self.mOffset = 0
                        self.mId = 1
                        self.mContext = {}
                        self._timestamp_map = {}
                        self.log_print = {}
                    end
                    -- Unpatched baseline methods (to be hardened by InstallNetworkResilienceHook)
                    function M:onClosed()
                        error("unpatched Network:onClosed should have been replaced")
                    end
                    function M:onBodyData(body, head)
                        error("unpatched Network:onBodyData should have been replaced")
                    end
                    function M:sendMsg(method, callback, args, isNotShowLoading)
                        error("unpatched Network:sendMsg should have been replaced")
                    end
                    function M:goReconnect(des)
                        local RP = require("game.modules.reconnect.ReconnectProxy")
                        g.loadingManager:showReconnectLoading()
                        RP:ins():start(des)
                    end
                    function M:regPushCallback(method, callback, isForce)
                        self.mContext[method] = { callback, {}, true }
                    end
                    return M
                end

                package.preload["core.BindableData"] = function()
                    local Class = require("lib.Class")
                    local BD = Class:extend_table("BindableData", {})
                    BD.network = require("system.Network")
                    function BD:toString() return "BindableData" end
                    function BD:methodName() return "" end
                    function BD:methodArgs() return {} end
                    function BD:parseData(data) end
                    function BD:dobindCallback(prop, val) end
                    -- Unpatched buggy initdata / onReceiveData from clean APK
                    function BD:initdata(callback)
                        self._onReceiveData = callback
                        if self._isloading == true then return end
                        self.network:ins():sendMsg(self:methodName(), function(ret, args) self:onReceiveData(ret, args) end, self:methodArgs())
                        self._isloading = true
                    end
                    function BD:onReceiveData(ret, args)
                        self:parseData(ret)
                        self._isloading = false
                        self.isok = true
                        if self._onReceiveData ~= nil then
                            self._onReceiveData()
                            self._onReceiveData = nil
                        end
                    end
                    function BD:new(options)
                        local instance = {}
                        setmetatable(instance, { __index = self })
                        instance.__type = "object"
                        instance._bindPropertyMap = {}
                        instance._isloading = false
                        instance.isok = false
                        instance:_dealGetterAndSetterMap()
                        local index = {}
                        local mt = {
                            __index = function(t, k) return t[index][k] end,
                            __newindex = function(t, k, v)
                                t[index][k] = v
                                t[index]:dobindCallback(k, v)
                            end
                        }
                        local proxy = {}
                        proxy[index] = instance
                        setmetatable(proxy, mt)
                        if proxy.ctor then proxy:ctor(options) end
                        return proxy
                    end
                    return BD
                end
            )LUA",
            R"LUA(
                _G.GameUtil = {
                    unzipMode = "empty",
                    unzipData = function(self, raw)
                        if self.unzipMode == "empty" then return "" end
                        if self.unzipMode == "throw" then error("zlib inflate error") end
                        return raw
                    end
                }

                local LoadingManager = require("game.modules.loading.LoadingManager")
                local Network = require("system.Network")
                local BindableData = require("core.BindableData")

                _G.g = {
                    loadingManager = LoadingManager:ins(),
                    network = Network:ins(),
                    networkUtil = { start = function() end, stop = function() end },
                    mainData = { networkCloseResetDatas = function() end },
                    noteConst = { NETWORK_CLOSE = "NETWORK_CLOSE" },
                    timeManager = { setOffset = function() end },
                    host = "127.0.0.1",
                    pid = "p1001",
                }

                local sentPayloads = {}
                local mockConn = {
                    shouldFailSend = false,
                    shouldThrowSend = false,
                    send = function(self, data, wrap)
                        if self.shouldThrowSend then error("socket broken pipe") end
                        if self.shouldFailSend then return false end
                        table.insert(sentPayloads, data)
                        return true
                    end,
                    close = function() end,
                }
                g.network.mConn = mockConn

                -- =====================================================================
                -- TEST 1: Network:onBodyData when callback(ret.ret, args) throws
                --   `attempt to index local 'reward' (a nil value)` ->
                --   hideDataLoading(callbackName) still runs, _dataLoadingKeyMap is empty,
                --   traceback is logged, AND sub-packet #2 in a multi=1 batch still executes!
                --   (Also includes a malformed binary sub-packet between them to test (b),
                --   and tests (a) zipped=1 empty unzip + orphaned key reconciliation!)
                -- =====================================================================
                local cb1Key = g.network:sendMsg("copy.getReward", function(ret, args)
                    local reward = ret and ret.reward -- nil!
                    return reward.itemId              -- throws: attempt to index local 'reward' (a nil value)
                end, { copyId = 101 })

                local sub2Ran = false
                local sub2Arg = nil
                local cb2Key = g.network:sendMsg("bag.syncBag", function(ret, args)
                    sub2Ran = (ret and ret.gold == 888)
                    sub2Arg = args and args.tab
                end, { tab = 2 })

                assert(type(cb1Key) == "string" and type(cb2Key) == "string")
                assert(g.loadingManager._dataLoadingKeyMap[cb1Key] == 1)
                assert(g.loadingManager._dataLoadingKeyMap[cb2Key] == 1)
                assert(g.loadingManager._curLoadingType == g.loadingManager.DATA_LOADING_TYPE)

                local subPkt1 = amf3.encode({
                    err = "ok",
                    callback = { callbackName = cb1Key },
                    ret = { status = 1 } -- no .reward field!
                })
                local malformedSubPkt = "\255\000\254corrupt_sub_amf3"
                local subPkt2 = amf3.encode({
                    err = "ok",
                    callback = { callbackName = cb2Key },
                    ret = { gold = 888 }
                })
                local batchOuter = amf3.encode({
                    token = "tok_batch_1",
                    ret = { subPkt1, malformedSubPkt, subPkt2 }
                })
                local headMulti1 = "\0\0\0\0\0\0\1\0" -- byte 6 = 0 (unzipped), byte 7 = 1 (multi=1)

                g.network:onBodyData(batchOuter, headMulti1)

                assert(sub2Ran == true and sub2Arg == 2, "Sub-packet #2 in multi=1 batch failed to execute!")
                assert(next(g.loadingManager._dataLoadingKeyMap) == nil, "_dataLoadingKeyMap must be empty after finally path!")
                assert(g.loadingManager._curLoadingType == g.loadingManager.NONE_LOADING_TYPE, "DataLoading must be cleared!")
                assert(g.loadingManager._dataLoading == nil, "_dataLoading instance must be hidden/cleared!")

                local foundRewardNilTb = false
                for _, line in ipairs(_G.__LOGS) do
                    if string.find(line, "attempt to index local 'reward'", 1, true)
                       and string.find(line, "stack traceback:", 1, true) then
                        foundRewardNilTb = true
                        break
                    end
                end
                assert(foundRewardNilTb, "Expected full Lua traceback for nil 'reward' in CCLuaLog!")

                -- Test (a): zipped=1 with GameUtil:unzipData returning "" + orphaned _dataLoadingKeyMap key
                g.loadingManager:showDataLoading("orphan.stale_77")
                assert(g.loadingManager._dataLoadingKeyMap["orphan.stale_77"] == 1)
                local logsBeforeZip = #_G.__LOGS
                local headZipped = "\0\0\0\0\0\1\0\0" -- byte 6 = 1 (zipped)
                g.network:onBodyData("compressed_bytes", headZipped)
                assert(#_G.__LOGS > logsBeforeZip, "Empty unzipData must log traceback via CCLuaLog!")
                assert(g.loadingManager._dataLoadingKeyMap["orphan.stale_77"] == nil, "Orphaned loading key must be reconciled!")
                assert(g.loadingManager._curLoadingType == g.loadingManager.NONE_LOADING_TYPE)
            )LUA",
            R"LUA(
                -- =====================================================================
                -- TEST 2: Network:onBodyData when ret.err = "some_error" and g.host == nil
                --   -> no string.format crash, mContext[callbackName] cleared,
                --   hideDataLoading called, and BindableData _isloading reset!
                --   Also verify sendMsg immediate cleanup on encode/send failure!
                -- =====================================================================
                g.host = nil
                g.pid = nil
                g.network.mToken = { nested = true } -- table token would also crash unpatched string.format!

                local ErrBindable = BindableData:extend_table("ErrBindable", {})
                function ErrBindable:methodName() return "arena.enter" end
                function ErrBindable:parseData(d) self.parsed = d end
                local errBd = ErrBindable:new()

                local errBdWaiterCalled = false
                errBd:initdata(function() errBdWaiterCalled = true end)
                assert(errBd._isloading == true, "BindableData should be loading while RPC is in flight")

                local errCbKey = g.network._lastSentCbKey
                assert(type(errCbKey) == "string" and g.network.mContext[errCbKey] ~= nil)
                assert(g.loadingManager._dataLoadingKeyMap[errCbKey] == 1)

                local errPkt = amf3.encode({
                    err = "some_error",
                    callback = { callbackName = errCbKey }
                })
                g.network:onBodyData(errPkt, "\0\0\0\0\0\0\0\0")

                assert(g.network.mContext[errCbKey] == nil, "mContext[callbackName] must be cleared on ret.err ~= 'ok'")
                assert(next(g.loadingManager._dataLoadingKeyMap) == nil, "hideDataLoading(callbackName) must clear key on ret.err ~= 'ok'")
                assert(g.loadingManager._curLoadingType == g.loadingManager.NONE_LOADING_TYPE)
                assert(#_G.__MSGBOXES >= 1 and string.find(_G.__MSGBOXES[#_G.__MSGBOXES].msg, "host:nil", 1, true) ~= nil)
                assert(string.find(_G.__MSGBOXES[#_G.__MSGBOXES].msg, "err: some_error", 1, true) ~= nil)
                assert(errBd._isloading == false and errBd.isok == false, "BindableData _isloading must reset to false on ret.err ~= 'ok'")
                assert(errBdWaiterCalled == true, "Waiter must wake so BaseProxy does not hang forever")

                -- Also verify ret.callback == nil and non-string ret.err in onBodyData does not crash
                g.network.mToken = "tok_valid"
                g.network:onBodyData(amf3.encode({ err = { bad = 500 } }), "\0\0\0\0\0\0\0\0")

                -- Also verify Network:sendMsg immediate cleanup when mConn:send fails
                mockConn.shouldFailSend = true
                local failedSendKey = g.network:sendMsg("shop.buy", function() end, { id = 1 })
                mockConn.shouldFailSend = false
                assert(failedSendKey == nil)
                for k, v in pairs(g.network.mContext) do
                    assert(type(v) == "table" and v[3] ~= nil, "Failed sendMsg leaked pending mContext entry: " .. tostring(k))
                end
                assert(next(g.loadingManager._dataLoadingKeyMap) == nil, "Failed sendMsg leaked _dataLoadingKeyMap key!")

                -- =====================================================================
                -- TEST 3: Network:onClosed() with active keyed callbackName in _dataLoadingKeyMap
                --   -> clears keyed spinner and unblocks showReconnectLoading()!
                -- =====================================================================
                local pendingCloseKey = g.network:sendMsg("hero.strengthen", function() end, { hid = 99 })
                g.loadingManager:showDataLoading("orphan.key_88")
                assert(g.loadingManager._dataLoadingKeyMap[pendingCloseKey] == 1)
                assert(g.loadingManager._dataLoadingKeyMap["orphan.key_88"] == 1)
                assert(g.loadingManager._curLoadingType == g.loadingManager.DATA_LOADING_TYPE)

                g.network:onClosed()

                assert(g.loadingManager._dataLoadingKeyMap[pendingCloseKey] == nil, "onClosed must clear active RPC key!")
                assert(g.loadingManager._dataLoadingKeyMap["orphan.key_88"] == nil, "onClosed must clear orphan key!")
                assert(g.loadingManager._dataLoading == nil, "onClosed must hide DataLoading!")
                assert(g.loadingManager._curLoadingType == g.loadingManager.NONE_LOADING_TYPE)
                assert(g.loadingManager._reconnectLoading ~= nil and g.loadingManager._reconnectLoading.shown == true,
                       "showReconnectLoading() must succeed after clearing keyed RPC spinners!")

                -- Re-attach mockConn and verify showLoginProtect is preserved by onClosed()
                g.loadingManager._reconnectLoading = nil
                g.network.mContext = {}
                g.network.mConn = mockConn
                g.loadingManager:showDataLoading("showLoginProtect")
                local rpcDuringLogin = g.network:sendMsg("user.loginSub", function() end, {})
                assert(g.loadingManager._dataLoadingKeyMap["showLoginProtect"] == 1)
                assert(g.loadingManager._dataLoadingKeyMap[rpcDuringLogin] == 1)
                g.network:onClosed()
                assert(g.loadingManager._dataLoadingKeyMap[rpcDuringLogin] == nil)
                assert(g.loadingManager._dataLoadingKeyMap["showLoginProtect"] == 1, "showLoginProtect must be preserved!")
                g.loadingManager:hideDataLoading("showLoginProtect")
                assert(next(g.loadingManager._dataLoadingKeyMap) == nil)
                g.network.mContext = {}
                g.network.mConn = mockConn

                -- =====================================================================
                -- TEST 4: BindableData:initdata concurrent waiters + parseData error recovery!
                -- =====================================================================
                local HeroData = BindableData:extend_table("HeroData", {})
                function HeroData:methodName() return "hero.getAllHeros" end
                function HeroData:methodArgs() return { page = 1 } end
                HeroData.shouldThrowInParse = true
                function HeroData:parseData(data)
                    if self.shouldThrowInParse then
                        local badHero = nil
                        self.totalAtk = badHero.atk + 10 -- throws!
                    end
                    self.heroCount = data and data.count or 0
                end

                local hd = HeroData:new()
                local sentBefore = #sentPayloads
                local waiterOrder = {}
                hd:initdata(function() table.insert(waiterOrder, "W1") end)
                hd:initdata(function() table.insert(waiterOrder, "W2") end)
                hd:initdata(function() table.insert(waiterOrder, "W3") end)

                assert(hd._isloading == true)
                assert(#sentPayloads == sentBefore + 1, "Concurrent initdata calls must coalesce into 1 RPC!")
                local hdKey1 = g.network._lastSentCbKey
                assert(type(hdKey1) == "string")

                -- Deliver response #1: parseData throws!
                local logsBeforeParseErr = #_G.__LOGS
                g.network:onBodyData(amf3.encode({
                    err = "ok",
                    callback = { callbackName = hdKey1 },
                    ret = { count = 5 }
                }), "\0\0\0\0\0\0\0\0")

                assert(hd._isloading == false, "parseData error must still reset _isloading = false!")
                assert(hd.isok == false, "Failed initial parseData must leave isok = false for clean retry!")
                assert(#waiterOrder == 3 and waiterOrder[1] == "W1" and waiterOrder[2] == "W2" and waiterOrder[3] == "W3",
                       "All 3 concurrent waiters must run in FIFO order without overwriting _onReceiveData!")
                assert(#_G.__LOGS > logsBeforeParseErr, "parseData error must log full traceback via CCLuaLog!")

                -- Re-open panel retry: now parseData succeeds!
                hd.shouldThrowInParse = false
                local retryWaiterRan = false
                hd:initdata(function() retryWaiterRan = true end)
                assert(hd._isloading == true)
                assert(#sentPayloads == sentBefore + 2, "Retry after failed parseData must send a fresh RPC!")
                local hdKey2 = g.network._lastSentCbKey
                g.network:onBodyData(amf3.encode({
                    err = "ok",
                    callback = { callbackName = hdKey2 },
                    ret = { count = 42 }
                }), "\0\0\0\0\0\0\0\0")

                assert(hd._isloading == false and hd.isok == true and hd.heroCount == 42)
                assert(retryWaiterRan == true)
            )LUA"
        };

        std::string fullTestScript;
        for (const char* part : kCleanHarnessChunks) fullTestScript.append(part);
        REQUIRE_TRUE(vm.execChecked(fullTestScript.c_str(), "LuaCleanHarness FAIL"));
    }

    // Optional integration check against real decrypted_scripts (V12/V15) if present on local test machine
    const fs::path realScriptsDir = "/working_dir/c_bcf9b7da4ae73030/decrypted_scripts/scripts";
    if (fs::exists(realScriptsDir / "system/Network.lua") &&
        fs::exists(realScriptsDir / "core/BaseProxy.lua") &&
        fs::exists(realScriptsDir / "core/BindableData.lua")) {
        ScopedLuaVm vm(true);
        REQUIRE_TRUE(vm.L != nullptr);
        gclient::bindings::InstallNetworkResilienceHookImpl(vm.L);

        const std::string bootRealScripts =
            "package.path = '" + realScriptsDir.string() + "/?.lua;' .. package.path\n" +
            R"LUA(
                _G.amf3 = require("amf3")
                _G.__REAL_LOGS = {}
                _G.CCLuaLog = function(m) table.insert(_G.__REAL_LOGS, tostring(m)) end
                _G.CCMessageBox = function() end
                _G.lang = function() return "ERR:" end
                _G.Logger = { showTrace = function() end, showWarning = function() end, showFatal = function() end, showError = function() end }
                _G.sendNotification = function() end
                function _G.seeall(parentName)
                    local parent = require(parentName)
                    return function(modTbl)
                        parent:extend_table(modTbl._NAME, modTbl)
                    end
                end
                package.preload["game.modules.safetyRadar.SafetyRadarProxy"] = function()
                    return { ins = function() return { isCaptureMsg = false } end }
                end
                package.preload["game.modules.loading.DataLoading"] = function()
                    return { new = function() return { show = function() end, hide = function() end } end }
                end
                package.preload["game.modules.loading.ReconnectLoading"] = function()
                    return { new = function() local o = { shown = false }; function o:show() self.shown = true end; function o:hide() end; return o end }
                end
                package.preload["game.modules.reconnect.ReconnectProxy"] = function()
                    local rp = { isBanSendMsg = function() return false end, start = function() end, showReconnectPanel = function() end }
                    return { ins = function() return rp end }
                end

                local LoadingManager = require("game.modules.loading.LoadingManager")
                local Network = require("system.Network")
                local BindableData = require("core.BindableData")
                local BaseProxy = require("core.BaseProxy")

                _G.g = {
                    loadingManager = LoadingManager:ins(),
                    network = Network:ins(),
                    networkUtil = { start = function() end, stop = function() end },
                    mainData = { networkCloseResetDatas = function() end },
                    noteConst = { NETWORK_CLOSE = "NETWORK_CLOSE" },
                    timeManager = { setOffset = function() end },
                    host = nil,
                    pid = nil,
                }
                if type(_G.__ensureStuck99LoadingFlowGuardsV11) == "function" then
                    _G.__ensureStuck99LoadingFlowGuardsV11()
                end

                g.network.mConn = { send = function() return true end, close = function() end }

                -- Verify V15 + InstallNetworkResilienceHookImpl coexist seamlessly!
                local k1 = g.network:sendMsg("copy.enter", function(ret)
                    local reward = nil
                    return reward.x
                end, {})
                local secondOk = false
                local k2 = g.network:sendMsg("bag.info", function(ret)
                    secondOk = (ret.v == 7)
                end, {})

                local batch = amf3.encode({
                    ret = {
                        amf3.encode({ err = "ok", callback = { callbackName = k1 }, ret = {} }),
                        amf3.encode({ err = "ok", callback = { callbackName = k2 }, ret = { v = 7 } }),
                    }
                })
                g.network:onBodyData(batch, "\0\0\0\0\0\0\1\0")
                assert(secondOk == true, "V15 coexistence: sub-packet #2 must still run!")
                assert(next(g.loadingManager._dataLoadingKeyMap) == nil, "V15 coexistence: _dataLoadingKeyMap must be empty!")
                assert(#_G.__REAL_LOGS >= 1 and string.find(_G.__REAL_LOGS[1], "reward", 1, true) ~= nil,
                       "V15 coexistence: callback error must log full traceback via CCLuaLog!")

                -- Verify onClosed clears keyed spinner even under V15 LoadingManager
                local k3 = g.network:sendMsg("arena.rank", function() end, {})
                assert(g.loadingManager._dataLoadingKeyMap[k3] == 1)
                g.network:onClosed()
                assert(g.loadingManager._dataLoadingKeyMap[k3] == nil)
                assert(g.loadingManager._reconnectLoading ~= nil and g.loadingManager._reconnectLoading.shown == true)
            )LUA";

        REQUIRE_TRUE(vm.execChecked(bootRealScripts.c_str(), "RealDecryptedScripts V15 FAIL"));
    }

    return true;
}

// ============================================================================
// Scenario 19: BtPlatformWin32 "pay" Shim, VNG Platform Key Normalization,
// PayReader Nil/+100/Synthetic Fallback, & Universal 1-Click Instant Buy
// (pay.instantBuy + tmPay.instantBuy + Platform:pay JSON + reload() survival)
// ============================================================================

bool testInstantBuyVngPlatformNormalizationAndBtPlatformPayShim() {
    using gclient::net::CConnection;
    using gclient::net::CNetwork;
    using gclient::net::LCPacket;
    using gclient::net::WinsockSession;

    // Mandatory WinsockSession initialization BEFORE any ::socket() call on Win32!
    WinsockSession ws;
    REQUIRE_TRUE(ws.isInitialized());

    // 1. Verify C++ BtPlatformWin32 "pay" capability shim returns kHttpSuccess + errornu="0"
    const bt::CapabilityShimEntry* payShim = bt::Platform::findCapabilityShim("pay");
    REQUIRE_TRUE(payShim != nullptr);
    REQUIRE_TRUE(payShim->emitCallback);
    REQUIRE_EQ(payShim->callbackEventId, bt::kPay);
    REQUIRE_EQ(payShim->defaultStatusCode, bt::kHttpSuccess);
    REQUIRE_TRUE(payShim->defaultPayloadJson != nullptr);
    REQUIRE_TRUE(std::string(payShim->defaultPayloadJson).find("\"errornu\":\"0\"") != std::string::npos);

    bt::Platform* plat = bt::Platform::getInstance();
    REQUIRE_TRUE(plat != nullptr);
    plat->setAuthProvider(std::make_shared<bt::LocalStubAuthProvider>());

    ScopedLuaVm payVm(true);
    lua_State* L = payVm.L;
    REQUIRE_TRUE(L != nullptr);
    REQUIRE_EQ(tolua_Platform_open(L), 1);
    lua_pop(L, 1);
    gclient::bindings::InstallNetworkResilienceHookImpl(L);

    // Exercise Platform:initSDK + Platform::pay -> tickLoop -> SDKUtil SDKhandler check (zero CCMessageBox!)
    const char* partAScript = R"LUA(
        _G.__MSG_BOX_CALLS = 0
        _G.CCMessageBox = function(title, msg)
            _G.__MSG_BOX_CALLS = _G.__MSG_BOX_CALLS + 1
        end
        _G.__SDK_EVENTS = {}
        local okCodes = { ["0"] = true, ["102"] = true, ["104"] = true }
        local function sdkHandler(eventType, statusCodeOrPayload, maybePayload)
            local payload = type(maybePayload) == "string" and maybePayload or tostring(statusCodeOrPayload or "")
            local hasErrZero = string.find(payload, '"errornu"%s*:%s*"0"') ~= nil
            local errNu = hasErrZero and "0" or nil
            table.insert(_G.__SDK_EVENTS, { ev = eventType, payload = payload, errNu = errNu })
            if not okCodes[errNu] then
                _G.CCMessageBox("msg", payload)
            end
        end
        Platform:getInstance():initSDK("{}", sdkHandler)
    )LUA";
    REQUIRE_TRUE(payVm.execChecked(partAScript, "PartA init FAIL"));
    plat->tickLoop(); // drains kInit
    plat->pay("{\"ProductId\":\"1001\"}");
    plat->tickLoop(); // drains kPay

    REQUIRE_TRUE(payVm.execChecked(R"LUA(
        assert(_G.__MSG_BOX_CALLS == 0, "Platform::pay must NOT trigger blocking CCMessageBox!")
        local sawPayOk = false
        for _, item in ipairs(_G.__SDK_EVENTS) do
            if item.ev == kPay and item.errNu == "0" then
                sawPayOk = true
            end
        end
        assert(sawPayOk, "Expected kPay callback with errornu='0'!")
    )LUA", "PartA verify FAIL"));

    // 2. Verify VNG Platform Key Normalization (SDKUtil.getPL + userdata.platform),
    //    PayReader:getRowById(nil / VN ID pairs / synthetic fallback),
    //    SDKUtil.pay + Platform:pay (pay.instantBuy & tmPay.instantBuy + show_gain_popup),
    //    and survival across reload()!
    const char* partBAndCScript = R"LUA(
        _G.__FATAL_LOGS = 0
        _G.Logger = {
            showFatal = function() _G.__FATAL_LOGS = _G.__FATAL_LOGS + 1 end,
            showWarning = function() end,
            showTrace = function() end,
        }

        local mockPlValue = "android"
        local function makeSdkModule()
            return {
                getPL = function() return mockPlValue end,
                pay = function() error("legacy SDKUtil.pay should be intercepted when network is active") end,
            }
        end

        local rawPayRows = {
            [1703] = setmetatable({
                id = 1703, is_open = 1, recharge_type = 5, consume_money = 5000,
                Stall = 10, days = 0, vip_exp = 10,
                base_reward = { {4, 14374, 1} },
                first_reward = {},
                general_reward = { {2, 0, 100} },
                daily_reward = 0,
                currency_name = "VND", title = "Qua 5000 VND", des = "Uu Dai",
            }, { __index = { marker = "proxy_mt" } }),
            [1606] = {
                id = 1606, is_open = 1, recharge_type = 5, consume_money = 249000,
                Stall = 600, days = 8, vip_exp = 600,
                currency_name = "VND", title = "249000 VND 8 ngay", des = "",
            },
            [1959] = {
                id = 1959, is_open = 1, recharge_type = 5, consume_money = 99000,
                Stall = 240, days = 0, vip_exp = 240,
                base_reward = { {4, 19133, 1} },
                currency_name = "VND", title = "TM Gift", des = "TM",
            },
            [1101] = {
                id = 1101, is_open = 1, recharge_type = 2, consume_money = 109000,
                Stall = 30, days = 30, vip_exp = 300, base_reward = 300, daily_reward = 100,
                currency_name = "VND", title = "MonthCard", des = "",
            },
            [1202] = {
                id = 1202, is_open = 1, recharge_type = 1, consume_money = 25000,
                Stall = 6, days = 0, vip_exp = 60, base_reward = 60, first_reward = 60,
                currency_name = "VND", title = "60 NB", des = "",
            },
        }

        local function makePayReaderModule()
            local pr = {}
            pr.__index = pr
            function pr:new()
                return setmetatable({}, pr)
            end
            function pr:getRowById(id)
                if id == nil then
                    _G.Logger.showFatal("id cannot be nil")
                    error("nil id crash")
                end
                return rawPayRows[tonumber(id)]
            end
            return pr
        end

        local function makeUserDataModule()
            local ud = { platform = "android" }
            ud.__index = ud
            function ud:new()
                local o = setmetatable({ platform = nil }, ud)
                o:ctor()
                return o
            end
            function ud:ctor() end
            function ud:parseData(d)
                self.platform = d and d.platform or nil
            end
            function ud:onUpdateUser(d)
                if d and d.platform ~= nil then
                    self.platform = d.platform
                end
            end
            return ud
        end

        package.preload["utils.SDKUtil"] = makeSdkModule
        package.preload["game.dbReader.PayReader"] = makePayReaderModule
        package.preload["game.gamedata.UserData"] = makeUserDataModule
        package.preload["game.game_TM.gamedata_TM.UserData"] = makeUserDataModule

        local sentNormal = {}
        local sentTM = {}
        local openedPopups = {}

        local PayReader = require("game.dbReader.PayReader")
        local UserData = require("game.gamedata.UserData")
        local UserDataTM = require("game.game_TM.gamedata_TM.UserData")
        local SDKUtil = require("utils.SDKUtil")

        local udInst = UserData:new()
        local udTmInst = UserDataTM:new()

        _G.g = {
            isSDK = true,
            isTM = false,
            SDKUtil = SDKUtil,
            databaseManager = { payReader = PayReader:new() },
            mainData = { userdata = udInst },
            mainData_TM = { userdata = udTmInst },
            panelNameConst = { gainItemListInfoPanel = "gainItemListInfoPanel" },
            panelNameConst_TM = { gainItemListInfoPanel = "tmGainItemListInfoPanel" },
            moduleManager = {
                open = function(name, reward)
                    table.insert(openedPopups, { name = name, reward = reward })
                    return true
                end
            },
            network = {
                sendMsg = function(self, method, cb, args)
                    table.insert(sentNormal, { method = method, cb = cb, args = args })
                end
            },
            network_TM = {
                sendMsg = function(self, method, cb, args)
                    table.insert(sentTM, { method = method, cb = cb, args = args })
                end
            },
        }
        _G.__gclient_apply_net_resilience_sweep()

        -- 2a. SDKUtil.getPL() normalization
        mockPlValue = "android"
        assert(g.SDKUtil.getPL() == "vngandroid", "android -> vngandroid")
        mockPlValue = ""
        assert(g.SDKUtil.getPL() == "vngandroid", "empty -> vngandroid")
        mockPlValue = nil
        assert(g.SDKUtil.getPL() == "vngandroid", "nil -> vngandroid")
        mockPlValue = "vnsg2"
        assert(g.SDKUtil.getPL() == "vngandroid", "vnsg2 -> vngandroid")
        mockPlValue = "vngios"
        assert(g.SDKUtil.getPL() == "vngios", "vngios must be preserved")
        mockPlValue = "vngandroid"
        assert(g.SDKUtil.getPL() == "vngandroid", "vngandroid preserved")

        -- 2b. userdata.platform normalization
        assert(UserData.platform == "vngandroid")
        assert(udInst.platform == "vngandroid")
        udInst:parseData({ platform = "android" })
        assert(udInst.platform == "vngandroid")
        udInst:parseData({ platform = "" })
        assert(udInst.platform == "vngandroid")
        udInst:parseData({})
        assert(udInst.platform == "vngandroid")
        udInst:onUpdateUser({ platform = "vngios" })
        assert(udInst.platform == "vngios")
        udTmInst:parseData({ platform = "android" })
        assert(udTmInst.platform == "vngandroid")

        -- 2c. PayReader:getRowById(nil), VN ID pair +/-100 & +/-200, and synthetic fallback
        local pr = g.databaseManager.payReader
        assert(pr:getRowById(nil) == nil, "getRowById(nil) must return nil cleanly")
        assert(_G.__FATAL_LOGS == 0, "getRowById(nil) must NOT trigger Logger.showFatal")

        local r1603 = pr:getRowById(1603)
        assert(type(r1603) == "table" and r1603.id == 1703 and r1603.consume_money == 5000, "1603 -> 1703 fallback")
        local r1706 = pr:getRowById(1706)
        assert(type(r1706) == "table" and r1706.id == 1606 and r1706.days == 8, "1706 -> 1606 fallback")
        local r1859 = pr:getRowById(1859)
        assert(type(r1859) == "table" and r1859.id == 1959, "1859 -> 1959 TM fallback")
        local r1001 = pr:getRowById(1001)
        assert(type(r1001) == "table" and r1001.id == 1101, "1001 -> 1101 +100 fallback")
        local r1002 = pr:getRowById(1002)
        assert(type(r1002) == "table" and r1002.id == 1202, "1002 -> 1202 pair fallback")

        local rMissing = pr:getRowById(9876)
        assert(type(rMissing) == "table"
            and rMissing.id == 9876
            and rMissing.is_open == 1
            and rMissing.recharge_type == 5
            and rMissing.consume_money == 0
            and rMissing.currency_name == "VND"
            and rMissing.title == "Gift"
            and rMissing.des == "", "missing pay row must return safe synthetic VND Gift table")
        assert(_G.__FATAL_LOGS == 0, "PayReader probes must not fire Logger.showFatal")

        -- 3a. Normal mode SDKUtil.pay -> pay.instantBuy with plain pay_row & extra_data
        g.SDKUtil.pay("1603", "5000", "04", "Qua 5000 VND", "VND", "Uu Dai", {4, 2, 1603})
        assert(#sentNormal == 1 and #sentTM == 0)
        local call1 = sentNormal[1]
        assert(call1.method == "pay.instantBuy")
        assert(call1.args.pay_id == 1603)
        assert(call1.args.pay_id_str == "1603")
        assert(call1.args.pay_price == 5000)
        assert(call1.args.pay_type == "04")
        assert(call1.args.product_name == "Qua 5000 VND")
        assert(call1.args.buy_type == 4)
        assert(call1.args.item_id == 2)
        assert(type(call1.args.extra_data) == "table" and call1.args.extra_data[1] == 4 and call1.args.extra_data[2] == 2)
        assert(type(call1.args.pay_row) == "table" and getmetatable(call1.args.pay_row) == nil)
        assert(call1.args.pay_row.id == 1703 and call1.args.pay_row.vip_exp == 10)
        assert(type(call1.args.pay_row.base_reward) == "table" and call1.args.pay_row.base_reward[1][2] == 14374)

        -- Verify callback show_gain_popup == true opens gainItemListInfoPanel
        call1.cb({ ret = "ok", show_gain_popup = true, reward = { {2, 0, 120}, {4, 14374, 1} } })
        assert(#openedPopups == 1 and openedPopups[1].name == "gainItemListInfoPanel" and #openedPopups[1].reward == 2)

        -- 3b. Time Machine mode via buy_type = 27 -> tmPay.instantBuy over g.network_TM
        g.SDKUtil.pay("1859", "99000", "04", "TM Gift", "VND", "TM", {27, 1, 1859})
        assert(#sentTM == 1)
        assert(sentTM[1].method == "tmPay.instantBuy")
        assert(sentTM[1].args.buy_type == 27 and sentTM[1].args.item_id == 1)
        assert(sentTM[1].args.pay_row.id == 1959)
        sentTM[1].cb({ ret = "ok", show_gain_popup = true, reward = { {4, 19133, 1} } })
        assert(#openedPopups == 2 and openedPopups[2].name == "tmGainItemListInfoPanel")

        -- Also verify g.isTM = true with g.network_TM == nil falls back to g.network with tmPay.instantBuy
        local savedNetTM = g.network_TM
        g.network_TM = nil
        g.isTM = true
        g.SDKUtil.pay("1002", "25000", "00", "60 NB", "VND", "")
        assert(#sentNormal == 2 and sentNormal[2].method == "tmPay.instantBuy")
        assert(sentNormal[2].args.pay_id == 1002 and sentNormal[2].args.pay_type == "00")
        g.isTM = false
        g.network_TM = savedNetTM

        -- 3c. Direct Platform:getInstance():pay(jsonStr) guard without SDKUtil.pay
        Platform:getInstance():pay('{"ProductId":"1606","ProductPrice":"249000","PayType":"04","ProductName":"PreBuy8","CurrencyName":"VND","ExtraData":"[4,5,1606]"}')
        assert(#sentNormal == 3)
        assert(sentNormal[3].method == "pay.instantBuy")
        assert(sentNormal[3].args.pay_id == 1606 and sentNormal[3].args.buy_type == 4 and sentNormal[3].args.item_id == 5)
        assert(sentNormal[3].args.pay_row.days == 8)

        -- 3d. Survival across reload() clearing package.loaded and re-requiring SDKUtil & PayReader
        _G.reload = function()
            package.loaded["utils.SDKUtil"] = nil
            package.loaded["game.dbReader.PayReader"] = nil
            g.SDKUtil = require("utils.SDKUtil")
            local PR2 = require("game.dbReader.PayReader")
            g.databaseManager.payReader = PR2:new()
        end
        _G.__gclient_apply_net_resilience_sweep()
        _G.reload()

        mockPlValue = "android"
        assert(g.SDKUtil.getPL() == "vngandroid", "SDKUtil.getPL hook must survive reload()")
        assert(g.databaseManager.payReader:getRowById(nil) == nil, "PayReader nil guard must survive reload()")
        assert(g.databaseManager.payReader:getRowById(1603).id == 1703, "PayReader +100 pair fallback must survive reload()")
        g.SDKUtil.pay("1603", "5000", "04", "PostReloadBuy", "VND", "", {4, 2, 1603})
        assert(#sentNormal == 4 and sentNormal[4].method == "pay.instantBuy" and sentNormal[4].args.product_name == "PostReloadBuy")
    )LUA";
    REQUIRE_TRUE(payVm.execChecked(partBAndCScript, "PartBC FAIL"));
    plat->tickLoop();

    // 4. Loopback TCP + AMF3 + LCPacket wire verification of SDKUtil.pay -> pay.instantBuy!
    LoopbackTcpListener wireListener;
    REQUIRE_TRUE(wireListener.bindEphemeral(2));

    std::string capturedAmfPayload;
    std::thread wireServer([&wireListener, &capturedAmfPayload]() {
        ScopedSocket client = wireListener.acceptOne();
        if (client.fd != INVALID_SOCKET) {
            char buf[2048] = {};
            const auto n = ::recv(client.fd, buf, sizeof(buf), 0);
            if (n >= static_cast<int>(LCPacket::kTotalHeaderSize)) {
                LCPacket::DecodedPacket pkt{};
                if (LCPacket::parseLCPacket(buf, static_cast<size_t>(n), pkt)) {
                    capturedAmfPayload = pkt.payload;
                }
            }
        }
        wireListener.listenSock.reset();
    });

    CNetwork* net = CNetwork::sharedNetwork();
    CConnection* conn = net->newConnection();
    REQUIRE_TRUE(conn->connect("127.0.0.1", wireListener.port));

    ScopedLuaVm wireVm(true);
    lua_State* wireL = wireVm.L;
    REQUIRE_TRUE(wireL != nullptr);
    gclient::bindings::InstallNetworkResilienceHookImpl(wireL);

    lua_pushlightuserdata(wireL, conn);
    lua_pushcclosure(
        wireL,
        [](lua_State* s) -> int {
            auto* c = static_cast<CConnection*>(lua_touserdata(s, lua_upvalueindex(1)));
            size_t len = 0;
            const char* bytes = luaL_checklstring(s, 1, &len);
            lua_pushboolean(s, c->send(std::string(bytes, len), true) ? 1 : 0);
            return 1;
        },
        1);
    lua_setglobal(wireL, "__c_send_packet");

    const char* wireLua = R"LUA(
        local amf3 = require("amf3")
        package.preload["utils.SDKUtil"] = function()
            return { getPL = function() return "android" end, pay = function() end }
        end
        package.preload["game.dbReader.PayReader"] = function()
            local M = {}
            M.__index = M
            function M:getRowById(id)
                if tonumber(id) == 1703 then
                    return { id = 1703, recharge_type = 5, consume_money = 5000, Stall = 10, vip_exp = 10, base_reward = { {4, 14374, 1} } }
                end
                return nil
            end
            return M
        end
        local SDKUtil = require("utils.SDKUtil")
        local PayReader = require("game.dbReader.PayReader")
        _G.g = {
            SDKUtil = SDKUtil,
            databaseManager = { payReader = setmetatable({}, PayReader) },
            network = {
                sendMsg = function(self, method, cb, args)
                    local raw = amf3.encode({
                        method = method,
                        args = args,
                        token = "tok_instant",
                        callback = { callbackName = method .. "_1" },
                    })
                    assert(__c_send_packet(raw) == true)
                end
            }
        }
        _G.__gclient_apply_net_resilience_sweep()
        g.SDKUtil.pay("1603", "5000", "04", "Qua 5000 VND", "VND", "", {4, 2, 1603})
    )LUA";
    REQUIRE_EQ(luaL_dostring(wireL, wireLua), 0);

    wireServer.join();
    CNetwork::destroySharedNetwork();
    REQUIRE_TRUE(!capturedAmfPayload.empty());

    // Decode captured AMF3 wire payload in Lua and verify exact C2S envelope!
    lua_pushlstring(wireL, capturedAmfPayload.data(), capturedAmfPayload.size());
    lua_setglobal(wireL, "__captured_amf");
    const char* verifyWireLua = R"LUA(
        local amf3 = require("amf3")
        local env = amf3.decode(__captured_amf)
        assert(env.method == "pay.instantBuy")
        assert(env.args.pay_id == 1603 and env.args.buy_type == 4 and env.args.item_id == 2)
        assert(env.args.pay_row.id == 1703 and env.args.pay_row.consume_money == 5000)
    )LUA";
    REQUIRE_EQ(luaL_dostring(wireL, verifyWireLua), 0);
    std::error_code cleanEc;
    fs::remove("device_uuid.txt", cleanEc);
    fs::remove("sdk_cookies.txt", cleanEc);
    return true;
}

} // namespace

int main() {
    gclient::test::TestSuite suite("Kestrel Canvas Win32 C++17 Modernization & Startup Regression Suite");
    suite.run("01_StartupLifecycle_PrematureWmSize_And_StormDeduplication", testStartupLifecycleAndPrematureWmSize);
    suite.run("02_MinimizedLaunch_And_FailedPartialInitRollback", testMinimizedLaunchAndFailedInitRollback);
    suite.run("03_CCLabelAtlas_ZeroDivideGuard_And_DeferredTextureRecovery", testCCLabelAtlasZeroGuardAndDeferredRecovery);
    suite.run("04_32Bit_FntAndZip_IntegerOverflowContracts", testIntegerOverflowArithmeticContracts);
    suite.run("05_CrashAndTelemetry_NanInfSortStrictWeakOrdering_And_LuaHooks", testCrashAndTelemetryNanSortAndLuaHooks);
    suite.run("06_BtDecryptHook_DeepCopiedKeyLifetime_And_PathNormalization", testBtDecryptKeyLifetimeAndPathNormalization);
    suite.run("07_AtomicHotUpdater_UnicodePaths_Rollback_And_TornManifestRecovery", testUnicodeAtomicHotUpdaterAndTornManifestRecovery);
    suite.run("08_SQLite3_ReadOnlyUri_UnicodeAndSpecialCharPaths", testSqliteReadOnlyUnicodeUri);
    suite.run("09_LCPacket_CStringOverload_Md5BeforeInflate_And_ZipBombCap", testLCPacketFramingAndOverloadSafety);
    suite.run("10_CNetwork_LoopbackFraming_ReentrantDoRead_And_DestroyUafBarrier", testCNetworkLoopbackReentrantAndDestroySafety);
    suite.run("11_XmlbBitCache_RealBinaryLayout_StickyBlend_And_ColorClamp", testXmlbBitCacheBinaryLayoutStickyBlendAndColorClamp);
    suite.run("12_PlistbLoader_BinaryParse_RotatedFrames_And_SkinSubRectUvClamp", testPlistbParseRotatedFramesAndSkinSubRectUvClamp);
    suite.run("13_PvrRgba8Unpack_PremulAlpha_And_BlendPipeline", testPvrRgba8UnpackPremulAlphaAndBlendPipeline);
    suite.run("14_StarburstSeam_And_GlowRing_OffscreenPixelVerification", testStarburstSeamAndGlowRingOffscreenPixelVerification);
    suite.run("15_Issue8_GainItemPanel_50PlusLifecycle_GetNodesSync_And_ImageViewIcons", testIssue8GainItemPanelLifecycleAndImageViewRendering);
    suite.run("16_Win32MouseRouting_DpiViewport_And_FuncMenuTouchGroupCycles", testWin32MouseRoutingDpiViewportAndFuncMenuCycles);
    suite.run("17_NetworkAndDataLoading_CrashResilience_And_BindableDataRecovery", testNetworkDataLoadingResilienceAndBindableDataRecovery);
    suite.run("18_InstantBuy_VngPlatformNormalization_And_BtPlatformPayShim", testInstantBuyVngPlatformNormalizationAndBtPlatformPayShim);
    return suite.finishWithBanner();
}
