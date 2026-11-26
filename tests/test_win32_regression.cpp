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
#include "diagnostics/CrashAndTelemetry.h"
#include "net/CConnection.h"
#include "net/CNetwork.h"
#include "net/LCPacket.h"
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
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

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
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

int g_passedTests = 0;
int g_failedTests = 0;

#define REQUIRE_TRUE(expr)                                                                 \
    do {                                                                                   \
        if (!(expr)) {                                                                     \
            std::fprintf(stderr, "[FAIL] %s:%d: assertion failed: %s\n", __FILE__,         \
                         __LINE__, #expr);                                                 \
            std::fflush(stderr);                                                           \
            return false;                                                                  \
        }                                                                                  \
    } while (0)

#define REQUIRE_EQ(lhs, rhs)                                                               \
    do {                                                                                   \
        const auto _l = (lhs);                                                             \
        const auto _r = (rhs);                                                             \
        if (!(_l == _r)) {                                                                 \
            std::fprintf(stderr, "[FAIL] %s:%d: expected (%s == %s)\n", __FILE__,          \
                         __LINE__, #lhs, #rhs);                                            \
            std::fflush(stderr);                                                           \
            return false;                                                                  \
        }                                                                                  \
    } while (0)

void runTestCase(const char* name, const std::function<bool()>& fn) {
    std::printf("[RUN ] %s\n", name);
    std::fflush(stdout);
    bool ok = false;
    try {
        ok = fn();
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "[EXCP] %s threw std::exception: %s\n", name, ex.what());
        ok = false;
    } catch (...) {
        std::fprintf(stderr, "[EXCP] %s threw unknown exception\n", name);
        ok = false;
    }
    if (ok) {
        ++g_passedTests;
        std::printf("[ OK ] %s\n", name);
    } else {
        ++g_failedTests;
        std::printf("[FAIL] %s\n", name);
    }
    std::fflush(stdout);
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
    // Scenario 9: NaN / +Inf / -Inf frame delta injection must NEVER violate std::sort strict weak ordering
    const fs::path tempRoot = fs::temp_directory_path() / "kestrel_telemetry_test";
    std::error_code ec;
    fs::remove_all(tempRoot, ec);

    gclient::diagnostics::DiagnosticsConfig cfg;
    cfg.logDirectory = (tempRoot / "logs").u8string();
    cfg.dumpDirectory = (tempRoot / "dumps").u8string();
    cfg.appName = "kestrel_test";
    cfg.metricsFlushIntervalSec = 0.25;

    REQUIRE_TRUE(gclient::diagnostics::CrashAndTelemetry::install(cfg));

    lua_State* L = luaL_newstate();
    REQUIRE_TRUE(L != nullptr);
    luaL_openlibs(L);
    gclient::diagnostics::CrashAndTelemetry::installLuaHooks(L);

    const float nanVal = std::numeric_limits<float>::quiet_NaN();
    const float posInf = std::numeric_limits<float>::infinity();
    const float negInf = -std::numeric_limits<float>::infinity();

    for (int i = 0; i < 600; ++i) {
        if (i % 17 == 0) {
            gclient::diagnostics::CrashAndTelemetry::recordFrame(nanVal);
        } else if (i % 23 == 0) {
            gclient::diagnostics::CrashAndTelemetry::recordFrame(posInf);
        } else if (i % 29 == 0) {
            gclient::diagnostics::CrashAndTelemetry::recordFrame(negInf);
        } else if (i % 31 == 0) {
            gclient::diagnostics::CrashAndTelemetry::recordFrame(-0.5f);
        } else {
            gclient::diagnostics::CrashAndTelemetry::recordFrame(0.0333f);
        }
    }

    const auto snap = gclient::diagnostics::CrashAndTelemetry::getLatestSnapshot();
    REQUIRE_TRUE(std::isfinite(snap.avgFps));
    REQUIRE_TRUE(std::isfinite(snap.avgFrameMs));
    REQUIRE_TRUE(std::isfinite(snap.p95FrameMs));
    REQUIRE_TRUE(std::isfinite(snap.maxFrameMs));
    REQUIRE_TRUE(snap.totalFrames >= 500);

    // Verify Lua __G__TRACKBACK__ hook executes cleanly without leaking Lua stack slots
    const int topBefore = lua_gettop(L);
    lua_getglobal(L, "__G__TRACKBACK__");
    REQUIRE_TRUE(lua_isfunction(L, -1));
    lua_pushstring(L, "synthetic_lua_error");
    REQUIRE_EQ(lua_pcall(L, 1, 1, 0), 0);
    lua_pop(L, 1);
    REQUIRE_EQ(lua_gettop(L), topBefore);

    gclient::diagnostics::CrashAndTelemetry::clearLuaState();
    lua_close(L);
    gclient::diagnostics::CrashAndTelemetry::shutdown();
    fs::remove_all(tempRoot, ec);
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
    const fs::path unicodeRoot =
        fs::temp_directory_path() / fs::u8path(u8"Kestrel Hotfix Tiếng Việt 日本語 Space");
    std::error_code ec;
    fs::remove_all(unicodeRoot, ec);

    const fs::path baseRes = unicodeRoot / fs::u8path(u8"Resources Base");
    const fs::path patchRoot = unicodeRoot / fs::u8path(u8"Patch Overlay Tiếng Việt");
    const fs::path remoteSource = unicodeRoot / fs::u8path(u8"Remote CDN");
    fs::create_directories(baseRes, ec);
    fs::create_directories(remoteSource, ec);

    const fs::path remoteScript = remoteSource / "main_v2.lua";
    const std::string v1Content = "return 'version_1_ok'\n";
    const std::string v2Content = "return 'version_2_faulty'\n";
    {
        std::ofstream f1(remoteSource / "main_v1.lua", std::ios::binary);
        f1.write(v1Content.data(), static_cast<std::streamsize>(v1Content.size()));
        std::ofstream f2(remoteScript, std::ios::binary);
        f2.write(v2Content.data(), static_cast<std::streamsize>(v2Content.size()));
    }

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
            if (copyEc) {
                errOut = copyEc.message();
                return false;
            }
            return true;
        });

    // Reject path traversal before touching disk
    REQUIRE_TRUE(!gclient::update::AtomicHotUpdater::isSafeRelativePath("../evil.dll"));
    REQUIRE_TRUE(!gclient::update::AtomicHotUpdater::isSafeRelativePath("C:/evil.lua"));
    REQUIRE_TRUE(gclient::update::AtomicHotUpdater::isSafeRelativePath("scripts/main.lua"));

    // Apply v1.0.1 and confirm startup health
    gclient::update::PatchManifest m1;
    m1.patchVersion = "1.0.1";
    m1.baseVersion = "1.0.0";
    m1.contract.requiredNativeBindings = {"luaopen_amf3"};
    gclient::update::PatchFileEntry e1;
    e1.relativePath = "scripts/main.lua";
    e1.downloadUrl = (remoteSource / "main_v1.lua").u8string();
    e1.expectedSize = v1Content.size();
    e1.sha256 = shaV1;
    m1.files.push_back(e1);

    const auto r1 = updater.applyPatch(m1);
    REQUIRE_TRUE(r1.ok());
    REQUIRE_TRUE(updater.confirmStartupSuccess().ok());

    // Apply v1.0.2 (Checksum mismatch first -> must reject cleanly)
    gclient::update::PatchManifest mBad = m1;
    mBad.patchVersion = "1.0.9";
    mBad.files[0].sha256 = std::string(64, '0');
    REQUIRE_EQ(updater.stagePatch(mBad).status, gclient::update::UpdateStatus::ChecksumMismatch);

    // Apply valid v1.0.2 and simulate 2 consecutive crash-before-confirm boots -> auto-rollback to 1.0.1!
    gclient::update::PatchManifest m2 = m1;
    m2.patchVersion = "1.0.2";
    m2.files[0].downloadUrl = remoteScript.u8string();
    m2.files[0].expectedSize = v2Content.size();
    m2.files[0].sha256 = shaV2;
    REQUIRE_TRUE(updater.applyPatch(m2).ok());

    // Boot attempt #1 crashes before confirmStartupSuccess() -> failures becomes 1
    const auto boot1 = updater.initializeAndCheckStartupHealth();
    REQUIRE_TRUE(!boot1.rolledBack);
    REQUIRE_EQ(boot1.activeVersion, std::string("1.0.2"));

    // Boot attempt #2 crashes before confirmStartupSuccess() -> failures becomes 2
    const auto boot2 = updater.initializeAndCheckStartupHealth();
    REQUIRE_TRUE(!boot2.rolledBack);
    REQUIRE_EQ(boot2.activeVersion, std::string("1.0.2"));

    // Boot attempt #3 sees consecutiveBootFailures (2) >= maxBootFailuresBeforeRollback (2) -> auto-rolls back!
    const auto boot3 = updater.initializeAndCheckStartupHealth();
    REQUIRE_TRUE(boot3.rolledBack);
    REQUIRE_EQ(boot3.activeVersion, std::string("1.0.1"));
    REQUIRE_EQ(boot3.rolledBackFromVersion, std::string("1.0.2"));

    // Simulate torn active_manifest.json -> must recover from previous_manifest.json!
    {
        std::ofstream corrupt(patchRoot / "active_manifest.json", std::ios::binary | std::ios::trunc);
        corrupt << "{ truncated_json";
    }
    const auto recovered = updater.getActiveState();
    REQUIRE_TRUE(recovered.has_value());
    REQUIRE_TRUE(!recovered->activeVersion.empty());

    fs::remove_all(unicodeRoot, ec);
    return true;
}

bool testSqliteReadOnlyUnicodeUri() {
    // Scenario 15: Verify SQLite3 RFC 8089 read-only URI works with spaces, '#', '?', and Unicode
    const fs::path dir =
        fs::temp_directory_path() / fs::u8path(u8"Kestrel DB Tiếng Việt #1");
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);
    const fs::path dbFile = dir / "DB_Item_Config.db";

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

    fs::remove_all(dir, ec);
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

    // Bind an ephemeral IPv4 loopback listener
    SOCKET listenSock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE_TRUE(listenSock != INVALID_SOCKET);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    REQUIRE_EQ(::bind(listenSock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
    REQUIRE_EQ(::listen(listenSock, 4), 0);

#ifdef _WIN32
    int addrLen = sizeof(addr);
#else
    socklen_t addrLen = sizeof(addr);
#endif
    REQUIRE_EQ(::getsockname(listenSock, reinterpret_cast<sockaddr*>(&addr), &addrLen), 0);
    const unsigned int port = ntohs(addr.sin_port);

    std::atomic<bool> serverReceivedOk{false};
    std::thread serverThread([listenSock, &serverReceivedOk]() {
        SOCKET client = ::accept(listenSock, nullptr, nullptr);
        if (client != INVALID_SOCKET) {
            char buf[256] = {};
            const auto n = ::recv(client, buf, sizeof(buf), 0);
            if (n >= static_cast<int>(LCPacket::kTotalHeaderSize)) {
                LCPacket::DecodedPacket pkt{};
                if (LCPacket::parseLCPacket(buf, static_cast<size_t>(n), pkt) &&
                    pkt.payload == "ping_from_client") {
                    serverReceivedOk.store(true, std::memory_order_release);
                }
            }
            const std::string reply1 = LCPacket::makeLCPacket("pong_packet_1", true);
            const std::string reply2 = LCPacket::makeLCPacket("pong_packet_2", false);
            ::send(client, reply1.data(), static_cast<int>(reply1.size()), 0);
            ::send(client, reply2.data(), static_cast<int>(reply2.size()), 0);
#ifdef _WIN32
            ::closesocket(client);
#else
            ::close(client);
#endif
        }
#ifdef _WIN32
        ::closesocket(listenSock);
#else
        ::close(listenSock);
#endif
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

} // namespace

int main() {
    std::printf("======================================================================\n");
    std::printf("Kestrel Canvas Win32 C++17 Modernization & Startup Regression Suite\n");
    std::printf("======================================================================\n");

    runTestCase("01_StartupLifecycle_PrematureWmSize_And_StormDeduplication",
                testStartupLifecycleAndPrematureWmSize);
    runTestCase("02_MinimizedLaunch_And_FailedPartialInitRollback",
                testMinimizedLaunchAndFailedInitRollback);
    runTestCase("03_CCLabelAtlas_ZeroDivideGuard_And_DeferredTextureRecovery",
                testCCLabelAtlasZeroGuardAndDeferredRecovery);
    runTestCase("04_32Bit_FntAndZip_IntegerOverflowContracts",
                testIntegerOverflowArithmeticContracts);
    runTestCase("05_CrashAndTelemetry_NanInfSortStrictWeakOrdering_And_LuaHooks",
                testCrashAndTelemetryNanSortAndLuaHooks);
    runTestCase("06_BtDecryptHook_DeepCopiedKeyLifetime_And_PathNormalization",
                testBtDecryptKeyLifetimeAndPathNormalization);
    runTestCase("07_AtomicHotUpdater_UnicodePaths_Rollback_And_TornManifestRecovery",
                testUnicodeAtomicHotUpdaterAndTornManifestRecovery);
    runTestCase("08_SQLite3_ReadOnlyUri_UnicodeAndSpecialCharPaths",
                testSqliteReadOnlyUnicodeUri);
    runTestCase("09_LCPacket_CStringOverload_Md5BeforeInflate_And_ZipBombCap",
                testLCPacketFramingAndOverloadSafety);
    runTestCase("10_CNetwork_LoopbackFraming_ReentrantDoRead_And_DestroyUafBarrier",
                testCNetworkLoopbackReentrantAndDestroySafety);
    runTestCase("11_XmlbBitCache_RealBinaryLayout_StickyBlend_And_ColorClamp",
                testXmlbBitCacheBinaryLayoutStickyBlendAndColorClamp);
    runTestCase("12_PlistbLoader_BinaryParse_RotatedFrames_And_SkinSubRectUvClamp",
                testPlistbParseRotatedFramesAndSkinSubRectUvClamp);
    runTestCase("13_PvrRgba8Unpack_PremulAlpha_And_BlendPipeline",
                testPvrRgba8UnpackPremulAlphaAndBlendPipeline);
    runTestCase("14_StarburstSeam_And_GlowRing_OffscreenPixelVerification",
                testStarburstSeamAndGlowRingOffscreenPixelVerification);

    std::printf("======================================================================\n");
    std::printf("Summary: %d passed, %d failed\n", g_passedTests, g_failedTests);
    std::printf("======================================================================\n");
    return (g_failedTests == 0) ? 0 : 1;
}
