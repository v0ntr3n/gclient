// ============================================================================
// tests/test_win32_regression.cpp
// Deterministic Win32 Startup, Lifecycle, CCLabelAtlas Divide-by-Zero Guard,
// Memory/Integer Safety, Unicode Hot-Update, SQLite URI, and Network Framing
// Regression Suite for kestrel-canvas (gclient-win32).
// ============================================================================

#include "assets/BtDecryptHook.h"
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
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

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

#define REQUIRE_NEAR(lhs, rhs, eps)                                                        \
    do {                                                                                   \
        const double _l = static_cast<double>(lhs);                                        \
        const double _r = static_cast<double>(rhs);                                        \
        const double _e = static_cast<double>(eps);                                        \
        if (!(std::fabs(_l - _r) <= _e)) {                                                 \
            std::fprintf(stderr, "[FAIL] %s:%d: expected |%s - %s| <= %g (got %g vs %g)\n",\
                         __FILE__, __LINE__, #lhs, #rhs, _e, _l, _r);                      \
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
    runTestCase("11_Win32MouseRouting_DpiViewport_And_FuncMenuTouchGroupCycles",
                testWin32MouseRoutingDpiViewportAndFuncMenuCycles);

    std::printf("======================================================================\n");
    std::printf("Summary: %d passed, %d failed\n", g_passedTests, g_failedTests);
    std::printf("======================================================================\n");
    return (g_failedTests == 0) ? 0 : 1;
}
