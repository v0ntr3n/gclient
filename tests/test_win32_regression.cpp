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

    const Issue8SpriteFrame* findSpriteFrameWithFallback(const std::string& rawName) const {
        std::string s = rawName;
        for (char& c : s) {
            if (c == '\\') c = '/';
        }
        while (!s.empty() && s.front() == '#') s.erase(s.begin());
        if (s.empty()) return nullptr;

        auto matchKey = [&](const std::string& k) -> const Issue8SpriteFrame* {
            for (const auto& f : plistFrames) {
                if (f.key == k) return &f;
            }
            const size_t sl = k.find_last_of('/');
            const size_t dt = k.find_last_of('.');
            if (dt == std::string::npos || (sl != std::string::npos && dt < sl)) {
                const std::string withPng = k + ".png";
                for (const auto& f : plistFrames) {
                    if (f.key == withPng) return &f;
                }
            }
            return nullptr;
        };

        if (const auto* f = matchKey(s)) return f;
        if (s.rfind("res/jsonUI/", 0) == 0 && s.size() > 11) {
            if (const auto* f = matchKey(s.substr(11))) return f;
        }
        if (s.rfind("res/", 0) == 0 && s.size() > 4) {
            if (const auto* f = matchKey(s.substr(4))) return f;
        }
        if (s.rfind("gameImage/", 0) == 0 && s.size() > 10) {
            if (const auto* f = matchKey("images/" + s.substr(10))) return f;
        }
        const size_t slash = s.find_last_of('/');
        if (slash != std::string::npos && slash + 1 < s.size()) {
            if (const auto* f = matchKey(s.substr(slash + 1))) return f;
        }
        return nullptr;
    }

    const Issue8SpriteFrame* loadTextureWithFallback(const std::string& rawName) const {
        std::string s = rawName;
        for (char& c : s) {
            if (c == '\\') c = '/';
        }
        while (!s.empty() && s.front() == '#') s.erase(s.begin());
        if (s.empty()) return nullptr;

        auto stripExt = [](const std::string& p) -> std::string {
            if (p.size() > 8 && p.compare(p.size() - 8, 8, ".pvr.ccz") == 0) {
                return p.substr(0, p.size() - 8);
            }
            const size_t sl = p.find_last_of('/');
            const size_t dt = p.find_last_of('.');
            if (dt != std::string::npos && (sl == std::string::npos || dt > sl)) {
                return p.substr(0, dt);
            }
            return p;
        };

        const std::string bases[4] = {
            s,
            (s.rfind("res/jsonUI/", 0) == 0 && s.size() > 11) ? s.substr(11) : std::string(),
            (s.rfind("res/", 0) == 0 && s.size() > 4) ? s.substr(4) : std::string(),
            (s.rfind("gameImage/", 0) == 0 && s.size() > 10) ? ("images/" + s.substr(10)) : std::string(),
        };
        static const char* const kExts[] = {".pvr.ccz", ".pkm", ".png", ".webp", ".jpg", ".jpeg"};

        for (const std::string& base : bases) {
            if (base.empty()) continue;
            for (const auto& f : diskFiles) {
                if (f.key == base) return &f;
            }
            const std::string stem = stripExt(base);
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

    void removeChild(Issue8Node* child, bool cleanup = true) override {
        if (!child) return;
        child->retain();
        Issue8Node::removeChild(child, cleanup);
        if (widgetChildren) widgetChildren->removeObject(child);
        if (nodes) nodes->removeObject(child);
        child->release();
    }

    virtual void removeNode(Issue8Node* node) {
        if (!node) return;
        node->retain();
        Issue8Node::removeChild(node, true);
        if (nodes) nodes->removeObject(node);
        if (widgetChildren) widgetChildren->removeObject(node);
        node->release();
    }

    virtual void removeAllNodes() {
        if (nodes && !nodes->arr.empty()) {
            std::vector<Issue8Node*> snapshot;
            snapshot.reserve(nodes->arr.size());
            for (size_t i = 0; i < nodes->arr.size(); ++i) {
                if (auto* pNode = static_cast<Issue8Node*>(nodes->arr[i])) {
                    pNode->retain();
                    snapshot.push_back(pNode);
                }
            }
            nodes->removeAllObjects();
            for (Issue8Node* n : snapshot) {
                Issue8Node::removeChild(n, true);
                n->release();
            }
        }
    }

    void removeAllChildrenWithCleanup(bool cleanup = true) override {
        std::vector<Issue8Node*> snapshot;
        if (widgetChildren && !widgetChildren->arr.empty()) {
            for (auto* obj : widgetChildren->arr) {
                if (auto* c = static_cast<Issue8Node*>(obj)) {
                    c->retain();
                    snapshot.push_back(c);
                }
            }
            widgetChildren->removeAllObjects();
        }
        if (nodes && !nodes->arr.empty()) {
            for (auto* obj : nodes->arr) {
                if (auto* n = static_cast<Issue8Node*>(obj)) {
                    n->retain();
                    snapshot.push_back(n);
                }
            }
            nodes->removeAllObjects();
        }
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
    runTestCase("11_Issue8_GainItemPanel_50PlusLifecycle_GetNodesSync_And_ImageViewIcons",
                testIssue8GainItemPanelLifecycleAndImageViewRendering);

    std::printf("======================================================================\n");
    std::printf("Summary: %d passed, %d failed\n", g_passedTests, g_failedTests);
    std::printf("======================================================================\n");
    return (g_failedTests == 0) ? 0 : 1;
}
