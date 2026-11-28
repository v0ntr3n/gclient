#pragma once
// ============================================================================
// tests/TestHarness.h
// Shared C++20 Test Runner, Timed Phase Harness, RAII Helpers & Assertion Macros
// Used across test_cobalt_relay_e2e.cpp, test_win32_regression.cpp,
// test_luajit_abi.cpp, and test_cocos2d_dll_init.cpp.
// ============================================================================

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace gclient::test {

template <typename Fn>
class ScopeExit {
public:
    explicit ScopeExit(Fn&& fn) noexcept : fn_(std::forward<Fn>(fn)) {}
    ScopeExit(const ScopeExit&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;
    ScopeExit(ScopeExit&& other) noexcept : fn_(std::move(other.fn_)), active_(other.active_) {
        other.active_ = false;
    }
    ~ScopeExit() noexcept {
        if (active_) {
            fn_();
        }
    }
    void release() noexcept { active_ = false; }

private:
    Fn fn_;
    bool active_ = true;
};

template <typename Fn>
[[nodiscard]] ScopeExit<Fn> makeScopeExit(Fn&& fn) noexcept {
    return ScopeExit<Fn>(std::forward<Fn>(fn));
}

struct ScopedTempDir {
    std::filesystem::path path;

    explicit ScopedTempDir(std::filesystem::path target, bool createNow = true)
        : path(std::move(target)) {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
        if (createNow) {
            std::filesystem::create_directories(path, ec);
        }
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    ~ScopedTempDir() noexcept {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

class TestSuite {
public:
    explicit TestSuite(const char* bannerTitle = nullptr) {
        if (bannerTitle != nullptr) {
            std::printf("======================================================================\n");
            std::printf("%s\n", bannerTitle);
            std::printf("======================================================================\n");
        }
    }

    bool run(const char* name, const std::function<bool()>& fn) {
        std::printf("[RUN ] %s\n", name);
        std::fflush(stdout);
        bool ok = false;
        try {
            ok = fn();
        } catch (const std::exception& ex) {
            std::fprintf(stderr, "[EXCP] %s: %s\n", name, ex.what());
            std::fflush(stderr);
            ok = false;
        } catch (...) {
            std::fprintf(stderr, "[EXCP] %s: unknown exception\n", name);
            std::fflush(stderr);
            ok = false;
        }
        if (ok) {
            ++passed_;
            std::printf("[ OK ] %s\n", name);
        } else {
            ++failed_;
            std::printf("[FAIL] %s\n", name);
        }
        std::fflush(stdout);
        return ok;
    }

    int passed() const noexcept { return passed_; }
    int failed() const noexcept { return failed_; }
    int exitCode() const noexcept { return (failed_ == 0) ? 0 : 1; }

    int finishWithBanner() const {
        std::printf("======================================================================\n");
        std::printf("Summary: %d passed, %d failed\n", passed_, failed_);
        std::printf("======================================================================\n");
        std::fflush(stdout);
        return exitCode();
    }

    int finishCompact(const char* modeLabel = nullptr) const {
        if (modeLabel != nullptr && modeLabel[0] != '\0') {
            std::printf("\n=== Summary: %d passed, %d failed (%s) ===\n",
                        passed_, failed_, modeLabel);
        } else {
            std::printf("\n=== Summary: %d passed, %d failed ===\n", passed_, failed_);
        }
        std::fflush(stdout);
        return exitCode();
    }

private:
    int passed_ = 0;
    int failed_ = 0;
};

struct PhaseRecord {
    std::string name;
    bool passed = false;
    uint64_t durationMs = 0;
    std::string detail;
};

template <typename StartHook>
inline bool runTimedPhase(const char* phaseName,
                          std::vector<PhaseRecord>& records,
                          const std::function<bool(std::string&)>& fn,
                          StartHook&& onStart) {
    onStart(phaseName);
    const auto t0 = std::chrono::steady_clock::now();
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
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    const uint64_t dt = static_cast<uint64_t>(elapsed.count());
    records.push_back(PhaseRecord{phaseName, ok, dt, detail});
    std::printf("[%s] %s (%llu ms) %s\n",
                ok ? " OK  " : "FAIL ",
                phaseName,
                static_cast<unsigned long long>(dt),
                detail.c_str());
    std::fflush(stdout);
    return ok;
}

} // namespace gclient::test

#define REQUIRE_TRUE(expr)                                                                 \
    do {                                                                                   \
        if (!(expr)) {                                                                     \
            std::fprintf(stderr, "[FAIL] %s:%d: assertion failed: %s\n", __FILE__,         \
                         __LINE__, #expr);                                                 \
            std::fflush(stderr);                                                           \
            return false;                                                                  \
        }                                                                                  \
    } while (0)

#define REQUIRE_FALSE(expr) REQUIRE_TRUE(!(expr))

#define REQUIRE_EQ(lhs, rhs)                                                               \
    do {                                                                                   \
        const auto _gclient_lhs = (lhs);                                                   \
        const auto _gclient_rhs = (rhs);                                                   \
        if (!(_gclient_lhs == _gclient_rhs)) {                                             \
            std::fprintf(stderr, "[FAIL] %s:%d: expected (%s == %s)\n", __FILE__,          \
                         __LINE__, #lhs, #rhs);                                            \
            std::fflush(stderr);                                                           \
            return false;                                                                  \
        }                                                                                  \
    } while (0)

#define REQUIRE_NE(lhs, rhs)                                                               \
    do {                                                                                   \
        const auto _gclient_lhs = (lhs);                                                   \
        const auto _gclient_rhs = (rhs);                                                   \
        if (!(_gclient_lhs != _gclient_rhs)) {                                             \
            std::fprintf(stderr, "[FAIL] %s:%d: expected (%s != %s)\n", __FILE__,          \
                         __LINE__, #lhs, #rhs);                                            \
            std::fflush(stderr);                                                           \
            return false;                                                                  \
        }                                                                                  \
    } while (0)

#define REQUIRE_NEAR(lhs, rhs, eps)                                                        \
    do {                                                                                   \
        const double _gclient_l = static_cast<double>(lhs);                                \
        const double _gclient_r = static_cast<double>(rhs);                                \
        const double _gclient_e = static_cast<double>(eps);                                \
        if (!(std::fabs(_gclient_l - _gclient_r) <= _gclient_e)) {                         \
            std::fprintf(stderr,                                                           \
                         "[FAIL] %s:%d: expected |%s - %s| <= %g (got %g vs %g)\n",        \
                         __FILE__, __LINE__, #lhs, #rhs, _gclient_e, _gclient_l,           \
                         _gclient_r);                                                      \
            std::fflush(stderr);                                                           \
            return false;                                                                  \
        }                                                                                  \
    } while (0)

#define CHECK_ABI(cond) REQUIRE_TRUE(cond)

#define PHASE_REQUIRE(cond, detailOut, msgExpr)                                            \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            (detailOut) = (msgExpr);                                                       \
            return false;                                                                  \
        }                                                                                  \
    } while (0)
