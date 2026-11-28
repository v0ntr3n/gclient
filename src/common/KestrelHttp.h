#pragma once
// Header-only C++20 libcurl initialization/TLS helper, dead-staging endpoint rewriter, and thread-safe MainThreadEventQueue<T>.

#include "common/KestrelBinaryReader.h"
#include "common/KestrelUtf8.h"

#include <array>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if __has_include(<curl/curl.h>)
#include <curl/curl.h>
#define GCLIENT_HTTP_HAS_CURL 1
#else
#define GCLIENT_HTTP_HAS_CURL 0
#endif

namespace gclient::http {

template <typename Event>
class MainThreadEventQueue {
public:
    void push(Event ev) {
        std::lock_guard<std::mutex> lk(mu_);
        items_.push_back(std::move(ev));
    }

    void drain(std::vector<Event>& out) {
        std::lock_guard<std::mutex> lk(mu_);
        if (items_.empty()) return;
        if (out.empty()) {
            out.swap(items_);
        } else {
            out.insert(out.end(), std::make_move_iterator(items_.begin()), std::make_move_iterator(items_.end()));
            items_.clear();
        }
    }

    template <typename Fn>
    size_t drainForEach(Fn&& fn) {
        std::vector<Event> batch;
        drain(batch);
        for (auto& ev : batch) {
            fn(std::move(ev));
        }
        return batch.size();
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        items_.clear();
    }

    bool empty() const {
        std::lock_guard<std::mutex> lk(mu_);
        return items_.empty();
    }

private:
    mutable std::mutex mu_;
    std::vector<Event> items_;
};

struct EndpointRewritePolicy {
    static constexpr std::array<std::string_view, 8> kLegacyStagingHosts = {
        "mapi.omg3q.zing.vn",
        "login.omg3q.zing.vn",
        "dir.omg3q.zing.vn",
        "update.omg3q.zing.vn",
        "cdn.omg3q.zing.vn",
        "192.168.1.240",
        "10.0.0.240",
        "staging.babeltime.com"
    };

    static inline bool isLegacyDeadHost(std::string_view host) noexcept {
        for (auto h : kLegacyStagingHosts) {
            if (gclient::common::equalsAsciiCI(host, h)) return true;
        }
        return gclient::common::endsWithAsciiCI(host, ".omg3q.zing.vn");
    }

    static inline std::string extractUrlHost(std::string_view url, size_t* hostStart = nullptr, size_t* hostEnd = nullptr) {
        size_t p = url.find("://");
        size_t s = (p == std::string_view::npos) ? 0 : (p + 3);
        size_t slash = url.find_first_of("/?#", s);
        size_t end = (slash == std::string_view::npos) ? url.size() : slash;
        size_t colon = url.substr(s, end - s).find(':');
        size_t hEnd = (colon == std::string_view::npos) ? end : (s + colon);
        if (hostStart) *hostStart = s;
        if (hostEnd) *hostEnd = end;
        return gclient::common::toLowerAscii(url.substr(s, hEnd - s));
    }

    static inline std::string rewriteToBase(std::string_view url, std::string_view overrideBase) {
        if (overrideBase.empty() || url.empty()) return std::string(url);
        size_t hs = 0, he = 0;
        const std::string host = extractUrlHost(url, &hs, &he);
        if (!isLegacyDeadHost(host)) return std::string(url);
        std::string base(gclient::common::trimAscii(overrideBase));
        while (!base.empty() && base.back() == '/') base.pop_back();
        return base + std::string(url.substr(he));
    }
};

#if GCLIENT_HTTP_HAS_CURL
inline void ensureCurlGlobalInit() {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    });
}

inline void configureCurlTlsAndTimeouts(
    CURL* curl,
    long connectTimeoutMs = 5000,
    long totalTimeoutMs = 15000,
    bool verifyPeer = true,
    const std::string& caBundle = {})
{
    if (!curl) return;
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, totalTimeoutMs);
#ifdef CURLSSLOPT_NATIVE_CA
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
#endif
    if (!verifyPeer) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        if (!caBundle.empty()) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, caBundle.c_str());
        }
    }
}

struct SimpleHttpResponse {
    long statusCode = 0;
    std::string body;
    std::string headers;
    std::string error;
    bool ok() const noexcept { return error.empty() && statusCode >= 200 && statusCode < 300; }
};

namespace detail {
inline size_t appendWriteCb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    const size_t total = size * nmemb;
    if (userdata && ptr && total > 0) {
        static_cast<std::string*>(userdata)->append(ptr, total);
    }
    return total;
}
} // namespace detail

inline SimpleHttpResponse performCurlRequest(
    const std::string& url,
    const std::string* postBody = nullptr,
    const std::string& cookieJarPath = {},
    long connectTimeoutMs = 5000,
    long totalTimeoutMs = 15000,
    bool verifyPeer = true,
    const std::string& caBundle = {})
{
    ensureCurlGlobalInit();
    SimpleHttpResponse res;
    CURL* curl = curl_easy_init();
    if (!curl) {
        res.error = "curl_easy_init failed";
        return res;
    }
    configureCurlTlsAndTimeouts(curl, connectTimeoutMs, totalTimeoutMs, verifyPeer, caBundle);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &detail::appendWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &detail::appendWriteCb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &res.headers);
    if (!cookieJarPath.empty()) {
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookieJarPath.c_str());
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookieJarPath.c_str());
    }
    if (postBody) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postBody->data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(postBody->size()));
    }
    CURLcode code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
        res.error = curl_easy_strerror(code);
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res.statusCode);
    }
    curl_easy_cleanup(curl);
    return res;
}
#endif

} // namespace gclient::http
