#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
using SOCKET = int;
constexpr SOCKET INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
#endif

#if defined(GCLIENT_USE_COCOS2DX)
#include "cocos2d.h"
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace gclient::net {

class CNetwork;

class WinsockSession {
public:
    WinsockSession();
    ~WinsockSession();

    WinsockSession(const WinsockSession&) = delete;
    WinsockSession& operator=(const WinsockSession&) = delete;

    bool isInitialized() const noexcept { return initialized_; }
    int lastError() const noexcept { return initError_; }

private:
    bool initialized_ = false;
    int initError_ = 0;

    static std::mutex s_mutex;
    static int s_refCount;
};

struct ProtocolTraceEntry {
    uint64_t timestampMs = 0;
    const char* event = "";
    int wsaError = 0;
    uint32_t byteCount = 0;
    uint32_t detailCode = 0;
};

class ProtocolTraceRingBuffer {
public:
    static constexpr size_t kCapacity = 256;

    void record(const char* event, int wsaError = 0, uint32_t byteCount = 0, uint32_t detailCode = 0);
    std::vector<ProtocolTraceEntry> snapshot() const;
    std::string formatSummary(size_t maxEntries = 32) const;
    void clear();

private:
    mutable std::mutex mutex_;
    std::array<ProtocolTraceEntry, kCapacity> entries_{};
    size_t writeIndex_ = 0;
    size_t count_ = 0;
};

class CConnection
#if defined(GCLIENT_USE_COCOS2DX)
    : public cocos2d::CCObject
#endif
{
public:
    enum class State {
        Disconnected,
        Connecting,
        Connected,
        Closing,
        Closed
    };

    using HeadCallback = std::function<uint32_t(const char* headerData, size_t headerSize)>;
    using BodyCallback = std::function<void(const char* bodyData, size_t bodySize,
                                            const char* headerData, size_t headerSize)>;
    using CloseCallback = std::function<void()>;

    CConnection();
#if defined(GCLIENT_USE_COCOS2DX)
    ~CConnection() override;
#else
    virtual ~CConnection();
    void retain() noexcept {}
    void release() noexcept {}
#endif

    class ScopedRetain {
    public:
        explicit ScopedRetain(CConnection* conn) noexcept : conn_(conn) {
            if (conn_ != nullptr) {
                conn_->retain();
            }
        }
        ~ScopedRetain() {
            if (conn_ != nullptr) {
                conn_->release();
            }
        }
        ScopedRetain(const ScopedRetain&) = delete;
        ScopedRetain& operator=(const ScopedRetain&) = delete;

    private:
        CConnection* conn_ = nullptr;
    };

    CConnection(const CConnection&) = delete;
    CConnection& operator=(const CConnection&) = delete;

    bool connect(const char* host, unsigned int port);

    bool send(const std::string& data, bool wrapLCPacket = false);
    // Explicit C-string overload prevents C++17 implicit conversion of (const char*, bool) -> (const void*, size_t(0|1))!
    bool send(const char* cstr, bool wrapLCPacket = false);
    bool send(const void* data, size_t length, bool wrapLCPacket = false);

    void close();

    void setHeaderSize(int headerSize);
    int getHeaderSize() const noexcept { return headerSize_; }

    void registerHeadFunc(int luaHandler);
    void registerBodyFunc(int luaHandler);
    void registerCloseFunc(int luaHandler);

    void setHeadCallback(HeadCallback cb);
    void setBodyCallback(BodyCallback cb);
    void setCloseCallback(CloseCallback cb);

    void setConnectTimeoutMs(uint32_t timeoutMs) noexcept { connectTimeoutMs_ = timeoutMs; }
    void setReadTimeoutMs(uint32_t timeoutMs) noexcept { readTimeoutMs_ = timeoutMs; }
    uint32_t getConnectTimeoutMs() const noexcept { return connectTimeoutMs_; }
    uint32_t getReadTimeoutMs() const noexcept { return readTimeoutMs_; }

    void doRead();
    void doPacketBody(const char* body, size_t bodyLength);

    State getState() const noexcept { return state_.load(std::memory_order_acquire); }
    bool isConnected() const noexcept { return getState() == State::Connected; }
    SOCKET nativeHandle() const noexcept { return socket_.load(std::memory_order_acquire); }
    uint64_t connectionEpoch() const noexcept { return epoch_.load(std::memory_order_acquire); }

    const ProtocolTraceRingBuffer& traceBuffer() const noexcept { return trace_; }

    friend class CNetwork;

private:
    struct ResolvedEndpoint {
        int family = 0;
        int socktype = 0;
        int protocol = 0;
        sockaddr_storage addr{};
        size_t addrLen = 0;
    };

    static int getLastSocketError() noexcept;
    static bool isWouldBlockError(int err) noexcept;

    void releaseAllScriptHandlers();
    static void removeLuaScriptHandler(int& handlerSlot);

    bool tryStartNextEndpointLocked(int& outLastErr, bool& outConnectedImmediately);
    uint32_t getBodyLength(const char* headerPtr, bool& outZeroBodyOk);
    void closeSocketHandle();

    bool pollCompleteConnect(int& outSoError);
    bool pollReadSocket(std::string& outChunk, bool& outPeerClosed, int& outError);
    bool pollFlushSendQueue(int& outError);
    bool hasPendingSendData() const;
    bool checkTimeouts(std::chrono::steady_clock::time_point now, const char*& outReason);

    bool appendIncomingData(const char* data, size_t length);
    void notifyClosedOnMainThread(int wsaError, const char* reason);

    WinsockSession winsock_;
    std::atomic<SOCKET> socket_{INVALID_SOCKET};
    std::atomic<uint64_t> epoch_{0};
    CNetwork* network_ = nullptr;
    std::atomic<State> state_{State::Disconnected};

    mutable std::mutex connectEndpointsMutex_;
    std::deque<ResolvedEndpoint> fallbackEndpoints_;
    unsigned int targetPort_ = 0;

    int headerSize_ = 8;
    uint32_t expectedBodyLength_ = 0;
    bool hasPendingHeader_ = false;
    bool inDoRead_ = false;
    std::vector<char> currentHeader_;
    std::vector<char> recvBuffer_;
    size_t recvReadOffset_ = 0;

    mutable std::mutex sendMutex_;
    std::deque<std::string> sendQueue_;
    size_t queuedSendBytes_ = 0;
    size_t frontSendOffset_ = 0;

    int headLuaHandler_ = 0;
    int bodyLuaHandler_ = 0;
    int closeLuaHandler_ = 0;
    bool closeNotified_ = false;

    HeadCallback headCallback_;
    BodyCallback bodyCallback_;
    CloseCallback closeCallback_;

    uint32_t connectTimeoutMs_ = 10000;
    uint32_t readTimeoutMs_ = 0;
    std::atomic<int64_t> connectStartMs_{0};
    std::atomic<int64_t> lastActivityMs_{0};

    ProtocolTraceRingBuffer trace_;
};

} // namespace gclient::net
