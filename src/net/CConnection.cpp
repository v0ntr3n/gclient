#include "CConnection.h"
#include "CNetwork.h"
#include "LCPacket.h"

#include "common/KestrelBinaryReader.h"
#include "common/KestrelCrypto.h"
#include "common/KestrelHttp.h"
#include "common/KestrelUtf8.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string_view>

#ifndef _WIN32
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(GCLIENT_USE_COCOS2DX)
#include "CCLuaEngine.h"
#include "cocos2d.h"
#include "tolua_fix.h"
#endif

extern "C" {
#include "lauxlib.h"
#include "lua.h"
}

namespace gclient::net {

namespace {

constexpr uint32_t kMaxFrameBodyLength = 64u * 1024u * 1024u;
constexpr size_t kMaxBufferedBytes = 64u * 1024u * 1024u;
constexpr int kMaxFrameHeaderSize = 65536;

#ifdef _WIN32
constexpr int kSocketTimeoutError = WSAETIMEDOUT;
#else
constexpr int kSocketTimeoutError = ETIMEDOUT;
#endif

uint64_t nowEpochMs() noexcept {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

int64_t steadyMs(std::chrono::steady_clock::time_point tp) noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(tp.time_since_epoch()).count();
}

int64_t nowSteadyMs() noexcept {
    return steadyMs(std::chrono::steady_clock::now());
}

void logMessage(const char* msg) {
#if defined(GCLIENT_USE_COCOS2DX)
    cocos2d::CCLog("%s", msg);
#else
    (void)msg;
#endif
}

bool isDeadLegacyTcpHost(std::string_view host) noexcept {
    if (host.empty()) return false;
    if (gclient::http::EndpointRewritePolicy::isLegacyDeadHost(host)) return true;
    using gclient::common::endsWithAsciiCI;
    using gclient::common::equalsAsciiCI;
    return endsWithAsciiCI(host, ".mto.zing.vn") || endsWithAsciiCI(host, ".zing.vn") ||
           endsWithAsciiCI(host, ".vnggames.com") || endsWithAsciiCI(host, ".babeltime.com") ||
           equalsAsciiCI(host, "mto.zing.vn") || equalsAsciiCI(host, "zing.vn");
}

std::string resolveConnectHost(const char* rawHost) {
    if (!rawHost || !*rawHost) return {};
    std::string host(rawHost);
    if (!gclient::utf8::readEnvBool({"GCLIENT_DISABLE_STAGING_REWRITE"}, false) &&
        isDeadLegacyTcpHost(host)) {
        std::string overrideHost = gclient::utf8::firstNonEmptyEnv(
            {"GCLIENT_TCP_HOST", "GCLIENT_RELAY_TCP_HOST", "KESTREL_GAME_HOST"});
        return overrideHost.empty() ? std::string("127.0.0.1") : overrideHost;
    }
    return host;
}

lua_State* resolveActiveConnectionLuaState(lua_State* standaloneFallback) noexcept {
#if defined(GCLIENT_USE_COCOS2DX)
    if (auto* mgr = ax::ScriptEngineManager::getInstance()) {
        if (auto* engine = dynamic_cast<ax::LuaEngine*>(mgr->getScriptEngine())) {
            if (auto* stack = engine->getLuaStack()) {
                if (lua_State* liveL = stack->getLuaState()) {
                    return liveL;
                }
            }
        }
    }
#endif
    return standaloneFallback;
}

int pushLuaTracebackErrorHandler(lua_State* L) {
    lua_getglobal(L, "__GCLIENT_NATIVE_TRACKBACK__");
    if (lua_isfunction(L, -1)) return lua_gettop(L);
    lua_pop(L, 1);

    lua_getglobal(L, "debug");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "traceback");
        lua_remove(L, -2);
        if (lua_isfunction(L, -1)) return lua_gettop(L);
        lua_pop(L, 1);
    } else {
        lua_pop(L, 1);
    }
    return 0;
}

bool pushRegisteredLuaFunction(lua_State* L, int luaHandler) {
    if (L == nullptr || luaHandler <= 0) return false;

#if defined(GCLIENT_USE_COCOS2DX)
    toluafix_get_function_by_refid(L, luaHandler);
    if (lua_isfunction(L, -1)) return true;
    lua_pop(L, 1);
#endif

    lua_pushliteral(L, "toluafix_refid_function_mapping");
    lua_rawget(L, LUA_REGISTRYINDEX);
    if (lua_istable(L, -1)) {
        lua_rawgeti(L, -1, luaHandler);
        lua_remove(L, -2);
        if (lua_isfunction(L, -1)) return true;
        lua_pop(L, 1);
    } else {
        lua_pop(L, 1);
    }

    lua_rawgeti(L, LUA_REGISTRYINDEX, luaHandler);
    if (lua_isfunction(L, -1)) return true;
    lua_pop(L, 1);
    return false;
}

void logLuaErrorViaCCLuaLog(lua_State* L, const std::string& formattedError) {
    if (L != nullptr) {
        lua_getglobal(L, "CCLuaLog");
        if (lua_isfunction(L, -1)) {
            lua_pushlstring(L, formattedError.data(), formattedError.size());
            if (lua_pcall(L, 1, 0, 0) == 0) return;
            lua_pop(L, 1);
        } else {
            lua_pop(L, 1);
        }
    }
    logMessage(formattedError.c_str());
}

void closeNativeSocket(SOCKET sock) noexcept {
    if (sock != INVALID_SOCKET) {
#ifdef _WIN32
        ::shutdown(sock, SD_BOTH);
        ::closesocket(sock);
#else
        ::shutdown(sock, SHUT_RDWR);
        ::close(sock);
#endif
    }
}

bool configureNonBlockingTcpSocket(SOCKET sock) noexcept {
#ifdef _WIN32
    u_long nonBlocking = 1;
    if (::ioctlsocket(sock, FIONBIO, &nonBlocking) == SOCKET_ERROR) return false;
#else
    const int flags = ::fcntl(sock, F_GETFL, 0);
    if (flags < 0 || ::fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) return false;
#endif
    int nodelay = 1;
    ::setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                 reinterpret_cast<const char*>(&nodelay),
                 static_cast<socklen_t>(sizeof(nodelay)));
    return true;
}

void resetRecvFraming(std::vector<char>& recvBuf, size_t& readOffset,
                      bool& hasPendingHdr, uint32_t& expectedBody,
                      bool releaseCapacity = false) noexcept {
    if (releaseCapacity) {
        std::vector<char>().swap(recvBuf);
    } else {
        recvBuf.clear();
    }
    readOffset = 0;
    hasPendingHdr = false;
    expectedBody = 0;
}

void clearSendQueueLocked(std::deque<std::string>& q, size_t& queuedBytes, size_t& frontOffset) noexcept {
    q.clear();
    queuedBytes = 0;
    frontOffset = 0;
}

} // namespace

std::mutex WinsockSession::s_mutex;
int WinsockSession::s_refCount = 0;

WinsockSession::WinsockSession() {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_refCount == 0) {
        WSADATA wsaData{};
        initError_ = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (initError_ == 0) {
            initialized_ = true;
            ++s_refCount;
        }
    } else {
        initialized_ = true;
        ++s_refCount;
    }
#else
    initialized_ = true;
#endif
}

WinsockSession::~WinsockSession() {
#ifdef _WIN32
    if (!initialized_) return;
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_refCount > 0 && --s_refCount == 0) {
        ::WSACleanup();
    }
#endif
}

void ProtocolTraceRingBuffer::record(const char* event, int wsaError,
                                     uint32_t byteCount, uint32_t detailCode) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_[writeIndex_] = ProtocolTraceEntry{
        nowEpochMs(), event != nullptr ? event : "", wsaError, byteCount, detailCode
    };
    writeIndex_ = (writeIndex_ + 1) % kCapacity;
    if (count_ < kCapacity) ++count_;
}

std::vector<ProtocolTraceEntry> ProtocolTraceRingBuffer::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ProtocolTraceEntry> result;
    result.reserve(count_);
    const size_t start = (count_ == kCapacity) ? writeIndex_ : 0;
    for (size_t i = 0; i < count_; ++i) {
        result.push_back(entries_[(start + i) % kCapacity]);
    }
    return result;
}

std::string ProtocolTraceRingBuffer::formatSummary(size_t maxEntries) const {
    const auto items = snapshot();
    const size_t beginIdx = items.size() > maxEntries ? (items.size() - maxEntries) : 0;
    std::ostringstream oss;
    for (size_t i = beginIdx; i < items.size(); ++i) {
        const auto& e = items[i];
        oss << "[" << e.timestampMs << "] " << e.event
            << " bytes=" << e.byteCount
            << " detail=" << e.detailCode
            << " wsaErr=" << e.wsaError << "\n";
    }
    return oss.str();
}

void ProtocolTraceRingBuffer::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    writeIndex_ = 0;
    count_ = 0;
}

CConnection::CConnection() {
    currentHeader_.resize(static_cast<size_t>(headerSize_), 0);
}

CConnection::~CConnection() {
    state_.store(State::Closed, std::memory_order_release);
    if (network_ != nullptr) {
        network_->onConnectionDestroyed(this);
        network_ = nullptr;
    }
    closeSocketHandle();
    releaseAllScriptHandlers();
}

void CConnection::setStandaloneLuaState(lua_State* L) noexcept {
    standaloneLuaState_ = L;
    if (L != nullptr && ownerLuaState_ == nullptr &&
        (headLuaHandler_ > 0 || bodyLuaHandler_ > 0 || closeLuaHandler_ > 0)) {
        ownerLuaState_ = L;
    }
}

void CConnection::bindOwnerLuaStateOnRegister() {
    if (lua_State* activeL = resolveActiveConnectionLuaState(standaloneLuaState_)) {
        if (ownerLuaState_ != nullptr && ownerLuaState_ != activeL) {
            headLuaHandler_ = 0;
            bodyLuaHandler_ = 0;
            closeLuaHandler_ = 0;
        }
        ownerLuaState_ = activeL;
    }
}

void CConnection::removeLuaScriptHandlerOwned(int& handlerSlot, bool removeFromLiveEngine) {
    if (handlerSlot <= 0) {
        handlerSlot = 0;
        return;
    }
#if defined(GCLIENT_USE_COCOS2DX)
    if (removeFromLiveEngine) {
        lua_State* activeL = resolveActiveConnectionLuaState(nullptr);
        if (activeL != nullptr && (ownerLuaState_ == nullptr || activeL == ownerLuaState_)) {
            if (auto* mgr = ax::ScriptEngineManager::getInstance()) {
                if (auto* engine = mgr->getScriptEngine()) {
                    engine->removeScriptHandler(handlerSlot);
                }
            }
        }
    }
#else
    (void)removeFromLiveEngine;
#endif
    handlerSlot = 0;
}

void CConnection::detachScriptHandlers(bool removeFromLiveEngine) {
    removeLuaScriptHandlerOwned(headLuaHandler_, removeFromLiveEngine);
    removeLuaScriptHandlerOwned(bodyLuaHandler_, removeFromLiveEngine);
    removeLuaScriptHandlerOwned(closeLuaHandler_, removeFromLiveEngine);
    ownerLuaState_ = nullptr;
}

void CConnection::releaseAllScriptHandlers() {
    detachScriptHandlers(true);
}

void CConnection::invokeProtectedLuaHandler(int luaHandler,
                                            const char* contextLabel,
                                            const char* traceErrorEvent,
                                            const char* bodyData,
                                            size_t bodyLength,
                                            const char* headerData,
                                            size_t headerLength,
                                            bool pushPacketArgs) {
    if (luaHandler <= 0) return;

    lua_State* L = resolveActiveConnectionLuaState(standaloneLuaState_);
    if (L == nullptr) return;
    if (ownerLuaState_ != nullptr && L != ownerLuaState_) {
        trace_.record("LUA_VM_GENERATION_MISMATCH", 0, 0, static_cast<uint32_t>(luaHandler));
        detachScriptHandlers(false);
        return;
    }

    const int savedTop = lua_gettop(L);
    if (!lua_checkstack(L, 8)) {
        trace_.record(traceErrorEvent != nullptr ? traceErrorEvent : "LUA_STACK_OVERFLOW",
                      LUA_ERRMEM, static_cast<uint32_t>(bodyLength), static_cast<uint32_t>(headerLength));
        return;
    }

    const int errFuncIdx = pushLuaTracebackErrorHandler(L);
    if (!pushRegisteredLuaFunction(L, luaHandler)) {
        trace_.record("LUA_HANDLER_INVALID", 0, static_cast<uint32_t>(bodyLength), static_cast<uint32_t>(luaHandler));
        lua_settop(L, savedTop);
        return;
    }

    int nargs = 0;
    if (pushPacketArgs) {
        lua_pushlstring(L, bodyData != nullptr ? bodyData : "", bodyLength);
        lua_pushlstring(L, headerData != nullptr ? headerData : "", headerLength);
        nargs = 2;
    }

    const int rc = lua_pcall(L, nargs, 0, errFuncIdx);
    if (rc != 0) {
        const char* errText = lua_tostring(L, -1);
        const std::string traceMsg =
            std::string("[CConnection::") + (contextLabel != nullptr ? contextLabel : "lua") +
            "] Uncaught Lua error: " + (errText != nullptr ? errText : "(non-string Lua error)");

        trace_.record(traceErrorEvent != nullptr ? traceErrorEvent : "LUA_CALLBACK_ERROR",
                      rc, static_cast<uint32_t>(bodyLength), static_cast<uint32_t>(headerLength));

        if (resolveActiveConnectionLuaState(standaloneLuaState_) == L) {
            logLuaErrorViaCCLuaLog(L, traceMsg);
        } else {
            logMessage(traceMsg.c_str());
        }
    }

    if (resolveActiveConnectionLuaState(standaloneLuaState_) == L) {
        lua_settop(L, savedTop);
    }
}

int CConnection::getLastSocketError() noexcept {
#ifdef _WIN32
    return ::WSAGetLastError();
#else
    return errno;
#endif
}

bool CConnection::isWouldBlockError(int err) noexcept {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEALREADY;
#else
    return err == EWOULDBLOCK || err == EAGAIN || err == EINPROGRESS || err == EALREADY;
#endif
}

bool CConnection::tryStartNextEndpointLocked(SOCKET& outSock, int& outLastErr, bool& outConnectedImmediately) {
    outSock = INVALID_SOCKET;
    outLastErr = 0;
    outConnectedImmediately = false;

    while (!fallbackEndpoints_.empty()) {
        const ResolvedEndpoint ep = fallbackEndpoints_.front();
        fallbackEndpoints_.pop_front();

        const SOCKET sock = ::socket(ep.family, ep.socktype, ep.protocol);
        if (sock == INVALID_SOCKET) {
            outLastErr = getLastSocketError();
            continue;
        }
        if (!configureNonBlockingTcpSocket(sock)) {
            outLastErr = getLastSocketError();
            closeNativeSocket(sock);
            continue;
        }

        const int rc = ::connect(
            sock, reinterpret_cast<const sockaddr*>(&ep.addr), static_cast<socklen_t>(ep.addrLen));
        if (rc == 0) {
            outSock = sock;
            outConnectedImmediately = true;
            return true;
        }

        outLastErr = getLastSocketError();
        if (isWouldBlockError(outLastErr)) {
            outSock = sock;
            return true;
        }
        closeNativeSocket(sock);
    }
    return false;
}

bool CConnection::connect(const char* host, unsigned int port) {
    const State curState = getState();
    if (socket_.load(std::memory_order_acquire) != INVALID_SOCKET ||
        curState == State::Connecting || curState == State::Connected || curState == State::Closing) {
        logMessage("socket already exists, you should use a new connection");
        trace_.record("CONNECT_REJECTED", 0, 0, port);
        return false;
    }
    if (!winsock_.isInitialized()) {
        trace_.record("WSA_INIT_FAILED", winsock_.lastError(), 0, port);
        return false;
    }
    if (host == nullptr || host[0] == '\0' || port == 0 || port > 65535u) {
        trace_.record("CONNECT_INVALID_ARGS", 0, 0, port);
        return false;
    }

    const std::string resolvedHost = resolveConnectHost(host);
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portStr[16];
    std::snprintf(portStr, sizeof(portStr), "%u", port);

    addrinfo* addrList = nullptr;
    if (::getaddrinfo(resolvedHost.c_str(), portStr, &hints, &addrList) != 0 || addrList == nullptr) {
        trace_.record("DNS_FAILED", getLastSocketError(), 0, port);
        return false;
    }

    SOCKET newSock = INVALID_SOCKET;
    int lastErr = 0;
    bool connectedImmediately = false;
    {
        std::lock_guard<std::mutex> epLock(connectEndpointsMutex_);
        fallbackEndpoints_.clear();
        targetPort_ = port;
        for (addrinfo* rp = addrList; rp != nullptr; rp = rp->ai_next) {
            if (rp->ai_addr == nullptr || rp->ai_addrlen == 0 ||
                static_cast<size_t>(rp->ai_addrlen) > sizeof(sockaddr_storage)) {
                continue;
            }
            ResolvedEndpoint ep{};
            ep.family = rp->ai_family;
            ep.socktype = rp->ai_socktype;
            ep.protocol = rp->ai_protocol;
            ep.addrLen = static_cast<size_t>(rp->ai_addrlen);
            std::memcpy(&ep.addr, rp->ai_addr, ep.addrLen);
            fallbackEndpoints_.push_back(ep);
        }
        ::freeaddrinfo(addrList);

        if (!tryStartNextEndpointLocked(newSock, lastErr, connectedImmediately)) {
            trace_.record("CONNECT_ERROR", lastErr, 0, port);
            return false;
        }
    }

    epoch_.fetch_add(1u, std::memory_order_acq_rel);
    closeNotified_ = false;
    currentHeader_.assign(static_cast<size_t>(headerSize_), 0);
    resetRecvFraming(recvBuffer_, recvReadOffset_, hasPendingHeader_, expectedBodyLength_);
    {
        std::lock_guard<std::mutex> sendLock(sendMutex_);
        clearSendQueueLocked(sendQueue_, queuedSendBytes_, frontSendOffset_);
    }

    const int64_t nowMs = nowSteadyMs();
    connectStartMs_.store(nowMs, std::memory_order_release);
    lastActivityMs_.store(nowMs, std::memory_order_release);
    socket_.store(newSock, std::memory_order_release);

    if (connectedImmediately) {
        state_.store(State::Connected, std::memory_order_release);
        trace_.record("CONNECT_OK", 0, 0, port);
    } else {
        state_.store(State::Connecting, std::memory_order_release);
        trace_.record("CONNECT_PENDING", lastErr, 0, port);
    }

    network_ = CNetwork::sharedNetwork();
    if (network_ != nullptr) {
        network_->addConnection(this);
    }
    return true;
}

bool CConnection::send(const std::string& data, bool wrapLCPacket) {
    return send(data.data(), data.size(), wrapLCPacket);
}

bool CConnection::send(const char* cstr, bool wrapLCPacket) {
    return (cstr != nullptr) && send(static_cast<const void*>(cstr), std::strlen(cstr), wrapLCPacket);
}

bool CConnection::send(const void* data, size_t length, bool wrapLCPacket) {
    const State st = getState();
    if (socket_.load(std::memory_order_acquire) == INVALID_SOCKET ||
        st == State::Closed || st == State::Closing || st == State::Disconnected) {
        trace_.record("SEND_DISCONNECTED", 0, static_cast<uint32_t>(length), wrapLCPacket ? 1u : 0u);
        return false;
    }
    if (data == nullptr && length > 0) return false;

    std::string wireBytes;
    bool wrappedNow = false;
    if (wrapLCPacket) {
        if (LCPacket::isFramedLCPacket(data, length)) {
            wireBytes.assign(static_cast<const char*>(data), length);
        } else {
            wireBytes = LCPacket::makeLCPacket(data, length, true);
            if (wireBytes.empty()) {
                trace_.record("SEND_PACK_FAILED", 0, static_cast<uint32_t>(length), 1u);
                return false;
            }
            wrappedNow = true;
        }
    } else if (data != nullptr && length > 0) {
        wireBytes.assign(static_cast<const char*>(data), length);
    }

    if (wireBytes.empty()) return true;

    const uint32_t wireLen = static_cast<uint32_t>(wireBytes.size());
    {
        std::lock_guard<std::mutex> lock(sendMutex_);
        if (wireBytes.size() > kMaxBufferedBytes ||
            queuedSendBytes_ > kMaxBufferedBytes - wireBytes.size()) {
            trace_.record("SEND_QUEUE_FULL", 0, wireLen, 0);
            return false;
        }
        queuedSendBytes_ += wireBytes.size();
        sendQueue_.push_back(std::move(wireBytes));
    }

    if (network_ != nullptr) network_->wakePollThread();
    trace_.record("SEND_QUEUED", 0, wireLen, wrappedNow ? 1u : 0u);
    return true;
}

void CConnection::close() {
    ScopedRetain selfGuard(this);
    const State prev = state_.exchange(State::Closed, std::memory_order_acq_rel);
    if (prev == State::Closed && socket_.load(std::memory_order_acquire) == INVALID_SOCKET) {
        return;
    }

    trace_.record("CLOSE_REQUESTED", 0, 0, 0);
    {
        std::lock_guard<std::mutex> epLock(connectEndpointsMutex_);
        fallbackEndpoints_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(sendMutex_);
        clearSendQueueLocked(sendQueue_, queuedSendBytes_, frontSendOffset_);
    }

    closeSocketHandle();
    if (network_ != nullptr) {
        network_->removeConnection(this);
    }
    notifyClosedOnMainThread(0, "LOCAL_CLOSE");
}

void CConnection::closeSocketHandle() {
    closeNativeSocket(socket_.exchange(INVALID_SOCKET, std::memory_order_acq_rel));
}

void CConnection::setHeaderSize(int headerSize) {
    if (headerSize <= 0 || headerSize > kMaxFrameHeaderSize) return;
    headerSize_ = headerSize;
    if (!hasPendingHeader_ && expectedBodyLength_ == 0) {
        currentHeader_.assign(static_cast<size_t>(headerSize_), 0);
    }
}

void CConnection::registerHeadFunc(int luaHandler) {
    bindOwnerLuaStateOnRegister();
    if (headLuaHandler_ != luaHandler) {
        removeLuaScriptHandlerOwned(headLuaHandler_, true);
        headLuaHandler_ = luaHandler;
    }
}

void CConnection::registerBodyFunc(int luaHandler) {
    bindOwnerLuaStateOnRegister();
    if (bodyLuaHandler_ != luaHandler) {
        removeLuaScriptHandlerOwned(bodyLuaHandler_, true);
        bodyLuaHandler_ = luaHandler;
    }
}

void CConnection::registerCloseFunc(int luaHandler) {
    bindOwnerLuaStateOnRegister();
    if (closeLuaHandler_ != luaHandler) {
        removeLuaScriptHandlerOwned(closeLuaHandler_, true);
        closeLuaHandler_ = luaHandler;
    }
}

void CConnection::setHeadCallback(HeadCallback cb) { headCallback_ = std::move(cb); }
void CConnection::setBodyCallback(BodyCallback cb) { bodyCallback_ = std::move(cb); }
void CConnection::setCloseCallback(CloseCallback cb) { closeCallback_ = std::move(cb); }

bool CConnection::appendIncomingData(const char* data, size_t length) {
    if (data == nullptr || length == 0) return true;
    const size_t activeUnread = recvBuffer_.size() - recvReadOffset_;
    if (length > kMaxBufferedBytes || activeUnread > kMaxBufferedBytes - length) {
        trace_.record("RECV_BUFFER_OVERFLOW", 0, static_cast<uint32_t>(length), 0);
        return false;
    }
    if (recvReadOffset_ > 0 && recvBuffer_.size() + length > kMaxBufferedBytes) {
        recvBuffer_.erase(recvBuffer_.begin(), recvBuffer_.begin() + static_cast<std::ptrdiff_t>(recvReadOffset_));
        recvReadOffset_ = 0;
    }
    recvBuffer_.insert(recvBuffer_.end(), data, data + length);
    lastActivityMs_.store(nowSteadyMs(), std::memory_order_release);
    return true;
}

uint32_t CConnection::getBodyLength(const char* headerPtr, bool& outZeroBodyOk) {
    outZeroBodyOk = false;
    if (headerPtr == nullptr || headerSize_ <= 0) return 0u;

    uint32_t bodyLen = 0u;
    bool resolved = false;

    if (headCallback_) {
        bodyLen = headCallback_(headerPtr, static_cast<size_t>(headerSize_));
        resolved = true;
    } else if (headLuaHandler_ > 0) {
        if (lua_State* L = resolveActiveConnectionLuaState(standaloneLuaState_)) {
            if (ownerLuaState_ != nullptr && L != ownerLuaState_) {
                trace_.record("LUA_VM_GENERATION_MISMATCH", 0, 0, static_cast<uint32_t>(headLuaHandler_));
                detachScriptHandlers(false);
                return kMaxFrameBodyLength + 1u;
            }
            const int savedTop = lua_gettop(L);
            if (!lua_checkstack(L, 6)) return kMaxFrameBodyLength + 1u;
            const int errIdx = pushLuaTracebackErrorHandler(L);
            if (!pushRegisteredLuaFunction(L, headLuaHandler_)) {
                lua_settop(L, savedTop);
                return kMaxFrameBodyLength + 1u;
            }
            lua_pushlstring(L, headerPtr, static_cast<size_t>(headerSize_));
            if (lua_pcall(L, 1, 1, errIdx) != 0) {
                const char* errText = lua_tostring(L, -1);
                const std::string msg = std::string("[CConnection::getBodyLength] Uncaught Lua error: ") +
                                        (errText != nullptr ? errText : "(non-string Lua error)");
                if (resolveActiveConnectionLuaState(standaloneLuaState_) == L) {
                    logLuaErrorViaCCLuaLog(L, msg);
                    lua_settop(L, savedTop);
                }
                return kMaxFrameBodyLength + 1u;
            }
            const bool isNum = lua_isnumber(L, -1) != 0;
            const lua_Number rawLen = isNum ? lua_tonumber(L, -1) : -1;
            if (resolveActiveConnectionLuaState(standaloneLuaState_) == L) {
                lua_settop(L, savedTop);
            }
            if (!isNum || rawLen < 0 || rawLen > static_cast<lua_Number>(kMaxFrameBodyLength)) {
                return kMaxFrameBodyLength + 1u;
            }
            bodyLen = static_cast<uint32_t>(rawLen);
            outZeroBodyOk = (bodyLen == 0u);
            resolved = true;
        }
    }

    if (!resolved && headerSize_ >= 4) {
        bodyLen = gclient::common::readBE<uint32_t>(reinterpret_cast<const uint8_t*>(headerPtr));
        outZeroBodyOk = (headerSize_ == static_cast<int>(LCPacket::kTotalHeaderSize) && bodyLen == 0u);
    }

    return (bodyLen > kMaxFrameBodyLength) ? (kMaxFrameBodyLength + 1u) : bodyLen;
}

void CConnection::doRead() {
    ScopedRetain selfGuard(this);
    if (inDoRead_) return;
    if (getState() == State::Closed) {
        resetRecvFraming(recvBuffer_, recvReadOffset_, hasPendingHeader_, expectedBodyLength_);
        return;
    }

    struct ReentrancyGuard {
        bool& flag;
        explicit ReentrancyGuard(bool& f) noexcept : flag(f) { flag = true; }
        ~ReentrancyGuard() { flag = false; }
    } guard(inDoRead_);

    const uint64_t startEpoch = connectionEpoch();
    auto checkAborted = [&]() -> bool {
        if (getState() == State::Closed) {
            resetRecvFraming(recvBuffer_, recvReadOffset_, hasPendingHeader_, expectedBodyLength_);
            return true;
        }
        return connectionEpoch() != startEpoch;
    };

    while (recvReadOffset_ <= recvBuffer_.size()) {
        if (!hasPendingHeader_) {
            if (headerSize_ <= 0) break;
            const size_t frameHeaderSize = static_cast<size_t>(headerSize_);
            if (recvBuffer_.size() - recvReadOffset_ < frameHeaderSize) break;

            std::vector<char> headerCopy(
                recvBuffer_.data() + recvReadOffset_,
                recvBuffer_.data() + recvReadOffset_ + frameHeaderSize);

            bool zeroBodyOk = false;
            const uint32_t bodyLen = getBodyLength(headerCopy.data(), zeroBodyOk);
            if (checkAborted()) return;

            if ((bodyLen == 0u && !zeroBodyOk) || bodyLen > kMaxFrameBodyLength) {
                logMessage("lua error occured for HeadScript, close socket now");
                trace_.record("HEAD_SCRIPT_ERROR", 0, bodyLen, static_cast<uint32_t>(frameHeaderSize));
                close();
                return;
            }

            if (recvBuffer_.size() - recvReadOffset_ < frameHeaderSize) break;
            currentHeader_ = std::move(headerCopy);
            recvReadOffset_ += frameHeaderSize;
            expectedBodyLength_ = bodyLen;
            hasPendingHeader_ = true;
        }

        if (recvReadOffset_ > recvBuffer_.size() ||
            recvBuffer_.size() - recvReadOffset_ < static_cast<size_t>(expectedBodyLength_)) {
            break;
        }

        const uint32_t bodyLen = expectedBodyLength_;
        std::string bodyCopy(recvBuffer_.data() + recvReadOffset_, static_cast<size_t>(bodyLen));
        recvReadOffset_ += static_cast<size_t>(bodyLen);
        expectedBodyLength_ = 0;
        hasPendingHeader_ = false;

        trace_.record("PACKET_DISPATCH", 0, bodyLen, static_cast<uint32_t>(currentHeader_.size()));
        doPacketBody(bodyCopy.data(), bodyCopy.size());

        if (checkAborted()) return;
    }

    if (recvReadOffset_ > 0) {
        if (recvReadOffset_ >= recvBuffer_.size()) {
            recvBuffer_.clear();
            recvReadOffset_ = 0;
        } else if (recvReadOffset_ >= 4096 || recvReadOffset_ * 2 >= recvBuffer_.size()) {
            recvBuffer_.erase(recvBuffer_.begin(), recvBuffer_.begin() + static_cast<std::ptrdiff_t>(recvReadOffset_));
            recvReadOffset_ = 0;
        }
    }
}

void CConnection::doPacketBody(const char* body, size_t bodyLength) {
    ScopedRetain selfGuard(this);
    if (bodyCallback_) {
        bodyCallback_(body, bodyLength, currentHeader_.data(), currentHeader_.size());
        return;
    }
    if (bodyLuaHandler_ > 0) {
        invokeProtectedLuaHandler(
            bodyLuaHandler_, "doPacketBody", "BODY_SCRIPT_ERROR",
            body, bodyLength, currentHeader_.empty() ? "" : currentHeader_.data(),
            currentHeader_.size(), true);
    }
}

bool CConnection::pollCompleteConnect(int& outSoError) {
    outSoError = 0;
    const SOCKET sock = socket_.load(std::memory_order_acquire);
    if (sock == INVALID_SOCKET || getState() != State::Connecting) return false;

    int soError = 0;
#ifdef _WIN32
    int optLen = sizeof(soError);
#else
    socklen_t optLen = sizeof(soError);
#endif
    if (::getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &optLen) == SOCKET_ERROR) {
        soError = getLastSocketError();
    }

    if (soError != 0) {
        SOCKET fallbackSock = INVALID_SOCKET;
        int fallbackErr = soError;
        bool connectedNow = false;
        bool startedFallback = false;
        {
            std::lock_guard<std::mutex> epLock(connectEndpointsMutex_);
            closeSocketHandle();
            if (!fallbackEndpoints_.empty()) {
                startedFallback = tryStartNextEndpointLocked(fallbackSock, fallbackErr, connectedNow);
            }
            if (startedFallback) {
                const int64_t nowMs = nowSteadyMs();
                connectStartMs_.store(nowMs, std::memory_order_release);
                lastActivityMs_.store(nowMs, std::memory_order_release);
                socket_.store(fallbackSock, std::memory_order_release);
            }
        }
        if (startedFallback) {
            state_.store(connectedNow ? State::Connected : State::Connecting, std::memory_order_release);
            trace_.record(connectedNow ? "CONNECT_OK_FALLBACK" : "CONNECT_FALLBACK_PENDING",
                          connectedNow ? 0 : fallbackErr, 0, targetPort_);
            return true;
        }

        outSoError = soError;
        trace_.record("CONNECT_FAILED", soError, 0, targetPort_);
        state_.store(State::Closing, std::memory_order_release);
        return false;
    }

    {
        std::lock_guard<std::mutex> epLock(connectEndpointsMutex_);
        fallbackEndpoints_.clear();
    }
    state_.store(State::Connected, std::memory_order_release);
    lastActivityMs_.store(nowSteadyMs(), std::memory_order_release);
    trace_.record("CONNECT_OK", 0, 0, targetPort_);
    return true;
}

bool CConnection::pollReadSocket(std::string& outChunk, bool& outPeerClosed, int& outError) {
    outChunk.clear();
    outPeerClosed = false;
    outError = 0;

    const SOCKET sock = socket_.load(std::memory_order_acquire);
    if (sock == INVALID_SOCKET || getState() != State::Connected) return false;

    char buf[8192];
    for (;;) {
        const int n = static_cast<int>(::recv(sock, buf, static_cast<int>(sizeof(buf)), 0));
        if (n > 0) {
            outChunk.append(buf, static_cast<size_t>(n));
            lastActivityMs_.store(nowSteadyMs(), std::memory_order_release);
            if (outChunk.size() >= 65536) break;
        } else if (n == 0) {
            outPeerClosed = true;
            trace_.record("RECV_EOF", 0, static_cast<uint32_t>(outChunk.size()), 0);
            break;
        } else {
            const int err = getLastSocketError();
            if (!isWouldBlockError(err)) {
                outError = err;
                trace_.record("RECV_ERROR", err, static_cast<uint32_t>(outChunk.size()), 0);
            }
            break;
        }
    }

    if (!outChunk.empty()) {
        trace_.record("RECV_BYTES", 0, static_cast<uint32_t>(outChunk.size()), 0);
        return true;
    }
    return false;
}

bool CConnection::pollFlushSendQueue(int& outError) {
    outError = 0;
    const SOCKET sock = socket_.load(std::memory_order_acquire);
    if (sock == INVALID_SOCKET || getState() != State::Connected) return true;

#ifdef MSG_NOSIGNAL
    constexpr int kSendFlags = MSG_NOSIGNAL;
#else
    constexpr int kSendFlags = 0;
#endif

    std::lock_guard<std::mutex> lock(sendMutex_);
    uint32_t totalSent = 0;

    while (!sendQueue_.empty()) {
        const std::string& front = sendQueue_.front();
        const size_t remaining = front.size() - frontSendOffset_;
        if (remaining == 0) {
            sendQueue_.pop_front();
            frontSendOffset_ = 0;
            continue;
        }

        const size_t chunkToSend = (std::min)(remaining, static_cast<size_t>(262144u));
        const int sent = static_cast<int>(
            ::send(sock, front.data() + frontSendOffset_, static_cast<int>(chunkToSend), kSendFlags));
        if (sent > 0) {
            const size_t sentSz = static_cast<size_t>(sent);
            frontSendOffset_ += sentSz;
            queuedSendBytes_ = (queuedSendBytes_ >= sentSz) ? (queuedSendBytes_ - sentSz) : 0;
            totalSent += static_cast<uint32_t>(sent);
            lastActivityMs_.store(nowSteadyMs(), std::memory_order_release);
            if (frontSendOffset_ >= front.size()) {
                sendQueue_.pop_front();
                frontSendOffset_ = 0;
            }
        } else if (sent == SOCKET_ERROR) {
            const int err = getLastSocketError();
            if (isWouldBlockError(err)) break;
            outError = err;
            trace_.record("SEND_ERROR", err, totalSent, 0);
            return false;
        } else {
            break;
        }
    }

    if (totalSent > 0) trace_.record("SEND_BYTES", 0, totalSent, 0);
    return true;
}

bool CConnection::hasPendingSendData() const {
    std::lock_guard<std::mutex> lock(sendMutex_);
    return !sendQueue_.empty();
}

bool CConnection::checkTimeouts(std::chrono::steady_clock::time_point now, const char*& outReason) {
    outReason = nullptr;
    const State st = getState();
    const int64_t nowMs = steadyMs(now);

    if (st == State::Connecting && connectTimeoutMs_ > 0 &&
        nowMs - connectStartMs_.load(std::memory_order_acquire) >= static_cast<int64_t>(connectTimeoutMs_)) {
        outReason = "CONNECT_TIMEOUT";
        trace_.record("CONNECT_TIMEOUT", kSocketTimeoutError, 0, connectTimeoutMs_);
        return true;
    }
    if (st == State::Connected && readTimeoutMs_ > 0 &&
        nowMs - lastActivityMs_.load(std::memory_order_acquire) >= static_cast<int64_t>(readTimeoutMs_)) {
        outReason = "READ_TIMEOUT";
        trace_.record("READ_TIMEOUT", kSocketTimeoutError, 0, readTimeoutMs_);
        return true;
    }
    return false;
}

void CConnection::notifyClosedOnMainThread(int wsaError, const char* reason) {
    ScopedRetain selfGuard(this);
    if (closeNotified_) return;
    closeNotified_ = true;
    state_.store(State::Closed, std::memory_order_release);
    closeSocketHandle();
    resetRecvFraming(recvBuffer_, recvReadOffset_, hasPendingHeader_, expectedBodyLength_, true);
    trace_.record(reason != nullptr ? reason : "CLOSED", wsaError, 0, 0);

    if (closeCallback_) {
        closeCallback_();
        return;
    }
    if (closeLuaHandler_ > 0) {
        invokeProtectedLuaHandler(
            closeLuaHandler_, "notifyClosedOnMainThread", "CLOSE_SCRIPT_ERROR",
            nullptr, 0, nullptr, 0, false);
    }
}

} // namespace gclient::net
