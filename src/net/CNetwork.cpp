#include "CNetwork.h"

#include "common/KestrelHttp.h"

#include <algorithm>
#include <chrono>

#ifndef _WIN32
#include <cerrno>
#include <poll.h>
#endif

namespace gclient::net {

namespace {

constexpr size_t kMaxQueuedEventBytes = 64u * 1024u * 1024u;

#ifdef _WIN32
constexpr int kNetworkTimeoutError = WSAETIMEDOUT;
using NativePollFd = WSAPOLLFD;
int runSocketPoll(std::vector<NativePollFd>& fds, int timeoutMs) {
    return fds.empty() ? 0 : ::WSAPoll(fds.data(), static_cast<ULONG>(fds.size()), timeoutMs);
}
#else
constexpr int kNetworkTimeoutError = ETIMEDOUT;
using NativePollFd = struct pollfd;
int runSocketPoll(std::vector<NativePollFd>& fds, int timeoutMs) {
    return fds.empty() ? 0 : ::poll(fds.data(), static_cast<nfds_t>(fds.size()), timeoutMs);
}
#endif

int querySocketErrorCode(SOCKET sock, int fallbackErr) noexcept {
    int soErr = 0;
#ifdef _WIN32
    int optLen = sizeof(soErr);
#else
    socklen_t optLen = sizeof(soErr);
#endif
    ::getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soErr), &optLen);
    return (soErr != 0) ? soErr : fallbackErr;
}

void joinOrDetachSelf(std::thread& th) {
    if (!th.joinable()) return;
    if (th.get_id() == std::this_thread::get_id()) {
        th.detach();
    } else {
        th.join();
    }
}

} // namespace

std::mutex CNetwork::s_instanceMutex;
CNetwork* CNetwork::s_instance = nullptr;

CNetwork* CNetwork::sharedNetwork() {
    std::lock_guard<std::mutex> lock(s_instanceMutex);
    if (s_instance == nullptr) {
        s_instance = new CNetwork();
    }
    return s_instance;
}

CNetwork* CNetwork::peekSharedNetwork() noexcept {
    std::lock_guard<std::mutex> lock(s_instanceMutex);
    return s_instance;
}

void CNetwork::destroySharedNetwork() {
    CNetwork* inst = nullptr;
    {
        std::lock_guard<std::mutex> lock(s_instanceMutex);
        inst = s_instance;
        s_instance = nullptr;
    }
    if (inst != nullptr) {
        inst->shutdown();
#if defined(GCLIENT_USE_COCOS2DX)
        inst->release();
#else
        delete inst;
#endif
    }
}

CNetwork::CNetwork() { startPollThread(); }
CNetwork::~CNetwork() { shutdown(); }

void CNetwork::wakePollThread() noexcept { pollWakeCv_.notify_all(); }

void CNetwork::startPollThread() {
    std::lock_guard<std::mutex> lock(threadLifecycleMutex_);
    bool expected = false;
    if (running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        if (pollThread_.joinable()) pollThread_.join();
        pollThread_ = std::thread(&CNetwork::pollLoop, this);
    }
}

void CNetwork::shutdown() {
    dispatchGeneration_.fetch_add(1u, std::memory_order_acq_rel);
    {
        std::lock_guard<std::mutex> lock(threadLifecycleMutex_);
        bool expected = true;
        if (running_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
            wakePollThread();
        }
        joinOrDetachSelf(pollThread_);
    }

    {
        std::lock_guard<std::mutex> pollGuard(pollIterationMutex_);
        polledConnections_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventQueue_.clear();
        queuedEventBytes_ = 0;
    }
    {
        std::lock_guard<std::mutex> lock(pendingOpsMutex_);
        pendingAdd_.clear();
        pendingRemove_.clear();
    }

    auto teardownConn = [](CConnection* conn) {
        if (conn == nullptr) return;
        conn->network_ = nullptr;
        conn->state_.store(CConnection::State::Closed, std::memory_order_release);
        conn->closeSocketHandle();
        conn->detachScriptHandlers(true);
    };

#if defined(GCLIENT_USE_COCOS2DX)
    std::vector<CConnection*> toRelease;
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.clear();
        toRelease.swap(ownedConnections_);
    }
    for (CConnection* conn : toRelease) {
        if (conn != nullptr) {
            teardownConn(conn);
            conn->release();
        }
    }
#else
    std::vector<std::unique_ptr<CConnection>> toDestroy;
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.clear();
        toDestroy.swap(ownedConnections_);
    }
    for (auto& conn : toDestroy) {
        teardownConn(conn.get());
    }
#endif
}

void CNetwork::resetForRestart(bool notifyLuaClose) {
    dispatchGeneration_.fetch_add(1u, std::memory_order_acq_rel);

    std::vector<CConnection*> liveSnapshot;
    {
        std::lock_guard<std::mutex> pollGuard(pollIterationMutex_);
        polledConnections_.clear();
        {
            std::lock_guard<std::mutex> lock(pendingOpsMutex_);
            pendingAdd_.clear();
            pendingRemove_.clear();
        }
        {
            std::lock_guard<std::mutex> lock(eventMutex_);
            eventQueue_.clear();
            queuedEventBytes_ = 0;
        }
        {
            std::lock_guard<std::mutex> lock(ownedMutex_);
            liveSnapshot.assign(liveSet_.begin(), liveSet_.end());
            liveSet_.clear();
#if defined(GCLIENT_USE_COCOS2DX)
            for (CConnection* c : liveSnapshot) {
                if (c != nullptr) c->retain();
            }
#endif
        }
    }

    for (CConnection* conn : liveSnapshot) {
        if (conn == nullptr) continue;
        conn->state_.store(CConnection::State::Closed, std::memory_order_release);
        conn->closeSocketHandle();
        {
            std::lock_guard<std::mutex> sendLock(conn->sendMutex_);
            conn->sendQueue_.clear();
            conn->queuedSendBytes_ = 0;
            conn->frontSendOffset_ = 0;
        }
        if (notifyLuaClose) {
            conn->notifyClosedOnMainThread(0, "RESTART_GAME");
        }
        conn->detachScriptHandlers(true);
#if defined(GCLIENT_USE_COCOS2DX)
        conn->release();
#endif
    }
}

void CNetwork::onConnectionDestroyed(CConnection* conn) {
    if (conn == nullptr) return;
    std::lock_guard<std::mutex> pollGuard(pollIterationMutex_);
    std::erase(polledConnections_, conn);
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.erase(conn);
    }
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        for (const auto& ev : eventQueue_) {
            if (ev.connection == conn && queuedEventBytes_ >= ev.data.size()) {
                queuedEventBytes_ -= ev.data.size();
            }
        }
        std::erase_if(eventQueue_, [conn](const PendingEvent& ev) { return ev.connection == conn; });
    }
    {
        std::lock_guard<std::mutex> lock(pendingOpsMutex_);
        std::erase(pendingAdd_, conn);
        std::erase_if(pendingRemove_, [conn](const auto& item) { return item.first == conn; });
    }
}

CConnection* CNetwork::newConnection() {
    startPollThread();
#if defined(GCLIENT_USE_COCOS2DX)
    auto* raw = new CConnection();
    raw->network_ = this;
    std::vector<CConnection*> toPrune;
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        for (auto it = ownedConnections_.begin(); it != ownedConnections_.end();) {
            CConnection* c = *it;
            if (c != nullptr && c->getState() == CConnection::State::Closed &&
                liveSet_.find(c) == liveSet_.end() && c->getReferenceCount() == 1u) {
                c->network_ = nullptr;
                toPrune.push_back(c);
                it = ownedConnections_.erase(it);
            } else {
                ++it;
            }
        }
        liveSet_.insert(raw);
        ownedConnections_.push_back(raw);
    }
    for (CConnection* dead : toPrune) dead->release();
    raw->retain();
    raw->autorelease();
    return raw;
#else
    auto conn = std::make_unique<CConnection>();
    CConnection* raw = conn.get();
    raw->network_ = this;
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.insert(raw);
        ownedConnections_.push_back(std::move(conn));
    }
    return raw;
#endif
}

void CNetwork::addConnection(CConnection* conn) {
    if (conn == nullptr) return;
    conn->network_ = this;
    startPollThread();
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.insert(conn);
    }
    {
        std::lock_guard<std::mutex> lock(pendingOpsMutex_);
        std::erase_if(pendingRemove_, [conn](const auto& item) { return item.first == conn; });
        if (std::find(pendingAdd_.begin(), pendingAdd_.end(), conn) == pendingAdd_.end()) {
            pendingAdd_.push_back(conn);
        }
    }
    wakePollThread();
}

void CNetwork::removeConnection(CConnection* conn) {
    if (conn == nullptr) return;
    const uint64_t ep = conn->connectionEpoch();
    {
        std::lock_guard<std::mutex> lock(pendingOpsMutex_);
        std::erase(pendingAdd_, conn);
        pendingRemove_.emplace_back(conn, ep);
    }
    wakePollThread();
}

size_t CNetwork::activeConnectionCount() const {
    std::lock_guard<std::mutex> lock(ownedMutex_);
    return liveSet_.size();
}

void CNetwork::doAddConnection(CConnection* conn) {
    if (conn != nullptr &&
        std::find(polledConnections_.begin(), polledConnections_.end(), conn) == polledConnections_.end()) {
        polledConnections_.push_back(conn);
    }
}

void CNetwork::doReleaseConnection(CConnection* conn, uint64_t expectedEpoch) {
    if (conn == nullptr || (expectedEpoch != 0 && conn->connectionEpoch() != expectedEpoch)) {
        return;
    }

    std::erase(polledConnections_, conn);
    conn->closeSocketHandle();
    {
        std::lock_guard<std::mutex> sendLock(conn->sendMutex_);
        conn->sendQueue_.clear();
        conn->queuedSendBytes_ = 0;
        conn->frontSendOffset_ = 0;
    }

    CConnection::State st = conn->state_.load(std::memory_order_acquire);
    while (st == CConnection::State::Connecting || st == CConnection::State::Connected) {
        if (conn->state_.compare_exchange_weak(st, CConnection::State::Closing, std::memory_order_acq_rel)) {
            st = CConnection::State::Closing;
            break;
        }
    }

    if (st == CConnection::State::Closed || st == CConnection::State::Disconnected) {
        const uint64_t curEp = conn->connectionEpoch();
        {
            std::lock_guard<std::mutex> evLock(eventMutex_);
            for (const auto& ev : eventQueue_) {
                if (ev.connection == conn && ev.epoch == curEp && queuedEventBytes_ >= ev.data.size()) {
                    queuedEventBytes_ -= ev.data.size();
                }
            }
            std::erase_if(eventQueue_, [conn, curEp](const PendingEvent& ev) {
                return ev.connection == conn && ev.epoch == curEp;
            });
        }
        {
            std::lock_guard<std::mutex> ownLock(ownedMutex_);
            if (conn->getState() == CConnection::State::Closed ||
                conn->getState() == CConnection::State::Disconnected) {
                liveSet_.erase(conn);
            }
        }
    }
}

void CNetwork::enqueueEvent(PendingEvent&& ev) {
    std::lock_guard<std::mutex> lock(eventMutex_);
    if (ev.type == EventType::Data) {
        if (ev.data.size() > kMaxQueuedEventBytes ||
            queuedEventBytes_ > kMaxQueuedEventBytes - ev.data.size()) {
            eventQueue_.push_back(PendingEvent{
                EventType::Closed, ev.connection, ev.epoch, {}, 0, "EVENT_QUEUE_OVERFLOW"
            });
            return;
        }
        queuedEventBytes_ += ev.data.size();
    }
    eventQueue_.push_back(std::move(ev));
}

void CNetwork::pollLoop() {
    std::vector<NativePollFd> pollFds;
    std::vector<CConnection*> pollOwners;

    auto enqueueClosed = [this](CConnection* conn, uint64_t ep, int err, const char* reason) {
        enqueueEvent(PendingEvent{EventType::Closed, conn, ep, {}, err, reason});
    };

    while (running_.load(std::memory_order_acquire)) {
        std::unique_lock<std::mutex> pollGuard(pollIterationMutex_);
        {
            std::vector<CConnection*> adds;
            std::vector<std::pair<CConnection*, uint64_t>> removes;
            {
                std::lock_guard<std::mutex> lock(pendingOpsMutex_);
                adds.swap(pendingAdd_);
                removes.swap(pendingRemove_);
            }
            for (CConnection* c : adds) doAddConnection(c);
            for (const auto& [c, ep] : removes) doReleaseConnection(c, ep);
        }

        if (polledConnections_.empty()) {
            pollGuard.unlock();
            std::unique_lock<std::mutex> wakeLock(pollWakeMutex_);
            pollWakeCv_.wait_for(wakeLock, std::chrono::milliseconds(5), [this]() {
                if (!running_.load(std::memory_order_acquire)) return true;
                std::lock_guard<std::mutex> opsLock(pendingOpsMutex_);
                return !pendingAdd_.empty() || !pendingRemove_.empty();
            });
            continue;
        }

        const auto now = std::chrono::steady_clock::now();
        pollFds.clear();
        pollOwners.clear();
        std::vector<std::pair<CConnection*, uint64_t>> timedOut;

        for (CConnection* conn : polledConnections_) {
            const CConnection::State st = conn->getState();
            const SOCKET sock = conn->nativeHandle();
            const uint64_t ep = conn->connectionEpoch();
            if (sock == INVALID_SOCKET || st == CConnection::State::Closed ||
                st == CConnection::State::Closing || st == CConnection::State::Disconnected) {
                timedOut.emplace_back(conn, ep);
                continue;
            }

            const char* timeoutReason = nullptr;
            if (conn->checkTimeouts(now, timeoutReason)) {
                timedOut.emplace_back(conn, ep);
                enqueueClosed(conn, ep, kNetworkTimeoutError, timeoutReason);
                continue;
            }

            short events = 0;
            if (st == CConnection::State::Connecting) {
                events = POLLOUT;
            } else if (st == CConnection::State::Connected) {
                events = static_cast<short>(POLLIN | (conn->hasPendingSendData() ? POLLOUT : 0));
            }

            if (events != 0) {
                pollFds.push_back(NativePollFd{sock, events, 0});
                pollOwners.push_back(conn);
            }
        }

        for (const auto& [c, ep] : timedOut) doReleaseConnection(c, ep);

        if (pollFds.empty()) {
            pollGuard.unlock();
            std::unique_lock<std::mutex> wakeLock(pollWakeMutex_);
            pollWakeCv_.wait_for(wakeLock, std::chrono::milliseconds(5), [this]() {
                return !running_.load(std::memory_order_acquire);
            });
            continue;
        }

        if (runSocketPoll(pollFds, 5) <= 0 || !running_.load(std::memory_order_acquire)) {
            continue;
        }

        std::vector<std::pair<CConnection*, uint64_t>> toRemove;
        for (size_t i = 0; i < pollFds.size(); ++i) {
            const short revents = pollFds[i].revents;
            if (revents == 0) continue;

            CConnection* conn = pollOwners[i];
            const SOCKET sock = conn->nativeHandle();
            const uint64_t ep = conn->connectionEpoch();
            if (sock == INVALID_SOCKET) {
                toRemove.emplace_back(conn, ep);
                continue;
            }

            const CConnection::State st = conn->getState();
            const bool isReadable = (revents & (POLLIN | POLLHUP)) != 0;
            const bool isWritable = (revents & POLLOUT) != 0;
            const bool isExcept   = (revents & (POLLERR | POLLNVAL)) != 0;

            if (st == CConnection::State::Connecting) {
                if (isWritable || isExcept || (revents & POLLHUP) != 0) {
                    int soError = 0;
                    if (!conn->pollCompleteConnect(soError)) {
                        toRemove.emplace_back(conn, ep);
                        enqueueClosed(conn, ep, soError, "CONNECT_FAILED");
                    }
                }
                continue;
            }
            if (st != CConnection::State::Connected) continue;

            if (isExcept && !isReadable) {
                const int soErr = querySocketErrorCode(sock, CConnection::getLastSocketError());
                toRemove.emplace_back(conn, ep);
                enqueueClosed(conn, ep, soErr, "SOCKET_EXCEPTION");
                continue;
            }

            if (isWritable) {
                int sendErr = 0;
                if (!conn->pollFlushSendQueue(sendErr)) {
                    toRemove.emplace_back(conn, ep);
                    enqueueClosed(conn, ep, sendErr, "SEND_ERROR");
                    continue;
                }
            }

            if (isReadable) {
                std::string chunk;
                bool peerClosed = false;
                int recvErr = 0;
                if (conn->pollReadSocket(chunk, peerClosed, recvErr)) {
                    enqueueEvent(PendingEvent{EventType::Data, conn, ep, std::move(chunk), 0, nullptr});
                }
                if (peerClosed || recvErr != 0) {
                    toRemove.emplace_back(conn, ep);
                    enqueueClosed(conn, ep, recvErr, peerClosed ? "PEER_CLOSED" : "RECV_ERROR");
                }
            }
        }

        for (const auto& [c, ep] : toRemove) doReleaseConnection(c, ep);
    }
}

void CNetwork::update(float /*dt*/) {
    gclient::http::MainThreadEventQueue<PendingEvent> batchQueue;
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        if (eventQueue_.empty()) return;
        for (auto& ev : eventQueue_) batchQueue.push(std::move(ev));
        eventQueue_.clear();
        queuedEventBytes_ = 0;
    }

#if defined(GCLIENT_USE_COCOS2DX)
    struct SelfRetainGuard {
        CNetwork* net;
        explicit SelfRetainGuard(CNetwork* n) noexcept : net(n) { if (net != nullptr) net->retain(); }
        ~SelfRetainGuard() { if (net != nullptr) net->release(); }
    } selfGuard(this);
#endif

    const uint64_t batchGeneration = dispatchGeneration_.load(std::memory_order_acquire);
    std::vector<PendingEvent> drained;
    batchQueue.drain(drained);

    for (auto& ev : drained) {
        if (!running_.load(std::memory_order_acquire) ||
            dispatchGeneration_.load(std::memory_order_acquire) != batchGeneration) {
            break;
        }

        CConnection* conn = ev.connection;
        if (conn == nullptr) continue;

        bool isLive = false;
        {
            std::lock_guard<std::mutex> lock(ownedMutex_);
            isLive = (liveSet_.find(conn) != liveSet_.end());
            if (isLive) conn->retain();
        }
        if (!isLive) continue;

        struct ReleaseOnScopeExit {
            CConnection* c;
            ~ReleaseOnScopeExit() { if (c != nullptr) c->release(); }
        } connRelease{conn};

        if (ev.epoch != 0 && conn->connectionEpoch() != ev.epoch) continue;

        if (ev.type == EventType::Data) {
            if (conn->getState() != CConnection::State::Closed) {
                if (!conn->appendIncomingData(ev.data.data(), ev.data.size())) {
                    conn->close();
                    continue;
                }
                conn->doRead();
            }
        } else if (ev.type == EventType::Closed) {
            conn->notifyClosedOnMainThread(ev.wsaError, ev.reason);
            if (!running_.load(std::memory_order_acquire) ||
                dispatchGeneration_.load(std::memory_order_acquire) != batchGeneration) {
                break;
            }
            if (conn->getState() == CConnection::State::Closed) {
                std::lock_guard<std::mutex> lock(ownedMutex_);
                liveSet_.erase(conn);
            }
        }
    }
}

} // namespace gclient::net
