#include "CNetwork.h"

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
    if (fds.empty()) {
        return 0;
    }
    return ::WSAPoll(fds.data(), static_cast<ULONG>(fds.size()), timeoutMs);
}
#else
constexpr int kNetworkTimeoutError = ETIMEDOUT;
using NativePollFd = struct pollfd;
int runSocketPoll(std::vector<NativePollFd>& fds, int timeoutMs) {
    if (fds.empty()) {
        return 0;
    }
    return ::poll(fds.data(), static_cast<nfds_t>(fds.size()), timeoutMs);
}
#endif

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

CNetwork::CNetwork() {
    startPollThread();
}

CNetwork::~CNetwork() {
    shutdown();
}

void CNetwork::startPollThread() {
    std::lock_guard<std::mutex> lock(threadLifecycleMutex_);
    bool expected = false;
    if (running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        if (pollThread_.joinable()) {
            pollThread_.join();
        }
        pollThread_ = std::thread(&CNetwork::pollLoop, this);
    }
}

void CNetwork::shutdown() {
    {
        std::lock_guard<std::mutex> lock(threadLifecycleMutex_);
        bool expected = true;
        if (running_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
            if (pollThread_.joinable()) {
                pollThread_.join();
            }
        }
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

#if defined(GCLIENT_USE_COCOS2DX)
    std::vector<CConnection*> toRelease;
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.clear();
        toRelease.swap(ownedConnections_);
    }

    for (CConnection* conn : toRelease) {
        if (conn != nullptr) {
            conn->network_ = nullptr;
            conn->closeSocketHandle();
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
        if (conn) {
            conn->network_ = nullptr;
            conn->closeSocketHandle();
        }
    }
#endif
}

void CNetwork::onConnectionDestroyed(CConnection* conn) {
    if (conn == nullptr) {
        return;
    }
    // Acquire pollIterationMutex_ FIRST so pollLoop() is guaranteed not to be touching `conn`,
    // and remove `conn` directly from polledConnections_ and pendingRemove_ (NEVER push a dying
    // CConnection* into pendingRemove_, which previously caused UAF on pollThread_!).
    std::lock_guard<std::mutex> pollGuard(pollIterationMutex_);
    polledConnections_.erase(
        std::remove(polledConnections_.begin(), polledConnections_.end(), conn),
        polledConnections_.end());
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
        eventQueue_.erase(
            std::remove_if(eventQueue_.begin(), eventQueue_.end(),
                           [conn](const PendingEvent& ev) { return ev.connection == conn; }),
            eventQueue_.end());
    }
    {
        std::lock_guard<std::mutex> lock(pendingOpsMutex_);
        pendingAdd_.erase(std::remove(pendingAdd_.begin(), pendingAdd_.end(), conn), pendingAdd_.end());
        pendingRemove_.erase(
            std::remove_if(pendingRemove_.begin(), pendingRemove_.end(),
                           [conn](const auto& item) { return item.first == conn; }),
            pendingRemove_.end());
    }
}

CConnection* CNetwork::newConnection() {
    startPollThread();
#if defined(GCLIENT_USE_COCOS2DX)
    auto* raw = new CConnection();
    raw->network_ = this;
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        // Prune previously closed owned connections whose Lua/user refcount dropped back to 1
        // so repeated reconnects over long sessions never leak closed CConnection objects.
        for (auto it = ownedConnections_.begin(); it != ownedConnections_.end();) {
            CConnection* c = *it;
            if (c != nullptr &&
                c->getState() == CConnection::State::Closed &&
                liveSet_.find(c) == liveSet_.end() &&
                c->retainCount() == 1u) {
                c->network_ = nullptr;
                c->release();
                it = ownedConnections_.erase(it);
            } else {
                ++it;
            }
        }
        liveSet_.insert(raw);
        ownedConnections_.push_back(raw);
    }
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
    if (conn == nullptr) {
        return;
    }
    conn->network_ = this;
    startPollThread();
    {
        std::lock_guard<std::mutex> lock(ownedMutex_);
        liveSet_.insert(conn);
    }
    {
        std::lock_guard<std::mutex> lock(pendingOpsMutex_);
        pendingRemove_.erase(
            std::remove_if(pendingRemove_.begin(), pendingRemove_.end(),
                           [conn](const auto& item) { return item.first == conn; }),
            pendingRemove_.end());
        if (std::find(pendingAdd_.begin(), pendingAdd_.end(), conn) == pendingAdd_.end()) {
            pendingAdd_.push_back(conn);
        }
    }
}

void CNetwork::removeConnection(CConnection* conn) {
    if (conn == nullptr) {
        return;
    }
    const uint64_t ep = conn->connectionEpoch();
    std::lock_guard<std::mutex> lock(pendingOpsMutex_);
    pendingAdd_.erase(std::remove(pendingAdd_.begin(), pendingAdd_.end(), conn), pendingAdd_.end());
    pendingRemove_.emplace_back(conn, ep);
}

size_t CNetwork::activeConnectionCount() const {
    std::lock_guard<std::mutex> lock(ownedMutex_);
    return liveSet_.size();
}

void CNetwork::doAddConnection(CConnection* conn) {
    if (conn == nullptr) {
        return;
    }
    if (std::find(polledConnections_.begin(), polledConnections_.end(), conn) ==
        polledConnections_.end()) {
        polledConnections_.push_back(conn);
    }
}

void CNetwork::doReleaseConnection(CConnection* conn, uint64_t expectedEpoch) {
    if (conn == nullptr) {
        return;
    }
    // If the main thread already called close() followed by a fresh connect() (incrementing epoch),
    // do NOT clobber the newly reconnected socket!
    if (expectedEpoch != 0 && conn->connectionEpoch() != expectedEpoch) {
        return;
    }

    polledConnections_.erase(
        std::remove(polledConnections_.begin(), polledConnections_.end(), conn),
        polledConnections_.end());

    conn->closeSocketHandle();
    {
        std::lock_guard<std::mutex> sendLock(conn->sendMutex_);
        conn->sendQueue_.clear();
        conn->queuedSendBytes_ = 0;
        conn->frontSendOffset_ = 0;
    }

    CConnection::State st = conn->state_.load(std::memory_order_acquire);
    while (st == CConnection::State::Connecting || st == CConnection::State::Connected) {
        if (conn->state_.compare_exchange_weak(
                st, CConnection::State::Closing, std::memory_order_acq_rel)) {
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
            eventQueue_.erase(
                std::remove_if(eventQueue_.begin(), eventQueue_.end(),
                               [conn, curEp](const PendingEvent& ev) {
                                   return ev.connection == conn && ev.epoch == curEp;
                               }),
                eventQueue_.end());
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
            PendingEvent overflowClose{};
            overflowClose.type = EventType::Closed;
            overflowClose.connection = ev.connection;
            overflowClose.epoch = ev.epoch;
            overflowClose.wsaError = 0;
            overflowClose.reason = "EVENT_QUEUE_OVERFLOW";
            eventQueue_.push_back(std::move(overflowClose));
            return;
        }
        queuedEventBytes_ += ev.data.size();
    }
    eventQueue_.push_back(std::move(ev));
}

void CNetwork::pollLoop() {
    std::vector<NativePollFd> pollFds;
    std::vector<CConnection*> pollOwners;

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
            for (CConnection* c : adds) {
                doAddConnection(c);
            }
            for (const auto& item : removes) {
                doReleaseConnection(item.first, item.second);
            }
        }

        if (polledConnections_.empty()) {
            pollGuard.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
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
                enqueueEvent(PendingEvent{
                    EventType::Closed,
                    conn,
                    ep,
                    {},
                    kNetworkTimeoutError,
                    timeoutReason
                });
                continue;
            }

            short events = 0;
            if (st == CConnection::State::Connecting) {
                events = POLLOUT;
            } else if (st == CConnection::State::Connected) {
                events = POLLIN;
                if (conn->hasPendingSendData()) {
                    events = static_cast<short>(events | POLLOUT);
                }
            }

            if (events != 0) {
                NativePollFd pfd{};
                pfd.fd = sock;
                pfd.events = events;
                pfd.revents = 0;
                pollFds.push_back(pfd);
                pollOwners.push_back(conn);
            }
        }

        for (const auto& dead : timedOut) {
            doReleaseConnection(dead.first, dead.second);
        }

        if (pollFds.empty()) {
            pollGuard.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        const int ready = runSocketPoll(pollFds, 5);
        if (ready <= 0) {
            continue;
        }

        std::vector<std::pair<CConnection*, uint64_t>> toRemove;
        for (size_t i = 0; i < pollFds.size(); ++i) {
            const short revents = pollFds[i].revents;
            if (revents == 0) {
                continue;
            }
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
                        enqueueEvent(PendingEvent{
                            EventType::Closed,
                            conn,
                            ep,
                            {},
                            soError,
                            "CONNECT_FAILED"
                        });
                    }
                }
                continue;
            }

            if (st != CConnection::State::Connected) {
                continue;
            }

            if (isExcept && !isReadable) {
                int soErr = 0;
#ifdef _WIN32
                int optLen = sizeof(soErr);
#else
                socklen_t optLen = sizeof(soErr);
#endif
                ::getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soErr), &optLen);
                if (soErr == 0) {
                    soErr = CConnection::getLastSocketError();
                }
                toRemove.emplace_back(conn, ep);
                enqueueEvent(PendingEvent{
                    EventType::Closed,
                    conn,
                    ep,
                    {},
                    soErr,
                    "SOCKET_EXCEPTION"
                });
                continue;
            }

            if (isWritable) {
                int sendErr = 0;
                if (!conn->pollFlushSendQueue(sendErr)) {
                    toRemove.emplace_back(conn, ep);
                    enqueueEvent(PendingEvent{
                        EventType::Closed,
                        conn,
                        ep,
                        {},
                        sendErr,
                        "SEND_ERROR"
                    });
                    continue;
                }
            }

            if (isReadable) {
                std::string chunk;
                bool peerClosed = false;
                int recvErr = 0;
                if (conn->pollReadSocket(chunk, peerClosed, recvErr)) {
                    enqueueEvent(PendingEvent{
                        EventType::Data,
                        conn,
                        ep,
                        std::move(chunk),
                        0,
                        nullptr
                    });
                }
                if (peerClosed || recvErr != 0) {
                    toRemove.emplace_back(conn, ep);
                    enqueueEvent(PendingEvent{
                        EventType::Closed,
                        conn,
                        ep,
                        {},
                        recvErr,
                        peerClosed ? "PEER_CLOSED" : "RECV_ERROR"
                    });
                }
            }
        }

        for (const auto& dead : toRemove) {
            doReleaseConnection(dead.first, dead.second);
        }
    }
}

void CNetwork::update(float /*dt*/) {
    std::deque<PendingEvent> drained;
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        if (eventQueue_.empty()) {
            return;
        }
        drained.swap(eventQueue_);
        queuedEventBytes_ = 0;
    }

    for (auto& ev : drained) {
        CConnection* conn = ev.connection;
        if (conn == nullptr) {
            continue;
        }

        bool isLive = false;
        {
            std::lock_guard<std::mutex> lock(ownedMutex_);
            isLive = (liveSet_.find(conn) != liveSet_.end());
            if (isLive) {
                conn->retain();
            }
        }
        if (!isLive) {
            continue;
        }

        struct ReleaseOnScopeExit {
            CConnection* c;
            ~ReleaseOnScopeExit() {
                if (c != nullptr) {
                    c->release();
                }
            }
        } releaseGuard{conn};

        // Ignore stale events belonging to an older connection epoch before reconnect!
        if (ev.epoch != 0 && conn->connectionEpoch() != ev.epoch) {
            continue;
        }

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
            if (conn->getState() == CConnection::State::Closed) {
                std::lock_guard<std::mutex> lock(ownedMutex_);
                liveSet_.erase(conn);
            }
        }
    }
}

} // namespace gclient::net
