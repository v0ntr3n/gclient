#pragma once

#include "CConnection.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace gclient::net {

class CNetwork
#if defined(GCLIENT_USE_COCOS2DX)
    : public cocos2d::CCObject
#endif
{
public:
    static CNetwork* sharedNetwork();
    static CNetwork* peekSharedNetwork() noexcept;
    static void destroySharedNetwork();

#if defined(GCLIENT_USE_COCOS2DX)
    ~CNetwork() override;
#else
    virtual ~CNetwork();
#endif

    CConnection* newConnection();
    void addConnection(CConnection* conn);
    void removeConnection(CConnection* conn);
    void update(float dt);
    void shutdown();
    void resetForRestart(bool notifyLuaClose = false);
    void wakePollThread() noexcept;
    size_t activeConnectionCount() const;

    friend class CConnection;

private:
    enum class EventType {
        Data,
        Closed
    };

    struct PendingEvent {
        EventType type = EventType::Data;
        CConnection* connection = nullptr;
        uint64_t epoch = 0;
        std::string data;
        int wsaError = 0;
        const char* reason = nullptr;
    };

    CNetwork();

    CNetwork(const CNetwork&) = delete;
    CNetwork& operator=(const CNetwork&) = delete;

    void onConnectionDestroyed(CConnection* conn);
    void startPollThread();
    void pollLoop();
    void doAddConnection(CConnection* conn);
    void doReleaseConnection(CConnection* conn, uint64_t expectedEpoch = 0);
    void enqueueEvent(PendingEvent&& ev);

    WinsockSession winsock_;

    std::mutex threadLifecycleMutex_;
    std::atomic<bool> running_{false};
    std::thread pollThread_;

    mutable std::mutex ownedMutex_;
#if defined(GCLIENT_USE_COCOS2DX)
    std::vector<CConnection*> ownedConnections_;
#else
    std::vector<std::unique_ptr<CConnection>> ownedConnections_;
#endif
    std::unordered_set<CConnection*> liveSet_;

    std::mutex pollIterationMutex_;
    std::mutex pendingOpsMutex_;
    std::vector<CConnection*> pendingAdd_;
    std::vector<std::pair<CConnection*, uint64_t>> pendingRemove_;

    std::vector<CConnection*> polledConnections_;

    std::mutex eventMutex_;
    std::deque<PendingEvent> eventQueue_;
    size_t queuedEventBytes_ = 0;

    std::atomic<uint64_t> dispatchGeneration_{0};
    std::mutex pollWakeMutex_;
    std::condition_variable pollWakeCv_;

    static std::mutex s_instanceMutex;
    static CNetwork* s_instance;
};

} // namespace gclient::net
