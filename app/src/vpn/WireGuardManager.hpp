#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace moonlight::vpn {
class WireGuardManager {
public:
    static WireGuardManager& instance();
    ~WireGuardManager();
    // Called once before host discovery. Options are immutable until shutdown;
    // editing settings never tears down a tunnel underneath streaming threads.
    void initialize(bool enabled, std::string profilePath, std::string target);
    void shutdown();
    bool enabled() const;
    std::string targetAddress() const;
    std::string statusText() const;

    // Empty connectTo means normal LAN operation. False always means stop:
    // an enabled VPN must never fall back to a direct GameStream connection.
    bool prepareHttp(const std::string& url, std::string& connectTo, std::string& error);
    bool prepareStream(const std::string& address, const char* rtspUrl,
                       std::string& rewrittenRtsp, int& packetSize, std::string& error);
    int packetSize() const;

private:
    WireGuardManager() = default;
    struct Backend;
    enum class State { Disabled, Starting, Ready, Failed, Stopping };
    void start();
    void fail(const char* error);
    bool waitReady(std::unique_lock<std::mutex>& lock, std::string& error);
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    State state_ = State::Disabled;
    bool enabled_ = false;
    bool initialized_ = false;
    std::string path_, target_, error_;
    int packetSize_ = 1024;
    std::thread worker_;
    std::unique_ptr<Backend> backend_;
};
} // namespace moonlight::vpn
