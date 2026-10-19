#include "WireGuardManager.hpp"
#include "WireGuardConfig.hpp"
#include "WireGuardRouting.hpp"

#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iterator>

#ifdef MOONLIGHT_WIREGUARD
#include <switch.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <wg_lwip_relay.hpp>
extern "C" {
#include <wireguard.h>
}
#endif

namespace moonlight::vpn {
namespace {
void wipe(void* data, size_t length) {
    auto p = static_cast<volatile unsigned char*>(data);
    while (length--) *p++ = 0;
}
}

struct WireGuardManager::Backend {
#ifdef MOONLIGHT_WIREGUARD
    WgTunnel* tunnel = nullptr;
    std::unique_ptr<wgnx::LwipRelay> relay;
    ~Backend() {
        // Join the packet producer before removing its callback and freeing
        // lwIP's zero-copy receive buffers. wg_close must be LAST.
        if (tunnel) wg_stop(tunnel);
        relay.reset();
        if (tunnel) wg_close(tunnel);
    }
#endif
};

WireGuardManager& WireGuardManager::instance() {
    static WireGuardManager manager;
    return manager;
}
WireGuardManager::~WireGuardManager() { shutdown(); }

void WireGuardManager::initialize(bool enabled, std::string profilePath, std::string target) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) return;
    initialized_ = true;
#ifdef MOONLIGHT_WIREGUARD
    enabled_ = enabled;
#else
    enabled_ = false;
#endif
    path_ = std::move(profilePath);
    target_ = std::move(target);
    if (!enabled_) return;
    state_ = State::Starting;
    try {
        worker_ = std::thread([this] {
            try { start(); }
            catch (...) { fail("WireGuard initialization failed due to a resource error."); }
        });
    } catch (...) {
        error_ = "Could not create the WireGuard initialization worker.";
        state_ = State::Failed;
    }
}

void WireGuardManager::fail(const char* error) {
    std::lock_guard<std::mutex> lock(mutex_);
    error_ = error;
    state_ = State::Failed;
    changed_.notify_all();
}

void WireGuardManager::start() {
#ifdef MOONLIGHT_WIREGUARD
    const auto appletType = appletGetAppletType();
    if (appletType != AppletType_Application && appletType != AppletType_SystemApplication) {
        fail("WireGuard requires full application mode. Start hbmenu using title takeover.");
        return;
    }
    if (!isIpv4Address(target_)) {
        fail("Set the PC's literal IPv4 address in WireGuard settings, then restart Moonlight.");
        return;
    }
    std::ifstream file(path_, std::ios::binary | std::ios::ate);
    if (!file || file.tellg() <= 0 || file.tellg() > 65536) {
        fail("Cannot read WireGuard profile (must be a nonempty file of at most 64 KiB).");
        return;
    }
    const auto length = static_cast<size_t>(file.tellg());
    std::string text(length, '\0');
    file.seekg(0);
    if (!file.read(text.data(), static_cast<std::streamsize>(length))) {
        wipe(text.data(), text.size());
        fail("Cannot read the complete WireGuard profile.");
        return;
    }
    auto parsed = parseConfig(text);
    wipe(text.data(), text.size());
    if (!parsed) { fail(parsed.error.c_str()); return; }
    if (!matchesAllowedIp(parsed.config, target_)) {
        fail("The PC address is outside the profile's AllowedIPs.");
        return;
    }
    if (target_ == parsed.config.address) {
        fail("The PC address must differ from the Switch's tunnel address.");
        return;
    }

    auto backend = std::make_unique<Backend>();
    WgConfig config{};
    std::memcpy(config.private_key, parsed.config.privateKey.data(), WG_KEY_LEN);
    std::memcpy(config.peer_public_key, parsed.config.publicKey.data(), WG_KEY_LEN);
    std::memcpy(config.preshared_key, parsed.config.presharedKey.data(), WG_KEY_LEN);
    config.has_preshared_key = parsed.config.hasPresharedKey;
    inet_pton(AF_INET, parsed.config.address.c_str(), &config.tunnel_ip);
    std::memcpy(config.endpoint_host, parsed.config.endpointHost.c_str(), parsed.config.endpointHost.size() + 1);
    config.endpoint_port = parsed.config.endpointPort;
    config.keepalive_interval = parsed.config.keepalive;
    config.mtu = parsed.config.mtu;
    backend->tunnel = wg_init(&config);
    wipe(&config, sizeof(config));
    parsed.config.wipeKeys();
    if (!backend->tunnel) { fail("Could not initialize WireGuard or resolve its endpoint."); return; }
    if (wg_connect(backend->tunnel) != WG_OK) {
        fail("WireGuard handshake failed. Check endpoint, keys, network and the Switch clock.");
        return;
    }

    backend->relay = std::make_unique<wgnx::LwipRelay>(backend->tunnel);
    if (!backend->relay->start(parsed.config.address, target_)) {
        fail("Could not start WireGuard's local network relay."); return;
    }
    // Fixed local ports keep GameStream's advertised port mapping unchanged.
    for (uint16_t port : {47989, 47984, 48010, 47995, 47999}) {
        if (backend->relay->startTcpRelay(port, port) == 0) {
            fail("A local GameStream TCP port is unavailable. Restart Moonlight."); return;
        }
    }
    for (uint16_t port : {47998, 48000, 47999, 48002, 48010}) {
        if (backend->relay->startUdpRelay(port, port) == 0) {
            fail("A local GameStream UDP port is unavailable. Restart Moonlight."); return;
        }
    }
    if (wg_start(backend->tunnel) != WG_OK) {
        fail("Could not start WireGuard's packet workers."); return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        packetSize_ = tunnelPacketSize(parsed.config.mtu);
        backend_ = std::move(backend);
        state_ = State::Ready;
    }
    changed_.notify_all();
#endif
}

bool WireGuardManager::waitReady(std::unique_lock<std::mutex>& lock, std::string& error) {
    if (!changed_.wait_for(lock, std::chrono::seconds(35), [this] { return state_ != State::Starting; })) {
        error = "WireGuard is still connecting. Retry after checking tunnel status.";
        return false;
    }
    if (state_ != State::Ready) {
        error = error_.empty() ? "WireGuard is unavailable. Direct connection is disabled." : error_;
        return false;
    }
    return true;
}

bool WireGuardManager::prepareHttp(const std::string& url, std::string& connectTo, std::string& error) {
    connectTo.clear();
    std::unique_lock<std::mutex> lock(mutex_);
    if (!enabled_) return true;
    if (!planHttpRoute(true, target_, url, connectTo)) {
        error = "WireGuard mode only connects to the configured PC IPv4 using standard GameStream ports.";
        return false;
    }
    if (!waitReady(lock, error)) { connectTo.clear(); return false; }
    return true;
}

bool WireGuardManager::prepareStream(const std::string& address, const char* rtspUrl,
                                     std::string& rewrittenRtsp, int& packetSize, std::string& error) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!enabled_) return true;
    if (address != target_ && address != target_ + ":47989") {
        error = "The stream host does not match the configured WireGuard PC."; return false;
    }
    if (!waitReady(lock, error)) return false;
    if (!rewriteRtspForTunnel(rtspUrl ? rtspUrl : "", rewrittenRtsp)) {
        error = "WireGuard requires the standard GameStream RTSP port (48010)."; return false;
    }
    packetSize = packetSize_;
    return true;
}

bool WireGuardManager::enabled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return enabled_;
}
std::string WireGuardManager::targetAddress() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return target_;
}
int WireGuardManager::packetSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return packetSize_;
}
std::string WireGuardManager::statusText() const {
    std::lock_guard<std::mutex> lock(mutex_);
    switch (state_) {
    case State::Disabled: return "WireGuard: off";
    case State::Starting: return "WireGuard: connecting...";
    case State::Ready: return "WireGuard: handshake completed; relay ready for " + target_;
    case State::Failed: return "WireGuard: " + error_;
    case State::Stopping: return "WireGuard: stopping";
    }
    return "WireGuard: unavailable";
}
void WireGuardManager::shutdown() {
    if (worker_.joinable()) worker_.join();
    std::unique_ptr<Backend> backend;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_ || state_ == State::Stopping) return;
        state_ = State::Stopping;
        backend = std::move(backend_);
    }
    changed_.notify_all();
    backend.reset();
}
} // namespace moonlight::vpn
