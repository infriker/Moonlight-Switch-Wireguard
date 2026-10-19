#include "WireGuardManager.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using moonlight::vpn::WireGuardManager;

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void testDisabledBuildRemainsTransparent() {
    WireGuardManager& manager = WireGuardManager::instance();
    // In this portable target MOONLIGHT_WIREGUARD is intentionally undefined.
    // Even a saved enabled preference must not attempt to load a profile.
    manager.initialize(true, "missing-profile.conf", "192.0.2.10");

    check(!manager.enabled(), "WireGuard must report disabled without the Switch backend");
    check(manager.statusText() == "WireGuard: off", "Disabled status should be explicit");
    check(manager.packetSize() == 1024, "Disabled mode should keep the normal packet size");

    std::string connectTo = "stale redirect";
    std::string error;
    check(manager.prepareHttp("not a URL in disabled mode", connectTo, error),
          "Disabled HTTP preparation should leave normal connection handling available");
    check(connectTo.empty(), "Disabled HTTP preparation should not add a tunnel redirect");

    std::string rewrittenRtsp = "original value";
    int packetSize = 777;
    check(manager.prepareStream("unmodified-host", "not an RTSP URL", rewrittenRtsp, packetSize, error),
          "Disabled stream preparation should not impose VPN validation");
    check(rewrittenRtsp == "original value" && packetSize == 777,
          "Disabled stream preparation should leave caller-owned values untouched");
}

} // namespace

int main() {
    try {
        testDisabledBuildRemainsTransparent();
        std::cout << "WireGuard disabled-manager tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "WireGuard disabled-manager test failed: " << error.what() << '\n';
        return 1;
    }
}
