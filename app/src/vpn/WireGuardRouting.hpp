#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace moonlight::vpn {
struct UrlEndpoint {
    std::string host;
    uint16_t port = 0;
    size_t authorityStart = 0;
    size_t authorityEnd = 0;
};

// Strict parsing at the VPN boundary. Never send an unrecognised URL directly.
bool parseServiceUrl(std::string_view url, UrlEndpoint& endpoint);
bool rewriteRtspForTunnel(std::string_view url, std::string& result);
bool isGameStreamTcpPort(uint16_t port);
// Returns false for every unsupported destination when VPN mode is enabled.
// Success with an empty connectTo value explicitly means LAN mode.
bool planHttpRoute(bool enabled, std::string_view target, std::string_view url,
                   std::string& connectTo);
int tunnelPacketSize(uint16_t mtu);
} // namespace moonlight::vpn
