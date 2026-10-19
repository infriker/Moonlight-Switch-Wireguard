#include "WireGuardRouting.hpp"

#include <algorithm>

namespace moonlight::vpn {
bool parseServiceUrl(std::string_view url, UrlEndpoint& endpoint) {
    endpoint = {};
    const auto scheme = url.find("://");
    if (scheme == std::string_view::npos) return false;
    const auto protocol = url.substr(0, scheme);
    if (protocol != "http" && protocol != "https" && protocol != "rtsp" &&
        protocol != "rtspenc" && protocol != "rtspru") return false;
    endpoint.authorityStart = scheme + 3;
    endpoint.authorityEnd = url.find_first_of("/?#", endpoint.authorityStart);
    if (endpoint.authorityEnd == std::string_view::npos) endpoint.authorityEnd = url.size();
    auto authority = url.substr(endpoint.authorityStart, endpoint.authorityEnd - endpoint.authorityStart);
    if (authority.empty() || authority.find_first_of("@[]\\ \t\r\n") != std::string_view::npos) return false;
    const auto colon = authority.find(':');
    if (colon == std::string_view::npos || colon == 0) return false;
    const auto port = authority.substr(colon + 1);
    if (port.empty() || port.size() > 5) return false;
    unsigned number = 0;
    for (char c : port) {
        if (c < '0' || c > '9') return false;
        number = number * 10 + static_cast<unsigned>(c - '0');
    }
    if (number == 0 || number > 65535) return false;
    endpoint.host = std::string(authority.substr(0, colon));
    endpoint.port = static_cast<uint16_t>(number);
    return true;
}

bool rewriteRtspForTunnel(std::string_view url, std::string& result) {
    result.clear();
    if (url.empty()) return true; // moonlight-common-c uses its default RTSP URL.
    if (url.substr(0, 7) != "rtsp://" && url.substr(0, 10) != "rtspenc://" &&
        url.substr(0, 9) != "rtspru://") return false;
    UrlEndpoint endpoint;
    if (!parseServiceUrl(url, endpoint) || endpoint.port != 48010) return false;
    result = std::string(url.substr(0, endpoint.authorityStart)) +
             "127.0.0.1:48010" + std::string(url.substr(endpoint.authorityEnd));
    return true;
}

bool isGameStreamTcpPort(uint16_t port) {
    return port == 47989 || port == 47984 || port == 48010 ||
           port == 47995 || port == 47999;
}

bool planHttpRoute(bool enabled, std::string_view target, std::string_view url,
                   std::string& connectTo) {
    connectTo.clear();
    if (!enabled) return true;
    if (target.empty() || (url.substr(0, 7) != "http://" && url.substr(0, 8) != "https://")) return false;
    UrlEndpoint endpoint;
    if (!parseServiceUrl(url, endpoint) || endpoint.host != target ||
        !isGameStreamTcpPort(endpoint.port)) return false;
    connectTo = endpoint.host + ":" + std::to_string(endpoint.port) +
                ":127.0.0.1:" + std::to_string(endpoint.port);
    return true;
}

int tunnelPacketSize(uint16_t mtu) {
    // Leave room for IPv4/UDP and Moonlight's encrypted video header. Keep the
    // normal remote-stream 1024-byte ceiling even when the tunnel MTU is larger.
    return (std::min(1024, static_cast<int>(mtu) - 96) / 16) * 16;
}
} // namespace moonlight::vpn
