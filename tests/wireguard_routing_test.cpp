#include "WireGuardRouting.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using moonlight::vpn::UrlEndpoint;
using moonlight::vpn::isGameStreamTcpPort;
using moonlight::vpn::parseServiceUrl;
using moonlight::vpn::planHttpRoute;
using moonlight::vpn::rewriteRtspForTunnel;
using moonlight::vpn::tunnelPacketSize;

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void testServiceUrlParsing() {
    UrlEndpoint endpoint;
    check(parseServiceUrl("https://192.0.2.10:47989/serverinfo?uniqueid=abc", endpoint),
          "HTTPS service URL should parse");
    check(endpoint.host == "192.0.2.10" && endpoint.port == 47989,
          "Service URL host and port should be extracted");
    check(endpoint.authorityStart == std::string("https://").size(),
          "Authority start should identify the URL host");
    check(endpoint.authorityEnd == std::string("https://192.0.2.10:47989").size(),
          "Authority end should stop before the path");

    const char* invalidUrls[] = {
        "ftp://192.0.2.10:47989/path",
        "https://user@192.0.2.10:47989/path",
        "https://[2001:db8::1]:47989/path",
        "https://192.0.2.10/path",
        "https://192.0.2.10:0/path",
        "https://192.0.2.10:65536/path",
        "https://192.0.2.10:abc/path",
        "not-a-url"
    };
    for (const char* url : invalidUrls) {
        check(!parseServiceUrl(url, endpoint), "Unsafe or malformed service URL should be rejected");
    }
}

void testRtspRewrite() {
    const char* urls[] = {
        "rtsp://192.0.2.10:48010/session?token=abc",
        "rtspenc://192.0.2.10:48010/session",
        "rtspru://192.0.2.10:48010/"
    };
    for (const char* url : urls) {
        std::string rewritten;
        check(rewriteRtspForTunnel(url, rewritten), "Supported RTSP URL should rewrite");
        check(rewritten.find("127.0.0.1:48010") != std::string::npos,
              "RTSP host should route through the local relay");
        check(rewritten.find("192.0.2.10:48010") == std::string::npos,
              "Rewritten RTSP URL must not retain the remote authority");
    }

    std::string rewritten = "old value";
    check(rewriteRtspForTunnel("", rewritten) && rewritten.empty(),
          "An empty RTSP URL should retain the library default behavior");
    check(!rewriteRtspForTunnel("https://192.0.2.10:48010/path", rewritten),
          "Non-RTSP schemes should not be accepted by the RTSP rewriter");
    check(!rewriteRtspForTunnel("rtsp://192.0.2.10:47989/path", rewritten),
          "A nonstandard RTSP port should be rejected");
    check(!rewriteRtspForTunnel("rtsp://user@192.0.2.10:48010/path", rewritten),
          "RTSP user information should be rejected");
}

void testGameStreamPortsAndPacketSizes() {
    const std::uint16_t ports[] = {47989, 47984, 48010, 47995, 47999};
    for (std::uint16_t port : ports) {
        check(isGameStreamTcpPort(port), "Every configured GameStream TCP port should be allowed");
    }
    check(!isGameStreamTcpPort(47990), "An unrelated TCP port should not be allowed");
    check(!isGameStreamTcpPort(48000), "A UDP-only port should not be allowed as TCP");

    check(tunnelPacketSize(576) == 480, "Minimum supported MTU should retain a safe packet size");
    check(tunnelPacketSize(1280) == 1024, "Normal MTU should use the standard packet ceiling");
    check(tunnelPacketSize(1420) == 1024, "Larger MTU should remain capped at the standard ceiling");
}

void testHttpRoutePlanning() {
    std::string connectTo = "stale route";
    check(planHttpRoute(false, "", "not a URL", connectTo),
          "Disabled VPN mode should leave HTTP route planning successful");
    check(connectTo.empty(), "Disabled VPN mode should return an empty CONNECT_TO route");

    check(planHttpRoute(true, "192.0.2.10", "http://192.0.2.10:47989/serverinfo", connectTo),
          "Exact configured host and allowed HTTP port should route");
    check(connectTo == "192.0.2.10:47989:127.0.0.1:47989",
          "Allowed HTTP request should map to the local relay on the same port");
    check(planHttpRoute(true, "192.0.2.10", "https://192.0.2.10:47984/pair", connectTo),
          "HTTPS should use the same approved GameStream route mapping");
    check(connectTo == "192.0.2.10:47984:127.0.0.1:47984",
          "HTTPS request should preserve its approved port in CONNECT_TO");

    struct RejectedRoute {
        const char* target;
        const char* url;
    };
    const RejectedRoute rejected[] = {
        {"192.0.2.10", "http://192.0.2.11:47989/serverinfo"},
        {"192.0.2.10", "http://moonlight-pc:47989/serverinfo"},
        {"192.0.2.10", "http://192.0.2.10.attacker.example:47989/serverinfo"},
        {"192.0.2.10", "http://evil.192.0.2.10:47989/serverinfo"},
        {"192.0.2.10", "http://192.0.2.10@attacker.example:47989/serverinfo"},
        {"", "http://192.0.2.10:47989/serverinfo"},
        {"192.0.2.10", "http://[2001:db8::1]:47989/serverinfo"},
        {"192.0.2.10", "ftp://192.0.2.10:47989/serverinfo"},
        {"192.0.2.10", "rtsp://192.0.2.10:48010/session"},
        {"192.0.2.10", "http://192.0.2.10:12345/custom"}
    };
    for (const RejectedRoute& candidate : rejected) {
        connectTo = "stale route";
        check(!planHttpRoute(true, candidate.target, candidate.url, connectTo),
              "Unsupported or mismatched enabled HTTP route should be rejected");
        check(connectTo.empty(), "Rejected HTTP route must clear CONNECT_TO");
    }
}

} // namespace

int main() {
    try {
        testServiceUrlParsing();
        testRtspRewrite();
        testGameStreamPortsAndPacketSizes();
        testHttpRoutePlanning();
        std::cout << "WireGuard routing tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "WireGuard routing test failed: " << error.what() << '\n';
        return 1;
    }
}
