#include "WireGuardConfig.hpp"

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using moonlight::vpn::Config;
using moonlight::vpn::ParseResult;
using moonlight::vpn::isIpv4Address;
using moonlight::vpn::matchesAllowedIp;
using moonlight::vpn::parseConfig;

const std::string kPrivateKey = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const std::string kPublicKey = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const std::string kPresharedKey = "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

std::string validConfig() {
    return "[Interface]\n"
           "PrivateKey = " + kPrivateKey + "\n"
           "Address = 10.8.0.2/32\n"
           "DNS = 192.168.1.1, router.lan\n"
           "MTU = 1280\n"
           "[Peer]\n"
           "PublicKey = " + kPublicKey + "\n"
           "Endpoint = vpn.example.com:51820\n"
           "AllowedIPs = 10.0.0.0/8, 192.168.5.10/32\n"
           "PersistentKeepalive = 25\n";
}

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

ParseResult mustFail(const std::string& text) {
    ParseResult result = parseConfig(text);
    check(!result, "Expected invalid configuration to fail");
    check(!result.error.empty(), "Failure must have a diagnostic");
    return result;
}

void testValidConfigAndDefaults() {
    ParseResult parsed = parseConfig(validConfig());
    check(static_cast<bool>(parsed), "Valid configuration should parse");
    check(parsed.config.address == "10.8.0.2", "Address should be stored without its prefix");
    check(parsed.config.endpointHost == "vpn.example.com", "DNS endpoint host should be retained");
    check(parsed.config.endpointPort == 51820, "Endpoint port should parse");
    check(parsed.config.mtu == 1280, "MTU should parse");
    check(parsed.config.keepalive == 25, "Keepalive should parse");
    check(parsed.config.allowedIps.size() == 2, "Comma-separated AllowedIPs should parse");
    check(parsed.warnings.size() == 1, "DNS should produce an unused-setting warning");
    check(parsed.config.privateKey[0] == 1 && parsed.config.publicKey[0] == 2,
          "Base64 keys should decode into 32-byte values");

    std::string defaults = "[Interface]\nPrivateKey = " + kPrivateKey +
                           "\nAddress = 10.8.0.2\n[Peer]\nPublicKey = " + kPublicKey +
                           "\nEndpoint = 203.0.113.9:1\nAllowedIPs = 0.0.0.0/0\n";
    ParseResult withDefaults = parseConfig(defaults);
    check(static_cast<bool>(withDefaults), "Minimal configuration should parse");
    check(withDefaults.config.mtu == 1280 && withDefaults.config.keepalive == 25,
          "Defaults should be applied when optional fields are absent");
    check(withDefaults.warnings.empty(), "No DNS means no warning");
}

void testBomCrLfAndComments() {
    std::string text = "\xef\xbb\xbf" + validConfig();
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n') text.insert(i++, 1, '\r');
    }
    text += "# trailing comment\r\n";
    check(static_cast<bool>(parseConfig(text)), "BOM, CRLF, and comments should parse");
}

void testOptionalPresharedKeyAndNumericRanges() {
    std::string text = validConfig();
    const std::size_t endpoint = text.find("Endpoint =");
    text.insert(endpoint, "PresharedKey = " + kPresharedKey + "\n");
    const std::size_t keepalive = text.find("PersistentKeepalive = 25");
    text.replace(keepalive, std::string("PersistentKeepalive = 25").size(), "PersistentKeepalive = 65535");
    const std::size_t mtu = text.find("MTU = 1280");
    text.replace(mtu, std::string("MTU = 1280").size(), "MTU = 1420");

    ParseResult parsed = parseConfig(text);
    check(static_cast<bool>(parsed), "Boundary numeric values should parse");
    check(parsed.config.hasPresharedKey && parsed.config.presharedKey[0] == 3,
          "Optional preshared key should decode");
    check(parsed.config.keepalive == 65535 && parsed.config.mtu == 1420,
          "Upper supported numeric bounds should parse");

    text.replace(text.find("PersistentKeepalive = 65535"),
                 std::string("PersistentKeepalive = 65535").size(), "PersistentKeepalive = 65536");
    mustFail(text);
}

void testKeysAreValidatedAndErrorsDoNotEchoInput() {
    std::string text = validConfig();
    const std::size_t privateKey = text.find(kPrivateKey);
    text.replace(privateKey, kPrivateKey.size(), "SECRET_RAW_KEY_CONTENT");
    ParseResult failure = mustFail(text);
    check(failure.error.find("SECRET_RAW_KEY_CONTENT") == std::string::npos,
          "Error must not echo raw configuration contents");
    check(failure.error.find(kPrivateKey) == std::string::npos,
          "Error must not echo a valid key from the input");

    text = validConfig();
    text.replace(text.find(kPrivateKey), kPrivateKey.size(),
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    mustFail(text);

    text = validConfig();
    std::string nonCanonicalKey = kPrivateKey;
    nonCanonicalKey[42] = 'B';
    text.replace(text.find(kPrivateKey), kPrivateKey.size(), nonCanonicalKey);
    mustFail(text);
}

void testSectionsFieldsAndUnsupportedOptions() {
    std::string text = validConfig();
    text += "[Peer]\nPublicKey = " + kPublicKey + "\n";
    mustFail(text);

    text = validConfig();
    text.insert(text.find("Address ="), "PrivateKey = " + kPrivateKey + "\n");
    mustFail(text);

    text = validConfig();
    text.insert(text.find("[Peer]"), "PreUp = echo unsafe\n");
    mustFail(text);

    text = validConfig();
    text.insert(text.find("[Peer]"), "ListenPort = 1234\n");
    mustFail(text);

    text = validConfig();
    text.insert(text.find("[Peer]"), "ListenPort = 0\n");
    check(static_cast<bool>(parseConfig(text)), "ListenPort zero should be accepted");
}

void testIpv6AndInvalidAddressesAreRejected() {
    std::string text = validConfig();
    text.replace(text.find("10.8.0.2/32"), std::string("10.8.0.2/32").size(), "fd00::2/128");
    mustFail(text);

    text = validConfig();
    text.replace(text.find("10.0.0.0/8"), std::string("10.0.0.0/8").size(), "2001:db8::/32");
    mustFail(text);

    text = validConfig();
    text.replace(text.find("vpn.example.com:51820"), std::string("vpn.example.com:51820").size(), "[2001:db8::1]:51820");
    mustFail(text);

    check(!isIpv4Address("256.1.2.3"), "Out-of-range IPv4 octet must fail");
    check(!isIpv4Address("01.2.3.4"), "Noncanonical IPv4 octet must fail");
    check(!isIpv4Address("1.2.3"), "IPv4 must have four octets");
    check(isIpv4Address("0.0.0.0"), "IPv4 zero address should be valid");
}

void testEndpointRoutesAndBoundaries() {
    const char* badEndpoints[] = {
        "host:0", "host:65536", "host:abc", "host", "bad_host:51820", "999.1.1.1:51820"
    };
    for (const char* endpoint : badEndpoints) {
        std::string text = validConfig();
        const std::string original = "vpn.example.com:51820";
        text.replace(text.find(original), original.size(), endpoint);
        mustFail(text);
    }

    const char* badRoutes[] = {
        "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/24/1", "10.0.0.0/24,"
    };
    for (const char* routes : badRoutes) {
        std::string text = validConfig();
        const std::string original = "10.0.0.0/8, 192.168.5.10/32";
        text.replace(text.find(original), original.size(), routes);
        mustFail(text);
    }
}

void testAllowedIpMatching() {
    Config config;
    config.allowedIps.push_back({{{10, 0, 0, 0}}, 8});
    config.allowedIps.push_back({{{192, 168, 5, 10}}, 32});
    config.allowedIps.push_back({{{172, 16, 16, 0}}, 20});

    check(matchesAllowedIp(config, "10.255.255.255"), "/8 upper boundary should match");
    check(matchesAllowedIp(config, "192.168.5.10"), "/32 should match exact address");
    check(!matchesAllowedIp(config, "192.168.5.11"), "/32 should reject adjacent address");
    check(matchesAllowedIp(config, "172.16.31.255"), "/20 upper boundary should match");
    check(!matchesAllowedIp(config, "2001:db8::1"), "IPv6 target must never match IPv4 routes");
    check(!matchesAllowedIp(config, "300.1.1.1"), "Invalid IPv4 target must never match");
    const std::array<std::uint8_t, 4> target{{10, 1, 2, 3}};
    check(matchesAllowedIp(config, target), "Byte-array IPv4 overload should match");

    Config defaultRoute;
    defaultRoute.allowedIps.push_back({{{0, 0, 0, 0}}, 0});
    check(matchesAllowedIp(defaultRoute, "203.0.113.1"), "/0 should match every IPv4 address");
}

} // namespace

int main() {
    try {
        testValidConfigAndDefaults();
        testBomCrLfAndComments();
        testOptionalPresharedKeyAndNumericRanges();
        testKeysAreValidatedAndErrorsDoNotEchoInput();
        testSectionsFieldsAndUnsupportedOptions();
        testIpv6AndInvalidAddressesAreRejected();
        testEndpointRoutesAndBoundaries();
        testAllowedIpMatching();
        std::cout << "WireGuard config parser tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "WireGuard config parser test failed: " << error.what() << '\n';
        return 1;
    }
}
