#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace moonlight::vpn {

struct Cidr {
    std::array<std::uint8_t, 4> address{};
    std::uint8_t prefix = 32;
};

struct Config {
    std::array<std::uint8_t, 32> privateKey{};
    // PublicKey from the single [Peer] section.
    std::array<std::uint8_t, 32> publicKey{};
    std::array<std::uint8_t, 32> presharedKey{};
    bool hasPresharedKey = false;

    // The [Interface] address without its optional CIDR suffix.
    std::string address;
    std::string endpointHost;
    std::uint16_t endpointPort = 0;
    std::uint16_t keepalive = 25;
    std::uint16_t mtu = 1280;
    std::vector<Cidr> allowedIps;

    Config() = default;
    Config(const Config&) = default;
    Config(Config&& other) noexcept;
    Config& operator=(const Config& other);
    Config& operator=(Config&& other) noexcept;
    ~Config();

    // Clears all key material. The destructor calls this automatically.
    void wipeKeys() noexcept;
};

struct ParseResult {
    Config config;
    std::string error;
    std::vector<std::string> warnings;

    explicit operator bool() const noexcept { return error.empty(); }
};

// Parses one Interface and one Peer from a WireGuard-style IPv4 configuration.
// Errors contain a safe diagnostic and line number, never a config value.
ParseResult parseConfig(std::string_view text);

bool isIpv4Address(std::string_view text) noexcept;

// target is a dotted-decimal IPv4 address. Invalid addresses never match.
bool matchesAllowedIp(const Config& config, std::string_view target) noexcept;
bool matchesAllowedIp(const Config& config,
                      const std::array<std::uint8_t, 4>& target) noexcept;

} // namespace moonlight::vpn
