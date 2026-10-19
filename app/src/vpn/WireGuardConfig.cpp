#include "WireGuardConfig.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <utility>

namespace moonlight::vpn {
namespace {

constexpr std::size_t kMaximumConfigBytes = 64 * 1024;

void secureZero(std::uint8_t* data, std::size_t size) noexcept {
    volatile std::uint8_t* bytes = data;
    while (size-- != 0) {
        *bytes++ = 0;
    }
}

std::string_view trim(std::string_view value) noexcept {
    const auto isSpace = [](char ch) { return ch == ' ' || ch == '\t'; };
    while (!value.empty() && isSpace(value.front())) {
        value.remove_prefix(1);
    }
    while (!value.empty() && isSpace(value.back())) {
        value.remove_suffix(1);
    }
    return value;
}

int base64Value(char ch) noexcept {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

bool decodeKey(std::string_view encoded, std::array<std::uint8_t, 32>& output) noexcept {
    std::array<std::uint8_t, 32> decoded{};
    if (encoded.size() != 44 || encoded.back() != '=') {
        return false;
    }

    std::uint32_t accumulator = 0;
    unsigned bitCount = 0;
    std::size_t outputIndex = 0;
    for (std::size_t i = 0; i < encoded.size() - 1; ++i) {
        const int value = base64Value(encoded[i]);
        if (value < 0) {
            secureZero(decoded.data(), decoded.size());
            return false;
        }

        accumulator = (accumulator << 6) | static_cast<std::uint32_t>(value);
        bitCount += 6;
        if (bitCount >= 8) {
            bitCount -= 8;
            if (outputIndex >= decoded.size()) {
                secureZero(decoded.data(), decoded.size());
                return false;
            }
            decoded[outputIndex++] = static_cast<std::uint8_t>((accumulator >> bitCount) & 0xffU);
            accumulator &= bitCount == 0 ? 0U : ((1U << bitCount) - 1U);
        }
    }

    // Thirty-two bytes encode to 43 data characters and leave two zero pad bits.
    const bool canonical = outputIndex == decoded.size() && bitCount == 2 && accumulator == 0;
    const bool nonzero = std::any_of(decoded.begin(), decoded.end(), [](std::uint8_t byte) {
        return byte != 0;
    });
    if (!canonical || !nonzero) {
        secureZero(decoded.data(), decoded.size());
        return false;
    }

    output = decoded;
    secureZero(decoded.data(), decoded.size());
    return true;
}

bool parseIpv4(std::string_view text, std::array<std::uint8_t, 4>& output) noexcept {
    if (text.empty()) return false;

    std::array<std::uint8_t, 4> parsed{};
    std::size_t octetIndex = 0;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t dot = text.find('.', start);
        const std::size_t end = dot == std::string_view::npos ? text.size() : dot;
        const std::string_view octetText = text.substr(start, end - start);
        if (octetText.empty() || octetText.size() > 3 || octetIndex >= parsed.size()) {
            return false;
        }
        if (octetText.size() > 1 && octetText.front() == '0') {
            return false;
        }

        unsigned octet = 0;
        const auto conversion = std::from_chars(octetText.data(), octetText.data() + octetText.size(), octet);
        if (conversion.ec != std::errc{} || conversion.ptr != octetText.data() + octetText.size() || octet > 255) {
            return false;
        }
        parsed[octetIndex++] = static_cast<std::uint8_t>(octet);

        if (dot == std::string_view::npos) break;
        start = dot + 1;
    }

    if (octetIndex != parsed.size()) return false;
    output = parsed;
    return true;
}

std::string formatIpv4(const std::array<std::uint8_t, 4>& address) {
    return std::to_string(address[0]) + "." + std::to_string(address[1]) + "." +
           std::to_string(address[2]) + "." + std::to_string(address[3]);
}

template <typename Number>
bool parseUnsigned(std::string_view text, Number& output) noexcept {
    static_assert(std::numeric_limits<Number>::is_integer && !std::numeric_limits<Number>::is_signed,
                  "parseUnsigned requires an unsigned integer type");
    if (text.empty()) return false;
    unsigned long long value = 0;
    const auto conversion = std::from_chars(text.data(), text.data() + text.size(), value);
    if (conversion.ec != std::errc{} || conversion.ptr != text.data() + text.size() ||
        value > std::numeric_limits<Number>::max()) {
        return false;
    }
    output = static_cast<Number>(value);
    return true;
}

bool validDnsName(std::string_view name) noexcept {
    if (name.empty() || name.size() > 253) return false;
    if (name.back() == '.') {
        name.remove_suffix(1);
        if (name.empty()) return false;
    }

    bool onlyDigitsAndDots = true;
    std::size_t start = 0;
    while (start <= name.size()) {
        const std::size_t dot = name.find('.', start);
        const std::size_t end = dot == std::string_view::npos ? name.size() : dot;
        const std::string_view label = name.substr(start, end - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') {
            return false;
        }
        for (char ch : label) {
            const bool alpha = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
            const bool digit = ch >= '0' && ch <= '9';
            if (!alpha && !digit && ch != '-') return false;
            if (!digit) onlyDigitsAndDots = false;
        }
        if (dot == std::string_view::npos) break;
        start = dot + 1;
    }

    if (onlyDigitsAndDots) {
        std::array<std::uint8_t, 4> address{};
        return parseIpv4(name, address);
    }
    return true;
}

bool parseAddress(std::string_view value, std::string& address, std::string& error) {
    if (value.find(':') != std::string_view::npos) {
        error = "IPv6 interface addresses are not supported.";
        return false;
    }
    if (value.find(',') != std::string_view::npos) {
        error = "Only one IPv4 interface address is supported.";
        return false;
    }

    const std::size_t slash = value.find('/');
    const std::string_view addressText = value.substr(0, slash);
    std::array<std::uint8_t, 4> parsed{};
    if (!parseIpv4(addressText, parsed)) {
        error = "The interface address must be a valid IPv4 address.";
        return false;
    }

    if (slash != std::string_view::npos) {
        if (value.find('/', slash + 1) != std::string_view::npos) {
            error = "The interface address prefix is invalid.";
            return false;
        }
        unsigned prefix = 0;
        if (!parseUnsigned(value.substr(slash + 1), prefix) || prefix > 32) {
            error = "The interface address prefix must be between 0 and 32.";
            return false;
        }
    }

    address = formatIpv4(parsed);
    return true;
}

bool parseCidr(std::string_view value, Cidr& result, std::string& error) {
    if (value.find(':') != std::string_view::npos) {
        error = "IPv6 routes are not supported.";
        return false;
    }

    const std::size_t slash = value.find('/');
    const std::string_view addressText = value.substr(0, slash);
    if (!parseIpv4(addressText, result.address)) {
        error = "AllowedIPs must contain valid IPv4 routes.";
        return false;
    }

    result.prefix = 32;
    if (slash != std::string_view::npos) {
        if (value.find('/', slash + 1) != std::string_view::npos) {
            error = "An AllowedIPs prefix is invalid.";
            return false;
        }
        unsigned prefix = 0;
        if (!parseUnsigned(value.substr(slash + 1), prefix) || prefix > 32) {
            error = "AllowedIPs prefixes must be between 0 and 32.";
            return false;
        }
        result.prefix = static_cast<std::uint8_t>(prefix);
    }
    return true;
}

bool parseEndpoint(std::string_view value, std::string& host, std::uint16_t& port,
                   std::string& error) {
    if (value.empty() || value.front() == '[') {
        error = "IPv6 endpoints are not supported; use an IPv4 address or DNS name.";
        return false;
    }
    const std::size_t colon = value.find(':');
    if (colon == std::string_view::npos || value.find(':', colon + 1) != std::string_view::npos) {
        error = value.find(':') == std::string_view::npos
                    ? "Endpoint must include a host and port."
                    : "IPv6 endpoints are not supported; use an IPv4 address or DNS name.";
        return false;
    }

    const std::string_view hostText = value.substr(0, colon);
    std::array<std::uint8_t, 4> address{};
    if (!parseIpv4(hostText, address) && !validDnsName(hostText)) {
        error = "Endpoint host must be a valid IPv4 address or DNS name.";
        return false;
    }

    unsigned parsedPort = 0;
    if (!parseUnsigned(value.substr(colon + 1), parsedPort) || parsedPort == 0 || parsedPort > 65535) {
        error = "Endpoint port must be between 1 and 65535.";
        return false;
    }
    host.assign(hostText);
    port = static_cast<std::uint16_t>(parsedPort);
    return true;
}

bool validateDnsList(std::string_view value, std::string& error) {
    std::size_t start = 0;
    while (start <= value.size()) {
        const std::size_t comma = value.find(',', start);
        const std::size_t end = comma == std::string_view::npos ? value.size() : comma;
        const std::string_view server = trim(value.substr(start, end - start));
        if (server.find(':') != std::string_view::npos) {
            error = "IPv6 DNS servers are not supported.";
            return false;
        }
        std::array<std::uint8_t, 4> address{};
        if (server.empty() || (!parseIpv4(server, address) && !validDnsName(server))) {
            error = "DNS entries must be valid IPv4 addresses or DNS names.";
            return false;
        }
        if (comma == std::string_view::npos) break;
        start = comma + 1;
    }
    return true;
}

} // namespace

Config::Config(Config&& other) noexcept
    : privateKey(other.privateKey),
      publicKey(other.publicKey),
      presharedKey(other.presharedKey),
      hasPresharedKey(other.hasPresharedKey),
      address(std::move(other.address)),
      endpointHost(std::move(other.endpointHost)),
      endpointPort(other.endpointPort),
      keepalive(other.keepalive),
      mtu(other.mtu),
      allowedIps(std::move(other.allowedIps)) {
    other.wipeKeys();
}

Config& Config::operator=(const Config& other) {
    if (this == &other) return *this;
    wipeKeys();
    privateKey = other.privateKey;
    publicKey = other.publicKey;
    presharedKey = other.presharedKey;
    hasPresharedKey = other.hasPresharedKey;
    address = other.address;
    endpointHost = other.endpointHost;
    endpointPort = other.endpointPort;
    keepalive = other.keepalive;
    mtu = other.mtu;
    allowedIps = other.allowedIps;
    return *this;
}

Config& Config::operator=(Config&& other) noexcept {
    if (this == &other) return *this;
    wipeKeys();
    privateKey = other.privateKey;
    publicKey = other.publicKey;
    presharedKey = other.presharedKey;
    hasPresharedKey = other.hasPresharedKey;
    address = std::move(other.address);
    endpointHost = std::move(other.endpointHost);
    endpointPort = other.endpointPort;
    keepalive = other.keepalive;
    mtu = other.mtu;
    allowedIps = std::move(other.allowedIps);
    other.wipeKeys();
    return *this;
}

Config::~Config() {
    wipeKeys();
}

void Config::wipeKeys() noexcept {
    secureZero(privateKey.data(), privateKey.size());
    secureZero(publicKey.data(), publicKey.size());
    secureZero(presharedKey.data(), presharedKey.size());
    hasPresharedKey = false;
}

ParseResult parseConfig(std::string_view text) {
    ParseResult result;
    if (text.size() > kMaximumConfigBytes) {
        result.error = "Configuration exceeds the 64 KiB size limit.";
        return result;
    }

    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xef &&
        static_cast<unsigned char>(text[1]) == 0xbb && static_cast<unsigned char>(text[2]) == 0xbf) {
        text.remove_prefix(3);
    }

    enum class Section { None, Interface, Peer };
    Section section = Section::None;
    bool sawInterface = false;
    bool sawPeer = false;
    bool havePrivateKey = false;
    bool haveAddress = false;
    bool haveDns = false;
    bool haveMtu = false;
    bool haveListenPort = false;
    bool havePublicKey = false;
    bool havePresharedKey = false;
    bool haveEndpoint = false;
    bool haveAllowedIps = false;
    bool haveKeepalive = false;
    Config config;

    const auto fail = [](std::size_t lineNumber, std::string_view message) {
        ParseResult failure;
        failure.error = "Line " + std::to_string(lineNumber) + ": " + std::string(message);
        return failure;
    };

    std::size_t lineNumber = 0;
    std::size_t lineStart = 0;
    while (lineStart <= text.size()) {
        ++lineNumber;
        const std::size_t newline = text.find('\n', lineStart);
        const std::size_t lineEnd = newline == std::string_view::npos ? text.size() : newline;
        std::string_view line = text.substr(lineStart, lineEnd - lineStart);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.find('\r') != std::string_view::npos || line.find('\0') != std::string_view::npos) {
            return fail(lineNumber, "Line contains an unsupported control character.");
        }
        const std::size_t comment = line.find('#');
        if (comment != std::string_view::npos) line = line.substr(0, comment);
        line = trim(line);

        if (!line.empty()) {
            if (line.front() == '[' && line.back() == ']') {
                if (line == "[Interface]") {
                    if (sawInterface) return fail(lineNumber, "Only one Interface section is supported.");
                    if (sawPeer) return fail(lineNumber, "Interface must appear before Peer.");
                    sawInterface = true;
                    section = Section::Interface;
                } else if (line == "[Peer]") {
                    if (!sawInterface) return fail(lineNumber, "Interface must appear before Peer.");
                    if (sawPeer) return fail(lineNumber, "Only one Peer section is supported.");
                    sawPeer = true;
                    section = Section::Peer;
                } else {
                    return fail(lineNumber, "Only Interface and Peer sections are supported.");
                }
            } else {
                if (section == Section::None) return fail(lineNumber, "A setting appears outside a section.");
                const std::size_t equals = line.find('=');
                if (equals == std::string_view::npos) return fail(lineNumber, "A setting must use key = value syntax.");
                const std::string_view key = trim(line.substr(0, equals));
                const std::string_view value = trim(line.substr(equals + 1));
                if (key.empty() || value.empty()) return fail(lineNumber, "A setting has an empty name or value.");

                std::string parseError;
                if (section == Section::Interface) {
                    if (key == "PrivateKey") {
                        if (havePrivateKey) return fail(lineNumber, "PrivateKey is specified more than once.");
                        havePrivateKey = true;
                        if (!decodeKey(value, config.privateKey)) {
                            return fail(lineNumber, "PrivateKey must be canonical base64 for a nonzero 32-byte key.");
                        }
                    } else if (key == "Address") {
                        if (haveAddress) return fail(lineNumber, "Address is specified more than once.");
                        haveAddress = true;
                        if (!parseAddress(value, config.address, parseError)) return fail(lineNumber, parseError);
                    } else if (key == "DNS") {
                        if (haveDns) return fail(lineNumber, "DNS is specified more than once.");
                        haveDns = true;
                        if (!validateDnsList(value, parseError)) return fail(lineNumber, parseError);
                        result.warnings.emplace_back("DNS entries are accepted but are not applied by this client.");
                    } else if (key == "MTU") {
                        if (haveMtu) return fail(lineNumber, "MTU is specified more than once.");
                        haveMtu = true;
                        unsigned mtu = 0;
                        if (!parseUnsigned(value, mtu) || mtu < 576 || mtu > 1420) {
                            return fail(lineNumber, "MTU must be between 576 and 1420.");
                        }
                        config.mtu = static_cast<std::uint16_t>(mtu);
                    } else if (key == "ListenPort") {
                        if (haveListenPort) return fail(lineNumber, "ListenPort is specified more than once.");
                        haveListenPort = true;
                        unsigned listenPort = 0;
                        if (!parseUnsigned(value, listenPort) || listenPort > 65535) {
                            return fail(lineNumber, "ListenPort must be between 0 and 65535.");
                        }
                        if (listenPort != 0) return fail(lineNumber, "A nonzero ListenPort is not supported.");
                    } else {
                        return fail(lineNumber, "This Interface setting is not supported.");
                    }
                } else {
                    if (key == "PublicKey") {
                        if (havePublicKey) return fail(lineNumber, "PublicKey is specified more than once.");
                        havePublicKey = true;
                        if (!decodeKey(value, config.publicKey)) {
                            return fail(lineNumber, "PublicKey must be canonical base64 for a nonzero 32-byte key.");
                        }
                    } else if (key == "PresharedKey") {
                        if (havePresharedKey) return fail(lineNumber, "PresharedKey is specified more than once.");
                        havePresharedKey = true;
                        if (!decodeKey(value, config.presharedKey)) {
                            return fail(lineNumber, "PresharedKey must be canonical base64 for a nonzero 32-byte key.");
                        }
                        config.hasPresharedKey = true;
                    } else if (key == "Endpoint") {
                        if (haveEndpoint) return fail(lineNumber, "Endpoint is specified more than once.");
                        haveEndpoint = true;
                        if (!parseEndpoint(value, config.endpointHost, config.endpointPort, parseError)) {
                            return fail(lineNumber, parseError);
                        }
                    } else if (key == "AllowedIPs") {
                        if (haveAllowedIps) return fail(lineNumber, "AllowedIPs is specified more than once.");
                        haveAllowedIps = true;
                        std::size_t itemStart = 0;
                        while (itemStart <= value.size()) {
                            const std::size_t comma = value.find(',', itemStart);
                            const std::size_t itemEnd = comma == std::string_view::npos ? value.size() : comma;
                            const std::string_view item = trim(value.substr(itemStart, itemEnd - itemStart));
                            if (item.empty()) return fail(lineNumber, "AllowedIPs contains an empty route.");
                            Cidr route;
                            if (!parseCidr(item, route, parseError)) return fail(lineNumber, parseError);
                            config.allowedIps.push_back(route);
                            if (comma == std::string_view::npos) break;
                            itemStart = comma + 1;
                        }
                    } else if (key == "PersistentKeepalive") {
                        if (haveKeepalive) return fail(lineNumber, "PersistentKeepalive is specified more than once.");
                        haveKeepalive = true;
                        unsigned keepalive = 0;
                        if (!parseUnsigned(value, keepalive) || keepalive > 65535) {
                            return fail(lineNumber, "PersistentKeepalive must be between 0 and 65535.");
                        }
                        config.keepalive = static_cast<std::uint16_t>(keepalive);
                    } else {
                        return fail(lineNumber, "This Peer setting is not supported.");
                    }
                }
            }
        }

        if (newline == std::string_view::npos) break;
        lineStart = newline + 1;
    }

    if (!sawInterface || !sawPeer) return fail(lineNumber, "Configuration must contain one Interface and one Peer section.");
    if (!havePrivateKey) return fail(lineNumber, "Interface PrivateKey is required.");
    if (!haveAddress) return fail(lineNumber, "Interface Address is required.");
    if (!havePublicKey) return fail(lineNumber, "Peer PublicKey is required.");
    if (!haveEndpoint) return fail(lineNumber, "Peer Endpoint is required.");
    if (!haveAllowedIps || config.allowedIps.empty()) return fail(lineNumber, "Peer AllowedIPs is required.");

    result.config = std::move(config);
    return result;
}

bool isIpv4Address(std::string_view text) noexcept {
    std::array<std::uint8_t, 4> parsed{};
    return parseIpv4(text, parsed);
}

bool matchesAllowedIp(const Config& config,
                      const std::array<std::uint8_t, 4>& target) noexcept {
    for (const Cidr& route : config.allowedIps) {
        const unsigned fullBytes = route.prefix / 8;
        const unsigned remainingBits = route.prefix % 8;
        bool matches = true;
        for (unsigned i = 0; i < fullBytes; ++i) {
            if (route.address[i] != target[i]) {
                matches = false;
                break;
            }
        }
        if (!matches) continue;
        if (remainingBits != 0) {
            const std::uint8_t mask = static_cast<std::uint8_t>(0xffU << (8 - remainingBits));
            matches = (route.address[fullBytes] & mask) == (target[fullBytes] & mask);
        }
        if (matches) return true;
    }
    return false;
}

bool matchesAllowedIp(const Config& config, std::string_view target) noexcept {
    std::array<std::uint8_t, 4> parsed{};
    return parseIpv4(target, parsed) && matchesAllowedIp(config, parsed);
}

} // namespace moonlight::vpn
