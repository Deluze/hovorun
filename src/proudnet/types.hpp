#pragma once

#include <array>
#include <cstdint>
#include <format>
#include <string>

namespace hovorun::proudnet
{

using host_id = uint32_t;

// 16 raw bytes in Windows GUID memory layout (Data1..Data3 little-endian).
using guid = std::array<uint8_t, 16>;

// Builds a GUID from its textual fields, e.g. make_guid(0x683ADDC6, 0x6740, 0x485B, {0xAF,0x8D,...}).
constexpr guid make_guid(uint32_t d1, uint16_t d2, uint16_t d3, std::array<uint8_t, 8> d4)
{
    guid g{};
    for (int i = 0; i < 4; ++i)
        g[i] = static_cast<uint8_t>(d1 >> (8 * i));
    g[4] = static_cast<uint8_t>(d2);
    g[5] = static_cast<uint8_t>(d2 >> 8);
    g[6] = static_cast<uint8_t>(d3);
    g[7] = static_cast<uint8_t>(d3 >> 8);
    for (int i = 0; i < 8; ++i)
        g[8 + i] = d4[i];
    return g;
}

inline std::string to_string(const guid &g)
{
    auto d1 = g[0] | (g[1] << 8) | (g[2] << 16) | (static_cast<uint32_t>(g[3]) << 24);
    return std::format("{{{:08X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}", d1, g[5],
                       g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
}

// The client derives one protocol version per server from this base by adding to Data1
// (0x9e7cfc, getters 0x67b790 / 0x67b8d0 / 0x67b970).
constexpr guid protocol_version_base =
    make_guid(0x683ADDC6, 0x6740, 0x485B, {0xAF, 0x8D, 0x88, 0x18, 0xC1, 0xCC, 0x04, 0x3C});

constexpr guid derive_protocol_version(uint32_t add)
{
    auto g = protocol_version_base;
    uint32_t d1 = (g[0] | (g[1] << 8) | (g[2] << 16) | (static_cast<uint32_t>(g[3]) << 24)) + add;
    for (int i = 0; i < 4; ++i)
        g[i] = static_cast<uint8_t>(d1 >> (8 * i));
    return g;
}

constexpr guid game_protocol_version = derive_protocol_version(1);
constexpr guid messenger_protocol_version = derive_protocol_version(4);
constexpr guid session_protocol_version = derive_protocol_version(5);

// Server-wide settings sent to every client in NotifyServerConnectionHint (reader 0x5f9b70, 0x30 bytes).
struct net_settings
{
    uint8_t fallback_method = 0;
    int32_t message_max_length = 0x100000;
    double default_timeout_sec = 60.0;
    uint8_t direct_p2p_start_condition = 2;
    int32_t over_send_suspecting_threshold = 0;
    uint8_t enable_nagle_algorithm = 0;
    int32_t encrypted_message_key_length = 128; // bits, RC4
    uint8_t allow_server_as_p2p_group_member = 0;
    uint8_t enable_p2p_encrypted_messaging = 0;
    uint8_t upnp_detect_nat_device = 0;
    uint8_t upnp_tcp_add_port_mapping = 0;
    int32_t emergency_log_line_count = 0;
    uint8_t enable_ping_test = 0;
    uint8_t unknown_bool = 0;
};

} // namespace hovorun::proudnet
