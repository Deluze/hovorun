#pragma once

#include <cstdint>

namespace hovorun::proudnet
{

// First byte of every ProudNet payload. Numbering is specific to the old ProudNet build in Client5.exe
// (client dispatcher 0x608390, jump table 0x608840). See docs/protocol/proudnet_core.md §1.
enum class message_type : uint8_t
{
    none = 0,
    rmi = 1,
    user_message = 2,
    connect_server_timedout = 3,
    notify_server_connection_hint = 4,
    notify_cs_public_key = 5,
    notify_cs_encrypted_session_key = 6,
    notify_server_connection_request_data = 7,
    notify_protocol_version_mismatch = 8,
    notify_server_denied_connection = 9,
    notify_server_connect_success = 10,
    request_start_server_holepunch = 11,
    server_holepunch = 12,
    server_holepunch_ack = 13,
    notify_holepunch_success = 14,
    notify_client_server_udp_matched = 15,
    peer_udp_server_holepunch = 16,
    peer_udp_server_holepunch_ack = 17,
    peer_udp_notify_holepunch_success = 18,
    reliable_udp_frame = 19,
    reliable_relay1 = 20,
    unreliable_relay1 = 21,
    reliable_udp_frame_relay1 = 22,
    reliable_relay2 = 23,
    unreliable_relay2 = 24,
    reliable_udp_frame_relay2 = 25,
    request_server_time_and_keep_alive = 26,
    speed_hack_detector_ping = 27,
    reply_server_time_and_keep_alive = 28,
    ignored_29 = 29,
    peer_udp_peer_holepunch = 30,
    peer_udp_peer_holepunch_ack = 31,
    p2p_indirect_server_time_and_ping = 32,
    p2p_indirect_server_time_and_pong = 33,
    s2c_routed_multicast1 = 34,
    s2c_routed_multicast2 = 35,
    encrypted_reliable = 36,
    encrypted_unreliable = 37,
    compressed = 38,
    request_receive_speed_at_receiver_side = 39,
    reply_receive_speed_at_receiver_side = 40,
};

// Well-known HostIDs. The client only accepts core messages whose sender is none or server.
// Clients get HostIDs from 3 upward (2 is reserved in ProudNet); 50 is skipped (see server.cpp).
enum : uint32_t
{
    host_id_none = 0,
    host_id_server = 1,
    host_id_first_client = 3,
};

// ProudNet's own RMIs, layered on MessageType::rmi.
namespace core_rmi
{
// Client -> server (Proxy@ProudC2S, base 64001). Names are unconfirmed guesses.
constexpr uint16_t c2s_first = 64001;
constexpr uint16_t c2s_last = 64019;
constexpr uint16_t c2s_reliable_ping = 64001;
constexpr uint16_t c2s_shutdown_tcp = 64003;

// Server -> client (Stub@ProudS2C, base 64501).
constexpr uint16_t p2p_group_member_join = 64501;
constexpr uint16_t p2p_group_member_join_unencrypted = 64502;
constexpr uint16_t request_p2p_holepunch = 64504;
constexpr uint16_t p2p_notify_direct_p2p_disconnected2 = 64505;
constexpr uint16_t p2p_group_member_leave = 64506;
constexpr uint16_t notify_direct_p2p_establish = 64507;
constexpr uint16_t reliable_pong = 64508;
constexpr uint16_t enable_log = 64509;
constexpr uint16_t disable_log = 64510;
constexpr uint16_t notify_udp_to_tcp_fallback_by_server = 64511;
constexpr uint16_t notify_speed_hack_detector_enabled = 64512;
constexpr uint16_t shutdown_tcp_ack = 64513;
constexpr uint16_t request_auto_prune = 64514;
constexpr uint16_t renew_p2p_connection_state = 64515;
constexpr uint16_t new_direct_p2p_connection = 64516;
constexpr uint16_t request_measure_send_speed = 64517;
constexpr uint16_t s2c_request_create_udp_socket = 64518; // never sent: keeps the client TCP-only
constexpr uint16_t s2c_create_udp_socket_ack = 64519;     // never sent
} // namespace core_rmi

} // namespace hovorun::proudnet
