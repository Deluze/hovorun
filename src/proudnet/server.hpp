#pragma once

// A minimal ProudNet (old version, as embedded in Client5.exe) server over TCP.
// Implements the handshake (connection hint, RSA-wrapped RC4 session key, connect request/success),
// encrypted message unwrapping, RMI dispatch, keepalive, and P2P groups with server relay.
// Everything runs on one io_context thread, so no locking is needed.

#include "../net/framing.hpp"
#include "../net/message.hpp"
#include "message_type.hpp"
#include "types.hpp"

#include <asio.hpp>

#include <array>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace hovorun::proudnet
{

class server;

// One connected client.
class peer : public std::enable_shared_from_this<peer>
{
public:
    enum class state
    {
        awaiting_public_key,
        awaiting_connection_request,
        connected,
        closed,
    };

    peer(server &owner, asio::ip::tcp::socket socket, host_id id);

    void start();
    void close();

    // Sends an already-built ProudNet payload. With `encrypt`, it is wrapped in Encrypted_Reliable.
    void send(std::span<const uint8_t> payload, bool encrypt = false);
    void send(const net::message_writer &message, bool encrypt = false) { send(message.bytes(), encrypt); }

    [[nodiscard]] host_id id() const { return m_id; }
    [[nodiscard]] state current_state() const { return m_state; }
    [[nodiscard]] const asio::ip::tcp::endpoint &remote() const { return m_remote; }

    // Game-side data attached to this connection (set by the RMI handler).
    std::shared_ptr<void> user_data;

private:
    friend class server;

    void read_loop();
    void write_next();
    void process_payload(std::span<const uint8_t> payload, bool was_encrypted = false);
    void on_public_key(net::message_reader &r);
    void on_connection_request(net::message_reader &r);
    void on_encrypted(net::message_reader &r, bool reliable);
    void on_rmi(net::message_reader &r);
    void send_connection_hint();
    void touch();

    server &m_server;
    asio::ip::tcp::socket m_socket;
    asio::ip::tcp::endpoint m_remote;
    host_id m_id;
    state m_state = state::awaiting_public_key;

    std::array<uint8_t, 8192> m_read_buffer{};
    net::frame_parser m_parser;
    std::vector<std::vector<uint8_t>> m_write_queue;
    bool m_writing = false;

    std::vector<uint8_t> m_session_key;
    uint16_t m_recv_serial = 0;
    uint16_t m_send_serial = 0;
    std::chrono::steady_clock::time_point m_last_receive;
};

// Callbacks from the ProudNet layer into game logic.
class event_sink
{
public:
    virtual ~event_sink() = default;
    virtual void on_client_join(peer &) {}
    virtual void on_client_leave(peer &) {}
    // Return false if the RMI was not handled (it will be logged).
    virtual bool on_rmi(peer &client, uint16_t rmi_id, net::message_reader &params) = 0;
};

struct server_config
{
    std::string name;             // for logs
    uint16_t port = 0;
    guid protocol_version{};      // must match what the client sends in NotifyServerConnectionRequestData
    net_settings settings;
    std::chrono::seconds timeout{90};
};

class server
{
public:
    server(asio::io_context &io, server_config config, event_sink &events);

    void start();
    void stop();

    [[nodiscard]] const server_config &config() const { return m_config; }
    [[nodiscard]] const guid &instance_guid() const { return m_instance_guid; }
    [[nodiscard]] std::mt19937 &rng() { return m_rng; }

    std::shared_ptr<peer> find(host_id id) const;

    void send(host_id to, const net::message_writer &message, bool encrypt = false);
    void send(std::span<const host_id> to, const net::message_writer &message, bool encrypt = false);

    // P2P groups: the client addresses all CLPE traffic to the group HostID it learned from P2PGroup_MemberJoin.
    host_id create_p2p_group(std::span<const host_id> members = {});
    void join_p2p_group(host_id group, host_id member);
    void leave_p2p_group(host_id group, host_id member);
    void destroy_p2p_group(host_id group);
    [[nodiscard]] const std::set<host_id> *p2p_group_members(host_id group) const;

private:
    friend class peer;

    void accept();
    void on_peer_joined(peer &p);
    void on_peer_closed(peer &p);
    void check_timeouts();
    host_id allocate_host_id();
    void release_host_id(host_id id);

    // Core RMIs (ProudC2S / ProudS2C) and relay messages that are part of the ProudNet layer itself.
    bool handle_core_message(peer &from, message_type type, net::message_reader &r);
    void handle_core_rmi(peer &from, uint16_t rmi_id, net::message_reader &r);
    void relay_reliable(peer &from, net::message_reader &r);
    void relay_unreliable(peer &from, net::message_reader &r);
    void relay_reliable_udp_frame(peer &from, net::message_reader &r);
    [[nodiscard]] double server_time_sec() const;
    void notify_group_member_join(host_id group, host_id member_to_notify, host_id joined_member);
    void notify_group_member_leave(host_id group, host_id member_to_notify, host_id left_member);

    asio::io_context &m_io;
    asio::ip::tcp::acceptor m_acceptor;
    asio::steady_timer m_timer;
    server_config m_config;
    event_sink &m_events;
    guid m_instance_guid{};
    std::mt19937 m_rng;

    std::map<host_id, std::shared_ptr<peer>> m_peers;
    std::map<host_id, std::set<host_id>> m_groups;
    std::set<host_id> m_free_ids;
    host_id m_next_id = host_id_first_client;
    std::chrono::steady_clock::time_point m_start_time = std::chrono::steady_clock::now();
    uint32_t m_next_event_id = 1;
};

} // namespace hovorun::proudnet
