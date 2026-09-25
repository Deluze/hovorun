#include "server.hpp"

#include "rmi.hpp"

#include "../crypto/rc4.hpp"
#include "../crypto/rsa.hpp"
#include "../net/framing.hpp"
#include "../util/log.hpp"

#include <algorithm>
#include <ranges>

namespace hovorun::proudnet
{

using net::message_reader;
using net::message_writer;

namespace
{

constexpr size_t rc4_key_bytes = 16; // 128-bit, matches net_settings::encrypted_message_key_length

message_writer begin(message_type type)
{
    message_writer w;
    w.write(type);
    return w;
}

} // namespace

// ---------------------------------------------------------------------------------------------------------------
// peer

peer::peer(server &owner, asio::ip::tcp::socket socket, host_id id)
    : m_server(owner), m_socket(std::move(socket)), m_id(id)
{
    asio::error_code ec;
    m_remote = m_socket.remote_endpoint(ec);
    m_socket.set_option(asio::ip::tcp::no_delay(true), ec);
    touch();
}

void peer::start()
{
    log::info(m_server.m_config.name, "client {} connected from {}:{}", m_id, m_remote.address().to_string(),
              m_remote.port());
    send_connection_hint();
    read_loop();
}

void peer::close()
{
    if (m_state == state::closed)
        return;

    auto was_connected = m_state == state::connected;
    m_state = state::closed;

    asio::error_code ec;
    m_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    m_socket.close(ec);

    log::info(m_server.m_config.name, "client {} disconnected", m_id);
    if (was_connected)
        m_server.m_events.on_client_leave(*this);
    m_server.on_peer_closed(*this);
}

void peer::touch() { m_last_receive = std::chrono::steady_clock::now(); }

void peer::send(std::span<const uint8_t> payload, bool encrypt)
{
    if (m_state == state::closed)
        return;

    if (encrypt && !m_session_key.empty())
    {
        // Encrypted_Reliable: [u8 36][u8 mode][cs length][RC4(u16 serial + inner payload)].
        message_writer plain;
        plain.write_u16(m_send_serial++);
        plain.write_bytes(payload);
        auto cipher = std::move(plain).data();
        crypto::rc4_apply(m_session_key, cipher);

        auto w = begin(message_type::encrypted_reliable);
        w.write_u8(1);
        w.write_scalar(std::ssize(cipher));
        w.write_bytes(cipher);
        m_write_queue.push_back(net::make_frame(w.bytes()));
    }
    else
    {
        m_write_queue.push_back(net::make_frame(payload));
    }

    if (!m_writing)
        write_next();
}

void peer::write_next()
{
    if (m_write_queue.empty() || m_state == state::closed)
    {
        m_writing = false;
        return;
    }

    m_writing = true;
    auto self = shared_from_this();
    auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(m_write_queue.front()));
    m_write_queue.erase(m_write_queue.begin());

    asio::async_write(m_socket, asio::buffer(*buffer), [self, buffer](asio::error_code ec, size_t) {
        if (ec)
        {
            self->close();
            return;
        }
        self->write_next();
    });
}

void peer::read_loop()
{
    auto self = shared_from_this();
    m_socket.async_read_some(asio::buffer(m_read_buffer), [self](asio::error_code ec, size_t bytes) {
        if (ec)
        {
            self->close();
            return;
        }

        self->touch();
        self->m_parser.feed(std::span(self->m_read_buffer).first(bytes));

        // Drain complete frames; the parser keeps any partial frame for the next read.
        while (true)
        {
            auto frame = self->m_parser.next();
            if (!frame)
            {
                if (frame.error() != net::frame_error::incomplete)
                {
                    log::warn(self->m_server.m_config.name, "client {} sent a malformed frame", self->m_id);
                    self->close();
                    return;
                }
                break;
            }

            try
            {
                self->process_payload(*frame);
            }
            catch (const std::exception &e)
            {
                log::warn(self->m_server.m_config.name, "client {}: bad message ({}): {}", self->m_id, e.what(),
                          log::hex(*frame));
            }

            if (self->m_state == state::closed)
                return;
        }

        self->read_loop();
    });
}

void peer::send_connection_hint()
{
    // NotifyServerConnectionHint (handler 0x605b30). Must be exactly this long or the client disconnects.
    const auto &s = m_server.m_config.settings;
    auto w = begin(message_type::notify_server_connection_hint);
    w.write_u8(0); // enableLog: client-side internal logging off
    w.write_u8(s.fallback_method);
    w.write_i32(s.message_max_length);
    w.write_f64(s.default_timeout_sec);
    w.write_u8(s.direct_p2p_start_condition);
    w.write_i32(s.over_send_suspecting_threshold);
    w.write_u8(s.enable_nagle_algorithm);
    w.write_i32(s.encrypted_message_key_length);
    w.write_u8(s.allow_server_as_p2p_group_member);
    w.write_u8(s.enable_p2p_encrypted_messaging);
    w.write_u8(s.upnp_detect_nat_device);
    w.write_u8(s.upnp_tcp_add_port_mapping);
    w.write_i32(s.emergency_log_line_count);
    w.write_u8(s.enable_ping_test);
    w.write_u8(s.unknown_bool);
    send(w);
}

void peer::process_payload(std::span<const uint8_t> payload, bool was_encrypted)
{
    message_reader r(payload);
    auto type = r.read<message_type>();

    switch (type)
    {
    case message_type::notify_cs_public_key:
        if (m_state == state::awaiting_public_key)
            on_public_key(r);
        return;

    case message_type::notify_server_connection_request_data:
        if (m_state == state::awaiting_connection_request)
            on_connection_request(r);
        return;

    case message_type::encrypted_reliable:
    case message_type::encrypted_unreliable:
        if (!was_encrypted)
            on_encrypted(r, type == message_type::encrypted_reliable);
        return;

    case message_type::rmi:
        if (m_state == state::connected)
            on_rmi(r);
        return;

    default:
        if (m_state == state::connected && m_server.handle_core_message(*this, type, r))
            return;
        log::debug(m_server.m_config.name, "client {}: unhandled message type {}: {}", m_id, std::to_underlying(type),
                   log::hex(payload));
    }
}

void peer::on_public_key(message_reader &r)
{
    // NotifyCSPublicKey: cs length + CryptoAPI PUBLICKEYBLOB of the client's RSA key-exchange key.
    auto blob = r.read_byte_array();
    auto key = crypto::parse_publickeyblob(blob);
    if (!key)
    {
        log::warn(m_server.m_config.name, "client {}: bad public key ({})", m_id, key.error());
        close();
        return;
    }

    m_session_key.resize(rc4_key_bytes);
    std::uniform_int_distribution<int> byte(0, 255);
    for (auto &b : m_session_key)
        b = static_cast<uint8_t>(byte(m_server.m_rng));

    // NotifyCSEncryptedSessionKey: cs length + SIMPLEBLOB the client imports with CryptImportKey.
    auto w = begin(message_type::notify_cs_encrypted_session_key);
    w.write_byte_array(crypto::make_rc4_simpleblob(*key, m_session_key, m_server.m_rng));
    send(w);

    m_state = state::awaiting_connection_request;
}

void peer::on_connection_request(message_reader &r)
{
    // NotifyServerConnectionRequestData: cs userDataLen + userData, Guid protocolVersion, u32 internalVersion.
    auto user_data = r.read_byte_array();
    auto version = r.read_guid();
    auto internal_version = r.read_u32();

    if (version != m_server.m_config.protocol_version)
    {
        log::warn(m_server.m_config.name, "client {}: protocol version {} does not match {}", m_id, to_string(version),
                  to_string(m_server.m_config.protocol_version));
        send(begin(message_type::notify_protocol_version_mismatch));
        close();
        return;
    }

    log::debug(m_server.m_config.name, "client {}: internal version {}, {} bytes of user data", m_id, internal_version,
               user_data.size());

    // NotifyServerConnectSuccess: u32 hostId, Guid serverInstance, cs replyLen + reply, u32 ip, u16 port.
    auto w = begin(message_type::notify_server_connect_success);
    w.write_u32(m_id);
    w.write_guid(m_server.m_instance_guid);
    w.write_byte_array({});
    auto address = m_remote.address().is_v4() ? m_remote.address().to_v4().to_bytes() : asio::ip::address_v4::bytes_type{};
    w.write_bytes(address);
    w.write_u16(m_remote.port());
    send(w);

    m_state = state::connected;

    // The speed-hack detector pings (type 27) are on by default; we have no use for them.
    auto disable = rmi_begin(core_rmi::notify_speed_hack_detector_enabled);
    disable.write_bool(false);
    send(disable);

    m_server.on_peer_joined(*this);
}

void peer::on_encrypted(message_reader &r, bool reliable)
{
    if (m_session_key.empty())
        return;

    r.read_u8();     // encrypt mode, ignored by the receiver
    r.read_scalar(); // ciphertext length, ignored by the receiver (the ciphertext runs to the end)

    auto rest = r.rest();
    std::vector<uint8_t> plain(rest.begin(), rest.end());
    crypto::rc4_apply(m_session_key, plain);

    std::span<const uint8_t> inner = plain;
    if (reliable)
    {
        message_reader serial_reader(inner);
        auto serial = serial_reader.read_u16();
        if (serial != m_recv_serial)
        {
            log::warn(m_server.m_config.name, "client {}: encrypted serial {} (expected {}), dropped", m_id, serial,
                      m_recv_serial);
            return;
        }
        ++m_recv_serial;
        inner = inner.subspan(2);
    }

    process_payload(inner, true);
}

void peer::on_rmi(message_reader &r)
{
    auto rmi_id = r.read_u16();
    if (rmi_id >= core_rmi::c2s_first && rmi_id <= core_rmi::c2s_last)
    {
        m_server.handle_core_rmi(*this, rmi_id, r);
        return;
    }

    if (!m_server.m_events.on_rmi(*this, rmi_id, r))
        log::debug(m_server.m_config.name, "client {}: unhandled RMI {} (0x{:x}) params: {}", m_id, rmi_id, rmi_id,
                   log::hex(r.rest()));
}

// ---------------------------------------------------------------------------------------------------------------
// server

server::server(asio::io_context &io, server_config config, event_sink &events)
    : m_io(io), m_acceptor(io), m_timer(io), m_config(std::move(config)), m_events(events),
      m_rng(std::random_device{}())
{
    std::uniform_int_distribution<int> byte(0, 255);
    for (auto &b : m_instance_guid)
        b = static_cast<uint8_t>(byte(m_rng));
}

void server::start()
{
    asio::ip::tcp::endpoint endpoint(asio::ip::tcp::v4(), m_config.port);
    m_acceptor.open(endpoint.protocol());
    m_acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    m_acceptor.bind(endpoint);
    m_acceptor.listen();

    log::info(m_config.name, "listening on port {}", m_config.port);
    accept();
    check_timeouts();
}

void server::stop()
{
    asio::error_code ec;
    m_acceptor.close(ec);
    m_timer.cancel();

    // close() erases from m_peers, so iterate over a copy.
    auto peers = m_peers | std::views::values | std::ranges::to<std::vector>();
    for (auto &p : peers)
        p->close();
}

void server::accept()
{
    m_acceptor.async_accept([this](asio::error_code ec, asio::ip::tcp::socket socket) {
        if (ec)
        {
            if (ec != asio::error::operation_aborted)
                log::error(m_config.name, "accept failed: {}", ec.message());
            return;
        }

        auto id = allocate_host_id();
        auto p = std::make_shared<peer>(*this, std::move(socket), id);
        m_peers.emplace(id, p);
        p->start();
        accept();
    });
}

void server::check_timeouts()
{
    m_timer.expires_after(std::chrono::seconds(5));
    m_timer.async_wait([this](asio::error_code ec) {
        if (ec)
            return;

        auto now = std::chrono::steady_clock::now();
        auto stale = m_peers | std::views::values |
                     std::views::filter([&](auto &p) { return now - p->m_last_receive > m_config.timeout; }) |
                     std::ranges::to<std::vector>();
        for (auto &p : stale)
        {
            log::info(m_config.name, "client {} timed out", p->id());
            p->close();
        }

        check_timeouts();
    });
}

host_id server::allocate_host_id()
{
    if (!m_free_ids.empty())
    {
        auto id = *m_free_ids.begin();
        m_free_ids.erase(m_free_ids.begin());
        return id;
    }

    auto id = m_next_id++;
    // The client runs a diagnostic path when it is assigned HostID 50 (0x6076e0); skip it.
    if (id == 50)
        id = m_next_id++;
    return id;
}

void server::release_host_id(host_id id) { m_free_ids.insert(id); }

std::shared_ptr<peer> server::find(host_id id) const
{
    auto it = m_peers.find(id);
    return it == m_peers.end() ? nullptr : it->second;
}

void server::send(host_id to, const message_writer &message, bool encrypt)
{
    if (auto p = find(to); p && p->current_state() == peer::state::connected)
        p->send(message, encrypt);
}

void server::send(std::span<const host_id> to, const message_writer &message, bool encrypt)
{
    for (auto id : to)
        send(id, message, encrypt);
}

void server::on_peer_joined(peer &p)
{
    log::info(m_config.name, "client {} joined", p.id());
    m_events.on_client_join(p);
}

void server::on_peer_closed(peer &p)
{
    auto id = p.id();

    // Leave every P2P group the peer was in.
    for (auto &[group, members] : m_groups)
        if (members.contains(id))
            leave_p2p_group(group, id);

    auto keep_alive = find(id);
    m_peers.erase(id);
    release_host_id(id);
}

// P2P group HostIDs share the HostID space with clients.
host_id server::create_p2p_group(std::span<const host_id> members)
{
    auto group = allocate_host_id();
    m_groups[group];
    for (auto m : members)
        join_p2p_group(group, m);
    log::debug(m_config.name, "created P2P group {}", group);
    return group;
}

void server::join_p2p_group(host_id group, host_id member)
{
    auto it = m_groups.find(group);
    if (it == m_groups.end() || !find(member))
        return;

    auto &members = it->second;
    if (!members.insert(member).second)
        return;

    // Tell the new member about everyone (including itself) and everyone else about the new member.
    for (auto existing : members)
    {
        notify_group_member_join(group, member, existing);
        if (existing != member)
            notify_group_member_join(group, existing, member);
    }
}

void server::leave_p2p_group(host_id group, host_id member)
{
    auto it = m_groups.find(group);
    if (it == m_groups.end() || !it->second.erase(member))
        return;

    for (auto remaining : it->second)
        notify_group_member_leave(group, remaining, member);
    notify_group_member_leave(group, member, member);
}

void server::destroy_p2p_group(host_id group)
{
    auto it = m_groups.find(group);
    if (it == m_groups.end())
        return;

    auto members = it->second | std::ranges::to<std::vector>();
    for (auto m : members)
        leave_p2p_group(group, m);
    m_groups.erase(group);
    release_host_id(group);
}

const std::set<host_id> *server::p2p_group_members(host_id group) const
{
    auto it = m_groups.find(group);
    return it == m_groups.end() ? nullptr : &it->second;
}

void server::notify_group_member_join(host_id group, host_id member_to_notify, host_id joined_member)
{
    // P2PGroup_MemberJoin_Unencrypted (64502): u32 group, u32 member, ByteArray custom, u32 eventId,
    // i32 firstFrameNumber, Guid connectionMagic, bool enableDirectP2P, u16.
    // Direct P2P stays off: we never give the client a UDP socket, so every peer message is relayed over TCP.
    // Both ends of every pair use the same first reliable frame number so relayed streams line up.
    auto w = rmi_begin(core_rmi::p2p_group_member_join_unencrypted);
    w.write_u32(group);
    w.write_u32(joined_member);
    w.write_byte_array({});
    w.write_u32(m_next_event_id++);
    w.write_i32(1);
    w.write_guid(m_instance_guid);
    w.write_bool(false);
    w.write_u16(0);
    send(member_to_notify, w);
}

void server::notify_group_member_leave(host_id group, host_id member_to_notify, host_id left_member)
{
    // P2PGroup_MemberLeave (64506): u32 member, u32 group.
    auto w = rmi_begin(core_rmi::p2p_group_member_leave);
    w.write_u32(left_member);
    w.write_u32(group);
    send(member_to_notify, w);
}

double server::server_time_sec() const
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - m_start_time).count();
}

bool server::handle_core_message(peer &from, message_type type, message_reader &r)
{
    switch (type)
    {
    case message_type::request_server_time_and_keep_alive: {
        // [f64 clientLocalTime][f64 clientAvgPing] -> [f64 echo][f64 serverTime]
        auto client_time = r.read_f64();
        r.read_f64();
        message_writer w;
        w.write(message_type::reply_server_time_and_keep_alive);
        w.write_f64(client_time);
        w.write_f64(server_time_sec());
        from.send(w);
        return true;
    }

    case message_type::speed_hack_detector_ping:
        return true;

    case message_type::request_receive_speed_at_receiver_side: {
        // Report a generous receive speed so the client's send limiter never throttles.
        message_writer w;
        w.write(message_type::reply_receive_speed_at_receiver_side);
        w.write_f64(10.0 * 1024 * 1024);
        from.send(w);
        return true;
    }

    case message_type::reply_receive_speed_at_receiver_side:
        return true;

    case message_type::reliable_relay1:
        relay_reliable(from, r);
        return true;

    case message_type::unreliable_relay1:
        relay_unreliable(from, r);
        return true;

    case message_type::reliable_udp_frame_relay1:
        relay_reliable_udp_frame(from, r);
        return true;

    case message_type::compressed:
        // Only sent when the game asks for compression on an RMI; this client never does.
        log::warn(m_config.name, "client {} sent a compressed message, which is not supported", from.id());
        return true;

    case message_type::notify_holepunch_success:
    case message_type::peer_udp_notify_holepunch_success:
        // UDP is never offered, so these should not arrive; ignore them if they do.
        return true;

    default:
        return false;
    }
}

void server::handle_core_rmi(peer &from, uint16_t rmi_id, message_reader &r)
{
    switch (rmi_id)
    {
    case core_rmi::c2s_reliable_ping:
        from.send(rmi_begin(core_rmi::reliable_pong));
        break;

    case core_rmi::c2s_shutdown_tcp:
        from.send(rmi_begin(core_rmi::shutdown_tcp_ack));
        break;

    default:
        // Member-join acks, P2P state reports, logs: nothing to do for a relay-only server.
        log::debug(m_config.name, "client {}: core RMI {} {}", from.id(), rmi_id, log::hex(r.rest()));
        break;
    }
}

// Resolves a relay destination: a client HostID, or a P2P group HostID meaning every other member.
namespace
{
template <typename F>
void for_each_destination(const std::map<host_id, std::set<host_id>> &groups, host_id sender, host_id dest, F &&fn)
{
    if (auto it = groups.find(dest); it != groups.end())
    {
        for (auto member : it->second)
            if (member != sender)
                fn(member);
        return;
    }
    fn(dest);
}
} // namespace

void server::relay_reliable(peer &from, message_reader &r)
{
    // [RelayDestList: cs n, n x (u32 dest, u32 frameNumber)][cs len][bytes]
    //   -> each dest: [23][u32 sender][u32 frameNumber][cs len][bytes]
    auto count = r.read_scalar();
    std::vector<std::pair<host_id, uint32_t>> dests;
    for (int64_t i = 0; i < count; ++i)
    {
        auto dest = r.read_u32();
        auto frame = r.read_u32();
        dests.emplace_back(dest, frame);
    }
    auto data = r.take(r.read_length());

    for (auto [dest, frame] : dests)
    {
        message_writer w;
        w.write(message_type::reliable_relay2);
        w.write_u32(from.id());
        w.write_u32(frame);
        w.write_scalar(std::ssize(data));
        w.write_bytes(data);
        send(dest, w);
    }
}

void server::relay_unreliable(peer &from, message_reader &r)
{
    // [u8 priority][cs uniqueId][cs n][n x u32 dest][cs len][payload]
    //   -> each dest: [24][u32 sender][cs len][payload]
    r.read_u8();
    r.read_scalar();
    auto count = r.read_scalar();
    std::vector<host_id> dests;
    for (int64_t i = 0; i < count; ++i)
        dests.push_back(r.read_u32());
    auto payload = r.take(r.read_length());

    message_writer w;
    w.write(message_type::unreliable_relay2);
    w.write_u32(from.id());
    w.write_scalar(std::ssize(payload));
    w.write_bytes(payload);

    std::set<host_id> sent;
    for (auto dest : dests)
        for_each_destination(m_groups, from.id(), dest, [&](host_id id) {
            if (sent.insert(id).second)
                send(id, w);
        });
}

void server::relay_reliable_udp_frame(peer &from, message_reader &r)
{
    // [u32 dest][u32 frameNumber][cs len][frame] -> dest: [25][u32 sender][u32 frameNumber][cs len][frame]
    auto dest = r.read_u32();
    auto frame = r.read_u32();
    auto data = r.take(r.read_length());

    message_writer w;
    w.write(message_type::reliable_udp_frame_relay2);
    w.write_u32(from.id());
    w.write_u32(frame);
    w.write_scalar(std::ssize(data));
    w.write_bytes(data);
    send(dest, w);
}

} // namespace hovorun::proudnet
