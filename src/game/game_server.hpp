#pragma once

// Game server: channels, lobby, rooms and race start. The client connects here with the address it got from
// the session server and logs in again with Logon_CLGS. Room members share a ProudNet P2P group, which carries
// the race traffic (CLPE RMIs) relayed through the server.

#include "../app/accounts.hpp"
#include "../app/config.hpp"
#include "../proudnet/server.hpp"
#include "clgs.hpp"
#include "gscl_types.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace hovorun::game
{

constexpr size_t channel_count = 6;
constexpr size_t room_slots = 8;
constexpr size_t rooms_per_page = 8; // the client's lobby list has 8 fixed rows
constexpr uint8_t no_channel = 0xff;

struct room;

struct player
{
    host_id host = 0;
    app::account account;
    std::string nickname;
    uint32_t exp = 0;
    uint32_t money = 100000;
    uint32_t character = 0;
    std::string comment;
    uint8_t nation = 1;
    uint8_t channel = no_channel;
    std::shared_ptr<room> current_room;
    uint32_t slot = 0;
    bool ready = false;
    uint8_t team = 0;
    avatar_info avatar;
};

struct room
{
    room_info info;
    uint8_t channel = 0;
    std::array<host_id, room_slots> slots{}; // 0 = empty
    std::array<bool, room_slots> closed{};
    uint32_t master_slot = 0;
    host_id p2p_group = 0;
    bool playing = false;

    [[nodiscard]] size_t player_count() const { return std::ranges::count_if(slots, [](host_id h) { return h != 0; }); }
    [[nodiscard]] size_t capacity() const { return std::min<size_t>(info.max_players ? info.max_players : room_slots, room_slots); }
    [[nodiscard]] std::optional<uint32_t> free_slot() const
    {
        for (uint32_t i = 0; i < capacity(); ++i)
            if (!slots[i] && !closed[i])
                return i;
        return std::nullopt;
    }
};

class game_server : public proudnet::event_sink
{
public:
    game_server(asio::io_context &io, const app::config &config, app::account_store &accounts);

    void start() { m_net.start(); }
    void stop() { m_net.stop(); }

    void on_client_leave(proudnet::peer &client) override;
    bool on_rmi(proudnet::peer &client, uint16_t rmi_id, net::message_reader &params) override;

private:
    using handler = void (game_server::*)(player &, net::message_reader &);

    std::shared_ptr<player> player_of(proudnet::peer &client) const;
    std::shared_ptr<player> player_by_host(host_id host) const;
    void send(const player &p, const net::message_writer &message) { m_net.send(p.host, message); }
    void send_room(const room &r, const net::message_writer &message, host_id except = 0);
    void send_channel_lobby(uint8_t channel, const net::message_writer &message);

    // Login
    void logon(proudnet::peer &client, net::message_reader &r);

    // Lobby / channels
    void enter_lobby(player &p, net::message_reader &r);
    void channel_list(player &p, net::message_reader &r);
    void enter_channel(player &p, net::message_reader &r);
    void leave_channel(player &p, net::message_reader &r);
    void change_channel(player &p, net::message_reader &r);
    void channel_total_room_number(player &p, net::message_reader &r);
    void channel_user_list(player &p, net::message_reader &r);
    void room_list(player &p, net::message_reader &r);
    void room_request_member(player &p, net::message_reader &r);
    void lobby_chat(player &p, net::message_reader &r);
    void cry(player &p, net::message_reader &r);

    // Rooms
    void create_room(player &p, net::message_reader &r);
    void enter_room(player &p, net::message_reader &r);
    void quick_join(player &p, net::message_reader &r);
    void leave_room(player &p, net::message_reader &r);
    void room_chat(player &p, net::message_reader &r);
    void team_chat(player &p, net::message_reader &r);
    void whisper_chat(player &p, net::message_reader &r);
    void change_map(player &p, net::message_reader &r);
    void change_type(player &p, net::message_reader &r);
    void change_lap(player &p, net::message_reader &r);
    void change_attribute(player &p, net::message_reader &r);
    void change_random_map(player &p, net::message_reader &r);
    void change_team(player &p, net::message_reader &r);
    void kick(player &p, net::message_reader &r);
    void close_slot(player &p, net::message_reader &r);
    void open_slot(player &p, net::message_reader &r);
    void mission(player &p, net::message_reader &r);
    void ready_game(player &p, net::message_reader &r);
    void start_game(player &p, net::message_reader &r);
    void game_ready(player &p, net::message_reader &r);
    void room_connect_ok(player &p, net::message_reader &r);
    void save_score(player &p, net::message_reader &r);
    void goto_wait_room(player &p, net::message_reader &r);
    void change_comment(player &p, net::message_reader &r);
    void gm_close_room(player &p, net::message_reader &r);
    void gm_kick(player &p, net::message_reader &r);

    // Character, items, misc
    void select_character(player &p, net::message_reader &r);
    void update_avatar(player &p, net::message_reader &r);
    void select_avatar(player &p, net::message_reader &r);
    void delete_item(player &p, net::message_reader &r);
    void buy_item(player &p, net::message_reader &r);
    void ranking(player &p, net::message_reader &r);
    void rank_info(player &p, net::message_reader &r);
    void enter_nation(player &p, net::message_reader &r);
    void new_cash(player &p, net::message_reader &r);
    void logout(player &p, net::message_reader &r);
    void check_error(player &p, net::message_reader &r);
    void ignore(player &p, net::message_reader &r);

    // Helpers
    void remove_from_room(player &p, bool kicked);
    void join_room(player &p, const std::shared_ptr<room> &r);
    room_member member_of(const player &p) const;
    avatar_info avatar_of(const player &p) const;
    room_info listed_info(const room &r) const;
    std::vector<std::shared_ptr<room>> rooms_in(uint8_t channel) const;
    std::shared_ptr<room> find_room(uint8_t channel, uint16_t number) const;
    bool is_master(const player &p) const;

    const app::config &m_config;
    app::account_store &m_accounts;
    proudnet::server m_net;
    std::map<host_id, std::shared_ptr<player>> m_players;
    std::map<uint16_t, std::shared_ptr<room>> m_rooms; // by room number
    uint16_t m_next_room_number = 1;
    std::map<clgs::id, handler> m_handlers;
};

} // namespace hovorun::game
