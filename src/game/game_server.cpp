#include "game_server.hpp"

#include "../util/log.hpp"
#include "gscl_proxy.hpp"

#include <algorithm>
#include <ranges>

namespace hovorun::game
{

namespace
{
constexpr std::string_view tag = "game";

// Enter_Room result codes (confirmed log strings in the client, match ports.txt).
namespace enter_result
{
constexpr uint16_t ok = 0;
constexpr uint16_t failed = 1;          // "JoinRoom Fales"
constexpr uint16_t wrong_password = 11; // "PassWord Fales"
constexpr uint16_t full = 12;           // "Room is Full"
constexpr uint16_t playing = 13;        // "Room is Playing"
} // namespace enter_result

// Room state byte shown in the lobby list (RoomInfo +0x1c). Values are inferred.
constexpr uint8_t room_state_waiting = 0;
constexpr uint8_t room_state_playing = 1;

constexpr uint32_t channel_capacity = 200;
} // namespace

game_server::game_server(asio::io_context &io, const app::config &config, app::account_store &accounts)
    : m_config(config), m_accounts(accounts),
      m_net(io,
            proudnet::server_config{.name = std::string(tag),
                                    .port = config.game_port,
                                    .protocol_version = proudnet::game_protocol_version},
            *this)
{
    using enum clgs::id;
    m_handlers = {
        {Logout_Notify, &game_server::logout},
        {Room_List, &game_server::room_list},
        {Room_Request_Room_Member, &game_server::room_request_member},
        {Create_Room, &game_server::create_room},
        {Enter_Room, &game_server::enter_room},
        {Room_Chat, &game_server::room_chat},
        {Team_Chat, &game_server::team_chat},
        {Wisper_Chat, &game_server::whisper_chat},
        {Leave_Room, &game_server::leave_room},
        {Change_Map, &game_server::change_map},
        {Change_Type, &game_server::change_type},
        {Kicked_Room, &game_server::kick},
        {CloseSlot_Room, &game_server::close_slot},
        {OpenSlot_Room, &game_server::open_slot},
        {Change_Team, &game_server::change_team},
        {Change_Lap, &game_server::change_lap},
        {Change_Attribute, &game_server::change_attribute},
        {Change_RandomMap, &game_server::change_random_map},
        {Mission_Request, &game_server::mission},
        {Start_Game, &game_server::start_game},
        {Ready_Game, &game_server::ready_game},
        {Room_Save_Score, &game_server::save_score},
        {GotoWaitRoom_Notify, &game_server::goto_wait_room},
        {Room_QuickJoin, &game_server::quick_join},
        {Room_ConnectOk, &game_server::room_connect_ok},
        {GameReady_Notify, &game_server::game_ready},
        {Select_Character_Request, &game_server::select_character},
        {Select_Avatar, &game_server::select_avatar},
        {Update_Avatar, &game_server::update_avatar},
        {Delete_Item_Request, &game_server::delete_item},
        {BuyItem_Request, &game_server::buy_item},
        {Channel_List, &game_server::channel_list},
        {Channel_UserList_Request, &game_server::channel_user_list},
        {Enter_Channel, &game_server::enter_channel},
        {Leave_Channel, &game_server::leave_channel},
        {Change_Channel, &game_server::change_channel},
        {Channel_Total_RoomNumber, &game_server::channel_total_room_number},
        {Check_Error_Notify, &game_server::check_error},
        {Enter_Lobby, &game_server::enter_lobby},
        {Lobby_Chat, &game_server::lobby_chat},
        {Change_Comment, &game_server::change_comment},
        {Cry, &game_server::cry},
        {Ranking_Request, &game_server::ranking},
        {Enter_Nation, &game_server::enter_nation},
        {RankInfo_Request, &game_server::rank_info},
        {GetUserNewCash, &game_server::new_cash},
        {BlastingRoom_GM, &game_server::gm_close_room},
        {UserKickRoom_GM, &game_server::gm_kick},
        // Accepted and ignored: anti-cheat traffic, clan refresh, item bookkeeping without a shop backend.
        {CL2GS_Test, &game_server::ignore},
        {Guid_Request, &game_server::ignore},
        {Check_Period_Answer, &game_server::ignore},
        {Update_Gs_UserClanInfo, &game_server::ignore},
        {Room_Index_Answer, &game_server::ignore},
        {DuraCheck_Item_Request, &game_server::ignore},
        {Update_ASDKEY, &game_server::ignore},
        {Insert_Item_Request, &game_server::ignore},
        {Gift_Item_Request, &game_server::ignore},
        {Answer_Gift, &game_server::ignore},
        {Create_Avatar, &game_server::ignore},
        {Change_Nation, &game_server::ignore},
    };
}

// ---------------------------------------------------------------------------------------------------------------
// Dispatch

std::shared_ptr<player> game_server::player_of(proudnet::peer &client) const { return player_by_host(client.id()); }

std::shared_ptr<player> game_server::player_by_host(host_id host) const
{
    auto it = m_players.find(host);
    return it == m_players.end() ? nullptr : it->second;
}

bool game_server::on_rmi(proudnet::peer &client, uint16_t rmi_id, net::message_reader &params)
{
    auto id = static_cast<clgs::id>(rmi_id);

    if (id == clgs::id::Logon_CLGS)
    {
        logon(client, params);
        return true;
    }
    if (id == clgs::id::CL2GS_Test)
        return true;

    auto it = m_handlers.find(id);
    if (it == m_handlers.end())
        return false;

    auto p = player_of(client);
    if (!p)
    {
        log::warn(tag, "client {} sent {} before logging in", client.id(), clgs::name(id));
        return true;
    }

    log::debug(tag, "{} -> {}", p->nickname, clgs::name(id));
    (this->*(it->second))(*p, params);
    return true;
}

void game_server::on_client_leave(proudnet::peer &client)
{
    auto p = player_of(client);
    if (!p)
        return;

    remove_from_room(*p, false);
    m_players.erase(client.id());
    log::info(tag, "{} left the game server", p->nickname);
}

void game_server::send_room(const room &r, const net::message_writer &message, host_id except)
{
    for (auto host : r.slots)
        if (host && host != except)
            m_net.send(host, message);
}

void game_server::send_channel_lobby(uint8_t channel, const net::message_writer &message)
{
    for (auto &[host, p] : m_players)
        if (p->channel == channel && !p->current_room)
            m_net.send(host, message);
}

// ---------------------------------------------------------------------------------------------------------------
// Login

void game_server::logon(proudnet::peer &client, net::message_reader &r)
{
    auto user = r.read_string();
    auto password = r.read_string();
    auto version = r.read_u32();

    if (version != clgs::client_version)
        log::warn(tag, "{} uses client version {} (expected {})", user, version, clgs::client_version);

    auto result = m_accounts.login(user, password);
    auto account = m_accounts.find(user);
    if (result != app::login_result::ok || !account)
    {
        log::info(tag, "game login for {} failed", user);
        // Result 1 shows "DB Login Failed".
        client.send(gscl::Logon_GSCL(client.id(), {}, 1, 0, 0, 0, 0, {}));
        return;
    }

    // Only one game connection per account: drop the older one.
    for (auto &[host, other] : m_players)
        if (other->account.username == user && host != client.id())
            if (auto old = m_net.find(host))
            {
                old->send(gscl::Forced_Close(2));
                old->close();
                break;
            }

    auto p = std::make_shared<player>();
    p->host = client.id();
    p->account = *account;
    p->nickname = user;
    p->avatar.host = p->host;
    m_players[p->host] = p;

    logon_info info;
    info.user_index = p->account.index;
    info.nickname = p->nickname;
    info.exp = p->exp;
    info.money = p->money;
    info.host = p->host;
    info.need_select_character = 0; // straight to channel select

    log::info(tag, "{} logged in to the game server as HostID {}", user, p->host);
    client.send(gscl::Logon_GSCL(p->host, info, gscl::ok, 0, 0, 0, 0, {}));
    client.send(gscl::Add_Items({}));
    client.send(gscl::Add_Avatars({avatar_of(*p)}));
    client.send(gscl::Add_Gifts({}));
}

void game_server::logout(player &p, net::message_reader &)
{
    remove_from_room(p, false);
    send(p, gscl::LogOut_OK());
}

// ---------------------------------------------------------------------------------------------------------------
// Lobby and channels

void game_server::enter_lobby(player &p, net::message_reader &)
{
    remove_from_room(p, false);
    p.channel = no_channel;
    send(p, gscl::Enter_Lobby(gscl::ok));
}

void game_server::channel_list(player &p, net::message_reader &)
{
    std::vector<channel_info> channels;
    for (uint8_t i = 0; i < channel_count; ++i)
    {
        channel_info c;
        c.index = i;
        c.users = static_cast<uint32_t>(std::ranges::count_if(m_players | std::views::values,
                                                              [i](auto &other) { return other->channel == i; }));
        c.capacity = channel_capacity;
        channels.push_back(c);
    }
    send(p, gscl::Channel_List(channels));
}

void game_server::enter_channel(player &p, net::message_reader &r)
{
    auto channel = r.read_u8();
    if (channel >= channel_count)
    {
        send(p, gscl::Enter_Channel(channel, 1));
        return;
    }

    p.channel = channel;
    send(p, gscl::Enter_Channel(channel, gscl::ok));

    std::vector<room_info> page;
    for (auto &room : rooms_in(channel) | std::views::take(rooms_per_page))
        page.push_back(listed_info(*room));
    send(p, gscl::Lobby_Add_Rooms(page, 0));
}

void game_server::leave_channel(player &p, net::message_reader &)
{
    remove_from_room(p, false);
    p.channel = no_channel;
    send(p, gscl::Leave_Channel(gscl::ok));
}

void game_server::change_channel(player &p, net::message_reader &r)
{
    auto channel = r.read_u8();
    if (channel >= channel_count)
    {
        send(p, gscl::Change_Channel(channel, 1));
        return;
    }

    remove_from_room(p, false);
    p.channel = channel;
    send(p, gscl::Change_Channel(channel, gscl::ok));

    std::vector<room_info> page;
    for (auto &room : rooms_in(channel) | std::views::take(rooms_per_page))
        page.push_back(listed_info(*room));
    send(p, gscl::Lobby_Add_Rooms(page, 0));
}

void game_server::channel_total_room_number(player &p, net::message_reader &)
{
    auto count = p.channel == no_channel ? 0 : rooms_in(p.channel).size();
    send(p, gscl::Channel_RoomNumber_Answer(static_cast<uint32_t>(count), gscl::ok));
}

void game_server::channel_user_list(player &p, net::message_reader &)
{
    std::vector<channel_user> users;
    for (auto &other : m_players | std::views::values)
        if (other->channel == p.channel)
            users.push_back(channel_user{.nickname = other->nickname, .host = other->host, .str_1c = other->comment});
    send(p, gscl::Channel_UserList_Answer(p.host, users, gscl::ok, 0));
}

void game_server::room_list(player &p, net::message_reader &r)
{
    auto page = r.read_u16();
    r.read_u16(); // list type/filter

    if (p.channel == no_channel)
        return;

    std::vector<room_info> rooms;
    for (auto &room : rooms_in(p.channel) | std::views::drop(page * rooms_per_page) | std::views::take(rooms_per_page))
        rooms.push_back(listed_info(*room));
    send(p, gscl::Lobby_Add_Rooms(rooms, 0));
}

void game_server::room_request_member(player &p, net::message_reader &r)
{
    auto number = r.read_u16();
    auto extra = r.read_u16();

    auto room = find_room(p.channel, number);
    if (!room)
    {
        send(p, gscl::Room_Member_Answer(number, 1, 0, {}, {}));
        return;
    }

    std::vector<room_member> members;
    std::vector<room_slot_user> slot_users;
    for (auto host : room->slots)
        if (auto other = player_by_host(host))
        {
            members.push_back(member_of(*other));
            slot_users.push_back(room_slot_user{.str_04 = other->nickname, .str_08 = other->comment,
                                                .u32_0c = other->account.index, .u32_10 = other->exp,
                                                .u8_18 = static_cast<uint8_t>(other->slot)});
        }
    // Parameter meaning is inferred: echo the room number and the request's second value.
    send(p, gscl::Room_Member_Answer(number, extra, room->slots[room->master_slot], members, slot_users));
}

void game_server::lobby_chat(player &p, net::message_reader &r)
{
    auto text = r.read_string();
    log::info(tag, "[lobby {}] {}: {}", p.channel, p.nickname, text);
    send_channel_lobby(p.channel, gscl::Lobby_Chat(p.host, text));
}

void game_server::cry(player &p, net::message_reader &r)
{
    auto text = r.read_string();
    log::info(tag, "[cry] {}: {}", p.nickname, text);
    auto message = gscl::Cry(std::format("{} : {}", p.nickname, text));
    for (auto &other : m_players | std::views::values)
        send(*other, message);
}

// ---------------------------------------------------------------------------------------------------------------
// Rooms

void game_server::create_room(player &p, net::message_reader &r)
{
    auto info = room_info::read(r);
    if (p.channel == no_channel)
    {
        send(p, gscl::Create_Room(info, 0, 1));
        return;
    }
    remove_from_room(p, false);

    auto room = std::make_shared<game::room>();
    room->channel = p.channel;
    room->info = info;
    while (m_rooms.contains(m_next_room_number) || m_next_room_number == 0)
        ++m_next_room_number;
    room->info.number = m_next_room_number++;
    room->info.has_password = room->info.password.empty() ? 0 : 1;
    if (room->info.max_players == 0 || room->info.max_players > room_slots)
        room->info.max_players = room_slots;
    room->p2p_group = m_net.create_p2p_group();
    m_rooms[room->info.number] = room;

    p.current_room = room;
    p.slot = 0;
    p.ready = false;
    room->slots[0] = p.host;
    room->master_slot = 0;
    m_net.join_p2p_group(room->p2p_group, p.host);

    log::info(tag, "{} created room {} \"{}\" in channel {}", p.nickname, room->info.number, room->info.title,
              room->channel);
    send(p, gscl::Create_Room(listed_info(*room), 0, gscl::ok));
}

void game_server::enter_room(player &p, net::message_reader &r)
{
    auto number = r.read_u16();
    auto password = r.read_string();

    auto room = find_room(p.channel, number);
    auto fail = [&](uint16_t code) { send(p, gscl::Enter_Room({}, {}, 0, room_info{}, code)); };

    if (!room)
        return fail(enter_result::failed);
    if (room->playing)
        return fail(enter_result::playing);
    if (!room->info.password.empty() && room->info.password != password)
        return fail(enter_result::wrong_password);
    if (!room->free_slot())
        return fail(enter_result::full);

    join_room(p, room);
}

void game_server::quick_join(player &p, net::message_reader &r)
{
    r.read_u16();
    for (auto &room : rooms_in(p.channel))
        if (!room->playing && room->info.password.empty() && room->free_slot())
            return join_room(p, room);
    send(p, gscl::Enter_Room({}, {}, 0, room_info{}, enter_result::failed));
}

void game_server::join_room(player &p, const std::shared_ptr<room> &room)
{
    remove_from_room(p, false);

    auto slot = *room->free_slot();
    room->slots[slot] = p.host;
    p.current_room = room;
    p.slot = slot;
    p.ready = false;

    std::vector<room_member> members;
    std::vector<avatar_info> avatars;
    for (auto host : room->slots)
        if (auto other = player_by_host(host))
        {
            members.push_back(member_of(*other));
            avatars.push_back(avatar_of(*other));
        }

    log::info(tag, "{} joined room {} in slot {}", p.nickname, room->info.number, slot);
    send(p, gscl::Enter_Room(members, avatars, room->master_slot, listed_info(*room), enter_result::ok));
    send_room(*room, gscl::Room_Add_User_Avatar(avatar_of(p), member_of(p)), p.host);
    m_net.join_p2p_group(room->p2p_group, p.host);
}

void game_server::leave_room(player &p, net::message_reader &)
{
    if (!p.current_room)
        return send(p, gscl::Leave_Room(1));
    remove_from_room(p, false);
    send(p, gscl::Leave_Room(gscl::ok));
}

void game_server::remove_from_room(player &p, bool kicked)
{
    auto room = p.current_room;
    if (!room)
        return;

    auto slot = p.slot;
    room->slots[slot] = 0;
    p.current_room.reset();
    p.ready = false;
    m_net.leave_p2p_group(room->p2p_group, p.host);

    if (kicked)
        send(p, gscl::Kicked_Room(gscl::ok));

    if (room->player_count() == 0)
    {
        log::info(tag, "room {} closed", room->info.number);
        m_net.destroy_p2p_group(room->p2p_group);
        m_rooms.erase(room->info.number);
        return;
    }

    send_room(*room, gscl::Room_Del_User(p.host, slot, 0));

    if (room->master_slot == slot)
    {
        auto next = std::ranges::find_if(room->slots, [](host_id h) { return h != 0; });
        room->master_slot = static_cast<uint32_t>(next - room->slots.begin());
        send_room(*room, gscl::New_RoomMaster(room->master_slot));
    }
}

void game_server::room_chat(player &p, net::message_reader &r)
{
    auto text = r.read_string();
    if (p.current_room)
        send_room(*p.current_room, gscl::Room_Chat(p.host, text));
}

void game_server::team_chat(player &p, net::message_reader &r)
{
    auto text = r.read_string();
    if (!p.current_room)
        return;
    for (auto host : p.current_room->slots)
        if (auto other = player_by_host(host); other && other->team == p.team)
            send(*other, gscl::Room_Chat(p.host, text));
}

void game_server::whisper_chat(player &p, net::message_reader &r)
{
    auto target = r.read_string();
    auto text = r.read_string();
    for (auto &other : m_players | std::views::values)
        if (other->nickname == target)
            send(*other, gscl::Room_Chat(p.host, std::format("[{}] {}", p.nickname, text)));
}

bool game_server::is_master(const player &p) const
{
    return p.current_room && p.current_room->master_slot == p.slot;
}

void game_server::change_map(player &p, net::message_reader &r)
{
    auto map = r.read_u8();
    if (!is_master(p))
        return;
    p.current_room->info.map = map;
    send_room(*p.current_room, gscl::Change_Map(map));
}

void game_server::change_type(player &p, net::message_reader &r)
{
    auto type = r.read_u8();
    if (!is_master(p))
        return;
    auto &room = *p.current_room;
    room.info.mode = type;

    std::vector<room_member> members;
    for (auto host : room.slots)
        if (auto other = player_by_host(host))
            members.push_back(member_of(*other));
    send_room(room, gscl::Change_Type(type, members));
}

void game_server::change_lap(player &p, net::message_reader &r)
{
    auto laps = r.read_u8();
    if (!is_master(p))
        return;
    p.current_room->info.max_lap = laps;
    send_room(*p.current_room, gscl::Change_Lap(laps));
}

void game_server::change_attribute(player &p, net::message_reader &r)
{
    auto attribute = r.read_u8();
    if (!is_master(p))
        return;
    p.current_room->info.u8_0e = attribute;
    send_room(*p.current_room, gscl::Change_Attribute(attribute));
}

void game_server::change_random_map(player &p, net::message_reader &r)
{
    auto random = r.read_u8() != 0;
    if (!is_master(p))
        return;
    send_room(*p.current_room, gscl::Change_RandomMap(random));
}

void game_server::change_team(player &p, net::message_reader &r)
{
    auto team = r.read_u8();
    if (!p.current_room)
        return;
    p.team = team;
    send_room(*p.current_room, gscl::Change_Team(p.slot, team));
}

void game_server::kick(player &p, net::message_reader &r)
{
    auto slot = r.read_u32();
    if (!is_master(p) || slot >= room_slots || slot == p.slot)
        return;
    if (auto target = player_by_host(p.current_room->slots[slot]))
        remove_from_room(*target, true);
}

void game_server::close_slot(player &p, net::message_reader &r)
{
    auto slot = r.read_u32();
    if (!is_master(p) || slot >= room_slots || p.current_room->slots[slot])
        return;
    p.current_room->closed[slot] = true;
    send_room(*p.current_room, gscl::CloseSlot_Room(slot));
}

void game_server::open_slot(player &p, net::message_reader &r)
{
    auto slot = r.read_u32();
    if (!is_master(p) || slot >= room_slots)
        return;
    p.current_room->closed[slot] = false;
    send_room(*p.current_room, gscl::OpenSlot_Room(slot));
}

void game_server::mission(player &p, net::message_reader &r)
{
    auto value = r.read_u8();
    send(p, gscl::Mission_Answer(value));
}

void game_server::ready_game(player &p, net::message_reader &r)
{
    auto ready = r.read_u8() != 0;
    if (!p.current_room)
        return;
    p.ready = ready;
    send_room(*p.current_room, gscl::Ready_Game(p.host, p.slot, ready));
}

void game_server::start_game(player &p, net::message_reader &r)
{
    r.read_u16();
    if (!is_master(p))
        return;

    auto &room = *p.current_room;
    room.playing = true;
    room.info.state = room_state_playing;
    log::info(tag, "room {} starts (map {}, mode {}, laps {})", room.info.number, room.info.map, room.info.mode,
              room.info.max_lap);

    // The client ignores StartGameInfo; the two u16 values land in the same globals as RoomInfo mode/laps.
    send_room(room, gscl::Start_Game(start_game_info{}, room.info.mode, room.info.max_lap, gscl::ok));
}

void game_server::game_ready(player &p, net::message_reader &)
{
    log::debug(tag, "{} finished loading", p.nickname);
}

void game_server::room_connect_ok(player &p, net::message_reader &r)
{
    auto state = r.read_u8();
    log::debug(tag, "{} reports P2P state {}", p.nickname, state);
}

void game_server::save_score(player &p, net::message_reader &r)
{
    std::array<uint32_t, 8> score{};
    for (auto &v : score)
        v = r.read_u32();
    log::info(tag, "{} race result {} {} {} {} {} {} {} {}", p.nickname, score[0], score[1], score[2], score[3], score[4],
              score[5], score[6], score[7]);
}

void game_server::goto_wait_room(player &p, net::message_reader &r)
{
    r.read_u8();
    p.ready = false;
    if (auto &room = p.current_room)
    {
        room->playing = false;
        room->info.state = room_state_waiting;
    }
}

void game_server::change_comment(player &p, net::message_reader &r)
{
    p.comment = r.read_string();
    if (p.current_room)
        send_room(*p.current_room, gscl::Room_Change_Comment(p.comment, p.slot));
}

void game_server::gm_close_room(player &p, net::message_reader &)
{
    auto room = p.current_room;
    if (!room)
        return;
    log::info(tag, "{} closes room {}", p.nickname, room->info.number);
    for (auto host : room->slots)
        if (auto other = player_by_host(host); other && other.get() != &p)
            remove_from_room(*other, true);
}

void game_server::gm_kick(player &p, net::message_reader &r)
{
    auto nickname = r.read_string();
    if (!p.current_room)
        return;
    for (auto host : p.current_room->slots)
        if (auto other = player_by_host(host); other && other->nickname == nickname)
            remove_from_room(*other, true);
}

// ---------------------------------------------------------------------------------------------------------------
// Character, items, misc

void game_server::select_character(player &p, net::message_reader &r)
{
    p.character = r.read_u32();
    send(p, gscl::Select_Character(p.character, p.nickname, {}, gscl::ok));
}

void game_server::select_avatar(player &p, net::message_reader &r)
{
    r.read_u8();
    update_avatar(p, r);
}

void game_server::update_avatar(player &p, net::message_reader &r)
{
    p.avatar = avatar_info::read(r);
    p.avatar.host = p.host;
    if (p.current_room)
        send_room(*p.current_room, gscl::Room_UpDataAvatar(p.avatar, p.slot));
}

void game_server::delete_item(player &p, net::message_reader &r)
{
    send(p, gscl::Delete_Item_Answer(r.read_u32(), gscl::ok));
}

void game_server::buy_item(player &p, net::message_reader &r)
{
    std::array<uint32_t, 4> args{};
    for (auto &v : args)
        v = r.read_u32();
    // No shop catalogue yet: the parameters' meaning is still unknown, so the purchase is only logged.
    log::info(tag, "{} tried to buy {} {} {} {}", p.nickname, args[0], args[1], args[2], args[3]);
}

void game_server::ranking(player &p, net::message_reader &r)
{
    r.read_u32();
    send(p, gscl::RankingAnswer({}));
}

void game_server::rank_info(player &p, net::message_reader &)
{
    send(p, gscl::RankInfo_Answer({}, {}, 0, 0, 0));
}

void game_server::enter_nation(player &p, net::message_reader &r)
{
    p.nation = r.read_u8();
    send(p, gscl::Enter_Nation(p.nation, gscl::ok));
}

void game_server::new_cash(player &p, net::message_reader &)
{
    send(p, gscl::User_New_Infor_Answer(p.money));
}

void game_server::check_error(player &p, net::message_reader &r)
{
    log::warn(tag, "{} anti-cheat report: {}", p.nickname, r.read_string());
}

void game_server::ignore(player &, net::message_reader &) {}

// ---------------------------------------------------------------------------------------------------------------
// Helpers

room_member game_server::member_of(const player &p) const
{
    room_member m;
    m.host = p.host;
    m.nickname = p.nickname;
    m.str_24 = p.comment;
    m.user_index = p.account.index;
    m.exp = p.exp;
    m.slot = p.slot;
    m.ready = p.ready ? 1 : 0;
    m.character = static_cast<uint8_t>(p.character);
    m.order = p.slot;
    return m;
}

avatar_info game_server::avatar_of(const player &p) const
{
    auto a = p.avatar;
    a.host = p.host;
    return a;
}

room_info game_server::listed_info(const room &r) const
{
    auto info = r.info;
    info.players = static_cast<uint8_t>(r.player_count());
    info.state = r.playing ? room_state_playing : room_state_waiting;
    info.has_password = info.password.empty() ? 0 : 1;
    for (size_t i = 0; i < room_slots; ++i)
        info.slots[i] = r.closed[i] ? 1 : 0; // per-slot byte; meaning inferred
    return info;
}

std::vector<std::shared_ptr<room>> game_server::rooms_in(uint8_t channel) const
{
    return m_rooms | std::views::values | std::views::filter([channel](auto &r) { return r->channel == channel; }) |
           std::ranges::to<std::vector>();
}

std::shared_ptr<room> game_server::find_room(uint8_t channel, uint16_t number) const
{
    auto it = m_rooms.find(number);
    return it != m_rooms.end() && it->second->channel == channel ? it->second : nullptr;
}

} // namespace hovorun::game
