#include "messenger_server.hpp"

#include "../proudnet/rmi.hpp"
#include "../util/log.hpp"

#include <chrono>
#include <format>
#include <ranges>

namespace hovorun::messenger
{

using net::message_reader;
using net::message_writer;
using proudnet::rmi_begin;

namespace
{
constexpr std::string_view tag = "messenger";

// Result codes (inferred from the client's handlers).
constexpr uint16_t ok = 0;
constexpr uint16_t whisper_target_offline = 9;  // "[%s] is Empty"
constexpr uint8_t invitation_not_connected = 1; // "user not connected / not exist"
constexpr uint16_t clan_create_failed = 9;      // MSG114
constexpr uint16_t clan_join_not_found = 6;     // MSG111 "clan does not exist"
constexpr uint16_t clan_not_member = 3;         // MSG108

constexpr uint16_t state_offline = 0;
constexpr uint16_t state_online = 1;

// Empty clan structures, only needed so failure answers parse (layouts in session_messenger.md §5).
void write_empty_clan_info(message_writer &w)
{
    w.write_u32(0);
    w.write_text({});
    w.write_text({});
    for (int i = 0; i < 14; ++i)
        w.write_u32(0);
    for (int i = 0; i < 9; ++i)
        w.write_u16(0);
    w.write_u8(0);
    w.write_text({});
    w.write_text({});
    w.write_text({});
    for (int i = 0; i < 5; ++i)
        w.write_u8(0);
}

void write_empty_clan_member_info(message_writer &w)
{
    w.write_u32(0);
    w.write_u32(0);
    w.write_text({});
    w.write_text({});
    w.write_u16(0);
    for (int i = 0; i < 10; ++i)
        w.write_u32(0);
    w.write_u8(0);
    w.write_u8(0);
    for (int i = 0; i < 4; ++i)
        w.write_u16(0);
    w.write_text({});
    w.write_u16(0);
    w.write_u8(0);
}

void write_empty_clan_board_info(message_writer &w)
{
    w.write_u32(0);
    w.write_u32(0);
    w.write_u32(0);
    w.write_u8(0);
    w.write_text({});
    w.write_text({});
    w.write_text({});
}

// MessageInfo: u32 index, u32 receiverIndex, u32, u8, u8, String sender, String text, String date (inferred).
void write_message_info(message_writer &w, uint32_t index, uint32_t receiver, const std::string &sender,
                        const std::string &text)
{
    auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    w.write_u32(index);
    w.write_u32(receiver);
    w.write_u32(0);
    w.write_u8(0);
    w.write_u8(0);
    w.write_text(sender);
    w.write_text(text);
    w.write_text(std::format("{:%Y-%m-%d %H:%M}", now));
}
} // namespace

messenger_server::messenger_server(asio::io_context &io, const app::config &config, app::account_store &accounts)
    : m_accounts(accounts),
      m_net(io,
            proudnet::server_config{.name = std::string(tag),
                                    .port = config.messenger_port,
                                    .protocol_version = proudnet::messenger_protocol_version},
            *this)
{
}

std::shared_ptr<messenger_user> messenger_server::online(const std::string &username) const
{
    for (auto &u : m_users | std::views::values)
        if (u->account.username == username)
            return u;
    return nullptr;
}

std::shared_ptr<messenger_user> messenger_server::by_index(uint32_t index) const
{
    for (auto &u : m_users | std::views::values)
        if (u->account.index == index)
            return u;
    return nullptr;
}

void messenger_server::on_client_leave(proudnet::peer &client)
{
    auto it = m_users.find(client.id());
    if (it == m_users.end())
        return;
    auto user = it->second;
    m_users.erase(it);
    notify_friends_state(*user, state_offline);
    log::info(tag, "{} left the messenger", user->account.username);
}

bool messenger_server::on_rmi(proudnet::peer &client, uint16_t rmi_id, message_reader &r)
{
    if (rmi_id == clms::Logon_CLMS)
    {
        logon(client, r);
        return true;
    }
    if (rmi_id == clms::CL2MS_Test)
        return true;

    auto it = m_users.find(client.id());
    if (it == m_users.end())
        return rmi_id >= 2601 && rmi_id <= 2650; // swallow anything sent before login
    auto &u = *it->second;

    switch (rmi_id)
    {
    case clms::Change_Position:
        u.room = r.read_u16();
        u.position_a = r.read_u8();
        u.position_b = r.read_u8();
        return true;

    case clms::Add_Friend_Nick:
    case clms::Add_Friend_UserID: {
        r.read_u32();
        add_friend(u, r.read_string());
        return true;
    }

    case clms::Agree_Friend_Answer: {
        auto requester = r.read_string();
        auto accept = r.read_u8() != 0;
        answer_friend(u, requester, accept);
        return true;
    }

    case clms::Del_Friend: {
        r.read_u32();
        if (auto target = by_index(r.read_u32()))
            delete_friend(u, target->account.username);
        return true;
    }

    case clms::Del_Friend_UserID:
        delete_friend(u, r.read_string());
        return true;

    case clms::Whisper_UserIndex: {
        auto target = by_index(r.read_u32());
        auto text = r.read_string();
        auto flag = r.read_u8();
        whisper(u, target ? target->account.username : std::string{}, text, flag);
        return true;
    }

    case clms::Whisper_UserID: {
        auto target = r.read_string();
        auto text = r.read_string();
        auto flag = r.read_u8();
        whisper(u, target, text, flag);
        return true;
    }

    case clms::Invitation: {
        // Room invitation: forwarded as-is with the sender's name in place of the target's.
        auto target = r.read_string();
        auto room = r.read_u32();
        auto text = r.read_string();
        if (auto other = online(target))
        {
            auto w = rmi_begin(mscl::Invitation);
            w.write_text(u.account.username);
            w.write_u32(room);
            w.write_text(text);
            m_net.send(other->host, w);
        }
        else
        {
            auto w = rmi_begin(mscl::Invitation_Answer);
            w.write_text(target);
            w.write_u8(invitation_not_connected);
            m_net.send(u.host, w);
        }
        return true;
    }

    case clms::Invitation_Answer: {
        auto inviter = r.read_string();
        auto answer = r.read_u8();
        if (auto other = online(inviter))
        {
            auto w = rmi_begin(mscl::Invitation_Answer);
            w.write_text(u.account.username);
            w.write_u8(answer);
            m_net.send(other->host, w);
        }
        return true;
    }

    case clms::Send_Message:
    case clms::Send_Message_Id: {
        std::shared_ptr<messenger_user> target;
        std::string target_name;
        if (rmi_id == clms::Send_Message)
        {
            target = by_index(r.read_u32());
            target_name = target ? target->account.username : std::string{};
        }
        else
        {
            target_name = r.read_string();
            target = online(target_name);
        }
        auto text = r.read_string();

        // Mail is only delivered to players who are online right now (no mailbox storage yet).
        auto receiver_index = target ? target->account.index : 0;
        if (target)
        {
            auto w = rmi_begin(mscl::Send_Message);
            write_message_info(w, 1, receiver_index, u.account.username, text);
            w.write_u16(ok);
            m_net.send(target->host, w);
        }

        auto w = rmi_begin(mscl::Send_Message);
        write_message_info(w, 1, receiver_index, u.account.username, text);
        w.write_u16(target ? ok : 15); // 15 = "User name Not Found"
        m_net.send(u.host, w);
        return true;
    }

    case clms::Get_Message: {
        r.read_u16();
        auto w = rmi_begin(mscl::Message_Info);
        w.write_i32(0);
        w.write_u16(ok);
        m_net.send(u.host, w);
        return true;
    }

    case clms::Clan_List: {
        auto w = rmi_begin(mscl::Clan_List_Request);
        w.write_i32(0);
        w.write_u16(ok);
        m_net.send(u.host, w);
        return true;
    }

    case clms::Check_Clan_Name: {
        auto name = r.read_string();
        auto w = rmi_begin(mscl::Check_Clan_Name);
        w.write_text(name);
        w.write_u16(1); // non-zero = "This name is available."
        m_net.send(u.host, w);
        return true;
    }

    case clms::Create_Clan: {
        // Clans are not implemented yet: answer "failed" with empty structures.
        auto w = rmi_begin(mscl::Create_Clan);
        write_empty_clan_info(w);
        write_empty_clan_member_info(w);
        w.write_u32(0);
        write_empty_clan_board_info(w);
        w.write_u16(clan_create_failed);
        m_net.send(u.host, w);
        return true;
    }

    case clms::Join_Clan:
    case clms::Join_Clan_Name: {
        auto w = rmi_begin(mscl::Join_Clan);
        w.write_text({});
        w.write_u8(0);
        w.write_u8(0);
        write_message_info(w, 0, 0, {}, {});
        w.write_u32(0);
        w.write_u16(clan_join_not_found);
        m_net.send(u.host, w);
        return true;
    }

    case clms::Secede_Clan:
    case clms::Dissolve_Clan: {
        auto w = rmi_begin(rmi_id == clms::Secede_Clan ? mscl::Secede_Clan : mscl::Dissolve_Clan);
        w.write_u16(clan_not_member);
        m_net.send(u.host, w);
        return true;
    }

    case clms::RankInfo_Request: {
        auto w = rmi_begin(mscl::RankInfo_Answer);
        w.write_i32(0);
        w.write_i32(0);
        w.write_u32(0);
        w.write_u32(0);
        m_net.send(u.host, w);
        return true;
    }

    case clms::Find_User_Clan: {
        auto w = rmi_begin(mscl::Find_User_Clan_Answer);
        w.write_i32(0);
        m_net.send(u.host, w);
        return true;
    }

    default:
        // Remaining clan/board RMIs have nothing to act on without clans.
        return rmi_id >= 2601 && rmi_id <= 2650;
    }
}

void messenger_server::logon(proudnet::peer &client, message_reader &r)
{
    auto user = r.read_string();
    auto password = r.read_string();

    auto reply = [&](uint32_t index, uint16_t result) {
        // Logon_MSCL: u8 inClan, u32 myUserIndex, u8 hasNewMail, u16 (unused), u32 clanIndex, u16 result.
        auto w = rmi_begin(mscl::Logon_MSCL);
        w.write_u8(0);
        w.write_u32(index);
        w.write_u8(0);
        w.write_u16(0);
        w.write_u32(0);
        w.write_u16(result);
        client.send(w);
    };

    auto account = m_accounts.find(user);
    if (m_accounts.login(user, password) != app::login_result::ok || !account)
    {
        log::info(tag, "messenger login for {} failed", user);
        reply(0, 1); // any non-zero, non-2 result shows "Messenger server connection failed"
        return;
    }

    if (auto old = online(user))
        if (auto peer = m_net.find(old->host))
            peer->close();

    auto u = std::make_shared<messenger_user>();
    u->host = client.id();
    u->account = *account;
    m_users[u->host] = u;

    log::info(tag, "{} logged in to the messenger", user);
    reply(account->index, ok);

    // Friend list, then tell online friends we are here.
    auto &friends = m_friendships[user];
    auto w = rmi_begin(mscl::Add_Friend_Info);
    w.write_i32(static_cast<int32_t>(friends.size()));
    for (auto &f : friends)
        write_friend_info(w, f);
    w.write_u16(ok);
    client.send(w);

    notify_friends_state(*u, state_online);
}

void messenger_server::write_friend_info(message_writer &w, const std::string &username) const
{
    // FriendInfo: u16 roomNo, u32, u32 userIndex, String name, AvatarLook16, u8, u8 channel, u8, u8, u32, String, String.
    auto account = m_accounts.find(username);
    auto other = online(username);
    w.write_u16(other ? other->room : 0);
    w.write_u32(0);
    w.write_u32(account ? account->index : 0);
    w.write_text(username);
    w.write_u32(0); // AvatarLook16
    w.write_u16(0);
    w.write_u16(0);
    for (int i = 0; i < 8; ++i)
        w.write_u8(0);
    w.write_u8(other ? other->position_a : 0);
    w.write_u8(other ? other->position_b : 0);
    w.write_u8(other ? 1 : 0); // online flag (inferred)
    w.write_u8(0);
    w.write_u32(0);
    w.write_text({});
    w.write_text({});
}

void messenger_server::notify_friends_state(const messenger_user &u, uint16_t state)
{
    for (auto &f : m_friendships[u.account.username])
        if (auto other = online(f))
        {
            auto w = rmi_begin(mscl::Change_State);
            w.write_u32(u.host);
            w.write_u32(u.account.index);
            w.write_u16(state);
            m_net.send(other->host, w);
        }
}

void messenger_server::add_friend(messenger_user &u, const std::string &target)
{
    auto other = online(target);
    if (!other || target == u.account.username)
    {
        // Insert_Friend result 1 = "Friend addition failed".
        auto w = rmi_begin(mscl::Insert_Friend);
        w.write_u32(u.host);
        w.write_u32(0);
        write_friend_info(w, target);
        w.write_u16(1);
        m_net.send(u.host, w);
        return;
    }

    if (m_friendships[u.account.username].contains(target))
    {
        auto w = rmi_begin(mscl::Insert_Friend);
        w.write_u32(u.host);
        w.write_u32(other->account.index);
        write_friend_info(w, target);
        w.write_u16(9); // "Already registered"
        m_net.send(u.host, w);
        return;
    }

    // Ask the target: Agree_Friend(u32 requesterHost, String requesterName).
    other->pending_requests.insert(u.account.username);
    auto w = rmi_begin(mscl::Agree_Friend);
    w.write_u32(u.host);
    w.write_text(u.account.username);
    m_net.send(other->host, w);
}

void messenger_server::answer_friend(messenger_user &u, const std::string &requester, bool accept)
{
    if (!u.pending_requests.erase(requester))
        return;

    if (accept)
    {
        m_friendships[u.account.username].insert(requester);
        m_friendships[requester].insert(u.account.username);
    }

    // Answerer: Agree_Friend_AnswerResult(FriendInfo requester, u8 accepted, u16 result).
    auto w = rmi_begin(mscl::Agree_Friend_AnswerResult);
    write_friend_info(w, requester);
    w.write_u8(accept ? 1 : 0);
    w.write_u16(ok);
    m_net.send(u.host, w);

    // Requester: Insert_Friend(u32 host, u32 index, FriendInfo, u16 result) when accepted.
    if (auto other = online(requester); other && accept)
    {
        auto insert = rmi_begin(mscl::Insert_Friend);
        insert.write_u32(u.host);
        insert.write_u32(u.account.index);
        write_friend_info(insert, u.account.username);
        insert.write_u16(ok);
        m_net.send(other->host, insert);
    }
}

void messenger_server::delete_friend(messenger_user &u, const std::string &target)
{
    m_friendships[u.account.username].erase(target);
    m_friendships[target].erase(u.account.username);

    auto w = rmi_begin(mscl::Delete_Friend_UserID);
    w.write_text(target);
    w.write_u16(ok);
    m_net.send(u.host, w);
}

void messenger_server::whisper(messenger_user &u, const std::string &target, const std::string &text, uint8_t flag)
{
    auto other = online(target);
    if (!other)
    {
        auto w = rmi_begin(mscl::Whisper_Answer);
        w.write_text(target);
        w.write_u16(whisper_target_offline);
        m_net.send(u.host, w);
        return;
    }

    // Whisper_UserIndex(String from, String text, u8 flag).
    auto w = rmi_begin(mscl::Whisper_UserIndex);
    w.write_text(u.account.username);
    w.write_text(text);
    w.write_u8(flag);
    m_net.send(other->host, w);
}

} // namespace hovorun::messenger
