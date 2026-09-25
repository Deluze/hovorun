#pragma once

// Messenger server, TCP 24111: friends, whispers, mail and clans. The client connects after the game-server
// login and sends Logon_CLMS. Clans and mail are answered with empty data; friends and whispers work in memory.
// Wire layouts: docs/protocol/session_messenger.md §5-7.

#include "../app/accounts.hpp"
#include "../app/config.hpp"
#include "../proudnet/server.hpp"

#include <map>
#include <memory>
#include <set>
#include <string>

namespace hovorun::messenger
{

namespace clms
{
constexpr uint16_t Logon_CLMS = 2601;          // String userId, String password
constexpr uint16_t Load_Agree_User = 2602;     // u32, String
constexpr uint16_t Add_Friend_Nick = 2603;     // u32, String
constexpr uint16_t Add_Friend_UserID = 2604;   // u32, String
constexpr uint16_t Add_Friend_FriendID = 2605; // u32, u32
constexpr uint16_t Agree_Friend_Answer = 2606; // String requester, u8 accept
constexpr uint16_t Del_Friend = 2607;          // u32, u32
constexpr uint16_t Del_Friend_UserID = 2608;   // String
constexpr uint16_t Change_Position = 2609;     // u16 roomNo, u8, u8
constexpr uint16_t Whisper_UserIndex = 2610;   // u32 target index, String text, u8
constexpr uint16_t Whisper_UserID = 2611;      // String target, String text, u8
constexpr uint16_t Invitation = 2612;          // String target, u32, String
constexpr uint16_t Invitation_Answer = 2613;   // String, u8
constexpr uint16_t Send_Message = 2616;        // u32 receiver index, String text
constexpr uint16_t Send_Message_Id = 2617;     // String receiver, String text
constexpr uint16_t Get_Message = 2618;         // u16
constexpr uint16_t Delete_Message = 2619;      // u32
constexpr uint16_t Create_Clan = 2620;
constexpr uint16_t Join_Clan = 2621;
constexpr uint16_t Join_Clan_Name = 2622;
constexpr uint16_t Secede_Clan = 2623;
constexpr uint16_t Dissolve_Clan = 2624;
constexpr uint16_t Clan_List = 2627;           // -
constexpr uint16_t Clan_Chat = 2635;           // String
constexpr uint16_t Check_Clan_Name = 2636;     // String
constexpr uint16_t RankInfo_Request = 2644;    // -
constexpr uint16_t Find_User_Clan = 2649;      // String[]
constexpr uint16_t CL2MS_Test = 2650;          // u8
} // namespace clms

namespace mscl
{
constexpr uint16_t Logon_MSCL = 2701;
constexpr uint16_t Forced_Close = 2702;
constexpr uint16_t Change_State = 2706;
constexpr uint16_t Insert_Friend = 2707;
constexpr uint16_t Agree_Friend = 2708;
constexpr uint16_t Agree_Friend_AnswerResult = 2710;
constexpr uint16_t Delete_Friend_UserID = 2713;
constexpr uint16_t Add_Friend_Info = 2714;
constexpr uint16_t Whisper_UserIndex = 2715;
constexpr uint16_t Whisper_Answer = 2716;
constexpr uint16_t Invitation = 2717;
constexpr uint16_t Invitation_Answer = 2718;
constexpr uint16_t Send_Message = 2720;
constexpr uint16_t Create_Clan = 2722;
constexpr uint16_t Join_Clan = 2723;
constexpr uint16_t Secede_Clan = 2727;
constexpr uint16_t Dissolve_Clan = 2729;
constexpr uint16_t Message_Info = 2735;
constexpr uint16_t Clan_List_Request = 2741;
constexpr uint16_t Check_Clan_Name = 2744;
constexpr uint16_t RankInfo_Answer = 2759;
constexpr uint16_t Find_User_Clan_Answer = 2763;
} // namespace mscl

struct messenger_user
{
    proudnet::host_id host = 0;
    app::account account;
    uint16_t room = 0;
    uint8_t position_a = 0;
    uint8_t position_b = 0;
    std::set<std::string> pending_requests; // usernames that asked to befriend this user
};

class messenger_server : public proudnet::event_sink
{
public:
    messenger_server(asio::io_context &io, const app::config &config, app::account_store &accounts);

    void start() { m_net.start(); }
    void stop() { m_net.stop(); }

    void on_client_leave(proudnet::peer &client) override;
    bool on_rmi(proudnet::peer &client, uint16_t rmi_id, net::message_reader &params) override;

private:
    void logon(proudnet::peer &client, net::message_reader &r);
    void add_friend(messenger_user &u, const std::string &target);
    void answer_friend(messenger_user &u, const std::string &requester, bool accept);
    void delete_friend(messenger_user &u, const std::string &target);
    void whisper(messenger_user &u, const std::string &target, const std::string &text, uint8_t flag);
    void notify_friends_state(const messenger_user &u, uint16_t state);

    void write_friend_info(net::message_writer &w, const std::string &username) const;
    std::shared_ptr<messenger_user> online(const std::string &username) const;
    std::shared_ptr<messenger_user> by_index(uint32_t index) const;

    app::account_store &m_accounts;
    proudnet::server m_net;
    std::map<proudnet::host_id, std::shared_ptr<messenger_user>> m_users;
    std::map<std::string, std::set<std::string>> m_friendships; // in-memory, lost on restart
};

} // namespace hovorun::messenger
