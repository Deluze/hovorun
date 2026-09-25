#pragma once

// Session (login) server, TCP 23111. The client logs in with the command-line credentials and gets the
// game server address back (SSCL User_Logon_SSCL). See docs/protocol/session_messenger.md.

#include "../app/accounts.hpp"
#include "../app/config.hpp"
#include "../proudnet/server.hpp"

#include <map>
#include <string>

namespace hovorun::session
{

namespace clss
{
constexpr uint16_t Logon_CLSS = 1201;     // String userId, String password
constexpr uint16_t Change_Nation = 1202;  // u8 nation
constexpr uint16_t Logout_CLSS = 1203;    // -
} // namespace clss

namespace sscl
{
constexpr uint16_t User_Logon_SSCL = 2301; // u8 nation (1-based), String ip, u16 port, u16 result
constexpr uint16_t Change_Nation = 2302;   // same params as User_Logon_SSCL
constexpr uint16_t Forced_Close = 2303;    // u16 reason

// User_Logon_SSCL result codes and the client message they show.
enum class logon_result : uint16_t
{
    ok = 0,
    repeated_login = 2,   // msg 61 "Repeated login attempts"
    visit_website = 3,    // msg 62
    visit_website_2 = 10, // msg 60
    wrong_password = 11,  // msg 59 "Wrong Password. Try again."
};

// Forced_Close reason 2 shows "Someone is trying to play Hovorun using your username".
constexpr uint16_t forced_close_duplicate_login = 2;
} // namespace sscl

class session_server : public proudnet::event_sink
{
public:
    session_server(asio::io_context &io, const app::config &config, app::account_store &accounts);

    void start() { m_net.start(); }
    void stop() { m_net.stop(); }

    void on_client_leave(proudnet::peer &client) override;
    bool on_rmi(proudnet::peer &client, uint16_t rmi_id, net::message_reader &params) override;

private:
    void logon(proudnet::peer &client, const std::string &user, const std::string &password);
    void send_logon_answer(proudnet::peer &client, uint16_t rmi, uint8_t nation, sscl::logon_result result);

    const app::config &m_config;
    app::account_store &m_accounts;
    proudnet::server m_net;
    std::map<std::string, proudnet::host_id> m_online; // username -> session HostID
};

} // namespace hovorun::session
