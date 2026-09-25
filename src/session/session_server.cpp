#include "session_server.hpp"

#include "../proudnet/rmi.hpp"
#include "../util/log.hpp"

namespace hovorun::session
{

namespace
{
constexpr std::string_view tag = "session";

struct session_user
{
    std::string username;
    uint8_t nation = 1;
};
} // namespace

session_server::session_server(asio::io_context &io, const app::config &config, app::account_store &accounts)
    : m_config(config), m_accounts(accounts),
      m_net(io,
            proudnet::server_config{.name = std::string(tag),
                                    .port = config.session_port,
                                    .protocol_version = proudnet::session_protocol_version},
            *this)
{
}

void session_server::on_client_leave(proudnet::peer &client)
{
    if (auto user = std::static_pointer_cast<session_user>(client.user_data))
        if (auto it = m_online.find(user->username); it != m_online.end() && it->second == client.id())
            m_online.erase(it);
}

bool session_server::on_rmi(proudnet::peer &client, uint16_t rmi_id, net::message_reader &params)
{
    switch (rmi_id)
    {
    case clss::Logon_CLSS: {
        auto user = params.read_string();
        auto password = params.read_string();
        logon(client, user, password);
        return true;
    }

    case clss::Change_Nation: {
        auto nation = params.read_u8();
        auto user = std::static_pointer_cast<session_user>(client.user_data);
        if (!user)
            return true;
        // The client sends a 0-based index and expects the 1-based value back (it stores value - 1).
        user->nation = static_cast<uint8_t>(nation + 1);
        log::info(tag, "{} changes nation to {}", user->username, nation);
        send_logon_answer(client, sscl::Change_Nation, user->nation, sscl::logon_result::ok);
        return true;
    }

    case clss::Logout_CLSS:
        client.close();
        return true;

    default:
        return false;
    }
}

void session_server::logon(proudnet::peer &client, const std::string &user, const std::string &password)
{
    switch (m_accounts.login(user, password))
    {
    case app::login_result::wrong_password:
        log::info(tag, "login for {} failed: wrong password", user);
        send_logon_answer(client, sscl::User_Logon_SSCL, 1, sscl::logon_result::wrong_password);
        return;
    case app::login_result::unknown_user:
        log::info(tag, "login for {} failed: unknown user", user);
        send_logon_answer(client, sscl::User_Logon_SSCL, 1, sscl::logon_result::wrong_password);
        return;
    case app::login_result::ok:
        break;
    }

    // Kick an older session of the same account.
    if (auto it = m_online.find(user); it != m_online.end() && it->second != client.id())
    {
        if (auto old = m_net.find(it->second))
        {
            auto kick = proudnet::rmi_begin(sscl::Forced_Close);
            kick.write_u16(sscl::forced_close_duplicate_login);
            old->send(kick);
        }
    }

    m_online[user] = client.id();
    client.user_data = std::make_shared<session_user>(session_user{.username = user});
    log::info(tag, "{} logged in, sending game server {}:{}", user, m_config.game_public_ip, m_config.game_port);
    send_logon_answer(client, sscl::User_Logon_SSCL, 1, sscl::logon_result::ok);
}

void session_server::send_logon_answer(proudnet::peer &client, uint16_t rmi, uint8_t nation,
                                       sscl::logon_result result)
{
    auto w = proudnet::rmi_begin(rmi);
    w.write_u8(nation);
    w.write_text(m_config.game_public_ip);
    w.write_u16(m_config.game_port);
    w.write_u16(std::to_underlying(result));
    client.send(w);
}

} // namespace hovorun::session
