#pragma once

// Account store shared by the session and game servers. Backed by a plain text file of "username password"
// lines; new accounts can be created on first login.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>

namespace hovorun::app
{

struct account
{
    uint32_t index = 0; // stable per-account number (line order), used as the game's user index
    std::string username;
    std::string password;
};

enum class login_result
{
    ok,
    wrong_password,
    unknown_user,
};

class account_store
{
public:
    account_store(std::filesystem::path file, bool auto_register)
        : m_file(std::move(file)), m_auto_register(auto_register)
    {
        std::ifstream in(m_file);
        for (std::string user, pass; in >> user >> pass;)
            add(user, pass);
    }

    login_result login(const std::string &username, const std::string &password)
    {
        if (auto it = m_accounts.find(username); it != m_accounts.end())
            return it->second.password == password ? login_result::ok : login_result::wrong_password;

        if (!m_auto_register || username.empty() || username.contains(' ') || password.contains(' '))
            return login_result::unknown_user;

        add(username, password);
        std::ofstream(m_file, std::ios::app) << username << ' ' << password << '\n';
        return login_result::ok;
    }

    [[nodiscard]] std::optional<account> find(const std::string &username) const
    {
        auto it = m_accounts.find(username);
        return it == m_accounts.end() ? std::nullopt : std::optional(it->second);
    }

private:
    void add(const std::string &username, const std::string &password)
    {
        m_accounts.try_emplace(username, account{static_cast<uint32_t>(m_accounts.size() + 1), username, password});
    }

    std::filesystem::path m_file;
    bool m_auto_register;
    std::map<std::string, account> m_accounts;
};

} // namespace hovorun::app
