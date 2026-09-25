#pragma once

// Tiny INI reader for config/server.ini: [section] headers, key=value lines, ';' or '#' comments.

#include <charconv>
#include <cstdint>
#include <format>
#include <expected>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <string_view>

namespace hovorun::app
{

class ini_file
{
public:
    static std::expected<ini_file, std::string> load(const std::filesystem::path &path)
    {
        std::ifstream in(path);
        if (!in)
            return std::unexpected(std::format("cannot open {}", path.string()));

        ini_file ini;
        std::string section;
        for (std::string line; std::getline(in, line);)
        {
            auto text = trim(line);
            if (text.empty() || text.starts_with(';') || text.starts_with('#'))
                continue;

            if (text.starts_with('[') && text.ends_with(']'))
            {
                section = trim(text.substr(1, text.size() - 2));
                continue;
            }

            if (auto eq = text.find('='); eq != std::string_view::npos)
                ini.m_values[section + "." + std::string(trim(text.substr(0, eq)))] = trim(text.substr(eq + 1));
        }
        return ini;
    }

    [[nodiscard]] std::string get(std::string_view key, std::string_view fallback = {}) const
    {
        auto it = m_values.find(std::string(key));
        return it == m_values.end() ? std::string(fallback) : it->second;
    }

    template <typename T>
    [[nodiscard]] T get_number(std::string_view key, T fallback) const
    {
        auto text = get(key);
        T value{};
        auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
        return ec == std::errc{} && ptr == text.data() + text.size() ? value : fallback;
    }

private:
    static std::string_view trim(std::string_view s)
    {
        auto begin = s.find_first_not_of(" \t\r\n");
        if (begin == std::string_view::npos)
            return {};
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(begin, end - begin + 1);
    }

    std::map<std::string, std::string> m_values;
};

// Values the servers need, with defaults that match the stock client (cliconfg.inp).
struct config
{
    uint16_t session_port = 23111;
    uint16_t messenger_port = 24111;
    uint16_t game_port = 25111;
    std::string game_public_ip = "127.0.0.1";
    std::filesystem::path accounts_file = "accounts.txt";
    bool auto_register = true;
    std::string log_level = "info";

    static config from(const ini_file &ini)
    {
        config c;
        c.session_port = ini.get_number<uint16_t>("session.port", c.session_port);
        c.messenger_port = ini.get_number<uint16_t>("messenger.port", c.messenger_port);
        c.game_port = ini.get_number<uint16_t>("game.port", c.game_port);
        c.game_public_ip = ini.get("game.public_ip", c.game_public_ip);
        c.accounts_file = ini.get("accounts.file", c.accounts_file.string());
        c.auto_register = ini.get("accounts.auto_register", "true") == "true";
        c.log_level = ini.get("log.level", c.log_level);
        return c;
    }
};

} // namespace hovorun::app
