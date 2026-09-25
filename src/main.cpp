// Hovorun server: session (login), messenger and game servers in one process, compatible with the stock
// Client5.exe (old ProudNet protocol). Usage: hovorun_server [path/to/server.ini]

#include "app/accounts.hpp"
#include "app/config.hpp"
#include "game/game_server.hpp"
#include "messenger/messenger_server.hpp"
#include "session/session_server.hpp"
#include "util/log.hpp"

#include <asio.hpp>

#include <csignal>
#include <exception>
#include <filesystem>

using namespace hovorun;

int main(int argc, char **argv)
{
    std::filesystem::path ini_path = argc > 1 ? argv[1] : "server.ini";

    app::config config;
    if (auto ini = app::ini_file::load(ini_path))
        config = app::config::from(*ini);
    else
        log::warn("main", "{}; using defaults", ini.error());

    log::min_level() = log::parse_level(config.log_level);

    try
    {
        asio::io_context io;
        app::account_store accounts(config.accounts_file, config.auto_register);

        session::session_server session(io, config, accounts);
        messenger::messenger_server messenger(io, config, accounts);
        game::game_server game(io, config, accounts);

        session.start();
        messenger.start();
        game.start();
        log::info("main", "game server address sent to clients: {}:{}", config.game_public_ip, config.game_port);

        asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait([&](asio::error_code, int) {
            log::info("main", "shutting down");
            session.stop();
            messenger.stop();
            game.stop();
            io.stop();
        });

        io.run();
    }
    catch (const std::exception &e)
    {
        log::error("main", "fatal: {}", e.what());
        return 1;
    }

    return 0;
}
