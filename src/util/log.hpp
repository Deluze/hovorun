#pragma once

#include <algorithm>
#include <chrono>
#include <iterator>
#include <ranges>
#include <cstdint>
#include <format>
#include <mutex>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace hovorun::log
{

enum class level
{
    debug,
    info,
    warn,
    error,
};

inline level &min_level()
{
    static level l = level::info;
    return l;
}

inline std::mutex &mutex()
{
    static std::mutex m;
    return m;
}

constexpr std::string_view name(level l)
{
    switch (l)
    {
    case level::debug:
        return "DBG";
    case level::info:
        return "INF";
    case level::warn:
        return "WRN";
    default:
        return "ERR";
    }
}

inline level parse_level(std::string_view s)
{
    if (s == "debug")
        return level::debug;
    if (s == "warn")
        return level::warn;
    if (s == "error")
        return level::error;
    return level::info;
}

template <typename... Args>
void write(level l, std::string_view tag, std::format_string<Args...> fmt, Args &&...args)
{
    if (l < min_level())
        return;

    auto now = std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto text = std::format(fmt, std::forward<Args>(args)...);

    std::lock_guard lock(mutex());
    std::println("{:%H:%M:%S} {} [{}] {}", now, name(l), tag, text);
}

template <typename... Args>
void debug(std::string_view tag, std::format_string<Args...> fmt, Args &&...args)
{
    write(level::debug, tag, fmt, std::forward<Args>(args)...);
}
template <typename... Args>
void info(std::string_view tag, std::format_string<Args...> fmt, Args &&...args)
{
    write(level::info, tag, fmt, std::forward<Args>(args)...);
}
template <typename... Args>
void warn(std::string_view tag, std::format_string<Args...> fmt, Args &&...args)
{
    write(level::warn, tag, fmt, std::forward<Args>(args)...);
}
template <typename... Args>
void error(std::string_view tag, std::format_string<Args...> fmt, Args &&...args)
{
    write(level::error, tag, fmt, std::forward<Args>(args)...);
}

// Hex dump used when logging unknown or unhandled messages.
inline std::string hex(std::span<const uint8_t> data, size_t max = 256)
{
    std::string out;
    auto shown = data.first(std::min(data.size(), max));
    for (size_t i = 0; i < shown.size(); ++i)
        std::format_to(std::back_inserter(out), "{}{:02x}", i ? " " : "", shown[i]);
    if (shown.size() < data.size())
        out += " ...";
    return out;
}

} // namespace hovorun::log
