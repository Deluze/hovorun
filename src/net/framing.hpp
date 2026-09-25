#pragma once

#include "message.hpp"

#include <cstdint>
#include <expected>
#include <span>
#include <utility>
#include <vector>

namespace hovorun::net
{

// Every ProudNet TCP frame starts with this 16-bit little-endian magic (bytes 13 57 on the wire).
constexpr uint16_t frame_magic = 0x5713;

// Largest payload we accept from a client. Matches the client's default MessageMaxLength (global 0x9e6a88).
constexpr size_t max_frame_payload = 0x100000;

// Wraps a payload into a TCP frame: magic, compact scalar length, payload.
inline std::vector<uint8_t> make_frame(std::span<const uint8_t> payload)
{
    message_writer w;
    w.write_u16(frame_magic);
    w.write_scalar(std::ssize(payload));
    w.write_bytes(payload);
    return std::move(w).data();
}

enum class frame_error
{
    incomplete, // not an error: wait for more bytes
    bad_magic,
    bad_length,
};

// Incremental splitter for the TCP byte stream.
class frame_parser
{
public:
    void feed(std::span<const uint8_t> data) { m_buffer.insert(m_buffer.end(), data.begin(), data.end()); }

    // Returns the next complete payload, frame_error::incomplete when more bytes are needed, or a fatal error.
    std::expected<std::vector<uint8_t>, frame_error> next()
    {
        // Magic (2) + scalar prefix (1) is the smallest header.
        if (m_buffer.size() < 3)
            return std::unexpected(frame_error::incomplete);

        if (auto magic = static_cast<uint16_t>(m_buffer[0] | (m_buffer[1] << 8)); magic != frame_magic)
            return std::unexpected(frame_error::bad_magic);

        size_t scalar_size = m_buffer[2];
        if (scalar_size != 1 && scalar_size != 2 && scalar_size != 4 && scalar_size != 8)
            return std::unexpected(frame_error::bad_length);

        size_t header = 3 + scalar_size;
        if (m_buffer.size() < header)
            return std::unexpected(frame_error::incomplete);

        message_reader r(std::span(m_buffer).subspan(2, header - 2));
        int64_t length = r.read_scalar();
        if (length < 0 || std::cmp_greater(length, max_frame_payload))
            return std::unexpected(frame_error::bad_length);

        size_t total = header + static_cast<size_t>(length);
        if (m_buffer.size() < total)
            return std::unexpected(frame_error::incomplete);

        std::vector<uint8_t> payload(m_buffer.begin() + header, m_buffer.begin() + total);
        m_buffer.erase(m_buffer.begin(), m_buffer.begin() + total);
        return payload;
    }

private:
    std::vector<uint8_t> m_buffer;
};

} // namespace hovorun::net
