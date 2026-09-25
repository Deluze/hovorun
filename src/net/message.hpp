#pragma once

#include <array>
#include <bit>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace hovorun::net
{

// Thrown when a message is shorter than what a reader asked for.
struct message_underflow : std::runtime_error
{
    message_underflow() : std::runtime_error("message underflow") {}
};

// ProudNet string type byte that precedes every serialized string.
enum class string_type : uint8_t
{
    ansi = 1,
    unicode = 2,
};

// Anything that is copied to the wire as its raw little-endian bytes.
template <typename T>
concept wire_scalar = (std::is_arithmetic_v<T> || std::is_enum_v<T>) && !std::same_as<T, bool>;

static_assert(std::endian::native == std::endian::little, "the wire format is little-endian; add byteswaps");

// Byte-level writer mirroring Proud::CMessage's write side.
class message_writer
{
public:
    message_writer() { m_data.reserve(64); }

    [[nodiscard]] std::span<const uint8_t> bytes() const { return m_data; }
    [[nodiscard]] size_t size() const { return m_data.size(); }

    // Deducing this: returns the buffer by reference from an lvalue writer, or moves it out of an rvalue.
    template <typename Self>
    [[nodiscard]] auto &&data(this Self &&self)
    {
        return std::forward<Self>(self).m_data;
    }

    void write_bytes(std::span<const uint8_t> src) { m_data.insert(m_data.end(), src.begin(), src.end()); }
    void write_bytes(const void *src, size_t count) { write_bytes({static_cast<const uint8_t *>(src), count}); }

    template <wire_scalar T>
    void write(T value)
    {
        auto raw = std::bit_cast<std::array<uint8_t, sizeof(T)>>(value);
        m_data.insert(m_data.end(), raw.begin(), raw.end());
    }

    void write_u8(uint8_t v) { write(v); }
    void write_u16(uint16_t v) { write(v); }
    void write_u32(uint32_t v) { write(v); }
    void write_i32(int32_t v) { write(v); }
    void write_u64(uint64_t v) { write(v); }
    void write_i64(int64_t v) { write(v); }
    void write_f32(float v) { write(v); }
    void write_f64(double v) { write(v); }
    void write_bool(bool v) { write_u8(v ? 1 : 0); }

    // Proud "compact scalar": a size byte (1, 2, 4 or 8) followed by the signed value in that many bytes.
    void write_scalar(int64_t v)
    {
        if (std::in_range<int8_t>(v))
        {
            write_u8(1);
            write(static_cast<int8_t>(v));
        }
        else if (std::in_range<int16_t>(v))
        {
            write_u8(2);
            write(static_cast<int16_t>(v));
        }
        else if (std::in_range<int32_t>(v))
        {
            write_u8(4);
            write(static_cast<int32_t>(v));
        }
        else
        {
            write_u8(8);
            write(v);
        }
    }

    // ANSI string: type byte 1, scalar char count, raw bytes (no terminator).
    void write_string(std::string_view s)
    {
        write(string_type::ansi);
        write_scalar(std::ssize(s));
        write_bytes(s.data(), s.size());
    }

    // Unicode string: type byte 2, scalar char count, UTF-16LE code units.
    void write_wstring(std::u16string_view s)
    {
        write(string_type::unicode);
        write_scalar(std::ssize(s));
        write_bytes(s.data(), s.size() * sizeof(char16_t));
    }

    // UTF-8 text sent as a unicode ProudNet string. The client itself always sends type 2 strings, so we
    // answer the same way to round-trip Korean/other non-ASCII names without a code page guess.
    void write_text(std::string_view utf8) { write_wstring(utf8_to_utf16(utf8)); }

    static std::u16string utf8_to_utf16(std::string_view s)
    {
        std::u16string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size();)
        {
            auto b = static_cast<uint8_t>(s[i]);
            char32_t c;
            size_t extra;
            if (b < 0x80)
                c = b, extra = 0;
            else if ((b & 0xE0) == 0xC0)
                c = b & 0x1F, extra = 1;
            else if ((b & 0xF0) == 0xE0)
                c = b & 0x0F, extra = 2;
            else
                c = b & 0x07, extra = 3;

            ++i;
            for (size_t k = 0; k < extra && i < s.size(); ++k, ++i)
                c = (c << 6) | (static_cast<uint8_t>(s[i]) & 0x3F);

            if (c >= 0x10000)
            {
                c -= 0x10000;
                out += static_cast<char16_t>(0xD800 + (c >> 10));
                out += static_cast<char16_t>(0xDC00 + (c & 0x3FF));
            }
            else
                out += static_cast<char16_t>(c);
        }
        return out;
    }

    // Proud::ByteArray: scalar length then raw bytes.
    void write_byte_array(std::span<const uint8_t> bytes)
    {
        write_scalar(std::ssize(bytes));
        write_bytes(bytes);
    }

    void write_guid(std::span<const uint8_t, 16> guid) { write_bytes(guid); }

private:
    std::vector<uint8_t> m_data;
};

// Byte-level reader mirroring Proud::CMessage's read side.
class message_reader
{
public:
    explicit message_reader(std::span<const uint8_t> data) : m_data(data) {}

    [[nodiscard]] size_t offset() const { return m_offset; }
    [[nodiscard]] size_t size() const { return m_data.size(); }
    [[nodiscard]] size_t remaining() const { return m_data.size() - m_offset; }
    [[nodiscard]] bool at_end() const { return m_offset >= m_data.size(); }
    [[nodiscard]] std::span<const uint8_t> rest() const { return m_data.subspan(m_offset); }

    void skip(size_t count) { take(count); }

    std::span<const uint8_t> take(size_t count)
    {
        if (count > remaining())
            throw message_underflow{};
        auto out = m_data.subspan(m_offset, count);
        m_offset += count;
        return out;
    }

    void read_bytes(void *dst, size_t count)
    {
        auto src = take(count);
        std::memcpy(dst, src.data(), count);
    }

    template <wire_scalar T>
    T read()
    {
        std::array<uint8_t, sizeof(T)> raw;
        read_bytes(raw.data(), raw.size());
        return std::bit_cast<T>(raw);
    }

    uint8_t read_u8() { return read<uint8_t>(); }
    uint16_t read_u16() { return read<uint16_t>(); }
    uint32_t read_u32() { return read<uint32_t>(); }
    int32_t read_i32() { return read<int32_t>(); }
    uint64_t read_u64() { return read<uint64_t>(); }
    int64_t read_i64() { return read<int64_t>(); }
    float read_f32() { return read<float>(); }
    double read_f64() { return read<double>(); }
    bool read_bool() { return read_u8() != 0; }

    int64_t read_scalar()
    {
        switch (read_u8())
        {
        case 1:
            return read<int8_t>();
        case 2:
            return read<int16_t>();
        case 4:
            return read<int32_t>();
        case 8:
            return read<int64_t>();
        default:
            throw std::runtime_error("bad compact scalar prefix");
        }
    }

    size_t read_length()
    {
        auto length = read_scalar();
        if (length < 0 || std::cmp_greater(length, remaining()))
            throw message_underflow{};
        return static_cast<size_t>(length);
    }

    // Reads either string flavour; unicode strings are converted to UTF-8.
    std::string read_string()
    {
        auto type = read<string_type>();
        auto length = read_scalar();
        if (length < 0)
            throw std::runtime_error("negative string length");

        if (type == string_type::unicode)
        {
            std::u16string w(static_cast<size_t>(length), u'\0');
            read_bytes(w.data(), w.size() * sizeof(char16_t));
            return utf16_to_utf8(w);
        }

        auto raw = take(static_cast<size_t>(length));
        return {raw.begin(), raw.end()};
    }

    std::vector<uint8_t> read_byte_array()
    {
        auto raw = take(read_length());
        return {raw.begin(), raw.end()};
    }

    std::array<uint8_t, 16> read_guid()
    {
        std::array<uint8_t, 16> guid;
        read_bytes(guid.data(), guid.size());
        return guid;
    }

    static std::string utf16_to_utf8(std::u16string_view w)
    {
        std::string out;
        out.reserve(w.size());
        for (size_t i = 0; i < w.size(); ++i)
        {
            char32_t c = w[i];
            if (c >= 0xD800 && c <= 0xDBFF && i + 1 < w.size() && w[i + 1] >= 0xDC00 && w[i + 1] <= 0xDFFF)
                c = 0x10000 + ((c - 0xD800) << 10) + (w[++i] - 0xDC00);

            if (c < 0x80)
                out += static_cast<char>(c);
            else if (c < 0x800)
                out += {static_cast<char>(0xC0 | (c >> 6)), static_cast<char>(0x80 | (c & 0x3F))};
            else if (c < 0x10000)
                out += {static_cast<char>(0xE0 | (c >> 12)), static_cast<char>(0x80 | ((c >> 6) & 0x3F)),
                        static_cast<char>(0x80 | (c & 0x3F))};
            else
                out += {static_cast<char>(0xF0 | (c >> 18)), static_cast<char>(0x80 | ((c >> 12) & 0x3F)),
                        static_cast<char>(0x80 | ((c >> 6) & 0x3F)), static_cast<char>(0x80 | (c & 0x3F))};
        }
        return out;
    }

private:
    std::span<const uint8_t> m_data;
    size_t m_offset = 0;
};

} // namespace hovorun::net
