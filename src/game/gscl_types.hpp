#pragma once

// Structs carried by the GSCL (game server -> client) RMIs. Field order below is WIRE order, which does not
// always match the client's in-memory order. Layouts reversed from Client5.exe; see docs/protocol/game_s2c.md.

#include "../net/message.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace hovorun::game
{

using host_id = uint32_t;

// GSCL arrays use a raw i32 element count (not a compact scalar). The client rejects counts >= 0x100000.
template <typename T, typename F>
void write_array(net::message_writer &w, const std::vector<T> &items, F &&write_one)
{
    w.write_i32(static_cast<int32_t>(items.size()));
    for (const auto &item : items)
        write_one(w, item);
}

// Reader 0x55dcf0. Only `need_select_character` (last field) and `exp` are known to change client behaviour.
struct logon_info
{
    uint32_t user_index = 0;        // #1  +0x04
    std::string nickname;           // #2  +0x08 (inferred)
    uint16_t unk_0c = 0;            // #3  +0x0c
    uint32_t exp = 0;               // #4  +0x10 converted to a level by the client (inferred)
    uint32_t money = 0;             // #5  +0x14 (inferred)
    uint32_t unk_18 = 0;            // #6  +0x18
    host_id host = 0;               // #7  +0x4c
    uint8_t unk_50 = 0;             // #8  +0x50
    uint32_t unk_1c = 0;            // #9  +0x1c
    uint32_t unk_20 = 0;            // #10 +0x20
    uint32_t unk_24 = 0;            // #11 +0x24
    uint32_t unk_28 = 0;            // #12 +0x28 copied to a global
    uint32_t unk_2c = 0;            // #13 +0x2c copied to a global
    uint32_t unk_30 = 0;            // #14 +0x30 copied to a global
    uint32_t unk_34 = 0;            // #15 +0x34 copied to a global
    uint32_t unk_38 = 0;            // #16 +0x38
    uint16_t unk_3c = 0;            // #17 +0x3c
    std::string str_40;             // #18 +0x40
    std::string str_44;             // #19 +0x44
    uint8_t need_select_character = 0; // #20 +0x48: 0 -> channel select, !=0 -> character select

    void write(net::message_writer &w) const
    {
        w.write_u32(user_index);
        w.write_text(nickname);
        w.write_u16(unk_0c);
        w.write_u32(exp);
        w.write_u32(money);
        w.write_u32(unk_18);
        w.write_u32(host);
        w.write_u8(unk_50);
        w.write_u32(unk_1c);
        w.write_u32(unk_20);
        w.write_u32(unk_24);
        w.write_u32(unk_28);
        w.write_u32(unk_2c);
        w.write_u32(unk_30);
        w.write_u32(unk_34);
        w.write_u32(unk_38);
        w.write_u16(unk_3c);
        w.write_text(str_40);
        w.write_text(str_44);
        w.write_u8(need_select_character);
    }
};

// Reader 0x55e000.
struct item_info
{
    std::string str_48;   // #1
    uint32_t item_id = 0; // #2 +0x08 (inferred)
    uint32_t item_code = 0; // #3 +0x0c (inferred)
    std::string str_10;   // #4
    uint16_t u16_14 = 0;  // #5
    uint16_t u16_16 = 0;  // #6
    uint16_t u16_18 = 0;  // #7
    uint32_t u32_1c = 0;  // #8
    uint32_t u32_20 = 0;  // #9
    double f64_28 = 0;    // #10 (probably a date as OLE VARIANT time)
    uint32_t u32_30 = 0;  // #11
    uint32_t u32_34 = 0;  // #12
    uint16_t u16_1a = 0;  // #13
    uint8_t u8_38 = 0;    // #14
    uint8_t u8_39 = 0;    // #15
    std::string str_3c;   // #16
    std::string str_40;   // #17
    uint32_t u32_44 = 0;  // #18

    void write(net::message_writer &w) const
    {
        w.write_text(str_48);
        w.write_u32(item_id);
        w.write_u32(item_code);
        w.write_text(str_10);
        w.write_u16(u16_14);
        w.write_u16(u16_16);
        w.write_u16(u16_18);
        w.write_u32(u32_1c);
        w.write_u32(u32_20);
        w.write_f64(f64_28);
        w.write_u32(u32_30);
        w.write_u32(u32_34);
        w.write_u16(u16_1a);
        w.write_u8(u8_38);
        w.write_u8(u8_39);
        w.write_text(str_3c);
        w.write_text(str_40);
        w.write_u32(u32_44);
    }
};

// Reader 0x55f180.
struct gift_info
{
    uint32_t u32_04 = 0, u32_08 = 0, u32_0c = 0, u32_10 = 0;
    uint16_t u16_14 = 0;
    uint32_t u32_18 = 0, u32_1c = 0;
    std::string str_20, str_24, str_28, str_2c, str_30;

    void write(net::message_writer &w) const
    {
        w.write_u32(u32_04);
        w.write_u32(u32_08);
        w.write_u32(u32_0c);
        w.write_u32(u32_10);
        w.write_u16(u16_14);
        w.write_u32(u32_18);
        w.write_u32(u32_1c);
        w.write_text(str_20);
        w.write_text(str_24);
        w.write_text(str_28);
        w.write_text(str_2c);
        w.write_text(str_30);
    }
};

// Reader 0x587b30.
struct channel_user
{
    std::string nickname;  // +0x04 (inferred)
    uint32_t u32_08 = 0;
    uint8_t u8_1a = 0;
    uint32_t u32_0c = 0;
    uint32_t u32_10 = 0;
    host_id host = 0;      // +0x14
    uint16_t u16_18 = 0;
    std::string str_1c;

    void write(net::message_writer &w) const
    {
        w.write_text(nickname);
        w.write_u32(u32_08);
        w.write_u8(u8_1a);
        w.write_u32(u32_0c);
        w.write_u32(u32_10);
        w.write_u32(host);
        w.write_u16(u16_18);
        w.write_text(str_1c);
    }
};

// Reader 0x587df0. The client only uses users (#1), capacity (#2) and index (#8, 0..5).
struct channel_info
{
    uint32_t users = 0;     // #1 +0x04 (inferred: current users)
    uint32_t capacity = 0;  // #2 +0x08 (inferred: max users)
    uint32_t u32_0c = 0;    // #3
    uint32_t u32_10 = 0;    // #4
    uint32_t u32_14 = 0;    // #5
    uint8_t u8_18 = 0;      // #6
    uint8_t u8_19 = 0;      // #7
    uint8_t index = 0;      // #8 +0x1a channel slot 0..5
    uint8_t u8_1b = 0;      // #9

    void write(net::message_writer &w) const
    {
        w.write_u32(users);
        w.write_u32(capacity);
        w.write_u32(u32_0c);
        w.write_u32(u32_10);
        w.write_u32(u32_14);
        w.write_u8(u8_18);
        w.write_u8(u8_19);
        w.write_u8(index);
        w.write_u8(u8_1b);
    }
};

// Reader 0x55e800.
struct room_info
{
    uint16_t number = 0;        // #1  +0x04 room number
    uint16_t u16_06 = 0;        // #2  +0x06
    uint16_t u16_08 = 0;        // #3  +0x08 copied to a global by Create_Room
    uint8_t players = 0;        // #4  +0x0a current players (inferred)
    uint8_t max_players = 0;    // #5  +0x0b enabled slots out of 8
    uint8_t map = 0;            // #6  +0x0c map code
    uint8_t mode = 0;           // #7  +0x0d (inferred: game mode, same global as Start_Game a)
    uint8_t max_lap = 0;        // #8  +0x0f (confirmed "MaxLap is")
    uint8_t u8_0e = 0;          // #9  +0x0e
    std::string title;          // #10 +0x10
    std::string password;       // #11 +0x14
    std::string str_18;         // #12 +0x18
    uint8_t state = 0;          // #13 +0x1c room state (inferred)
    uint8_t u8_26 = 0;          // #14 +0x26
    uint8_t u8_27 = 0;          // #15 +0x27
    std::array<uint8_t, 8> slots{}; // #16..23 +0x1d..+0x24 per-slot bytes (fixed, no count)
    uint8_t has_password = 0;   // #24 +0x25

    void write(net::message_writer &w) const
    {
        w.write_u16(number);
        w.write_u16(u16_06);
        w.write_u16(u16_08);
        w.write_u8(players);
        w.write_u8(max_players);
        w.write_u8(map);
        w.write_u8(mode);
        w.write_u8(max_lap);
        w.write_u8(u8_0e);
        w.write_text(title);
        w.write_text(password);
        w.write_text(str_18);
        w.write_u8(state);
        w.write_u8(u8_26);
        w.write_u8(u8_27);
        for (auto b : slots)
            w.write_u8(b);
        w.write_u8(has_password);
    }

    // CLGS Create_Room sends the same layout (writer 0x573f80), strings as UTF-16.
    static room_info read(net::message_reader &r)
    {
        room_info i;
        i.number = r.read_u16();
        i.u16_06 = r.read_u16();
        i.u16_08 = r.read_u16();
        i.players = r.read_u8();
        i.max_players = r.read_u8();
        i.map = r.read_u8();
        i.mode = r.read_u8();
        i.max_lap = r.read_u8();
        i.u8_0e = r.read_u8();
        i.title = r.read_string();
        i.password = r.read_string();
        i.str_18 = r.read_string();
        i.state = r.read_u8();
        i.u8_26 = r.read_u8();
        i.u8_27 = r.read_u8();
        for (auto &b : i.slots)
            b = r.read_u8();
        i.has_password = r.read_u8();
        return i;
    }
};

// Reader 0x55ecc0.
struct room_member
{
    host_id host = 0;        // #1  +0x1c
    std::string nickname;    // #2  +0x20
    std::string str_24;      // #3  +0x24
    uint32_t user_index = 0; // #4  +0x28
    uint32_t u32_2c = 0;     // #5  +0x2c
    uint32_t exp = 0;        // #6  +0x30 -> level
    uint32_t u32_04 = 0;     // #7  +0x04
    uint32_t slot = 0;       // #8  +0x08 slot 0..7
    uint8_t ready = 0;       // #9  +0x34
    uint32_t u32_0c = 0;     // #10 +0x0c
    uint32_t u32_10 = 0;     // #11 +0x10
    uint8_t u8_35 = 0;       // #12 +0x35
    uint8_t character = 0;   // #13 +0x36 avatar / character
    uint32_t u32_14 = 0;     // #14 +0x14
    uint32_t order = 0;      // #15 +0x18 "MyOrder"

    void write(net::message_writer &w) const
    {
        w.write_u32(host);
        w.write_text(nickname);
        w.write_text(str_24);
        w.write_u32(user_index);
        w.write_u32(u32_2c);
        w.write_u32(exp);
        w.write_u32(u32_04);
        w.write_u32(slot);
        w.write_u8(ready);
        w.write_u32(u32_0c);
        w.write_u32(u32_10);
        w.write_u8(u8_35);
        w.write_u8(character);
        w.write_u32(u32_14);
        w.write_u32(order);
    }
};

// Reader 0x55e370. 81 bytes on the wire.
struct avatar_info
{
    uint32_t u32_04 = 0;
    host_id host = 0; // +0x08 matched against room_member::host
    uint32_t u32_0c = 0, u32_10 = 0, u32_14 = 0, u32_18 = 0;
    uint8_t u8_1c = 0;
    std::array<uint32_t, 14> parts{}; // +0x20..+0x54 equipped parts (9 of them are used)

    void write(net::message_writer &w) const
    {
        w.write_u32(u32_04);
        w.write_u32(host);
        w.write_u32(u32_0c);
        w.write_u32(u32_10);
        w.write_u32(u32_14);
        w.write_u32(u32_18);
        w.write_u8(u8_1c);
        for (auto p : parts)
            w.write_u32(p);
    }

    // CLGS Select_Avatar / Update_Avatar send the same 81-byte layout (writer 0x5730f0).
    static avatar_info read(net::message_reader &r)
    {
        avatar_info a;
        a.u32_04 = r.read_u32();
        a.host = r.read_u32();
        a.u32_0c = r.read_u32();
        a.u32_10 = r.read_u32();
        a.u32_14 = r.read_u32();
        a.u32_18 = r.read_u32();
        a.u8_1c = r.read_u8();
        for (auto &p : a.parts)
            p = r.read_u32();
        return a;
    }
};

// Reader 0x55efc0. The client ignores its contents.
struct start_game_info
{
    uint32_t u32_04 = 0;
    std::string str_08;
    uint32_t u32_0c = 0, u32_10 = 0, u32_14 = 0, u32_18 = 0;
    std::string str_1c;

    void write(net::message_writer &w) const
    {
        w.write_u32(u32_04);
        w.write_text(str_08);
        w.write_u32(u32_0c);
        w.write_u32(u32_10);
        w.write_u32(u32_14);
        w.write_u32(u32_18);
        w.write_text(str_1c);
    }
};

// Reader 0x588470.
struct room_slot_user
{
    std::string str_04, str_08;
    uint32_t u32_0c = 0, u32_10 = 0;
    uint16_t u16_14 = 0, u16_16 = 0;
    uint8_t u8_18 = 0;

    void write(net::message_writer &w) const
    {
        w.write_text(str_04);
        w.write_text(str_08);
        w.write_u32(u32_0c);
        w.write_u32(u32_10);
        w.write_u16(u16_14);
        w.write_u16(u16_16);
        w.write_u8(u8_18);
    }
};

// Reader 0x5888c0.
struct rank_entry
{
    uint32_t u32_04 = 0, u32_08 = 0, u32_0c = 0;
    std::string str_10;
    uint32_t u32_14 = 0, u32_18 = 0, u32_1c = 0, u32_20 = 0;
    std::string str_24, str_28;

    void write(net::message_writer &w) const
    {
        w.write_u32(u32_04);
        w.write_u32(u32_08);
        w.write_u32(u32_0c);
        w.write_text(str_10);
        w.write_u32(u32_14);
        w.write_u32(u32_18);
        w.write_u32(u32_1c);
        w.write_u32(u32_20);
        w.write_text(str_24);
        w.write_text(str_28);
    }
};

// Reader 0x588bd0.
struct rank_info
{
    uint16_t u16_04 = 0, u16_06 = 0, u16_08 = 0;
    uint32_t u32_0c = 0, u32_10 = 0;
    std::string str_14, str_18;

    void write(net::message_writer &w) const
    {
        w.write_u16(u16_04);
        w.write_u16(u16_06);
        w.write_u16(u16_08);
        w.write_u32(u32_0c);
        w.write_u32(u32_10);
        w.write_text(str_14);
        w.write_text(str_18);
    }
};

} // namespace hovorun::game
