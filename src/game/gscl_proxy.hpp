#pragma once

// Builders for every GSCL (game server -> client) RMI. Each returns the full ProudNet payload
// ([u8 MessageType_Rmi][u16 RmiID][params]) ready to be sent on the client's connection.
// RmiIDs and names are the original IDL names from the client's stub name table (0x9e5948).

#include "../proudnet/rmi.hpp"
#include "gscl_types.hpp"

namespace hovorun::game::gscl
{

namespace id
{
constexpr uint16_t Logon_GSCL = 0x579;
constexpr uint16_t LogOut_OK = 0x57a;
constexpr uint16_t Add_Items = 0x57b;
constexpr uint16_t Add_Gifts = 0x57c;
constexpr uint16_t Channel_UserList_Notify = 0x57d;
constexpr uint16_t Create_Avatar = 0x57e;
constexpr uint16_t Room_Del_User = 0x57f;
constexpr uint16_t Channel_List = 0x580;
constexpr uint16_t Channel_UserList_Answer = 0x581;
constexpr uint16_t Enter_Lobby = 0x582;
constexpr uint16_t Enter_Channel = 0x583;
constexpr uint16_t Leave_Channel = 0x584;
constexpr uint16_t Change_Channel = 0x585;
constexpr uint16_t Create_Room = 0x586;
constexpr uint16_t Enter_Room = 0x587;
constexpr uint16_t Room_Add_User_Avatar = 0x588;
constexpr uint16_t Leave_Room = 0x589;
constexpr uint16_t Change_Map = 0x58a;
constexpr uint16_t Change_Type = 0x58b;
constexpr uint16_t Kicked_Room = 0x58c;
constexpr uint16_t Change_Team = 0x58d;
constexpr uint16_t CloseSlot_Room = 0x58e;
constexpr uint16_t OpenSlot_Room = 0x58f;
constexpr uint16_t Change_Lap = 0x590;
constexpr uint16_t Change_Attribute = 0x591;
constexpr uint16_t Change_RandomMap = 0x592;
constexpr uint16_t Mission_Answer = 0x593;
constexpr uint16_t Start_Game_Answer = 0x594;
constexpr uint16_t Start_Game = 0x595;
constexpr uint16_t Start_Game_Notify = 0x596;
constexpr uint16_t Ready_Game = 0x597;
constexpr uint16_t Ready_Game_Notify = 0x598;
constexpr uint16_t New_RoomMaster = 0x599;
constexpr uint16_t Select_Character = 0x59a;
constexpr uint16_t Insert_Item = 0x59b;
constexpr uint16_t Delete_Item_Answer = 0x59c;
constexpr uint16_t Gift_Item = 0x59d;
constexpr uint16_t Answer_Gift = 0x59e;
constexpr uint16_t Room_UpDataAvatar = 0x59f;
constexpr uint16_t Room_Change_Comment = 0x5a0;
constexpr uint16_t EnableRoom = 0x5a1;
constexpr uint16_t Room_Member_Answer = 0x5a2;
constexpr uint16_t Channel_RoomNumber_Answer = 0x5a3;
constexpr uint16_t Lobby_Add_Rooms = 0x5a4;
constexpr uint16_t Lobby_Chat = 0x5a5;
constexpr uint16_t Room_Chat = 0x5a6;
constexpr uint16_t Cry = 0x5a7;
constexpr uint16_t RankingAnswer = 0x5a8;
constexpr uint16_t RankInfo_Answer = 0x5a9;
constexpr uint16_t HS_Period_Check = 0x5aa; // never send: the client writes through an unallocated buffer
constexpr uint16_t HS_Client_Out = 0x5ab;
constexpr uint16_t Forced_Close = 0x5ac;
constexpr uint16_t Add_Avatars = 0x5ad;
constexpr uint16_t Enter_Nation = 0x5ae;
constexpr uint16_t Change_Nation = 0x5af;
constexpr uint16_t Updata_Ranking = 0x5b0;
constexpr uint16_t Check_HS_Request = 0x5b1;
constexpr uint16_t Room_Index_Request = 0x5b2;
constexpr uint16_t RankingAnswer_Notice = 0x5b3;
constexpr uint16_t User_New_Infor_Answer = 0x5b4;
constexpr uint16_t GS2CL_Test = 0x5b5;
} // namespace id

using net::message_writer;
using proudnet::rmi_begin;

// Result code 0 means success for every RMI that carries one.
constexpr uint16_t ok = 0;

inline message_writer Logon_GSCL(host_id my_host, const logon_info &info, uint16_t result, uint32_t a, uint16_t b,
                                 uint32_t gender, uint32_t age, const std::string &location)
{
    auto w = rmi_begin(id::Logon_GSCL);
    w.write_u32(my_host);
    info.write(w);
    w.write_u16(result);
    w.write_u32(a);
    w.write_u16(b);
    w.write_u32(gender);
    w.write_u32(age);
    w.write_text(location);
    return w;
}

inline message_writer LogOut_OK() { return rmi_begin(id::LogOut_OK); }

inline message_writer Add_Items(const std::vector<item_info> &items)
{
    auto w = rmi_begin(id::Add_Items);
    write_array(w, items, [](message_writer &w, const item_info &i) { i.write(w); });
    return w;
}

inline message_writer Add_Gifts(const std::vector<gift_info> &gifts)
{
    auto w = rmi_begin(id::Add_Gifts);
    write_array(w, gifts, [](message_writer &w, const gift_info &g) { g.write(w); });
    return w;
}

inline message_writer Channel_UserList_Notify(const std::vector<channel_user> &users)
{
    auto w = rmi_begin(id::Channel_UserList_Notify);
    write_array(w, users, [](message_writer &w, const channel_user &u) { u.write(w); });
    return w;
}

inline message_writer Room_Del_User(host_id host, uint32_t slot, uint32_t unk)
{
    auto w = rmi_begin(id::Room_Del_User);
    w.write_u32(host);
    w.write_u32(slot);
    w.write_u32(unk);
    return w;
}

inline message_writer Channel_List(const std::vector<channel_info> &channels)
{
    auto w = rmi_begin(id::Channel_List);
    write_array(w, channels, [](message_writer &w, const channel_info &c) { c.write(w); });
    return w;
}

inline message_writer Channel_UserList_Answer(host_id host, const std::vector<channel_user> &users, uint16_t u16v,
                                              uint8_t flag)
{
    auto w = rmi_begin(id::Channel_UserList_Answer);
    w.write_u32(host);
    write_array(w, users, [](message_writer &w, const channel_user &u) { u.write(w); });
    w.write_u16(u16v);
    w.write_u8(flag);
    return w;
}

inline message_writer Enter_Lobby(uint16_t result)
{
    auto w = rmi_begin(id::Enter_Lobby);
    w.write_u16(result);
    return w;
}

inline message_writer Enter_Channel(uint8_t channel, uint16_t result)
{
    auto w = rmi_begin(id::Enter_Channel);
    w.write_u8(channel);
    w.write_u16(result);
    return w;
}

inline message_writer Leave_Channel(uint16_t result)
{
    auto w = rmi_begin(id::Leave_Channel);
    w.write_u16(result);
    return w;
}

inline message_writer Change_Channel(uint8_t channel, uint16_t result)
{
    auto w = rmi_begin(id::Change_Channel);
    w.write_u8(channel);
    w.write_u16(result);
    return w;
}

inline message_writer Create_Room(const room_info &room, uint16_t unk, uint16_t result)
{
    auto w = rmi_begin(id::Create_Room);
    room.write(w);
    w.write_u16(unk);
    w.write_u16(result);
    return w;
}

inline message_writer Enter_Room(const std::vector<room_member> &members, const std::vector<avatar_info> &avatars,
                                 uint32_t master_slot, const room_info &room, uint16_t result)
{
    auto w = rmi_begin(id::Enter_Room);
    write_array(w, members, [](message_writer &w, const room_member &m) { m.write(w); });
    write_array(w, avatars, [](message_writer &w, const avatar_info &a) { a.write(w); });
    w.write_u32(master_slot);
    room.write(w);
    w.write_u16(result);
    return w;
}

inline message_writer Room_Add_User_Avatar(const avatar_info &avatar, const room_member &member)
{
    auto w = rmi_begin(id::Room_Add_User_Avatar);
    avatar.write(w);
    member.write(w);
    return w;
}

inline message_writer Leave_Room(uint16_t result)
{
    auto w = rmi_begin(id::Leave_Room);
    w.write_u16(result);
    return w;
}

inline message_writer Change_Map(uint8_t map)
{
    auto w = rmi_begin(id::Change_Map);
    w.write_u8(map);
    return w;
}

inline message_writer Change_Type(uint8_t type, const std::vector<room_member> &members)
{
    auto w = rmi_begin(id::Change_Type);
    w.write_u8(type);
    write_array(w, members, [](message_writer &w, const room_member &m) { m.write(w); });
    return w;
}

inline message_writer Kicked_Room(uint16_t reason)
{
    auto w = rmi_begin(id::Kicked_Room);
    w.write_u16(reason);
    return w;
}

inline message_writer Change_Team(uint32_t slot, uint8_t team)
{
    auto w = rmi_begin(id::Change_Team);
    w.write_u32(slot);
    w.write_u8(team);
    return w;
}

inline message_writer CloseSlot_Room(uint32_t slot)
{
    auto w = rmi_begin(id::CloseSlot_Room);
    w.write_u32(slot);
    return w;
}

inline message_writer OpenSlot_Room(uint32_t slot)
{
    auto w = rmi_begin(id::OpenSlot_Room);
    w.write_u32(slot);
    return w;
}

inline message_writer Change_Lap(uint8_t laps)
{
    auto w = rmi_begin(id::Change_Lap);
    w.write_u8(laps);
    return w;
}

inline message_writer Change_Attribute(uint8_t attribute)
{
    auto w = rmi_begin(id::Change_Attribute);
    w.write_u8(attribute);
    return w;
}

inline message_writer Change_RandomMap(bool random)
{
    auto w = rmi_begin(id::Change_RandomMap);
    w.write_bool(random);
    return w;
}

inline message_writer Mission_Answer(uint8_t v)
{
    auto w = rmi_begin(id::Mission_Answer);
    w.write_u8(v);
    return w;
}

inline message_writer Start_Game(const start_game_info &info, uint16_t mode, uint16_t laps, uint16_t result)
{
    auto w = rmi_begin(id::Start_Game);
    info.write(w);
    w.write_u16(mode);
    w.write_u16(laps);
    w.write_u16(result);
    return w;
}

inline message_writer Ready_Game(host_id host, uint32_t slot, bool ready)
{
    auto w = rmi_begin(id::Ready_Game);
    w.write_u32(host);
    w.write_u32(slot);
    w.write_bool(ready);
    return w;
}

inline message_writer New_RoomMaster(uint32_t slot)
{
    auto w = rmi_begin(id::New_RoomMaster);
    w.write_u32(slot);
    return w;
}

inline message_writer Select_Character(uint32_t character, const std::string &a, const std::string &b,
                                       uint16_t result)
{
    auto w = rmi_begin(id::Select_Character);
    w.write_u32(character);
    w.write_text(a);
    w.write_text(b);
    w.write_u16(result);
    return w;
}

inline message_writer Insert_Item(const item_info &item, uint16_t result)
{
    auto w = rmi_begin(id::Insert_Item);
    item.write(w);
    w.write_u16(result);
    return w;
}

inline message_writer Delete_Item_Answer(uint32_t item_id, uint16_t result)
{
    auto w = rmi_begin(id::Delete_Item_Answer);
    w.write_u32(item_id);
    w.write_u16(result);
    return w;
}

inline message_writer Gift_Item(const gift_info &gift, const std::string &s, uint32_t v, uint16_t result)
{
    auto w = rmi_begin(id::Gift_Item);
    gift.write(w);
    w.write_text(s);
    w.write_u32(v);
    w.write_u16(result);
    return w;
}

inline message_writer Answer_Gift(const item_info &item, uint32_t v, uint16_t a, uint16_t result)
{
    auto w = rmi_begin(id::Answer_Gift);
    item.write(w);
    w.write_u32(v);
    w.write_u16(a);
    w.write_u16(result);
    return w;
}

inline message_writer Room_UpDataAvatar(const avatar_info &avatar, uint32_t v)
{
    auto w = rmi_begin(id::Room_UpDataAvatar);
    avatar.write(w);
    w.write_u32(v);
    return w;
}

inline message_writer Room_Change_Comment(const std::string &comment, uint32_t v)
{
    auto w = rmi_begin(id::Room_Change_Comment);
    w.write_text(comment);
    w.write_u32(v);
    return w;
}

inline message_writer Room_Member_Answer(uint16_t a, uint16_t b, host_id host, const std::vector<room_member> &members,
                                         const std::vector<room_slot_user> &slots)
{
    auto w = rmi_begin(id::Room_Member_Answer);
    w.write_u16(a);
    w.write_u16(b);
    w.write_u32(host);
    write_array(w, members, [](message_writer &w, const room_member &m) { m.write(w); });
    write_array(w, slots, [](message_writer &w, const room_slot_user &s) { s.write(w); });
    return w;
}

inline message_writer Channel_RoomNumber_Answer(uint32_t number, uint16_t result)
{
    auto w = rmi_begin(id::Channel_RoomNumber_Answer);
    w.write_u32(number);
    w.write_u16(result);
    return w;
}

// The client fills 8 fixed UI slots without a bounds check: never send more than 8 rooms.
inline message_writer Lobby_Add_Rooms(const std::vector<room_info> &rooms, uint32_t unk)
{
    auto w = rmi_begin(id::Lobby_Add_Rooms);
    write_array(w, rooms, [](message_writer &w, const room_info &r) { r.write(w); });
    w.write_u32(unk);
    return w;
}

inline message_writer Lobby_Chat(host_id sender, const std::string &text)
{
    auto w = rmi_begin(id::Lobby_Chat);
    w.write_u32(sender);
    w.write_text(text);
    return w;
}

inline message_writer Room_Chat(host_id sender, const std::string &text)
{
    auto w = rmi_begin(id::Room_Chat);
    w.write_u32(sender);
    w.write_text(text);
    return w;
}

inline message_writer Cry(const std::string &text)
{
    auto w = rmi_begin(id::Cry);
    w.write_text(text);
    return w;
}

inline message_writer RankingAnswer(const std::vector<rank_entry> &entries)
{
    auto w = rmi_begin(id::RankingAnswer);
    write_array(w, entries, [](message_writer &w, const rank_entry &e) { e.write(w); });
    return w;
}

inline message_writer RankInfo_Answer(const std::vector<rank_info> &a, const std::vector<rank_info> &b, uint32_t x,
                                      uint32_t y, uint32_t z)
{
    auto w = rmi_begin(id::RankInfo_Answer);
    write_array(w, a, [](message_writer &w, const rank_info &r) { r.write(w); });
    write_array(w, b, [](message_writer &w, const rank_info &r) { r.write(w); });
    w.write_u32(x);
    w.write_u32(y);
    w.write_u32(z);
    return w;
}

inline message_writer HS_Client_Out(bool v)
{
    auto w = rmi_begin(id::HS_Client_Out);
    w.write_bool(v);
    return w;
}

inline message_writer Forced_Close(uint16_t reason)
{
    auto w = rmi_begin(id::Forced_Close);
    w.write_u16(reason);
    return w;
}

inline message_writer Add_Avatars(const std::vector<avatar_info> &avatars)
{
    auto w = rmi_begin(id::Add_Avatars);
    write_array(w, avatars, [](message_writer &w, const avatar_info &a) { a.write(w); });
    return w;
}

inline message_writer Enter_Nation(uint8_t nation, uint16_t result)
{
    auto w = rmi_begin(id::Enter_Nation);
    w.write_u8(nation);
    w.write_u16(result);
    return w;
}

inline message_writer Updata_Ranking(const std::vector<rank_entry> &entries)
{
    auto w = rmi_begin(id::Updata_Ranking);
    write_array(w, entries, [](message_writer &w, const rank_entry &e) { e.write(w); });
    return w;
}

inline message_writer Room_Index_Request(uint16_t v)
{
    auto w = rmi_begin(id::Room_Index_Request);
    w.write_u16(v);
    return w;
}

inline message_writer RankingAnswer_Notice(const std::vector<rank_entry> &entries)
{
    auto w = rmi_begin(id::RankingAnswer_Notice);
    write_array(w, entries, [](message_writer &w, const rank_entry &e) { e.write(w); });
    return w;
}

inline message_writer User_New_Infor_Answer(uint32_t v)
{
    auto w = rmi_begin(id::User_New_Infor_Answer);
    w.write_u32(v);
    return w;
}

} // namespace hovorun::game::gscl
