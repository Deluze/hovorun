#pragma once

// CLGS (client -> game server) RmiIDs, original names from the client's proxy (vtable 0x6c13a4).
// Parameter lists are in docs/protocol/game_c2s.md and are decoded in game_server.cpp.

#include <cstdint>
#include <string_view>

namespace hovorun::game::clgs
{

enum class id : uint16_t
{
    Logon_CLGS = 1001,             // wstr userId, wstr password, u32 clientVersion (20070204)
    Create_Avatar = 1002,          // u16, u8, u16, u8
    Select_Avatar = 1003,          // u8, Avatar
    Logout_Notify = 1004,          // -
    Room_List = 1005,              // u16 page, u16 type
    Room_Request_Room_Member = 1006, // u16 roomIndex, u16
    Create_Room = 1007,            // CreateRoomInfo (= room_info layout)
    Enter_Room = 1008,             // u16 roomIndex, wstr password
    Room_Chat = 1009,              // wstr text
    Team_Chat = 1010,              // wstr text
    Wisper_Chat = 1011,            // wstr target, wstr text
    Leave_Room = 1012,             // -
    Change_Map = 1013,             // u8
    Change_Type = 1014,            // u8
    Kicked_Room = 1015,            // u32 slot
    CloseSlot_Room = 1016,         // u32 slot
    OpenSlot_Room = 1017,          // u32 slot
    Change_Team = 1018,            // u8
    Change_Lap = 1019,             // u8
    Change_Attribute = 1020,       // u8
    Change_RandomMap = 1021,       // u8
    Mission_Request = 1022,        // u8
    Start_Game = 1023,             // u16
    Ready_Game = 1024,             // u8
    Room_Save_Score = 1025,        // u32 x8
    GotoWaitRoom_Notify = 1026,    // u8
    Room_QuickJoin = 1027,         // u16
    Room_ConnectOk = 1028,         // u8
    GameReady_Notify = 1029,       // -
    Select_Character_Request = 1030, // u32 characterId
    Insert_Item_Request = 1031,    // u32 x4
    Delete_Item_Request = 1032,    // u32 itemId
    Gift_Item_Request = 1033,      // wstr, wstr, u32 x4
    Answer_Gift = 1034,            // u8, u32, u16
    DuraCheck_Item_Request = 1035, // u32
    Update_Avatar = 1036,          // Avatar
    Update_ASDKEY = 1037,          // u32 x4
    BuyItem_Request = 1038,        // u32 x4
    Channel_List = 1039,           // -
    Channel_UserList_Request = 1040, // -
    Enter_Channel = 1041,          // u8 channel
    Leave_Channel = 1042,          // -
    Change_Channel = 1043,         // u8 channel
    Channel_Total_RoomNumber = 1044, // -
    Guid_Request = 1045,           // u32 count + bytes
    Check_Period_Answer = 1046,    // u32 count + bytes, u32
    Check_Error_Notify = 1047,     // wstr
    Enter_Lobby = 1048,            // -
    Lobby_Chat = 1049,             // wstr text
    Change_Comment = 1050,         // wstr
    Cry = 1051,                    // wstr
    Ranking_Request = 1052,        // u32
    Enter_Nation = 1053,           // u8
    Change_Nation = 1054,          // u8
    RankInfo_Request = 1055,       // -
    Update_Gs_UserClanInfo = 1056, // -
    Room_Index_Answer = 1057,      // u16
    GetUserNewCash = 1058,         // -
    BlastingRoom_GM = 1059,        // -
    UserKickRoom_GM = 1060,        // wstr nickname
    CL2GS_Test = 1061,             // -
};

// The version number the client sends in Logon_CLGS.
constexpr uint32_t client_version = 20070204;

constexpr std::string_view name(id v)
{
    constexpr std::string_view names[] = {
        "Logon_CLGS", "Create_Avatar", "Select_Avatar", "Logout_Notify", "Room_List", "Room_Request_Room_Member",
        "Create_Room", "Enter_Room", "Room_Chat", "Team_Chat", "Wisper_Chat", "Leave_Room", "Change_Map",
        "Change_Type", "Kicked_Room", "CloseSlot_Room", "OpenSlot_Room", "Change_Team", "Change_Lap",
        "Change_Attribute", "Change_RandomMap", "Mission_Request", "Start_Game", "Ready_Game", "Room_Save_Score",
        "GotoWaitRoom_Notify", "Room_QuickJoin", "Room_ConnectOk", "GameReady_Notify", "Select_Character_Request",
        "Insert_Item_Request", "Delete_Item_Request", "Gift_Item_Request", "Answer_Gift", "DuraCheck_Item_Request",
        "Update_Avatar", "Update_ASDKEY", "BuyItem_Request", "Channel_List", "Channel_UserList_Request",
        "Enter_Channel", "Leave_Channel", "Change_Channel", "Channel_Total_RoomNumber", "Guid_Request",
        "Check_Period_Answer", "Check_Error_Notify", "Enter_Lobby", "Lobby_Chat", "Change_Comment", "Cry",
        "Ranking_Request", "Enter_Nation", "Change_Nation", "RankInfo_Request", "Update_Gs_UserClanInfo",
        "Room_Index_Answer", "GetUserNewCash", "BlastingRoom_GM", "UserKickRoom_GM", "CL2GS_Test",
    };
    auto index = static_cast<size_t>(v) - 1001;
    return index < std::size(names) ? names[index] : "unknown";
}

} // namespace hovorun::game::clgs
