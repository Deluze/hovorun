# Client -> Game Server (CLGS) RMI interface, connect/login flow, P2P (CLPE)

Source: Client5.exe (image base 0x400000). Analysis done with capstone over the on-disk exe
(helper scripts in `scratchpad/re/tools/`), cross-checked with Binary Ninja disasm.

## 0. Wire primitives used by the proxies (CMessage WRITE side)

All multi-byte values are little-endian. CMessage `m_isSimplePacketMode`-like debug flag at CMessage+0x18
is initialised from the const byte at 0x6cf118 (= 0), so the optional `0xFE` "field separator" byte that
every writer can append is NEVER emitted. Ignore it.

| Writer (addr) | What it emits |
|---|---|
| 0x5729a0 / 0x572a00 `Write(ptr,len)` | `len` raw bytes (used for u8/u16/u32 params and RmiID) |
| 0x579fc0 / 0x574270 `WriteByte(b)` | 1 raw byte |
| 0x57a030 `WriteInt32(v)` | 4 raw bytes |
| 0x5fa890 `WriteScalar(int64)` (encoder 0x62a990) | compact scalar: 1 byte size N (1,2,4,8) then N bytes signed LE. N = smallest of 1/2/4/8 whose signed range holds the value (-128..127 -> 1, -32768..32767 -> 2, int32 -> 4, else 8) |
| 0x5faac0 `WriteString(CStringW)` | `u8 0x02` (string type = UTF-16) + compact scalar char-count + count*2 bytes UTF-16LE, no terminator |
| 0x589a80 / 0x579f50 `Write(ByteArray)` | `u32 count` (raw 4 bytes, NOT compact) + `count` bytes |

**RMI message payload** (inside the TCP frame `13 57 | scalar len | payload`):

```
u8   0x01            MessageType_Rmi  (written by the RmiSend core 0x5d5ac0, header CMessage)
u16  RmiID
...  params in declaration order
```

Note: the proxy function itself writes only RmiID+params; the send core 0x5d5ac0 writes the `0x01` header
byte in front. All CLGS proxies are sent to HostID 1 (= server) with RmiContext 0x9e5fe0 (reliable).

## 1. CLGS::Proxy (client -> game server)

- RTTI TypeDescriptor 0x9e5748 (name ".?AVProxy@CLGS@@"), COL 0x9c0404, **vtable 0x6c13a4**.
- vtable slots 0-4 are IRmiProxy base methods; from slot 5 on every RMI occupies 2 slots:
  `+N` = multi-target overload (`HostID* list, int count, RmiContext*, ...`), `+N+4` = single-target
  overload (`HostID, RmiContext*, ...`) - the game always calls the `+N+4` one.
  (So Bart's offsets in ports.txt are the `+N+4` slots.)
- The C++ owner is the global network manager `[0x9e8f48]`; the CLGS proxy is embedded at `+0x7bc`,
  CLSS (session) proxy at `+0x9c`, CGameClient object at `+0xdc`, messenger proxy (CLMS) at `+0x16bc`.
- RmiIDs 1001..1061 (0x3E9..0x425), **61 RMIs**. Names are the RMI name strings the proxy passes to the
  send core (exact original names).

Types: `u8`/`u16`/`u32` = raw LE; `wstr` = string type 2 as above; `Avatar` / `CreateRoomInfo` see below.

| ID dec | ID hex | vt call off | Name (original) | Params (in order) | Proxy fn | Caller / trigger (wrapper in CGameMain @0x52xxxx/0x54xxxx) |
|---|---|---|---|---|---|---|
| 1001 | 0x3E9 | 0x18 | Logon_CLGS | wstr userId, wstr password, u32 clientVersion (=20070204 / 0x01323F3C) | 0x572860 | 0x54b640, called from OnJoinServerComplete (0x508db0) on successful connect. See section 2 |
| 1002 | 0x3EA | 0x20 | Create_Avatar | u16, u8, u16, u8 | 0x572ca0 | not referenced via +0x7bc (unused / char creation) |
| 1003 | 0x3EB | 0x28 | Select_Avatar | u8, Avatar | 0x572fc0 | not referenced via +0x7bc |
| 1004 | 0x3EC | 0x30 | Logout_Notify | - | 0x573770 | 0x54ba00 "LogOut()" (exit game, `/Logout`) |
| 1005 | 0x3ED | 0x38 | Room_List | u16 page(+0x28c), u16 type/mode(+0x28e, default 1) | 0x573970 | 0x5248e0 / 0x524b30 room list prev/next/refresh in lobby |
| 1006 | 0x3EE | 0x40 | Room_Request_Room_Member | u16 roomIndex, u16 (2nd arg, >=0) | 0x573bf0 | 0x5241a0 (clicking a room in lobby list -> show members) |
| 1007 | 0x3EF | 0x48 | Create_Room | CreateRoomInfo | 0x573e70 | 0x5242d0 create room dialog |
| 1008 | 0x3F0 | 0x50 | Enter_Room | u16 roomIndex, wstr password | 0x5743f0 | 0x524730 "Starting Client Enter Room request"; 0x5247c0 |
| 1009 | 0x3F1 | 0x58 | Room_Chat | wstr text | 0x574650 | room chat, `/RoomChat` |
| 1010 | 0x3F2 | 0x60 | Team_Chat | wstr text | 0x574870 | (no +0x7bc caller found; maybe via other path) |
| 1011 | 0x3F3 | 0x68 | Wisper_Chat | wstr targetNick, wstr text | 0x574a90 | (no caller found) |
| 1012 | 0x3F4 | 0x70 | Leave_Room | - | 0x574cd0 | 0x5264c0 "Starting Client Leave Room Request" (Escape in waiting room, etc.) |
| 1013 | 0x3F5 | 0x78 | Change_Map | u8 map | 0x574ed0 | 0x525e80 room master map select |
| 1014 | 0x3F6 | 0x80 | Change_Type | u8 type | 0x575110 | 0x525ec0 / 0x525f30 |
| 1015 | 0x3F7 | 0x88 | Kicked_Room | u32 (slot/player index) | 0x575350 | 0x5261b0 room master kicks a slot |
| 1016 | 0x3F8 | 0x90 | CloseSlot_Room | u32 slot | 0x575590 | (no direct +0x7bc caller found) |
| 1017 | 0x3F9 | 0x98 | OpenSlot_Room | u32 slot | 0x5757d0 | 0x526200 |
| 1018 | 0x3FA | 0xa0 | Change_Team | u8 team | 0x575a10 | 0x5266c0 |
| 1019 | 0x3FB | 0xa8 | Change_Lap | u8 laps | 0x575c50 | 0x5266f0 |
| 1020 | 0x3FC | 0xb0 | Change_Attribute | u8 | 0x575e90 | (none found) |
| 1021 | 0x3FD | 0xb8 | Change_RandomMap | u8 bool | 0x5760d0 | 0x526730 |
| 1022 | 0x3FE | 0xc0 | Mission_Request | u8 | 0x576310 | 0x526760 |
| 1023 | 0x3FF | 0xc8 | Start_Game | u16 | 0x576550 | 0x525080 "Start Event" (room master presses Start) |
| 1024 | 0x400 | 0xd0 | Ready_Game | u8 ready | 0x576790 | 0x525020 Ready button |
| 1025 | 0x401 | 0xd8 | Room_Save_Score | u32 x8 (see below) | 0x5769d0 | 0x526090 at race end "Received %d EXP and %d Points" / "score & rank calc, send score to server" |
| 1026 | 0x402 | 0xe0 | GotoWaitRoom_Notify | u8 | 0x576e70 | 0x526030 (back to waiting room after race) |
| 1027 | 0x403 | 0xe8 | Room_QuickJoin | u16 | 0x5770b0 | 0x5265c0 "Join Room : %d", `/QuickJoin` |
| 1028 | 0x404 | 0xf0 | Room_ConnectOk | u8 | 0x5772f0 | 0x5267a0, from P2P status code (RSignal/Relay/ConOK debug) -> client reports P2P connection state |
| 1029 | 0x405 | 0xf8 | GameReady_Notify | - | 0x577530 | 0x525e10 (loading finished) |
| 1030 | 0x406 | 0x100 | Select_Character_Request | u32 characterId (0..1000) | 0x577730 | 0x5267d0, `/SelectCharacter` |
| 1031 | 0x407 | 0x108 | Insert_Item_Request | u32, u32, u32, u32 | 0x577970 | (none found) |
| 1032 | 0x408 | 0x110 | Delete_Item_Request | u32 itemId | 0x577c90 | 0x526ac0 |
| 1033 | 0x409 | 0x118 | Gift_Item_Request | wstr, wstr, u32, u32, u32, u32 | 0x577ed0 | 0x526870, `/Gift` (wstr targetNick, wstr message?, item params inferred) |
| 1034 | 0x40A | 0x120 | Answer_Gift | u8, u32, u16 | 0x578210 | 0x526a30 |
| 1035 | 0x40B | 0x128 | DuraCheck_Item_Request | u32 | 0x5784d0 | 0x526b70 "owned item loading / ItemGNIndex, Dura" |
| 1036 | 0x40C | 0x130 | Update_Avatar | Avatar | 0x578710 | (none found via +0x7bc) |
| 1037 | 0x40D | 0x138 | Update_ASDKEY | u32, u32, u32, u32 | 0x578930 | 0x54f2d0 (weapon/skill key assignment, "SelectWeapon.wav") |
| 1038 | 0x40E | 0x140 | BuyItem_Request | u32, u32, u32, u32 | 0x578c50 | 0x526820 shop buy, `/BuyClanEmblen` (Bart: Buy Clan Emblem) |
| 1039 | 0x40F | 0x148 | Channel_List | - | 0x578f70 | 0x523ae0 Get Channel List |
| 1040 | 0x410 | 0x150 | Channel_UserList_Request | - | 0x579170 | (none found) |
| 1041 | 0x411 | 0x158 | Enter_Channel | u8 channel | 0x579370 | 0x523b10 channel select |
| 1042 | 0x412 | 0x160 | Leave_Channel | - | 0x5795b0 | 0x523df0 |
| 1043 | 0x413 | 0x168 | Change_Channel | u8 channel | 0x5797b0 | 0x523e80 |
| 1044 | 0x414 | 0x170 | Channel_Total_RoomNumber | - | 0x5799f0 | 0x524fe0 (periodic every 5s in lobby) |
| 1045 | 0x415 | 0x178 | Guid_Request | ByteArray (u32 count + bytes) | 0x579bf0 | (none found via +0x7bc) |
| 1046 | 0x416 | 0x180 | Check_Period_Answer | ByteArray (u32 count + bytes), u32 | 0x579e10 | (anti-hack challenge answer; none found via +0x7bc) |
| 1047 | 0x417 | 0x188 | Check_Error_Notify | wstr message | 0x57a1e0 | 0x54fd00 anti-cheat: "hacking tool found", "SpeedHack" messages |
| 1048 | 0x418 | 0x190 | Enter_Lobby | - | 0x57a400 | 0x5238e0 |
| 1049 | 0x419 | 0x198 | Lobby_Chat | wstr text | 0x57a600 | lobby chat (0x54e5e3) |
| 1050 | 0x41A | 0x1a0 | Change_Comment | wstr comment | 0x57a820 | profile comment edit |
| 1051 | 0x41B | 0x1a8 | Cry | wstr text | 0x57aa40 | `/Cry` megaphone (0x54f420) |
| 1052 | 0x41C | 0x1b0 | Ranking_Request | u32 | 0x57ac60 | 0x5238e0 (after Enter_Lobby) |
| 1053 | 0x41D | 0x1b8 | Enter_Nation | u8 nation | 0x57aea0 | 0x5239d0 |
| 1054 | 0x41E | 0x1c0 | Change_Nation | u8 nation | 0x57b0e0 | 0x523a20 "nation move -> %d" |
| 1055 | 0x41F | 0x1c8 | RankInfo_Request | - | 0x57b320 | 0x54fca0 |
| 1056 | 0x420 | 0x1d0 | Update_Gs_UserClanInfo | - | 0x57b520 | 0x523650 after clan create/join ("Empty ClanName", "Duplicate emblem") |
| 1057 | 0x421 | 0x1d8 | Room_Index_Answer | u16 | 0x57b720 | (none found) |
| 1058 | 0x422 | 0x1e0 | GetUserNewCash | - | 0x57b960 | lobby/shop enter (refresh cash) |
| 1059 | 0x423 | 0x1e8 | BlastingRoom_GM | - | 0x57bb60 | GM `/closeroom` (Bart: Close Room) |
| 1060 | 0x424 | 0x1f0 | UserKickRoom_GM | wstr nickname | 0x57bd60 | GM `/kick` (Bart: Kick Player) |
| 1061 | 0x425 | 0x1f8 | CL2GS_Test | - | 0x57bf80 | sent right before Logon_CLGS (0x54b676) |

Bart's ports.txt mapping check (`+0x7bc` object): +0x100 Select_Character_Request, +0x148 Channel_List,
+0x70 Leave_Room, +0x58 Room_Chat, +0x1e8 BlastingRoom_GM (close room), +0x1f0 UserKickRoom_GM,
+0x140 BuyItem_Request. The `+0x16bc` object is the messenger proxy (CLMS), not covered here.

### Struct `Avatar` (writer 0x5730f0) - 81 bytes
Source object offsets in brackets.
```
u32 [+0x04]
u32 [+0x08]
u32 [+0x0c]
u32 [+0x10]
u32 [+0x14]
u32 [+0x18]
u8  [+0x1c]
u32 [+0x20] .. [+0x54]   14 x u32
```

### Struct `CreateRoomInfo` (writer 0x573f80)
```
u16  [+0x04]
u16  [+0x06]
u16  [+0x08]
u8   [+0x0a]
u8   [+0x0b]
u8   [+0x0c]
u8   [+0x0d]
u8   [+0x0f]      <- note order: +0x0f is written BEFORE +0x0e
u8   [+0x0e]
wstr [+0x10]      (room name - inferred)
wstr [+0x14]      (password - inferred)
wstr [+0x18]
u8   [+0x1c]
u8   [+0x26]
u8   [+0x27]
u8   [+0x1d] x 8  (+0x1d..+0x24, 8 bytes, e.g. per-slot flags)
u8   [+0x25]
```

### Room_Save_Score (1025) params
`u32 a, u32 b, u32 c, u32 d, u32 e, u32 f, u32 g, u32 h` (8 raw u32, stack args 0x10..0x2c). Sent at race
end. Meaning (rank, time, exp, points ...) not yet resolved.

## 2. How CGameClient finds, connects and logs in to the game server

### 2.1 Where ID / password come from
`Client.exe <userId> <password> 4912160` (see start.bat). WinMain (0x407470) reads argv[1..3]
(`[0x9f1178]+4/+8/+0xc`); argv[3] must equal 4912160 (0x4AF420) or the client exits. argv[1]/argv[2] are
passed to `0x54ac50(id, pw)` on the network manager `[0x9e8f48]`, which stores them as CStringW at
`mgr+0x34` (userId) and `mgr+0x38` (password). Session server address comes from `cliconfg.inp`
(`[SERVER] SESSIONIP / SESSIONPORT`, 0x54b510). Session login (0x54b310) sends CLSS slot 0x18 (the
session "logon" RMI) with the same (userId, password) wide strings.

### 2.2 Game server address = session server reply `User_Logon_SSCL` (SSCL RmiID 2301 / 0x8FD)
SSCL stub (dispatcher 0x571370) case 0x8FD reads, in order:
```
u8    serverIndex      (stored-1 into session client +0x18; inferred nation/server index, 1-based)
wstr  gameServerIp     (read via 0x5fa900: string type byte + compact len + chars)
u16   gameServerPort
u16   result
```
Handler 0x59c510 (`CSessionClient::User_Logon_SSCL`): `switch(result)`: 0 = success -> calls
`0x54b710(ip, port)`; 1, 2, 10, 11 -> different error message boxes; anything else -> ignored.

### 2.3 Connect (0x54b710 -> CGameClient::Connect 0x508bf0)
`0x54b710` stores ip in `CGameClient+0x714` and port in `+0x718` (CGameClient = mgr+0xdc), then
`0x508bf0` builds a `CNetConnectionParam` and calls `CNetClient::Connect` (`[CGameClient+0x6dc]->vtbl[0x3c]`):

| CNetConnectionParam field | value |
|---|---|
| +0x00 m_serverIP (CStringW) | ip from User_Logon_SSCL |
| +0x04 m_serverPort (u16) | port from User_Logon_SSCL |
| +0x08 m_protocolVersion (GUID, 16 bytes) | see below |
| +0x18 m_userData (ByteArray) | **empty** (not set) |

**Protocol version GUIDs.** Base GUID is the static at 0x9e7cfc:
`{683ADDC6-6740-485B-AF8D-8818C1CC043C}` = bytes `c6 dd 3a 68 40 67 5b 48 af 8d 88 18 c1 cc 04 3c`.
It is copied into a config object at 0x9e9e20 (init 0x67b670) and each server type derives its version by
adding a constant to Data1 (the first little-endian u32):

| server | getter | Data1 | 16 wire/memory bytes |
|---|---|---|---|
| **Game server** (CGameClient, 0x508bf0) | 0x67b790: +1 | 0x683ADDC7 | `c7 dd 3a 68 40 67 5b 48 af 8d 88 18 c1 cc 04 3c` |
| Messenger (0x533207) | 0x67b8d0: +4 | 0x683ADDCA | `ca dd 3a 68 40 67 5b 48 af 8d 88 18 c1 cc 04 3c` |
| Session (0x59c900) | 0x67b970: +5 | 0x683ADDCB | `cb dd 3a 68 40 67 5b 48 af 8d 88 18 c1 cc 04 3c` |

(The same config object also holds ports 22111/23111/24111/21111/25111 and the wide strings "Hovorun" and
"85.158.207.76" at +0x24/+0x28 - apparently the original live server; not used for the game connect.)

### 2.4 First messages after connect
INetClientEvent vtable of CGameClient = 0x6c16f4; slot 7 = `OnJoinServerComplete` 0x508db0. On failure it
shows "connection to server failed"; on success (ErrorInfo* == NULL) it sets `+0x710=1` and calls
`0x54b640`, which sends back to back to HostID 1 (reliable RmiContext 0x9e5fe0):
1. **CL2GS_Test** (1061 / 0x425), no params: payload `01 25 04`
2. **Logon_CLGS** (1001 / 0x3E9): `wstr userId (mgr+0x34), wstr password (mgr+0x38), u32 20070204`

Example payload for id "abc", pw "pw":
```
01 e9 03                      MessageType_Rmi, RmiID 1001
02 01 03 61 00 62 00 63 00    wstr "abc"  (type 2, compact len 01 03, UTF-16LE)
02 01 02 70 00 77 00          wstr "pw"
3c 3f 32 01                   u32 20070204
```
Then it sets global state `[0x9e5944] = 9`. The server's answer is a GSCL RMI (not covered here).

## 3. P2P: CLPE (client <-> client over ProudNet P2P)

- CLPE::Proxy vtable 0x6c1364 (embedded at CGameClient+0x6f4 = mgr+0x7d0). CLPE::Stub vtable 0x6c1734
  (at CGameClient+0x18; dispatcher 0x55f3c0; readers mirror the writers). Stub handlers are CGameClient
  overrides in vtable 0x6c15a4 slots 7..11. (CGameClient members: +0x08 GSCL stub, +0x18 CLPE stub,
  +0x6dc CNetClient*, +0x6e0 CLGS proxy, +0x6f4 CLPE proxy, +0x70c P2P group HostID, +0x714 ip, +0x718 port.)
- All 5 RMIs are sent to HostID `CGameClient+0x70c` (= **the P2P group HostID**, section 4) with
  RmiContext 0x9e6038 (reliability field 0 = **Unreliable**, priority 3). Normal RMI payload
  `01 | u16 id | params`, travelling P2P (UDP direct, or relayed by the server).

| ID | hex | vt call off | Name | Params | Proxy fn | Receiver handler |
|---|---|---|---|---|---|---|
| 2901 | 0xB55 | 0x18 | UDP_Chat | wstr text, u32 | 0x57c180 | 0x50a130 "Chat : %s" |
| 2902 | 0xB56 | 0x20 | UDP_RoomSignal | RealTime_Room_Packet | 0x57c3e0 | 0x508f40 |
| 2903 | 0xB57 | 0x28 | UDP_RacingSignal | RealTime_Racing_Packet | 0x57caf0 | 0x5095c0 |
| 2904 | 0xB58 | 0x30 | UDP_ItemAttack | u32 x9 | 0x57d580 | 0x50a310 (combo items: all-missile, light speed) |
| 2905 | 0xB59 | 0x38 | UDP_CrashReport | u32, u32, u32 | 0x57db00 | 0x50a960 ("%s shot down %s", self-destruct) |

Senders: UDP_Chat 0x54e626; UDP_RoomSignal 0x5250e0 (from the frame loop 0x54ae30 every 5th 100 ms tick,
~500 ms); UDP_RacingSignal 0x525520 (race loop); UDP_ItemAttack 0x525d60; UDP_CrashReport 0x525dc0.

### RealTime_Room_Packet (C++ class, vtable 0x6c1a38, ctor 0x678a80; writer 0x57c4f0, reader 0x560da0)
Not a ProudNet UserMessage: it is serialized as the single parameter of RMI 2902. Wire order (object
offsets in brackets; "player" = local player record `[0x9e9080] + myIdx*0x5c0`, myIdx = `[0x9e90cc]+0x15c`):
```
u32  [+0x10] playerIndex (my slot)
u32  [+0x24] player+0x1b0
u8   [+0x04..+0x0e] 11 bytes = player+0x70..+0x7a (character / kart / equipment ids - inferred)
u8   [+0x28] player+0x3b0
u8   [+0x30] player+0x2ae
u32  [+0x3c] mgr+0x6a8
u32  [+0x40] mgr+0x6ac
u32  [+0x44] mgr+0x6b0
u32  [+0x48] player+0x434
u32  [+0x4c] always 0
u8   [+0x5c] game+0x132ed
wstr [+0x58] nickname (inferred; converted from an ANSI string)
u32  [+0x50] [0x9e9158]+0xd1c
u32  [+0x54] [0x9e9158]+0xd20
```
Fixed part = 49 bytes + wstr. (Object fields +0x14/+0x18/+0x1c/+0x20 are filled but NOT serialized.)

### RealTime_Racing_Packet (vtable 0x6c1a40, ctor 0x678cd0; writer 0x57cc00, reader 0x561220) - 147 bytes
```
u32 [+0x34] playerIndex
u32 [+0xac] sender timeGetTime()
u32 [+0x50] player+0x1ac
f32 [+0x28] [+0x2c] [+0x30]   position (player+0xf8..+0x100)
f32 [+0x04] [+0x08] [+0x0c]   player+0x34..+0x3c   (orientation rows - inferred)
f32 [+0x1c] [+0x20] [+0x24]   player+0x4c..+0x54
f32 [+0x10] [+0x14] [+0x18]   player+0x40..+0x48
u32 [+0x44] player+0x1a0
u32 [+0x38] [+0x3c] [+0x40]   player+0x194..+0x19c
u32 [+0x60] player+0x1c4
u32 [+0x48] [+0x4c]           player+0x1a4, +0x1a8
u8  [+0x68] player+0x2ad
u32 [+0x64] player+0x284
u8  [+0x69] player+0x2d4
u8  [+0x6a] player+0x374
u32 [+0x6c] player+0x3b4
u32 [+0x70] player+0x3b8
u8  [+0x74] player+0x3b0
u32 [+0x78] [+0x7c] [+0x80] [+0x84] [+0x88]   player+0x2bc, 0x2b8, 0x2c0, 0x2b0, 0x2b4
u32 [+0x90] player+0x3ec
u16 [+0x8c] player+0x3f0
u32 [+0x94] mgr+0x69c
u8  [+0x98] mgr+0x6a1
f32 [+0xa0] [+0xa4] [+0xa8]   velocity (player+0x104..+0x10c, position delta / dt)
```
4-byte fields not marked f32 may be int or float (only position / velocity were confirmed via FPU use;
the three orientation triples are very likely float too). A relaying server does not need the semantics.

## 4. Does the game rely on ProudNet P2P groups?  YES.

- CGameClient INetClientEvent slot 9 (0x508bd0) = `OnP2PMemberJoin(HostID member, HostID group, int count,
  ByteArray custom)` (4 args): it stores `group` into `CGameClient+0x70c`. Slot 10 (0x511620,
  OnP2PMemberLeave) is empty. `+0x70c` is reset to 0 in Connect.
- Every CLPE RMI (room heartbeat, race position sync, item attacks, crash/kill reports, UDP chat) is sent to
  that group HostID. Without a P2P group, `+0x70c` stays 0 and nothing is delivered, so other players would
  never appear or move.
- Therefore the server must, for each room, create a ProudNet P2P group containing the room members
  (CreateP2PGroup / JoinP2PGroup as they enter) so every client receives P2PGroup_MemberJoin (group HostID
  + member HostIDs), and it must support ProudNet P2P relay (the server forwards P2P RMIs addressed to the
  group when UDP hole punching fails). The client's debug overlay shows RSignal / HoleAns / Relay / ConOK
  per player, and the client reports P2P readiness to the server with `Room_ConnectOk` (1028).
- There is no custom UserMessage path for the RealTime_* packets; they are only RMI parameters.

## 5. Binary Ninja annotations made

- Functions: `CLGS_Proxy_<RmiName>` / `_multi` (122), `CLPE_Proxy_<RmiName>` / `_multi` (10), `NetMgr_Send*` UI-side wrappers, `CGameClient_Connect`, `CGameClient_OnJoinServerComplete`, `CGameClient_OnP2PMemberJoin/Leave`, `CGameClient_CLPE_UDP_*` handlers, `CLPE_Stub_ProcessReceivedMessage`, `CMessage_Write_*` struct writers, `CMessage_Read_RealTime_*`, `RealTime_*_Packet_ctor/dtor`, `NetConfig_Get{Game,Messenger,Session}ProtocolVersion`, `RmiProxy_RmiSend`.
- Types: `RealTime_Room_Packet`, `RealTime_Racing_Packet`, `CLGS_CreateRoomInfo`, `CLGS_Avatar`.
- Data: `g_ProtocolVersionBaseGuid` (0x9e7cfc).

## 6. Open questions

- Semantics of many numeric params (Room_Save_Score 8 x u32, BuyItem/Insert_Item/Update_ASDKEY 4 x u32, Gift_Item, Answer_Gift, CreateRoomInfo fields) not resolved.
- Several RMIs (Create_Avatar, Select_Avatar, Team_Chat, Wisper_Chat, CloseSlot_Room, Change_Attribute, Insert_Item, Update_Avatar, Channel_UserList_Request, Guid_Request, Check_Period_Answer, Room_Index_Answer) have no caller via the `+0x7bc` proxy pointer; they may be dead or called through a different pointer path.
- Whether the server must relay CLPE RMIs itself (ProudNet relay) or clients always hole-punch: implement ProudNet P2P relay to be safe.
