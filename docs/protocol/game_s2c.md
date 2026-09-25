# GSCL: Game Server -> Client RMI interface (GSCL::Stub, handled by CGameClient)

Binary: Client5.exe (image base 0x400000). Status: wire formats COMPLETE for all 61 RMIs; semantics done for login/channel/lobby/room/start path, partial elsewhere.

## Location
- RTTI `.?AVStub@GSCL@@` TD = 0x9e57b8, COL = 0x9c0590, **GSCL::Stub vtable = 0x6c176c**.
- ProcessReceivedMessage (vtable slot 2) = **0x550250**. Reads RmiID (u16) via 0x5f9a50, then
  `switch (RmiID - 0x579)` with `cmp 0x3c / ja default`, jump table at 0x55da73 (61 entries, all populated).
- **RmiID range: 0x579..0x5b5 (1401..1461), 61 RMIs, contiguous.** Unknown IDs fall through (return false).
- RMI names come from the stub's own logging name table (pointer array at 0x9e5948, wide strings at 0x6c49a0..0x6c50b0),
  so the names below are the ORIGINAL IDL names (not guesses). Meanings of parameters are inferred.
- CGameClient: GSCL::Stub subobject at offset +8 inside CGameClient (COL 0x9c042c). CGameClient's GSCL-vtable = **0x6c15dc**.
  Handler for RmiID r is CGameClient-vtable slot `7 + (r - 0x579)` (byte offset in table below).
  Handlers are called `bool Handler(HostID remote, RmiContext& ctx, params...)` with `this` = CGameClient+8.
  If the handler returns false, the stub reports "RMI not handled" via this->m_core (+8) vtbl[+0x20].
- 6 RMIs are NOT overridden by CGameClient (base default returns false, client ignores them):
  0x57e Create_Avatar, 0x594 Start_Game_Answer, 0x596 Start_Game_Notify, 0x598 Ready_Game_Notify, 0x5a1 EnableRoom, 0x5af Change_Nation.

## Wire encoding (all little-endian, no padding, byte-aligned)
Payload of a MessageType_Rmi message: `[u8 MessageType_Rmi][u16 RmiID][params in order]`.
Primitive readers used by GSCL (all go through 0x5f8f00 = raw read N bytes):

| Reader fn | Wire type | Notes |
|---|---|---|
| 0x55dbd0, 0x55db90 | u8 | 1 raw byte (two distinct template instances; one is probably `bool`, one `BYTE`) |
| 0x55dc10, 0x587170 | u16 | 2 raw bytes |
| 0x55dc50, 0x5871f0, 0x5871b0 | u32/i32 | 4 raw bytes |
| 0x55dc90 -> 0x5f9ad0 | HostID (u32) | 4 raw bytes |
| 0x55db70 -> 0x5fa900 | string | ProudNet string: u8 stringType (1=ANSI/MBCS, 2=UTF-16LE) + compact-scalar length in characters + chars (see CONTEXT.md). Use type 1 (ANSI, CP949 probably) |
| (inside ItemInfo) | f64 | 8 raw bytes read as `fld qword` -> IEEE double |

**Arrays** (functions 0x5873b0, 0x587890, 0x587a30, 0x587cf0, 0x588030, 0x588130, 0x588370, 0x588620,
0x5887c0, 0x588ad0, 0x588d80): **count is a raw 4-byte i32 (NOT a compact scalar)**, must be `0 <= count < 0x100000`
(global 0x9e6a88), otherwise 0x5fac70 throws. Then `count` elements, each read by the element reader below.

**HSBuffer** (0x55eb80, only in HS_Period_Check): u32 length + `length` raw bytes copied into a buffer pointer at obj+8
that is never allocated by the ctor (0x679530) -> sending a non-zero length will likely crash; do not send this RMI.

## Struct layouts (wire order; +off = field offset in the client's in-memory struct, useful for tracing handlers)

### LogonInfo (reader 0x55dcf0) — used by Logon_GSCL
| # | wire | mem off |
|---|---|---|
| 1 | u32 | +0x04 |
| 2 | string | +0x08 |
| 3 | u16 | +0x0c |
| 4 | u32 | +0x10 |
| 5 | u32 | +0x14 |
| 6 | u32 | +0x18 |
| 7 | HostID u32 | +0x4c |
| 8 | u8 | +0x50 |
| 9 | u32 | +0x1c |
| 10 | u32 | +0x20 |
| 11 | u32 | +0x24 |
| 12 | u32 | +0x28 |
| 13 | u32 | +0x2c |
| 14 | u32 | +0x30 |
| 15 | u32 | +0x34 |
| 16 | u32 | +0x38 |
| 17 | u16 | +0x3c |
| 18 | string | +0x40 |
| 19 | string | +0x44 |
| 20 | u8 | +0x48 |

### ItemInfo (reader 0x55e000, ctor 0x678190, size 0x50) — Add_Items (array), Insert_Item, Answer_Gift
| # | wire | mem off |
|---|---|---|
| 1 | string | +0x48 |
| 2 | u32 | +0x08 |
| 3 | u32 | +0x0c |
| 4 | string | +0x10 |
| 5 | u16 | +0x14 |
| 6 | u16 | +0x16 |
| 7 | u16 | +0x18 |
| 8 | u32 | +0x1c |
| 9 | u32 | +0x20 |
| 10 | f64 (double, 8 bytes) | +0x28 |
| 11 | u32 | +0x30 |
| 12 | u32 | +0x34 |
| 13 | u16 | +0x1a |
| 14 | u8 | +0x38 |
| 15 | u8 | +0x39 |
| 16 | string | +0x3c |
| 17 | string | +0x40 |
| 18 | u32 | +0x44 |

### GiftInfo (reader 0x55f180, ctor 0x678390, size 0x34) — Add_Gifts (array), Gift_Item
u32(+4), u32(+8), u32(+0xc), u32(+0x10), u16(+0x14), u32(+0x18), u32(+0x1c), string(+0x20), string(+0x24), string(+0x28), string(+0x2c), string(+0x30)

### ChannelUser (reader 0x587b30, ctor 0x677f20, size 0x20) — Channel_UserList_Notify / _Answer (arrays)
string(+4), u32(+8), u8(+0x1a), u32(+0xc), u32(+0x10), HostID u32(+0x14), u16(+0x18), string(+0x1c)

### ChannelInfo (reader 0x587df0, ctor 0x678d20, size 0x1c) — Channel_List (array)
u32(+4), u32(+8), u32(+0xc), u32(+0x10), u32(+0x14), u8(+0x18), u8(+0x19), u8(+0x1a), u8(+0x1b)

### RoomInfo (reader 0x55e800, ctor 0x677130, size 0x28) — Create_Room, Enter_Room, Lobby_Add_Rooms (array)
| # | wire | mem off |
|---|---|---|
| 1 | u16 | +0x04 |
| 2 | u16 | +0x06 |
| 3 | u16 | +0x08 |
| 4 | u8 | +0x0a |
| 5 | u8 | +0x0b |
| 6 | u8 | +0x0c |
| 7 | u8 | +0x0d |
| 8 | u8 | +0x0f |
| 9 | u8 | +0x0e |
| 10 | string | +0x10 |
| 11 | string | +0x14 |
| 12 | string | +0x18 |
| 13 | u8 | +0x1c |
| 14 | u8 | +0x26 |
| 15 | u8 | +0x27 |
| 16..23 | u8[8] (8 separate bytes, fixed, no count) | +0x1d..+0x24 |
| 24 | u8 | +0x25 |

### RoomMember (reader 0x55ecc0, ctor 0x678700, size 0x38) — Enter_Room, Change_Type, Room_Member_Answer (arrays), Room_Add_User_Avatar
| # | wire | mem off |
|---|---|---|
| 1 | HostID u32 | +0x1c |
| 2 | string | +0x20 |
| 3 | string | +0x24 |
| 4 | u32 | +0x28 |
| 5 | u32 | +0x2c |
| 6 | u32 | +0x30 |
| 7 | u32 | +0x04 |
| 8 | u32 | +0x08 |
| 9 | u8 | +0x34 |
| 10 | u32 | +0x0c |
| 11 | u32 | +0x10 |
| 12 | u8 | +0x35 |
| 13 | u8 | +0x36 |
| 14 | u32 | +0x14 |
| 15 | u32 | +0x18 |

### AvatarInfo (reader 0x55e370, ctor 0x6775e0, size 0x58) — Enter_Room, Add_Avatars (arrays), Room_Add_User_Avatar, Room_UpDataAvatar
u32(+4), HostID u32(+8), u32(+0xc), u32(+0x10), u32(+0x14), u32(+0x18), u8(+0x1c),
then 14 x u32 (+0x20,+0x24,+0x28,+0x2c,+0x30,+0x34,+0x38,+0x3c,+0x40,+0x44,+0x48,+0x4c,+0x50,+0x54)
Total wire size = 4+4+4+4+4+4+1+56 = 81 bytes.

### StartGameInfo (reader 0x55efc0, ctor 0x6791e0) — Start_Game
u32(+4), string(+8), u32(+0xc), u32(+0x10), u32(+0x14), u32(+0x18), string(+0x1c)

### RoomSlotUser (reader 0x588470, ctor 0x6796e0, size 0x1c) — Room_Member_Answer (array)
string(+4), string(+8), u32(+0xc), u32(+0x10), u16(+0x14), u16(+0x16), u8(+0x18)

### RankEntry (reader 0x5888c0, ctor 0x6798f0, size 0x2c) — RankingAnswer, Updata_Ranking, RankingAnswer_Notice (arrays)
u32(+4), u32(+8), u32(+0xc), string(+0x10), u32(+0x14), u32(+0x18), u32(+0x1c), u32(+0x20), string(+0x24), string(+0x28)

### RankInfo (reader 0x588bd0, ctor 0x677cd0, size 0x1c) — RankInfo_Answer (2 arrays)
u16(+4), u16(+6), u16(+8), u32(+0xc), u32(+0x10), string(+0x14), string(+0x18)

### array<u8> (0x588d80) — Check_HS_Request, GS2CL_Test
i32 count + count raw bytes.

## RMI table (params in exact wire order; all come after `[u8 MsgType_Rmi][u16 RmiID]`)
| RmiID hex | dec | IDL name | params (wire order) | CGameClient handler | vt off |
|---|---|---|---|---|---|
| 0x579 | 1401 | Logon_GSCL | HostID u32, LogonInfo, u16, u32, u16, u32, u32, string | 0x511860 | 0x1c |
| 0x57a | 1402 | LogOut_OK | (none) | 0x512150 | 0x20 |
| 0x57b | 1403 | Add_Items | array<ItemInfo> | 0x518150 | 0x24 |
| 0x57c | 1404 | Add_Gifts | array<GiftInfo> | 0x518660 | 0x28 |
| 0x57d | 1405 | Channel_UserList_Notify | array<ChannelUser> | 0x512fa0 | 0x2c |
| 0x57e | 1406 | Create_Avatar | u16, u16 | 0x511130 (not overridden) | 0x30 |
| 0x57f | 1407 | Room_Del_User | HostID u32, u32, u32 | 0x519350 | 0x34 |
| 0x580 | 1408 | Channel_List | array<ChannelInfo> | 0x512800 | 0x38 |
| 0x581 | 1409 | Channel_UserList_Answer | HostID u32, array<ChannelUser>, u16, u8 (bool/byte) | 0x512ad0 | 0x3c |
| 0x582 | 1410 | Enter_Lobby | u16 | 0x5121e0 | 0x40 |
| 0x583 | 1411 | Enter_Channel | u8, u16 | 0x5122f0 | 0x44 |
| 0x584 | 1412 | Leave_Channel | u16 | 0x512470 | 0x48 |
| 0x585 | 1413 | Change_Channel | u8, u16 | 0x512520 | 0x4c |
| 0x586 | 1414 | Create_Room | RoomInfo, u16, u16 | 0x5151b0 | 0x50 |
| 0x587 | 1415 | Enter_Room | array<RoomMember>, array<AvatarInfo>, u32, RoomInfo, u16 | 0x515ac0 | 0x54 |
| 0x588 | 1416 | Room_Add_User_Avatar | AvatarInfo, RoomMember | 0x518a80 | 0x58 |
| 0x589 | 1417 | Leave_Room | u16 | 0x5171a0 | 0x5c |
| 0x58a | 1418 | Change_Map | u8 | 0x5150b0 | 0x60 |
| 0x58b | 1419 | Change_Type | u8, array<RoomMember> | 0x517590 | 0x64 |
| 0x58c | 1420 | Kicked_Room | u16 | 0x5176f0 | 0x68 |
| 0x58d | 1421 | Change_Team | u32, u8 (bool/byte) | 0x517b50 | 0x6c |
| 0x58e | 1422 | CloseSlot_Room | u32 | 0x517b10 | 0x70 |
| 0x58f | 1423 | OpenSlot_Room | u32 | 0x517b30 | 0x74 |
| 0x590 | 1424 | Change_Lap | u8 | 0x517bb0 | 0x78 |
| 0x591 | 1425 | Change_Attribute | u8 | 0x517bf0 | 0x7c |
| 0x592 | 1426 | Change_RandomMap | u8 (bool/byte) | 0x517c20 | 0x80 |
| 0x593 | 1427 | Mission_Answer | u8 | 0x517c40 | 0x84 |
| 0x594 | 1428 | Start_Game_Answer | u16 | 0x511290 (not overridden) | 0x88 |
| 0x595 | 1429 | Start_Game | StartGameInfo, u16, u16, u16 | 0x517d20 | 0x8c |
| 0x596 | 1430 | Start_Game_Notify | u8 (bool/byte) | 0x5112b0 (not overridden) | 0x90 |
| 0x597 | 1431 | Ready_Game | HostID u32, u32, u8 (bool/byte) | 0x517e50 | 0x94 |
| 0x598 | 1432 | Ready_Game_Notify | u32, u8 (bool/byte) | 0x5112d0 (not overridden) | 0x98 |
| 0x599 | 1433 | New_RoomMaster | u32 | 0x51c780 | 0x9c |
| 0x59a | 1434 | Select_Character | u32, string, string, u16 | 0x5196c0 | 0xa0 |
| 0x59b | 1435 | Insert_Item | ItemInfo, u16 | 0x5198b0 | 0xa4 |
| 0x59c | 1436 | Delete_Item_Answer | u32, u16 | 0x51a4f0 | 0xa8 |
| 0x59d | 1437 | Gift_Item | GiftInfo, string, u32, u16 | 0x51acf0 | 0xac |
| 0x59e | 1438 | Answer_Gift | ItemInfo, u32, u16, u16 | 0x51b4a0 | 0xb0 |
| 0x59f | 1439 | Room_UpDataAvatar | AvatarInfo, u32 | 0x51c7f0 | 0xb4 |
| 0x5a0 | 1440 | Room_Change_Comment | string, u32 | 0x51c950 | 0xb8 |
| 0x5a1 | 1441 | EnableRoom | u8 (bool/byte) | 0x511360 (not overridden) | 0xbc |
| 0x5a2 | 1442 | Room_Member_Answer | u16, u16, HostID u32, array<RoomMember>, array<RoomSlotUser> | 0x5143e0 | 0xc0 |
| 0x5a3 | 1443 | Channel_RoomNumber_Answer | u32, u16 | 0x5127c0 | 0xc4 |
| 0x5a4 | 1444 | Lobby_Add_Rooms | array<RoomInfo>, u32 | 0x513ec0 | 0xc8 |
| 0x5a5 | 1445 | Lobby_Chat | HostID u32, string | 0x514a70 | 0xcc |
| 0x5a6 | 1446 | Room_Chat | HostID u32, string | 0x5150f0 | 0xd0 |
| 0x5a7 | 1447 | Cry | string | 0x514b40 | 0xd4 |
| 0x5a8 | 1448 | RankingAnswer | array<RankEntry> | 0x51bb30 | 0xd8 |
| 0x5a9 | 1449 | RankInfo_Answer | array<RankInfo>, array<RankInfo>, u32, u32, u32 | 0x514c10 | 0xdc |
| 0x5aa | 1450 | HS_Period_Check | HSBuffer, u32 | 0x51ce70 | 0xe0 |
| 0x5ab | 1451 | HS_Client_Out | u8 (bool/byte) | 0x51d0c0 | 0xe4 |
| 0x5ac | 1452 | Forced_Close | u16 | 0x512170 | 0xe8 |
| 0x5ad | 1453 | Add_Avatars | array<AvatarInfo> | 0x517eb0 | 0xec |
| 0x5ae | 1454 | Enter_Nation | u8, u16 | 0x512280 | 0xf0 |
| 0x5af | 1455 | Change_Nation | u8, u16 | 0x511440 (not overridden) | 0xf4 |
| 0x5b0 | 1456 | Updata_Ranking | array<RankEntry> | 0x51bf80 | 0xf8 |
| 0x5b1 | 1457 | Check_HS_Request | array<u8> | 0x51cb60 | 0xfc |
| 0x5b2 | 1458 | Room_Index_Request | u16 | 0x51cab0 | 0x100 |
| 0x5b3 | 1459 | RankingAnswer_Notice | array<RankEntry> | 0x51c380 | 0x104 |
| 0x5b4 | 1460 | User_New_Infor_Answer | u32 | 0x51cb00 | 0x108 |
| 0x5b5 | 1461 | GS2CL_Test | array<u8> | 0x51cb30 | 0x10c |


## Handler semantics (inferred unless stated). "result" = trailing u16, **0 = success** everywhere it was checked.
Client scene variable = `[0x9e9158]+0xa9760`. Observed values: 0xe = server-lobby / channel select, 0xf = character select
(first login), 2 = channel lobby (room list), 1 = waiting room (set by CGameUI_EnterRoomScene 0x45dd00).

### 0x579 Logon_GSCL (handler 0x511860) — REQUIRED
params: `HostID myHostId, LogonInfo info, u16 result, u32 a, u16 b, u32 gender, u32 age, string location`
- myHostId is stored at CGameClient+0x700 (confirmed: Enter_Room compares RoomMember.hostId against it to find "me").
  Send the client's real ProudNet HostID here.
- info is copied to CGameClient+0x120. info wire #4 (u32 @+0x10) -> converted to level via 0x4fc7c0 (EXP, inferred).
  wire #12..#15 (+0x28..+0x34) copied to globals. **wire #20 (u8 @+0x48, last field): 0 -> scene 0xe (channel select);
  != 0 -> scene 0xf (character select)**. Select_Character success clears it. Use 0 for an existing character.
- result: **0 = OK**; 1 = MessageBox "DB Login Failed" / "SC_FAILED"; 2 and 13 = localized error box then ExitProcess;
  3..12 = silently ignored (returns true, nothing happens).
- a -> CGameClient+0x174; b -> CGameClient+0x1a0 (and [+0x714]+0x44); gender (0 = "male", else "female"), age, location:
  only used to write banner.html for an ad banner.

### 0x582 Enter_Lobby (0x5121e0): `u16 result`
0 = OK: channel reset to 0xff, in-room state cleared; debug log "server lobby connect answer" (Korean). Non-zero -> error box.

### 0x580 Channel_List (0x512800): `array<ChannelInfo>`
For each element: CGameUI_SetChannelInfo(ChannelInfo.u8@+0x1a = channel index 0..5 (others ignored), u32@+0x8, u32@+0x4) — two
per-channel counters (likely current / max users, inferred). So only wire fields #1 (u32 +4), #2 (u32 +8) and #8 (u8 +0x1a) matter.

### 0x583 Enter_Channel (0x5122f0): `u8 channel, u16 result`
result 0 -> channel stored at CGameClient+0x1a3, scene = 2 (lobby / room list), UI refresh. channel == 0xff -> MessageBox.
result != 0 -> error box.

### 0x584 Leave_Channel (0x512470): `u16 result` — 0 -> back to scene 0xe.
### 0x585 Change_Channel: `u8 channel, u16 result` (same shape as Enter_Channel; not traced).

### 0x5a4 Lobby_Add_Rooms (0x513ec0): `array<RoomInfo>, u32 (unused)`
Fills the lobby room-list page. **Send at most 8 rooms** (no bounds check; writes 8 fixed UI slots).
Uses RoomInfo roomNumber(+4), +0xa (current players, inferred), maxPlayers(+0xb), +0xc (map code: >=0xf6 -> -0xf6, >=10 -> -10, else raw),
+0xd, title string (+0x10), +0x1c (room state, inferred), hasPassword (+0x25).

### 0x586 Create_Room (0x5151b0): `RoomInfo room, u16 unk, u16 result`
result 0 -> I am slot 0 / room master; room scene (1) opened. 0xe -> ignored. Other -> error box.
RoomInfo usage: roomNumber(+4) -> CGameClient+0x1a4; w08 -> global 0x132f0; maxPlayers(+0xb) = number of enabled slots out of 8;
b0d -> g+0x180; **maxLap (+0xf, confirmed by log "MaxLap is : %d")** -> g+0x17c; title (+0x10); password (+0x14); hasPassword (+0x25).

### 0x587 Enter_Room (0x515ac0): `array<RoomMember> members, array<AvatarInfo> avatars, u32 masterSlot, RoomInfo room, u16 result`
- result: **0 OK**; 1 "JoinRoom Fales"; 11 "PassWord Fales"; 12 "Room is Full"; 13 "Room is Playing"; 14 silent; 4 UI message 0xcf;
  8 localized message. (Log strings confirmed; matches ports.txt.)
- members: one per occupied slot; the entry whose hostId == myHostId (from Logon_GSCL) is "me". Fields used:
  slotIndex (+8, 0..7), order (+0x18, "MyOrder"), hostId (+0x1c), nickname string (+0x20), string (+0x24),
  userIndex (+0x28, "UserIndex"), exp (+0x30 -> level), ready u8 (+0x34), u8 (+0x35) -> player+0x38c, avatar/character u8 (+0x36, "Avator").
- avatars: matched to members by AvatarInfo.hostId (+8) == member.hostId; 9 of the 14 trailing u32 copied as equipped parts.
- masterSlot: player[masterSlot]+0x2ae = 1 (room master flag, inferred).
- room: as in Create_Room; then CGameUI_EnterRoomScene -> scene 1.

### Other room messages
- 0x588 Room_Add_User_Avatar: `AvatarInfo, RoomMember` — a player joined my room (inferred).
- 0x57f Room_Del_User: `HostID, u32, u32` — a player left (inferred hostId, slot, ?).
- 0x589 Leave_Room: `u16 result` (0 -> lobby scene 2). 0x58c Kicked_Room: `u16` (-> lobby).
- 0x597 Ready_Game (0x517e50): `HostID, u32 slot, u8 ready` -> player[slot]+0x2ac = ready (slot < 0 ignored). CONFIRMED.
- 0x599 New_RoomMaster: `u32 slot`.
- Room option broadcasts (inferred from names): 0x58a Change_Map `u8`, 0x590 Change_Lap `u8`, 0x591 Change_Attribute `u8`,
  0x592 Change_RandomMap `u8`, 0x58b Change_Type `u8, array<RoomMember>`, 0x58d Change_Team `u32 slot, u8 team`,
  0x58e CloseSlot_Room `u32 slot`, 0x58f OpenSlot_Room `u32 slot`, 0x5a0 Room_Change_Comment `string, u32`.

### 0x595 Start_Game (0x517d20): `StartGameInfo (NOT used by client), u16 a, u16 b, u16 result`
Only processed while scene == 1 (room), otherwise ignored. result 0: g+0x180 = a, g+0x17c = b (the same globals RoomInfo.b0d and
RoomInfo.maxLap feed, so a ~ mode/map, b ~ laps; inferred), sets race-start flag ([0x9e9158]+0xa976a = 1), calls 0x5084e0(4).
Regardless of result it then begins loading (0x490970, 0x4186e0) and clears per-slot flags. Log "Starting Game.. %d".
No race sync / finish / result RMI exists in GSCL: those must be in CLPE (P2P) / RealTime_Racing_Packet / CLGS.

### Chat
0x5a5 Lobby_Chat / 0x5a6 Room_Chat: `HostID sender, string text`. 0x5a7 Cry: `string` (server notice / shout, inferred).

### 0x59a Select_Character (0x5196c0): `u32 characterId, string, string, u16 result`
0 -> clears LogonInfo.needSelectCharacter, sets current character ("JoinRoom My Charac") = characterId, two strings into the character record.

### Inventory / shop / gifts
0x57b Add_Items `array<ItemInfo>`, 0x59b Insert_Item `ItemInfo, u16 result`, 0x59c Delete_Item_Answer `u32 itemId, u16 result`,
0x57c Add_Gifts `array<GiftInfo>`, 0x59d Gift_Item `GiftInfo, string, u32, u16 result`, 0x59e Answer_Gift `ItemInfo, u32, u16, u16`,
0x5ad Add_Avatars `array<AvatarInfo>` (owned avatars / characters, inferred), 0x59f Room_UpDataAvatar `AvatarInfo, u32`.

### Channel users / ranking / misc
- 0x57d Channel_UserList_Notify `array<ChannelUser>`, 0x581 Channel_UserList_Answer `HostID, array<ChannelUser>, u16, u8`.
- 0x5a8 RankingAnswer / 0x5b0 Updata_Ranking / 0x5b3 RankingAnswer_Notice `array<RankEntry>`; 0x5a9 RankInfo_Answer `array<RankInfo>, array<RankInfo>, u32, u32, u32`.
- 0x57a LogOut_OK (no params), 0x5ac Forced_Close `u16` (forced disconnect), 0x5ae Enter_Nation `u8, u16`,
  0x5a2 Room_Member_Answer `u16, u16, HostID, array<RoomMember>, array<RoomSlotUser>`, 0x5a3 Channel_RoomNumber_Answer `u32, u16`,
  0x5b2 Room_Index_Request `u16`, 0x5b4 User_New_Infor_Answer `u32`, 0x593 Mission_Answer `u8`, 0x5b5 GS2CL_Test `array<u8>`.
- HackShield: 0x5aa HS_Period_Check `HSBuffer, u32` (**never send**, see HSBuffer), 0x5ab HS_Client_Out `u8`, 0x5b1 Check_HS_Request `array<u8>`.

## Minimal happy path (server -> client)
1. Client connects to the game server and sends its logon (CLGS). Reply **Logon_GSCL**(myHostId = client's HostID,
   LogonInfo with last u8 = 0, result = 0, ...). Client -> scene 0xe (channel select).
   Optional: Add_Items / Add_Avatars / Add_Gifts (empty arrays are valid: i32 count 0).
2. On server-lobby / channel-list requests: **Enter_Lobby**(0) and **Channel_List**(ChannelInfo with channel index 0..5 in wire field #8).
3. On channel enter: **Enter_Channel**(channel, 0) -> scene 2 (room list). Then **Lobby_Add_Rooms**(<= 8 RoomInfo, 0).
4. Create: **Create_Room**(RoomInfo, 0, 0). Join: **Enter_Room**(members incl. me with hostId = myHostId, avatars, masterSlot, RoomInfo, 0).
   Others in the room get Room_Add_User_Avatar.
5. Ready: Ready_Game(hostId, slot, ready). Start: **Start_Game**(StartGameInfo any, a, b, 0) while the client is in the room scene.
6. Race runtime traffic is outside GSCL.

## Open questions
- Meaning of most LogonInfo fields (only #4 exp-ish and #20 needSelectCharacter known); Create_Room `unk`; Start_Game a/b exact meaning.
- Which of the two u8 readers is bool (no wire difference).
- ChannelInfo counters; RoomInfo +0x1c, slots1d[8], +0x26, +0x27; RoomMember +0x35; AvatarInfo part mapping.
- Race sync / finish is not in GSCL.

## Binary Ninja annotations made
GSCL_Stub_ProcessReceivedMessage (0x550250, function comment lists all IDs), jt_GSCL_Stub_RmiSwitch (0x55da73), g_GSCL_RmiNames (0x9e5948),
CMessage_Read_* readers, CGameClient_GSCL_<IdlName> for all 55 overridden handlers, CGameUI_EnterRoomScene (0x45dd00),
CGameUI_SetChannelInfo (0x470510). Types: GSCL_RoomInfo, GSCL_RoomInfoEx (named fields), GSCL_RoomMember, GSCL_AvatarInfo,
GSCL_ChannelInfo, GSCL_LogonInfo.
