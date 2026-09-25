# Session & Messenger RMI interfaces (Client5.exe) — reverse-engineered

Binary: Client5.exe (image base 0x400000). All addresses are VAs. "inferred" = meaning deduced from client usage.
Functions have been renamed in the BN database (SSCL_* / CLSS_* / MSCL_* / CLMS_* / CLPE2_* / CSessionClient_* / CMessengerClient_* / NetMgr_*).
Types added: MS_AvatarLook16, MS_FriendInfo, MS_MessageInfo, Proud_CNetConnectionParam_old.

## 0. Encoding rules (apply to every RMI below)
- Payload of an RMI message: `u8 MessageType_Rmi` + `u16 RmiID (LE)` + params in the listed order. No padding, no per-field markers.
  (CMessage has a "test splitter" flag at +0x18 that would append 0xFE after every field; its default comes from the
  const byte 0x6cf118 = 0, so it is OFF — never emit 0xFE markers.)
- `u8/u16/u32` = raw little-endian (`CMessage::Read(dst,N)` 0x5f8f00 / `CMessage_WriteRaw` 0x5729a0).
- `String` = Proud::String (wide). Writer 0x5faac0: `u8 type = 2` + compact-scalar char count + count×2 bytes UTF-16LE, no NUL.
  Reader 0x5fa900 accepts type 1 (ANSI, count bytes) or type 2 (UTF-16LE). Server should send type 2.
- compact scalar (0x62a990): `u8 size` in {1,2,4,8} then `size` bytes signed LE; writer picks the smallest that fits
  (-128..127 -> 1, -32768..32767 -> 2, int32 -> 4, else 8).
- **Arrays (`X[]`) use a raw `i32` element count (4 bytes LE), NOT a compact scalar**, followed by the elements
  (e.g. Read_FriendInfoArray 0x588ed0: Read(4) count, check 0 <= count < [0x9e6a88], then count × element). Writer 0x57a030 = 4-byte count.
- "u32 (HostID-typed)" = read with the Proud HostID reader 0x55dc90/0x5f9ad0 — still just 4 bytes LE.
- Client UI strings: file `StringEng.dll` (UTF-8 text, lines "N [text]") loaded by 0x4faf00 into `[0x9e90cc]+0x6d2+N*0x100`;
  "MSGn" below = line N of that file.

## 1. RMI ranges (stub dispatchers return false = "unknown RMI" for anything else)
| Interface | Direction | RmiID range | dispatcher / proxy vtable |
|---|---|---|---|
| SSCL | session->client | 0x8fd..0x8ff (2301..2303), explicit cmp per ID | Stub vtable 0x6c52b4, dispatcher 0x571370 |
| CLSS | client->session | 0x4b1..0x4b3 (1201..1203) | Proxy vtable 0x6c5218 |
| MSCL | messenger->client | 0xa8d..0xacb (2701..2763): `id-0xa8d > 0x3e` -> reject | Stub vtable 0x6c2a04, dispatcher 0x561850, jumptable 0x56fee6 |
| CLMS | client->messenger | 0xa29..0xa5a (2601..2650) | Proxy vtable 0x6c26ac |
| CLPE2 | peer<->peer (P2P) | 0xd49 (3401) only | Stub dispatcher 0x5722f0 (vtable 0x6c29dc), Proxy vtable 0x6c268c |

Proxy vtables: slot 5+2k = "multi-remote" overload, slot 6+2k = single-remote overload of RMI k (IDs consecutive).
Handler vtables: CSessionClient 0x6c5248 (slot 7+k = handler of SSCL RMI k), CMessengerClient 0x6c287c (slot 7+k = MSCL RMI k).
RMI debug-name tables (wide string pointers in RMI order): SSCL 0x9e5b4c.., CLSS 0x9e5d2c.., MSCL 0x9e5a50.., CLMS 0x9e5c64.., CLPE2 0x9e5b58 / 0x9e5d38.

## 2. Command line, connection flow, connection parameters

### Command line: `Client.exe <userID> <password> <launcherVersion>` (WinMain area ~0x407a87, argv = [0x9f1178])
- argv[1] missing -> MessageBox "Execute by Launcher.exe", exit.
- argv[3] = atoi -> stored as "%d" at [0x9e90cc]+0x2c4. **Must equal 4912160 (0x4AF420)** (0x407ba4):
  `< 4912160` -> ShellExecute("open","Launcher.exe") (auto-update) and exit; `> 4912160` -> "Execute by Launcher.exe", exit.
  It is only a launcher/patch-version gate; it is not sent to the session or messenger server.
- argv[1] (ID) and argv[2] (PW) are ANSI; NetMgr_SetLoginCredentials 0x54ac50 converts them to Proud::String (A2W, system code page)
  into NetMgr+0x34 (ID) and NetMgr+0x38 (PW). NetMgr = global object [0x9e8f48].
  If NetMgr+0x11 (session connection already set up) -> sends Logon_CLSS immediately, else connects to the session server.

### Session server connect — NetMgr_ConnectSessionServer 0x54b510 -> CSessionClient_Connect 0x59c900
- IP = GetPrivateProfileStringA("SERVER","SESSIONIP", default, "<exe dir>\cliconfg.inp"); port = GetPrivateProfileIntA("SERVER","SESSIONPORT",0,...)
  (stored at CSessionClient+0x48 / +0x66; CSessionClient lives at NetMgr+0x74).
- CNetConnectionParam (ctor 0x5f7670): +0 serverIP (Proud::String), +4 u16 serverPort, +8 Guid protocolVersion,
  +0x18 ByteArray userData (**left empty — no user data sent**), +0x38 double (default 0.0, untouched).
  Then CNetClient::Connect = netclient vtbl+0x3c.
- **Protocol version GUIDs**: base GUID at 0x9e7cfc: `c6 dd 3a 68 40 67 5b 48 af 8d 88 18 c1 cc 04 3c`
  ({683ADDC6-6740-485B-AF8D-8818C1CC043C}). NetConfig singleton (GetNetConfig 0x50c210, ctor 0x67b670) holds it; getters add to Data1 (first LE dword):

  | server | getter | Data1 | exact 16 bytes (memory/wire order) |
  |---|---|---|---|
  | Session | 0x67b970 (+5) | 0x683ADDCB | `cb dd 3a 68 40 67 5b 48 af 8d 88 18 c1 cc 04 3c` |
  | Messenger | 0x67b8d0 (+4) | 0x683ADDCA | `ca dd 3a 68 40 67 5b 48 af 8d 88 18 c1 cc 04 3c` |
  | Game (reference) | 0x67b790 (+1) | 0x683ADDC7 | `c7 dd 3a 68 40 67 5b 48 af 8d 88 18 c1 cc 04 3c` |

  (0x67b830 gives +3, 0x67ba10 another +5 — other/unused.) The NetConfig ctor also stores ports 21111, 22111, 23111, 24111, 25111 and
  wide strings "Hovorun", "85.158.207.76" (defaults, not used by the session/messenger connect code).
- **OnJoinServerComplete** (CSessionClient 0x59ca80): on failure (ErrorInfo type != 0) logs "connection to server failed" and **immediately reconnects** (0x59c900).
  On success: CSessionClient+0x40=1, then SessionLogin_SendLogonCLSS 0x54b310 -> **first RMI = CLSS 0x4b1 Logon_CLSS(ID, PW)**. Nothing else is sent.
  OnLeaveServer 0x59c8e0 only clears +0x40.

### Messenger server connect — NetMgr_ConnectMessengerServer 0x54b870 -> CMessengerClient_Connect 0x5331d0
- Called from NetMgr_SendEnterLobby 0x5238e0 (itself called by the GSCL Logon_GSCL handler after game-server login succeeds, and from 0x54ae30),
  only if the messenger-logged-in byte [0x9ea0cc] == 0.
- IP/port: cliconfg.inp [SERVER] MESSENGER_IP / MESSENGER_PORT (NetMgr+0x16ec / +0x170a; CMessengerClient at NetMgr+0x7fc).
  Same CNetConnectionParam usage, messenger GUID (+4), empty userData. If Connect() fails -> MSG74 "Messenger server connection failed".
- OnJoinServerComplete (0x533350): failure -> reconnect immediately; success -> msgr+0xee8=1, NetMgr_SendLogonCLMS 0x54b9b0 ->
  **first RMI = CLMS 0xa29 Logon_CLMS(ID, PW)** (same strings as session).
- After MSCL Logon_MSCL result 0 the client sends CLMS Change_Position (0xa31) and CLMS Clan_List (0xa43, no params).

---
## 3. SSCL (session -> client)

### 0x8fd (2301) User_Logon_SSCL — handler CSessionClient_User_Logon_SSCL 0x59c510
| # | type | meaning |
|---|---|---|
| 1 | u8 | nation / server-group number, **1-based** (client stores value-1 at CSessionClient+0x18) |
| 2 | String | game server IP (logged "add = %s") |
| 3 | u16 | game server TCP port (logged "port = %d") |
| 4 | u16 | result code |

Result codes (switch at 0x59c593, index table 0x59c753):
- **0 = success**: global state [0x9e5944]=2, app+0x275=1, CSessionClient+0x38=1, then GameConn_ConnectToGameServer 0x54b710(ip, port):
  stores ip -> NetMgr+0x7f0, port -> +0x7f4 and connects the game client; if Connect() fails: MSG69 "Game Server not connected" + "Not connect GameServer." box and the app exits.
- 2 = MSG61 "Repeated login attempts"
- 3 = MSG62 "Visit the Hovorun website at hovorun.gamersoxygen.com"
- 10 = MSG60 "Visit the Hovorun website at hovorun.gamersoxygen.com"
- 11 = MSG59 "Wrong Password. Try again."
- (2/3/10/11 set state 9 and clear app+0x690.) 1, 4..9, >= 12: no reaction at all (client hangs) — don't use.
  Params 1-3 are only used on success; on failure send anything (e.g. 0, empty string, 0).

### 0x8fe (2302) Change_Nation — handler 0x59c760
Same layout as 0x8fd: `u8 nation (1-based), String gameServerIP, u16 gameServerPort, u16 result`.
- result == 1 -> MessageBox "Server Error".
- otherwise -> store nation-1, disconnect current game server (0x54b6c0), connect to new ip/port (0x54b710).

### 0x8ff (2303) Forced_Close — handler 0x59c840
| # | type | meaning |
|---|---|---|
| 1 | u16 | reason |
- 2 -> MSG58 "Someone is trying to play Hovorun using your username" (duplicate-login kick).
- other -> logs "%d: session server connection terminated" and deletes the session net client object (CSessionClient+0x1c).

## 4. CLSS (client -> session)
| RmiID | name | sender fn | params | when |
|---|---|---|---|---|
| 0x4b1 (1201) | Logon_CLSS | 0x5857a0 | String userID; String password | first RMI after session connect (0x54b310), and on re-login (0x54ac50) |
| 0x4b2 (1202) | Change_Nation | 0x5859e0 | u8 nation | NetMgr_SendChangeNation 0x523a20 when the player picks another nation/server group (!= NetMgr+0x94); the same value is also sent to the game server via CLGS (vtbl+0x1c0). Base (0/1) not verified; the reply SSCL 0x8fe is treated as 1-based. |
| 0x4b3 (1203) | Logout_CLSS | 0x585c20 | (none) | no call site found (proxy slot +0x28 never called on NetMgr+0x9c) |

---
## 5. Messenger structs (wire order = read order; "+off" = client struct offset, for reference only)

**AvatarLook16** (Read_AvatarLook16 0x5711e0), 16 bytes: `u32 (+4)`, `u16 (+0)`, `u16 (+2)`, `u8[8] (+8..+0xf)`. Character/equipment look (inferred).

**FriendInfo** (Read_FriendInfo 0x571040), wire order:
1. u16 roomNo (+4; updated by MSCL Change_Position)
2. u32 (+8)
3. u32 friend user index (+0xc, HostID-typed reader; lookup key)
4. String (+0x10) — nickname/ID (inferred)
5. AvatarLook16 (+0x14)
6. u8 (+0x24; = 5th param of Change_Position), u8 channel (+0x25), u8 (+0x26), u8 (+0x27)
7. u32 (+0x28)
8. String (+0x2c), String (+0x30)

**MessageInfo** (mail; Read_MessageInfo 0x570580): u32 (+4, message index, inferred); u32 receiver user index (+8; compared with own index from Logon_MSCL); u32 (+0xc); u8 (+0x10); u8 (+0x11); String (+0x14); String (+0x18); String (+0x1c) (sender, text, date — inferred).

**ClanInfo** (Read_ClanInfo 0x570060 == Write_ClanInfo 0x583810), wire order:
u32 (+4); String (+0x54); String (+0x58); 13 × u32 (+0x8, +0xc, ..., +0x38); u32 (+0x3c); 9 × u16 (+0x40..+0x50); u8 (+0x68); String (+0x5c); String (+0x60); String (+0x64); 5 × u8 (+0x69..+0x6d).
(Find_Clan_Request logs "Clan Name [%s], Clan Master [%s], Clan Member [%d]" -> the first two Strings are probably clan name / master name.)

**ClanMemberInfo** (0x570750): u32 (+4); u32 (+8, via 0x5871f0); String (+0xc); String (+0x10); u16 (+0x14); 10 × u32 (+0x18..+0x3c); u8 (+0x40); u8 (+0x41); 4 × u16 (+0x42..+0x48); String (+0x4c); u16 (+0x50); u8 (+0x52).
(MSCL Change_Position also writes +0x40/+0x41/+0x42 of the clan member = the same position triple.)

**ClanBoardInfo** (0x570be0): u32 (+4), u32 (+8), u32 (+0xc), u8 (+0x10), String (+0x14), String (+0x18), String (+0x1c).

**ClanJoinUserInfo** (0x570d80): u32 (+0), u32 (+4), String (+8), String (+0xc), String (+0x10).

**ClanInvitationInfo** (0x570ed0): u32 (+4), u32 (+8), u32 (+0xc), String (+0x10), String (+0x14), String (+0x18).

**ClanListEntry** (0x589550): u32 (+4), u32 (+8), u32 (+0xc), u16 (+0x10), u16 (+0x12), String (+0x14), String (+0x18), String (+0x1c), u8 (+0x20).

**RankInfo** (0x588bd0, shared with GSCL): u16 (+4), u16 (+6), u16 (+8), u32 (+0xc), u32 (+0x10), String (+0x14), String (+0x18).

**UserClanEntry** (0x588470, same reader the GSCL worker named RoomSlotUser): String (+4), String (+8), u32 (+0xc), u32 (+0x10), u16 (+0x14), u16 (+0x16), u8 (+0x18).

`X[]` = i32 count + count × X.

## 6. MSCL (messenger -> client)

Every handler also receives (HostID remote, RmiContext) first; those are not on the wire.

| ID | dec | name | CMessengerClient handler | params (wire order) | notes |
|---|---|---|---|---|---|
| 0xa8d | 2701 | Logon_MSCL | 0x541890 | u8; u32; u8; u16; u32; u16 | Logon result. p1 u8 clanFlag? (==1 sets app 'in clan' flag +0x132ed; stored msgr+0x74, also gates clan-member updates), p2 u32 = my user index (msgr+0x24, used to recognise mail addressed to me), p3 u8 = has-new-mail flag (app+0x13496), p4 u16 unused by handler, p5 u32 -> msgr+0x360 (clan index? inferred), p6 u16 result: 0=OK (state 5, then client sends Change_Position + Clan_List), 2='duplicate login, retry?' dialog, other=MSG74 'Messenger server connection failed'. |
| 0xa8e | 2702 | Forced_Close | 0x5419f0 | u16 | u16 reason (handler 0x5419f0). |
| 0xa8f | 2703 | Load_Agree_User | 0x541a20 | FriendInfo[] (i32 count + N x FriendInfo) |  |
| 0xa90 | 2704 | Change_Relation | 0x541bf0 | u32 (HostID-typed reader; user index); String; u32; u32 | Friendship broken by peer: p1 u32 (HostID-typed), p2 String peer name, p3 u32, p4 u32 type/result: 9 -> MSG73 'Break of friendship by %s' (else ignored). |
| 0xa91 | 2705 | Change_Position | 0x542d00 | u32 (HostID-typed reader; user index); u32; u16; u8; u8 | Friend/clan-member moved: p1 u32 (HostID-typed, unused), p2 u32 friend userIdx (lookup key), u16 roomNo, u8 channel (log '%d channel %d room'), u8 (stored friend+0x24). Stored in friend entry +4/+0x25/+0x24. |
| 0xa92 | 2706 | Change_State | 0x542df0 | u32 (HostID-typed reader; user index); u32; u16 | Friend online state: p1 u32 (HostID-typed, unused), p2 u32 friend userIdx, u16 state: 1 = logged in (shows MSG70 'Logged in'), 0 = logged out (inferred). |
| 0xa93 | 2707 | Insert_Friend | 0x5422d0 | u32 (HostID-typed reader; user index); u32 (HostID-typed reader; user index); FriendInfo; u16 | Add-friend result: HostID, u32, FriendInfo, u16 result: 0=OK (friend added to list), 9=MSG71 'Already registered', 1/17=MSG72 'Friend addition failed', others silent. |
| 0xa94 | 2708 | Agree_Friend | 0x541d50 | u32 (HostID-typed reader; user index); String |  |
| 0xa95 | 2709 | Agree_Friend_Result | 0x541e20 | u32 (HostID-typed reader; user index); String; FriendInfo; u8; u16 |  |
| 0xa96 | 2710 | Agree_Friend_AnswerResult | 0x541fb0 | FriendInfo; u8; u16 |  |
| 0xa97 | 2711 | Updata_Friend_Point | 0x5421b0 | u32 (HostID-typed reader; user index); u32; u32 |  |
| 0xa98 | 2712 | Update_Friend_Info | 0x542200 | FriendInfo; u8 |  |
| 0xa99 | 2713 | Delete_Friend_UserID | 0x5425c0 | String; u16 |  |
| 0xa9a | 2714 | Add_Friend_Info | 0x542790 | FriendInfo[] (i32 count + N x FriendInfo); u16 |  |
| 0xa9b | 2715 | Whisper_UserIndex | 0x543040 | String; String; u8 | Incoming whisper: String fromUserID, String message, u8 (flag). |
| 0xa9c | 2716 | Whisper_Answer | 0x5433d0 | String; u16 | Whisper failed: String targetName, u16 result (9 -> '[%s] is Empty' i.e. user not online). |
| 0xa9d | 2717 | Invitation | 0x5434b0 | String; u32; String |  |
| 0xa9e | 2718 | Invitation_Answer | 0x543710 | String; u8 | Invitation answer: String name, u8 result: 1='user not connected / not exist', 2='currently racing', 3='declined'. |
| 0xa9f | 2719 | User_Logon | 0x541400 | String; String | Not overridden by CMessengerClient (default stub) - unused. |
| 0xaa0 | 2720 | Send_Message | 0x5438c0 | MessageInfo; u16 | Mail result/notify: MessageInfo, u16 result: 1=ignored, 15=MSG155 'User name Not Found', else if msg.receiverUserIndex==myIdx -> new mail arrives, otherwise MSG146 'Message sent'. |
| 0xaa1 | 2721 | Delete_Message | 0x543b80 | u32; u16 |  |
| 0xaa2 | 2722 | Create_Clan | 0x543bc0 | ClanInfo; ClanMemberInfo; u32; ClanBoardInfo; u16 | Create clan result: ClanInfo, ClanMemberInfo, u32, ClanBoardInfo, u16 result: 8=MSG115 success, 9=MSG114 failed, 10=MSG113 name exists, 11=MSG106 already in clan, 14='Empty ClanName', 15='Duplicate emblem! Try again please!'. |
| 0xaa3 | 2723 | Join_Clan | 0x544110 | String; u8; u8; MessageInfo; u32; u16 | Join clan result: String, u8, u8, MessageInfo, u32, u16 result: 0=MSG112 request sent, 1=MSG109 failed, 3=MSG106 already in clan, 4=MSG110 waiting approval, 6=MSG111 clan does not exist, 9='Clan User is FULL'. |
| 0xaa4 | 2724 | Join_Clan_Request | 0x544690 | ClanJoinUserInfo |  |
| 0xaa5 | 2725 | Join_Clan_Answer | 0x5447f0 | u32; u8; MessageInfo; u32; String; u16 | Join request answered: ... u16 result: 1 => MSG208 declined, 9 => 'Clan User is FULL', else MSG207 approved. |
| 0xaa6 | 2726 | Delete_JoinUser | 0x544ca0 | u32 |  |
| 0xaa7 | 2727 | Secede_Clan | 0x544ce0 | u16 | Secede result u16: 0=MSG224 withdrawn, 3=?, 18(0x12)=MSG223 kicked out. |
| 0xaa8 | 2728 | Secede_Clan_Member | 0x544f10 | String; ClanInfo |  |
| 0xaa9 | 2729 | Dissolve_Clan | 0x544fa0 | u16 | Dissolve result u16: 0=MSG107 disbanded, 3=MSG108 not in clan, 5=MSG105 only clan master. |
| 0xaaa | 2730 | Clan_Mandate | 0x5452c0 | u16 |  |
| 0xaab | 2731 | Clan_Mandate_Select | 0x545300 | u32 |  |
| 0xaac | 2732 | Clan_Mandate_Answer | 0x545330 | u32; u32; String; u8; u16 |  |
| 0xaad | 2733 | JoinUser_Clan | 0x545550 | ClanJoinUserInfo[]; u16 |  |
| 0xaae | 2734 | Clan_JoinUser_List_Answer | 0x545790 | ClanJoinUserInfo[]; u16 |  |
| 0xaaf | 2735 | Message_Info | 0x5459e0 | MessageInfo[]; u16 |  |
| 0xab0 | 2736 | Add_ClanMember | 0x545c50 | u32 |  |
| 0xab1 | 2737 | Add_ClanMembers | 0x545cc0 | ClanInfo; ClanMemberInfo[] |  |
| 0xab2 | 2738 | ClanMembers_Info | 0x5461c0 | ClanMemberInfo[]; u32; u16 |  |
| 0xab3 | 2739 | Add_New_ClanMember | 0x5465b0 | ClanMemberInfo |  |
| 0xab4 | 2740 | Logout_ClanMember | 0x546bf0 | u32 |  |
| 0xab5 | 2741 | Clan_List_Request | 0x546c40 | ClanListEntry[]; u16 |  |
| 0xab6 | 2742 | Find_Clan_Request | 0x546e90 | ClanInfo |  |
| 0xab7 | 2743 | Clan_Chatting | 0x5470d0 | String |  |
| 0xab8 | 2744 | Check_Clan_Name | 0x5471f0 | String; u16 | Check clan name: String, u16 result: 0 => MSG211 'This clan already exists!', nonzero => MSG210 'This name is available.' |
| 0xab9 | 2745 | Board_Clan | 0x547270 | ClanBoardInfo; ClanBoardInfo[] |  |
| 0xaba | 2746 | Clan_NoticeBoard_Info | 0x547480 | ClanBoardInfo; ClanInfo |  |
| 0xabb | 2747 | Clan_Board_Info | 0x5474b0 | ClanBoardInfo[]; ClanBoardInfo |  |
| 0xabc | 2748 | Clan_Board_Info_40 | 0x5476c0 | ClanBoardInfo[]; u16 |  |
| 0xabd | 2749 | Notice_Clan_Board | 0x5478d0 | String |  |
| 0xabe | 2750 | Clan_Board | 0x547970 | ClanBoardInfo |  |
| 0xabf | 2751 | UpDate_Clan_Info | 0x547c60 | ClanInfo |  |
| 0xac0 | 2752 | UpData_Clan_MemberScore | 0x547ca0 | ClanInfo; ClanMemberInfo |  |
| 0xac1 | 2753 | UpDate_Clan_ReSetPoint | 0x547e00 | u16; u16; u8 |  |
| 0xac2 | 2754 | Clan2Member_Message | 0x547f20 | MessageInfo; u16 |  |
| 0xac3 | 2755 | Clan2User_Invitation | 0x5480f0 | u16 |  |
| 0xac4 | 2756 | Clan2User_Invitation_Request | 0x548110 | ClanInvitationInfo |  |
| 0xac5 | 2757 | Clan2User_Invitation_Request_vector | 0x548290 | ClanInvitationInfo[] |  |
| 0xac6 | 2758 | Clan2User_Invitation_Answer_Answer | 0x548490 | ClanInvitationInfo[] |  |
| 0xac7 | 2759 | RankInfo_Answer | 0x5484a0 | RankInfo[]; RankInfo[]; u32; u32 |  |
| 0xac8 | 2760 | Check_Clan_Emblem | 0x548940 | u32; u32; u16 |  |
| 0xac9 | 2761 | Delete_Clan_Board | 0x548980 | u32; u16 |  |
| 0xaca | 2762 | Buy_Clan_Item_Answer | 0x5489c0 | u32; u16; u16; u16 |  |
| 0xacb | 2763 | Find_User_Clan_Answer | 0x5489d0 | UserClanEntry[] (same struct as GSCL RoomSlotUser reader 0x588470) |  |

## 7. CLMS (client -> messenger)

| ID | dec | name | proxy fn (single remote) | params (wire order) | notes |
|---|---|---|---|---|---|
| 0xa29 | 2601 | Logon_CLMS | 0x57ddc0 | String; String | String userID, String password (same as session). Sent from NetMgr_SendLogonCLMS 0x54b9b0 in CMessengerClient::OnJoinServerComplete. |
| 0xa2a | 2602 | Load_Agree_User | 0x57e000 | u32; String |  |
| 0xa2b | 2603 | Add_Friend_Nick | 0x57e260 | u32; String |  |
| 0xa2c | 2604 | Add_Friend_UserID | 0x57e4c0 | u32; String |  |
| 0xa2d | 2605 | Add_Friend_FriendID | 0x57e720 | u32; u32 |  |
| 0xa2e | 2606 | Agree_Friend_Answer | 0x57e9a0 | String; u8 |  |
| 0xa2f | 2607 | Del_Friend | 0x57ec00 | u32; u32 |  |
| 0xa30 | 2608 | Del_Friend_UserID | 0x57ee80 | String |  |
| 0xa31 | 2609 | Change_Position | 0x57f0a0 | u16; u8; u8 | u16 roomNo, u8 (NetMgr+0x287), u8 (NetMgr+0x286) - own position; sent right after Logon_MSCL OK (0x54e730). |
| 0xa32 | 2610 | Whisper_UserIndex | 0x57f360 | u32; String; u8 | u32 target user index, String message, u8 |
| 0xa33 | 2611 | Whisper_UserID | 0x57f600 | String; String; u8 | String targetUserID, String message, u8 |
| 0xa34 | 2612 | Invitation | 0x57f880 | String; u32; String |  |
| 0xa35 | 2613 | Invitation_Answer | 0x57fb00 | String; u8 |  |
| 0xa36 | 2614 | Update_TotalPoint | 0x57fd60 | u32; u32; u8 |  |
| 0xa37 | 2615 | Clan_Race_Result | 0x580020 | String; String; u32; u32; u8 |  |
| 0xa38 | 2616 | Send_Message | 0x580320 | u32; String | u32 receiver user index, String text |
| 0xa39 | 2617 | Send_Message_Id | 0x580580 | String; String | String receiverUserID, String text |
| 0xa3a | 2618 | Get_Message | 0x5807c0 | u16 |  |
| 0xa3b | 2619 | Delete_Message | 0x580a00 | u32 |  |
| 0xa3c | 2620 | Create_Clan | 0x580c40 | u16; u16; String; String; u32; String |  |
| 0xa3d | 2621 | Join_Clan | 0x580f40 | u32; String |  |
| 0xa3e | 2622 | Join_Clan_Name | 0x5811a0 | String; String |  |
| 0xa3f | 2623 | Secede_Clan | 0x5813e0 | (none) |  |
| 0xa40 | 2624 | Dissolve_Clan | 0x5815e0 | String |  |
| 0xa41 | 2625 | Info_Clan | 0x581800 | u32 |  |
| 0xa42 | 2626 | ClanInfo_Request | 0x581a40 | (none) |  |
| 0xa43 | 2627 | Clan_List | 0x581c40 | (none) | no params; sent after Logon_MSCL OK (0x522250) |
| 0xa44 | 2628 | Clan_Member_List | 0x581e40 | u16 |  |
| 0xa45 | 2629 | Clan_Mandate | 0x582080 | u32 |  |
| 0xa46 | 2630 | Clan_Mandate_Selected | 0x5822c0 | u32; u32; u8 |  |
| 0xa47 | 2631 | Find_Clan | 0x582580 | String |  |
| 0xa48 | 2632 | Find_Clan_Index | 0x5827a0 | u32 |  |
| 0xa49 | 2633 | Clan_Answer | 0x5829e0 | String; u8 |  |
| 0xa4a | 2634 | Clan_JoinUser_List_Request | 0x582c40 | u16 |  |
| 0xa4b | 2635 | Clan_Chat | 0x582e80 | String |  |
| 0xa4c | 2636 | Check_Clan_Name | 0x5830a0 | String |  |
| 0xa4d | 2637 | Notice_Board | 0x5832c0 | String |  |
| 0xa4e | 2638 | Clan_Board | 0x5834e0 | String |  |
| 0xa4f | 2639 | Update_Clan_Info | 0x583700 | ClanInfo | ClanInfo (Write_ClanInfo 0x583810, same layout as reader) |
| 0xa50 | 2640 | Clan_To_Member_Message | 0x583ee0 | String |  |
| 0xa51 | 2641 | Clan_To_ClanMaster_Message | 0x584100 | String |  |
| 0xa52 | 2642 | Clan_To_User_Invitation | 0x584320 | String |  |
| 0xa53 | 2643 | Clan_To_User_Invitation_Answer | 0x584540 | String; u8 |  |
| 0xa54 | 2644 | RankInfo_Request | 0x5847a0 | (none) |  |
| 0xa55 | 2645 | Check_Clan_Emblem | 0x5849a0 | u32; u32 |  |
| 0xa56 | 2646 | Delete_Clan_Board | 0x584c20 | u32 |  |
| 0xa57 | 2647 | Buy_Clan_Item | 0x584e60 | u32; u16; u16 |  |
| 0xa58 | 2648 | Clan_Kick_Out | 0x585120 | String |  |
| 0xa59 | 2649 | Find_User_Clan | 0x585340 | String[] | String[] (i32 count + N x String) |
| 0xa5a | 2650 | CL2MS_Test | 0x585560 | u8 |  |

Known CLMS call sites (NetMgr+0x16bc is the CLMS proxy): Logon 0x54b9cf; Add_Friend_Nick 0x54bc65; Add_Friend_UserID 0x54bea2; Agree_Friend_Answer 0x4dfc5c/0x4dfd73;
Del_Friend 0x54bf55; Del_Friend_UserID 0x54c06d; Change_Position 0x54e76f; Whisper_UserIndex 0x54eb56; Whisper_UserID 0x54ed84; Invitation 0x54ef9c/0x54f10a/0x54f275;
Update_TotalPoint 0x52618e/0x54d44b; Clan_Race_Result 0x5237b6/0x54e400; Send_Message 0x54f82a; Send_Message_Id 0x54fa70/0x54fc58; Get_Message 0x54faec;
Delete_Message 0x54fb3a; Create_Clan 0x521ed7; Join_Clan 0x521ff5; Join_Clan_Name 0x522107; Secede_Clan 0x522171; Dissolve_Clan 0x5221ea;
ClanInfo_Request 0x522231/0x5225f0; Clan_List 0x522261; Clan_Mandate 0x52340b/0x54dff6; Clan_Mandate_Selected 0x4eff1f/0x4effe2/0x54e0ab; Find_Clan 0x52232a;
Find_Clan_Index 0x522385; Clan_Answer 0x52244e; Check_Clan_Name 0x52272f; Notice_Board 0x52292c; Clan_Board 0x522ab7; Update_Clan_Info 0x522da3;
Clan_To_Member_Message 0x522f54; Clan_To_ClanMaster_Message 0x54fa41; Clan_To_User_Invitation 0x52304a; Clan_To_User_Invitation_Answer 0x52313e;
RankInfo_Request 0x54fcdd; Check_Clan_Emblem 0x5231b9; Delete_Clan_Board 0x5231f5; Clan_Kick_Out 0x52357a/0x54e19d; Find_User_Clan 0x523614.
No call site found by the `add ecx,0x16bc; call [reg+X]` scan: Load_Agree_User, Add_Friend_FriendID, Invitation_Answer, Info_Clan, Clan_Member_List,
Clan_JoinUser_List_Request, Clan_Chat, Buy_Clan_Item, CL2MS_Test (they may be reached another way).

## 8. CLPE2 (P2P between clients in the messenger P2P group)
- 0xd49 (3401) UDP_ClanChat: `String text; u32; u8`. Proxy 0x585e20 (multi 0x585f70); stub dispatcher 0x5722f0 reads String, Read(4), Read(1);
  handler = CMessengerClient vtable 0x6c2854 slot 7 (0x5334d0). Only RMI of this interface. The server only matters here if it relays P2P traffic.

## 9. Open questions
- Exact meaning of many u32/u8 fields in FriendInfo / ClanInfo / ClanMemberInfo (order and sizes are certain; semantics mostly unknown).
- Logon_MSCL p1/p4/p5 semantics are inferred; p4 is ignored by the client.
- Base (0- vs 1-based) of the CLSS Change_Nation u8.
- Logout_CLSS has no found call site.
