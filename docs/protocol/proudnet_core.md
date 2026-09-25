# ProudNet (old) core layer — Client5.exe

Every address in this doc is a Client5.exe VA. "C2S" means client to server, "S2C" means server to client.
Every integer is little-endian unless the text says otherwise.

**Important finding:** Client5.exe also links the ProudNet **server** (`CNetServerImpl`, `Stub@ProudC2S`,
`Proxy@ProudS2C`, `CP2PGroup_S`). I used the embedded server code to cross-check the handshake. Its functions
are renamed `CNetServerImpl_*` in the BN database.

## 0. Wire primitives

| name | encoding | reader / writer |
|---|---|---|
| u8/bool | 1 byte | 0x5d86c0, 0x587140 / 0x579fc0, 0x574270 |
| u16 | 2 bytes LE | 0x5d86f0, 0x5d9060 / 0x5e1590 |
| u32/i32/HostID | 4 bytes LE | 0x5871b0, 0x5f9ad0 / 0x57a030, 0x5e1650, 0x5f9f20 |
| f64 | 8 bytes (reader byte-aligns first) | 0x5f9790 / 0x5e17d0 |
| f32 | 4 bytes | ? / 0x5e1710 |
| cs (compact scalar) | u8 N in {1,2,4,8} + N bytes signed LE | 0x5f9650 / 0x5fa890 (writer picks smallest size) |
| ByteArray | cs length + bytes. Length must satisfy 0 <= len <= MessageMaxLength (global 0x9e6a88, default 0x100000) | 0x5dde60, 0x6030f0 / 0x5e8ce0 |
| Guid | 16 raw bytes (Windows GUID memory layout: Data1 LE, Data2 LE, Data3 LE, Data4 bytes) | 0x5d8750 / 0x5e1890 |
| AddrPort | u32 IPv4 (in_addr raw bytes a.b.c.d) + u16 port (LE host order) | 0x5f9a80, 0x5d9110 / 0x5fa010 |
| String | u8 type (1 = ANSI bytes, 2 = UTF-16LE) + cs charCount + chars | 0x5fa650, 0x5fa460 / 0x5faac0 |
| NamedAddrPort | String hostname-or-ip + u16 port | 0x5fa9f0 |
| RelayDestList | cs count + count × {u32 HostID, u32 frameNumber} | ? / 0x5fa9b0 |

The writers 0x579fc0 and 0x57a030 append an extra 0xFE after each value if CMessage+0x18 (the "debug tag"
flag) is set. That flag is off in normal traffic. The server must not emit it.

TCP framing is the same as in CONTEXT.md: `13 57` + cs payloadLen + payload. Payload byte 0 is the MessageType.

## 1. MessageType enum (verified against dispatcher 0x608390 and client send code)

`S` = handled by the client (the server sends it). `C` = the client sends it. The client dispatcher ignores
a C type if one arrives.

| # | name | dir | notes / handler |
|---|---|---|---|
| 1 | Rmi | both | 0x607ed0. [u16 RmiID][params]. Tried in order: ProudS2C stub, then C2C stub, then user stubs |
| 2 | UserMessage | both | 0x608130. The rest of the payload goes to the user as raw bytes |
| 3 | ConnectServerTimedout | S | 0x601e80. No payload. ErrorType 7, then disconnect |
| 4 | NotifyServerConnectionHint | S | 0x605b30. See §2 |
| 5 | NotifyCSPublicKey | C | Client RSA PUBLICKEYBLOB. See §2 |
| 6 | NotifyCSEncryptedSessionKey | S | 0x607280. SIMPLEBLOB. See §2 |
| 7 | NotifyServerConnectionRequestData | C | See §2 |
| 8 | NotifyProtocolVersionMismatch | S | 0x601ed0. No payload read. ErrorType 8, then disconnect |
| 9 | NotifyServerDeniedConnection | S | 0x601f20. The client reads no payload. The embedded server sends a ByteArray after the type byte; the client ignores it. ErrorType 9, then disconnect |
| 10 | NotifyServerConnectSuccess | S | 0x6076e0. See §2 |
| 11 | RequestStartServerHolepunch | S | 0x601e20. [Guid magic]. Stored at (client+0xc4c)->+4 |
| 12 | ServerHolepunch | C (UDP) | [Guid magic]. Sent (0x5ec580) to the server UDP addr |
| 13 | ServerHolepunchAck | S (UDP) | 0x604430. [Guid magic][AddrPort clientAddrSeenByServer]. Magic must match, and the sender must be the server UDP addr |
| 14 | NotifyHolepunchSuccess | C (TCP) | [Guid magic][AddrPort clientLocalUdpAddr][AddrPort clientAddrSeenByServer] |
| 15 | NotifyClientServerUdpMatched | S | 0x607580. [Guid magic]. Enables server-UDP |
| 16 | PeerUdp_ServerHolepunch | C (UDP) | Inferred |
| 17 | PeerUdp_ServerHolepunchAck | S (UDP) | 0x6033a0. [Guid magic][AddrPort][u32 peerHostID] |
| 18 | PeerUdp_NotifyHolepunchSuccess | C | Inferred |
| 19 | ReliableUdp_Frame | peer<->peer (UDP) | 0x606070. [u8 frameType] then: type 1 (data) = [u32 frameNumber][cs len][bytes]; type 2 (ack) = [ackList][u32][u32] (serializer 0x6314e0) |
| 20 | ReliableRelay1 | C | See §7 |
| 21 | UnreliableRelay1 | C | See §7 |
| 22 | ReliableUdpFrameRelay1 ("LingerDataFrame1") | C | See §7 |
| 23 | ReliableRelay2 | S | 0x606370. See §7 |
| 24 | UnreliableRelay2 | S | 0x603510. See §7 |
| 25 | ReliableUdpFrameRelay2 ("LingerDataFrame2") | S | 0x6066d0. See §7 |
| 26 | RequestServerTimeAndKeepAlive | C | [f64 clientLocalTime][f64 clientAvgPing]. See §5 |
| 27 | SpeedHackDetectorPing | C | No payload. See §5 |
| 28 | ReplyServerTimeAndKeepAlive | S | 0x607ce0. [f64 echoedClientTime][f64 serverTime] |
| 29 | (ignored by the client) | ? | The jump table routes it to "handled, do nothing" |
| 30 | PeerUdp_PeerHolepunch | peer | 0x601700 -> 0x622080. [u32 peerHostID][Guid peerMagic][Guid serverInstanceGuid][AddrPort] |
| 31 | PeerUdp_PeerHolepunchAck | peer | 0x601730 -> 0x622760 |
| 32 | P2PIndirectServerTimeAndPing | peer | 0x604d90. [f64 t][f32 x]. The client replies with 33 |
| 33 | P2PIndirectServerTimeAndPong | peer | 0x6038d0. [f64][f64][f64][f32] |
| 34 | S2CRoutedMulticast1 | S | 0x6057b0. [u8?][cs][HostID array][ByteArray payload]. The client forwards the payload to the listed peers as type 35 and also processes it locally |
| 35 | S2CRoutedMulticast2 | peer | 0x604710. [ByteArray innerMessage] |
| 36 | Encrypted_Reliable | both | 0x600c70. See §3 |
| 37 | Encrypted_Unreliable | both | 0x600c70. See §3 |
| 38 | Compressed | both | 0x5ffb00. See §4 |
| 39 | RequestReceiveSpeedAtReceiverSide | both | 0x605010. No payload. The receiver answers with 40 |
| 40 | ReplyReceiveSpeedAtReceiverSide | both | 0x603ae0. [f64 receiveSpeed]. Feeds the send-rate limiter |

Guard 0x601760 runs before types 3,4,6,8,9,10,11,13,15,17,23,24,25,28,34. The message is processed only if
the sender HostID is 0 (None) or 1 (**Server**). Types 24 and 25 also require sender == 1 explicitly.
After a handler returns, if the read cursor is not at the end (types 36 and 37 excepted), the client logs
error 0x1f. This is a warning only.

## 2. Handshake (byte exact, in order)

Crypto provider (0x629600): `CryptAcquireContextW(NULL, "Microsoft Enhanced Cryptographic Provider v1.0",
PROV_RSA_FULL=1, CRYPT_VERIFYCONTEXT)`. **The session cipher is CryptoAPI RC4, not AES.** The Rijndael tables
in the binary are not used by this path.

### 2.1 S2C type 4 NotifyServerConnectionHint (server sends immediately after accept)

Built by 0x66af60 on the server side and parsed by 0x605b30 (settings reader 0x5f9b70):
```
u8   0x04
u8   enableLog (bool; client+0xd90. Send 0)
-- CNetSettings, 34 bytes --
u8   fallbackMethod              enum. Send 0
i32  messageMaxLength            global max = max(old, this). Send 0x100000 (1048576) or more
f64  defaultTimeoutTimeSec       TCP silence timeout (see §5). E.g. 60.0
u8   directP2PStartCondition     client default 2. Send 2 (inferred meaning)
i32  overSendSuspectingThresholdInBytes   E.g. 0x4000 (inferred)
u8   enableNagleAlgorithm        bool. Passed to the TCP socket setup
i32  encryptedMessageKeyLength   RC4 key length in BITS. The embedded server asserts 0 < x <= 128. Send 128
u8   allowServerAsP2PGroupMember (inferred)
u8   enableP2PEncryptedMessaging (inferred)
u8   upnpDetectNatDevice         (inferred) Send 0
u8   upnpTcpAddPortMapping       (inferred) Send 0
i32  emergencyLogLineCount       if (enableLog || this > 0) client logs. Send 0
u8   bool @+0x28                 if set, client stamps time +0x170 (enablePingTest? inferred)
u8   bool @+0x29                 unknown. Send 0
```
The total message is exactly **36 bytes** (1 type + 1 + 34). A short read or any trailing bytes cause an error
and disconnect.

Client action: it takes or creates its RSA key-exchange key, `CryptGenKey(AT_KEYEXCHANGE, CRYPT_EXPORTABLE)`,
which is **1024-bit** by default for the Enhanced provider. It also creates a local RC4 key of
encryptedMessageKeyLength bits (client+0x98, unused on the wire). Then it sends type 5.

### 2.2 C2S type 5 NotifyCSPublicKey
```
u8 0x05 ; cs len ; u8[len] PUBLICKEYBLOB   (CryptExportKey(hRsa, 0, PUBLICKEYBLOB=6, 0))
```
The blob is 148 bytes for 1024-bit RSA:
- BLOBHEADER `06 02 00 00 00 A4 00 00` (bType 6, ver 2, reserved 0, aiKeyAlg CALG_RSA_KEYX 0xA400)
- RSAPUBKEY `52 53 41 31` ("RSA1"), u32 bitlen = 1024, u32 pubexp (65537)
- modulus: 128 bytes, **little-endian**. Reverse it for a big-endian bignum library.

### 2.3 S2C type 6 NotifyCSEncryptedSessionKey
```
u8 0x06 ; cs len ; u8[len] SIMPLEBLOB
```
The embedded server builds this in 0x629f50: import the client blob, `CryptGenKey(CALG_RC4, (bits<<16)|EXPORTABLE)`,
then `CryptExportKey(rc4, hClientPub, SIMPLEBLOB=1)`. The client parses it in 0x62a0a0 with
`CryptImportKey(prov, blob, len, hClientRsa, 0)`.

SIMPLEBLOB layout (140 bytes for RSA-1024):
- `01 02 00 00` + `01 68 00 00` (aiKeyAlg CALG_RC4 = 0x6801)
- `00 A4 00 00` (algid CALG_RSA_KEYX)
- 128 bytes of RSA ciphertext, **byte-reversed (little-endian)**

The ciphertext is RSAES-PKCS1-v1_5 (type 2 padding) of the 16 raw RC4 key bytes. To produce it with
OpenSSL: `RSA_public_encrypt(16, key, out, rsa, RSA_PKCS1_PADDING)`, then reverse `out`. No salt: the Enhanced
provider uses a 128-bit RC4 key with no salt. If the read or the import fails: ErrorType 6, then disconnect.

### 2.4 C2S type 7 NotifyServerConnectionRequestData (sent right after the key import)
```
u8   0x07
cs   len ; u8[len] userData        (game connect-param user data, client+0xc80)
Guid protocolVersion               (client+0xc70; the game sets it in CNetConnectionParam)
u32  internalVersion               = 0x00030069 (global 0x9e6a54)
```
Embedded-server check (0x66bde0):
- guid == server protocolVersion AND u32 == its internal version, else it sends **type 8** (no payload).
- Then an optional user callback. On reject it sends **type 9** + ByteArray reply (the client ignores the
  ByteArray).
- Otherwise it sends type 10.

### 2.5 S2C type 10 NotifyServerConnectSuccess
Server side 0x652e00, client side 0x6076e0:
```
u8    0x0A
u32   assignedHostID                 -> client+0xc60 (local HostID)
Guid  serverInstanceGuid             -> client+0x208 (later compared in P2P holepunch msgs)
cs    len ; u8[len] replyUserData    -> delivered in OnJoinServerComplete
AddrPort clientTcpAddrAsSeenByServer (u32 ip, u16 port)
```
A read failure raises ErrorType 0x1f, then disconnect. After success the client fires OnJoinServerComplete(ok)
and starts the keepalive timers (§5). **Avoid HostID 50:** when HostID == 0x32 and rand()%3 == 0, the client
runs GetModuleFileName + 0x6291b0, which looks like a reporting routine. Use HostIDs >= 3 (0 = None,
1 = Server, 2 = reserved in ProudNet).

### Handshake summary
```
S: 04 <settings>        C: 05 <pubkey>        S: 06 <simpleblob>
C: 07 <user,guid,ver>   S: 0A <hostid,guid,reply,addr>   (or 08 / 09)
```
The whole exchange is unencrypted plain TCP frames.

## 3. Encryption (types 36/37)

**Algorithm.** CryptoAPI RC4 with the session key from §2.3.
- Encrypt 0x5fa140: `CryptEncrypt(key, 0, Final=TRUE, 0, buf, &len, cap)`
- Decrypt 0x5fa2e0: `CryptDecrypt(key, 0, Final=TRUE, 0, buf, &len)`

**Keystream reset.** With Final=TRUE, CryptoAPI resets the RC4 key state after every call. So **every message
is XORed with the RC4 keystream starting at offset 0** (the same keystream each time). Implement it as:
`rc4_init(key16); rc4_crypt(data)` per message.

**Wire format** (client sender 0x6005f0, receiver 0x600c70):
```
u8   0x24 (reliable) | 0x25 (unreliable)
u8   encryptMode   (sendOpt+0x24; receiver ignores it; client sends 1 (inferred))
cs   length        (receiver reads it and IGNORES it; sender writes the plaintext/ciphertext length)
u8[] RC4(plaintext)  (everything to end of message)
plaintext(0x24) = u16 serial + inner message (starts with a MessageType byte, e.g. 01 = Rmi)
plaintext(0x25) = inner message
```

**Serial rules (0x24 only).** Per direction, u16, starts at 0 on each connect (0x5f2b60 zeroes client+0x230
and +0x232).
- Client send counter to server: client+0x230, post-increment.
- Client expected receive counter from server: client+0x232.
- On mismatch the message is dropped and error 6 is logged. On match, expected++.
- The server must keep its own send counter starting at 0 and should check the client's counter the same way.

**When the client encrypts.** When the RMI send option `encryptMode != 0`. That flag comes from the game's
RmiContext (e.g. `RmiContext::SecureReliableSend`), per call site. Loopback is never encrypted. A decrypted
message is dispatched again, so any type (usually 1 = Rmi) can be inside. The server may send plaintext RMIs
at any time. The client accepts both.

## 4. Compression (type 38)
```
u8 0x26 ; cs compressedLen ; cs originalLen ; u8[compressedLen] zlib stream
```
- The payload is a **zlib stream (RFC1950 header)**. 0x62ddb0 = `uncompress()` with `inflateInit2_(15)`.
- The receiver requires originalLen <= max message length (vtbl+0x60), Z_OK, and an exact decompressed size.
- The output is a full inner message and is dispatched again.
- The server never has to send this.

## 5. Keepalive, time sync and timeouts

**Type 26.** The client sends it (0x5e7980) every `0.5 s / timeScale(=1.0)` once HostID != 0. It goes via the
server-remote object 0x60a830 (UDP if enabled, else TCP).
- C2S: `[1A][f64 clientLocalTimeSec][f64 clientAvgPingSec]`
- S2C: `[1C][f64 echo of clientLocalTimeSec][f64 serverTimeSec]` (embedded server 0x66ad90)
- The client computes ping = (now - echo) * 0.5, smooths it with 0.8, and derives the server-time offset.

**Type 27.** Speed-hack detector ping. No payload, sent about every 0.59 s. The initial timer is 0 at connect,
so it is **on by default**. The server may ignore it. The server can disable it by sending S2C RMI 64512
`NotifySpeedHackDetectorEnabled(false)`.

**Timeout.** The client heartbeat 0x604020 disconnects with ErrorType 0xc if
`now - lastTcpRecvTime(client+0xe60) > settings.defaultTimeoutTimeSec`. lastTcpRecvTime updates on **any**
received TCP bytes (0x608dd0).
- Answering every type 26 with a type 28 is enough to keep the connection alive.
- Pick defaultTimeoutTimeSec comfortably large, e.g. 30–60.

## 6. UDP: none of it is required
- The client never starts UDP on its own. The server's UDP address reaches the client only through S2C RMI
  64518 `S2C_RequestCreateUdpSocket(NamedAddrPort)` or 64519 `S2C_CreateUdpSocketAck(bool, NamedAddrPort)`.
  These write (client+0xc4c)->+0x6c/+0x70.
- Holepunch (types 11/12/13/14/15) only starts after the server sends 11.
- **Minimal TCP-only server:** never send 11, 64518 or 64519. The client then routes everything to the server
  over TCP, including types 26, 21 and 20.
- For P2P groups, set `enableDirectP2P = false` in MemberJoin (§7) and handle relays 20/21/22.

## 7. P2P groups & relay

### ProudS2C RMIs (S2C, RmiID base 0xFBF5 = 64501)

Stub 0x5e1c00, jump table 0x5e4de4. Handlers are in the vtable 0x6cc334 slot (0x18 + 4n). Wire =
`[01][u16 id][params]`.

| id | hex | params (wire order) | inferred name |
|---|---|---|---|
| 64501 | FBF5 | u32 groupHostID, u32 memberHostID, ByteArray customField, u32 eventID, ByteArray p2pSessionKey, i32 p2pFirstFrameNumber, Guid connectionMagicNumber, bool enableDirectP2P, u16 (bind port?) | P2PGroup_MemberJoin |
| 64502 | FBF6 | same as 64501 minus p2pSessionKey | P2PGroup_MemberJoin_Unencrypted |
| 64503 | FBF7 | u32 hostID, bool, AddrPort ×4 | (P2P recycle/established notify, uncertain) |
| 64504 | FBF8 | u32 peerHostID, AddrPort internal, AddrPort external | RequestP2PHolepunch |
| 64505 | FBF9 | u32 peerHostID, u32 reason(ErrorType) | P2P_NotifyDirectP2PDisconnected2 |
| 64506 | FBFA | u32 memberHostID, u32 groupHostID | P2PGroup_MemberLeave |
| 64507 | FBFB | u32 A, u32 B, AddrPort ABSend, ABRecv, BASend, BARecv | NotifyDirectP2PEstablish |
| 64508 | FBFC | — | ReliablePong (handler is a no-op) |
| 64509 | FBFD | — | EnableLog (client+0xd90 = 1) |
| 64510 | FBFE | — | DisableLog |
| 64511 | FBFF | — | NotifyUdpToTcpFallbackByServer (0x5f5a20) |
| 64512 | FC00 | bool | NotifySpeedHackDetectorEnabled |
| 64513 | FC01 | — | ShutdownTcpAck |
| 64514 | FC02 | — | RequestAutoPrune (client disconnects itself, err 0xb) |
| 64515 | FC03 | u32 hostID | RenewP2PConnectionState |
| 64516 | FC04 | u32 hostID | NewDirectP2PConnection |
| 64517 | FC05 | bool | RequestMeasureSendSpeed |
| 64518 | FC06 | NamedAddrPort serverUdpAddr | S2C_RequestCreateUdpSocket |
| 64519 | FC07 | bool ok, NamedAddrPort serverUdpAddr | S2C_CreateUdpSocketAck |

For 64501/64502, the p2pFirstFrameNumber is the reliable-UDP frame number that the member expects first from
this peer. The server must use the same number for the relayed frames in 20/23 (see the relay rules below).

### ProudC2S RMIs (C2S, RmiID base 0xFA01 = 64001)

Proxy vtable 0x6cbaec. Params are in wire order. The names are not confirmed. The server can safely consume
and ignore all of them except ReliablePing. My **guess**: 64001 = ReliablePing (reply with 64508). Others:
64003 = ShutdownTcp (reply 64513), 64005 = NotifyP2PHolepunchSuccess.

| id | params |
|---|---|
| 64001 | 4 bytes (f32/u32) |
| 64002 | u32, u32 |
| 64003 | — |
| 64004 | u32, u32, u32, bool |
| 64005 | u32 A, u32 B, AddrPort ×4 |
| 64006 | ByteArray |
| 64007 | — |
| 64008 | u8, String |
| 64009 | u32, String |
| 64010 | String |
| 64011 | u32 |
| 64012 | u32 |
| 64013 | String |
| 64014 | f64 |
| 64015 | u32, u32 |
| 64016 | — |
| 64017 | bool |
| 64018 | u32, u32, u32 |
| 64019 | u32 |

### Relay formats (the client builds 20/21 in the send path at 0x5f0100–0x5f0840)

**20 ReliableRelay1 (C2S, TCP)**
```
[14][RelayDestList: cs n, n×(u32 destHostID, u32 frameNumber)][cs len][len bytes]
```
The bytes are a reliable-UDP **stream chunk**: the message wrapped with the TCP-style framing from 0x626160
(`13 57 cs len msg`).

The server relays to each dest as **23 ReliableRelay2**:
```
[17][u32 senderHostID][u32 frameNumber (that dest's)][cs len][same bytes]
```
The receiving client (0x606370) feeds this to that peer's reliable-UDP receiver as frame `frameNumber`.
Frames are consumed in order. The first expected number is the p2pFirstFrameNumber from MemberJoin. Then
extracted messages are dispatched as if sent by senderHostID.

**21 UnreliableRelay1 (C2S)**
```
[15][u8 priority][cs uniqueId(int64)][cs n][n × u32 destHostID][cs len][payload message]
```
The server sends to each dest **24 UnreliableRelay2**:
```
[18][u32 senderHostID][cs len][payload message]
```
The client dispatches the payload with sender = senderHostID.

**22 ReliableUdpFrameRelay1 (C2S, TCP; used when the direct peer UDP path is gone)**
```
[16][u32 destHostID][u32 frameNumber][cs len][frame data]
```
The server sends **25**:
```
[19][u32 senderHostID][u32 frameNumber][cs len][frame data]
```
The client (0x6066d0) creates a data frame and feeds the peer's reliable-UDP receiver.

**34/35.** Server-routed multicast. Optional for the server.

## 8. HostIDs
- 0 = None, 1 = Server. The client guard treats 0/1 as "from server".
- Assign clients from **3** upward and skip 50.
- The client only needs its HostID to be nonzero; it compares relay/RMI HostIDs against the one assigned in
  type 10.
