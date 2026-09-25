# Hovorun server

A server for the Hovorun client, written from scratch in C++26 with standalone Asio.
It speaks the client's old ProudNet protocol, reversed from the binary in Binary Ninja.

One process runs all three servers the client talks to:

| Server | Port | Client config | What it does |
|---|---|---|---|
| Session | 23111 | `cliconfg.inp` `SESSIONPORT` | Login with the command-line credentials, hands out the game server address |
| Messenger | 24111 | `cliconfg.inp` `MESSENGER_PORT` | Friends, whispers, room invitations, mail (online only); clans answer "not available" |
| Game | 25111 | sent by the session server | Channels, lobby, rooms, race start, and relay of the race P2P traffic |

## Build

Requires CMake 3.30+ and a C++26-capable compiler (MSVC 19.40 / VS 2022 17.10+, GCC 14+, Clang 18+).
Asio is taken from an installed `asio` package if present, otherwise downloaded by CMake.

```bash
cmake -S . -B build
cmake --build build
```

## Releases

`.github/workflows/release.yml` builds Windows x64 (MSVC), Linux x64/arm64 (GCC 14) and macOS arm64/x64
(Homebrew LLVM) packages. Pushing a `v*` tag creates a GitHub release with a zip/tarball per platform
(binary + `server.ini` + README); a manual run only uploads the packages as workflow artifacts.
The runtime libraries are linked statically, so the packages need nothing else installed.

## Run

```bash
build/hovorun_server build/server.ini
```

`server.ini` is copied next to the binary at configure time. Set `[game] public_ip` to an address the clients can
reach. Accounts live in `accounts.txt` (`username password` per line) and are created on first login when
`auto_register=true`.

Start the client the way `start.bat` does: `Client.exe <username> <password> 4912160`
(the number is a launcher version check inside the client and is never sent to the server).

## Layout

```
src/net/        message reader/writer (ProudNet wire primitives) and TCP framing
src/crypto/     RC4 and the RSA-1024 key wrap used by the handshake (no external crypto library)
src/proudnet/   ProudNet server core: handshake, encryption, keepalive, core RMIs, P2P groups and relay
src/session/    session server
src/messenger/  messenger server
src/game/       game server, GSCL message builders and structs, CLGS ids
src/app/        config and account store
docs/protocol/  reversed protocol notes (byte-exact layouts, client addresses)
```

## Protocol in short

- **Framing:** every TCP packet is `13 57` (u16 0x5713) + compact scalar length + payload. A compact scalar is a
  size byte (1/2/4/8) followed by that many little-endian bytes.
- **Payload:** first byte is the ProudNet message type; `01` = RMI, followed by a u16 RMI id and the parameters.
- **Handshake:** server sends a 36-byte settings hint (type 4) → client sends its RSA-1024 CryptoAPI public key
  blob (5) → server answers with a SIMPLEBLOB holding a 128-bit RC4 key (6) → client sends user data, protocol
  GUID and internal version (7) → server replies with the client's HostID (10).
- **Protocol GUIDs:** base `{683ADDC6-6740-485B-AF8D-8818C1CC043C}`; Data1 + 1 for game, + 4 for messenger,
  + 5 for session.
- **Encryption:** RC4 with the keystream restarted for every message; reliable encrypted messages carry a u16
  serial per direction.
- **Keepalive:** client sends type 26 every 0.5 s, server answers with type 28. The client drops the connection
  if the server is silent longer than the timeout in the settings hint.
- **Strings:** type byte (1 = ANSI, 2 = UTF-16LE) + compact scalar length. The client sends UTF-16, and so does
  this server.
- **Game arrays** use a raw i32 count (not a compact scalar).
- **Race traffic** (positions, items, room heartbeats) goes client-to-client as CLPE RMIs addressed to the room's
  P2P group. The server keeps UDP off, creates one P2P group per room and relays that traffic over TCP.

See `docs/protocol/` for every RMI (122 game, 113 messenger, 6 session, 5 P2P) with exact parameter layouts.

## Status and unknowns

Written from static analysis only; not yet tested against a running client.

- Not verified live: RC4 keystream reset per message, the P2P relay path, and the reliable-relay first frame number.
- Many numeric fields have no known meaning (LogonInfo, ItemInfo, avatar parts, Room_Save_Score, clan structs).
  They are sent as zero and named by their client struct offsets.
- Not implemented: item shop/inventory contents, gifts, clans, persistent mail and friends, rankings (empty lists),
  and compressed (type 38) messages from the client.
