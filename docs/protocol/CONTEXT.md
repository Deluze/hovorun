# Hovorun Client5.exe RE — shared context

Binary Ninja via `mcp__binassist__*` tools, binary name `Client5.exe.bndb` (32-bit x86 MSVC, image base 0x400000).
IMPORTANT: HLIL/MLIL/LLIL/pseudo_c are NOT available in this database. Use `mcp__binassist__get_code` with
format `disasm` only. Use `get_data_at` to read vtables / jump tables, `search_bytes` for pointer searches,
`xrefs` for references. Do not patch bytes. Renaming symbols / adding comments is fine but optional.

The client uses an OLD version of ProudNet (Nettention) — confirmed from strings. Game servers:
session server TCP 23111, messenger server TCP 24111 (cliconfg.inp). Game server address likely handed out by
the session server.

## Game RMI interfaces (from RTTI)
- CSessionClient: Proxy `CLSS` (client->session server), Stub `SSCL` (session->client)
- CMessengerClient: Proxy `CLMS`, Stub `MSCL`, plus P2P Proxy/Stub `CLPE2`
- CGameClient: Proxy `CLGS` (client->game server), Stub `GSCL`, plus P2P Proxy/Stub `CLPE`
- Also classes RealTime_Room_Packet, RealTime_Racing_Packet (custom packets, maybe via UserMessage).

Finding a vtable: RTTI TypeDescriptor name string is at X (e.g. ".?AVStub@SSCL@@" at 0x9e5da0);
TypeDescriptor starts at X-8. search_bytes for that address little-endian finds the CompleteObjectLocator's
pTypeDescriptor field (COL+0xC). Then search_bytes for the COL address gives vtable-4. vtable follows.
Example: SSCL::Stub vtable = 0x6c52b4, COL = 0x9c0a78. Stub vtable slot 2 (+8) = ProcessReceivedMessage
(0x571370 for SSCL). The stub dispatcher reads RmiID (ushort) via 0x5f9a50 then switches on it; each case
reads parameters and calls a virtual `this->vtbl[...]` handler (the user-overridden stub function).
The Proxy side: each RMI function builds a CMessage: writes MessageType_Rmi byte, RmiID ushort, params,
then calls the send core.

## CMessage serialization primitives (reading)
- 0x5f8f00 `Read(void* dst, int count)` raw little-endian bytes (byte-aligns first). `push N` before the call = size.
- 0x5f9a50 read RmiID: ushort (2 bytes)
- 0x5f9900 read MessageType: 1 byte
- 0x5f9650 read compact scalar: 1 byte size prefix (1,2,4,8) followed by that many bytes signed LE.
- 0x5fa900 -> 0x5fa650 read string: byte stringType (1 = ANSI/MBCS bytes, 2 = UTF-16LE), then compact scalar
  length (in characters), then length chars.
- 0x5d86c0 read 1 byte, 0x5d86f0 read 2 bytes
- 0x5fb0f0 / 0x5fb150 / 0x5fb600 / 0x5335e0 are only ToString() for logging — ignore.
- Global 0x9e5f94 = empty string sentinel.
Other readers will exist (int64, float, arrays = compact scalar count + elements, structs with custom
operator>>). Identify them the same way and document them.

## Framing (TCP)
Each TCP packet: `u16 magic 0x5713 (bytes 13 57)` + compact scalar payload length + payload.
Payload first byte = ProudNet MessageType (1 byte). Client-side dispatcher at 0x608390, jumptable 0x608840.
MessageType_Rmi payload = [type byte][u16 RmiID][params...].

## Output rules for agents
Write findings to a markdown file in this folder. For every RMI: numeric RmiID (hex and dec), direction,
best-guess name, and the exact ordered parameter list with wire types (u8/u16/u32/i32/i64/float/double/
string(ansi|unicode)/compact scalar/array-of-X/struct layout). Note the handler/sender address. Where the
meaning is inferable from how the client uses a parameter (UI strings nearby, what it's compared to), say so
and mark it as inferred. Do NOT call any mcp__hearthbot__ tools.
