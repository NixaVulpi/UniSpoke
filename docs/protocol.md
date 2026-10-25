# Observed protocol subset

English | [Español](protocol.es.md) | [简体中文](protocol.zh.md)

[← Back to README](../README.md)

This document records the subset of the **Leagsoft UniVPN (Huawei SVN) SSL VPN** protocol implemented by `unispoke`. The content comes from analysis of the vendor implementation and interoperability testing against one authorized gateway. Unknown fields and unverified behavior are marked as such. It contains no credentials, endpoints or site-specific information.

## Gateway generations

Two gateway generations have been observed. The client probes the gateway with `FirstConnect` and chooses a generation from the magic value in the first response:

- **Legacy** — HTTPS login, 16-byte frames, data multiplexed over the control TLS connection.
- **V1** — binary authentication inside TLS, 8-byte frames, a separate data TLS channel.

## Frame format

### V1 (8-byte header)

| Offset | Length | Field |
|---|---|---|
| 0 | 4 | magic `c1 92 a4 d6` |
| 4 | 1 | version `01` |
| 5 | 1 | command |
| 6 | 2 | payload length, big-endian, header excluded |
| 8 | n | payload |

### Legacy (16-byte header)

| Offset | Length | Field |
|---|---|---|
| 0 | 4 | magic `fe fc ef be` |
| 4 | 4 | magic `c1 92 a4 d6` |
| 8 | 4 | session ID (user ID), big-endian |
| 12 | 2 | command, big-endian |
| 14 | 2 | payload length, big-endian |
| 16 | n | payload |

One Legacy response (the ACL response) uses a little-endian length field; all other responses are big-endian. Readers must accept both byte orders.

## Legacy session establishment

1. HTTPS `GET /netextension/netextensionlogin.html?SelectLanguage=0&UserName=..&Password=..&MacAddress=..&SVN_Seco_AaA=1`
2. The response is binary rather than HTTP: magic `f0 f0 f0 f0`, a signed result at `+4` (negative means failure), and the user ID at `+44`.
3. Open a new TLS connection and send ACL (cmd `0x06`, four zero bytes) and REQVIP (cmd `0x03`).
4. The REQVIP response has a fixed layout: `+0` VIP, `+4` netmask, `+8` address assignment method, `+20` route type, `+160` three DNS servers, `+184` route count, and 12-byte route entries starting at `+188`.
5. Data uses cmd `0x02` with raw IPv4 packets as the payload. Control keepalive is cmd `0x07` every 10 seconds.

## V1 session establishment

1. `FirstConnect` (cmd `0x1D`, Legacy frame format): 64 bytes of OS information, 256 bytes for the authentication domain, and four bytes `00 01 00 00`, for a total of 340 bytes.
2. `AUTH` (cmd `0x01`): 256-byte domain, 16-bit authentication type, followed by TLVs — type 1 username, type 2 password, type 3 MAC string.
3. The response has the result at `+0` and TLVs starting at `+8`; type 3 with length 32 is the session token.
4. `REQVIP` (cmd `0x03`) carries that token. The response is TLV-based: type 1 (length 5) is the VIP, types 5/6 are routes, type 7 is the tunnel mode, and type 9 is the UDP port.
5. A second TLS connection sends `DATA_CONNECT` (cmd `0x64`) carrying the token.
6. Data uses cmd `0x66`, with a payload of eight zero bytes followed by a raw IPv4 packet. Control keepalive is cmd `0x06` (token + elapsed milliseconds, every 10 seconds); data keepalive is cmd `0x65` (empty payload, every 15 seconds).

## Command overview

| V1 | Legacy | Purpose |
|---|---|---|
| `0x01` | — | Authentication |
| `0x02` | — | Secondary authentication (not implemented) |
| `0x03` | `0x03` | Request virtual IP / network configuration |
| `0x06` | `0x07` | Keepalive |
| `0x09` | — | Tunnel mode switch (not implemented) |
| `0x32` | `0x08` | Kick-out |
| — | `0x02` | Data |
| — | `0x05` | DHCP (not implemented) |
| `0x64` | — | Data channel connect |
| `0x65` | — | Data channel keepalive |
| `0x66` | — | Data |

## Reconnection

The vendor client preserves the authenticated session:

1. When a channel fails, it sets a reconnect flag; a 10-second watchdog starts the process.
2. The client saves the current VIP as a baseline and opens a new TLS connection to the same gateway with the same parameters.
3. It sends REQVIP again (or DHCP if address assignment uses DHCP).
4. The new VIP must match the baseline; otherwise reconnection fails and the user is asked to log in again.
5. On success, V1 rebuilds the data TLS channel with `DATA_CONNECT`; UDP mode rebuilds the UDP link.

`unispoke` follows this behavior on both gateway generations and falls back to a full login when the gateway rejects session reuse.

## Endpoint check boundary

A gateway may require an endpoint compliance check (CEPS) before the tunnel is established. The authentication response carries an endpoint check flag; when it is set, the vendor client completes the check on the control channel before starting the tunnel. `unispoke` does not implement this check, so such gateways cannot complete setup.

## Implementer notes

- The tunnel MTU is roughly 1300 bytes; an MSS of 1200 is safe.
- The gateway drops IP packets of 40 bytes or less. A bare TCP ACK is exactly 40 bytes, so pure ACKs must carry an option (for example, four NOP TCP options) to get through. `unispoke`'s `internal/packet` pads all packets of ≤40 bytes: TCP gets NOP options, UDP/ICMP gets IP NOP options (without changing the transport payload).
- Legacy data payloads may have a two-byte prefix before the IPv4 packet.
- V1 data payloads begin with eight zero bytes before the IPv4 packet.

### Non-TCP payloads

The gateway does **not** filter by IP protocol number; raw IPv4 packets on the data channel may use any protocol. Measurements during reverse engineering:

| Protocol | Target | Result |
|---|---|---|
| ICMP echo | 172.22.1.11 | 3/3, type 0 reply |
| UDP NTP | 192.168.200.3:123 | 3/3, 48-byte reply |
| UDP NetBIOS | 172.22.1.11:137 | 2/2, 157-byte NBSTAT reply |
| UDP DNS | 192.168.200.2:53 | 2/2, 29-byte reply |

SOCKS5 `UDP ASSOCIATE` can therefore be built directly on the data channel without implementing the outer UDP transport mode.
Note that UDP payloads must be >12 bytes (20 IP + 8 UDP + payload > 40); smaller packets must be padded with IP options.

The `UDPPort` field (TLV 9) in V1 `REQVIP` belongs to the **fast transport mode that carries the tunnel over UDP** and is unrelated to payload UDP; this project only uses TLS/TCP transport.
