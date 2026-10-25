# Architecture and compatibility

English | [Español](architecture.es.md) | [简体中文](architecture.zh.md)

[← Back to README](../README.md)

## Module layout

```text
cmd/unispoke            CLI, listeners, mode selection
internal/tunnel         frame format, TLS, Legacy/V1 authentication, sessions, keepalive, network parameters
internal/netstack       gVisor netstack (TCP/UDP), raw tunnel IP injection and extraction
internal/packet         padding and checksums for the gateway ≤40-byte packet limit
internal/proxy          SOCKS5 (CONNECT/UDP ASSOCIATE) and HTTP front ends
internal/dnsrelay       in-tunnel DNS resolution and local UDP DNS relay
internal/vpn            TUN/Wintun device, system route/DNS configuration, raw IP forwarding
```

The data plane uses [gVisor netstack](https://gvisor.dev/); the virtual adapter uses [wireguard-go tun](https://git.zx2c4.com/wireguard-go/).

Proxy mode:

```text
application -> SOCKS5/HTTP -> netstack(TCP/UDP) -> packet.Pad -> tunnel.SendIP
application <- SOCKS5/HTTP <- netstack          <-               tunnel.RecvIP <- gateway
```

VPN mode:

```text
system stack -> TUN/Wintun -> packet.Pad -> tunnel.SendIP
system stack <- TUN/Wintun <-            <- tunnel.RecvIP <- gateway
```

The tunnel is a raw IPv4 channel over TLS (Legacy cmd `0x02`, V1 cmd `0x66`).
Proxy mode does not modify the host's routes or adapters; VPN mode creates a virtual adapter and changes routes and DNS as needed.

## Protocol

The observed protocol is documented in [protocol.md](protocol.md), including frame layout, command numbers, Legacy and V1 session establishment, reconnection, and the endpoint check (CEPS) boundary. Leagsoft UniVPN is Huawei SVN; the client service is named `UniVPNCS`. Unverified server behavior is marked as such.

## Status

| Capability | Status |
|---|---|
| Legacy gateway | Verified against a real gateway (authentication, TCP, UDP, HTTP, reconnect) |
| V1 gateway | Implemented from protocol observations; not yet run against a real V1 gateway |
| SOCKS5 TCP / UDP | Verified |
| HTTP proxy | Verified (the HTTP proxy protocol itself cannot carry UDP) |
| UDP data plane (legacy mode 3) | Implemented and verified; several times faster than the TLS data path on the same gateway |
| DNS relay | Implemented; availability depends on gateway-provided DNS or `-dns-server` |
| VPN mode (Windows) | Implemented (Wintun + netsh); requires administrator privileges |
| VPN mode (Linux/macOS) | Linux verified against a real gateway; macOS implemented but not yet run; full tunnel is Windows-only |

## Platforms

| OS | Proxy mode | VPN mode |
|---|---|---|
| Linux amd64/arm64 | ✅ | ✅ (verified on Fedora 44 amd64; requires `CAP_NET_ADMIN` or root) |
| Windows amd64/arm64 | ✅ | ✅ (requires administrator privileges and `wintun.dll`) |
| macOS amd64/arm64 | ✅ | ✅ (requires root; not yet verified) |

## Validation record

On 2026-10-25, against a Legacy gateway (gVisor data plane):

- Auto-detection selected Legacy; authentication succeeded; a `/24` virtual address and nine routes were assigned
- HTTP `absolute-form` and keep-alive reuse: `/` and `/openapi.json` (2,035,183 bytes) both returned 200
- SOCKS5 `CONNECT`: a 2 MB response completed intact
- SOCKS5 `UDP ASSOCIATE`: NetBIOS NBSTAT to `172.22.1.11:137` returned a 167-byte reply
- The binary was built on Windows/amd64; proxy mode and UDP were verified against a real gateway
- VPN mode's TUN creation correctly returned a permission error without administrator rights; the administrator path is still unverified
- `go test ./...`, `go vet ./...`, `gofmt -l .` passed

On 2026-10-25, on Linux (Fedora 44 Server, kernel 7.1.10, amd64; binary cross-built on Windows/amd64):

- Proxy mode: SOCKS5 `CONNECT` returned the SSH banner from `172.22.1.102:22`; HTTP `absolute-form` and `CONNECT` both returned 301 from the internal web server; 200 keep-alive requests through each proxy (1.55 MB) completed without errors
- SOCKS5 `UDP ASSOCIATE`: NetBIOS NBSTAT to `172.22.1.11:137` returned a 157-byte reply
- The gateway sent no DNS servers, so the DNS relay stayed disabled and internal names could not be resolved; only the split routes were reachable (no Internet egress)
- VPN mode: TUN created with VIP `10.10.100.64/24`, MTU 1240 and nine routes; ICMP and TCP to two internal subnets succeeded; HTTP returned 301
- Graceful shutdown removed every route and the adapter; `-drop-after` re-established the session in about 150 ms, kept the VIP and resumed traffic
- Without root, VPN mode failed cleanly with `operation not permitted`
- Fixed during this run: inbound packets were not written to the TUN on Linux (`invalid offset`), and macOS could not have worked either. `wireguard-go` requires a platform-specific offset — 10 bytes of virtio-net header on Linux, 4 bytes of address-family header on macOS — which the VPN data path now reserves

## Compatibility

| Dimension | Support | Notes |
|---|---|---|
| Gateway generation | Legacy, V1 | V1 has not been tested against a real environment |
| Authentication | Username/password | MFA, certificate and host identity authentication are not implemented |
| Transport | TLS (TCP) | Outer UDP transport modes 2/3/4 are not implemented |
| Payload protocols | TCP, UDP, ICMP | SOCKS5 UDP verified; the HTTP proxy has no UDP |
| Address family | IPv4 | IPv6 is not implemented |
| Endpoint check | Not implemented | Gateways requiring CEPS cannot complete setup |
| Address assignment | `REQVIP` | DHCP-based address assignment is not implemented |

## Scope and limitations

- The HTTP proxy cannot carry UDP; this is a protocol limitation. Use SOCKS5 or VPN mode for UDP.
- Proxy mode and VPN mode are mutually exclusive; VPN mode requires administrator/root privileges.
- Full tunneling is currently Windows-only; on Linux/macOS use the split routes provided by the gateway.
- Internal DNS resolution relies on gateway-provided DNS or `-dns-server`; when neither is available it falls back to the system resolver.
- One authenticated session carries multiple flows; all flows are multiplexed by netstack.
- CEPS endpoint checks, Chinese national cryptography TLS (`SM2`/`SM3`/`SM4`), IPsec and L2TP are out of scope.

## Third-party components

| Component | Purpose | License |
|---|---|---|
| `gvisor.dev/gvisor` | User-space TCP/IP stack | Apache-2.0 |
| `golang.zx2c4.com/wireguard` / `wintun` | TUN device | MIT |
| `github.com/go-gost/gosocks5` | SOCKS5 protocol codec | MIT |
| `github.com/miekg/dns` | DNS client | BSD-3-Clause |
