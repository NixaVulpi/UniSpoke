# Usage

English | [Español](usage.es.md) | [简体中文](usage.zh.md)

[← Back to README](../README.md)

All configuration is passed through command-line flags. The password can also be supplied via the `UNISPOKE_PASSWORD` environment variable to keep it out of the process list.

## Proxy mode (default)

```sh
# Linux / macOS
./unispoke -gateway vpn.example.com:10443 \
  -user alice -password 'secret' -ca /path/to/private-ca.pem \
  -socks 127.0.0.1:1080 -http 127.0.0.1:8080

# Windows (PowerShell)
.\unispoke.exe -gateway vpn.example.com:10443 `
  -user alice -password 'secret' -ca C:\certs\private-ca.pem `
  -socks 127.0.0.1:1080 -http 127.0.0.1:8080
```

Verify:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://10.20.1.5/     # TCP
curl -x http://127.0.0.1:8080 http://10.20.1.5/             # HTTP
curl -p -x http://127.0.0.1:8080 http://10.20.1.5/          # CONNECT
```

SOCKS5 UDP requires client support (for example games, voice tools and DNS utilities using `socks5h`).
The HTTP proxy protocol itself cannot carry UDP; use SOCKS5 or VPN mode when you need UDP.

## VPN mode

```sh
# Windows (administrator terminal)
.\unispoke.exe -gateway vpn.example.com:10443 -user alice -password secret `
  -ca C:\certs\private-ca.pem -vpn -vpn-name unispoke

# Linux (root or CAP_NET_ADMIN)
sudo ./unispoke -gateway vpn.example.com:10443 -user alice -password secret \
  -vpn -vpn-name unispoke
```

VPN mode:

1. Creates a TUN device (a Wintun adapter on Windows)
2. Configures the VIP/netmask, MTU (`-mss + 40`) and gateway-provided DNS
3. Adds the gateway-provided routes (the 9 entries in the `REQVIP` response)
4. Forwards raw IPv4 packets in both directions; TCP/UDP/ICMP all work
5. Syncs the new VIP/routes automatically after session re-establishment
6. Removes the routes on exit

`-vpn-full` attempts a full tunnel on Windows: it first pins the gateway address as a /32 route on the physical adapter, then adds `0.0.0.0/0`. Linux/macOS currently support split tunneling only.

> Proxy listeners and VPN mode are mutually exclusive: `-vpn` ignores `-socks`/`-http`.

### Windows setup

Wintun is a user-space TUN driver (MIT, Microsoft-signed). Place the `wintun.dll` matching your architecture next to `unispoke.exe`:

1. Download `wintun-0.14.1.zip` from <https://www.wintun.net/>
2. Copy `bin/amd64/wintun.dll` (or `arm64`) into the program directory
3. Run as **Administrator**

Windows installs the driver the first time the adapter is created; VPN mode reports a clear error when `wintun.dll` is missing.

## UDP transport

Legacy gateways also expose a UDP data plane (tunnel mode 3). It replaces the
TLS data frames with UDP datagrams and is several times faster than the TCP
path on the same gateway:

```sh
./unispoke -gateway vpn.example.com:10443 -user alice \
  -password 'secret' -ca ca.pem -transport udp
```

The gateway only accepts UDP frames up to 1280 bytes, so the tunnel MTU is
capped at 1240 (`-mss 1200`) even when a larger `-mss` is requested. The UDP
plane encrypts the IP packet body with AES-128-CBC, but the 20-byte IPv4 header
travels in clear, matching the vendor client. `-transport auto` tries UDP and
falls back to TCP when the gateway does not offer it.

## Options

| Flag | Default | Description |
|---|---|---|
| `-gateway` | required | Gateway `host:port` |
| `-user` / `-password` | required | Credentials (the password can also come from `UNISPOKE_PASSWORD`) |
| `-mode` | `auto` | `auto`, `legacy` or `v1` |
| `-transport` | `tcp` | Data transport: `tcp`, `udp` or `auto` |
| `-domain` | gateway host | Authentication domain |
| `-mac` | derived | Client MAC |
| `-socks` | `127.0.0.1:1080` | SOCKS5 listen address; empty disables |
| `-http` | `127.0.0.1:8080` | HTTP proxy listen address; empty disables |
| `-dns` | empty | Local UDP DNS relay address, e.g. `127.0.0.1:5353` |
| `-dns-server` | empty | Override gateway DNS, comma-separated |
| `-vpn` | false | Enable system-level TUN mode |
| `-vpn-name` | `unispoke` | TUN/Wintun adapter name |
| `-vpn-full` | false | Full tunnel (Windows) |
| `-vpn-debug` | false | Log VPN packet summaries, periodic counters and the route table |
| `-mss` | `1200` | TCP MSS inside the tunnel; adapter MTU = MSS + 40 |
| `-timeout` | `10s` | Network timeout |
| `-insecure` | false | Skip certificate verification |
| `-ca` | empty | Private CA bundle |
| `-sni` | gateway host | TLS server name |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `-log-format` | `plain` | `plain`, `logfmt` or `json` |
| `-quiet` | false | Same as `-log-level warn` |
| `-drop-after` | `0` | Test hook: drop tunnel sockets after the given duration |
| `-version` | false | Print version, OS and architecture |

## Log formats

- `plain` (default): `2026-10-25T13:02:27.500+08:00 INFO unispoke 0.1.3 (windows/amd64)`
- `logfmt`: `time=2026-10-25T13:02:27.500+08:00 level=INFO msg="unispoke 0.1.3 (windows/amd64)"`
- `json`: `{"time":"2026-10-25T13:02:27.500+08:00","level":"INFO","msg":"unispoke 0.1.3 (windows/amd64)"}`

`-log-level` and `-quiet` apply to all three formats.

## Security

- Certificates are verified by default. `-insecure` is only for lab gateways with self-signed certificates.
- Credentials on the command line may leak into the process list; prefer `UNISPOKE_PASSWORD` for unattended use.
- Use this tool only on networks you are authorized to test.
