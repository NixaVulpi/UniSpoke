# unispoke

English | [Español](README.es.md) | [简体中文](README.zh.md)

An experimental **Leagsoft UniVPN (Huawei SVN) SSL VPN client** implementing the subset of the protocol observed so far. It supports both **Legacy** and **V1** gateways and offers two ways to expose the tunnel:

- **Proxy mode** — local SOCKS5 and HTTP proxies
- **VPN mode** — creates a TUN adapter and takes over system traffic using the VIP, routes and DNS assigned by the gateway

## Build

Requires Go 1.27.3+.

```sh
go build -o unispoke ./cmd/unispoke          # Linux / macOS
go build -o unispoke.exe ./cmd/unispoke      # Windows
```

Cross-compilation:

```sh
GOOS=linux   GOARCH=arm64 go build -trimpath -o dist/unispoke-linux-arm64 ./cmd/unispoke
GOOS=windows GOARCH=amd64 go build -trimpath -o dist/unispoke-windows.exe ./cmd/unispoke
GOOS=darwin  GOARCH=arm64 go build -trimpath -o dist/unispoke-macos-arm64 ./cmd/unispoke
```

## Quick start

```sh
./unispoke -gateway vpn.example.com:10443 -user alice -password 'secret' -ca /path/to/private-ca.pem
```

By default SOCKS5 listens on `127.0.0.1:1080` and HTTP on `127.0.0.1:8080`. Add `-vpn` for VPN mode; it requires administrator/root privileges, and on Windows `wintun.dll` must be placed next to the executable.

## Development

```sh
go build ./...
go test ./...
go vet ./...
gofmt -w .
```

CI runs formatting checks, vet, tests and cross-compilation on Linux, Windows and macOS.

## Documentation

- [Usage](docs/usage.md) — proxy/VPN modes, all options, Windows setup, security notes
- [Architecture and compatibility](docs/architecture.md) — module layout, data flow, validation record, limitations, third-party components
- [Protocol notes](docs/protocol.md) — frame layout, command numbers, session establishment and reconnection

## License

MIT, see [LICENSE.md](LICENSE.md).
