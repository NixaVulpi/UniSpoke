# unispoke

[English](README.md) | Español | [简体中文](README.zh.md)

Un **cliente SSL VPN experimental de Leagsoft UniVPN (Huawei SVN)** que implementa el subconjunto del protocolo observado hasta la fecha. Compatible con gateways **Legacy** y **V1**, y ofrece dos formas de exponer el túnel:

- **Modo proxy** — proxies SOCKS5 y HTTP locales
- **Modo VPN** — crea una interfaz TUN y asume el tráfico del sistema con la VIP, las rutas y el DNS asignados por el gateway

## Compilación

Requiere Go 1.27.3 o superior.

```sh
go build -o unispoke ./cmd/unispoke          # Linux / macOS
go build -o unispoke.exe ./cmd/unispoke      # Windows
```

Compilación cruzada:

```sh
GOOS=linux   GOARCH=arm64 go build -trimpath -o dist/unispoke-linux-arm64 ./cmd/unispoke
GOOS=windows GOARCH=amd64 go build -trimpath -o dist/unispoke-windows.exe ./cmd/unispoke
GOOS=darwin  GOARCH=arm64 go build -trimpath -o dist/unispoke-macos-arm64 ./cmd/unispoke
```

## Inicio rápido

```sh
./unispoke -gateway vpn.example.com:10443 -user alice -password 'secret' -ca /path/to/private-ca.pem
```

Por defecto, SOCKS5 escucha en `127.0.0.1:1080` y HTTP en `127.0.0.1:8080`. Añade `-vpn` para el modo VPN; requiere privilegios de administrador/root y, en Windows, `wintun.dll` debe estar junto al ejecutable.

## Desarrollo

```sh
go build ./...
go test ./...
go vet ./...
gofmt -w .
```

CI ejecuta comprobaciones de formato, vet, pruebas y compilación cruzada en Linux, Windows y macOS.

## Documentación

- [Uso](docs/usage.es.md) — modos proxy/VPN, todas las opciones, preparación en Windows, notas de seguridad
- [Arquitectura y compatibilidad](docs/architecture.es.md) — estructura de módulos, flujo de datos, registro de validación, limitaciones y componentes de terceros
- [Notas del protocolo](docs/protocol.es.md) — formato de tramas, números de comando, establecimiento de sesión y reconexión

## Licencia

MIT, consulta [LICENSE.md](LICENSE.md).
