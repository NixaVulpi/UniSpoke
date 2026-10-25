# Uso

[English](usage.md) | Español | [简体中文](usage.zh.md)

[← Volver al README](../README.es.md)

Toda la configuración se pasa mediante opciones de línea de comandos. La contraseña también puede proporcionarse con la variable de entorno `UNISPOKE_PASSWORD` para que no aparezca en la lista de procesos.

## Modo proxy (predeterminado)

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

Verificación:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://10.20.1.5/     # TCP
curl -x http://127.0.0.1:8080 http://10.20.1.5/             # HTTP
curl -p -x http://127.0.0.1:8080 http://10.20.1.5/          # CONNECT
```

SOCKS5 UDP requiere soporte del cliente (por ejemplo, juegos, herramientas de voz y utilidades DNS que usan `socks5h`).
El protocolo del proxy HTTP no puede transportar UDP; usa SOCKS5 o el modo VPN cuando necesites UDP.

## Modo VPN

```sh
# Windows (terminal de administrador)
.\unispoke.exe -gateway vpn.example.com:10443 -user alice -password secret `
  -ca C:\certs\private-ca.pem -vpn -vpn-name unispoke

# Linux (root o CAP_NET_ADMIN)
sudo ./unispoke -gateway vpn.example.com:10443 -user alice -password secret \
  -vpn -vpn-name unispoke
```

El modo VPN:

1. Crea un dispositivo TUN (un adaptador Wintun en Windows)
2. Configura la VIP/máscara, la MTU (`-mss + 40`) y el DNS proporcionado por el gateway
3. Añade las rutas proporcionadas por el gateway (las 9 entradas de la respuesta `REQVIP`)
4. Reenvía paquetes IPv4 sin procesar en ambas direcciones; TCP/UDP/ICMP funcionan
5. Sincroniza automáticamente la nueva VIP y las rutas tras restablecer la sesión
6. Elimina las rutas al salir

`-vpn-full` intenta un túnel completo en Windows: primero fija la dirección del gateway como una ruta /32 en el adaptador físico y después añade `0.0.0.0/0`. Linux/macOS solo admiten túnel dividido por ahora.

> Los listeners de proxy y el modo VPN son mutuamente excluyentes: `-vpn` ignora `-socks`/`-http`.

### Preparación en Windows

Wintun es un controlador TUN en espacio de usuario (MIT, firmado por Microsoft). Coloca el `wintun.dll` correspondiente a tu arquitectura junto a `unispoke.exe`:

1. Descarga `wintun-0.14.1.zip` desde <https://www.wintun.net/>
2. Copia `bin/amd64/wintun.dll` (o `arm64`) al directorio del programa
3. Ejecuta como **Administrador**

Windows instala el controlador la primera vez que se crea el adaptador; el modo VPN muestra un error claro si falta `wintun.dll`.

## Transporte UDP

Los gateways Legacy y V1 también ofrecen un plano de datos UDP. Sustituye las tramas TLS por datagramas UDP y es varias veces más rápido que la ruta TCP en el mismo gateway:

```sh
./unispoke -gateway vpn.example.com:10443 -user alice \
  -password 'secret' -ca ca.pem -transport udp
```

El gateway solo acepta tramas UDP de hasta 1280 bytes, por lo que la MTU del túnel se limita a 1240 (`-mss 1200`) aunque se pida una mayor. El plano UDP cifra el cuerpo del paquete IP con AES-128-CBC, pero la cabecera IPv4 de 20 bytes viaja en claro, igual que en el cliente del fabricante. En gateways V1 el cliente elige el modo 3 o el modo 4 exclusivo de V1 (AES-256-GCM) según la configuración del gateway. `-transport auto` intenta UDP y vuelve a TCP si el gateway no lo ofrece.

## Opciones

| Opción | Valor predeterminado | Descripción |
|---|---|---|
| `-gateway` | obligatorio | Gateway `host:port` |
| `-user` / `-password` | obligatorio | Credenciales (la contraseña también puede venir de `UNISPOKE_PASSWORD`) |
| `-mode` | `auto` | `auto`, `legacy` o `v1` |
| `-transport` | `tcp` | Transporte de datos: `tcp`, `udp` o `auto` |
| `-domain` | host del gateway | Dominio de autenticación |
| `-mac` | derivado | MAC del cliente |
| `-socks` | `127.0.0.1:1080` | Dirección de escucha SOCKS5; vacío lo desactiva |
| `-http` | `127.0.0.1:8080` | Dirección de escucha del proxy HTTP; vacío lo desactiva |
| `-dns` | vacío | Dirección del relay DNS UDP local, p. ej. `127.0.0.1:5353` |
| `-dns-server` | vacío | Sobrescribe el DNS del gateway, separado por comas |
| `-vpn` | false | Activa el modo TUN a nivel de sistema |
| `-vpn-name` | `unispoke` | Nombre del adaptador TUN/Wintun |
| `-vpn-full` | false | Túnel completo (Windows) |
| `-vpn-debug` | false | Registra resúmenes de paquetes VPN, contadores periódicos y la tabla de rutas |
| `-mss` | `1200` | MSS TCP dentro del túnel; MTU del adaptador = MSS + 40 |
| `-timeout` | `10s` | Tiempo de espera de red |
| `-insecure` | false | Omite la verificación del certificado |
| `-ca` | vacío | Paquete de CA privada |
| `-sni` | host del gateway | Nombre del servidor TLS |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `-log-format` | `plain` | `plain`, `logfmt` o `json` |
| `-quiet` | false | Equivale a `-log-level warn` |
| `-drop-after` | `0` | Hook de prueba: cierra los sockets del túnel tras el tiempo indicado |
| `-version` | false | Muestra versión, sistema operativo y arquitectura |

## Formatos de registro

- `plain` (predeterminado): `2026-10-25T13:02:27.500+08:00 INFO unispoke 0.1.3 (windows/amd64)`
- `logfmt`: `time=2026-10-25T13:02:27.500+08:00 level=INFO msg="unispoke 0.1.3 (windows/amd64)"`
- `json`: `{"time":"2026-10-25T13:02:27.500+08:00","level":"INFO","msg":"unispoke 0.1.3 (windows/amd64)"}`

`-log-level` y `-quiet` se aplican a los tres formatos.

## Seguridad

- Los certificados se verifican de forma predeterminada. `-insecure` solo debe usarse con gateways de laboratorio que tengan certificados autofirmados.
- Las credenciales en la línea de comandos pueden filtrarse a la lista de procesos; para uso desatendido, prefiere `UNISPOKE_PASSWORD`.
- El plano UDP cifra el cuerpo del paquete IP pero deja en claro la cabecera IPv4 de 20 bytes, igual que el cliente del fabricante.
- Usa esta herramienta únicamente en redes en las que tengas autorización para realizar pruebas.
