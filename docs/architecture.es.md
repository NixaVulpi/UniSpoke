# Arquitectura y compatibilidad

[English](architecture.md) | Español | [简体中文](architecture.zh.md)

[← Volver al README](../README.es.md)

## Estructura de módulos

```text
cmd/unispoke            CLI, listeners, selección de modo
internal/tunnel         formato de tramas, TLS, autenticación Legacy/V1, sesiones, keepalive, parámetros de red
internal/netstack       netstack de gVisor (TCP/UDP), inyección y extracción de IP del túnel
internal/packet         relleno y checksums para el límite de ≤40 bytes del gateway
internal/proxy          frontales SOCKS5 (CONNECT/UDP ASSOCIATE) y HTTP
internal/dnsrelay       resolución DNS dentro del túnel y relay DNS UDP local
internal/vpn            dispositivo TUN/Wintun, configuración de rutas/DNS del sistema, reenvío de IP sin procesar
```

El plano de datos usa [gVisor netstack](https://gvisor.dev/); el adaptador virtual usa [wireguard-go tun](https://git.zx2c4.com/wireguard-go/).

Modo proxy:

```text
aplicación -> SOCKS5/HTTP -> netstack(TCP/UDP) -> packet.Pad -> tunnel.SendIP
aplicación <- SOCKS5/HTTP <- netstack          <-               tunnel.RecvIP <- gateway
```

Modo VPN:

```text
pila del sistema -> TUN/Wintun -> packet.Pad -> tunnel.SendIP
pila del sistema <- TUN/Wintun <-            <- tunnel.RecvIP <- gateway
```

El túnel es un canal IPv4 sin procesar sobre TLS (cmd `0x02` en Legacy, cmd `0x66` en V1).
El modo proxy no modifica las rutas ni los adaptadores del host; el modo VPN crea un adaptador virtual y cambia las rutas y el DNS según sea necesario.

## Protocolo

El protocolo observado está documentado en [protocol.es.md](protocol.es.md), incluidos el formato de tramas, los números de comando, el establecimiento de sesión Legacy y V1, la reconexión y el límite de la comprobación de endpoint (CEPS). Leagsoft UniVPN es Huawei SVN; el servicio del cliente se llama `UniVPNCS`. Los comportamientos del servidor no verificados están marcados como tales.

## Estado

| Capacidad | Estado |
|---|---|
| Gateway Legacy | Verificado contra un gateway real (autenticación, TCP, UDP, HTTP, reconexión) |
| Gateway V1 | Implementado a partir de observaciones del protocolo; aún no se ha ejecutado contra un gateway V1 real |
| SOCKS5 TCP / UDP | Verificado |
| Proxy HTTP | Verificado (el protocolo del proxy HTTP no puede transportar UDP) |
| Plano de datos UDP | Legacy modo 3 verificado contra un gateway real; V1 modos 3/4 implementados y probados con tests unitarios, aún no ejecutados contra un gateway V1 |
| Relay DNS | Implementado; su disponibilidad depende del DNS proporcionado por el gateway o de `-dns-server` |
| Modo VPN (Windows) | Implementado (Wintun + netsh); requiere privilegios de administrador |
| Modo VPN (Linux/macOS) | Linux verificado contra un gateway real; macOS implementado pero aún no ejecutado; el túnel completo es exclusivo de Windows |

## Plataformas

| Sistema operativo | Modo proxy | Modo VPN |
|---|---|---|
| Linux amd64/arm64 | ✅ | ✅ (verificado en Fedora 44 amd64; requiere `CAP_NET_ADMIN` o root) |
| Windows amd64/arm64 | ✅ | ✅ (requiere privilegios de administrador y `wintun.dll`) |
| macOS amd64/arm64 | ✅ | ✅ (requiere root; aún no verificado) |

## Registro de validación

El 2026-10-25, contra un gateway Legacy (plano de datos gVisor):

- La autodetección seleccionó Legacy; la autenticación se completó; se asignaron una dirección virtual `/24` y nueve rutas
- HTTP `absolute-form` y reutilización keep-alive: `/` y `/openapi.json` (2.035.183 bytes) devolvieron 200
- SOCKS5 `CONNECT`: una respuesta de 2 MB se completó íntegra
- SOCKS5 `UDP ASSOCIATE`: NetBIOS NBSTAT a `172.22.1.11:137` devolvió una respuesta de 167 bytes
- El binario se compiló en Windows/amd64; el modo proxy y UDP se verificaron contra un gateway real
- La creación del TUN en modo VPN devolvió correctamente un error de permisos sin privilegios de administrador; la ruta con administrador aún no se ha verificado
- `go test ./...`, `go vet ./...`, `gofmt -l .` pasaron

El 2026-10-25, en Linux (Fedora 44 Server, kernel 7.1.10, amd64; binario compilado de forma cruzada en Windows/amd64):

- Modo proxy: SOCKS5 `CONNECT` obtuvo el banner SSH de `172.22.1.102:22`; HTTP `absolute-form` y `CONNECT` devolvieron 301 desde el servidor web interno; 200 peticiones keep-alive por cada proxy (1,55 MB) sin errores
- SOCKS5 `UDP ASSOCIATE`: NetBIOS NBSTAT a `172.22.1.11:137` devolvió una respuesta de 157 bytes
- El gateway no envió servidores DNS, por lo que el relay DNS permaneció desactivado y los nombres internos no se pudieron resolver; solo eran alcanzables las rutas divididas (sin salida a Internet)
- Modo VPN: TUN creado con VIP `10.10.100.64/24`, MTU 1240 y nueve rutas; ICMP y TCP a dos subredes internas funcionaron; HTTP devolvió 301
- La salida ordenada eliminó todas las rutas y el adaptador; `-drop-after` restableció la sesión en unos 150 ms, conservó la VIP y reanudó el tráfico
- Sin root, el modo VPN falló limpiamente con `operation not permitted`
- Corregido durante esta ejecución: los paquetes de vuelta no se escribían en el TUN en Linux (`invalid offset`) y macOS tampoco habría funcionado. `wireguard-go` exige un desplazamiento específico de la plataforma — 10 bytes de cabecera virtio-net en Linux, 4 bytes de cabecera de familia de direcciones en macOS — que ahora reserva el plano de datos de la VPN

El 2026-10-25, plano de datos UDP (Legacy modo 3, derivado de capturas y de la base IDA del cliente del fabricante):

- El cliente del fabricante mantiene una conexión TCP/TLS de control (puerto 10443) y envía datos por UDP al puerto 443
- El comando `0x1A` devuelve el puerto UDP; el comando `0x0D` devuelve el modo 3 y una clave AES-128 de 16 bytes
- Cada datagrama lleva una cabecera de 28 bytes, la cabecera IPv4 de 20 bytes en claro y el resto del paquete IP con AES-128-CBC y relleno de ceros
- El gateway acepta como máximo 1280 bytes por datagrama, por lo que la MTU interna se limita a 1240 (`-mss 1200`)
- Reutilizar los búferes de recepción y ampliar los búferes del socket UDP duplicó aproximadamente el rendimiento; cuatro flujos paralelos alcanzaron unos 2,8 MiB/s
- Comparación A/B en el mismo periodo contra el cliente del fabricante: `unispoke` 0,93–2,11 MiB/s, cliente del fabricante 0,89–1,17 MiB/s
- Los modos 3 y 4 de V1 se implementaron a partir del mismo cliente; los tests cubren el análisis TLV, la sonda del modo 4, el viaje de ida y vuelta GCM y la trama de cambio, pero el gateway disponible es solo Legacy

## Compatibilidad

| Dimensión | Soporte | Notas |
|---|---|---|
| Generación de gateway | Legacy, V1 | V1 no se ha probado en un entorno real |
| Autenticación | Usuario/contraseña | No se implementan MFA, certificados ni autenticación por identidad de host |
| Transporte | TLS/TCP, UDP | Modo UDP 3 verificado en Legacy; modos 3/4 de V1 implementados pero no verificados en vivo; el modo 2 no está implementado |
| Protocolos de carga | TCP, UDP, ICMP | SOCKS5 UDP verificado; el proxy HTTP no tiene UDP |
| Familia de direcciones | IPv4 | IPv6 no está implementado |
| Comprobación de endpoint | No implementada | Los gateways que requieren CEPS no pueden completar el establecimiento |
| Asignación de direcciones | `REQVIP` | No se implementa la asignación de direcciones basada en DHCP |

## Alcance y limitaciones

- El proxy HTTP no puede transportar UDP; es una limitación del protocolo. Usa SOCKS5 o el modo VPN para UDP.
- El modo proxy y el modo VPN son mutuamente excluyentes; el modo VPN requiere privilegios de administrador/root.
- El túnel completo actualmente solo está disponible en Windows; en Linux/macOS usa las rutas divididas proporcionadas por el gateway.
- La resolución DNS interna depende del DNS proporcionado por el gateway o de `-dns-server`; si no existe ninguno, se usa el resolver del sistema.
- Una sesión autenticada transporta múltiples flujos; netstack los multiplexa.
- El transporte UDP limita la MTU interna a 1240 y deja en claro la cabecera IPv4 de 20 bytes, igual que el cliente del fabricante. El modo 2 (IV estático) no está implementado y la ruta UDP de V1 no se ha verificado contra un gateway V1 real.
- Las comprobaciones de endpoint CEPS, TLS con criptografía nacional china (`SM2`/`SM3`/`SM4`), IPsec y L2TP están fuera de alcance.

## Componentes de terceros

| Componente | Propósito | Licencia |
|---|---|---|
| `gvisor.dev/gvisor` | Pila TCP/IP en espacio de usuario | Apache-2.0 |
| `golang.zx2c4.com/wireguard` / `wintun` | Dispositivo TUN | MIT |
| `github.com/go-gost/gosocks5` | Códec del protocolo SOCKS5 | MIT |
| `github.com/miekg/dns` | Cliente DNS | BSD-3-Clause |
