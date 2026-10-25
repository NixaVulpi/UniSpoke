# Subconjunto del protocolo observado

[English](protocol.md) | Español | [简体中文](protocol.zh.md)

[← Volver al README](../README.es.md)

Este documento registra el subconjunto del protocolo **Leagsoft UniVPN (Huawei SVN) SSL VPN** que implementa `unispoke`. El contenido proviene del análisis de la implementación del fabricante y de pruebas de interoperabilidad contra un gateway autorizado. Los campos desconocidos y los comportamientos no verificados están marcados como tales. No contiene credenciales, endpoints ni información específica de ningún sitio.

## Generaciones de gateway

Se han observado dos generaciones de gateway. El cliente sondea el gateway con `FirstConnect` y elige la generación según el valor magic de la primera respuesta:

- **Legacy** — inicio de sesión por HTTPS, tramas de 16 bytes, datos multiplexados sobre la conexión TLS de control.
- **V1** — autenticación binaria dentro de TLS, tramas de 8 bytes, canal TLS de datos independiente.

## Formato de trama

### V1 (cabecera de 8 bytes)

| Desplazamiento | Longitud | Campo |
|---|---|---|
| 0 | 4 | magic `c1 92 a4 d6` |
| 4 | 1 | versión `01` |
| 5 | 1 | comando |
| 6 | 2 | longitud de carga, big-endian, sin cabecera |
| 8 | n | carga |

### Legacy (cabecera de 16 bytes)

| Desplazamiento | Longitud | Campo |
|---|---|---|
| 0 | 4 | magic `fe fc ef be` |
| 4 | 4 | magic `c1 92 a4 d6` |
| 8 | 4 | ID de sesión (ID de usuario), big-endian |
| 12 | 2 | comando, big-endian |
| 14 | 2 | longitud de carga, big-endian |
| 16 | n | carga |

Una respuesta Legacy (la respuesta ACL) usa un campo de longitud little-endian; el resto de respuestas usa big-endian. El lector debe aceptar ambos órdenes de bytes.

## Establecimiento de sesión Legacy

1. HTTPS `GET /netextension/netextensionlogin.html?SelectLanguage=0&UserName=..&Password=..&MacAddress=..&SVN_Seco_AaA=1`
2. La respuesta es binaria, no HTTP: magic `f0 f0 f0 f0`, un resultado con signo en `+4` (negativo indica fallo) y el ID de usuario en `+44`.
3. Se abre una nueva conexión TLS y se envían ACL (cmd `0x06`, cuatro bytes a cero) y REQVIP (cmd `0x03`).
4. La respuesta REQVIP tiene un formato fijo: `+0` VIP, `+4` máscara, `+8` método de asignación de direcciones, `+20` tipo de ruta, `+160` tres servidores DNS, `+184` número de rutas y entradas de ruta de 12 bytes a partir de `+188`.
5. Los datos usan cmd `0x02` con un paquete IPv4 sin procesar como carga. El keepalive de control es cmd `0x07` cada 10 segundos.

## Establecimiento de sesión V1

1. `FirstConnect` (cmd `0x1D`, formato de trama Legacy): 64 bytes de información del sistema operativo, 256 bytes para el dominio de autenticación y cuatro bytes `00 01 00 00`, en total 340 bytes.
2. `AUTH` (cmd `0x01`): dominio de 256 bytes, tipo de autenticación de 16 bits y después TLVs: tipo 1 nombre de usuario, tipo 2 contraseña, tipo 3 cadena MAC.
3. La respuesta tiene el resultado en `+0` y los TLVs a partir de `+8`; el tipo 3 con longitud 32 es el token de sesión.
4. `REQVIP` (cmd `0x03`) transporta ese token. La respuesta está basada en TLV: el tipo 1 (longitud 5) es la VIP, los tipos 5/6 son rutas, el tipo 7 es el modo de túnel y el tipo 9 es el puerto UDP.
5. Una segunda conexión TLS envía `DATA_CONNECT` (cmd `0x64`) con el token.
6. Los datos usan cmd `0x66`, con una carga de ocho bytes a cero seguida de un paquete IPv4 sin procesar. El keepalive de control es cmd `0x06` (token + milisegundos transcurridos, cada 10 segundos); el keepalive de datos es cmd `0x65` (carga vacía, cada 15 segundos).

## Resumen de comandos

| V1 | Legacy | Uso |
|---|---|---|
| `0x01` | — | Autenticación |
| `0x02` | — | Autenticación secundaria (no implementada) |
| `0x03` | `0x03` | Solicitar IP virtual / configuración de red |
| `0x06` | `0x07` | Keepalive |
| `0x09` | — | Cambio de modo de túnel (no implementado) |
| `0x32` | `0x08` | Expulsión |
| — | `0x02` | Datos |
| — | `0x05` | DHCP (no implementado) |
| `0x64` | — | Conexión del canal de datos |
| `0x65` | — | Keepalive del canal de datos |
| `0x66` | — | Datos |

## Reconexión

El cliente del fabricante conserva la sesión autenticada:

1. Cuando un canal falla, activa una marca de reconexión; un watchdog de 10 segundos inicia el proceso.
2. El cliente guarda la VIP actual como referencia y abre una nueva conexión TLS al mismo gateway con los mismos parámetros.
3. Vuelve a enviar REQVIP (o DHCP si la asignación de direcciones usa DHCP).
4. La nueva VIP debe coincidir con la referencia; de lo contrario, la reconexión falla y se pide al usuario que vuelva a iniciar sesión.
5. Si tiene éxito, V1 reconstruye el canal TLS de datos con `DATA_CONNECT`; el modo UDP reconstruye el enlace UDP.

`unispoke` sigue este comportamiento en ambas generaciones y, si el gateway rechaza la reutilización de la sesión, vuelve al inicio de sesión completo.

## Límite de la comprobación de endpoint

El gateway puede exigir una comprobación de cumplimiento del endpoint (CEPS) antes de establecer el túnel. La respuesta de autenticación incluye una marca de comprobación de endpoint; cuando está activa, el cliente del fabricante completa la comprobación en el canal de control antes de iniciar el túnel. `unispoke` no implementa esta comprobación, por lo que esos gateways no pueden completar el establecimiento.

## Notas para implementadores

- La MTU del túnel es de aproximadamente 1300 bytes; un MSS de 1200 es seguro.
- El gateway descarta paquetes IP de 40 bytes o menos. Un ACK TCP sin opciones mide exactamente 40 bytes, así que los ACK puros deben incluir opciones (por ejemplo, cuatro opciones NOP de TCP) para pasar. `internal/packet` de `unispoke` rellena todos los paquetes de ≤40 bytes: TCP recibe opciones NOP, UDP/ICMP recibe opciones NOP de IP (sin cambiar la carga de transporte).
- Las cargas de datos Legacy pueden llevar un prefijo de dos bytes antes del paquete IPv4.
- Las cargas de datos V1 comienzan con ocho bytes a cero antes del paquete IPv4.

### Cargas que no son TCP

El gateway **no** filtra por número de protocolo IP; los paquetes IPv4 sin procesar del canal de datos pueden usar cualquier protocolo. Mediciones durante la ingeniería inversa:

| Protocolo | Destino | Resultado |
|---|---|---|
| ICMP echo | 172.22.1.11 | 3/3, respuesta de tipo 0 |
| UDP NTP | 192.168.200.3:123 | 3/3, respuesta de 48 bytes |
| UDP NetBIOS | 172.22.1.11:137 | 2/2, respuesta NBSTAT de 157 bytes |
| UDP DNS | 192.168.200.2:53 | 2/2, respuesta de 29 bytes |

Por lo tanto, SOCKS5 `UDP ASSOCIATE` puede construirse directamente sobre el canal de datos sin implementar el modo de transporte UDP externo.
Ten en cuenta que las cargas UDP deben ser >12 bytes (20 IP + 8 UDP + carga > 40); los paquetes más pequeños deben rellenarse con opciones IP.

El campo `UDPPort` (TLV 9) de `REQVIP` en V1 pertenece al **modo de transporte rápido que lleva el túnel sobre UDP** y no está relacionado con el UDP de carga; este proyecto solo usa transporte TLS/TCP.
