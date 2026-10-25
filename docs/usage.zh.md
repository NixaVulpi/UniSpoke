# 使用说明

[English](usage.md) | [Español](usage.es.md) | 简体中文

[← 返回 README](../README.zh.md)

所有配置均通过命令行参数传入；密码也可用 `UNISPOKE_PASSWORD` 环境变量提供，避免出现在进程列表中。

## 代理模式（默认）

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

验证：

```sh
curl --socks5-hostname 127.0.0.1:1080 http://10.20.1.5/     # TCP
curl -x http://127.0.0.1:8080 http://10.20.1.5/             # HTTP
curl -p -x http://127.0.0.1:8080 http://10.20.1.5/          # CONNECT
```

SOCKS5 UDP 需要客户端支持（例如 `socks5h` 场景下的游戏、语音、DNS 工具）。
HTTP 代理协议本身不承载 UDP，需要 UDP 时请用 SOCKS5 或 VPN 模式。

## VPN 模式

```sh
# Windows（管理员终端）
.\unispoke.exe -gateway vpn.example.com:10443 -user alice -password secret `
  -ca C:\certs\private-ca.pem -vpn -vpn-name unispoke

# Linux（root 或 CAP_NET_ADMIN）
sudo ./unispoke -gateway vpn.example.com:10443 -user alice -password secret \
  -vpn -vpn-name unispoke
```

VPN 模式会：

1. 创建 TUN（Windows 为 Wintun 适配器）
2. 配置 VIP/掩码、MTU（`-mss + 40`）、网关下发的 DNS
3. 添加网关下发的路由（`REQVIP` 响应中的 9 条）
4. 双向转发原始 IPv4 报文；TCP/UDP/ICMP 全部可用
5. 会话重建后自动同步新 VIP/路由
6. 退出时删除路由

`-vpn-full` 在 Windows 上尝试全隧道：先把网关地址 /32 固定到物理网卡，再加 `0.0.0.0/0`。
Linux/macOS 目前只支持分隧道。

> 代理监听与 VPN 模式互斥：`-vpn` 会忽略 `-socks`/`-http`。

### Windows 准备

Wintun 是用户态 TUN 驱动（MIT，微软签名）。把对应架构的 `wintun.dll` 放在 `unispoke.exe`
同目录即可：

1. 从 <https://www.wintun.net/> 下载 `wintun-0.14.1.zip`
2. 复制 `bin/amd64/wintun.dll`（或 `arm64`）到程序目录
3. 以**管理员身份**运行

首次创建适配器时 Windows 会安装驱动；`wintun.dll` 缺失时 VPN 模式会给出明确错误。

## 参数

| 参数 | 默认值 | 含义 |
|---|---|---|
| `-gateway` | 必填 | 网关 `host:port` |
| `-user` / `-password` | 必填 | 账号凭据（密码也可用 `UNISPOKE_PASSWORD`） |
| `-mode` | `auto` | `auto`、`legacy` 或 `v1` |
| `-domain` | 网关主机名 | 认证域 |
| `-mac` | 自动推导 | 客户端 MAC |
| `-socks` | `127.0.0.1:1080` | SOCKS5 监听地址；留空禁用 |
| `-http` | `127.0.0.1:8080` | HTTP 代理监听地址；留空禁用 |
| `-dns` | 空 | 本地 UDP DNS 转发地址，如 `127.0.0.1:5353` |
| `-dns-server` | 空 | 覆盖网关 DNS，逗号分隔 |
| `-vpn` | false | 启用系统级 TUN 模式 |
| `-vpn-name` | `unispoke` | TUN/Wintun 适配器名 |
| `-vpn-full` | false | 全隧道（Windows） |
| `-vpn-debug` | false | 打印 VPN 报文摘要、周期计数与路由表 |
| `-mss` | `1200` | 隧道内 TCP MSS；网卡 MTU = MSS + 40 |
| `-timeout` | `10s` | 网络超时 |
| `-insecure` | false | 跳过证书校验 |
| `-ca` | 空 | 私有 CA 证书包 |
| `-sni` | 网关主机名 | TLS 服务器名称 |
| `-log-level` | `info` | `debug`、`info`、`warn`、`error` |
| `-log-format` | `plain` | `plain`、`logfmt` 或 `json` |
| `-quiet` | false | 等同 `-log-level warn` |
| `-drop-after` | `0` | 测试钩子：指定时长后断开隧道套接字 |
| `-version` | false | 输出版本、操作系统与架构 |

## 安全

- 默认校验证书。`-insecure` 仅用于自签名证书的实验网关。
- 命令行中的凭据可能泄漏到进程列表；无人值守场景优先用 `UNISPOKE_PASSWORD`。
- 仅可在获得授权测试的网络上使用本工具。
