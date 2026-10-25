# 架构与兼容性

[English](architecture.md) | [Español](architecture.es.md) | 简体中文

[← 返回 README](../README.zh.md)

## 模块结构

```text
cmd/unispoke            CLI、监听器、模式选择
internal/tunnel         帧格式、TLS、Legacy/V1 认证、会话、心跳、网络参数
internal/netstack       gVisor netstack（TCP/UDP），隧道原始 IP 注入与取出
internal/packet         网关 ≤40 字节报文的补齐与校验和
internal/proxy          SOCKS5（CONNECT/UDP ASSOCIATE）与 HTTP 前端
internal/dnsrelay       隧道内 DNS 解析与本地 UDP DNS 转发
internal/vpn            TUN/Wintun 设备、系统路由/DNS 配置、原始 IP 转发
```

数据面使用 [gVisor netstack](https://gvisor.dev/)，虚拟网卡使用 [wireguard-go tun](https://git.zx2c4.com/wireguard-go/)。

代理模式：

```text
应用 -> SOCKS5/HTTP -> netstack(TCP/UDP) -> packet.Pad -> tunnel.SendIP
应用 <- SOCKS5/HTTP <- netstack          <-               tunnel.RecvIP <- 网关
```

VPN 模式：

```text
系统协议栈 -> TUN/Wintun -> packet.Pad -> tunnel.SendIP
系统协议栈 <- TUN/Wintun <-            <- tunnel.RecvIP <- 网关
```

隧道是承载在 TLS 之上的裸 IPv4 通道（Legacy cmd `0x02`，V1 cmd `0x66`）。
代理模式不修改主机的路由或网卡；VPN 模式会创建虚拟网卡并按需修改路由与 DNS。

## 协议

观测到的协议记录在 [protocol.zh.md](protocol.zh.md)，包括帧布局、命令号、Legacy 与 V1
的会话建立、重连以及端点检查（CEPS）边界。Leagsoft UniVPN 即华为 SVN，其客户端服务名为
`UniVPNCS`；文档中未验证的服务器行为均已标注。

## 状态

| 能力 | 状态 |
|---|---|
| Legacy 网关 | 真实网关验证通过（认证、TCP、UDP、HTTP、重连） |
| V1 网关 | 依据协议观测实现，尚未在真实 V1 网关上运行 |
| SOCKS5 TCP / UDP | 验证通过 |
| HTTP 代理 | 验证通过（HTTP 代理协议本身不支持 UDP） |
| UDP 数据面 | Legacy 模式 3 已在真实网关验证；V1 模式 3/4 已实现并通过单元测试，尚未在 V1 网关上运行 |
| DNS 转发 | 已实现；是否可用取决于网关是否下发 DNS 或 `-dns-server` |
| VPN 模式（Windows） | 已实现（Wintun + netsh）；需要管理员权限 |
| VPN 模式（Linux/macOS） | Linux 已在真实网关验证；macOS 已实现但尚未运行；全隧道仅 Windows |

## 平台

| 操作系统 | 代理模式 | VPN 模式 |
|---|---|---|
| Linux amd64/arm64 | ✅ | ✅（已在 Fedora 44 amd64 验证；需要 `CAP_NET_ADMIN` 或 root） |
| Windows amd64/arm64 | ✅ | ✅（需要管理员权限与 `wintun.dll`） |
| macOS amd64/arm64 | ✅ | ✅（需要 root；尚未验证） |

## 验证记录

2026-10-25，针对一个 Legacy 网关（gVisor 数据面）：

- 自动识别选中 Legacy；认证成功；分配 `/24` 虚拟地址与九条路由
- HTTP `absolute-form` 与 keep-alive 复用：`/` 与 `/openapi.json`（2,035,183 字节）均为 200
- SOCKS5 `CONNECT`：2 MB 响应完整
- SOCKS5 `UDP ASSOCIATE`：向 `172.22.1.11:137` 发送 NetBIOS NBSTAT，收到 167 字节应答
- 二进制在 Windows/amd64 上构建，代理模式与 UDP 均通过真实网关验证
- VPN 模式的 TUN 创建在非管理员环境下正确返回权限错误；管理员环境尚待验证
- `go test ./...`、`go vet ./...`、`gofmt -l .` 通过

2026-10-25，在 Linux（Fedora 44 Server，内核 7.1.10，amd64；二进制在 Windows/amd64 上交叉编译）上：

- 代理模式：SOCKS5 `CONNECT` 成功读取 `172.22.1.102:22` 的 SSH banner；HTTP `absolute-form` 与 `CONNECT` 均从内网 Web 服务器得到 301；每个代理各跑 200 次 keep-alive 请求（1.55 MB），无错误
- SOCKS5 `UDP ASSOCIATE`：向 `172.22.1.11:137` 发送 NetBIOS NBSTAT，收到 157 字节应答
- 网关未下发 DNS，因此 DNS 转发保持关闭，内网域名无法解析；仅分割路由可达（无公网出口）
- VPN 模式：TUN 创建成功，VIP `10.10.100.64/24`、MTU 1240、九条路由；对两个内网网段的 ICMP 与 TCP 均成功；HTTP 返回 301
- 优雅退出删除了全部路由与虚拟网卡；`-drop-after` 后约 150 ms 完成重连，VIP 保持不变，流量恢复
- 非 root 下 VPN 模式以 `operation not permitted` 干净失败
- 本次验证中修复：Linux 上回程报文无法写入 TUN（`invalid offset`），macOS 同样无法工作。`wireguard-go` 要求平台相关的偏移量——Linux 为 10 字节 virtio-net 头，macOS 为 4 字节地址族头——VPN 数据面现已按平台预留

2026-10-25，UDP 数据面（Legacy 模式 3，依据抓包与厂商客户端 IDA 数据库逆向）：

- 厂商客户端保持一条 TCP/TLS 控制连接（10443），数据走 UDP 443
- cmd `0x1A` 返回 UDP 端口；cmd `0x0D` 返回模式 3 与 16 字节 AES-128 密钥
- 每个数据报为 28 字节头 + 明文 20 字节 IPv4 头 + 对其余 IP 包的 AES-128-CBC 密文（零填充）
- 网关单个 UDP 报文上限 1280 字节，因此内层 MTU 固定为 1240（`-mss 1200`）
- 复用收包缓冲并加大 UDP socket 缓冲后，吞吐约翻倍；4 条并发流合计约 2.8 MiB/s
- 同一时段与厂商客户端 A/B 对比：`unispoke` 0.93–2.11 MiB/s，厂商客户端 0.89–1.17 MiB/s
- V1 模式 3/4 已按同一客户端实现；单元测试覆盖 TLV 解析、模式 4 探测包、GCM 往返与切换帧，但当前网关为 legacy-only

## 兼容性

| 维度 | 支持情况 | 说明 |
|---|---|---|
| 网关代际 | Legacy、V1 | V1 未做真实环境测试 |
| 认证方式 | 用户名/密码 | 未实现 MFA、证书与主机标识认证 |
| 传输 | TLS/TCP、UDP | Legacy UDP 模式 3 已验证；V1 模式 3/4 已实现但未实测；模式 2 未实现 |
| 载荷协议 | TCP、UDP、ICMP | SOCKS5 UDP 已验证；HTTP 代理无 UDP |
| 地址族 | IPv4 | 未实现 IPv6 |
| 端点检查 | 未实现 | 要求 CEPS 的网关无法完成建立 |
| 地址分配 | `REQVIP` | 未实现基于 DHCP 的地址分配 |

## 适用范围与限制

- HTTP 代理无法承载 UDP，这是协议限制；UDP 请走 SOCKS5 或 VPN 模式。
- 代理模式与 VPN 模式互斥；VPN 模式需要管理员/root 权限。
- 全隧道目前仅 Windows；Linux/macOS 请使用网关下发的分隧道路由。
- 内网域名解析依赖网关下发 DNS 或 `-dns-server`；两者都没有时回退系统解析器。
- 一个已认证会话承载多条流；各流由 netstack 复用。
- UDP 传输把内层 MTU 限制在 1240，并与厂商客户端一致保留 20 字节 IPv4 头为明文；模式 2（静态 IV）未实现，V1 UDP 路径尚未在真实 V1 网关验证。
- CEPS 端点检查、国密 TLS（`SM2`/`SM3`/`SM4`）、IPsec 与 L2TP 不在范围内。

## 第三方组件

| 组件 | 用途 | 许可证 |
|---|---|---|
| `gvisor.dev/gvisor` | 用户态 TCP/IP 栈 | Apache-2.0 |
| `golang.zx2c4.com/wireguard` / `wintun` | TUN 设备 | MIT |
| `github.com/go-gost/gosocks5` | SOCKS5 协议编解码 | MIT |
| `github.com/miekg/dns` | DNS 客户端 | BSD-3-Clause |
