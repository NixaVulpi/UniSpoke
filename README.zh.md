# unispoke

[English](README.md) | [Español](README.es.md) | 简体中文

一个实验性的 **Leagsoft UniVPN（Huawei SVN）SSL VPN 客户端**，实现协议中观测到的部分子集。支持 **Legacy** 与 **V1** 两代网关，提供两种使用方式：

- **代理模式** — 本地 SOCKS5 与 HTTP 代理
- **VPN 模式** — 创建 TUN 网卡，按网关下发的 VIP/路由/DNS 接管系统流量

隧道数据面默认走 TLS/TCP，可通过 `-transport udp` 使用网关的 UDP 传输。

## 构建

需要 Go 1.27.3+。

```sh
go build -o unispoke ./cmd/unispoke          # Linux / macOS
go build -o unispoke.exe ./cmd/unispoke      # Windows
```

交叉编译：

```sh
GOOS=linux   GOARCH=arm64 go build -trimpath -o dist/unispoke-linux-arm64 ./cmd/unispoke
GOOS=windows GOARCH=amd64 go build -trimpath -o dist/unispoke-windows.exe ./cmd/unispoke
GOOS=darwin  GOARCH=arm64 go build -trimpath -o dist/unispoke-macos-arm64 ./cmd/unispoke
```

## 快速开始

```sh
./unispoke -gateway vpn.example.com:10443 -user alice -password 'secret' -ca /path/to/private-ca.pem
```

默认在 `127.0.0.1:1080` 提供 SOCKS5、在 `127.0.0.1:8080` 提供 HTTP 代理。VPN 模式加 `-vpn`，需要管理员/root 权限；Windows 还需在程序目录放置 `wintun.dll`。

## 开发

```sh
go build ./...
go test ./...
go vet ./...
gofmt -w .
```

CI 在 Linux、Windows、macOS 上执行格式检查、vet、测试与交叉编译。

## 文档

- [使用说明](docs/usage.zh.md) — 代理/VPN 模式、全部参数、Windows 准备、安全提示
- [架构与兼容性](docs/architecture.zh.md) — 模块结构、数据流、验证记录、限制与第三方组件
- [协议记录](docs/protocol.zh.md) — 帧布局、命令号、会话建立与重连

## 许可证

MIT，见 [LICENSE](LICENSE.md)。
