//go:build linux

package vpn

// Linux TUN 始终启用 IFF_VNET_HDR，写入前需预留 10 字节 virtio-net 头。
const tunWriteOffset = 10

const tunReadOffset = 0
