//go:build linux

package vpn

// tunWriteOffset mirrors wireguard-go's unexported virtioNetHdrLen.
// Linux TUN devices are created with IFF_VNET_HDR, and the wireguard tun
// write path requires this much headroom for the virtio_net_hdr.
const tunWriteOffset = 10

// tunReadOffset is zero on Linux: wireguard-go strips the virtio_net_hdr
// itself and delivers the packet at the requested offset.
const tunReadOffset = 0
