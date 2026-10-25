//go:build linux

package vpn

// tunWriteOffset mirrors wireguard-go's unexported virtioNetHdrLen.
// Linux TUN devices are created with IFF_VNET_HDR, and the wireguard tun
// write path requires this much headroom for the virtio_net_hdr.
const tunWriteOffset = 10
