//go:build darwin

package vpn

// macOS utun devices prefix every packet with a 4-byte address-family
// header. wireguard-go's tun requires offset >= 4 for both directions and
// places the packet at buf[offset:offset+size].
const (
	tunWriteOffset = 4
	tunReadOffset  = 4
)
