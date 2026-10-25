//go:build !linux && !darwin

package vpn

// Windows 的 Wintun 直接收发裸 IP 报文。
const (
	tunWriteOffset = 0
	tunReadOffset  = 0
)
