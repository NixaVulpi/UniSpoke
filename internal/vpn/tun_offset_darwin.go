//go:build darwin

package vpn

// macOS utun 的每个报文都带 4 字节地址族头，读写均需预留。
const (
	tunWriteOffset = 4
	tunReadOffset  = 4
)
