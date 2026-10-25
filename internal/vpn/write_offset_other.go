//go:build !linux

package vpn

// Windows and other platforms write packets directly from the start of the
// buffer.
const tunWriteOffset = 0
