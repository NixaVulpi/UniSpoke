//go:build !linux && !darwin

package vpn

// Windows and other platforms write packets directly from the start of the
// buffer.
const tunWriteOffset = 0

// tunReadOffset is zero as well: packets are delivered at the buffer start.
const tunReadOffset = 0
