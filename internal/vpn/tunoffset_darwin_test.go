//go:build darwin

package vpn

import "testing"

func TestTunOffsetsPlatform(t *testing.T) {
	if tunWriteOffset != 4 || tunReadOffset != 4 {
		t.Fatalf("darwin offsets = (write %d, read %d), want (4, 4)", tunWriteOffset, tunReadOffset)
	}
}
