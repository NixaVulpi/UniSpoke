//go:build !linux && !darwin

package vpn

import "testing"

func TestTunOffsetsPlatform(t *testing.T) {
	if tunWriteOffset != 0 || tunReadOffset != 0 {
		t.Fatalf("other offsets = (write %d, read %d), want (0, 0)", tunWriteOffset, tunReadOffset)
	}
}
