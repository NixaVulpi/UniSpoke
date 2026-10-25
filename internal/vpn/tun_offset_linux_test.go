//go:build linux

package vpn

import "testing"

func TestTunOffsetsPlatform(t *testing.T) {
	if tunWriteOffset != 10 || tunReadOffset != 0 {
		t.Fatalf("linux offsets = (write %d, read %d), want (10, 0)", tunWriteOffset, tunReadOffset)
	}
}
