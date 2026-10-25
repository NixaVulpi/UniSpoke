package vpn

import (
	"bytes"
	"testing"
)

func testPacket(size int) []byte {
	pkt := make([]byte, size)
	for i := range pkt {
		pkt[i] = byte(i)
	}
	pkt[0] = 0x45 // IPv4，IHL=5
	return pkt
}

func TestTunWriteFrame(t *testing.T) {
	for _, size := range []int{20, 40, 60, 1500, 65535} {
		buf := bytes.Repeat([]byte{0xaa}, tunWriteOffset+65535)
		pkt := testPacket(size)

		frame := tunWriteFrame(buf, pkt)

		if len(frame) != tunWriteOffset+size {
			t.Fatalf("size %d: frame len = %d, want %d", size, len(frame), tunWriteOffset+size)
		}
		if tunWriteOffset >= len(frame) {
			t.Fatalf("size %d: write offset %d outside frame len %d", size, tunWriteOffset, len(frame))
		}
		if !bytes.Equal(frame[tunWriteOffset:], pkt) {
			t.Fatalf("size %d: packet not placed at offset %d", size, tunWriteOffset)
		}
		for i := 0; i < tunWriteOffset; i++ {
			if frame[i] != 0 {
				t.Fatalf("size %d: header byte %d = %#x, want 0", size, i, frame[i])
			}
		}
	}
}

func TestTunReadPacket(t *testing.T) {
	pkt := testPacket(100)
	buf := bytes.Repeat([]byte{0xaa}, tunReadOffset+len(pkt))
	copy(buf[tunReadOffset:], pkt)

	got, ok := tunReadPacket(buf, len(pkt))
	if !ok {
		t.Fatal("valid IPv4 packet rejected")
	}
	if !bytes.Equal(got, pkt) {
		t.Fatal("packet not extracted from its offset")
	}
}

func TestTunReadPacketRejects(t *testing.T) {
	short := testPacket(19)
	if _, ok := tunReadPacket(short, len(short)); ok {
		t.Fatal("accepted packet shorter than 20 bytes")
	}

	pkt := testPacket(100)
	buf := make([]byte, tunReadOffset+len(pkt))
	copy(buf[tunReadOffset:], pkt)
	if _, ok := tunReadPacket(buf, len(pkt)+1); ok {
		t.Fatal("accepted size beyond buffer")
	}

	v6 := testPacket(100)
	v6[0] = 0x60
	buf6 := make([]byte, tunReadOffset+len(v6))
	copy(buf6[tunReadOffset:], v6)
	if _, ok := tunReadPacket(buf6, len(v6)); ok {
		t.Fatal("accepted non-IPv4 packet")
	}
}
