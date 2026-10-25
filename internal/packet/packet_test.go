package packet

import (
	"encoding/binary"
	"testing"
)

func ipv4(src, dst [4]byte, proto byte, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[20:], payload)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))
	return pkt
}

func TestPadPureACK(t *testing.T) {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4
	tcp[13] = tcpACK
	pkt := ipv4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, protoTCP, tcp)
	if len(pkt) != 40 {
		t.Fatalf("packet len = %d, want 40", len(pkt))
	}
	binary.BigEndian.PutUint16(pkt[36:38], tcpChecksum(pkt[12:16], pkt[16:20], pkt[20:]))

	out := Pad(pkt)
	if len(out) != 44 {
		t.Fatalf("padded len = %d, want 44", len(out))
	}
	if got := int(out[32] >> 4); got != 6 {
		t.Fatalf("tcp data offset = %d, want 6", got)
	}
	if got := binary.BigEndian.Uint16(out[2:4]); int(got) != len(out) {
		t.Fatalf("ip total len = %d, want %d", got, len(out))
	}
	if checksum(out[:20]) != 0 {
		t.Fatalf("ip checksum invalid")
	}
	if tcpChecksum(out[12:16], out[16:20], out[20:]) != 0 {
		t.Fatalf("tcp checksum invalid")
	}
	for i := 40; i < 44; i++ {
		if out[i] != 1 {
			t.Fatalf("expected NOP at %d", i)
		}
	}
}

func TestPadSmallUDP(t *testing.T) {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	pkt := ipv4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, protoUDP, udp)

	out := Pad(pkt)
	if len(out) <= 40 {
		t.Fatalf("padded len = %d, want > 40", len(out))
	}
	// 28 字节需要补到 41 以上，按 4 字节对齐补 16 字节 → IHL 9，总长 44。
	if out[0] != 0x49 {
		t.Fatalf("ip header = %#x, want 0x49", out[0])
	}
	if got := binary.BigEndian.Uint16(out[2:4]); int(got) != len(out) {
		t.Fatalf("ip total len = %d, want %d", got, len(out))
	}
	if checksum(out[:36]) != 0 {
		t.Fatalf("ip checksum invalid")
	}
	// UDP 头被整体后移到偏移 36；端口与（此处为 0 的）校验和都应保持不变。
	if got := binary.BigEndian.Uint16(out[36:38]); got != 5353 {
		t.Fatalf("udp source port = %d, want 5353", got)
	}
	if got := binary.BigEndian.Uint16(out[42:44]); got != 0 {
		t.Fatalf("udp checksum = %d, want 0", got)
	}
}

func TestPadLeavesLargePacket(t *testing.T) {
	tcp := make([]byte, 100)
	tcp[12] = 5 << 4
	tcp[13] = tcpACK
	pkt := ipv4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, protoTCP, tcp)
	out := Pad(pkt)
	if &out[0] != &pkt[0] || len(out) != len(pkt) {
		t.Fatalf("large packet should be returned unchanged")
	}
}
