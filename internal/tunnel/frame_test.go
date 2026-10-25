package tunnel

import (
	"encoding/binary"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	v1 := BuildV1(CmdV1Data, []byte{1, 2, 3})
	f, n, st := parseFrame(v1)
	if st != 1 || n != len(v1) || f.Version != 1 || f.Cmd != CmdV1Data {
		t.Fatalf("v1 parse: st=%d n=%d f=%+v", st, n, f)
	}
	if string(f.Payload) != string([]byte{1, 2, 3}) {
		t.Fatalf("v1 payload = %v", f.Payload)
	}

	leg := BuildLegacy(CmdLegacyREQVIP, []byte{9, 8}, 0x1234)
	f, n, st = parseFrame(leg)
	if st != 1 || n != len(leg) || f.Version != 0 || f.Cmd != CmdLegacyREQVIP || f.SID != 0x1234 {
		t.Fatalf("legacy parse: st=%d n=%d f=%+v", st, n, f)
	}
}

func TestFrameIncomplete(t *testing.T) {
	v1 := BuildV1(CmdV1Data, make([]byte, 16))
	if _, _, st := parseFrame(v1[:10]); st != 0 {
		t.Fatalf("expected incomplete, got %d", st)
	}
}

func TestLegacyLengthEndianFallback(t *testing.T) {
	// 长度字段声明 0x1400（大端），实际负载 20 字节，应回退到小端。
	p := make([]byte, 16+20)
	binary.BigEndian.PutUint32(p[0:4], MagicLegacy1)
	binary.BigEndian.PutUint32(p[4:8], MagicV1)
	binary.BigEndian.PutUint16(p[12:14], CmdLegacyACL)
	binary.BigEndian.PutUint16(p[14:16], 0x1400)
	binary.LittleEndian.PutUint16(p[14:16], 20)
	f, n, st := parseFrame(p)
	if st != 1 || n != len(p) || len(f.Payload) != 20 {
		t.Fatalf("acl fallback: st=%d n=%d len=%d", st, n, len(f.Payload))
	}
}

func TestParseLegacyConfig(t *testing.T) {
	p := make([]byte, 956)
	copy(p[0:4], []byte{10, 10, 100, 5})
	copy(p[4:8], []byte{255, 255, 255, 0})
	binary.BigEndian.PutUint32(p[184:188], 1)
	copy(p[188:192], []byte{172, 22, 1, 0})
	copy(p[192:196], []byte{255, 255, 255, 0})
	c, err := parseLegacyConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.VIP.String() != "10.10.100.5" {
		t.Fatalf("vip = %s", c.VIP)
	}
	if len(c.Routes) != 1 || c.Routes[0].String() != "172.22.1.0/24" {
		t.Fatalf("routes = %v", c.Routes)
	}
}

func TestParseAuthResponse(t *testing.T) {
	p := make([]byte, 8+4+32)
	// 结果 0，随后是 TLV type 3、长度 32
	binary.BigEndian.PutUint16(p[8:10], 3)
	binary.BigEndian.PutUint16(p[10:12], 32)
	for i := 0; i < 32; i++ {
		p[12+i] = byte(i)
	}
	tok, err := parseAuthResponse(p)
	if err != nil || len(tok) != 32 || tok[0] != 0 || tok[31] != 31 {
		t.Fatalf("token=%v err=%v", tok, err)
	}
}
