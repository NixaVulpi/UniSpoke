package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParseV1ConfigUDP(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	p := []byte{0, 0, 0, 0}
	p = append(p, tlv(1, []byte{10, 10, 100, 1, 24})...)
	p = append(p, tlv(7, []byte{4})...)
	p = append(p, tlv(8, key)...)
	p = append(p, tlv(9, []byte{0x01, 0xBB})...)

	c, err := parseV1Config(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.VIP.Equal(net.IPv4(10, 10, 100, 1)) {
		t.Fatalf("vip=%v", c.VIP)
	}
	if c.Mode != v1ModeGCM {
		t.Fatalf("mode=%d", c.Mode)
	}
	if !bytes.Equal(c.GCMKey, key) {
		t.Fatal("gcm key mismatch")
	}
	if c.UDPPort != 443 {
		t.Fatalf("port=%d", c.UDPPort)
	}
}

func TestV1ProbeLayout(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	vip := net.IPv4(10, 10, 100, 9).To4()
	probe := buildV1Probe(vip, key)
	if len(probe) != 60 {
		t.Fatalf("probe len=%d, want 60", len(probe))
	}
	if probe[0] != 1 || probe[1] != 2 {
		t.Fatalf("bad prefix %x", probe[:2])
	}
	if !bytes.Equal(probe[4:8], vip) {
		t.Fatal("vip mismatch")
	}
	plain, err := gcmOpen(key, probe[20:32], probe[52:], probe[36:52])
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 8 || binary.BigEndian.Uint32(plain[:4]) != MagicV1 || plain[5] != v1ProbeCmd {
		t.Fatalf("bad probe header %x", plain)
	}
}

func TestV1GCMPacketRoundTrip(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	vip := net.IPv4(10, 10, 100, 9).To4()
	pkt := testIPPacket(80)

	if err := sendV1GCM(cli, vip, key, pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != v1GCMHdr+8+len(pkt) {
		t.Fatalf("datagram len=%d", n)
	}
	if !bytes.Equal(buf[4:8], vip) {
		t.Fatal("vip mismatch")
	}
	plain, err := gcmOpen(key, buf[20:32], buf[52:n], buf[36:52])
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(plain[:4]) != MagicV1 || plain[5] != CmdV1Data {
		t.Fatalf("bad v1 header %x", plain[:8])
	}
	if l := int(binary.BigEndian.Uint16(plain[6:8])); l != len(pkt) {
		t.Fatalf("payload len=%d", l)
	}
	if !bytes.Equal(plain[8:], pkt) {
		t.Fatal("packet mismatch")
	}

	// 下行：构造同样布局的数据报，recvV1GCM 应还原 IP 包。
	down := make([]byte, v1GCMHdr+8+len(pkt))
	down[0], down[1] = 1, 2
	copy(down[4:8], vip)
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	ct, tag := gcmSeal(key, iv[:v1GCMNonce], BuildV1(CmdV1Data, pkt))
	copy(down[20:36], iv)
	copy(down[36:52], tag)
	copy(down[52:], ct)
	go func() { _, _ = cli.Write(down) }()
	got, err := recvV1GCM(srv, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatal("downlink mismatch")
	}
}

func TestV1SwitchFrame(t *testing.T) {
	token := bytes.Repeat([]byte{0x5A}, 32)
	sw := BuildV1(CmdV1TunnelSwitch, append(append([]byte(nil), token...), 2))
	if len(sw) != 8+33 {
		t.Fatalf("switch len=%d", len(sw))
	}
	if sw[5] != CmdV1TunnelSwitch {
		t.Fatalf("cmd=%d", sw[5])
	}
	if !bytes.Equal(sw[8:40], token) || sw[40] != 2 {
		t.Fatal("switch payload mismatch")
	}
}
