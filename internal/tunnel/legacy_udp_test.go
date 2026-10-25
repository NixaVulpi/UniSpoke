package tunnel

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func testIPPacket(n int) []byte {
	pkt := make([]byte, n)
	pkt[0] = 0x45
	for i := 20; i < n; i++ {
		pkt[i] = byte(i)
	}
	binary.BigEndian.PutUint16(pkt[2:4], uint16(n))
	return pkt
}

func TestEncryptDecryptCBC(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 16)
	for _, n := range []int{0, 1, 15, 16, 17, 100} {
		pt := bytes.Repeat([]byte{0xAB}, n)
		ct := encryptCBC(key, iv, pt)
		if len(ct)%aesBlockSize != 0 || len(ct) < n {
			t.Fatalf("n=%d: ciphertext len %d", n, len(ct))
		}
		got := decryptCBC(key, iv, ct)
		if !bytes.Equal(got[:n], pt) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestLegacyUDPFrame(t *testing.T) {
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

	key := [16]byte{0x30, 0x31, 0x32, 0x33}
	uid := uint32(0x0b0001d4)
	pkt := testIPPacket(60)
	if err := sendLegacyUDP(cli, uid, key, pkt); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:8], legacyUDPMagic) {
		t.Fatalf("bad magic %x", buf[:8])
	}
	if binary.BigEndian.Uint16(buf[8:10]) != 0x021C || binary.BigEndian.Uint16(buf[10:12]) != 0x0010 {
		t.Fatalf("bad type field %x", buf[8:12])
	}
	if binary.BigEndian.Uint32(buf[12:16]) != uid {
		t.Fatalf("bad session id %x", buf[12:16])
	}
	if !bytes.Equal(buf[28:48], pkt[:20]) {
		t.Fatal("ip header not sent in clear")
	}
	plain := decryptCBC(key[:], buf[12:28], buf[48:n])
	if !bytes.Equal(plain[:len(pkt)-20], pkt[20:]) {
		t.Fatal("encrypted body round trip mismatch")
	}
}

func TestRecvLegacyUDP(t *testing.T) {
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

	key := [16]byte{0x40, 0x41, 0x42, 0x43}
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv, 0x0b0001d4)
	pkt := testIPPacket(100)
	body := encryptCBC(key[:], iv, pkt[20:])
	dgram := make([]byte, legacyUDPBodyOffset+len(body))
	copy(dgram[:8], legacyUDPMagic)
	binary.BigEndian.PutUint16(dgram[8:10], 0x011C)
	binary.BigEndian.PutUint16(dgram[10:12], 0x0010)
	copy(dgram[12:28], iv)
	copy(dgram[28:48], pkt[:20])
	copy(dgram[48:], body)

	go func() { _, _ = cli.Write(dgram) }()

	got, err := recvLegacyUDP(srv, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatalf("packet mismatch: got %d bytes, want %d", len(got), len(pkt))
	}
}
