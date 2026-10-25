package proxy

import (
	"net"
	"testing"

	"github.com/go-gost/gosocks5"
)

func TestUDPDatagramRoundTrip(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 5353}
	payload := []byte("dns-payload")

	out, err := encodeUDPDatagram(src, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	hdr, got, ok := parseUDPDatagram(out)
	if !ok {
		t.Fatalf("parse failed")
	}
	if hdr.Addr.Host != "10.1.2.3" || hdr.Addr.Port != 5353 {
		t.Fatalf("addr = %s:%d", hdr.Addr.Host, hdr.Addr.Port)
	}
	if hdr.Frag != 0 {
		t.Fatalf("frag = %d", hdr.Frag)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestWithDefaultPort(t *testing.T) {
	cases := map[string]string{
		"example.com":      "example.com:80",
		"example.com:8080": "example.com:8080",
		"[::1]":            "[::1]:80",
		"[::1]:443":        "[::1]:443",
		"10.0.0.1":         "10.0.0.1:80",
	}
	for in, want := range cases {
		if got := withDefaultPort(in, "80"); got != want {
			t.Errorf("withDefaultPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUDPDatagramDomain(t *testing.T) {
	// RSV 2 字节、FRAG 1 字节、ATYP=3、域名长 11、端口 53，后接数据。
	pkt := []byte{
		0, 0, 0, 3, 11,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0, 53,
		'x',
	}
	hdr, data, ok := parseUDPDatagram(pkt)
	if !ok {
		t.Fatalf("parse failed")
	}
	if hdr.Addr.Type != gosocks5.AddrDomain || hdr.Addr.Host != "example.com" || hdr.Addr.Port != 53 {
		t.Fatalf("addr = %+v", hdr.Addr)
	}
	if string(data) != "x" {
		t.Fatalf("data = %q", data)
	}
}
