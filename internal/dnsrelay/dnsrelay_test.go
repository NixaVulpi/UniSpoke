package dnsrelay

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startFakeDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dns.Msg
			if err := q.Unpack(buf[:n]); err != nil || len(q.Question) == 0 {
				continue
			}
			r := new(dns.Msg)
			r.SetReply(&q)
			r.Answer = append(r.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(1, 2, 3, 4),
			})
			out, _ := r.Pack()
			_, _ = pc.WriteTo(out, src)
		}
	}()
	return pc.LocalAddr().String()
}

func TestLookupIPViaPacketConn(t *testing.T) {
	server := startFakeDNS(t)
	r := NewResolver(func() (net.PacketConn, error) {
		return net.ListenPacket("udp", "127.0.0.1:0")
	}, nil, 2*time.Second, nil)
	r.Servers = []string{server}

	ips, err := r.LookupIP("example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("ips = %v", ips)
	}
}

func TestLookupIPLiteral(t *testing.T) {
	r := NewResolver(nil, nil, time.Second, nil)
	ips, err := r.LookupIP("10.1.2.3")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.1.2.3")) {
		t.Fatalf("ips = %v, err = %v", ips, err)
	}
}
