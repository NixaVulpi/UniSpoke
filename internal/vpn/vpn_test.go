package vpn

import (
	"net"
	"testing"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestSameRoutes(t *testing.T) {
	a := []*net.IPNet{mustCIDR("172.22.1.0/24"), mustCIDR("10.0.0.0/8")}
	b := []*net.IPNet{mustCIDR("10.0.0.0/8"), mustCIDR("172.22.1.0/24")}
	if !sameRoutes(a, b) {
		t.Fatalf("expected same set")
	}
	c := []*net.IPNet{mustCIDR("172.22.1.0/24")}
	if sameRoutes(a, c) {
		t.Fatalf("expected different sets")
	}
}

func TestSameDNS(t *testing.T) {
	a := []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}
	b := []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}
	if !sameDNS(a, b) {
		t.Fatalf("expected same dns")
	}
	c := []net.IP{net.ParseIP("10.0.0.1")}
	if sameDNS(a, c) {
		t.Fatalf("expected different dns")
	}
}
