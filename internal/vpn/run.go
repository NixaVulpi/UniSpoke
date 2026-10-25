package vpn

import (
	"fmt"
	"net"
	"strings"
)

func run(logf func(string, ...any), name string, args ...string) error {
	if logf != nil {
		logf("[vpn] %s %s", name, strings.Join(args, " "))
	}
	out, err := command(name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s %s: %v (%s)", name, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return nil
}

func maskDotted(m net.IPMask) string {
	if len(m) == net.IPv4len {
		return net.IP(m).String()
	}
	return "255.255.255.0"
}

func prefixLen(m net.IPMask) int {
	ones, bits := m.Size()
	if bits != 32 || ones == 0 {
		return 24
	}
	return ones
}

func isDefaultRoute(r *net.IPNet) bool {
	if r == nil {
		return false
	}
	ones, bits := r.Mask.Size()
	return bits == 32 && ones == 0
}

func hasDefaultRoute(routes []*net.IPNet) bool {
	for _, r := range routes {
		if isDefaultRoute(r) {
			return true
		}
	}
	return false
}

func gatewayIP(gateway string) net.IP {
	host, _, err := net.SplitHostPort(gateway)
	if err != nil {
		host = gateway
	}
	return net.ParseIP(host)
}
