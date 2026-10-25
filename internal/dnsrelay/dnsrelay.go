// Package dnsrelay 通过隧道转发 DNS 查询。
package dnsrelay

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"

	"unispoke/internal/proxy"
)

type Resolver struct {
	Servers   []string // host:53
	NewPacket proxy.PacketFunc
	Timeout   time.Duration
	Logf      func(string, ...any)
}

func NewResolver(newPacket proxy.PacketFunc, servers []net.IP, timeout time.Duration, logf func(string, ...any)) *Resolver {
	r := &Resolver{NewPacket: newPacket, Timeout: timeout, Logf: logf}
	for _, ip := range servers {
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		r.Servers = append(r.Servers, net.JoinHostPort(ip.String(), "53"))
	}
	if r.Timeout <= 0 {
		r.Timeout = 5 * time.Second
	}
	return r
}

// LookupIP 先走隧道 DNS，失败后回退系统解析。
func (r *Resolver) LookupIP(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if len(r.Servers) > 0 {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
		msg.RecursionDesired = true

		if reply, err := r.exchange(msg); err == nil {
			var ips []net.IP
			for _, rr := range reply.Answer {
				if a, ok := rr.(*dns.A); ok {
					ips = append(ips, append(net.IP(nil), a.A...))
				}
			}
			if len(ips) > 0 {
				return ips, nil
			}
		} else if r.Logf != nil {
			r.Logf("[dns] %s via tunnel: %v", host, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupIP(ctx, "ip4", host)
}

func (r *Resolver) exchange(msg *dns.Msg) (*dns.Msg, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	reply, err := r.exchangeRaw(packed)
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(reply); err != nil {
		return nil, err
	}
	if out.Id != msg.Id {
		return nil, errors.New("dns: response id mismatch")
	}
	return out, nil
}

func (r *Resolver) exchangeRaw(query []byte) ([]byte, error) {
	if r.NewPacket == nil {
		return nil, errors.New("dns: no packet endpoint")
	}
	var lastErr error
	for _, server := range r.Servers {
		pc, err := r.NewPacket()
		if err != nil {
			lastErr = err
			continue
		}
		reply, err := exchangePacket(pc, server, query, r.Timeout)
		_ = pc.Close()
		if err == nil {
			return reply, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("dns: no servers configured")
	}
	return nil, lastErr
}

func exchangePacket(pc net.PacketConn, server string, query []byte, timeout time.Duration) ([]byte, error) {
	dst, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	if err := pc.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := pc.WriteTo(query, dst); err != nil {
		return nil, err
	}
	buf := make([]byte, 8192)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		if n >= 12 {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// Server 是经隧道转发的本地 UDP DNS 端口。
type Server struct {
	Resolver *Resolver
	Addr     string
	Logf     func(string, ...any)
}

func (s *Server) Serve() error {
	addr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if s.Logf != nil {
		s.Logf("[dns] listening on %s (servers %v)", conn.LocalAddr(), s.Resolver.Servers)
	}
	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		query := append([]byte(nil), buf[:n]...)
		go func(query []byte, src *net.UDPAddr) {
			reply, err := s.Resolver.exchangeRaw(query)
			if err != nil {
				if s.Logf != nil {
					s.Logf("[dns] %s: %v", src, err)
				}
				return
			}
			_, _ = conn.WriteToUDP(reply, src)
		}(query, src)
	}
}

func (r *Resolver) ServersString() string {
	out := ""
	for i, s := range r.Servers {
		if i > 0 {
			out += ","
		}
		host, port, err := net.SplitHostPort(s)
		if err == nil && port == "53" {
			out += host
			continue
		}
		out += s
	}
	if out == "" {
		return "-"
	}
	return out
}
