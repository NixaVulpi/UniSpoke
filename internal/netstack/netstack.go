// Package netstack 在隧道之上运行 gVisor 用户态 TCP/IP 栈。
package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"unispoke/internal/packet"
	"unispoke/internal/tunnel"
)

const nicID tcpip.NICID = 1

type LookupFunc func(host string) ([]net.IP, error)

type Stack struct {
	st  *stack.Stack
	ep  *channel.Endpoint
	mgr *tunnel.Manager
	vip net.IP
	mtu int

	logf   func(string, ...any)
	lookup LookupFunc

	closeOnce sync.Once
}

func NewStack(mgr *tunnel.Manager, vip net.IP, mtu int, logf func(string, ...any)) (*Stack, error) {
	v4 := vip.To4()
	if v4 == nil {
		return nil, errors.New("netstack: IPv4 VIP required")
	}
	if mtu <= 0 {
		mtu = 1240
	}

	ep := channel.New(1024, uint32(mtu), "")
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := st.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("netstack: create NIC: %s", err)
	}
	addr := tcpip.AddrFrom4([4]byte{v4[0], v4[1], v4[2], v4[3]})
	if err := st.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 32},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("netstack: add address: %s", err)
	}
	st.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
		Min: 4096, Default: 1 << 20, Max: 4 << 20,
	})
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min: 4096, Default: 1 << 20, Max: 4 << 20,
	})

	return &Stack{
		st:     st,
		ep:     ep,
		mgr:    mgr,
		vip:    v4,
		mtu:    mtu,
		logf:   logf,
		lookup: net.LookupIP,
	}, nil
}

func (s *Stack) SetLookup(f LookupFunc) {
	if f != nil {
		s.lookup = f
	}
}

func (s *Stack) LookupIP(host string) ([]net.IP, error) { return s.lookup(host) }

func (s *Stack) VIP() net.IP { return s.vip }
func (s *Stack) MTU() int    { return s.mtu }

func (s *Stack) Run() {
	go s.outbound()
	for {
		pkt, err := s.mgr.RecvIP()
		if err != nil {
			// 会话重连期间会出现临时错误，保持循环即可。
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.inject(pkt)
	}
}

func (s *Stack) inject(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	})
	s.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
	pb.DecRef()
}

func (s *Stack) outbound() {
	for {
		pkt := s.ep.ReadContext(context.Background())
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		out := packet.Pad(view.AsSlice())
		if len(out) > 0 {
			if err := s.mgr.SendIP(out); err != nil && s.logf != nil {
				s.logf("[netstack] send: %v", err)
			}
		}
		view.Release()
		pkt.DecRef()
	}
}

func (s *Stack) Dial(addr string) (net.Conn, error) {
	fa, err := s.fullAddress(addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return gonet.DialContextTCP(ctx, s.st, fa, ipv4.ProtocolNumber)
}

func (s *Stack) ListenPacket() (net.PacketConn, error) {
	v4 := s.vip.To4()
	laddr := &tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4([4]byte{v4[0], v4[1], v4[2], v4[3]}),
		Port: 0,
	}
	return gonet.DialUDP(s.st, laddr, nil, ipv4.ProtocolNumber)
}

func (s *Stack) fullAddress(addr string) (tcpip.FullAddress, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return tcpip.FullAddress{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return tcpip.FullAddress{}, fmt.Errorf("bad port %q", portStr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := s.lookup(host)
		if err != nil {
			return tcpip.FullAddress{}, err
		}
		for _, cand := range ips {
			if v4 := cand.To4(); v4 != nil {
				ip = v4
				break
			}
		}
	}
	v4 := ip.To4()
	if v4 == nil {
		return tcpip.FullAddress{}, fmt.Errorf("no IPv4 address for %s", host)
	}
	return tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4([4]byte{v4[0], v4[1], v4[2], v4[3]}),
		Port: uint16(port),
	}, nil
}

func (s *Stack) Close() {
	s.closeOnce.Do(func() {
		s.st.Close()
		s.st.Wait()
	})
}
