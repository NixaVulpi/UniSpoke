package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	legacyAuthMagic = 0xF0F0F0F0
	legacyKeepalive = 10 * time.Second
)

type legacySession struct {
	cfg Config

	mu     sync.Mutex // 保护 conn、rd、vip、网络参数与 closed
	conn   net.Conn
	rd     *FrameReader
	uid    uint32
	vip    net.IP
	mask   net.IPMask
	dns    []net.IP
	routes []*net.IPNet
	closed bool
}

func newLegacySession(cfg Config) (Session, error) {
	uid, err := legacyAuth(cfg)
	if err != nil {
		return nil, err
	}
	cfg.logf("[legacy] authenticated, uid=0x%08x", uid)

	conn, err := dialTLS(cfg.Gateway, cfg.tls())
	if err != nil {
		return nil, fmt.Errorf("tunnel tls: %w", err)
	}
	s := &legacySession{cfg: cfg, conn: conn, rd: NewFrameReader(conn), uid: uid}

	// ACL 请求固定携带 4 字节 0。
	if _, err := s.request(CmdLegacyACL, []byte{0, 0, 0, 0}, CmdLegacyACL, cfg.timeout()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("acl: %w", err)
	}
	fr, err := s.request(CmdLegacyREQVIP, nil, CmdLegacyREQVIP, cfg.timeout())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reqvip: %w", err)
	}
	ncfg, err := parseLegacyConfig(fr.Payload)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reqvip parse: %w", err)
	}
	s.vip = ncfg.VIP
	s.mask = ncfg.Mask
	s.dns = ncfg.DNS
	s.routes = ncfg.Routes
	cfg.logf("[legacy] vip=%s mask=%s routes=%d dns=%v", ncfg.VIP, net.IP(ncfg.Mask).String(), len(ncfg.Routes), ncfg.DNS)

	go s.keepaliveLoop()
	return s, nil
}

func legacyAuth(cfg Config) (uint32, error) {
	conn, err := dialTLS(cfg.Gateway, cfg.tls())
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	mac := strings.ReplaceAll(cfg.macString(), "-", "")
	path := fmt.Sprintf("/netextension/netextensionlogin.html?SelectLanguage=0&UserName=%s&Password=%s&MacAddress=%s&SVN_Seco_AaA=1",
		escape(cfg.User), escape(cfg.Password), mac)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/msword, application/vnd.ms-excel, application/vnd.ms-powerpoint, */*\r\n"+
		"Accept-Language: zh-cn\r\n"+
		"Accept-Encoding: gzip, deflate\r\n"+
		"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; NT 5.1; SV1; .NET CLR 2.0.50727)\r\n"+
		"OS=Windows64\r\n"+
		"Host: %s\r\n\r\n", path, cfg.Gateway)
	conn.SetWriteDeadline(time.Now().Add(cfg.timeout()))
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, err
	}

	var buf []byte
	tmp := make([]byte, 8192)
	conn.SetReadDeadline(time.Now().Add(cfg.timeout()))
	for len(buf) < 65536 {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break // 网关返回后关闭连接
		}
	}
	if len(buf) < 8 {
		return 0, fmt.Errorf("short auth reply (%d bytes)", len(buf))
	}
	if binary.BigEndian.Uint32(buf[0:4]) != legacyAuthMagic {
		return 0, fmt.Errorf("unexpected auth reply: %x", buf[:min(16, len(buf))])
	}
	res := int32(binary.BigEndian.Uint32(buf[4:8]))
	if res < 0 {
		return 0, fmt.Errorf("auth rejected, code=%d", res)
	}
	if len(buf) < 48 {
		return 0, fmt.Errorf("short auth success (%d bytes)", len(buf))
	}
	return binary.BigEndian.Uint32(buf[44:48]), nil
}

func (s *legacySession) request(cmd uint16, payload []byte, want int, timeout time.Duration) (Frame, error) {
	if err := s.write(cmd, payload); err != nil {
		return Frame{}, err
	}
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		rd := s.rd
		s.mu.Unlock()
		if rd == nil {
			return Frame{}, errors.New("tunnel: no connection")
		}
		left := time.Until(deadline)
		if left <= 0 {
			return Frame{}, errTimeout
		}
		fr, err := rd.Next(left)
		if err != nil {
			return Frame{}, err
		}
		if fr.Cmd == want {
			return fr, nil
		}
		if fr.Cmd == CmdLegacyKickout {
			return Frame{}, errors.New("kicked by gateway")
		}
	}
}

func (s *legacySession) write(cmd uint16, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.conn == nil {
		return errClosed
	}
	s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := s.conn.Write(BuildLegacy(cmd, payload, s.uid))
	return err
}

func (s *legacySession) SendIP(pkt []byte) error { return s.write(CmdLegacyData, pkt) }

func (s *legacySession) RecvIP() ([]byte, error) {
	s.mu.Lock()
	rd := s.rd
	s.mu.Unlock()
	if rd == nil {
		return nil, errClosed
	}
	for {
		fr, err := rd.Next(0)
		if err != nil {
			return nil, err
		}
		switch fr.Cmd {
		case CmdLegacyData:
			return stripVnicPrefix(fr.Payload), nil
		case CmdLegacyKeepalive:
			continue
		case CmdLegacyKickout:
			return nil, errors.New("kicked by gateway")
		}
	}
}

func (s *legacySession) VIP() net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vip
}

func (s *legacySession) Network() NetworkConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return NetworkConfig{VIP: s.vip, Mask: s.mask, DNS: s.dns, Routes: s.routes}
}

func (s *legacySession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.conn != nil {
		s.conn.Close()
	}
	return nil
}

// Drop 关闭当前 socket 但不标记会话结束，用于模拟网络故障。
func (s *legacySession) Drop() {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

// Reconnect 复用已认证的 UserID，只重建 TLS 通道并重发 REQVIP；VIP 不一致视为会话失效。
func (s *legacySession) Reconnect() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errClosed
	}
	old := s.conn
	oldVIP := s.vip
	s.mu.Unlock()
	if old != nil {
		old.Close()
	}

	conn, err := dialTLS(s.cfg.Gateway, s.cfg.tls())
	if err != nil {
		return fmt.Errorf("reconnect tls: %w", err)
	}
	s.mu.Lock()
	s.conn = conn
	s.rd = NewFrameReader(conn)
	s.mu.Unlock()
	s.cfg.logf("[legacy] reconnecting on a new TLS channel (session uid=0x%08x kept)", s.uid)

	fr, err := s.request(CmdLegacyREQVIP, nil, CmdLegacyREQVIP, 5*time.Second)
	if err != nil {
		// 部分网关要求新通道先发 ACL。
		if _, err2 := s.request(CmdLegacyACL, []byte{0, 0, 0, 0}, CmdLegacyACL, 5*time.Second); err2 == nil {
			fr, err = s.request(CmdLegacyREQVIP, nil, CmdLegacyREQVIP, s.cfg.timeout())
		}
	}
	if err != nil {
		conn.Close()
		return fmt.Errorf("reconnect reqvip: %w", err)
	}
	ncfg, err := parseLegacyConfig(fr.Payload)
	if err != nil {
		conn.Close()
		return fmt.Errorf("reconnect parse: %w", err)
	}
	if oldVIP != nil && !oldVIP.Equal(ncfg.VIP) {
		conn.Close()
		return fmt.Errorf("reconnect: vip changed %s -> %s", oldVIP, ncfg.VIP)
	}
	s.mu.Lock()
	s.vip = ncfg.VIP
	s.mask = ncfg.Mask
	s.dns = ncfg.DNS
	s.routes = ncfg.Routes
	s.mu.Unlock()
	s.cfg.logf("[legacy] reconnect ok, vip=%s", ncfg.VIP)
	return nil
}

func (s *legacySession) keepaliveLoop() {
	t := time.NewTicker(legacyKeepalive)
	defer t.Stop()
	for range t.C {
		if err := s.write(CmdLegacyKeepalive, nil); err != nil {
			// 不在这里关闭会话：接收侧会发现故障并由 Manager 重连。
			time.Sleep(time.Second)
		}
	}
}

func stripVnicPrefix(p []byte) []byte {
	if len(p) >= 20 && p[0]>>4 == 4 {
		return p
	}
	if len(p) >= 22 && p[2]>>4 == 4 {
		return p[2:]
	}
	return p
}

// LegacyConfig 是 REQVIP 的旧格式固定布局回包。
type LegacyConfig struct {
	VIP       net.IP
	Mask      net.IPMask
	IPAlloc   uint32
	RouteType uint32
	DNS       []net.IP
	Routes    []*net.IPNet
}

func parseLegacyConfig(p []byte) (*LegacyConfig, error) {
	if len(p) < 8 {
		return nil, fmt.Errorf("config too short (%d)", len(p))
	}
	c := &LegacyConfig{
		VIP:  net.IPv4(p[0], p[1], p[2], p[3]).To4(),
		Mask: net.IPv4Mask(p[4], p[5], p[6], p[7]),
	}
	if len(p) >= 24 {
		c.IPAlloc = binary.BigEndian.Uint32(p[8:12])
		c.RouteType = binary.BigEndian.Uint32(p[20:24])
	}
	if len(p) >= 172 {
		for i := 0; i < 3; i++ {
			a := p[160+4*i : 164+4*i]
			if a[0]|a[1]|a[2]|a[3] != 0 {
				c.DNS = append(c.DNS, net.IPv4(a[0], a[1], a[2], a[3]).To4())
			}
		}
	}
	if len(p) >= 188 {
		n := int(binary.BigEndian.Uint32(p[184:188]))
		if n > 0 && n <= 0x400 && len(p) >= 188+12*n {
			for i := 0; i < n; i++ {
				e := p[188+12*i : 200+12*i]
				ipn := net.IPv4(e[0], e[1], e[2], e[3]).To4()
				m := net.IPv4Mask(e[4], e[5], e[6], e[7])
				c.Routes = append(c.Routes, &net.IPNet{IP: ipn, Mask: m})
			}
		}
	}
	return c, nil
}
