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
	v1ControlKeepalive = 10 * time.Second
	v1DataKeepalive    = 15 * time.Second
)

type v1Session struct {
	cfg Config

	ctrlMu sync.Mutex
	ctrl   net.Conn
	crd    *FrameReader

	dataMu sync.Mutex
	data   net.Conn
	drd    *FrameReader

	udpMu     sync.Mutex
	udp       *net.UDPConn
	udpMode   int
	udpSID    uint32
	udpKey    [16]byte
	udpGCMKey []byte
	udpVIP    net.IP

	stateMu sync.Mutex
	token   []byte
	vip     net.IP
	routes  []*net.IPNet
	kicked  bool
	closed  bool

	start time.Time
	done  chan struct{}
	once  sync.Once
}

func newV1Session(cfg Config) (Session, error) {
	ctrl, err := dialTLS(cfg.Gateway, cfg.tls())
	if err != nil {
		return nil, fmt.Errorf("control tls: %w", err)
	}
	s := &v1Session{
		cfg:   cfg,
		ctrl:  ctrl,
		crd:   NewFrameReader(ctrl),
		start: time.Now(),
		done:  make(chan struct{}),
	}

	// FirstConnect（cmd 0x1D）用于版本/站点探测，失败不阻塞。
	if err := s.writeCtrl(buildFirstConnect(cfg)); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("firstconnect: %w", err)
	}
	if _, err := s.crd.Next(3 * time.Second); err != nil {
		cfg.logf("[v1] firstconnect reply: %v (continuing)", err)
	}

	// AUTH（cmd 1）获取会话 token。
	if err := s.writeCtrl(BuildV1(CmdV1Auth, buildAuthPayload(cfg))); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("auth send: %w", err)
	}
	fr, err := waitCmd(s.crd, CmdV1Auth, cfg.timeout())
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("auth reply: %w", err)
	}
	token, err := parseAuthResponse(fr.Payload)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	s.token = token
	cfg.logf("[v1] authenticated, token=%x...", token[:4])

	ncfg, err := s.requestVIP(s.crd)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	s.vip = ncfg.VIP
	s.routes = ncfg.Routes
	cfg.logf("[v1] vip=%s mode=%d routes=%d", ncfg.VIP, ncfg.Mode, len(ncfg.Routes))

	data, drd, err := s.openDataChannel()
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	s.data = data
	s.drd = drd

	if strings.EqualFold(cfg.Transport, "udp") || strings.EqualFold(cfg.Transport, "auto") {
		if err := s.startUDP(ncfg); err != nil {
			cfg.logf("[v1] UDP transport disabled: %v", err)
		}
	}

	go s.controlKeepalive()
	go s.dataKeepalive()
	go s.controlReader(s.crd)
	return s, nil
}

func (s *v1Session) requestVIP(rd *FrameReader) (*V1Config, error) {
	if err := s.writeCtrl(BuildV1(CmdV1REQVIP, s.token)); err != nil {
		return nil, fmt.Errorf("reqvip send: %w", err)
	}
	fr, err := waitCmd(rd, CmdV1REQVIP, s.cfg.timeout())
	if err != nil {
		return nil, fmt.Errorf("reqvip reply: %w", err)
	}
	return parseV1Config(fr.Payload)
}

func (s *v1Session) openDataChannel() (net.Conn, *FrameReader, error) {
	data, err := dialTLS(s.cfg.Gateway, s.cfg.tls())
	if err != nil {
		return nil, nil, fmt.Errorf("data tls: %w", err)
	}
	drd := NewFrameReader(data)
	data.SetWriteDeadline(time.Now().Add(s.cfg.timeout()))
	if _, err := data.Write(BuildV1(CmdV1DataConnect, s.token)); err != nil {
		data.Close()
		return nil, nil, fmt.Errorf("data connect send: %w", err)
	}
	if _, err := waitCmd(drd, CmdV1DataConnect, s.cfg.timeout()); err != nil {
		data.Close()
		return nil, nil, fmt.Errorf("data connect reply: %w", err)
	}
	return data, drd, nil
}

func waitCmd(rd *FrameReader, want int, timeout time.Duration) (Frame, error) {
	deadline := time.Now().Add(timeout)
	for {
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
		if fr.Cmd == CmdV1Kickout {
			return Frame{}, errors.New("kicked by gateway")
		}
	}
}

func (s *v1Session) writeCtrl(pkt []byte) error {
	s.ctrlMu.Lock()
	defer s.ctrlMu.Unlock()
	if s.closed || s.ctrl == nil {
		return errClosed
	}
	s.ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := s.ctrl.Write(pkt)
	return err
}

func (s *v1Session) controlKeepalive() {
	t := time.NewTicker(v1ControlKeepalive)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			elapsed := uint32(time.Since(s.start) / time.Millisecond)
			payload := make([]byte, 36)
			copy(payload, s.token)
			binary.BigEndian.PutUint32(payload[32:36], elapsed)
			if err := s.writeCtrl(BuildV1(CmdV1Keepalive, payload)); err != nil {
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
}

func (s *v1Session) dataKeepalive() {
	t := time.NewTicker(v1DataKeepalive)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.dataMu.Lock()
			data := s.data
			s.dataMu.Unlock()
			if data == nil {
				continue
			}
			data.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := data.Write(BuildV1(CmdV1DataKeepalive, nil)); err != nil {
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
}

func (s *v1Session) controlReader(rd *FrameReader) {
	for {
		fr, err := rd.Next(0)
		if err != nil {
			return
		}
		if fr.Cmd == CmdV1Kickout {
			s.stateMu.Lock()
			s.kicked = true
			s.stateMu.Unlock()
			// 关闭数据通道，让接收侧感知故障。
			s.dataMu.Lock()
			if s.data != nil {
				s.data.Close()
			}
			s.dataMu.Unlock()
			return
		}
	}
}

func buildFirstConnect(cfg Config) []byte {
	b := make([]byte, 340)
	binary.BigEndian.PutUint32(b[0:4], MagicLegacy1)
	binary.BigEndian.PutUint32(b[4:8], MagicV1)
	binary.BigEndian.PutUint32(b[8:12], 0)
	binary.BigEndian.PutUint16(b[12:14], 0x1D)
	binary.BigEndian.PutUint16(b[14:16], 0x0144)
	copy(b[80:336], []byte(cfg.domain()))
	binary.BigEndian.PutUint32(b[336:340], 1)
	return b
}

func tlv(typ uint16, val []byte) []byte {
	b := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(val)))
	copy(b[4:], val)
	return b
}

func buildAuthPayload(cfg Config) []byte {
	p := make([]byte, 260)
	copy(p[0:256], []byte(cfg.domain()))
	p[256] = 0 // 认证类型 0：用户名 + 口令
	p = append(p, tlv(1, append([]byte(escape(cfg.User)), 0))...)
	p = append(p, tlv(2, append([]byte(escape(cfg.Password)), 0))...)
	p = append(p, tlv(3, []byte(cfg.macString()))...)
	return p
}

func parseAuthResponse(p []byte) ([]byte, error) {
	if len(p) < 8 {
		return nil, fmt.Errorf("short auth reply (%d)", len(p))
	}
	if res := int32(binary.BigEndian.Uint32(p[0:4])); res != 0 {
		return nil, fmt.Errorf("auth rejected, code=%d", res)
	}
	i := 8
	for i+4 <= len(p) {
		t := binary.BigEndian.Uint16(p[i : i+2])
		l := int(binary.BigEndian.Uint16(p[i+2 : i+4]))
		if i+4+l > len(p) {
			break
		}
		if t == 3 && l >= 32 {
			return append([]byte(nil), p[i+4:i+4+32]...), nil
		}
		i += 4 + l
	}
	return nil, errors.New("session token not found")
}

// V1Config 是 REQVIP 的 TLV 回包。
type V1Config struct {
	VIP     net.IP
	Routes  []*net.IPNet
	Mode    int
	UDPPort int
	GCMKey  []byte
	RawTLVs map[uint16][]byte
}

func parseV1Config(p []byte) (*V1Config, error) {
	if len(p) < 1 {
		return nil, errors.New("empty config")
	}
	if p[0] != 0 {
		return nil, fmt.Errorf("reqvip result=%d", p[0])
	}
	c := &V1Config{RawTLVs: map[uint16][]byte{}}
	i := 4
	for i+4 <= len(p) {
		t := binary.BigEndian.Uint16(p[i : i+2])
		l := int(binary.BigEndian.Uint16(p[i+2 : i+4]))
		if i+4+l > len(p) {
			break
		}
		v := p[i+4 : i+4+l]
		c.RawTLVs[t] = append([]byte(nil), v...)
		switch t {
		case 1:
			if l >= 4 {
				c.VIP = net.IPv4(v[0], v[1], v[2], v[3]).To4()
			}
		case 5, 6:
			for k := 0; k+5 <= l; k += 5 {
				ipn := net.IPv4(v[k], v[k+1], v[k+2], v[k+3]).To4()
				c.Routes = append(c.Routes, &net.IPNet{IP: ipn, Mask: net.CIDRMask(int(v[k+4]), 32)})
			}
		case 7:
			if l >= 1 {
				c.Mode = int(v[0])
			}
		case 8:
			if l >= 32 {
				c.GCMKey = append([]byte(nil), v[:32]...)
			}
		case 9:
			if l >= 2 {
				c.UDPPort = int(binary.BigEndian.Uint16(v[0:2]))
			}
		}
		i += 4 + l
	}
	if c.VIP == nil {
		return nil, errors.New("config has no VIP")
	}
	return c, nil
}

func (s *v1Session) SendIP(pkt []byte) error {
	s.udpMu.Lock()
	uc, mode, sid, key, vip, gkey := s.udp, s.udpMode, s.udpSID, s.udpKey, s.udpVIP, s.udpGCMKey
	s.udpMu.Unlock()
	if uc != nil {
		switch mode {
		case v1ModeCHIV:
			return sendLegacyUDP(uc, sid, key, pkt)
		case v1ModeGCM:
			return sendV1GCM(uc, vip, gkey, pkt)
		}
	}
	payload := make([]byte, 8+len(pkt))
	copy(payload[8:], pkt)
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	if s.closed || s.data == nil {
		return errClosed
	}
	s.data.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := s.data.Write(BuildV1(CmdV1Data, payload))
	return err
}

func (s *v1Session) RecvIP() ([]byte, error) {
	s.udpMu.Lock()
	uc, mode, key, gkey := s.udp, s.udpMode, s.udpKey, s.udpGCMKey
	s.udpMu.Unlock()
	if uc != nil {
		switch mode {
		case v1ModeCHIV:
			return recvLegacyUDP(uc, key)
		case v1ModeGCM:
			return recvV1GCM(uc, gkey)
		}
	}
	s.dataMu.Lock()
	rd := s.drd
	s.dataMu.Unlock()
	if rd == nil {
		return nil, errClosed
	}
	for {
		fr, err := rd.Next(0)
		if err != nil {
			return nil, err
		}
		switch fr.Cmd {
		case CmdV1Data:
			if len(fr.Payload) < 8 {
				continue
			}
			return fr.Payload[8:], nil
		case CmdV1DataKeepalive:
			continue
		case CmdV1Kickout:
			return nil, errors.New("kicked by gateway")
		}
	}
}

func (s *v1Session) VIP() net.IP {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.vip
}

func (s *v1Session) Network() NetworkConfig {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return NetworkConfig{VIP: s.vip, Routes: s.routes}
}

func (s *v1Session) Close() error {
	s.stateMu.Lock()
	already := s.closed
	s.closed = true
	s.stateMu.Unlock()
	if already {
		return nil
	}
	s.once.Do(func() { close(s.done) })
	s.ctrlMu.Lock()
	if s.ctrl != nil {
		s.ctrl.Close()
	}
	s.ctrlMu.Unlock()
	s.dataMu.Lock()
	if s.data != nil {
		s.data.Close()
	}
	s.dataMu.Unlock()
	s.udpMu.Lock()
	if s.udp != nil {
		s.udp.Close()
	}
	s.udpMu.Unlock()
	return nil
}

// Drop 关闭控制与数据 socket 但不标记会话结束，用于模拟网络故障。
func (s *v1Session) Drop() {
	s.ctrlMu.Lock()
	if s.ctrl != nil {
		s.ctrl.Close()
	}
	s.ctrlMu.Unlock()
	s.dataMu.Lock()
	if s.data != nil {
		s.data.Close()
	}
	s.dataMu.Unlock()
}

// Reconnect 保留 token，新建控制 TLS 并重发 REQVIP 校验 VIP，随后重建数据通道。
func (s *v1Session) Reconnect() error {
	s.stateMu.Lock()
	if s.closed {
		s.stateMu.Unlock()
		return errClosed
	}
	if s.kicked {
		s.stateMu.Unlock()
		return errors.New("kicked by gateway")
	}
	oldVIP := s.vip
	s.stateMu.Unlock()

	s.Drop()

	ctrl, err := dialTLS(s.cfg.Gateway, s.cfg.tls())
	if err != nil {
		return fmt.Errorf("reconnect control tls: %w", err)
	}
	crd := NewFrameReader(ctrl)
	s.ctrlMu.Lock()
	s.ctrl = ctrl
	s.crd = crd
	s.ctrlMu.Unlock()
	s.cfg.logf("[v1] reconnecting on new TLS channels (token kept)")

	// 部分网关仍会响应 FirstConnect，失败可忽略。
	ctrl.SetWriteDeadline(time.Now().Add(s.cfg.timeout()))
	if _, err := ctrl.Write(buildFirstConnect(s.cfg)); err == nil {
		_, _ = crd.Next(2 * time.Second)
	}

	ncfg, err := s.requestVIP(crd)
	if err != nil {
		ctrl.Close()
		return fmt.Errorf("reconnect reqvip: %w", err)
	}
	if oldVIP != nil && !oldVIP.Equal(ncfg.VIP) {
		ctrl.Close()
		return fmt.Errorf("reconnect: vip changed %s -> %s", oldVIP, ncfg.VIP)
	}

	data, drd, err := s.openDataChannel()
	if err != nil {
		ctrl.Close()
		return fmt.Errorf("reconnect data channel: %w", err)
	}
	s.dataMu.Lock()
	s.data = data
	s.drd = drd
	s.dataMu.Unlock()
	s.stateMu.Lock()
	s.vip = ncfg.VIP
	s.routes = ncfg.Routes
	s.stateMu.Unlock()

	s.udpMu.Lock()
	oldUDP := s.udp
	s.udpMu.Unlock()
	if oldUDP != nil {
		oldUDP.Close()
		s.udpMu.Lock()
		s.udp = nil
		s.udpMu.Unlock()
		if err := s.startUDP(ncfg); err != nil {
			s.cfg.logf("[v1] UDP renegotiation failed, falling back to TLS: %v", err)
		}
	}

	go s.controlReader(crd)
	s.cfg.logf("[v1] reconnect ok, vip=%s", ncfg.VIP)
	return nil
}
