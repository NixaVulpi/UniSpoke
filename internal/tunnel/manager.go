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

type Session interface {
	SendIP(pkt []byte) error
	RecvIP() ([]byte, error)
	VIP() net.IP
	Network() NetworkConfig
	Close() error
}

// Reconnector 表示可在新 TLS 通道上复用已认证状态的会话。
type Reconnector interface {
	Reconnect() error
}

// Manager 管理会话，失败时重建。
type Manager struct {
	cfg     Config
	mu      sync.Mutex
	sess    Session
	lastTry time.Time
}

func NewManager(cfg Config) *Manager { return &Manager{cfg: cfg} }

func (m *Manager) Ensure() (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess != nil {
		return m.sess, nil
	}
	s, err := openSession(m.cfg)
	if err != nil {
		return nil, err
	}
	m.sess = s
	return s, nil
}

// SendIP 发送 IP 报文，连接故障由接收侧发现。
func (m *Manager) SendIP(pkt []byte) error {
	s, err := m.Ensure()
	if err != nil {
		return err
	}
	return s.SendIP(pkt)
}

func (m *Manager) RecvIP() ([]byte, error) {
	s, err := m.Ensure()
	if err != nil {
		return nil, err
	}
	pkt, err := s.RecvIP()
	if err != nil {
		m.recover(s)
		return nil, err
	}
	return pkt, nil
}

// recover 先尝试复用已认证会话建立新通道；失败则丢弃会话，下次 Ensure 完整登录。
func (m *Manager) recover(s Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess != s {
		return
	}
	if time.Since(m.lastTry) < 2*time.Second {
		return
	}
	m.lastTry = time.Now()
	if r, ok := s.(Reconnector); ok {
		if err := r.Reconnect(); err == nil {
			return
		} else {
			m.cfg.logf("[reconnect] session reuse failed: %v", err)
		}
	}
	s.Close()
	m.sess = nil
}

func (m *Manager) VIP() net.IP {
	s, err := m.Ensure()
	if err != nil {
		return nil
	}
	return s.VIP()
}

func (m *Manager) Network() NetworkConfig {
	s, err := m.Ensure()
	if err != nil {
		return NetworkConfig{}
	}
	return s.Network()
}

// NetworkSnapshot 返回网络参数且不触发登录。
func (m *Manager) NetworkSnapshot() NetworkConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess == nil {
		return NetworkConfig{}
	}
	return m.sess.Network()
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess != nil {
		m.sess.Close()
		m.sess = nil
	}
}

func openSession(cfg Config) (Session, error) {
	mode := strings.ToLower(cfg.Mode)
	switch mode {
	case "", "auto":
		isV1, err := probeV1(cfg)
		if err != nil {
			cfg.logf("[probe] %v", err)
		}
		if isV1 {
			cfg.logf("[mode] detected V1 gateway")
			return newV1Session(cfg)
		}
		cfg.logf("[mode] detected legacy gateway")
		return newLegacySession(cfg)
	case "legacy":
		return newLegacySession(cfg)
	case "v1":
		return newV1Session(cfg)
	default:
		return nil, fmt.Errorf("unknown mode %q", cfg.Mode)
	}
}

// probeV1 发送 FirstConnect，根据首包魔数判断网关版本。
func probeV1(cfg Config) (bool, error) {
	conn, err := dialTLS(cfg.Gateway, cfg.tls())
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(cfg.timeout()))
	if _, err := conn.Write(buildFirstConnect(cfg)); err != nil {
		return false, err
	}
	conn.SetReadDeadline(time.Now().Add(cfg.timeout()))
	var hdr [4]byte
	if _, err := readFull(conn, hdr[:]); err != nil {
		return false, err
	}
	return binary.BigEndian.Uint32(hdr[:]) == MagicV1, nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// escape 仅转义 %、&、+ 三个字符。
func escape(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "&", "%26")
	s = strings.ReplaceAll(s, "+", "%2B")
	return s
}

var errClosed = errors.New("tunnel: session closed")
