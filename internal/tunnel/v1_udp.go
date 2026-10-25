package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// V1 UDP 数据面：模式 3 复用 legacy，模式 4 为 52 字节前缀 + AES-256-GCM 密文。
const (
	v1ModeCHIV = 3
	v1ModeGCM  = 4
	v1ProbeCmd = 0x07
	v1GCMHdr   = 52
	v1GCMNonce = 12
	v1GCMTag   = 16
)

func (s *v1Session) startUDP(vc *V1Config) error {
	mode := vc.Mode
	if mode != v1ModeCHIV && mode != v1ModeGCM {
		if len(vc.GCMKey) == 32 {
			mode = v1ModeGCM
		} else {
			mode = v1ModeCHIV
		}
	}

	sid := binary.BigEndian.Uint32(s.token[:4])
	var key16 [16]byte
	haveKey := false
	keyPayload := []byte(nil)
	if mode == v1ModeCHIV {
		keyPayload = []byte{0, 0, 0, 4}
	}
	if fr, err := s.requestLegacy(CmdLegacyUDPKey, keyPayload, CmdLegacyUDPKey, s.cfg.timeout()); err == nil && len(fr.Payload) >= 20 {
		m := int(binary.BigEndian.Uint32(fr.Payload[:4]))
		copy(key16[:], fr.Payload[4:20])
		haveKey = true
		if m == v1ModeCHIV || m == v1ModeGCM {
			mode = m
		}
		s.cfg.logf("[v1] UDP key reply mode=%d", m)
	}

	port := vc.UDPPort
	if fr, err := s.requestLegacy(CmdLegacyUDPPort, make([]byte, 4), CmdLegacyUDPPort, s.cfg.timeout()); err == nil && len(fr.Payload) >= 2 {
		port = int(binary.BigEndian.Uint16(fr.Payload[:2]))
	}
	if port == 0 {
		port = legacyUDPPort
	}
	if mode != v1ModeCHIV && mode != v1ModeGCM {
		return fmt.Errorf("v1 udp: unsupported mode %d", mode)
	}
	if mode == v1ModeCHIV && !haveKey {
		return errors.New("v1 udp: mode 3 requires the cmd 0x0D key")
	}
	if mode == v1ModeGCM && len(vc.GCMKey) != 32 {
		return errors.New("v1 udp: mode 4 requires a 32-byte GCM key")
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.cfg.host(), fmt.Sprint(port)))
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("v1 udp dial: %w", err)
	}
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)

	if mode == v1ModeGCM {
		probe := buildV1Probe(vc.VIP, vc.GCMKey)
		if _, err := conn.Write(probe); err != nil {
			conn.Close()
			return err
		}
	}

	// 切换到 UDP 数据面：token(32) + 模式字节 2。
	sw := BuildV1(CmdV1TunnelSwitch, append(append([]byte(nil), s.token...), 2))
	if err := s.writeCtrl(sw); err != nil {
		conn.Close()
		return fmt.Errorf("v1 udp switch: %w", err)
	}

	s.udpMu.Lock()
	s.udp = conn
	s.udpMode = mode
	s.udpSID = sid
	s.udpKey = key16
	s.udpGCMKey = append([]byte(nil), vc.GCMKey...)
	s.udpVIP = append(net.IP(nil), vc.VIP...)
	s.udpMu.Unlock()
	s.cfg.logf("[v1] UDP mode=%d -> %s", mode, addr)
	return nil
}

func (s *v1Session) requestLegacy(cmd uint16, payload []byte, want int, timeout time.Duration) (Frame, error) {
	if err := s.writeCtrl(BuildLegacy(cmd, payload, binary.BigEndian.Uint32(s.token[:4]))); err != nil {
		return Frame{}, err
	}
	deadline := time.Now().Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return Frame{}, errTimeout
		}
		fr, err := s.crd.Next(left)
		if err != nil {
			return Frame{}, err
		}
		if fr.Cmd == want {
			return fr, nil
		}
		if fr.Cmd == CmdV1Kickout || fr.Cmd == CmdLegacyKickout {
			return Frame{}, errors.New("kicked by gateway")
		}
	}
}

func buildV1Probe(vip net.IP, key []byte) []byte {
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	hdr := BuildV1(v1ProbeCmd, nil)
	ct, tag := gcmSeal(key, iv[:v1GCMNonce], hdr)
	buf := make([]byte, v1GCMHdr+len(ct))
	buf[0], buf[1] = 1, 2
	copy(buf[4:8], vip.To4())
	copy(buf[20:36], iv)
	copy(buf[36:52], tag)
	copy(buf[52:], ct)
	return buf
}

func sendV1GCM(conn *net.UDPConn, vip net.IP, key, pkt []byte) error {
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return err
	}
	ct, tag := gcmSeal(key, iv[:v1GCMNonce], BuildV1(CmdV1Data, pkt))
	buf := make([]byte, v1GCMHdr+len(ct))
	buf[0], buf[1] = 1, 2
	copy(buf[4:8], vip.To4())
	copy(buf[20:36], iv)
	copy(buf[36:52], tag)
	copy(buf[52:], ct)
	_, err := conn.Write(buf)
	return err
}

func recvV1GCM(conn *net.UDPConn, key []byte) ([]byte, error) {
	buf := make([]byte, v1GCMHdr+65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < v1GCMHdr+v1GCMTag+8 {
			continue
		}
		if buf[0] != 1 || buf[1] != 2 {
			continue
		}
		plain, err := gcmOpen(key, buf[20:20+v1GCMNonce], buf[v1GCMHdr:n], buf[36:52])
		if err != nil || len(plain) < 8 {
			continue
		}
		if binary.BigEndian.Uint32(plain[0:4]) != MagicV1 || plain[5] != CmdV1Data {
			continue
		}
		l := int(binary.BigEndian.Uint16(plain[6:8]))
		if 8+l > len(plain) {
			continue
		}
		out := make([]byte, l)
		copy(out, plain[8:8+l])
		return out, nil
	}
}

func gcmSeal(key, nonce, plain []byte) (ct, tag []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil
	}
	out := g.Seal(nil, nonce, plain, nil)
	return out[:len(out)-v1GCMTag], out[len(out)-v1GCMTag:]
}

func gcmOpen(key, nonce, ct, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, append(append([]byte(nil), ct...), tag...), nil)
}
