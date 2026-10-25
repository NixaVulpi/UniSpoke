package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
)

// Legacy UDP 数据面：28 字节头 + 明文 IPv4 头 + AES-128-CBC 密文。
const (
	legacyUDPHeaderLen   = 28
	legacyUDPIPHeaderLen = 20
	legacyUDPBodyOffset  = legacyUDPHeaderLen + legacyUDPIPHeaderLen
)

var legacyUDPMagic = []byte{0xFE, 0xFC, 0xEF, 0xBE, 0xC1, 0x92, 0xA4, 0xD6}

var legacyUDPBufPool = sync.Pool{New: func() any {
	b := make([]byte, legacyUDPBodyOffset+65535)
	return &b
}}

func (s *legacySession) startUDP() error {
	port := defaultUDPPort
	if fr, err := s.request(CmdLegacyUDPPort, make([]byte, 4), CmdLegacyUDPPort, s.cfg.timeout()); err == nil {
		if len(fr.Payload) >= 2 {
			port = int(binary.BigEndian.Uint16(fr.Payload[:2]))
		}
		s.cfg.logf("[legacy] UDP port=%d", port)
	} else {
		s.cfg.logf("[legacy] UDP port request failed: %v", err)
	}

	fr, err := s.request(CmdLegacyUDPKey, []byte{0, 0, 0, 4}, CmdLegacyUDPKey, s.cfg.timeout())
	if err != nil {
		return fmt.Errorf("udp key request: %w", err)
	}
	if len(fr.Payload) < 20 {
		return fmt.Errorf("udp key reply too short (%d)", len(fr.Payload))
	}
	mode := binary.BigEndian.Uint32(fr.Payload[:4])
	if mode != 3 {
		return fmt.Errorf("udp mode %d not supported", mode)
	}
	var key [16]byte
	copy(key[:], fr.Payload[4:20])
	s.cfg.logf("[legacy] UDP mode=%d key=%d bytes", mode, len(fr.Payload)-4)

	host := s.cfg.host()
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("udp dial: %w", err)
	}
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return errClosed
	}
	s.udp = conn
	s.udpKey = key
	s.mu.Unlock()
	s.cfg.logf("[legacy] UDP transport -> %s", addr)
	return nil
}

func sendLegacyUDP(conn *net.UDPConn, uid uint32, key [16]byte, pkt []byte) error {
	if len(pkt) < legacyUDPIPHeaderLen {
		return errors.New("udp: packet too short")
	}
	iv := make([]byte, aesBlockSize)
	binary.BigEndian.PutUint32(iv[0:4], uid)
	if _, err := rand.Read(iv[4:]); err != nil {
		return err
	}
	body := encryptCBC(key[:], iv, pkt[legacyUDPIPHeaderLen:])

	bp := legacyUDPBufPool.Get().(*[]byte)
	defer legacyUDPBufPool.Put(bp)
	buf := (*bp)[:legacyUDPBodyOffset+len(body)]
	copy(buf[0:8], legacyUDPMagic)
	binary.BigEndian.PutUint16(buf[8:10], 0x021C)
	binary.BigEndian.PutUint16(buf[10:12], 0x0010)
	copy(buf[12:28], iv)
	copy(buf[28:48], pkt[:legacyUDPIPHeaderLen])
	copy(buf[48:], body)

	_, err := conn.Write(buf)
	return err
}

func recvLegacyUDP(conn *net.UDPConn, key [16]byte) ([]byte, error) {
	bp := legacyUDPBufPool.Get().(*[]byte)
	defer legacyUDPBufPool.Put(bp)
	buf := *bp

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < legacyUDPBodyOffset || !bytes.Equal(buf[:8], legacyUDPMagic) {
			continue
		}
		ipHead := buf[legacyUDPHeaderLen : legacyUDPHeaderLen+legacyUDPIPHeaderLen]
		if ipHead[0]>>4 != 4 {
			continue // 控制帧，不是数据报文
		}
		total := int(binary.BigEndian.Uint16(ipHead[2:4]))
		bodyLen := total - legacyUDPIPHeaderLen
		if bodyLen < 0 || legacyUDPBodyOffset+bodyLen > n {
			continue
		}
		plain := decryptCBC(key[:], buf[12:28], buf[legacyUDPBodyOffset:n])
		if len(plain) < bodyLen {
			continue
		}
		out := make([]byte, total)
		copy(out[:legacyUDPIPHeaderLen], ipHead)
		copy(out[legacyUDPIPHeaderLen:], plain[:bodyLen])
		return out, nil
	}
}
