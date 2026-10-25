package tunnel

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

const (
	MagicV1      uint32 = 0xC192A4D6
	MagicLegacy1 uint32 = 0xFEFCEFBE
)

const (
	// Legacy 帧命令（16 字节头，cmd 位于 +12）。
	CmdLegacyData      = 0x02
	CmdLegacyREQVIP    = 0x03
	CmdLegacyDHCP      = 0x05
	CmdLegacyACL       = 0x06
	CmdLegacyKeepalive = 0x07
	CmdLegacyKickout   = 0x08

	// V1 帧命令（8 字节头，cmd 位于 +5）。
	CmdV1Auth          = 0x01
	CmdV1REQVIP        = 0x03
	CmdV1Keepalive     = 0x06
	CmdV1TunnelSwitch  = 0x09
	CmdV1Kickout       = 0x32
	CmdV1DataConnect   = 0x64
	CmdV1DataKeepalive = 0x65
	CmdV1Data          = 0x66
)

const (
	maxPayload = 1 << 16
	// 超过该值视为长度字段字节序异常：个别网关使用小端。
	lenSanityLimit = 4096
)

var errTimeout = errors.New("tunnel: read timeout")

type Frame struct {
	Version int // 1=V1（8 字节头），0=legacy（16 字节头）
	Cmd     int
	SID     uint32
	Payload []byte
}

func BuildV1(cmd byte, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(b[0:4], MagicV1)
	b[4] = 1
	b[5] = cmd
	binary.BigEndian.PutUint16(b[6:8], uint16(len(payload)))
	copy(b[8:], payload)
	return b
}

func BuildLegacy(cmd uint16, payload []byte, sid uint32) []byte {
	b := make([]byte, 16+len(payload))
	binary.BigEndian.PutUint32(b[0:4], MagicLegacy1)
	binary.BigEndian.PutUint32(b[4:8], MagicV1)
	binary.BigEndian.PutUint32(b[8:12], sid)
	binary.BigEndian.PutUint16(b[12:14], cmd)
	binary.BigEndian.PutUint16(b[14:16], uint16(len(payload)))
	copy(b[16:], payload)
	return b
}

type FrameReader struct {
	conn net.Conn
	buf  []byte
}

func NewFrameReader(c net.Conn) *FrameReader { return &FrameReader{conn: c} }

// Next 返回下一帧；timeout 为 0 时阻塞等待。
func (r *FrameReader) Next(timeout time.Duration) (Frame, error) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		f, n, status := parseFrame(r.buf)
		switch status {
		case 1:
			r.buf = r.buf[n:]
			return f, nil
		case -1:
			// 跳过一个字节重新同步。
			r.buf = r.buf[1:]
			continue
		}
		if timeout > 0 {
			r.conn.SetReadDeadline(deadline)
		} else {
			r.conn.SetReadDeadline(time.Time{})
		}
		tmp := make([]byte, 65536)
		nr, err := r.conn.Read(tmp)
		if nr > 0 {
			r.buf = append(r.buf, tmp[:nr]...)
			continue
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return Frame{}, errTimeout
			}
			return Frame{}, err
		}
	}
}

// parseFrame 返回（帧、消耗字节数、状态）。状态 0=数据不足，1=解析成功，-1=头部非法。
func parseFrame(b []byte) (Frame, int, int) {
	if len(b) < 4 {
		return Frame{}, 0, 0
	}
	if binary.BigEndian.Uint32(b[0:4]) == MagicV1 {
		if len(b) < 8 {
			return Frame{}, 0, 0
		}
		l := int(binary.BigEndian.Uint16(b[6:8]))
		if len(b) < 8+l {
			return Frame{}, 0, 0
		}
		return Frame{Version: 1, Cmd: int(b[5]), Payload: b[8 : 8+l]}, 8 + l, 1
	}
	if len(b) < 8 {
		return Frame{}, 0, 0
	}
	if binary.BigEndian.Uint32(b[0:4]) != MagicLegacy1 ||
		binary.BigEndian.Uint32(b[4:8]) != MagicV1 {
		return Frame{}, 0, -1
	}
	if len(b) < 16 {
		return Frame{}, 0, 0
	}
	be := int(binary.BigEndian.Uint16(b[14:16]))
	le := int(binary.LittleEndian.Uint16(b[14:16]))
	l := be
	if be > lenSanityLimit && le <= lenSanityLimit {
		l = le // 该回包长度字段为小端
	}
	if len(b) < 16+l {
		return Frame{}, 0, 0
	}
	return Frame{
		Version: 0,
		Cmd:     int(binary.BigEndian.Uint16(b[12:14])),
		SID:     binary.BigEndian.Uint32(b[8:12]),
		Payload: b[16 : 16+l],
	}, 16 + l, 1
}
