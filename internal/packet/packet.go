// Package packet 处理网关丢弃 ≤40 字节 IPv4 报文的限制。
package packet

import (
	"encoding/binary"
	"net"
)

const gatewayMinLen = 40

const (
	protoTCP  = 6
	protoUDP  = 17
	protoICMP = 1
)

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// Pad 返回可发往网关的报文，无需补齐时返回原切片。
func Pad(pkt []byte) []byte {
	if len(pkt) > gatewayMinLen || len(pkt) < 20 || pkt[0]>>4 != 4 {
		return pkt
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return pkt
	}
	if pkt[9] == protoTCP {
		if out, ok := padTCP(pkt, ihl); ok {
			return out
		}
	}
	return padIPOptions(pkt, ihl)
}

// padTCP 给无载荷、无选项的 TCP 报文追加 4 个 NOP 选项。
func padTCP(pkt []byte, ihl int) ([]byte, bool) {
	if ihl != 20 || len(pkt) > gatewayMinLen {
		return nil, false
	}
	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return nil, false
	}
	doff := int(tcp[12]>>4) * 4
	if doff != 20 || len(tcp) != doff {
		return nil, false
	}
	// SYN 通常带 MSS 选项，这里只处理无选项短包。
	if tcp[13]&tcpACK == 0 {
		return nil, false
	}

	out := make([]byte, len(pkt)+4)
	copy(out, pkt)
	for i := len(pkt); i < len(out); i++ {
		out[i] = 1 // NOP 选项
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[ihl+12] = 6 << 4 // 首部长度 24 字节
	binary.BigEndian.PutUint16(out[ihl+16:ihl+18], 0)
	binary.BigEndian.PutUint16(out[ihl+16:ihl+18], tcpChecksum(out[12:16], out[16:20], out[ihl:]))
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:ihl]))
	return out, true
}

// padIPOptions 用 IP NOP 选项撑长报文，只需重算 IP 校验和。
func padIPOptions(pkt []byte, ihl int) []byte {
	if ihl != 20 || len(pkt) > gatewayMinLen {
		return pkt
	}
	// 补到至少 41 字节并按 4 字节对齐。
	add := gatewayMinLen + 1 - len(pkt)
	if add < 4 {
		add = 4
	}
	add = (add + 3) &^ 3
	if add > 40 {
		return pkt
	}

	out := make([]byte, len(pkt)+add)
	copy(out[:20], pkt[:20])
	for i := 20; i < 20+add; i++ {
		out[i] = 1 // NOP 选项
	}
	copy(out[20+add:], pkt[20:])
	out[0] = byte(0x40 | (20+add)/4) // 版本 4 与新的 IHL
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20+add]))
	return out
}

func tcpChecksum(src, dst, seg []byte) uint16 {
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = protoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	return checksum(pseudo)
}

func checksum(b []byte) uint16 {
	var sum uint32
	i := 0
	for ; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if i < len(b) {
		sum += uint32(b[i]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func Addrs(pkt []byte) (src, dst net.IP, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, nil, false
	}
	return net.IP(pkt[12:16]), net.IP(pkt[16:20]), true
}
