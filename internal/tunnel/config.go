package tunnel

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"time"
)

type Config struct {
	Gateway    string
	User       string
	Password   string
	Domain     string // 默认取网关主机名
	MAC        string // 可选
	Mode       string // auto | legacy | v1
	Transport  string // auto | tcp | udp
	Insecure   bool
	ServerName string
	CAFile     string
	Timeout    time.Duration
	Debug      bool
	Logf       func(format string, args ...any)
}

func (c Config) tls() TLSOptions {
	return TLSOptions{
		ServerName: c.ServerName,
		Insecure:   c.Insecure,
		CAFile:     c.CAFile,
		Timeout:    c.Timeout,
	}
}

func (c Config) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 10 * time.Second
}

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func (c Config) host() string {
	h, _, err := net.SplitHostPort(c.Gateway)
	if err != nil {
		return c.Gateway
	}
	return h
}

func (c Config) domain() string {
	if c.Domain != "" {
		return c.Domain
	}
	return c.host()
}

// macString 返回 V1 认证 TLV 使用的 14 字符 MAC 格式。
func (c Config) macString() string {
	if c.MAC != "" {
		s := strings.ToUpper(c.MAC)
		s = strings.ReplaceAll(s, ":", "")
		s = strings.ReplaceAll(s, "-", "")
		if len(s) == 12 {
			return s[0:4] + "-" + s[4:8] + "-" + s[8:12]
		}
		return c.MAC
	}
	sum := sha256.Sum256([]byte(c.User + "|" + c.Gateway))
	b := sum[:6]
	b[0] = (b[0] | 0x02) & 0xFE
	return fmt.Sprintf("%02X%02X-%02X%02X-%02X%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}

// NetworkConfig 是网关 REQVIP 下发的网络参数。
type NetworkConfig struct {
	VIP    net.IP
	Mask   net.IPMask
	DNS    []net.IP
	Routes []*net.IPNet
}
