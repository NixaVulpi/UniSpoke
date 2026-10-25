// Package vpn 提供系统级 TUN 模式。
package vpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"unispoke/internal/packet"
	"unispoke/internal/tunnel"
)

type Config struct {
	Name    string
	Gateway string // 全隧道时用于排除自身路由
	VIP     net.IP
	Mask    net.IPMask
	MTU     int
	Routes  []*net.IPNet
	DNS     []net.IP
	Full    bool // 全隧道（0.0.0.0/0）
	Debug   bool // 打印前若干报文与周期计数
}

type Device struct {
	dev   tun.Device
	name  string
	mgr   *tunnel.Manager
	logf  func(string, ...any)
	debug bool

	done chan struct{}
	once sync.Once

	mu  sync.Mutex
	cur Config // 当前生效的网络参数

	sent     atomic.Uint64
	received atomic.Uint64
	logged   atomic.Uint64
}

func Start(cfg Config, mgr *tunnel.Manager, logf func(string, ...any)) (*Device, error) {
	if cfg.Name == "" {
		cfg.Name = "unispoke"
	}
	if cfg.VIP == nil {
		return nil, errors.New("vpn: VIP is required")
	}
	if cfg.Mask == nil {
		cfg.Mask = net.CIDRMask(24, 32)
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1240
	}

	dev, err := tun.CreateTUN(cfg.Name, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("vpn: create TUN (需要管理员权限；Windows 需要 wintun.dll): %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("vpn: device name: %w", err)
	}
	cfg.Name = name

	if err := configure(name, cfg, logf); err != nil {
		_ = dev.Close()
		return nil, err
	}

	d := &Device{
		dev:   dev,
		name:  name,
		mgr:   mgr,
		logf:  logf,
		debug: cfg.Debug,
		cur:   cfg,
		done:  make(chan struct{}),
	}
	go d.toTunnel()
	go d.fromTunnel()
	go d.watchNetwork()
	if cfg.Debug {
		go d.statsLoop()
	}
	return d, nil
}

// watchNetwork 在会话重建后同步 VIP/路由/DNS。
func (d *Device) watchNetwork() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-d.done:
			return
		case <-t.C:
		}

		nc := d.mgr.NetworkSnapshot()
		if nc.VIP == nil {
			continue
		}
		d.mu.Lock()
		cur := d.cur
		d.mu.Unlock()

		next := cur
		next.VIP = nc.VIP
		if nc.Mask != nil {
			next.Mask = nc.Mask
		}
		if len(nc.Routes) > 0 {
			next.Routes = nc.Routes
		}
		if len(nc.DNS) > 0 {
			next.DNS = nc.DNS
		}
		if next.VIP.Equal(cur.VIP) && sameRoutes(next.Routes, cur.Routes) && sameDNS(next.DNS, cur.DNS) {
			continue
		}

		d.logf("[vpn] network changed: vip %s -> %s routes=%d", cur.VIP, next.VIP, len(next.Routes))
		if err := reconfigure(d.name, cur, next, d.logf); err != nil {
			d.logf("[vpn] reconfigure: %v", err)
			continue
		}
		d.mu.Lock()
		d.cur = next
		d.mu.Unlock()
	}
}

func sameRoutes(a, b []*net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	as := make(map[string]struct{}, len(a))
	for _, r := range a {
		if r != nil {
			as[r.String()] = struct{}{}
		}
	}
	for _, r := range b {
		if r == nil {
			continue
		}
		if _, ok := as[r.String()]; !ok {
			return false
		}
	}
	return true
}

func sameDNS(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func (d *Device) statsLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-d.done:
			return
		case <-t.C:
			d.logf("[vpn] stats: os->tunnel=%d tunnel->os=%d", d.sent.Load(), d.received.Load())
		}
	}
}

func (d *Device) logPacket(dir string, pkt []byte) {
	if !d.debug || len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	if d.logged.Add(1) > 60 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	proto := pkt[9]
	src := net.IP(pkt[12:16])
	dst := net.IP(pkt[16:20])
	detail := ""
	if ihl >= 20 && len(pkt) >= ihl+4 && (proto == 6 || proto == 17) {
		detail = fmt.Sprintf(" %d->%d", binary.BigEndian.Uint16(pkt[ihl:ihl+2]), binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]))
		if proto == 6 && len(pkt) >= ihl+14 {
			detail += fmt.Sprintf(" flags=0x%02x", pkt[ihl+13])
		}
	}
	d.logf("[vpn] %s proto=%d %s->%s len=%d%s", dir, proto, src, dst, len(pkt), detail)
}

func (d *Device) Name() string { return d.name }

func (d *Device) Close() error {
	d.once.Do(func() {
		close(d.done)
		_ = d.dev.Close()
		d.mu.Lock()
		cfg := d.cur
		d.mu.Unlock()
		cleanup(d.name, cfg, d.logf)
	})
	return nil
}

func (d *Device) toTunnel() {
	batch := d.dev.BatchSize()
	if batch <= 0 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	for {
		select {
		case <-d.done:
			return
		default:
		}

		n, err := d.dev.Read(bufs, sizes, tunReadOffset)
		if err != nil {
			select {
			case <-d.done:
				return
			default:
			}
			d.logf("[vpn] read: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		for i := 0; i < n; i++ {
			if sizes[i] < 20 || tunReadOffset+sizes[i] > len(bufs[i]) {
				continue
			}
			pkt := bufs[i][tunReadOffset : tunReadOffset+sizes[i]]
			if pkt[0]>>4 != 4 {
				continue // 隧道只承载 IPv4
			}
			// 网关丢弃 ≤40 字节的 IPv4 报文（纯 ACK 恰好 40 字节）。
			pkt = packet.Pad(pkt)
			d.sent.Add(1)
			d.logPacket("os->tunnel", pkt)
			if err := d.mgr.SendIP(pkt); err != nil {
				d.logf("[vpn] send: %v", err)
			}
		}
	}
}

func (d *Device) fromTunnel() {
	// Keep headroom for the platform TUN header. Linux TUN devices are
	// created with IFF_VNET_HDR, so writes must begin at tunWriteOffset.
	buf := make([]byte, tunWriteOffset+65535)
	for {
		pkt, err := d.mgr.RecvIP()
		if err != nil {
			select {
			case <-d.done:
				return
			default:
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if len(pkt) < 20 || pkt[0]>>4 != 4 || len(pkt) > 65535 {
			continue
		}
		end := tunWriteOffset + len(pkt)
		clear(buf[:tunWriteOffset]) // virtio-net 头必须全零（非 GSO）
		copy(buf[tunWriteOffset:end], pkt)
		d.received.Add(1)
		d.logPacket("tunnel->os", pkt)
		if _, err := d.dev.Write([][]byte{buf[:end]}, tunWriteOffset); err != nil {
			select {
			case <-d.done:
				return
			default:
			}
			d.logf("[vpn] write: %v", err)
		}
	}
}
