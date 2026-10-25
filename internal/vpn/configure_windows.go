//go:build windows

package vpn

import (
	"fmt"
	"net"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

func configure(name string, cfg Config, logf func(string, ...any)) error {
	_ = run(logf, "netsh", "interface", "ipv4", "set", "subinterface", name,
		"mtu="+strconv.Itoa(cfg.MTU), "store=active")

	if err := setAddress(name, cfg, logf); err != nil {
		return err
	}

	// 加默认路由前必须先把网关自身固定到物理网卡，否则隧道 TLS 重连会走进隧道。
	pinned := false
	if cfg.Full || hasDefaultRoute(cfg.Routes) {
		if err := pinGateway(logf, cfg.Gateway); err != nil {
			logf("[vpn] full tunnel unavailable: %v", err)
		} else {
			pinned = true
		}
	}

	applyRoutes(name, cfg, pinned, logf)
	applyDNS(name, cfg, logf)

	if cfg.Debug {
		out, _ := command("netsh", "interface", "ipv4", "show", "route").CombinedOutput()
		logf("[vpn] route table:\n%s", out)
	}
	return nil
}

// reconfigure 在会话重建、VIP/路由/DNS 变化后重新配置网卡。
func reconfigure(name string, old, next Config, logf func(string, ...any)) error {
	removeRoutes(name, old.Routes, logf)
	if old.Full {
		_ = run(logf, "netsh", "interface", "ipv4", "delete", "route",
			"prefix=0.0.0.0/0", "interface="+name, "store=active")
	}

	if err := setAddress(name, next, logf); err != nil {
		return err
	}

	// 之前全隧道时固定的网关 /32 路由仍然有效。
	pinned := old.Full
	if (next.Full || hasDefaultRoute(next.Routes)) && !pinned {
		if err := pinGateway(logf, next.Gateway); err != nil {
			logf("[vpn] full tunnel unavailable: %v", err)
		} else {
			pinned = true
		}
	}

	applyRoutes(name, next, pinned, logf)
	applyDNS(name, next, logf)
	return nil
}

func setAddress(name string, cfg Config, logf func(string, ...any)) error {
	if err := run(logf, "netsh", "interface", "ipv4", "set", "address",
		"name="+name, "source=static",
		"addr="+cfg.VIP.String(), "mask="+maskDotted(cfg.Mask), "gateway=none"); err != nil {
		return fmt.Errorf("vpn: set address on %s: %w", name, err)
	}
	return nil
}

func applyRoutes(name string, cfg Config, pinned bool, logf func(string, ...any)) {
	for _, r := range cfg.Routes {
		if r == nil {
			continue
		}
		if isDefaultRoute(r) && !pinned {
			continue
		}
		if err := run(logf, "netsh", "interface", "ipv4", "add", "route",
			"prefix="+r.String(), "interface="+name, "store=active"); err != nil {
			logf("[vpn] add route %s: %v", r, err)
		}
	}
	if cfg.Full && pinned {
		if err := run(logf, "netsh", "interface", "ipv4", "add", "route",
			"prefix=0.0.0.0/0", "interface="+name, "store=active"); err != nil {
			logf("[vpn] add default route: %v", err)
		}
	}
}

func removeRoutes(name string, routes []*net.IPNet, logf func(string, ...any)) {
	for _, r := range routes {
		if r == nil {
			continue
		}
		_ = run(logf, "netsh", "interface", "ipv4", "delete", "route",
			"prefix="+r.String(), "interface="+name, "store=active")
	}
}

func applyDNS(name string, cfg Config, logf func(string, ...any)) {
	for i, dns := range cfg.DNS {
		if dns == nil || dns.IsUnspecified() {
			continue
		}
		if i == 0 {
			if err := run(logf, "netsh", "interface", "ipv4", "set", "dnsservers",
				"name="+name, "static", dns.String(), "primary"); err != nil {
				logf("[vpn] dns %s: %v", dns, err)
			}
		} else {
			if err := run(logf, "netsh", "interface", "ipv4", "add", "dnsservers",
				"name="+name, "address="+dns.String(), "index="+strconv.Itoa(i+1)); err != nil {
				logf("[vpn] dns %s: %v", dns, err)
			}
		}
	}
}

func cleanup(name string, cfg Config, logf func(string, ...any)) {
	removeRoutes(name, cfg.Routes, logf)
	if cfg.Full {
		_ = run(logf, "netsh", "interface", "ipv4", "delete", "route",
			"prefix=0.0.0.0/0", "interface="+name, "store=active")
		if gw := gatewayIP(cfg.Gateway); gw != nil {
			_ = run(logf, "route", "DELETE", gw.String())
		}
	}
}

func pinGateway(logf func(string, ...any), gateway string) error {
	gw := gatewayIP(gateway).To4()
	if gw == nil {
		return fmt.Errorf("bad gateway %q", gateway)
	}
	sa := &windows.SockaddrInet4{}
	copy(sa.Addr[:], gw)
	var ifIdx uint32
	if err := windows.GetBestInterfaceEx(sa, &ifIdx); err != nil {
		return fmt.Errorf("best interface: %w", err)
	}
	nextHop, err := gatewayFor(ifIdx)
	if err != nil {
		return err
	}
	return run(logf, "route", "ADD", gw.String(), "MASK", "255.255.255.255",
		nextHop.String(), "IF", strconv.Itoa(int(ifIdx)), "METRIC", "1")
}

func gatewayFor(ifIdx uint32) (net.IP, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, nil, &size)
	if err != nil && err != windows.ERROR_BUFFER_OVERFLOW {
		return nil, fmt.Errorf("adapters: %w", err)
	}
	if size == 0 {
		return nil, fmt.Errorf("no adapters")
	}
	buf := make([]byte, size)
	aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, aa, &size); err != nil {
		return nil, fmt.Errorf("adapters: %w", err)
	}
	for a := aa; a != nil; a = a.Next {
		if a.IfIndex != ifIdx {
			continue
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := g.Address.IP(); ip != nil {
				return ip.To4(), nil
			}
		}
	}
	return nil, fmt.Errorf("no gateway on interface %d", ifIdx)
}
