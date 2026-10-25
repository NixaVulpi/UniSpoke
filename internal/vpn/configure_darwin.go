//go:build darwin

package vpn

import (
	"fmt"
	"strconv"
)

func configure(name string, cfg Config, logf func(string, ...any)) error {
	if err := run(logf, "ifconfig", name, "inet",
		cfg.VIP.String(), cfg.VIP.String(), "netmask", maskDotted(cfg.Mask), "up"); err != nil {
		return fmt.Errorf("vpn: configure %s: %w", name, err)
	}
	_ = run(logf, "ifconfig", name, "mtu", strconv.Itoa(cfg.MTU))

	for _, r := range cfg.Routes {
		if r == nil {
			continue
		}
		if isDefaultRoute(r) {
			logf("[vpn] default route through TUN is not supported on darwin")
			continue
		}
		if err := run(logf, "route", "-n", "add", "-net", r.String(), "-interface", name); err != nil {
			logf("[vpn] add route %s: %v", r, err)
		}
	}
	if len(cfg.DNS) > 0 {
		logf("[vpn] dns: configure %v manually via networksetup or scutil", cfg.DNS)
	}
	return nil
}

func reconfigure(name string, old, next Config, logf func(string, ...any)) error {
	for _, r := range old.Routes {
		if r == nil || isDefaultRoute(r) {
			continue
		}
		_ = run(logf, "route", "-n", "delete", "-net", r.String(), "-interface", name)
	}
	if old.VIP != nil {
		_ = run(logf, "ifconfig", name, "inet", old.VIP.String(), "-alias")
	}
	if err := run(logf, "ifconfig", name, "inet",
		next.VIP.String(), next.VIP.String(), "netmask", maskDotted(next.Mask), "up"); err != nil {
		return fmt.Errorf("vpn: reconfigure %s: %w", name, err)
	}
	for _, r := range next.Routes {
		if r == nil || isDefaultRoute(r) {
			continue
		}
		if err := run(logf, "route", "-n", "add", "-net", r.String(), "-interface", name); err != nil {
			logf("[vpn] add route %s: %v", r, err)
		}
	}
	return nil
}

func cleanup(name string, cfg Config, logf func(string, ...any)) {
	for _, r := range cfg.Routes {
		if r == nil || isDefaultRoute(r) {
			continue
		}
		_ = run(logf, "route", "-n", "delete", "-net", r.String(), "-interface", name)
	}
}
