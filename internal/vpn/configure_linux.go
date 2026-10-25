//go:build linux

package vpn

import (
	"fmt"
	"strconv"
)

func configure(name string, cfg Config, logf func(string, ...any)) error {
	_ = run(logf, "ip", "link", "set", "dev", name, "mtu", strconv.Itoa(cfg.MTU), "up")

	addr := fmt.Sprintf("%s/%d", cfg.VIP.String(), prefixLen(cfg.Mask))
	if err := run(logf, "ip", "addr", "replace", addr, "dev", name); err != nil {
		return fmt.Errorf("vpn: set address %s: %w", addr, err)
	}

	for _, r := range cfg.Routes {
		if r == nil {
			continue
		}
		if isDefaultRoute(r) {
			logf("[vpn] default route is not supported on linux; use split routes")
			continue
		}
		if err := run(logf, "ip", "route", "add", r.String(), "dev", name); err != nil {
			logf("[vpn] add route %s: %v", r, err)
		}
	}

	if len(cfg.DNS) > 0 {
		args := []string{"dns", name}
		for _, dns := range cfg.DNS {
			if dns != nil && !dns.IsUnspecified() {
				args = append(args, dns.String())
			}
		}
		if len(args) > 2 {
			_ = run(logf, "resolvectl", args...)
		}
	}
	return nil
}

func reconfigure(name string, old, next Config, logf func(string, ...any)) error {
	for _, r := range old.Routes {
		if r == nil || isDefaultRoute(r) {
			continue
		}
		_ = run(logf, "ip", "route", "del", r.String(), "dev", name)
	}
	addr := fmt.Sprintf("%s/%d", next.VIP.String(), prefixLen(next.Mask))
	if err := run(logf, "ip", "addr", "replace", addr, "dev", name); err != nil {
		return fmt.Errorf("vpn: set address %s: %w", addr, err)
	}
	for _, r := range next.Routes {
		if r == nil || isDefaultRoute(r) {
			continue
		}
		if err := run(logf, "ip", "route", "add", r.String(), "dev", name); err != nil {
			logf("[vpn] add route %s: %v", r, err)
		}
	}
	if len(next.DNS) > 0 {
		args := []string{"dns", name}
		for _, dns := range next.DNS {
			if dns != nil && !dns.IsUnspecified() {
				args = append(args, dns.String())
			}
		}
		if len(args) > 2 {
			_ = run(logf, "resolvectl", args...)
		}
	}
	return nil
}

func cleanup(name string, cfg Config, logf func(string, ...any)) {
	for _, r := range cfg.Routes {
		if r == nil || isDefaultRoute(r) {
			continue
		}
		_ = run(logf, "ip", "route", "del", r.String(), "dev", name)
	}
}
