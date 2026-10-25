//go:build !windows && !linux && !darwin

package vpn

import "errors"

func configure(name string, cfg Config, logf func(string, ...any)) error {
	return errors.New("vpn: unsupported platform")
}

func reconfigure(name string, old, next Config, logf func(string, ...any)) error {
	return errors.New("vpn: unsupported platform")
}

func cleanup(name string, cfg Config, logf func(string, ...any)) {}
