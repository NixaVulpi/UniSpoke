package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestServiceArguments(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "flag with separate value",
			in:   []string{"-service", "install", "-gateway", "vpn.example.com:443", "-user", "alice"},
			want: []string{"-gateway", "vpn.example.com:443", "-user", "alice"},
		},
		{
			name: "flag with equals",
			in:   []string{"-service=install", "-vpn", "-vpn-full"},
			want: []string{"-vpn", "-vpn-full"},
		},
		{
			name: "double dash",
			in:   []string{"--service=uninstall", "-quiet"},
			want: []string{"-quiet"},
		},
		{
			name: "flag at the end",
			in:   []string{"-gateway", "vpn.example.com:443", "-service", "start"},
			want: []string{"-gateway", "vpn.example.com:443"},
		},
		{
			name: "no service flag",
			in:   []string{"-vpn", "-mss", "1200"},
			want: []string{"-vpn", "-mss", "1200"},
		},
		{
			name: "keeps password value",
			in:   []string{"-service", "install", "-user", "alice", "-password", "p w"},
			want: []string{"-user", "alice", "-password", "p w"},
		},
		{
			name: "empty",
			in:   nil,
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serviceArguments(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("serviceArguments(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestAbsoluteCaPath(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "ca.pem")
	if got := absoluteCaPath([]string{"-ca", abs}); got[1] != abs {
		t.Fatalf("absolute path changed: %q", got[1])
	}

	for _, args := range [][]string{
		{"-ca", "certs/ca.pem"},
		{"-ca=certs/ca.pem"},
		{"--ca=certs/ca.pem"},
	} {
		got := absoluteCaPath(args)
		value := strings.TrimPrefix(got[len(got)-1], "-ca=")
		value = strings.TrimPrefix(value, "--ca=")
		if !filepath.IsAbs(value) {
			t.Fatalf("absoluteCaPath(%q) = %q, want an absolute path", args, got)
		}
	}
}

func TestServiceConfigBakesArguments(t *testing.T) {
	args := []string{"-gateway", "vpn.example.com:443", "-user", "alice", "-password", "secret", "-vpn"}
	cfg := serviceConfig(args)
	if cfg.Name != serviceName {
		t.Fatalf("Name = %q, want %q", cfg.Name, serviceName)
	}
	if !reflect.DeepEqual(cfg.Arguments, args) {
		t.Fatalf("Arguments = %q, want %q", cfg.Arguments, args)
	}
}
