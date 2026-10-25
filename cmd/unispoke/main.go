// Command unispoke 提供 SOCKS5 与 HTTP 代理。
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"unispoke/internal/dnsrelay"
	"unispoke/internal/netstack"
	"unispoke/internal/proxy"
	"unispoke/internal/tunnel"
	"unispoke/internal/vpn"
)

// 构建时可通过 -ldflags "-X main.version=..." 覆盖版本号。
var version = "0.2.1"

func main() {
	var (
		gateway   = flag.String("gateway", "", "gateway host:port (required)")
		user      = flag.String("user", "", "VPN username (required)")
		password  = flag.String("password", "", "VPN password (required)")
		mode      = flag.String("mode", "auto", "gateway mode: auto|legacy|v1")
		transport = flag.String("transport", "tcp", "data transport: tcp|udp|auto")
		insecure  = flag.Bool("insecure", false, "skip TLS certificate verification")
		sni       = flag.String("sni", "", "TLS server name (defaults to gateway host)")
		caFile    = flag.String("ca", "", "CA bundle for private gateways")
		mac       = flag.String("mac", "", "client MAC (optional)")
		socksAdr  = flag.String("socks", "127.0.0.1:1080", "SOCKS5 listen address (empty disables)")
		httpAdr   = flag.String("http", "127.0.0.1:8080", "HTTP proxy listen address (empty disables)")
		dnsAdr    = flag.String("dns", "", "local DNS relay listen address, e.g. 127.0.0.1:5353 (empty disables)")
		vpnMode   = flag.Bool("vpn", false, "system-level TUN mode (requires admin; disables proxy listeners)")
		vpnName   = flag.String("vpn-name", "unispoke", "TUN adapter name")
		vpnFull   = flag.Bool("vpn-full", false, "route all IPv4 traffic through the tunnel (Windows)")
		vpnDebug  = flag.Bool("vpn-debug", false, "log VPN packet summaries and counters")
		timeout   = flag.Duration("timeout", 10*time.Second, "network timeout")
		mss       = flag.Int("mss", 1200, "TCP MSS used inside the tunnel")
		domain    = flag.String("domain", "", "authentication domain (defaults to gateway host)")
		quiet     = flag.Bool("quiet", false, "only log errors (same as -log-level warn)")
		dropAfter = flag.Duration("drop-after", 0, "test hook: drop tunnel sockets after this duration")
		showVer   = flag.Bool("version", false, "print version and exit")
		dnsServer = flag.String("dns-server", "", "comma-separated DNS servers inside the VPN (overrides gateway)")
		logLevel  = flag.String("log-level", "info", "log level: debug|info|warn|error")
		logFormat = flag.String("log-format", "plain", "log format: plain|logfmt|json")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("unispoke %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	if *password == "" {
		*password = os.Getenv("UNISPOKE_PASSWORD")
	}

	if *gateway == "" || *user == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "usage: unispoke -gateway host:port -user USER -password PASS [options]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	level := slog.LevelInfo
	switch strings.ToLower(*logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	if *quiet {
		level = slog.LevelWarn
	}
	hopts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch strings.ToLower(*logFormat) {
	case "plain", "":
		handler = newPlainHandler(os.Stderr, hopts)
	case "logfmt":
		handler = slog.NewTextHandler(os.Stderr, hopts)
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, hopts)
	default:
		fmt.Fprintf(os.Stderr, "unknown log format %q (use plain|logfmt|json)\n", *logFormat)
		os.Exit(2)
	}
	logger := slog.New(handler)
	logf := func(format string, args ...any) {
		logger.Info(fmt.Sprintf(format, args...))
	}
	fatal := func(format string, args ...any) {
		logger.Error(fmt.Sprintf(format, args...))
		os.Exit(1)
	}
	logf("unispoke %s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)

	if (strings.EqualFold(*transport, "udp") || strings.EqualFold(*transport, "auto")) && *mss > 1200 {
		logf("mss capped to 1200 for UDP transport (gateway UDP frame is 1280 bytes)")
		*mss = 1200
	}

	cfg := tunnel.Config{
		Gateway:    *gateway,
		User:       *user,
		Password:   *password,
		Domain:     *domain,
		MAC:        *mac,
		Mode:       *mode,
		Transport:  *transport,
		Insecure:   *insecure,
		ServerName: *sni,
		CAFile:     *caFile,
		Timeout:    *timeout,
		Logf:       logf,
	}

	mgr := tunnel.NewManager(cfg)
	sess, err := mgr.Ensure()
	if err != nil {
		fatal("connect: %v", err)
	}
	vip := sess.VIP()
	if vip == nil {
		fatal("gateway returned no virtual IP")
	}
	netCfg := mgr.Network()

	dnsIPs := netCfg.DNS
	if *dnsServer != "" {
		dnsIPs = nil
		for _, part := range strings.Split(*dnsServer, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			ip := net.ParseIP(part)
			if ip == nil {
				fatal("bad DNS server %q", part)
			}
			dnsIPs = append(dnsIPs, ip)
		}
	}
	logf("connected: vip=%s mask=%s mode=%s dns=%v routes=%d", vip, maskString(netCfg.Mask), *mode, dnsIPs, len(netCfg.Routes))

	if *dropAfter > 0 {
		go func() {
			time.Sleep(*dropAfter)
			if d, ok := sess.(interface{ Drop() }); ok {
				logf("test hook: dropping tunnel sockets")
				d.Drop()
			}
		}()
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	if *vpnMode {
		dev, err := vpn.Start(vpn.Config{
			Name:    *vpnName,
			Gateway: *gateway,
			VIP:     netCfg.VIP,
			Mask:    netCfg.Mask,
			MTU:     *mss + 40,
			Routes:  netCfg.Routes,
			DNS:     dnsIPs,
			Full:    *vpnFull,
			Debug:   *vpnDebug,
		}, mgr, logf)
		if err != nil {
			fatal("vpn: %v", err)
		}
		logf("VPN mode: adapter=%s vip=%s mtu=%d routes=%d full=%v", dev.Name(), vip, *mss+40, len(netCfg.Routes), *vpnFull)
		<-ch
		logf("shutting down")
		dev.Close()
		mgr.Close()
		return
	}

	stack, err := netstack.NewStack(mgr, vip, *mss+40, logf)
	if err != nil {
		fatal("netstack: %v", err)
	}
	go stack.Run()

	dial := func(addr string) (net.Conn, error) { return stack.Dial(addr) }
	packet := func() (net.PacketConn, error) { return stack.ListenPacket() }
	lookup := func(host string) ([]net.IP, error) { return stack.LookupIP(host) }

	resolver := dnsrelay.NewResolver(packet, dnsIPs, *timeout, logf)
	if len(resolver.Servers) > 0 {
		stack.SetLookup(resolver.LookupIP)
		logf("tunnel DNS: %s", resolver.ServersString())
		if *dnsAdr != "" {
			srv := &dnsrelay.Server{Resolver: resolver, Addr: *dnsAdr, Logf: logf}
			go func() {
				if err := srv.Serve(); err != nil {
					logf("[dns] %v", err)
				}
			}()
		}
	} else if *dnsAdr != "" {
		logf("[dns] gateway did not provide DNS servers; relay disabled")
	}

	var listeners []net.Listener
	if *socksAdr != "" {
		l, err := net.Listen("tcp", *socksAdr)
		if err != nil {
			fatal("socks listen: %v", err)
		}
		listeners = append(listeners, l)
		logf("SOCKS5 proxy listening on %s", l.Addr())
		go func() { _ = proxy.ServeSOCKS5(l, dial, packet, lookup, logf) }()
	}
	if *httpAdr != "" {
		l, err := net.Listen("tcp", *httpAdr)
		if err != nil {
			fatal("http listen: %v", err)
		}
		listeners = append(listeners, l)
		logf("HTTP proxy listening on %s", l.Addr())
		go func() { _ = proxy.ServeHTTP(l, dial, logf) }()
	}
	if len(listeners) == 0 {
		fatal("both -socks and -http are empty")
	}

	<-ch
	logf("shutting down")
	for _, l := range listeners {
		_ = l.Close()
	}
	mgr.Close()
}

func maskString(m net.IPMask) string {
	if m == nil {
		return "-"
	}
	ones, bits := m.Size()
	if bits == 0 {
		return "-"
	}
	return fmt.Sprintf("/%d", ones)
}
