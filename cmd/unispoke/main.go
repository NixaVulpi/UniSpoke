// Command unispoke 提供 SOCKS5 与 HTTP 代理。
package main

import (
	"errors"
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

	"github.com/kardianos/service"

	"unispoke/internal/dnsrelay"
	"unispoke/internal/netstack"
	"unispoke/internal/proxy"
	"unispoke/internal/tunnel"
	"unispoke/internal/vpn"
)

// 构建时可通过 -ldflags "-X main.version=..." 覆盖版本号。
var version = "0.2.3"

type options struct {
	gateway     string
	user        string
	password    string
	passwordEnv bool // -password 未显式给出，口令来自环境变量
	domain      string
	mac         string
	mode        string
	transport   string
	insecure    bool
	sni         string
	caFile      string
	socksAdr    string
	httpAdr     string
	dnsAdr      string
	vpnMode     bool
	vpnName     string
	vpnFull     bool
	vpnDebug    bool
	timeout     time.Duration
	mss         int
	dnsServer   string
	dropAfter   time.Duration
	quiet       bool
	logLevel    string
	logFormat   string
	showVersion bool
	service     string
}

func parseOptions() options {
	var o options
	flag.StringVar(&o.gateway, "gateway", "", "gateway host:port (required)")
	flag.StringVar(&o.user, "user", "", "VPN username (required)")
	flag.StringVar(&o.password, "password", "", "VPN password (required)")
	flag.StringVar(&o.domain, "domain", "", "authentication domain (defaults to gateway host)")
	flag.StringVar(&o.mac, "mac", "", "client MAC (optional)")
	flag.StringVar(&o.mode, "mode", "auto", "gateway mode: auto|legacy|v1")
	flag.StringVar(&o.transport, "transport", "auto", "data transport: auto|tcp|udp")
	flag.BoolVar(&o.insecure, "insecure", false, "skip TLS certificate verification")
	flag.StringVar(&o.sni, "sni", "", "TLS server name (defaults to gateway host)")
	flag.StringVar(&o.caFile, "ca", "", "CA bundle for private gateways")
	flag.StringVar(&o.socksAdr, "socks", "127.0.0.1:1080", "SOCKS5 listen address (empty disables)")
	flag.StringVar(&o.httpAdr, "http", "127.0.0.1:8080", "HTTP proxy listen address (empty disables)")
	flag.StringVar(&o.dnsAdr, "dns", "", "local DNS relay listen address, e.g. 127.0.0.1:5353 (empty disables)")
	flag.BoolVar(&o.vpnMode, "vpn", false, "system-level TUN mode (requires admin; disables proxy listeners)")
	flag.StringVar(&o.vpnName, "vpn-name", "unispoke", "TUN adapter name")
	flag.BoolVar(&o.vpnFull, "vpn-full", false, "route all IPv4 traffic through the tunnel (Windows)")
	flag.BoolVar(&o.vpnDebug, "vpn-debug", false, "log VPN packet summaries and counters")
	flag.DurationVar(&o.timeout, "timeout", 10*time.Second, "network timeout")
	flag.IntVar(&o.mss, "mss", 1200, "TCP MSS used inside the tunnel")
	flag.StringVar(&o.dnsServer, "dns-server", "", "comma-separated DNS servers inside the VPN (overrides gateway)")
	flag.BoolVar(&o.quiet, "quiet", false, "only log errors (same as -log-level warn)")
	flag.DurationVar(&o.dropAfter, "drop-after", 0, "test hook: drop tunnel sockets after this duration")
	flag.BoolVar(&o.showVersion, "version", false, "print version and exit")
	flag.StringVar(&o.logLevel, "log-level", "info", "log level: debug|info|warn|error")
	flag.StringVar(&o.logFormat, "log-format", "plain", "log format: plain|logfmt|json")
	flag.StringVar(&o.service, serviceFlag, "", "system service action: "+serviceActions)
	flag.Parse()

	if o.password == "" {
		o.password = os.Getenv("UNISPOKE_PASSWORD")
		o.passwordEnv = o.password != ""
	}
	return o
}

func main() {
	opts := parseOptions()

	if opts.showVersion {
		fmt.Printf("unispoke %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	if opts.service != "" {
		if err := runServiceAction(opts); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if opts.gateway == "" || opts.user == "" || opts.password == "" {
		fmt.Fprintln(os.Stderr, "usage: unispoke -gateway host:port -user USER -password PASS [options]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	logger, err := newLogger(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logf := func(format string, args ...any) {
		logger.Info(fmt.Sprintf(format, args...))
	}
	errf := func(format string, args ...any) {
		logger.Error(fmt.Sprintf(format, args...))
	}

	prg := &serviceProgram{
		opts: opts,
		logf: logf,
		errf: errf,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	if service.Interactive() {
		// 交互运行不依赖服务管理器，同时处理 Ctrl+C 与 SIGTERM。
		runInteractive(prg)
		return
	}

	svc, err := service.New(prg, serviceConfig(serviceArguments(os.Args[1:])))
	if err != nil {
		fmt.Fprintf(os.Stderr, "service: %v\n", err)
		os.Exit(1)
	}
	// Windows 服务的 stderr 不可见，以服务方式运行时同时写系统事件日志。
	if runtime.GOOS == "windows" {
		if l, err := svc.Logger(nil); err == nil {
			prg.logf = teeInfo(logf, l)
			prg.errf = teeError(errf, l)
		}
	}

	prg.logf("unispoke %s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
	if err := svc.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		os.Exit(1)
	}
}

// runInteractive 以前台方式运行，收到 Ctrl+C 或 SIGTERM 后清理退出。
func runInteractive(prg *serviceProgram) {
	prg.logf("unispoke %s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
	if err := prg.Start(nil); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		os.Exit(1)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	_ = prg.Stop(nil)
}

func newLogger(opts options) (*slog.Logger, error) {
	level := slog.LevelInfo
	switch strings.ToLower(opts.logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	if opts.quiet {
		level = slog.LevelWarn
	}
	hopts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch strings.ToLower(opts.logFormat) {
	case "plain", "":
		handler = newPlainHandler(os.Stderr, hopts)
	case "logfmt":
		handler = slog.NewTextHandler(os.Stderr, hopts)
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, hopts)
	default:
		return nil, fmt.Errorf("unknown log format %q (use plain|logfmt|json)", opts.logFormat)
	}
	return slog.New(handler), nil
}

// runApplication 执行完整的连接与代理/隧道流程，stop 关闭后清理退出。
func runApplication(opts options, stop <-chan struct{}, logf func(string, ...any)) error {
	if (strings.EqualFold(opts.transport, "udp") || strings.EqualFold(opts.transport, "auto")) && opts.mss > 1200 {
		logf("mss capped to 1200 for UDP transport (gateway UDP frame is 1280 bytes)")
		opts.mss = 1200
	}

	cfg := tunnel.Config{
		Gateway:    opts.gateway,
		User:       opts.user,
		Password:   opts.password,
		Domain:     opts.domain,
		MAC:        opts.mac,
		Mode:       opts.mode,
		Transport:  opts.transport,
		Insecure:   opts.insecure,
		ServerName: opts.sni,
		CAFile:     opts.caFile,
		Timeout:    opts.timeout,
		Logf:       logf,
	}

	mgr := tunnel.NewManager(cfg)
	defer mgr.Close()

	sess, err := mgr.Ensure()
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	vip := sess.VIP()
	if vip == nil {
		return errors.New("gateway returned no virtual IP")
	}
	netCfg := mgr.Network()

	dnsIPs := netCfg.DNS
	if opts.dnsServer != "" {
		dnsIPs = nil
		for _, part := range strings.Split(opts.dnsServer, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			ip := net.ParseIP(part)
			if ip == nil {
				return fmt.Errorf("bad DNS server %q", part)
			}
			dnsIPs = append(dnsIPs, ip)
		}
	}
	logf("connected: vip=%s mask=%s mode=%s dns=%v routes=%d", vip, maskString(netCfg.Mask), opts.mode, dnsIPs, len(netCfg.Routes))

	if opts.dropAfter > 0 {
		go func() {
			time.Sleep(opts.dropAfter)
			if d, ok := sess.(interface{ Drop() }); ok {
				logf("test hook: dropping tunnel sockets")
				d.Drop()
			}
		}()
	}

	if opts.vpnMode {
		dev, err := vpn.Start(vpn.Config{
			Name:    opts.vpnName,
			Gateway: opts.gateway,
			VIP:     netCfg.VIP,
			Mask:    netCfg.Mask,
			MTU:     opts.mss + 40,
			Routes:  netCfg.Routes,
			DNS:     dnsIPs,
			Full:    opts.vpnFull,
			Debug:   opts.vpnDebug,
		}, mgr, logf)
		if err != nil {
			return fmt.Errorf("vpn: %w", err)
		}
		logf("VPN mode: adapter=%s vip=%s mtu=%d routes=%d full=%v", dev.Name(), vip, opts.mss+40, len(netCfg.Routes), opts.vpnFull)
		<-stop
		logf("shutting down")
		dev.Close()
		return nil
	}

	stack, err := netstack.NewStack(mgr, vip, opts.mss+40, logf)
	if err != nil {
		return fmt.Errorf("netstack: %w", err)
	}
	go stack.Run()

	dial := func(addr string) (net.Conn, error) { return stack.Dial(addr) }
	packet := func() (net.PacketConn, error) { return stack.ListenPacket() }
	lookup := func(host string) ([]net.IP, error) { return stack.LookupIP(host) }

	resolver := dnsrelay.NewResolver(packet, dnsIPs, opts.timeout, logf)
	if len(resolver.Servers) > 0 {
		stack.SetLookup(resolver.LookupIP)
		logf("tunnel DNS: %s", resolver.ServersString())
		if opts.dnsAdr != "" {
			srv := &dnsrelay.Server{Resolver: resolver, Addr: opts.dnsAdr, Logf: logf}
			go func() {
				if err := srv.Serve(); err != nil {
					logf("[dns] %v", err)
				}
			}()
		}
	} else if opts.dnsAdr != "" {
		logf("[dns] gateway did not provide DNS servers; relay disabled")
	}

	var listeners []net.Listener
	if opts.socksAdr != "" {
		l, err := net.Listen("tcp", opts.socksAdr)
		if err != nil {
			return fmt.Errorf("socks listen: %w", err)
		}
		listeners = append(listeners, l)
		logf("SOCKS5 proxy listening on %s", l.Addr())
		go func() { _ = proxy.ServeSOCKS5(l, dial, packet, lookup, logf) }()
	}
	if opts.httpAdr != "" {
		l, err := net.Listen("tcp", opts.httpAdr)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return fmt.Errorf("http listen: %w", err)
		}
		listeners = append(listeners, l)
		logf("HTTP proxy listening on %s", l.Addr())
		go func() { _ = proxy.ServeHTTP(l, dial, logf) }()
	}
	if len(listeners) == 0 {
		return errors.New("both -socks and -http are empty")
	}

	<-stop
	logf("shutting down")
	for _, l := range listeners {
		_ = l.Close()
	}
	return nil
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
