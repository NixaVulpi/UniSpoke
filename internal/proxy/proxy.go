// Package proxy 实现 SOCKS5 与 HTTP 代理前端。
package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/gosocks5"
)

type DialFunc func(addr string) (net.Conn, error)

type PacketFunc func() (net.PacketConn, error)

type LookupFunc func(host string) ([]net.IP, error)

// ServeSOCKS5 提供 CONNECT 与 UDP ASSOCIATE（RFC 1928）。
func ServeSOCKS5(l net.Listener, dial DialFunc, packet PacketFunc, lookup LookupFunc, logf func(string, ...any)) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go handleSOCKS5(c, dial, packet, lookup, logf)
	}
}

func handleSOCKS5(c net.Conn, dial DialFunc, newPacket PacketFunc, lookup LookupFunc, logf func(string, ...any)) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)

	methods, err := gosocks5.ReadMethods(br)
	if err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == gosocks5.MethodNoAuth {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_ = gosocks5.WriteMethod(gosocks5.MethodNoAcceptable, c)
		return
	}
	if err := gosocks5.WriteMethod(gosocks5.MethodNoAuth, c); err != nil {
		return
	}

	req, err := gosocks5.ReadRequest(br)
	if err != nil {
		return
	}
	switch req.Cmd {
	case gosocks5.CmdConnect:
		handleSOCKS5Connect(c, br, req, dial, logf)
	case gosocks5.CmdUdp:
		handleSOCKS5UDP(c, req, newPacket, lookup, logf)
	default:
		_ = gosocks5.NewReply(gosocks5.CmdUnsupported, nil).Write(c)
	}
}

func handleSOCKS5Connect(c net.Conn, br *bufio.Reader, req *gosocks5.Request, dial DialFunc, logf func(string, ...any)) {
	target := req.Addr.String()
	up, err := dial(target)
	if err != nil {
		logf("[socks5] dial %s: %v", target, err)
		_ = gosocks5.NewReply(gosocks5.NetUnreachable, nil).Write(c)
		return
	}
	defer up.Close()
	logf("[socks5] %s -> %s", c.RemoteAddr(), target)
	if err := gosocks5.NewReply(gosocks5.Succeeded, nil).Write(c); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	relay(c, br, up)
}

// handleSOCKS5UDP 建立 UDP 关联，控制连接关闭即终止。
func handleSOCKS5UDP(c net.Conn, req *gosocks5.Request, newPacket PacketFunc, lookup LookupFunc, logf func(string, ...any)) {
	_ = c.SetDeadline(time.Time{})
	_ = req

	relayConn, err := listenRelay(c)
	if err != nil {
		logf("[socks5] udp listen: %v", err)
		_ = gosocks5.NewReply(gosocks5.Failure, nil).Write(c)
		return
	}
	defer relayConn.Close()

	up, err := newPacket()
	if err != nil {
		logf("[socks5] udp tunnel: %v", err)
		_ = gosocks5.NewReply(gosocks5.Failure, nil).Write(c)
		return
	}
	defer up.Close()

	bnd, err := gosocks5.NewAddr(relayConn.LocalAddr().String())
	if err != nil {
		_ = gosocks5.NewReply(gosocks5.Failure, nil).Write(c)
		return
	}
	if err := gosocks5.NewReply(gosocks5.Succeeded, bnd).Write(c); err != nil {
		return
	}
	logf("[socks5] UDP %s relay=%s", c.RemoteAddr(), relayConn.LocalAddr())

	peerIP := remoteIP(c)
	var (
		clientMu   sync.RWMutex
		clientAddr *net.UDPAddr
	)

	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			close(done)
			_ = relayConn.Close()
			_ = up.Close()
		})
	}
	defer stop()

	go func() {
		_, _ = io.Copy(io.Discard, c)
		stop()
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := relayConn.ReadFromUDP(buf)
			if err != nil {
				stop()
				return
			}
			if peerIP != nil && !sameIP(src.IP, peerIP) {
				continue
			}
			clientMu.Lock()
			clientAddr = src
			clientMu.Unlock()

			hdr, payload, ok := parseUDPDatagram(buf[:n])
			if !ok || hdr.Frag != 0 {
				continue
			}
			dst, err := resolveUDPAddr(hdr.Addr, lookup)
			if err != nil {
				continue
			}
			if _, err := up.WriteTo(payload, dst); err != nil {
				logf("[socks5] udp send %s: %v", dst, err)
			}
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := up.ReadFrom(buf)
			if err != nil {
				stop()
				return
			}
			dst, ok := src.(*net.UDPAddr)
			if !ok {
				continue
			}
			clientMu.RLock()
			to := clientAddr
			clientMu.RUnlock()
			if to == nil {
				continue
			}
			out, err := encodeUDPDatagram(dst, buf[:n])
			if err != nil {
				continue
			}
			if _, err := relayConn.WriteToUDP(out, to); err != nil {
				logf("[socks5] udp reply %s: %v", to, err)
			}
		}
	}()

	<-done
}

// withDefaultPort 在缺少端口时补默认端口，正确保留 IPv6 字面量的方括号。
func withDefaultPort(hostport, def string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return hostport + ":" + def
	}
	if strings.Contains(hostport, ":") {
		return hostport
	}
	return net.JoinHostPort(hostport, def)
}

func listenRelay(c net.Conn) (*net.UDPConn, error) {
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("bad local address %q", host)
	}
	// 绑定到控制连接的本地 IP：多网卡时保证 BND.ADDR 与回包源地址一致。
	return net.ListenUDP("udp", &net.UDPAddr{IP: ip})
}

func remoteIP(c net.Conn) net.IP {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP
	}
	return nil
}

func sameIP(a, b net.IP) bool {
	if a4, b4 := a.To4(), b.To4(); a4 != nil && b4 != nil {
		return a4.Equal(b4)
	}
	return a.Equal(b)
}

func parseUDPDatagram(b []byte) (*gosocks5.UDPHeader, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	h := &gosocks5.UDPHeader{
		Rsv:  binary.BigEndian.Uint16(b[:2]),
		Frag: b[2],
		Addr: &gosocks5.Addr{},
	}
	r := bytes.NewReader(b[3:])
	if _, err := h.Addr.ReadFrom(r); err != nil {
		return nil, nil, false
	}
	return h, b[len(b)-r.Len():], true
}

func encodeUDPDatagram(src *net.UDPAddr, data []byte) ([]byte, error) {
	addr := &gosocks5.Addr{
		Host: src.IP.String(),
		Port: uint16(src.Port),
	}
	var buf bytes.Buffer
	buf.Grow(3 + 1 + net.IPv6len + 2 + len(data))
	if _, err := gosocks5.NewUDPHeader(0, 0, addr).WriteTo(&buf); err != nil {
		return nil, err
	}
	buf.Write(data)
	return buf.Bytes(), nil
}

func resolveUDPAddr(a *gosocks5.Addr, lookup LookupFunc) (*net.UDPAddr, error) {
	if a == nil {
		return nil, errors.New("socks5: nil udp address")
	}
	if ip := net.ParseIP(a.Host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: int(a.Port)}, nil
	}
	if lookup == nil {
		lookup = net.LookupIP
	}
	ips, err := lookup(a.Host)
	if err != nil {
		return nil, err
	}
	for _, cand := range ips {
		if v4 := cand.To4(); v4 != nil {
			return &net.UDPAddr{IP: v4, Port: int(a.Port)}, nil
		}
	}
	return nil, fmt.Errorf("socks5: no IPv4 address for %s", a.Host)
}

// ServeHTTP 接受 CONNECT 与 absolute-form 请求。
func ServeHTTP(l net.Listener, dial DialFunc, logf func(string, ...any)) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go handleHTTP(c, dial, logf)
	}
}

func handleHTTP(c net.Conn, dial DialFunc, logf func(string, ...any)) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)

	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})

		if req.Method == http.MethodConnect {
			handleHTTPConnect(bw, br, c, req, dial, logf)
			return
		}
		if !forwardRequest(c, bw, br, req, dial, logf) {
			return
		}
	}
}

func handleHTTPConnect(bw *bufio.Writer, br *bufio.Reader, c net.Conn, req *http.Request, dial DialFunc, logf func(string, ...any)) {
	target := withDefaultPort(req.Host, "443")
	up, err := dial(target)
	if err != nil {
		logf("[http] connect %s: %v", target, err)
		writeHTTPError(bw, 502, "Bad Gateway")
		return
	}
	defer up.Close()
	logf("[http] CONNECT %s", target)
	if _, err := io.WriteString(bw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := bw.Flush(); err != nil {
		return
	}
	relay(c, br, up)
}

func forwardRequest(c net.Conn, bw *bufio.Writer, br *bufio.Reader, req *http.Request, dial DialFunc, logf func(string, ...any)) bool {
	if req.URL == nil || req.URL.Host == "" {
		writeHTTPError(bw, 400, "Bad Request")
		return false
	}
	host := withDefaultPort(req.URL.Host, "80")
	up, err := dial(host)
	if err != nil {
		logf("[http] %s %s: %v", req.Method, host, err)
		writeHTTPError(bw, 502, "Bad Gateway")
		return false
	}
	defer up.Close()
	logf("[http] %s %s%s", req.Method, host, req.URL.Path)

	upgrade := strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") &&
		req.Header.Get("Upgrade") != ""

	// 改写为源站格式（origin-form），并清理逐跳头部。
	out := new(http.Request)
	*out = *req
	out.RequestURI = ""
	out.URL.Scheme = ""
	out.URL.Host = ""
	out.Header = req.Header.Clone()
	stripHopHeaders(out.Header, upgrade)
	if err := out.Write(up); err != nil {
		return false
	}

	upBr := bufio.NewReader(up)
	for {
		resp, err := http.ReadResponse(upBr, req)
		if err != nil {
			writeHTTPError(bw, 502, "Bad Gateway")
			return false
		}
		// 1xx 中间响应转发后继续等待最终响应。
		if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
			if err := resp.Write(bw); err != nil {
				return false
			}
			_ = resp.Body.Close()
			if err := bw.Flush(); err != nil {
				return false
			}
			continue
		}
		if err := resp.Write(bw); err != nil {
			return false
		}
		_ = resp.Body.Close()
		if err := bw.Flush(); err != nil {
			return false
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			// 协议升级（如 WebSocket）：此后为裸字节双向转发。
			relayBoth(c, br, up, upBr)
			return false
		}
		return !req.Close && !resp.Close
	}
}

func writeHTTPError(bw *bufio.Writer, code int, text string) {
	fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, text)
	_ = bw.Flush()
}

// stripHopHeaders 移除仅对单段连接有意义的逐跳头部。
func stripHopHeaders(h http.Header, upgrade bool) {
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
	for _, k := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding"} {
		h.Del(k)
	}
	if upgrade {
		h.Set("Connection", "Upgrade")
	} else {
		h.Del("Upgrade")
	}
}

func relay(client net.Conn, clientBuf *bufio.Reader, upstream net.Conn) {
	relayBoth(client, clientBuf, upstream, nil)
}

func relayBoth(client net.Conn, clientBuf *bufio.Reader, upstream net.Conn, upstreamBuf *bufio.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if clientBuf != nil {
			_, _ = io.Copy(upstream, clientBuf)
		} else {
			_, _ = io.Copy(upstream, client)
		}
		if tc, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = upstream.Close()
		}
	}()
	go func() {
		defer wg.Done()
		if upstreamBuf != nil {
			_, _ = io.Copy(client, upstreamBuf)
		} else {
			_, _ = io.Copy(client, upstream)
		}
		if tc, ok := client.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}
