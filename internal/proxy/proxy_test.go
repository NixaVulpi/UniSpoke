package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func newRawOrigin(t *testing.T) (net.Listener, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var (
		mu    sync.Mutex
		lines []string
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				mu.Lock()
				lines = append(lines, strings.TrimSpace(line))
				mu.Unlock()
				for {
					h, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if h == "\r\n" || h == "\n" {
						break
					}
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}(conn)
		}
	}()
	return ln, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func TestHTTPProxyKeepAliveNormalizesAbsoluteForm(t *testing.T) {
	origin, received := newRawOrigin(t)
	defer origin.Close()

	dial := func(string) (net.Conn, error) { return net.Dial("tcp", origin.Addr().String()) }

	client, server := net.Pipe()
	defer client.Close()
	go handleHTTP(server, dial, func(string, ...any) {})
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	br := bufio.NewReader(client)
	for _, path := range []string{"/", "/openapi.json"} {
		if _, err := fmt.Fprintf(client, "GET http://172.22.1.103:4000%s HTTP/1.1\r\nHost: 172.22.1.103:4000\r\n\r\n", path); err != nil {
			t.Fatalf("write request %s: %v", path, err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read response for %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, resp.StatusCode)
		}
	}

	got := received()
	want := []string{"GET / HTTP/1.1", "GET /openapi.json HTTP/1.1"}
	if len(got) != len(want) {
		t.Fatalf("origin saw %d requests %q, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request %d = %q, want %q (absolute-form leaked to origin)", i, got[i], want[i])
		}
	}
}
