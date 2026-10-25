package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"
)

type TLSOptions struct {
	ServerName string
	Insecure   bool
	CAFile     string
	Timeout    time.Duration
}

func dialTLS(addr string, o TLSOptions) (net.Conn, error) {
	cfg := &tls.Config{ServerName: o.ServerName}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		cfg.ServerName = host
	}
	if o.Insecure {
		cfg.InsecureSkipVerify = true
	} else if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca file %s contains no certificates", o.CAFile)
		}
		cfg.RootCAs = pool
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}
