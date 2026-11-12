// Exported socks5 exit-IP probe: the daemon's web panel reuses this
// (internal/client owns the socks5 dialer — panel.go must not duplicate it).
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// FetchExitIP asks api.ipify.org through the given SOCKS5 proxy (the
// router-side tunnel: 127.0.0.1:1080 upstream / relay). Returns the
// tunnel's public exit IP; an error means the tunnel is not carrying
// traffic right now.
func FetchExitIP(proxyAddr string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := socksConnect(ctx, proxyAddr, "api.ipify.org", 443)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	tr := &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return tls.Client(conn, &tls.Config{ServerName: "api.ipify.org", MinVersion: tls.VersionTLS12}), nil
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return "", fmt.Errorf("exit-ip запрос: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
