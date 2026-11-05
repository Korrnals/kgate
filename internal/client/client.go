// Package client is the mTLS client for the kgate daemon running on the router.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"kgate/internal/model"
)

func httpc(c *model.Config) *http.Client {
	ca, err := os.ReadFile(c.API.CA)
	if err != nil {
		fatal("CA не найден (%s): %v — сначала `kgate apply`", c.API.CA, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		fatal("CA файл битый: %s", c.API.CA)
	}
	cert, err := tls.LoadX509KeyPair(c.API.Cert, c.API.Key)
	if err != nil {
		fatal("клиентский сертификат: %v — сначала `kgate apply`", err)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS12,
		}},
	}
}

func fatal(f string, a ...any) {
	fmt.Printf("FAIL: "+f+"\n", a...)
	os.Exit(1)
}

func api(c *model.Config, method, path string, body io.Reader) ([]byte, int) {
	req, err := http.NewRequest(method, fmt.Sprintf("https://%s:%d%s", c.Host, c.API.Port, path), body)
	if err != nil {
		fatal("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc(c).Do(req)
	if err != nil {
		fatal("daemon %s:%d недоступен: %v — на роутере жив ли `S99kgate status`?", c.Host, c.API.Port, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return out, resp.StatusCode
}

func pretty(b []byte) string {
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		lines := []string{}
		for k, v := range m {
			lines = append(lines, fmt.Sprintf("%-9s %v", k+":", v))
		}
		return strings.Join(lines, "\n")
	}
	return string(b)
}

func Status(c *model.Config) {
	b, code := api(c, "GET", "/api/v1/status", nil)
	fmt.Println("=== status (mTLS", code, ") ===")
	fmt.Println(pretty(b))
}

// WaitProxyUp polls the daemon until Proxy0 is up (deploy uses it to wait out
// the autoup delay instead of failing the battery at +5s). Soft-fails on
// transient connection errors and keeps polling.
func WaitProxyUp(c *model.Config, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	client := httpc(c)
	url := fmt.Sprintf("https://%s:%d/api/v1/status", c.Host, c.API.Port)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(b), "state: up") {
				return true
			}
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

func Verify(c *model.Config) {
	b, code := api(c, "GET", "/api/v1/verify", nil)
	fmt.Println("=== verify daemon (mTLS", code, ") ===")
	fmt.Println(pretty(b))
	ip, err := socksFetchIP(c)
	if err != nil {
		fatal("локальный socks-тест: %v", err)
	}
	fmt.Printf("%-9s %s (ожидаем NL exit)\n", "socks:", ip)
}

// socksFetchIP asks api.ipify.org through the router's SOCKS5 (port 1080)
// and returns the exit IP — the pure-Go replacement of the curl battery.
func socksFetchIP(c *model.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := socksConnect(ctx, fmt.Sprintf("%s:1080", c.Host), "api.ipify.org", 443)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "api.ipify.org", MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("tls через туннель: %w", err)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org/", nil)
	tr := &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return tlsConn, nil // single-purpose client: the tunnelled conn is pre-established
	}}
	resp, err := (&http.Client{Timeout: 12 * time.Second, Transport: tr}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api.ipify.org: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func Toggle(c *model.Config, state string) {
	b, _ := api(c, "POST", "/api/v1/toggle",
		strings.NewReader(`{"state":"`+state+`"}`))
	fmt.Println("=== toggle", state, "===")
	fmt.Println(pretty(b))
}

func Ruexit(c *model.Config, mode string) {
	b, _ := api(c, "POST", "/api/v1/ruexit",
		strings.NewReader(`{"mode":"`+mode+`"}`))
	fmt.Println("=== ruexit (", mode, ") ===")
	fmt.Println(pretty(b))
}

func Logs(c *model.Config) {
	b, _ := api(c, "GET", "/api/v1/logs", nil)
	fmt.Println(string(b))
}

func Reboot(c *model.Config) {
	req, _ := http.NewRequest("POST", fmt.Sprintf("https://%s:%d/api/v1/reboot", c.Host, c.API.Port), nil)
	resp, err := httpc(c).Do(req)
	if err != nil {
		// connection drop during reboot is expected: the daemon goes down with ndm
		fmt.Println("reboot: команда принята (обрыв соединения нормален, роутер ребутается ~2 мин); затем: kgate status")
		return
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Println("reboot:", strings.TrimSpace(string(b)))
}
