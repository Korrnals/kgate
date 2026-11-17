package client

// Тесты `kgate doctor` (v1.10.0): каждая проверка на сеам-моках, OK/FAIL и
// код выхода. Живой роутер не нужен — все внешние эффекты в doctorDeps.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fmt"
	"kgate/internal/build"
	"kgate/internal/model"
	"net/http"
	"net/http/httptest"
)

func doctorTestConfig(t *testing.T) *model.Config {
	t.Helper()
	c := &model.Config{}
	c.Panel.Password = "pw" // панель включена
	// живой конфиг sing-box для серт-проверки: минимальный hy2-outbound
	cfg := filepath.Join(t.TempDir(), "sing-box-config.json")
	if err := os.WriteFile(cfg, []byte(`{"outbounds":[{"type":"hy2","server":"cdn.srwx.app","server_port":443,"tls":{"server_name":"cdn.srwx.app"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c.Daemon.SingBoxConfig = cfg
	return c
}

func okDeps() doctorDeps {
	return doctorDeps{
		daemonStatus: func() (string, error) { return build.Version, nil },
		ndmcShow: func(cmd string) (string, error) {
			if cmd == "show ip policy" {
				return "policy, name = VPN, description = t\npolicy, name = NO-VPN, description = d\n", nil
			}
			// running-config: привязки сходятся с пустой декларацией (нет policies/dns в конфиге)
			return "", nil
		},
		tunnelProbe: func(proxy string) (int, error) { return 204, nil },
		certProbe:   func(server, sni string) error { return nil },
		panelProbe:  func(url string) (int, error) { return 200, nil },
	}
}

func doctorRun(t *testing.T, deps doctorDeps) (string, int) {
	t.Helper()
	var buf bytes.Buffer
	code := runDoctor(doctorTestConfig(t), deps, &buf)
	return buf.String(), code
}

func TestDoctor_AllOK(t *testing.T) {
	out, code := doctorRun(t, okDeps())
	if code != 0 {
		t.Fatalf("exit = %d, want 0:\n%s", code, out)
	}
	if strings.Count(out, "FAIL") != 0 || !strings.Contains(out, "все проверки зелёные") {
		t.Fatalf("expected all-OK table:\n%s", out)
	}
}

func TestDoctor_VersionMismatch(t *testing.T) {
	deps := okDeps()
	deps.daemonStatus = func() (string, error) { return "1.9.2", nil } // инцидент 16.11
	out, code := doctorRun(t, deps)
	if code != 1 {
		t.Fatalf("exit = %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "бинарник "+build.Version) || !strings.Contains(out, "демон 1.9.2") ||
		!strings.Contains(out, "S99kgate restart") {
		t.Fatalf("version mismatch not reported with restart hint:\n%s", out)
	}
}

func TestDoctor_DaemonDown(t *testing.T) {
	deps := okDeps()
	deps.daemonStatus = func() (string, error) { return "", errors.New("HTTP 000") }
	out, code := doctorRun(t, deps)
	if code != 1 || !strings.Contains(out, "FAIL") || !strings.Contains(out, "S99kgate status") {
		t.Fatalf("daemon-down check wrong (exit=%d):\n%s", code, out)
	}
}

func TestDoctor_SocksProbeFail(t *testing.T) {
	deps := okDeps()
	deps.tunnelProbe = func(proxy string) (int, error) { return 0, errors.New("connection refused") }
	out, code := doctorRun(t, deps)
	if code != 1 || !strings.Contains(out, "туннель") || !strings.Contains(out, "connection refused") {
		t.Fatalf("socks fail not surfaced:\n%s", out)
	}
}

func TestDoctor_SocksWrongStatus(t *testing.T) {
	deps := okDeps()
	deps.tunnelProbe = func(proxy string) (int, error) { return 200, nil } // не generate_204
	out, code := doctorRun(t, deps)
	if code != 1 || !strings.Contains(out, "ожидался 204") {
		t.Fatalf("non-204 egress must FAIL:\n%s", out)
	}
}

func TestDoctor_CertMismatch(t *testing.T) {
	deps := okDeps()
	deps.certProbe = func(server, sni string) error {
		return errors.New("x509: certificate is valid for example.com, not cdn.srwx.app")
	}
	out, code := doctorRun(t, deps)
	if code != 1 || !strings.Contains(out, "серт сервера") || !strings.Contains(out, "умрёт при следующем handle") {
		t.Fatalf("cert mismatch not warned:\n%s", out)
	}
}

func TestDoctor_PolicyDrift(t *testing.T) {
	deps := okDeps()
	c := doctorTestConfig(t)
	c.Policies.Segments = map[string]string{"Home": "VPN"}
	deps.ndmcShow = func(cmd string) (string, error) {
		if cmd == "show ip policy" {
			return "policy, name = VPN\n", nil // NO-VPN политика отсутствует
		}
		return "ip hotspot\n  policy Home NO-VPN\n", nil // живая привязка расходится
	}
	var buf bytes.Buffer
	code := runDoctor(c, deps, &buf)
	if code != 1 || !strings.Contains(buf.String(), "политики (дрейф)") ||
		!strings.Contains(buf.String(), "kgate apply") {
		t.Fatalf("policy drift not reported:\n%s", buf.String())
	}
}

func TestDoctor_DNSDrift(t *testing.T) {
	deps := okDeps()
	c := doctorTestConfig(t)
	c.DNS.Hosts = map[string]string{"nas.home.arpa": "192.168.1.60"}
	var buf bytes.Buffer
	code := runDoctor(c, deps, &buf)
	if code != 1 || !strings.Contains(buf.String(), "dns.hosts (дрейф)") {
		t.Fatalf("dns drift not reported:\n%s", buf.String())
	}
}

func TestDoctor_PanelOffAndUp(t *testing.T) {
	c := doctorTestConfig(t)
	c.Panel.Password = "" // панель выключена = OK, не FAIL
	var buf bytes.Buffer
	if code := runDoctor(c, okDeps(), &buf); code != 0 || !strings.Contains(buf.String(), "выключена") {
		t.Fatalf("panel-off must be OK:\n%s", buf.String())
	}
}

func TestDoctor_PanelDown(t *testing.T) {
	deps := okDeps()
	deps.panelProbe = func(url string) (int, error) { return 0, errors.New("refused") }
	out, code := doctorRun(t, deps)
	if code != 1 || !strings.Contains(out, "панель") {
		t.Fatalf("panel-down must FAIL:\n%s", out)
	}
}

func TestServerEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"outbounds":[{"type":"direct"},{"type":"hy2","server":"cdn.srwx.app","server_port":443,"tls":{"server_name":"cdn.srwx.app"}}]}`)
	server, sni, err := serverEndpoint(path)
	if err != nil || server != "cdn.srwx.app" || sni != "cdn.srwx.app" {
		t.Fatalf("serverEndpoint = (%q,%q,%v)", server, sni, err)
	}
	write(`{"outbounds":[{"type":"direct"}]}`)
	if _, _, err := serverEndpoint(path); err == nil {
		t.Fatal("config без tls.server_name должен давать ошибку")
	}
}

// Router-local fallback: mTLS-сёртов нет, но панель с паролем отвечает —
// версия демона должна приходить из /kgate/api/status (инцидент 16.11:
// doctor на роутере падал с «CA не найден» до этого fallback'а).
func TestPanelDaemonVersion_Fallback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kgate/login":
			if r.PostFormValue("password") != "pw" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "kgate_panel", Value: "t"})
			w.WriteHeader(http.StatusSeeOther)
		case "/kgate/api/status":
			for _, ck := range r.Cookies() {
				if ck.Name == "kgate_panel" && ck.Value == "t" {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{"version":"1.10.0","singbox":"running"}`)
					return
				}
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	v, err := panelDaemonVersion(srv.URL, "pw")
	if err != nil {
		t.Fatalf("panel fallback: %v", err)
	}
	if v != "1.10.0" {
		t.Fatalf("version = %q, want 1.10.0", v)
	}
	if _, err := panelDaemonVersion(srv.URL, "wrong"); err == nil {
		t.Fatal("неверный пароль должен давать ошибку")
	}
}
