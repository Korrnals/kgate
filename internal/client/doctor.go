// kgate doctor — самодиагностика НА РОУТЕРЕ (v1.10.0). Все проверки кодифицируют
// реальные инциденты поля ноября 2026:
//   - версия (инцидент 16.11: бинарник апгрейднули до 1.9.3, демон крутил
//     старый код 4 дня) — диск vs работающий демон;
//   - туннель (инциденты x509 12.11/16.11: egress умирал/серт-мисматч, а
//     `state: up` продолжал гореть) — реальный запрос через socks-релей;
//   - серт сервера — TLS-рукопожатие до сервера с проверкой SAN ДО того,
//     как туннель умрёт при следующем handle;
//   - политики / dns.hosts — dry-прогон декларативных планов (реюз
//     internal/deploy): дрейф = «кто-то правил ndm руками»;
//   - панель — логин-страница отвечает, если панель включена.
//
// doctor ТОЛЬКО ЧИТАЕТ (ndmc show + mTLS /status + сетевые проб): ndm-записей
// не делает by design. Сеам doctorDeps позволяет гонять проверки в тестах
// с моками без живого роутера.
package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"kgate/internal/build"
	"kgate/internal/deploy"
	"kgate/internal/model"
)

// doctorDeps — сеам внешних эффектов доктора; каждая функция мокается в тестах.
type doctorDeps struct {
	daemonStatus func() (version string, err error)    // mTLS /api/v1/status
	ndmcShow     func(cmd string) (string, error)      // локальный read-only ndmc show
	tunnelProbe  func(proxy string) (int, error)       // socks5 → generate_204
	certProbe    func(server string, sni string) error // TLS-рукопожатие + SAN
	panelProbe   func(url string) (int, error)         // GET login-страницы
}

type checkResult struct {
	name   string
	ok     bool
	detail string
	hint   string // подсказка только для FAIL
}

func defaultDoctorDeps(c *model.Config) doctorDeps {
	return doctorDeps{
		daemonStatus: func() (string, error) {
			// Двухступенчатый доступ к версии РАБОТАЮЩЕГО демона (инцидент 16.11):
			// 1) mTLS API — control-node case (клиентские серты есть);
			// 2) fallback: панель с паролем из конфига — router-local case:
			//    CA-ключ живёт на control-node, локальных клиентских сертов
			//    на роутере нет by construction, mTLS сам-к-себе невозможен.
			if v, err := mtlsDaemonVersion(c); err == nil {
				return v, nil
			}
			v, err := panelDaemonVersion(fmt.Sprintf("https://127.0.0.1:%d", c.Panel.Port), c.Panel.Password)
			if err != nil {
				return "", fmt.Errorf("mTLS и панель недоступны: %w", err)
			}
			return v, nil
		},
		ndmcShow: func(cmd string) (string, error) {
			out, err := exec.Command("/bin/ndmc", "-c", cmd).CombinedOutput()
			if err != nil && strings.TrimSpace(string(out)) == "" {
				return "", fmt.Errorf("ndmc %q: %v", cmd, err)
			}
			return string(out), nil
		},
		tunnelProbe: func(proxy string) (int, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := socksConnect(ctx, proxy, "www.google.com", 443)
			if err != nil {
				return 0, err
			}
			defer conn.Close()
			tr := &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Client(conn, &tls.Config{ServerName: "www.google.com", MinVersion: tls.VersionTLS12}), nil
			}}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.google.com/generate_204", nil)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				return 0, err
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64))
			return resp.StatusCode, nil
		},
		certProbe: func(server, sni string) error {
			conn, err := tls.Dial("tcp", server+":443", &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
			if err != nil {
				return err
			}
			defer conn.Close()
			// явная SAN-проверка: сообщение понятнее голой verify-ошибки
			cert := conn.ConnectionState().PeerCertificates[0]
			for _, n := range cert.DNSNames {
				if n == sni || (strings.HasPrefix(sni, "*.") && strings.HasSuffix(n, strings.TrimPrefix(sni, "*"))) {
					return nil
				}
			}
			if sni == cert.Subject.CommonName {
				return nil
			}
			return fmt.Errorf("серт не покрывает SNI %q (SAN: %v)", sni, cert.DNSNames)
		},
		panelProbe: func(url string) (int, error) {
			cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // self-signed панельный серт
			}}
			resp, err := cl.Get(url)
			if err != nil {
				return 0, err
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64))
			return resp.StatusCode, nil
		},
	}
}

// serverEndpoint достаёт из живого конфига sing-box первый outbound с TLS
// (hy2/vless/...): server + tls.server_name — цель серт-проверки доктора.
func serverEndpoint(singboxConfig string) (server, sni string, err error) {
	raw, err := os.ReadFile(singboxConfig)
	if err != nil {
		return "", "", fmt.Errorf("читаю %s: %w", singboxConfig, err)
	}
	var cfg struct {
		Outbounds []struct {
			Type   string `json:"type"`
			Server string `json:"server"`
			TLS    struct {
				ServerName string `json:"server_name"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", "", fmt.Errorf("парсю %s: %w", singboxConfig, err)
	}
	for _, ob := range cfg.Outbounds {
		if ob.Server != "" && ob.TLS.ServerName != "" {
			return ob.Server, ob.TLS.ServerName, nil
		}
	}
	return "", "", fmt.Errorf("в %s нет outbound с tls.server_name", singboxConfig)
}

// runDoctor выполняет все проверки, печатает таблицу и возвращает код выхода
// (1 = есть FAIL). Инъекция deps — точка моков в тестах.
func runDoctor(c *model.Config, deps doctorDeps, w io.Writer) int {
	var results []checkResult
	fail := func(r checkResult) {
		if !r.ok {
			results = append(results, r)
			return
		}
		results = append(results, r)
	}

	// a. версия: диск vs работающий демон
	dv, err := deps.daemonStatus()
	if err != nil {
		fail(checkResult{"версия демона", false, "mTLS /status: " + err.Error(),
			"проверь, жив ли демон: S99kgate status"})
	} else if dv == build.Version {
		fail(checkResult{"версия демона", true, dv + " (= бинарнику " + build.Version + ")", ""})
	} else {
		fail(checkResult{"версия демона", false,
			"бинарник " + build.Version + ", демон " + dv + " — рестарт не активировал апгрейд",
			"на роутере: S99kgate restart"})
	}

	// b. туннель: socks → generate_204 (инцидент x509 12.11/16.11)
	code, err := deps.tunnelProbe(c.Daemon.RelayListen)
	if err != nil {
		fail(checkResult{"туннель (egress)", false, c.Daemon.RelayListen + ": " + err.Error(),
			"туннель не несёт трафик: S99kgate status, логи sing-box (kgate logs singbox), сервер жив?"})
	} else if code == http.StatusNoContent {
		fail(checkResult{"туннель (egress)", true, fmt.Sprintf("%s → generate_204", c.Daemon.RelayListen), ""})
	} else {
		fail(checkResult{"туннель (egress)", false,
			fmt.Sprintf("%s → HTTP %d (ожидался 204)", c.Daemon.RelayListen, code),
			"прокси отвечает, но egress ведёт не туда — проверь сервер/серты"})
	}

	// c. серт сервера: рукопожатие + SAN ДО смерти туннеля
	server, sni, err := serverEndpoint(c.Daemon.SingBoxConfig)
	if err != nil {
		fail(checkResult{"серт сервера", false, err.Error(),
			"конфиг sing-box не читается/без tls.server_name — проверь " + c.Daemon.SingBoxConfig})
	} else if err := deps.certProbe(server, sni); err != nil {
		fail(checkResult{"серт сервера", false, fmt.Sprintf("%s:443 SNI=%s: %v", server, sni, err),
			"серт не покрывает SNI → туннель умрёт при следующем handle — обнови серт/подписку заранее"})
	} else {
		fail(checkResult{"серт сервера", true, fmt.Sprintf("%s:443 SNI=%s OK", server, sni), ""})
	}

	// d/e. политики + dns.hosts: dry-прогон декларативных планов
	runCfg, rcErr := deps.ndmcShow("show running-config")
	ipPolicy, ipErr := deps.ndmcShow("show ip policy")
	if rcErr != nil || ipErr != nil {
		fail(checkResult{"политики (дрейф)", false, firstErr(rcErr, ipErr),
			"ndmc не отвечает — read-only show не должен падать"})
	} else {
		plan := deploy.PolicyPlan(runCfg, ipPolicy, c.Policies)
		if len(plan) == 0 {
			fail(checkResult{"политики (дрейф)", true, "план пуст — декларация сходится", ""})
		} else {
			fail(checkResult{"политики (дрейф)", false, fmt.Sprintf("дрейф: %d вербов", len(plan)),
				"кто-то правил ndm руками — выполни kgate apply"})
		}
		dnsPlan := deploy.DNSHostsPlan(runCfg, c.DNS.Hosts)
		if len(dnsPlan) == 0 {
			fail(checkResult{"dns.hosts (дрейф)", true, "план пуст — декларация сходится", ""})
		} else {
			fail(checkResult{"dns.hosts (дрейф)", false, fmt.Sprintf("дрейф: %d вербов", len(dnsPlan)),
				"выполни kgate apply"})
		}
	}

	// f. панель: логин-страница, если панель включена
	if c.Panel.Password == "" {
		fail(checkResult{"панель", true, "выключена (panel.password не задан)", ""})
	} else if code, err := deps.panelProbe(fmt.Sprintf("https://127.0.0.1:%d/kgate/login", c.Panel.Port)); err != nil {
		fail(checkResult{"панель", false, err.Error(),
			"панель включена, но не отвечает — S99kgate status, порт " + fmt.Sprint(c.Panel.Port)})
	} else if code != http.StatusOK {
		fail(checkResult{"панель", false, fmt.Sprintf("HTTP %d (ожидался 200)", code),
			"логин-страница панели отвечает не-200 — проверь S99kgate логи"})
	} else {
		fail(checkResult{"панель", true, fmt.Sprintf("https://127.0.0.1:%d/kgate/login → 200", c.Panel.Port), ""})
	}

	fmt.Fprintln(w, "=== kgate doctor ===")
	okAll := true
	for _, r := range results {
		mark, cls := "OK  ", ""
		if !r.ok {
			mark, cls, okAll = "FAIL", " (!!)", false
		}
		fmt.Fprintf(w, "%s %-20s %s%s\n", mark, r.name, r.detail, cls)
		if r.hint != "" {
			fmt.Fprintf(w, "     ↳ %s\n", r.hint)
		}
	}
	if okAll {
		fmt.Fprintln(w, "итог: все проверки зелёные")
		return 0
	}
	fmt.Fprintln(w, "итог: есть проблемы — см. подсказки выше")
	return 1
}

func firstErr(errs ...error) string {
	for _, e := range errs {
		if e != nil {
			return e.Error()
		}
	}
	return ""
}

// Doctor — CLI-команда; запускается НА РОУТЕРЕ (kgate.yaml с секцией daemon).
func Doctor(c *model.Config) {
	os.Exit(runDoctor(c, defaultDoctorDeps(c), os.Stdout))
}

// mtlsDaemonVersion — версия работающего демона через mTLS API (control-node:
// клиентские серты есть). Ошибки возвращаются, не фаталятся — вызывающий
// деградирует на панельный fallback.
func mtlsDaemonVersion(c *model.Config) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:%d/api/v1/status", c.Host, c.API.Port), nil)
	if err != nil {
		return "", err
	}
	resp, err := httpc(c).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var st struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return "", err
	}
	if st.Version == "" {
		return "", errors.New("демон без поля version — старый код, рестартуй S99kgate")
	}
	return st.Version, nil
}

// panelDaemonVersion — версия через панель (router-local fallback: локальных
// клиентских mTLS-сёртов на роутере нет by construction — CA-ключ на
// control-node). Логин паролем из конфига → cookie → /kgate/api/status.
func panelDaemonVersion(base, password string) (string, error) {
	if password == "" {
		return "", errors.New("panel.password не задан — панель выключена")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	cl := &http.Client{
		Timeout:   8 * time.Second,
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	loginURL := base + "/kgate/login"
	form := url.Values{"password": {password}}
	lr, err := cl.Post(loginURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	lr.Body.Close()
	if lr.StatusCode != http.StatusSeeOther && lr.StatusCode != http.StatusOK {
		return "", fmt.Errorf("панель login: HTTP %d (пароль верен?)", lr.StatusCode)
	}
	sr, err := cl.Get(base + "/kgate/api/status")
	if err != nil {
		return "", err
	}
	defer sr.Body.Close()
	if sr.StatusCode >= 400 {
		return "", fmt.Errorf("панель status: HTTP %d", sr.StatusCode)
	}
	var st struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(sr.Body).Decode(&st); err != nil {
		return "", err
	}
	if st.Version == "" {
		return "", errors.New("панель без поля version — демон старого кода (до 1.10.0), рестартуй S99kgate")
	}
	return st.Version, nil
}
