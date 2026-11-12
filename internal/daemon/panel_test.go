package daemon

// Тесты веб-панели (slice v1.9.0): auth, rate-limit, toggle-делегация в
// кодовый путь mTLS API, Origin-guard, policies через ndmc-seam, конфиг
// panel-секции тестируются частично здесь, частично в internal/model.

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"kgate/internal/certs"
	"time"

	"kgate/internal/model"
	"kgate/internal/policy"
)

func newPanelTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	cfg := &model.Config{}
	cfg.Panel.Password = "test-pw"
	cfg.Panel.Port = 8443
	d := New(cfg)
	d.intentPath = filepath.Join(t.TempDir(), "intent")
	// ndmc-seam: show-вербы отдают fixture-поверхность (reюз формата
	// internal/policy), мутации — успех; toggle-путь пишет intent и видит его.
	d.ndmcFn = func(cmd string) string {
		switch cmd {
		case policy.ShowHotspotCmd:
			return `
          interface: Bridge0
             description: "Home"
                  active: yes
                hostname: "phone"
                     mac: aa:bb:cc:dd:ee:01
                      ip: 192.168.1.52
                  policy:
                   active: yes
`
		case policy.ShowRunningConfigCmd:
			return "! $$ConfigList\r\nhost aa:bb:cc:dd:ee:01 policy VPN\r\n"
		case policy.ShowPolicies:
			return "policy: VPN\r\npolicy: NO-VPN\r\n"
		default:
			return "Ok"
		}
	}
	return d
}

func panelPost(srv *panelServer, path, body string, cookie string, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	srv.muxHandler().ServeHTTP(rec, req)
	return rec
}

func panelGet(srv *panelServer, path, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	srv.muxHandler().ServeHTTP(rec, req)
	return rec
}

// login через полный обработчик (rate-limit хранится в panelServer).
func panelLogin(srv *panelServer, pw string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/kgate/login",
		strings.NewReader("password="+pw))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.9:5555"
	rec := httptest.NewRecorder()
	srv.loginHandler(rec, req)
	return rec
}

func TestPanel_Auth(t *testing.T) {
	d := newPanelTestDaemon(t)
	srv := newPanelServer(d)

	// нет cookie → API 401
	if rec := panelGet(srv, "/kgate/api/status", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("api без cookie = %d, want 401", rec.Code)
	}
	// неверный пароль → 401
	if rec := panelLogin(srv, "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login wrong pw = %d, want 401", rec.Code)
	}
	// верный пароль → 303 + cookie
	rec := panelLogin(srv, "test-pw")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login ok = %d, want 303", rec.Code)
	}
	cookies := rec.Result().Cookies()
	var tok string
	for _, c := range cookies {
		if c.Name == cookieName {
			tok = c.Value
			if !c.HttpOnly {
				t.Error("cookie не HttpOnly")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Error("cookie не SameSite=Lax")
			}
		}
	}
	if tok == "" {
		t.Fatal("login не выдал cookie-сессию")
	}
	// cookie работает
	if rec := panelGet(srv, "/kgate/api/status", tok); rec.Code != http.StatusOK {
		t.Fatalf("api с cookie = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	// login-страница без cookie доступна
	if rec := panelGet(srv, "/kgate/login", ""); rec.Code != http.StatusOK {
		t.Fatalf("login page = %d, want 200", rec.Code)
	}
	// GET / → 302 на /kgate/
	if rec := panelGet(srv, "/kgate", tok); rec.Code != http.StatusFound ||
		rec.Header().Get("Location") != "/kgate/" {
		t.Fatalf("/kgate = %d %q, want 302 /kgate/", rec.Code, rec.Header().Get("Location"))
	}
}

func TestPanel_LoginRateLimit(t *testing.T) {
	d := newPanelTestDaemon(t)
	srv := newPanelServer(d)
	for i := 0; i < 5; i++ {
		if rec := panelLogin(srv, "nope"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, rec.Code)
		}
	}
	if rec := panelLogin(srv, "nope"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6-я неудача = %d, want 429", rec.Code)
	}
	// верный пароль тоже задушен до конца окна
	if rec := panelLogin(srv, "test-pw"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("login после лимита = %d, want 429", rec.Code)
	}
}

func TestPanel_ToggleDelegatesToAPIPath(t *testing.T) {
	d := newPanelTestDaemon(t)
	srv := newPanelServer(d)
	toggleOK := false
	prev := d.ndmcFn
	d.ndmcFn = func(cmd string) string {
		if strings.Contains(cmd, "interface Proxy0") {
			toggleOK = true
			return "Ok"
		}
		return prev(cmd)
	}
	var tok string
	{
		rec := panelLogin(srv, "test-pw")
		for _, c := range rec.Result().Cookies() {
			if c.Name == cookieName {
				tok = c.Value
			}
		}
	}
	// on:true → /api/v1/toggle {"state":"on"} — intent-файл записан (тот же
	// кодовый путь: handler пишет intent ДО ndmc)
	rec := panelPost(srv, "/kgate/api/toggle", `{"on":true}`, tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if !toggleOK {
		t.Fatal("toggle панели НЕ прошёл через кодовый путь mTLS toggle (нет Proxy0-верба)")
	}
	b, err := readFile(d.intentPath)
	if err != nil || string(b) != "up\n" {
		t.Fatalf("intent после panel toggle = %q (err %v), want \"up\\n\"", string(b), err)
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["proxy0"] == "" {
		t.Fatalf("ответ toggle без proxy0: %s (%v)", rec.Body.String(), err)
	}
	// мусорный body → 400
	if rec := panelPost(srv, "/kgate/api/toggle", `{"nope":1}`, tok, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("toggle bad body = %d, want 400", rec.Code)
	}
}

func TestPanel_OriginGuard(t *testing.T) {
	d := newPanelTestDaemon(t)
	srv := newPanelServer(d)
	var tok string
	for _, c := range panelLogin(srv, "test-pw").Result().Cookies() {
		if c.Name == cookieName {
			tok = c.Value
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/kgate/api/toggle", strings.NewReader(`{"on":false}`))
	req.Host = "192.168.1.1:8443"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	srv.muxHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("чужой Origin = %d, want 403", rec.Code)
	}
	// свой Origin проходит до handler'а (404 нет: путь валиден)
	req2 := httptest.NewRequest(http.MethodPost, "/kgate/api/toggle", strings.NewReader(`{"on":false}`))
	req2.Host = "192.168.1.1:8443"
	req2.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
	req2.Header.Set("Origin", "https://192.168.1.1:8443")
	rec2 := httptest.NewRecorder()
	srv.muxHandler().ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusForbidden {
		t.Fatal("свой Origin отклонён")
	}
}

func TestPanel_Policies(t *testing.T) {
	d := newPanelTestDaemon(t)
	srv := newPanelServer(d)
	var tok string
	for _, c := range panelLogin(srv, "test-pw").Result().Cookies() {
		if c.Name == cookieName {
			tok = c.Value
		}
	}
	rec := panelGet(srv, "/kgate/api/policies", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("policies = %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Segments []map[string]any `json:"segments"`
		Hosts    []map[string]any `json:"hosts"`
		Policies []string         `json:"policies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("policies json: %v (%s)", err, rec.Body.String())
	}
	if len(out.Segments) != 1 || out.Segments[0]["name"] != "Bridge0" {
		t.Fatalf("segments = %+v", out.Segments)
	}
	if len(out.Hosts) != 1 || out.Hosts[0]["policy"] != "VPN" {
		// VPN пришёл из running-config overlay (binding source of truth)
		t.Fatalf("hosts = %+v", out.Hosts)
	}
	// смена политики устройства: unbind = prefix no-форма
	saw := ""
	d.ndmcFn = func(cmd string) string {
		if strings.HasPrefix(cmd, "no ip hotspot host") || strings.HasPrefix(cmd, "ip hotspot host") {
			saw = cmd
		}
		switch cmd {
		case policy.ShowHotspotCmd:
			return "\n                hostname: \"phone\"\n                     mac: aa:bb:cc:dd:ee:01\n                      ip: 192.168.1.52\n                  policy:\n                   active: yes\n"
		case policy.ShowRunningConfigCmd:
			return "host aa:bb:cc:dd:ee:01 policy VPN\n"
		case policy.ShowPolicies:
			return "policy: VPN\npolicy: NO-VPN\n"
		default:
			return "Ok"
		}
	}
	rec = panelPost(srv, "/kgate/api/policy/device", `{"mac":"aa:bb:cc:dd:ee:01","policy":"none"}`, tok, "")
	if rec.Code != http.StatusOK || saw != "no ip hotspot host aa:bb:cc:dd:ee:01 policy" {
		t.Fatalf("unbind: code=%d body=%s cmd=%q", rec.Code, rec.Body.String(), saw)
	}
	// невалидная политика → 400 (та же валидация, что у mTLS API)
	rec = panelPost(srv, "/kgate/api/policy/device", `{"mac":"aa:bb:cc:dd:ee:01","policy":"HOME"}`, tok, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad policy = %d, want 400", rec.Code)
	}
}

func TestPanel_Logs(t *testing.T) {
	d := newPanelTestDaemon(t)
	d.cfg.Daemon.Log = filepath.Join(t.TempDir(), "kgate.log")
	d.cfg.Daemon.SingBoxLog = filepath.Join(t.TempDir(), "singbox.log")
	srv := newPanelServer(d)
	var tok string
	for _, c := range panelLogin(srv, "test-pw").Result().Cookies() {
		if c.Name == cookieName {
			tok = c.Value
		}
	}
	log := bytes.Repeat([]byte("line\n"), 300)
	if err := writeFile(d.cfg.Daemon.Log, log); err != nil {
		t.Fatal(err)
	}
	rec := panelGet(srv, "/kgate/api/logs?src=kgate&tail=200", tok)
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), "line") != 200 {
		t.Fatalf("logs = %d, строк %d, want 200", rec.Code, strings.Count(rec.Body.String(), "line"))
	}
	// src мусор
	if rec := panelGet(srv, "/kgate/api/logs?src=x", tok); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad src = %d, want 400", rec.Code)
	}
}

func TestPanel_SessionExpiry(t *testing.T) {
	d := newPanelTestDaemon(t)
	srv := newPanelServer(d)
	var tok string
	for _, c := range panelLogin(srv, "test-pw").Result().Cookies() {
		if c.Name == cookieName {
			tok = c.Value
		}
	}
	srv.mu.Lock()
	srv.sessions[tok] = panelSession{expires: time.Now().Add(-time.Minute)}
	srv.mu.Unlock()
	if rec := panelGet(srv, "/kgate/api/status", tok); rec.Code != http.StatusUnauthorized {
		t.Fatalf("просроченная сессия = %d, want 401", rec.Code)
	}
}

func TestPanel_TailLinesChunkBoundary(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "l.log")
	var b bytes.Buffer
	for i := 0; i < 3000; i++ {
		b.WriteString("строка-" + itoa(i) + "\n")
	}
	if err := writeFile(p, b.Bytes()); err != nil {
		t.Fatal(err)
	}
	out, err := tailLines(p, 200)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out, "\n")
	if len(lines) != 200 || !strings.Contains(lines[199], "строка-2999") {
		t.Fatalf("tail: %d строк, последняя %q", len(lines), lines[len(lines)-1])
	}
	if strings.HasPrefix(lines[0], "строка-") == false || strings.HasSuffix(lines[0], "строка-2799") {
		// первая строка может быть обрезана посередине chunk'а — допускаем
		// только полный «строка-N»; если нет — это остаток обрезанной строки
		if !strings.HasPrefix(lines[0], "строка-") {
			t.Fatalf("первая строка мусорная: %q", lines[0])
		}
	}
}

// Регрессия 12.11.2026: srv.ServeTLS(nil, …) = SIGSEGV при старте демона
// (панель поднималась и мгновенно валила процесс). servePanelOn обязан
// работать на реальном TLS-пути: живой листенер, живой HTTPS-запрос.
func TestServePanelOn_RealTLS(t *testing.T) {
	dir := t.TempDir()
	if _, err := certs.Ensure(dir, "127.0.0.1"); err != nil {
		t.Fatalf("certs: %v", err)
	}
	d, _ := testDaemon(t, "192.0.2.1") // ndmc-seam фикстура
	d.cfg.Daemon.WebRoot = dir
	d.cfg.Panel.Password = "test-pass"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() { done <- d.servePanelOn(ln, func(string) {}) }()

	// дождаться старта и дернуть /kgate/login по HTTPS (self-signed → Insecure)
	var page *http.Response
	for i := 0; i < 40; i++ {
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 2 * time.Second}
		page, err = cl.Get("https://" + ln.Addr().String() + "/kgate/login")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("HTTPS GET /kgate/login: %v", err)
	}
	defer page.Body.Close()
	if page.StatusCode != 200 {
		t.Fatalf("login page: HTTP %d", page.StatusCode)
	}
	select {
	case err := <-done:
		t.Fatalf("servePanelOn вернулся (упал?): %v", err)
	default:
	}
}
