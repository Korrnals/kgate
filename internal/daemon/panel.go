package daemon

// Веб-панель kgate: HTTPS-листенер на panel.port (default :8443) в том же
// процессе демона (никаких дочерних процессов/pty). TLS — реюз серверных
// сертификатов mTLS API из web_root (server.crt/server.key уже генерятся
// для API). Панель включена ТОЛЬКО при заданном panel.password — пусто или
// нет секции = панель off (одна строка в логе старта, fail-safe).
//
// Auth: POST /kgate/login (form password) → cookie-сессия (random 32B
// token, HttpOnly, SameSite=Lax, TTL 12ч, in-memory store). Логин
// rate-limited: 5 неудач/мин с одного IP → 429. Все /kgate/api/* требуют
// валидную cookie; мутации дополнительно проверяют Origin (CSRF).
//
// Бизнес-логика НЕ дублируется: status/toggle/policies идут через те же
// внутренние методы демона, что питают mTLS API (d.status, d.toggleHandler,
// d.policyList, d.policySetDevice).

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kgate/internal/client"
)

const (
	cookieName  = "kgate_panel"
	sessionTTL  = 12 * time.Hour
	loginFails  = 5                // неудачных попыток...
	loginWindow = time.Minute      // ...за это окно с одного IP → 429
	exitIPCache = 60 * time.Second // exit-IP опрашивается не чаще
)

type panelSession struct {
	expires time.Time
}

type panelServer struct {
	d        *Daemon
	password string
	mu       sync.Mutex
	sessions map[string]panelSession
	fails    map[string][]time.Time
	exitIP   string
	exitIPAt time.Time
}

func newPanelServer(d *Daemon) *panelServer {
	return &panelServer{
		d:        d,
		password: d.cfg.Panel.Password,
		sessions: map[string]panelSession{},
		fails:    map[string][]time.Time{},
	}
}

// muxHandler собирает маршруты панели (отдельно — для httptest-тестов).
func (p *panelServer) muxHandler() *http.ServeMux {
	mux := http.NewServeMux()
	page := strings.ReplaceAll(panelHTML, "{{RETURN_URL}}", p.d.cfg.Panel.ReturnURL)

	mux.HandleFunc("/kgate", func(w http.ResponseWriter, r *http.Request) { // canonical → /kgate/
		http.Redirect(w, r, "/kgate/", http.StatusFound)
	})
	mux.HandleFunc("/kgate/login", p.loginHandler)
	mux.HandleFunc("/kgate/logout", p.requireAuth(p.postOnly(p.logoutHandler)))
	mux.HandleFunc("/kgate/", p.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kgate/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, page)
		case "/kgate/manifest.webmanifest":
			w.Header().Set("Content-Type", "application/manifest+json")
			fmt.Fprint(w, panelManifest)
		case "/kgate/icon.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			fmt.Fprint(w, panelIcon)
		case "/kgate/api/status":
			p.statusHandler(w, r)
		case "/kgate/api/toggle":
			p.postOnly(p.originGuard(p.toggleProxy))(w, r)
		case "/kgate/api/policies":
			p.policiesHandler(w, r)
		case "/kgate/api/policy/device":
			p.postOnly(p.originGuard(p.policyDeviceHandler))(w, r)
		case "/kgate/api/logs":
			p.logsHandler(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	return mux
}

// servePanel blocks: TLS-листенер панели (вызывается в горутине из Run).
func (d *Daemon) servePanel(logger func(string)) error {
	cert, err := tls.LoadX509KeyPair(d.cfg.Daemon.WebRoot+"/server.crt", d.cfg.Daemon.WebRoot+"/server.key")
	if err != nil {
		return fmt.Errorf("server cert (web_root): %w", err)
	}
	p := newPanelServer(d)
	mux := p.muxHandler()

	addr := ":" + strconv.Itoa(d.cfg.Panel.Port)
	srv := &http.Server{Addr: addr, Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 5 * time.Second}
	logger("panel: HTTPS listener " + addr + " (/kgate/)")
	return srv.ServeTLS(nil, "", "")
}

// ---- auth ----

func (p *panelServer) newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (p *panelServer) sessionOK(token string) bool {
	if token == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[token]
	if !ok || time.Now().After(s.expires) {
		delete(p.sessions, token)
		return false
	}
	return true
}

func (p *panelServer) currentToken(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func (p *panelServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.sessionOK(p.currentToken(r)) {
			if r.URL.Path == "/kgate/" || r.URL.Path == "/kgate" {
				http.Redirect(w, r, "/kgate/login", http.StatusFound)
				return
			}
			http.Error(w, "требуется вход (/kgate/login)", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// postOnly — та же дисциплина мутаций, что у mTLS API (postOnly в daemon.go):
// GET/превью-краулер не может выполнить мутацию.
func (p *panelServer) postOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "метод "+r.Method+" запрещён: endpoint мутирует — используй POST", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

// originGuard — CSRF-щит мутаций: если браузер прислал Origin, он обязан
// совпадать с хостом запроса (панель отдаётся только по https с этого же
// хоста). Origin отсутствует (curl/httplib) — пропускаем: cookie уже
// HttpOnly+SameSite=Lax.
func (p *panelServer) originGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && origin != "https://"+r.Host {
			http.Error(w, "origin "+origin+" не совпадает с хостом панели (CSRF)", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (p *panelServer) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, strings.ReplaceAll(panelHTML, "{{RETURN_URL}}", p.d.cfg.Panel.ReturnURL))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "метод "+r.Method+" запрещён", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if p.rateLimited(ip) {
		http.Error(w, "слишком много неудачных попыток — подожди минуту", http.StatusTooManyRequests)
		return
	}
	var pw string
	if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "json") {
		var in struct {
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		pw = in.Password
	} else {
		pw = r.PostFormValue("password")
	}
	if pw != p.password {
		p.recordFail(ip)
		http.Error(w, "неверный пароль", http.StatusUnauthorized)
		return
	}
	token, err := p.newToken()
	if err != nil {
		http.Error(w, "token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	p.mu.Lock()
	p.sessions[token] = panelSession{expires: time.Now().Add(sessionTTL)}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/kgate",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/kgate/", http.StatusSeeOther)
}

func (p *panelServer) logoutHandler(w http.ResponseWriter, r *http.Request) {
	token := p.currentToken(r)
	p.mu.Lock()
	delete(p.sessions, token)
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/kgate", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode})
	fmt.Fprint(w, "ok")
}

// rateLimited / recordFail: окно из loginWindow, не больше loginFails неудач.
func (p *panelServer) rateLimited(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	cut := time.Now().Add(-loginWindow)
	live := p.fails[ip][:0]
	for _, t := range p.fails[ip] {
		if t.After(cut) {
			live = append(live, t)
		}
	}
	p.fails[ip] = live
	return len(live) >= loginFails
}

func (p *panelServer) recordFail(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fails[ip] = append(p.fails[ip], time.Now())
}

func clientIP(r *http.Request) string {
	host, _, err := splitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func splitHostPort(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, "", fmt.Errorf("no port")
	}
	return addr[:i], addr[i+1:], nil
}

// ---- API ----

// statusHandler: реюз d.status() (тот же кодовый путь, что питает
// /api/v1/status mTLS API) + exit-IP через socks-туннель (internal/client).
func (p *panelServer) statusHandler(w http.ResponseWriter, r *http.Request) {
	st := p.d.status()
	p.mu.Lock()
	if p.exitIP == "" || time.Since(p.exitIPAt) > exitIPCache {
		if ip, err := client.FetchExitIP(p.d.cfg.Daemon.RelayUpstream); err == nil {
			p.exitIP = ip
			p.exitIPAt = time.Now()
		}
	}
	exitIP := p.exitIP
	p.mu.Unlock()
	if exitIP == "" {
		exitIP = "недоступен"
	}
	json.NewEncoder(w).Encode(map[string]any{
		"singbox": st.SingBox, "relay": st.Relay, "proxy0": st.Proxy0,
		"mode": st.Mode, "uptime": st.Uptime, "exit_ip": exitIP,
	})
}

// toggleProxy: ТОТ ЖЕ кодовый путь, что у штатного API — делегация в
// d.toggleHandler() (intent-файл → d.toggle → ndmc-проверка → save).
func (p *panelServer) toggleProxy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		On *bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.On == nil {
		http.Error(w, "body: {\"on\": true|false}", http.StatusBadRequest)
		return
	}
	state := map[bool]string{true: "on", false: "off"}[*in.On]
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/toggle", strings.NewReader(`{"state":"`+state+`"}`))
	rec := &responseSink{header: http.Header{}}
	p.d.toggleHandler()(rec, req)
	if rec.code == 0 {
		rec.code = http.StatusOK // handler ответил через Write без WriteHeader
	}
	w.WriteHeader(rec.code)
	for k, vs := range rec.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Write(rec.body)
}

// responseSink captures the delegated handler's response (status/body/headers)
// so the panel can replay it verbatim — toggle semantics stay byte-identical
// with the mTLS API.
type responseSink struct {
	header http.Header
	code   int
	body   []byte
}

func (s *responseSink) Header() http.Header { return s.header }
func (s *responseSink) Write(b []byte) (int, error) {
	s.body = append(s.body, b...)
	return len(b), nil
}
func (s *responseSink) WriteHeader(code int) { s.code = code }

// policiesHandler: read-only сегменты + устройства (тот же policyList, что
// питает /api/v1/policy/list mTLS API).
func (p *panelServer) policiesHandler(w http.ResponseWriter, r *http.Request) {
	out, err := p.d.policyList()
	if err != nil {
		if isClientPolicyErr(err) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(out)
}

// policyDeviceHandler: смена политики устройства через существующий
// daemon-путь (d.policySetDevice → BindDeviceCmd, unbind = prefix no-форма).
func (p *panelServer) policyDeviceHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MAC    string `json:"mac"`
		Policy string `json:"policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "body: {\"mac\": ..., \"policy\": VPN|NO-VPN|none}", http.StatusBadRequest)
		return
	}
	out, err := p.d.policySetDevice(in.MAC, in.Policy)
	if err != nil {
		if isClientPolicyErr(err) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(out)
}

// logsHandler: хвост kgate.log / singbox.log (последние tail строк; чтение
// последнего блока файла — лог может расти месяцами).
func (p *panelServer) logsHandler(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("src")
	path := map[string]string{
		"kgate":   p.d.cfg.Daemon.Log,
		"singbox": p.d.cfg.Daemon.SingBoxLog,
	}[src]
	if path == "" {
		http.Error(w, "src: kgate|singbox", http.StatusBadRequest)
		return
	}
	tail := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("tail")); err == nil && n > 0 && n <= 5000 {
		tail = n
	}
	out, err := tailLines(path, tail)
	if err != nil {
		http.Error(w, src+" log: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="kgate-`+src+`.log"`)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, out)
}

// tailLines читает последний chunk файла и возвращает не более n строк.
func tailLines(path string, n int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	const chunk = 128 * 1024
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	off := st.Size() - chunk
	if off < 0 {
		off = 0
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // первая строка почти наверняка обрезана посередине
	}
	return strings.Join(lines, "\n"), nil
}
