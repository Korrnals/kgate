// Package daemon is the server side of kgate: the VPN-stack supervisor plus
// the mTLS API. It replaces the legacy glue (S99sing-box, rc-redirect v5,
// rc-redirect-watchdog, boot-autoup). Runs on the router as root
// (iptables/ndmc). Every supervisor tick:
//  1. make sure sing-box is alive (restart with backoff, inherited RLIMIT_NOFILE)
//  2. make sure the SBREDIRECT DNS chain survives in nat (ndm likes to wipe it)
package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"kgate/internal/model"
)

type Daemon struct {
	cfg      *model.Config
	mgr      *procManager
	lastIPOK bool
	upOnce   bool
	cfgWarn  bool // template placeholders detected: do not auto-raise a dead tunnel
	// route-pin: источник истины — фактический `show ip route`; pins содержит
	// только пины, которые мы сами подтвердили (ip → хост-владелец из конфига;
	// "" = seed ServerIP от deploy до первой сверки)
	pins      map[string]string
	pinWarned map[string]bool                // log-once: аномалии пина молчат не дольше одного состояния
	ndmcFn    func(string) string            // seam для тестов: подмена ndm CLI
	resolveFn func(string) ([]net.IP, error) // seam для тестов: подмена резолвера
}

func New(cfg *model.Config) *Daemon {
	d := &Daemon{cfg: cfg, mgr: newProcManager(cfg), pinWarned: map[string]bool{}}
	d.ndmcFn = d.ndmc // тесты подменяют ndmcFn/resolveFn фейками
	d.resolveFn = net.LookupIP
	return d
}

// ndm — вызов ndm CLI через seam (в проде это d.ndmc, тесты подменяют ndmcFn).
func (d *Daemon) ndm(cmd string) string {
	if d.ndmcFn != nil {
		return d.ndmcFn(cmd)
	}
	return d.ndmc(cmd)
}

// warnPlaceholders fails loud on un-edited template configs: the packaged
// examples carry placeholder credentials, and a daemon silently supervising a
// placeholder sing-box looks healthy (Proxy0 up) while no traffic moves.
func (d *Daemon) warnPlaceholders(logger func(string)) {
	b, err := os.ReadFile(d.cfg.Daemon.SingBoxConfig)
	if err != nil {
		return // missing config is reported elsewhere; do not duplicate
	}
	var hits []string
	for _, m := range []string{"HY2_PASSWORD", "hy2.example.com"} {
		if strings.Contains(string(b), m) {
			hits = append(hits, m)
		}
	}
	if len(hits) == 0 {
		return
	}
	d.cfgWarn = true
	_ = d.toggle("down") // a stale raised Proxy0 would blackhole the whole LAN
	logger("КОНФИГ НЕ НАСТРОЕН: " + d.cfg.Daemon.SingBoxConfig +
		" содержит плейсхолдеры (" + strings.Join(hits, ", ") + ") — туннель работать НЕ будет.")
	logger("Замени server/password реальными значениями, затем: /opt/etc/init.d/S99kgate restart")
}

// ---- shell wrappers ----

func sh(script string) string {
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Env = daemonEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("ERR(%v): ", err) + strings.TrimSpace(string(out))
	}
	return strings.TrimSpace(string(out))
}

// daemonEnv returns a deterministic environment: rc.unslung may hand a
// stripped env at boot, making ndmc/grep inside status scripts behave
// differently compared to a restart from an ssh session.
func daemonEnv() []string {
	env := []string{
		"PATH=/opt/bin:/opt/sbin:/opt/usr/bin:/opt/usr/sbin:/sbin:/usr/sbin:/bin:/usr/bin",
		"HOME=/",
		"TERM=linux",
	}
	// CA fallback: firmware normally ships /etc/ssl/certs (sing-box TLS to the
	// hy2 server works out of the box). The ipk-shipped bundle covers firmware
	// builds without a system cert dir; only set it then, so we never override
	// fresher firmware roots with a stale bundle.
	if _, err := os.Stat("/etc/ssl/certs"); err != nil {
		if _, err := os.Stat("/opt/etc/kgate/ca-bundle.crt"); err == nil {
			env = append(env, "SSL_CERT_FILE=/opt/etc/kgate/ca-bundle.crt")
		}
	}
	return env
}

func (d *Daemon) ndmc(cmd string) string {
	return sh(`/bin/ndmc -c "` + strings.ReplaceAll(cmd, `"`, `\"`) + `"`)
}

// ---- process manager ----

type proc struct {
	name    string
	bin     string
	args    []string
	logfile string
	pidfile string
	cmd     *exec.Cmd
	backoff time.Duration
}

func newProcManager(cfg *model.Config) *procManager {
	d := cfg.Daemon
	m := &procManager{cfg: cfg}
	// xray is no longer used: replaced by the built-in tolerant SOCKS relay (:1090).
	m.procs = []*proc{
		{name: "sing-box", bin: d.SingBoxBin, args: []string{"run", "-c", d.SingBoxConfig}, logfile: d.SingBoxLog,
			pidfile: "/opt/var/run/kgate-singbox.pid"},
	}
	return m
}

type procManager struct {
	cfg   *model.Config
	procs []*proc
}

func (m *procManager) alive(p *proc) bool {
	b, err := os.ReadFile(p.pidfile)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return false
	}
	st, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return false
	}
	// a zombie sits in /proc but is not running — do not count it as alive
	for _, l := range strings.Split(string(st), "\n") {
		if strings.HasPrefix(l, "State:") && strings.Contains(l, "Z") {
			return false
		}
	}
	return true
}

func (m *procManager) start(p *proc) error {
	logf, err := os.OpenFile(p.logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer logf.Close()
	// the FD limit is set on the DAEMON (unix.Setrlimit in Run) — children inherit it.
	// (SysProcAttr.Rlimit is unavailable on arm64, and busybox ash chokes on the
	// sh-wrap ulimit form.)
	cmd := exec.Command(p.bin, p.args...)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// reaper: collect the exit status of a dead child (otherwise zombies in /proc lie to alive)
	go cmd.Wait()
	p.cmd = cmd
	p.backoff = 0
	return os.WriteFile(p.pidfile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
}

func (m *procManager) killAll() {
	// via ps (busybox killall is unreliable for these names)
	out := sh(`ps w | grep -E "sing-box|xray" | grep -v grep | awk "{print \$1}"`)
	for _, s := range strings.Fields(out) {
		if pid, err := strconv.Atoi(s); err == nil && pid != os.Getpid() {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	for _, p := range m.procs {
		os.Remove(p.pidfile)
	}
	time.Sleep(time.Second)
}

func (m *procManager) ensure() []string {
	var report []string
	for _, p := range m.procs {
		wasAlive := m.alive(p)
		if wasAlive {
			if p.backoff != 0 { // log only the Dead->Alive transition
				report = append(report, p.name+": running (восстановлен)")
				p.backoff = 0
			}
			continue
		}
		if p.backoff > 0 {
			time.Sleep(p.backoff)
		}
		if err := m.start(p); err != nil {
			report = append(report, p.name+": START ERR "+err.Error())
			if p.backoff < 30*time.Second {
				p.backoff *= 2
			}
			if p.backoff == 0 {
				p.backoff = 5 * time.Second
			}
		} else {
			report = append(report, p.name+": started (был мёртв)")
		}
	}
	return report
}

// ---- iptables DNS-DNAT (the former rc-redirect v5, now inside the daemon) ----

const wanDNS = "77.88.8.8"

func (d *Daemon) iptablesOK() bool {
	out := sh("/opt/sbin/iptables -t nat -L PREROUTING -n 2>/dev/null | grep -c SBREDIRECT")
	return strings.HasPrefix(out, "1")
}

func (d *Daemon) iptablesApply() string {
	return sh(`/opt/sbin/iptables -t nat -N SBREDIRECT 2>/dev/null
/opt/sbin/iptables -t nat -F SBREDIRECT
/opt/sbin/iptables -t nat -A SBREDIRECT -p udp --dport 53 -j DNAT --to-destination ` + wanDNS + `
/opt/sbin/iptables -t nat -A SBREDIRECT -p tcp --dport 53 -j DNAT --to-destination ` + wanDNS + `
/opt/sbin/iptables -t nat -C PREROUTING -j SBREDIRECT 2>/dev/null || /opt/sbin/iptables -t nat -A PREROUTING -j SBREDIRECT
/opt/sbin/ip6tables -t filter -N SBREDIR6 2>/dev/null
/opt/sbin/ip6tables -t filter -F SBREDIR6
/opt/sbin/ip6tables -t filter -A SBREDIR6 -i Bridge0 -p udp --dport 53 -j DROP
/opt/sbin/ip6tables -t filter -A SBREDIR6 -p tcp --dport 53 -j DROP
/opt/sbin/ip6tables -t filter -C FORWARD -j SBREDIR6 2>/dev/null || /opt/sbin/ip6tables -t filter -A FORWARD -j SBREDIR6
echo dns-rules-applied`)
}

// ---- hy2 server route-pin (dynamic) ----

// serverHosts extracts EVERY non-direct outbound endpoint from the sing-box
// config: the static hy2 out plus any subscription nodes (vless/trojan/ss/
// hysteria2 — whatever the provider feed merged in). The daemon is the source
// of truth for tunnel endpoints; subscription configs drop hy2-out entirely,
// so the old first-hysteria2 scan went blind on them (wave-1 review MAJOR-2).
func (d *Daemon) serverHosts() []string {
	b, err := os.ReadFile(d.cfg.Daemon.SingBoxConfig)
	if err != nil {
		return []string{d.cfg.ServerIP} // fallback: operator yaml value
	}
	var sb struct {
		Outbounds []struct {
			Type   string `json:"type"`
			Server string `json:"server"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(b, &sb) != nil {
		return []string{d.cfg.ServerIP}
	}
	seen := map[string]bool{}
	hosts := []string{}
	for _, ob := range sb.Outbounds {
		if ob.Server == "" || ob.Type == "direct" {
			continue
		}
		if !seen[ob.Server] {
			seen[ob.Server] = true
			hosts = append(hosts, ob.Server)
		}
	}
	return hosts
}

// syncServerPin keeps the ndm route-pins pointed at the CURRENT addresses of
// every tunnel endpoint. The server-side DNS watchdog flips cdn.srwx.ru
// between exits (failover); a stale pin routes the tunnel's own traffic
// through Proxy0 — self-loop, no internet (the 03.11 class). Runs every
// supervisor tick.
//
// Reconciliation discipline (wave-1 review MAJOR-1): d.pins holds ONLY pins
// whose ndmc result we confirmed (plus the deploy-seeded ServerIP); failed
// ndmc calls are logged loudly, leave the state untouched and retry next
// tick. Anomalies (resolver down, AAAA-only, no endpoints) log once per
// state via pinWarned (wave-1 review MINOR-3).
func (d *Daemon) syncServerPin(logger func(string)) {
	if d.pins == nil { // first tick: deploy already pinned cfg.ServerIP (seed: "" = владелец-неизвестен)
		d.pins = map[string]string{}
		if ip := net.ParseIP(d.cfg.ServerIP); ip != nil {
			d.pins[ip.String()] = ""
		}
	}
	if d.pinWarned == nil {
		d.pinWarned = map[string]bool{}
	}
	warn := func(key, msg string) {
		if d.pinWarned[key] {
			return
		}
		d.pinWarned[key] = true
		logger(msg)
	}
	clearWarn := func(key string) { delete(d.pinWarned, key) }

	want := map[string]bool{}
	hostsByIP := map[string]string{} // провенанс: какой хост дал этот IP
	knownHosts := map[string]bool{}  // все хосты, живущие в конфиге сейчас
	resolvedOK := map[string]bool{}  // хосты, давшие ≥1 дозваниваемый v4 в этом тике
	resolveFailed := false           // хоть один хост не резолвится в этом тике
	nov4Seen := false                // хоть один хост AAAA-only (W4-3: тоже DNS-нездоровье)
	for _, h := range d.serverHosts() {
		knownHosts[h] = true
		if ip := net.ParseIP(h); ip != nil { // literal endpoint: no DNS to follow
			resolvedOK[h] = true // литерал всегда «здоров» для removal-гейта
			if v4 := ip.To4(); v4 != nil {
				want[v4.String()] = true
				hostsByIP[v4.String()] = h
			} else {
				warn("literal6:"+h, "route-pin: endpoint "+h+" — не IPv4, пин не ставлю")
			}
			continue
		}
		ips, err := d.resolveFn(h)
		if err != nil {
			resolveFailed = true
			warn("resolve:"+h, "route-pin: DNS "+h+" не резолвится ("+err.Error()+") — держу текущие пины")
			continue
		}
		clearWarn("resolve:" + h)
		n := 0
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				want[v4.String()] = true
				if hostsByIP[v4.String()] == "" {
					hostsByIP[v4.String()] = h
				}
				n++
			}
		}
		if n == 0 {
			// AAAA-only (wave-3 F-3): хозяин жив, но дозваниваемого v4 не дал —
			// replacement-определённость неизвестна → его пины удерживаются
			// provenance-гейтом (resolvedOK не выставляется) + seed-гейтом (W4-3)
			nov4Seen = true
			warn("nov4:"+h, "route-pin: у "+h+" нет A-записей (только AAAA?) — пин не ставлю")
		} else {
			clearWarn("nov4:" + h)
			resolvedOK[h] = true // волна-4 W4-1: здоровый доменный хост ре-стампится КАЖДЫЙ тик
		}
	}
	if len(want) == 0 {
		warn("noendpoints", "route-pin: в конфиге нет ни одного endpoint — пины не обновляю (риск петли при смене выхода сервера)")
		return
	}
	clearWarn("noendpoints")
	dnsUnhealthy := resolveFailed || nov4Seen // W4-3: seed-гейт видит полное DNS-здоровье тика

	// Adds first, then stale removes; every ndmc result is checked — on
	// failure the pin state stays untouched and the next tick retries.
	// Removals are gated on ALL adds being confirmed: otherwise a failed add
	// plus a successful remove leaves ZERO pins (unpinned endpoint — loop
	// risk); keeping the stale pin one extra tick is safe (direct route).
	pendingAdds := 0
	for ip := range want {
		if _, ok := d.pins[ip]; ok {
			continue
		}
		out := d.ndm("ip route " + ip + " ISP")
		if ndmcFailed(out) {
			logger("route-pin: НЕ удалось запинить " + ip + " (ndmc: " + strings.TrimSpace(out) + ") — повтор на следующем тике")
			pendingAdds++
			continue
		}
		d.pins[ip] = hostsByIP[ip] // провенанс: какой хост дал этот IP ("" = seed)
		logger("route-pin: + " + ip + " (endpoint актуализирован)")
	}
	if pendingAdds > 0 {
		warn("removals-deferred", "route-pin: есть неподтверждённые добавления — снятие устаревших пинов отложено до следующего тика")
		clearWarn("removals-deferred-dns")
		return
	}
	clearWarn("removals-deferred")
	// wave-3 F-1: provenance-scoped DNS gate (замена глобального). Пин
	// удерживается, если его ВЛАДЕЛЕЦ ещё в конфиге, но DNS-нездоров в этом
	// тике (ошибка резолва или AAAA-only — replacement-определённость
	// неизвестна; wave-3 F-3). Пины владельцев, ушедших из конфига, или чьи
	// владельцы резолвятся нормально — снимаются. Ownerless seed (deploy)
	// ждёт полностью здорового тика. Stale-пин = прямой маршрут — safe
	// direction, удержание всегда безопасно.
	removedDeferred := false
	for ip, owner := range d.pins {
		if want[ip] {
			continue
		}
		if (knownHosts[owner] && !resolvedOK[owner]) || (owner == "" && dnsUnhealthy) {
			removedDeferred = true
			continue
		}
		out := d.ndm("no ip route " + ip + " ISP")
		if ndmcFailed(out) {
			logger("route-pin: НЕ удалось снять устаревший пин " + ip + " (ndmc: " + strings.TrimSpace(out) + ") — повтор на следующем тике")
			continue
		}
		delete(d.pins, ip)
		logger("route-pin: − " + ip + " (endpoint ушёл — DNS сервера уехал)")
	}
	if removedDeferred {
		warn("removals-deferred-dns", "route-pin: часть endpoint'ов DNS-нездорова — их пины удержаны (stale-пин = прямой маршрут, безопасно)")
	} else {
		clearWarn("removals-deferred-dns")
	}
}

// ndmcFailed reads the ndm CLI's failure surface: errors come back as
// "[C] ... system failed [0x...]" / "invalid parameters"; exec-level failures
// surface as sh()'s "ERR(...)" prefix (wave-2 review). Success for
// `ip route` / `no ip route` is silence.
func ndmcFailed(out string) bool {
	o := strings.ToLower(out)
	return strings.Contains(o, "system failed") || strings.Contains(o, "invalid") || strings.Contains(o, "err(")
}

// ---- tunnel ----

func (d *Daemon) toggle(state string) string {
	return d.ndmc("interface Proxy0 " + state)
}

func (d *Daemon) proxyState() string {
	out := d.ndmc("show interface Proxy0")
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "state:") {
			return strings.TrimSpace(l)
		}
	}
	return "state: unknown"
}

// waitPort blocks until the sing-box port accepts connections (avoids the boot race)
func (d *Daemon) waitPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

// ---- status / verification ----

type Status struct {
	SingBox  string `json:"singbox"`
	Relay    string `json:"relay"`
	FDLimit  string `json:"fd_limit"`
	Proxy0   string `json:"proxy0"`
	Pins     string `json:"pins"`
	DNSRules string `json:"dns_rules"`
	Mode     string `json:"mode"`
	Uptime   string `json:"uptime"`
	Debug    string `json:"debug"`
}

func (d *Daemon) status() Status {
	pin := sh(`echo "pins: $(/bin/ndmc -c "show ip route" | grep -cE "/32 .*ISP")"`)
	dns := sh(`echo "dns rules: $(/opt/sbin/iptables -t nat -L SBREDIRECT -n | grep -c "77.88.8.8")"`)
	fd := sh(`grep "open files" /proc/$(pidof sing-box)/limits`)
	up := sh(`cat /proc/uptime`)
	debugRaw := sh(`/bin/ndmc -c "show interface Proxy0" 2>&1 | head -c 200`)
	return Status{
		SingBox:  boolStr(d.mgr.alive(d.mgr.procs[0])),
		Relay:    boolStr(d.relayAlive()),
		FDLimit:  strings.TrimSpace(fd),
		Proxy0:   d.proxyState(),
		Pins:     strings.TrimSpace(pin),
		DNSRules: strings.TrimSpace(dns),
		Mode:     d.clashMode(),
		Uptime:   strings.Fields(up)[0] + "s",
		Debug:    "raw=" + strconv.Quote(debugRaw),
	}
}

func boolStr(b bool) string {
	if b {
		return "running"
	}
	return "DEAD"
}

func (d *Daemon) clashEndpoints() []string {
	return []string{"http://127.0.0.1:9090", "http://192.168.1.1:9090"}
}

func (d *Daemon) clashMode() string {
	for _, ep := range d.clashEndpoints() {
		resp, err := http.Get(ep + "/configs")
		if err != nil {
			continue
		}
		var m struct {
			Mode string `json:"mode"`
		}
		if json.NewDecoder(resp.Body).Decode(&m) == nil {
			return m.Mode
		}
	}
	return "unknown"
}

func (d *Daemon) setClashMode(mode string) error {
	body := `{"mode":"` + mode + `"}`
	var lastErr error
	for _, ep := range d.clashEndpoints() {
		req, _ := http.NewRequest("PATCH", ep+"/configs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if _, err := http.DefaultClient.Do(req); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

// ---- main loop ----

func (d *Daemon) Run() error {
	fmt.Println("kgate daemon: старт, тик", d.cfg.Daemon.Interval)
	// FD limit on the daemon itself: children inherit it. Two steps: hard first, then soft.
	lim := unix.Rlimit{Cur: d.cfg.Daemon.RlimitNofile * 2, Max: d.cfg.Daemon.RlimitNofile * 2}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		fmt.Println("setrlimit hard:", err)
	}
	lim.Cur = d.cfg.Daemon.RlimitNofile
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		fmt.Println("setrlimit soft:", err)
	}
	f, _ := os.OpenFile(d.cfg.Daemon.Log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	logger := func(s string) {
		line := time.Now().Format("Jan 02 15:04:05") + " kgate: " + s + "\n"
		fmt.Print(line)
		if f != nil {
			f.WriteString(line)
		}
	}

	// once at startup: clear foreign processes and take ownership of the stack
	d.mgr.killAll()
	d.warnPlaceholders(logger)
	logger("supervisor: принял стек (sing-box + xray)")
	d.mgr.ensure()
	d.iptablesApply()
	if err := d.relayListen(d.cfg.Daemon.RelayListen, d.cfg.Daemon.RelayUpstream); err != nil {
		logger("relay: ОШИБКА " + err.Error())
	} else {
		logger("relay: слушаю " + d.cfg.Daemon.RelayListen + " -> " + d.cfg.Daemon.RelayUpstream + " (толерантный socks: замена xray)")
	}
	logger("supervisor: dns-rules применены")

	go func() { // tunnel auto-raise: wait for :1080, then up (no Entware race)
		if !d.cfg.Daemon.BootAutoup {
			return
		}
		delay := model.Dur(d.cfg.Daemon.AutoupDelay, 25*time.Second)
		time.Sleep(delay)
		if d.cfgWarn {
			logger("autoup: пропущен — конфиг не настроен (шаблон с плейсхолдерами), Proxy0 не трогаю")
			return
		}
		if d.waitPort("127.0.0.1:1080", 60*time.Second) {
			d.toggle("up")
			logger("autoup: Proxy0 up (tunnel engine готов)")
			d.upOnce = true
		} else {
			logger("autoup: sing-box не поднялся за 60с — Proxy0 не трогаю")
		}
	}()

	interval := model.Dur(d.cfg.Daemon.Interval, 15*time.Second)
	tick := time.NewTicker(interval)
	go func() {
		d.syncServerPin(logger) // pin мог устареть за время простоя
		for range tick.C {
			for _, l := range d.mgr.ensure() {
				logger("supervisor: " + l)
			}
			d.syncServerPin(logger)
			if !d.iptablesOK() {
				logger("supervisor: dns-rules снесены — восстанавливаю")
				d.iptablesApply()
			}
		}
	}()

	err := d.serveAPI(logger)
	tick.Stop()
	return err
}

// ---- mTLS API ----

func (d *Daemon) serveAPI(logger func(string)) error {
	ca, err := os.ReadFile(d.cfg.Daemon.WebRoot + "/ca.crt")
	if err != nil {
		return fmt.Errorf("ca.crt: %w (сначала kgate apply — он разложит сертификаты)", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	cert, err := tls.LoadX509KeyPair(d.cfg.Daemon.WebRoot+"/server.crt", d.cfg.Daemon.WebRoot+"/server.key")
	if err != nil {
		return fmt.Errorf("server cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(d.status())
	})
	mux.HandleFunc("/api/v1/toggle", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			State string `json:"state"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		if in.State != "on" && in.State != "off" {
			http.Error(w, "state: on|off", 400)
			return
		}
		verb := map[string]string{"on": "up", "off": "down"}[in.State]
		out := d.toggle(verb)
		time.Sleep(6 * time.Second)
		json.NewEncoder(w).Encode(map[string]string{"ndmc": out, "proxy0": d.proxyState()})
	})
	mux.HandleFunc("/api/v1/ruexit", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Mode string `json:"mode"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		if in.Mode != "global" && in.Mode != "rule" {
			http.Error(w, "mode: global|rule", 400)
			return
		}
		if err := d.setClashMode(in.Mode); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"mode": d.clashMode()})
	})
	mux.HandleFunc("/api/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		rep := d.mgr.ensure()
		json.NewEncoder(w).Encode(map[string]any{"status": d.status(), "supervisor": rep})
	})
	mux.HandleFunc("/api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		boot := strings.Replace(d.cfg.Daemon.Log, "kgate.log", "kgate-boot.log", 1)
		out := sh(fmt.Sprintf("tail -40 %s; echo '--- boot ---'; tail -10 %s",
			strconv.Quote(d.cfg.Daemon.Log), strconv.Quote(boot)))
		fmt.Fprintln(w, out)
	})
	mux.HandleFunc("/api/v1/reboot", func(w http.ResponseWriter, r *http.Request) {
		out := d.ndmc("system reboot")
		json.NewEncoder(w).Encode(map[string]string{"ndmc": out})
		time.Sleep(time.Second)
		os.Exit(0)
	})

	srv := &http.Server{Addr: d.cfg.Daemon.APIListen, Handler: mux, TLSConfig: tlsCfg,
		ReadHeaderTimeout: 5 * time.Second}
	logger("api: mTLS listener " + d.cfg.Daemon.APIListen)
	return srv.ListenAndServeTLS(d.cfg.Daemon.WebRoot+"/server.crt", d.cfg.Daemon.WebRoot+"/server.key")
}
