// Package daemon is the server side of kgate: the VPN-stack supervisor plus
// the mTLS API. It replaces the legacy glue (S99sing-box, rc-redirect v5,
// rc-redirect-watchdog, boot-autoup). Runs on the router as root
// (iptables/ndmc). Every supervisor tick:
//  1. make sure sing-box is alive (restart with backoff, inherited RLIMIT_NOFILE)
//  2. make sure the SBREDIRECT DNS chain survives in nat (ndm likes to wipe it)
package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"kgate/internal/model"
)

type Daemon struct {
	cfg     *model.Config
	mgr     *procManager
	cfgWarn bool // template placeholders detected: do not auto-raise a dead tunnel
	// web-switch adoption (поле-приёмка 2026-11-11): внешний down/up Proxy0
	// (веб-тумблер, ручной ndmc) принимается как намерение владельца —
	// supervisor переписывает intent-файл, а не откатывает действие.
	lastSelfToggleMu sync.Mutex
	lastSelfToggle   time.Time   // момент последнего СОБСТВЕННОГО toggle демона
	singboxAliveFn   func() bool // seam для тестов: жив ли процесс sing-box
	// route-pin: источник истины — фактический `show ip route`; pins содержит
	// только пины, которые мы сами подтвердили (ip → хост-владелец из конфига;
	// "" = seed ServerIP от deploy до первой сверки)
	pins       map[string]string
	pinWarned  map[string]bool                // log-once: аномалии пина молчат не дольше одного состояния
	ndmcFn     func(string) string            // seam для тестов: подмена ndm CLI
	resolveFn  func(string) ([]net.IP, error) // seam для тестов: подмена резолвера
	intentPath string                         // seam для тестов: путь intent-файла ("" = дефолт)
}

func New(cfg *model.Config) *Daemon {
	d := &Daemon{cfg: cfg, mgr: newProcManager(cfg), pinWarned: map[string]bool{}}
	d.ndmcFn = d.ndmc                  // тесты подменяют ndmcFn/resolveFn фейками
	d.resolveFn = tcpLookupIP          // endpoint-пины: DNS-over-TCP (анти- poisoning)
	d.singboxAliveFn = procScanSingbox // web-switch adoption: жив ли движок (тесты подменяют)
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
	// defense-in-depth (wave-1 D6): cmd is interpolated into sh -c "…" with
	// only double quotes escaped; $ or ` inside cmd would expand in the
	// router shell. Audited (grep): no legitimate call site passes either,
	// so the filter refuses instead of attempting partial escaping.
	if strings.ContainsAny(cmd, "$`") {
		return fmt.Sprintf("ERR(ndmc: cmd rejected, '$'/backtick not allowed: %q)", cmd)
	}
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
	out := sh(`ps w | awk "/[s]ing-box|[x]ray/ && \$NF !~ /awk|sh -c/ {print \$1}"`)
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

// tcpLookupIP resolves host via DNS-over-TCP (system resolver, forced TCP
// transport). Endpoint pinning MUST NOT trust plain UDP answers: the tunnel
// front domain (cdn.srwx.ru) is a prime ТСПУ poisoning target — poisoned UDP
// answers returned bogus IPs (incl. the DNS pin's own 77.88.8.8), which the
// daemon then pinned as tunnel endpoints, blackholing traffic intermittently
// (field 2026-11-11: the whole day's «tunnel flaps» boil down to this).
// DNS-over-TCP responses cannot be injected the same way.
func tcpLookupIP(host string) ([]net.IP, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", address) // force TCP transport
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

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
		if ip == wanDNS {
			// DNS-пин из deploy-скрипта — не endpoint туннеля; reconciler не
			// должен его снимать (поле 2026-11-11: пин 77.88.8.8 исчезал)
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

// ndmExecFailed is the SHOW-path matcher (wave-2 F5): PREFIX-only matching.
// A failed exec surfaces as the sh()/ndmc() "ERR(" prefix; an ndmc that ran
// but failed reports "[C] ndm: Cli::Main: system failed" at the very start
// of the output. Verdict-verbs (bind/save/toggle) use ndmcFailed; SHOW
// output must NOT be word-matched — a legitimate hostname/policy containing
// "invalid" or "err(" would false-500.
func ndmExecFailed(out string) bool {
	return strings.HasPrefix(out, "ERR(") || strings.HasPrefix(out, "[C] ndm")
}

// ---- tunnel ----

func (d *Daemon) toggle(state string) string {
	return d.ndm("interface Proxy0 " + state)
}

// intentPath holds the OPERATOR intent for the tunnel switch ("up"/"down").
// The sc view cannot serve this role: it mirrors the live state (an interface
// down → the up-node vanishes), so "owner turned it off" and "flap" are
// indistinguishable there. kgate toggle on/off writes this file; the web
// switch does NOT — a web click (which writes a raw down to a live tunnel)
// is overridden by flapSelfHeal within one tick. This is deliberate: the
// off-switch is `kgate toggle off`, documented in operations.md.
const defaultIntentPath = "/opt/etc/kgate/intent"

func (d *Daemon) intentDown() bool {
	b, err := os.ReadFile(d.intentFile())
	if err != nil {
		return false // no file = no explicit off → default up (deploy intent)
	}
	return strings.TrimSpace(string(b)) == "down"
}

func (d *Daemon) intentFile() string {
	if d.intentPath != "" {
		return d.intentPath
	}
	return defaultIntentPath
}

// superviseProxy (kgate-1.4.4 self-heal, переработано поле-приёмкой
// 2026-11-11 — «веб-тумблер должен работать»):
//
//	down + intent=down            → ничего (оператор выключил, уважаем)
//	down + intent=up + sing-box ЖИВ  → ВНЕШНЕЕ выключение (веб-тумблер / ndmc) —
//	                                  ПРИНИМАЕМ: intent := down, НЕ поднимаем
//	down + intent=up + sing-box МЁРТВ → крэш движка — flap self-heal: поднимаем
//	up + intent=down + sing-box ЖИВ  → внешнее включение — принимаем: intent := up
//
// Собственные toggle демона (CLI/API/autoup/heal) помечаются lastSelfToggle и
// 30с не участвуют в adoption — гасит гонку «intent записан, верб в полёте».
func (d *Daemon) flapSelfHeal(logger func(string)) {
	if d.deployInFlight() {
		return // deploy-окно (рестарт движка): adoption/heal молчат — autoup рулит
	}
	state := d.proxyState()
	if strings.Contains(state, "state: down") {
		if d.intentDown() {
			return // operator intent: off (kgate toggle off / принятый веб-тумблер)
		}
		if d.selfToggleFresh() {
			return // собственное действие демона в полёте — не вмешиваемся
		}
		if d.singboxAlive() {
			if err := d.writeIntent("down"); err != nil {
				logger("supervisor: веб-тумблер опустил Proxy0, но intent записать не удалось: " + err.Error())
				return
			}
			logger("supervisor: Proxy0 опущен вне kgate (веб-тумблер) — принят как intent=down, туннель остаётся выключенным")
			return
		}
		// sing-box мёртв — это крэш движка, не действие оператора: flap self-heal
		d.toggle("up")
		d.markSelfToggle()
		logger("supervisor: Proxy0 упал при intent=up (движок мёртв) — поднимаю (flap self-heal)")
		return
	}
	// Proxy0 поднят, но intent говорит down: внешний up (веб-тумблер ON) —
	// принимаем как намерение (симметрично down), иначе self-heal позже
	// задушит легитимное включение.
	if d.intentDown() && d.singboxAlive() && !d.selfToggleFresh() {
		if err := d.writeIntent("up"); err == nil {
			logger("supervisor: Proxy0 поднят вне kgate (веб-тумблер) — принят как intent=up")
		}
	}
}

// markSelfToggle помечает момент собственного toggle демона (grace-окно для
// superviseProxy — не путать собственное действие с внешним переключением).
func (d *Daemon) markSelfToggle() {
	d.lastSelfToggleMu.Lock()
	defer d.lastSelfToggleMu.Unlock()
	d.lastSelfToggle = time.Now()
}

// deployInFlight сообщает, что на роутере идёт/недавно прошёл deploy: штамп
// deploy.epoch ставит Services-шаг деплоя перед рестартом движка. В этом окне
// Proxy0 закономерно вниз, sing-box жив — без маркера adoption принимал бы
// деплой за «веб-тумблер» и глушил intent (поле 2026-11-11: туннель завис
// вниз после деплоя, autoup пропустил подъём по принятому intent=down).
func (d *Daemon) deployInFlight() bool {
	path := filepath.Join(filepath.Dir(d.intentFile()), "deploy.epoch")
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	epoch, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return false
	}
	return time.Since(time.Unix(epoch, 0)) < 3*time.Minute
}

func (d *Daemon) selfToggleFresh() bool {
	d.lastSelfToggleMu.Lock()
	defer d.lastSelfToggleMu.Unlock()
	return time.Since(d.lastSelfToggle) < 30*time.Second
}

// singboxAlive проверяет, жив ли процесс sing-box на роутере (локальный proc
// скан: демон исполняется на том же хосте). Различает «крэш движка» (heal) и
// «ручное выключение тумблером» (adopt): тумблер опускает ТОЛЬКО интерфейс,
// процесс sing-box остаётся жить.
func (d *Daemon) singboxAlive() bool {
	if d.singboxAliveFn != nil {
		return d.singboxAliveFn()
	}
	return false // nil seam (прямая сборка в тестах): детерминированно «мёртв» → heal-путь; прод-конструктор New() ставит procScanSingbox
}

// procScanSingbox — /proc cmdline scan for a live sing-box process.
func procScanSingbox() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return true // не смогли проверить — считаем живым (не откатываем внешнее)
	}
	for _, e := range entries {
		if !e.IsDir() || !isPid(e.Name()) {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "sing-box") {
			return true
		}
	}
	return false
}

func isPid(name string) bool {
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}
	return name != ""
}

// writeIntent пишет intent-файл (adopt-путь супервизора; toggle-хендлер и
// deploy пишут сами). Ошибка возвращается вызывающему — adopt молчит.
func (d *Daemon) writeIntent(state string) error {
	return os.WriteFile(d.intentFile(), []byte(state+"\n"), 0644)
}

func (d *Daemon) proxyState() string {
	out := d.ndm("show interface Proxy0")
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
	logger("supervisor: принял стек (sing-box)")
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
		if d.intentDown() {
			logger("autoup: пропущен — intent=down (туннель явно выключен владельцем)")
			return
		}
		if d.waitPort("127.0.0.1:1080", 60*time.Second) {
			// БЕЗ admin-проверки (revert vol.3): running-config ЗЕРКАЛИТ
			// operational state — в окне прогрева движка там закономерно `down`,
			// и чек принимал прогрев за операторский OFF, глуша подъём навсегда
			// (field 2026-11-11: туннель застревал вниз после холодного деплоя).
			// OFF-клик в deploy-окне (~60-90с) — известная потеря, документирована.
			d.toggle("up")
			d.markSelfToggle()
			logger("autoup: Proxy0 up (tunnel engine готов)")
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
			d.flapSelfHeal(logger)
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

// toggleHandler is the /api/v1/toggle endpoint (extracted for tests, wave-1 A3).
func (d *Daemon) toggleHandler() http.HandlerFunc {
	return postOnly(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			State string `json:"state"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		if in.State != "on" && in.State != "off" {
			http.Error(w, "state: on|off", 400)
			return
		}
		verb := map[string]string{"on": "up", "off": "down"}[in.State]
		// operator intent file: the ONLY off-switch the self-heal respects
		// (kgate-1.4.6). /opt/etc/kgate survives reboots without ndm save.
		// Written BEFORE d.toggle: flapSelfHeal (15s tick) reads this file —
		// writing after the toggle raced the tick (a "down" click could be
		// re-raised before the intent landed). Readers expect the literal
		// verb ("up"/"down"), not the API state word (kgate.init, ndmc-shim,
		// intentDown all compare against "down").
		if err := os.WriteFile(d.intentFile(), []byte(verb+"\n"), 0644); err != nil {
			// wave-2 F4: the off-switch contract requires the intent to land
			// BEFORE the mutation — a failed write must abort the toggle
			// entirely (no ndmc call, no 200): an unrecorded "down" would be
			// re-raised by flapSelfHeal while the client saw success.
			fmt.Printf("kgate: intent write FAILED (%s): %v — toggle прерван\n", d.intentFile(), err)
			http.Error(w, fmt.Sprintf("запись intent (%s) не удалась: %v — toggle НЕ выполнен (off-switch не удержится)", d.intentFile(), err), http.StatusInternalServerError)
			return
		}
		out := d.toggle(verb)
		d.markSelfToggle()
		if ndmcFailed(out) {
			// intent is already persisted (the off-switch holds); the response
			// must surface the ndmc rejection, not fake success (wave-1 C4)
			http.Error(w, "ndmc отклонил toggle: "+strings.TrimSpace(out), http.StatusInternalServerError)
			return
		}
		// keep the sc view/dashboard switch truthful for on-toggles
		time.Sleep(1 * time.Second)
		_ = d.ndm("system configuration save")
		time.Sleep(5 * time.Second)
		json.NewEncoder(w).Encode(map[string]string{"ndmc": out, "proxy0": d.proxyState()})
	})
}

// postOnly enforces the mutate method discipline (wave-2 F10): non-POST gets
// 405 + Allow before the handler body runs, so a GET (link-preview/crawler)
// can never fire a mutation. Mirrors the policy mutate() wrapper.
func postOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "метод "+r.Method+" запрещён: endpoint мутирует — используй POST", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
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
	mux.Handle("/api/v1/toggle", postOnly(d.toggleHandler()))
	mux.HandleFunc("/api/v1/ruexit", postOnly(func(w http.ResponseWriter, r *http.Request) {
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
	}))
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
	mux.HandleFunc("/api/v1/reboot", postOnly(func(w http.ResponseWriter, r *http.Request) {
		out := d.ndmc("system reboot")
		json.NewEncoder(w).Encode(map[string]string{"ndmc": out})
		time.Sleep(time.Second)
		os.Exit(0)
	}))
	d.registerPolicyHandlers(mux, logger)

	srv := &http.Server{Addr: d.cfg.Daemon.APIListen, Handler: mux, TLSConfig: tlsCfg,
		ReadHeaderTimeout: 5 * time.Second}
	logger("api: mTLS listener " + d.cfg.Daemon.APIListen)
	return srv.ListenAndServeTLS(d.cfg.Daemon.WebRoot+"/server.crt", d.cfg.Daemon.WebRoot+"/server.key")
}
