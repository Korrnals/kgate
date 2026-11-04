// Package daemon — серверная часть kgate: супервизор VPN-стека + mTLS API.
// Заменяет обвязку: S99sing-box, rc-redirect v5, rc-redirect-watchdog, boot-autoup.
// Работает на роутере как root (iptables/ndmc). Один тик супервизора:
//   1. убедиться, что sing-box и xray живы (рестарт с бэкоффом, RLIMIT_NOFILE)
//   2. убедиться, что DNS-цепочка SBREDIRECT в nat на месте (ndm любит её сносить)
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

	"kgate/internal/model"
	"golang.org/x/sys/unix"
)

type Daemon struct {
	cfg     *model.Config
	mgr     *procManager
	lastIPOK bool
	upOnce  bool
}

func New(cfg *model.Config) *Daemon {
	return &Daemon{cfg: cfg, mgr: newProcManager(cfg)}
}

// ---- системные вызовы-обёртки ----

func sh(script string) string {
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Env = daemonEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("ERR(%v): ", err) + strings.TrimSpace(string(out))
	}
	return strings.TrimSpace(string(out))
}

// daemonEnv — детерминированное окружение: при буте rc.unslung может дать урезанный env,
// из-за чего ndmc/grep в статус-скриптах вели себя иначе, чем при рестарте из ssh.
func daemonEnv() []string {
	return []string{
		"PATH=/opt/bin:/opt/sbin:/opt/usr/bin:/opt/usr/sbin:/sbin:/usr/sbin:/bin:/usr/bin",
		"HOME=/",
		"TERM=linux",
	}
}

func (d *Daemon) ndmc(cmd string) string {
	return sh(`/bin/ndmc -c "` + strings.ReplaceAll(cmd, `"`, `\"`) + `"`)
}

// ---- процесс-менеджер ----

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
	// xray больше не используется: его заменил собственный толерантный socks-relay (:1090).
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
	// зомби висит в /proc но не живой — не считать рабочим
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
	// FD-лимит выставлен на ДЕМОНЕ (unix.Setrlimit в Run) — дети наследуют.
	// (SysProcAttr.Rlimit отсутствует на arm64, sh-wrap с ulimit busybox ash не переваривает.)
	cmd := exec.Command(p.bin, p.args...)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// reaper: забирать статус умершего ребёнка (иначе зомби в /proc врёт alive)
	go cmd.Wait()
	p.cmd = cmd
	p.backoff = 0
	return os.WriteFile(p.pidfile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
}


func (m *procManager) killAll() {
	// по ps (killall в busybox ненадёжен для наших имён)
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
			if p.backoff != 0 { // только переходDead->Alive логируем
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

// ---- iptables DNS-DNAT (rc-redirect v5, внутри демона) ----

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

// ---- туннель ----

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

// ждать порт sing-box (для автоподъёма туннеля без гонки)
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

// ---- статус/верификация ----

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

func (d *Daemon) clashEndpoints() []string { return []string{"http://127.0.0.1:9090", "http://192.168.1.1:9090"} }

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

// ---- главный цикл ----

func (d *Daemon) Run() error {
	fmt.Println("kgate daemon: старт, тик", d.cfg.Daemon.Interval)
	// FD-лимит на себя: дети (sing-box/xray) наследуют. Двухступенчато: hard, потом soft.
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

	// один раз при старте: чистим чужие процессы и берём управление на себя
	d.mgr.killAll()
	logger("supervisor: принял стек (sing-box + xray)")
	d.mgr.ensure()
	d.iptablesApply()
	if err := d.relayListen(d.cfg.Daemon.RelayListen, d.cfg.Daemon.RelayUpstream); err != nil {
		logger("relay: ОШИБКА " + err.Error())
	} else {
		logger("relay: слушаю " + d.cfg.Daemon.RelayListen + " -> " + d.cfg.Daemon.RelayUpstream + " (толерантный socks: замена xray)")
	}
	logger("supervisor: dns-rules применены")

	go func() { // автоподъём туннеля: ждём :1080, потом up (без гонки с Entware)
		if !d.cfg.Daemon.BootAutoup {
			return
		}
		delay := model.Dur(d.cfg.Daemon.AutoupDelay, 25*time.Second)
		time.Sleep(delay)
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
		for range tick.C {
			for _, l := range d.mgr.ensure() {
				logger("supervisor: " + l)
			}
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
		var in struct{ State string `json:"state"` }
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
		var in struct{ Mode string `json:"mode"` }
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
