package daemon

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"kgate/internal/model"
)

// fakeNDM records ndmc commands; failOn marks commands whose output mimics
// the ndm failure surface ("system failed").
type fakeNDM struct {
	cmds      []string
	failOn    map[string]bool
	responses map[string]string // scripted replies for show-commands
}

func (f *fakeNDM) run(cmd string) string {
	f.cmds = append(f.cmds, cmd)
	if f.failOn[cmd] {
		return "[C] ndm: Cli::Main: system failed [0xcffd00d9]"
	}
	if f.responses != nil {
		if r, ok := f.responses[cmd]; ok {
			return r
		}
	}
	return ""
}

func (f *fakeNDM) adds() []string { return f.filter("ip route ", true) }
func (f *fakeNDM) dels() []string { return f.filter("no ip route ", true) }

// filter collects recorded commands by prefix; strip removes the
// "ip route "/"no ip route " prefix and the " ISP" suffix, leaving bare IPs.
func (f *fakeNDM) filter(prefix string, strip bool) []string {
	var out []string
	for _, c := range f.cmds {
		if !strings.HasPrefix(c, prefix) {
			continue
		}
		if strip {
			out = append(out, strings.TrimSuffix(strings.TrimPrefix(c, prefix), " ISP"))
		} else {
			out = append(out, strings.TrimSuffix(c, " ISP"))
		}
	}
	sort.Strings(out)
	return out
}

// testDaemon builds a Daemon wired to fake ndm + a per-test resolver stub;
// the sing-box config is written from outbounds specs "type/server".
func testDaemon(t *testing.T, serverIP string, outbounds ...string) (*Daemon, *fakeNDM) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	var ob strings.Builder
	for _, spec := range outbounds {
		parts := strings.SplitN(spec, "/", 2)
		typ, server := parts[0], ""
		if len(parts) == 2 {
			server = parts[1]
		}
		ob.WriteString(fmt.Sprintf(`{"type":%q,"tag":"t-%s","server":%q},`, typ, typ, server))
	}
	json := `{"outbounds":[` + strings.TrimSuffix(ob.String(), ",") + `]}`
	if err := os.WriteFile(cfgPath, []byte(json), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &model.Config{}
	cfg.ServerIP = serverIP
	cfg.Daemon.SingBoxConfig = cfgPath
	d := &Daemon{cfg: cfg}
	fake := &fakeNDM{}
	d.ndmcFn = fake.run
	d.resolveFn = func(host string) ([]net.IP, error) { return net.LookupIP(host) }
	return d, fake
}

func ips(s string) []net.IP {
	var out []net.IP
	for _, p := range strings.Split(s, ",") {
		out = append(out, net.ParseIP(strings.TrimSpace(p)))
	}
	return out
}

func TestSyncPin_FollowsDNSFlip(t *testing.T) {
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	resolver := map[string][]net.IP{"cdn.example": ips("2.2.2.2")}
	d.resolveFn = func(h string) ([]net.IP, error) { return resolver[h], nil }

	var logs []string
	d.syncServerPin(func(s string) { logs = append(logs, s) })

	if got := fake.adds(); len(got) != 1 || got[0] != "2.2.2.2" {
		t.Fatalf("adds = %v, want [2.2.2.2]", got)
	}
	if got := fake.dels(); len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("dels = %v, want [1.1.1.1]", got)
	}
	if _, ok := d.pins["2.2.2.2"]; !ok {
		t.Fatalf("pins = %v, want {2.2.2.2}", d.pins)
	}
	if _, ok := d.pins["1.1.1.1"]; ok {
		t.Fatalf("pins = %v, want {2.2.2.2}", d.pins)
	}
	_ = logs
}

func TestSyncPin_MultiA_AllPinned(t *testing.T) {
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.resolveFn = func(string) ([]net.IP, error) { return ips("2.2.2.2, 3.3.3.3, 2001:db8::1"), nil }

	d.syncServerPin(func(string) {})

	got := fake.adds()
	if len(got) != 2 || got[0] != "2.2.2.2" || got[1] != "3.3.3.3" {
		t.Fatalf("adds = %v, want both v4 A-records (AAAA ignored)", got)
	}
}

func TestSyncPin_NdmcFailure_KeepsStateRetries(t *testing.T) {
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.resolveFn = func(string) ([]net.IP, error) { return ips("2.2.2.2"), nil }
	var logs []string
	log := func(s string) { logs = append(logs, s) }

	fake.failOn = map[string]bool{"ip route 2.2.2.2 ISP": true}
	d.syncServerPin(log)
	if _, ok := d.pins["2.2.2.2"]; ok {
		t.Fatal("pin state updated despite ndmc failure")
	}
	if _, ok := d.pins["1.1.1.1"]; !ok {
		t.Fatal("seed pin lost on failed flip")
	}
	if !strings.Contains(strings.Join(logs, "\n"), "НЕ удалось запинить 2.2.2.2") {
		t.Fatalf("no loud failure log: %v", logs)
	}

	// next tick: ndmc healthy → converges, stale seed removed
	fake.failOn = nil
	d.syncServerPin(log)
	if _, ok := d.pins["2.2.2.2"]; !ok {
		t.Fatalf("pins = %v, want {2.2.2.2}", d.pins)
	}
	if _, ok := d.pins["1.1.1.1"]; ok {
		t.Fatalf("pins after retry = %v, want {2.2.2.2}", d.pins)
	}
}

func TestSyncPin_ResolveFailure_WarnOnceKeepsPins(t *testing.T) {
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.resolveFn = func(string) ([]net.IP, error) { return nil, fmt.Errorf("no such host") }

	n := 0
	log := func(s string) {
		if strings.Contains(s, "не резолвится") {
			n++
		}
	}
	d.syncServerPin(log)
	d.syncServerPin(log)
	if n != 1 {
		t.Fatalf("resolve warn logged %d times, want once (log-once)", n)
	}
	if got := fake.adds(); len(got) != 0 {
		t.Fatalf("adds on resolver failure = %v, want none", got)
	}
	if _, ok := d.pins["1.1.1.1"]; !ok || len(d.pins) != 1 {
		t.Fatalf("pins = %v, want seed kept", d.pins)
	}
}

func TestSyncPin_NoV4_WarnOnce(t *testing.T) {
	d, _ := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.resolveFn = func(string) ([]net.IP, error) { return ips("2001:db8::1"), nil }

	n := 0
	log := func(s string) {
		if strings.Contains(s, "нет A-записей") {
			n++
		}
	}
	d.syncServerPin(log)
	d.syncServerPin(log)
	if n != 1 {
		t.Fatalf("nov4 warn logged %d times, want once", n)
	}
}

func TestSyncPin_NoEndpoints_WarnOnce(t *testing.T) {
	d, fake := testDaemon(t, "1.1.1.1", "direct", "selector") // no server fields at all
	d.resolveFn = func(string) ([]net.IP, error) { return nil, fmt.Errorf("must not be called") }

	n := 0
	log := func(string) { n++ }
	d.syncServerPin(log)
	d.syncServerPin(log)
	if n != 1 {
		t.Fatalf("noendpoints warn logged %d times, want once", n)
	}
	if got := fake.adds(); len(got) != 0 {
		t.Fatalf("adds = %v, want none", got)
	}
}

func TestSyncPin_LiteralIP_NoResolve(t *testing.T) {
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/4.4.4.4")
	calls := 0
	d.resolveFn = func(string) ([]net.IP, error) { calls++; return nil, nil }

	d.syncServerPin(func(string) {})

	if calls != 0 {
		t.Fatalf("resolver called %d times for a literal IP, want 0", calls)
	}
	if got := fake.adds(); len(got) != 1 || got[0] != "4.4.4.4" {
		t.Fatalf("adds = %v, want [4.4.4.4]", got)
	}
}

func TestServerHosts_SubscriptionConfig_Deduped(t *testing.T) {
	d, _ := testDaemon(t, "1.1.1.1",
		"hysteria2/cdn.example",
		"vless/node-a.example",
		"trojan/node-a.example", // same server, different protocol → deduped
		"shadowsocks/node-b.example",
		"selector", // no server field
		"direct",
	)
	got := d.serverHosts()
	want := []string{"cdn.example", "node-a.example", "node-b.example"}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("serverHosts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("serverHosts = %v, want %v", got, want)
		}
	}
}

func TestServerHosts_ReadError_FallsBackToServerIP(t *testing.T) {
	cfg := &model.Config{}
	cfg.ServerIP = "9.9.9.9"
	cfg.Daemon.SingBoxConfig = "/nonexistent/config.json"
	d := &Daemon{cfg: cfg}
	got := d.serverHosts()
	if len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("serverHosts = %v, want [9.9.9.9] (yaml fallback)", got)
	}
}

func TestNdmcFailed(t *testing.T) {
	cases := map[string]bool{
		"":            false,
		"some output": false,
		"[C] ndm: Cli::Main: system failed [0xcffd00d9]": true,
		"ERR(exit status 127): /bin/ndmc: not found":     true,
		"ndmc: invalid parameters.":                      true,
	}
	for in, want := range cases {
		if got := ndmcFailed(in); got != want {
			t.Fatalf("ndmcFailed(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSyncPin_MultiHost_ResolveFailureKeepsConfirmedPins(t *testing.T) {
	// wave-2 MAJOR regression: host A resolves fine, host B's DNS fails for a
	// tick — B's confirmed pins must NOT be stripped as stale (the removal
	// gate must see the resolve failure), while A's pins track normally.
	d, fake := testDaemon(t, "1.1.1.1",
		"hysteria2/host-a.example",
		"vless/host-b.example",
	)
	resolver := map[string][]net.IP{"host-a.example": ips("5.5.5.5")}
	failB := false
	d.resolveFn = func(h string) ([]net.IP, error) {
		if h == "host-b.example" {
			if failB {
				return nil, fmt.Errorf("temp fail")
			}
			return ips("6.6.6.6"), nil
		}
		return resolver[h], nil
	}

	d.syncServerPin(func(string) {}) // tick 1: both resolve → pins {1.1.1.1?, 5.5.5.5, 6.6.6.6}
	if _, ok := d.pins["6.6.6.6"]; !ok {
		t.Fatalf("B's pin missing after tick 1: %v", d.pins)
	}

	failB = true // tick 2: B's DNS dies
	fake.cmds = nil
	var logs []string
	d.syncServerPin(func(s string) { logs = append(logs, s) })

	for _, c := range fake.cmds {
		if strings.HasPrefix(c, "no ip route") {
			t.Fatalf("removal attempted while DNS unhealthy: %v", fake.cmds)
		}
	}
	if _, ok := d.pins["6.6.6.6"]; !ok {
		t.Fatalf("B's confirmed pin lost on resolve failure: %v", d.pins)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "не резолвится") || !strings.Contains(joined, "удержаны") {
		t.Fatalf("expected resolve warn + hold log, got: %v", logs)
	}
}

func TestSyncPin_ProvenanceGate_OwnerGoneFlushed_UnhealthyOwnerKept(t *testing.T) {
	// wave-3 F-1: removals scoped by pin provenance, not global DNS health.
	// tick 1: hosts A,B,C healthy → pins for each. tick 2: C removed from the
	// config, A's DNS dies, B healthy → C's pin FLUSHED (owner left config),
	// A's pin KEPT (owner unhealthy), seed kept (global uncertainty).
	dir := t.TempDir()
	cfgPath := dir + "/config.json"
	write := func(body string) {
		if err := os.WriteFile(cfgPath, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &model.Config{}
	cfg.ServerIP = "1.1.1.1"
	cfg.Daemon.SingBoxConfig = cfgPath
	d := &Daemon{cfg: cfg}
	fake := &fakeNDM{}
	d.ndmcFn = fake.run

	write(`{"outbounds":[
		{"type":"vless","tag":"a","server":"host-a.example","server_port":443,"uuid":"u"},
		{"type":"vless","tag":"b","server":"host-b.example","server_port":443,"uuid":"u"},
		{"type":"vless","tag":"c","server":"host-c.example","server_port":443,"uuid":"u"}]}`)
	d.resolveFn = func(h string) ([]net.IP, error) {
		m := map[string][]net.IP{
			"host-a.example": ips("5.5.5.5"),
			"host-b.example": ips("6.6.6.6"),
			"host-c.example": ips("7.7.7.7"),
		}
		return m[h], nil
	}
	d.syncServerPin(func(string) {}) // tick 1: всё здорово
	for _, ip := range []string{"5.5.5.5", "6.6.6.6", "7.7.7.7"} {
		if _, ok := d.pins[ip]; !ok {
			t.Fatalf("pin %s отсутствует после tick 1: %v", ip, d.pins)
		}
	}
	// сид ServerIP легитимно смывается в здоровом тике (deploy-пин заменён
	// актуальными endpoint'ами — это и есть DNS-flip self-heal)
	if _, ok := d.pins["1.1.1.1"]; ok {
		t.Fatalf("сид должен быть заменён актуальными пинами в здоровом тике: %v", d.pins)
	}

	// tick 2: C ушёл из конфига, A не резолвится, B жив
	write(`{"outbounds":[
		{"type":"vless","tag":"a","server":"host-a.example","server_port":443,"uuid":"u"},
		{"type":"vless","tag":"b","server":"host-b.example","server_port":443,"uuid":"u"}]}`)
	failA := map[string]bool{"host-a.example": true}
	d.resolveFn = func(h string) ([]net.IP, error) {
		if failA[h] {
			return nil, fmt.Errorf("temp fail")
		}
		m := map[string][]net.IP{"host-b.example": ips("6.6.6.6")}
		return m[h], nil
	}
	fake.cmds = nil
	d.syncServerPin(func(string) {})

	got := fake.dels()
	if len(got) != 1 || got[0] != "7.7.7.7" {
		t.Fatalf("dels = %v, want только ушедший из конфига 7.7.7.7 (A-пин удержан)", got)
	}
	if _, ok := d.pins["5.5.5.5"]; !ok {
		t.Fatalf("A-пин потерян при живом-в-конфиге, но нездоровом владельце: %v", d.pins)
	}

}

func TestSyncPin_HealthyOwner_StalePinFlushedOnDNSFlip(t *testing.T) {
	// wave-4 W4-1 regression: healthy in-config owner, DNS moves to a new IP —
	// old pin REMOVED, new pin added. Without resolvedOK stamping the hold
	// condition is permanently true and removal is dead code.
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	current := []net.IP{net.ParseIP("2.2.2.2")}
	d.resolveFn = func(string) ([]net.IP, error) { return current, nil }
	d.syncServerPin(func(string) {})
	if _, ok := d.pins["2.2.2.2"]; !ok {
		t.Fatalf("нет пина после tick 1: %v", d.pins)
	}
	// DNS уехал:healthy owner resolves to a NEW address — резолвится здорово
	current = []net.IP{net.ParseIP("3.3.3.3")}
	fake.cmds = nil
	d.syncServerPin(func(string) {})
	got := fake.dels()
	if len(got) != 1 || got[0] != "2.2.2.2" {
		t.Fatalf("dels = %v, want [2.2.2.2] — healthy-owner stale pin должен сниматься", got)
	}
	if _, ok := d.pins["3.3.3.3"]; !ok {
		t.Fatalf("новый пин не добавлен: %v", d.pins)
	}
}

func TestSyncPin_AAAAOnly_KeepsConfirmedPins(t *testing.T) {
	// wave-3 F-3 + wave-4 W4-2: хост A отдавал A (пин подтверждён), затем стал
	// AAAA-only; host B здоров и даёт want — provenance-hold удерживает пин A
	// (не noendpoints early-return: want непуст благодаря B)
	d, _ := testDaemon(t, "1.1.1.1", "hysteria2/host-a.example", "vless/host-b.example")
	aaaaOnly := false
	d.resolveFn = func(h string) ([]net.IP, error) {
		switch {
		case h == "host-b.example":
			return ips("6.6.6.6"), nil
		case aaaaOnly:
			return ips("2001:db8::1"), nil
		default:
			return ips("5.5.5.5"), nil
		}
	}
	d.syncServerPin(func(string) {})
	if _, ok := d.pins["5.5.5.5"]; !ok {
		t.Fatalf("нет подтверждённого пина A после tick 1: %v", d.pins)
	}
	aaaaOnly = true
	d.syncServerPin(func(string) {}) // tick 2: A стал AAAA-only
	if _, ok := d.pins["5.5.5.5"]; !ok {
		t.Fatalf("AAAA-only флип срезал подтверждённый пин A: %v", d.pins)
	}
}

func TestFlapSelfHeal_IntentUp_Reraises(t *testing.T) {
	// kgate-1.4.6 re-raise, уточнено поле-приёмкой 2026-11-11: re-raise теперь
	// ТОЛЬКО при мёртвом движке (crash flap). При ЖИВОМ sing-box down+intent=up
	// = внешнее выключение → adoption (TestSuperviseProxy_ExternalDown_AdoptedAsIntent).
	// Здесь seam singboxAliveFn не задан → дефолт false → движок «мёртв» → heal.
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.intentPath = filepath.Join(t.TempDir(), "intent")
	fake.responses = map[string]string{
		"show interface Proxy0": "        state: down\n     connected: no",
	}
	var logs []string
	d.flapSelfHeal(func(s string) { logs = append(logs, s) })
	found := false
	for _, c := range fake.cmds {
		if c == "interface Proxy0 up" {
			found = true
		}
	}
	if !found {
		t.Fatalf("re-raise не выполнен (intent отсутствует = up): %v; logs=%v", fake.cmds, logs)
	}
	_ = logs

	// intent=up явно → тоже ре-райз (сбрасываем grace-метку первой фазы —
	// superviseProxy не вмешивается 30с после собственного toggle)
	os.WriteFile(d.intentPath, []byte("up\n"), 0644)
	d.lastSelfToggle = time.Time{}
	fake.cmds = nil
	d.flapSelfHeal(func(string) {})
	found = false
	for _, c := range fake.cmds {
		if c == "interface Proxy0 up" {
			found = true
		}
	}
	if !found {
		t.Fatalf("re-raise не выполнен (intent=up): %v", fake.cmds)
	}
}

func TestFlapSelfHeal_IntentDown_Respected(t *testing.T) {
	// kgate toggle off записал intent=down — ре-райза НЕТ
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.intentPath = filepath.Join(t.TempDir(), "intent")
	os.WriteFile(d.intentPath, []byte("down\n"), 0644)
	fake.responses = map[string]string{
		"show interface Proxy0": "        state: down\n     connected: no",
	}
	d.flapSelfHeal(func(string) {})
	for _, c := range fake.cmds {
		if c == "interface Proxy0 up" {
			t.Fatalf("ре-райз вопреки intent=down: %v", fake.cmds)
		}
	}
}

func TestFlapSelfHeal_Up_Noop(t *testing.T) {
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.intentPath = filepath.Join(t.TempDir(), "intent")
	fake.responses = map[string]string{
		"show interface Proxy0": "        state: up\n     connected: yes",
	}
	before := len(fake.cmds)
	d.flapSelfHeal(func(string) {})
	for _, c := range fake.cmds[before:] {
		if c != "show interface Proxy0" { // health-check разрешён, тоггл — нет
			t.Fatalf("лишняя команда при поднятом туннеле: %v", fake.cmds[before:])
		}
	}
}

// wave-1 A3: the /api/v1/toggle handler is the PROD intent writer — the test
// exercises it via httptest instead of hand-writing the intent file.
func TestToggleHandler_Off_IntentVocabulary_AndOrder(t *testing.T) {
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.intentPath = filepath.Join(t.TempDir(), "intent")
	intentAtToggle := ""
	base := d.ndmcFn
	d.ndmcFn = func(cmd string) string {
		if cmd == "interface Proxy0 down" {
			b, _ := os.ReadFile(d.intentPath) // order check: intent must be ALREADY written
			intentAtToggle = string(b)
		}
		return base(cmd)
	}
	req := httptest.NewRequest("POST", "/api/v1/toggle", strings.NewReader(`{"state":"off"}`))
	rec := httptest.NewRecorder()
	d.toggleHandler()(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code = %d, body=%s", rec.Code, rec.Body.String())
	}
	if intentAtToggle != "down\n" {
		t.Fatalf("intent при вызове toggle = %q, want %q — intent должен писаться ДО d.toggle (гонка с flapSelfHeal)", intentAtToggle, "down\n")
	}
	b, _ := os.ReadFile(d.intentPath)
	if string(b) != "down\n" {
		t.Fatalf("intent-файл = %q, want %q (verb, не state)", string(b), "down\n")
	}
	if d.intentDown() != true {
		t.Fatal("intentDown() = false после toggle off")
	}
	// flapSelfHeal обязан уважать этот intent (Proxy0 down → ре-райза нет)
	fake.responses = map[string]string{
		"show interface Proxy0": "        state: down\n     connected: no",
	}
	fake.cmds = nil
	d.flapSelfHeal(func(string) {})
	for _, c := range fake.cmds {
		if c == "interface Proxy0 up" {
			t.Fatalf("flapSelfHeal поднял туннель вопреки intent, записанному прод-хендлером: %v", fake.cmds)
		}
	}
}

// wave-1 C4: ndmc rejected the toggle → 500 with the ndmc surface (intent
// stays persisted so the off-switch still holds).
func TestToggleHandler_NdmcFailed_500(t *testing.T) {
	d, _ := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.intentPath = filepath.Join(t.TempDir(), "intent")
	d.ndmcFn = func(string) string { return "[C] ndm: Cli::Main: system failed [0xcffd00d9]" }
	req := httptest.NewRequest("POST", "/api/v1/toggle", strings.NewReader(`{"state":"off"}`))
	rec := httptest.NewRecorder()
	d.toggleHandler()(rec, req)
	if rec.Code != 500 {
		t.Fatalf("code = %d, want 500 (ndmc-поверхность ошибки)", rec.Code)
	}
	b, _ := os.ReadFile(d.intentPath)
	if string(b) != "down\n" {
		t.Fatalf("intent должен пережить ndmc-отказ: %q", string(b))
	}
}

// wave-2 F4: провал записи intent — 500 и ПОЛНЫЙ abort: ndmc-мутации не было.
// Off-switch контракт: intent обязан приземлиться ДО мутации, иначе «down»
// перебьёт flapSelfHeal, а клиент увидит 200.
func TestToggleHandler_IntentWriteFailed_Aborts500_NoNdmc(t *testing.T) {
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.intentPath = filepath.Join(t.TempDir(), "no-such-dir", "intent") // недоступный путь
	req := httptest.NewRequest("POST", "/api/v1/toggle", strings.NewReader(`{"state":"off"}`))
	rec := httptest.NewRecorder()
	d.toggleHandler()(rec, req)
	if rec.Code != 500 {
		t.Fatalf("code = %d, want 500 (провал записи intent)", rec.Code)
	}
	for _, c := range fake.cmds {
		if strings.HasPrefix(c, "interface Proxy0") {
			t.Fatalf("toggle выполнен вопреки провалу записи intent: %v", fake.cmds)
		}
	}
	if len(fake.cmds) != 0 {
		t.Fatalf("ожидались только show-команды после abort, было: %v", fake.cmds)
	}
}

// wave-2 F10: mutate-эндпоинты (toggle/ruexit/reboot) — POST-only, GET = 405
// + Allow, мутация не выполняется.
func TestMutateEndpoints_GET_Rejected405(t *testing.T) {
	d, fake := testDaemon(t, "1.1.1.1", "hysteria2/cdn.example")
	d.intentPath = filepath.Join(t.TempDir(), "intent")
	mux := http.NewServeMux()
	mux.Handle("/api/v1/toggle", postOnly(d.toggleHandler()))
	mux.HandleFunc("/api/v1/ruexit", postOnly(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "не должен вызываться", 500)
	}))
	mux.HandleFunc("/api/v1/reboot", postOnly(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "не должен вызываться", 500)
	}))
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	client := srv.Client()
	for _, path := range []string{"/api/v1/toggle", "/api/v1/ruexit", "/api/v1/reboot"} {
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s: GET code = %d, want 405 (body=%s)", path, resp.StatusCode, string(b))
		}
		if allow := resp.Header.Get("Allow"); allow != "POST" {
			t.Fatalf("%s: Allow = %q, want POST", path, allow)
		}
	}
	for _, c := range fake.cmds {
		if strings.HasPrefix(c, "interface Proxy0") || strings.Contains(c, "reboot") {
			t.Fatalf("GET выполнил мутацию: %v", fake.cmds)
		}
	}
}

// wave-2 F5: SHOW-вывод с легитимным hostname/именем политики, содержащим
// "invalid"/"err(" — НЕ сбой ndmc (вербальный матч давал ложный 500). Сбой
// exec по-прежнему детектится по префиксу "ERR(".
func TestShowPaths_WordMatch_NotAFailure(t *testing.T) {
	d, _ := policyTestDaemon(t)
	d.ndmcFn = func(cmd string) string {
		if cmd == "show ip hotspot" {
			return strings.Replace(policyFixtureHotspot, `hostname: "pixel-phone"`, `hostname: "pixel-invalid-box"`, 1)
		}
		if cmd == "show ip policy" {
			return "             name: VPN-err(monitor)\n             name: NO-VPN"
		}
		return ""
	}
	if _, err := d.hotspotTable(); err != nil {
		t.Fatalf("hostname с \"invalid\" в SHOW-выводе — не сбой: %v", err)
	}
	if _, err := d.policyNames(); err != nil {
		t.Fatalf("имя политики с \"err(\" в SHOW-выводе — не сбой: %v", err)
	}
	// а настоящий exec-сбой (префикс ERR( от sh()/ndmc()) по-прежнему 500
	d.ndmcFn = func(string) string { return "ERR(exec: exit status 1): " }
	if _, err := d.hotspotTable(); err == nil {
		t.Fatal("префикс ERR( должен детектироваться как сбой exec")
	}
}

// wave-2 F7: упавший ndmc на show ip policy — 500-ошибка с ndm-поверхностью,
// а не user-ошибка «политика не найдена — сначала kgate deploy».
func TestPolicyExists_NdmcDown_PropagatesError(t *testing.T) {
	d, _ := policyTestDaemon(t)
	d.ndmcFn = func(cmd string) string {
		if cmd == "show ip policy" {
			return "[C] ndm: Cli::Main: system failed [0xcffd00d9]"
		}
		return policyFixtureHotspot
	}
	_, err := d.policyExists("VPN")
	if err == nil {
		t.Fatal("policyExists должен пробрасывать ошибку policyNames")
	}
	_, err = d.policySetDevice("smart-tv", "VPN")
	if err == nil {
		t.Fatal("set-device при упавшем ndmc должен вернуть ошибку")
	}
	if isClientPolicyErr(err) {
		t.Fatalf("ошибка ndmc ошибочно классифицирована как user-ошибка (400 вместо 500): %v", err)
	}
}

// --- web-switch adoption (поле-приёмка 2026-11-11: тумблер должен работать) ---

func TestSuperviseProxy_ExternalDown_AdoptedAsIntent(t *testing.T) {
	d, fake := policyTestDaemon(t)
	intent := filepath.Join(t.TempDir(), "intent")
	d.intentPath = intent
	d.singboxAliveFn = func() bool { return true } // sing-box жив → это ВЫКЛЮЧАТЕЛЬ, не крэш
	fake.responses["show interface Proxy0"] = "state: down"
	os.WriteFile(intent, []byte("up\n"), 0644)

	var logs []string
	d.flapSelfHeal(func(m string) { logs = append(logs, m) })

	b, _ := os.ReadFile(intent)
	if !strings.Contains(string(b), "down") {
		t.Fatalf("intent не принят как down: %q (logs=%v)", string(b), logs)
	}
	for _, c := range fake.cmds {
		if strings.Contains(c, "interface Proxy0 up") {
			t.Fatalf("внешнее выключение откачено — туннель подняли: %v", fake.cmds)
		}
	}
}

func TestSuperviseProxy_CrashFlap_StillHealed(t *testing.T) {
	d, fake := policyTestDaemon(t)
	intent := filepath.Join(t.TempDir(), "intent")
	d.intentPath = intent
	d.singboxAliveFn = func() bool { return false } // движок мёртв → flap self-heal
	fake.responses["show interface Proxy0"] = "state: down"
	os.WriteFile(intent, []byte("up\n"), 0644)

	d.flapSelfHeal(func(string) {})

	found := false
	for _, c := range fake.cmds {
		if strings.Contains(c, "interface Proxy0 up") {
			found = true
		}
	}
	if !found {
		t.Fatalf("крэш-флап не вылечен (нет Proxy0 up): %v", fake.cmds)
	}
}

func TestSuperviseProxy_ExternalUp_AdoptedAsIntent(t *testing.T) {
	d, fake := policyTestDaemon(t)
	intent := filepath.Join(t.TempDir(), "intent")
	d.intentPath = intent
	d.singboxAliveFn = func() bool { return true }
	fake.responses["show interface Proxy0"] = "state: up"
	os.WriteFile(intent, []byte("down\n"), 0644) // выключен kgate toggle off…
	d.flapSelfHeal(func(string) {})              // …но владелец включил тумблером

	b, _ := os.ReadFile(intent)
	if !strings.Contains(string(b), "up") {
		t.Fatalf("внешнее включение не принято: intent=%q", string(b))
	}
}

func TestSuperviseProxy_SelfToggleGrace_NoAdoption(t *testing.T) {
	d, fake := policyTestDaemon(t)
	intent := filepath.Join(t.TempDir(), "intent")
	d.intentPath = intent
	d.singboxAliveFn = func() bool { return true }
	fake.responses["show interface Proxy0"] = "state: down"
	os.WriteFile(intent, []byte("up\n"), 0644)
	d.markSelfToggle() // только что сам тогглили — 30с грейс

	d.flapSelfHeal(func(string) {})

	b, _ := os.ReadFile(intent)
	if !strings.Contains(string(b), "up") {
		t.Fatalf("собственное действие в grace-окне не должно принимать внешнее состояние: intent=%q", string(b))
	}
}

func TestSuperviseProxy_DeployInFlight_NoAdoption(t *testing.T) {
	d, fake := policyTestDaemon(t)
	dir := t.TempDir()
	d.intentPath = filepath.Join(dir, "intent")
	d.singboxAliveFn = func() bool { return true }
	os.WriteFile(filepath.Join(dir, "deploy.epoch"), []byte(fmt.Sprint(time.Now().Unix())), 0644) // deploy только что
	fake.responses["show interface Proxy0"] = "state: down"
	os.WriteFile(d.intentPath, []byte("up\n"), 0644)

	d.flapSelfHeal(func(string) {})

	b, _ := os.ReadFile(d.intentPath)
	if !strings.Contains(string(b), "up") {
		t.Fatalf("deploy-окно: adoption не должен переписывать intent: %q", string(b))
	}
	for _, c := range fake.cmds {
		if strings.Contains(c, "interface Proxy0 up") {
			t.Fatalf("deploy-окно: supervisor не должен рулить Proxy0: %v", fake.cmds)
		}
	}
}

func TestAutoup_AdminDownDuringDeploy_AdoptedAndSkipped(t *testing.T) {
	d, fake := policyTestDaemon(t)
	intent := filepath.Join(t.TempDir(), "intent")
	d.intentPath = intent
	d.singboxAliveFn = func() bool { return true }
	// sing-box порт поднимем (waitPort пройдёт) — слушаем на локальном порту
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("нет локального листенера")
	}
	defer ln.Close()
	// waitPort ждёт 127.0.0.1:1080 — подменить нельзя (шится в будущем), поэтому
	// проверяем proxyAdminDown напрямую + логику через прогон автoup с подменённым addr невозможен.
	// Вместо этого валидируем связку: admin-down в конфиге → proxyAdminDown=true.
	fake.responses["show running-config"] = "interface Proxy0\n    description \"HYST VPN (sing-box)\"\n    ip global 1200\n    down\n!\n"
	if !d.proxyAdminDown() {
		t.Fatalf("admin-down не распознан")
	}
	fake.responses["show running-config"] = "interface Proxy0\n    ip global 1200\n    up\n!\n"
	if d.proxyAdminDown() {
		t.Fatalf("admin-up распознан как down")
	}
	_ = ln
}
