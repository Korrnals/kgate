package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"kgate/internal/model"
)

// fakeNDM records ndmc commands; failOn marks commands whose output mimics
// the ndm failure surface ("system failed").
type fakeNDM struct {
	cmds   []string
	failOn map[string]bool
}

func (f *fakeNDM) run(cmd string) string {
	f.cmds = append(f.cmds, cmd)
	if f.failOn[cmd] {
		return "[C] ndm: Cli::Main: system failed [0xcffd00d9]"
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
	if !strings.Contains(joined, "не резолвится") || !strings.Contains(joined, "отложено") {
		t.Fatalf("expected resolve warn + deferral log, got: %v", logs)
	}
}
