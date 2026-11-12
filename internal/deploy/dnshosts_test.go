package deploy

import (
	"strings"
	"testing"

	"kgate/internal/model"
	"kgate/internal/policy"
)

// Fixture running-config: живая поверхность KeeneticOS 4.x — top-level
// строки `ip host <fqdn> <ip>` (без отступа); indented строки внутри блока
// ip hotspot (`host <mac> policy ...`) — ДРУГОЙ парсер и сюда не попадают.
const fixtureDNSRunCfg = "ip host nas.abyss.lab 192.168.1.10\nip host vpn.abyss.lab 203.0.113.10\nip hotspot\n    host 54:ae:bc:9c:de:bf policy NO-VPN\n"

func dnsDeclaredHosts() map[string]string {
	return map[string]string{
		"nas.abyss.lab": "192.168.1.10",
		"vpn.abyss.lab": "203.0.113.10",
	}
}

func dnsVerbsCmds(plan []dnsVerb) []string {
	out := make([]string, 0, len(plan))
	for _, v := range plan {
		out = append(out, v.cmd)
	}
	return out
}

// Полное схождение: обе записи уже в running-config = пустая дельта
// (no-op при повторном apply, ndmc-записей нет).
func TestDNSHostsPlanConvergedIsNoop(t *testing.T) {
	plan := DNSHostsPlan(fixtureDNSRunCfg, dnsDeclaredHosts())
	if len(plan) != 0 {
		t.Fatalf("ожидался пустой план (no-op), получили: %v", dnsVerbsCmds(plan))
	}
}

// Дельта: запись отсутствует — единственный bind-верб той же формой.
func TestDNSHostsPlanMissingRecord(t *testing.T) {
	want := map[string]string{"nas.abyss.lab": "192.168.1.10", "app.abyss.lab": "192.168.1.20"}
	plan := DNSHostsPlan(fixtureDNSRunCfg, want)
	cmds := dnsVerbsCmds(plan)
	if len(cmds) != 1 || cmds[0] != "ip host app.abyss.lab 192.168.1.20" {
		t.Fatalf("ожидался единственный верб для app.abyss.lab, получили: %v", cmds)
	}
}

// Дельта: fqdn есть, ip другой → re-bind той же формой (ndm перезапишет).
func TestDNSHostsPlanWrongIPRebind(t *testing.T) {
	want := dnsDeclaredHosts()
	want["nas.abyss.lab"] = "192.168.1.99"
	plan := DNSHostsPlan(fixtureDNSRunCfg, want)
	cmds := dnsVerbsCmds(plan)
	if len(cmds) != 1 || cmds[0] != "ip host nas.abyss.lab 192.168.1.99" {
		t.Fatalf("ожидался re-bind nas.abyss.lab, получили: %v", cmds)
	}
}

// Детерминизм: записи обходятся по отсортированным fqdn.
func TestDNSHostsPlanDeterministicOrder(t *testing.T) {
	want := map[string]string{"zeta.abyss.lab": "10.0.0.3", "alpha.abyss.lab": "10.0.0.1", "mid.abyss.lab": "10.0.0.2"}
	a := dnsVerbsCmds(DNSHostsPlan("", want))
	b := dnsVerbsCmds(DNSHostsPlan("", want))
	if len(a) != 3 {
		t.Fatalf("ожидались 3 верба, получили %d: %v", len(a), a)
	}
	if a[0] != "ip host alpha.abyss.lab 10.0.0.1" || a[2] != "ip host zeta.abyss.lab 10.0.0.3" {
		t.Fatalf("план не в отсортированном порядке: %v", a)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("план недетерминирован: %v vs %v", a, b)
		}
	}
}

// Парсинг живой поверхности: ANSI \x1b[K + \r (PTY) + CRLF — парсить только
// после StripANSI; indented `host <mac> policy` внутри ip hotspot НЕ считается
// dns-записью (regex якорится на top-level).
func TestParseHostRecordsANSICRLF(t *testing.T) {
	raw := "ip host nas.abyss.lab 192.168.1.10\r\n\x1b[Kip host vpn.abyss.lab 203.0.113.10\r\nip hotspot\r\n    host 54:ae:bc:9c:de:bf policy NO-VPN\r\n"
	recs := parseHostRecords(policy.StripANSI(raw))
	if len(recs) != 2 {
		t.Fatalf("ожидались 2 записи, получили %v", recs)
	}
	if recs["nas.abyss.lab"] != "192.168.1.10" || recs["vpn.abyss.lab"] != "203.0.113.10" {
		t.Fatalf("значения разъехались: %v", recs)
	}
	// а без strip парсер слеп (ANSI ломает строки) — документируем инвариант
	if got := parseHostRecords(raw); len(got) == len(recs) && len(recs) == 2 {
		if _, ok := got["vpn.abyss.lab"]; ok {
			t.Fatalf("strip-инвариант нарушился: ANSI-муусор распарсился")
		}
	}
	// sanity: indented host-строка не матчится и на чистом тексте
	if recs := parseHostRecords(fixtureDNSRunCfg); len(recs) != 2 {
		t.Fatalf("indented-строки просятся в dns-записи: %v", recs)
	}
}

// Unbind-скрипт: no-форма без значения, отсортированный порядок, echo-маркер.
func TestDNSUnbindScript(t *testing.T) {
	script := dnsUnbindScript(map[string]string{"zeta.abyss.lab": "10.0.0.3", "alpha.abyss.lab": "10.0.0.1"})
	lines := strings.Split(strings.TrimSuffix(script, "\n"), "\n")
	if len(lines) != 3 || lines[0] != `ndmc -c "no ip host alpha.abyss.lab"` || lines[1] != `ndmc -c "no ip host zeta.abyss.lab"` || lines[2] != `echo "declarative dns hosts unbound"` {
		t.Fatalf("скрипт не такой: %q", script)
	}
	if strings.Contains(script, "no ip host alpha.abyss.lab 10") {
		t.Fatalf("no-форма со значением запрещена (truth table 12.11): %q", script)
	}
}

// dnsDeclared как gates destroy-стадии.
func TestDNSDeclared(t *testing.T) {
	if dnsDeclared(nil) || dnsDeclared(map[string]string{}) {
		t.Fatalf("пустая декларация не должна быть declared")
	}
	if !dnsDeclared(map[string]string{"a.b.c": "1.2.3.4"}) {
		t.Fatalf("непустая декларация должна быть declared")
	}
}

// Ретрай-хелпер: пустой вывод первой попытки (полевой кейс 2026-11-12) →
// успех второй; три пустых/ошибочных = провал.
func TestReadStateRetrying(t *testing.T) {
	calls := 0
	fetch := func(string) (string, error) {
		calls++
		if calls == 1 {
			return "", nil // пустой вывод при живом транспорте
		}
		return "ip host a.b.c 1.2.3.4\n", nil
	}
	out, ok := readStateRetrying(fetch, "show running-config")
	if !ok || calls != 2 || !strings.Contains(out, "ip host") {
		t.Fatalf("ретрай не сработал: ok=%v calls=%d out=%q", ok, calls, out)
	}
	calls = 0
	fetchFail := func(string) (string, error) {
		calls++
		return "", errTestFetch{}
	}
	if _, ok := readStateRetrying(fetchFail, "x"); ok || calls != 3 {
		t.Fatalf("ожидались ровно 3 попытки и провал: ok=%v calls=%d", ok, calls)
	}
	// только-ANSI вывод (\x1b[K\r) — тоже пустой
	if _, ok := readStateRetrying(func(string) (string, error) { return "\x1b[K\r\n", nil }, "x"); ok {
		t.Fatalf("ANSI-only вывод должен считаться пустым")
	}
}

type errTestFetch struct{}

func (errTestFetch) Error() string { return "transport down" }

// Guard: дельта DNSHostsPlan на фикстуре с моделью (симметрия с policies-тестом).
func TestDNSHostsPlanWithModelConfig(t *testing.T) {
	var c model.Config
	c.DNS.Hosts = dnsDeclaredHosts()
	if err := c.DNS.Validate(); err != nil {
		t.Fatalf("валидация фикстуры: %v", err)
	}
	plan := DNSHostsPlan(fixtureDNSRunCfg, c.DNS.Hosts)
	if len(plan) != 0 {
		t.Fatalf("no-op сломан: %v", dnsVerbsCmds(plan))
	}
}
