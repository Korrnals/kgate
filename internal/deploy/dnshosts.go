// Declarative static dns hosts (1.10.0): секция dns.hosts в kgate.yaml
// применяется стадией DNSHosts() ПОСЛЕ policies — полный структурный близнец
// policies-слоя: дельта в Go по живому running-config, исполнение только
// недостающих вербов, один save, детерминизм (сортировка ключей).
//
// Truth table 12.11 (живой роутер, KeeneticOS 4.x):
//   - BIND:   `ip host <fqdn> <ip>` — работает молча, запись появляется в
//     running-config top-level строкой `ip host <fqdn> <ip>`;
//   - UNBIND: `no ip host <fqdn>` — работает молча (форма со значением не нужна);
//   - running-config: строки top-level (без отступа) `ip host <fqdn> <ip4>`;
//     indented `host <mac> policy` внутри блока ip hotspot — ДРУГОЙ парсер
//     (policy.ParseHotspotBindings), не путать;
//   - вывод ndmc несёт ANSI \x1b[K и \r (PTY): парсить только после
//     policy.StripANSI.
package deploy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"kgate/internal/policy"
)

// hostRecordRE выцепляет статические host-записи из running-config.
// Якорь ^ без отступа: только top-level строки; indented `host <mac> policy`
// внутри `ip hotspot` сюда не попадает по определению.
var hostRecordRE = regexp.MustCompile(`(?m)^ip host ([^ \t]+) ([0-9.]+)$`)

// parseHostRecords парсит running-config в map(fqdn → ip). Вызывается
// ТОЛЬКО на вычищенном (policy.StripANSI) тексте — ANSI-муусор ломает regex.
func parseHostRecords(runCfg string) map[string]string {
	out := map[string]string{}
	for _, m := range hostRecordRE.FindAllStringSubmatch(runCfg, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// dnsVerb — один ndmc-верб дельты с человеческой подписью для консоли.
type dnsVerb struct {
	label string
	cmd   string
}

// DNSHostsPlan возвращает дельту: только недостающие/расходящиеся bind-вербы.
// fqdn есть, ip другой → re-bind той же формой (ndm перезапишет запись).
// Ключи обходятся по отсортированным fqdn — план детерминирован (одинаковый
// конфиг = одинаковый план, тестируемость и честный diff в логе). Уже
// сходящиеся записи вербов не порождают (no-op при повторном apply).
func DNSHostsPlan(runCfg string, want map[string]string) []dnsVerb {
	var plan []dnsVerb
	fqdns := make([]string, 0, len(want))
	for f := range want {
		fqdns = append(fqdns, f)
	}
	sort.Strings(fqdns)
	current := parseHostRecords(runCfg)
	for _, f := range fqdns {
		ip := want[f]
		if current[f] == ip {
			continue // уже сходится — ndmc-записи не будет
		}
		plan = append(plan, dnsVerb{
			label: fmt.Sprintf("dns-запись %s → %s", f, ip),
			cmd:   fmt.Sprintf("ip host %s %s", f, ip), // truth table 12.11
		})
	}
	return plan
}

// dnsUnbindScript рендерит destroy-скрипт: снимает РОВНО декларированные
// записи (`no ip host <fqdn>` безопасен и на несуществующей записи),
// чтобы re-apply после destroy восстанавливал заявленное состояние с нуля.
func dnsUnbindScript(hosts map[string]string) string {
	var b strings.Builder
	fqdns := make([]string, 0, len(hosts))
	for f := range hosts {
		fqdns = append(fqdns, f)
	}
	sort.Strings(fqdns)
	for _, f := range fqdns {
		fmt.Fprintf(&b, "ndmc -c \"no ip host %s\"\n", f) // truth table 12.11: no-form без значения
	}
	b.WriteString("echo \"declarative dns hosts unbound\"\n")
	return b.String()
}

// dnsDeclared — есть ли хоть одна декларативная dns-запись.
func dnsDeclared(hosts map[string]string) bool {
	return len(hosts) > 0
}

// readStateRetrying — ретрай-ядро чтения show-состояния: до 3 попыток с
// бэкоффом 2s/4s; пустой (после StripANSI) вывод или ошибка ssh = провал
// попытки. После тяжёлых стадий (ndm-commands.sh = сотни ndmc-вызовов)
// роутер может кратко отдавать ПУСТОЙ вывод с nil-ошибкой ssh (полевой
// кейс 2026-11-12). Повтор идемпотентен, пауза даёт ndm выдохнуть.
func readStateRetrying(fetch func(string) (string, error), cmd string) (string, bool) {
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		out, err := fetch(cmd)
		if err != nil || strings.TrimSpace(policy.StripANSI(out)) == "" {
			continue
		}
		return out, true
	}
	return "", false
}

// readState — чтение show-состояния через pty (усечённый non-tty вывод ndmc
// ломает парсинг) с ретраем и бэкоффом. Общий хелпер стадий Policies/DNSHosts.
func (r *Runner) readState(cmd string) (string, bool) {
	return readStateRetrying(r.ssh.ptyRun, cmd)
}

// DNSHosts — декларативная стадия: считает дельту по живому running-config и
// исполняет ТОЛЬКО недостающие bind-вербы, затем один save (если было что
// писать). Вызывается сразу после Policies().
func (r *Runner) DNSHosts() {
	fmt.Println("→ deploy: static dns hosts (declarative)")
	if err := r.c.DNS.Validate(); err != nil {
		r.fatal("конфиг dns: " + err.Error())
	}
	if !dnsDeclared(r.c.DNS.Hosts) {
		fmt.Printf("  %s секция dns.hosts пуста — статические dns-записи не декларированы\n", r.mark(true))
		return
	}
	if r.dry {
		fmt.Printf("  %s dns.hosts (dry-run: %d записей декларировано — план не считается, роутер не трогается)\n",
			r.mark(true), len(r.c.DNS.Hosts))
		return
	}
	out, ok := r.readState(`ndmc -c "show running-config"`)
	if !ok {
		r.failures++
		fmt.Printf("  %s чтение живого состояния (show running-config): не удалось за 3 попытки — транспорт или ndmc перегружены\n", r.mark(false))
		return
	}
	plan := DNSHostsPlan(policy.StripANSI(out), r.c.DNS.Hosts)
	if len(plan) == 0 {
		fmt.Printf("  %s состояние сходится — ndmc-записей не было (no-op, flash не тронут)\n", r.mark(true))
		return
	}
	applied := 0
	for _, v := range plan {
		vo, err := r.ssh.run(`ndmc -c '` + v.cmd + `'`)
		if err != nil || ndmcVerbFailed(vo) {
			r.failures++
			fmt.Printf("  %s %s: верб отклонён ndm (rc/verbal): %v %q\n", r.mark(false), v.label, err, strings.TrimSpace(vo))
			continue
		}
		applied++
		fmt.Printf("  %s %s\n", r.mark(true), v.label)
	}
	if applied == 0 {
		return // все вербы провалились — save бессмысленен
	}
	if so, err := r.ssh.run(`ndmc -c "system configuration save"`); err != nil || ndmcSaveFailed(so) {
		r.failures++
		fmt.Printf("  %s system configuration save — dns-записи НЕ зафиксированы (воскреснут при ребуте)\n", r.mark(false))
	}
}
