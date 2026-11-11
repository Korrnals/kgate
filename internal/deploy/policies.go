// Declarative hotspot policies (1.8.0): секция policies в kgate.yaml
// применяется стадией Policies() ПОСЛЕ ndm-стадии (там ndm-commands.sh
// создаёт политики VPN/NO-VPN) и снимается destroy'ом ДО удаления политик
// (ndm отказывается удалять `no ip policy`, пока остаются привязки).
//
// Правила (живьём проверено, нарушения = инцидент):
//   - ключи policies.segments — ndm-имена интерфейсов РОВНО как в
//     running-config (`policy Home VPN`), НЕ description («WLAN»): резолв
//     описаний kgate не используется (bug 3de63d9e — show отдаёт description,
//     ndm-имя резолвится в пустоту); применяется напрямую;
//   - источник истины по привязкам — running-config (`show ip hotspot` на
//     KeeneticOS 4.x рендерит policy: пустым), тот же, что у демона;
//   - идемпотентность: привязка, уже совпадающая с декларацией, НЕ порождает
//     ndmc-записи (no-op при повторном apply — flash не изнашивается).
package deploy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"kgate/internal/model"
	"kgate/internal/policy"
)

// policyVerb — один ndmc-верб дельты с человеческой подписью для консоли.
type policyVerb struct {
	label string
	cmd   string
}

// segmentBindingRE выцепляет segment-привязки из running-config:
// `policy <ndm-имя> <VPN|NO-VPN>` внутри блока `ip hotspot`. Линия
// `policy Bridge1 permit` (access-policy веб-морды) матчится только если
// второй токен — VPN|NO-VPN, что и есть наше управляемое множество.
var segmentBindingRE = regexp.MustCompile(`(?m)^[ \t]*policy[ \t]+([^ \t]+)[ \t]+(VPN|NO-VPN)[ \t]*$`)

// policyObjectRE — наличие объекта политики в `show ip policy`
// (те же формы, что у policy_exists в ndm-commands.sh).
var policyObjectRE = func(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)(^|[ \t])name:[ \t]*` + regexp.QuoteMeta(name) + `([ \t]|$)|(^|[ \t])policy[ \t]+` + regexp.QuoteMeta(name) + `([ \t]|$)`)
}

// segmentBindings парсит running-config в map(ndm-имя → политика).
func segmentBindings(runCfg string) map[string]string {
	out := map[string]string{}
	for _, m := range segmentBindingRE.FindAllStringSubmatch(runCfg, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// createRecipe — вербы полного создания ndm-политики (зеркало
// ndm-commands.sh: описание для дропдауна веб-морды + permit/no permit
// рецепт policy-v2: туннель = permit Proxy0, эскейп = permit ISP).
func createRecipe(name string) []policyVerb {
	switch name {
	case policy.PolicyVPN:
		return []policyVerb{
			{"создание политики VPN", "ip policy VPN"},
			{"описание политики VPN", `ip policy VPN description "Туннель - весь трафик идет через VPN"`},
			{"permit Proxy0 (VPN)", "ip policy VPN permit global Proxy0"},
			{"no permit ISP (VPN)", "ip policy VPN no permit global ISP"},
		}
	case policy.PolicyNoVPN:
		return []policyVerb{
			{"создание политики NO-VPN", "ip policy NO-VPN"},
			{"описание политики NO-VPN", `ip policy NO-VPN description "Напрямую - весь трафик идет через провайдера, минуя VPN"`},
			{"permit ISP (NO-VPN)", "ip policy NO-VPN permit global ISP"},
			{"no permit Proxy0 (NO-VPN)", "ip policy NO-VPN no permit global Proxy0"},
		}
	}
	return nil
}

// PolicyPlan возвращает дельту: только те ndmc-вербы, которых не хватает для
// схождения живого состояния с декларацией. Сегменты обходятся по
// отсортированным ключам — план детерминирован (одинаковый конфиг = одинаковый
// план, тестируемость и честный diff в логе). Уже совпадающие привязки и
// существующие политики вербов не порождают.
func PolicyPlan(runCfg, ipPolicy string, want model.Policies) []policyVerb {
	var plan []policyVerb
	// 1. гарантия существования политик VPN/NO-VPN (штатно их создаёт
	// ndm-commands.sh ndm-стадии; рецепты здесь — IaC-страховка)
	for _, name := range []string{policy.PolicyVPN, policy.PolicyNoVPN} {
		if !policyObjectRE(name).MatchString(ipPolicy) {
			plan = append(plan, createRecipe(name)...)
		}
	}
	// 2. сегментные привязки (детерминированный порядок)
	segs := make([]string, 0, len(want.Segments))
	for seg := range want.Segments {
		segs = append(segs, seg)
	}
	sort.Strings(segs)
	current := segmentBindings(runCfg)
	for _, seg := range segs {
		pol := want.Segments[seg]
		if current[seg] == pol {
			continue // уже сходится — ndmc-записи не будет
		}
		plan = append(plan, policyVerb{
			label: fmt.Sprintf("сегмент %s → %s", seg, pol),
			cmd:   fmt.Sprintf("ip hotspot %s policy %s", seg, pol),
		})
	}
	// 3. device-привязки (ParseHotspotBindings нормализует MAC в lower)
	bindings := policy.ParseHotspotBindings(runCfg)
	for _, d := range want.Devices {
		mac := strings.ToLower(strings.TrimSpace(d.MAC))
		if bindings[mac] == d.Policy {
			continue
		}
		plan = append(plan, policyVerb{
			label: fmt.Sprintf("устройство %s → %s", mac, d.Policy),
			cmd:   fmt.Sprintf("ip hotspot host %s policy %s", mac, d.Policy),
		})
	}
	return plan
}

// showSeparator — маркер разделения двух show-выводов за один ssh-заход
// (дельта считается в Go: та же функция, что покрыта тестами).
const showSeparator = "=== kgate-show-split ==="

// splitShows режет вывод `rc; sep; pol` на running-config и show ip policy.
func splitShows(out string) (runCfg, ipPolicy string, err error) {
	i := strings.Index(out, showSeparator)
	if i < 0 {
		return "", "", fmt.Errorf("вывод ssh без маркера %q — транспорт или ndmc сломаны", showSeparator)
	}
	return out[:i], out[i+len(showSeparator):], nil
}

// Policies — декларативная стадия: считает дельту по живому состоянию и
// исполняет ТОЛЬКО недостающие вербы, затем один save (если было что писать).
func (r *Runner) Policies() {
	fmt.Println("→ deploy: hotspot policies (declarative)")
	if err := r.c.Policies.Validate(); err != nil {
		r.fatal("конфиг policies: " + err.Error())
	}
	if len(r.c.Policies.Segments) == 0 && len(r.c.Policies.Devices) == 0 {
		fmt.Printf("  %s секция policies пуста — hotspot-привязки не декларированы (fail-safe прямой дефолт сохранён)\n", r.mark(true))
		return
	}
	if r.dry {
		fmt.Printf("  %s policies (dry-run: %d сегментных и %d device-привязок декларировано — план не считается, роутер не трогается)\n",
			r.mark(true), len(r.c.Policies.Segments), len(r.c.Policies.Devices))
		return
	}
	out, err := r.ssh.run(`printf '%s\n' "` + showSeparator + `"; ndmc -c "show running-config"; ndmc -c "show ip policy"`)
	if err != nil {
		r.failures++
		fmt.Printf("  %s чтение живого состояния (show running-config / show ip policy): %v\n", r.mark(false), err)
		return
	}
	runCfg, ipPolicy, err := splitShows(out)
	if err != nil {
		r.failures++
		fmt.Printf("  %s %v\n", r.mark(false), err)
		return
	}
	plan := PolicyPlan(runCfg, ipPolicy, r.c.Policies)
	if len(plan) == 0 {
		fmt.Printf("  %s состояние сходится — ndmc-записей не было (no-op, flash не тронут)\n", r.mark(true))
		return
	}
	applied := 0
	for _, v := range plan {
		if _, err := r.ssh.run(`ndmc -c '` + v.cmd + `'`); err != nil {
			r.failures++
			fmt.Printf("  %s %s: %v\n", r.mark(false), v.label, err)
			continue
		}
		applied++
		fmt.Printf("  %s %s\n", r.mark(true), v.label)
	}
	if applied == 0 {
		return // все вербы провалились — save бессмысленен
	}
	if out, err := r.ssh.run(`ndmc -c "system configuration save"`); err != nil || ndmcSaveFailed(out) {
		r.failures++
		fmt.Printf("  %s system configuration save — привязки НЕ зафиксированы (воскреснут при ребуте)\n", r.mark(false))
	}
}

// ndmcSaveFailed — ndmc-сбой может прийти и вербальной поверхностью
// ("system failed"), не только exit-кодом ssh (та же гигиена, что у демона).
func ndmcSaveFailed(out string) bool {
	o := strings.ToLower(out)
	return strings.Contains(o, "system failed") || strings.Contains(o, "error")
}

// policiesUnbindScript рендерит destroy-скрипт: снимает РОВНО декларированные
// привязки (`no policy` верб безопасен и на несуществующей привязке), чтобы
// удаление политик не блокировалось и re-apply после destroy восстанавливал
// заявленное состояние с нуля.
func policiesUnbindScript(p model.Policies) string {
	var b strings.Builder
	segs := make([]string, 0, len(p.Segments))
	for seg := range p.Segments {
		segs = append(segs, seg)
	}
	sort.Strings(segs)
	for _, seg := range segs {
		fmt.Fprintf(&b, "ndmc -c \"ip hotspot %s no policy\"\n", seg)
	}
	for _, d := range p.Devices {
		fmt.Fprintf(&b, "ndmc -c \"ip hotspot host %s no policy\"\n", strings.ToLower(strings.TrimSpace(d.MAC)))
	}
	b.WriteString("echo \"declarative bindings unbound\"\n")
	return b.String()
}

// policiesDeclared — есть ли хоть одна декларативная привязка.
func policiesDeclared(p model.Policies) bool {
	return len(p.Segments) > 0 || len(p.Devices) > 0
}
