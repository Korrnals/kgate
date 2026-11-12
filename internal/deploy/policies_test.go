package deploy

import (
	"strings"
	"testing"

	"kgate/internal/model"
	"kgate/internal/policy"
)

// Fixture running-config: живая поверхность KeeneticOS 4.x — сегментные
// привязки `policy <ndm-имя> <POL>` внутри `ip hotspot`, device-привязки
// `host <MAC> policy <POL>`, access-policy веб-морды (`policy Bridge1 permit`)
// не должна матчиться как segment-привязка.
const fixtureRunCfg = `ip hotspot
    policy Home VPN
    policy Bridge1 permit
    policy Bridge2 NO-VPN
    host 54:ae:bc:9c:de:bf policy NO-VPN
    host 34:f3:9a:b5:13:19 policy NO-VPN
`
const fixturePolicies = "name: VPN\nname: NO-VPN\n"

func declarated() model.Policies {
	return model.Policies{
		Segments: map[string]string{"Home": "VPN", "Bridge2": "NO-VPN"},
		Devices: []model.DevicePolicy{
			{MAC: "54:AE:BC:9C:DE:BF", Policy: "NO-VPN"},
		},
	}
}

func verbsCmds(plan []policyVerb) []string {
	out := make([]string, 0, len(plan))
	for _, v := range plan {
		out = append(out, v.cmd)
	}
	return out
}

func containsCmd(cmds []string, want string) bool {
	for _, c := range cmds {
		if c == want {
			return true
		}
	}
	return false
}

// Полное схождение: уже созданные политики + совпадающие привязки = пустая
// дельта (no-op при повторном apply, ndmc-записей нет).
func TestPolicyPlanConvergedIsNoop(t *testing.T) {
	plan := PolicyPlan(fixtureRunCfg, fixturePolicies, declarated())
	if len(plan) != 0 {
		t.Fatalf("ожидался пустой план (no-op), получили: %v", verbsCmds(plan))
	}
}

// Дельта: расхождение ровно по одной device-привязке — единственный верб.
func TestPolicyPlanDeviceDelta(t *testing.T) {
	want := declarated()
	want.Devices[0].Policy = "VPN"
	plan := PolicyPlan(fixtureRunCfg, fixturePolicies, want)
	cmds := verbsCmds(plan)
	if len(cmds) != 1 {
		t.Fatalf("ожидался ровно 1 верб, получили %d: %v", len(cmds), cmds)
	}
	if want_ := "ip hotspot host 54:ae:bc:9c:de:bf policy VPN"; cmds[0] != want_ {
		t.Fatalf("верб = %q, want %q (MAC нормализован в lower)", cmds[0], want_)
	}
}

// Дельта: сегмент без привязки — один segment-верб; access-policy
// (`policy Bridge1 permit`) не считается segment-привязкой.
func TestPolicyPlanSegmentDelta(t *testing.T) {
	want := declarated()
	want.Segments["Bridge1"] = "NO-VPN"
	plan := PolicyPlan(fixtureRunCfg, fixturePolicies, want)
	cmds := verbsCmds(plan)
	if len(cmds) != 1 || cmds[0] != "ip hotspot policy Bridge1 NO-VPN" {
		t.Fatalf("ожидался единственный верб для Bridge1, получили: %v", cmds)
	}
}

// Дельта: перевернутая сегментная привязка (VPN вместо NO-VPN) — override-верб.
func TestPolicyPlanSegmentOverride(t *testing.T) {
	want := declarated()
	want.Segments["Bridge2"] = "VPN"
	plan := PolicyPlan(fixtureRunCfg, fixturePolicies, want)
	if cmds := verbsCmds(plan); len(cmds) != 1 || cmds[0] != "ip hotspot policy Bridge2 VPN" {
		t.Fatalf("ожидался override-верб Bridge2→VPN, получили: %v", cmds)
	}
}

// Гарантия существования: на чистом роутере (пустой show ip policy) план
// несёт полные рецепты создания обеих политик + все привязки.
func TestPolicyPlanCreatesMissingPolicies(t *testing.T) {
	plan := PolicyPlan("", "", declarated())
	cmds := verbsCmds(plan)
	for _, want := range []string{
		"ip policy VPN",
		"ip policy NO-VPN",
		"ip policy VPN permit global Proxy0",
		"ip policy NO-VPN permit global ISP",
		"ip hotspot policy Home VPN",
		"ip hotspot policy Bridge2 NO-VPN",
		"ip hotspot host 54:ae:bc:9c:de:bf policy NO-VPN",
	} {
		if !containsCmd(cmds, want) {
			t.Fatalf("в плане нет верба %q; план: %v", want, cmds)
		}
	}
}

// Детерминизм: сегменты обходятся по отсортированным ключам.
func TestPolicyPlanDeterministicOrder(t *testing.T) {
	want := declarated()
	want.Segments["Bridge1"] = "VPN"
	want.Segments["Bridge3"] = "VPN"
	a := verbsCmds(PolicyPlan("", "", want))
	b := verbsCmds(PolicyPlan("", "", want))
	if strings.Join(a, "|") != strings.Join(b, "|") {
		t.Fatalf("план недетерминирован:\n%v\n%v", a, b)
	}
	if !strings.HasPrefix(strings.Join(a, "|"), "ip policy") {
		t.Fatalf("ожидаем рецепты создания политик первыми: %v", a)
	}
}

// Парсер segment-привязок: ndm-имя берётся как есть (Home — ndm-имя, не
// «Bridge0», не description «WLAN»; bug 3de63d9e не участвует).
func TestSegmentBindings(t *testing.T) {
	got := segmentBindings(fixtureRunCfg)
	want := map[string]string{"Home": "VPN", "Bridge2": "NO-VPN"}
	if len(got) != len(want) {
		t.Fatalf("segmentBindings = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("segmentBindings[%q] = %q, want %q", k, got[k], v)
		}
	}
}

// Разделение двух show за один ssh-заход.
func TestSplitShows(t *testing.T) {
	rc, pol, err := splitShows("ip hotspot\n    policy Home VPN\n=== kgate-show-split ===\nname: VPN\n")
	if err != nil {
		t.Fatalf("splitShows: %v", err)
	}
	if !strings.Contains(rc, "policy Home VPN") || !strings.Contains(pol, "name: VPN") {
		t.Fatalf("splitShows потерял содержимое: rc=%q pol=%q", rc, pol)
	}
	if _, _, err := splitShows("no marker here"); err == nil {
		t.Fatal("ожидалась ошибка на выводе без маркера")
	}
}

// Destroy: скрипт снятия декларативных привязок — по вербу на привязку.
func TestPoliciesUnbindScript(t *testing.T) {
	s := policiesUnbindScript(declarated())
	for _, want := range []string{
		"ndmc -c \"no ip hotspot policy Bridge2\"",
		"ndmc -c \"no ip hotspot policy Home\"",
		"ndmc -c \"no ip hotspot host 54:ae:bc:9c:de:bf policy\"",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("в скрипте нет %q; скрипт:\n%s", want, s)
		}
	}
}

// Пустая декларация: destroy-шаг не ставится вовсе.
func TestPoliciesDeclared(t *testing.T) {
	if policiesDeclared(model.Policies{}) {
		t.Fatal("пустая декларация не должна считаться объявленной")
	}
	if !policiesDeclared(declarated()) {
		t.Fatal("декларация с привязками должна считаться объявленной")
	}
}

// Валидация декларации — table-driven по оскорбившим элементам.
func TestPoliciesValidate(t *testing.T) {
	cases := []struct {
		name    string
		p       model.Policies
		wantErr string // "" = валидно
	}{
		{"valid", declarated(), ""},
		{"bad enum segment", model.Policies{Segments: map[string]string{"Home": "DIRECT"}}, `разрешены VPN|NO-VPN`},
		{"bad enum device", model.Policies{Devices: []model.DevicePolicy{{MAC: "54:AE:BC:9C:DE:BF", Policy: "vpn"}}}, `разрешены VPN|NO-VPN`},
		{"bad mac", model.Policies{Devices: []model.DevicePolicy{{MAC: "nope", Policy: "VPN"}}}, "не похож на MAC"},
		{"empty segment", model.Policies{Segments: map[string]string{"": "VPN"}}, "пустое или содержит"},
		{"quote in segment", model.Policies{Segments: map[string]string{`Home"; rm -rf /`: "VPN"}}, "пустое или содержит"},
	}
	for _, c := range cases {
		err := c.p.Validate()
		if c.wantErr == "" {
			if err != nil {
				t.Fatalf("%s: неожиданная ошибка %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Fatalf("%s: err = %v, want содержащий %q", c.name, err, c.wantErr)
		}
	}
}

// sanity: используем policy-константы, чтобы маппинг VPN→«Туннель…» не отвязался
func TestPolicyNameMapping(t *testing.T) {
	if policy.PolicyVPN != "VPN" || policy.PolicyNoVPN != "NO-VPN" {
		t.Fatalf("канонические имена политик изменились: %q / %q — обнови модель и доки", policy.PolicyVPN, policy.PolicyNoVPN)
	}
}

// Truth table 08.11: `\x1b[K` prefixes must not blind splitShows/парсеры —
// иначе план считает всё расходящимся и пере-применяет вербы + лишний save.
func TestSplitShowsStripANSI(t *testing.T) {
	out := "\x1b[Kip hotspot\x1b[K\n\x1b[K    policy Home VPN\x1b[K\n=== kgate-show-split ===\nname: VPN\n"
	rc, pol, err := splitShows(out)
	if err != nil {
		t.Fatalf("splitShows: %v", err)
	}
	if got := segmentBindings(rc); got["Home"] != "VPN" {
		t.Errorf("segmentBindings after ANSI strip: %v", got)
	}
	if pol != "\nname: VPN\n" {
		t.Errorf("ipPolicy: %q", pol)
	}
}

// Вербальная проверка apply-цикла: rc=0 + "error[7405600]" в выводе = FAIL
// (ndmc в tty не возвращает ненулевой код на invalid-вербах).
func TestNdmcVerbFailed(t *testing.T) {
	for _, s := range []string{"error[7405600]: no such command: Bridge0", "system failed [7405602], arg parse"} {
		if !ndmcVerbFailed(s) {
			t.Errorf("ndmcVerbFailed(%q) = false", s)
		}
	}
	if ndmcVerbFailed("Hotspot::Manager: Policy VPN applied to interface Home.") {
		t.Error("успешный вывод матчится как отказ")
	}
}

// Истинные формы unbind-вербов (truth table 08.11, live router).
func TestPoliciesUnbindScriptTrueForms(t *testing.T) {
	var p model.Policies
	p.Segments = map[string]string{"Home": "VPN"}
	p.Devices = []model.DevicePolicy{{MAC: "54:AE:BC:9C:DE:BF"}}
	got := policiesUnbindScript(p)
	for _, want := range []string{
		`ndmc -c "no ip hotspot policy Home"`,
		`ndmc -c "no ip hotspot host 54:ae:bc:9c:de:bf policy"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("unbind-скрипт без %q:\n%s", want, got)
		}
	}
}

// Полевой формат `show ip policy` (KeeneticOS 4.x, живой роутер 2026-11-12):
// табличная строка "policy, name = VPN, description = ..." — рецепт создания
// не должен порождаться, когда политика существует.
func TestPolicyObjectRE_TableFormat(t *testing.T) {
	out := "\n           policy, name = VPN, description = Туннель - весь трафик идет через VPN: \n" +
		"           policy, name = NO-VPN, description = Напрямую: \n"
	if !policyObjectRE("VPN").MatchString(out) {
		t.Fatal("VPN не найден в табличном формате show ip policy")
	}
	if !policyObjectRE("NO-VPN").MatchString(out) {
		t.Fatal("NO-VPN не найден в табличном формате show ip policy")
	}
	absent := "policy, name = OTHER, description = x:\n"
	if policyObjectRE("VPN").MatchString(absent) {
		t.Fatal("ложное срабатывание на отсутствующей политике")
	}
}

// PTY-сессии рендерят CRLF; StripANSI обязан снять \r до парсинга.
func TestSegmentBindings_CRLF(t *testing.T) {
	raw := "ip hotspot\r\n    \x1b[Kpolicy Home VPN\r\n    policy Bridge2 NO-VPN\r\n    host aa:bb:cc:dd:ee:ff policy VPN\r\n"
	clean := policy.StripANSI(raw)
	got := segmentBindings(clean)
	if got["Home"] != "VPN" || got["Bridge2"] != "NO-VPN" {
		t.Fatalf("CRLF-парсинг сегментов сломан: %v", got)
	}
	bindings := policy.ParseHotspotBindings(clean)
	if bindings["aa:bb:cc:dd:ee:ff"] != "VPN" {
		t.Fatalf("CRLF-парсинг host-привязок сломан: %v", bindings)
	}
}

// Порядок splitShows: running-config ДО маркера, show ip policy — после.
func TestSplitShows_Order(t *testing.T) {
	out := "ip hotspot\n    policy Home VPN\n=== kgate-show-split ===\npolicy, name = VPN\n"
	rc, ip, err := splitShows(out)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if !strings.Contains(rc, "policy Home VPN") {
		t.Fatalf("runCfg не содержит running-config: %q", rc)
	}
	if !strings.Contains(ip, "policy, name = VPN") {
		t.Fatalf("ipPolicy не содержит таблицу политик: %q", ip)
	}
}
