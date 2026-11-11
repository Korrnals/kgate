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
	if len(cmds) != 1 || cmds[0] != "ip hotspot Bridge1 policy NO-VPN" {
		t.Fatalf("ожидался единственный верб для Bridge1, получили: %v", cmds)
	}
}

// Дельта: перевернутая сегментная привязка (VPN вместо NO-VPN) — override-верб.
func TestPolicyPlanSegmentOverride(t *testing.T) {
	want := declarated()
	want.Segments["Bridge2"] = "VPN"
	plan := PolicyPlan(fixtureRunCfg, fixturePolicies, want)
	if cmds := verbsCmds(plan); len(cmds) != 1 || cmds[0] != "ip hotspot Bridge2 policy VPN" {
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
		"ip hotspot Home policy VPN",
		"ip hotspot Bridge2 policy NO-VPN",
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
		"ndmc -c \"ip hotspot Bridge2 no policy\"",
		"ndmc -c \"ip hotspot Home no policy\"",
		"ndmc -c \"ip hotspot host 54:ae:bc:9c:de:bf no policy\"",
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
