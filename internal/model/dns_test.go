package model

import "testing"

// Декларация dns.hosts: ndm-безопасный fqdn ([a-z0-9.-], 1+ точка, без
// кавычек/метасимволов/shell-токенов) и строгая IPv4-форма адреса.
func TestDNSValidate(t *testing.T) {
	good := func() map[string]string {
		return map[string]string{"nas.abyss.lab": "192.168.1.10", "a-b.abyss.lab": "10.0.0.1"}
	}
	if err := (&DNS{Hosts: good()}).Validate(); err != nil {
		t.Fatalf("корректная декларация отклонена: %v", err)
	}

	bad := []struct {
		name string
		fqdn string
		ip   string
	}{
		{"точки нет", "nas", "192.168.1.10"},
		{"заглавные", "NAS.abyss.lab", "192.168.1.10"},
		{"кавычка", `nas".abyss.lab`, "192.168.1.10"},
		{"shell-метасимвол", "nas;reboot.abyss.lab", "192.168.1.10"},
		{"dollar", "nas$ ().abyss.lab", "192.168.1.10"},
		{"underscore", "nas_1.abyss.lab", "192.168.1.10"},
		{"дефис в начале", "-nas.abyss.lab", "192.168.1.10"},
		{"пустой fqdn", "", "192.168.1.10"},
		{"пустой ip", "nas.abyss.lab", ""},
		{"не ip", "nas.abyss.lab", "nas"},
		{"ipv6", "nas.abyss.lab", "::1"},
		{"v6-форма", "nas.abyss.lab", "fe80::1"},
	}
	for _, c := range bad {
		if err := (&DNS{Hosts: map[string]string{c.fqdn: c.ip}}).Validate(); err == nil {
			t.Fatalf("%s: ожидается отказ, принято fqdn=%q ip=%q", c.name, c.fqdn, c.ip)
		}
	}
}
