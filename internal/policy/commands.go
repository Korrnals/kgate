package policy

import (
	"fmt"
	"strings"
)

// Command generators for the ndm verbs of the policy-v2 model. Every generated
// string is embedded by the daemon into `ndmc -c "<cmd>"` (daemon.go escapes
// the outer quotes) — generators still reject quote-bearing tokens at the
// boundary so no ndm parse error / injection can pass through.

func checkName(what, name string) error {
	if !ValidPolicyName(name) {
		return fmt.Errorf("%s: %q недопустимо для ndm (буквы/цифры/_/-)", what, name)
	}
	return nil
}

func checkToken(what, s string) error {
	if s == "" || strings.ContainsAny(s, "\"'`$;&|<>\\\n\t ") {
		return fmt.Errorf("%s: %q содержит недопустимые символы", what, s)
	}
	return nil
}

// BindDeviceCmd: `ip hotspot host <MAC> policy <NAME>`; name "" (or "none" is
// resolved by the caller) → the unbind attribute form `ip hotspot host <MAC>
// no policy` (design ground truth: `no ... policy <NAME>` is a parse error).
func BindDeviceCmd(mac, name string) (string, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !ValidMAC(mac) {
		return "", fmt.Errorf("mac: %q не похож на MAC (aa:bb:cc:dd:ee:ff)", mac)
	}
	if name == "" {
		return "ip hotspot host " + mac + " no policy", nil
	}
	if err := checkName("policy", name); err != nil {
		return "", err
	}
	return "ip hotspot host " + mac + " policy " + name, nil
}

// BindSegmentCmd: `ip hotspot <segment> policy <NAME>`; name "" → the unbind
// attribute form `ip hotspot <segment> no policy`.
func BindSegmentCmd(segment, name string) (string, error) {
	if err := checkToken("segment", segment); err != nil {
		return "", err
	}
	if name == "" {
		return "ip hotspot " + segment + " no policy", nil
	}
	if err := checkName("policy", name); err != nil {
		return "", err
	}
	return "ip hotspot " + segment + " policy " + name, nil
}

// CreatePolicyCmd: `ip policy <NAME>` — bare object, routes are added separately.
func CreatePolicyCmd(name string) (string, error) {
	if err := checkName("policy", name); err != nil {
		return "", err
	}
	return "ip policy " + name, nil
}

// PolicyDescriptionCmd: `ip policy <NAME> description "<text>"`. The text is
// ndm-quoted here; the daemon's ndmc() escapes it once more for the shell.
// Descriptions are free text (spaces, Cyrillic) — only quote/backslash and
// shell-dangerous characters are rejected.
func PolicyDescriptionCmd(name, desc string) (string, error) {
	if err := checkName("policy", name); err != nil {
		return "", err
	}
	if desc == "" || strings.ContainsAny(desc, "\"\\`$\n\r\t") {
		return "", fmt.Errorf("description: %q содержит недопустимые символы", desc)
	}
	return fmt.Sprintf("ip policy %s description \"%s\"", name, desc), nil
}

// PolicyPermitCmd(permit=false → deny): `ip policy <NAME> [no ]permit global <iface>`
// — the escape/tunnel recipe from the design (escape = permit ISP + no permit
// Proxy0; tunnel = permit Proxy0 + no permit ISP).
func PolicyPermitCmd(name, iface string, permit bool) (string, error) {
	if err := checkName("policy", name); err != nil {
		return "", err
	}
	if err := checkToken("interface", iface); err != nil {
		return "", err
	}
	verb := "permit"
	if !permit {
		verb = "no permit"
	}
	return fmt.Sprintf("ip policy %s %s global %s", name, verb, iface), nil
}

// DeletePolicyCmd: `no ip policy <NAME>`. Callers must re-point bindings first
// (design back-compat rule) — ndm refuses deletion while bindings remain.
func DeletePolicyCmd(name string) (string, error) {
	if err := checkName("policy", name); err != nil {
		return "", err
	}
	return "no ip policy " + name, nil
}

// Show verbs and friends (fixed strings, no parameters — no validation needed).
const (
	ShowHotspotCmd = "show ip hotspot"
	ShowPolicies   = "show ip policy"
	SaveCmd        = "system configuration save"
)

// SetGlobalPriorityCmd: `interface Proxy0 ip global <prio>` — policy-v2 sets
// 1200 so ISP (1000) stays the honest default and bind decides everything.
func SetGlobalPriorityCmd(priority int) string {
	return fmt.Sprintf("interface Proxy0 ip global %d", priority)
}
