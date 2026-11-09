// Package policy implements the policy-v2 model (docs/dev/policy-v2-design.md):
// parsing of the live ndm binding tables (`show ip hotspot`, `show ip policy`)
// and generation of the ndm verbs the daemon executes via ndmc.
//
// Ground truth (design, verified live 09.11):
//   - the SOURCE OF TRUTH for bindings is `show ip hotspot` (running-config's
//     `ip hotspot` block does NOT reflect host binds);
//   - host entries carry hostname/mac/ip/policy/active; interface blocks
//     (access points / bridges: Bridge0="Home", Bridge1="LAN", Bridge2="SMART")
//     carry the segment and its segment-level binding;
//   - policy: "" (empty) = unbound = follows the DEFAULT route table, which
//     policy-v2 makes ISP (the honest default; Proxy0 ip global 1200 > ISP 1000).
//
// The parser is deliberately tolerant: it keys on `key: value` tokens, not on
// indentation or field order, so cosmetic drift in ndm output cannot break it.
package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// Canonical policy names of the v2 model plus the CLI/API sentinel for unbind.
const (
	PolicyVPN   = "VPN"    // tunnel policy: permit Proxy0, no permit ISP
	PolicyNoVPN = "NO-VPN" // escape policy: permit ISP, no permit Proxy0
	PolicyNone  = "none"   // CLI/API sentinel: unbind (follow the default table)
)

// ValidPolicies lists the bind targets accepted by the API/CLI ("none" = unbind).
func ValidPolicies() []string { return []string{PolicyVPN, PolicyNoVPN, PolicyNone} }

// Host is one entry of `show ip hotspot`: a known hotspot client and its live
// policy binding. Policy == "" means unbound (honest default = ISP).
type Host struct {
	Hostname string
	MAC      string
	IP       string
	Policy   string // "" = unbound
	Segment  string // access point / bridge name as ndm knows it (Bridge0…)
	Active   bool
}

// Segment is one interface/access-point block of `show ip hotspot`.
type Segment struct {
	Name        string // e.g. Bridge0
	Description string // e.g. Home
	Policy      string // segment-level binding ("" = none)
	Active      bool
}

// Table is the parsed `show ip hotspot` output.
type Table struct {
	Hosts    []Host
	Segments []Segment
}

// splitKV reads one ndm `key: value` line (alignment-insensitive, quoted
// values unquoted). ok=false for lines without a key.
func splitKV(line string) (key, val string, ok bool) {
	i := strings.Index(line, ":")
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	val = strings.Trim(strings.TrimSpace(line[i+1:]), `"`)
	return key, val, true
}

var macRE = regexp.MustCompile(`(?i)^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// ValidMAC reports whether s is a colon-separated MAC address.
func ValidMAC(s string) bool { return macRE.MatchString(strings.TrimSpace(s)) }

var policyNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidPolicyName guards ndm policy object names before they are embedded
// into `ndmc -c "..."`: ndm accepts a conservative token, and anything else
// would be a quote-injection or parse error.
func ValidPolicyName(name string) bool { return policyNameRE.MatchString(name) }

// ParseHotspot parses `show ip hotspot` into hosts + segments. A host block is
// delimited by its own hostname/mac/ip fields; interface/access-point lines
// delimit segment blocks. Tolerates empty values (policy: / hostname:),
// missing lines (offline host without ip) and any field order.
func ParseHotspot(out string) Table {
	var t Table
	var cur *Host
	seg := -1 // index into t.Segments, -1 = outside a segment block
	flushHost := func() {
		if cur != nil {
			t.Hosts = append(t.Hosts, *cur)
			cur = nil
		}
	}
	for _, raw := range strings.Split(out, "\n") {
		key, val, ok := splitKV(raw)
		if !ok || key == "" {
			continue
		}
		switch key {
		case "interface", "access point":
			flushHost()
			seg = -1
			// value may carry a remark ("Bridge0 (Home)") — the bind token is
			// the first field; the full text is the fallback description
			name := val
			desc := ""
			if f := strings.Fields(val); len(f) > 0 {
				name = f[0]
				desc = strings.Trim(strings.TrimSpace(strings.Join(f[1:], " ")), "()")
			}
			t.Segments = append(t.Segments, Segment{Name: name, Description: desc})
			seg = len(t.Segments) - 1
		case "description":
			if cur == nil && seg >= 0 {
				t.Segments[seg].Description = val
			}
		case "hostname":
			if cur != nil && cur.Hostname != "" {
				flushHost() // a repeated identifier starts the next host block
			}
			if cur == nil {
				cur = &Host{}
				if seg >= 0 {
					cur.Segment = t.Segments[seg].Name
				}
			}
			cur.Hostname = val
		case "mac":
			if cur != nil && cur.MAC != "" {
				flushHost()
			}
			if cur == nil {
				cur = &Host{}
				if seg >= 0 {
					cur.Segment = t.Segments[seg].Name
				}
			}
			cur.MAC = strings.ToLower(val)
		case "ip":
			if cur == nil {
				cur = &Host{}
				if seg >= 0 {
					cur.Segment = t.Segments[seg].Name
				}
			}
			cur.IP = val
		case "policy":
			if cur != nil {
				cur.Policy = val
			} else if seg >= 0 {
				t.Segments[seg].Policy = val
			}
		case "active":
			v := strings.EqualFold(strings.TrimSpace(val), "yes")
			if cur != nil {
				cur.Active = v
			} else if seg >= 0 {
				t.Segments[seg].Active = v
			}
		}
	}
	flushHost()
	return t
}

// ParsePolicies parses `show ip policy` into policy object names. ndm renders
// this differently across versions (`name: VPN` fields or config-style
// `policy VPN` lines) — both surfaces are accepted, order preserved, deduped.
func ParsePolicies(out string) []string {
	var names []string
	seen := map[string]bool{}
	add := func(n string) {
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		names = append(names, n)
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if k, v, ok := splitKV(line); ok && (k == "name" || k == "policy") {
			add(v)
			continue
		}
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "policy" {
			add(f[1])
		}
	}
	return names
}

// ResolveHost matches target (MAC or hostname, case-insensitive) against the
// parsed table. Ambiguous hostname matches are an error (MAC is the unambiguous
// form — the CLI help says so).
func ResolveHost(tbl Table, target string) (Host, error) {
	q := strings.ToLower(strings.TrimSpace(target))
	if q == "" {
		return Host{}, fmt.Errorf("пустой адрес устройства: укажи MAC (aa:bb:cc:dd:ee:ff) или hostname")
	}
	if ValidMAC(q) {
		for _, h := range tbl.Hosts {
			if h.MAC == q {
				return h, nil
			}
		}
		return Host{}, fmt.Errorf("устройство с MAC %s не найдено в show ip hotspot", q)
	}
	var hits []Host
	for _, h := range tbl.Hosts {
		if strings.EqualFold(strings.TrimSpace(h.Hostname), q) {
			hits = append(hits, h)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return Host{}, fmt.Errorf("устройство %q не найдено в show ip hotspot (hostname с кавычками? используй MAC)", target)
	default:
		macs := make([]string, 0, len(hits))
		for _, h := range hits {
			macs = append(macs, h.MAC)
		}
		return Host{}, fmt.Errorf("hostname %q неоднозначен (%s) — укажи MAC явно", target, strings.Join(macs, ", "))
	}
}

// ResolveSegment matches target (bridge/ap token like Bridge0, or description
// like Home, case-insensitive) against the parsed table.
func ResolveSegment(tbl Table, target string) (Segment, error) {
	q := strings.ToLower(strings.TrimSpace(target))
	if q == "" {
		return Segment{}, fmt.Errorf("пустой адрес сегмента: укажи имя (Bridge0) или описание (Home)")
	}
	for _, s := range tbl.Segments {
		if strings.EqualFold(s.Name, q) || strings.EqualFold(s.Description, q) {
			return s, nil
		}
	}
	return Segment{}, fmt.Errorf("сегмент %q не найден в show ip hotspot", target)
}
