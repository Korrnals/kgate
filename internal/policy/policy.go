// Package policy implements the policy-v2 model (docs/dev/policy-v2-design.md):
// parsing of the live ndm binding tables (`show ip hotspot`, `show ip policy`)
// and generation of the ndm verbs the daemon executes via ndmc.
//
// Ground truth (design, verified live 09.11; association render verified live
// 13.11 on 192.168.1.1 — kgate-001):
//   - the binding SOURCE OF TRUTH is `show running-config` (`ip hotspot`
//     block: `policy <seg> <VPN|NO-VPN>` + `host <MAC> policy <NAME>`);
//     `show ip hotspot` renders association policy: inconsistently across
//     firmware builds (empty on 11.11, per-association effective on 13.11),
//     so it is display-only and the daemon overlays config truth on top;
//   - `show ip hotspot` carries TWO renders of segment blocks:
//   - design render: `interface: Bridge0` + `description: "Home"` —
//     the ndm name is the interface: value;
//   - association render (live 4.x, kgate-001): `interface:` EMPTY with
//     the identity on sub-lines — `id: Bridge0`, `name: Home`,
//     `description: WLAN` — one block per wireless association, hosts
//     precede their interface block, policy:/active: follow it and
//     describe the ASSOCIATION (not the segment). The ndm verb token is
//     the `name:` sub-line (running-config binds render `policy Home
//     VPN`); `id:` is the bridge alias (bug 3de63d9e: the parser took
//     the empty interface: value → Segment.Name == "" → every resolve
//     died — the declarative deploy path had to bypass descriptions);
//   - policy: "" (empty) = unbound = follows the DEFAULT route table, which
//     policy-v2 makes ISP (the honest default: ISP ip global 700 < Proxy0 1200 —
//     Proxy0 is a standby in the chain and the default policy is provider-only;
//     ip global membership itself is REQUIRED — without it KeeneticOS hides the
//     interface from the dashboard, priorities and policy bindings).
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
	Name        string // ndm name — the verb token (`ip hotspot policy Home VPN`)
	Id          string // ndm bridge id — resolve alias (Bridge0), "" on legacy renders
	Description string // e.g. WLAN
	Policy      string // segment-level binding ("" = none; daemon overlays config truth)
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

// policyNameRes matches the ndm object-name surfaces across firmware renders:
// the real `policy, name = VPN, description = ...` (KeeneticOS 4.x, field
// evidence 2026-11-11) and any `interface, name = ...`-style header is NOT
// matched — only the policy keyword with an `=` value is.
var policyNameRes = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^\s*policy,\s*name\s*=\s*([^\s,]+)`),
}

var macRE = regexp.MustCompile(`(?i)^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// ValidMAC reports whether s is a colon-separated MAC address.
func ValidMAC(s string) bool { return macRE.MatchString(strings.TrimSpace(s)) }

var policyNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidPolicyName guards ndm policy object names before they are embedded
// into `ndmc -c "..."`: ndm accepts a conservative token, and anything else
// would be a quote-injection or parse error.
func ValidPolicyName(name string) bool { return policyNameRE.MatchString(name) }

// segPending accumulates the identity of the CURRENT interface/segment
// sub-block (association render: `interface:` empty → `id:`/`name:`/
// `description:` sub-lines) until the block ends; then finalizeSeg resolves
// the ndm name (name: > id: > interface: value), upserts it (dedup per
// segment across associations) and re-links the association host.
type segPending struct {
	idx  int    // index of the appended slot in t.Segments
	name string // from the interface:/access point: value (design renders)
	id   string // `id:` sub-line (Bridge0)
	ndm  string // `name:` sub-line (Home — the verb token)
	desc string
}

// ParseHotspot parses `show ip hotspot` into hosts + segments. A host block is
// delimited by its own hostname/mac/ip fields; interface/access-point lines
// delimit segment blocks. Tolerates empty values (policy: / hostname:,
// interface: in the association render), missing lines (offline host without
// ip) and any field order. ANSI escape prefixes are stripped first (truth
// table 08.11: \x1b[K on line starts blinds key matching).
//
// The two segment-block renders are discriminated by the interface: VALUE:
// non-empty = design render (identity complete; policy:/active: belong to the
// SEGMENT — hosts come after); empty = association render (identity arrives
// on id:/name: sub-lines; the association's host fields PRECEDED the block
// and its policy:/active: belong to that HOST — kept via assocIdx).
func ParseHotspot(out string) Table {
	out = StripANSI(out)
	var t Table
	var cur *Host
	seg := -1      // index into t.Segments, -1 = outside a segment block
	inSeg := false // inside an interface/segment sub-block (id:/name:/description:)
	assoc := -1    // index into t.Hosts: the host of the current association block
	var pend segPending
	flushHost := func() {
		if cur != nil {
			t.Hosts = append(t.Hosts, *cur)
			cur = nil
		}
	}
	// finalizeSeg closes the segment sub-block: resolve identity, merge the
	// slot into an existing same-identity segment (association render emits
	// one block per association — without upsert the table fills with
	// nameless/duplicate rows), re-link the association host.
	finalizeSeg := func() {
		inSeg = false
		if seg < 0 {
			return
		}
		name := pend.ndm
		if name == "" {
			name = pend.id
		}
		if name == "" {
			name = pend.name
		}
		id := pend.id
		if id == "" {
			id = pend.name
		}
		if name == "" && id == "" {
			// interface: with no identity at all (no value, no sub-lines) —
			// drop the empty slot so the table never regresses to nameless rows
			t.Segments = append(t.Segments[:pend.idx], t.Segments[pend.idx+1:]...)
			seg = -1
			return
		}
		merged := -1
		for i := range t.Segments {
			if i == pend.idx {
				continue
			}
			if t.Segments[i].Name != "" && t.Segments[i].Name == name ||
				(id != "" && t.Segments[i].Id != "" && t.Segments[i].Id == id) {
				merged = i
				break
			}
		}
		if merged >= 0 {
			// duplicate association on an already-known segment: carry the
			// description over if the original lacks one, drop the new slot
			if t.Segments[merged].Description == "" {
				t.Segments[merged].Description = pend.desc
			}
			t.Segments = append(t.Segments[:pend.idx], t.Segments[pend.idx+1:]...)
			seg = merged
		} else {
			s := &t.Segments[pend.idx]
			s.Name, s.Id, s.Description = name, id, pend.desc
			seg = pend.idx
		}
		if assoc >= 0 && assoc < len(t.Hosts) {
			t.Hosts[assoc].Segment = t.Segments[seg].Name // association host → its own segment
		}
	}
	// associationTarget: who owns policy:/active: after an association block —
	// the flushed association host; nil when no association is linked.
	associationTarget := func() *Host {
		if assoc >= 0 && assoc < len(t.Hosts) {
			return &t.Hosts[assoc]
		}
		return nil
	}
	for _, raw := range strings.Split(out, "\n") {
		key, val, ok := splitKV(raw)
		if !ok || key == "" {
			continue
		}
		if inSeg && key != "id" && key != "name" && key != "description" {
			finalizeSeg() // first non-identity key ends the interface sub-block
		}
		switch key {
		case "host":
			// association render: every association entry starts with a bare
			// `host:` — a hard boundary (hostnames may repeat/be empty) and a
			// segment reset: the host stays unattached until ITS interface
			// block arrives (wired hosts without one stay honestly unattached)
			flushHost()
			assoc = -1
			seg = -1
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
			if name != "" {
				// design render: identity complete, no sub-block expected;
				// policy:/active: below belong to the segment itself
				inSeg = false
				assoc = -1
			} else {
				// association render: identity pending; the association's host
				// was just flushed — keep it linked for policy:/active: and
				// the post-finalize segment re-link
				pend = segPending{idx: seg}
				inSeg = true
				assoc = -1
				if len(t.Hosts) > 0 {
					assoc = len(t.Hosts) - 1
				}
			}
		case "id":
			if inSeg {
				pend.id = val
			}
		case "name":
			if inSeg {
				pend.ndm = val
			}
			// outside a segment sub-block `name:` is the host's registered
			// ndm name — hostname: is the display surface, keep ignoring it
		case "description":
			if inSeg {
				pend.desc = val
			} else if cur == nil && seg >= 0 {
				t.Segments[seg].Description = val
			}
		case "hostname":
			if cur != nil && cur.Hostname != "" {
				flushHost() // a repeated identifier starts the next host block
			}
			if cur == nil {
				assoc = -1 // a new host takes over from any linked association
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
				assoc = -1
				cur = &Host{}
				if seg >= 0 {
					cur.Segment = t.Segments[seg].Name
				}
			}
			cur.MAC = strings.ToLower(val)
		case "ip":
			if cur == nil {
				assoc = -1
				cur = &Host{}
				if seg >= 0 {
					cur.Segment = t.Segments[seg].Name
				}
			}
			cur.IP = val
		case "policy":
			if cur != nil {
				cur.Policy = val
			} else if h := associationTarget(); h != nil {
				h.Policy = val
			} else if seg >= 0 {
				t.Segments[seg].Policy = val
			}
		case "active":
			v := strings.EqualFold(strings.TrimSpace(val), "yes")
			if cur != nil {
				cur.Active = v
			} else if h := associationTarget(); h != nil {
				h.Active = v
			} else if seg >= 0 {
				t.Segments[seg].Active = v
			}
		}
	}
	if inSeg {
		finalizeSeg() // an unterminated trailing sub-block
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
	// real KeeneticOS renders objects as `policy, name = VPN, description = ...`
	// (field E2E 2026-11-11: the lab mock printed `name: VPN` and the parser
	// missed the real shape — set-device refused on a live router). The comma
	// form takes priority: f[0] == "policy," would never match the bare-word
	// branch below.
	for _, re := range policyNameRes {
		for _, m := range re.FindAllStringSubmatch(out, -1) {
			add(m[1])
		}
	}
	if len(names) > 0 {
		return names
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

// ParseHotspotBindings extracts MAC→policy bindings from `show running-config`
// (the binding source of truth on KeeneticOS 4.x — see ShowRunningConfigCmd).
// MACs are normalized to lowercase; only explicit `host <MAC> policy <NAME>`
// lines count (the bare `policy Bridge1 permit` segment lines do not match).
func ParseHotspotBindings(runCfg string) map[string]string {
	out := map[string]string{}
	for _, raw := range strings.Split(StripANSI(runCfg), "\n") {
		line := strings.TrimSpace(raw)
		if m := hotspotBindingRE.FindStringSubmatch(line); m != nil {
			out[strings.ToLower(m[1])] = m[2]
		}
	}
	return out
}

var hotspotBindingRE = regexp.MustCompile(`(?i)^host\s+([0-9a-f:]{17})\s+policy\s+([A-Za-z0-9_-]+)$`)

// segmentBindingRE extracts SEGMENT bindings from running-config:
// `policy <ndm-name> <VPN|NO-VPN>` lines inside the `ip hotspot` block.
// The name is the ndm verb token exactly as running-config renders it
// (`policy Home VPN` — NOT the description, NOT the Bridge0 id: the
// declarative deploy path and the daemon's segment overlay both key on it).
// A `policy Bridge1 permit` line (web-UI access policy) matches only when
// the second token is VPN|NO-VPN — kgate's managed set.
var segmentBindingRE = regexp.MustCompile(`(?m)^[ \t]*policy[ \t]+([^ \t]+)[ \t]+(VPN|NO-VPN)[ \t]*$`)

// ParseSegmentBindings parses running-config into map(ndm-name → policy).
// ANSI/CRLF noise is stripped first (truth table 08.11 + PTY renders) — the
// caller may pass raw ndmc output. Mirrors ParseHotspotBindings semantics.
func ParseSegmentBindings(runCfg string) map[string]string {
	out := map[string]string{}
	for _, m := range segmentBindingRE.FindAllStringSubmatch(StripANSI(runCfg), -1) {
		out[m[1]] = m[2]
	}
	return out
}

// ansiRE strips terminal escape sequences from ndmc output: on a live
// Keenetic every line can carry a `\x1b[K` (erase-to-EOL) prefix, which
// otherwise blinds both config parsers and makes the plan re-apply verbs on
// an already-converged state. Covers full CSI forms (`\x1b[0m`, `\x1b[2J`, …).
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// StripANSI removes ANSI escape sequences — run it before any parsing of
// ndmc show-output (truth table 08.11, field probe on 192.168.1.1).
func StripANSI(s string) string {
	// \r тоже мусор: PTY-сессии (см. ssh.go run) рендерят CRLF — голый \r
	// ломает ^/$-якоря regexp'ов парсеров (^policy ... $ без \r? не матчит).
	s = strings.ReplaceAll(s, "\r", "")
	return ansiRE.ReplaceAllString(s, "")
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

// ResolveSegment matches target (ndm name like Home, bridge id like Bridge0,
// or description like WLAN — case-insensitive) against the parsed table.
// The ndm name is the verb token; id/description are resolve aliases.
func ResolveSegment(tbl Table, target string) (Segment, error) {
	q := strings.ToLower(strings.TrimSpace(target))
	if q == "" {
		return Segment{}, fmt.Errorf("пустой адрес сегмента: укажи ndm-имя (Home), id (Bridge0) или описание (WLAN)")
	}
	for _, s := range tbl.Segments {
		if strings.EqualFold(s.Name, q) || strings.EqualFold(s.Id, q) || strings.EqualFold(s.Description, q) {
			return s, nil
		}
	}
	// kgate-001: the failure must be LOUD — what was searched for, what the
	// table actually held (an empty/blank table is a parser-vs-firmware
	// drift signal, not a user mistake).
	return Segment{}, fmt.Errorf("сегмент %q не найден в show ip hotspot; ndm показал сегменты: %s", target, segmentSummary(tbl))
}

// segmentSummary renders the parsed segments for diagnostics (kgate-001):
// name [id] (description) per row, capped so a drift storm stays readable.
func segmentSummary(tbl Table) string {
	if len(tbl.Segments) == 0 {
		return "ПУСТО — ни одного сегмента (ndmc вернул мусор или парсинг не совпал с рендером прошивки)"
	}
	const cap = 8
	parts := make([]string, 0, cap)
	for i, s := range tbl.Segments {
		if i == cap {
			parts = append(parts, fmt.Sprintf("… (ещё %d)", len(tbl.Segments)-cap))
			break
		}
		p := s.Name
		if p == "" {
			p = "(без имени)"
		}
		if s.Id != "" && s.Id != s.Name {
			p += " [" + s.Id + "]"
		}
		if s.Description != "" {
			p += " (" + s.Description + ")"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", ")
}
