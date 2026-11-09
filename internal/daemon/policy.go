package daemon

// policy-v2 API: /api/v1/policy/* (docs/dev/policy-v2-design.md).
// The daemon executes ndm verbs via the ndmc seam; the binding source of
// truth is `show ip hotspot` (running-config does NOT reflect host binds).
// Every mutating verb is idempotent: re-binding the same policy and
// all-vpn/all-direct on a converged system send no ndmc writes at all.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"kgate/internal/policy"
)

// policyUserErr marks 400-grade failures (bad enum, unknown device/segment/
// policy, malformed body) as opposed to 500-grade ndm rejections.
type policyUserErr struct{ msg string }

func (e policyUserErr) Error() string { return e.msg }

func userErrf(format string, a ...any) error {
	return policyUserErr{msg: fmt.Sprintf(format, a...)}
}

func isClientPolicyErr(err error) bool {
	_, ok := err.(policyUserErr)
	return ok
}

// hotspotTable queries and parses the live binding table.
func (d *Daemon) hotspotTable() policy.Table {
	return policy.ParseHotspot(d.ndm(policy.ShowHotspotCmd))
}

// policyNames lists the policy objects ndm currently knows.
func (d *Daemon) policyNames() []string {
	return policy.ParsePolicies(d.ndm(policy.ShowPolicies))
}

func (d *Daemon) policyExists(name string) bool {
	for _, n := range d.policyNames() {
		if n == name {
			return true
		}
	}
	return false
}

// validTarget checks the API policy enum (VPN|NO-VPN|none).
func validTarget(name string) bool {
	for _, p := range policy.ValidPolicies() {
		if p == name {
			return true
		}
	}
	return false
}

// policyBind executes a bind/unbind verb and translates the ndm failure
// surface ("system failed"/"invalid"/exec ERR) into an error.
func (d *Daemon) policyBind(cmd string) error {
	out := d.ndm(cmd)
	if ndmcFailed(out) {
		return fmt.Errorf("ndmc отклонил %q: %s", cmd, strings.TrimSpace(out))
	}
	return nil
}

// policySave persists the running-config after successful mutations
// (mirrors the toggle handler: /opt intent aside, ndm state must survive
// reboot). Best effort — the save output is returned for observability.
func (d *Daemon) policySave() string {
	return strings.TrimSpace(d.ndm(policy.SaveCmd))
}

// ---- views ----

type hostView struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Segment  string `json:"segment"`
	Policy   string `json:"policy"` // "" = unbound: honest default (ISP)
	Active   bool   `json:"active"`
}

type segmentView struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Policy      string `json:"policy"` // "" = unbound
	Active      bool   `json:"active"`
	Hosts       int    `json:"hosts"`
}

func hostViews(tbl policy.Table) []hostView {
	out := make([]hostView, 0, len(tbl.Hosts))
	for _, h := range tbl.Hosts {
		out = append(out, hostView{
			Hostname: h.Hostname, IP: h.IP, MAC: h.MAC,
			Segment: h.Segment, Policy: h.Policy, Active: h.Active,
		})
	}
	return out
}

func segmentViews(tbl policy.Table) []segmentView {
	counts := map[string]int{}
	for _, h := range tbl.Hosts {
		if h.Segment != "" {
			counts[h.Segment]++
		}
	}
	out := make([]segmentView, 0, len(tbl.Segments))
	for _, s := range tbl.Segments {
		out = append(out, segmentView{
			Name: s.Name, Description: s.Description,
			Policy: s.Policy, Active: s.Active, Hosts: counts[s.Name],
		})
	}
	return out
}

// ---- operations ----

// policyList serves the live table: policies + hosts + segments.
func (d *Daemon) policyList() map[string]any {
	tbl := d.hotspotTable()
	return map[string]any{
		"policies": d.policyNames(),
		"hosts":    hostViews(tbl),
		"segments": segmentViews(tbl),
	}
}

// policySetDevice binds target (MAC|hostname) to VPN|NO-VPN or unbinds
// ("none"). Errors name the missing piece: unknown device, unknown policy
// object (v2 deploy not applied), ndm rejection.
func (d *Daemon) policySetDevice(target, pol string) (map[string]any, error) {
	if !validTarget(pol) {
		return nil, userErrf("policy: %q — разрешены VPN|NO-VPN|none", pol)
	}
	tbl := d.hotspotTable()
	h, err := policy.ResolveHost(tbl, target)
	if err != nil {
		return nil, policyUserErr{msg: err.Error()}
	}
	bind := pol
	if pol == policy.PolicyNone {
		bind = ""
	} else if !d.policyExists(pol) {
		return nil, userErrf("политика %s не найдена в ndm (show ip policy) — сначала kgate deploy: ndm-commands.sh v2 создаёт VPN/NO-VPN", pol)
	}
	cmd, err := policy.BindDeviceCmd(h.MAC, bind)
	if err != nil {
		return nil, err
	}
	if err := d.policyBind(cmd); err != nil {
		return nil, err
	}
	return map[string]any{
		"resolved": map[string]string{
			"hostname": h.Hostname, "mac": h.MAC, "ip": h.IP, "segment": h.Segment,
		},
		"policy": pol,
		"ndmc":   cmd,
		"save":   d.policySave(),
	}, nil
}

// policySetSegment binds target (bridge/ap token or description) to
// VPN|NO-VPN or unbinds ("none"). Segment bind covers the whole segment;
// per-device binds override it (ndm semantics).
func (d *Daemon) policySetSegment(target, pol string) (map[string]any, error) {
	if !validTarget(pol) {
		return nil, userErrf("policy: %q — разрешены VPN|NO-VPN|none", pol)
	}
	tbl := d.hotspotTable()
	s, err := policy.ResolveSegment(tbl, target)
	if err != nil {
		return nil, policyUserErr{msg: err.Error()}
	}
	bind := pol
	if pol == policy.PolicyNone {
		bind = ""
	} else if !d.policyExists(pol) {
		return nil, userErrf("политика %s не найдена в ndm (show ip policy) — сначала kgate deploy: ndm-commands.sh v2 создаёт VPN/NO-VPN", pol)
	}
	cmd, err := policy.BindSegmentCmd(s.Name, bind)
	if err != nil {
		return nil, err
	}
	if err := d.policyBind(cmd); err != nil {
		return nil, err
	}
	return map[string]any{
		"resolved": map[string]string{"name": s.Name, "description": s.Description},
		"policy":   pol,
		"ndmc":     cmd,
		"save":     d.policySave(),
	}, nil
}

// policyAllVPN binds EVERY ACTIVE host to VPN (design §CLI: all-vpn).
// Already-bound and offline hosts are skipped without ndmc writes; per-host
// ndm rejections are collected, not fatal — the summary stays honest.
func (d *Daemon) policyAllVPN() (map[string]any, error) {
	if !d.policyExists(policy.PolicyVPN) {
		return nil, userErrf("политика VPN не найдена в ndm — сначала kgate deploy (ndm-commands.sh v2)")
	}
	tbl := d.hotspotTable()
	bound, skipped := 0, 0
	var errs []string
	for _, h := range tbl.Hosts {
		if !h.Active || h.Policy == policy.PolicyVPN {
			skipped++
			continue
		}
		cmd, err := policy.BindDeviceCmd(h.MAC, policy.PolicyVPN)
		if err == nil {
			err = d.policyBind(cmd)
		}
		if err != nil {
			errs = append(errs, h.MAC+": "+err.Error())
			continue
		}
		bound++
	}
	if bound > 0 {
		d.policySave()
	}
	return map[string]any{
		"policy": policy.PolicyVPN, "bound": bound, "skipped": skipped,
		"total": len(tbl.Hosts), "errors": errs, "saved": bound > 0,
	}, nil
}

// policyAllDirect unbinds EVERY bound host (design §CLI: all-direct) —
// including offline ones, whose stale binds would silently re-apply later.
// Unbound hosts are skipped without ndmc writes.
func (d *Daemon) policyAllDirect() (map[string]any, error) {
	tbl := d.hotspotTable()
	unbound, skipped := 0, 0
	var errs []string
	for _, h := range tbl.Hosts {
		if h.Policy == "" {
			skipped++
			continue
		}
		cmd, err := policy.BindDeviceCmd(h.MAC, "")
		if err == nil {
			err = d.policyBind(cmd)
		}
		if err != nil {
			errs = append(errs, h.MAC+": "+err.Error())
			continue
		}
		unbound++
	}
	if unbound > 0 {
		d.policySave()
	}
	return map[string]any{
		"policy": policy.PolicyNone, "unbound": unbound, "skipped": skipped,
		"total": len(tbl.Hosts), "errors": errs, "saved": unbound > 0,
	}, nil
}

// ---- HTTP wiring ----

// registerPolicyHandlers wires /api/v1/policy/* into the mTLS mux.
// GET: list, segments. POST (JSON body): set-device, set-segment;
// no body: all-vpn, all-direct. A GET on a mutating endpoint fails body
// decoding (400) — the mutation never runs blind.
func (d *Daemon) registerPolicyHandlers(mux *http.ServeMux, logger func(string)) {
	writeErr := func(w http.ResponseWriter, err error, code int) {
		logger("policy: ОШИБКА " + err.Error())
		http.Error(w, err.Error(), code)
	}
	mutate := func(wrap func(r *http.Request) (map[string]any, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			out, err := wrap(r)
			if err != nil {
				code := http.StatusInternalServerError
				if isClientPolicyErr(err) {
					code = http.StatusBadRequest
				}
				writeErr(w, err, code)
				return
			}
			logger("policy: " + strings.TrimSpace(fmt.Sprintf("%v %v", r.URL.Path, out["ndmc"])))
			json.NewEncoder(w).Encode(out)
		}
	}
	withBody := func(fn func(target, pol string) (map[string]any, error)) func(r *http.Request) (map[string]any, error) {
		return func(r *http.Request) (map[string]any, error) {
			var in struct {
				Target string `json:"target"`
				Policy string `json:"policy"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				return nil, userErrf("ожидаю JSON {\"target\":..., \"policy\":\"VPN|NO-VPN|none\"}: %v", err)
			}
			return fn(in.Target, in.Policy)
		}
	}

	mux.HandleFunc("/api/v1/policy/list", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(d.policyList())
	})
	mux.HandleFunc("/api/v1/policy/segments", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"segments": segmentViews(d.hotspotTable())})
	})
	mux.HandleFunc("/api/v1/policy/set-device", mutate(withBody(d.policySetDevice)))
	mux.HandleFunc("/api/v1/policy/set-segment", mutate(withBody(d.policySetSegment)))
	mux.HandleFunc("/api/v1/policy/all-vpn", mutate(func(r *http.Request) (map[string]any, error) {
		return d.policyAllVPN()
	}))
	mux.HandleFunc("/api/v1/policy/all-direct", mutate(func(r *http.Request) (map[string]any, error) {
		return d.policyAllDirect()
	}))
}
