package daemon

// policy-v2 API: /api/v1/policy/* (docs/dev/policy-v2-design.md).
// The daemon executes ndm verbs via the ndmc seam; the binding source of
// truth is `show ip hotspot` (running-config does NOT reflect host binds).
// Mutating verbs are idempotent: a set to the ALREADY-BOUND policy sends no
// ndmc writes at all (no bind verb, no flash save); all-vpn/all-direct skip
// hosts whose binding already matches.

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

// hotspotTable queries and parses the live binding table. A ndmc failure is
// NOT silently parsed into an empty table (wave-1 C1: that surfaced as a
// "healthy" bound=0/total=0 response while ndmc was down) — callers must
// surface the error as a 500.
func (d *Daemon) hotspotTable() (policy.Table, error) {
	out := d.ndm(policy.ShowHotspotCmd)
	if ndmcFailed(out) {
		return policy.Table{}, fmt.Errorf("ndmc не ответил на %q: %s", policy.ShowHotspotCmd, strings.TrimSpace(out))
	}
	return policy.ParseHotspot(out), nil
}

// policyNames lists the policy objects ndm currently knows (error surface:
// wave-1 C1, same as hotspotTable).
func (d *Daemon) policyNames() ([]string, error) {
	out := d.ndm(policy.ShowPolicies)
	if ndmcFailed(out) {
		return nil, fmt.Errorf("ndmc не ответил на %q: %s", policy.ShowPolicies, strings.TrimSpace(out))
	}
	return policy.ParsePolicies(out), nil
}

func (d *Daemon) policyExists(name string) bool {
	ns, err := d.policyNames()
	if err != nil {
		return false // caller sees the real error via hotspotTable/policyNames surfaces
	}
	for _, n := range ns {
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
func (d *Daemon) policyList() (map[string]any, error) {
	tbl, err := d.hotspotTable()
	if err != nil {
		return nil, err
	}
	names, err := d.policyNames()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"policies": names,
		"hosts":    hostViews(tbl),
		"segments": segmentViews(tbl),
	}, nil
}

// policySetDevice binds target (MAC|hostname) to VPN|NO-VPN or unbinds
// ("none"). Errors name the missing piece: unknown device, unknown policy
// object (v2 deploy not applied), ndm rejection.
func (d *Daemon) policySetDevice(target, pol string) (map[string]any, error) {
	if !validTarget(pol) {
		return nil, userErrf("policy: %q — разрешены VPN|NO-VPN|none", pol)
	}
	tbl, err := d.hotspotTable()
	if err != nil {
		return nil, err
	}
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
	// idempotence (wave-1 C6): the binding already matches — no bind verb,
	// no flash save (each ndm-save wears the flash).
	if h.Policy == bind {
		return map[string]any{
			"resolved": map[string]string{
				"hostname": h.Hostname, "mac": h.MAC, "ip": h.IP, "segment": h.Segment,
			},
			"policy": pol, "ndmc": "(уже привязан — ndmc-записей не было)", "save": "", "already": true,
		}, nil
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
	tbl, err := d.hotspotTable()
	if err != nil {
		return nil, err
	}
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
	// idempotence (wave-1 C6): see policySetDevice
	if s.Policy == bind {
		return map[string]any{
			"resolved": map[string]string{"name": s.Name, "description": s.Description},
			"policy":   pol, "ndmc": "(уже привязан — ndmc-записей не было)", "save": "", "already": true,
		}, nil
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
	tbl, err := d.hotspotTable()
	if err != nil {
		return nil, err
	}
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
	tbl, err := d.hotspotTable()
	if err != nil {
		return nil, err
	}
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
// GET: list, segments (read-only). POST (JSON body): set-device, set-segment;
// no body: all-vpn, all-direct. Every mutating endpoint is POST-only
// (wave-1 C2): a GET — including link-preview/crawler traffic — is refused
// 405 before any wrap runs, so a mutation can never fire blind.
func (d *Daemon) registerPolicyHandlers(mux *http.ServeMux, logger func(string)) {
	writeErr := func(w http.ResponseWriter, err error, code int) {
		logger("policy: ОШИБКА " + err.Error())
		http.Error(w, err.Error(), code)
	}
	mutate := func(wrap func(r *http.Request) (map[string]any, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				writeErr(w, policyUserErr{msg: "метод " + r.Method + " запрещён: endpoint мутирует — используй POST"}, http.StatusMethodNotAllowed)
				return
			}
			out, err := wrap(r)
			if err != nil {
				code := http.StatusInternalServerError
				if isClientPolicyErr(err) {
					code = http.StatusBadRequest
				}
				writeErr(w, err, code)
				return
			}
			// honest log line for both verb shapes (wave-1 C5: all-vpn/
			// all-direct carry bound/unbound, not "ndmc")
			summary := fmt.Sprintf("%v", out["ndmc"])
			if b, ok := out["bound"]; ok {
				summary = fmt.Sprintf("bound=%v skipped=%v total=%v", b, out["skipped"], out["total"])
			} else if u, ok := out["unbound"]; ok {
				summary = fmt.Sprintf("unbound=%v skipped=%v total=%v", u, out["skipped"], out["total"])
			}
			logger("policy: " + r.URL.Path + " " + summary)
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
		out, err := d.policyList()
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError) // ndmc down = 500, не пустая таблица (wave-1 C1)
			return
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/api/v1/policy/segments", func(w http.ResponseWriter, r *http.Request) {
		tbl, err := d.hotspotTable()
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"segments": segmentViews(tbl)})
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
