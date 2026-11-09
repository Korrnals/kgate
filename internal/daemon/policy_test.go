package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// policyFixtureHotspot mirrors the design's ground truth for `show ip hotspot`:
// two segments (Bridge0=Home, Bridge1=LAN), a bound host, an unbound host
// (empty policy = honest default), an inactive host and a duplicate hostname.
const policyFixtureHotspot = `
          interface: Bridge0
             description: "Home"
                  active: yes

                hostname: "pixel-phone"
                     mac: 5c:eb:f6:aa:bb:01
                      ip: 192.168.1.52
                  policy: VPN
                   active: yes

                hostname: "smart-tv"
                     mac: aa:bb:cc:dd:ee:ff
                      ip: 192.168.2.20
                  policy:
                   active: yes

                hostname: "vacuum"
                     mac: 50:8f:4c:aa:bb:03
                  policy:
                   active: no

          interface: Bridge1
             description: "LAN"
                  active: yes

                hostname: "dup"
                     mac: aa:bb:cc:dd:ee:10
                  policy:
                   active: yes

                hostname: "dup"
                     mac: aa:bb:cc:dd:ee:11
                  policy:
                   active: yes
`

const policyFixturePolicies = `
             name: VPN
             name: NO-VPN
`

func policyTestDaemon(t *testing.T) (*Daemon, *fakeNDM) {
	t.Helper()
	d, fake := testDaemon(t, "203.0.113.10")
	fake.responses = map[string]string{
		"show ip hotspot": policyFixtureHotspot,
		"show ip policy":  policyFixturePolicies,
	}
	return d, fake
}

func assertCmds(t *testing.T, fake *fakeNDM, want []string, label string) {
	t.Helper()
	if len(fake.cmds) != len(want) {
		t.Fatalf("%s: cmds = %v, want %v", label, fake.cmds, want)
	}
	for i := range want {
		if fake.cmds[i] != want[i] {
			t.Fatalf("%s: cmds[%d] = %q, want %q (all: %v)", label, i, fake.cmds[i], want[i], fake.cmds)
		}
	}
}

func TestPolicySetDevice_ByHostname_BindsVPN(t *testing.T) {
	d, fake := policyTestDaemon(t)
	out, err := d.policySetDevice("pixel-phone", "VPN")
	if err != nil {
		t.Fatalf("set device: %v", err)
	}
	if out["ndmc"] != "ip hotspot host 5c:eb:f6:aa:bb:01 policy VPN" {
		t.Errorf("ndmc = %v", out["ndmc"])
	}
	assertCmds(t, fake, []string{
		"show ip hotspot",
		"show ip policy",
		"ip hotspot host 5c:eb:f6:aa:bb:01 policy VPN",
		"system configuration save",
	}, "bind-vpn")
}

func TestPolicySetDevice_None_UnbindAttrForm(t *testing.T) {
	d, fake := policyTestDaemon(t)
	// design ground truth: unbind is the attribute form, NOT `no policy <NAME>`
	if _, err := d.policySetDevice("aa:bb:cc:dd:ee:ff", "none"); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	assertCmds(t, fake, []string{
		"show ip hotspot",
		"ip hotspot host aa:bb:cc:dd:ee:ff no policy",
		"system configuration save",
	}, "unbind")
}

func TestPolicySetDevice_RejectsUnknownPolicy(t *testing.T) {
	d, fake := policyTestDaemon(t)
	if _, err := d.policySetDevice("pixel-phone", "DIRECT"); err == nil {
		t.Fatal("unknown policy enum must fail")
	} else if !isClientPolicyErr(err) {
		t.Errorf("enum violation must be a user error, got: %v", err)
	}
	assertCmds(t, fake, nil, "reject-enum") // enum checked first: no ndmc traffic at all
}

func TestPolicySetDevice_PolicyObjectMissing(t *testing.T) {
	d, fake := policyTestDaemon(t)
	fake.responses["show ip policy"] = "" // v2 deploy not applied
	_, err := d.policySetDevice("smart-tv", "NO-VPN")
	if err == nil || !strings.Contains(err.Error(), "не найдена") || !isClientPolicyErr(err) {
		t.Fatalf("missing policy object must be a user error, got: %v", err)
	}
	assertCmds(t, fake, []string{"show ip hotspot", "show ip policy"}, "missing-policy")
}

func TestPolicySetDevice_MissingHost(t *testing.T) {
	d, _ := policyTestDaemon(t)
	_, err := d.policySetDevice("ghost", "VPN")
	if err == nil || !strings.Contains(err.Error(), "не найдено") {
		t.Fatalf("unknown host must fail with a named error, got: %v", err)
	}
	// ambiguous hostname must name the MACs
	_, err = d.policySetDevice("dup", "VPN")
	if err == nil || !strings.Contains(err.Error(), "aa:bb:cc:dd:ee:11") {
		t.Fatalf("ambiguous hostname must name MACs, got: %v", err)
	}
}

func TestPolicySetDevice_NdmcFailure(t *testing.T) {
	d, fake := policyTestDaemon(t)
	fake.failOn = map[string]bool{"ip hotspot host 5c:eb:f6:aa:bb:01 policy NO-VPN": true}
	if _, err := d.policySetDevice("pixel-phone", "NO-VPN"); err == nil ||
		!strings.Contains(err.Error(), "system failed") {
		t.Fatalf("ndm rejection must surface, got: %v", err)
	}
}

func TestPolicySetSegment_ByName(t *testing.T) {
	d, fake := policyTestDaemon(t)
	out, err := d.policySetSegment("Home", "NO-VPN") // by description
	if err != nil {
		t.Fatalf("set segment: %v", err)
	}
	if out["ndmc"] != "ip hotspot Bridge0 policy NO-VPN" {
		t.Errorf("ndmc = %v", out["ndmc"])
	}
	if _, err := d.policySetSegment("bridge1", "none"); err != nil { // by token
		t.Fatalf("unbind segment: %v", err)
	}
	assertCmds(t, fake, []string{
		"show ip hotspot", "show ip policy", "ip hotspot Bridge0 policy NO-VPN", "system configuration save",
		"show ip hotspot", "ip hotspot Bridge1 no policy", "system configuration save",
	}, "segment")
}

func TestPolicyAllVPN_ActiveOnly_SkipsBound(t *testing.T) {
	d, fake := policyTestDaemon(t)
	out, err := d.policyAllVPN()
	if err != nil {
		t.Fatalf("all-vpn: %v", err)
	}
	// active unbound: smart-tv + 2×dup; pixel-phone already VPN; vacuum inactive
	if out["bound"] != 3 || out["skipped"] != 2 || out["total"] != 5 {
		t.Errorf("summary = %v", out)
	}
	assertCmds(t, fake, []string{
		"show ip policy", "show ip hotspot",
		"ip hotspot host aa:bb:cc:dd:ee:ff policy VPN",
		"ip hotspot host aa:bb:cc:dd:ee:10 policy VPN",
		"ip hotspot host aa:bb:cc:dd:ee:11 policy VPN",
		"system configuration save",
	}, "all-vpn")
}

func TestPolicyAllDirect_UnbindsAllBound(t *testing.T) {
	d, fake := policyTestDaemon(t)
	out, err := d.policyAllDirect()
	if err != nil {
		t.Fatalf("all-direct: %v", err)
	}
	// only pixel-phone is bound; unbound + inactive are skipped
	if out["unbound"] != 1 || out["skipped"] != 4 || out["total"] != 5 {
		t.Errorf("summary = %v", out)
	}
	assertCmds(t, fake, []string{
		"show ip hotspot",
		"ip hotspot host 5c:eb:f6:aa:bb:01 no policy",
		"system configuration save",
	}, "all-direct")
}

func TestPolicyList_Shape(t *testing.T) {
	d, _ := policyTestDaemon(t)
	rep := d.policyList()
	pols, _ := rep["policies"].([]string)
	if len(pols) != 2 || pols[0] != "VPN" || pols[1] != "NO-VPN" {
		t.Errorf("policies = %v", rep["policies"])
	}
	if hosts := rep["hosts"].([]hostView); len(hosts) != 5 {
		t.Errorf("hosts = %d", len(hosts))
	}
	if segs := rep["segments"].([]segmentView); len(segs) != 2 || segs[1].Name != "Bridge1" {
		t.Errorf("segments = %+v", rep["segments"])
	}
}

func TestPolicyHandlers_HTTP(t *testing.T) {
	d, _ := policyTestDaemon(t)
	mux := http.NewServeMux()
	d.registerPolicyHandlers(mux, func(string) {})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// GET list: 200 + JSON shape
	resp, err := http.Get(srv.URL + "/api/v1/policy/list")
	if err != nil {
		t.Fatal(err)
	}
	var rep policyListReplyShape
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	resp.Body.Close()
	if rep.Policies[0] != "VPN" || len(rep.Hosts) != 5 || len(rep.Segments) != 2 {
		t.Errorf("list reply: %+v", rep)
	}

	// GET segments: 200
	if resp, err = http.Get(srv.URL + "/api/v1/policy/segments"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("segments: %v %v", resp, err)
	}
	resp.Body.Close()

	// GET on a mutating endpoint: 400, no mutation
	if resp, err = http.Get(srv.URL + "/api/v1/policy/set-device"); err != nil || resp.StatusCode != 400 {
		t.Fatalf("GET set-device must 400: %v %v", resp, err)
	}
	resp.Body.Close()

	// POST set-device bad enum: 400
	resp, err = http.Post(srv.URL+"/api/v1/policy/set-device", "application/json",
		strings.NewReader(`{"target":"pixel-phone","policy":"DIRECT"}`))
	if err != nil || resp.StatusCode != 400 {
		t.Fatalf("bad enum must 400: %v %v", resp, err)
	}
	resp.Body.Close()

	// POST set-device: 200 + resolved host
	resp, err = http.Post(srv.URL+"/api/v1/policy/set-device", "application/json",
		strings.NewReader(`{"target":"pixel-phone","policy":"NO-VPN"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("set-device: %v %v", resp, err)
	}
	var set map[string]any
	json.NewDecoder(resp.Body).Decode(&set)
	resp.Body.Close()
	if set["policy"] != "NO-VPN" || set["ndmc"] != "ip hotspot host 5c:eb:f6:aa:bb:01 policy NO-VPN" {
		t.Errorf("set-device reply: %v", set)
	}

	// POST all-vpn / all-direct: 200
	for _, ep := range []string{"all-vpn", "all-direct"} {
		resp, err = http.Post(srv.URL+"/api/v1/policy/"+ep, "application/json", strings.NewReader("{}"))
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", ep, resp, err)
		}
		resp.Body.Close()
	}
}

// policyListReplyShape mirrors the client's view structs without importing them.
type policyListReplyShape struct {
	Policies []string `json:"policies"`
	Hosts    []struct {
		Hostname string `json:"hostname"`
		Policy   string `json:"policy"`
		Active   bool   `json:"active"`
	} `json:"hosts"`
	Segments []struct {
		Name  string `json:"name"`
		Hosts int    `json:"hosts"`
	} `json:"segments"`
}
