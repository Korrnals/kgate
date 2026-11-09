package policy

import (
	"reflect"
	"strings"
	"testing"
)

// Fixtures are built from the design's verified-live ground truth
// (docs/dev/policy-v2-design.md): `show ip hotspot` entries carry
// hostname/mac/ip/policy/active, segment blocks carry the bridge/access-point
// name; values are ndm-conventional (aligned `key: value`, quoted strings,
// yes/no booleans). The parser keys on tokens, not layout — see the tolerance
// test below.

const fixtureHotspot = `
          interface: Bridge0
             description: "Home"
                  active: yes

                hostname: "pixel-phone"
                     mac: 5C:EB:F6:AA:BB:01
                      ip: 192.168.1.52
                  policy: VPN
                   active: yes

                hostname: "nas"
                     mac: 00:11:32:aa:bb:02
                      ip: 192.168.1.60
                  policy: NO-VPN
                   active: yes

          interface: Bridge1
             description: "LAN"
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
`

func TestParseHotspot_DesignFixture(t *testing.T) {
	tbl := ParseHotspot(fixtureHotspot)

	if len(tbl.Segments) != 2 {
		t.Fatalf("segments: got %d, want 2 (%+v)", len(tbl.Segments), tbl.Segments)
	}
	s0, s1 := tbl.Segments[0], tbl.Segments[1]
	if s0.Name != "Bridge0" || s0.Description != "Home" || !s0.Active || s0.Policy != "" {
		t.Errorf("segment0 = %+v", s0)
	}
	if s1.Name != "Bridge1" || s1.Description != "LAN" {
		t.Errorf("segment1 = %+v", s1)
	}

	if len(tbl.Hosts) != 4 {
		t.Fatalf("hosts: got %d, want 4 (%+v)", len(tbl.Hosts), tbl.Hosts)
	}
	if h := tbl.Hosts[0]; h.Hostname != "pixel-phone" || h.MAC != "5c:eb:f6:aa:bb:01" ||
		h.IP != "192.168.1.52" || h.Policy != "VPN" || h.Segment != "Bridge0" || !h.Active {
		t.Errorf("host0 = %+v", h)
	}
	// empty policy field = unbound (honest default)
	if h := tbl.Hosts[2]; h.Policy != "" || h.Hostname != "smart-tv" {
		t.Errorf("empty-policy host = %+v", h)
	}
	// inactive host, no ip line
	if h := tbl.Hosts[3]; h.Active || h.IP != "" || h.Segment != "Bridge1" {
		t.Errorf("inactive host = %+v", h)
	}
}

func TestParseHotspot_AccessPointRemark(t *testing.T) {
	// "access point:" is a two-word key and the value may carry a remark —
	// the bind token is the first field, the remark is a fallback description
	out := `
          access point: Bridge2 (SMART)
             description: "SMART segment"
                  policy: NO-VPN
                hostname: "sensor"
                     mac: aa:bb:cc:dd:ee:09
                  policy:
                   active: yes
`
	tbl := ParseHotspot(out)
	if len(tbl.Segments) != 1 || len(tbl.Hosts) != 1 {
		t.Fatalf("parsed %+v", tbl)
	}
	if s := tbl.Segments[0]; s.Name != "Bridge2" || s.Description != "SMART segment" || s.Policy != "NO-VPN" {
		t.Errorf("segment = %+v", s)
	}
	if h := tbl.Hosts[0]; h.Segment != "Bridge2" || h.Policy != "" || !h.Active {
		t.Errorf("host = %+v", h)
	}
}

func TestParseHotspot_MissingHostname(t *testing.T) {
	out := `
                hostname: "known"
                     mac: aa:bb:cc:dd:ee:01
                      ip: 192.168.1.10
                  policy: VPN
                   active: yes

                     mac: aa:bb:cc:dd:ee:02
                      ip: 192.168.1.11
                  policy:
                   active: yes
`
	tbl := ParseHotspot(out)
	if len(tbl.Hosts) != 2 {
		t.Fatalf("hosts: got %d, want 2 (%+v)", len(tbl.Hosts), tbl.Hosts)
	}
	if tbl.Hosts[1].Hostname != "" || tbl.Hosts[1].MAC != "aa:bb:cc:dd:ee:02" || tbl.Hosts[1].Policy != "" {
		t.Errorf("missing-hostname host = %+v", tbl.Hosts[1])
	}
}

func TestParseHotspot_MultiHostSameFields(t *testing.T) {
	out := `
                hostname: "a"
                     mac: aa:bb:cc:dd:ee:01
                  policy: VPN
                   active: yes
                hostname: "b"
                     mac: aa:bb:cc:dd:ee:02
                  policy: NO-VPN
                   active: yes
                hostname: "c"
                     mac: aa:bb:cc:dd:ee:03
                  policy:
                   active: no
`
	tbl := ParseHotspot(out)
	if len(tbl.Hosts) != 3 {
		t.Fatalf("hosts: got %d, want 3 (%+v)", len(tbl.Hosts), tbl.Hosts)
	}
	if tbl.Hosts[1].Policy != "NO-VPN" || tbl.Hosts[2].Active {
		t.Errorf("multi-host parse drifted: %+v", tbl.Hosts)
	}
}

func TestParseHotspot_ToleratesLayoutDrift(t *testing.T) {
	// reordered fields + wild indentation must parse identically
	out := strings.ReplaceAll(fixtureHotspot, "                    ", "\t\t\t\t\t\t\t")
	tbl := ParseHotspot(out)
	ref := ParseHotspot(fixtureHotspot)
	if !reflect.DeepEqual(tbl, ref) {
		t.Errorf("layout drift changed the parse: %+v vs %+v", tbl, ref)
	}
}

func TestParseHotspot_EmptyOutput(t *testing.T) {
	tbl := ParseHotspot("")
	if len(tbl.Hosts) != 0 || len(tbl.Segments) != 0 {
		t.Errorf("empty output parsed into %+v", tbl)
	}
}

const fixturePolicies = `
             name: VPN
      description: "policy-v2: туннель"
           permit: Proxy0

             name: NO-VPN
      description: "policy-v2: напрямую"
           permit: ISP
`

func TestParsePolicies_NameStyle(t *testing.T) {
	got := ParsePolicies(fixturePolicies)
	if !reflect.DeepEqual(got, []string{"VPN", "NO-VPN"}) {
		t.Errorf("got %v", got)
	}
}

func TestParsePolicies_ConfigStyle(t *testing.T) {
	out := `
policy VPN
     description "ЭСКАП: телевизоры"
     permit global ISP
policy VPN-TV
policy DIRECT-NOVPN
`
	got := ParsePolicies(out)
	want := []string{"VPN", "VPN-TV", "DIRECT-NOVPN"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveHost(t *testing.T) {
	tbl := ParseHotspot(fixtureHotspot)

	h, err := ResolveHost(tbl, "pixel-phone")
	if err != nil || h.MAC != "5c:eb:f6:aa:bb:01" {
		t.Errorf("by hostname: (%+v, %v)", h, err)
	}
	h, err = ResolveHost(tbl, "5C:EB:F6:AA:BB:01") // case-insensitive MAC
	if err != nil || h.Hostname != "pixel-phone" {
		t.Errorf("by MAC: (%+v, %v)", h, err)
	}
	if _, err = ResolveHost(tbl, "nope"); err == nil {
		t.Error("unknown target must fail")
	}
	if _, err = ResolveHost(tbl, ""); err == nil {
		t.Error("empty target must fail")
	}
}

func TestResolveHost_AmbiguousHostname(t *testing.T) {
	out := `
                hostname: "dup"
                     mac: aa:bb:cc:dd:ee:01
                   active: yes
                hostname: "dup"
                     mac: aa:bb:cc:dd:ee:02
                   active: yes
`
	_, err := ResolveHost(ParseHotspot(out), "dup")
	if err == nil || !strings.Contains(err.Error(), "aa:bb:cc:dd:ee:02") {
		t.Errorf("ambiguous hostname must name the MACs, got: %v", err)
	}
}

func TestResolveSegment(t *testing.T) {
	tbl := ParseHotspot(fixtureHotspot)
	s, err := ResolveSegment(tbl, "Home")
	if err != nil || s.Name != "Bridge0" {
		t.Errorf("by description: (%+v, %v)", s, err)
	}
	s, err = ResolveSegment(tbl, "bridge1")
	if err != nil || s.Description != "LAN" {
		t.Errorf("by token: (%+v, %v)", s, err)
	}
	if _, err = ResolveSegment(tbl, "Bridge9"); err == nil {
		t.Error("unknown segment must fail")
	}
}

// ---- command generators ----

func TestBindDeviceCmd(t *testing.T) {
	cmd, err := BindDeviceCmd("AA:BB:CC:DD:EE:FF", "VPN")
	if err != nil || cmd != "ip hotspot host aa:bb:cc:dd:ee:ff policy VPN" {
		t.Errorf("bind: (%q, %v)", cmd, err)
	}
	// design ground truth: unbind is the attribute form, NOT `no policy <NAME>`
	cmd, err = BindDeviceCmd("aa:bb:cc:dd:ee:ff", "")
	if err != nil || cmd != "ip hotspot host aa:bb:cc:dd:ee:ff no policy" {
		t.Errorf("unbind: (%q, %v)", cmd, err)
	}
	if _, err = BindDeviceCmd("aa:bb:cc:dd:ee", "VPN"); err == nil {
		t.Error("bad MAC must fail")
	}
	if _, err = BindDeviceCmd("aa:bb:cc:dd:ee:ff", `bad"name`); err == nil {
		t.Error("quote-bearing policy name must fail")
	}
}

func TestBindSegmentCmd(t *testing.T) {
	cmd, err := BindSegmentCmd("Bridge0", "NO-VPN")
	if err != nil || cmd != "ip hotspot Bridge0 policy NO-VPN" {
		t.Errorf("bind: (%q, %v)", cmd, err)
	}
	cmd, err = BindSegmentCmd("Bridge0", "")
	if err != nil || cmd != "ip hotspot Bridge0 no policy" {
		t.Errorf("unbind: (%q, %v)", cmd, err)
	}
	if _, err = BindSegmentCmd(`Bridge0; rm -rf /`, "VPN"); err == nil {
		t.Error("shell metacharacters in segment must fail")
	}
}

func TestPolicyObjectCmds(t *testing.T) {
	create, err := CreatePolicyCmd("VPN")
	if err != nil || create != "ip policy VPN" {
		t.Errorf("create: (%q, %v)", create, err)
	}
	desc, err := PolicyDescriptionCmd("VPN", "policy-v2 tunnel")
	if err != nil || desc != `ip policy VPN description "policy-v2 tunnel"` {
		t.Errorf("desc: (%q, %v)", desc, err)
	}
	permit, err := PolicyPermitCmd("VPN", "Proxy0", true)
	if err != nil || permit != "ip policy VPN permit global Proxy0" {
		t.Errorf("permit: (%q, %v)", permit, err)
	}
	deny, err := PolicyPermitCmd("VPN", "ISP", false)
	if err != nil || deny != "ip policy VPN no permit global ISP" {
		t.Errorf("deny: (%q, %v)", deny, err)
	}
	del, err := DeletePolicyCmd("VPN-TV")
	if err != nil || del != "no ip policy VPN-TV" {
		t.Errorf("delete: (%q, %v)", del, err)
	}
	if _, err := PolicyDescriptionCmd("VPN", `has"quote`); err == nil {
		t.Error("quote-bearing description must fail (ndmc -c embedding)")
	}
}

func TestSetGlobalPriorityCmd(t *testing.T) {
	if got := SetGlobalPriorityCmd(1200); got != "interface Proxy0 ip global 1200" {
		t.Errorf("got %q", got)
	}
}
