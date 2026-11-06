package subscribe

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseVLESSReality(t *testing.T) {
	uri := "vless://d3361c9a-1cf5-4e4f-b7a1-7a3f7afbcc85@cdn.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBLICKEY123&sid=abcd&type=tcp#RU-Front"
	n, err := parseVLESS(uri)
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != "vless" || n.Tag != "sub-RU-Front" {
		t.Fatalf("tag/type: %+v", n)
	}
	ob := n.Outbound
	if ob["uuid"] != "d3361c9a-1cf5-4e4f-b7a1-7a3f7afbcc85" || ob["server"] != "cdn.example.com" {
		t.Fatalf("outbound: %+v", ob)
	}
	if ob["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow missing")
	}
	tls := ob["tls"].(map[string]any)
	if tls["server_name"] != "www.microsoft.com" {
		t.Fatalf("sni: %+v", tls)
	}
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] != "PUBLICKEY123" || reality["short_id"] != "abcd" {
		t.Fatalf("reality: %+v", reality)
	}
}

func TestParseHysteria2(t *testing.T) {
	uri := "hysteria2://secretpw@hy2.example.net:8443/?sni=hy2.example.net&obfs=salamander&obfs-password=obfspw#Backup-HY2"
	n, err := parseHysteria2(uri)
	if err != nil {
		t.Fatal(err)
	}
	if n.Outbound["password"] != "secretpw" || n.Outbound["server"] != "hy2.example.net" {
		t.Fatalf("outbound: %+v", n.Outbound)
	}
	if n.Outbound["server_port"] != 8443 {
		t.Fatalf("port: %+v", n.Outbound)
	}
	obfs := n.Outbound["obfs"].(map[string]any)
	if obfs["password"] != "obfspw" {
		t.Fatalf("obfs: %+v", obfs)
	}
}

func TestParseSS(t *testing.T) {
	// форма ss://base64(method:pass@host:port)#name
	inner := "chacha20-ietf-poly1305:sspass@10.2.3.4:8388"
	uri := "ss://" + base64.RawStdEncoding.EncodeToString([]byte(inner)) + "#SS-Node"
	n, err := parseSS(uri)
	if err != nil {
		t.Fatal(err)
	}
	ob := n.Outbound
	if ob["method"] != "chacha20-ietf-poly1305" || ob["password"] != "sspass" || ob["server"] != "10.2.3.4" {
		t.Fatalf("ss outbound: %+v", ob)
	}
}

func TestParseURIListBase64(t *testing.T) {
	list := "vless://uuid-1@a.example:443?sni=a.example#Node-A\nhysteria2://pw@b.example:443?sni=b.example#Node-B"
	b64 := base64.StdEncoding.EncodeToString([]byte(list))
	nodes, err := Parse([]byte(b64))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes: %d", len(nodes))
	}
}

func TestParseSingboxJSON(t *testing.T) {
	cfg := `{"outbounds":[
		{"type":"vless","tag":"my-vless","server":"x","server_port":443,"uuid":"u"},
		{"type":"direct","tag":"direct"},
		{"type":"selector","tag":"sel","outbounds":["my-vless"]}
	]}`
	nodes, err := Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Tag != "sub-my-vless" {
		t.Fatalf("json nodes: %+v", nodes)
	}
}

func TestMergeRewritesRoute(t *testing.T) {
	skeleton := []byte(`{
		"inbounds":[{"type":"mixed","tag":"proxy-in"}],
		"outbounds":[{"type":"hysteria2","tag":"hy2-out"},{"type":"direct","tag":"direct"}],
		"route":{"final":"hy2-out","rules":[
			{"clash_mode":"Global","outbound":"hy2-out"},
			{"ip_is_private":true,"outbound":"direct"},
			{"rule_set":["geoip-ru"],"outbound":"direct"}
		]}
	}`)
	nodes, _ := Parse([]byte("vless://u1@n1.example:443#Exit-1\nvless://u2@n2.example:443#Exit-2"))
	merged, err := Merge(skeleton, nodes)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	obs := cfg["outbounds"].([]any)
	var tags []string
	var sel map[string]any
	for _, o := range obs {
		om := o.(map[string]any)
		tags = append(tags, om["tag"].(string))
		if om["tag"] == "sub-proxy" {
			sel = om
		}
	}
	if len(tags) != 4 { // direct + 2 nodes + selector
		t.Fatalf("tags: %v", tags)
	}
	if sel == nil || sel["default"] != "sub-Exit-1" {
		t.Fatalf("selector: %+v", sel)
	}
	route := cfg["route"].(map[string]any)
	if route["final"] != "sub-proxy" {
		t.Fatalf("final: %v", route["final"])
	}
	for _, r := range route["rules"].([]any) {
		rm := r.(map[string]any)
		if rm["outbound"] == "hy2-out" {
			t.Fatalf("stale hy2-out reference: %+v", rm)
		}
	}
	if !strings.Contains(string(merged), "sub-Exit-2") {
		t.Fatalf("второй узел потерян")
	}
}
